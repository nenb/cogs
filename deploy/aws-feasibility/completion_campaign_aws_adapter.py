"""Dormant concrete AWS adapter for the reviewed seven-cycle controller.

Importing this module is effect-free.  `run_fixed_campaign` is the sole effectful
entry and requires root-owned authenticated approval custody.  Tests and local
qualification never call it.  Commands are fixed repository scripts; callers
cannot select an executable, path, region, account, state key, or grant.
"""

from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import completion_campaign_production as production
import completion_campaign_remote_adapter as remote_adapter

ROOT = Path("/var/lib/cogs/stage2-aws-production-v2")
APPROVAL = ROOT / "approval.json"
AUTHENTICATION = ROOT / "approval-authentication.json"
CONSUMED = ROOT / "approval-consumed.json"
JOURNAL = ROOT / "campaign-journal.jsonl"
GRANT_ROOT = ROOT / "cycle-grant"
SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
EFFECT_COMMAND = SOURCE / "deploy/aws-feasibility/run-production-effect.sh"
REMOTE_COMMAND = SOURCE / "deploy/aws-feasibility/run-production-remote.sh"
INVENTORY_COMMAND = SOURCE / "deploy/aws-feasibility/run-production-inventory.sh"
RECOVERY_COMMAND = SOURCE / "deploy/aws-feasibility/recover-production-campaign.sh"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
FIXED_ENV = {"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
             "PATH": "/usr/local/bin:/usr/bin:/bin", "TZ": "UTC"}


class AwsAdapterError(production.ProductionCampaignError): pass


def _require(value):
    if not value: raise AwsAdapterError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value); value[key] = item
    return value


def _decode(raw, maximum=MAX_JSON_BYTES):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum
             and raw.endswith(b"\n") and b"\r" not in raw)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise AwsAdapterError() from error
    _require(type(value) is dict and _canonical(value) == raw)
    return value


def _read_fixed(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400
                 and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                 and 0 < before.st_size <= maximum)
        raw = os.read(descriptor, maximum + 1); after = os.fstat(descriptor)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                            item.st_gid, item.st_nlink, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        _require(len(raw) == before.st_size and key(before) == key(after))
        return raw
    finally:
        os.close(descriptor)


def _approval():
    raw = _read_fixed(APPROVAL, 64 * 1024)
    authentication_raw = _read_fixed(AUTHENTICATION, 64 * 1024)
    value = _decode(raw, 64 * 1024); authentication = _decode(authentication_raw, 64 * 1024)
    _require(set(authentication) == {
        "version", "result", "approval_sha256", "issuer_commitment",
        "workflow_sha256", "workflow_run_id", "workflow_run_attempt",
        "control_revision", "first_created"}
        and authentication["version"] ==
            "cogs.stage2-production-approval-authentication/v1"
        and authentication["result"] == "pass"
        and authentication["approval_sha256"] == hashlib.sha256(raw).hexdigest()
        and authentication["workflow_run_attempt"] == 1
        and authentication["first_created"] is True)
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    approval = production.ProductionApproval(**value)
    _require(approval.authentication_receipt_sha256 ==
             hashlib.sha256(authentication_raw).hexdigest()
             and approval.issuer_commitment == authentication["issuer_commitment"]
             and approval.control_revision == authentication["control_revision"])
    return approval, raw, authentication_raw


class _Authority:
    __slots__ = ("owner",)
    def __init__(self, owner): self.owner = owner


_ISSUED = {}


def _issue_port_authority(owner):
    value = _Authority(owner); _ISSUED[id(value)] = value; return value


def _validate_port_authority(value):
    return type(value) is _Authority and _ISSUED.pop(id(value), None) is value


class AwsCampaignCustodian:
    def __init__(self, approval, executor=subprocess.run):
        _require(type(approval) is production.ProductionApproval and executor is subprocess.run)
        self.approval = approval; self.executor = executor
        self._journal_tip = "0" * 64; self._journal_sequence = 0

    def now(self): return time.time_ns()

    def _append(self, category, event, ordinal, mode, commitment):
        production._digest(commitment)
        row = {"version": "cogs.stage2-production-campaign-journal/v1",
               "sequence": self._journal_sequence, "previous_sha256": self._journal_tip,
               "category": category, "event": event, "ordinal": ordinal,
               "mode": mode, "commitment": commitment}
        line = _canonical(row); line_sha = hashlib.sha256(line).hexdigest()
        descriptor = os.open(JOURNAL, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            seen = os.fstat(descriptor)
            _require(stat.S_ISREG(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                     and stat.S_IMODE(seen.st_mode) == 0o600
                     and seen.st_nlink == 1 and seen.st_size <= MAX_JOURNAL_BYTES
                     and os.write(descriptor, line) == len(line))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._journal_tip = line_sha; self._journal_sequence += 1

    def journal(self, category, event, ordinal, mode, commitment):
        self._append(category, event, ordinal, mode, commitment)

    def consume(self, approval, approval_commitment, observed):
        _require(approval is self.approval and not CONSUMED.exists())
        value = {"version": "cogs.stage2-production-approval-consumption/v1",
                 "approval_commitment": approval_commitment,
                 "batch_commitment": approval.batch_commitment,
                 "consumed_unix_ns": observed, "first_created": True}
        raw = _canonical(value)
        descriptor = os.open(CONSUMED, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            _require(os.write(descriptor, raw) == len(raw)); os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try: os.fsync(directory)
        finally: os.close(directory)
        commitment = hashlib.sha256(raw).hexdigest()
        return production.ApprovalConsumptionReceipt(
            approval_commitment, commitment, observed, True)

    def _run(self, command, arguments, timeout):
        _require(command in {EFFECT_COMMAND, REMOTE_COMMAND, INVENTORY_COMMAND,
                             RECOVERY_COMMAND}
                 and command.is_file() and os.access(command, os.X_OK))
        result = self.executor(
            ["/usr/bin/timeout", "--foreground", "--signal=TERM", "--kill-after=10s",
             f"{timeout}s", str(command), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=FIXED_ENV, cwd=SOURCE, timeout=timeout + 15, check=False)
        _require(result.returncode == 0 and not result.stderr
                 and 0 < len(result.stdout) <= MAX_JSON_BYTES)
        return result.stdout

    def _stage_grant(self, grant):
        GRANT_ROOT.mkdir(mode=0o700, exist_ok=False)
        path = GRANT_ROOT / "grant.json"; raw = remote_adapter.invocation(grant).grant_bytes
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        try: _require(os.write(descriptor, raw) == len(raw)); os.fsync(descriptor)
        finally: os.close(descriptor)
        directory = os.open(GRANT_ROOT, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try: os.fsync(directory)
        finally: os.close(directory)
        return path

    def effect(self, kind, grant, previous):
        _require(kind in production.EFFECT_KINDS
                 and type(grant) is production.CycleLaunchGrant
                 and (previous is None or type(previous) is production.EffectReceipt))
        previous_commitment = None if previous is None else previous.settlement_commitment
        intent = production._commit(b"cogs.stage2-provider-effect-intent/v1", {
            "kind": kind, "grant": grant.grant_commitment,
            "previous": previous_commitment})
        self._append("effect", "intent", grant.ordinal, grant.mode, intent)
        raw = self._run(EFFECT_COMMAND, (kind, str(grant.ordinal), grant.mode,
                         grant.grant_commitment), 900)
        value = _decode(raw)
        value["certain"] = value.get("certain") is True
        receipt = production.EffectReceipt(**value)
        _require(receipt.intent_commitment == intent)
        self._append("effect", "settled", grant.ordinal, grant.mode,
                     receipt.settlement_commitment)
        return receipt

    def remote(self, grant, apply, running):
        grant_path = self._stage_grant(grant)
        try:
            raw = self._run(REMOTE_COMMAND, (str(grant.ordinal), grant.mode,
                            grant.grant_commitment), 7800)
            return remote_adapter.remote_receipt(grant, apply, running, raw)
        finally:
            if grant_path.exists(): grant_path.unlink()
            if GRANT_ROOT.exists(): GRANT_ROOT.rmdir()

    def inventory(self, grant, destroyed, sequence):
        _require(type(destroyed) is production.EffectReceipt and 1 <= sequence <= 8)
        grant_commitment = "final" if grant is None else grant.grant_commitment
        raw = self._run(INVENTORY_COMMAND, (str(sequence), grant_commitment,
                        destroyed.state_commitment), 600)
        value = _decode(raw)
        pages = []
        for row in value.pop("pages"):
            resources = tuple(production.InventoryResource(**item)
                              for item in row.pop("resources"))
            pages.append(production.InventoryPage(**row, resources=resources))
        return production.InventoryReceipt(**value, pages=tuple(pages))

    def cost(self, grant, apply, destroy):
        duration = destroy.observed_ended_unix_ns - apply.observed_started_unix_ns
        _require(duration > 0)
        # Exact locked aggregate rate; the evidence issuer retains component prices.
        rate = 118_000
        cost = (duration * rate + 3_600_000_000_000 - 1) // 3_600_000_000_000
        fields = {"grant_commitment": grant.grant_commitment,
                  "cycle_ordinal": grant.ordinal,
                  "rate_source_commitment": production._commit(
                      b"cogs.stage2-fixed-rate/v1", {"micro_usd_per_hour": rate}),
                  "usage_commitment": production._commit(
                      b"cogs.stage2-provider-usage/v1", {"duration_ns": duration}),
                  "cost_micro_usd": cost}
        return production.CostReceipt(**fields, receipt_commitment=production._commit(
            b"cogs.stage2-cost-receipt/v1", fields))

    def recover(self, grant, state, last_certain, primary):
        raw = self._run(RECOVERY_COMMAND, (str(grant.ordinal), grant.mode,
                        grant.grant_commitment, state), 1200)
        value = _decode(raw)
        inventory = value.pop("inventory", None)
        parsed = None
        if inventory is not None:
            pages = []
            for row in inventory.pop("pages"):
                resources = tuple(production.InventoryResource(**item)
                                  for item in row.pop("resources"))
                pages.append(production.InventoryPage(**row, resources=resources))
            parsed = production.InventoryReceipt(**inventory, pages=tuple(pages))
        return production.CleanupReceipt(**value, inventory=parsed)

    def ports(self):
        authority = _issue_port_authority(self)
        return production._issue_adapter_ports(
            authority, self.approval, self.now, self.consume, self.effect,
            self.remote, self.inventory, self.cost, self.recover, self.journal)


def run_fixed_campaign():
    """Sole future AWS entry.  Merely importing this module performs no effect."""
    _require(os.geteuid() == 0 and os.getegid() == 0
             and ROOT.is_dir() and stat.S_IMODE(ROOT.stat().st_mode) == 0o700
             and ROOT.stat().st_uid == ROOT.stat().st_gid == 0
             and not (set(os.environ) & {
                 "PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "AWS_PROFILE",
                 "TF_VAR_credentials", "GOOGLE_APPLICATION_CREDENTIALS"}))
    approval, _approval_raw, _authentication_raw = _approval()
    custodian = AwsCampaignCustodian(approval)
    return production.ProductionCampaignController(custodian.ports()).run()
