"""Dormant concrete AWS adapter for the reviewed seven-cycle controller.

Importing this module is effect-free. ``run_fixed_campaign`` is the sole normal
entry; ``recover_fixed_campaign`` is cleanup-only and cannot return a candidate.
Both require the same root-owned custody directory and fixed repository scripts.
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
LOCK = ROOT / "campaign.lock"
ACTIVE = ROOT / "cleanup-active.json"
CLEANUP_COMPLETE = ROOT / "cleanup-complete.json"
STATE_ROOT = ROOT / "provider-state"
SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
EFFECT_COMMAND = SOURCE / "deploy/aws-feasibility/run-production-effect.sh"
REMOTE_COMMAND = SOURCE / "deploy/aws-feasibility/run-production-remote.sh"
INVENTORY_COMMAND = SOURCE / "deploy/aws-feasibility/run-production-inventory.sh"
RECOVERY_COMMAND = SOURCE / "deploy/aws-feasibility/recover-production-campaign.sh"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
FIXED_ENV = {
    "HOME": "/root", "LANG": "C", "LC_ALL": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin", "TZ": "UTC",
    "AWS_PROFILE": "nebula", "AWS_REGION": "us-east-1",
    "AWS_DEFAULT_REGION": "us-east-1", "AWS_PAGER": "",
    "AWS_EC2_METADATA_DISABLED": "true",
}


class AwsAdapterError(production.ProductionCampaignError):
    pass


def _require(value):
    if not value:
        raise AwsAdapterError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value)
        value[key] = item
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


def _read_fixed(path, maximum, modes=(0o400,)):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) in modes
                 and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                 and 0 < before.st_size <= maximum)
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                            item.st_gid, item.st_nlink, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        _require(len(raw) == before.st_size and key(before) == key(after))
        return raw
    finally:
        os.close(descriptor)


def _write_once(path, raw, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        _require(os.write(descriptor, raw) == len(raw))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _replace_durable(path, raw):
    temporary = path.with_name(path.name + ".new")
    try:
        _write_once(temporary, raw)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _approval():
    raw = _read_fixed(APPROVAL, 64 * 1024)
    authentication_raw = _read_fixed(AUTHENTICATION, 64 * 1024)
    value = _decode(raw, 64 * 1024)
    authentication = _decode(authentication_raw, 64 * 1024)
    _require(set(authentication) == {
        "version", "result", "approval_sha256", "issuer_commitment",
        "workflow_sha256", "workflow_run_id", "workflow_run_attempt",
        "control_revision", "approver_principal_commitment",
        "executor_principal_commitment", "signature_verification_commitment",
        "first_created"}
        and authentication["version"] ==
            "cogs.stage2-production-approval-authentication/v1"
        and authentication["result"] == "pass"
        and authentication["approval_sha256"] == hashlib.sha256(raw).hexdigest()
        and authentication["workflow_run_attempt"] == 1
        and authentication["first_created"] is True)
    for key in ("issuer_commitment", "workflow_sha256",
                "approver_principal_commitment", "executor_principal_commitment",
                "signature_verification_commitment"):
        production._digest(authentication[key])
    _require(authentication["approver_principal_commitment"] !=
             authentication["executor_principal_commitment"])
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    approval = production.ProductionApproval(**value)
    _require(approval.authentication_receipt_sha256 ==
             hashlib.sha256(authentication_raw).hexdigest()
             and approval.issuer_commitment == authentication["issuer_commitment"]
             and approval.control_revision == authentication["control_revision"])
    return approval


class _Authority:
    __slots__ = ("owner",)
    def __init__(self, owner):
        self.owner = owner


_ISSUED = {}
_ADAPTER_SEAL = object()


def _issue_port_authority(owner, seal):
    _require(seal is _ADAPTER_SEAL and type(owner) is AwsCampaignCustodian)
    value = _Authority(owner)
    _ISSUED[id(value)] = value
    return value


def _validate_port_authority(value):
    return (type(value) is _Authority and type(value.owner) is AwsCampaignCustodian
            and _ISSUED.pop(id(value), None) is value)


def _decode_inventory(value):
    pages = []
    for source in value.pop("pages"):
        row = dict(source)
        resources = tuple(production.InventoryResource(**item)
                          for item in row.pop("resources"))
        pages.append(production.InventoryPage(**row, resources=resources))
    return production.InventoryReceipt(**value, pages=tuple(pages))


class AwsCampaignCustodian:
    def __init__(self, seal, approval, executor=subprocess.run):
        _require(seal is _ADAPTER_SEAL and type(approval) is production.ProductionApproval
                 and callable(executor))
        self.approval = approval
        self.executor = executor

    def now(self):
        return time.time_ns()

    def _journal_state(self, descriptor):
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = b""
        while block := os.read(descriptor, 1024 * 1024):
            raw += block
            _require(len(raw) <= MAX_JOURNAL_BYTES)
        tip = "0" * 64
        sequence = 0
        for line in raw.splitlines(keepends=True):
            row = _decode(line, 64 * 1024)
            _require(row == {
                "version": "cogs.stage2-production-campaign-journal/v1",
                "sequence": sequence, "previous_sha256": tip,
                "category": row.get("category"), "event": row.get("event"),
                "ordinal": row.get("ordinal"), "mode": row.get("mode"),
                "commitment": row.get("commitment"),
            })
            production._digest(row["commitment"])
            tip = hashlib.sha256(line).hexdigest()
            sequence += 1
        return sequence, tip

    def _append(self, category, event, ordinal, mode, commitment):
        production._digest(commitment)
        descriptor = os.open(JOURNAL, os.O_RDWR | os.O_APPEND | os.O_CREAT |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            seen = os.fstat(descriptor)
            _require(stat.S_ISREG(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                     and stat.S_IMODE(seen.st_mode) == 0o600 and seen.st_nlink == 1
                     and seen.st_size <= MAX_JOURNAL_BYTES)
            sequence, tip = self._journal_state(descriptor)
            row = {"version": "cogs.stage2-production-campaign-journal/v1",
                   "sequence": sequence, "previous_sha256": tip,
                   "category": category, "event": event, "ordinal": ordinal,
                   "mode": mode, "commitment": commitment}
            line = _canonical(row)
            _require(seen.st_size + len(line) <= MAX_JOURNAL_BYTES
                     and os.write(descriptor, line) == len(line))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _active(self, grant, state):
        value = {"version": "cogs.stage2-cleanup-active/v1",
                 "batch_commitment": grant.batch_commitment,
                 "ordinal": grant.ordinal, "mode": grant.mode,
                 "grant_commitment": grant.grant_commitment,
                 "state_commitment": state}
        _replace_durable(ACTIVE, _canonical(value))

    def journal(self, category, event, ordinal, mode, commitment):
        self._append(category, event, ordinal, mode, commitment)
        if category == "cycle" and event == "opened":
            grant = production._grant(self.approval, ordinal)
            self._active(grant, grant.grant_commitment)
        elif ((category == "cycle" and event == "sealed")
              or (category == "cleanup" and event == "settled")):
            _require(ACTIVE.exists())
            ACTIVE.unlink()
            if category == "cleanup":
                _write_once(CLEANUP_COMPLETE, _canonical({
                    "version": "cogs.stage2-cleanup-complete/v1",
                    "reconciliation_commitment": commitment,
                    "certain_zero": True,
                }))
            directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def consume(self, approval, approval_commitment, observed):
        _require(approval is self.approval and type(observed) is int
                 and approval.not_before_unix_ns <= observed < approval.expires_unix_ns)
        value = {"version": "cogs.stage2-production-approval-consumption/v1",
                 "approval_commitment": approval_commitment,
                 "batch_commitment": approval.batch_commitment,
                 "consumed_unix_ns": observed, "first_created": True}
        raw = _canonical(value)
        _write_once(CONSUMED, raw)
        return production.ApprovalConsumptionReceipt(
            approval_commitment, hashlib.sha256(raw).hexdigest(), observed, True)

    def _run(self, command, arguments, timeout):
        _require(command in {EFFECT_COMMAND, REMOTE_COMMAND, INVENTORY_COMMAND,
                             RECOVERY_COMMAND}
                 and command.is_file() and os.access(command, os.X_OK)
                 and type(arguments) is tuple
                 and all(type(item) is str and "\0" not in item for item in arguments))
        result = self.executor(
            ["/usr/bin/timeout", "--foreground", "--signal=TERM", "--kill-after=10s",
             f"{timeout}s", str(command), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=FIXED_ENV, cwd=SOURCE, timeout=timeout + 15, check=False)
        _require(result.returncode == 0 and not result.stderr
                 and 0 < len(result.stdout) <= MAX_JSON_BYTES)
        return result.stdout

    def _ensure_grant(self, grant):
        directory = STATE_ROOT / f"cycle-{grant.ordinal}"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / "grant.json"
        raw = remote_adapter.invocation(grant).grant_bytes
        if path.exists():
            _require(_read_fixed(path, 64 * 1024, (0o400,)) == raw)
        else:
            _write_once(path, raw, 0o400)
        return directory

    def effect(self, kind, grant, previous):
        _require(kind in production.EFFECT_KINDS
                 and type(grant) is production.CycleLaunchGrant
                 and (previous is None or type(previous) is production.EffectReceipt))
        self._ensure_grant(grant)
        previous_commitment = None if previous is None else previous.settlement_commitment
        intent = production._commit(b"cogs.stage2-provider-effect-intent/v1", {
            "kind": kind, "grant": grant.grant_commitment,
            "previous": previous_commitment})
        self._append("effect", "intent", grant.ordinal, grant.mode, intent)
        raw = self._run(EFFECT_COMMAND, (kind, str(grant.ordinal), grant.mode,
                        grant.grant_commitment, intent), 900)
        receipt = production.EffectReceipt(**_decode(raw))
        _require(receipt.intent_commitment == intent)
        if kind in {"plan", "apply", "running"}:
            self._active(grant, receipt.state_commitment)
        self._append("effect", "settled", grant.ordinal, grant.mode,
                     receipt.settlement_commitment)
        return receipt

    def remote(self, grant, apply, running):
        self._ensure_grant(grant)
        raw = self._run(REMOTE_COMMAND, (str(grant.ordinal), grant.mode,
                        grant.grant_commitment), 7800)
        return remote_adapter.remote_receipt(grant, apply, running, raw)

    def inventory(self, grant, destroyed, sequence):
        _require(type(destroyed) is production.EffectReceipt and 1 <= sequence <= 8)
        grant_commitment = "final" if grant is None else grant.grant_commitment
        raw = self._run(INVENTORY_COMMAND, (str(sequence), grant_commitment,
                        destroyed.state_commitment), 600)
        return _decode_inventory(_decode(raw))

    def cost(self, grant, apply, destroy):
        duration = destroy.observed_ended_unix_ns - apply.observed_started_unix_ns
        _require(duration > 0)
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
        _require(type(grant) is production.CycleLaunchGrant)
        self._active(grant, state)
        raw = self._run(RECOVERY_COMMAND, (str(grant.ordinal), grant.mode,
                        grant.grant_commitment, state), 1200)
        value = _decode(raw)
        inventory = value.pop("inventory", None)
        parsed = None if inventory is None else _decode_inventory(inventory)
        return production.CleanupReceipt(**value, inventory=parsed)

    def ports(self, seal):
        authority = _issue_port_authority(self, seal)
        return production._issue_adapter_ports(
            authority, self.approval, self.now, self.consume, self.effect,
            self.remote, self.inventory, self.cost, self.recover, self.journal)


def _root_lock():
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600)
    seen = os.fstat(descriptor)
    _require(stat.S_ISREG(seen.st_mode) and seen.st_uid == seen.st_gid == 0
             and stat.S_IMODE(seen.st_mode) == 0o600 and seen.st_nlink == 1)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise AwsAdapterError() from error
    return descriptor


def _admit_root():
    seen = ROOT.stat()
    _require(os.geteuid() == 0 and os.getegid() == 0 and ROOT.is_dir()
             and stat.S_IMODE(seen.st_mode) == 0o700
             and seen.st_uid == seen.st_gid == 0
             and not (set(os.environ) & {
                 "PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "AWS_PROFILE",
                 "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "TF_VAR_credentials", "GOOGLE_APPLICATION_CREDENTIALS"}))


def run_fixed_campaign():
    """Sole future normal AWS entry. Merely importing this module has no effect."""
    _admit_root()
    lock = _root_lock()
    try:
        _require(not CONSUMED.exists() and not JOURNAL.exists() and not ACTIVE.exists()
                 and not CLEANUP_COMPLETE.exists())
        approval = _approval()
        custodian = AwsCampaignCustodian(_ADAPTER_SEAL, approval)
        return production.ProductionCampaignController(
            custodian.ports(_ADAPTER_SEAL)).run()
    finally:
        os.close(lock)


def recover_fixed_campaign():
    """Cleanup-only crash entry; it cannot resume cycles or mint a candidate."""
    _admit_root()
    lock = _root_lock()
    try:
        _require(CONSUMED.exists() and JOURNAL.exists() and ACTIVE.exists())
        approval = _approval()
        active = _decode(_read_fixed(ACTIVE, 64 * 1024, (0o600,)))
        _require(active.get("version") == "cogs.stage2-cleanup-active/v1"
                 and active.get("batch_commitment") == approval.batch_commitment)
        grant = production._grant(approval, active["ordinal"])
        _require(active.get("mode") == grant.mode
                 and active.get("grant_commitment") == grant.grant_commitment)
        custodian = AwsCampaignCustodian(_ADAPTER_SEAL, approval)
        receipt = custodian.recover(grant, active["state_commitment"], None,
                                    production.ProductionUncertainty())
        custodian.journal("cleanup", "settled" if receipt.certain_zero else "uncertain",
                          grant.ordinal, grant.mode, receipt.reconciliation_commitment)
        if not receipt.certain_zero:
            raise production.ProductionUncertainty()
        return receipt
    finally:
        os.close(lock)
