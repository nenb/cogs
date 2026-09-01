"""Dormant concrete AWS adapter for the reviewed seven-cycle controller.

Importing this module is effect-free. ``run_fixed_campaign`` is the sole normal
entry; ``recover_fixed_campaign`` is cleanup-only and cannot return a candidate.
Both require the same root-owned custody directory and fixed repository scripts.
"""

from dataclasses import asdict, dataclass
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
AUTHENTICATION_BUNDLE = ROOT / "approval-authentication.bundle.json"
COSIGN = ROOT / "cosign"
TRUSTED_ROOT = ROOT / "sigstore-trusted-root.json"
COSIGN_SHA256 = "5db1043ec70bf92296da977941b19b3d86869af3018d4f4a0f457bf54d76bb68"
TRUSTED_ROOT_SHA256 = "844a1c6de3986c9f02070266b25e0d1a2fa99ceccc89f6b9ad90aae47b62a16e"
AWS_CONFIG = ROOT / "aws-config"
AWS_CREDENTIALS = ROOT / "aws-credentials"
TOFU = ROOT / "tofu"
TOFU_SHA256 = "e11e783ab8ee0a029da32c2ab1817952121208d0ae9d6cf2d91fa0687f573a88"
TOFU_PROVIDER = ROOT / "terraform-provider-aws_v6.54.0_x5"
TOFU_CONFIG = ROOT / "tofu-cli.tfrc"
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
    "AWS_CONFIG_FILE": str(AWS_CONFIG),
    "AWS_SHARED_CREDENTIALS_FILE": str(AWS_CREDENTIALS),
    "AWS_PROFILE": "nebula",
    "AWS_REGION": "us-east-1",
    "AWS_DEFAULT_REGION": "us-east-1", "AWS_PAGER": "",
    "AWS_EC2_METADATA_DISABLED": "true",
    "TF_CLI_CONFIG_FILE": str(TOFU_CONFIG), "TF_IN_AUTOMATION": "1",
}


class AwsAdapterError(production.ProductionCampaignError):
    pass


@dataclass(frozen=True)
class NoActiveCleanupReceipt:
    version: str
    reconciliation_commitment: str
    certain_zero: bool

    def __post_init__(self):
        _require(self.version == "cogs.stage2-cleanup-complete/v1"
                 and self.certain_zero is True)
        production._digest(self.reconciliation_commitment)


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
    _read_fixed(AWS_CONFIG, 4096); _read_fixed(AWS_CREDENTIALS, 16 * 1024)
    authentication_raw = _read_fixed(AUTHENTICATION, 64 * 1024)
    bundle_raw = _read_fixed(AUTHENTICATION_BUNDLE, 1024 * 1024)
    cosign_raw = _read_fixed(COSIGN, 160 * 1024 * 1024, (0o555,))
    tofu_raw = _read_fixed(TOFU, 140 * 1024 * 1024, (0o555,))
    provider_raw = _read_fixed(TOFU_PROVIDER, 1024 * 1024 * 1024, (0o555,))
    _read_fixed(TOFU_CONFIG, 4096)
    trusted_root_raw = _read_fixed(TRUSTED_ROOT, 64 * 1024)
    _require(hashlib.sha256(cosign_raw).hexdigest() == COSIGN_SHA256
             and hashlib.sha256(tofu_raw).hexdigest() == TOFU_SHA256
             and hashlib.sha256(trusted_root_raw).hexdigest() == TRUSTED_ROOT_SHA256)
    verification = subprocess.run(
        ("/usr/bin/unshare", "--net", "--", str(COSIGN), "verify-blob",
         "--trusted-root", str(TRUSTED_ROOT), "--bundle", str(AUTHENTICATION_BUNDLE),
         "--certificate-identity",
         "https://github.com/nenb/cogs/.github/workflows/stage2-production-approval.yml@refs/heads/main",
         "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
         str(AUTHENTICATION)), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={"HOME": "/nonexistent", "LANG": "C",
        "LC_ALL": "C", "PATH": "/usr/bin:/bin"}, close_fds=True,
        start_new_session=True, timeout=30, check=False)
    _require(verification.returncode == 0)
    value = _decode(raw, 64 * 1024)
    authentication = _decode(authentication_raw, 64 * 1024)
    _require(set(authentication) == {
        "version", "result", "approval_sha256", "issuer_commitment",
        "workflow_sha256", "workflow_run_id", "workflow_run_attempt",
        "control_revision", "approver_principal_commitment",
        "executor_principal_commitment", "inventory_observer_principal_commitment",
        "first_created"}
        and authentication["version"] ==
            "cogs.stage2-production-approval-authentication/v1"
        and authentication["result"] == "pass"
        and authentication["approval_sha256"] == hashlib.sha256(raw).hexdigest()
        and authentication["workflow_run_attempt"] == 1
        and authentication["first_created"] is True)
    for key in ("issuer_commitment", "workflow_sha256",
                "approver_principal_commitment", "executor_principal_commitment",
                "inventory_observer_principal_commitment"):
        production._digest(authentication[key])
    _require(len({authentication["approver_principal_commitment"],
                  authentication["executor_principal_commitment"],
                  authentication["inventory_observer_principal_commitment"]}) == 3
             and type(authentication["workflow_run_id"]) is int
             and authentication["workflow_run_id"] > 0)
    production._sha1(authentication["control_revision"])
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    approval = production.ProductionApproval(**value)
    _require(hashlib.sha256(provider_raw).hexdigest() == approval.provider_binary_sha256)
    _require(approval.issuer_commitment == authentication["issuer_commitment"]
             and approval.control_revision == authentication["control_revision"]
             and approval.executor_principal_commitment ==
                 authentication["executor_principal_commitment"]
             and approval.inventory_observer_principal_commitment ==
                 authentication["inventory_observer_principal_commitment"])
    custody = production._commit(b"cogs.stage2-approval-authentication-custody/v1", {
        "authentication_sha256": hashlib.sha256(authentication_raw).hexdigest(),
        "bundle_sha256": hashlib.sha256(bundle_raw).hexdigest(),
        "cosign_sha256": COSIGN_SHA256, "trusted_root_sha256": TRUSTED_ROOT_SHA256})
    return approval, custody


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
    def __init__(self, seal, approval, authentication_receipt_sha256,
                 executor=subprocess.run):
        _require(seal is _ADAPTER_SEAL and type(approval) is production.ProductionApproval
                 and production._digest(authentication_receipt_sha256) ==
                     authentication_receipt_sha256
                 and callable(executor))
        self.approval = approval
        self.authentication_receipt_sha256 = authentication_receipt_sha256
        self.executor = executor
        self.apply_started = {}
        self.first_apply_started = None

    def now(self):
        return time.time_ns()

    def _journal_state(self, descriptor, repair_tail=False):
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = b""
        while block := os.read(descriptor, 1024 * 1024):
            raw += block
            _require(len(raw) <= MAX_JOURNAL_BYTES)
        if raw and not raw.endswith(b"\n"):
            _require(repair_tail)
            boundary = raw.rfind(b"\n") + 1; tail = raw[boundary:]
            _require(0 < len(tail) <= 64 * 1024)
            # An unterminated append never became an authoritative record. Cleanup-only
            # recovery may truncate exactly that final tail; complete lines remain chained.
            os.ftruncate(descriptor, boundary); os.fsync(descriptor); raw = raw[:boundary]
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
            sequence, tip = self._journal_state(descriptor, category == "cleanup")
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
                 "state_commitment": state,
                 "cleanup_deadline_unix_ns": (
                    self.approval.expires_unix_ns if self.first_apply_started is None else
                    self.first_apply_started + self.approval.effect_deadline_ns +
                    self.approval.cleanup_reserve_ns)}
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
            approval_commitment, self.authentication_receipt_sha256,
            hashlib.sha256(raw).hexdigest(), observed, True)

    def _run(self, command, arguments, timeout):
        _require(command in {EFFECT_COMMAND, REMOTE_COMMAND, INVENTORY_COMMAND,
                             RECOVERY_COMMAND}
                 and command.is_file() and os.access(command, os.X_OK)
                 and type(arguments) is tuple
                 and all(type(item) is str and "\0" not in item for item in arguments))
        result = self.executor(
            ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
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
        now = time.time_ns()
        latest = self.approval.expires_unix_ns - self.approval.cleanup_reserve_ns
        if self.first_apply_started is not None:
            latest = min(latest, self.first_apply_started + self.approval.effect_deadline_ns)
        if kind == "plan":
            timeout = min(900, max(1, (latest - now) // 1_000_000_000))
        elif kind == "apply":
            if self.first_apply_started is None:
                _require(now + self.approval.effect_deadline_ns +
                         self.approval.cleanup_reserve_ns < self.approval.expires_unix_ns)
            timeout = min(900, max(1, self.approval.maximum_cycle_duration_ns // 1_000_000_000),
                          max(1, (latest - now) // 1_000_000_000))
        else:
            _require(grant.ordinal in self.apply_started)
            cycle_latest = self.apply_started[grant.ordinal] + self.approval.maximum_cycle_duration_ns
            _require(now < min(latest, cycle_latest))
            timeout = min(900, max(1, (min(latest, cycle_latest) - now) // 1_000_000_000))
        _require(now < latest and timeout > 0)
        if kind == "apply" and self.first_apply_started is None:
            self.first_apply_started = now
            self.apply_started[grant.ordinal] = now
            _require(previous is not None)
            self._active(grant, previous.state_commitment)
        raw = self._run(EFFECT_COMMAND, (kind, str(grant.ordinal), grant.mode,
                        grant.grant_commitment, intent), timeout)
        value = _decode(raw)
        value["resource_commitments"] = tuple(
            tuple(row) for row in value["resource_commitments"])
        receipt = production.EffectReceipt(**value)
        _require(receipt.intent_commitment == intent)
        if kind == "apply":
            self.apply_started[grant.ordinal] = receipt.observed_started_unix_ns
        if kind in {"plan", "apply", "running"}:
            self._active(grant, receipt.state_commitment)
        if kind == "destroy":
            self.apply_started.pop(grant.ordinal, None)
        self._append("effect", "settled", grant.ordinal, grant.mode,
                     receipt.settlement_commitment)
        return receipt

    def remote(self, grant, apply, running, effect_deadline):
        self._ensure_grant(grant)
        _require(type(effect_deadline) is int)
        remaining_ns = effect_deadline - time.time_ns()
        _require(remaining_ns > 0)
        timeout = max(1, min(7800, remaining_ns // 1_000_000_000))
        raw = self._run(REMOTE_COMMAND, (str(grant.ordinal), grant.mode,
                        grant.grant_commitment, str(timeout)), timeout)
        return remote_adapter.remote_receipt(grant, apply, running, raw)

    def inventory(self, grant, destroyed, sequence):
        _require(type(destroyed) is production.EffectReceipt and 1 <= sequence <= 8)
        grant_commitment = "final" if grant is None else grant.grant_commitment
        deadline = (self.approval.expires_unix_ns if self.first_apply_started is None else
                    self.first_apply_started + self.approval.effect_deadline_ns +
                    self.approval.cleanup_reserve_ns)
        remaining = deadline - time.time_ns(); _require(remaining > 0)
        timeout = min(600, max(1, remaining // 1_000_000_000))
        raw = self._run(INVENTORY_COMMAND, (str(sequence), grant_commitment,
                        destroyed.state_commitment), timeout)
        return _decode_inventory(_decode(raw))

    def cost(self, grant, apply, destroy):
        duration = destroy.observed_ended_unix_ns - apply.observed_started_unix_ns
        _require(duration > 0)
        rate = production.FIXED_RATE_MICRO_USD_PER_HOUR
        cost = (duration * rate + 3_600_000_000_000 - 1) // 3_600_000_000_000
        fields = {"grant_commitment": grant.grant_commitment,
                  "cycle_ordinal": grant.ordinal,
                  "rate_source_commitment": self.approval.rate_source_commitment,
                  "usage_commitment": production._commit(
                      b"cogs.stage2-provider-usage/v1", {"duration_ns": duration}),
                  "cost_micro_usd": cost}
        return production.CostReceipt(**fields, receipt_commitment=production._commit(
            b"cogs.stage2-cost-receipt/v1", fields))

    def recover(self, grant, state, last_certain, primary):
        _require(type(grant) is production.CycleLaunchGrant)
        default_deadline = (self.approval.expires_unix_ns
                            if self.first_apply_started is None else
                            self.first_apply_started + self.approval.effect_deadline_ns +
                            self.approval.cleanup_reserve_ns)
        deadline = getattr(self, "recovery_deadline", default_deadline)
        remaining = deadline - time.time_ns()
        _require(remaining > 0)
        timeout = min(1200, self.approval.cleanup_reserve_ns // 1_000_000_000,
                      max(1, remaining // 1_000_000_000))
        raw = self._run(RECOVERY_COMMAND, (str(grant.ordinal), grant.mode,
                        grant.grant_commitment, state), timeout)
        value = _decode(raw)
        inventory = value.pop("inventory", None)
        parsed = None if inventory is None else _decode_inventory(inventory)
        return production.CleanupReceipt(**value, inventory=parsed)

    def ports(self, seal):
        authority = _issue_port_authority(self, seal)
        return production._issue_adapter_ports(
            authority, self.approval, self.now, self.consume, self.effect,
            self.remote, self.inventory, self.cost, self.recover, self.journal)


def _retire_credentials():
    descriptor = os.open(AWS_CREDENTIALS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                 and stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1)
        AWS_CREDENTIALS.unlink(); os.fsync(descriptor)
        after = os.fstat(descriptor)
        _require((after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                  after.st_gid, after.st_size) ==
                 (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                  before.st_gid, before.st_size) and after.st_nlink == 0)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        os.close(descriptor)


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
                 "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
                 "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "TF_VAR_credentials", "GOOGLE_APPLICATION_CREDENTIALS"}))


def run_fixed_campaign():
    """Sole future normal AWS entry. Merely importing this module has no effect."""
    _admit_root()
    lock = _root_lock()
    try:
        _require(not CONSUMED.exists() and not JOURNAL.exists() and not ACTIVE.exists()
                 and not CLEANUP_COMPLETE.exists())
        approval, authentication_sha256 = _approval()
        custodian = AwsCampaignCustodian(
            _ADAPTER_SEAL, approval, authentication_sha256)
        try:
            candidate = production.ProductionCampaignController(
                custodian.ports(_ADAPTER_SEAL)).run()
        except BaseException:
            if CLEANUP_COMPLETE.exists() and not ACTIVE.exists() and AWS_CREDENTIALS.exists():
                _retire_credentials()
            raise
        _write_once(CLEANUP_COMPLETE, _canonical({
            "version": "cogs.stage2-cleanup-complete/v1",
            "reconciliation_commitment": candidate.inventories[-1].zero_commitment,
            "certain_zero": True}))
        _retire_credentials()
        import completion_campaign_evidence_issuer as evidence_issuer
        evidence_root = ROOT / "evidence-publication"
        evidence_root.mkdir(mode=0o700, exist_ok=False)
        os.chown(evidence_root, 0, 0); os.chmod(evidence_root, 0o700)
        parent_fd = os.open(evidence_root, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            custody = evidence_issuer.open_publication_custody(parent_fd, 0)
            return evidence_issuer.issue_completion_evidence(candidate, custody)
        finally:
            os.close(parent_fd)
    except BaseException:
        if not CONSUMED.exists() and AWS_CREDENTIALS.exists():
            _retire_credentials()
        raise
    finally:
        os.close(lock)


def recover_fixed_campaign():
    """Cleanup-only crash entry; it cannot resume cycles or mint a candidate."""
    _admit_root()
    lock = _root_lock()
    try:
        approval, authentication_sha256 = _approval()
        if not CONSUMED.exists():
            _require(not JOURNAL.exists() and not ACTIVE.exists()
                     and not any(STATE_ROOT.glob("cycle-*/[a-z]*.intent.json")))
            complete_raw = _canonical({
                "version": "cogs.stage2-cleanup-complete/v1",
                "reconciliation_commitment": production._commit(
                    b"cogs.stage2-unconsumed-approval-retirement/v1",
                    {"batch": approval.batch_commitment}), "certain_zero": True})
            if CLEANUP_COMPLETE.exists():
                _require(_read_fixed(CLEANUP_COMPLETE, 64 * 1024, (0o600,)) == complete_raw)
            else:
                _write_once(CLEANUP_COMPLETE, complete_raw)
            _retire_credentials(); return NoActiveCleanupReceipt(**_decode(complete_raw))
        custodian = AwsCampaignCustodian(
            _ADAPTER_SEAL, approval, authentication_sha256)
        if not ACTIVE.exists():
            if JOURNAL.exists():
                descriptor = os.open(JOURNAL, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    custodian._journal_state(descriptor, True)
                    os.lseek(descriptor, 0, os.SEEK_SET); rows = os.read(
                        descriptor, MAX_JOURNAL_BYTES).splitlines(keepends=True)
                    if rows:
                        last = _decode(rows[-1], 64 * 1024)
                        _require((last["category"], last["event"]) in {
                            ("batch", "consumed"), ("batch", "candidate"),
                            ("campaign", "opened"),
                            ("cycle", "opened"), ("cycle", "sealed"),
                            ("cleanup", "settled")})
                finally:
                    os.close(descriptor)
            complete_raw = _canonical({
                "version": "cogs.stage2-cleanup-complete/v1",
                "reconciliation_commitment": production._commit(
                    b"cogs.stage2-no-active-cleanup/v1", {"batch": approval.batch_commitment}),
                "certain_zero": True})
            if CLEANUP_COMPLETE.exists():
                existing = _decode(_read_fixed(CLEANUP_COMPLETE, 64 * 1024, (0o600,)))
                _require(existing.get("version") == "cogs.stage2-cleanup-complete/v1"
                         and existing.get("certain_zero") is True)
                production._digest(existing.get("reconciliation_commitment"))
            else:
                _write_once(CLEANUP_COMPLETE, complete_raw)
            _retire_credentials()
            return NoActiveCleanupReceipt(**_decode(
                _read_fixed(CLEANUP_COMPLETE, 64 * 1024, (0o600,))))
        active = _decode(_read_fixed(ACTIVE, 64 * 1024, (0o600,)))
        _require(active.get("version") == "cogs.stage2-cleanup-active/v1"
                 and active.get("batch_commitment") == approval.batch_commitment
                 and type(active.get("cleanup_deadline_unix_ns")) is int
                 and time.time_ns() < active["cleanup_deadline_unix_ns"])
        grant = production._grant(approval, active["ordinal"])
        _require(active.get("mode") == grant.mode
                 and active.get("grant_commitment") == grant.grant_commitment)
        custodian.recovery_deadline = active["cleanup_deadline_unix_ns"]
        receipt = custodian.recover(grant, active["state_commitment"], None,
                                    production.ProductionUncertainty())
        custodian.journal("cleanup", "settled" if receipt.certain_zero else "uncertain",
                          grant.ordinal, grant.mode, receipt.reconciliation_commitment)
        if not receipt.certain_zero:
            raise production.ProductionUncertainty()
        _retire_credentials()
        return receipt
    finally:
        os.close(lock)
