"""One-shot fixed-file authority for non-cloud formal qualification cycles.

This authority is deliberately disjoint from completion_cycle_authority and from
all production/AWS grants.  A grant authorizes exactly one hosted-KVM
qualification cycle in one workflow batch; it can never authorize a provider
operation or production publication.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True

AUTHORITY = "non-cloud-formal-qualification-cycle-only"
VERSION = "cogs.stage2-formal-local-cycle-grant/v1"
CYCLE_MODES = ("full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness")
ROOT = Path("/var/lib/cogs/stage2-completion-v1/formal-cycle-authority-v1")
GRANT = ROOT / "grant.json"
MAX_BYTES = 4096
_claimed = False
_HEX = frozenset("0123456789abcdef")


class FormalCycleAuthorityError(ValueError): pass


def _require(condition):
    if not condition: raise FormalCycleAuthorityError()


def _digest(value):
    _require(type(value) is str and len(value) == 64 and set(value) <= _HEX)
    return value


def _sha1(value):
    _require(type(value) is str and len(value) == 40 and set(value) <= _HEX)
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _commit(domain, value):
    return hashlib.sha256(domain + b"\0" + _canonical(value)).hexdigest()


def batch_commitment(value):
    fields = dict(value)
    fields.pop("batch_commitment", None)
    fields.pop("grant_commitment", None)
    fields.pop("ordinal", None)
    fields.pop("mode", None)
    return _commit(b"cogs.stage2-formal-local-qualification-batch/v1", fields)


@dataclass(frozen=True)
class FormalCycleGrant:
    authority: str
    batch_commitment: str
    ordinal: int
    mode: str
    implementation_revision: str
    control_revision: str
    source_manifest_sha256: str
    static_control_sha256: str
    workflow_sha256: str
    result_schema_sha256: str
    rootfs_descriptor_sha256: str
    workflow_run_id: int
    workflow_run_attempt: int
    grant_commitment: str

    def __post_init__(self):
        _require(self.authority == AUTHORITY)
        _digest(self.batch_commitment); _sha1(self.implementation_revision)
        _sha1(self.control_revision)
        for value in (self.source_manifest_sha256, self.static_control_sha256,
                      self.workflow_sha256, self.result_schema_sha256,
                      self.rootfs_descriptor_sha256, self.grant_commitment):
            _digest(value)
        _require(type(self.ordinal) is int and 1 <= self.ordinal <= 7
                 and self.mode == CYCLE_MODES[self.ordinal - 1]
                 and type(self.workflow_run_id) is int and self.workflow_run_id > 0
                 and self.workflow_run_attempt == 1)
        fields = asdict(self); fields.pop("grant_commitment")
        _require(self.batch_commitment == batch_commitment(fields)
                 and self.grant_commitment == _commit(
                     b"cogs.stage2-formal-local-cycle-grant/v1", fields))


def issue(fields):
    values = dict(fields)
    values["authority"] = AUTHORITY
    values["batch_commitment"] = batch_commitment(values)
    values["grant_commitment"] = _commit(
        b"cogs.stage2-formal-local-cycle-grant/v1", values)
    return FormalCycleGrant(**values)


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value); value[key] = item
    return value


def encode(grant):
    _require(type(grant) is FormalCycleGrant)
    return _canonical({"version": VERSION, **asdict(grant)}) + b"\n"


def decode(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES
             and raw.endswith(b"\n") and b"\r" not in raw)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise FormalCycleAuthorityError() from error
    names = {"version", *(field.name for field in FormalCycleGrant.__dataclass_fields__.values())}
    _require(type(value) is dict and set(value) == names and value.pop("version") == VERSION
             and _canonical({"version": VERSION, **value}) + b"\n" == raw)
    return FormalCycleGrant(**value)


def _read_fixed(path, mode, owner):
    _require(isinstance(path, Path) and mode in {"full", "readiness"}
             and type(owner) is tuple and len(owner) == 2)
    parent = path.parent; seen = parent.lstat()
    _require(stat.S_ISDIR(seen.st_mode) and stat.S_IMODE(seen.st_mode) == 0o700
             and (seen.st_uid, seen.st_gid) == owner)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400
                 and (before.st_uid, before.st_gid) == owner and before.st_nlink == 1
                 and 0 < before.st_size <= MAX_BYTES)
        raw = b""
        while len(raw) < before.st_size:
            part = os.read(descriptor, min(MAX_BYTES + 1 - len(raw), before.st_size - len(raw)))
            _require(part); raw += part
        _require(not os.read(descriptor, 1))
        stable = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                               item.st_gid, item.st_nlink, item.st_size,
                               item.st_mtime_ns, item.st_ctime_ns)
        _require(stable(before) == stable(os.fstat(descriptor)))
        grant = decode(raw); _require(grant.mode == mode)
        path.unlink(); directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(directory)
        finally: os.close(directory)
        _require(os.fstat(descriptor).st_nlink == 0)
        parent.rmdir()
        return grant
    finally: os.close(descriptor)


def _claim(mode):
    global _claimed
    _require(os.geteuid() == 0 and sys.argv == [sys.argv[0]] and not _claimed)
    _claimed = True
    return _read_fixed(GRANT, mode, (0, 0))


def claim_full(): return _claim("full")
def claim_readiness(): return _claim("readiness")
