#!/usr/bin/env python3
"""Source and report sealing cuts through the production sealing state machines."""

import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

if not __debug__:
    raise SystemExit("optimized mode is forbidden")
if sys.argv[1:]:
    raise SystemExit("this suite accepts no arguments")
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
FIXTURES = ROOT / "test/fixtures/outcome-two"
sys.path.insert(0, str(REMOTE))
elf = importlib.import_module("completion_elf")
closure = importlib.import_module("completion_trusted_runtime_closure")
def load_ledger(path):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    if not values or values[0].get("type") != "header": raise AssertionError("sealing ledger header")
    return values[0], values[1:]
HEADER, CASES = load_ledger(FIXTURES / "sealing/faults.jsonl")
RAW = (FIXTURES / "elf" / HEADER["success"]["source"]).read_bytes()
REPORT = (FIXTURES / "reports/runtime-closure-v1.canonical.jsonl").read_bytes()
SOURCE_FD = 41
GENERATION = closure.SourceGeneration(
    8, 101, len(RAW), 1, 1, stat.S_IFREG | 0o755, 0, 0,
)
SOURCE = closure.AuthenticatedObject(
    "executable", "/usr/bin/gzip", SOURCE_FD, GENERATION, (), len(RAW),
    hashlib.sha256(RAW).hexdigest(), elf.parse_elf64(RAW),
)
SEAL_BITS = {name: getattr(closure, "_" + name) for name in HEADER["required_exec_seals"]}
ROW_KEYS = {"id", "production_method", "primitive_fault", "intended_code",
            "cleanup_domains", "sentinel"}
if sum(SEAL_BITS.values()) != closure._EXEC_SEALS:
    raise AssertionError("fixture seal profile diverged from production")


def manifest_cases():
    for row in CASES:
        branch = getattr(closure, row["sentinel"], None)
        if set(row) != ROW_KEYS or row["production_method"] != row["sentinel"] or not callable(branch):
            raise AssertionError("sealing manifest row/method")
        yield row, row["primitive_fault"]["target"], row["primitive_fault"]["name"], branch


class KernelObject:
    def __init__(self, data=b"", mode=0o600, identity=77):
        self.data = bytearray(data)
        self.mode = mode
        self.identity = identity
        self.seals = 0


class SealOps(closure._Ops):
    """Independent descriptor/object table exposes close-after-effect reuse."""
    def __init__(self, fault):
        self.fault = fault
        self.events = []
        self.objects = {SOURCE_FD: KernelObject(RAW, 0o755, 101)}
        self.access = {SOURCE_FD: os.O_RDONLY}
        self.close_attempts = []
        self.source_stats = 0
        self.write_calls = 0
        self.replacement = None
        self.consumed = set()

    def record(self, event):
        self.events.append(event)
        if self.fault != "none" and event.startswith(expected_stage("source" if self.fault.startswith("source") else "report", self.fault)):
            self.consumed.add(self.fault)

    def memfd_create(self, name, flags):
        source = name == "cogs-runtime-object"
        self.record("source:memfd" if source else "report:memfd")
        expected = closure._MFD_CLOEXEC | closure._MFD_ALLOW_SEALING
        if source:
            expected |= closure._MFD_EXEC
        if flags != expected:
            raise AssertionError("production weakened memfd flags")
        if self.fault == ("source-memfd" if source else "report-memfd"):
            raise OSError("memfd")
        self.objects[77] = KernelObject()
        self.access[77] = os.O_RDWR
        return 77

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del mode, dir_fd
        self.record("reopen")
        if path != "/proc/self/fd/77":
            raise AssertionError("sealing reopened a source pathname")
        if self.fault in {"source-reopen", "report-reopen"}:
            raise OSError("reopen")
        if flags != os.O_RDONLY | closure._O_CLOEXEC:
            raise AssertionError("sealed reopen was not fixed read-only")
        self.objects[78] = self.objects[77]
        access_fault = self.fault in {"source-reopen-access", "report-reopen-access"}
        self.access[78] = os.O_RDWR if access_fault else os.O_RDONLY
        return 78

    def fstat(self, fd):
        self.record("fstat")
        item = self.objects[fd]
        if fd == SOURCE_FD:
            self.source_stats += 1
            before = self.fault == "source-generation-before" and self.source_stats == 1
            after = self.fault == "source-generation-after" and self.source_stats > 1
            mtime = 2 if before or after else 1
            return SimpleNamespace(
                st_dev=8, st_ino=101, st_size=len(item.data), st_mtime_ns=mtime,
                st_ctime_ns=1, st_mode=stat.S_IFREG | item.mode, st_uid=0, st_gid=0,
            )
        identity_fault = self.fault in {
            "source-reopen-identity", "report-reopen-identity", "report-read-close",
        }
        identity = item.identity + (1 if identity_fault and fd == 78 else 0)
        return SimpleNamespace(
            st_dev=0, st_ino=identity, st_size=len(item.data), st_mtime_ns=1,
            st_ctime_ns=1, st_mode=stat.S_IFREG | item.mode, st_uid=0, st_gid=0,
        )

    def pread(self, fd, size, offset):
        self.record("source:pread" if fd == SOURCE_FD else "sealed:pread")
        if fd == SOURCE_FD:
            error_fault = "source-read-error"
            short_fault = "source-short-read"
        elif self.fault.startswith("source"):
            error_fault = "source-readback-error"
            short_fault = "source-readback-short"
        else:
            error_fault = "report-readback-error"
            short_fault = "report-readback-short"
        if self.fault == error_fault:
            raise OSError("pread")
        if self.fault == short_fault and offset == 0:
            return b""
        item = self.objects[fd]
        if self.fault == "source-grew" and fd == SOURCE_FD and offset == len(item.data):
            return b"x"
        value = bytes(item.data[offset:offset + size])
        mismatch = self.fault in {"source-readback-digest", "report-readback-mismatch"} and fd != SOURCE_FD
        if mismatch and value:
            value = bytes([value[0] ^ 1]) + value[1:]
        return value

    def pwrite(self, fd, data, offset):
        source = self.fault.startswith("source")
        self.record("source:pwrite" if source else "report:pwrite")
        prefix = "source" if source else "report"
        self.write_calls += 1
        if self.fault == f"{prefix}-write-error":
            raise OSError("write")
        if self.fault == f"{prefix}-write-zero":
            return 0
        if self.fault == "source-partial-then-error" and self.write_calls > 1:
            raise OSError("write after partial")
        partial = self.fault in {"source-write-partial", "source-partial-then-error", "report-write-partial"}
        count = 1 if partial else len(data)
        item = self.objects[fd]
        end = offset + count
        if len(item.data) < end:
            item.data.extend(b"\0" * (end - len(item.data)))
        item.data[offset:end] = data[:count]
        return count

    def fchmod(self, fd, mode):
        prefix = "source" if self.fault.startswith("source") else "report"
        self.record(f"{prefix}:chmod")
        if self.fault == f"{prefix}-chmod":
            raise OSError("chmod")
        self.objects[fd].mode = mode

    def fsync(self, fd):
        prefix = "source" if self.fault.startswith("source") else "report"
        self.record(f"{prefix}:fsync")
        if self.fault == f"{prefix}-fsync":
            raise OSError("fsync")

    def fcntl(self, fd, command, argument=0):
        prefix = "source" if self.fault.startswith("source") else "report"
        self.record(f"{prefix}:fcntl:{command}")
        if command == closure._F_ADD_SEALS:
            if self.fault == f"{prefix}-add-seals":
                raise OSError("add seals")
            self.objects[fd].seals = argument
            return 0
        if command == closure._F_GET_SEALS:
            if self.fault == f"{prefix}-get-seals":
                raise OSError("get seals")
            seals = self.objects[fd].seals
            if self.fault.startswith("source-missing-"):
                seals &= ~SEAL_BITS[self.fault.removeprefix("source-missing-")]
            if self.fault == "report-missing-seal":
                seals &= ~closure._F_SEAL_WRITE
            reopen_seals = self.fault in {"source-reopen-seals", "report-reopen-seals"}
            if reopen_seals and fd == 78:
                seals &= ~closure._F_SEAL_WRITE
            return seals
        if command == closure._F_GETFL:
            return self.access[fd]
        if command == closure._F_GETFD:
            cloexec_fault = self.fault in {"source-reopen-cloexec", "report-reopen-cloexec"}
            return 0 if cloexec_fault and fd == 78 else closure._FD_CLOEXEC
        raise AssertionError("unexpected fcntl command")

    def close(self, fd):
        self.record("close")
        self.close_attempts.append(fd)
        if fd not in self.objects:
            raise AssertionError("production retried an uncertain descriptor")
        after_reuse = self.fault in {"source-close-after-reuse", "report-close-after-reuse"} and fd == 77
        before = self.fault in {"source-close-before", "report-close-before"} and fd == 77
        read_fault = self.fault == "report-read-close" and fd == 78
        if before:
            raise OSError("close before effect")
        item = self.objects.pop(fd)
        self.access.pop(fd)
        if after_reuse:
            self.replacement = KernelObject(b"foreign", identity=900)
            self.objects[fd] = self.replacement
            self.access[fd] = os.O_RDONLY
            raise OSError("close after effect")
        if read_fault:
            raise OSError("read close after effect")
        del item


def run_source(row, fault, branch):
    ops = SealOps(fault)
    ops.events.append(f"enter:{branch.__name__}")
    try:
        sealed = branch(ops, SOURCE)
    except (closure.RuntimeClosureError, closure.RuntimeClosureCleanupError, OSError) as error:
        if type(error).__name__ != row["intended_code"]:
            raise AssertionError(f"{row['id']}: {type(error).__name__}") from error
    else:
        if row["intended_code"] != "accept":
            raise AssertionError(f"source fault accepted: {row['id']}")
        exact = bytes(ops.objects[sealed.fd].data) == RAW
        readonly = ops.access[sealed.fd] == os.O_RDONLY
        if not exact or not readonly or sealed.seals != closure._EXEC_SEALS or 77 in ops.objects:
            raise AssertionError("sealed source was not exact read-only/CLOEXEC")
        ops.close(sealed.fd)
    if ops.replacement is not None and ops.objects.get(77) is not ops.replacement:
        raise AssertionError("close retry consumed a reused descriptor")
    if ops.close_attempts.count(77) > 1:
        raise AssertionError("uncertain source descriptor was retried")
    ops.events.append(f"oracle:{row['id']}")
    return ops


def run_report(row, fault, branch):
    ops = SealOps(fault)
    ops.events.append(f"enter:{branch.__name__}")
    try:
        fd = branch(ops, REPORT)
    except (closure.RuntimeClosureError, closure.RuntimeClosureCleanupError, OSError) as error:
        if type(error).__name__ != row["intended_code"]:
            raise AssertionError(f"{row['id']}: {type(error).__name__}") from error
        if fault == "report-read-close" and len(error.failures) < 2:
            raise AssertionError("report primary and close failures were not aggregated") from error
    else:
        if row["intended_code"] != "accept":
            raise AssertionError(f"report fault accepted: {row['id']}")
        if bytes(ops.objects[fd].data) != REPORT or ops.access[fd] != os.O_RDONLY:
            raise AssertionError("report descriptor was not exact and read-only")
        ops.close(fd)
    if ops.replacement is not None and ops.objects.get(77) is not ops.replacement:
        raise AssertionError("report close retry consumed a reused descriptor")
    if ops.close_attempts.count(77) > 1:
        raise AssertionError("uncertain report descriptor was retried")
    ops.events.append(f"oracle:{row['id']}")
    return ops


def expected_stage(target, fault):
    if fault == "none":
        return "close"
    if "memfd" in fault:
        return f"{target}:memfd"
    if "write" in fault and "read" not in fault:
        return f"{target}:pwrite"
    if "chmod" in fault:
        return f"{target}:chmod"
    if "fsync" in fault:
        return f"{target}:fsync"
    if "reopen" in fault:
        return "reopen"
    if "close" in fault:
        return "close"
    if any(token in fault for token in ("seal", "access", "cloexec")):
        return f"{target}:fcntl"
    if "readback" in fault or fault == "report-read-close":
        return "sealed:pread"
    return "source:pread" if target == "source" and "generation" not in fault else "fstat"


manifest = list(manifest_cases())
identifiers = [row["id"] for row, _target, _fault, _branch in manifest]
declared = set(identifiers)
if len(declared) != len(identifiers):
    raise AssertionError("duplicate declared sealing case")
selected = set()
consumed = set()
oracle = set()
for row, target, fault, branch in manifest:
    selected.add(row["id"])
    ops = run_source(row, fault, branch) if target == "source" else run_report(row, fault, branch)
    if f"enter:{row['sentinel']}" not in ops.events:
        raise AssertionError(f"sealing production sentinel missed: {row['id']}")
    stage = expected_stage(target, fault)
    if not any(event.startswith(stage) for event in ops.events):
        raise AssertionError(f"sealing selected cut was not reached: {row['id']} ({stage})")
    if fault != "none" and ops.consumed != {fault}:
        raise AssertionError(f"sealing fault was not consumed by its production syscall: {row['id']}")
    expected_objects = {SOURCE_FD}
    if fault in {"source-close-before", "report-close-before"}: expected_objects.add(77)
    if fault in {"source-close-after-reuse", "report-close-after-reuse"}: expected_objects.add(77)
    if set(ops.objects) != expected_objects:
        raise AssertionError(f"sealing descriptor settlement changed: {row['id']} {ops.objects}")
    consumed.add(row["id"])
    if f"oracle:{row['id']}" not in ops.events:
        raise AssertionError(f"sealing oracle missed: {row['id']}")
    oracle.add(row["id"])
if not declared == selected == consumed == oracle:
    raise AssertionError("sealing declared/selected/consumed/oracle mismatch")
print("Outcome 2 sealing portable tests passed")
