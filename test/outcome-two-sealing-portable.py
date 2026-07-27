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
MATRIX = json.loads((FIXTURES / "sealing/faults.json").read_text())
RAW = (FIXTURES / "elf" / MATRIX["success"]["source"]).read_bytes()
REPORT = (FIXTURES / "reports/runtime-closure-v1.canonical.jsonl").read_bytes()
SOURCE_FD = 41
GENERATION = closure.SourceGeneration(
    8, 101, len(RAW), 1, 1, stat.S_IFREG | 0o755, 0, 0,
)
SOURCE = closure.AuthenticatedObject(
    "executable", "/usr/bin/gzip", SOURCE_FD, GENERATION, (), len(RAW),
    hashlib.sha256(RAW).hexdigest(), elf.parse_elf64(RAW),
)
SEAL_BITS = {name: getattr(closure, "_" + name) for name in MATRIX["required_exec_seals"]}
if sum(SEAL_BITS.values()) != closure._EXEC_SEALS:
    raise AssertionError("fixture seal profile diverged from production")


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
        self.objects = {SOURCE_FD: KernelObject(RAW, 0o755, 101)}
        self.access = {SOURCE_FD: os.O_RDONLY}
        self.close_attempts = []
        self.source_stats = 0
        self.write_calls = 0
        self.replacement = None

    def memfd_create(self, name, flags):
        source = name == "cogs-runtime-object"
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
        if path != "/proc/self/fd/77":
            raise AssertionError("sealing reopened a source pathname")
        if self.fault == "report-reopen":
            raise OSError("reopen")
        if flags != os.O_RDONLY | closure._O_CLOEXEC:
            raise AssertionError("report reopen was not fixed read-only")
        self.objects[78] = self.objects[77]
        self.access[78] = os.O_RDWR if self.fault == "report-reopen-access" else os.O_RDONLY
        return 78

    def fstat(self, fd):
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
        identity_fault = self.fault in {"report-reopen-identity", "report-read-close"}
        identity = item.identity + (1 if identity_fault and fd == 78 else 0)
        return SimpleNamespace(
            st_dev=0, st_ino=identity, st_size=len(item.data), st_mtime_ns=1,
            st_ctime_ns=1, st_mode=stat.S_IFREG | item.mode, st_uid=0, st_gid=0,
        )

    def pread(self, fd, size, offset):
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
        if self.fault == f"{prefix}-chmod":
            raise OSError("chmod")
        self.objects[fd].mode = mode

    def fsync(self, fd):
        prefix = "source" if self.fault.startswith("source") else "report"
        if self.fault == f"{prefix}-fsync":
            raise OSError("fsync")

    def fcntl(self, fd, command, argument=0):
        prefix = "source" if self.fault.startswith("source") else "report"
        if command == closure._F_ADD_SEALS:
            if self.fault == f"{prefix}-add-seals":
                raise OSError("add seals")
            self.objects[fd].seals = argument
            return 0
        if command == closure._F_GET_SEALS:
            if self.fault in {f"{prefix}-get-seals", "source-close-before", "source-close-after-reuse"}:
                raise OSError("get seals")
            seals = self.objects[fd].seals
            if self.fault.startswith("source-missing-"):
                seals &= ~SEAL_BITS[self.fault.removeprefix("source-missing-")]
            if self.fault == "report-missing-seal":
                seals &= ~closure._F_SEAL_WRITE
            if self.fault == "report-reopen-seals" and fd == 78:
                seals &= ~closure._F_SEAL_WRITE
            return seals
        if command == getattr(closure, "_F_GETFL", 3):
            return self.access[fd]
        raise AssertionError("unexpected fcntl command")

    def close(self, fd):
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


def run_source(case):
    fault = case.get("fault", "")
    ops = SealOps(fault)
    try:
        sealed = closure._seal_source(ops, SOURCE, "gzip")
    except (closure.RuntimeClosureError, OSError):
        if case["expect"] != "reject":
            raise
    else:
        if case["expect"] != "accept":
            raise AssertionError(f"source fault accepted: {case['id']}")
        if bytes(ops.objects[sealed.fd].data) != RAW or sealed.seals != closure._EXEC_SEALS:
            raise AssertionError("sealed source bytes/profile mismatch")
        ops.close(sealed.fd)
    if ops.replacement is not None and ops.objects.get(77) is not ops.replacement:
        raise AssertionError("close retry consumed a reused descriptor")
    if ops.close_attempts.count(77) > 1:
        raise AssertionError("uncertain source descriptor was retried")


def run_report(case):
    fault = case.get("fault", "")
    ops = SealOps(fault)
    try:
        fd = closure._seal_report(ops, REPORT)
    except (closure.RuntimeClosureError, OSError) as error:
        if case["expect"] != "reject":
            raise
        if fault == "report-read-close":
            if not isinstance(error, closure.RuntimeClosureCleanupError) or len(error.failures) < 2:
                raise AssertionError("report primary and close failures were not aggregated") from error
    else:
        if case["expect"] != "accept":
            raise AssertionError(f"report fault accepted: {case['id']}")
        if bytes(ops.objects[fd].data) != REPORT or ops.access[fd] != os.O_RDONLY:
            raise AssertionError("report descriptor was not exact and read-only")
        ops.close(fd)
    if ops.replacement is not None and ops.objects.get(77) is not ops.replacement:
        raise AssertionError("report close retry consumed a reused descriptor")
    if ops.close_attempts.count(77) > 1:
        raise AssertionError("uncertain report descriptor was retried")


executed = []
for case in MATRIX["source_cases"]:
    run_source(case)
    executed.append(case["id"])
for case in MATRIX["report_cases"]:
    run_report(case)
    executed.append(case["id"])
declared = [case["id"] for group in ("source_cases", "report_cases") for case in MATRIX[group]]
if executed != declared or len(executed) != len(set(executed)):
    raise AssertionError("sealing manifest rows were not executed exactly once")
print("Outcome 2 sealing portable tests passed")
