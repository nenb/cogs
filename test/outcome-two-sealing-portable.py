#!/usr/bin/env python3
"""Portable fault matrix for source-descriptor-direct executable sealing."""

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
SOURCE_FD = 41
SOURCE_GENERATION = closure.SourceGeneration(
    8, 101, len(RAW), 1, 1, stat.S_IFREG | 0o755, 0, 0,
)
SOURCE = closure.AuthenticatedObject(
    "executable", "/usr/bin/gzip", SOURCE_FD, SOURCE_GENERATION,
    len(RAW), hashlib.sha256(RAW).hexdigest(), elf.parse_elf64(RAW),
)
SEAL_NAMES = {
    name: getattr(closure, "_" + name) for name in MATRIX["required_seals"]
}
assert sum(SEAL_NAMES.values()) == closure._EXEC_SEALS


class SealOps(closure._Ops):
    def __init__(self, fault=None):
        self.fault = fault
        self.destination = bytearray()
        self.live = {SOURCE_FD}
        self.mode = 0
        self.seals = 0
        self.source_stats = 0
        self.write_calls = 0
        self.open_calls = 0
        self.closed = []

    def open(self, *args, **kwargs):
        self.open_calls += 1
        raise AssertionError("sealing rediscovered a pathname")

    def memfd_create(self, name, flags):
        assert name == "cogs-runtime"
        assert flags == closure._MFD_CLOEXEC | closure._MFD_ALLOW_SEALING | closure._MFD_EXEC
        if self.fault == "memfd-create":
            raise OSError("memfd fault")
        self.live.add(77)
        return 77

    def fstat(self, fd):
        if fd == SOURCE_FD:
            self.source_stats += 1
            drift = ((self.fault == "source-generation-before-copy" and self.source_stats == 1) or
                     (self.fault == "source-generation-after-copy" and self.source_stats > 1))
            generation = SOURCE_GENERATION
            return SimpleNamespace(st_dev=generation.device, st_ino=generation.inode,
                st_size=generation.size, st_mtime_ns=2 if drift else generation.mtime_ns,
                st_ctime_ns=generation.ctime_ns, st_mode=generation.mode,
                st_uid=generation.uid, st_gid=generation.gid)
        assert fd == 77
        return SimpleNamespace(st_dev=0, st_ino=77, st_size=len(self.destination),
            st_mtime_ns=1, st_ctime_ns=1, st_mode=stat.S_IFREG | self.mode, st_uid=0, st_gid=0)

    def pread(self, fd, size, offset):
        if fd == SOURCE_FD:
            if self.fault == "source-pread-error": raise OSError("source read fault")
            if self.fault == "source-pread-short" and offset == 0: return b""
            return RAW[offset:offset + size]
        if self.fault == "destination-pread-error": raise OSError("readback fault")
        if self.fault == "destination-pread-short" and offset == 0: return b""
        value = bytes(self.destination[offset:offset + size])
        if self.fault == "readback-digest-mismatch" and value:
            value = bytes([value[0] ^ 1]) + value[1:]
        return value

    def pwrite(self, fd, data, offset):
        assert fd == 77
        self.write_calls += 1
        if self.fault == "destination-write-error": raise OSError("write fault")
        if self.fault == "destination-write-zero": return 0
        if self.fault == "destination-write-partial-then-error" and self.write_calls > 1:
            raise OSError("write after partial fault")
        count = 1 if self.fault in {"destination-write-partial", "destination-write-partial-then-error"} else len(data)
        end = offset + count
        if len(self.destination) < end: self.destination.extend(b"\0" * (end - len(self.destination)))
        self.destination[offset:end] = data[:count]
        return count

    def fchmod(self, fd, mode):
        assert fd == 77
        if self.fault in {"fchmod", "destination-close"}: raise OSError("chmod fault")
        self.mode = mode

    def fsync(self, fd):
        assert fd == 77
        if self.fault == "fsync": raise OSError("fsync fault")

    def fcntl(self, fd, command, argument=0):
        assert fd == 77
        if command == closure._F_ADD_SEALS:
            if self.fault == "add-seals": raise OSError("add seals fault")
            self.seals = argument
            return 0
        assert command == closure._F_GET_SEALS
        if self.fault == "get-seals": raise OSError("get seals fault")
        if self.fault and self.fault.startswith("get-seals-missing-"):
            suffix = self.fault.removeprefix("get-seals-missing-").replace("-", "_").upper()
            return self.seals & ~SEAL_NAMES["F_SEAL_" + suffix]
        return self.seals

    def close(self, fd):
        assert fd in self.live, "production double close"
        self.live.remove(fd)
        self.closed.append(fd)
        if self.fault == "destination-close" and fd == 77:
            raise OSError("close fault")


def success(fault=None):
    ops = SealOps(fault)
    sealed = closure._seal_source(ops, SOURCE, "gzip")
    assert sealed.fd == 77 and sealed.source_generation == SOURCE_GENERATION
    assert sealed.sha256 == SOURCE.sha256 and sealed.seals == closure._EXEC_SEALS
    assert bytes(ops.destination) == RAW and ops.mode == MATRIX["success"]["mode"]
    assert ops.live == {SOURCE_FD, 77} and ops.open_calls == 0
    ops.close(77)
    assert ops.live == {SOURCE_FD}


success()
success("destination-write-partial")
for fault in MATRIX["faults"]:
    ops = SealOps(fault)
    try:
        closure._seal_source(ops, SOURCE, "gzip")
    except (closure.RuntimeClosureError, OSError):
        pass
    else:
        raise AssertionError(f"sealing fault accepted: {fault}")
    assert ops.live == {SOURCE_FD}, f"descriptor residue after {fault}: {ops.live}"
    assert ops.open_calls == 0

print("Outcome 2 sealing portable tests passed")
