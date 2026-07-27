#!/usr/bin/env python3
"""Manifest-exact strict maps parsing, binding, bounds, and close aggregation."""

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
CASES = json.loads((FIXTURES / "maps/cases.json").read_text())
BEFORE = (FIXTURES / "maps/stable/maps-before.txt").read_bytes()
AFTER = (FIXTURES / "maps/stable/maps-after.txt").read_bytes()


def object_(role, fixture, device, inode):
    raw = (FIXTURES / "elf" / fixture).read_bytes()
    generation = closure.SourceGeneration(
        os.makedev(device, 1), inode, len(raw), 1, 1,
        stat.S_IFREG | 0o755, 0, 0,
    )
    return closure.AuthenticatedObject(
        role, f"/fixed/{fixture}", 900 + inode, generation, (), len(raw),
        hashlib.sha256(raw).hexdigest(), elf.parse_elf64(raw),
    )


EXECUTABLE = object_("executable", "valid-executable.elf", 8, 101)
LOADER = object_("loader", "valid-loader.elf", 8, 102)
ALPHA = object_("library", "valid-libalpha.elf", 8, 103)
BETA = object_("library", "valid-libbeta.elf", 8, 104)
RESOLVED = closure.ResolvedToolClosure("python3-parser", EXECUTABLE, LOADER, (ALPHA, BETA))
CHILD = closure.HelperLease(
    321,
    closure.FdLease(500, "pidfd"),
    closure.FdLease(501, "input"),
    closure.FdLease(502, "release"),
    closure.FdLease(503, "status"),
    closure._HelperState.EXEC_IDENTIFIED,
    10,
    321,
    321,
    EXECUTABLE.identity,
)


def remove(raw, address):
    prefix = address.encode()
    return b"".join(line + b"\n" for line in raw.splitlines() if not line.startswith(prefix))


def replace_row(raw, replacement):
    rows = raw.splitlines()
    rows[0] = replacement.encode()
    return b"\n".join(rows) + b"\n"


class MapOps(closure._Ops):
    """Kernel model keeps fd objects separate from production ownership state."""
    def __init__(self, before, after, objects, fault=None):
        self.snapshots = [before, after]
        self.objects = objects
        self.fault = fault
        self.next_fd = 10
        self.fds = {}
        self.positions = {}
        self.map_stats = {}
        self.maps_opened = 0
        self.close_attempts = []

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        if path == "/proc/321/maps":
            raw = self.snapshots[min(self.maps_opened, 1)]
            self.maps_opened += 1
            item = ("maps", raw)
        elif "/map_files/" in path:
            if self.fault == "map-open-eacces":
                raise PermissionError(path)
            address = path.rsplit("/", 1)[1]
            address = "-".join(f"{int(value, 16):08x}" for value in address.split("-"))
            row = self.objects.get(address)
            if row is None:
                raise FileNotFoundError(path)
            raw = (FIXTURES / "elf" / row["fixture"]).read_bytes()
            item = ("object", raw)
            self.map_stats[self.next_fd] = tuple(row["identity"])
        else:
            raise AssertionError(f"unexpected production open: {path}")
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = item
        self.positions[fd] = 0
        return fd

    def read(self, fd, size):
        if self.fault == "maps-read-and-close" and self.fds[fd][0] == "maps":
            raise OSError("primary maps read")
        raw = self.fds[fd][1]
        offset = self.positions[fd]
        if self.fault == "maps-over-4m":
            raw = b"x" * (closure._MAX_MAP_BYTES + 1)
        value = raw[offset:offset + size]
        self.positions[fd] += len(value)
        return value

    def pread(self, fd, size, offset):
        raw = self.fds[fd][1]
        value = raw[offset:offset + size]
        if self.fault == "map-parse-and-close" and value:
            return bytes([value[0] ^ 1]) + value[1:]
        return value

    def fstat(self, fd):
        raw = self.fds[fd][1]
        device_major, inode = self.map_stats[fd]
        device = os.makedev(device_major, 1)
        key = ("fstat", fd)
        count = self.positions.get(key, 0)
        self.positions[key] = count + 1
        mtime = 2 if self.fault == "fstat-generation-change" and count else 1
        return SimpleNamespace(
            st_dev=device, st_ino=inode, st_size=len(raw), st_mtime_ns=mtime,
            st_ctime_ns=1, st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0,
        )

    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("production double-closed a map descriptor")
        kind = self.fds.pop(fd)[0]
        self.close_attempts.append(fd)
        close_fault = (
            self.fault == "maps-read-and-close" and kind == "maps"
            or self.fault == "map-parse-and-close" and kind == "object"
        )
        if close_fault:
            raise OSError(f"{kind} close")


def case_inputs(case):
    before = BEFORE
    after = AFTER
    objects = dict(CASES["objects"])
    resolved = RESOLVED
    fault = case.get("fault")
    if "after" in case:
        after = (FIXTURES / "maps" / case["after"]).read_bytes()
    if case.get("mapping"):
        before = before.replace(
            b"7fff0000-7fff1000 r-xp 00000000 00:00 0 [vdso]\n",
            b"7f003000-7f004000 r-xp 00000000 08:01 105 /unexpected\n"
            b"7fff0000-7fff1000 r-xp 00000000 00:00 0 [vdso]\n",
        )
        after = before
    if case.get("remove"):
        before = remove(before, case["remove"])
        after = before
    if case.get("row"):
        before = replace_row(before, case["row"])
        after = before
    if fault == "missing-lf":
        before = before.rstrip(b"\n")
        after = before
    if fault == "overlapping-row":
        extra = b"00400800-00401800 r--p 00000000 08:01 101 /overlap\n"
        before = before.splitlines(keepends=True)[0] + extra + b"".join(before.splitlines(keepends=True)[1:])
        after = before
    if fault == "maps-over-4096-lines":
        before = b"10000000-10001000 r--p 00000000 00:00 0\n" * 4097
        after = before
    if fault == "two-roles-same-fingerprint":
        duplicate = object_("loader", "valid-libalpha.elf", 8, 103)
        resolved = closure.ResolvedToolClosure("python3-parser", EXECUTABLE, duplicate, (ALPHA, BETA))
    if fault == "129-unique-objects":
        rows = []
        libraries = []
        objects = {}
        for index in range(129):
            start = 0x60000000 + index * 0x1000
            address = f"{start:08x}-{start + 0x1000:08x}"
            identity = [8, 1000 + index]
            objects[address] = {"fixture": "valid-libbeta.elf", "identity": identity}
            rows.append(f"{address} r-xp 00000000 08:01 {identity[1]} /lib{index}.so\n")
            libraries.append(object_("library", "valid-libbeta.elf", *identity))
        before = "".join(rows).encode()
        after = before
        resolved = closure.ResolvedToolClosure("python3-parser", libraries[0], libraries[1], tuple(libraries[2:]))
    return before, after, objects, resolved, fault


def run(case):
    before, after, objects, resolved, fault = case_inputs(case)
    ops = MapOps(before, after, objects, fault)
    try:
        result = closure._mapped_closure(ops, CHILD, resolved)
    except BaseException as error:
        if case["expect"] != "reject":
            raise
        if fault in {"maps-read-and-close", "map-parse-and-close"}:
            if not isinstance(error, closure.RuntimeClosureCleanupError):
                raise AssertionError("close replaced rather than aggregated the primary") from error
            if len(error.failures) < 2:
                raise AssertionError("primary plus close failure was not preserved")
    else:
        if case["expect"] != "accept":
            raise AssertionError(f"hostile map case accepted: {case['id']}")
        if result.mapped != tuple((item.role, item.sha256) for item in resolved.objects):
            raise AssertionError("mapping sequence was not exact")
    if ops.fds:
        raise AssertionError(f"descriptor residue after {case['id']}: {ops.fds}")


executed = []
for case in CASES["cases"]:
    run(case)
    executed.append(case["id"])
declared = [case["id"] for case in CASES["cases"]]
if executed != declared or len(executed) != len(set(executed)):
    raise AssertionError("maps manifest rows were not executed exactly once")
print("Outcome 2 mapped closure portable tests passed")
