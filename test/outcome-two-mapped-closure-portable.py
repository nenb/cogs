#!/usr/bin/env python3
"""Portable hostile qualification for trusted mapped-closure capture."""

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


def rejected(call, label):
    try:
        call()
    except (closure.RuntimeClosureError, OSError, UnicodeError):
        return
    raise AssertionError(f"hostile mapped closure accepted: {label}")


def object_(role, fixture, device, inode):
    raw = (FIXTURES / "elf" / fixture).read_bytes()
    generation = closure.SourceGeneration(
        device, inode, len(raw), 1, 1, stat.S_IFREG | 0o755, 0, 0,
    )
    return closure.AuthenticatedObject(
        role, f"/fixed/{fixture}", 900 + inode, generation, len(raw),
        hashlib.sha256(raw).hexdigest(), elf.parse_elf64(raw),
    )


EXECUTABLE = object_("executable", "valid-executable.elf", 8, 101)
LOADER = object_("loader", "valid-loader.elf", 8, 102)
ALPHA = object_("library", "valid-libalpha.elf", 8, 103)
BETA = object_("library", "valid-libbeta.elf", 8, 104)
RESOLVED = closure.ResolvedToolClosure("python3-parser", EXECUTABLE, LOADER, (ALPHA, BETA))
CHILD = closure._Child(321, 500, 10, 321, 321, EXECUTABLE.identity)
CASES = json.loads((FIXTURES / "maps/cases.json").read_text())
BEFORE = (FIXTURES / "maps/stable/maps-before.txt").read_bytes()
AFTER = (FIXTURES / "maps/stable/maps-after.txt").read_bytes()
CHANGED = (FIXTURES / "maps/changed/maps-after.txt").read_bytes()


class MapOps(closure._Ops):
    def __init__(self, before=BEFORE, after=AFTER, *, fault=None, fail_open=None):
        self.snapshots = [before, after]
        self.fault = fault
        self.fail_open = fail_open
        self.open_calls = 0
        self.next_fd = 10
        self.opened = {}
        self.positions = {}
        self.map_stats = {}
        self.maps_opened = 0
        self.closed = []
        self.max_read = 0

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        self.open_calls += 1
        if self.open_calls == self.fail_open:
            raise OSError(24, "injected descriptor exhaustion")
        if path == "/proc/321/maps":
            content = self.snapshots[min(self.maps_opened, 1)]
            self.maps_opened += 1
            kind = ("stream", content)
        elif "/map_files/" in path:
            address = path.rsplit("/", 1)[1]
            start, end = address.split("-", 1)
            address = f"{int(start, 16):08x}-{int(end, 16):08x}"
            if self.fault == "map-open-eacces":
                raise PermissionError(path)
            row = CASES["objects"].get(address)
            if row is None:
                raise FileNotFoundError(path)
            raw = (FIXTURES / "elf" / row["fixture"]).read_bytes()
            kind = ("map", raw)
            self.map_stats[self.next_fd] = tuple(row["identity"])
        else:
            raise AssertionError(f"unexpected production open: {path}")
        fd = self.next_fd
        self.next_fd += 1
        self.opened[fd] = kind
        self.positions[fd] = 0
        return fd

    def read(self, fd, size):
        self.max_read = max(self.max_read, size)
        kind, content = self.opened[fd]
        assert kind == "stream" and size <= 65536
        offset = self.positions[fd]
        if self.fault == "maps-over-4m" and offset <= closure._MAX_MAP_BYTES:
            data = b"x" * size
        else:
            data = content[offset:offset + size]
        self.positions[fd] += len(data)
        return data

    def pread(self, fd, size, offset):
        return self.opened[fd][1][offset:offset + size]

    def fstat(self, fd):
        raw = self.opened[fd][1]
        device, inode = self.map_stats[fd]
        count = self.positions.get(("fstat", fd), 0)
        self.positions[("fstat", fd)] = count + 1
        drift = self.fault == "fstat-generation-change" and count > 0
        return SimpleNamespace(st_dev=device, st_ino=inode, st_size=len(raw),
            st_mtime_ns=2 if drift else 1, st_ctime_ns=1,
            st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0)

    def close(self, fd):
        assert fd in self.opened, "production double-closed a map descriptor"
        self.closed.append(fd)
        del self.opened[fd]


def capture(ops):
    try:
        return closure._mapped_closure(ops, CHILD, RESOLVED)
    finally:
        assert not ops.opened, "mapped capture leaked a descriptor"
        assert ops.max_read <= 65536


def without(raw, address):
    return b"\n".join(line for line in raw.splitlines() if not line.startswith(address.encode())) + b"\n"


first = capture(MapOps())
second = capture(MapOps())
assert first == second
assert first.mapped == tuple((item.role, item.sha256) for item in RESOLVED.objects)
assert len(first.mapping_sha256) == 64

rejected(lambda: capture(MapOps(after=CHANGED)), "maps changed")
unknown = BEFORE.replace(
    b"7fff0000-7fff1000 r-xp 00000000 00:00 0 [vdso]\n",
    b"7f003000-7f004000 r-xp 00000000 08:01 105 /libunexpected.so.1\n"
    b"7fff0000-7fff1000 r-xp 00000000 00:00 0 [vdso]\n",
)
rejected(lambda: capture(MapOps(before=unknown, after=unknown)), "unknown executable")
rejected(lambda: capture(MapOps(fault="map-open-eacces")), "unopenable executable")
rejected(lambda: capture(MapOps(fault="fstat-generation-change")), "mapped generation drift")
for address, label in (("7f000000-7f001000", "missing loader"),
                       ("7f002000-7f003000", "missing dependency")):
    reduced = without(BEFORE, address)
    rejected(lambda reduced=reduced: capture(MapOps(before=reduced, after=reduced)), label)
line = b"10000000-10001000 r--p 00000000 00:00 0\n"
too_many = line * 4097
rejected(lambda: capture(MapOps(before=too_many, after=too_many)), "maps line bound")
rejected(lambda: capture(MapOps(fault="maps-over-4m")), "maps byte bound")
for open_number in range(1, 7):
    rejected(lambda open_number=open_number: capture(MapOps(fail_open=open_number)),
             f"descriptor exhaustion at mapping open {open_number}")

print("Outcome 2 mapped closure portable tests passed")
