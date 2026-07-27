#!/usr/bin/env python3
"""Portable hostile qualification for ELF parsing and fixed closure resolution."""

import importlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace
from unittest.mock import patch

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
assert closure.FIXED_TOOL_TABLE == (
    ("python3-parser", "/usr/bin/python3"),
    ("zstd", "/usr/bin/zstd"),
    ("gzip", "/usr/bin/gzip"),
)


def rejected(call, error, label):
    try:
        call()
    except error:
        return
    raise AssertionError(f"hostile case accepted: {label}")


def parser_matrix():
    read = lambda name: (FIXTURES / "elf" / name).read_bytes()
    executable = elf.parse_elf64(read("valid-executable.elf"))
    assert executable.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert executable.soname is None and executable.needed == ("libalpha.so.1",)
    assert elf.parse_elf64(read("valid-loader.elf")).soname == "ld-linux-x86-64.so.2"
    assert elf.parse_elf64(read("valid-libalpha.elf")).needed == ("libbeta.so.1",)
    assert elf.parse_elf64(read("valid-libbeta.elf")).needed == ()
    assert elf.parse_elf64(read("missing-interpreter.elf")).interpreter is None
    for name in ("malformed-magic.elf", "truncated.elf", "unknown-interpreter.elf",
                 "forbidden-runpath.elf", "duplicate-needed.elf"):
        rejected(lambda name=name: elf.parse_elf64(read(name)), elf.ElfParseError, name)
    rejected(lambda: elf.parse_elf64(bytearray(read("valid-executable.elf"))),
             elf.ElfParseError, "non-bytes")
    raw = bytearray(read("valid-executable.elf"))
    struct.pack_into("<H", raw, 56, 257)
    rejected(lambda: elf.parse_elf64(bytes(raw)), elf.ElfParseError, "program-header-bound")
    struct.pack_into("<H", raw, 56, 3)
    struct.pack_into("<Q", raw, 32, (1 << 64) - 32)
    rejected(lambda: elf.parse_elf64(bytes(raw)), elf.ElfParseError, "table-overflow")


class FsOps(closure._Ops):
    def __init__(self, files, *, aliases=None, fault=None, reverse=False):
        self.files = files
        self.aliases = aliases or {}
        self.fault = fault
        self.reverse = reverse
        self.next_fd = 10
        self.opened = {}
        self.fstats = {}
        self.closed = []
        self.directories = {"/"}
        for path in files:
            parent = Path(path).parent
            while str(parent) != ".":
                self.directories.add(str(parent))
                if str(parent) == "/":
                    break
                parent = parent.parent

    def _path(self, path, dir_fd=None):
        if path.startswith("/"):
            return os.path.normpath(path)
        return os.path.normpath(self.opened[dir_fd].rstrip("/") + "/" + path)

    def _stat(self, path, *, fstat=False):
        is_dir = path in self.directories
        if not is_dir and path not in self.files:
            raise FileNotFoundError(path)
        inode = self.aliases.get(path, sorted(self.files).index(path) + 100 if not is_dir else hash(path) & 0xffff)
        mode = (stat.S_IFDIR | 0o755) if is_dir else (stat.S_IFREG | 0o755)
        uid = 0
        if self.fault == "group-writable" and path == "/usr/bin/python3":
            mode |= 0o020
        if self.fault == "non-root-owner" and path == "/usr/bin/python3":
            uid = 1000
        count = self.fstats.get(path, 0)
        if fstat:
            self.fstats[path] = count + 1
        drift = self.fault == "fstat-generation-change" and path == "/usr/bin/python3" and count >= 1
        size = 0 if is_dir else len(self.files[path])
        return SimpleNamespace(st_dev=8, st_ino=inode, st_size=size,
            st_mtime_ns=2 if drift else 1, st_ctime_ns=1, st_mode=mode, st_uid=uid, st_gid=0)

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode
        full = self._path(path, dir_fd)
        self._stat(full)
        fd = self.next_fd
        self.next_fd += 1
        self.opened[fd] = full
        return fd

    def stat(self, path, *, dir_fd, follow_symlinks):
        del follow_symlinks
        return self._stat(self._path(path, dir_fd))

    def fstat(self, fd):
        return self._stat(self.opened[fd], fstat=True)

    def pread(self, fd, size, offset):
        raw = self.files[self.opened[fd]]
        if self.fault == "read-eof-before-size" and self.opened[fd] == "/usr/bin/python3" and offset:
            return b""
        return raw[offset:offset + min(size, len(raw) // 2 or 1)]

    def close(self, fd):
        if fd not in self.opened:
            raise OSError("double close")
        self.closed.append(fd)
        del self.opened[fd]

    def order(self, name, values):
        assert name == "library-roots"
        return tuple(reversed(values)) if self.reverse else tuple(values)


def filesystem(case=None, *, reverse=False):
    data = json.loads((FIXTURES / "closure/cases.json").read_text())
    files = {path: (FIXTURES / "elf" / name).read_bytes() for path, name in data["fixed_paths"].items()}
    aliases = {}
    fault = None
    if case:
        for path in case.get("remove", []): files.pop(path)
        for path, name in case.get("replace", {}).items(): files[path] = (FIXTURES / "elf" / name).read_bytes()
        for path, name in case.get("add", {}).items():
            files[path] = (FIXTURES / "elf" / name).read_bytes()
            aliases[path] = 103 if not case["distinct_identity"] else 999
        fault = case.get("fault")
    return FsOps(files, aliases=aliases, fault=fault, reverse=reverse)


def closure_matrix():
    for reverse in (False, True):
        ops = filesystem(reverse=reverse)
        value = closure._resolve_tool(ops, "python3-parser", "/usr/bin/python3")
        assert [item.role for item in value.objects] == ["executable", "loader", "library", "library"]
        assert [item.elf.soname for item in value.libraries] == ["libalpha.so.1", "libbeta.so.1"]
        closure._close_local(ops, (item.held_fd for item in value.objects))
        assert not ops.opened
    cases = json.loads((FIXTURES / "closure/cases.json").read_text())["hostile"]
    for case in cases[:10]:
        ops = filesystem(case)
        rejected(lambda ops=ops: closure._resolve_tool(ops, "python3-parser", "/usr/bin/python3"),
                 (closure.RuntimeClosureError, elf.ElfParseError, OSError), case["name"])
        assert not ops.opened, case["name"]


def object_(role, inode, size, needed=(), soname=None):
    generation = closure.SourceGeneration(8, inode, size, 1, 1, stat.S_IFREG | 0o755, 0, 0)
    return closure.AuthenticatedObject(role, f"/fixed/{inode}", inode, generation, size,
        f"{inode:064x}"[-64:], elf.ElfMetadata(None if role != "executable" else closure._INTERPRETER,
                                                soname, tuple(needed)))


def resolver_bounds():
    class CloseOps(closure._Ops):
        def __init__(self): self.closed = []
        def close(self, fd): self.closed.append(fd)
    for count, size, label in ((127, 1, "object-bound"), (3, 128 * 1024 * 1024, "byte-bound")):
        names = tuple(f"lib{index:03}.so" for index in range(count))
        root = object_("executable", 1, size, names)
        loader = object_("loader", 2, size, soname="loader.so")
        libraries = [object_("library", index + 3, size, soname=name) for index, name in enumerate(names)]
        ops = CloseOps()
        with patch.object(closure, "_authenticate", side_effect=(root, loader)), \
             patch.object(closure, "_resolve_library", side_effect=libraries):
            rejected(lambda: closure._resolve_tool(ops, "python3-parser", "/usr/bin/python3"),
                     closure.RuntimeClosureError, label)
        assert len(ops.closed) == count + 2


parser_matrix()
closure_matrix()
resolver_bounds()
print("Outcome 2 runtime closure portable tests passed")
