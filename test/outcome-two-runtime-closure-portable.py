#!/usr/bin/env python3
"""Exhaustive portable ELF, component, alias, race, and closure-bound matrix."""
import dataclasses
import hashlib, importlib, json, os
from pathlib import Path
import signal, stat, struct, sys
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
ROW_KEYS = {"id", "production_method", "primitive_fault", "intended_code",
            "cleanup_domains", "sentinel"}
def load_ledger(path):
    values = [json.loads(line) for line in path.read_text().splitlines()]
    if not values or values[0].get("type") != "header": raise AssertionError("closure ledger header")
    return values[0], values[1:]
HEADER, CASES = load_ledger(FIXTURES / "closure/cases.jsonl")
def manifest_cases():
    for row in CASES:
        branch = getattr(closure, row["sentinel"], None)
        if set(row) != ROW_KEYS or row["production_method"] != row["sentinel"] or not callable(branch):
            raise AssertionError("closure manifest row/method")
        case = dict(row["primitive_fault"])
        case["id"] = row["id"]
        case["expect"] = "accept" if row["intended_code"] == "accept" else "reject"
        yield row, case, branch
def reject(call, label, expected=None):
    try:
        call()
    except (elf.ElfParseError, closure.RuntimeClosureError, OSError, UnicodeError) as error:
        if expected is not None and type(error).__name__ != expected: raise AssertionError(f"{label}: {type(error).__name__}") from error
        return
    raise AssertionError(f"hostile case accepted: {label}")
def synthetic(names=("libalpha.so.1",), *, interp=True, soname=None,
              tags=(), loads=(), load_size=4096, memory_size=4096):
    raw = bytearray(max(4096, load_size))
    base = 0x400000
    interp_raw = b"/lib64/ld-linux-x86-64.so.2\0"
    strings = bytearray(b"\0")
    offsets = []
    for name in names:
        offsets.append(len(strings))
        strings.extend(name if type(name) is bytes else name.encode("ascii"))
        strings.append(0)
    soname_offset = len(strings)
    if soname is not None:
        strings.extend(soname if type(soname) is bytes else soname.encode("ascii"))
        strings.append(0)
    raw[0x380:0x380 + len(strings)] = strings
    dynamic = [(1, value) for value in offsets]
    if soname is not None:
        dynamic.append((14, soname_offset))
    dynamic.extend(((5, base + 0x380), (10, len(strings))))
    dynamic.extend(tags)
    dynamic.append((0, 0))
    dynamic_raw = b"".join(struct.pack("<QQ", *item) for item in dynamic)
    raw[0x200:0x200 + len(dynamic_raw)] = dynamic_raw
    if interp:
        raw[0x180:0x180 + len(interp_raw)] = interp_raw
    phdrs = [(1, 5, 0, base, 0, load_size, memory_size, 0x1000)]
    if interp:
        phdrs.append((3, 4, 0x180, base + 0x180, 0, len(interp_raw), len(interp_raw), 1))
    phdrs.append((2, 6, 0x200, base + 0x200, 0, len(dynamic_raw), len(dynamic_raw), 8))
    phdrs.extend(loads)
    ident = b"\x7fELF\x02\x01\x01\0" + b"\0" * 8
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 62, 1, 0, 64, 0, 0,
                         64, 56, len(phdrs), 0, 0, 0)
    raw[:64] = header
    for index, phdr in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", raw, 64 + index * 56, *phdr)
    return bytes(raw)
def parser_matrix():
    fixture_expectations = {
        "valid-executable.elf": True,
        "valid-loader.elf": True,
        "valid-libalpha.elf": True,
        "valid-libbeta.elf": True,
        "missing-interpreter.elf": True,
        "malformed-magic.elf": False,
        "truncated.elf": False,
        "unknown-interpreter.elf": False,
        "forbidden-runpath.elf": False,
        "duplicate-needed.elf": False,
    }
    actual = {path.name for path in (FIXTURES / "elf").glob("*.elf")}
    if actual != set(fixture_expectations):
        raise AssertionError("ELF fixture inventory has an unimplemented row")
    for name, accepted in fixture_expectations.items():
        raw = (FIXTURES / "elf" / name).read_bytes()
        if accepted:
            elf.parse_elf64(raw)
        else:
            reject(lambda raw=raw: elf.parse_elf64(raw), name)
    valid = synthetic()
    assert elf.parse_elf64(valid).needed == ("libalpha.so.1",)
    assert elf.parse_elf64(synthetic(interp=False, soname="libself.so")).soname == "libself.so"
    assert elf.parse_elf64(synthetic(("libz.so.1", "libc.so.6"))).needed[0] == "libz.so.1"
    assert elf.parse_elf64(synthetic(("libfixed_name++.so.1-2",))).needed
    for offset, value in ((0, 0), (4, 1), (5, 2), (6, 0), (7, 4), (8, 1),
                          (16, 1), (18, 3), (20, 2), (48, 1), (52, 63),
                          (54, 55), (56, 0)):
        raw = bytearray(valid)
        raw[offset] = value
        reject(lambda raw=raw: elf.parse_elf64(bytes(raw)), f"header-{offset}")
    for length in (0, 1, 63, 64, 120, 500, 1023):
        reject(lambda length=length: elf.parse_elf64(valid[:length]), f"truncate-{length}")
    for offset, value, form in ((32, 2**64 - 32, "Q"), (58, 4097, "H"),
                                (40, 2**64 - 32, "Q")):
        raw = bytearray(valid)
        struct.pack_into("<" + form, raw, offset, value)
        reject(lambda raw=raw: elf.parse_elf64(bytes(raw)), f"table-{offset}")
    for section_offset in (0, 64):
        raw = bytearray(valid)
        struct.pack_into("<Q", raw, 40, section_offset)
        struct.pack_into("<HHH", raw, 58, 64, 1, 0)
        reject(lambda raw=raw: elf.parse_elf64(bytes(raw)), f"section-{section_offset}")
    def phmut(index, field, value):
        raw = bytearray(valid)
        struct.pack_into("<Q", raw, 64 + index * 56 + field, value)
        return bytes(raw)
    for label, raw in (
        ("load-file-bound", phmut(0, 32, 8192)), ("filesz-memsz", phmut(0, 40, 512)),
        ("align-nonpower", phmut(0, 48, 3)), ("align-zero", phmut(0, 48, 0)),
        ("align-one", phmut(0, 48, 1)), ("page-incongruent", phmut(0, 16, 0x400001)),
        ("interp-unmapped", phmut(1, 16, 0x500180)),
        ("dynamic-unmapped", phmut(2, 16, 0x500200)),
        ("dynamic-partial", phmut(2, 32, 17)),
    ):
        reject(lambda raw=raw: elf.parse_elf64(raw), label)
    base = 0x400000
    overlap = (1, 4, 0x800, base + 0x800, 0, 0x400, 0x400, 0x1000)
    alias = (1, 4, 0x1000, base + 0x800, 0, 0x400, 0x400, 0x1000)
    reverse = (1, 4, 0, base - 0x1000, 0, 0x100, 0x100, 0x1000)
    for label, row in (("rounded-overlap", overlap), ("page-alias", alias),
                       ("reversed-load", reverse)):
        reject(lambda row=row: elf.parse_elf64(synthetic(loads=(row,))), label)
    compatible = (1, 4, 0x1000, base + 0x1000, 0, 0x1000, 0x1000, 0x1000)
    assert elf.parse_elf64(
        synthetic(loads=(compatible,), load_size=8192, memory_size=8192)
    ).needed
    file_alias = (1, 4, 0x800, base + 0x2800, 0, 0x400, 0x400, 0x1000)
    assert elf.parse_elf64(synthetic(loads=(file_alias,))).needed
    assert elf.parse_elf64(synthetic(memory_size=8192)).needed
    reject(lambda: elf.parse_elf64(synthetic(load_size=0x180, memory_size=4096)), "bss-interp")
    reject(lambda: elf.parse_elf64(synthetic(load_size=0x300, memory_size=4096)), "bss-strings")
    reject(lambda: elf.parse_elf64(synthetic(loads=((2, 6, 0x200, base + 0x200, 0, 64, 64, 8),))), "duplicate-dynamic")
    reject(lambda: elf.parse_elf64(synthetic(loads=((3, 4, 0x180, base + 0x180, 0, 32, 32, 1),))), "duplicate-interp")
    for tag in (15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF):
        reject(lambda tag=tag: elf.parse_elf64(synthetic(tags=((tag, 1),))), f"tag-{tag:x}")
    assert elf.parse_elf64(synthetic(tags=((0x6FFFFFFB, 0x08000001),))).needed
    for flags in (0x800, 0x80000000):
        reject(lambda flags=flags: elf.parse_elf64(synthetic(tags=((0x6FFFFFFB, flags),))), f"flags-{flags:x}")
    reject(lambda: elf.parse_elf64(synthetic(tags=((0x6FFFFFFB, 1), (0x6FFFFFFB, 1)))), "duplicate-flags")
    names = (b"bad/name.so", b"bad\\name.so", b"bad\x1fname.so", b"", b"$LIB")
    for name in names:
        reject(lambda name=name: elf.parse_elf64(synthetic((name,))), f"needed-{name!r}")
        reject(lambda name=name: elf.parse_elf64(synthetic((), soname=name)), f"soname-{name!r}")
    reject(lambda: elf.parse_elf64(synthetic(("libsame.so", "libsame.so"))), "duplicate-needed")
    reject(lambda: elf.parse_elf64(synthetic((), soname="libself.so", tags=((14, 1),))), "duplicate-soname")
    reject(lambda: elf.parse_elf64(synthetic(tags=((30, 1 << 20),))), "unknown-DT_FLAGS")
    reject(lambda: elf.parse_elf64(synthetic(tags=((31, 1),))), "unsupported-tag")
    for offset, value, label in (
        (0x180, ord("x"), "interpreter-value"),
        (0x180 + len(b"/lib64/ld-linux-x86-64.so.2"), ord("x"), "interpreter-nul"),
    ):
        raw = bytearray(valid)
        raw[offset] = value
        reject(lambda raw=raw: elf.parse_elf64(bytes(raw)), label)
    for offset, value, label in (
        (0x210 + 8, 0xFFFFFFFFFFFFFFF0, "string-address"),
        (0x220 + 8, 2**32, "string-size"),
        (0x230, 1, "missing-DT_NULL"),
        (0x230 + 8, 123, "nonzero-DT_NULL"),
    ):
        raw = bytearray(valid)
        struct.pack_into("<Q", raw, offset, value)
        reject(lambda raw=raw: elf.parse_elf64(bytes(raw)), label)
    unterminated = bytearray(synthetic((), soname="libunterminated.so"))
    end = unterminated.index(b"libunterminated.so\0") + len(b"libunterminated.so")
    unterminated[end] = ord("x")
    reject(lambda: elf.parse_elf64(bytes(unterminated)), "unterminated-soname")
    reject(lambda: elf.parse_elf64(bytearray(valid)), "non-bytes")
class FsOps(closure._Ops):
    """Independent inode/fd model; production walkers perform every decision."""
    def __init__(self, case):
        self.files = {path: (FIXTURES / "elf" / name).read_bytes()
                      for path, name in HEADER["fixed_paths"].items()}
        self.case = case
        self.fault = case.get("fault")
        self.links = {}
        self.next_fd = 10
        self.fds = {}
        self.closed = []
        self.observations = {}
        self.inodes = {}
        for index, path in enumerate(self.files): self.inodes[path] = 100 + index
        for path in case.get("remove", ()): self.files.pop(path)
        if "replace" in case: self.files[case["replace"][0]] = (FIXTURES / "elf" / case["replace"][1]).read_bytes()
        if "add" in case:
            path = case["add"]
            source = "/lib/x86_64-linux-gnu/libalpha.so.1"
            self.files[path] = self.files[source]
            self.inodes[path] = 999 if case["distinct"] else self.inodes[source]
        if "symlink" in case:
            path, target = case["symlink"]
            raw = self.files.pop(path)
            if target.startswith("/"):
                final = target
            else:
                final = os.path.normpath(os.path.join(os.path.dirname(path), target))
            self.links[path] = target
            self.files[final] = raw
            self.inodes[final] = self.inodes[path]
        if self.fault == "symlink-bound":
            self.files.pop("/usr/bin/python3")
            self.links["/usr/bin/python3"] = "link0"
            for index in range(41): self.links[f"/usr/bin/link{index}"] = f"link{index + 1}"
        if self.fault == "component-bound":
            self.files.pop("/usr/bin/python3")
            self.links["/usr/bin/python3"] = "/" + "/".join(["usr", ".."] * 129)
        self.dirs = {"/"}
        for path in (*self.files, *self.links):
            parent = Path(path).parent
            while str(parent) != ".":
                self.dirs.add(str(parent))
                if str(parent) == "/":
                    break
                parent = parent.parent
    def _path(self, path, dir_fd=None):
        return os.path.normpath(path if path.startswith("/") else self.fds[dir_fd].rstrip("/") + "/" + path)
    def _stat(self, path, *, opened=False):
        count = self.observations.get((path, opened), 0)
        self.observations[(path, opened)] = count + 1
        if path in self.links:
            mode, size, inode, uid = stat.S_IFLNK | 0o777, len(self.links[path]), self.inodes.get(path, 700), 0
        elif path in self.dirs:
            mode, size, inode, uid = stat.S_IFDIR | 0o755, 0, self.inodes.get(path, hash(path) & 0xffff), 0
        elif path in self.files:
            mode, size, inode, uid = stat.S_IFREG | 0o755, len(self.files[path]), self.inodes[path], 0
        else: raise FileNotFoundError(path)
        target = path == "/usr/bin/python3"
        if self.fault == "ancestor-open-race" and path == "/usr" and opened: inode += 1
        if self.fault == "final-open-race" and target and opened: inode += 1
        if self.fault == "second-resolution" and target and not opened and count > 0: inode += 1
        if self.fault == "generation-after" and target and opened and count > 0: mtime = 2
        else: mtime = 1
        if self.fault == "chmod-after" and target and opened and count > 0: mode |= 0o020
        if self.fault == "chown-after" and target and opened and count > 0: uid = 1000
        return SimpleNamespace(st_dev=8, st_ino=inode, st_size=size, st_mtime_ns=mtime,
                               st_ctime_ns=1, st_mode=mode, st_uid=uid, st_gid=0)
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode
        full = self._path(path, dir_fd)
        self._stat(full)
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = full
        return fd
    def stat(self, path, *, dir_fd, follow_symlinks):
        if follow_symlinks: raise AssertionError("production followed a component stat")
        return self._stat(self._path(path, dir_fd))
    def fstat(self, fd): return self._stat(self.fds[fd], opened=True)
    def readlink(self, path, *, dir_fd):
        full = self._path(path, dir_fd)
        if self.fault == "symlink-target-race": self.inodes[full] = self.inodes.get(full, 700) + 1
        return self.links[full]
    def pread(self, fd, size, offset):
        raw = self.files[self.fds[fd]]
        if self.fault == "short-before" and offset == 0: return b""
        if self.fault == "short-during" and offset > 0: return b""
        if self.fault == "grew-after" and offset == len(raw): return b"x"
        return raw[offset:offset + min(size, max(1, len(raw) // 2))]
    def close(self, fd):
        if fd not in self.fds: raise AssertionError("production double close")
        self.closed.append(fd)
        del self.fds[fd]
    def order(self, name, values):
        if name != "library-roots": raise AssertionError("caller-selected enumeration")
        return tuple(values)
def closure_matrix():
    manifest = list(manifest_cases())
    identifiers = [row["id"] for row, _case, _branch in manifest]
    declared = set(identifiers)
    if len(declared) != len(identifiers):
        raise AssertionError("duplicate declared closure case")
    selected = set()
    consumed = set()
    oracle = set()
    deferred = []
    for row, case, branch in manifest:
        selected.add(row["id"])
        if case.get("fault") in {"object-bound", "tool-byte-bound", "aggregate-byte-bound", "cross-role-alias"}:
            deferred.append((row, case, branch))
            continue
        ops = FsOps(case)
        try:
            value = branch(ops, "python3-parser", "/usr/bin/python3")
        except (closure.RuntimeClosureError, elf.ElfParseError, OSError) as error:
            if case["expect"] != "reject": raise
            if type(error).__name__ != row["intended_code"]: raise AssertionError(f"{row['id']}: {type(error).__name__}") from error
        else:
            if case["expect"] != "accept": raise AssertionError(f"accepted {case['id']}")
            assert [item.role for item in value.objects[:2]] == ["executable", "loader"]
            closure._close_objects(ops, value.objects)
        if ops.fds:
            raise AssertionError(f"descriptor residue: {case['id']}")
        consumed.add(row["id"])
        oracle.add(row["id"])
    for row, case, branch in deferred:
        fault = case["fault"]
        if fault == "object-bound":
            rows = [[((8, index), 1) for index in range(129)]]
            reject(lambda: branch(rows), case["id"], row["intended_code"])
        elif fault == "tool-byte-bound":
            rows = [[((8, index), 128 * 1024 * 1024) for index in range(5)]]
            reject(lambda: branch(rows), case["id"], row["intended_code"])
        elif fault == "aggregate-byte-bound":
            rows = [[((tool, index), 100 * 1024 * 1024) for index in range(2)]
                    for tool in range(3)]
            reject(lambda: branch(rows), case["id"], row["intended_code"])
        elif fault == "cross-role-alias":
            ops = FsOps({"id": "stable", "expect": "accept"})
            first = closure._resolve_tool(ops, "python3-parser", "/usr/bin/python3")
            conflicting = dataclasses.replace(first.executable, role="loader")
            second = closure.ResolvedToolClosure("zstd", first.loader, conflicting, first.libraries)
            reject(lambda: branch((first, second)), case["id"], row["intended_code"])
            closure._close_objects(ops, first.objects)
        else:
            raise AssertionError(f"unimplemented closure bound case: {fault}")
        consumed.add(row["id"])
        oracle.add(row["id"])
    if not declared == selected == consumed == oracle:
        raise AssertionError("closure declared/selected/consumed/oracle mismatch")
def dirent(value):
    name = str(value).encode() + b"\0"
    length = (19 + len(name) + 7) & ~7
    return struct.pack("=QqHB", value + 1, 0, length, 0) + name + bytes(length - 19 - len(name))
class DescriptorOps(FsOps):
    """Filesystem plus process adapter for the complete descriptor owner."""
    def __init__(self, kernel=None):
        super().__init__({"id": "descriptor", "expect": "accept"})
        self.fds.update({0: "stdio", 1: "stdio", 2: "stdio", 50: "ambient"})
        self.dir_read = set()
        self.limit = (1024, 16384)
        self.effects = []
        self.pipe_count = 0
        self.data = {}
        self.child = False
        self.exec_attempted = False
        self.exec_failed = False
        self.kernel = kernel or {"channels": {name: bytearray() for name in ("source", "status", "release")},
                                 "clone_fds": None, "child_fds": None,
                                 "child_created": False, "child_exited": False,
                                 "child_reaped": False, "child_status": None,
                                 "child_branch_started": False, "child_release": None, "release_succeeded": False}
    def architecture_gate(self): self.effects.append("architecture")
    def _allocate(self, kind, preferred=None):
        fd = preferred
        if fd is None:
            while self.next_fd in self.fds:
                self.next_fd += 1
            fd = self.next_fd
            self.next_fd += 1
        self.fds[fd] = kind
        return fd
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        if path in ("/proc/self/fd", "/proc/123/fd"): return self._allocate(path)
        if path == "/proc/thread-self/children": return self._allocate("children")
        if path == "/proc/123/stat":
            fd = self._allocate("proc-stat")
            fields = b" ".join([b"1"] * 19 + [b"10"] + [b"1"] * 8)
            self.data[fd] = b"123 (held-python) S " + fields + b"\n"
            return fd
        if path == "/proc/123/exe": return self._allocate("proc-exe")
        return super().open(path, flags, mode, dir_fd=dir_fd)
    def close(self, fd):
        if fd not in self.fds: raise AssertionError("descriptor operation double close")
        self.closed.append(fd)
        del self.fds[fd]
        self.data.pop(fd, None)
    def getdents(self, fd, maximum=32768):
        del maximum
        if fd in self.dir_read: return b""
        self.dir_read.add(fd)
        if self.fds[fd] == "/proc/123/fd":
            child_fds = self.kernel["child_fds"]
            if child_fds is None:
                raise AssertionError("parent observed child fds before modeled exec")
            values = tuple(sorted(child_fds))
        elif self.child and self.exec_attempted:
            values = (*self.baseline_fds, fd)
        else:
            values = tuple(sorted(self.fds))
        return b"".join(dirent(value) for value in values)
    def read(self, fd, size):
        kind = self.fds.get(fd, "")
        if kind.endswith("-read") and kind.split("-", 1)[0] in self.kernel["channels"]:
            channel = self.kernel["channels"][kind.split("-", 1)[0]]
            value = bytes(channel[:size])
            del channel[:len(value)]
            return value
        value = self.data.get(fd, b"")[:size]
        self.data[fd] = self.data.get(fd, b"")[len(value):]
        return value
    def write(self, fd, data):
        kind = self.fds.get(fd, "")
        if kind.endswith("-write") and kind.split("-", 1)[0] in self.kernel["channels"]:
            self.kernel["channels"][kind.split("-", 1)[0]].extend(data)
        if kind == "release-write" and data == b"G" and type(self) is DescriptorOps:
            self.kernel["channels"]["status"].extend(b"R")
            self.kernel["child_fds"] = {number: self.fds.get(number, "child") for number in (0, 1, 2, 197, 4096)}
        if kind == "source-write" and data == b"G":
            self.kernel["child_exited"] = True
            self.kernel["child_status"] = ("exit", 0)
        return len(data)
    def fstat(self, fd):
        if fd not in self.fds: raise OSError(9, "closed")
        kind = self.fds[fd]
        if type(kind) is str and kind.startswith("/") and kind not in {"/proc/self/fd", "/proc/123/fd"}: return super().fstat(fd)
        inode = 100 if kind == "proc-exe" else fd
        return SimpleNamespace(st_dev=8, st_ino=inode, st_size=0, st_mtime_ns=1,
                               st_ctime_ns=1, st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0)
    def getrlimit(self): return self.limit
    def setrlimit(self, value): self.limit = value
    def pipe(self):
        purpose = ("source", "status", "release")[self.pipe_count]
        self.pipe_count += 1
        return self._allocate(purpose + "-read"), self._allocate(purpose + "-write")
    def clone3_pidfd(self):
        self.baseline_fds = (0, 1, 2, 50)
        if self.child:
            if self.kernel["clone_fds"] is not None:
                self.fds = dict(self.kernel["clone_fds"])
            return 0, -1
        self.kernel["clone_fds"] = dict(self.fds)
        self.kernel["child_created"] = True
        return 123, self._allocate("pidfd")
    def dup2(self, source, target, inheritable=True):
        self.fds[target] = self.fds[source]
    def getsid(self, pid): return 77
    def getpgid(self, pid): return 77
    def getuid(self): return 0
    def poll_readable(self, fd, seconds):
        del seconds
        return self.fds.get(fd) == "status-read" and (
            bool(self.kernel["channels"]["status"]) or self.kernel["child_exited"]
        )
    def wait_pidfd_nohang(self, fd): return self.fds[fd] == "pidfd" and self.kernel["child_exited"]
    def waitid_pidfd_nohang(self, fd):
        if self.fds[fd] != "pidfd": raise AssertionError("waitid without pidfd")
        self.effects.append("C:waitid")
        terminal = self.kernel["child_status"]
        if not self.kernel["child_exited"] or terminal is None:
            return None
        kind, status = terminal
        code = os.CLD_EXITED if kind == "exit" else os.CLD_KILLED
        return SimpleNamespace(si_pid=123, si_uid=0, si_code=code, si_status=status)
    def reap_pid_nohang(self, pid):
        self.effects.append("C:waitpid")
        if not self.kernel["child_exited"] or self.kernel["child_status"] is None:
            return 0, 0
        self.kernel["child_reaped"] = True
        kind, status = self.kernel["child_status"]
        wait_status = status << 8 if kind == "exit" else status
        return pid, wait_status
    def monotonic(self): return 0.0
    def sleep(self, seconds): pass
    def pidfd_signal(self, fd, signum): pass
    def execve(self, fd, argv, environment):
        del fd, argv, environment
        self.exec_attempted = True
        raise ChildExec()
    def exit_child(self, status):
        if self.exec_attempted and not self.exec_failed: raise ChildExec()
        raise ChildReject(status)
    def fcntl(self, fd, command, argument=0):
        if fd not in self.fds:
            raise OSError(9, "closed")
        if command in (getattr(__import__("fcntl"), "F_DUPFD_CLOEXEC"),
                       getattr(__import__("fcntl"), "F_DUPFD")):
            kind = "low" if command == __import__("fcntl").F_DUPFD_CLOEXEC else "high"
            return self._allocate(kind, argument)
        if command == closure._F_GETFD:
            return closure._FD_CLOEXEC if self.fds[fd] == "low" else 0
        raise AssertionError(command)
    def close_range(self, first, last):
        self.effects.append(("close_range", first, last))
        for fd in tuple(self.fds):
            if first <= fd <= last:
                del self.fds[fd]

class DescriptorAdmission:
    revision = "0" * 40
    source_set_sha256 = "1" * 64
    used = False
    def _consume_fixed_operation(self, operation, module):
        del module
        if self.used or operation != "descriptor":
            return False
        self.used = True
        return True
def descriptor_owner_matrix():
    admission = DescriptorAdmission()
    ops = DescriptorOps()
    result = closure._qualify_fixed_descriptor_primitives_with_ops(admission, ops)
    facts = dataclasses.asdict(result)
    if result.version != "cogs.runtime-descriptor-qualification/v1":
        raise AssertionError("descriptor result version")
    if not all(value is True for name, value in facts.items() if name not in {
        "version", "source_revision", "source_set_sha256"
    }):
        raise AssertionError(f"descriptor owner observation failed: {facts}")
    if ("close_range", 4096, 4096) not in ops.effects or ops.limit != (1024, 16384):
        raise AssertionError("descriptor operation bypassed production primitive/restoration")
    before = list(ops.effects)
    reject(lambda: closure._qualify_fixed_descriptor_primitives_with_ops(admission, ops),
           "descriptor replay")
    if ops.effects != before:
        raise AssertionError("descriptor replay reached an effect")
class ChildExec(BaseException): pass
class ChildReject(BaseException): pass


class DescriptorCutOps(DescriptorOps):
    """Drives C through production; modeled child exec causes parent readiness."""
    def __init__(self, row, *, nested_child=False, kernel=None):
        super().__init__(kernel)
        self.row = row
        self.point = row["primitive_fault"]["point"]
        self.mutation = row["primitive_fault"]["mutation"]
        self.sentinel = row["sentinel"]
        self.fired = False
        self.events = []
        self.child = nested_child or self.mutation == "child"
        if self.child and self.kernel["child_release"] is None:
            self.kernel["child_release"] = b"G"
        self.child_exec_proved = False
        self.child_reaped = False
        self.dir_calls = {}
        self.bound_fd = None
        self.limit_reads = 0
        self.limit_sets = 0
        self.foreign = None
        self.clock = 0.0
        self.edge_counts = {}
    def edge(self, name):
        self.edge_counts[name] = self.edge_counts.get(name, 0) + 1
        occurrence = self.row["primitive_fault"].get("occurrence", 1)
        expected_phase = self.row["primitive_fault"].get("phase", self.phase)
        selected = self.point == "edge" and self.mutation == name
        selected = selected and self.phase == expected_phase
        if selected and self.edge_counts[name] == occurrence:
            self.consume_fault("edge", name)
            raise OSError(f"C edge:{name}:{occurrence}")
    def consume_fault(self, point, mutation=None):
        selected = self.point == point and (mutation is None or self.mutation == mutation)
        if selected and not self.fired:
            self.fired = True
            self.events.append(self.sentinel)
            return True
        return False
    def checkpoint(self, name):
        self.phase = name
        self.events.append(f"checkpoint:{name}")
        if self.point == "checkpoint" and self.mutation == name:
            self.consume_fault("checkpoint", name)
            raise RuntimeError(f"fault at {name}")
    def monotonic(self):
        self.clock += 0.1
        return self.clock
    def _dot(self, maximum):
        return struct.pack("=QqHB", 1, 0, maximum, 0) + b".\0" + bytes(maximum - 21)
    def getdents(self, fd, maximum=32768):
        call = self.dir_calls.get(fd, 0) + 1
        self.dir_calls[fd] = call
        if self.point == "edge" and self.mutation == "getdents:final-baseline" and self.kernel["child_reaped"] and self.fds.get(fd) == "/proc/self/fd":
            self.consume_fault("edge", "getdents:final-baseline")
            return b"bad"
        mutation = self.mutation if self.point == "getdents" else None
        if mutation == "unaligned" and not self.fired:
            self.consume_fault("getdents")
            return struct.pack("=QqHB", 1, 0, 21, 0) + b"0\0"
        if mutation == "padding" and not self.fired:
            self.consume_fault("getdents")
            raw = bytearray(dirent(0))
            raw[-1] = 1
            return bytes(raw)
        if mutation in {"call-bound", "first-over-bound", "exact-boundary"}:
            if self.bound_fd is None:
                self.bound_fd = fd
            if fd == self.bound_fd:
                self.consume_fault("getdents")
                nonempty = 32 if mutation == "exact-boundary" else 33
                if call == 1:
                    return b"".join(dirent(value) for value in sorted(self.fds))
                if call <= nonempty:
                    return self._dot(24)
                return b""
        if mutation == "byte-bound":
            self.consume_fault("getdents")
            return self._dot(maximum) if call <= 33 else b""
        if mutation == "entry-bound":
            self.consume_fault("getdents")
            first = (call - 1) * 1300
            if first >= 16_385:
                return b""
            return b"".join(dirent(value) for value in range(first, min(first + 1300, 16_385)))
        if self.fds.get(fd) == "/proc/123/fd" and not self.child_exec_proved:
            raise AssertionError("parent observed post-exec fds without causal child exec")
        return super().getdents(fd, maximum)
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        if path in {"/proc/123/exe", "/proc/123/stat"}:
            self.edge(f"open:{path}")
        return super().open(path, flags, mode, dir_fd=dir_fd)
    def pread(self, fd, size, offset):
        if self.fds.get(fd) == "/usr/bin/python3":
            self.edge("pread:held-python")
        return super().pread(fd, size, offset)
    def fstat(self, fd):
        if self.fds.get(fd) == "proc-exe":
            self.edge("fstat:proc-exe")
        return super().fstat(fd)
    def getsid(self, pid):
        self.edge("getsid:child")
        return super().getsid(pid)
    def getpgid(self, pid):
        self.edge("getpgid:child")
        return super().getpgid(pid)
    def getuid(self):
        self.edge("getuid:wait")
        return super().getuid()
    def getrlimit(self):
        self.limit_reads += 1
        if self.point == "getrlimit" and self.mutation == "normalized-drift" and self.limit_reads == 2:
            self.consume_fault("getrlimit")
            return 8192, self.limit[1]
        if self.point == "getrlimit" and self.mutation == "restore-drift" and self.limit_reads >= 3:
            self.consume_fault("getrlimit")
            return self.limit[0] - 1, self.limit[1]
        return self.limit
    def setrlimit(self, value):
        self.limit_sets += 1
        if self.point == "setrlimit":
            restoring = self.limit_sets > 1
            selected = self.mutation == "restore-before" if restoring else self.mutation == "before"
            if selected:
                self.consume_fault("setrlimit")
                raise OSError("setrlimit")
        self.limit = value
    def pipe(self):
        purpose = ("source", "status", "release")[self.pipe_count]
        if self.point == "pipe" and self.mutation == purpose:
            self.consume_fault("pipe")
            raise OSError(f"{purpose} pipe")
        return super().pipe()
    def fcntl(self, fd, command, argument=0):
        low = command == __import__("fcntl").F_DUPFD_CLOEXEC
        high = command == __import__("fcntl").F_DUPFD
        if self.point == "fcntl" and ((low and self.mutation == "low") or (high and self.mutation == "high")):
            self.consume_fault("fcntl")
            raise OSError("duplicate")
        return super().fcntl(fd, command, argument)
    def clone3_pidfd(self):
        if self.consume_fault("clone3_pidfd"):
            raise OSError("clone3")
        return super().clone3_pidfd()
    def _execute_child_branch(self):
        if self.kernel["child_branch_started"]:
            return
        self.kernel["child_branch_started"] = True
        child_fault = self.point == "execve" or self.mutation.startswith("drop-")
        child_row = self.row if child_fault else {
            "primitive_fault": {"point": "none", "mutation": "child"},
            "sentinel": "C:nested-child-exec",
        }
        child_ops = DescriptorCutOps(child_row, nested_child=True, kernel=self.kernel)
        terminal = None
        try:
            closure._qualify_fixed_descriptor_primitives_with_ops(DescriptorAdmission(), child_ops)
        except (ChildExec, ChildReject) as error:
            terminal = error
        except closure.RuntimeClosureCleanupError as error:
            first = error.failures[0] if error.failures else None
            if type(first) not in (ChildExec, ChildReject):
                raise
            terminal = first
        else:
            raise AssertionError("C modeled fork branch did not reach child terminal state")
        self.events.extend(event for event in child_ops.events if event.startswith("C:"))
        if child_ops.fired:
            self.fired = True
        if type(terminal) is ChildExec and "C:execve-exact" in child_ops.events:
            if self.kernel["child_fds"] is None:
                raise AssertionError(f"C child exec did not publish fd table: {child_ops.fds}")
            self.child_exec_proved = True
            self.events.append("C:execve-causally-proved")
            self.kernel["channels"]["status"].extend(b"R")
        elif type(terminal) is ChildReject:
            self.kernel["channels"]["status"].extend(b"E")
            self.kernel["child_exited"] = True
        else:
            raise AssertionError("C child terminal did not match its production branch")
    def write(self, fd, data):
        release = self.fds.get(fd) == "release-write" and data == b"G"
        if self.point == "write" and self.mutation == "release-short" and release:
            self.consume_fault("write")
            return 0
        if self.point == "edge" and self.mutation == "write:completion" and self.fds.get(fd) == "source-write":
            self.consume_fault("edge", "write:completion")
            return 0
        result = super().write(fd, data)
        if release and result == 1 and not self.child and not self.child_exec_proved:
            self.kernel["child_release"] = b"G"
            self.kernel["release_succeeded"] = True
            self._execute_child_branch()
        return result
    def read(self, fd, size):
        if self.child and self.fds.get(fd) == "release-read":
            value = self.kernel["child_release"]
            return b"" if value is None else value
        status = self.fds.get(fd) == "status-read"
        if self.point == "read" and self.mutation == "status-eof" and status:
            self.consume_fault("read")
            return b""
        if self.point == "read" and self.mutation == "trailing-status" and status and self.kernel["child_exited"]:
            self.consume_fault("read")
            return b"X"
        return super().read(fd, size)
    def poll_readable(self, fd, seconds):
        if self.point == "edge" and self.mutation == "poll:readiness":
            self.consume_fault("edge", "poll:readiness")
            return False
        return super().poll_readable(fd, seconds)
    def execve(self, fd, argv, environment):
        self.exec_attempted = True
        expected = {0, 1, 2, 197, 198, 4096, fd}
        exact_table = set(self.fds) == expected
        exact_table = exact_table and self.fds.get(0) == "source-read"
        exact_table = exact_table and self.fds.get(197) == "status-write"
        exact_fd = self.fds.get(fd) == "/usr/bin/python3"
        exact_argv = argv == closure._descriptor_child_argv()
        exact_environment = environment == {}
        if not exact_table or not exact_fd or not exact_argv or not exact_environment:
            self.exec_failed = True
            raise AssertionError("production C exec descriptor causality changed")
        observer_faults = {"wrong-fd", "wrong-argv", "environment"}
        if self.point == "execve" and self.mutation in observer_faults:
            self.consume_fault("execve")
            self.exec_failed = True
            raise OSError(f"injected exec observer: {self.mutation}")
        self.events.append("C:execve-exact")
        if self.consume_fault("execve"):
            self.exec_failed = True
            raise OSError("execve")
        post_exec = {number: kind for number, kind in self.fds.items() if number not in {198, fd}}
        self.kernel["child_fds"] = post_exec
        raise ChildExec()
    def exit_child(self, status):
        if self.exec_attempted and not self.exec_failed:
            raise ChildExec()
        if self.child and self.kernel["child_status"] is None:
            self.kernel["child_status"] = ("exit", status)
            self.kernel["child_exited"] = True
        raise ChildReject(self.kernel["child_status"][1] if self.child else status)
    def waitid_pidfd_nohang(self, fd):
        if self.point == "edge" and self.mutation == "pidfd_signal:kill":
            return None
        if self.fds.get(fd) != "pidfd":
            raise AssertionError("C waitid did not use retained pidfd")
        self.events.append("C:waitid")
        if self.point == "waitid":
            self.consume_fault("waitid")
            if self.mutation == "none":
                return None
        if not self.kernel["child_exited"] or self.kernel["child_status"] is None:
            return None
        mutation = self.mutation if self.point == "waitid" else ""
        terminal_kind, terminal_status = self.kernel["child_status"]
        natural_code = getattr(os, "CLD_EXITED", 1) if terminal_kind == "exit" else getattr(os, "CLD_KILLED", 2)
        code = 0 if mutation == "wrong-code" else natural_code
        status = terminal_status + 1 if mutation == "wrong-status" else terminal_status
        pid = 999 if mutation == "wrong-pid" else 123
        uid = 999 if mutation == "wrong-uid" else 0
        return SimpleNamespace(si_pid=pid, si_uid=uid, si_code=code, si_status=status)
    def reap_pid_nohang(self, pid):
        self.events.append("C:waitpid")
        if self.point == "waitpid":
            self.consume_fault("waitpid")
            if self.mutation == "wrong-pid":
                return 0, 0
            if self.mutation == "wrong-status":
                self.child_reaped = True
                self.kernel["child_reaped"] = True
                return pid, 1 << 8
        if not self.kernel["child_exited"] or self.kernel["child_status"] is None:
            return 0, 0
        self.child_reaped = True
        self.kernel["child_reaped"] = True
        kind, status = self.kernel["child_status"]
        wait_status = status << 8 if kind == "exit" else status
        return pid, wait_status
    def wait_pidfd_nohang(self, fd):
        self.events.append("C:legacy-wait")
        return super().wait_pidfd_nohang(fd)
    def pidfd_signal(self, fd, signum):
        if self.point == "edge" and self.mutation == "pidfd_signal:kill":
            self.consume_fault("edge", "pidfd_signal:kill")
            raise OSError("C edge:pidfd_signal:kill")
        if self.fds.get(fd) != "pidfd" or signum != signal.SIGKILL:
            raise AssertionError("C cleanup signal lacked exact pidfd/SIGKILL authority")
        self.kernel["child_exited"] = True
        self.kernel["child_status"] = ("signal", signal.SIGKILL)
    def dup2(self, source, target, inheritable=True):
        name = f"drop-dup2:{target}"
        if self.child and self.point == "edge" and self.mutation == name:
            self.consume_fault("edge", name)
            return
        super().dup2(source, target, inheritable)
    def close_range(self, first, last):
        if self.child and self.point == "edge" and self.mutation == "drop-close-complement":
            self.consume_fault("edge", "drop-close-complement")
            return
        if self.point == "close_range" and self.mutation == "before":
            self.consume_fault("close_range")
            raise OSError("close_range before")
        super().close_range(first, last)
        if self.point == "close_range" and self.mutation == "after-reuse":
            self.consume_fault("close_range")
            self.fds[first] = "foreign"
            self.foreign = first
            raise OSError("close_range after reuse")
    def close(self, fd):
        if self.point == "close" and not self.fired:
            self.consume_fault("close")
            if self.mutation == "before":
                raise OSError("close before")
            super().close(fd)
            self.fds[fd] = "foreign"
            self.foreign = fd
            raise OSError("close after reuse")
        kind = self.fds.get(fd)
        super().close(fd)
        if not self.child and kind == "release-write":
            self.kernel["child_release"] = b""
            self._execute_child_branch()
        if not self.child and kind == "source-write" and self.child_exec_proved:
            self.kernel["child_exited"] = True
            self.kernel["child_status"] = ("exit", 0)


def descriptor_cut_corpus():
    path = FIXTURES / "lifecycle/descriptor-cases.jsonl"
    document = [json.loads(line) for line in path.read_text().splitlines()]
    header, *rows = document
    if header["version"] != "cogs.outcome-two-descriptor-owner/v1":
        raise AssertionError("descriptor cut fixture version")
    if set(header["case_fields"]) != ROW_KEYS or any(set(row) != ROW_KEYS for row in rows):
        raise AssertionError("descriptor cut fixture shape")
    identifiers = [row["id"] for row in rows]
    declared = set(identifiers)
    if len(declared) != len(identifiers):
        raise AssertionError("duplicate declared C case")
    selected = set()
    consumed = set()
    oracle = set()
    production = closure._qualify_fixed_descriptor_primitives_with_ops
    for row in rows:
        if row["production_method"] != production.__name__:
            raise AssertionError(f"C production route changed: {row['id']}")
        selected.add(row["id"])
        ops = DescriptorCutOps(row)
        rejection = None
        try:
            result = production(DescriptorAdmission(), ops)
        except ChildExec:
            outcome = "child-exec"
        except ChildReject:
            outcome = "child-reject"
        except closure.RuntimeClosureCleanupError as error:
            first = error.failures[0] if error.failures else None
            if type(first) is ChildExec:
                outcome = "child-exec"
            elif type(first) is ChildReject:
                outcome = "child-reject"
            else:
                outcome = "reject"
                rejection = error
        except (closure.RuntimeClosureError, OSError, RuntimeError) as error:
            outcome = "reject"
            rejection = error
        else:
            outcome = "accept"
            facts = dataclasses.asdict(result)
            metadata = {"version", "source_revision", "source_set_sha256"}
            if not all(value is True for name, value in facts.items() if name not in metadata):
                raise AssertionError(f"C completed with a false fact: {row['id']}")
        if outcome != row["intended_code"]:
            failures = getattr(rejection, "failures", ())
            detail = repr((rejection, [(type(item).__name__, str(item)) for item in failures]))
            raise AssertionError(
                f"{row['id']}: expected {row['intended_code']}, got {outcome}: {detail}"
            )
        faulted = row["primitive_fault"]["point"] != "none"
        if faulted and (not ops.fired or row["sentinel"] not in ops.events):
            raise AssertionError(f"C selected fault was not causally consumed: {row['id']}")
        if not faulted:
            if outcome == "accept":
                ops.events.append("C:complete-parent")
            elif outcome == "child-exec":
                ops.events.append("C:exec-fixed-python")
        if row["sentinel"] not in ops.events:
            raise AssertionError(f"C declared sentinel was not observed: {row['id']}")
        consumed.add(row["id"])
        if outcome == "accept":
            required = {"C:execve-causally-proved", "C:waitid", "C:waitpid"}
            if not required <= set(ops.events) or not ops.child_reaped:
                raise AssertionError("C accepted without causal exec/waitid/reap")
        if outcome == "child-exec" and "C:execve-exact" not in ops.events:
            raise AssertionError("C child accepted without exact held-Python exec")
        if "limits" in row["cleanup_domains"] and ops.limit != (1024, 16384):
            restore_fault = row["primitive_fault"] in (
                {"point": "setrlimit", "mutation": "restore-before"},
                {"point": "getrlimit", "mutation": "restore-drift"},
            )
            if not restore_fault:
                raise AssertionError(f"C limit baseline was not restored: {row['id']}")
        if "descriptors" in row["cleanup_domains"]:
            if len(ops.closed) != len(set(ops.closed)):
                raise AssertionError(f"C retried a descriptor close: {row['id']}")
            settled = outcome == "child-exec" or set(ops.fds) == {0, 1, 2, 50}
            allowed_uncertainty = row["primitive_fault"]["point"] in {"close", "close_range"}
            allowed_uncertainty = allowed_uncertainty or row["primitive_fault"]["mutation"] in {"none", "wrong-pid", "pidfd_signal:kill"}
            if not settled and (outcome != "reject" or not allowed_uncertainty):
                raise AssertionError(f"C descriptor uncertainty was not declared: {row['id']} {ops.fds}")
        exact_terminal = ops.kernel["child_exited"] and ops.kernel["child_status"] is not None
        if ops.kernel["child_reaped"] and not exact_terminal:
            raise AssertionError(f"C fabricated reap without exact terminal status: {row['id']}")
        gated = ops.kernel["child_created"] and not ops.kernel["release_succeeded"]
        if gated and row["primitive_fault"]["point"] not in {"close", "close_range"}:
            assert ops.kernel["child_status"] == ("exit", 125), f"C gated child did not exit on gate EOF: {row['id']}"
        if ops.kernel["child_created"] and not ops.kernel["child_reaped"]:
            retained = any(kind == "pidfd" for kind in ops.fds.values())
            allowed = row["primitive_fault"]["mutation"] in {"none", "wrong-pid", "pidfd_signal:kill"}
            if not allowed or outcome != "reject" or not retained or not isinstance(rejection, closure.RuntimeClosureCleanupError):
                raise AssertionError(f"C child uncertainty lost authority: {row['id']}")
        if ops.foreign is not None and ops.fds.get(ops.foreign) != "foreign":
            raise AssertionError("C cleanup deleted a reused descriptor")
        diagnostic = {
            "call-bound": "descriptor enumeration call bound before EOF",
            "first-over-bound": "descriptor enumeration call bound before EOF",
            # 32 * the per-call maximum equals the aggregate byte cap; the
            # next byte is necessarily the separately checked non-empty EOF.
            "byte-bound": "descriptor enumeration call bound before EOF",
            "entry-bound": "descriptor baseline bound",
        }.get(row["primitive_fault"]["mutation"])
        failures = getattr(rejection, "failures", ())
        messages = [str(rejection), *(str(item) for item in failures)]
        if diagnostic is not None and not any(message == diagnostic for message in messages):
            raise AssertionError(f"C named bound missed its production diagnostic: {row['id']} {messages}")
        oracle.add(row["id"])
    if not declared == selected == consumed == oracle:
        raise AssertionError("C declared/selected/consumed/oracle mismatch")


parser_matrix()
closure_matrix()
descriptor_owner_matrix()
descriptor_cut_corpus()
print("Outcome 2 runtime closure portable tests passed")
