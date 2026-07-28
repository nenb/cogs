#!/usr/bin/env python3
"""Exhaustive portable ELF, component, alias, race, and closure-bound matrix."""
import dataclasses
import hashlib, importlib, json, os
from pathlib import Path
import stat, struct, sys
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
    selected = list(manifest_cases())
    executed = []
    for row, case, branch in selected:
        if case.get("fault") in {"object-bound", "tool-byte-bound", "aggregate-byte-bound", "cross-role-alias"}:
            continue
        executed.append(row["id"])
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
        if ops.fds: raise AssertionError(f"descriptor residue: {case['id']}")
    bound_cases = [(row, case, branch) for row, case, branch in selected if row["id"] not in executed]
    for row, case, branch in bound_cases:
        executed.append(row["id"])
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
    declared = [row["id"] for row, _case, _branch in selected]
    if declared != executed or len(executed) != len(set(executed)):
        raise AssertionError("closure selected/consumed/oracle/sentinel mismatch")
def dirent(value):
    name = str(value).encode() + b"\0"
    length = (19 + len(name) + 7) & ~7
    return struct.pack("=QqHB", value + 1, 0, length, 0) + name + bytes(length - 19 - len(name))
class DescriptorOps(closure._Ops):
    def __init__(self):
        self.fds = {0: "stdio", 1: "stdio", 2: "stdio", 50: "ambient"}
        self.next_fd = 10
        self.dir_read = set()
        self.limit = (1024, 16384)
        self.effects = []
        self.pipe_count = 0
        self.data = {}
    def architecture_gate(self):
        self.effects.append("architecture")
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
        del flags, mode, dir_fd
        if path == "/proc/self/fd":
            return self._allocate("directory")
        if path == "/proc/self/task/self/children":
            return self._allocate("children")
        raise AssertionError(path)
    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("descriptor operation double close")
        del self.fds[fd]
    def getdents(self, fd, maximum=32768):
        del maximum
        if fd in self.dir_read:
            return b""
        self.dir_read.add(fd)
        return b"".join(dirent(value) for value in sorted(self.fds))
    def read(self, fd, size):
        value = self.data.get(fd, b"")[:size]
        self.data[fd] = self.data.get(fd, b"")[len(value):]
        return value
    def write(self, fd, data):
        del fd
        if data == b"G":
            target = next(number for number, kind in self.fds.items() if kind == "status-read")
            self.data[target] = b"exact"
        return len(data)
    def fstat(self, fd):
        if fd not in self.fds:
            raise OSError(9, "closed")
        return SimpleNamespace(st_dev=1, st_ino=fd, st_size=0, st_mtime_ns=1,
                               st_ctime_ns=1, st_mode=stat.S_IFREG | 0o600,
                               st_uid=0, st_gid=0)
    def getrlimit(self):
        return self.limit
    def setrlimit(self, value):
        self.limit = value
    def pipe(self):
        self.pipe_count += 1
        purpose = "status" if self.pipe_count == 2 else "pipe"
        return self._allocate(purpose + "-read"), self._allocate(purpose + "-write")
    def clone3_pidfd(self):
        return 123, self._allocate("pidfd")
    def wait_pidfd_nohang(self, fd):
        return self.fds[fd] == "pidfd"
    def monotonic(self):
        return 0.0
    def sleep(self, seconds):
        del seconds
    def pidfd_signal(self, fd, signum):
        del fd, signum
    def fcntl(self, fd, command, argument=0):
        if fd not in self.fds:
            raise OSError(9, "closed")
        if command in (getattr(__import__("fcntl"), "F_DUPFD_CLOEXEC"),
                       getattr(__import__("fcntl"), "F_DUPFD")):
            return self._allocate("low" if command == __import__("fcntl").F_DUPFD_CLOEXEC else "high", argument)
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
parser_matrix()
closure_matrix()
descriptor_owner_matrix()
print("Outcome 2 runtime closure portable tests passed")
