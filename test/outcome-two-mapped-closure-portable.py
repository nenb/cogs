#!/usr/bin/env python3
"""Manifest-exact strict maps parsing, binding, bounds, and close aggregation."""

import dataclasses
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import threading
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
    if not values or values[0].get("type") != "header": raise AssertionError("maps ledger header")
    return values[0], values[1:]
HEADER, CASES = load_ledger(FIXTURES / "maps/cases.jsonl")
BEFORE = (FIXTURES / "maps/stable/maps-before.txt").read_bytes()
AFTER = (FIXTURES / "maps/stable/maps-after.txt").read_bytes()
ROW_KEYS = {"id", "production_method", "primitive_fault", "intended_code",
            "cleanup_domains", "sentinel"}


def manifest_cases():
    for row in CASES:
        branch = getattr(closure, row["sentinel"], None)
        if set(row) != ROW_KEYS or row["production_method"] != row["sentinel"] or not callable(branch):
            raise AssertionError("maps manifest row/method")
        case = dict(row["primitive_fault"])
        case["id"] = row["id"]
        case["expect"] = "accept" if row["intended_code"] == "accept" else "reject"
        yield row, case, branch


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
        self.fired = fault is None
        self.events = []
        self.next_fd = 10
        self.fds = {}
        self.positions = {}
        self.map_stats = {}
        self.maps_opened = 0
        self.close_attempts = []

    def consume(self, fault):
        if self.fault == fault:
            self.fired = True
            self.events.append(f"fault:{fault}")
            return True
        return False

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        if path == "/proc/321/maps":
            raw = self.snapshots[min(self.maps_opened, 1)]
            self.maps_opened += 1
            item = ("maps", raw)
        elif "/map_files/" in path:
            if self.consume("map-open-eacces"):
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
            self.consume("maps-read-and-close")
            raise OSError("primary maps read")
        raw = self.fds[fd][1]
        offset = self.positions[fd]
        if self.consume("maps-over-4m"):
            raw = b"x" * (closure._MAX_MAP_BYTES + 1)
        value = raw[offset:offset + size]
        self.positions[fd] += len(value)
        return value

    def pread(self, fd, size, offset):
        raw = self.fds[fd][1]
        value = raw[offset:offset + size]
        if self.fault == "map-parse-and-close" and value:
            self.consume("map-parse-and-close")
            return bytes([value[0] ^ 1]) + value[1:]
        return value

    def fstat(self, fd):
        raw = self.fds[fd][1]
        device_major, inode = self.map_stats[fd]
        device = os.makedev(device_major, 1)
        key = ("fstat", fd)
        count = self.positions.get(key, 0)
        self.positions[key] = count + 1
        changed = self.fault == "fstat-generation-change" and count
        if changed:
            self.consume("fstat-generation-change")
        mtime = 2 if changed else 1
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
    objects = dict(HEADER["objects"])
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
        duplicate = object_("loader", "valid-libalpha.elf", 8, 105)
        resolved = closure.ResolvedToolClosure("python3-parser", EXECUTABLE, duplicate, (ALPHA, BETA))
        objects["7f000000-7f001000"] = {"fixture": "valid-libalpha.elf", "identity": [8, 105]}
        before = before.replace(b"08:01 102", b"08:01 105")
        after = before
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


def run(row, case, branch):
    before, after, objects, resolved, fault = case_inputs(case)
    ops = MapOps(before, after, objects, fault)
    data_faults = {
        "missing-lf", "overlapping-row", "maps-over-4096-lines",
        "two-roles-same-fingerprint", "129-unique-objects",
    }
    if fault in data_faults:
        ops.fired = True
        ops.events.append(f"input:{fault}")
    ops.events.append(f"enter:{branch.__name__}")
    try:
        result = branch(ops, CHILD, resolved)
    except (closure.RuntimeClosureError, closure.RuntimeClosureCleanupError, OSError) as error:
        if case["expect"] != "reject":
            raise
        if type(error).__name__ != row["intended_code"]:
            raise AssertionError(f"{row['id']}: {type(error).__name__}") from error
        if case.get("branch_message") and str(error) != case["branch_message"]:
            raise AssertionError(f"{row['id']}: named branch missed") from error
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
    if fault is not None and not ops.fired:
        raise AssertionError(f"selected map fault was not consumed: {row['id']}")
    if ops.fds:
        raise AssertionError(f"descriptor residue after {case['id']}: {ops.fds}")
    ops.events.append(f"oracle:{row['id']}")
    return ops


class MappingOwnerOps(MapOps):
    """A's complete owner over fixed source, helper, proc, map, and reap syscalls."""
    fixed = {
        "/usr/bin/python3": "valid-executable.elf",
        "/lib64/ld-linux-x86-64.so.2": "valid-loader.elf",
        "/lib/x86_64-linux-gnu/libalpha.so.1": "valid-libalpha.elf",
        "/lib/x86_64-linux-gnu/libbeta.so.1": "valid-libbeta.elf",
    }
    def __init__(self, fault="none", shared=None, child_mode=False):
        super().__init__(BEFORE, AFTER, dict(HEADER["objects"]))
        self.fault, self.child_mode = fault, child_mode
        self.shared = shared or {name: threading.Event() for name in ("registration", "ready", "release", "exec", "failed")}
        self.shared.setdefault("events", [])
        self.shared.setdefault("clone_fds", None)
        self.shared.setdefault("clone_paths", None)
        self.shared.setdefault("thread", None)
        self.source = {
            path: (FIXTURES / "elf" / fixture).read_bytes()
            for path, fixture in self.fixed.items()
        }
        self.source_inodes = {path: 101 + index for index, path in enumerate(self.source)}
        self.paths = {}
        self.dirs = {"/"}
        for path in self.source:
            parent = Path(path).parent
            while str(parent) != ".":
                self.dirs.add(str(parent))
                if str(parent) == "/":
                    break
                parent = parent.parent
        self.dir_reads = set()
        self.pipe_number = 0
        self.status_reads = 0
        self.child_live = False
        self.child_reaped = False
        self.events = self.shared["events"]
        self.next_fd = 10
        self.fds = {0: ("stdio", b""), 1: ("stdio", b""), 2: ("stdio", b""), 50: ("ambient", b"")}
        self.positions = {}
    def architecture_gate(self):
        self.events.append("A:architecture")
    def allocate(self, kind, raw=b""):
        while self.next_fd in self.fds:
            self.next_fd += 1
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = (kind, raw)
        self.positions[fd] = 0
        return fd
    def full_path(self, path, dir_fd):
        if path.startswith("/"):
            return os.path.normpath(path)
        parent = self.paths[dir_fd]
        return os.path.normpath(parent.rstrip("/") + "/" + path)
    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode
        if path == "/proc/self/fd":
            return self.allocate("fd-directory")
        if path == "/proc/thread-self/children" or path.endswith("/children"):
            return self.allocate("proc", b"")
        if path == "/dev/null":
            return self.allocate("devnull")
        if path.endswith("/stat"):
            fields = b" ".join([b"1"] * 19 + [b"10"] + [b"1"] * 8)
            return self.allocate("proc", b"321 (held-python) S " + fields + b"\n")
        if path.endswith("/exe"):
            return self.allocate("proc-exe")
        if path == "/proc/321/maps" or "/map_files/" in path:
            return super().open(path, 0)
        full = self.full_path(path, dir_fd)
        if full not in self.dirs and full not in self.source:
            raise FileNotFoundError(full)
        fd = self.allocate("source" if full in self.source else "directory")
        self.paths[fd] = full
        return fd
    def stat_value(self, path):
        if path not in self.dirs and path not in self.source:
            raise FileNotFoundError(path)
        directory = path in self.dirs
        raw = self.source.get(path, b"")
        inode = self.source_inodes.get(path, abs(hash(path)) & 0xffff)
        mode = stat.S_IFDIR | 0o755 if directory else stat.S_IFREG | 0o755
        return SimpleNamespace(
            st_dev=os.makedev(8, 1), st_ino=inode, st_size=len(raw), st_mtime_ns=1,
            st_ctime_ns=1, st_mode=mode, st_uid=0, st_gid=0,
        )
    def stat(self, path, *, dir_fd, follow_symlinks):
        if follow_symlinks:
            raise AssertionError("A source walker followed a component")
        return self.stat_value(self.full_path(path, dir_fd))
    def fstat(self, fd):
        kind = self.fds[fd][0]
        if kind in {"source", "directory"}:
            return self.stat_value(self.paths[fd])
        if kind == "proc-exe":
            return SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=101)
        if kind == "object":
            raw = self.fds[fd][1]
            major, inode = self.map_stats[fd]
            return SimpleNamespace(
                st_dev=os.makedev(major, 1), st_ino=inode, st_size=len(raw),
                st_mtime_ns=1, st_ctime_ns=1, st_mode=stat.S_IFREG | 0o755,
                st_uid=0, st_gid=0,
            )
        return SimpleNamespace(
            st_dev=1, st_ino=fd, st_size=0, st_mtime_ns=1, st_ctime_ns=1,
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
        )
    def pread(self, fd, size, offset):
        if self.fds[fd][0] == "source":
            raw = self.source[self.paths[fd]]
            return raw[offset:offset + size]
        return super().pread(fd, size, offset)
    def read(self, fd, size):
        kind, raw = self.fds[fd]
        if self.child_mode and kind in {"registration-read", "release-read"}:
            event = self.shared["registration" if kind.startswith("registration") else "release"]
            if not event.wait(1): raise AssertionError(f"A child blocked at {kind}")
            return b"G\n"
        if kind == "status-read":
            self.status_reads += 1
            event = self.shared["ready" if self.status_reads == 1 else ("failed" if self.shared["failed"].is_set() else "exec")]
            if not event.wait(1): raise AssertionError("A child status was not causally published")
            if self.status_reads == 2 and self.shared["failed"].is_set() and self.fault == "none":
                raise AssertionError(f"A child exec model rejected production effects: {self.shared.get('child_error')}")
            return b"R\n" if self.status_reads == 1 else (b"E\n" if self.status_reads == 2 and self.shared["failed"].is_set() else b"")
        offset = self.positions.get(fd, 0)
        value = raw[offset:offset + size]
        self.positions[fd] = offset + len(value)
        return value
    def getdents(self, fd, maximum=32768):
        del maximum
        if fd in self.dir_reads:
            return b""
        self.dir_reads.add(fd)
        return b"".join(
            struct.pack("=QqHB", value + 1, 0, 24, 0)
            + str(value).encode() + b"\0" + bytes(4 - len(str(value)))
            for value in sorted(self.fds)
        )
    def pipe(self):
        purpose = ("input", "registration", "release", "status")[self.pipe_number]
        self.pipe_number += 1
        return self.allocate(purpose + "-read"), self.allocate(purpose + "-write")
    def clone3_pidfd(self):
        if self.child_mode:
            self.fds = dict(self.shared["clone_fds"])
            self.paths = dict(self.shared["clone_paths"])
            return 0, -1
        self.child_live = True
        self.events.append("A:child-atomically-registered")
        self.shared["clone_fds"], self.shared["clone_paths"] = dict(self.fds), dict(self.paths)
        def child():
            child_ops = MappingOwnerOps(self.fault, self.shared, True)
            try: closure._qualify_fixed_python_mapping_with_ops(MappingAdmission(), child_ops)
            except (MappingChildExec, MappingChildReject): pass
            except BaseException as error:
                pending, flattened = [error], []
                while pending:
                    item = pending.pop()
                    flattened.append(item)
                    pending.extend(getattr(item, "failures", ()))
                if not any(type(item) is MappingChildExec for item in flattened):
                    self.shared["child_error"] = [(type(item).__name__, str(item)) for item in flattened]
                    self.shared["failed"].set()
        thread = threading.Thread(target=child, name="portable-A-child")
        self.shared["thread"] = thread
        thread.start()
        return 321, self.allocate("pidfd")
    def getpid(self):
        return 7
    def getsid(self, pid):
        return pid
    def getpgid(self, pid):
        return pid
    def write(self, fd, data):
        kind = self.fds[fd][0]
        if self.child_mode and kind == "status-write":
            if self.shared["exec"].is_set(): raise OSError("status closed by exec")
            self.shared["ready"].set()
        if kind == "registration-write":
            self.events.append("A:registration-release")
            self.shared["registration"].set()
        if kind == "release-write":
            if "A:registration-release" not in self.events:
                raise AssertionError("A helper release preceded registration")
            self.events.append("A:exec-release")
            self.shared["release"].set()
        return len(data)
    def poll_readable(self, fd, seconds):
        if seconds <= 0 or self.fds[fd][0] != "status-read": return False
        event = self.shared["ready" if self.status_reads == 0 else ("failed" if self.shared["failed"].is_set() else "exec")]
        return event.wait(1)
    def monotonic(self):
        return len(self.events) / 100
    def sleep(self, seconds):
        del seconds
    def wait_pidfd_nohang(self, fd):
        if self.fds[fd][0] != "pidfd":
            raise AssertionError("A reap did not use pidfd authority")
        thread = self.shared["thread"]
        if thread is not None:
            thread.join(1)
            if thread.is_alive(): return False
        self.child_live = False
        self.child_reaped = True
        self.events.append("A:pidfd-reap")
        return True
    def setsid(self): return 321
    def set_parent_death_signal(self, signum): del signum
    def getppid(self): return 7
    def dup2(self, source, target, inheritable=True):
        if not (self.child_mode and self.fault == f"drop-dup2:{target}"):
            self.fds[target] = self.fds[source]
    def close_range(self, first, last):
        if self.child_mode and self.fault == "drop-close-complement": return
        for fd in tuple(self.fds):
            if first <= fd <= last: self.fds.pop(fd)
    def execve(self, fd, argv, environment):
        release = [number for number, value in self.fds.items() if value[0] == "release-read"]
        status = [number for number, value in self.fds.items() if value[0] == "status-write"]
        exact = self.fds.get(0, (None,))[0] == "input-read" and len(release) == len(status) == 1
        exact = exact and set(self.fds) == {0, 1, 2, fd, release[0], status[0]}
        exact = exact and argv == closure._child_argv("python3-parser") and environment == {}
        if not exact or self.fault == "execve":
            self.events.append(f"A:edge:{self.fault}")
            self.shared["exec_failure"] = (dict(self.fds), fd, argv, environment)
            self.shared["failed"].set()
            raise OSError("A child exec edge")
        self.events.append("A:production-child-exec")
        self.shared["exec"].set()
        raise MappingChildExec()
    def exit_child(self, status):
        if self.shared["exec"].is_set(): raise MappingChildExec()
        self.shared["exit_failure"] = (status, dict(self.fds))
        self.shared["failed"].set()
        raise MappingChildReject()
    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("A owner double-closed a descriptor")
        kind = self.fds.pop(fd)[0]
        self.paths.pop(fd, None)
        self.positions.pop(fd, None)
        self.events.append(f"A:close:{kind}")


class MappingChildExec(BaseException): pass
class MappingChildReject(BaseException): pass


class MappingAdmission:
    revision = "0" * 40
    source_set_sha256 = "1" * 64
    used = False
    def _consume_fixed_operation(self, operation, module):
        if self.used or operation != "mapping" or module is not closure:
            return False
        self.used = True
        return True


def mapping_owner_success():
    document = [json.loads(line) for line in (FIXTURES / "maps/owner-cases.jsonl").read_text().splitlines()]
    owner_header, *rows = document
    if owner_header["version"] != "cogs.outcome-two-mapping-owner/v1" or any(set(row) != ROW_KEYS for row in rows):
        raise AssertionError("A owner ledger shape/version")
    identifiers = [row["id"] for row in rows]
    declared, selected, consumed, oracle = set(identifiers), set(), set(), set()
    if len(declared) != len(identifiers): raise AssertionError("A owner duplicate case")
    production = closure._qualify_fixed_python_mapping_with_ops
    for row in rows:
        if row["production_method"] != production.__name__: raise AssertionError("A production method changed")
        selected.add(row["id"])
        fault = row["primitive_fault"]["mutation"]
        ops = MappingOwnerOps(fault)
        try: result = production(MappingAdmission(), ops)
        except (closure.RuntimeClosureError, closure.RuntimeClosureCleanupError) as error:
            if row["intended_code"] != type(error).__name__: raise AssertionError(f"{row['id']}: {type(error).__name__}") from error
        else:
            if row["intended_code"] != "accept": raise AssertionError(f"A edge deletion accepted: {row['id']}")
            facts = dataclasses.asdict(result)
            metadata = {"version", "source_revision", "source_set_sha256", "closure_sha256", "mapping_sha256", "objects", "mapped", "mapped_objects"}
            if not all(value is True for name, value in facts.items() if name not in metadata): raise AssertionError("A owner emitted false fact")
        causal = ["A:child-atomically-registered", "A:registration-release", "A:exec-release", "A:pidfd-reap"]
        positions = [ops.events.index(event) for event in causal if event in ops.events]
        if len(positions) != len(causal) or positions != sorted(positions) or ops.child_live or not ops.child_reaped:
            raise AssertionError(f"A child registration/reap settlement changed: {row['id']}")
        if set(ops.fds) != {0, 1, 2, 50}: raise AssertionError(f"A descriptor residue: {row['id']}")
        if row["sentinel"] not in ops.events: raise AssertionError(f"A causal sentinel missed: {row['id']}")
        consumed.add(row["id"])
        if fault == "complete" and "A:production-child-exec" not in ops.events: raise AssertionError("A production child branch missed")
        if fault != "complete" and "exec_failure" not in ops.shared: raise AssertionError("A edge oracle was nominal")
        oracle.add(row["id"])
    if not declared == selected == consumed == oracle: raise AssertionError("A owner ledger mismatch")


def mapping_owner_admission_contract():
    events = []
    class Replayed:
        revision = "0" * 40
        source_set_sha256 = "1" * 64
        def _consume_fixed_operation(self, operation, module):
            events.append((operation, module.__name__))
            return False
    class NoEffects(closure._Ops):
        def architecture_gate(self):
            raise AssertionError("mapping replay reached architecture")
    try:
        closure._qualify_fixed_python_mapping_with_ops(Replayed(), NoEffects())
    except closure.RuntimeClosureError:
        pass
    else:
        raise AssertionError("mapping replay admission accepted")
    if events != [("mapping", closure.__name__)]:
        raise AssertionError("mapping operation was not exactly bound")
    source = (ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py").read_text()
    owner = source[source.index("def _qualify_fixed_python_mapping_with_ops"):source.index("def _qualify_fixed_descriptor_primitives_with_ops")]
    required = ("PreparedRuntimeClosure._for_fixed_mapping", "_resolve_tool(",
                "_spawn_helper(", "_mapped_closure(", "_stop_helper(")
    if not all(token in owner for token in required):
        raise AssertionError("mapping owner branch removal sentinel")
    launcher_source = (ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py").read_text()
    if "_MappingAuthority" in launcher_source or "_coordinate_admitted_mapping_only" in launcher_source:
        raise AssertionError("launcher retains private mapping coordinator")


def parent():
    mapping_owner_admission_contract()
    mapping_owner_success()
    manifest = list(manifest_cases())
    identifiers = [row["id"] for row, _case, _branch in manifest]
    declared = set(identifiers)
    if len(declared) != len(identifiers):
        raise AssertionError("duplicate declared maps case")
    selected = set()
    consumed = set()
    oracle = set()
    for row, case, branch in manifest:
        selected.add(row["id"])
        ops = run(row, case, branch)
        if f"enter:{row['sentinel']}" not in ops.events:
            raise AssertionError(f"maps production sentinel missed: {row['id']}")
        consumed.add(row["id"])
        if f"oracle:{row['id']}" not in ops.events:
            raise AssertionError(f"maps oracle missed: {row['id']}")
        oracle.add(row["id"])
    if not declared == selected == consumed == oracle:
        raise AssertionError("maps declared/selected/consumed/oracle mismatch")
    print("Outcome 2 mapped closure portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()
