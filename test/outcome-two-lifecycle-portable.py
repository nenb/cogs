#!/usr/bin/env python3
"""Portable hostile descriptor, helper, and owner lifecycle qualification."""

import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import stat
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
MATRIX = json.loads((FIXTURES / "lifecycle/faults.json").read_text())
RAW = (FIXTURES / "elf/valid-executable.elf").read_bytes()


class ChildExit(BaseException):
    pass


def rejected(call, label):
    try:
        call()
    except (closure.RuntimeClosureError, OSError, ChildExit):
        return
    raise AssertionError(f"lifecycle fault accepted: {label}")


class AuthOps(closure._Ops):
    def __init__(self, fail_open):
        self.fail_open = fail_open
        self.opens = 0
        self.next_fd = 10
        self.live = {}
        self.dirs = {"/", "/usr", "/usr/bin"}

    def _path(self, path, dir_fd=None):
        if path.startswith("/"): return os.path.normpath(path)
        return os.path.normpath(self.live[dir_fd].rstrip("/") + "/" + path)

    def _stat(self, path):
        if path not in self.dirs and path != "/usr/bin/python3": raise FileNotFoundError(path)
        directory = path in self.dirs
        return SimpleNamespace(st_dev=8, st_ino=hash(path) & 0xffff,
            st_size=0 if directory else len(RAW), st_mtime_ns=1, st_ctime_ns=1,
            st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o755),
            st_uid=0, st_gid=0)

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode
        self.opens += 1
        if self.opens == self.fail_open: raise OSError(errno.EMFILE, "injected open exhaustion")
        full = self._path(path, dir_fd)
        self._stat(full)
        fd = self.next_fd; self.next_fd += 1; self.live[fd] = full
        return fd

    def stat(self, path, *, dir_fd, follow_symlinks):
        del follow_symlinks
        return self._stat(self._path(path, dir_fd))

    def fstat(self, fd): return self._stat(self.live[fd])
    def pread(self, fd, size, offset): return RAW[offset:offset + size]
    def close(self, fd):
        assert fd in self.live, "authentication double close"
        del self.live[fd]


for open_number in MATRIX["authentication_open_numbers"]:
    ops = AuthOps(open_number)
    rejected(lambda ops=ops: closure._authenticate(ops, "/usr/bin/python3", "executable"),
             f"authenticate open {open_number}")
    assert not ops.live, f"fd residue at open {open_number}"


GENERATION = closure.SourceGeneration(8, 101, len(RAW), 1, 1, stat.S_IFREG | 0o755, 0, 0)
OBJECT = closure.AuthenticatedObject(
    "executable", "/usr/bin/python3", 900, GENERATION, len(RAW),
    hashlib.sha256(RAW).hexdigest(), elf.parse_elf64(RAW),
)
RESOLVED = closure.ResolvedToolClosure("python3-parser", OBJECT, OBJECT, ())
STAT_ROW = b"123 (helper) " + b" ".join([b"S"] + [b"1"] * 19)


class ProcessOps(closure._Ops):
    def __init__(self, fault=None, child=False):
        self.fault = fault
        self.child = child
        self.next_fd = 20
        self.live = {}
        self.positions = {}
        self.pipe_calls = 0
        self.signals = []
        self.wait_calls = 0
        self.exec_called = False
        self.writes = []
        self.clock = 0.0

    def _new(self, kind, content=b""):
        fd = self.next_fd; self.next_fd += 1
        self.live[fd] = (kind, content); self.positions[fd] = 0
        return fd

    def pipe(self):
        self.pipe_calls += 1
        if self.fault == ("gate-pipe" if self.pipe_calls == 1 else "status-pipe"):
            raise OSError(errno.EMFILE, "pipe exhaustion")
        return self._new("pipe-r"), self._new("pipe-w")

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        if path == "/dev/null":
            if self.fault == "devnull-open": raise OSError(errno.EMFILE, "devnull exhaustion")
            return self._new("devnull")
        if path.endswith("/stat"):
            if self.fault in {"proc-stat-open", "identity-stat-open"}:
                raise OSError(errno.EMFILE, "proc exhaustion")
            return self._new("stat", STAT_ROW)
        if path.endswith("/children"):
            if self.fault == "children-open": raise OSError(errno.EMFILE, "children exhaustion")
            return self._new("children", b"")
        if path.endswith("/exe"):
            if self.fault == "identity-exe-open": raise OSError(errno.EMFILE, "exe exhaustion")
            return self._new("exe")
        raise AssertionError(path)

    def close(self, fd):
        assert fd in self.live, f"helper double close: {fd}"
        del self.live[fd]

    def fork(self):
        if self.fault == "fork": raise OSError("fork fault")
        return 0 if self.child else 123

    def pidfd_open(self, pid):
        assert pid == 123
        if self.fault == "pidfd-open": raise OSError(errno.EMFILE, "pidfd exhaustion")
        return self._new("pidfd")

    def poll_readable(self, fd, seconds):
        del fd, seconds
        return self.fault != "exec-status-poll"

    def read(self, fd, size):
        if self.fault == "exec-status-read": raise OSError("status read fault")
        if self.fault == "proc-stat-read" and self.live[fd][0] == "stat": raise OSError("stat read fault")
        kind, raw = self.live[fd]; offset = self.positions[fd]
        self.positions[fd] += min(size, len(raw) - offset)
        return raw[offset:offset + size]

    def getsid(self, pid):
        if self.fault == "session-read": raise OSError("session fault")
        return pid
    def getpgid(self, pid): return pid
    def kill(self, pid, signum): self.signals.append((pid, signum))
    def waitpid(self, pid, options):
        self.wait_calls += 1
        if self.fault == "wait": raise OSError("wait fault")
        if self.fault in {"kill", "reap"}: return (0, 0)
        return (pid, 0)
    def fstat(self, fd):
        if self.live[fd][0] == "exe":
            return SimpleNamespace(st_dev=8, st_ino=101)
        raise AssertionError("unexpected helper fstat")
    def pidfd_signal(self, pidfd, signum):
        assert self.live[pidfd][0] == "pidfd"
        self.signals.append((pidfd, signum))
        if self.fault == "term" and signum == signal.SIGTERM: raise OSError("term fault")
        if self.fault == "kill" and signum == signal.SIGKILL: raise OSError("kill fault")
    def monotonic(self): self.clock += 0.6; return self.clock
    def setsid(self):
        if self.fault == "child-setup": raise OSError("setsid fault")
    def getppid(self): return os.getpid()
    def dup2(self, source, target): del source, target
    def execve(self, fd, argv, environment):
        del fd, argv, environment
        self.exec_called = True
        raise OSError("exec fault") if self.fault == "child-exec" else ChildExit()
    def write(self, fd, data): self.writes.append((fd, data)); return len(data)
    def exit_child(self, status):
        self.live.clear()
        raise ChildExit(status)


for fault in MATRIX["helper_start_faults"]:
    ops = ProcessOps(fault)
    rejected(lambda ops=ops: closure._spawn_helper(ops, RESOLVED), fault)
    assert not ops.live and (fault in {"gate-pipe", "status-pipe", "devnull-open", "fork"} or ops.wait_calls)


class Libc:
    def prctl(self, *args): del args; return 0


for fault in MATRIX["child_faults"]:
    ops = ProcessOps(fault, child=True)
    with patch.object(closure.ctypes, "CDLL", return_value=Libc()):
        rejected(lambda ops=ops: closure._spawn_helper(ops, RESOLVED), fault)
    assert not ops.live and ops.writes and ops.writes[-1][1] == b"E"
    assert ops.exec_called == (fault == "child-exec")


def started_ops(fault=None):
    ops = ProcessOps(fault)
    child, gate = closure._spawn_helper(ops, RESOLVED)
    assert set(kind for kind, _raw in ops.live.values()) == {"pipe-w", "pidfd"}
    return ops, child, gate


ops, child, gate = started_ops()
closure._stop_helper(ops, child, gate)
assert child.reaped and not ops.live
for fault in MATRIX["stop_faults"]:
    ops, child, gate = started_ops(fault)
    rejected(lambda ops=ops, child=child, gate=gate: closure._stop_helper(ops, child, gate), fault)
    assert not ops.live, f"stop residue after {fault}"
for fault in MATRIX["stop_open_faults"]:
    ops, child, gate = started_ops()
    ops.fault = fault
    rejected(lambda ops=ops, child=child, gate=gate: closure._stop_helper(ops, child, gate), fault)
    assert not ops.live, f"stop-open residue after {fault}"


class CloseOps(closure._Ops):
    def __init__(self, fail=False): self.live = set(); self.closed = []; self.fail = fail
    def close(self, fd):
        assert fd in self.live, "owner double close"
        self.live.remove(fd); self.closed.append(fd)
        if self.fail: raise OSError(f"close-{fd}")


ops = CloseOps(True); registry = closure._Registry(ops)
for fd in (30, 31, 32): ops.live.add(fd); registry.add(fd)
failures = registry.close_all()
assert len(failures) == 3 and ops.closed == [32, 31, 30] and not ops.live
ops.live.update((30, 31, 32))
try:
    closure._close_local(ops, (30, 31, 32), ValueError("primary"))
except closure.RuntimeClosureCleanupError as error:
    assert len(error.failures) == 4 and isinstance(error.failures[0], ValueError)
else:
    raise AssertionError("primary and cleanup failures were not aggregated")
ops.live.add(32)  # the kernel reused a number after the failed close
assert registry.close_all() == () and ops.live == {32}
rejected(lambda: (registry.add(40), registry.add(40)), "duplicate registration")

ops = CloseOps(); owner = closure.PreparedRuntimeClosure(closure._PRIVATE_CONSTRUCTOR, ops)
owner._state = closure._State.READY; owner._fd_baseline = frozenset(); owner._child_baseline = b""
ops.list_fds = lambda: frozenset(ops.live); ops.child_baseline = lambda: b""
owner.close(); owner.close()
assert not ops.closed and not ops.live

print("Outcome 2 lifecycle portable tests passed")
