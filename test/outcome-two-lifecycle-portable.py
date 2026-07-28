#!/usr/bin/env python3
"""Production lifecycle state machines over an independent deterministic kernel model."""

import errno
import hashlib
import importlib
import json
from pathlib import Path
import signal
import stat
import struct
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
launcher = importlib.import_module("completion_trusted_runtime_launcher")
MATRIX = json.loads((FIXTURES / "lifecycle/faults.json").read_text())
RAW = (FIXTURES / "elf/valid-executable.elf").read_bytes()
GENERATION = closure.SourceGeneration(8, 101, len(RAW), 1, 1, stat.S_IFREG | 0o755, 0, 0)
OBJECT = closure.AuthenticatedObject(
    "executable", "/usr/bin/python3", 900, GENERATION, (), len(RAW),
    hashlib.sha256(RAW).hexdigest(), elf.parse_elf64(RAW),
)
RESOLVED = closure.ResolvedToolClosure("python3-parser", OBJECT, OBJECT, ())
def stat_row(start=10):
    return b"123 (fixed helper) S " + b" ".join([b"1"] * 18 + [str(start).encode()]) + b"\n"


def dirent(name):
    raw_name = str(name).encode() + b"\0"
    length = 19 + len(raw_name)
    aligned = (length + 7) & ~7
    return struct.pack("=QqHB", 1, 0, aligned, 0) + raw_name + b"\0" * (aligned - length)


class Process:
    def __init__(self):
        self.live = True
        self.reaped = False
        self.start = 10
        self.session = 123
        self.group = 123
        self.executable = (8, 101)
        self.children = ()
        self.signals = []


class KernelOps(closure._Ops):
    """Fd objects, pidfds, processes, clocks, and owner leases are independent."""
    def __init__(self, fault=None):
        self.fault = fault
        self.next_fd = 10
        self.fds = {0: "stdio", 1: "stdio", 2: "stdio", 88: "ambient"}
        self.fd_data = {}
        self.positions = {}
        self.processes = {}
        self.pidfds = {}
        self.close_attempts = []
        self.clock = 0.0
        self.pipe_count = 0
        self.status_reads = 0
        self.children_reads = 0
        self.dir_reads = 0
        self.enumerator_round = 0
        self.close_ranges = []
        self.preparation = None
        self.preregistration_observed = False
        self.release_observed = False
        if fault in {"closed-stdin", "closed-stdout", "closed-stderr"}:
            self.fds.pop({"closed-stdin": 0, "closed-stdout": 1, "closed-stderr": 2}[fault])

    def allocate(self, kind, data=b"", preferred=None):
        if preferred is None:
            while self.next_fd in self.fds:
                self.next_fd += 1
            fd = self.next_fd
            self.next_fd += 1
        else:
            fd = preferred
        self.fds[fd] = kind
        self.fd_data[fd] = data
        self.positions[fd] = 0
        return fd

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        del flags, mode, dir_fd
        if path == "/proc/self/fd":
            if self.fault == "fd-dir-open":
                raise OSError(errno.EMFILE, "fd directory")
            preferred = 20 + self.enumerator_round if self.fault == "enumerator-reuse" else None
            self.enumerator_round += 1
            return self.allocate("fd-directory", preferred=preferred)
        if path == "/dev/null":
            if self.fault == "devnull-open":
                raise OSError(errno.EMFILE, "devnull")
            for candidate in range(3):
                if candidate not in self.fds:
                    return self.allocate("devnull", preferred=candidate)
            return self.allocate("devnull")
        if path.endswith("/stat"):
            if not self.preparation or not self.preparation.helpers:
                raise AssertionError("helper effect preceded surviving-owner registration")
            helper = self.preparation.helpers[-1]
            if helper.pid != 123 or helper.pidfd.state is not closure._FdState.OWNED:
                raise AssertionError("helper preregistration omitted exact pidfd authority")
            self.preregistration_observed = True
            if self.fault == "stat-open":
                raise OSError(errno.EMFILE, "stat")
            start = self.processes[123].start
            return self.allocate("proc-stat", stat_row(start))
        if path.endswith("/children"):
            if self.fault == "children-open":
                raise OSError(errno.EMFILE, "children")
            process = self.processes[123]
            children = process.children
            if self.fault == "unstable-descendants":
                self.children_reads += 1
                children = () if self.children_reads == 1 else (124,)
            raw = b" ".join(str(value).encode() for value in children)
            return self.allocate("children", raw + (b"\n" if raw else b""))
        if path.endswith("/exe"):
            return self.allocate("exe")
        raise AssertionError(f"unexpected open: {path}")

    def close(self, fd):
        self.close_attempts.append(fd)
        if fd not in self.fds:
            raise AssertionError("production double-closed a descriptor number")
        if self.fault == "spawn-after" and self.preparation.helpers:
            self.fault = "spawn-after-fired"
            raise OSError("fault after registered spawn")
        if self.fault in {"fd-dir-close", "fd-dir-read-close"} and self.fds[fd] == "fd-directory":
            del self.fds[fd]
            raise OSError("fd directory close")
        del self.fds[fd]
        self.fd_data.pop(fd, None)
        self.positions.pop(fd, None)

    def getdents(self, fd, maximum=32768):
        del maximum
        if self.fault in {"fd-dir-read", "fd-dir-read-close"}:
            raise OSError("getdents")
        if self.fault == "transient-library-fd":
            transient = self.allocate("library-duplicate")
            del self.fds[transient]
            self.fd_data.pop(transient, None)
            self.positions.pop(transient, None)
        if self.fault == "dirent-tail":
            self.fault = None
            self.dir_reads += 1
            return self.fd_data.pop(fd)
        if self.dir_reads:
            return b""
        self.dir_reads += 1
        names = sorted(self.fds)
        if self.fault == "fd-dir-malformed":
            return b"bad"
        if self.fault == "fd-dir-duplicate":
            names.append(names[0])
        if self.fault == "fd-dir-bound":
            names = range(closure._MAX_FDS + 1)
        raw = b"".join(dirent(value) for value in names)
        if self.fault == "dirent-chunks" and len(names) > 2:
            split_at = len(dirent(names[0])) + len(dirent(names[1]))
            value, self.fd_data[fd] = raw[:split_at], raw[split_at:]
            self.fault = "dirent-tail"
            return value
        return raw

    def pipe(self):
        self.pipe_count += 1
        if self.fault == ("gate-pipe" if self.pipe_count == 1 else "status-pipe"):
            raise OSError(errno.EMFILE, "pipe")
        return self.allocate("pipe-read"), self.allocate("pipe-write")

    def clone3_pidfd(self):
        if self.fault == "spawn-before":
            raise OSError("clone before effect")
        if self.fault == "pidfd-open":
            raise OSError(errno.EMFILE, "atomic pidfd result")
        process = Process()
        self.processes[123] = process
        pidfd = self.allocate("pidfd")
        self.pidfds[pidfd] = process
        return 123, pidfd

    def poll_readable(self, fd, seconds):
        del fd, seconds
        return self.fault != "status-timeout"

    def read(self, fd, size):
        kind = self.fds[fd]
        if self.fault == "status-read" and kind == "pipe-read":
            raise OSError("status")
        if self.fault == "stat-read" and kind == "proc-stat":
            raise OSError("stat")
        if kind == "pipe-read":
            self.status_reads += 1
            return b"R\n" if self.status_reads == 1 else b""
        raw = self.fd_data.get(fd, b"")
        offset = self.positions.get(fd, 0)
        value = raw[offset:offset + size]
        self.positions[fd] = offset + len(value)
        return value

    def write(self, fd, data):
        del fd
        if data == b"G\n":
            if not self.preregistration_observed or not self.preparation.helpers:
                raise AssertionError("helper release preceded complete registration")
            helper = self.preparation.helpers[-1]
            identity = (helper.start_time, helper.session, helper.process_group,
                        helper.executable_identity)
            if any(value is None for value in identity):
                raise AssertionError("helper release preceded identity registration")
            self.release_observed = True
        return len(data)

    def fstat(self, fd):
        if fd not in self.fds:
            raise OSError(errno.EBADF, "closed")
        if self.fds[fd] == "exe":
            process = self.processes[123]
            return SimpleNamespace(st_dev=process.executable[0], st_ino=process.executable[1])
        return SimpleNamespace(st_dev=1, st_ino=fd, st_size=0, st_mtime_ns=1,
                               st_ctime_ns=1, st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0)

    def dup2(self, source, target, inheritable=True):
        del inheritable
        self.fds[target] = self.fds[source]
    def close_range(self, first, last): self.close_ranges.append((first, last))
    def getpid(self): return 7
    def getsid(self, pid):
        if self.fault == "session-read": raise OSError("session")
        process = self.processes[pid]
        return process.session + (1 if self.fault == "session-drift" else 0)
    def getpgid(self, pid):
        process = self.processes[pid]
        return process.group + (1 if self.fault == "process-group-drift" else 0)
    def monotonic(self):
        self.clock += 0.4
        return self.clock
    def sleep(self, seconds): self.clock += seconds

    def pidfd_signal(self, pidfd, signum):
        process = self.pidfds[pidfd]
        if self.fault == "term-error" and signum == signal.SIGTERM: raise OSError("TERM")
        if self.fault == "kill-error" and signum == signal.SIGKILL: raise OSError("KILL")
        process.signals.append(signum)
        if self.fault == "identity-drift-before-kill" and signum == signal.SIGTERM:
            process.start += 1

    def wait_pidfd_nohang(self, pidfd):
        if self.fault == "wait-error": raise OSError("wait")
        if self.fault == "reap-lost": raise ChildProcessError()
        process = self.pidfds[pidfd]
        if not process.signals:
            return False
        last = process.signals[-1]
        exits = self.fault not in {
            "term-timeout-kill-exit", "identity-drift-before-kill",
            "kill-error", "kill-timeout", "eof-while-live", "pidfd-close-while-live",
        }
        if last == signal.SIGKILL and self.fault == "term-timeout-kill-exit": exits = True
        if exits:
            process.live = False
            process.reaped = True
            return True
        return False


def case_fault(case):
    fault = case["primitive_fault"]
    return None if fault == "none" else fault


def fd_case(case):
    implementations = (
        ("closure", closure._snapshot_fds, frozenset({0, 1, 2, 88})),
        ("launcher", launcher._descriptor_snapshot, (0, 1, 2, 88)),
    )
    for owner, snapshot, expected in implementations:
        ops = KernelOps(case_fault(case))
        try:
            first = snapshot(ops)
            ops.dir_reads = 0
            second = snapshot(ops)
        except (OSError, closure.RuntimeClosureError, launcher.RuntimeLauncherError) as error:
            if case["expect"] != "reject":
                raise
            if case_fault(case) == "fd-dir-read-close":
                cleanup_types = (
                    closure.RuntimeClosureCleanupError,
                    launcher.RuntimeLauncherCleanupError,
                )
                if not isinstance(error, cleanup_types):
                    raise AssertionError("fd primary/close failures were not aggregated") from error
        else:
            if case["expect"] != "accept":
                raise AssertionError(f"{owner} fd case accepted: {case['id']}")
            if first != second or first != expected:
                raise AssertionError(f"{owner} enumerator contaminated the baseline")
            if case_fault(case) == "transient-library-fd" and any(
                kind == "library-duplicate" for kind in ops.fds.values()
            ):
                raise AssertionError("transient library descriptor survived enumeration")


def start(ops):
    closure._reserve_stdio(ops)
    baseline = frozenset(ops.fds)
    preparation = closure.PreparationLease(ops, baseline, ())
    ops.preparation = preparation
    helper = closure._spawn_helper(ops, preparation, RESOLVED)
    if helper not in preparation.helpers or helper.state is not closure._HelperState.EXEC_IDENTIFIED:
        raise AssertionError("helper was not registered and identified")
    return preparation, helper


def helper_case(case):
    ops = KernelOps(case_fault(case))
    closure._reserve_stdio(ops)
    preparation = closure.PreparationLease(ops, frozenset(ops.fds), ())
    ops.preparation = preparation
    try:
        helper = closure._spawn_helper(ops, preparation, RESOLVED)
        if case_fault(case) == "ambient-fd":
            closure._close_complement(ops, (0, 1, 2, 900))
            if not any(first <= 88 <= last for first, last in ops.close_ranges):
                raise AssertionError("ambient fd was not in the closed complement")
        closure._stop_helper(ops, preparation, helper)
    except (OSError, closure.RuntimeClosureError):
        if case["expect"] != "reject":
            raise
    else:
        if case["expect"] != "accept":
            raise AssertionError(f"helper case accepted: {case['id']}")
        if ops.processes[123].live or not ops.processes[123].reaped:
            raise AssertionError("helper success did not reap the independent process")
        if not ops.preregistration_observed or not ops.release_observed:
            raise AssertionError("helper production registration/release gates were bypassed")
    if 123 in ops.processes and ops.processes[123].live:
        retained = any(helper.pid == 123 and helper.pidfd.state is closure._FdState.OWNED
                       for helper in preparation.helpers)
        if not retained:
            raise AssertionError(f"live helper lacks retained recovery authority: {case['id']}")


def stop_case(case):
    ops = KernelOps()
    preparation, helper = start(ops)
    fault = case_fault(case)
    ops.fault = fault
    process = ops.processes[123]
    if fault == "direct-descendant":
        process.children = (124,)
    if fault == "grandchild":
        process.children = (124, 125)
    if fault == "start-time-drift":
        process.start += 1
    if fault == "executable-drift":
        process.executable = (8, 999)
    try:
        closure._stop_helper(ops, preparation, helper)
    except (OSError, closure.RuntimeClosureError):
        if case["expect"] != "reject":
            raise
    else:
        if case["expect"] != "accept":
            raise AssertionError(f"stop case accepted: {case['id']}")
    if process.signals and fault in {"start-time-drift", "session-drift", "process-group-drift", "executable-drift"}:
        raise AssertionError("production signaled after identity drift")
    if fault == "pidfd-close-while-live" and helper.pidfd.fd in ops.close_attempts:
        raise AssertionError("pidfd was discarded while the child could remain live")


def lease_implementations():
    return (
        ("closure", closure.FdLease),
        ("launcher", launcher._FdLease),
    )


def cleanup_case(case):
    fault = case_fault(case)
    if fault == "three-close-errors":
        for owner, lease_type in lease_implementations():
            ops = KernelOps()
            leases = [lease_type(ops.allocate("owned"), str(index)) for index in range(3)]
            original = ops.close

            def failing(fd):
                original(fd)
                raise OSError(f"close-{fd}")

            ops.close = failing
            try:
                if owner == "closure":
                    closure._finish_fds(ops, leases, ValueError("primary"))
                else:
                    launcher._close_leases(ops, leases, ValueError("primary"))
            except (closure.RuntimeClosureCleanupError, launcher.RuntimeLauncherCleanupError) as error:
                failures = error.failures
                expected = 4 if owner == "closure" else 3
                if len(failures) != expected:
                    raise AssertionError(f"{owner} cleanup aggregation lost failures")
            else:
                raise AssertionError(f"{owner} cleanup errors accepted")
    elif fault in {"close-before-reuse", "close-after-reuse"}:
        for owner, lease_type in lease_implementations():
            ops = KernelOps()
            fd = ops.allocate("owned")
            lease = lease_type(fd, "reuse")
            original = ops.close

            def uncertain(value):
                if fault == "close-before-reuse":
                    ops.close_attempts.append(value)
                    raise OSError("before effect")
                original(value)
                ops.fds[value] = "foreign"
                raise OSError("after effect")

            ops.close = uncertain
            first = None
            try:
                lease.close(ops)
            except OSError as error:
                first = error
            if first is None:
                raise AssertionError(f"{owner} uncertain close was accepted")
            ops.fds[fd] = "foreign"
            try:
                lease.close(ops)
            except OSError as error:
                if error is not first:
                    raise AssertionError(f"{owner} poison error identity changed")
            else:
                raise AssertionError(f"{owner} poisoned lease became successful")
            if ops.close_attempts.count(fd) != 1 or ops.fds[fd] != "foreign":
                raise AssertionError(f"{owner} retried a reused descriptor number")
    elif fault == "double-close":
        for owner, lease_type in lease_implementations():
            ops = KernelOps()
            fd = ops.allocate("owned")
            lease = lease_type(fd, "double")
            lease.close(ops)
            lease.close(ops)
            if ops.close_attempts.count(fd) != 1:
                raise AssertionError(f"{owner} proved close was repeated")
    else:
        ops = KernelOps()
    if fault == "duplicate-registration":
        preparation = closure.PreparationLease(ops, frozenset(), ())
        fd = ops.allocate("owned")
        preparation.register_fd(fd, "one")
        try:
            preparation.register_fd(fd, "two")
        except closure.RuntimeClosureError:
            pass
        else:
            raise AssertionError("duplicate registration accepted")
    elif fault == "unexpected-child":
        preparation, helper = start(ops)
        ops.processes[123].children = (124,)
        try:
            closure._stop_helper(ops, preparation, helper)
        except closure.RuntimeClosureError:
            pass
        else:
            raise AssertionError("unexpected owned descendant branch was removed")
    elif fault == "cleanup-after":
        for owner, lease_type in lease_implementations():
            owned = KernelOps()
            fd = owned.allocate("owned")
            lease = lease_type(fd, "cleanup")
            original = owned.close

            def after_effect(value):
                original(value)
                owned.fds[value] = "foreign"
                raise OSError("cleanup after effect")

            owned.close = after_effect
            first = None
            try:
                lease.close(owned)
            except OSError as error:
                first = error
            try:
                lease.close(owned)
            except OSError as error:
                if first is None or error is not first:
                    raise AssertionError(f"{owner} cleanup poison changed")
            else:
                raise AssertionError(f"{owner} cleanup poison became success")
    elif fault not in {
        "three-close-errors", "close-before-reuse", "close-after-reuse", "double-close"
    }:
        raise AssertionError(f"unimplemented cleanup row: {fault}")


groups = (
    ("fd_baseline_cases", fd_case),
    ("helper_cases", helper_case),
    ("stop_cases", stop_case),
    ("cleanup_cases", cleanup_case),
)
metadata = {"version", "acceptance_ids", "case_fields"}
if set(MATRIX) != metadata | {name for name, _runner in groups}:
    raise AssertionError("lifecycle manifest shape is not closed")
case_fields = set(MATRIX["case_fields"])
cases = [case for name, _runner in groups for case in MATRIX[name]]
if any(set(case) != case_fields for case in cases):
    raise AssertionError("lifecycle manifest case is not closed")
for case in cases:
    if not case["production_method"] or not case["sentinel"]:
        raise AssertionError("lifecycle case lacks a production branch sentinel")
    if (case["intended_code"] == "OK") != (case["expect"] == "accept"):
        raise AssertionError("lifecycle typed oracle contradicts expectation")
executed = []
for group, runner in groups:
    for case in MATRIX[group]:
        runner(case)
        executed.append(case["id"])
declared = [case["id"] for group, _runner in groups for case in MATRIX[group]]
if executed != declared or len(executed) != len(set(executed)):
    raise AssertionError("lifecycle manifest rows were not executed exactly once")
print("Outcome 2 lifecycle portable tests passed")
