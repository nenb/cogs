#!/usr/bin/env python3
"""Production lifecycle state machines over an independent deterministic kernel model."""
from array import array
import ctypes
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import socket
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
records = [json.loads(line) for line in (FIXTURES / "lifecycle/faults.jsonl").read_text().splitlines()]
header, *fixture_cases = records
MATRIX = {key: header[key] for key in ("version", "acceptance_ids", "case_fields")}
for family in ("fd_baseline_cases", "helper_cases", "stop_cases", "cleanup_cases"):
    selected = (row for row in fixture_cases if row["primitive_fault"]["family"] == family)
    MATRIX[family] = [
        {**row, "primitive_fault": row["primitive_fault"]["name"],
         "expect": row["primitive_fault"]["expect"]} for row in selected
    ]
RAW = (FIXTURES / "elf/valid-executable.elf").read_bytes()
GENERATION = closure.SourceGeneration(8, 101, len(RAW), 1, 1, stat.S_IFREG | 0o755, 0, 0)
OBJECT = closure.AuthenticatedObject(
    "executable", "/usr/bin/python3", 900, GENERATION, (), len(RAW),
    hashlib.sha256(RAW).hexdigest(), elf.parse_elf64(RAW),
)
RESOLVED = closure.ResolvedToolClosure("python3-parser", OBJECT, OBJECT, ())
def stat_row(start=10):
    return b"123 (fixed helper) S " + b" ".join([b"1"] * 18 + [str(start).encode()]) + b"\n"
def check(condition, message):
    if not condition:
        raise AssertionError(message)
fault_events = []
class Fault(str):
    def __eq__(self, other):
        matched = super().__eq__(other)
        if matched:
            fault_events.append(f"primitive:{self}")
        return matched
    __hash__ = str.__hash__
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
        self.fault = Fault(fault) if fault else None
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
        self.outer_helpers = {}
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
            check(self.preparation and self.preparation.helpers, "helper effect preceded surviving-owner registration")
            helper = self.preparation.helpers[-1]
            check(helper.pid == 123 and helper.pidfd.state is closure._FdState.OWNED,
                  "helper preregistration omitted exact pidfd authority")
            self.preregistration_observed = True
            if self.fault == "stat-open":
                raise OSError(errno.EMFILE, "stat")
            start = self.processes[123].start
            return self.allocate("proc-stat", stat_row(start))
        if path.endswith("/children"):
            if self.fault == "children-open":
                raise OSError(errno.EMFILE, "children")
            pid = int(path.split("/")[2])
            process = self.processes.get(pid)
            children = process.children if process is not None else ()
            if self.fault == "unstable-descendants" and pid == 123:
                self.children_reads += 1
                children = () if self.children_reads == 1 else (124,)
            raw = b" ".join(str(value).encode() for value in children)
            return self.allocate("children", raw + (b"\n" if raw else b""))
        if path.endswith("/exe"):
            return self.allocate("exe")
        raise AssertionError(f"unexpected open: {path}")
    def close(self, fd):
        self.close_attempts.append(fd)
        check(fd in self.fds, "production double-closed a descriptor number")
        if self.fault == "spawn-after":
            check(
                self.preparation is not None and len(self.preparation.helpers) == 1,
                "spawn-after fault preceded exact helper registration",
            )
            helper = self.preparation.helpers[0]
            check(
                self.fds[fd] == "proc-stat" and self.preregistration_observed
                and helper.state is closure._HelperState.SPAWNED
                and helper.pidfd.state is closure._FdState.OWNED
                and helper.start_time is None and helper.outer_token is None
                and not helper.outer_registration_attempted
                and self.processes[helper.pid].live,
                "spawn-after fault missed the post-clone, pre-identity cut",
            )
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
            check(self.preregistration_observed and self.preparation.helpers,
                  "helper release preceded complete registration")
            helper = self.preparation.helpers[-1]
            identity = (helper.start_time, helper.session, helper.process_group,
                        helper.executable_identity)
            check(not any(value is None for value in identity), "helper release preceded identity registration")
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
    def close_range(self, first, last):
        self.close_ranges.append((first, last))
    def _register_runtime_helper(self, helper, deadline):
        token = (helper.pid, helper.pidfd.fd)
        self.outer_helpers[token] = helper
        return token
    def _release_runtime_helper(self, token, deadline):
        check(token in self.outer_helpers, "unregistered outer helper release")
    def _retire_runtime_helper(self, token, deadline):
        check(self.outer_helpers.pop(token).reaped is True, "outer helper retired before reap")
    def getpid(self):
        return 7
    def getsid(self, pid):
        if self.fault == "session-read":
            raise OSError("session")
        process = self.processes[pid]
        return process.session + (1 if self.fault == "session-drift" else 0)
    def getpgid(self, pid):
        process = self.processes[pid]
        return process.group + (1 if self.fault == "process-group-drift" else 0)
    def monotonic(self):
        self.clock += 0.4
        return self.clock
    def sleep(self, seconds):
        self.clock += seconds
    def pidfd_signal(self, pidfd, signum):
        process = self.pidfds[pidfd]
        if self.fault == "term-error" and signum == signal.SIGTERM:
            raise OSError("TERM")
        if self.fault == "kill-error" and signum == signal.SIGKILL:
            raise OSError("KILL")
        process.signals.append(signum)
        if self.fault == "identity-drift-before-kill" and signum == signal.SIGTERM:
            process.start += 1
    def wait_pidfd_nohang(self, pidfd):
        if self.fault == "wait-error":
            raise OSError("wait")
        if self.fault == "reap-lost":
            raise ChildProcessError()
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
            check(case["expect"] == "accept", f"{owner} fd case accepted: {case['id']}")
            check(first == second == expected, f"{owner} enumerator contaminated the baseline")
            if case_fault(case) == "transient-library-fd" and any(
                kind == "library-duplicate" for kind in ops.fds.values()
            ):
                raise AssertionError("transient library descriptor survived enumeration")
def start(ops):
    closure._reserve_stdio(ops)
    baseline = frozenset(ops.fds)
    preparation = closure.PreparationLease(ops, baseline, (), outer=ops)
    ops.preparation = preparation
    helper = closure._spawn_helper(ops, preparation, RESOLVED)
    registered = helper in preparation.helpers and helper.state is closure._HelperState.EXEC_IDENTIFIED
    check(registered, "helper was not registered and identified")
    return preparation, helper

def helper_case(case):
    ops = KernelOps(case_fault(case))
    closure._reserve_stdio(ops)
    preparation = closure.PreparationLease(ops, frozenset(ops.fds), (), outer=ops)
    ops.preparation = preparation
    try:
        helper = closure._spawn_helper(ops, preparation, RESOLVED)
        if case_fault(case) == "ambient-fd":
            closure._close_complement(ops, (0, 1, 2, 900))
            check(any(first <= 88 <= last for first, last in ops.close_ranges),
                  "ambient fd was not in the closed complement")
        closure._stop_helper(ops, preparation, helper)
    except (OSError, closure.RuntimeClosureError):
        if case["expect"] != "reject":
            raise
    else:
        check(case["expect"] == "accept", f"helper case accepted: {case['id']}")
        check(not ops.processes[123].live and ops.processes[123].reaped,
              "helper success did not reap the independent process")
        check(ops.preregistration_observed and ops.release_observed,
              "helper production registration/release gates were bypassed")
    if 123 in ops.processes and ops.processes[123].live:
        retained = any(helper.pid == 123 and helper.pidfd.state is closure._FdState.OWNED
                       for helper in preparation.helpers)
        check(retained, f"live helper lacks retained recovery authority: {case['id']}")
    if case_fault(case) == "spawn-after":
        process = ops.processes[123]
        check(not process.live and process.reaped and not preparation.helpers,
              "spawn-after did not use atomic pidfd authority to reap the gated helper")
        check(not any(kind == "pidfd" for kind in ops.fds.values()),
              "spawn-after recovery retained its pidfd")

def stop_case(case):
    ops = KernelOps()
    preparation, helper = start(ops)
    fault = case_fault(case)
    ops.fault = Fault(fault) if fault else None
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
        check(case["expect"] == "accept", f"stop case accepted: {case['id']}")
    identity_faults = {"start-time-drift", "session-drift", "process-group-drift", "executable-drift"}
    check(not process.signals or fault not in identity_faults, "production signaled after identity drift")
    discarded_live = fault == "pidfd-close-while-live" and helper.pidfd.fd in ops.close_attempts
    check(not discarded_live, "pidfd was discarded while the child could remain live")

def lease_implementations():
    return (
        ("closure", closure.FdLease),
        ("launcher", launcher._FdLease),
        ("launcher-received", lambda fd, _purpose: launcher._received_leases((fd,))[0]),
    )
def caught(call):
    try:
        call()
    except BaseException as error:
        return error
    return None

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
            finish = closure._finish_fds if owner == "closure" else launcher._close_leases
            error = caught(lambda: finish(ops, leases, ValueError("primary")))
            cleanup_types = (closure.RuntimeClosureCleanupError, launcher.RuntimeLauncherCleanupError)
            if type(error) not in cleanup_types:
                raise AssertionError(f"{owner} cleanup errors lacked their exact aggregate")
            expected = 4 if owner == "closure" else 3
            check(len(error.failures) == expected, f"{owner} cleanup aggregation lost failures")
    elif fault in {"close-before-reuse", "close-after-reuse", "cleanup-after"}:
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
            first = caught(lambda: lease.close(ops))
            check(type(first) is OSError, f"{owner} uncertain close was accepted")
            ops.fds[fd] = "foreign"
            second = caught(lambda: lease.close(ops))
            check(second is first, f"{owner} poison error identity changed")
            if ops.close_attempts.count(fd) != 1 or ops.fds[fd] != "foreign":
                raise AssertionError(f"{owner} retried a reused descriptor number")
    elif fault == "double-close":
        for owner, lease_type in lease_implementations():
            ops = KernelOps()
            fd = ops.allocate("owned")
            lease = lease_type(fd, "double")
            lease.close(ops)
            lease.close(ops)
            check(ops.close_attempts.count(fd) == 1, f"{owner} proved close was repeated")
    else:
        ops = KernelOps()
    if fault == "duplicate-registration":
        preparation = closure.PreparationLease(ops, frozenset(), (), outer=ops)
        fd = ops.allocate("owned")
        preparation.register_fd(fd, "one")
        error = caught(lambda: preparation.register_fd(fd, "two"))
        check(type(error) is closure.RuntimeClosureError, "duplicate registration accepted")
    elif fault == "unexpected-child":
        preparation, helper = start(ops)
        ops.processes[123].children = (124,)
        error = caught(lambda: closure._stop_helper(ops, preparation, helper))
        check(type(error) is closure.RuntimeClosureCleanupError,
              "unexpected owned descendant branch was removed")
    elif fault not in {
        "three-close-errors", "close-before-reuse", "close-after-reuse", "cleanup-after", "double-close"
    }:
        raise AssertionError(f"unimplemented cleanup row: {fault}")

def production_clone3_abi():
    values = closure._clone3_arguments(0x1234)
    expected = (closure._CLONE_PIDFD, 0x1234, 0, 0, signal.SIGCHLD, 0, 0, 0, 0, 0, 0)
    check(values == expected, "production clone3 clone_args ABI field order changed")
    ops = KernelOps()
    pidfd = ops.allocate("pidfd")
    lease = launcher._ProcessLease(123, launcher._FdLease(pidfd, "pidfd"), reaped=True)
    launcher._stop_process(lease, None, ops)
    check(ops.close_attempts.count(pidfd) == 1,
          "successful production pidfd finalizer did not close exactly once")
class TransferOps:
    def __init__(self):
        self.closed = []
    def close(self, fd):
        self.closed.append(fd)


class TransferEndpoint:
    def __init__(self, packet, credentials, rights):
        self.packet = packet
        self.credentials = credentials
        self.rights = rights
    def recvmsg(self, data_bound, control_bound, flags):
        del data_bound, control_bound, flags
        ancillary = [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
             struct.pack("3i", *self.credentials)),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS,
             array("i", self.rights).tobytes()),
        ]
        return self.packet, ancillary, 0, None


def process_owner_matrix():
    if not hasattr(launcher.socket, "SCM_CREDENTIALS"):
        launcher.socket.SCM_CREDENTIALS = 2
    if not hasattr(launcher.socket, "MSG_CMSG_CLOEXEC"):
        launcher.socket.MSG_CMSG_CLOEXEC = 0x40000000
    path = FIXTURES / "lifecycle/owner-cases.jsonl"
    document = [json.loads(line) for line in path.read_text().splitlines()]
    header, *rows = document
    fields = {"id", "production_method", "primitive_fault", "intended_code",
              "cleanup_domains", "sentinel"}
    header_keys = {"type", "version", "acceptance_ids", "case_fields"}
    check(set(header) == header_keys and header["type"] == "header" and
          header["version"] == "cogs.outcome-two-process-owner/v1" and
          header["acceptance_ids"] == ["AT91-PROC-01"] and
          set(header["case_fields"]) == fields,
          "process-owner fixture header")
    selected = []
    for row in rows:
        check(set(row) == fields and callable(getattr(launcher._ProcessOwner,
              row["production_method"].split(".")[-1])), "process-owner row shape")
        selected.append(row["id"])
        fault = row["primitive_fault"]["name"]
        ops = TransferOps()
        owner = launcher._ProcessOwner(ops)
        leader = launcher._ProcessLease(
            123, launcher._FdLease(700, "leader"), start_time=10,
            session=7, process_group=7, executable=(8, 101),
        )
        owner.processes.append(leader)
        if row["production_method"].endswith("confirm_setsid"):
            owner.plan_setsid(leader)
            old_start = launcher._start_time
            old_exe = launcher._exe_identity
            old_sid = launcher.os.getsid
            old_group = launcher.os.getpgid
            launcher._start_time = lambda pid: 10
            launcher._exe_identity = lambda pid: (8, 101)
            launcher.os.getsid = lambda pid: 122 if fault == "session-drift" else 123
            launcher.os.getpgid = lambda pid: 123
            try:
                error = caught(lambda: owner.confirm_setsid(leader))
            finally:
                launcher._start_time = old_start
                launcher._exe_identity = old_exe
                launcher.os.getsid = old_sid
                launcher.os.getpgid = old_group
            if fault == "none":
                check(error is None and leader.identity_phase == row["sentinel"],
                      "planned setsid was not advanced")
            else:
                check(getattr(error, "code", None) == row["intended_code"] and
                      leader.identity_phase == row["sentinel"],
                      "planned setsid drift was accepted")
        elif row["production_method"].endswith("receive_descendant"):
            packet = launcher._canonical({
                "executable": [8, 102], "nonce": (b"n" * 32).hex(),
                "parent": 123, "pid": 124, "process_group": 123,
                "sequence": 1, "session": 123, "start_time": 11,
                "version": "cogs.process-transfer/v1",
            })
            credentials = (999 if fault == "credentials" else 123, 0, 0)
            endpoint = TransferEndpoint(packet, credentials, (800,))
            old_start = launcher._start_time
            old_exe = launcher._exe_identity
            old_sid = launcher.os.getsid
            old_group = launcher.os.getpgid
            old_euid = launcher.os.geteuid
            old_egid = launcher.os.getegid
            launcher._start_time = lambda pid: 11
            launcher._exe_identity = lambda pid: (8, 102)
            launcher.os.getsid = lambda pid: 123
            launcher.os.getpgid = lambda pid: 123
            launcher.os.geteuid = lambda: 0
            launcher.os.getegid = lambda: 0
            try:
                error = caught(lambda: owner.receive_descendant(
                    endpoint, leader, b"n" * 32, 1,
                ))
            finally:
                launcher._start_time = old_start
                launcher._exe_identity = old_exe
                launcher.os.getsid = old_sid
                launcher.os.getpgid = old_group
                launcher.os.geteuid = old_euid
                launcher.os.getegid = old_egid
            if fault == "none":
                check(error is None and len(leader.descendants) == 1 and
                      leader.descendants[0].pidfd.fd == 800,
                      f"credentialed pidfd was not registered before ack: {error!r}")
            else:
                check(getattr(error, "code", None) == row["intended_code"] and
                      ops.closed == [800], "malformed transfer leaked its right")
        else:
            descendant = launcher._ProcessLease(124, launcher._FdLease(800, "desc"))
            leader.descendants = (descendant,)
            old_census = launcher._descendant_census
            values = iter(((124,), (125,)) if fault == "spawn-after" else
                          ((124,), (124,)))
            launcher._descendant_census = lambda pid, actual_ops: next(values)
            try:
                error = caught(lambda: owner.stable_census(leader))
            finally:
                launcher._descendant_census = old_census
            if fault == "none":
                check(error is None, "stable census rejected")
            else:
                check(getattr(error, "code", None) == row["intended_code"],
                      "spawn-after census accepted")
    check(selected == [row["id"] for row in rows] and len(selected) == len(set(selected)),
          "process-owner declared/selected/consumed/oracle mismatch")


def error_signature(error):
    failures = getattr(error, "failures", None)
    if failures is not None:
        code = [error_signature(item) for item in failures]
    elif hasattr(error, "code"):
        code = error.code
    elif isinstance(error, OSError) and error.errno is not None:
        code = error.errno
    else:
        code = str(error)
    return [type(error).__name__, code]

def observe_case(case, runner):
    fault_events.clear()
    codes = []
    sentinels = []
    originals = []
    for name in case["production_method"]:
        module_name, path = name.split(".", 1)
        owner = {"closure": closure, "launcher": launcher}[module_name]
        parts = path.split(".")
        for part in parts[:-1]:
            owner = getattr(owner, part)
        attribute = parts[-1]
        original = getattr(owner, attribute)
        def observed(*args, _method=original, _name=name, **kwargs):
            try:
                result = _method(*args, **kwargs)
            except BaseException as error:
                code = error_signature(error)
                codes.append(code)
                encoded = json.dumps(code, separators=(",", ":"))
                sentinels.append(f"{_name}:raise:{encoded}")
                raise
            codes.append("OK")
            sentinels.append(f"{_name}:return")
            return result
        setattr(owner, attribute, observed)
        originals.append((owner, attribute, original))
    try:
        runner(case)
    finally:
        for owner, attribute, original in reversed(originals):
            setattr(owner, attribute, original)
    sentinels[:0] = fault_events
    if codes != case["intended_code"]:
        raise AssertionError(
            f"{case['id']}: exact exception class/code changed: "
            f"{codes!r} != {case['intended_code']!r}"
        )
    if sentinels != case["sentinel"]:
        raise AssertionError(
            f"{case['id']}: production event sentinel changed: "
            f"{sentinels!r} != {case['sentinel']!r}"
        )
    if (all(code == "OK" for code in codes)) != (case["expect"] == "accept"):
        raise AssertionError(f"{case['id']}: typed oracle contradicts expectation")
class ScriptedSocket:
    """One endpoint in the parent-side deterministic lifecycle protocol."""
    def __init__(self, kernel, fd, role, child=False):
        self.kernel = kernel
        self.fd = fd
        self.role = role
        self.child = child
        self.reads = 0
    def fileno(self):
        return self.fd
    def detach(self):
        fd, self.fd = self.fd, -1
        return fd
    def close(self):
        if self.fd >= 0:
            self.kernel.close(self.detach())
    def send(self, value, flags=0):
        del flags
        self.kernel.events.append(f"{self.kernel.case}:{self.role}:send:{value!r}")
        if self.role == "control" and value.startswith(b"X:"):
            self.kernel.exit_leader()
        return len(value)
    def recv(self, bound, flags=0):
        del bound, flags
        if self.role == "transfer":
            mode = self.kernel.hit("transfer-eof")
            return b"extra" if mode == "extra" else b""
        case = self.kernel.case
        index = self.reads
        self.reads += 1
        if index == 0:
            mode = self.kernel.hit("transition-packet")
            return b"bad" if mode == "malformed" else b"S:" + case.encode()
        if index == 1:
            return b"T:" + case.encode()
        mode = self.kernel.hit("release-packet")
        return b"bad" if mode == "malformed" else b"R:" + case.encode()
    def recvmsg(self, data_bound, control_bound, flags):
        del data_bound, control_bound, flags
        mode = self.kernel.hit("transfer-recv")
        if mode == "error":
            raise OSError(errno.EIO, "transfer recv")
        mode = self.kernel.hit("transfer-packet")
        descendant = self.kernel.create_descendant()
        packet_case = "wrong" if mode == "case" else self.kernel.case
        start = descendant.start + (1 if mode == "identity" else 0)
        transfer_id = hashlib.sha256(
            self.kernel.current_nonce + launcher._canonical([self.kernel.case, "descendant", 1])
        ).hexdigest()
        packet = launcher._canonical({
            "case": packet_case,
            "executable": list(descendant.executable),
            "nonce": self.kernel.current_nonce.hex(),
            "parent": self.kernel.leader.pid,
            "pid": descendant.pid,
            "process_group": descendant.group,
            "role": "descendant",
            "sequence": 1,
            "session": descendant.session,
            "start_time": start,
            "transfer": transfer_id,
            "version": "cogs.process-transfer/v1",
        })
        credential_pid = 999 if mode == "credentials" else self.kernel.leader.pid
        credentials = (socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
                       struct.pack("3i", credential_pid, self.kernel.euid, self.kernel.egid))
        rights = []
        if mode != "no-right":
            rights.append(self.kernel.allocate("pidfd", target=descendant))
        if mode == "extra-right":
            rights.append(self.kernel.allocate("pidfd", target=descendant))
        ancillary = [credentials]
        if rights:
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              array("i", rights).tobytes()))
        if mode in {"credentials", "no-right", "extra-right", "case", "identity"}:
            self.kernel.creator_abort_descendant()
        return packet, ancillary, 0, None
    def sendmsg(self, values, ancillary, flags=0):
        del ancillary, flags
        value = b"".join(values)
        return len(value)
    def shutdown(self, direction):
        del direction

class ScriptedProcess:
    def __init__(self, pid, parent, start, session, group):
        self.pid = pid
        self.parent = parent
        self.start = start
        self.session = session
        self.group = group
        self.executable = (8, 1000 + pid)
        self.live = True
        self.reaped = False
        self.exit_status = None
        self.term_ignored = False

class ScriptedLibc:
    def __init__(self, kernel):
        self.kernel = kernel
    def prctl(self, option, pointer, *unused):
        del unused
        check(option == launcher._PR_GET_CHILD_SUBREAPER, "unexpected modeled libc prctl")
        if self.kernel.subreaper_reads == 0:
            self.kernel.subreaper_reads += 1
            if self.kernel.hit("subreaper-read") == "error":
                return -1
        value = self.kernel.subreaper
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int)).contents.value = value
        return 0

class ProductionLifecycleKernel:
    """Scripted child protocol with real production parent ownership and parsers."""
    def __init__(self, row):
        self.row = row
        self.selected = row["id"]
        self.spec = row["primitive_fault"]
        self.case = "qualifier"
        self.events = []
        self.consumed = set()
        self.clock = 0.0
        self.euid = 1000
        self.egid = 1000
        self.main_pid = 7
        self.next_fd = 10
        self.next_pid = 100
        self.fds = {0: ("stdio", None), 1: ("stdio", None),
                    2: ("stdio", None), 88: ("ambient", None)}
        self.positions = {}
        self.socket_count = 0
        self.case_socket_count = 0
        self.snapshot_count = 0
        self.current_nonce = b""
        self.processes = {}
        self.leader = None
        self.descendant = None
        self.subreaper = 0
        self.original_subreaper = 0
        self.subreaper_reads = 0
        self.libc = ScriptedLibc(self)
        self.baseline = frozenset(self.fds)
    def hit(self, cut):
        if self.spec["cut"] != cut:
            return None
        selected_case = self.spec["case"]
        qualifier_cut = cut.startswith("subreaper-") or cut.startswith("final-")
        if selected_case == "qualifier" and not qualifier_cut:
            return None
        if selected_case not in ("all", "qualifier", self.case):
            return None
        if self.selected in self.consumed:
            return None
        self.consumed.add(self.selected)
        self.events.append(f"fault:{self.selected}")
        return self.spec["mode"]
    def allocate(self, kind, data=b"", target=None):
        while self.next_fd in self.fds:
            self.next_fd += 1
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = (kind, target if target is not None else data)
        self.positions[fd] = 0
        return fd
    def open(self, path, flags, mode=0o600):
        del flags, mode
        if path == "/proc/self/fd":
            self.snapshot_count += 1
            return self.allocate("fd-directory")
        if path.endswith("/stat"):
            pid = int(path.split("/")[2])
            process = self.processes[pid]
            values = [1] * 49
            values[18] = process.start
            raw = (f"{pid} (scripted) S " + " ".join(map(str, values)) + "\n").encode()
            return self.allocate("proc", raw)
        if path.endswith("/children"):
            if path.startswith("/proc/self/"):
                children = self.direct_children(self.main_pid)
            else:
                pid = int(path.split("/")[2])
                children = self.direct_children(pid)
                if pid == getattr(self.leader, "pid", -1) and self.hit("census") == "drift":
                    children = ()
            raw = b" ".join(str(pid).encode() for pid in children)
            return self.allocate("proc", raw + (b" " if raw else b""))
        if path.endswith("/exe"):
            pid = int(path.split("/")[2])
            return self.allocate("exe", target=self.processes[pid])
        raise AssertionError(f"unexpected scripted open: {path}")
    def close(self, fd):
        check(fd in self.fds, f"scripted close of unknown fd {fd}")
        del self.fds[fd]
        self.positions.pop(fd, None)
    def read(self, fd, size):
        kind, value = self.fds[fd]
        if kind == "pipe-read":
            return b"G"
        check(kind == "proc", f"unexpected scripted read kind: {kind}")
        offset = self.positions[fd]
        part = value[offset:offset + size]
        self.positions[fd] += len(part)
        return part
    def write(self, fd, data):
        kind, _value = self.fds[fd]
        if kind == "pipe-write" and data == b"G":
            mode = self.hit("leader-release")
            if mode == "short":
                return 0
            if self.leader is not None:
                self.leader.session = self.leader.pid
                self.leader.group = self.leader.pid
        return len(data)
    def fstat(self, fd):
        kind, value = self.fds[fd]
        if kind == "exe":
            return SimpleNamespace(st_dev=value.executable[0], st_ino=value.executable[1])
        return SimpleNamespace(st_dev=1, st_ino=fd, st_size=0, st_mtime_ns=1,
                               st_ctime_ns=1, st_mode=stat.S_IFREG | 0o600,
                               st_uid=self.euid, st_gid=self.egid)
    def getdents(self, fd, maximum=32768):
        del maximum
        if self.positions[fd]:
            return b""
        self.positions[fd] = 1
        names = sorted(self.fds)
        if self.snapshot_count == 2 and self.hit("final-descriptor-baseline") == "drift":
            names.append(99)
        return b"".join(dirent(value) for value in names)
    def pipe2(self, flags):
        del flags
        return self.allocate("pipe-read"), self.allocate("pipe-write")
    def socketpair(self):
        role = "control" if self.case_socket_count % 2 == 0 else "transfer"
        self.case_socket_count += 1
        if self.hit(f"{role}-socketpair") == "error":
            raise OSError(errno.EIO, f"{role} socketpair")
        left_fd = self.allocate("socket")
        right_fd = self.allocate("socket")
        left = ScriptedSocket(self, left_fd, role)
        right = ScriptedSocket(self, right_fd, role, child=True)
        self.fds[left_fd] = ("socket", left)
        self.fds[right_fd] = ("socket", right)
        return left, right
    def nonce(self):
        self.current_nonce = hashlib.sha256(self.case.encode()).digest()
        return self.current_nonce
    def clone_pidfd(self):
        mode = self.hit("leader-clone")
        if mode == "error":
            raise OSError(errno.EIO, "leader clone")
        if mode == "secondary-pidfd":
            raise OSError(errno.EIO, "secondary pidfd")
        pid = self.next_pid
        self.next_pid += 10
        process = ScriptedProcess(pid, self.main_pid, 1000 + pid, self.main_pid, self.main_pid)
        self.processes[pid] = process
        self.leader = process
        return pid, self.allocate("pidfd", target=process)
    def prctl(self, option, value=0, arg3=0):
        del arg3
        if option == launcher._PR_SET_CHILD_SUBREAPER:
            if value == 1 and self.hit("subreaper-set") == "error":
                raise OSError(errno.EIO, "subreaper set")
            if value == self.original_subreaper:
                mode = self.hit("subreaper-restore")
                self.subreaper = value
                if mode == "after-error":
                    raise OSError(errno.EIO, "subreaper restore")
            else:
                self.subreaper = value
            return 0
        raise AssertionError(f"unexpected scripted prctl: {option}")
    def create_descendant(self):
        if self.descendant is None:
            pid = self.leader.pid + 1
            process = ScriptedProcess(
                pid, self.leader.pid, self.leader.start + 1,
                self.leader.session, self.leader.group,
            )
            process.term_ignored = self.case == "term-kill"
            self.processes[pid] = process
            self.descendant = process
        return self.descendant
    def creator_abort_descendant(self):
        if self.descendant is not None:
            self.descendant.live = False
            self.descendant.reaped = True
            self.descendant.exit_status = signal.SIGKILL
    def direct_children(self, parent):
        return tuple(sorted(
            process.pid for process in self.processes.values()
            if process.parent == parent and not process.reaped
        ))
    def exit_process(self, process, status):
        if process is None or not process.live:
            return
        process.live = False
        process.exit_status = status
        if process is self.leader and self.descendant is not None and not self.descendant.reaped:
            self.descendant.parent = self.main_pid
            if self.descendant.live:
                self.exit_process(self.descendant, signal.SIGKILL)
    def exit_leader(self):
        self.exit_process(self.leader, 0)
    def select(self, readers, writers, exceptional, timeout=None):
        del exceptional, timeout
        ready = []
        for item in readers:
            if isinstance(item, ScriptedSocket):
                ready.append(item)
            elif type(item) is int and item in self.fds:
                kind, value = self.fds[item]
                if kind == "pidfd" and not value.live:
                    ready.append(item)
        return ready, list(writers), []
    def monotonic(self):
        return self.clock
    def sleep(self, seconds):
        self.clock += max(seconds, 0.25)
    def pidfd_signal(self, pidfd, signum):
        kind, process = self.fds[pidfd]
        check(kind == "pidfd", "signal did not use pidfd")
        cut = "term-signal" if signum == signal.SIGTERM else "kill-signal"
        mode = self.hit(cut)
        if mode == "error":
            raise OSError(errno.EIO, f"{cut} error")
        if signum == signal.SIGTERM and mode == "exit":
            self.exit_process(process, signal.SIGTERM)
        elif signum == signal.SIGTERM and not process.term_ignored:
            self.exit_process(process, signal.SIGTERM)
        elif signum == signal.SIGKILL:
            self.exit_process(process, signal.SIGKILL)
    def waitpid(self, pid, options):
        del options
        process = self.processes[pid]
        if process.live:
            return 0, 0
        process.reaped = True
        status = process.exit_status or 0
        return pid, status
    def waitid(self, idtype, pidfd, options):
        del idtype, options
        kind, process = self.fds[pidfd]
        check(kind == "pidfd" and not process.live, "waitid before exact death")
        status = signal.SIGTERM if self.hit("waitid") == "status" else signal.SIGKILL
        return SimpleNamespace(si_pid=process.pid, si_uid=self.euid,
                               si_code=os.CLD_KILLED, si_status=status)
    def audit(self):
        live = [process.pid for process in self.processes.values() if process.live]
        unreaped = [process.pid for process in self.processes.values() if not process.reaped]
        check(not live and not unreaped, f"lifecycle cleanup retained processes: {live}/{unreaped}")
        check(frozenset(self.fds) == self.baseline,
              f"lifecycle cleanup retained descriptors: {sorted(self.fds)}")
        check(self.subreaper == self.original_subreaper, "subreaper was not restored")
        self.events.append("cleanup:restored")

def lifecycle_admission():
    return launcher._SourceAdmission(
        "a" * 40, "b" * 64, "c" * 64, b"", "", 0, None,
        launcher._BOOTSTRAP_OPERATION_TOKEN, 0, 0, 0, "lifecycle",
    )

def production_lifecycle_case(row):
    # Keep the mocked Linux ABI available when this portable suite runs on macOS.
    if not hasattr(launcher.os, "pipe2"):
        launcher.os.pipe2 = lambda _flags: (_ for _ in ()).throw(AssertionError("unpatched pipe2"))
    if not hasattr(launcher.os, "O_PATH"):
        launcher.os.O_PATH = 0x200000
    if not hasattr(launcher.os, "waitid"):
        launcher.os.waitid = lambda *_args: (_ for _ in ()).throw(AssertionError("unpatched waitid"))
    if not hasattr(launcher.os, "P_PIDFD"):
        launcher.os.P_PIDFD = 3
    if not hasattr(launcher.os, "CLD_KILLED"):
        launcher.os.CLD_KILLED = 2
    if not hasattr(launcher.os, "WEXITED"):
        launcher.os.WEXITED = 4
    if not hasattr(launcher.os, "WNOWAIT"):
        launcher.os.WNOWAIT = 0x01000000
    if not hasattr(launcher.signal, "pidfd_send_signal"):
        launcher.signal.pidfd_send_signal = lambda *_args: (_ for _ in ()).throw(
            AssertionError("unpatched pidfd_send_signal")
        )
    kernel = ProductionLifecycleKernel(row)
    originals = {
        "system_ops": launcher._SystemOps,
        "run_case": launcher._run_lifecycle_case,
        "pipe2": launcher.os.pipe2,
        "fstat": launcher.os.fstat,
        "getsid": launcher.os.getsid,
        "getpgid": launcher.os.getpgid,
        "geteuid": launcher.os.geteuid,
        "getegid": launcher.os.getegid,
        "waitpid": launcher.os.waitpid,
        "waitid": launcher.os.waitid,
        "pidfd_signal": launcher.signal.pidfd_send_signal,
        "select": launcher.select.select,
        "monotonic": launcher.time.monotonic,
        "sleep": launcher.time.sleep,
    }
    original_run = launcher._run_lifecycle_case
    def observed_run(case, ops, owner):
        kernel.case = case
        kernel.case_socket_count = 0
        kernel.leader = None
        kernel.descendant = None
        kernel.events.append(f"case:{case}:start")
        value = original_run(case, ops, owner)
        kernel.events.append(f"case:{case}:complete")
        return value
    launcher._SystemOps = lambda: kernel
    launcher._run_lifecycle_case = observed_run
    launcher.os.pipe2 = kernel.pipe2
    launcher.os.fstat = kernel.fstat
    launcher.os.getsid = lambda pid: kernel.processes[pid].session
    launcher.os.getpgid = lambda pid: kernel.processes[pid].group
    launcher.os.geteuid = lambda: kernel.euid
    launcher.os.getegid = lambda: kernel.egid
    launcher.os.waitpid = kernel.waitpid
    launcher.os.waitid = kernel.waitid
    launcher.signal.pidfd_send_signal = kernel.pidfd_signal
    launcher.select.select = kernel.select
    launcher.time.monotonic = kernel.monotonic
    launcher.time.sleep = kernel.sleep
    error = None
    result = None
    try:
        result = launcher._qualify_admitted_fixed_process_lifecycle(
            lifecycle_admission(), kernel,
        )
        kernel.events.append("qualification:complete")
        if row["primitive_fault"]["cut"] == "none":
            kernel.consumed.add(row["id"])
    except BaseException as caught_error:
        error = caught_error
    finally:
        launcher._SystemOps = originals["system_ops"]
        launcher._run_lifecycle_case = originals["run_case"]
        launcher.os.pipe2 = originals["pipe2"]
        launcher.os.fstat = originals["fstat"]
        launcher.os.getsid = originals["getsid"]
        launcher.os.getpgid = originals["getpgid"]
        launcher.os.geteuid = originals["geteuid"]
        launcher.os.getegid = originals["getegid"]
        launcher.os.waitpid = originals["waitpid"]
        launcher.os.waitid = originals["waitid"]
        launcher.signal.pidfd_send_signal = originals["pidfd_signal"]
        launcher.select.select = originals["select"]
        launcher.time.monotonic = originals["monotonic"]
        launcher.time.sleep = originals["sleep"]
    expected = row["intended_code"]
    observed = "OK" if error is None else error_signature(error)
    check(observed == expected, f"{row['id']}: {observed!r} != {expected!r}")
    check(kernel.consumed == {row["id"]}, f"{row['id']}: selected fault did not fire exactly")
    kernel.audit()
    cursor = -1
    for sentinel in row["sentinel"]:
        try:
            cursor = kernel.events.index(sentinel, cursor + 1)
        except ValueError as missing:
            raise AssertionError(f"{row['id']}: missing ordered sentinel {sentinel}") from missing
    expected_accept = row["primitive_fault"]["expect"] == "accept"
    check((error is None) == expected_accept, f"{row['id']}: expectation contradicted exact oracle")
    if error is None:
        check(type(result) is launcher.LifecycleQualificationResult,
              "full lifecycle did not return its exact production result")
        values = tuple(getattr(result, field.name) for field in launcher.fields(result))[3:]
        check(values and all(value is True for value in values),
              "full lifecycle production observations were not all exact")
    return kernel

def production_lifecycle_matrix():
    path = FIXTURES / "lifecycle/qualification-cases.jsonl"
    document = [json.loads(line) for line in path.read_text().splitlines()]
    fixture_header, *rows = document
    expected_fields = {"id", "production_method", "primitive_fault", "intended_code",
                       "cleanup_domains", "sentinel"}
    header_keys = {"type", "version", "acceptance_ids", "case_fields"}
    check(set(fixture_header) == header_keys and fixture_header["type"] == "header" and
          fixture_header["version"] == "cogs.outcome-two-lifecycle-production/v1" and
          fixture_header["acceptance_ids"] == ["AT91-PROC-01"] and
          set(fixture_header["case_fields"]) == expected_fields,
          "production lifecycle fixture header")
    declared = [row["id"] for row in rows]
    selected = []
    consumed = []
    oracle = []
    for row in rows:
        check(set(row) == expected_fields, f"closed production lifecycle row: {row['id']}")
        check(row["primitive_fault"]["expect"] in {"accept", "reject"},
              f"production lifecycle expectation: {row['id']}")
        check(set(row["cleanup_domains"]) == {"descriptors", "children", "descendants", "subreaper"},
              f"production lifecycle cleanup domains: {row['id']}")
        for production_method in row["production_method"]:
            owner = launcher
            module_name, path = production_method.split(".", 1)
            check(module_name == "launcher", f"production lifecycle owner: {row['id']}")
            for part in path.split("."):
                owner = getattr(owner, part)
            check(callable(owner), f"production lifecycle method: {row['id']}")
        selected.append(row["id"])
        kernel = production_lifecycle_case(row)
        consumed.extend(kernel.consumed)
        oracle.append(row["id"])
    check(declared == selected == consumed == oracle and
          len(declared) == len(set(declared)),
          "production lifecycle declared/selected/consumed/oracle mismatch")

production_clone3_abi()
process_owner_matrix()
production_lifecycle_matrix()
groups = (
    ("fd_baseline_cases", fd_case),
    ("helper_cases", helper_case),
    ("stop_cases", stop_case),
    ("cleanup_cases", cleanup_case),
)
metadata = {"version", "acceptance_ids", "case_fields"}
check(set(MATRIX) == metadata | {name for name, _runner in groups},
      "lifecycle manifest shape is not closed")
case_fields = set(MATRIX["case_fields"])
cases = [case for name, _runner in groups for case in MATRIX[name]]
check(not any(set(case) != case_fields | {"expect"} for case in cases),
      "lifecycle manifest case is not closed")
executed = []
for group, runner in groups:
    for case in MATRIX[group]:
        observe_case(case, runner)
        executed.append(case["id"])
declared = [case["id"] for group, _runner in groups for case in MATRIX[group]]
check(executed == declared and len(executed) == len(set(executed)),
      "lifecycle manifest rows were not executed exactly once")
print("Outcome 2 lifecycle portable tests passed")
