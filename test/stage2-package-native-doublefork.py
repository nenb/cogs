#!/usr/bin/env python3
"""Portable checks plus the required privileged double-fork native probe."""

import ctypes
import importlib.util
import os
from pathlib import Path
import array
import shutil
import signal
import select
import socket
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/run-stage2-package-native-candidate.py"
spec = importlib.util.spec_from_file_location("stage2_package_doublefork", SOURCE)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def _fd_baseline():
    return frozenset(os.listdir("/proc/self/fd"))


def _direct_child_pids():
    children = set()
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            rows = Path(f"/proc/{name}/status").read_bytes().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        parent = [row for row in rows if row.startswith(b"PPid:\t")]
        if len(parent) == 1 and int(parent[0].split()[1]) == os.getpid():
            children.add(int(name))
    return frozenset(children)


def _native_baseline():
    return _fd_baseline(), _direct_child_pids(), module._subreaper_state()


def _check_native_baseline(baseline, label):
    observed = _native_baseline()
    check(observed == baseline, f"{label} changed fd/child/subreaper baseline: {baseline!r} -> {observed!r}")


def portable_tests():
    original = module.NativeCandidateError("work")
    late = module.NativeCandidateError("late")
    outcome = module._Outcome()
    outcome.work(original)
    outcome.cleanup("close", late)
    try:
        outcome.finish()
    except module.CleanupUncertain as error:
        check(error.work_error is original, "cleanup uncertainty lost original work error")
        check(error.cleanup_errors == (("close", late),), "cleanup uncertainty lost late error")
    else:
        raise AssertionError("cleanup uncertainty was not sticky")

    success = b'{}'
    frame = len(success + b"S").to_bytes(4, "big") + b"S" + success
    check(module._parse_frame(frame) == success, "success frame did not round trip")
    failure = b"transaction:OSError_5"
    frame = len(failure + b"E").to_bytes(4, "big") + b"E" + failure
    try:
        module._parse_frame(frame)
    except module.ChildCandidateError as error:
        check((error.stage, error.category) == ("transaction", "OSError_5"),
              "child diagnostics changed")
    else:
        raise AssertionError("child error envelope was accepted")

    oversize = (module.MAX_PROTOCOL_BYTES + 1).to_bytes(4, "big") + b"S"
    try:
        module._parse_frame(oversize)
    except module.NativeCandidateError:
        pass
    else:
        raise AssertionError("oversize frame was accepted")

    # recvmsg installs rights before protocol validation; every rejected right
    # must be retired exactly once, including truncation/multiple-rights cuts.
    portable_cmsg_flag = not hasattr(socket, "MSG_CMSG_CLOEXEC")
    if portable_cmsg_flag: socket.MSG_CMSG_CLOEXEC = 0
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    sources = [os.open("/dev/null", os.O_RDONLY) for _ in range(2)]
    before = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").exists() else None
    try:
        rights = array.array("i", sources)
        left.sendmsg([b"BAD"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        try:
            module._control_receive(right.fileno())
        except module.NativeCandidateError:
            pass
        else:
            raise AssertionError("multiple SCM_RIGHTS were accepted")
        if before is not None:
            check(set(os.listdir("/proc/self/fd")) == before, "rejected SCM_RIGHTS leaked")
    finally:
        left.close(); right.close()
        for descriptor in sources: os.close(descriptor)

    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    source = os.open("/dev/null", os.O_RDONLY)
    before = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").exists() else None
    try:
        module._control_send(left.fileno(), b"WRONG", source)
        raw, passed = module._control_receive(right.fileno())
        try:
            module._control_no_fd(raw, passed, module.HELPER_GO, "bad gate")
        except module.NativeCandidateError:
            pass
        else:
            raise AssertionError("malformed gate with a right was accepted")
        if before is not None:
            check(set(os.listdir("/proc/self/fd")) == before, "malformed packet right leaked")
    finally:
        left.close(); right.close(); os.close(source)

    # An empty datagram can still install a right.  The transport gate owns
    # and retires it before reporting EOF.
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    source = os.open("/dev/null", os.O_RDONLY)
    guard_read, guard_write = os.pipe()
    before = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").exists() else None
    try:
        rights = array.array("i", [source])
        left.sendmsg([b""], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        try:
            module._wait_control(
                right.fileno(), guard_read, module.time.monotonic_ns() + module.NS)
        except module.NativeCandidateError:
            pass
        else:
            raise AssertionError("empty control packet with a right was accepted")
        if before is not None:
            check(set(os.listdir("/proc/self/fd")) == before, "empty packet right leaked")
    finally:
        left.close(); right.close(); os.close(source)
        os.close(guard_read); os.close(guard_write)
        if portable_cmsg_flag: del socket.MSG_CMSG_CLOEXEC

    reads = []
    read_end, write_end = os.pipe()
    guard_end, guard_write = os.pipe()
    original_read = module.os.read
    module.os.read = lambda descriptor, count: reads.append(count) or original_read(descriptor, count)
    try:
        try: module._wait_pipe_token(read_end, b"", guard_end, module.time.monotonic_ns() + module.NS)
        except module.NativeCandidateError: pass
        else: raise AssertionError("empty pipe token was accepted")
        check(reads == [], "pipe gate issued read(0)")
    finally:
        module.os.read = original_read
        for descriptor in (read_end, write_end, guard_end, guard_write): os.close(descriptor)

    # Even invalid ownership inputs and expired budgets are returned as sticky
    # diagnostics rather than escaping the supervision boundary.
    result, work_error, cleanup, settled = module._supervise_candidate(
        -1, -1, -1, -1, module.time.monotonic_ns(), module.time.monotonic_ns(), original, True)
    check(result is None and work_error is original and cleanup and not settled,
          "supervision exception boundary did not return uncertainty")

    calls = []
    original_close = module._close_and_prove
    module._close_and_prove = lambda descriptor: calls.append(descriptor) or (_ for _ in ()).throw(OSError(5, "close uncertain"))
    try:
        try:
            module._control_adopt(b"MALFORMED-PID1", 12345, module._classify_pid1_gate_packet)
        except module.CleanupUncertain as error:
            check(isinstance(error.work_error, module.NativeCandidateError),
                  "malformed PID1 packet primary error was replaced")
            check(len(error.cleanup_errors) == 1,
                  "rejected PID1 right close uncertainty was not aggregated")
        else:
            raise AssertionError("uncertain rejected PID1-right close was not sticky")
        check(calls == [12345], "uncertain close was retried")
    finally:
        module._close_and_prove = original_close

    if sys.platform.startswith("linux") and hasattr(os, "pidfd_open"):
        _supervisor_protocol_tests()


def _success_frame(payload):
    return len(payload + b"S").to_bytes(4, "big") + b"S" + payload


def _supervisor_protocol_row(raw, *, report=False):
    parent_control, child_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        parent_control.close(); os.close(result_read)
        try:
            module._write_all(result_write, raw)
            if report:
                module._control_send(child_control.fileno(), f"PID1-EXIT:{os.CLD_EXITED}:0".encode("ascii"))
        finally:
            os.close(result_write); child_control.close()
        os._exit(0)
    child_control.close(); os.close(result_write)
    helper_pidfd = os.pidfd_open(child, 0)
    deadline = module.time.monotonic_ns() + 2 * module.NS
    return module._supervise_candidate(
        helper_pidfd, -1, parent_control.detach(), result_read,
        deadline - module.NS, deadline, initial_no_pid1=not report, helper_pid=child)


def _supervisor_protocol_tests():
    payload = b'{}'
    frame = _success_frame(payload)
    result, error, cleanup, settled = _supervisor_protocol_row(frame)
    check((result, error, cleanup, settled) == (payload, None, [], True), "exact frame supervision failed")
    maximum = b"m" * module.MAX_RESULT_BYTES
    result, error, cleanup, settled = _supervisor_protocol_row(_success_frame(maximum))
    check(result == maximum and error is None and cleanup == [] and settled,
          "exact maximum streamed success was rejected")
    result, error, cleanup, settled = _supervisor_protocol_row(
        _success_frame(b"m" * (module.MAX_RESULT_BYTES + 1)))
    check(result is None and isinstance(error, module.NativeCandidateError) and cleanup == [] and settled,
          "one-byte-over-success streamed frame was not rejected and settled")
    result, error, cleanup, settled = _supervisor_protocol_row(
        b"x" * (module.MAX_PROTOCOL_BYTES + 5))
    check(result is None and isinstance(error, module.NativeCandidateError) and cleanup == [] and settled,
          "actual oversized writer was not settled")
    result, error, cleanup, settled = _supervisor_protocol_row(b"\0\0\0\x05Sx")
    check(result is None and isinstance(error, module.NativeCandidateError) and cleanup == [] and settled,
          "partial-frame EOF was not diagnosed and settled")
    result, error, cleanup, settled = _supervisor_protocol_row(frame, report=True)
    check(result == payload and error is None and cleanup == [] and settled,
          "queued PID1 report was lost to helper readiness/EOF race")

    child_failure = b"transaction:OSError_5"
    error_frame = len(child_failure + b"E").to_bytes(4, "big") + b"E" + child_failure
    original_poll = module.select.poll
    module.select.poll = lambda: (_ for _ in ()).throw(OSError(5, "poll fault"))
    try:
        result, error, cleanup, settled = _supervisor_protocol_row(error_frame)
    finally:
        module.select.poll = original_poll
    check(isinstance(error, OSError) and not isinstance(error, module.ChildCandidateError) and settled,
          f"child E frame replaced poll fault or ownership was abandoned: {error!r}; {cleanup!r}")

    _withheld_result_eof_test()
    _waitid_fault_tests()
    _helper_signal_retry_test()


def _withheld_result_eof_test():
    """A complete writer that withholds EOF is killed only after the work deadline."""
    baseline_fds, baseline_children = _fd_baseline(), _direct_child_pids()
    parent_control, child_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        parent_control.close(); os.close(result_read)
        module._write_all(result_write, _success_frame(b'{"withheld":true}'))
        while True:
            signal.pause()
    child_control.close(); os.close(result_write)
    helper_pidfd = os.pidfd_open(child, 0)
    oracle_pidfd = os.dup(helper_pidfd)
    work_deadline = module.time.monotonic_ns() + module.NS // 2
    try:
        result, error, cleanup, settled = module._supervise_candidate(
            helper_pidfd, -1, parent_control.detach(), result_read,
            work_deadline, work_deadline + 2 * module.NS, initial_no_pid1=True, helper_pid=child)
        check(module.time.monotonic_ns() >= work_deadline, "withheld EOF did not reach the work deadline")
        check(result == b'{"withheld":true}' and isinstance(error, module.NativeCandidateError),
              f"withheld EOF lost its complete frame/deadline error: {result!r}; {error!r}")
        check(cleanup == [] and settled, f"withheld EOF did not settle: {cleanup!r}")
        poller = select.poll()
        poller.register(oracle_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        check(bool(poller.poll(0)) and not Path(f"/proc/{child}").exists(),
              "independent oracle still sees withheld writer")
        try:
            os.waitid(os.P_PIDFD, oracle_pidfd, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("withheld writer was not exactly reaped by supervisor")
    finally:
        try:
            module._libc_call("kill", ctypes.c_int(child), ctypes.c_int(signal.SIGKILL))
        except OSError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
        os.close(oracle_pidfd)
    check(_fd_baseline() == baseline_fds and _direct_child_pids() == baseline_children,
          "withheld EOF case changed fd/child baseline")


def _waitid_fault_tests():
    for permanent in (False, True):
        baseline_fds, baseline_children = _fd_baseline(), _direct_child_pids()
        parent_control, child_control = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        result_read, result_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            parent_control.close(); os.close(result_read)
            module._write_all(result_write, _success_frame(b'{}'))
            os.close(result_write); child_control.close()
            os._exit(0)
        child_control.close(); os.close(result_write)
        helper_pidfd = os.pidfd_open(child, 0)
        oracle_pidfd = os.dup(helper_pidfd)
        original_waitid = module.os.waitid
        failures = []
        def faulty_waitid(idtype, identifier, options):
            if idtype == os.P_PIDFD and identifier == helper_pidfd and (permanent or not failures):
                failures.append(identifier)
                raise OSError(5, "injected helper waitid fault")
            return original_waitid(idtype, identifier, options)
        module.os.waitid = faulty_waitid
        try:
            deadline = module.time.monotonic_ns() + module.NS
            result, error, cleanup, settled = module._supervise_candidate(
                helper_pidfd, -1, parent_control.detach(), result_read,
                deadline - module.NS // 2, deadline, initial_no_pid1=True, helper_pid=child)
        finally:
            module.os.waitid = original_waitid
        try:
            check(failures, "helper waitid fault was not reached")
            if permanent:
                check(not settled and any(stage == "helper-reap-timeout" for stage, _error in cleanup),
                      f"final helper waitid fault did not retain uncertainty: {cleanup!r}")
                info = original_waitid(os.P_PIDFD, oracle_pidfd, os.WEXITED)
                check(info is not None, "oracle could not exactly reap final-waitid helper")
            else:
                check(settled and isinstance(error, OSError),
                      f"transient helper waitid fault did not settle/stay primary: {error!r}; {cleanup!r}")
                try:
                    original_waitid(os.P_PIDFD, oracle_pidfd, os.WEXITED | os.WNOHANG)
                except ChildProcessError:
                    pass
                else:
                    raise AssertionError("transient-waitid helper was not exactly reaped by supervisor")
        finally:
            try:
                module._libc_call("kill", ctypes.c_int(child), ctypes.c_int(signal.SIGKILL))
            except OSError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
            os.close(oracle_pidfd)
        check(_fd_baseline() == baseline_fds and _direct_child_pids() == baseline_children,
              f"helper waitid case permanent={permanent} changed fd/child baseline")


def _helper_signal_retry_test():
    """The reserve retries helper SIGKILL and reaps after the successful retry."""
    baseline_fds, baseline_children = _fd_baseline(), _direct_child_pids()
    parent_control, child_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    result_read, result_write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        parent_control.close(); os.close(result_read)
        while True:
            signal.pause()
    child_control.close(); os.close(result_write)
    helper_pidfd = os.pidfd_open(child, 0)
    oracle_pidfd = os.dup(helper_pidfd)
    original_signal = module.signal.pidfd_send_signal
    attempts = []
    primary = OSError(5, "supervisor work fault")
    def fail_once(pidfd, sent_signal, siginfo=None, flags=0):
        if pidfd == helper_pidfd and sent_signal == signal.SIGKILL:
            attempts.append(pidfd)
            if len(attempts) == 1:
                raise OSError(5, "first helper signal fault")
        return original_signal(pidfd, sent_signal, siginfo, flags)
    module.signal.pidfd_send_signal = fail_once
    try:
        deadline = module.time.monotonic_ns() + 2 * module.NS
        result, error, cleanup, settled = module._supervise_candidate(
            helper_pidfd, -1, parent_control.detach(), result_read,
            deadline - module.NS, deadline, primary, True, child)
        check(result is None and error is primary and settled,
              f"helper signal retry did not preserve work and settlement: {error!r}; {cleanup!r}")
        check(len(attempts) >= 2, "helper SIGKILL was not retried during the reap reserve")
        check(any(stage == "helper-final-signal" for stage, _error in cleanup),
              "first helper signal failure was not retained")
        poller = select.poll()
        poller.register(oracle_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        check(bool(poller.poll(0)) and not Path(f"/proc/{child}").exists(),
              "independent oracle still sees helper after supervisor return")
        try:
            os.waitid(os.P_PIDFD, oracle_pidfd, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("helper was not exactly reaped by supervisor")
    finally:
        module.signal.pidfd_send_signal = original_signal
        try:
            module._libc_call("kill", ctypes.c_int(child), ctypes.c_int(signal.SIGKILL))
        except OSError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
        os.close(oracle_pidfd)
    check(_fd_baseline() == baseline_fds and _direct_child_pids() == baseline_children,
          "helper signal retry changed fd/child baseline")


class _ProbeError(Exception):
    def __init__(self, category):
        self.category = category
        super().__init__(category)


def probe(condition, category):
    if not condition:
        raise _ProbeError(category)


class _ProbePackage:
    @staticmethod
    def run_candidate_transaction():
        probe(os.getpid() == 1, "pid1")
        status = Path("/proc/self/status").read_bytes()
        nspid = [row for row in status.splitlines() if row.startswith(b"NSpid:")]
        probe(len(nspid) == 1 and nspid[0].split()[-1] == b"1", "proc-nspid")
        probe({name for name in os.listdir("/proc") if name.isdigit()} == {"1"}, "proc-private")
        probe(set(os.listdir("/dev")) == {"null", "urandom"}, "dev-allowlist")
        probe(Path("/marker").read_bytes() == b"detached-before-outer-fork", "operation-descriptor")
        with open("/dev/urandom", "rb", buffering=0) as source:
            probe(len(source.read(16)) == 16, "urandom-bind")
        with open("/dev/null", "wb", buffering=0) as sink:
            probe(sink.write(b"x") == 1, "null-bind")
        Path("/tmp/probe").write_bytes(b"ok")
        probe(os.statvfs("/").f_flag & os.ST_RDONLY, "root-readonly")
        network = Path("/proc/net/dev").read_bytes().splitlines()[2:]
        probe([row.split(b":", 1)[0].strip() for row in network] == [b"lo"], "network-private")
        return b'{"native":true}'


class _DescendantProbePackage:
    @staticmethod
    def run_candidate_transaction():
        _ProbePackage.run_candidate_transaction()
        if os.fork() == 0:
            while True: signal.pause()
        return b'{"descendant":true}'


def _set_subreaper(enabled):
    observed = ctypes.c_int(-1)
    module._libc_call("prctl", ctypes.c_int(module.PR_GET_CHILD_SUBREAPER), ctypes.byref(observed),
                      ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    previous = observed.value
    module._libc_call("prctl", ctypes.c_int(module.PR_SET_CHILD_SUBREAPER), ctypes.c_ulong(int(enabled)),
                      ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    return previous


def _parent_death_gate_test(tree):
    """Kill the outer owner after both pidfds exist but before PID1 GO."""
    parent_control, creator_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    previous = _set_subreaper(True)
    creator = os.fork()
    if creator == 0:
        parent_control.close()
        control_fd = creator_control.detach()
        def hold_before_go(helper, pid1, gate):
            module._control_send(control_fd, f"{helper}:{pid1}".encode("ascii"), gate)
            while True:
                signal.pause()
        module._NATIVE_TEST_BEFORE_PID1_GO = hold_before_go
        try:
            deadline = module.time.monotonic_ns() + 20 * module.NS
            module._run_candidate_child(tree, {}, {}, _ProbePackage, deadline, deadline + 5 * module.NS)
        except BaseException:
            pass
        os._exit(125)

    creator_control.close()
    control_fd = parent_control.detach()
    os.close(tree)
    descriptors = []
    process_pidfds = []
    try:
        creator_pidfd = os.pidfd_open(creator, 0)
        descriptors.append(creator_pidfd)
        process_pidfds.append(creator_pidfd)
        packet, held_gate = module._wait_control(
            control_fd, creator_pidfd, module.time.monotonic_ns() + 10 * module.NS)
        descriptors.append(held_gate)
        helper_raw, pid1_raw = packet.split(b":", 1)
        helper, pid1 = int(helper_raw), int(pid1_raw)
        helper_pidfd, pid1_pidfd = os.pidfd_open(helper, 0), os.pidfd_open(pid1, 0)
        descriptors.extend((helper_pidfd, pid1_pidfd))
        process_pidfds.extend((pid1_pidfd, helper_pidfd))
        module._validate_pidfd(helper_pidfd, helper, creator, namespace_pid1=False)
        module._validate_pidfd(pid1_pidfd, pid1, helper, namespace_pid1=True)
        signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
        deadline = module.time.monotonic_ns() + 10 * module.NS
        creator_info = module._wait_pidfd_reap(creator_pidfd, deadline)
        helper_info = module._wait_pidfd_reap(helper_pidfd, deadline)
        pid1_info = module._wait_pidfd_reap(pid1_pidfd, deadline)
        for name, info in (("creator", creator_info), ("helper", helper_info), ("PID1", pid1_info)):
            check(info.si_code == os.CLD_KILLED and info.si_status == signal.SIGKILL,
                  f"{name} did not follow chained PDEATHSIG: {info}")
        check(not Path(f"/proc/{helper}").exists() and not Path(f"/proc/{pid1}").exists(),
              "parent-death gate left a process identity")
    finally:
        for descriptor in process_pidfds:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        for descriptor in process_pidfds:
            try:
                module._wait_pidfd_reap(descriptor, module.time.monotonic_ns() + 2 * module.NS)
            except BaseException:
                pass
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(control_fd)
        except OSError:
            pass
        _set_subreaper(bool(previous))


def _pre_pdeath_gate_test(tree, cut):
    """Drive parent death before helper/PID1 has armed and read back PDEATHSIG."""
    parent_control, creator_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    previous = _set_subreaper(True)
    creator = os.fork()
    if creator == 0:
        parent_control.close()
        control_fd = creator_control.detach()
        original_pdeath = module._set_parent_death_signal
        original_close_except = module._close_except
        original_snapshot = module._fd_snapshot
        calls = [0]
        helper_identity = [-1]
        module._close_except = lambda allowed: original_close_except([*allowed, control_fd])
        module._fd_snapshot = lambda audit: original_snapshot(audit) - {control_fd}
        def pause_before_arm():
            calls[0] += 1
            if calls[0] == 1:
                helper_identity[0] = os.getpid()
            selected = (cut == "helper" and calls[0] == 1) or (cut == "pid1" and calls[0] == 2)
            if selected:
                if cut == "helper":
                    payload = f"HELPER:{helper_identity[0]}".encode("ascii")
                else:
                    status = Path("/proc/self/status").read_bytes().splitlines()
                    nspid = [row for row in status if row.startswith(b"NSpid:\t")]
                    host_pid = int(nspid[0].split()[1])
                    payload = f"PID1:{helper_identity[0]}:{host_pid}".encode("ascii")
                module._control_send(control_fd, payload)
                gate = socket.socket(fileno=control_fd)
                try:
                    check(gate.recv(16) == b"ARM", "pre-PDEATH gate malformed")
                finally:
                    gate.detach()
            original_pdeath()
        module._set_parent_death_signal = pause_before_arm
        try:
            deadline = module.time.monotonic_ns() + 12 * module.NS
            outcome = module._run_candidate_child(
                tree, {}, {}, _ProbePackage, deadline, deadline + 3 * module.NS)
            module._control_send(
                control_fd,
                f"OUTCOME:{int(outcome[3])}:{len(outcome[2])}:{int(outcome[1] is not None)}".encode("ascii"),
            )
        except BaseException as error:
            try:
                module._control_send(control_fd, f"RAISED:{type(error).__name__}".encode("ascii"))
            except BaseException:
                pass
        os._exit(0)

    creator_control.close()
    os.close(tree)
    control = parent_control
    control.settimeout(10)
    creator_pidfd = os.pidfd_open(creator, 0)
    target_pidfds = []
    try:
        packet = control.recv(128)
        if cut == "helper":
            prefix, helper_raw = packet.split(b":")
            check(prefix == b"HELPER", f"wrong helper pre-arm packet: {packet!r}")
            helper = int(helper_raw)
            helper_pidfd = os.pidfd_open(helper, 0)
            target_pidfds.append(helper_pidfd)
            signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
            creator_info = module._wait_pidfd_reap(
                creator_pidfd, module.time.monotonic_ns() + 5 * module.NS)
            check((creator_info.si_code, creator_info.si_status) == (os.CLD_KILLED, signal.SIGKILL),
                  f"outer pre-arm oracle got wrong creator status: {creator_info}")
            control.send(b"ARM")
            helper_info = module._wait_pidfd_reap(
                helper_pidfd, module.time.monotonic_ns() + 5 * module.NS)
            check(helper_info.si_code == os.CLD_EXITED,
                  f"helper did not exit after arming against dead outer: {helper_info}")
            check(not Path(f"/proc/{helper}").exists(), "helper pre-arm identity remains")
        else:
            prefix, helper_raw, pid1_raw = packet.split(b":")
            check(prefix == b"PID1", f"wrong PID1 pre-arm packet: {packet!r}")
            helper, pid1 = int(helper_raw), int(pid1_raw)
            helper_pidfd, pid1_pidfd = os.pidfd_open(helper, 0), os.pidfd_open(pid1, 0)
            target_pidfds.extend((helper_pidfd, pid1_pidfd))
            signal.pidfd_send_signal(helper_pidfd, signal.SIGKILL)
            control.send(b"ARM")
            outcome = control.recv(128)
            check(outcome.startswith(b"OUTCOME:1:"), f"PID1 pre-arm cut did not settle: {outcome!r}")
            creator_info = module._wait_pidfd_reap(
                creator_pidfd, module.time.monotonic_ns() + 5 * module.NS)
            check(creator_info.si_code == os.CLD_EXITED and creator_info.si_status == 0,
                  f"PID1 pre-arm creator failed: {creator_info}")
            for name, pidfd, pid in (("helper", helper_pidfd, helper), ("PID1", pid1_pidfd, pid1)):
                poller = select.poll()
                poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                check(bool(poller.poll(0)) and not Path(f"/proc/{pid}").exists(),
                      f"{name} pre-arm identity remains")
    finally:
        for pidfd in target_pidfds:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except OSError:
                pass
        try:
            signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
        except OSError:
            pass
        for pidfd in target_pidfds:
            try:
                module._wait_pidfd_reap(pidfd, module.time.monotonic_ns() + module.NS)
            except BaseException:
                pass
        try:
            module._wait_pidfd_reap(creator_pidfd, module.time.monotonic_ns() + module.NS)
        except BaseException:
            pass
        for pidfd in target_pidfds:
            os.close(pidfd)
        os.close(creator_pidfd)
        control.close()
        _set_subreaper(bool(previous))


def _custodied_native_case(descriptor, *, helper_exit=None, fail_helper_pidfd=False,
                            fail_pidfd=False, package=_ProbePackage, waitid_fault=None):
    """Run a sacrificial outer while this process retains helper/PID1 pidfds."""
    baseline = _native_baseline()
    previous = _set_subreaper(True)
    parent_control, creator_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    tree = module._open_detached_tree(descriptor)
    creator = os.fork()
    if creator == 0:
        parent_control.close()
        control_fd = creator_control.detach()
        outer_pid = os.getpid()
        original_helper = module._helper_main
        original_pid1 = module._pid1_main
        original_close_except = module._close_except
        original_snapshot = module._fd_snapshot
        original_waitid = module.os.waitid
        original_fork = module.os.fork
        original_gate_classifier = module._classify_pid1_gate_packet
        target_pid = [-1]
        target_fds = set()
        helper_fds = set()
        wait_failures = []
        module._close_except = lambda allowed: original_close_except([*allowed, control_fd])
        module._fd_snapshot = lambda audit: original_snapshot(audit) - {control_fd}
        def advertise(kind):
            rows = Path("/proc/self/status").read_bytes().splitlines()
            nspid = [row for row in rows if row.startswith(b"NSpid:\t")]
            host_pid = int(nspid[0].split()[1])
            authority = os.pidfd_open(os.getpid(), 0)
            try:
                module._control_send(control_fd, f"{kind}:{host_pid}".encode("ascii"), authority)
            finally:
                os.close(authority)
        def observed_helper(*arguments):
            advertise("HELPER")
            return original_helper(*arguments)
        def observed_pid1(*arguments):
            advertise("PID1")
            return original_pid1(*arguments)
        module._helper_main = observed_helper
        module._pid1_main = observed_pid1
        if fail_helper_pidfd or fail_pidfd or helper_exit == "before-pidfd-transfer":
            def gated_observation_fork():
                pid = original_fork()
                expected = None
                if pid > 0 and os.getpid() == outer_pid and fail_helper_pidfd:
                    expected = b"HELPER-SEEN"
                elif pid > 0 and os.getpid() != outer_pid:
                    expected = b"PID1-SEEN"
                if expected is not None:
                    gate = socket.socket(fileno=control_fd)
                    try:
                        check(gate.recv(32) == expected, "custodian fork gate failed")
                    finally:
                        gate.detach()
                return pid
            module.os.fork = gated_observation_fork
        if waitid_fault is not None:
            def capture_report(packet, passed, expected_parent=None, available=True):
                action = original_gate_classifier(packet, passed, expected_parent, available)
                if action[0] == "pid1":
                    target_pid[0] = action[1]
                    target_fds.add(action[2])
                    for name in os.listdir("/proc/self/fd"):
                        if not name.isdigit():
                            continue
                        try:
                            if module._pidfd_process(int(name)) == expected_parent:
                                helper_fds.add(int(name))
                        except BaseException:
                            pass
                return action
            module._classify_pid1_gate_packet = capture_report
            def capture_pid1(helper, pid1, _gate):
                check(target_pid[0] == pid1 and helper_fds,
                      "outer PID1 gate hook lacked transferred/adopted authority")
            def faulty_waitid(idtype, identifier, options):
                if os.getpid() == outer_pid and idtype == os.P_PIDFD:
                    if target_pid[0] > 0 and identifier not in helper_fds:
                        target_fds.add(identifier)
                    if identifier not in target_fds and target_pid[0] > 0:
                        try:
                            if module._pidfd_process(identifier) == target_pid[0]:
                                target_fds.add(identifier)
                        except BaseException:
                            pass
                    if identifier in target_fds and (waitid_fault == "final" or not wait_failures):
                        wait_failures.append(identifier)
                        raise OSError(5, "injected outer adopted-PID1 waitid fault")
                return original_waitid(idtype, identifier, options)
            module._NATIVE_TEST_BEFORE_PID1_GO = capture_pid1
            module.os.waitid = faulty_waitid
            module._NATIVE_TEST_HELPER_EXIT_STAGE = "after-pidfd-transfer"
        else:
            module._NATIVE_TEST_HELPER_EXIT_STAGE = helper_exit
        module._NATIVE_TEST_FAIL_HELPER_PIDFD_OPEN = fail_helper_pidfd
        module._NATIVE_TEST_FAIL_PID1_PIDFD_OPEN = fail_pidfd
        try:
            deadline = module.time.monotonic_ns() + 8 * module.NS
            result, error, cleanup, settled = module._run_candidate_child(
                tree, {}, {}, package, deadline, deadline + 3 * module.NS)
            adopted_diagnostic = int(any(stage.startswith("adopted-") for stage, _item in cleanup))
            payload = (f"OUTCOME:{int(settled)}:{int(result is not None)}:"
                       f"{int(error is not None)}:{len(wait_failures)}:{adopted_diagnostic}").encode("ascii")
            module._control_send(control_fd, payload)
            gate = socket.socket(fileno=control_fd)
            try:
                check(gate.recv(16) == b"CUSTODIAN-OK", "custodian acknowledgement missing")
            finally:
                gate.detach()
        except BaseException as error:
            try:
                module._control_send(control_fd, f"RAISED:{type(error).__name__}".encode("ascii"))
            except BaseException:
                pass
        os._exit(0)

    creator_control.close()
    os.close(tree)
    control_fd = parent_control.detach()
    creator_pidfd = os.pidfd_open(creator, 0)
    authorities = {}
    outcome = None
    try:
        deadline = module.time.monotonic_ns() + 15 * module.NS
        while outcome is None:
            packet, passed = module._wait_control(control_fd, creator_pidfd, deadline)
            if packet.startswith((b"HELPER:", b"PID1:")):
                kind, pid_raw = packet.split(b":")
                check(passed >= 0 and kind.decode("ascii") not in authorities,
                      f"duplicate/missing custodian authority: {packet!r}")
                decoded_kind = kind.decode("ascii")
                authorities[decoded_kind] = (module._pidfd_process(passed), passed)
                release = None
                if decoded_kind == "HELPER" and fail_helper_pidfd:
                    release = b"HELPER-SEEN"
                elif decoded_kind == "PID1" and (fail_pidfd or helper_exit == "before-pidfd-transfer"):
                    release = b"PID1-SEEN"
                if release is not None:
                    control = socket.socket(fileno=control_fd)
                    try:
                        check(control.send(release) == len(release), "short custodian fork gate")
                    finally:
                        control.detach()
            else:
                check(passed < 0 and packet.startswith(b"OUTCOME:"),
                      f"custodied outer failed before outcome: {packet!r}")
                outcome = packet.decode("ascii").split(":")
        expect_pid1 = not fail_helper_pidfd
        check("HELPER" in authorities and (("PID1" in authorities) == expect_pid1),
              f"wrong custodian authority set: {authorities!r}")
        residual_pid1 = waitid_fault == "final"
        if residual_pid1:
            check(outcome[1] == "0", f"final adopted waitid fault was not unsettled: {outcome!r}")
        for kind, (pid, pidfd) in authorities.items():
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            terminal = bool(poller.poll(0))
            if residual_pid1 and kind == "PID1":
                check(terminal and Path(f"/proc/{pid}").exists(),
                      "final adopted waitid oracle did not retain the unreaped PID1")
                rows = Path(f"/proc/{pid}/status").read_bytes().splitlines()
                parent = [row for row in rows if row.startswith(b"PPid:\t")]
                check(len(parent) == 1 and int(parent[0].split()[1]) == creator,
                      "final adopted PID1 was not owned by sacrificial outer")
            else:
                check(terminal and not Path(f"/proc/{pid}").exists(),
                      f"{kind} escaped or remained unreaped while outer was alive: pid={pid}")
                try:
                    os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
                except ChildProcessError:
                    pass
                else:
                    raise AssertionError(f"external custodian unexpectedly owned {kind} reap")
        control = socket.socket(fileno=control_fd)
        try:
            check(control.send(b"CUSTODIAN-OK") == len(b"CUSTODIAN-OK"),
                  "short custodian acknowledgement")
        finally:
            control.detach()
        creator_info = module._wait_pidfd_reap(
            creator_pidfd, module.time.monotonic_ns() + 5 * module.NS)
        check(creator_info.si_code == os.CLD_EXITED and creator_info.si_status == 0,
              f"custodied outer failed: {creator_info}")
        if residual_pid1:
            pid, pidfd = authorities["PID1"]
            info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            check(info is not None and not Path(f"/proc/{pid}").exists(),
                  "external custodian did not exactly reap final-fault PID1")
    finally:
        for _kind, (pid, pidfd) in authorities.items():
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except OSError:
                pass
        try:
            signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
        except OSError:
            pass
        try:
            control = socket.socket(fileno=control_fd)
            control.send(b"CUSTODIAN-OK")
            control.detach()
        except OSError:
            pass
        for _kind, (_pid, pidfd) in authorities.items():
            try:
                module._wait_pidfd_reap(pidfd, module.time.monotonic_ns() + module.NS)
            except BaseException:
                pass
            os.close(pidfd)
        try:
            module._wait_pidfd_reap(creator_pidfd, module.time.monotonic_ns() + module.NS)
        except BaseException:
            pass
        os.close(creator_pidfd)
        os.close(control_fd)
        _set_subreaper(bool(previous))
    _check_native_baseline(baseline, "external custodian case")
    return outcome


def _native_case(descriptor, *, helper_exit=None, fail_helper_pidfd=False,
                 fail_pidfd=False, package=_ProbePackage):
    baseline = _native_baseline()
    module._NATIVE_TEST_HELPER_EXIT_STAGE = helper_exit
    module._NATIVE_TEST_FAIL_HELPER_PIDFD_OPEN = fail_helper_pidfd
    module._NATIVE_TEST_FAIL_PID1_PIDFD_OPEN = fail_pidfd
    try:
        tree = module._open_detached_tree(descriptor)
        deadline = module.time.monotonic_ns() + 10 * module.NS
        outcome = module._run_candidate_child(tree, {}, {}, package, deadline, deadline + 5 * module.NS)
    finally:
        module._NATIVE_TEST_HELPER_EXIT_STAGE = None
        module._NATIVE_TEST_FAIL_HELPER_PIDFD_OPEN = False
        module._NATIVE_TEST_FAIL_PID1_PIDFD_OPEN = False
    _check_native_baseline(baseline, f"native case helper-exit={helper_exit}")
    return outcome


def _adopted_waitid_fault_case(descriptor, permanent):
    outcome = _custodied_native_case(
        descriptor, waitid_fault="final" if permanent else "transient")
    expected_settled = "0" if permanent else "1"
    check(outcome[1] == expected_settled and int(outcome[4]) >= 1,
          f"adopted waitid fault did not run after helper exit: {outcome!r}")
    check(outcome[5] == "1", f"adopted waitid diagnostic missing after helper exit: {outcome!r}")


def _subreaper_fault_cases(descriptor):
    for cut in ("set", "readback"):
        baseline = _native_baseline()
        original_libc = module._libc_call
        gets = [0]
        def faulty_libc(name, *arguments):
            operation = arguments[0].value if name == "prctl" and arguments else -1
            if operation == module.PR_GET_CHILD_SUBREAPER:
                gets[0] += 1
                if cut == "readback" and gets[0] == 3:
                    raise OSError(5, "injected subreaper readback fault")
            if cut == "set" and operation == module.PR_SET_CHILD_SUBREAPER:
                cut_seen = getattr(faulty_libc, "cut_seen", False)
                if not cut_seen:
                    faulty_libc.cut_seen = True
                    raise OSError(5, "injected subreaper set fault")
            return original_libc(name, *arguments)
        module._libc_call = faulty_libc
        try:
            tree = module._open_detached_tree(descriptor)
            deadline = module.time.monotonic_ns() + 5 * module.NS
            result, error, cleanup, settled = module._run_candidate_child(
                tree, {}, {}, _ProbePackage, deadline, deadline + 2 * module.NS)
        finally:
            module._libc_call = original_libc
        check(result is None and isinstance(error, OSError) and settled,
              f"pre-fork subreaper {cut} fault was not no-child settled: {error!r}; {cleanup!r}")
        _check_native_baseline(baseline, f"subreaper {cut}")


def _subreaper_restore_sacrificial_case(descriptor):
    baseline = _native_baseline()
    marker_fd, marker_name = tempfile.mkstemp(prefix="stage2-no-cleanup-")
    os.close(marker_fd)
    marker = Path(marker_name)
    parent_control, creator_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    tree = module._open_detached_tree(descriptor)
    creator = os.fork()
    if creator == 0:
        parent_control.close()
        control = creator_control
        check(control.recv(16) == b"START", "restore sacrificial start gate failed")
        original_set = module._set_subreaper
        calls = [0]
        def fail_before_restore(enabled):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError(5, "injected restore failure before state change")
            return original_set(enabled)
        module._set_subreaper = fail_before_restore
        deadline = module.time.monotonic_ns() + 8 * module.NS
        result, error, cleanup, settled = module._run_candidate_child(
            tree, {}, {}, _ProbePackage, deadline, deadline + 3 * module.NS)
        # Model the production caller's cleanup gate without touching retained
        # authority: an unsettled result must leave the sentinel untouched.
        if settled:
            marker.unlink()
        state = module._subreaper_state()
        stages = ",".join(stage for stage, _item in cleanup) or "none"
        module._control_send(
            control.fileno(),
            f"OUTCOME:{int(settled)}:{state}:{int(marker.exists())}:{stages}".encode("ascii"),
        )
        check(control.recv(16) == b"CLEANED", "restore custodian acknowledgement missing")
        os._exit(0)

    creator_control.close()
    os.close(tree)
    previous = _set_subreaper(True)
    creator_pidfd = os.pidfd_open(creator, 0)
    try:
        check(parent_control.send(b"START") == len(b"START"), "short restore start gate")
        packet, passed = module._wait_control(
            parent_control.fileno(), creator_pidfd, module.time.monotonic_ns() + 15 * module.NS)
        check(passed < 0, "restore outcome carried a descriptor")
        outcome = packet.decode("ascii").split(":")
        check(outcome[0:4] == ["OUTCOME", "0", "1", "1"]
              and "subreaper-restore" in outcome[4] and marker.exists(),
              f"before-effect restore failure did not prove unsettled/no-cleanup: {outcome!r}")
        check(parent_control.send(b"CLEANED") == len(b"CLEANED"), "short restore cleanup ack")
        info = module._wait_pidfd_reap(
            creator_pidfd, module.time.monotonic_ns() + 5 * module.NS)
        check(info.si_code == os.CLD_EXITED and info.si_status == 0,
              f"restore sacrificial outer failed: {info}")
    finally:
        try:
            signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
        except OSError:
            pass
        try:
            parent_control.send(b"CLEANED")
        except OSError:
            pass
        try:
            module._wait_pidfd_reap(creator_pidfd, module.time.monotonic_ns() + module.NS)
        except BaseException:
            pass
        for child in _direct_child_pids():
            try:
                authority = os.pidfd_open(child, 0)
                signal.pidfd_send_signal(authority, signal.SIGKILL)
                module._wait_pidfd_reap(authority, module.time.monotonic_ns() + module.NS)
                os.close(authority)
            except BaseException:
                pass
        os.close(creator_pidfd)
        parent_control.close()
        _set_subreaper(bool(previous))
        try:
            marker.unlink()
        except FileNotFoundError:
            pass
    _check_native_baseline(baseline, "before-effect subreaper restore failure")


def _parent_close_uncertainty_cases(descriptor):
    for close_index, expected_stage in ((1, "control_helper-close"), (6, "parent-tree-close"),
                                        (7, "parent-device-null-close")):
        baseline = _native_baseline()
        outer_pid = os.getpid()
        original_fork = module.os.fork
        original_close = module._close_and_prove
        parent_forked = [False]
        parent_closes = [0]
        injected = [False]
        def tracked_fork():
            pid = original_fork()
            if pid > 0 and os.getpid() == outer_pid:
                parent_forked[0] = True
            return pid
        def uncertain_close(fd):
            if os.getpid() == outer_pid and parent_forked[0]:
                parent_closes[0] += 1
                if parent_closes[0] == close_index:
                    injected[0] = True
                    original_close(fd)
                    raise OSError(5, "injected actual parent close uncertainty")
            return original_close(fd)
        module.os.fork = tracked_fork
        module._close_and_prove = uncertain_close
        try:
            tree = module._open_detached_tree(descriptor)
            deadline = module.time.monotonic_ns() + 5 * module.NS
            result, error, cleanup, settled = module._run_candidate_child(
                tree, {}, {}, _ProbePackage, deadline, deadline + 2 * module.NS)
        finally:
            module.os.fork = original_fork
            module._close_and_prove = original_close
        check(injected[0] and not settled
              and any(stage == expected_stage for stage, _error in cleanup),
              f"actual parent {expected_stage} uncertainty was not retained: {error!r}; {cleanup!r}")
        _check_native_baseline(baseline, expected_stage)


def _spawn_known_adopted_namespace_child():
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    creator = os.fork()
    if creator == 0:
        os.close(read_end)
        module._libc_call("unshare", ctypes.c_int(module.CLONE_NEWPID))
        pid = os.fork()
        if pid == 0:
            rows = Path("/proc/self/status").read_bytes().splitlines()
            nspid = [row for row in rows if row.startswith(b"NSpid:\t")]
            host_pid = int(nspid[0].split()[1])
            os.write(write_end, f"{host_pid}\n".encode("ascii"))
            while True:
                signal.pause()
        os._exit(0)
    os.close(write_end)
    try:
        waited, status = os.waitpid(creator, 0)
        check(waited == creator and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
              "namespace-child creator failed")
        raw = os.read(read_end, 64)
        check(raw.endswith(b"\n") and raw[:-1].isdigit(), "missing known adopted child identity")
        child = int(raw)
    finally:
        os.close(read_end)
    deadline = module.time.monotonic_ns() + module.NS
    while module.time.monotonic_ns() < deadline:
        children = _direct_child_pids()
        if child in children:
            return child
        module.time.sleep(0.01)
    raise AssertionError("known namespace child was not adopted")


def _adopted_census_retry_case(descriptor):
    baseline = _native_baseline()
    original = module._direct_namespace_children
    calls = []
    known_adopted = set()
    retry_verified = [False]
    def fail_once():
        if not known_adopted:
            known_adopted.add(_spawn_known_adopted_namespace_child())
        children = original()
        calls.append(tuple(children))
        observed = {pid for pid, _is_pid1 in children}
        if len(calls) == 1:
            check(known_adopted <= observed, "known adopted child missing at first census fault")
            raise OSError(5, "injected adopted census fault with known child held")
        if known_adopted and not retry_verified[0]:
            check(known_adopted & observed, "known adopted child was not held across census retry")
            retry_verified[0] = True
        return children
    module._direct_namespace_children = fail_once
    try:
        tree = module._open_detached_tree(descriptor)
        deadline = module.time.monotonic_ns() + 5 * module.NS
        result, error, cleanup, settled = module._run_candidate_child(
            tree, {}, {}, _ProbePackage, deadline, deadline + 2 * module.NS)
    finally:
        module._direct_namespace_children = original
    check(result == b'{"native":true}' and error is None and settled and len(calls) >= 2
          and known_adopted and retry_verified[0]
          and any(stage == "adopted-census" for stage, _error in cleanup),
          f"adopted census was not retried to settlement: {error!r}; {cleanup!r}")
    _check_native_baseline(baseline, "adopted census retry")


def _post_go_lifecycle_case(descriptor, cut):
    """Causal deadline/helper/outer cuts after PID1 GO with a live descendant."""
    baseline = _native_baseline()
    own_mount = os.stat("/proc/self/ns/mnt")
    own_mount_identity = own_mount.st_dev, own_mount.st_ino
    previous = _set_subreaper(True)
    parent_control, creator_control = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    tree = module._open_detached_tree(descriptor)
    creator = os.fork()
    if creator == 0:
        parent_control.close()
        control_fd = creator_control.detach()
        original_helper = module._helper_main
        original_pid1 = module._pid1_main
        original_close_except = module._close_except
        original_snapshot = module._fd_snapshot
        module._close_except = lambda allowed: original_close_except([*allowed, control_fd])
        module._fd_snapshot = lambda audit: original_snapshot(audit) - {control_fd}
        def advertise(kind):
            rows = Path("/proc/self/status").read_bytes().splitlines()
            nspid = [row for row in rows if row.startswith(b"NSpid:\t")]
            host_pid = int(nspid[0].split()[1])
            authority = os.pidfd_open(os.getpid(), 0)
            try:
                module._control_send(control_fd, f"{kind}:{host_pid}".encode("ascii"), authority)
            finally:
                os.close(authority)
            return host_pid
        def observed_helper(*arguments):
            advertise("HELPER")
            return original_helper(*arguments)
        def observed_pid1(*arguments):
            advertise("PID1")
            return original_pid1(*arguments)
        module._helper_main = observed_helper
        module._pid1_main = observed_pid1
        work_deadline = module.time.monotonic_ns() + ((2 if cut == "deadline" else 8) * module.NS)
        class ActiveDescendantPackage:
            @staticmethod
            def run_candidate_transaction():
                _ProbePackage.run_candidate_transaction()
                ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
                descendant = os.fork()
                if descendant == 0:
                    os.close(ready_read)
                    advertise("DESCENDANT")
                    os.write(ready_write, b"1")
                    while True:
                        signal.pause()
                os.close(ready_write)
                check(os.read(ready_read, 1) == b"1", "descendant did not become active")
                os.close(ready_read)
                module._control_send(control_fd, f"ACTIVE:{work_deadline}".encode("ascii"))
                while True:
                    signal.pause()
        result, error, cleanup, settled = module._run_candidate_child(
            tree, {}, {}, ActiveDescendantPackage, work_deadline, work_deadline + 3 * module.NS)
        stages = ",".join(stage for stage, _item in cleanup) or "none"
        module._control_send(
            control_fd,
            f"OUTCOME:{int(settled)}:{int(error is not None)}:{stages}".encode("ascii"),
        )
        gate = socket.socket(fileno=control_fd)
        try:
            check(gate.recv(16) == b"POST-GO-OK", "post-GO custodian acknowledgement missing")
        finally:
            gate.detach()
        os._exit(0)

    creator_control.close()
    os.close(tree)
    control_fd = parent_control.detach()
    creator_pidfd = os.pidfd_open(creator, 0)
    authorities = {}
    active_deadline = None
    outcome = None
    creator_reaped = False
    mount_identities = {}
    try:
        deadline = module.time.monotonic_ns() + 15 * module.NS
        while active_deadline is None:
            packet, passed = module._wait_control(control_fd, creator_pidfd, deadline)
            if packet.startswith((b"HELPER:", b"PID1:", b"DESCENDANT:")):
                kind, pid_raw = packet.split(b":")
                decoded = kind.decode("ascii")
                check(passed >= 0 and decoded not in authorities,
                      f"invalid post-GO authority: {packet!r}")
                pid = module._pidfd_process(passed)
                authorities[decoded] = (pid, passed)
            else:
                check(passed < 0 and packet.startswith(b"ACTIVE:"),
                      f"post-GO case failed before activation: {packet!r}")
                active_deadline = int(packet.split(b":", 1)[1])
        check(set(authorities) == {"HELPER", "PID1", "DESCENDANT"},
              f"post-GO authority set incomplete: {authorities!r}")
        for kind, (pid, _pidfd) in authorities.items():
            observed = os.stat(f"/proc/{pid}/ns/mnt")
            mount_identities[kind] = observed.st_dev, observed.st_ino
        check(mount_identities["PID1"] == mount_identities["DESCENDANT"]
              and mount_identities["PID1"] != own_mount_identity,
              f"post-GO mount oracle did not observe private namespace: {mount_identities!r}")
        if cut == "helper":
            signal.pidfd_send_signal(authorities["HELPER"][1], signal.SIGKILL)
        elif cut == "outer":
            signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
        if cut == "outer":
            info = module._wait_pidfd_reap(
                creator_pidfd, module.time.monotonic_ns() + 5 * module.NS)
            creator_reaped = True
            check((info.si_code, info.si_status) == (os.CLD_KILLED, signal.SIGKILL),
                  f"post-GO outer got wrong status: {info}")
        else:
            packet, passed = module._wait_control(control_fd, creator_pidfd, deadline)
            check(passed < 0 and packet.startswith(b"OUTCOME:1:1:"),
                  f"post-GO {cut} did not settle with work error: {packet!r}")
            outcome = packet
            if cut == "deadline":
                check(module.time.monotonic_ns() >= active_deadline,
                      "native post-GO deadline case returned before work deadline")
        for kind, (pid, pidfd) in authorities.items():
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            wait_deadline = module.time.monotonic_ns() + 5 * module.NS
            while not poller.poll(50) and module.time.monotonic_ns() < wait_deadline:
                pass
            check(bool(poller.poll(0)), f"post-GO {cut} left live {kind} identity {pid}")
            if cut == "outer":
                try:
                    info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
                    check(info is not None, f"missing external {kind} reap status")
                except ChildProcessError:
                    pass
            check(not Path(f"/proc/{pid}").exists(),
                  f"post-GO {cut} left unreaped {kind} identity {pid}")
            check(not Path(f"/proc/{pid}/ns/mnt").exists(),
                  f"post-GO {cut} left {kind} mount namespace path")
        if cut != "outer":
            control = socket.socket(fileno=control_fd)
            try:
                check(control.send(b"POST-GO-OK") == len(b"POST-GO-OK"),
                      "short post-GO acknowledgement")
            finally:
                control.detach()
            info = module._wait_pidfd_reap(
                creator_pidfd, module.time.monotonic_ns() + 5 * module.NS)
            creator_reaped = True
            check(info.si_code == os.CLD_EXITED and info.si_status == 0,
                  f"post-GO {cut} outer failed: {info}")
    finally:
        for _kind, (_pid, pidfd) in authorities.items():
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except OSError:
                pass
        try:
            signal.pidfd_send_signal(creator_pidfd, signal.SIGKILL)
        except OSError:
            pass
        if cut != "outer":
            try:
                control = socket.socket(fileno=control_fd)
                control.send(b"POST-GO-OK")
                control.detach()
            except OSError:
                pass
        if not creator_reaped:
            try:
                module._wait_pidfd_reap(creator_pidfd, module.time.monotonic_ns() + module.NS)
            except BaseException:
                pass
        for _kind, (_pid, pidfd) in authorities.items():
            try:
                module._wait_pidfd_reap(pidfd, module.time.monotonic_ns() + module.NS)
            except BaseException:
                pass
            os.close(pidfd)
        os.close(creator_pidfd)
        os.close(control_fd)
        _set_subreaper(bool(previous))
    current_mount = os.stat("/proc/self/ns/mnt")
    check((current_mount.st_dev, current_mount.st_ino) == own_mount_identity,
          f"post-GO {cut} changed custodian mount namespace")
    check(not module.PRIVATE_STAGING.exists(), f"post-GO {cut} leaked private mount staging")
    _check_native_baseline(baseline, f"post-GO {cut}")


def native_test():
    module._platform_gate()
    module._lifecycle_preflight()
    root = Path(tempfile.mkdtemp(prefix="stage2-doublefork-native-"))
    source = root / "source"
    source.mkdir(mode=0o755)
    for name in ("proc", "dev", "tmp"):
        (source / name).mkdir(mode=0o755)
    (source / "marker").write_bytes(b"detached-before-outer-fork")
    descriptor = -1
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        case_baseline = _native_baseline()
        result, work_error, cleanup_errors, settled = _native_case(descriptor)
        check(work_error is None,
              f"native child failed: {work_error!r}; result={result!r}; cleanup={cleanup_errors!r}")
        check(cleanup_errors == [], f"native cleanup uncertain: {cleanup_errors!r}")
        check(result == b'{"native":true}', f"unexpected native result: {result!r}")
        check(settled, "double-fork tree did not settle")
        check(not module.PRIVATE_STAGING.exists(), "private staging escaped helper mount namespace")

        result, error, cleanup, settled = _native_case(descriptor, package=_DescendantProbePackage)
        check(result == b'{"descendant":true}' and error is None and cleanup == [] and settled,
              f"adopted namespace descendant did not settle: {error!r}; {cleanup!r}")
        custodied_descendant = _custodied_native_case(descriptor, package=_DescendantProbePackage)
        check(custodied_descendant[1:4] == ["1", "1", "0"],
              f"custodied descendant case failed: {custodied_descendant!r}")

        for stage, fail_helper_pidfd, fail_pidfd in (
            ("before-pidfd-transfer", False, False),
            ("after-pidfd-transfer", False, False),
            (None, False, True),
            (None, True, False),
        ):
            outcome = _custodied_native_case(
                descriptor, helper_exit=stage, fail_helper_pidfd=fail_helper_pidfd,
                fail_pidfd=fail_pidfd)
            check(outcome[1:4] == ["1", "0", "1"],
                  f"custodied fault cut did not settle: stage={stage}; "
                  f"helper-pidfd={fail_helper_pidfd}; outcome={outcome!r}")

        # A failed outer fork creates no process tree.  Once every setup FD and
        # detached tree closes, child absence is proved and cleanup is safe.
        fork_baseline = _native_baseline()
        fork_tree = module._open_detached_tree(descriptor)
        original_fork = module.os.fork
        module.os.fork = lambda: (_ for _ in ()).throw(OSError(11, "test outer fork failure"))
        try:
            deadline = module.time.monotonic_ns() + 5 * module.NS
            result, error, cleanup, settled = module._run_candidate_child(
                fork_tree, {}, {}, _ProbePackage, deadline, deadline + 2 * module.NS)
        finally:
            module.os.fork = original_fork
        check(result is None and isinstance(error, OSError) and cleanup == [] and settled,
              f"pre-fork no-child failure was not settled: {error!r}; {cleanup!r}")
        _check_native_baseline(fork_baseline, "outer fork failure")

        _adopted_census_retry_case(descriptor)
        for permanent in (False, True):
            _adopted_waitid_fault_case(descriptor, permanent)
        _subreaper_fault_cases(descriptor)
        _subreaper_restore_sacrificial_case(descriptor)
        _parent_close_uncertainty_cases(descriptor)
        for cut in ("deadline", "helper", "outer"):
            _post_go_lifecycle_case(descriptor, cut)

        death_baseline = _native_baseline()
        death_tree = module._open_detached_tree(descriptor)
        _parent_death_gate_test(death_tree)
        _check_native_baseline(death_baseline, "armed parent-death gate")
        for cut in ("helper", "pid1"):
            baseline = _native_baseline()
            prearm_tree = module._open_detached_tree(descriptor)
            _pre_pdeath_gate_test(prearm_tree, cut)
            _check_native_baseline(baseline, f"pre-PDEATH {cut}")
        _check_native_baseline(case_baseline, "complete hostile native corpus")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        shutil.rmtree(root)


portable_tests()
required = os.environ.get("COGS_REQUIRE_DOUBLEFORK_NATIVE_TEST") == "1"
enabled = os.environ.get("COGS_DOUBLEFORK_NATIVE_TEST") == "1"
if required:
    check(enabled, "required native gate was not enabled")
if enabled:
    native_test()
print(f"stage2 package double-fork tests passed; native={'ran' if enabled else 'not-requested'}")
