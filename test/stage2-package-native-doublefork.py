#!/usr/bin/env python3
"""Portable checks plus the required privileged double-fork native probe."""

import ctypes
import importlib.util
import os
from pathlib import Path
import array
import shutil
import signal
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
        try: module._control_no_fd(b"BAD", 12345, module.HELPER_GO, "bad gate")
        except module.CleanupUncertain: pass
        else: raise AssertionError("uncertain rejected-right close was not sticky")
        check(calls == [12345], "uncertain close was retried")
    finally:
        module._close_and_prove = original_close

    if sys.platform.startswith("linux") and hasattr(os, "pidfd_open"):
        _supervisor_protocol_tests()


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
    frame = len(payload + b"S").to_bytes(4, "big") + b"S" + payload
    result, error, cleanup, settled = _supervisor_protocol_row(frame)
    check((result, error, cleanup, settled) == (payload, None, [], True), "exact frame supervision failed")
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

    original_poll = module.select.poll
    module.select.poll = lambda: (_ for _ in ()).throw(OSError(5, "poll fault"))
    try:
        result, error, cleanup, settled = _supervisor_protocol_row(frame)
    finally:
        module.select.poll = original_poll
    check(isinstance(error, OSError) and settled,
          f"supervisor poll exception escaped or abandoned ownership: {error!r}; {cleanup!r}")


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


def _native_case(descriptor, *, helper_exit=None, fail_pidfd=False, package=_ProbePackage):
    module._NATIVE_TEST_HELPER_EXIT_STAGE = helper_exit
    module._NATIVE_TEST_FAIL_PID1_PIDFD_OPEN = fail_pidfd
    try:
        tree = module._open_detached_tree(descriptor)
        deadline = module.time.monotonic_ns() + 10 * module.NS
        return module._run_candidate_child(tree, {}, {}, package, deadline, deadline + 5 * module.NS)
    finally:
        module._NATIVE_TEST_HELPER_EXIT_STAGE = None
        module._NATIVE_TEST_FAIL_PID1_PIDFD_OPEN = False


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

        for stage, fail_pidfd in (("before-pidfd-transfer", False), ("after-pidfd-transfer", False),
                                  (None, True)):
            result, error, cleanup, settled = _native_case(
                descriptor, helper_exit=stage, fail_pidfd=fail_pidfd)
            check(result is None and error is not None, f"fault cut unexpectedly succeeded: {stage}")
            check(cleanup == [] and settled,
                  f"fault cut did not settle: stage={stage}; error={error!r}; cleanup={cleanup!r}")

        death_tree = module._open_detached_tree(descriptor)
        _parent_death_gate_test(death_tree)
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
