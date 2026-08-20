#!/usr/bin/env python3
"""Portable checks plus the required privileged double-fork native probe."""

import ctypes
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
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
        with open("/dev/urandom", "rb", buffering=0) as source:
            probe(len(source.read(16)) == 16, "urandom-bind")
        with open("/dev/null", "wb", buffering=0) as sink:
            probe(sink.write(b"x") == 1, "null-bind")
        Path("/tmp/probe").write_bytes(b"ok")
        probe(os.statvfs("/").f_flag & os.ST_RDONLY, "root-readonly")
        network = Path("/proc/net/dev").read_bytes().splitlines()[2:]
        probe([row.split(b":", 1)[0].strip() for row in network] == [b"lo"], "network-private")
        return b'{"native":true}'


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


def native_test():
    module._platform_gate()
    module._lifecycle_preflight()
    root = Path(tempfile.mkdtemp(prefix="stage2-doublefork-native-"))
    source = root / "source"
    source.mkdir(mode=0o755)
    for name in ("proc", "dev", "tmp"):
        (source / name).mkdir(mode=0o755)
    (source / "marker").write_bytes(b"detached-before-outer-fork")
    mounted = False
    descriptor = -1
    try:
        subprocess.run(["mount", "--bind", source, source], check=True)
        mounted = True
        descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        tree = module._open_detached_tree(descriptor, allow_root_mount=True)
        deadline = module.time.monotonic_ns() + 15 * module.NS
        result, work_error, cleanup_errors, settled = module._run_candidate_child(
            tree, {}, {}, _ProbePackage, deadline, deadline + 5 * module.NS)
        check(work_error is None,
              f"native child failed: {work_error!r}; result={result!r}; cleanup={cleanup_errors!r}")
        check(cleanup_errors == [], f"native cleanup uncertain: {cleanup_errors!r}")
        check(result == b'{"native":true}', f"unexpected native result: {result!r}")
        check(settled, "double-fork tree did not settle")
        check(not module.PRIVATE_STAGING.exists(), "private staging escaped helper mount namespace")
        death_tree = module._open_detached_tree(descriptor, allow_root_mount=True)
        _parent_death_gate_test(death_tree)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if mounted:
            subprocess.run(["umount", source], check=True)
        shutil.rmtree(root)


portable_tests()
required = os.environ.get("COGS_REQUIRE_DOUBLEFORK_NATIVE_TEST") == "1"
enabled = os.environ.get("COGS_DOUBLEFORK_NATIVE_TEST") == "1"
if required:
    check(enabled, "required native gate was not enabled")
if enabled:
    native_test()
print(f"stage2 package double-fork tests passed; native={'ran' if enabled else 'not-requested'}")
