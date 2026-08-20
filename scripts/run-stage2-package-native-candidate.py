#!/usr/bin/env python3
"""One-shot native Linux/amd64 package candidate over the fixed Stage 2 rootfs.

The package transaction runs as PID 1 in a new PID namespace.  A directly
forked, parent-gated helper unshares mount/PID/network namespaces and uses a
second os.fork() to create namespace PID 1.  The trusted parent validates
pidfds for both processes before releasing the transaction.  This is a small,
one-purpose trusted-root containment launcher, not a hostile-root sandbox.
"""

import array
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import stat
import sys
import threading
import time

sys.dont_write_bytecode = True

FIXED_SOURCE = Path("/var/lib/cogs/stage2-completion-v1/source")
FIXED_DRIVER = FIXED_SOURCE / "scripts/run-stage2-package-native-candidate.py"
FIXED_PHASE_A = FIXED_SOURCE / "scripts/run-stage2-phase-a-candidate.py"
REMOTE = FIXED_SOURCE / "deploy/aws-feasibility/remote"
PRIVATE_STAGING = Path("/run/cogs-stage2-native-private-v1")
PRIVATE_ROOT = PRIVATE_STAGING / "root"
PREFLIGHT_SOURCE = Path("/run/cogs-stage2-native-preflight-source-v1")
APPROVAL = "download-16-fixed-public-stage2-artifacts"
TRUST_BOUNDARY = (
    "reviewed CPython PID1 and imported transaction modules are trusted; "
    "namespaces contain lifecycle and residue, not hostile initial-user-namespace root"
)
FIXED_CPYTHON = (3, 12)
MAX_RESULT_BYTES = 4096
MAX_PROTOCOL_BYTES = MAX_RESULT_BYTES + 128
OUTER_SECONDS = 2_700
CHILD_SECONDS = 1_300
CLEANUP_RESERVE_SECONDS = 600
REAP_SECONDS = 15
NS = 1_000_000_000
UINT_MAX = (1 << 32) - 1

# Linux x86-64 ABI constants.  _platform_gate() rejects every other ABI.
SYS_GETDENTS64 = 217
SYS_OPEN_TREE = 428
SYS_MOVE_MOUNT = 429
SYS_CLOSE_RANGE = 436
SYS_MOUNT_SETATTR = 442
CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
AT_FDCWD = -100
AT_EMPTY_PATH = 0x1000
AT_RECURSIVE = 0x8000
OPEN_TREE_CLONE = 1
OPEN_TREE_CLOEXEC = 0o2000000
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MOVE_MOUNT_T_EMPTY_PATH = 0x00000040
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
PR_SET_PDEATHSIG = 1
PR_GET_PDEATHSIG = 2
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
HELPER_READY = b"HELPER-READY"
HELPER_GO = b"HELPER-GO"
PID1_READY = b"PID1-READY\n"
PID1_GO = b"PID1-GO"
PID1_FD = b"PID1-FD:"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_NATIVE_TEST_BEFORE_PID1_GO = None

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


class _MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64),
    ]


_require_abi = (
    ctypes.sizeof(_MountAttr) == 32
    and tuple(getattr(_MountAttr, name).offset for name, _kind in _MountAttr._fields_) == (0, 8, 16, 24)
)


class NativeCandidateError(Exception):
    """A bounded, fail-closed candidate error."""


class ChildCandidateError(NativeCandidateError):
    def __init__(self, stage, category):
        self.stage = stage
        self.category = category
        super().__init__(f"{stage}:{category}")


class CleanupUncertain(NativeCandidateError):
    category = "cleanup_uncertain"

    def __init__(self, work_error, cleanup_errors):
        self.work_error = work_error
        self.cleanup_errors = tuple(cleanup_errors)
        detail = ",".join(f"{stage}:{_category(error)}" for stage, error in cleanup_errors)
        super().__init__(detail or "cleanup uncertainty")


class _Outcome:
    """Monotonic terminal aggregate: cleanup errors never mask work errors."""

    def __init__(self):
        self.work_error = None
        self.cleanup_errors = []

    def work(self, error):
        if self.work_error is None:
            self.work_error = error

    def cleanup(self, stage, error):
        self.cleanup_errors.append((stage, error))

    def finish(self):
        if self.cleanup_errors:
            raise CleanupUncertain(self.work_error, self.cleanup_errors) from self.work_error
        if self.work_error is not None:
            raise self.work_error


def _require(condition, message="candidate invariant"):
    if not condition:
        raise NativeCandidateError(message)


def _category(error):
    if isinstance(error, OSError) and error.errno is not None:
        return f"OSError_{error.errno}"
    value = getattr(error, "category", type(error).__name__)
    return value if isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) else "unknown"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    _require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _platform_gate():
    _require(sys.implementation.name == "cpython" and sys.version_info[:2] == FIXED_CPYTHON,
             "fixed CPython 3.12 required")
    _require(threading.current_thread() is threading.main_thread() and threading.active_count() == 1,
             "fork launcher requires the sole CPython main thread")
    _require(_require_abi, "fixed Linux ABI structure mismatch")
    _require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    _require(hasattr(os, "pidfd_open") and hasattr(os, "P_PIDFD"), "pidfd wait unavailable")
    _require(hasattr(signal, "pidfd_send_signal"), "pidfd signaling unavailable")
    _require(hasattr(os, "fork"), "os.fork unavailable")


def _libc_call(name, *arguments):
    call = getattr(_LIBC, name)
    call.restype = ctypes.c_int
    if call(*arguments) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, f"{name}: {os.strerror(saved)}")


def _syscall(number, *arguments):
    result = _LIBC.syscall(ctypes.c_long(number), *arguments)
    if result < 0:
        saved = ctypes.get_errno()
        raise OSError(saved, f"syscall-{number}: {os.strerror(saved)}")
    return int(result)


def _mount(source, target, filesystem, flags, data=None):
    encoded = lambda value: None if value is None else os.fsencode(value)
    _libc_call(
        "mount",
        ctypes.c_char_p(encoded(source)),
        ctypes.c_char_p(encoded(target)),
        ctypes.c_char_p(encoded(filesystem)),
        ctypes.c_ulong(flags),
        ctypes.c_char_p(encoded(data)),
    )


def _mount_setattr(path, set_flags, *, clear_flags=0, recursive=False):
    attributes = _MountAttr(set_flags, clear_flags, 0, 0)
    flags = AT_RECURSIVE if recursive else 0
    _syscall(
        SYS_MOUNT_SETATTR, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(os.fsencode(path)),
        ctypes.c_uint(flags), ctypes.byref(attributes), ctypes.c_size_t(ctypes.sizeof(attributes)),
    )


def _mount_setattr_fd(descriptor, set_flags, *, clear_flags=0, recursive=False):
    attributes = _MountAttr(set_flags, clear_flags, 0, 0)
    flags = AT_EMPTY_PATH | (AT_RECURSIVE if recursive else 0)
    _syscall(
        SYS_MOUNT_SETATTR, ctypes.c_int(descriptor), ctypes.c_char_p(b""),
        ctypes.c_uint(flags), ctypes.byref(attributes), ctypes.c_size_t(ctypes.sizeof(attributes)),
    )


def _unescape_mount_path(raw):
    for encoded, value in ((b"\\040", b" "), (b"\\011", b"\t"),
                           (b"\\012", b"\n"), (b"\\134", b"\\")):
        raw = raw.replace(encoded, value)
    return raw


def _require_no_nested_mounts(root_descriptor, *, allow_root_mount=False):
    source = os.fsencode(os.readlink(f"/proc/self/fd/{root_descriptor}"))
    _require(source.startswith(b"/") and b"\n" not in source, "invalid retained root path")
    rows = []
    for row in Path("/proc/self/mountinfo").read_bytes().splitlines():
        fields = row.split(b" - ", 1)[0].split()
        _require(len(fields) >= 6, "malformed mountinfo")
        mountpoint = _unescape_mount_path(fields[4])
        if mountpoint == source or mountpoint.startswith(source + b"/"):
            rows.append(mountpoint)
    expected = [source] if allow_root_mount else []
    _require(rows == expected, "retained root contains an unexpected mount")


def _open_detached_tree(root_descriptor, *, allow_root_mount=False):
    """Clone and harden the retained mount in the parent's mount namespace."""
    _require_no_nested_mounts(root_descriptor, allow_root_mount=allow_root_mount)
    tree = _syscall(
        SYS_OPEN_TREE, ctypes.c_int(root_descriptor), ctypes.c_char_p(b""),
        ctypes.c_uint(AT_EMPTY_PATH | AT_RECURSIVE | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC),
    )
    try:
        _mount_setattr_fd(
            tree, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, recursive=True)
    except BaseException as primary:
        try:
            _close_and_prove(tree)
        except BaseException as cleanup:
            raise CleanupUncertain(primary, (("detached-root-close", cleanup),)) from primary
        raise
    return tree


def _close_range(first, last):
    _syscall(SYS_CLOSE_RANGE, ctypes.c_uint(first), ctypes.c_uint(last), ctypes.c_uint(0))


def _close_except(allowed):
    kept = sorted(set(allowed))
    _require(len(kept) == len(allowed) and all(type(fd) is int and 0 <= fd <= UINT_MAX for fd in kept),
             "invalid descriptor allowlist")
    cursor = 0
    for descriptor in kept:
        if cursor < descriptor:
            _close_range(cursor, descriptor - 1)
        cursor = descriptor + 1
    if cursor <= UINT_MAX:
        _close_range(cursor, UINT_MAX)


def _fd_snapshot(directory):
    """Read /proc/self/fd without allocating another descriptor."""
    found = set()
    while True:
        buffer = ctypes.create_string_buffer(4096)
        count = _syscall(SYS_GETDENTS64, ctypes.c_int(directory), ctypes.byref(buffer), ctypes.sizeof(buffer))
        if count == 0:
            return found
        raw = buffer.raw[:count]
        offset = 0
        while offset < count:
            _require(offset + 19 <= count, "malformed getdents record")
            length = int.from_bytes(raw[offset + 16:offset + 18], sys.byteorder)
            _require(length >= 20 and offset + length <= count, "malformed getdents length")
            name = raw[offset + 19:offset + length].split(b"\0", 1)[0]
            if name not in (b".", b".."):
                _require(name.isdigit(), "non-numeric fd entry")
                found.add(int(name))
            offset += length


def _close_and_prove(descriptor):
    os.close(descriptor)
    try:
        fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    raise NativeCandidateError("descriptor remained open")


def _open_device_sources():
    sources = []
    pending = []
    try:
        for name, flags, device in (
            ("null", os.O_RDWR, (1, 3)), ("urandom", os.O_RDONLY, (1, 9)),
        ):
            descriptor = os.open(f"/dev/{name}", flags | os.O_NOFOLLOW | os.O_CLOEXEC)
            pending.append(descriptor)
            observed = os.fstat(descriptor)
            _require(stat.S_ISCHR(observed.st_mode) and observed.st_uid == observed.st_gid == 0
                     and observed.st_nlink == 1 and (os.major(observed.st_rdev), os.minor(observed.st_rdev)) == device,
                     f"unauthenticated /dev/{name}")
            tree = _syscall(
                SYS_OPEN_TREE, ctypes.c_int(descriptor), ctypes.c_char_p(b""),
                ctypes.c_uint(AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC),
            )
            pending.append(tree)
            _mount_setattr_fd(tree, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC)
            _close_and_prove(descriptor)
            pending.remove(descriptor)
            sources.append((name, tree, device))
            pending.remove(tree)
        return tuple(sources)
    except BaseException as primary:
        cleanup = []
        for descriptor in [*pending, *(tree for _name, tree, _device in sources)]:
            try:
                _close_and_prove(descriptor)
            except BaseException as error:
                cleanup.append(("device-source-close", error))
        if cleanup:
            raise CleanupUncertain(primary, cleanup) from primary
        raise


def _private_rootfs(tree, device_sources, stage):
    """Attach the hardened tree under child-private, bounded staging."""
    stage[0] = "root-private"
    _mount(None, "/", None, MS_REC | MS_PRIVATE)
    stage[0] = "staging-tmpfs"
    _mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
           "mode=0700,size=1048576,nr_inodes=32")
    os.mkdir(PRIVATE_STAGING, 0o700)
    os.mkdir(PRIVATE_ROOT, 0o700)
    target = os.open(PRIVATE_ROOT, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    stage[0] = "root-move-mount"
    try:
        _syscall(
            SYS_MOVE_MOUNT, ctypes.c_int(tree), ctypes.c_char_p(b""),
            ctypes.c_int(target), ctypes.c_char_p(b""),
            ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH),
        )
    finally:
        _close_and_prove(target)
    stage[0] = "root-tree-close"
    _close_and_prove(tree)
    root = str(PRIVATE_ROOT)

    stage[0] = "proc-fresh"
    _mount("proc", f"{root}/proc", "proc", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)

    stage[0] = "dev-tmpfs"
    _mount("tmpfs", f"{root}/dev", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
           "mode=0755,size=65536,nr_inodes=16")
    for name, source_tree, device in device_sources:
        target_path = f"{root}/dev/{name}"
        placeholder = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o666)
        _close_and_prove(placeholder)
        target_fd = os.open(target_path, os.O_PATH | os.O_CLOEXEC)
        stage[0] = f"dev-{name}-bind"
        try:
            _syscall(
                SYS_MOVE_MOUNT, ctypes.c_int(source_tree), ctypes.c_char_p(b""),
                ctypes.c_int(target_fd), ctypes.c_char_p(b""),
                ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH),
            )
        finally:
            _close_and_prove(target_fd)
        observed = os.stat(target_path, follow_symlinks=False)
        _require(stat.S_ISCHR(observed.st_mode)
                 and (os.major(observed.st_rdev), os.minor(observed.st_rdev)) == device,
                 f"wrong /dev/{name} bind")
        _close_and_prove(source_tree)
    _require(set(os.listdir(f"{root}/dev")) == {"null", "urandom"}, "unexpected device entry")
    _mount_setattr(
        f"{root}/dev", MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC)

    stage[0] = "tmp-tmpfs"
    _mount("tmpfs", f"{root}/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
           "mode=1777,size=134217728,nr_inodes=65536")
    stage[0] = "chroot"
    os.chroot(root)
    os.chdir("/")


def _write_all(descriptor, raw):
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        _require(written > 0, "short pipe write")
        offset += written


def _write_frame(descriptor, kind, payload):
    body = kind + payload
    _require(kind in (b"S", b"E") and 0 < len(body) <= MAX_PROTOCOL_BYTES)
    _write_all(descriptor, len(body).to_bytes(4, "big") + body)


def _child_error(descriptor, stage, error):
    stage_token = stage if _SAFE_TOKEN.fullmatch(stage) else "unknown"
    payload = f"{stage_token}:{_category(error)}".encode("ascii")
    try:
        _write_frame(descriptor, b"E", payload)
    except BaseException:
        pass
def _set_parent_death_signal():
    _libc_call("prctl", ctypes.c_int(PR_SET_PDEATHSIG), ctypes.c_ulong(signal.SIGKILL),
               ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    observed = ctypes.c_int(0)
    _libc_call("prctl", ctypes.c_int(PR_GET_PDEATHSIG), ctypes.byref(observed),
               ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    _require(observed.value == signal.SIGKILL, "PDEATHSIG readback mismatch")
def _parent_is_dead(parent_pidfd):
    poller = select.poll()
    poller.register(parent_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))
def _control_send(descriptor, payload, passed_descriptor=-1):
    _require(type(payload) is bytes and 0 < len(payload) <= 128, "invalid control payload")
    control = socket.socket(fileno=descriptor)
    try:
        ancillary = []
        if passed_descriptor >= 0:
            rights = array.array("i", [passed_descriptor])
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
        _require(control.sendmsg([payload], ancillary) == len(payload), "short control send")
    finally:
        control.detach()
def _control_receive(descriptor):
    control = socket.socket(fileno=descriptor)
    try:
        raw, ancillary, flags, _address = control.recvmsg(
            128, socket.CMSG_SPACE(array.array("i", [0]).itemsize), socket.MSG_CMSG_CLOEXEC)
    finally:
        control.detach()
    _require(not (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)), "truncated control packet")
    received = []
    for level, kind, data in ancillary:
        _require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                 "unexpected control ancillary data")
        values = array.array("i")
        values.frombytes(data[:len(data) - (len(data) % values.itemsize)])
        received.extend(values)
    _require(len(received) <= 1, "multiple control descriptors")
    return raw, (received[0] if received else -1)
def _wait_control(descriptor, guard_pidfd, deadline_ns):
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    poller.register(guard_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        remaining = deadline_ns - time.monotonic_ns()
        _require(remaining > 0, "control gate timeout")
        for ready, _event in poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000))):
            if ready == guard_pidfd:
                raise NativeCandidateError("gate owner exited")
            if ready == descriptor:
                raw, passed = _control_receive(descriptor)
                _require(raw, "control gate EOF")
                return raw, passed
def _wait_pipe_token(descriptor, token, guard_pidfd, deadline_ns):
    raw = bytearray()
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    poller.register(guard_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while bytes(raw) != token:
        remaining = deadline_ns - time.monotonic_ns()
        _require(remaining > 0, "pipe gate timeout")
        for ready, _event in poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000))):
            if ready == guard_pidfd:
                raise NativeCandidateError("gate owner exited")
            chunk = os.read(descriptor, len(token) - len(raw))
            _require(chunk, "pipe gate EOF")
            raw.extend(chunk)
            _require(token.startswith(raw), "malformed pipe gate")
def _pidfd_process(pidfd):
    rows = Path(f"/proc/self/fdinfo/{pidfd}").read_bytes().splitlines()
    matches = [row for row in rows if row.startswith(b"Pid:\t")]
    _require(len(matches) == 1 and matches[0][5:].isdigit(), "pidfd identity unavailable")
    return int(matches[0][5:])
def _validate_pidfd(pidfd, pid, expected_parent, *, namespace_pid1):
    _require(_pidfd_process(pidfd) == pid, "received pidfd names wrong process")
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    _require(not poller.poll(0), "process exited before release")
    return _proc_identity_without_open(pid, expected_parent, namespace_pid1=namespace_pid1)
def _proc_identity_without_open(pid, expected_parent, *, namespace_pid1):
    status = Path(f"/proc/{pid}/status").read_bytes()
    nspid_rows = [row for row in status.splitlines() if row.startswith(b"NSpid:\t")]
    _require(len(nspid_rows) == 1, "missing NSpid")
    nspids = tuple(int(value) for value in nspid_rows[0].split()[1:])
    if namespace_pid1:
        _require(len(nspids) >= 2 and nspids[0] == pid and nspids[-1] == 1,
                 "process is not namespace PID 1")
    else:
        _require(nspids[-1] == pid, "helper PID namespace mismatch")
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    close = raw.rfind(b")")
    fields = raw[close + 2:].split()
    _require(close > 1 and len(fields) >= 20 and int(raw[:raw.find(b" ")]) == pid,
             "malformed process stat")
    _require(int(fields[1]) == expected_parent, "unexpected process parent")
    _require(int(fields[19]) > 0, "invalid process starttime")
    return pid, int(fields[19])
def _pid1_main(ready_write, go_read, result_write, tree, device_sources,
               helper_pidfd, control_descriptor, parent_pidfd, contract, closure, package):
    stage = ["pid1-start"]
    try:
        _close_and_prove(control_descriptor)
        _close_and_prove(parent_pidfd)
        stage[0] = "pid1-pdeathsig"
        _set_parent_death_signal()
        if _parent_is_dead(helper_pidfd):
            os._exit(1)
        stage[0] = "pid1-descriptor-allowlist"
        audit = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        allowed = {
            0, 1, 2, ready_write, go_read, result_write, tree, helper_pidfd, audit,
            *(descriptor for _name, descriptor, _device in device_sources),
        }
        _close_except(allowed)
        _require(_fd_snapshot(audit) == allowed, "PID1 descriptor allowlist mismatch")
        _close_and_prove(audit)
        stage[0] = "pid1-ready"
        _write_all(ready_write, PID1_READY)
        _close_and_prove(ready_write)
        stage[0] = "pid1-go"
        _wait_pipe_token(go_read, PID1_GO, helper_pidfd, time.monotonic_ns() + 30 * NS)
        _close_and_prove(go_read)
        _close_and_prove(helper_pidfd)

        _private_rootfs(tree, device_sources, stage)
        stage[0] = "transaction-fds"
        audit = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        _require(_fd_snapshot(audit) == {0, 1, 2, result_write, audit},
                 "setup descriptor reached transaction")
        _close_and_prove(audit)
        stage[0] = "transaction"
        package.load_candidate_contract = lambda: contract
        package.exact_runtime_closure = lambda: closure
        raw = package.run_candidate_transaction()
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_RESULT_BYTES, "invalid candidate result")
        _write_frame(result_write, b"S", raw)
        _close_and_prove(result_write)
        os._exit(0)
    except BaseException as error:
        _child_error(result_write, stage[0], error)
        try:
            os.close(result_write)
        except OSError:
            pass
        os._exit(1)


def _wait_pidfd_reap(pidfd, deadline_ns):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while time.monotonic_ns() < deadline_ns:
        remaining = deadline_ns - time.monotonic_ns()
        if poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000))):
            info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            _require(info is not None, "missing pidfd wait status")
            return info
    raise NativeCandidateError("pidfd reap timeout")


def _helper_main(control_descriptor, ready_write, go_read, result_write, tree,
                 device_sources, parent_pidfd, work_deadline_ns, settlement_deadline_ns,
                 contract, closure, package):
    stage = ["helper-start"]
    pid = -1
    pidfd = -1
    reaped = False
    exit_code = 4
    helper_pidfd = -1
    try:
        stage[0] = "helper-pdeathsig"
        _set_parent_death_signal()
        _require(not _parent_is_dead(parent_pidfd), "parent died before helper arm")

        stage[0] = "helper-descriptor-allowlist"
        audit = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        allowed = {
            0, 1, 2, control_descriptor, ready_write, go_read, result_write,
            tree, parent_pidfd, audit,
            *(descriptor for _name, descriptor, _device in device_sources),
        }
        _close_except(allowed)
        _require(_fd_snapshot(audit) == allowed, "helper descriptor allowlist mismatch")
        _close_and_prove(audit)
        _control_send(control_descriptor, HELPER_READY)
        raw, passed = _wait_control(control_descriptor, parent_pidfd, work_deadline_ns)
        _require(raw == HELPER_GO and passed < 0, "malformed helper GO")

        stage[0] = "unshare"
        _libc_call("unshare", ctypes.c_int(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET))
        helper_pidfd = os.pidfd_open(os.getpid(), 0)
        stage[0] = "pid1-fork"
        pid = os.fork()
        if pid == 0:
            _pid1_main(ready_write, go_read, result_write, tree, device_sources,
                       helper_pidfd, control_descriptor, parent_pidfd,
                       contract, closure, package)
            os._exit(127)

        # Acquire the child authority before any fallible parent-side closure.
        pidfd = os.pidfd_open(pid, 0)
        for descriptor in (
            ready_write, go_read, result_write, tree, helper_pidfd,
            *(fd for _name, fd, _device in device_sources),
        ):
            _close_and_prove(descriptor)
        _validate_pidfd(pidfd, pid, os.getpid(), namespace_pid1=True)
        _control_send(control_descriptor, PID1_FD + str(pid).encode("ascii"), pidfd)

        kill_sent = False
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.register(parent_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        helper_reap_deadline_ns = max(work_deadline_ns, settlement_deadline_ns - NS)
        while time.monotonic_ns() < helper_reap_deadline_ns:
            now = time.monotonic_ns()
            if now >= work_deadline_ns and not kill_sent:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                kill_sent = True
            remaining = helper_reap_deadline_ns - now
            for descriptor, _event in poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000))):
                if descriptor == parent_pidfd:
                    os._exit(5)
                info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
                _require(info is not None, "missing namespace PID1 wait status")
                reaped = True
                _control_send(
                    control_descriptor,
                    f"PID1-EXIT:{info.si_code}:{info.si_status}".encode("ascii"),
                )
                exit_code = 0
                return
        raise NativeCandidateError("namespace PID1 settlement timeout")
    except BaseException as error:
        try:
            prefix = "HELPER-NO-PID1-ERROR" if pid < 0 else "HELPER-ERROR"
            _control_send(control_descriptor, f"{prefix}:{stage[0]}:{_category(error)}".encode("ascii"))
        except BaseException:
            pass
    finally:
        if pidfd >= 0 and not reaped:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                exit_code = 6
            try:
                _wait_pidfd_reap(pidfd, settlement_deadline_ns)
                reaped = True
            except BaseException:
                exit_code = 7
        for descriptor in (pidfd, parent_pidfd, control_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        os._exit(exit_code)


def _signal_kill(pidfd, cleanup_errors, stage="pidfd-signal"):
    if pidfd < 0:
        return
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException as error:
        cleanup_errors.append((stage, error))


def _parse_frame(raw):
    _require(len(raw) >= 5, "short child result")
    length = int.from_bytes(raw[:4], "big")
    _require(length == len(raw) - 4 and length <= MAX_PROTOCOL_BYTES, "invalid child result frame")
    kind, payload = raw[4:5], bytes(raw[5:])
    if kind == b"S":
        _require(0 < len(payload) <= MAX_RESULT_BYTES, "invalid success result")
        return payload
    _require(kind == b"E", "unknown child result kind")
    try:
        stage, category = payload.decode("ascii").split(":", 1)
    except (UnicodeError, ValueError) as error:
        raise NativeCandidateError("malformed child error") from error
    _require(_SAFE_TOKEN.fullmatch(stage) is not None and _SAFE_TOKEN.fullmatch(category) is not None,
             "malformed child error tokens")
    raise ChildCandidateError(stage, category)


def _supervise_candidate(helper_pidfd, pid1_pidfd, control_descriptor, result_descriptor,
                         work_deadline_ns, settlement_deadline_ns, initial_error=None,
                         initial_no_pid1=False):
    raw = bytearray()
    oversize = False
    pipe_eof = False
    control_eof = False
    pid1_terminal = False
    helper_reaped = False
    helper_info = None
    pid1_report = None
    no_pid1 = initial_no_pid1
    kill_sent = False
    launch_grace_ns = time.monotonic_ns() + NS
    work_error = initial_error
    cleanup_errors = []
    poller = select.poll()
    for descriptor in (result_descriptor, control_descriptor, pid1_pidfd, helper_pidfd):
        if descriptor >= 0:
            poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)

    while time.monotonic_ns() < settlement_deadline_ns:
        now = time.monotonic_ns()
        if not kill_sent and (work_error is not None or now >= work_deadline_ns):
            if work_error is None:
                work_error = NativeCandidateError("child deadline")
            if pid1_pidfd >= 0:
                _signal_kill(pid1_pidfd, cleanup_errors)
                kill_sent = True
            elif no_pid1 or now >= launch_grace_ns:
                _signal_kill(helper_pidfd, cleanup_errors, "helper-signal")
                kill_sent = True
        if helper_reaped and pid1_report is None and work_error is None:
            work_error = NativeCandidateError("helper exited before PID1 settlement report")
            _signal_kill(pid1_pidfd, cleanup_errors)
            kill_sent = True
        if (helper_reaped and pipe_eof and control_eof
                and (no_pid1 or (pid1_terminal and pid1_report is not None))):
            break
        remaining = settlement_deadline_ns - now
        events = poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000)))
        for descriptor, _event in events:
            if descriptor == result_descriptor and not pipe_eof:
                chunk = os.read(result_descriptor, 65_536)
                if not chunk:
                    pipe_eof = True
                elif not oversize:
                    if len(raw) + len(chunk) > MAX_PROTOCOL_BYTES + 4:
                        oversize = True
                        raw.clear()
                        if work_error is None:
                            work_error = NativeCandidateError("oversize child result")
                        _signal_kill(pid1_pidfd, cleanup_errors)
                        kill_sent = True
                    else:
                        raw.extend(chunk)
            elif descriptor == control_descriptor and not control_eof:
                packet, passed = _control_receive(control_descriptor)
                if packet.startswith(PID1_FD) and passed >= 0 and pid1_pidfd < 0:
                    try:
                        reported_pid = int(packet[len(PID1_FD):])
                        _validate_pidfd(
                            passed, reported_pid, _pidfd_process(helper_pidfd), namespace_pid1=True)
                        pid1_pidfd = passed
                        poller.register(pid1_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                    except BaseException as error:
                        try:
                            _close_and_prove(passed)
                        except BaseException as close_error:
                            cleanup_errors.append(("late-pid1-pidfd-close", close_error))
                        if work_error is None:
                            work_error = error
                    continue
                if passed >= 0:
                    try:
                        _close_and_prove(passed)
                    except BaseException as error:
                        cleanup_errors.append(("unexpected-control-fd-close", error))
                    if work_error is None:
                        work_error = NativeCandidateError("unexpected control descriptor")
                if not packet:
                    control_eof = True
                elif packet.startswith(b"PID1-EXIT:"):
                    try:
                        _, code, status = packet.decode("ascii").split(":")
                        pid1_report = (int(code), int(status))
                    except (UnicodeError, ValueError) as error:
                        if work_error is None:
                            work_error = NativeCandidateError("malformed PID1 exit report")
                elif packet.startswith(b"HELPER-NO-PID1-ERROR:"):
                    no_pid1 = True
                    if work_error is None:
                        work_error = NativeCandidateError("helper setup failed before PID1")
                elif packet.startswith(b"HELPER-ERROR:") and work_error is None:
                    work_error = NativeCandidateError("helper setup failed")
                elif work_error is None:
                    work_error = NativeCandidateError("unexpected control packet")
            elif descriptor == pid1_pidfd:
                pid1_terminal = True
            elif descriptor == helper_pidfd and not helper_reaped:
                try:
                    helper_info = os.waitid(os.P_PIDFD, helper_pidfd, os.WEXITED | os.WNOHANG)
                    helper_reaped = helper_info is not None
                except ChildProcessError as error:
                    cleanup_errors.append(("helper-pidfd-reap", error))
                    helper_reaped = True

    if not (helper_reaped and pipe_eof and control_eof
            and (no_pid1 or (pid1_terminal and pid1_report is not None))):
        _signal_kill(pid1_pidfd, cleanup_errors)
        _signal_kill(helper_pidfd, cleanup_errors, "helper-final-signal")
    if not helper_reaped:
        cleanup_errors.append(("helper-reap-timeout", NativeCandidateError("helper not reaped")))
    if not no_pid1 and (not pid1_terminal or pid1_report is None):
        cleanup_errors.append(("pid1-settlement", NativeCandidateError("PID namespace teardown unproved")))
    if not pipe_eof:
        cleanup_errors.append(("result-pipe-eof", NativeCandidateError("result pipe not closed")))
    if not control_eof:
        cleanup_errors.append(("control-eof", NativeCandidateError("helper control not closed")))

    for stage, descriptor in (
        ("result-pipe-close", result_descriptor), ("control-close", control_descriptor),
        ("pid1-pidfd-close", pid1_pidfd), ("helper-pidfd-close", helper_pidfd),
    ):
        if descriptor >= 0:
            try:
                _close_and_prove(descriptor)
            except BaseException as error:
                cleanup_errors.append((stage, error))

    if helper_info is not None and (helper_info.si_code != os.CLD_EXITED or helper_info.si_status != 0):
        if work_error is None:
            work_error = NativeCandidateError("helper failed")
    if pid1_report is not None and pid1_report != (os.CLD_EXITED, 0) and work_error is None:
        work_error = NativeCandidateError(f"PID1 status {pid1_report[0]}:{pid1_report[1]}")

    result = None
    if raw and not oversize:
        try:
            result = _parse_frame(bytes(raw))
        except BaseException as error:
            if work_error is None or isinstance(error, ChildCandidateError):
                work_error = error
    elif work_error is None:
        work_error = NativeCandidateError("missing child result")
    settled = (helper_reaped and pipe_eof and control_eof
               and (no_pid1 or (pid1_terminal and pid1_report is not None)))
    return result, work_error, cleanup_errors, settled


def _run_candidate_child(tree, contract, closure, package, work_deadline_ns, settlement_deadline_ns):
    device_sources = ()
    descriptors = {name: -1 for name in (
        "control_parent", "control_helper", "ready_read", "ready_write",
        "go_read", "go_write", "result_read", "result_write", "parent_pidfd",
    )}
    helper = -1
    helper_pidfd = -1
    pid1_pidfd = -1
    parent_close_errors = []
    parent_detached_pending = []
    initial_error = None
    known_no_pid1 = False
    launched = False
    try:
        # Root and device detached trees are all opened before the first fork.
        device_sources = _open_device_sources()
        parent_socket, helper_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        descriptors["control_parent"] = parent_socket.detach()
        descriptors["control_helper"] = helper_socket.detach()
        descriptors["ready_read"], descriptors["ready_write"] = os.pipe2(os.O_CLOEXEC)
        descriptors["go_read"], descriptors["go_write"] = os.pipe2(os.O_CLOEXEC)
        descriptors["result_read"], descriptors["result_write"] = os.pipe2(os.O_CLOEXEC)
        descriptors["parent_pidfd"] = os.pidfd_open(os.getpid(), 0)

        helper = os.fork()
        if helper == 0:
            try:
                for name in ("control_parent", "ready_read", "go_write", "result_read"):
                    _close_and_prove(descriptors[name])
                _helper_main(
                    descriptors["control_helper"], descriptors["ready_write"], descriptors["go_read"],
                    descriptors["result_write"], tree, device_sources, descriptors["parent_pidfd"],
                    work_deadline_ns, settlement_deadline_ns, contract, closure, package,
                )
            except BaseException:
                os._exit(126)
            os._exit(127)
        launched = True
        helper_pidfd = os.pidfd_open(helper, 0)

        for name in ("control_helper", "ready_write", "go_read", "result_write", "parent_pidfd"):
            try:
                _close_and_prove(descriptors[name])
                descriptors[name] = -1
            except BaseException as error:
                parent_close_errors.append((f"{name}-close", error))
        for stage, descriptor in (("parent-tree-close", tree), *(
            (f"parent-device-{name}-close", fd) for name, fd, _device in device_sources)):
            try:
                _close_and_prove(descriptor)
            except BaseException as error:
                parent_close_errors.append((stage, error))
                parent_detached_pending.append((stage, descriptor))
        tree = -1
        device_sources = ()
        if parent_close_errors:
            raise NativeCandidateError("pre-gate descriptor closure failed")

        packet, passed = _wait_control(descriptors["control_parent"], helper_pidfd, work_deadline_ns)
        _require(packet == HELPER_READY and passed < 0, "helper READY malformed")
        _validate_pidfd(helper_pidfd, helper, os.getpid(), namespace_pid1=False)
        _control_send(descriptors["control_parent"], HELPER_GO)

        pid1_ready = False
        pid1 = -1
        while not (pid1_ready and pid1_pidfd >= 0):
            remaining = work_deadline_ns - time.monotonic_ns()
            _require(remaining > 0, "PID1 gate timeout")
            poller = select.poll()
            poller.register(descriptors["control_parent"], select.POLLIN | select.POLLHUP | select.POLLERR)
            poller.register(descriptors["ready_read"], select.POLLIN | select.POLLHUP | select.POLLERR)
            poller.register(helper_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            for ready, _event in poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000))):
                if ready == helper_pidfd:
                    raise NativeCandidateError("helper exited before PID1 release")
                if ready == descriptors["ready_read"] and not pid1_ready:
                    _wait_pipe_token(descriptors["ready_read"], PID1_READY, helper_pidfd, work_deadline_ns)
                    pid1_ready = True
                elif ready == descriptors["control_parent"]:
                    packet, passed = _control_receive(descriptors["control_parent"])
                    if packet.startswith(b"HELPER-NO-PID1-ERROR:") and passed < 0:
                        known_no_pid1 = True
                        raise NativeCandidateError("helper failed before PID1")
                    _require(packet.startswith(PID1_FD) and packet[len(PID1_FD):].isdigit(),
                             "PID1 descriptor report malformed")
                    _require(pid1_pidfd < 0 and passed >= 0, "PID1 pidfd missing or duplicate")
                    pid1 = int(packet[len(PID1_FD):])
                    pid1_pidfd = passed
        _validate_pidfd(pid1_pidfd, pid1, helper, namespace_pid1=True)
        _validate_pidfd(helper_pidfd, helper, os.getpid(), namespace_pid1=False)
        if _NATIVE_TEST_BEFORE_PID1_GO is not None: _NATIVE_TEST_BEFORE_PID1_GO(helper, pid1, descriptors["go_write"])
        _close_and_prove(descriptors["ready_read"])
        descriptors["ready_read"] = -1
        _write_all(descriptors["go_write"], PID1_GO)
        _close_and_prove(descriptors["go_write"])
        descriptors["go_write"] = -1
    except BaseException as error:
        initial_error = error

    if launched and helper_pidfd >= 0:
        result, work_error, cleanup_errors, settled = _supervise_candidate(
            helper_pidfd, pid1_pidfd, descriptors["control_parent"], descriptors["result_read"],
            work_deadline_ns, settlement_deadline_ns, initial_error, known_no_pid1)
        cleanup_errors[:0] = parent_close_errors
        descriptors["control_parent"] = descriptors["result_read"] = -1
        for name, descriptor in descriptors.items():
            if descriptor >= 0:
                try:
                    _close_and_prove(descriptor)
                    descriptors[name] = -1
                except BaseException as error:
                    cleanup_errors.append((f"{name}-close", error))
        for stage, descriptor in parent_detached_pending:
            try:
                _close_and_prove(descriptor)
            except BaseException as error:
                cleanup_errors.append((f"{stage}-second-close", error))
        return result, work_error, cleanup_errors, settled and not parent_detached_pending

    cleanup_errors = list(parent_close_errors)
    if helper > 0:
        emergency_pidfd = -1
        try:
            emergency_pidfd = os.pidfd_open(helper, 0)
            signal.pidfd_send_signal(emergency_pidfd, signal.SIGKILL)
            _wait_pidfd_reap(emergency_pidfd, time.monotonic_ns() + REAP_SECONDS * NS)
        except ProcessLookupError:
            pass
        except BaseException as error:
            cleanup_errors.append(("failed-launch-helper-settle", error))
        finally:
            if emergency_pidfd >= 0:
                try:
                    _close_and_prove(emergency_pidfd)
                except BaseException as error:
                    cleanup_errors.append(("failed-launch-helper-pidfd-close", error))
    for name, descriptor in descriptors.items():
        if descriptor >= 0:
            try:
                _close_and_prove(descriptor)
            except BaseException as error:
                cleanup_errors.append((f"failed-launch-{name}-close", error))
    for stage, descriptor in (("failed-launch-tree-close", tree), *(
        (f"failed-launch-device-{name}-close", fd) for name, fd, _device in device_sources)):
        if descriptor >= 0:
            try:
                _close_and_prove(descriptor)
            except BaseException as error:
                cleanup_errors.append((stage, error))
    return None, initial_error or NativeCandidateError("launch failed"), cleanup_errors, not cleanup_errors


class _PreflightError(NativeCandidateError):
    def __init__(self, category):
        self.category = category
        super().__init__(category)


def _preflight_require(condition, category):
    if not condition:
        raise _PreflightError(category)


class _PreflightPackage:
    """Trusted PID1 probe; deliberately does not pretend to be hostile code."""

    @staticmethod
    def run_candidate_transaction():
        _preflight_require(os.getpid() == 1, "preflight-pid1")
        status = Path("/proc/self/status").read_bytes()
        nspid = [row for row in status.splitlines() if row.startswith(b"NSpid:")]
        _preflight_require(len(nspid) == 1 and nspid[0].split()[-1] == b"1", "preflight-proc")
        _preflight_require({name for name in os.listdir("/proc") if name.isdigit()} == {"1"},
                           "preflight-proc-private")
        network = Path("/proc/net/dev").read_bytes().splitlines()[2:]
        _preflight_require(
            [row.split(b":", 1)[0].strip() for row in network] == [b"lo"], "preflight-network-private")
        _preflight_require(set(os.listdir("/dev")) == {"null", "urandom"}, "preflight-dev")
        null_status = os.stat("/dev/null", follow_symlinks=False)
        random_status = os.stat("/dev/urandom", follow_symlinks=False)
        _preflight_require(
            stat.S_ISCHR(null_status.st_mode) and (os.major(null_status.st_rdev), os.minor(null_status.st_rdev)) == (1, 3)
            and stat.S_ISCHR(random_status.st_mode)
            and (os.major(random_status.st_rdev), os.minor(random_status.st_rdev)) == (1, 9),
            "preflight-dev-identity",
        )
        null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        random_fd = os.open("/dev/urandom", os.O_RDONLY | os.O_CLOEXEC)
        try:
            _preflight_require(os.write(null_fd, b"x") == 1 and len(os.read(random_fd, 16)) == 16,
                               "preflight-dev-io")
        finally:
            os.close(random_fd)
            os.close(null_fd)
        Path("/tmp/preflight").write_bytes(b"ok")
        mountinfo = Path("/proc/self/mountinfo").read_bytes().splitlines()
        rows = {}
        for row in mountinfo:
            before = row.split(b" - ", 1)[0].split()
            if len(before) >= 6:
                rows[before[4]] = set(before[5].split(b","))
        _preflight_require({b"ro", b"nosuid", b"nodev"} <= rows.get(b"/", set())
                           and b"noexec" not in rows[b"/"], "preflight-root-flags")
        _preflight_require({b"ro", b"nosuid", b"nodev", b"noexec"} <= rows.get(b"/proc", set()),
                           "preflight-proc-flags")
        _preflight_require({b"ro", b"nosuid", b"nodev", b"noexec"} <= rows.get(b"/dev", set()),
                           "preflight-dev-flags")
        _preflight_require({b"rw", b"nosuid", b"nodev", b"noexec"} <= rows.get(b"/tmp", set()),
                           "preflight-tmp-flags")
        for name in (b"/dev/null", b"/dev/urandom"):
            _preflight_require({b"ro", b"nosuid", b"noexec"} <= rows.get(name, set())
                               and b"nodev" not in rows[name], "preflight-device-bind-flags")
        return b'{"preflight":true}'


def _lifecycle_preflight():
    """Cheap exact double-fork/mount/fd/pidfd probe before acquisition."""
    _platform_gate()
    outcome = _Outcome()
    descriptor = None
    source_created = False
    mounted = False
    result = None
    try:
        _require(not PREFLIGHT_SOURCE.exists(), "preflight source residue")
        os.mkdir(PREFLIGHT_SOURCE, 0o700)
        source_created = True
        _mount("tmpfs", str(PREFLIGHT_SOURCE), "tmpfs", MS_NOSUID | MS_NODEV,
               "mode=0755,size=1048576,nr_inodes=32")
        mounted = True
        for name in ("proc", "dev", "tmp"):
            os.mkdir(PREFLIGHT_SOURCE / name, 0o755)
        (PREFLIGHT_SOURCE / "marker").write_bytes(b"preflight")
        descriptor = os.open(PREFLIGHT_SOURCE, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        tree = _open_detached_tree(descriptor, allow_root_mount=True)
        _close_and_prove(descriptor)
        descriptor = None
        work_deadline = time.monotonic_ns() + 12 * NS
        result, work_error, cleanup_errors, settled = _run_candidate_child(
            tree, {}, {}, _PreflightPackage, work_deadline, work_deadline + 5 * NS)
        if work_error is not None:
            outcome.work(work_error)
        for stage, error in cleanup_errors:
            outcome.cleanup(f"preflight-{stage}", error)
        if not settled:
            outcome.cleanup("preflight-settlement", NativeCandidateError("PID namespace not settled"))
    except BaseException as error:
        outcome.work(error)
    if descriptor is not None:
        try:
            _close_and_prove(descriptor)
        except BaseException as error:
            outcome.cleanup("preflight-source-close", error)
    if mounted:
        try:
            _libc_call("umount2", ctypes.c_char_p(os.fsencode(PREFLIGHT_SOURCE)), ctypes.c_int(0))
        except BaseException as error:
            outcome.cleanup("preflight-source-unmount", error)
    if source_created:
        try:
            os.rmdir(PREFLIGHT_SOURCE)
        except BaseException as error:
            outcome.cleanup("preflight-source-remove", error)
    outcome.finish()
    _require(result == b'{"preflight":true}', "preflight result mismatch")


def _cache_rows(contract):
    rows = [contract["oci"][name] for name in ("index", "manifest", "config", "layer")]
    rows.extend(contract["snapshot"][name] for name in ("inrelease", "packages_index"))
    rows.extend(contract["packages"])
    _require(len(rows) == 16 and len({row["cache_name"] for row in rows}) == 16)
    return tuple(rows)


def _identity(status):
    return (status.st_dev, status.st_ino, status.st_mode, status.st_uid, status.st_gid,
            status.st_nlink, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


def _read_fd(descriptor, expected_size):
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        _require(chunk)
        chunks.append(chunk)
        remaining -= len(chunk)
    _require(os.read(descriptor, 1) == b"")
    return b"".join(chunks)


def _hold_cache(verifier, contract):
    root = os.open(verifier.ARTIFACT_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    cache = -1
    held = []
    sentinel = None
    try:
        root_identity = _identity(os.fstat(root))
        cache = os.open("cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        cache_identity = _identity(os.fstat(cache))
        rows = _cache_rows(contract)
        _require(set(os.listdir(root)) == {"cache", verifier.SENTINEL})
        _require(set(os.listdir(cache)) == {row["cache_name"] for row in rows})
        for row in rows:
            descriptor = os.open(row["cache_name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cache)
            observed = os.fstat(descriptor)
            raw = _read_fd(descriptor, row["size"])
            _require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1)
            _require(len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"])
            held.append((row, descriptor, _identity(observed)))
        sentinel = os.open(verifier.SENTINEL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        sentinel_identity = _identity(os.fstat(sentinel))
        _require(_read_fd(sentinel, len(verifier.SENTINEL_BYTES)) == verifier.SENTINEL_BYTES)
        return root, root_identity, cache, cache_identity, held, sentinel, sentinel_identity
    except BaseException:
        for _row, descriptor, _held_identity in held:
            os.close(descriptor)
        if sentinel is not None:
            os.close(sentinel)
        if cache >= 0:
            os.close(cache)
        os.close(root)
        raise


def _cleanup_cache(verifier, authority):
    root, root_identity, cache, cache_identity, held, sentinel, sentinel_identity = authority
    errors = []
    try:
        _require(_identity(os.fstat(root)) == root_identity and _identity(os.fstat(cache)) == cache_identity)
        _require(set(os.listdir(cache)) == {row["cache_name"] for row, _fd, _identity_value in held})
        for row, descriptor, held_identity in held:
            current = os.stat(row["cache_name"], dir_fd=cache, follow_symlinks=False)
            _require(_identity(os.fstat(descriptor)) == held_identity == _identity(current))
            _require(hashlib.sha256(_read_fd(descriptor, row["size"])).hexdigest() == row["sha256"])
            os.unlink(row["cache_name"], dir_fd=cache)
            os.fsync(cache)
        _require(_identity(os.fstat(sentinel)) == sentinel_identity)
        _require(_read_fd(sentinel, len(verifier.SENTINEL_BYTES)) == verifier.SENTINEL_BYTES)
        os.rmdir("cache", dir_fd=root)
        os.unlink(verifier.SENTINEL, dir_fd=root)
        os.fsync(root)
    except BaseException as error:
        errors.append(error)
    for descriptor in [*(fd for _row, fd, _held in held), sentinel, cache, root]:
        try:
            _close_and_prove(descriptor)
        except BaseException as error:
            errors.append(error)
    if not errors:
        try:
            os.rmdir(verifier.ARTIFACT_ROOT)
        except BaseException as error:
            errors.append(error)
    if errors:
        raise CleanupUncertain(None, tuple(("cache", error) for error in errors))


def _cleanup_retained(retained, materializer, fs, deadline_ns):
    errors = []
    try:
        control = fs.OperationControl(deadline_ns, lambda: False)
        materializer._reload_and_cleanup(retained.owned, control)
        retained.disposition = "retired"
    except BaseException as error:
        errors.append(error)
    try:
        fs._close_chain(retained.base_chain)
    except BaseException as error:
        errors.append(error)
    if errors:
        combined = errors[0]
        for error in errors[1:]:
            combined = fs.RootfsFsError(combined, error)
        raise combined


def run():
    lifecycle_deadline_ns = time.monotonic_ns() + OUTER_SECONDS * NS
    _platform_gate()
    reviewed_head = os.environ.get("COGS_PACKAGE_REVIEWED_HEAD", "")
    _require(_HEX40.fullmatch(reviewed_head) is not None)
    _require(Path(__file__).resolve() == FIXED_DRIVER and os.environ.get(
        "COGS_STAGE2_ARTIFACT_ACQUISITION_APPROVED") == APPROVAL)
    # Exact lifecycle compatibility fails in seconds, before contract loading,
    # downloads, rootfs bootstrap, or any retained-root/cache authority.
    _lifecycle_preflight()
    phase_a = _load("package_native_phase_a", FIXED_PHASE_A)
    phase_a._fixed_preflight(True)
    revision, manifest_sha256 = phase_a._source_approval()
    _require(revision == reviewed_head)
    phase_a._verify_fixed_source(revision, manifest_sha256)
    verifier = phase_a._load_artifact_verifier()
    _require(not verifier.ARTIFACT_ROOT.exists())
    contract = phase_a._verifier_call(
        verifier, "contract", lambda: verifier.verify_contract(verifier.CONTRACT_PATH))
    phase_a._verifier_call(
        verifier, "acquisition", lambda: verifier.acquire_completion_artifacts(
            verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT), True)

    outcome = _Outcome()
    cache_authority = None
    retained = None
    result = None
    child_settled = True
    sys.path.insert(0, str(REMOTE))
    import completion_package_native_candidate as package
    import completion_rootfs_build as build
    import completion_rootfs_builder as builder
    import completion_rootfs_fs as fs
    import completion_rootfs_materializer as materializer
    import completion_rootfs_publish as publication
    from completion_runtime_contract import exact_runtime_closure, load_candidate_contract
    try:
        phase_a._verifier_call(verifier, "postverify", lambda: verifier.verify_package_archives(
            verifier.CONTRACT_PATH, verifier.ARTIFACT_ROOT))
        cache_authority = _hold_cache(verifier, contract)
        candidate_contract = load_candidate_contract()
        closure = exact_runtime_closure()
        approval = fs.SourceApproval(revision, manifest_sha256)
        control = fs.OperationControl(lifecycle_deadline_ns, lambda: False)
        phase_a._bootstrap_rootfs(builder, fs, approval, control)
        rootfs, retained = build._build_once_retained(approval, os.urandom(32).hex(), control)
        build._require_pinned(rootfs, publication._load_pins())
        _require(len(rootfs.cache) == 16)

        work_deadline_ns = min(
            time.monotonic_ns() + CHILD_SECONDS * NS,
            lifecycle_deadline_ns - CLEANUP_RESERVE_SECONDS * NS,
        )
        _require(work_deadline_ns > time.monotonic_ns(), "cleanup reserve exhausted")
        settlement_deadline_ns = min(lifecycle_deadline_ns, work_deadline_ns + REAP_SECONDS * NS)
        # This must precede the outer fork: only the trusted parent can clone
        # and harden the retained mount from its current namespace.  From the
        # ownership transfer onward cleanup is prohibited until both pidfds,
        # helper reap, PID1 report, and both channel EOFs prove settlement.
        tree = _open_detached_tree(retained.owned.root.operation_fd.number)
        child_settled = False
        result, child_error, child_cleanup, child_settled = _run_candidate_child(
            tree, candidate_contract, closure, package, work_deadline_ns, settlement_deadline_ns)
        if child_error is not None:
            outcome.work(child_error)
        for stage, error in child_cleanup:
            outcome.cleanup(stage, error)
    except BaseException as error:
        outcome.work(error)

    # Retained names are touched only after terminal pidfd readiness and exact
    # reap prove PID-namespace teardown (and therefore descendant absence).
    if child_settled:
        if retained is not None:
            try:
                _cleanup_retained(retained, materializer, fs, lifecycle_deadline_ns)
                retained = None
            except BaseException as error:
                outcome.cleanup("retained-root-cleanup", error)
        if cache_authority is not None:
            try:
                _cleanup_cache(verifier, cache_authority)
                cache_authority = None
            except BaseException as error:
                outcome.cleanup("cache-cleanup", error)
    else:
        outcome.cleanup("unsafe-cleanup-suppressed", NativeCandidateError("child absence unproved"))

    try:
        _require(not verifier.ARTIFACT_ROOT.exists(), "artifact cache remains")
        rootfs_state = phase_a.ROOTFS_STATE
        _require(rootfs_state.is_dir())
        _require(set(os.listdir(rootfs_state)) == {builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text})
    except BaseException as error:
        outcome.cleanup("final-residue-check", error)
    outcome.finish()
    _require(result is not None)
    return result


def main():
    if len(sys.argv) != 1:
        return 1
    try:
        raw = run()
        _write_all(sys.stdout.fileno(), raw)
        return 0
    except BaseException as error:
        category = _category(error)
        detail = ""
        if isinstance(error, CleanupUncertain):
            work = "none" if error.work_error is None else _category(error.work_error)
            cleanup = ",".join(f"{stage}-{_category(item)}" for stage, item in error.cleanup_errors)
            detail = f":work-{work}:cleanup-{cleanup}"[:512]
        elif isinstance(error, ChildCandidateError):
            detail = f":{error.stage}"
        try:
            os.write(2, f"native package candidate failed:{category}{detail}\n".encode("ascii"))
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
