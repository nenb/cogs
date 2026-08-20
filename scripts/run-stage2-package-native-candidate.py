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
POST_KILL_REAP_SECONDS = 5
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
_NATIVE_TEST_HELPER_EXIT_STAGE = None
_NATIVE_TEST_FAIL_HELPER_PIDFD_OPEN = False
_NATIVE_TEST_FAIL_PID1_PIDFD_OPEN = False

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


class StageCandidateError(NativeCandidateError):
    category = "stage_error"

    def __init__(self, stage, reason):
        _require_safe_token(stage)
        _require_safe_token(reason)
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}:{reason}")


class ChildCandidateError(NativeCandidateError):
    def __init__(self, stage, category):
        _require_safe_token(stage)
        _require_safe_token(category)
        self.stage = stage
        self.category = category
        super().__init__(f"{stage}:{category}")


class HelperCandidateError(NativeCandidateError):
    category = "helper_error"

    def __init__(self, stage, reason):
        _require_safe_token(stage)
        _require_safe_token(reason)
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}:{reason}")


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


def _require_safe_token(value):
    if not isinstance(value, str) or _SAFE_TOKEN.fullmatch(value) is None:
        raise NativeCandidateError("unsafe diagnostic token")


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
    # Detached clones retain a shared source mount's peer-group membership.
    # Privatize the detached object itself before any later move_mount attachment.
    attributes = _MountAttr(set_flags, clear_flags, MS_PRIVATE, 0)
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


def _open_retained_tree(root_descriptor):
    try:
        return _open_detached_tree(root_descriptor)
    except CleanupUncertain:
        raise
    except StageCandidateError:
        raise
    except OSError as error:
        raise StageCandidateError("retained-root-prepare", _category(error)) from error
    except NativeCandidateError as error:
        raise StageCandidateError("retained-root-prepare", "invariant") from error


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
            pending.remove(descriptor)
            _close_and_prove(descriptor)
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
    reported = getattr(error, "stage", stage)
    stage_token = reported if isinstance(reported, str) and _SAFE_TOKEN.fullmatch(reported) else "unknown"
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
def _subreaper_state():
    observed = ctypes.c_int(-1)
    _libc_call("prctl", ctypes.c_int(PR_GET_CHILD_SUBREAPER), ctypes.byref(observed),
               ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    _require(observed.value in (0, 1), "subreaper readback invalid")
    return observed.value

def _set_subreaper(enabled):
    previous = _subreaper_state()
    _libc_call("prctl", ctypes.c_int(PR_SET_CHILD_SUBREAPER), ctypes.c_ulong(int(enabled)),
               ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    _require(_subreaper_state() == int(enabled), "subreaper readback mismatch")
    return previous

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
            128, socket.CMSG_SPACE(2 * array.array("i", [0]).itemsize), socket.MSG_CMSG_CLOEXEC)
    finally:
        control.detach()
    received = []
    valid_ancillary = True
    try:
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                valid_ancillary = False
                continue
            values = array.array("i")
            values.frombytes(data[:len(data) - (len(data) % values.itemsize)])
            received.extend(values)
        _require(not (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)), "truncated control packet")
        _require(valid_ancillary, "unexpected control ancillary data")
        _require(len(received) <= 1, "multiple control descriptors")
        return raw, (received[0] if received else -1)
    except BaseException as primary:
        cleanup = []
        for passed in received:
            cleanup.extend(_retire_rejected_control_right(passed))
        if cleanup: raise CleanupUncertain(primary, cleanup) from primary
        raise

def _retire_rejected_control_right(passed):
    if passed < 0:
        return []
    try:
        _close_and_prove(passed)
        return []
    except BaseException as error:
        return [("rejected-control-fd-close", error)]

def _control_adopt(raw, passed, validator):
    """Transfer a received right only after the complete packet validates."""
    try:
        return validator(raw, passed)
    except BaseException as primary:
        cleanup = _retire_rejected_control_right(passed)
        if cleanup:
            raise CleanupUncertain(primary, cleanup) from primary
        raise

def _control_no_fd(raw, passed, expected, message):
    def validate(packet, right):
        _require(packet == expected and right < 0, message)
    _control_adopt(raw, passed, validate)

def _helper_error_tokens(packet, prefix):
    try:
        marker, stage, category = packet.decode("ascii").split(":")
    except (UnicodeError, ValueError) as error:
        raise NativeCandidateError("malformed helper error") from error
    _require(marker == prefix and _SAFE_TOKEN.fullmatch(stage) is not None
             and _SAFE_TOKEN.fullmatch(category) is not None, "malformed helper error tokens")
    return stage, category


def _classify_pid1_gate_packet(packet, passed, expected_parent=None, available=True):
    if packet.startswith(b"HELPER-NO-PID1-ERROR:"):
        _require(passed < 0, "helper error carried a descriptor")
        return "no-pid1", *_helper_error_tokens(packet, "HELPER-NO-PID1-ERROR")
    _require(packet.startswith(PID1_FD) and packet[len(PID1_FD):].isdigit(),
             "PID1 descriptor report malformed")
    _require(available and passed >= 0, "PID1 pidfd missing or duplicate")
    pid = int(packet[len(PID1_FD):])
    if expected_parent is not None:
        _validate_pidfd(passed, pid, expected_parent, namespace_pid1=True)
    return "pid1", pid, passed

def _classify_supervisor_packet(packet, passed, expected_parent, pid1_available):
    if packet.startswith(PID1_FD):
        _require(packet[len(PID1_FD):].isdigit(), "malformed PID1 descriptor report")
        _require(passed >= 0 and pid1_available, "PID1 pidfd missing or duplicate")
        pid = int(packet[len(PID1_FD):])
        _validate_pidfd(passed, pid, expected_parent, namespace_pid1=True)
        return "pid1", passed
    if not packet:
        _require(passed < 0, "control EOF carried a descriptor")
        return "eof",
    if packet.startswith(b"PID1-EXIT:"):
        _require(passed < 0, "PID1 exit report carried a descriptor")
        _prefix, code_raw, status_raw = packet.decode("ascii").split(":")
        _require(code_raw.isdigit() and status_raw.isdigit(), "PID1 exit report malformed")
        code, status = int(code_raw), int(status_raw)
        _require(code in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED},
                 "PID1 exit code outside terminal domain")
        _require((code == os.CLD_EXITED and 0 <= status <= 255)
                 or (code != os.CLD_EXITED and 0 < status < signal.NSIG),
                 "PID1 exit status outside terminal domain")
        return "pid1-exit", code, status
    if packet.startswith(b"HELPER-NO-PID1-ERROR:"):
        _require(passed < 0, "helper error carried a descriptor")
        return "no-pid1", *_helper_error_tokens(packet, "HELPER-NO-PID1-ERROR")
    if packet.startswith(b"HELPER-ERROR:"):
        _require(passed < 0, "helper error carried a descriptor")
        return "helper-error", *_helper_error_tokens(packet, "HELPER-ERROR")
    raise NativeCandidateError("unexpected control packet")

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
                if not raw:
                    _control_adopt(
                        raw, passed,
                        lambda _raw, _passed: _require(False, "control gate EOF"),
                    )
                return raw, passed
def _wait_pipe_token(descriptor, token, guard_pidfd, deadline_ns):
    _require(type(token) is bytes and token, "empty pipe gate token")
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
        retired, result_write = result_write, -1
        _close_and_prove(retired)
        os._exit(0)
    except BaseException as error:
        if result_write >= 0:
            _child_error(result_write, stage[0], error)
            retired, result_write = result_write, -1
            try: os.close(retired)
            except OSError: pass
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

def _wait_status(status):
    if os.WIFEXITED(status): return os.CLD_EXITED, os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status): return os.CLD_DUMPED if os.WCOREDUMP(status) else os.CLD_KILLED, os.WTERMSIG(status)
    raise NativeCandidateError("nonterminal child wait status")

def _kill_wait_child_pid(pid, deadline_ns):
    try: _libc_call("kill", ctypes.c_int(pid), ctypes.c_int(signal.SIGKILL))
    except OSError as error:
        if error.errno != errno.ESRCH: raise
    while time.monotonic_ns() < deadline_ns:
        try: waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError: return None
        if waited == pid: return _wait_status(status)
        time.sleep(0.01)
    raise NativeCandidateError("numeric child reap timeout")


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
        _control_no_fd(raw, passed, HELPER_GO, "malformed helper GO")

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
        if _NATIVE_TEST_FAIL_PID1_PIDFD_OPEN: raise OSError(errno.EMFILE, "test pidfd_open failure")
        pidfd = os.pidfd_open(pid, 0)
        if _NATIVE_TEST_HELPER_EXIT_STAGE == "before-pidfd-transfer": os._exit(91)
        for descriptor in (
            ready_write, go_read, result_write, tree, helper_pidfd,
            *(fd for _name, fd, _device in device_sources),
        ):
            _close_and_prove(descriptor)
        _validate_pidfd(pidfd, pid, os.getpid(), namespace_pid1=True)
        _control_send(control_descriptor, PID1_FD + str(pid).encode("ascii"), pidfd)
        if _NATIVE_TEST_HELPER_EXIT_STAGE == "after-pidfd-transfer": os._exit(92)

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
        terminal = None
        if pid > 0 and not reaped:
            if pidfd >= 0:
                try: signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError: pass
                except BaseException: exit_code = 6
                try:
                    info = _wait_pidfd_reap(pidfd, settlement_deadline_ns)
                    terminal, reaped = (info.si_code, info.si_status), True
                except BaseException: exit_code = 7
            else:
                try:
                    terminal = _kill_wait_child_pid(pid, settlement_deadline_ns)
                    reaped = True
                except BaseException: exit_code = 7
        if terminal is not None:
            try: _control_send(control_descriptor, f"PID1-EXIT:{terminal[0]}:{terminal[1]}".encode("ascii"))
            except BaseException: exit_code = 8
        for descriptor in (pidfd, parent_pidfd, control_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        os._exit(exit_code)


def _signal_kill(pidfd, cleanup_errors, stage="pidfd-signal"):
    if pidfd < 0:
        return True
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return True
    except BaseException as error:
        cleanup_errors.append((stage, error))
        return False

def _signal_kill_pid(pid, cleanup_errors, stage="numeric-signal"):
    try:
        _libc_call("kill", ctypes.c_int(pid), ctypes.c_int(signal.SIGKILL))
        return True
    except OSError as error:
        if error.errno == errno.ESRCH:
            return True
        cleanup_errors.append((stage, error))
        return False


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


def _direct_namespace_children():
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid(): continue
        try: rows = Path(f"/proc/{name}/status").read_bytes().splitlines()
        except (FileNotFoundError, ProcessLookupError): continue
        ppid = [row for row in rows if row.startswith(b"PPid:\t")]
        nspid = [row for row in rows if row.startswith(b"NSpid:\t")]
        if len(ppid) == len(nspid) == 1 and int(ppid[0].split()[1]) == os.getpid():
            values = tuple(int(value) for value in nspid[0].split()[1:])
            if len(values) >= 2: found.append((int(name), values[-1] == 1))
    return found

def _signal_reap_pidfd(pidfd, deadline_ns, cleanup_errors, stage):
    start = time.monotonic_ns()
    window = max(0, deadline_ns - start)
    reap_tail = min(NS, max(NS // 10, window // 5))
    signal_until_ns = max(start, deadline_ns - reap_tail)
    next_signal_ns = start
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while time.monotonic_ns() < deadline_ns:
        now = time.monotonic_ns()
        if now <= signal_until_ns and now >= next_signal_ns:
            _signal_kill(pidfd, cleanup_errors, stage)
            next_signal_ns = now + NS // 10
        remaining = deadline_ns - now
        if poller.poll(min(50, max(1, (remaining + 999_999) // 1_000_000))):
            info = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            _require(info is not None, "missing adopted wait status")
            return info
    raise NativeCandidateError("adopted pidfd reap timeout")

def _drain_adopted_namespace(deadline_ns, cleanup_errors):
    pid1_status = None
    try:
        while time.monotonic_ns() < deadline_ns:
            children = _direct_namespace_children()
            if not children: return pid1_status, True
            for pid, is_pid1 in children:
                pidfd = -1
                try:
                    try: pidfd = os.pidfd_open(pid, 0)
                    except OSError: status = _kill_wait_child_pid(pid, deadline_ns)
                    else:
                        info = _signal_reap_pidfd(
                            pidfd, deadline_ns, cleanup_errors, "adopted-signal")
                        status = (info.si_code, info.si_status)
                    if is_pid1 and status is not None: pid1_status = status
                except (ProcessLookupError, ChildProcessError): pass
                except BaseException as error: cleanup_errors.append(("adopted-reap", error))
                finally:
                    if pidfd >= 0:
                        try: _close_and_prove(pidfd)
                        except BaseException as error: cleanup_errors.append(("adopted-pidfd-close", error))
        return pid1_status, False
    except BaseException as error:
        cleanup_errors.append(("adopted-census", error))
        return pid1_status, False

def _supervise_candidate(helper_pidfd, pid1_pidfd, control_descriptor, result_descriptor,
                         work_deadline_ns, settlement_deadline_ns, initial_error=None,
                         initial_no_pid1=False, helper_pid=-1):
    raw, cleanup_errors = bytearray(), []
    oversize = pipe_eof = control_eof = pid1_terminal = helper_reaped = False
    no_pid1, work_error = initial_no_pid1, initial_error
    helper_info = pid1_report = adopted_pid1 = None
    descendants_empty = False
    reap_reserve = min(POST_KILL_REAP_SECONDS * NS, max(NS // 10, (settlement_deadline_ns - work_deadline_ns) // 2))
    force_ns = max(time.monotonic_ns(), settlement_deadline_ns - reap_reserve)
    signal_until_ns = force_ns
    next_signal_ns = force_ns
    def reserve_reap_time():
        nonlocal signal_until_ns
        window = max(0, settlement_deadline_ns - force_ns)
        reap_tail = min(NS, max(NS // 10, window // 5))
        signal_until_ns = max(force_ns, settlement_deadline_ns - reap_tail)
    if work_error is not None:
        settlement_deadline_ns = min(settlement_deadline_ns, time.monotonic_ns() + REAP_SECONDS * NS)
        force_ns = time.monotonic_ns()
        next_signal_ns = force_ns
    reserve_reap_time()
    def work(error):
        nonlocal work_error, force_ns, settlement_deadline_ns, next_signal_ns
        if work_error is None:
            work_error = error
            settlement_deadline_ns = min(settlement_deadline_ns, time.monotonic_ns() + REAP_SECONDS * NS)
            force_ns = min(force_ns, time.monotonic_ns())
            next_signal_ns = min(next_signal_ns, force_ns)
            reserve_reap_time()
    try:
        for descriptor in (result_descriptor, control_descriptor):
            if descriptor >= 0:
                try: os.set_blocking(descriptor, False)
                except BaseException as error: work(error)
        while time.monotonic_ns() < settlement_deadline_ns:
            now = time.monotonic_ns()
            pid1_done = (no_pid1 or adopted_pid1 is not None
                         or (pid1_report is not None and (pid1_terminal or pid1_pidfd < 0))
                         or (pid1_terminal and helper_reaped and control_eof))
            if helper_reaped and pipe_eof and control_eof and pid1_done:
                adopted, descendants_empty = _drain_adopted_namespace(settlement_deadline_ns, cleanup_errors)
                if adopted is not None: adopted_pid1 = adopted
                if descendants_empty: break
            if work_error is None and now >= work_deadline_ns:
                work(NativeCandidateError("child deadline"))
            if now >= force_ns:
                if work_error is None:
                    work(NativeCandidateError("settlement deadline"))
                if now <= signal_until_ns and now >= next_signal_ns:
                    if not pid1_terminal and adopted_pid1 is None and not no_pid1:
                        _signal_kill(pid1_pidfd, cleanup_errors)
                    if not helper_reaped:
                        if helper_pidfd >= 0:
                            _signal_kill(helper_pidfd, cleanup_errors, "helper-final-signal")
                        elif helper_pid > 0:
                            _signal_kill_pid(helper_pid, cleanup_errors, "helper-final-numeric-signal")
                    next_signal_ns = now + NS // 10
            ready = set()
            try:
                poller = select.poll()
                for descriptor in (result_descriptor if not pipe_eof else -1,
                                   control_descriptor if not control_eof else -1,
                                   pid1_pidfd, helper_pidfd):
                    if descriptor >= 0: poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
                ready = {descriptor for descriptor, _event in poller.poll(50)}
            except BaseException as error:
                work(error)
                ready = {result_descriptor, control_descriptor, pid1_pidfd, helper_pidfd}
            if result_descriptor in ready and not pipe_eof:
                try: chunk = os.read(result_descriptor, 65_536)
                except BlockingIOError: chunk = None
                except BaseException as error: work(error); chunk = None
                if chunk == b"": pipe_eof = True
                elif chunk:
                    if len(raw) + len(chunk) > MAX_PROTOCOL_BYTES + 4:
                        oversize, raw = True, bytearray()
                        work(NativeCandidateError("oversize child result"))
                    elif not oversize: raw.extend(chunk)
            if control_descriptor in ready and not control_eof:
                try: packet, passed = _control_receive(control_descriptor)
                except BlockingIOError: packet = None
                except BaseException as error: work(error); packet = None
                if packet is not None:
                    try:
                        action = _control_adopt(
                            packet, passed,
                            lambda raw_packet, right: _classify_supervisor_packet(
                                raw_packet, right,
                                ((_pidfd_process(helper_pidfd) if helper_pidfd >= 0 else helper_pid)
                                 if raw_packet.startswith(PID1_FD) else -1),
                                pid1_pidfd < 0,
                            ),
                        )
                    except CleanupUncertain as error:
                        work(error.work_error or error)
                        cleanup_errors.extend(error.cleanup_errors)
                    except BaseException as error:
                        work(error)
                    else:
                        if action[0] == "pid1": pid1_pidfd = action[1]
                        elif action[0] == "eof": control_eof = True
                        elif action[0] == "pid1-exit": pid1_report = action[1], action[2]
                        elif action[0] == "no-pid1":
                            no_pid1 = True; work(HelperCandidateError(action[1], action[2]))
                        elif action[0] == "helper-error":
                            work(HelperCandidateError(action[1], action[2]))
            if pid1_pidfd in ready: pid1_terminal = True
            if helper_pidfd >= 0 and not helper_reaped:
                try:
                    info = os.waitid(os.P_PIDFD, helper_pidfd, os.WEXITED | os.WNOHANG)
                    if info is not None: helper_info, helper_reaped = info, True
                except ChildProcessError as error:
                    cleanup_errors.append(("helper-pidfd-reap", error)); helper_reaped = True
                except BaseException as error: work(error)
            elif helper_pidfd < 0 and helper_pid > 0 and not helper_reaped:
                try:
                    waited, status = os.waitpid(helper_pid, os.WNOHANG)
                    if waited == helper_pid:
                        helper_info, helper_reaped = _wait_status(status), True
                except ChildProcessError:
                    helper_reaped = True
                except BaseException as error:
                    work(error)
            if helper_reaped and pid1_terminal and adopted_pid1 is None:
                try:
                    info = os.waitid(os.P_PIDFD, pid1_pidfd, os.WEXITED | os.WNOHANG)
                    if info is not None: adopted_pid1 = (info.si_code, info.si_status)
                except ChildProcessError: pass
                except BaseException as error: cleanup_errors.append(("adopted-pid1-reap", error))
            if helper_reaped and control_eof and not no_pid1 and pid1_report is None and adopted_pid1 is None:
                work(NativeCandidateError("helper exited without PID1 settlement report"))
                if pid1_pidfd < 0:
                    adopted, descendants_empty = _drain_adopted_namespace(settlement_deadline_ns, cleanup_errors)
                    if adopted is not None: adopted_pid1, pid1_terminal = adopted, True
    except BaseException as error: work(error)
    finally:
        pid1_done = (no_pid1 or adopted_pid1 is not None
                     or (pid1_report is not None and (pid1_terminal or pid1_pidfd < 0))
                     or (pid1_terminal and helper_reaped and control_eof))
        if not (helper_reaped and pipe_eof and control_eof and pid1_done and descendants_empty):
            now = time.monotonic_ns()
            if now <= signal_until_ns:
                if not pid1_terminal and adopted_pid1 is None and not no_pid1:
                    _signal_kill(pid1_pidfd, cleanup_errors)
                if not helper_reaped:
                    if helper_pidfd >= 0:
                        _signal_kill(helper_pidfd, cleanup_errors, "helper-final-signal")
                    elif helper_pid > 0:
                        _signal_kill_pid(helper_pid, cleanup_errors, "helper-final-numeric-signal")
            adopted, descendants_empty = _drain_adopted_namespace(settlement_deadline_ns, cleanup_errors)
            if adopted is not None: adopted_pid1, pid1_terminal = adopted, True
        if not helper_reaped: cleanup_errors.append(("helper-reap-timeout", NativeCandidateError("helper not reaped")))
        if not (no_pid1 or adopted_pid1 is not None or (pid1_report is not None and (pid1_terminal or pid1_pidfd < 0))
                or (pid1_terminal and helper_reaped and control_eof)):
            cleanup_errors.append(("pid1-settlement", NativeCandidateError("PID namespace teardown unproved")))
        if not descendants_empty: cleanup_errors.append(("adopted-settlement", NativeCandidateError("adopted descendants remain")))
        if not pipe_eof: cleanup_errors.append(("result-pipe-eof", NativeCandidateError("result pipe not closed")))
        if not control_eof: cleanup_errors.append(("control-eof", NativeCandidateError("helper control not closed")))
        for stage, descriptor in (("result-pipe-close", result_descriptor), ("control-close", control_descriptor),
                                  ("pid1-pidfd-close", pid1_pidfd), ("helper-pidfd-close", helper_pidfd)):
            if descriptor >= 0:
                try: _close_and_prove(descriptor)
                except BaseException as error: cleanup_errors.append((stage, error))
    helper_status = ((helper_info.si_code, helper_info.si_status)
                     if hasattr(helper_info, "si_code") else helper_info)
    if helper_status is not None and helper_status != (os.CLD_EXITED, 0):
        work(StageCandidateError("helper-terminal", "nonzero-status"))
    result = frame_error = None
    if raw and not oversize:
        try: result = _parse_frame(bytes(raw))
        except BaseException as error: frame_error = error
    terminal = pid1_report if pid1_report is not None else adopted_pid1
    if terminal is not None and terminal != (os.CLD_EXITED, 0):
        if (isinstance(frame_error, ChildCandidateError)
                and terminal == (os.CLD_EXITED, 1)):
            work(frame_error)
        else:
            work(StageCandidateError("pid1-terminal", "nonzero-status"))
    elif isinstance(frame_error, ChildCandidateError):
        reason = ("error-frame-zero-status" if terminal == (os.CLD_EXITED, 0)
                  else "error-frame-missing-status")
        work(StageCandidateError("pid1-protocol", reason))
    elif frame_error is not None:
        work(frame_error)
    elif not raw and work_error is None:
        work_error = StageCandidateError("pid1-result", "missing-frame")
    settled = (helper_reaped and pipe_eof and control_eof and descendants_empty
               and (no_pid1 or adopted_pid1 is not None
                    or (pid1_report is not None and (pid1_terminal or pid1_pidfd < 0)) or pid1_terminal))
    return result, work_error, cleanup_errors, settled

def _run_candidate_child(tree, contract, closure, package, work_deadline_ns, settlement_deadline_ns):
    device_sources = ()
    descriptors = {name: -1 for name in ("control_parent", "control_helper", "ready_read", "ready_write",
        "go_read", "go_write", "result_read", "result_write", "parent_pidfd")}
    helper = helper_pidfd = pid1_pidfd = -1
    parent_close_errors, initial_error = [], None
    known_no_pid1 = launched = helper_go_sent = close_uncertain = False
    subreaper_previous = -1
    try:
        subreaper_previous = _subreaper_state()
        _set_subreaper(True)
        device_sources = _open_device_sources()
        parent_socket, helper_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        descriptors["control_parent"], descriptors["control_helper"] = parent_socket.detach(), helper_socket.detach()
        descriptors["ready_read"], descriptors["ready_write"] = os.pipe2(os.O_CLOEXEC)
        descriptors["go_read"], descriptors["go_write"] = os.pipe2(os.O_CLOEXEC)
        descriptors["result_read"], descriptors["result_write"] = os.pipe2(os.O_CLOEXEC)
        descriptors["parent_pidfd"] = os.pidfd_open(os.getpid(), 0)
        helper = os.fork()
        if helper == 0:
            try:
                for name in ("control_parent", "ready_read", "go_write", "result_read"): _close_and_prove(descriptors[name])
                _helper_main(descriptors["control_helper"], descriptors["ready_write"], descriptors["go_read"],
                    descriptors["result_write"], tree, device_sources, descriptors["parent_pidfd"],
                    work_deadline_ns, settlement_deadline_ns, contract, closure, package)
            except BaseException: os._exit(126)
            os._exit(127)
        launched = True
        if _NATIVE_TEST_FAIL_HELPER_PIDFD_OPEN:
            raise OSError(errno.EMFILE, "test helper pidfd_open failure")
        helper_pidfd = os.pidfd_open(helper, 0)
    except BaseException as error: initial_error = error
    if launched:
        for name in ("control_helper", "ready_write", "go_read", "result_write", "parent_pidfd"):
            descriptor, descriptors[name] = descriptors[name], -1
            if descriptor >= 0:
                try: _close_and_prove(descriptor)
                except BaseException as error: parent_close_errors.append((f"{name}-close", error)); close_uncertain = True
        detached = (("parent-tree-close", tree), *((f"parent-device-{name}-close", fd) for name, fd, _device in device_sources))
        tree, device_sources = -1, ()
        for stage, descriptor in detached:
            if descriptor >= 0:
                try: _close_and_prove(descriptor)
                except BaseException as error: parent_close_errors.append((stage, error)); close_uncertain = True
        if parent_close_errors and initial_error is None: initial_error = NativeCandidateError("pre-gate descriptor closure failed")
    try:
        if initial_error is None:
            packet, passed = _wait_control(descriptors["control_parent"], helper_pidfd, work_deadline_ns)
            _control_no_fd(packet, passed, HELPER_READY, "helper READY malformed")
            _validate_pidfd(helper_pidfd, helper, os.getpid(), namespace_pid1=False)
            _control_send(descriptors["control_parent"], HELPER_GO)
            helper_go_sent = True
            pid1_ready, pid1 = False, -1
            while not (pid1_ready and pid1_pidfd >= 0):
                remaining = work_deadline_ns - time.monotonic_ns(); _require(remaining > 0, "PID1 gate timeout")
                poller = select.poll()
                for descriptor in (descriptors["control_parent"], descriptors["ready_read"], helper_pidfd):
                    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
                ready = {descriptor for descriptor, _event in poller.poll(min(250, max(1, (remaining + 999_999) // 1_000_000)))}
                if descriptors["ready_read"] in ready and not pid1_ready:
                    _wait_pipe_token(descriptors["ready_read"], PID1_READY, helper_pidfd, work_deadline_ns); pid1_ready = True
                if descriptors["control_parent"] in ready:
                    packet, passed = _control_receive(descriptors["control_parent"])
                    try:
                        action = _control_adopt(
                            packet, passed,
                            lambda raw, right: _classify_pid1_gate_packet(
                                raw, right, helper, pid1_pidfd < 0),
                        )
                    except CleanupUncertain as error:
                        if error.work_error is not None and initial_error is None:
                            initial_error = error.work_error
                        parent_close_errors.extend(error.cleanup_errors)
                        close_uncertain = True
                        raise
                    if action[0] == "no-pid1":
                        known_no_pid1 = True
                        raise HelperCandidateError(action[1], action[2])
                    _require(pid1_pidfd < 0, "PID1 pidfd duplicate")
                    pid1, pid1_pidfd = action[1], action[2]
                if helper_pidfd in ready and pid1_pidfd < 0: raise NativeCandidateError("helper exited before PID1 release")
            _validate_pidfd(pid1_pidfd, pid1, helper, namespace_pid1=True)
            _validate_pidfd(helper_pidfd, helper, os.getpid(), namespace_pid1=False)
            if _NATIVE_TEST_BEFORE_PID1_GO is not None: _NATIVE_TEST_BEFORE_PID1_GO(helper, pid1, descriptors["go_write"])
            descriptor, descriptors["ready_read"] = descriptors["ready_read"], -1; _close_and_prove(descriptor)
            _write_all(descriptors["go_write"], PID1_GO)
            descriptor, descriptors["go_write"] = descriptors["go_write"], -1; _close_and_prove(descriptor)
    except BaseException as error:
        if initial_error is None: initial_error = error
    cleanup_errors = list(parent_close_errors)
    if launched:
        control, descriptors["control_parent"] = descriptors["control_parent"], -1
        result_fd, descriptors["result_read"] = descriptors["result_read"], -1
        result, work_error, supervised, settled = _supervise_candidate(helper_pidfd, pid1_pidfd, control, result_fd,
            work_deadline_ns, settlement_deadline_ns, initial_error,
            known_no_pid1 or not helper_go_sent, helper)
        cleanup_errors.extend(supervised)
    else:
        result = None
        work_error = initial_error or NativeCandidateError("launch failed")
        settled = not isinstance(work_error, CleanupUncertain)
    for name, descriptor in tuple(descriptors.items()):
        if descriptor >= 0:
            descriptors[name] = -1
            try: _close_and_prove(descriptor)
            except BaseException as error:
                cleanup_errors.append((f"failed-launch-{name}-close", error))
                settled = False
    detached = (("failed-launch-tree-close", tree), *((f"failed-launch-device-{name}-close", fd) for name, fd, _device in device_sources))
    tree, device_sources = -1, ()
    for stage, descriptor in detached:
        if descriptor >= 0:
            try: _close_and_prove(descriptor)
            except BaseException as error:
                cleanup_errors.append((stage, error))
                settled = False
    if subreaper_previous >= 0:
        try: _set_subreaper(bool(subreaper_previous))
        except BaseException as error: cleanup_errors.append(("subreaper-restore", error)); settled = False
    return result, work_error, cleanup_errors, settled and not close_uncertain


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
        _preflight_require(Path("/marker").read_bytes() == b"preflight", "preflight-operation-descriptor")
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
    """Exact non-mount operation-descriptor probe; mounts occur only child-private."""
    _platform_gate()
    outcome, descriptor, source_created, result, tree = _Outcome(), None, False, None, -1
    try:
        _require(not PREFLIGHT_SOURCE.exists(), "preflight source residue")
        os.mkdir(PREFLIGHT_SOURCE, 0o700); source_created = True
        for name in ("proc", "dev", "tmp"): os.mkdir(PREFLIGHT_SOURCE / name, 0o755)
        (PREFLIGHT_SOURCE / "marker").write_bytes(b"preflight")
        descriptor = os.open(PREFLIGHT_SOURCE, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        tree = _open_detached_tree(descriptor)
        retired, descriptor = descriptor, None; _close_and_prove(retired)
        work_deadline = time.monotonic_ns() + 12 * NS
        owned_tree, tree = tree, -1
        result, work_error, cleanup_errors, settled = _run_candidate_child(
            owned_tree, {}, {}, _PreflightPackage, work_deadline, work_deadline + 5 * NS)
        if work_error is not None: outcome.work(work_error)
        for stage, error in cleanup_errors: outcome.cleanup(f"preflight-{stage}", error)
        if not settled: outcome.cleanup("preflight-settlement", NativeCandidateError("PID namespace not settled"))
    except BaseException as error: outcome.work(error)
    if descriptor is not None:
        retired, descriptor = descriptor, None
        try: _close_and_prove(retired)
        except BaseException as error: outcome.cleanup("preflight-source-close", error)
    if tree >= 0:
        retired, tree = tree, -1
        try: _close_and_prove(retired)
        except BaseException as error: outcome.cleanup("preflight-tree-close", error)
    if source_created:
        try:
            os.unlink(PREFLIGHT_SOURCE / "marker")
            for name in ("proc", "dev", "tmp"): os.rmdir(PREFLIGHT_SOURCE / name)
            os.rmdir(PREFLIGHT_SOURCE)
        except BaseException as error: outcome.cleanup("preflight-source-remove", error)
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


def _cleanup_cache(verifier, authority, deadline_ns):
    root, root_identity, cache, cache_identity, held, sentinel, sentinel_identity = authority
    errors = []

    def before_effect():
        _require(time.monotonic_ns() < deadline_ns, "cache cleanup deadline")
    try:
        before_effect()
        _require(_identity(os.fstat(root)) == root_identity and _identity(os.fstat(cache)) == cache_identity)
        _require(set(os.listdir(cache)) == {row["cache_name"] for row, _fd, _identity_value in held})
        for row, descriptor, held_identity in held:
            before_effect()
            current = os.stat(row["cache_name"], dir_fd=cache, follow_symlinks=False)
            _require(_identity(os.fstat(descriptor)) == held_identity == _identity(current))
            _require(hashlib.sha256(_read_fd(descriptor, row["size"])).hexdigest() == row["sha256"])
            before_effect()
            os.unlink(row["cache_name"], dir_fd=cache)
            before_effect()
            os.fsync(cache)
        before_effect()
        _require(_identity(os.fstat(sentinel)) == sentinel_identity)
        _require(_read_fd(sentinel, len(verifier.SENTINEL_BYTES)) == verifier.SENTINEL_BYTES)
        before_effect()
        os.rmdir("cache", dir_fd=root)
        before_effect()
        os.unlink(verifier.SENTINEL, dir_fd=root)
        before_effect()
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
            before_effect()
            os.rmdir(verifier.ARTIFACT_ROOT)
            before_effect()
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
        rootfs_deadline_ns = lifecycle_deadline_ns - CLEANUP_RESERVE_SECONDS * NS
        _require(rootfs_deadline_ns > time.monotonic_ns(), "cleanup reserve exhausted")
        rootfs_control = fs.OperationControl(rootfs_deadline_ns, lambda: False)
        lifecycle_control = fs.OperationControl(lifecycle_deadline_ns, lambda: False)
        phase_a._bootstrap_rootfs(builder, fs, approval, rootfs_control)
        rootfs, retained = build._native_package_build_once_retained(
            approval, os.urandom(32).hex(), lifecycle_control)
        build._require_pinned(rootfs, publication._load_pins())
        if len(rootfs.cache) != 16:
            raise StageCandidateError("post-build-cache", "unexpected-count")

        work_deadline_ns = min(
            time.monotonic_ns() + CHILD_SECONDS * NS,
            rootfs_deadline_ns,
        )
        if work_deadline_ns <= time.monotonic_ns():
            raise StageCandidateError("post-build-budget", "cleanup-reserve-exhausted")
        settlement_deadline_ns = min(lifecycle_deadline_ns, work_deadline_ns + REAP_SECONDS * NS)
        # This must precede the outer fork: only the trusted parent can clone
        # and harden the retained mount from its current namespace.  From the
        # ownership transfer onward cleanup is prohibited until both pidfds,
        # helper reap, PID1 report, and both channel EOFs prove settlement.
        tree = _open_retained_tree(retained.owned.root.operation_fd.number)
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
                _cleanup_cache(verifier, cache_authority, lifecycle_deadline_ns)
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
    if result is None:
        raise StageCandidateError("pid1-result", "absent-after-settlement")
    return result


def _diagnostic_line(error):
    category = _category(error)
    detail = ""
    if isinstance(error, CleanupUncertain):
        work = "none" if error.work_error is None else _category(error.work_error)
        cleanup = ",".join(
            f"{stage if isinstance(stage, str) and _SAFE_TOKEN.fullmatch(stage) else 'unknown'}-{_category(item)}"
            for stage, item in error.cleanup_errors)
        detail = f":work-{work}:cleanup-{cleanup}"[:512]
    elif isinstance(error, ChildCandidateError):
        detail = f":{error.stage}"
    elif isinstance(error, (StageCandidateError, HelperCandidateError)):
        detail = f":{error.stage}:{error.reason}"
    raw = f"native package candidate failed:{category}{detail}\n".encode("ascii")
    return raw if len(raw) <= 640 else b"native package candidate failed:unknown\n"


def main():
    if len(sys.argv) != 1:
        return 1
    try:
        raw = run()
        _write_all(sys.stdout.fileno(), raw)
        return 0
    except BaseException as error:
        try:
            os.write(2, _diagnostic_line(error))
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
