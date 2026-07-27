#!/usr/bin/python3
"""Bounded, metadata-only runner capability observation.

This program is deliberately non-authoritative.  Its normal mode emits one
canonical JSON line.  ``--self-test`` uses only an in-memory fake backend and
is safe on non-Linux hosts.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import resource
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

SCHEMA = "cogs.runner-capability-probe/v1alpha1"
PYTHON = "/usr/bin/python3"
SUDO = "/usr/bin/sudo"
UNSHARE = "/usr/bin/unshare"
GZIP = "/usr/bin/gzip"
ZSTD = "/usr/bin/zstd"
KVM = "/dev/kvm"
PRIVATE_PARENT = "/tmp/cogs-runner-capability-probe"
MAX_JSON = 32_768
MAX_OUTPUT = 4_096
MAX_TOOL = 128 * 1024 * 1024
MAX_TOOL_AGGREGATE = 384 * 1024 * 1024
GLOBAL_SECONDS = 120.0
CASE_SECONDS = 5.0
NS_SECONDS = 10.0

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MNT_DETACH = 2
AT_EMPTY_PATH = 0x1000
O_PATH = getattr(os, "O_PATH", 0o10000000)
O_TMPFILE = getattr(os, "O_TMPFILE", 0o20000000)
SYS_CLOSE_RANGE = 436
SYS_SECCOMP = 317
SECCOMP_SET_MODE_FILTER = 1
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_GET_SECCOMP = 21
PR_CAPBSET_DROP = 24
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
KVM_GET_API_VERSION = 0xAE00
KVM_CHECK_EXTENSION = 0xAE03
KVM_CAP_USER_MEMORY = 3

libc = ctypes.CDLL(None, use_errno=True)
PRIVATE_PARENT_OWNED = False
ACTIVE_LEDGER: Ledger | None = None


def _missing_libc(*_arguments: Any) -> int:
    ctypes.set_errno(errno.ENOSYS)
    return -1


def _libc_function(name: str) -> Any:
    return getattr(libc, name, _missing_libc)


MOUNT = _libc_function("mount")
UMOUNT2 = _libc_function("umount2")
UNSHARE_CALL = _libc_function("unshare")
PRCTL = _libc_function("prctl")
SYSCALL = _libc_function("syscall")
CAPSET = _libc_function("capset")
STATFS = _libc_function("statfs")
LINKAT = _libc_function("linkat")
if MOUNT is not _missing_libc:
    MOUNT.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    MOUNT.restype = ctypes.c_int
if UMOUNT2 is not _missing_libc:
    UMOUNT2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    UMOUNT2.restype = ctypes.c_int
if UNSHARE_CALL is not _missing_libc:
    UNSHARE_CALL.argtypes = [ctypes.c_int]
    UNSHARE_CALL.restype = ctypes.c_int
if PRCTL is not _missing_libc:
    PRCTL.restype = ctypes.c_int
if SYSCALL is not _missing_libc:
    SYSCALL.restype = ctypes.c_long


def status(state: str, err: int | None = None) -> dict[str, Any]:
    if state not in {"ok", "unsupported", "denied", "blocked", "mismatch", "error"}:
        raise ValueError("bad status state")
    if err is not None and not (1 <= err <= 4095):
        raise ValueError("bad errno")
    return {"state": state, "errno": err}


def from_errno(err: int) -> dict[str, Any]:
    if err in (errno.ENOSYS, errno.EOPNOTSUPP):
        return status("unsupported", err)
    if err in (errno.EPERM, errno.EACCES):
        return status("denied", err)
    return status("error", err if 1 <= err <= 4095 else None)


def call_errno(result: int) -> int:
    if result != -1:
        return 0
    value = ctypes.get_errno()
    return value if value else errno.EIO


def canonical_bytes(value: Any) -> bytes:
    def check(item: Any) -> None:
        if item is None or isinstance(item, (bool, int, str)):
            return
        if isinstance(item, list):
            for child in item:
                check(child)
            return
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError("non-string JSON key")
            for child in item.values():
                check(child)
            return
        raise ValueError("non-canonical JSON value")

    check(value)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8", "strict"
    ) + b"\n"
    if len(encoded) > MAX_JSON:
        raise ValueError("report too large")
    return encoded


def safe_close(fd: int) -> bool:
    try:
        os.close(fd)
        return True
    except OSError:
        return False


def read_bounded(fd: int, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(65_536, limit + 1 - total))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[: limit + 1], True


@dataclass
class CommandResult:
    invocation: dict[str, Any]
    exit_code: int | None
    output: bytes
    overflow: bool = False
    timed_out: bool = False


@dataclass
class Ledger:
    deadline: float
    children_reaped: bool = True
    descriptors_restored: bool = True
    mounts_gone: bool = True
    temporary_names_gone: bool = True
    uncertainty: bool = False
    child_count: int = 0
    tool_bytes_read: int = 0
    live_children: set[int] = field(default_factory=set)

    def remaining(self, wanted: float) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            self.uncertainty = True
            return 0.001
        return min(wanted, left)

    def run(self, argv: list[str], seconds: float = CASE_SECONDS, pass_fds: tuple[int, ...] = ()) -> CommandResult:
        if self.child_count >= 16:
            self.uncertainty = True
            return CommandResult(status("blocked"), None, b"")
        try:
            process = subprocess.Popen(
                argv,
                executable=argv[0],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
                pass_fds=pass_fds,
                env={"LC_ALL": "C"},
                start_new_session=True,
            )
        except OSError as exc:
            return CommandResult(from_errno(exc.errno or errno.EIO), None, b"")
        self.child_count += 1
        self.live_children.add(process.pid)
        assert process.stdout is not None
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        output = bytearray()
        overflow = False
        timed_out = False
        end = time.monotonic() + self.remaining(seconds)
        try:
            while True:
                wait = end - time.monotonic()
                if wait <= 0:
                    timed_out = True
                    break
                events = selector.select(min(wait, 0.05))
                for _, _ in events:
                    try:
                        chunk = os.read(fd, min(1024, MAX_OUTPUT + 1 - len(output)))
                    except BlockingIOError:
                        chunk = None
                    if chunk == b"":
                        selector.unregister(fd)
                    elif chunk:
                        output.extend(chunk)
                        if len(output) > MAX_OUTPUT:
                            overflow = True
                            break
                if overflow:
                    break
                code = process.poll()
                if code is not None and not selector.get_map():
                    break
            if timed_out or overflow:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    self.uncertainty = True
            try:
                code = process.wait(timeout=self.remaining(1.0))
            except subprocess.TimeoutExpired:
                code = None
                self.children_reaped = False
                self.uncertainty = True
        finally:
            selector.close()
            process.stdout.close()
            self.live_children.discard(process.pid)
        if timed_out or overflow:
            self.uncertainty = True
            return CommandResult(status("error", errno.ETIMEDOUT if timed_out else errno.EOVERFLOW), code, b"", overflow, timed_out)
        return CommandResult(status("ok") if code == 0 else status("mismatch"), code, bytes(output))

    def abort(self) -> None:
        for pid in tuple(self.live_children):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                self.uncertainty = True
        for pid in tuple(self.live_children):
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            except OSError:
                self.children_reaped = False
            self.live_children.discard(pid)
        self.uncertainty = True

    def fork_case(self, function: Callable[[], Any], seconds: float = CASE_SECONDS) -> tuple[dict[str, Any], Any | None]:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            pid = os.fork()
        except OSError as exc:
            safe_close(read_fd)
            safe_close(write_fd)
            return from_errno(exc.errno or errno.EIO), None
        self.child_count += 1
        self.live_children.add(pid)
        if pid == 0:
            safe_close(read_fd)
            try:
                os.setsid()
                payload = canonical_bytes({"value": function()})
                if len(payload) > MAX_OUTPUT:
                    os._exit(121)
                os.write(write_fd, payload)
                safe_close(write_fd)
                os._exit(0)
            except BaseException:
                safe_close(write_fd)
                os._exit(120)
        safe_close(write_fd)
        os.set_blocking(read_fd, False)
        end = time.monotonic() + self.remaining(seconds)
        data = bytearray()
        code: int | None = None
        while time.monotonic() < end:
            try:
                chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
                if chunk:
                    data.extend(chunk)
                    if len(data) > MAX_OUTPUT:
                        break
            except BlockingIOError:
                pass
            waited, wait_status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                code = os.waitstatus_to_exitcode(wait_status)
                break
            time.sleep(0.005)
        if code is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                _, wait_status = os.waitpid(pid, 0)
                code = os.waitstatus_to_exitcode(wait_status)
            except OSError:
                self.children_reaped = False
            self.uncertainty = True
        self.live_children.discard(pid)
        if code == 0:
            while len(data) <= MAX_OUTPUT:
                try:
                    chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
                except BlockingIOError:
                    time.sleep(0.001)
                    continue
                if not chunk:
                    break
                data.extend(chunk)
        safe_close(read_fd)
        if code != 0 or len(data) > MAX_OUTPUT:
            return status("error", errno.ETIMEDOUT if code == -signal.SIGKILL else errno.EIO), None
        try:
            parsed = json.loads(bytes(data))
            if set(parsed) != {"value"}:
                raise ValueError
            return status("ok"), parsed["value"]
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            return status("mismatch"), None


def fixed_identity(path: str, version_args: list[str], pattern: re.Pattern[str], ledger: Ledger) -> dict[str, Any]:
    empty = {
        "path": path,
        "present": False,
        "regular_file": None,
        "root_owned": None,
        "mode": None,
        "size": None,
        "sha256": None,
        "version_line": None,
        "version_output_sha256": None,
        "observation": status("unsupported"),
    }
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return empty
    except OSError as exc:
        empty["present"] = exc.errno not in (errno.ENOENT, errno.ENOTDIR)
        empty["observation"] = from_errno(exc.errno or errno.EIO)
        return empty
    empty["present"] = True
    try:
        before = os.fstat(fd)
        empty["regular_file"] = stat.S_ISREG(before.st_mode)
        empty["root_owned"] = before.st_uid == 0
        empty["mode"] = format(stat.S_IMODE(before.st_mode), "04o")
        if not stat.S_ISREG(before.st_mode) or not (1 <= before.st_size <= MAX_TOOL):
            empty["observation"] = status("mismatch")
            return empty
        empty["size"] = before.st_size
        if ledger.tool_bytes_read + before.st_size > MAX_TOOL_AGGREGATE:
            empty["observation"] = status("blocked")
            return empty
        ledger.tool_bytes_read += before.st_size
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                empty["observation"] = status("mismatch")
                return empty
            digest.update(chunk)
            remaining -= len(chunk)
        after_read = os.fstat(fd)
        empty["sha256"] = digest.hexdigest()
        command = ledger.run([path, *version_args])
        if command.invocation["state"] != "ok" or command.overflow:
            empty["observation"] = command.invocation
            return empty
        empty["version_output_sha256"] = hashlib.sha256(command.output).hexdigest()
        first = command.output.splitlines()[0] if command.output.splitlines() else b""
        try:
            line = first.decode("ascii", "strict")
        except UnicodeDecodeError:
            line = ""
        if 1 <= len(first) <= 160 and pattern.fullmatch(line) and all(32 <= byte <= 126 for byte in first):
            empty["version_line"] = line
        try:
            path_fd = os.open(path, flags)
            try:
                after_path = os.fstat(path_fd)
            finally:
                safe_close(path_fd)
        except OSError:
            empty["observation"] = status("mismatch")
            return empty
        generation = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if generation(before) != generation(after_read) or generation(before) != generation(after_path):
            empty["observation"] = status("mismatch")
        elif command.exit_code != 0:
            empty["observation"] = status("mismatch")
        else:
            empty["observation"] = status("ok")
        return empty
    except OSError as exc:
        empty["observation"] = from_errno(exc.errno or errno.EIO)
        return empty
    finally:
        if not safe_close(fd):
            ledger.descriptors_restored = False
            ledger.uncertainty = True


def statfs_kind(path: str) -> str:
    buffer = ctypes.create_string_buffer(256)
    result = STATFS(os.fsencode(path), ctypes.byref(buffer))
    if result == -1:
        return "unknown"
    magic = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_long))[0]
    return {0xEF53: "ext4", 0x58465342: "xfs", 0x01021994: "tmpfs"}.get(magic, "other")


def empty_tmpfile_case(filesystem: str = "unknown", blocked: bool = False) -> dict[str, Any]:
    initial = status("blocked") if blocked else status("unsupported")
    return {
        "filesystem": filesystem,
        "open_otmpfile": initial,
        "initial_nlink_zero": None,
        "owner_is_probe_identity": None,
        "initial_mode_0600": None,
        "linkat_empty_path": status("blocked"),
        "linked_identity_matches": None,
        "cleanup": status("ok"),
    }


def tmpfile_case(directory: str) -> dict[str, Any]:
    result = empty_tmpfile_case(statfs_kind(directory))
    dir_fd = -1
    file_fd = -1
    linked = False
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            file_fd = os.open(".", O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
        except OSError as exc:
            result["open_otmpfile"] = from_errno(exc.errno or errno.EIO)
            return result
        result["open_otmpfile"] = status("ok")
        opened = os.fstat(file_fd)
        result["initial_nlink_zero"] = opened.st_nlink == 0
        result["owner_is_probe_identity"] = opened.st_uid == os.geteuid()
        result["initial_mode_0600"] = stat.S_IMODE(opened.st_mode) == 0o600
        os.write(file_fd, b"x")
        os.fsync(file_fd)
        ctypes.set_errno(0)
        linked_result = LINKAT(file_fd, b"", dir_fd, b"published", AT_EMPTY_PATH)
        linked_errno = call_errno(linked_result)
        if linked_errno:
            result["linkat_empty_path"] = from_errno(linked_errno)
            return result
        linked = True
        result["linkat_empty_path"] = status("ok")
        linked_stat = os.stat("published", dir_fd=dir_fd, follow_symlinks=False)
        current = os.fstat(file_fd)
        result["linked_identity_matches"] = (linked_stat.st_dev, linked_stat.st_ino) == (current.st_dev, current.st_ino)
        return result
    except OSError as exc:
        if result["open_otmpfile"]["state"] == "unsupported":
            result["open_otmpfile"] = from_errno(exc.errno or errno.EIO)
        return result
    finally:
        cleanup_error = 0
        if linked and dir_fd >= 0:
            try:
                os.unlink("published", dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError as exc:
                cleanup_error = exc.errno or errno.EIO
        if file_fd >= 0 and not safe_close(file_fd):
            cleanup_error = cleanup_error or errno.EIO
        if dir_fd >= 0 and not safe_close(dir_fd):
            cleanup_error = cleanup_error or errno.EIO
        result["cleanup"] = from_errno(cleanup_error) if cleanup_error else status("ok")


def mount_call(source: str | None, target: str, fstype: str | None, flags: int, data: str | None = None) -> dict[str, Any]:
    ctypes.set_errno(0)
    value = MOUNT(
        os.fsencode(source) if source is not None else None,
        os.fsencode(target),
        os.fsencode(fstype) if fstype is not None else None,
        flags,
        os.fsencode(data) if data is not None else None,
    )
    err = call_errno(value)
    return from_errno(err) if err else status("ok")


def umount_call(target: str) -> dict[str, Any]:
    ctypes.set_errno(0)
    err = call_errno(UMOUNT2(os.fsencode(target), 0))
    return from_errno(err) if err else status("ok")


def unshare_call(flags: int) -> dict[str, Any]:
    ctypes.set_errno(0)
    err = call_errno(UNSHARE_CALL(flags))
    return from_errno(err) if err else status("ok")


def mount_namespace_batch() -> dict[str, Any]:
    return {"namespace": basic_namespace("mount"), "private": private_mount_cases()}


def private_mount_cases() -> dict[str, Any]:
    private_dir = f"{PRIVATE_PARENT}/private-tmpfs"
    op_root = f"{PRIVATE_PARENT}/opath-root"
    result = {
        "private_tmpfs": empty_tmpfile_case(blocked=True),
        "same": empty_opath_case(True),
        "across": empty_opath_case(True),
        "mounts_gone": True,
    }
    created: list[str] = []
    mounted: list[str] = []
    namespace = unshare_call(CLONE_NEWNS)
    if namespace["state"] != "ok":
        result["private_tmpfs"]["open_otmpfile"] = namespace
        result["same"]["open_opath_directory"] = namespace
        result["across"]["open_opath_directory"] = namespace
        return result
    propagation = mount_call(None, "/", None, MS_REC | MS_PRIVATE)
    if propagation["state"] != "ok":
        result["private_tmpfs"]["open_otmpfile"] = propagation
        result["same"]["open_opath_directory"] = propagation
        result["across"]["open_opath_directory"] = propagation
        return result
    tmp_mount = mount_call("tmpfs", private_dir, "tmpfs", 0, "nodev,nosuid,noexec,size=1048576,mode=0700")
    if tmp_mount["state"] == "ok":
        mounted.append(private_dir)
        result["private_tmpfs"] = tmpfile_case(private_dir)
    else:
        result["private_tmpfs"]["open_otmpfile"] = tmp_mount
    op_mount = mount_call("tmpfs", op_root, "tmpfs", 0, "nodev,nosuid,noexec,size=1048576,mode=0700")
    if op_mount["state"] != "ok":
        result["same"]["open_opath_directory"] = op_mount
        result["across"]["open_opath_directory"] = op_mount
    else:
        mounted.append(op_root)
        for name in ("source", "same-target", "cross-target"):
            path = f"{op_root}/{name}"
            os.mkdir(path, 0o700)
            created.append(path)
        result["same"] = opath_one(f"{op_root}/source", f"{op_root}/same-target", False)
        result["across"] = opath_one(f"{op_root}/source", f"{op_root}/cross-target", True)
    for path in reversed(created):
        try:
            os.rmdir(path)
        except OSError:
            result["mounts_gone"] = False
    for path in reversed(mounted):
        if umount_call(path)["state"] != "ok":
            result["mounts_gone"] = False
    return result


def empty_opath_case(blocked: bool = False) -> dict[str, Any]:
    initial = status("blocked") if blocked else status("unsupported")
    return {
        "open_opath_directory": initial,
        "fstat_stable": None,
        "bind_mount_from_proc_fd": status("blocked"),
        "bind_target_identity_matches": None,
        "cleanup": status("ok"),
    }


def opath_one(source: str, target: str, across: bool) -> dict[str, Any]:
    result = empty_opath_case()
    fd = -1
    mounted = False
    try:
        opened = os.open(source, O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                os.close(197)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            os.dup2(opened, 197, inheritable=False)
            fd = 197
        finally:
            if opened != fd:
                safe_close(opened)
        result["open_opath_directory"] = status("ok")
        before = os.fstat(fd)
        if across:
            namespace = unshare_call(CLONE_NEWNS)
            if namespace["state"] != "ok":
                result["bind_mount_from_proc_fd"] = namespace
                return result
            propagation = mount_call(None, "/", None, MS_REC | MS_PRIVATE)
            if propagation["state"] != "ok":
                result["bind_mount_from_proc_fd"] = propagation
                return result
        after = os.fstat(fd)
        result["fstat_stable"] = (before.st_dev, before.st_ino, before.st_mode) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
        )
        bind = mount_call(f"/proc/self/fd/{fd}", target, None, MS_BIND)
        result["bind_mount_from_proc_fd"] = bind
        if bind["state"] == "ok":
            mounted = True
            target_stat = os.stat(target, follow_symlinks=False)
            result["bind_target_identity_matches"] = stat.S_IFMT(target_stat.st_mode) == stat.S_IFMT(after.st_mode) and (
                target_stat.st_dev,
                target_stat.st_ino,
            ) == (after.st_dev, after.st_ino)
        return result
    except OSError as exc:
        if result["open_opath_directory"]["state"] != "ok":
            result["open_opath_directory"] = from_errno(exc.errno or errno.EIO)
        else:
            result["bind_mount_from_proc_fd"] = from_errno(exc.errno or errno.EIO)
        return result
    finally:
        cleanup = status("ok")
        if mounted:
            cleanup = umount_call(target)
        if fd >= 0 and not safe_close(fd):
            cleanup = status("error", errno.EIO)
        result["cleanup"] = cleanup


def caps_zero() -> bool:
    try:
        with open("/proc/self/status", "rb", buffering=0) as handle:
            data = handle.read(65_537)
    except OSError:
        return False
    if len(data) > 65_536:
        return False
    values: dict[bytes, bytes] = {}
    for line in data.splitlines():
        if b":" in line:
            key, value = line.split(b":", 1)
            if key in {b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"}:
                values[key] = value.strip()
    return len(values) == 5 and all(value and set(value) == {ord("0")} for value in values.values())


def drop_all_caps() -> dict[str, Any]:
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]

    header = Header(0x20080522, 0)
    values = (Data * 2)()
    # Bounding capabilities require CAP_SETPCAP, so remove them before
    # clearing the effective and permitted sets.
    for capability in range(64):
        ctypes.set_errno(0)
        value = PRCTL(PR_CAPBSET_DROP, capability, 0, 0, 0)
        if value == -1 and ctypes.get_errno() not in (errno.EINVAL, errno.EPERM):
            return from_errno(ctypes.get_errno() or errno.EIO)
    ctypes.set_errno(0)
    ambient = PRCTL(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    if ambient == -1 and ctypes.get_errno() not in (errno.EINVAL, errno.EPERM):
        return from_errno(ctypes.get_errno() or errno.EIO)
    ctypes.set_errno(0)
    if CAPSET(ctypes.byref(header), ctypes.byref(values)) == -1:
        return from_errno(ctypes.get_errno() or errno.EIO)
    return status("ok") if caps_zero() else status("mismatch")


def empty_map_case(created: str, zero: bool) -> dict[str, Any]:
    return {
        "proc_mount_created_in": created,
        "capability_sets_zero": zero,
        "maps_read": status("blocked"),
        "executable_mappings_selected": 0,
        "map_files_opened": 0,
        "first_open_failure": None,
        "all_opened_descriptors_closed": True,
    }


def map_files_case(created: str) -> dict[str, Any]:
    result = empty_map_case(created, caps_zero())
    try:
        fd = os.open("/proc/self/maps", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw, overflow = read_bounded(fd, 1024 * 1024)
        finally:
            safe_close(fd)
        lines = raw.splitlines()
        if overflow or len(lines) > 4096:
            result["maps_read"] = status("mismatch")
            return result
        selected: list[str] = []
        for line in lines:
            parts = line.split(None, 5)
            if len(parts) < 5 or b"x" not in parts[1] or parts[4] == b"0":
                continue
            address = parts[0]
            if not re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+", address):
                result["maps_read"] = status("mismatch")
                return result
            selected.append(address.decode("ascii"))
            if len(selected) == 8:
                break
        result["maps_read"] = status("ok")
        result["executable_mappings_selected"] = len(selected)
        for address in selected:
            try:
                mapped = os.open(f"/proc/self/map_files/{address}", os.O_RDONLY | os.O_CLOEXEC)
                try:
                    os.fstat(mapped)
                    result["map_files_opened"] += 1
                finally:
                    if not safe_close(mapped):
                        result["all_opened_descriptors_closed"] = False
            except OSError as exc:
                if result["first_open_failure"] is None:
                    result["first_open_failure"] = from_errno(exc.errno or errno.EIO)
        return result
    except OSError as exc:
        result["maps_read"] = from_errno(exc.errno or errno.EIO)
        return result


def parse_internal_output(command: CommandResult, expected: set[str]) -> dict[str, Any] | None:
    if command.invocation["state"] != "ok" or command.exit_code != 0:
        return None
    try:
        value = json.loads(command.output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) and set(value) == expected else None


def internal_user_case(created: str) -> dict[str, Any]:
    before = map_files_case(created)
    dropped = drop_all_caps()
    after = map_files_case(created)
    return {"before": before, "after": after, "drop": dropped}


def read_id_maps() -> dict[str, Any]:
    result: dict[str, Any] = {
        "uid_map_status": status("blocked"),
        "uid_map": None,
        "gid_map_status": status("blocked"),
        "gid_map": None,
        "setgroups": "unexpected",
    }
    for name in ("uid_map", "gid_map"):
        try:
            with open(f"/proc/self/{name}", "rb", buffering=0) as handle:
                raw = handle.read(4097)
            rows: list[list[int]] = []
            if len(raw) > 4096:
                raise ValueError
            for line in raw.splitlines():
                fields = line.split()
                if len(fields) != 3 or len(rows) == 5:
                    raise ValueError
                row = [int(field, 10) for field in fields]
                if any(value < 0 or value > 0xFFFFFFFF for value in row):
                    raise ValueError
                rows.append(row)
            if not rows:
                raise ValueError
            result[f"{name}_status"] = status("ok")
            result[name] = rows
        except OSError as exc:
            result[f"{name}_status"] = from_errno(exc.errno or errno.EIO)
        except ValueError:
            result[f"{name}_status"] = status("mismatch")
    try:
        with open("/proc/self/setgroups", "rb", buffering=0) as handle:
            raw_setgroups = handle.read(33)
        text = raw_setgroups.strip()
        result["setgroups"] = text.decode("ascii") if text in (b"allow", b"deny") else "unexpected"
    except FileNotFoundError:
        result["setgroups"] = "absent"
    except OSError:
        result["setgroups"] = "unexpected"
    return result


def proc_is_read_only() -> bool | None:
    try:
        return bool(os.statvfs("/proc").f_flag & os.ST_RDONLY)
    except OSError:
        return None


def ns_identity(name: str) -> tuple[int, int] | None:
    try:
        value = os.stat(f"/proc/self/ns/{name}")
        return value.st_dev, value.st_ino
    except OSError:
        return None


def proc_mount_identity() -> tuple[int, int] | None:
    try:
        value = os.stat("/proc")
        return value.st_dev, value.st_ino
    except OSError:
        return None


def basic_namespace(kind: str) -> dict[str, Any]:
    flag = {"network": CLONE_NEWNET, "mount": CLONE_NEWNS}[kind]
    before = ns_identity("net" if kind == "network" else "mnt")
    created = unshare_call(flag)
    distinct: bool | None = None
    if created["state"] == "ok":
        if kind == "mount":
            propagation = mount_call(None, "/", None, MS_REC | MS_PRIVATE)
            if propagation["state"] != "ok":
                created = propagation
        after = ns_identity("net" if kind == "network" else "mnt")
        distinct = before is not None and after is not None and before != after
    return {"create": created, "distinct_from_parent": distinct}


def pid_namespace_case() -> dict[str, Any]:
    created = unshare_call(CLONE_NEWPID)
    result = {"create": created, "child_is_namespace_pid_1": None, "nspid_final_component_is_1": None}
    if created["state"] != "ok":
        return result
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        safe_close(read_fd)
        is_one = os.getpid() == 1
        nspid_one = False
        try:
            with open("/proc/self/status", "rb", buffering=0) as handle:
                raw = handle.read(65_537)
            for line in raw.splitlines():
                if line.startswith(b"NSpid:"):
                    fields = line.split()[1:]
                    nspid_one = bool(fields) and fields[-1] == b"1"
        except OSError:
            pass
        os.write(write_fd, bytes((1 if is_one else 0, 1 if nspid_one else 0)))
        safe_close(write_fd)
        os._exit(0)
    safe_close(write_fd)
    payload = os.read(read_fd, 3)
    safe_close(read_fd)
    _, wait_status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(wait_status) == 0 and len(payload) == 2:
        result["child_is_namespace_pid_1"] = payload[0] == 1
        result["nspid_final_component_is_1"] = payload[1] == 1
    else:
        result["create"] = status("mismatch")
    return result


def sudo_descriptor_case(close_from: int, ledger: Ledger) -> dict[str, Any]:
    helper = (
        "import fcntl,os\n"
        "v=[]\n"
        "for n in (3,4):\n"
        " try: fcntl.fcntl(n,fcntl.F_GETFD);v.append(1)\n"
        " except OSError:v.append(0)\n"
        "os._exit(40+v[0]+2*v[1])\n"
    )
    # A dedicated fork is needed so fds 3 and 4 can be normalized without
    # disturbing the supervisor's own descriptors.
    pid = os.fork()
    ledger.child_count += 1
    ledger.live_children.add(pid)
    if pid == 0:
        os.setsid()
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        for target in (0, 1, 2, 3, 4):
            os.dup2(null, target, inheritable=target in (3, 4))
        if null > 4:
            safe_close(null)
        argv = [SUDO, "-n", f"--close-from={close_from}", "--", PYTHON, "-I", "-c", helper]
        try:
            os.execve(SUDO, argv, {"LC_ALL": "C"})
        except OSError:
            os._exit(127)
    end = time.monotonic() + ledger.remaining(CASE_SECONDS)
    code: int | None = None
    while time.monotonic() < end:
        waited, wait_status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            code = os.waitstatus_to_exitcode(wait_status)
            break
        time.sleep(0.005)
    if code is None:
        try:
            os.killpg(pid, signal.SIGKILL)
            _, wait_status = os.waitpid(pid, 0)
            code = os.waitstatus_to_exitcode(wait_status)
        except OSError:
            ledger.children_reaped = False
        ledger.uncertainty = True
    ledger.live_children.discard(pid)
    decoded = code is not None and 40 <= code <= 43
    present3 = bool((code - 40) & 1) if decoded else None
    present4 = bool((code - 40) & 2) if decoded else None
    if close_from == 3:
        return {
            "invocation": status("ok") if decoded else status("mismatch"),
            "fd3_closed": not present3 if present3 is not None else None,
            "fd4_closed": not present4 if present4 is not None else None,
            "exit_code": code if code is not None and 0 <= code <= 255 else None,
        }
    return {
        "invocation": status("ok") if decoded else status("mismatch"),
        "fd3_preserved": present3,
        "fd4_closed": not present4 if present4 is not None else None,
        "exit_code": code if code is not None and 0 <= code <= 255 else None,
    }


def descriptor_exec_case(ledger: Ledger) -> dict[str, Any]:
    helper = (
        "import fcntl,json,os\n"
        "def p(n):\n"
        " try:fcntl.fcntl(n,fcntl.F_GETFD);return True\n"
        " except OSError:return False\n"
        "os.write(1,json.dumps({'a':p(198),'b':p(199)},sort_keys=True,separators=(',',':')).encode())\n"
    )
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        pid = os.fork()
    except OSError as exc:
        safe_close(read_fd)
        safe_close(write_fd)
        return {"invocation": from_errno(exc.errno or errno.EIO), "non_cloexec_fd_198_survived": None, "cloexec_fd_199_closed": None}
    ledger.child_count += 1
    ledger.live_children.add(pid)
    if pid == 0:
        os.setsid()
        safe_close(read_fd)
        os.dup2(write_fd, 1, inheritable=True)
        if write_fd != 1:
            safe_close(write_fd)
        for target in (198, 199):
            try:
                os.close(target)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    os._exit(122)
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        os.dup2(null, 0, inheritable=False)
        os.dup2(null, 2, inheritable=False)
        for target in (198, 199):
            os.dup2(null, target, inheritable=target == 198)
        if null not in (0, 1, 2, 198, 199):
            safe_close(null)
        try:
            os.execve(PYTHON, [PYTHON, "-I", "-c", helper], {"LC_ALL": "C"})
        except OSError:
            os._exit(127)
    safe_close(write_fd)
    os.set_blocking(read_fd, False)
    end = time.monotonic() + ledger.remaining(CASE_SECONDS)
    data = bytearray()
    code: int | None = None
    while time.monotonic() < end:
        try:
            chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
            if chunk:
                data.extend(chunk)
        except BlockingIOError:
            pass
        waited, wait_status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            code = os.waitstatus_to_exitcode(wait_status)
            break
        time.sleep(0.005)
    if code is None:
        try:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            ledger.children_reaped = False
        ledger.uncertainty = True
    else:
        while len(data) <= MAX_OUTPUT:
            try:
                chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
            except BlockingIOError:
                time.sleep(0.001)
                continue
            if not chunk:
                break
            data.extend(chunk)
    ledger.live_children.discard(pid)
    safe_close(read_fd)
    if code != 0 or len(data) > MAX_OUTPUT:
        invocation = status("error", errno.ETIMEDOUT) if code is None else status("mismatch")
        return {"invocation": invocation, "non_cloexec_fd_198_survived": None, "cloexec_fd_199_closed": None}
    try:
        parsed = json.loads(bytes(data))
        if not isinstance(parsed, dict) or set(parsed) != {"a", "b"} or not all(isinstance(value, bool) for value in parsed.values()):
            raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {"invocation": status("mismatch"), "non_cloexec_fd_198_survived": None, "cloexec_fd_199_closed": None}
    return {
        "invocation": status("ok"),
        "non_cloexec_fd_198_survived": parsed["a"],
        "cloexec_fd_199_closed": not parsed["b"],
    }


def close_range_case(target: int) -> dict[str, Any]:
    result = {
        "syscall_number_amd64": SYS_CLOSE_RANGE,
        "flags": 0,
        "first": target,
        "last": target,
        "invocation": status("blocked"),
        "known_fd_closed": None,
    }
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if target == 4096 and hard != resource.RLIM_INFINITY and hard < 4097:
        return result
    if target == 4096 and soft < 4097:
        resource.setrlimit(resource.RLIMIT_NOFILE, (4097, hard))
    base = duplicate = -1
    try:
        try:
            os.close(target)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        base = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        duplicate = fcntl.fcntl(base, fcntl.F_DUPFD, target)
        if duplicate != target:
            result["invocation"] = status("mismatch")
            return result
        ctypes.set_errno(0)
        err = call_errno(SYSCALL(SYS_CLOSE_RANGE, target, target, 0))
        if err:
            result["invocation"] = from_errno(err)
            return result
        duplicate = -1
        result["invocation"] = status("ok")
        try:
            fcntl.fcntl(target, fcntl.F_GETFD)
            result["known_fd_closed"] = False
        except OSError as exc:
            result["known_fd_closed"] = exc.errno == errno.EBADF
        return result
    except OSError as exc:
        result["invocation"] = from_errno(exc.errno or errno.EIO)
        return result
    finally:
        if base >= 0:
            safe_close(base)
        if duplicate >= 0:
            safe_close(duplicate)


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def prctl_value(option: int) -> tuple[dict[str, Any], int | None]:
    ctypes.set_errno(0)
    value = PRCTL(option, 0, 0, 0, 0)
    if value == -1:
        return from_errno(ctypes.get_errno() or errno.EIO), None
    return status("ok"), int(value)


def seccomp_case() -> dict[str, Any]:
    initial_status, initial_mode = prctl_value(PR_GET_SECCOMP)
    nnp_status, initial_nnp = prctl_value(PR_GET_NO_NEW_PRIVS)
    result = {
        "initial_mode": initial_mode if initial_mode in (0, 1, 2) else 0,
        "initial_no_new_privs": initial_nnp if initial_nnp in (0, 1) else 0,
        "set_no_new_privs": status("blocked"),
        "install_filter": status("blocked"),
        "final_mode": None,
        "network_syscalls_policy": "filter-unavailable",
    }
    if initial_status["state"] != "ok" or nnp_status["state"] != "ok":
        result["set_no_new_privs"] = initial_status if initial_status["state"] != "ok" else nnp_status
        return result
    ctypes.set_errno(0)
    nnp_err = call_errno(PRCTL(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    result["set_no_new_privs"] = from_errno(nnp_err) if nnp_err else status("ok")
    if nnp_err:
        return result
    denied = [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307, 425, 426, 427]
    instructions: list[SockFilter] = [
        SockFilter(0x20, 0, 0, 4),
        SockFilter(0x15, 1, 0, 0xC000003E),
        SockFilter(0x06, 0, 0, 0x80000000),
        SockFilter(0x20, 0, 0, 0),
    ]
    for number in denied:
        instructions.extend((SockFilter(0x15, 0, 1, number), SockFilter(0x06, 0, 0, 0x00050000 | errno.EPERM)))
    instructions.append(SockFilter(0x06, 0, 0, 0x7FFF0000))
    array = (SockFilter * len(instructions))(*instructions)
    program = SockFprog(len(instructions), array)
    ctypes.set_errno(0)
    seccomp_err = call_errno(SYSCALL(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(program)))
    result["install_filter"] = from_errno(seccomp_err) if seccomp_err else status("ok")
    final_status, final_mode = prctl_value(PR_GET_SECCOMP)
    if final_status["state"] == "ok" and final_mode in (0, 1, 2):
        result["final_mode"] = final_mode
    if not seccomp_err and final_mode == 2:
        result["network_syscalls_policy"] = "fixed-eperm-filter-installed"
    elif not seccomp_err:
        result["install_filter"] = status("mismatch")
    return result


def kvm_case() -> dict[str, Any]:
    result = {
        "device_present": False,
        "character_device": None,
        "open_read_write": status("unsupported"),
        "get_api_version": status("blocked"),
        "api_version": None,
        "check_extension_user_memory": status("blocked"),
        "user_memory_extension": None,
    }
    try:
        info = os.lstat(KVM)
    except FileNotFoundError:
        return result
    except OSError as exc:
        result["device_present"] = exc.errno not in (errno.ENOENT, errno.ENOTDIR)
        result["open_read_write"] = from_errno(exc.errno or errno.EIO)
        return result
    result["device_present"] = True
    result["character_device"] = stat.S_ISCHR(info.st_mode)
    if not result["character_device"]:
        result["open_read_write"] = status("mismatch")
        return result
    try:
        fd = os.open(KVM, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        result["open_read_write"] = from_errno(exc.errno or errno.EIO)
        return result
    result["open_read_write"] = status("ok")
    try:
        try:
            version = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
            if 0 <= version <= 255:
                result["get_api_version"] = status("ok")
                result["api_version"] = version
            else:
                result["get_api_version"] = status("mismatch")
        except OSError as exc:
            result["get_api_version"] = from_errno(exc.errno or errno.EIO)
        try:
            extension = fcntl.ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY)
            if 0 <= extension <= 0x7FFFFFFF:
                result["check_extension_user_memory"] = status("ok")
                result["user_memory_extension"] = extension
            else:
                result["check_extension_user_memory"] = status("mismatch")
        except OSError as exc:
            result["check_extension_user_memory"] = from_errno(exc.errno or errno.EIO)
    finally:
        safe_close(fd)
    return result


def limit_value(value: int) -> int | str:
    return "infinity" if value == resource.RLIM_INFINITY else min(max(int(value), 0), 2**63 - 1)


def validated_env(name: str, pattern: re.Pattern[str]) -> str | None:
    value = os.environ.get(name)
    return value if value is not None and pattern.fullmatch(value) else None


def source_metadata() -> tuple[dict[str, Any], bool]:
    repository = validated_env("GITHUB_REPOSITORY", re.compile(r"nenb/cogs"))
    head = validated_env("GITHUB_SHA", re.compile(r"[0-9a-f]{40}"))
    workflow = validated_env("COGS_RUNNER_CAPABILITY_WORKFLOW_SHA256", re.compile(r"[0-9a-f]{64}"))
    run_id = validated_env("GITHUB_RUN_ID", re.compile(r"0|[1-9][0-9]{0,19}"))
    attempt_text = validated_env("GITHUB_RUN_ATTEMPT", re.compile(r"[1-9][0-9]{0,2}"))
    attempt = int(attempt_text) if attempt_text is not None else 1
    valid = repository is not None and head is not None and workflow is not None and run_id is not None and attempt <= 255
    return {
        "repository": "nenb/cogs",
        "head_sha": head or "0" * 40,
        "workflow_sha256": workflow or "0" * 64,
        "run_id": run_id or "0",
        "run_attempt": attempt if attempt <= 255 else 1,
    }, valid


def runner_metadata() -> dict[str, Any]:
    image_os = validated_env("ImageOS", re.compile(r"[a-z0-9.-]{1,32}"))
    image_version = validated_env("ImageVersion", re.compile(r"[A-Za-z0-9._-]{1,64}"))
    arch = validated_env("RUNNER_ARCH", re.compile(r"X64"))
    environment = validated_env("RUNNER_ENVIRONMENT", re.compile(r"github-hosted"))
    complete = image_os is not None and image_version is not None and arch is not None and environment is not None
    return {
        "requested_label": "ubuntu-24.04",
        "environment": environment or "unexpected",
        "image_os": image_os,
        "image_version": image_version,
        "runner_arch": arch or "unexpected",
        "image_metadata_status": status("ok") if complete else status("unsupported"),
    }


def create_private_parent(ledger: Ledger) -> bool:
    global PRIVATE_PARENT_OWNED
    try:
        os.mkdir(PRIVATE_PARENT, 0o700)
        PRIVATE_PARENT_OWNED = True
        for name in ("runner-temp", "private-tmpfs", "opath-root", "proc"):
            os.mkdir(f"{PRIVATE_PARENT}/{name}", 0o700)
        return True
    except OSError:
        if PRIVATE_PARENT_OWNED:
            cleanup_private_parent(ledger)
        else:
            ledger.temporary_names_gone = False
        ledger.uncertainty = True
        return False


def cleanup_private_parent(ledger: Ledger) -> None:
    global PRIVATE_PARENT_OWNED
    if not PRIVATE_PARENT_OWNED:
        return
    for name in ("proc", "opath-root", "private-tmpfs", "runner-temp"):
        try:
            os.rmdir(f"{PRIVATE_PARENT}/{name}")
        except FileNotFoundError:
            pass
        except OSError:
            ledger.temporary_names_gone = False
            ledger.uncertainty = True
    try:
        os.rmdir(PRIVATE_PARENT)
    except FileNotFoundError:
        pass
    except OSError:
        ledger.temporary_names_gone = False
        ledger.uncertainty = True
    else:
        PRIVATE_PARENT_OWNED = False


def user_namespace_invocation(ledger: Ledger, combined: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not os.path.isfile(UNSHARE) or not os.path.isfile(PYTHON):
        return status("unsupported"), None
    argv = [UNSHARE, "--user", "--map-user=0", "--map-group=0"]
    if combined:
        argv.extend(("--mount", "--pid", "--fork", f"--mount-proc={PRIVATE_PARENT}/proc"))
        created = "child-userns"
    else:
        created = "parent-userns"
    argv.extend((PYTHON, "-I", os.path.realpath(__file__), "--_internal-user", created))
    command = ledger.run(argv, NS_SECONDS)
    parsed = parse_internal_output(command, {"maps", "ids", "pid_one", "proc_read_only", "proc_ns"})
    return (command.invocation if parsed is None else status("ok")), parsed


def sudo_noninteractive_and_maps(ledger: Ledger) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not os.path.isfile(SUDO):
        return status("unsupported"), None
    command = ledger.run([SUDO, "-n", "--", PYTHON, "-I", os.path.realpath(__file__), "--_internal-sudo"])
    parsed = parse_internal_output(command, {"map"})
    return (command.invocation if parsed is None else status("ok")), parsed


def probe_linux() -> dict[str, Any]:
    global ACTIVE_LEDGER
    ledger = Ledger(time.monotonic() + GLOBAL_SECONDS)
    ACTIVE_LEDGER = ledger
    source, source_valid = source_metadata()
    uname = os.uname()
    release_ok = bool(re.fullmatch(r"[ -~]{1,128}", uname.release))
    linux_amd64 = uname.sysname == "Linux" and uname.machine == "x86_64"
    kernel = {
        "sysname": "Linux" if uname.sysname == "Linux" else "unexpected",
        "release": uname.release if release_ok else "unexpected",
        "machine": "x86_64" if uname.machine == "x86_64" else "unexpected",
        "uname_status": status("ok") if linux_amd64 and release_ok else status("mismatch"),
    }
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    identities = {
        "python3": fixed_identity(PYTHON, ["--version"], re.compile(r"Python [0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[ -~]*)"), ledger),
        "gzip": fixed_identity(GZIP, ["--version"], re.compile(r"gzip \(GNU gzip\) [ -~]+"), ledger),
        "zstd": fixed_identity(ZSTD, ["--version"], re.compile(r"\*\*\* (?:Zstandard CLI|zstd command line interface) [ -~]+"), ledger),
        "unshare": fixed_identity(UNSHARE, ["--version"], re.compile(r"unshare from util-linux [ -~]+"), ledger),
    }
    sudo_identity = fixed_identity(SUDO, ["--version"], re.compile(r"Sudo version [ -~]+"), ledger)
    private_ready = create_private_parent(ledger)
    runner_tmp = tmpfile_case(f"{PRIVATE_PARENT}/runner-temp") if private_ready else empty_tmpfile_case(blocked=True)
    if private_ready:
        mount_status, mount_batch = ledger.fork_case(mount_namespace_batch, NS_SECONDS)
        mount_payload = mount_batch["private"] if mount_batch else None
        mount_ns = mount_batch["namespace"] if mount_batch else None
    else:
        mount_status, mount_payload, mount_ns = status("blocked"), None, None
    if mount_payload is None:
        private_tmp = empty_tmpfile_case(blocked=True)
        private_tmp["open_otmpfile"] = mount_status
        same_opath = empty_opath_case(True)
        across_opath = empty_opath_case(True)
        same_opath["open_opath_directory"] = mount_status
        across_opath["open_opath_directory"] = mount_status
    else:
        private_tmp = mount_payload["private_tmpfs"]
        same_opath = mount_payload["same"]
        across_opath = mount_payload["across"]
        if not mount_payload["mounts_gone"]:
            ledger.mounts_gone = False
            ledger.uncertainty = True
    exec_case = descriptor_exec_case(ledger)
    close_status, close_payload = ledger.fork_case(lambda: {"low": close_range_case(198), "high": close_range_case(4096)})
    if close_payload is None:
        low = close_range_case_shape(198, close_status)
        high = close_range_case_shape(4096, close_status)
    else:
        low, high = close_payload["low"], close_payload["high"]
    network_status, network = ledger.fork_case(lambda: basic_namespace("network"))
    pid_status, pid_ns = ledger.fork_case(pid_namespace_case, NS_SECONDS)
    network = network or {"create": network_status, "distinct_from_parent": None}
    mount_ns = mount_ns or {"create": mount_status, "distinct_from_parent": None}
    pid_ns = pid_ns or {"create": pid_status, "child_is_namespace_pid_1": None, "nspid_final_component_is_1": None}
    host_map = map_files_case("host")
    sudo_noninteractive, sudo_payload = sudo_noninteractive_and_maps(ledger)
    sudo_map = sudo_payload["map"] if sudo_payload else empty_map_case("host", False)
    if sudo_payload is None:
        sudo_map["maps_read"] = sudo_noninteractive
    user_create, user_payload = user_namespace_invocation(ledger, False) if private_ready else (status("blocked"), None)
    combined_create, combined_payload = user_namespace_invocation(ledger, True) if private_ready else (status("blocked"), None)
    if user_payload:
        user_maps = user_payload["maps"]
        ids = user_payload["ids"]
    else:
        user_maps = {"before": empty_map_case("parent-userns", False), "after": empty_map_case("parent-userns", True), "drop": status("blocked")}
        user_maps["before"]["maps_read"] = user_create
        user_maps["after"]["maps_read"] = status("blocked")
        ids = {"uid_map_status": user_create, "uid_map": None, "gid_map_status": user_create, "gid_map": None, "setgroups": "unexpected"}
    if combined_payload:
        child_maps = combined_payload["maps"]
    else:
        child_maps = {"before": empty_map_case("child-userns", False), "after": empty_map_case("child-userns", True), "drop": status("blocked")}
        child_maps["before"]["maps_read"] = combined_create
        child_maps["after"]["maps_read"] = status("blocked")
    seccomp_status, seccomp_payload = ledger.fork_case(seccomp_case)
    seccomp_result = seccomp_payload or {
        "initial_mode": 0,
        "initial_no_new_privs": 0,
        "set_no_new_privs": seccomp_status,
        "install_filter": status("blocked"),
        "final_mode": None,
        "network_syscalls_policy": "filter-unavailable",
    }
    close3 = sudo_descriptor_case(3, ledger) if sudo_identity["present"] else empty_sudo_close(3)
    close4 = sudo_descriptor_case(4, ledger) if sudo_identity["present"] else empty_sudo_close(4)
    cleanup_cases = (runner_tmp, private_tmp, same_opath, across_opath)
    if any(case["cleanup"]["state"] != "ok" for case in cleanup_cases):
        ledger.uncertainty = True
    all_map_cases = (host_map, sudo_map, user_maps["before"], user_maps["after"], child_maps["before"], child_maps["after"])
    if any(not case["all_opened_descriptors_closed"] for case in all_map_cases):
        ledger.descriptors_restored = False
        ledger.uncertainty = True
    cleanup_private_parent(ledger)
    cleanup = {
        "children_reaped": ledger.children_reaped and not ledger.live_children,
        "descriptors_restored": ledger.descriptors_restored,
        "mounts_gone": ledger.mounts_gone,
        "temporary_names_gone": ledger.temporary_names_gone,
        "namespace_handles_retained": False,
        "uncertainty": ledger.uncertainty,
    }
    runner = runner_metadata()
    complete = linux_amd64 and source_valid and runner["image_metadata_status"]["state"] == "ok" and all(cleanup[key] for key in ("children_reaped", "descriptors_restored", "mounts_gone", "temporary_names_gone")) and not cleanup["uncertainty"]
    parent_proc_ns = proc_mount_identity()
    child_proc_ns = combined_payload.get("proc_ns") if combined_payload else None
    report = {
        "schema": SCHEMA,
        "authority": "none",
        "qualified": False,
        "outcome": "complete" if complete else "incomplete",
        "source": source,
        "runner": runner,
        "kernel": kernel,
        "rlimit_nofile": {"soft": limit_value(soft), "hard": limit_value(hard), "high_fd_4096_possible": hard == resource.RLIM_INFINITY or hard >= 4097},
        "sudo": {"executable": sudo_identity, "noninteractive": sudo_noninteractive, "close_from_3": close3, "close_from_4": close4},
        "descriptors": {"exec_cloexec": exec_case, "close_range_low": low, "close_range_high": high, "inherited_baseline_restored": ledger.descriptors_restored},
        "temporary_files": {"runner_temp": runner_tmp, "private_tmpfs": private_tmp},
        "opath": {"same_mount_namespace": same_opath, "across_mount_namespace": across_opath},
        "namespaces": {
            "network": network,
            "mount": mount_ns,
            "pid": pid_ns,
            "user_direct_root": {"create": user_create, **ids},
            "combined_user_mount_pid_fork": {
                "create": combined_create,
                "child_is_namespace_pid_1": combined_payload.get("pid_one") if combined_payload else None,
                "proc_mount": combined_payload["maps"]["before"]["maps_read"] if combined_payload else status("blocked"),
                "cleanup": status("ok") if combined_payload else status("blocked"),
            },
        },
        "procfs": {
            "host_runner": host_map,
            "host_sudo_root": sudo_map,
            "child_userns_parent_proc_before_cap_drop": user_maps["before"],
            "child_userns_parent_proc_after_cap_drop": user_maps["after"],
            "child_owned_proc_before_cap_drop": child_maps["before"],
            "child_owned_proc_after_cap_drop": child_maps["after"],
            "parent_proc_read_only": proc_is_read_only(),
            "child_proc_read_only": combined_payload.get("proc_read_only") if combined_payload else None,
            "child_proc_distinct_from_parent": child_proc_ns is not None and parent_proc_ns is not None and tuple(child_proc_ns) != parent_proc_ns,
            "child_proc_view_has_pid_1": combined_payload.get("pid_one") if combined_payload else None,
        },
        "seccomp": seccomp_result,
        "kvm": kvm_case(),
        "tools": identities,
        "cleanup": cleanup,
    }
    ACTIVE_LEDGER = None
    return report


def close_range_case_shape(target: int, invocation: dict[str, Any]) -> dict[str, Any]:
    return {"syscall_number_amd64": SYS_CLOSE_RANGE, "flags": 0, "first": target, "last": target, "invocation": invocation, "known_fd_closed": None}


def empty_sudo_close(close_from: int) -> dict[str, Any]:
    if close_from == 3:
        return {"invocation": status("unsupported"), "fd3_closed": None, "fd4_closed": None, "exit_code": None}
    return {"invocation": status("unsupported"), "fd3_preserved": None, "fd4_closed": None, "exit_code": None}


class DeterministicFakeBackend:
    """Pure in-memory backend used only by the portable self-test."""

    def __init__(self, inject_cleanup_failure: bool = False, inject_timeout: bool = False) -> None:
        self.inject_cleanup_failure = inject_cleanup_failure
        self.inject_timeout = inject_timeout

    def report(self) -> dict[str, Any]:
        report = fake_report(self.inject_cleanup_failure or self.inject_timeout)
        if self.inject_timeout:
            report["kvm"]["open_read_write"] = status("error", errno.ETIMEDOUT)
        return report


def fake_report(inject_cleanup_failure: bool = False) -> dict[str, Any]:
    ok = status("ok")
    tool = lambda path: {
        "path": path,
        "present": True,
        "regular_file": True,
        "root_owned": True,
        "mode": "0755",
        "size": 1,
        "sha256": "1" * 64,
        "version_line": "fixed 1.0",
        "version_output_sha256": "2" * 64,
        "observation": status("ok"),
    }
    tmp = {"filesystem": "tmpfs", "open_otmpfile": status("ok"), "initial_nlink_zero": True, "owner_is_probe_identity": True, "initial_mode_0600": True, "linkat_empty_path": status("ok"), "linked_identity_matches": True, "cleanup": status("ok")}
    opath = {"open_opath_directory": status("ok"), "fstat_stable": True, "bind_mount_from_proc_fd": status("denied", errno.EPERM), "bind_target_identity_matches": None, "cleanup": status("ok")}
    mapping = {"proc_mount_created_in": "host", "capability_sets_zero": True, "maps_read": status("ok"), "executable_mappings_selected": 1, "map_files_opened": 1, "first_open_failure": None, "all_opened_descriptors_closed": True}
    cleanup = {"children_reaped": True, "descriptors_restored": True, "mounts_gone": True, "temporary_names_gone": not inject_cleanup_failure, "namespace_handles_retained": False, "uncertainty": inject_cleanup_failure}
    report = {
        "schema": SCHEMA, "authority": "none", "qualified": False, "outcome": "incomplete" if inject_cleanup_failure else "complete",
        "source": {"repository": "nenb/cogs", "head_sha": "0" * 40, "workflow_sha256": "1" * 64, "run_id": "1", "run_attempt": 1},
        "runner": {"requested_label": "ubuntu-24.04", "environment": "github-hosted", "image_os": "ubuntu24", "image_version": "fixed", "runner_arch": "X64", "image_metadata_status": status("ok")},
        "kernel": {"sysname": "Linux", "release": "fixed", "machine": "x86_64", "uname_status": status("ok")},
        "rlimit_nofile": {"soft": 1024, "hard": 8192, "high_fd_4096_possible": True},
        "sudo": {"executable": tool(SUDO), "noninteractive": status("ok"), "close_from_3": {"invocation": ok, "fd3_closed": True, "fd4_closed": True, "exit_code": 40}, "close_from_4": {"invocation": ok, "fd3_preserved": True, "fd4_closed": True, "exit_code": 41}},
        "descriptors": {"exec_cloexec": {"invocation": ok, "non_cloexec_fd_198_survived": True, "cloexec_fd_199_closed": True}, "close_range_low": close_range_case_shape(198, ok), "close_range_high": close_range_case_shape(4096, ok), "inherited_baseline_restored": True},
        "temporary_files": {"runner_temp": tmp, "private_tmpfs": tmp}, "opath": {"same_mount_namespace": opath, "across_mount_namespace": opath},
        "namespaces": {"network": {"create": ok, "distinct_from_parent": True}, "mount": {"create": ok, "distinct_from_parent": True}, "pid": {"create": ok, "child_is_namespace_pid_1": True, "nspid_final_component_is_1": True}, "user_direct_root": {"create": ok, "uid_map_status": ok, "uid_map": [[0, 1000, 1]], "gid_map_status": ok, "gid_map": [[0, 1000, 1]], "setgroups": "deny"}, "combined_user_mount_pid_fork": {"create": ok, "child_is_namespace_pid_1": True, "proc_mount": ok, "cleanup": ok}},
        "procfs": {"host_runner": mapping, "host_sudo_root": mapping, "child_userns_parent_proc_before_cap_drop": mapping, "child_userns_parent_proc_after_cap_drop": mapping, "child_owned_proc_before_cap_drop": mapping, "child_owned_proc_after_cap_drop": mapping, "parent_proc_read_only": True, "child_proc_read_only": True, "child_proc_distinct_from_parent": True, "child_proc_view_has_pid_1": True},
        "seccomp": {"initial_mode": 2, "initial_no_new_privs": 0, "set_no_new_privs": ok, "install_filter": ok, "final_mode": 2, "network_syscalls_policy": "fixed-eperm-filter-installed"},
        "kvm": {"device_present": False, "character_device": None, "open_read_write": status("unsupported"), "get_api_version": status("blocked"), "api_version": None, "check_extension_user_memory": status("blocked"), "user_memory_extension": None},
        "tools": {"python3": tool(PYTHON), "gzip": tool(GZIP), "zstd": tool(ZSTD), "unshare": tool(UNSHARE)}, "cleanup": cleanup,
    }
    return report


def self_test() -> None:
    first = canonical_bytes(DeterministicFakeBackend().report())
    second = canonical_bytes(DeterministicFakeBackend().report())
    assert first == second and first.endswith(b"\n") and first.count(b"\n") == 1
    assert json.loads(first)["authority"] == "none" and json.loads(first)["qualified"] is False
    failed = DeterministicFakeBackend(inject_cleanup_failure=True).report()
    timed_out = DeterministicFakeBackend(inject_timeout=True).report()
    assert canonical_bytes(failed) != first
    assert json.loads(canonical_bytes(failed))["outcome"] == "incomplete"
    assert timed_out["kvm"]["open_read_write"] == status("error", errno.ETIMEDOUT)
    assert timed_out["cleanup"]["uncertainty"] is True
    assert from_errno(errno.ENOSYS) == status("unsupported", errno.ENOSYS)
    assert from_errno(errno.EPERM) == status("denied", errno.EPERM)
    assert from_errno(errno.EIO) == status("error", errno.EIO)
    try:
        canonical_bytes({"bad": 1.5})
        raise AssertionError("float accepted")
    except ValueError:
        pass

    approved_paths = {PYTHON, SUDO, UNSHARE, GZIP, ZSTD}

    def validate_fake(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) == {"state", "errno"}:
                assert value["state"] in {"ok", "unsupported", "denied", "blocked", "mismatch", "error"}
                assert value["errno"] is None or 1 <= value["errno"] <= 4095
            for child in value.values():
                validate_fake(child)
        elif isinstance(value, list):
            for child in value:
                validate_fake(child)
        elif isinstance(value, str) and value.startswith("/"):
            assert value in approved_paths

    validate_fake(json.loads(first))
    # The fake path is intentionally independent of libc calls, subprocesses,
    # files, privileges, the environment, and the host clock.
    sys.stdout.write("runner-capability-probe self-test: ok\n")


def internal_main(arguments: list[str]) -> bool:
    if arguments == ["--_internal-sudo"]:
        sys.stdout.buffer.write(canonical_bytes({"map": map_files_case("host")}))
        return True
    if len(arguments) == 2 and arguments[0] == "--_internal-user" and arguments[1] in ("parent-userns", "child-userns"):
        created = arguments[1]
        proc_identity = proc_mount_identity()
        value = {
            "maps": internal_user_case(created),
            "ids": read_id_maps(),
            "pid_one": os.getpid() == 1,
            "proc_read_only": proc_is_read_only(),
            "proc_ns": list(proc_identity) if proc_identity is not None else None,
        }
        sys.stdout.buffer.write(canonical_bytes(value))
        return True
    return False


def _interrupt(_signum: int, _frame: Any) -> None:
    raise InterruptedError


def main() -> int:
    global ACTIVE_LEDGER
    arguments = sys.argv[1:]
    if internal_main(arguments):
        return 0
    if arguments == ["--self-test"]:
        self_test()
        return 0
    if arguments:
        return 2
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        if not sys.platform.startswith("linux"):
            report = fake_report(True)
            report["kernel"] = {"sysname": "unexpected", "release": "unexpected", "machine": "unexpected", "uname_status": status("unsupported")}
        else:
            report = probe_linux()
        output = canonical_bytes(report)
    except BaseException:
        if ACTIVE_LEDGER is not None:
            ACTIVE_LEDGER.abort()
            cleanup_private_parent(ACTIVE_LEDGER)
            ACTIVE_LEDGER = None
        report = fake_report(True)
        report["source"], _ = source_metadata()
        output = canonical_bytes(report)
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0 if report["outcome"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
