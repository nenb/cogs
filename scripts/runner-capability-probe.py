#!/usr/bin/python3
"""Bounded, metadata-only, non-authoritative runner capability observation."""
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
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
AT_EMPTY_PATH = 0x1000
O_PATH = getattr(os, "O_PATH", 0o10000000)
O_TMPFILE = getattr(os, "O_TMPFILE", 0o20000000)
SYS_CLOSE_RANGE = 436
SYS_SECCOMP = 317
SECCOMP_SET_MODE_FILTER = 1
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_GET_SECCOMP = 21
KVM_GET_API_VERSION = 0xAE00
KVM_CHECK_EXTENSION = 0xAE03
KVM_CAP_USER_MEMORY = 3
libc = ctypes.CDLL(None, use_errno=True)
PRIVATE_PARENT_OWNED = False
ACTIVE_LEDGER: Ledger | None = None
FIXED_CHILD_FILTER = 'import ctypes,os\nclass F(ctypes.Structure):_fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint32)]\nclass P(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(F))]\nc=ctypes.CDLL(None,use_errno=True);deny=(41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,288,299,307,425,426,427);r=[F(0x20,0,0,4),F(0x15,1,0,0xc000003e),F(0x06,0,0,0x80000000),F(0x20,0,0,0)]\nfor n in deny:r.extend((F(0x15,0,1,n),F(0x06,0,0,0x50001)))\nr.append(F(0x06,0,0,0x7fff0000));a=(F*len(r))(*r);p=P(len(r),a)\nif c.prctl(38,1,0,0,0) or c.syscall(317,1,0,ctypes.byref(p))==-1:os._exit(119)\n'
def _missing_libc(*_arguments: Any) -> int: ctypes.set_errno(errno.ENOSYS); return -1
def _libc_function(name: str) -> Any: return getattr(libc, name, _missing_libc)
MOUNT = _libc_function("mount")
UMOUNT2 = _libc_function("umount2")
UNSHARE_CALL = _libc_function("unshare")
PRCTL = _libc_function("prctl")
SYSCALL = _libc_function("syscall")
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
    return status("error", err if 1 <= err <= 4095 else errno.EIO)
def call_errno(result: int) -> int:
    value = ctypes.get_errno()
    return 0 if result != -1 else value or errno.EIO
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
@dataclass
class CommandResult:
    invocation: dict[str, Any]
    exit_code: int | None
    record: bytes
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
    state: str = "NEW"
    def transition(self, next_state: str) -> None:
        allowed = {"NEW": {"BASELINED"}, "BASELINED": {"RUNNING"}, "RUNNING": {"CLEANING", "POISONED"}, "CLEANING": {"COMPLETE", "POISONED"}, "POISONED": {"FAILED"}}
        if next_state not in allowed.get(self.state, set()): raise RuntimeError("invalid supervisor transition")
        self.state = next_state
    def remaining(self, wanted: float) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            self.uncertainty = True
            return 0.001
        return min(wanted, left)
    def run(
        self,
        argv: tuple[str, ...],
        seconds: float = CASE_SECONDS,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        """Run one fixed child with empty environment and fully captured output."""
        if self.child_count >= 24:
            self.uncertainty = True
            return CommandResult(status("blocked"), None, b"")
        if not argv or any(not item or "\x00" in item for item in argv) or not argv[0].startswith("/usr/bin/"):
            raise ValueError("non-fixed child command")
        try:
            process = subprocess.Popen(
                argv,
                executable=argv[0],
                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                env={},
                start_new_session=True,
            )
        except OSError as exc:
            return CommandResult(from_errno(exc.errno or errno.EIO), None, b"")
        if process.stdin is not None:
            try:
                process.stdin.write(input_bytes)
                process.stdin.close()
            except OSError:
                process.stdin.close()
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
        if self.state in {"RUNNING", "CLEANING"}: self.transition("POISONED")
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
        if self.state == "POISONED": self.transition("FAILED")
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
def generation(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
def resolve_fixed_tool(path: str) -> tuple[int, tuple[tuple[int, ...], ...]]:
    """Resolve an approved logical path through a bounded, held symlink chain."""
    if path not in {PYTHON, SUDO, UNSHARE, GZIP, ZSTD}:
        raise ValueError("unapproved logical tool")
    pending = path[1:].split("/")
    directories = [os.open("/", O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)]
    held: list[int] = []
    chain: list[tuple[int, ...]] = [generation(os.fstat(directories[0]))]
    links = 0
    try:
        while pending:
            component = pending.pop(0)
            if component in ("", "."):
                continue
            if component == "..":
                if len(directories) == 1:
                    raise OSError(errno.EPERM, "chain escapes root")
                safe_close(directories.pop())
                continue
            probe = os.open(component, O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directories[-1])
            info = os.fstat(probe)
            if info.st_uid != 0:
                safe_close(probe)
                raise OSError(errno.EPERM, "non-root chain component")
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 16:
                    safe_close(probe)
                    raise OSError(errno.ELOOP, "symlink bound")
                target = os.readlink(component, dir_fd=directories[-1])
                held.append(probe)
                chain.append(generation(info))
                parts = target.split("/")
                if target.startswith("/"):
                    while len(directories) > 1:
                        safe_close(directories.pop())
                pending = parts + pending
                if len(pending) > 64:
                    raise OSError(errno.ELOOP, "component bound")
                continue
            if stat.S_IMODE(info.st_mode) & 0o022:
                safe_close(probe)
                raise OSError(errno.EPERM, "writable chain component")
            if pending:
                if not stat.S_ISDIR(info.st_mode):
                    safe_close(probe)
                    raise OSError(errno.ENOTDIR, "non-directory component")
                directories.append(probe)
                chain.append(generation(info))
                continue
            safe_close(probe)
            final_fd = os.open(component, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directories[-1])
            return final_fd, tuple(chain)
        raise OSError(errno.ENOENT, "empty tool path")
    finally:
        for descriptor in reversed(held):
            safe_close(descriptor)
        for descriptor in reversed(directories):
            safe_close(descriptor)
def fixed_identity(path: str, ledger: Ledger) -> dict[str, Any]:
    result = {
        "path": path,
        "present": False,
        "regular_file": None,
        "root_owned": None,
        "mode": None,
        "size": None,
        "sha256": None,
        "observation": status("unsupported"),
    }
    try:
        fd, chain_before = resolve_fixed_tool(path)
    except FileNotFoundError:
        return result
    except OSError as exc:
        result["present"] = exc.errno not in (errno.ENOENT, errno.ENOTDIR)
        result["observation"] = from_errno(exc.errno or errno.EIO)
        return result
    result["present"] = True
    try:
        before = os.fstat(fd)
        result["regular_file"] = stat.S_ISREG(before.st_mode)
        result["root_owned"] = before.st_uid == 0
        result["mode"] = format(stat.S_IMODE(before.st_mode), "04o")
        policy = stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not stat.S_IMODE(before.st_mode) & 0o022
        if not policy or not (1 <= before.st_size <= MAX_TOOL):
            result["observation"] = status("mismatch")
            return result
        result["size"] = before.st_size
        if ledger.tool_bytes_read + before.st_size > MAX_TOOL_AGGREGATE:
            result["observation"] = status("blocked")
            return result
        ledger.tool_bytes_read += before.st_size
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                result["observation"] = status("mismatch")
                return result
            digest.update(chunk)
            remaining -= len(chunk)
        after_read = os.fstat(fd)
        result["sha256"] = digest.hexdigest()
        replacement, chain_after = resolve_fixed_tool(path)
        try:
            after_path = os.fstat(replacement)
        finally:
            safe_close(replacement)
        if generation(before) != generation(after_read) or generation(before) != generation(after_path) or chain_before != chain_after:
            result["observation"] = status("mismatch")
        else:
            result["observation"] = status("ok")
        return result
    except OSError as exc:
        result["observation"] = from_errno(exc.errno or errno.EIO)
        return result
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
        if not all((result["initial_nlink_zero"], result["owner_is_probe_identity"], result["initial_mode_0600"])):
            result["open_otmpfile"] = status("mismatch")
            return result
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
        if not result["linked_identity_matches"]:
            result["linkat_empty_path"] = status("mismatch")
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
        if not result["fstat_stable"]:
            result["open_opath_directory"] = status("mismatch")
            return result
        bind = mount_call(f"/proc/self/fd/{fd}", target, None, MS_BIND)
        result["bind_mount_from_proc_fd"] = bind
        if bind["state"] == "ok":
            mounted = True
            target_stat = os.stat(target, follow_symlinks=False)
            result["bind_target_identity_matches"] = stat.S_IFMT(target_stat.st_mode) == stat.S_IFMT(after.st_mode) and (
                target_stat.st_dev,
                target_stat.st_ino,
            ) == (after.st_dev, after.st_ino)
            if not result["bind_target_identity_matches"]:
                result["bind_mount_from_proc_fd"] = status("mismatch")
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
FIXED_CASE_HELPER = 'import ctypes,errno,fcntl,json,os,re,sys\nclass F(ctypes.Structure):_fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint32)]\nclass P(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(F))]\ndef s(state,number=None):return {"state":state,"errno":number}\ndef e(number):\n return s("unsupported",number) if number in (38,95) else s("denied",number) if number in (1,13) else s("error",number)\ndef filter_now():\n c=ctypes.CDLL(None,use_errno=True)\n if c.prctl(38,1,0,0,0):return e(ctypes.get_errno() or 5)\n deny=(41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,288,299,307,425,426,427)\n rows=[F(0x20,0,0,4),F(0x15,1,0,0xc000003e),F(0x06,0,0,0x80000000),F(0x20,0,0,0)]\n for n in deny:rows.extend((F(0x15,0,1,n),F(0x06,0,0,0x50000|1)))\n rows.append(F(0x06,0,0,0x7fff0000));a=(F*len(rows))(*rows);p=P(len(rows),a)\n if c.syscall(317,1,0,ctypes.byref(p))==-1:return e(ctypes.get_errno() or 5)\n return s("ok")\ndef zero():\n try:\n  data=open("/proc/self/status","rb",buffering=0).read(65537)\n except OSError:return False\n found={}\n for line in data.splitlines():\n  if b":" in line:\n   k,v=line.split(b":",1)\n   if k in (b"CapInh",b"CapPrm",b"CapEff",b"CapBnd",b"CapAmb"):found[k]=v.strip()\n return len(data)<=65536 and len(found)==5 and all(v and set(v)=={48} for v in found.values())\ndef maps(created):\n out={"proc_mount_created_in":created,"capability_sets_zero":zero(),"maps_read":s("blocked"),"executable_mappings_selected":0,"map_files_opened":0,"first_open_failure":None,"all_opened_descriptors_closed":True}\n try:\n  raw=open("/proc/self/maps","rb",buffering=0).read(1048577);lines=raw.splitlines()\n  if len(raw)>1048576 or len(lines)>4096:out["maps_read"]=s("mismatch");return out\n  selected=[]\n  for line in lines:\n   p=line.split(None,5)\n   if len(p)>=5 and b"x" in p[1] and p[4]!=b"0":\n    if not re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+",p[0]):out["maps_read"]=s("mismatch");return out\n    selected.append(p[0])\n    if len(selected)==8:break\n  out["maps_read"]=s("ok");out["executable_mappings_selected"]=len(selected)\n  for address in selected:\n   try:\n    fd=os.open(b"/proc/self/map_files/"+address,os.O_RDONLY|os.O_CLOEXEC);os.fstat(fd);os.close(fd);out["map_files_opened"]+=1\n   except OSError as x:\n    if out["first_open_failure"] is None:out["first_open_failure"]=e(x.errno or 5)\n  return out\n except OSError as x:out["maps_read"]=e(x.errno or 5);return out\ndef drop():\n c=ctypes.CDLL(None,use_errno=True)\n class H(ctypes.Structure):_fields_=[("version",ctypes.c_uint32),("pid",ctypes.c_int)]\n class D(ctypes.Structure):_fields_=[("effective",ctypes.c_uint32),("permitted",ctypes.c_uint32),("inheritable",ctypes.c_uint32)]\n for n in range(64):c.prctl(24,n,0,0,0)\n c.prctl(47,4,0,0,0)\n if c.capset(ctypes.byref(H(0x20080522,0)),ctypes.byref((D*2)())):return e(ctypes.get_errno() or 5)\n return s("ok") if zero() else s("mismatch")\ndef ids():\n out={"uid_map_status":s("blocked"),"uid_map":None,"gid_map_status":s("blocked"),"gid_map":None,"setgroups":"unexpected"}\n for name in ("uid_map","gid_map"):\n  try:\n   raw=open("/proc/self/"+name,"rb",buffering=0).read(4097);rows=[]\n   for line in raw.splitlines():\n    row=[int(v) for v in line.split()]\n    if len(row)!=3 or len(rows)==5 or any(v<0 or v>4294967295 for v in row):raise ValueError\n    rows.append(row)\n   if len(raw)>4096 or not rows:raise ValueError\n   out[name+"_status"]=s("ok");out[name]=rows\n  except OSError as x:out[name+"_status"]=e(x.errno or 5)\n  except ValueError:out[name+"_status"]=s("mismatch")\n try:\n  text=open("/proc/self/setgroups","rb",buffering=0).read(33).strip();out["setgroups"]=text.decode() if text in (b"allow",b"deny") else "unexpected"\n except FileNotFoundError:out["setgroups"]="absent"\n except OSError:pass\n return out\nsetup=filter_now()\nif setup["state"]!="ok":value={"setup":setup}\nelif len(sys.argv)!=2 or sys.argv[1] not in ("host-map","sudo-map","parent-userns","child-userns"):value={"setup":s("mismatch")}\nelif sys.argv[1]=="sudo-map":value={"map":maps("host")}\nelif sys.argv[1]=="host-map":\n try:ro=bool(os.statvfs("/proc").f_flag&os.ST_RDONLY)\n except OSError:ro=None\n value={"map":maps("host"),"read_only":ro}\nelse:\n created=sys.argv[1];before=maps(created);d=drop();after=maps(created)\n try:ro=bool(os.statvfs("/proc").f_flag&os.ST_RDONLY)\n except OSError:ro=None\n value={"maps":{"before":before,"after":after,"drop":d},"ids":ids(),"pid_one":os.getpid()==1,"proc_read_only":ro}\nos.write(1,(json.dumps(value,sort_keys=True,separators=(",",":"))+"\\n").encode())\n'
def parse_internal_output(command: CommandResult, expected: set[str]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if command.invocation["state"] != "ok" or command.exit_code != 0 or command.overflow:
        return command.invocation, None
    try:
        value = json.loads(command.record)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return status("mismatch"), None
    if not isinstance(value, dict):
        return status("mismatch"), None
    if set(value) == {"setup"}:
        setup = value["setup"]
        try:
            validate_status(setup)
        except ValueError:
            return status("mismatch"), None
        return setup, None
    if set(value) != expected:
        return status("mismatch"), None
    return status("ok"), value
def ns_identity(name: str) -> tuple[int, int] | None:
    try:
        value = os.stat(f"/proc/self/ns/{name}")
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
        if not distinct:
            created = status("mismatch")
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
        if not result["child_is_namespace_pid_1"] or not result["nspid_final_component_is_1"]:
            result["create"] = status("mismatch")
    else:
        result["create"] = status("mismatch")
    return result
def sudo_descriptor_case(close_from: int, ledger: Ledger) -> dict[str, Any]:
    helper = FIXED_CHILD_FILTER + (
        "import fcntl,os\n"
        "v=[]\n"
        "for n in (3,4):\n"
        " try: fcntl.fcntl(n,fcntl.F_GETFD);v.append(1)\n"
        " except OSError:v.append(0)\n"
        "os._exit(40+v[0]+2*v[1])\n"
    )
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
            os.execve(SUDO, argv, {})
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
    helper = FIXED_CHILD_FILTER + (
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
            os.execve(PYTHON, [PYTHON, "-I", "-c", helper], {})
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
    survived, closed = parsed["a"], not parsed["b"]
    return {
        "invocation": status("ok") if survived and closed else status("mismatch"),
        "non_cloexec_fd_198_survived": survived,
        "cloexec_fd_199_closed": closed,
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
        if not result["known_fd_closed"]:
            result["invocation"] = status("mismatch")
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
def required_env(name: str, pattern: str) -> str:
    value = validated_env(name, re.compile(pattern))
    if value is None:
        raise ValueError("invalid public control")
    return value
def source_and_envelope_metadata() -> tuple[dict[str, Any], dict[str, Any]]:
    sha1 = r"[0-9a-f]{40}"
    sha256 = r"[0-9a-f]{64}"
    repository = required_env("COGS_CAP_REPOSITORY", r"nenb/cogs")
    workflow = required_env("COGS_CAP_WORKFLOW", r"\.github/workflows/outcome-two-runner-capability\.yml")
    job = required_env("COGS_CAP_JOB", r"runner-capability-probe")
    event = required_env("COGS_CAP_EVENT", r"pull_request")
    action = required_env("COGS_CAP_ACTION", r"labeled")
    head_repository = required_env("COGS_CAP_PR_HEAD_REPOSITORY", r"nenb/cogs")
    pr_head = required_env("COGS_CAP_PR_HEAD_SHA", sha1)
    checkout = required_env("COGS_CAP_CHECKOUT_SHA", sha1)
    base = required_env("COGS_CAP_BASE_SHA", sha1)
    github_sha = required_env("COGS_CAP_GITHUB_SHA", sha1)
    workflow_sha = required_env("COGS_CAP_GITHUB_WORKFLOW_SHA", sha1)
    merge_sha = required_env("COGS_CAP_EVENT_MERGE_SHA", sha1)
    run_id = required_env("COGS_CAP_RUN_ID", r"[1-9][0-9]{0,19}")
    attempt = int(required_env("COGS_CAP_RUN_ATTEMPT", r"1"))
    pull_request = int(required_env("COGS_CAP_PULL_REQUEST_NUMBER", r"[1-9][0-9]{0,9}"))
    if head_repository != repository or checkout != pr_head or github_sha != merge_sha:
        raise ValueError("source/envelope identity mismatch")
    source = {
        "pr_head_sha": pr_head,
        "checkout_sha": checkout,
        "driver_sha256": required_env("COGS_CAP_DRIVER_SHA256", sha256),
        "schema_sha256": required_env("COGS_CAP_SCHEMA_SHA256", sha256),
        "source_head_workflow_blob_sha256": required_env("COGS_CAP_SOURCE_HEAD_WORKFLOW_BLOB_SHA256", sha256),
    }
    envelope = {
        "repository": repository,
        "workflow": workflow,
        "job": job,
        "event": event,
        "action": action,
        "run_id": run_id,
        "run_attempt": attempt,
        "pull_request_number": pull_request,
        "base_sha": base,
        "github_sha": github_sha,
        "github_workflow_sha": workflow_sha,
        "event_merge_sha": merge_sha,
    }
    return source, envelope
def runner_metadata() -> dict[str, Any]:
    return {
        "requested_label": "ubuntu-24.04",
        "environment": required_env("COGS_CAP_RUNNER_ENVIRONMENT", r"github-hosted"),
        "image_os": required_env("COGS_CAP_IMAGE_OS", r"[a-z0-9.-]{1,32}"),
        "image_version": required_env("COGS_CAP_IMAGE_VERSION", r"[A-Za-z0-9._-]{1,64}"),
        "runner_arch": required_env("COGS_CAP_RUNNER_ARCH", r"X64"),
        "image_metadata_status": status("ok"),
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
    arguments = [UNSHARE, "--user", "--map-user=0", "--map-group=0"]
    if combined:
        arguments.extend(("--mount", "--pid", "--fork", f"--mount-proc={PRIVATE_PARENT}/proc"))
        created = "child-userns"
    else:
        created = "parent-userns"
    arguments.extend((PYTHON, "-I", "-c", FIXED_CASE_HELPER, created))
    command = ledger.run(tuple(arguments), NS_SECONDS)
    return parse_internal_output(command, {"maps", "ids", "pid_one", "proc_read_only"})
def sudo_noninteractive_and_maps(ledger: Ledger) -> tuple[dict[str, Any], dict[str, Any] | None]:
    command = ledger.run(
        (SUDO, "-n", "--", PYTHON, "-I", "-", "sudo-map"),
        input_bytes=FIXED_CASE_HELPER.encode("utf-8"),
    )
    return parse_internal_output(command, {"map"})
def probe_linux() -> dict[str, Any]:
    global ACTIVE_LEDGER
    ledger = Ledger(time.monotonic() + GLOBAL_SECONDS)
    ACTIVE_LEDGER = ledger
    source, envelope = source_and_envelope_metadata()
    uname = os.uname()
    release_ok = bool(re.fullmatch(r"[ -~]{1,128}", uname.release))
    linux_amd64 = uname.sysname == "Linux" and uname.machine == "x86_64"
    if not linux_amd64 or not release_ok: raise RuntimeError("unsupported bootstrap host")
    kernel = {
        "sysname": "Linux" if uname.sysname == "Linux" else "unexpected",
        "release": uname.release if release_ok else "unexpected",
        "machine": "x86_64" if uname.machine == "x86_64" else "unexpected",
        "uname_status": status("ok") if linux_amd64 and release_ok else status("mismatch"),
    }
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE); ledger.transition("BASELINED"); ledger.transition("RUNNING")
    identities = {
        "python3": fixed_identity(PYTHON, ledger),
        "gzip": fixed_identity(GZIP, ledger),
        "zstd": fixed_identity(ZSTD, ledger),
        "unshare": fixed_identity(UNSHARE, ledger),
    }
    if identities["python3"]["observation"]["state"] != "ok":
        raise RuntimeError("bootstrap identity unavailable")
    sudo_identity = fixed_identity(SUDO, ledger)
    private_ready = create_private_parent(ledger)
    if private_ready:
        runner_tmp_status, runner_tmp_payload = ledger.fork_case(lambda: tmpfile_case(f"{PRIVATE_PARENT}/runner-temp"))
        runner_tmp = runner_tmp_payload or empty_tmpfile_case(blocked=True)
        if runner_tmp_payload is None:
            runner_tmp["open_otmpfile"] = runner_tmp_status
    else:
        runner_tmp = empty_tmpfile_case(blocked=True)
    if private_ready:
        mount_status, mount_batch = ledger.fork_case(mount_namespace_batch, NS_SECONDS)
        mount_payload = mount_batch["private"] if mount_batch else None
        mount_ns = mount_batch["namespace"] if mount_batch else None
    else:
        mount_status, mount_payload, mount_ns = status("blocked"), None, None
    if mount_payload is None:
        private_tmp = empty_tmpfile_case(blocked=True)
        same_opath = empty_opath_case(True)
        across_opath = empty_opath_case(True)
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
    host_command = ledger.run((PYTHON, "-I", "-c", FIXED_CASE_HELPER, "host-map"))
    host_status, host_payload = parse_internal_output(host_command, {"map", "read_only"})
    host_map = host_payload["map"] if host_payload else empty_map_case("host", False)
    if host_payload is None:
        host_map["maps_read"] = host_status
    sudo_noninteractive, sudo_payload = (
        sudo_noninteractive_and_maps(ledger)
        if sudo_identity["observation"]["state"] == "ok"
        else (status("blocked"), None)
    )
    sudo_map = sudo_payload["map"] if sudo_payload else empty_map_case("host", False)
    if sudo_payload is None:
        sudo_map["maps_read"] = status("blocked")
    user_prerequisite = private_ready and identities["unshare"]["observation"]["state"] == "ok"
    user_create, user_payload = user_namespace_invocation(ledger, False) if user_prerequisite else (status("blocked"), None)
    combined_create, combined_payload = user_namespace_invocation(ledger, True) if user_prerequisite else (status("blocked"), None)
    if user_payload:
        user_maps = user_payload["maps"]
        ids = user_payload["ids"]
    else:
        user_maps = {"before": empty_map_case("parent-userns", False), "after": empty_map_case("parent-userns", True), "drop": status("blocked")}
        user_maps["before"]["maps_read"] = status("blocked")
        user_maps["after"]["maps_read"] = status("blocked")
        ids = {"uid_map_status": status("blocked"), "uid_map": None, "gid_map_status": status("blocked"), "gid_map": None, "setgroups": "unexpected"}
    if combined_payload:
        child_maps = combined_payload["maps"]
    else:
        child_maps = {"before": empty_map_case("child-userns", False), "after": empty_map_case("child-userns", True), "drop": status("blocked")}
        child_maps["before"]["maps_read"] = status("blocked")
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
    close3 = sudo_descriptor_case(3, ledger) if sudo_identity["observation"]["state"] == "ok" else empty_sudo_close(3)
    close4 = sudo_descriptor_case(4, ledger) if sudo_identity["observation"]["state"] == "ok" else empty_sudo_close(4)
    ledger.transition("CLEANING")
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
    complete = linux_amd64 and all(cleanup[key] for key in ("children_reaped", "descriptors_restored", "mounts_gone", "temporary_names_gone")) and not cleanup["uncertainty"]
    report = {
        "schema": SCHEMA,
        "authority": "none",
        "qualified": False,
        "outcome": "complete" if complete else "incomplete",
        "source": source,
        "envelope": envelope,
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
            "parent_proc_read_only": host_payload.get("read_only") if host_payload else None,
            "child_proc_read_only": combined_payload.get("proc_read_only") if combined_payload else None,
            "child_proc_distinct_from_parent": None,
            "child_proc_view_has_pid_1": combined_payload.get("pid_one") if combined_payload else None,
        },
        "seccomp": seccomp_result,
        "kvm": (lambda pair: pair[1] or {
            "device_present": False,
            "character_device": None,
            "open_read_write": pair[0],
            "get_api_version": status("blocked"),
            "api_version": None,
            "check_extension_user_memory": status("blocked"),
            "user_memory_extension": None,
        })(ledger.fork_case(kvm_case)),
        "tools": identities,
        "cleanup": cleanup,
    }
    validate_report(report)
    ledger.transition("COMPLETE" if complete else "POISONED")
    if ledger.state == "POISONED": ledger.transition("FAILED")
    ACTIVE_LEDGER = None
    return report
def close_range_case_shape(target: int, invocation: dict[str, Any]) -> dict[str, Any]:
    observed = True if invocation["state"] == "ok" else None
    return {"syscall_number_amd64": SYS_CLOSE_RANGE, "flags": 0, "first": target, "last": target, "invocation": invocation, "known_fd_closed": observed}
def empty_sudo_close(close_from: int) -> dict[str, Any]:
    if close_from == 3:
        return {"invocation": status("blocked"), "fd3_closed": None, "fd4_closed": None, "exit_code": None}
    return {"invocation": status("blocked"), "fd3_preserved": None, "fd4_closed": None, "exit_code": None}
def validate_status(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"state", "errno"}:
        raise ValueError("invalid status shape")
    state, number = value["state"], value["errno"]
    if state in {"ok", "blocked", "mismatch"}:
        valid = number is None
    elif state == "unsupported":
        valid = number is None or number in (errno.ENOSYS, errno.EOPNOTSUPP)
    elif state == "denied":
        valid = number in (errno.EPERM, errno.EACCES)
    elif state == "error":
        valid = isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= 4095 and number not in (
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.EPERM,
            errno.EACCES,
        )
    else:
        valid = False
    if not valid:
        raise ValueError("invalid status coupling")
def validate_observation(operation: dict[str, Any], fields: tuple[Any, ...]) -> None:
    validate_status(operation)
    state = operation["state"]
    if state == "ok" and not all(value is True for value in fields):
        raise ValueError("successful operation lacks successful postcondition")
    if state == "mismatch" and (not fields or not any(value is False for value in fields)):
        raise ValueError("mismatch lacks false postcondition")
    if state not in {"ok", "mismatch"} and any(value is not None for value in fields):
        raise ValueError("unobserved postcondition is non-null")
def validate_report(report: dict[str, Any]) -> None:
    """Production semantics beyond the recursively closed JSON schema."""
    if report.get("authority") != "none" or report.get("qualified") is not False:
        raise ValueError("authority expansion")
    if set(report.get("source", {})) != {
        "pr_head_sha", "checkout_sha", "driver_sha256", "schema_sha256", "source_head_workflow_blob_sha256"
    }:
        raise ValueError("source contract")
    if set(report.get("envelope", {})) != {
        "repository", "workflow", "job", "event", "action", "run_id", "run_attempt", "pull_request_number",
        "base_sha", "github_sha", "github_workflow_sha", "event_merge_sha"
    }:
        raise ValueError("envelope contract")
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) == {"state", "errno"}:
                validate_status(value)
            else:
                closed = {"maps_read": {"proc_mount_created_in", "capability_sets_zero", "maps_read", "executable_mappings_selected", "map_files_opened", "first_open_failure", "all_opened_descriptors_closed"}, "uid_map_status": {"create", "uid_map_status", "uid_map", "gid_map_status", "gid_map", "setgroups"}}
                for marker, keys in closed.items():
                    if marker in value and set(value) != keys: raise ValueError("non-categorical helper record")
                if "maps_read" in value:
                    if value["proc_mount_created_in"] not in {"host", "parent-userns", "child-userns"} or not isinstance(value["capability_sets_zero"], bool) or not isinstance(value["all_opened_descriptors_closed"], bool): raise ValueError("invalid map category")
                    if any(not isinstance(value[name], int) or isinstance(value[name], bool) or not 0 <= value[name] <= 8 for name in ("executable_mappings_selected", "map_files_opened")): raise ValueError("invalid map bound")
                if "uid_map_status" in value and any(rows is not None and (not isinstance(rows, list) or len(rows) > 5 or any(not isinstance(row, list) or len(row) != 3 or any(not isinstance(number, int) or isinstance(number, bool) or not 0 <= number <= 0xffffffff for number in row) for row in rows)) for rows in (value["uid_map"], value["gid_map"])): raise ValueError("invalid ID-map category")
                for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(report)
    cleanup = report["cleanup"]
    exact_cleanup = all(cleanup[name] for name in ("children_reaped", "descriptors_restored", "mounts_gone", "temporary_names_gone"))
    exact_cleanup = exact_cleanup and cleanup["namespace_handles_retained"] is False and cleanup["uncertainty"] is False
    if report["outcome"] != ("complete" if exact_cleanup else "incomplete"):
        raise ValueError("outcome/cleanup mismatch")
    python = report["tools"]["python3"]
    if not python["present"] or python["observation"]["state"] != "ok":
        raise ValueError("unauthenticated bootstrap Python")
    for identity in [report["sudo"]["executable"], *report["tools"].values()]:
        observed = identity["observation"]["state"]
        metadata = tuple(identity[name] for name in ("regular_file", "root_owned", "mode", "size", "sha256"))
        if observed == "ok":
            if not identity["present"] or metadata[0:2] != (True, True) or any(value is None for value in metadata[2:]):
                raise ValueError("incomplete tool identity")
        elif not identity["present"] and any(value is not None for value in metadata):
            raise ValueError("fabricated absent tool metadata")
    for name in ("network", "mount"):
        case = report["namespaces"][name]
        validate_observation(case["create"], (case["distinct_from_parent"],))
    pid_case = report["namespaces"]["pid"]
    validate_observation(
        pid_case["create"],
        (pid_case["child_is_namespace_pid_1"], pid_case["nspid_final_component_is_1"]),
    )
    for name in ("close_range_low", "close_range_high"):
        case = report["descriptors"][name]
        validate_observation(case["invocation"], (case["known_fd_closed"],))
    exec_case = report["descriptors"]["exec_cloexec"]
    validate_observation(
        exec_case["invocation"],
        (exec_case["non_cloexec_fd_198_survived"], exec_case["cloexec_fd_199_closed"]),
    )
    for case in report["temporary_files"].values():
        validate_observation(
            case["open_otmpfile"],
            (case["initial_nlink_zero"], case["owner_is_probe_identity"], case["initial_mode_0600"]),
        )
        validate_observation(case["linkat_empty_path"], (case["linked_identity_matches"],))
        if case["linkat_empty_path"]["state"] == "blocked" and case["open_otmpfile"]["state"] == "ok":
            raise ValueError("unnamed tmpfile prerequisite")
    for case in report["opath"].values():
        validate_observation(case["open_opath_directory"], (case["fstat_stable"],))
        validate_observation(case["bind_mount_from_proc_fd"], (case["bind_target_identity_matches"],))
        if case["bind_mount_from_proc_fd"]["state"] == "blocked" and case["open_opath_directory"]["state"] == "ok":
            raise ValueError("unnamed O_PATH prerequisite")
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
        "observation": status("ok"),
    }
    tmp = {"filesystem": "tmpfs", "open_otmpfile": status("ok"), "initial_nlink_zero": True, "owner_is_probe_identity": True, "initial_mode_0600": True, "linkat_empty_path": status("ok"), "linked_identity_matches": True, "cleanup": status("ok")}
    opath = {"open_opath_directory": status("ok"), "fstat_stable": True, "bind_mount_from_proc_fd": status("denied", errno.EPERM), "bind_target_identity_matches": None, "cleanup": status("ok")}
    mapping = {"proc_mount_created_in": "host", "capability_sets_zero": True, "maps_read": status("ok"), "executable_mappings_selected": 1, "map_files_opened": 1, "first_open_failure": None, "all_opened_descriptors_closed": True}
    cleanup = {"children_reaped": True, "descriptors_restored": True, "mounts_gone": True, "temporary_names_gone": not inject_cleanup_failure, "namespace_handles_retained": False, "uncertainty": inject_cleanup_failure}
    report = {
        "schema": SCHEMA, "authority": "none", "qualified": False, "outcome": "incomplete" if inject_cleanup_failure else "complete",
        "source": {"pr_head_sha": "0" * 40, "checkout_sha": "0" * 40, "driver_sha256": "1" * 64, "schema_sha256": "2" * 64, "source_head_workflow_blob_sha256": "3" * 64},
        "envelope": {"repository": "nenb/cogs", "workflow": ".github/workflows/outcome-two-runner-capability.yml", "job": "runner-capability-probe", "event": "pull_request", "action": "labeled", "run_id": "1", "run_attempt": 1, "pull_request_number": 1, "base_sha": "4" * 40, "github_sha": "5" * 40, "github_workflow_sha": "6" * 40, "event_merge_sha": "5" * 40},
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
    first_report = DeterministicFakeBackend().report()
    second_report = DeterministicFakeBackend().report()
    validate_report(first_report)
    validate_report(second_report)
    first = canonical_bytes(first_report)
    second = canonical_bytes(second_report)
    assert first == second and first.endswith(b"\n") and first.count(b"\n") == 1
    assert json.loads(first)["authority"] == "none" and json.loads(first)["qualified"] is False
    failed = DeterministicFakeBackend(inject_cleanup_failure=True).report()
    timed_out = DeterministicFakeBackend(inject_timeout=True).report()
    validate_report(failed)
    validate_report(timed_out)
    assert canonical_bytes(failed) != first
    assert json.loads(canonical_bytes(failed))["outcome"] == "incomplete"
    assert timed_out["kvm"]["open_read_write"] == status("error", errno.ETIMEDOUT)
    assert timed_out["cleanup"]["uncertainty"] is True
    assert from_errno(errno.ENOSYS) == status("unsupported", errno.ENOSYS)
    assert from_errno(errno.EPERM) == status("denied", errno.EPERM)
    assert from_errno(errno.EIO) == status("error", errno.EIO)
    for invalid in (
        {"state": "ok", "errno": errno.EPERM},
        {"state": "denied", "errno": errno.ENOENT},
        {"state": "unsupported", "errno": errno.EINVAL},
        {"state": "error", "errno": None},
    ):
        try:
            validate_status(invalid)
            raise AssertionError("invalid status accepted")
        except ValueError:
            pass
    bad_cleanup = DeterministicFakeBackend().report()
    bad_cleanup["cleanup"]["uncertainty"] = True
    try:
        validate_report(bad_cleanup)
        raise AssertionError("complete outcome accepted uncertain cleanup")
    except ValueError:
        pass
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
    sys.stdout.write("runner-capability-probe self-test: ok\n")
def _interrupt(_signum: int, _frame: Any) -> None:
    raise InterruptedError
def main() -> int:
    global ACTIVE_LEDGER
    arguments = sys.argv[1:]
    if sys.flags.isolated != 1 or sys.flags.optimize != 0:
        return 2
    if arguments == ["--self-test"]:
        self_test()
        return 0
    if arguments != ["--workflow-bound"]:
        return 2
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        report = probe_linux()
        output = canonical_bytes(report)
    except (Exception, KeyboardInterrupt):
        if ACTIVE_LEDGER is not None:
            ACTIVE_LEDGER.abort()
            cleanup_private_parent(ACTIVE_LEDGER)
            ACTIVE_LEDGER = None
        return 1
    try:
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except (Exception, KeyboardInterrupt):
        return 1
    return 0 if report["outcome"] == "complete" else 1
if __name__ == "__main__":
    raise SystemExit(main())
