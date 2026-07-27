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
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable
SCHEMA = "cogs.runner-capability-probe/v1alpha1"
BLOCKED_BY = frozenset({
    "kvm.open_read_write", "namespaces.combined_user_mount_pid_fork.create", "namespaces.mount.create",
    "namespaces.user_direct_root.create", "opath.across_mount_namespace.open_opath_directory",
    "opath.same_mount_namespace.open_opath_directory", "procfs.child_owned_proc_after_cap_drop.setup",
    "procfs.child_owned_proc_before_cap_drop.setup", "procfs.child_userns_parent_proc_after_cap_drop.setup",
    "procfs.child_userns_parent_proc_before_cap_drop.setup", "procfs.host_runner.setup", "procfs.host_sudo_root.setup",
    "rlimit_nofile.high_fd_4096_status", "seccomp.initial_mode_status", "seccomp.initial_no_new_privs_status",
    "seccomp.set_no_new_privs", "sudo.executable.observation", "sudo.noninteractive",
    "temporary_files.private_tmpfs.open_otmpfile", "temporary_files.runner_temp.open_otmpfile", "tools.unshare.observation",
})
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
PR_SET_PDEATHSIG = 1
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_GET_SECCOMP = 21
PR_SET_CHILD_SUBREAPER = 36
KVM_GET_API_VERSION = 0xAE00
KVM_CHECK_EXTENSION = 0xAE03
KVM_CAP_USER_MEMORY = 3
libc = ctypes.CDLL(None, use_errno=True)
ACTIVE_LEDGER: Ledger | None = None
FIXED_CHILD_FILTER = 'import ctypes,os\nparent=os.getppid();c0=ctypes.CDLL(None,use_errno=True)\nif c0.prctl(1,9,0,0,0) or os.getppid()!=parent:os._exit(125)\nclass F(ctypes.Structure):_fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint32)]\nclass P(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(F))]\nc=ctypes.CDLL(None,use_errno=True);deny=(41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,288,299,307,425,426,427);r=[F(0x20,0,0,4),F(0x15,1,0,0xc000003e),F(0x06,0,0,0x80000000),F(0x20,0,0,0)]\nfor n in deny:r.extend((F(0x15,0,1,n),F(0x06,0,0,0x50001)))\nr.append(F(0x06,0,0,0x7fff0000));a=(F*len(r))(*r);p=P(len(r),a)\nif c.prctl(38,1,0,0,0) or c.syscall(317,1,0,ctypes.byref(p))==-1:os._exit(119)\n'
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
def status(state: str, err: int | None = None, blocked_by: str | None = None) -> dict[str, Any]:
    if state not in {"ok", "unsupported", "denied", "blocked", "mismatch", "error"}:
        raise ValueError("bad status state")
    if err is not None and not (1 <= err <= 4095): raise ValueError("bad errno")
    if state == "blocked":
        if blocked_by not in BLOCKED_BY:
            raise ValueError("blocked status lacks fixed prerequisite")
    elif blocked_by is not None:
        raise ValueError("non-blocked status names prerequisite")
    return {"state": state, "errno": err, "blocked_by": blocked_by}
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

def fd_snapshot() -> frozenset[tuple[Any, ...]]:
    directory = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        result = []
        for name in os.listdir(directory):
            fd = int(name)
            if fd == directory: continue
            try: result.append((fd, generation(os.fstat(fd)), fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL)))
            except OSError as exc:
                if exc.errno != errno.EBADF: raise
        return frozenset(result)
    finally:
        if not safe_close(directory): raise OSError(errno.EIO, "fd snapshot close")

def process_start(pid: int) -> str | None:
    descriptor = -1
    try:
        descriptor = os.open(f"/proc/{pid}/stat", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        raw = os.read(descriptor, 4097); end = raw.rfind(b")"); fields = raw[end + 2 :].split()
        return fields[19].decode("ascii") if end > 0 and len(fields) > 19 else None
    except (OSError, UnicodeDecodeError): return None
    finally:
        if descriptor >= 0 and not safe_close(descriptor): return None

def child_boundary(record_fd: int | tuple[int, ...] | None = None) -> None:
    """Establish the disposable-child boundary before case code or exec."""
    parent = os.getppid()
    if PRCTL(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
        os._exit(125)
    os.setsid()
    os.chdir("/")
    os.environ.clear()
    null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    for target in (0, 1, 2):
        os.dup2(null, target, inheritable=False)
    keep = {0, 1, 2}
    if isinstance(record_fd, int): keep.add(record_fd)
    elif record_fd is not None: keep.update(record_fd)
    for text in os.listdir("/proc/self/fd"):
        descriptor = int(text)
        if descriptor not in keep and descriptor != null:
            safe_close(descriptor)
    if null not in keep:
        safe_close(null)
    if os.getppid() != parent:
        os._exit(125)

@dataclass
class CommandResult:
    invocation: dict[str, Any]
    exit_code: int | None
    record: bytes
    overflow: bool = False
    timed_out: bool = False

@dataclass
class ChildIdentity:
    pid: int
    start: str
    session: int
    pidfd: int

@dataclass
class Ledger:
    deadline: float
    fd_baseline: frozenset[tuple[Any, ...]]
    cwd_baseline: tuple[int, ...]
    children_reaped: bool = True
    descriptors_restored: bool = False
    mounts_gone: bool = True
    temporary_names_gone: bool = True
    uncertainty: bool = False
    child_count: int = 0
    tool_bytes_read: int = 0
    live_children: dict[int, ChildIdentity] = field(default_factory=dict)
    tracked_fds: set[int] = field(default_factory=set)
    private_fd: int = -1
    private_identity: tuple[int, ...] | None = None
    tmp_fd: int = -1
    tmp_identity: tuple[int, ...] | None = None
    private_children: dict[str, tuple[int, ...]] = field(default_factory=dict)
    state: str = "NEW"
    def transition(self, next_state: str) -> None:
        allowed = {"NEW": {"BASELINED"}, "BASELINED": {"RUNNING"}, "RUNNING": {"CLEANING", "POISONED"}, "CLEANING": {"COMPLETE", "POISONED"}, "POISONED": {"FAILED"}}
        if next_state not in allowed.get(self.state, set()): raise RuntimeError("invalid supervisor transition")
        self.state = next_state
    def can_effect(self) -> bool:
        return self.state == "RUNNING" and not self.uncertainty and time.monotonic() < self.deadline - 20.0
    def remaining(self, wanted: float) -> float:
        return max(0.0, min(wanted, self.deadline - time.monotonic()))
    def track_fd(self, fd: int) -> int:
        self.tracked_fds.add(fd); return fd
    def close_fd(self, fd: int) -> bool:
        ok = safe_close(fd)
        if ok: self.tracked_fds.discard(fd)
        else: self.uncertainty = True
        return ok
    def close_stream(self, stream: Any) -> None:
        fd = stream.fileno()
        try: stream.close(); self.tracked_fds.discard(fd)
        except OSError: self.uncertainty = True
    def register_child(self, pid: int) -> ChildIdentity | None:
        self.child_count += 1
        try:
            pidfd = self.track_fd(os.pidfd_open(pid, 0))
            end = time.monotonic() + min(0.25, self.remaining(0.25))
            while time.monotonic() < end:
                start = process_start(pid)
                try: session = os.getsid(pid)
                except OSError: session = -1
                if start is not None and session == pid:
                    child = ChildIdentity(pid, start, session, pidfd)
                    self.live_children[pid] = child
                    return child
                time.sleep(0.002)
        except OSError:
            pass
        self.uncertainty = True
        fallback = ChildIdentity(pid, locals().get("start") or "", pid, locals().get("pidfd", -1)); self.live_children[pid] = fallback
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass
        end = time.monotonic() + self.remaining(0.25)
        while time.monotonic() < end:
            if self.poll(fallback) is not None: return None
            time.sleep(0.002)
        self.children_reaped = False
        return None
    def matches(self, child: ChildIdentity) -> bool:
        try:
            return process_start(child.pid) == child.start and os.getsid(child.pid) == child.session == child.pid
        except OSError:
            return False
    def poll(self, child: ChildIdentity) -> int | None:
        try:
            waited, wait_status = os.waitpid(child.pid, os.WNOHANG)
        except ChildProcessError:
            self.children_reaped = False; self.uncertainty = True; return None
        except OSError:
            self.uncertainty = True; return None
        if waited != child.pid: return None
        self.live_children.pop(child.pid, None)
        if child.pidfd >= 0: self.close_fd(child.pidfd)
        return os.waitstatus_to_exitcode(wait_status)
    def stop(self, child: ChildIdentity, end: float) -> int | None:
        for sig, fraction in ((signal.SIGTERM, 0.25), (signal.SIGKILL, 1.0)):
            if self.matches(child):
                try: os.killpg(child.session, sig)
                except ProcessLookupError: pass
                except OSError: self.uncertainty = True
            limit = min(end, time.monotonic() + fraction)
            while time.monotonic() < limit:
                code = self.poll(child)
                if code is not None: return code
                time.sleep(0.003)
        self.children_reaped = False; self.uncertainty = True
        return None
    def run(self, argv: tuple[str, ...], seconds: float = CASE_SECONDS, input_bytes: bytes | None = None) -> CommandResult:
        """Run one fixed child with a private bounded record channel."""
        if not self.can_effect() or self.child_count >= 24:
            return CommandResult(status("error", errno.ETIMEDOUT), None, b"")
        if not argv or any(not item or "\x00" in item for item in argv) or not argv[0].startswith("/usr/bin/"):
            raise ValueError("non-fixed child command")
        try:
            process = subprocess.Popen(argv, executable=argv[0], stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, env={}, cwd="/", preexec_fn=child_boundary)
        except OSError as exc:
            return CommandResult(from_errno(exc.errno or errno.EIO), None, b"")
        child = self.register_child(process.pid)
        if child is None:
            return CommandResult(status("error", errno.EIO), None, b"")
        assert process.stdout is not None
        self.track_fd(process.stdout.fileno())
        if process.stdin is not None:
            input_fd = self.track_fd(process.stdin.fileno()); os.set_blocking(input_fd, False); offset = 0
            while offset < len(input_bytes) and self.can_effect():
                try: offset += os.write(input_fd, input_bytes[offset:])
                except BlockingIOError: time.sleep(0.002)
                except OSError: break
            if offset != len(input_bytes): self.uncertainty = True
            self.close_stream(process.stdin)
        fd = process.stdout.fileno(); os.set_blocking(fd, False)
        output = bytearray(); overflow = False; code: int | None = None
        end = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < end:
            try:
                chunk = os.read(fd, min(1024, MAX_OUTPUT + 1 - len(output)))
                if chunk: output.extend(chunk)
                elif (code := self.poll(child)) is not None: break
            except BlockingIOError: pass
            if len(output) > MAX_OUTPUT: overflow = True; break
            polled = self.poll(child)
            if polled is not None: code = polled; break
            time.sleep(0.003)
        timed_out = code is None and not overflow
        if code is None: code = self.stop(child, self.deadline)
        self.close_stream(process.stdout); process.returncode = code
        if timed_out or overflow:
            self.uncertainty = True
            return CommandResult(status("error", errno.ETIMEDOUT if timed_out else errno.EOVERFLOW), code, b"", overflow, timed_out)
        return CommandResult(status("ok") if code == 0 else status("mismatch"), code, bytes(output))
    def abort(self) -> None:
        if self.state in {"RUNNING", "CLEANING"}: self.transition("POISONED")
        for child in tuple(self.live_children.values()): self.stop(child, self.deadline)
        retained = {self.private_fd, self.tmp_fd, *(child.pidfd for child in self.live_children.values())}
        for fd in tuple(self.tracked_fds):
            if fd not in retained: self.close_fd(fd)
        self.uncertainty = True
        if self.state == "POISONED": self.transition("FAILED")
    def fork_case(self, function: Callable[[], Any], seconds: float = CASE_SECONDS) -> tuple[dict[str, Any], Any | None]:
        if not self.can_effect() or self.child_count >= 24:
            return status("error", errno.ETIMEDOUT), None
        try:
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC); gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
            for fd in (read_fd, write_fd, gate_read, gate_write): self.track_fd(fd)
            pid = os.fork()
        except OSError as exc:
            for name in ("read_fd", "write_fd", "gate_read", "gate_write"):
                if name in locals(): self.close_fd(locals()[name])
            return from_errno(exc.errno or errno.EIO), None
        if pid == 0:
            safe_close(read_fd); safe_close(gate_write)
            try:
                child_boundary((write_fd, gate_read))
                if os.read(gate_read, 1) != b"G": os._exit(124)
                safe_close(gate_read)
                payload = canonical_bytes({"value": function()})
                if len(payload) > MAX_OUTPUT: os._exit(121)
                os.write(write_fd, payload); safe_close(write_fd); os._exit(0)
            except BaseException:
                safe_close(write_fd); os._exit(120)
        child = self.register_child(pid); self.close_fd(write_fd); self.close_fd(gate_read)
        if child is None:
            self.close_fd(gate_write); self.close_fd(read_fd); return status("error", errno.EIO), None
        try:
            if not self.can_effect(): raise OSError(errno.ETIMEDOUT, "release barred")
            os.write(gate_write, b"G")
        except OSError:
            self.uncertainty = True; self.stop(child, self.deadline)
        self.close_fd(gate_write)
        os.set_blocking(read_fd, False); end = min(self.deadline, time.monotonic() + seconds)
        data = bytearray(); code: int | None = None
        while time.monotonic() < end:
            try:
                chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
                if chunk: data.extend(chunk)
            except BlockingIOError: pass
            code = self.poll(child)
            if code is not None or len(data) > MAX_OUTPUT: break
            time.sleep(0.003)
        timed_out = code is None
        if code is None: code = self.stop(child, self.deadline)
        if code == 0:
            while time.monotonic() < end and len(data) <= MAX_OUTPUT:
                try: chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
                except BlockingIOError: time.sleep(0.001); continue
                if not chunk: break
                data.extend(chunk)
        self.close_fd(read_fd)
        if code != 0 or len(data) > MAX_OUTPUT:
            return status("error", errno.ETIMEDOUT if timed_out else errno.EIO), None
        try:
            parsed = json.loads(bytes(data))
            if not isinstance(parsed, dict) or set(parsed) != {"value"}: raise ValueError
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
def resolve_fixed_tool(path: str, ledger: Ledger) -> tuple[int, tuple[tuple[int, ...], ...]]:
    """Resolve an approved logical path through a bounded, held symlink chain."""
    if path not in {PYTHON, SUDO, UNSHARE, GZIP, ZSTD} or not ledger.can_effect():
        raise OSError(errno.ETIMEDOUT, "new acquisition barred")
    pending = path[1:].split("/")
    root = ledger.track_fd(os.open("/", O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
    directories = [root]; held: list[int] = []
    root_info = os.fstat(root)
    if root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022:
        ledger.close_fd(root); raise OSError(errno.EPERM, "root component policy")
    chain: list[tuple[int, ...]] = [generation(root_info)]; links = 0
    try:
        while pending:
            if not ledger.can_effect(): raise OSError(errno.ETIMEDOUT, "new acquisition barred")
            component = pending.pop(0)
            if component in ("", "."): continue
            if component == "..":
                if len(directories) == 1: raise OSError(errno.EPERM, "chain escapes root")
                if not ledger.close_fd(directories.pop()): raise OSError(errno.EIO, "chain close")
                continue
            probe = ledger.track_fd(os.open(component, O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directories[-1]))
            info = os.fstat(probe)
            if info.st_uid != 0:
                ledger.close_fd(probe); raise OSError(errno.EPERM, "non-root chain component")
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 16:
                    ledger.close_fd(probe); raise OSError(errno.ELOOP, "symlink bound")
                target = os.readlink(component, dir_fd=directories[-1])
                held.append(probe); chain.append(generation(info)); parts = target.split("/")
                if target.startswith("/"):
                    while len(directories) > 1: ledger.close_fd(directories.pop())
                pending = parts + pending
                if len(pending) > 64: raise OSError(errno.ELOOP, "component bound")
                continue
            if stat.S_IMODE(info.st_mode) & 0o022:
                ledger.close_fd(probe); raise OSError(errno.EPERM, "writable chain component")
            if pending:
                if not stat.S_ISDIR(info.st_mode):
                    ledger.close_fd(probe); raise OSError(errno.ENOTDIR, "non-directory component")
                directories.append(probe); chain.append(generation(info)); continue
            if not ledger.close_fd(probe): raise OSError(errno.EIO, "chain close")
            final_fd = ledger.track_fd(os.open(component, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directories[-1]))
            return final_fd, tuple(chain)
        raise OSError(errno.ENOENT, "empty tool path")
    finally:
        for descriptor in reversed(held): ledger.close_fd(descriptor)
        for descriptor in reversed(directories): ledger.close_fd(descriptor)
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
    if not ledger.can_effect():
        result["observation"] = status("error", errno.ETIMEDOUT)
        return result
    try:
        fd, chain_before = resolve_fixed_tool(path, ledger)
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
            result["observation"] = status("error", errno.EFBIG)
            return result
        ledger.tool_bytes_read += before.st_size
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            if not ledger.can_effect():
                result["observation"] = status("error", errno.ETIMEDOUT)
                return result
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                result["observation"] = status("mismatch")
                return result
            digest.update(chunk)
            remaining -= len(chunk)
        after_read = os.fstat(fd)
        result["sha256"] = digest.hexdigest()
        replacement, chain_after = resolve_fixed_tool(path, ledger)
        try:
            after_path = os.fstat(replacement)
        finally:
            ledger.close_fd(replacement)
        if generation(before) != generation(after_read) or generation(before) != generation(after_path) or chain_before != chain_after:
            result["observation"] = status("mismatch")
        else:
            result["observation"] = status("ok")
        return result
    except OSError as exc:
        result["observation"] = from_errno(exc.errno or errno.EIO)
        return result
    finally:
        ledger.close_fd(fd)
def statfs_kind(path: str) -> str:
    buffer = ctypes.create_string_buffer(256)
    result = STATFS(os.fsencode(path), ctypes.byref(buffer))
    if result == -1:
        return "unknown"
    magic = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_long))[0]
    return {0xEF53: "ext4", 0x58465342: "xfs", 0x01021994: "tmpfs"}.get(magic, "other")
def empty_tmpfile_case(filesystem: str = "unknown", blocked: bool = False, private: bool = False) -> dict[str, Any]:
    initial = status("blocked", blocked_by="namespaces.mount.create") if blocked else status("unsupported")
    open_path = "temporary_files.private_tmpfs.open_otmpfile" if private else "temporary_files.runner_temp.open_otmpfile"
    return {
        "filesystem": filesystem,
        "open_otmpfile": initial,
        "initial_nlink_zero": None,
        "owner_is_probe_identity": None,
        "initial_mode_0600": None,
        "linkat_empty_path": status("blocked", blocked_by=open_path),
        "linked_identity_matches": None,
        "cleanup": status("ok"),
    }
def tmpfile_case(directory: str) -> dict[str, Any]:
    result = empty_tmpfile_case(statfs_kind(directory), private="private-tmpfs" in directory)
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
    private_dir = f"{PRIVATE_PARENT}/private-tmpfs"; op_root = f"{PRIVATE_PARENT}/opath-root"
    result = {"private_tmpfs": empty_tmpfile_case(blocked=True, private=True), "same": empty_opath_case(True), "across": empty_opath_case(True, across=True), "mounts_gone": True}
    mounted: list[tuple[str, tuple[int, ...], tuple[int, ...]]] = []; root_fd = -1
    namespace = unshare_call(CLONE_NEWNS)
    if namespace["state"] != "ok": return result
    propagation = mount_call(None, "/", None, MS_REC | MS_PRIVATE)
    if propagation["state"] != "ok": return result
    original = generation(os.stat(private_dir, follow_symlinks=False))[:5]
    tmp_mount = mount_call("tmpfs", private_dir, "tmpfs", 0, "nodev,nosuid,noexec,size=1048576,mode=0700")
    if tmp_mount["state"] == "ok":
        mounted.append((private_dir, generation(os.stat(private_dir))[:5], original)); result["private_tmpfs"] = tmpfile_case(private_dir)
    original = generation(os.stat(op_root, follow_symlinks=False))[:5]
    op_mount = mount_call("tmpfs", op_root, "tmpfs", 0, "nodev,nosuid,noexec,size=1048576,mode=0700")
    if op_mount["state"] == "ok":
        mounted.append((op_root, generation(os.stat(op_root))[:5], original))
        try:
            root_fd = os.open(op_root, O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            for name in ("source", "same-target", "cross-target"): os.mkdir(name, 0o700, dir_fd=root_fd)
            result["same"] = opath_one(f"{op_root}/source", f"{op_root}/same-target", False)
            result["across"] = opath_one(f"{op_root}/source", f"{op_root}/cross-target", True)
            for name in ("cross-target", "same-target", "source"): os.rmdir(name, dir_fd=root_fd)
        except OSError:
            result["mounts_gone"] = False
        finally:
            if root_fd >= 0 and not safe_close(root_fd): result["mounts_gone"] = False
    for path, mounted_identity, original_identity in reversed(mounted):
        try:
            if generation(os.stat(path, follow_symlinks=False))[:5] != mounted_identity: raise OSError(errno.ESTALE, "mount replaced")
            if umount_call(path)["state"] != "ok" or generation(os.stat(path, follow_symlinks=False))[:5] != original_identity:
                raise OSError(errno.EIO, "mount cleanup")
        except OSError:
            result["mounts_gone"] = False
    return result
def empty_opath_case(blocked: bool = False, across: bool = False) -> dict[str, Any]:
    initial = status("blocked", blocked_by="namespaces.mount.create") if blocked else status("unsupported")
    open_path = "opath.across_mount_namespace.open_opath_directory" if across else "opath.same_mount_namespace.open_opath_directory"
    return {
        "open_opath_directory": initial,
        "fstat_stable": None,
        "bind_mount_from_proc_fd": status("blocked", blocked_by=open_path),
        "bind_target_identity_matches": None,
        "cleanup": status("ok"),
    }
def opath_one(source: str, target: str, across: bool) -> dict[str, Any]:
    result = empty_opath_case(across=across)
    fd = -1; mounted = False; close_failed = False
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
            if opened != fd and not safe_close(opened): close_failed = True
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
        cleanup = status("error", errno.EIO) if close_failed else status("ok")
        if mounted:
            cleanup = umount_call(target)
        if fd >= 0 and not safe_close(fd):
            cleanup = status("error", errno.EIO)
        result["cleanup"] = cleanup
def empty_map_case(created: str, zero: bool, key: str, setup: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "setup": setup or status("error", errno.ECHILD),
        "proc_mount_created_in": created,
        "capability_sets_zero": zero,
        "maps_read": status("blocked", blocked_by=key + ".setup"),
        "executable_mappings_selected": 0,
        "map_files_opened": 0,
        "first_open_failure": None,
        "all_opened_descriptors_closed": True,
    }
FIXED_CASE_HELPER = 'import ctypes,errno,fcntl,json,os,re,sys\nparent=os.getppid();c0=ctypes.CDLL(None,use_errno=True)\nif c0.prctl(1,9,0,0,0) or os.getppid()!=parent:os._exit(125)\nclass F(ctypes.Structure):_fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint32)]\nclass P(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(F))]\ndef s(state,number=None,blocked_by=None):return {"state":state,"errno":number,"blocked_by":blocked_by}\ndef e(number):\n return s("unsupported",number) if number in (38,95) else s("denied",number) if number in (1,13) else s("error",number)\ndef filter_now():\n c=ctypes.CDLL(None,use_errno=True)\n if c.prctl(38,1,0,0,0):return e(ctypes.get_errno() or 5)\n deny=(41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,288,299,307,425,426,427)\n rows=[F(0x20,0,0,4),F(0x15,1,0,0xc000003e),F(0x06,0,0,0x80000000),F(0x20,0,0,0)]\n for n in deny:rows.extend((F(0x15,0,1,n),F(0x06,0,0,0x50000|1)))\n rows.append(F(0x06,0,0,0x7fff0000));a=(F*len(rows))(*rows);p=P(len(rows),a)\n if c.syscall(317,1,0,ctypes.byref(p))==-1:return e(ctypes.get_errno() or 5)\n return s("ok")\ndef zero():\n try:\n  data=open("/proc/self/status","rb",buffering=0).read(65537)\n except OSError:return False\n found={}\n for line in data.splitlines():\n  if b":" in line:\n   k,v=line.split(b":",1)\n   if k in (b"CapInh",b"CapPrm",b"CapEff",b"CapBnd",b"CapAmb"):found[k]=v.strip()\n return len(data)<=65536 and len(found)==5 and all(v and set(v)=={48} for v in found.values())\ndef maps(created,root,key):\n out={"setup":s("ok"),"proc_mount_created_in":created,"capability_sets_zero":zero(),"maps_read":s("blocked",blocked_by=key+".setup"),"executable_mappings_selected":0,"map_files_opened":0,"first_open_failure":None,"all_opened_descriptors_closed":True}\n try:\n  raw=open(root+"/self/maps","rb",buffering=0).read(1048577);lines=raw.splitlines()\n  if len(raw)>1048576 or len(lines)>4096:out["maps_read"]=s("mismatch");return out\n  selected=[]\n  for line in lines:\n   p=line.split(None,5)\n   if len(p)>=5 and b"x" in p[1] and p[4]!=b"0":\n    if not re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+",p[0]):out["maps_read"]=s("mismatch");return out\n    selected.append(p[0])\n    if len(selected)==8:break\n  out["maps_read"]=s("ok");out["executable_mappings_selected"]=len(selected)\n  for address in selected:\n   fd=-1\n   try:\n    fd=os.open(os.fsencode(root+"/self/map_files/")+address,os.O_RDONLY|os.O_CLOEXEC)\n   except OSError as x:\n    if out["first_open_failure"] is None:out["first_open_failure"]=e(x.errno or 5)\n   finally:\n    if fd>=0:\n     try:os.close(fd);out["map_files_opened"]+=1\n     except OSError as x:out["all_opened_descriptors_closed"]=False;out["first_open_failure"]=out["first_open_failure"] or e(x.errno or 5)\n  return out\n except OSError as x:out["maps_read"]=e(x.errno or 5);return out\ndef drop():\n c=ctypes.CDLL(None,use_errno=True)\n class H(ctypes.Structure):_fields_=[("version",ctypes.c_uint32),("pid",ctypes.c_int)]\n class D(ctypes.Structure):_fields_=[("effective",ctypes.c_uint32),("permitted",ctypes.c_uint32),("inheritable",ctypes.c_uint32)]\n for n in range(64):c.prctl(24,n,0,0,0)\n c.prctl(47,4,0,0,0)\n if c.capset(ctypes.byref(H(0x20080522,0)),ctypes.byref((D*2)())):return e(ctypes.get_errno() or 5)\n return s("ok") if zero() else s("mismatch")\ndef ids(root="/proc"):\n out={"uid_map_status":s("blocked",blocked_by="namespaces.user_direct_root.create"),"gid_map_status":s("blocked",blocked_by="namespaces.user_direct_root.create"),"exact_root_mapping":None,"setgroups":"unexpected"};seen=[]\n for name in ("uid_map","gid_map"):\n  try:\n   raw=open(root+"/self/"+name,"rb",buffering=0).read(4097);rows=[]\n   for line in raw.splitlines():\n    row=[int(v) for v in line.split()]\n    if len(row)!=3 or len(rows)==5 or any(v<0 or v>4294967295 for v in row):raise ValueError\n    rows.append(row)\n   if len(raw)>4096 or not rows:raise ValueError\n   exact=len(rows)==1 and rows[0][0]==0 and rows[0][2]==1\n   out[name+"_status"]=s("ok") if exact else s("mismatch");seen.append(exact)\n  except OSError as x:out[name+"_status"]=e(x.errno or 5);seen.append(None)\n  except ValueError:out[name+"_status"]=s("mismatch");seen.append(False)\n out["exact_root_mapping"]=None if None in seen else all(seen)\n try:\n  text=open(root+"/self/setgroups","rb",buffering=0).read(33).strip();out["setgroups"]=text.decode() if text in (b"allow",b"deny") else "unexpected"\n except FileNotFoundError:out["setgroups"]="absent"\n except OSError:pass\n return out\nsetup=filter_now()\nif setup["state"]!="ok":value={"setup":setup}\nelif len(sys.argv)!=2 or sys.argv[1] not in ("host-map","sudo-map","parent-userns","child-userns"):value={"setup":s("mismatch")}\nelif sys.argv[1]=="sudo-map":value={"map":maps("host","/proc","procfs.host_sudo_root")}\nelif sys.argv[1]=="host-map":\n try:ro=bool(os.statvfs("/proc").f_flag&os.ST_RDONLY)\n except OSError:ro=None\n value={"map":maps("host","/proc","procfs.host_runner"),"read_only":ro}\nelse:\n created=sys.argv[1];root="/tmp/cogs-runner-capability-probe/proc" if created=="child-userns" else "/proc";prefix="procfs.child_owned_proc" if created=="child-userns" else "procfs.child_userns_parent_proc";before=maps(created,root,prefix+"_before_cap_drop");d=drop()\n if d["state"]=="ok":after=maps(created,root,prefix+"_after_cap_drop")\n else:after={"setup":d,"proc_mount_created_in":created,"capability_sets_zero":False,"maps_read":s("blocked",blocked_by=prefix+"_after_cap_drop.setup"),"executable_mappings_selected":0,"map_files_opened":0,"first_open_failure":None,"all_opened_descriptors_closed":True}\n try:ro=bool(os.statvfs(root).f_flag&os.ST_RDONLY)\n except OSError:ro=None\n try:distinct=os.stat(root).st_dev!=os.stat("/proc").st_dev if created=="child-userns" else False\n except OSError:distinct=None\n value={"maps":{"before":before,"after":after,"drop":d},"ids":ids(root),"pid_one":os.getpid()==1,"proc_read_only":ro,"proc_distinct":distinct}\nos.write(1,(json.dumps(value,sort_keys=True,separators=(",",":"))+"\\n").encode())\n'
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
        return status("ok"), {"setup": setup}
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
    if created["state"] != "ok": return result
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC); pid = os.fork()
    if pid == 0:
        safe_close(read_fd); parent = os.getppid()
        if PRCTL(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent: os._exit(125)
        is_one = os.getpid() == 1; nspid_one = False
        try:
            with open("/proc/self/status", "rb", buffering=0) as handle: raw = handle.read(65_537)
            for line in raw.splitlines():
                if line.startswith(b"NSpid:"):
                    fields = line.split()[1:]; nspid_one = bool(fields) and fields[-1] == b"1"
        except OSError: pass
        os.write(write_fd, bytes((is_one, nspid_one))); safe_close(write_fd); os._exit(0)
    safe_close(write_fd); os.set_blocking(read_fd, False); payload = b""; code = None
    start = process_start(pid); session = os.getsid(pid); end = time.monotonic() + 2.0
    while time.monotonic() < end:
        try: payload += os.read(read_fd, 3 - len(payload))
        except BlockingIOError: pass
        waited, wait_status = os.waitpid(pid, os.WNOHANG)
        if waited == pid: code = os.waitstatus_to_exitcode(wait_status); break
        time.sleep(0.002)
    if code is None and start is not None and process_start(pid) == start and os.getsid(pid) == session:
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass
        limit = time.monotonic() + 0.25
        while time.monotonic() < limit:
            waited, wait_status = os.waitpid(pid, os.WNOHANG)
            if waited == pid: code = os.waitstatus_to_exitcode(wait_status); break
            time.sleep(0.002)
    safe_close(read_fd)
    if code == 0 and len(payload) == 2:
        result["child_is_namespace_pid_1"] = payload[0] == 1; result["nspid_final_component_is_1"] = payload[1] == 1
        if not all((result["child_is_namespace_pid_1"], result["nspid_final_component_is_1"])): result["create"] = status("mismatch")
    else: result["create"] = status("error", errno.EIO)
    return result
def sudo_descriptor_case(close_from: int, ledger: Ledger) -> dict[str, Any]:
    if not ledger.can_effect(): return empty_sudo_close(close_from, upstream=status("error", errno.ETIMEDOUT))
    helper = FIXED_CHILD_FILTER + "import fcntl,os\nv=[]\nfor n in (3,4):\n try:fcntl.fcntl(n,fcntl.F_GETFD);v.append(1)\n except OSError:v.append(0)\nos._exit(40+v[0]+2*v[1])\n"
    try:
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC); ledger.track_fd(gate_read); ledger.track_fd(gate_write); pid = os.fork()
    except OSError as exc:
        if "gate_read" in locals(): ledger.close_fd(gate_read)
        if "gate_write" in locals(): ledger.close_fd(gate_write)
        return empty_sudo_close(close_from, upstream=from_errno(exc.errno or errno.EIO))
    if pid == 0:
        safe_close(gate_write); child_boundary(gate_read)
        if os.read(gate_read, 1) != b"G": os._exit(124)
        safe_close(gate_read); null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        for target in (3, 4): os.dup2(null, target, inheritable=True)
        if null not in (3, 4): safe_close(null)
        argv = [SUDO, "-n", f"--close-from={close_from}", "--", PYTHON, "-I", "-c", helper]
        try: os.execve(SUDO, argv, {})
        except OSError: os._exit(127)
    child = ledger.register_child(pid); ledger.close_fd(gate_read)
    if child is None: ledger.close_fd(gate_write); return empty_sudo_close(close_from, upstream=status("error", errno.EIO))
    try:
        if not ledger.can_effect(): raise OSError(errno.ETIMEDOUT, "release barred")
        os.write(gate_write, b"G")
    except OSError: ledger.uncertainty = True; ledger.stop(child, ledger.deadline)
    ledger.close_fd(gate_write)
    end = min(ledger.deadline, time.monotonic() + CASE_SECONDS); code = None
    while time.monotonic() < end:
        code = ledger.poll(child)
        if code is not None: break
        time.sleep(0.003)
    if code is None: code = ledger.stop(child, ledger.deadline); ledger.uncertainty = True
    decoded = code is not None and 40 <= code <= 43
    present3 = bool((code - 40) & 1) if decoded else None; present4 = bool((code - 40) & 2) if decoded else None
    fields = (not present3, not present4) if decoded and close_from == 3 else (present3, not present4) if decoded else (None, None)
    invocation = status("ok") if decoded and all(fields) else status("mismatch") if decoded else status("error", errno.ETIMEDOUT if code is None else errno.EIO)
    names = ("fd3_closed", "fd4_closed") if close_from == 3 else ("fd3_preserved", "fd4_closed")
    return {"invocation": invocation, names[0]: fields[0], names[1]: fields[1], "exit_code": code if code is not None and 0 <= code <= 255 else None}
def descriptor_exec_case(ledger: Ledger) -> dict[str, Any]:
    empty = lambda invocation: {"invocation": invocation, "non_cloexec_fd_198_survived": None, "cloexec_fd_199_closed": None}
    if not ledger.can_effect(): return empty(status("error", errno.ETIMEDOUT))
    helper = FIXED_CHILD_FILTER + "import fcntl,json,os\ndef p(n):\n try:fcntl.fcntl(n,fcntl.F_GETFD);return True\n except OSError:return False\nos.write(3,json.dumps({'a':p(198),'b':p(199)},sort_keys=True,separators=(',',':')).encode())\n"
    try:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC); gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        for fd in (read_fd, write_fd, gate_read, gate_write): ledger.track_fd(fd)
        pid = os.fork()
    except OSError as exc:
        for name in ("read_fd", "write_fd", "gate_read", "gate_write"):
            if name in locals(): ledger.close_fd(locals()[name])
        return empty(from_errno(exc.errno or errno.EIO))
    if pid == 0:
        safe_close(read_fd); safe_close(gate_write); child_boundary((write_fd, gate_read))
        if os.read(gate_read, 1) != b"G": os._exit(124)
        safe_close(gate_read); os.dup2(write_fd, 3, inheritable=True)
        if write_fd != 3: safe_close(write_fd)
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        for target in (198, 199): os.dup2(null, target, inheritable=target == 198)
        if null not in (198, 199): safe_close(null)
        try: os.execve(PYTHON, [PYTHON, "-I", "-c", helper], {})
        except OSError: os._exit(127)
    child = ledger.register_child(pid); ledger.close_fd(write_fd); ledger.close_fd(gate_read)
    if child is None:
        ledger.close_fd(gate_write); ledger.close_fd(read_fd); return empty(status("error", errno.EIO))
    try:
        if not ledger.can_effect(): raise OSError(errno.ETIMEDOUT, "release barred")
        os.write(gate_write, b"G")
    except OSError: ledger.uncertainty = True; ledger.stop(child, ledger.deadline)
    ledger.close_fd(gate_write)
    os.set_blocking(read_fd, False); end = min(ledger.deadline, time.monotonic() + CASE_SECONDS); data = bytearray(); code = None
    while time.monotonic() < end:
        try:
            chunk = os.read(read_fd, MAX_OUTPUT + 1 - len(data))
            if chunk: data.extend(chunk)
        except BlockingIOError: pass
        code = ledger.poll(child)
        if code is not None or len(data) > MAX_OUTPUT: break
        time.sleep(0.003)
    if code is None: code = ledger.stop(child, ledger.deadline); ledger.uncertainty = True
    ledger.close_fd(read_fd)
    if code != 0 or len(data) > MAX_OUTPUT: return empty(status("error", errno.ETIMEDOUT if code is None else errno.EOVERFLOW if len(data) > MAX_OUTPUT else errno.EIO))
    try:
        parsed = json.loads(bytes(data))
        if not isinstance(parsed, dict) or set(parsed) != {"a", "b"} or not all(isinstance(value, bool) for value in parsed.values()): raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError): return empty(status("error", errno.EPROTO))
    survived, closed = parsed["a"], not parsed["b"]
    return {"invocation": status("ok") if survived and closed else status("mismatch"), "non_cloexec_fd_198_survived": survived, "cloexec_fd_199_closed": closed}
def close_range_case(target: int) -> dict[str, Any]:
    result = {
        "syscall_number_amd64": SYS_CLOSE_RANGE,
        "flags": 0,
        "first": target,
        "last": target,
        "invocation": status("blocked", blocked_by="rlimit_nofile.high_fd_4096_status"),
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
        if base >= 0 and not safe_close(base): result["invocation"] = status("error", errno.EIO)
        if duplicate >= 0 and not safe_close(duplicate): result["invocation"] = status("error", errno.EIO)
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
    if initial_status["state"] == "ok" and initial_mode not in (0, 1, 2): initial_status = status("error", errno.EIO)
    if nnp_status["state"] == "ok" and initial_nnp not in (0, 1): nnp_status = status("error", errno.EIO)
    result = {
        "initial_mode_status": initial_status,
        "initial_mode": initial_mode if initial_status["state"] == "ok" and initial_mode in (0, 1, 2) else None,
        "initial_no_new_privs_status": nnp_status,
        "initial_no_new_privs": initial_nnp if nnp_status["state"] == "ok" and initial_nnp in (0, 1) else None,
        "set_no_new_privs": status("blocked", blocked_by="seccomp.initial_mode_status" if initial_status["state"] != "ok" else "seccomp.initial_no_new_privs_status"),
        "install_filter": status("blocked", blocked_by="seccomp.set_no_new_privs"),
        "final_mode": None,
        "network_syscalls_policy": "filter-unavailable",
    }
    if initial_status["state"] != "ok" or nnp_status["state"] != "ok": return result
    ctypes.set_errno(0)
    nnp_err = call_errno(PRCTL(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    result["set_no_new_privs"] = from_errno(nnp_err) if nnp_err else status("ok")
    if nnp_err: return result
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
    if seccomp_err: return result
    final_status, final_mode = prctl_value(PR_GET_SECCOMP)
    if final_status["state"] == "ok" and final_mode in (0, 1, 2): result["final_mode"] = final_mode
    if not seccomp_err and final_status["state"] != "ok": result["install_filter"] = status("error", errno.EIO)
    elif not seccomp_err and final_mode == 2: result["network_syscalls_policy"] = "fixed-eperm-filter-installed"
    elif not seccomp_err: result["install_filter"] = status("mismatch")
    return result
def kvm_case() -> dict[str, Any]:
    result = {
        "device_present": False,
        "character_device": None,
        "open_read_write": status("unsupported"),
        "get_api_version": status("blocked", blocked_by="kvm.open_read_write"),
        "api_version": None,
        "check_extension_user_memory": status("blocked", blocked_by="kvm.open_read_write"),
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
        if not safe_close(fd):
            result["open_read_write"] = status("error", errno.EIO)
            result["get_api_version"] = status("blocked", blocked_by="kvm.open_read_write")
            result["api_version"] = None
            result["check_extension_user_memory"] = status("blocked", blocked_by="kvm.open_read_write")
            result["user_memory_extension"] = None
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
    if pull_request > 2_147_483_647: raise ValueError("invalid public control")
    if head_repository != repository or checkout != pr_head:
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
    """Create exact names while retaining the private parent and /tmp authority."""
    if not ledger.can_effect(): return False
    try:
        ledger.tmp_fd = ledger.track_fd(os.open("/tmp", O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
        ledger.tmp_identity = generation(os.fstat(ledger.tmp_fd))[:5]
        os.mkdir("cogs-runner-capability-probe", 0o700, dir_fd=ledger.tmp_fd)
        ledger.private_identity = generation(os.stat("cogs-runner-capability-probe", dir_fd=ledger.tmp_fd, follow_symlinks=False))[:5]
        ledger.private_fd = ledger.track_fd(os.open("cogs-runner-capability-probe", O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=ledger.tmp_fd))
        info = os.fstat(ledger.private_fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError(errno.EPERM, "private parent policy")
        for name in ("runner-temp", "private-tmpfs", "opath-root", "proc"):
            if not ledger.can_effect(): raise OSError(errno.ETIMEDOUT, "new acquisition barred")
            os.mkdir(name, 0o700, dir_fd=ledger.private_fd)
            ledger.private_children[name] = generation(os.stat(name, dir_fd=ledger.private_fd, follow_symlinks=False))[:5]
        return True
    except OSError:
        ledger.uncertainty = True
        cleanup_private_parent(ledger)
        return False
def cleanup_private_parent(ledger: Ledger) -> None:
    """Remove only the retained generation and exact fd-relative names."""
    if ledger.private_fd >= 0:
        for name in ("proc", "opath-root", "private-tmpfs", "runner-temp"):
            identity = ledger.private_children.get(name)
            if identity is None: continue
            try:
                if generation(os.stat(name, dir_fd=ledger.private_fd, follow_symlinks=False))[:5] != identity:
                    raise OSError(errno.ESTALE, "replaced private child")
                os.rmdir(name, dir_fd=ledger.private_fd)
                del ledger.private_children[name]
            except OSError:
                ledger.temporary_names_gone = False; ledger.uncertainty = True
        try:
            current = os.stat("cogs-runner-capability-probe", dir_fd=ledger.tmp_fd, follow_symlinks=False)
            if generation(os.fstat(ledger.private_fd))[:5] != ledger.private_identity or generation(current)[:5] != ledger.private_identity:
                raise OSError(errno.ESTALE, "replaced private parent")
            os.rmdir("cogs-runner-capability-probe", dir_fd=ledger.tmp_fd)
        except OSError:
            ledger.temporary_names_gone = False; ledger.uncertainty = True
        ledger.close_fd(ledger.private_fd); ledger.private_fd = -1
    elif ledger.tmp_fd >= 0 and ledger.private_identity is not None:
        try:
            current = os.stat("cogs-runner-capability-probe", dir_fd=ledger.tmp_fd, follow_symlinks=False)
            if generation(current)[:5] != ledger.private_identity: raise OSError(errno.ESTALE, "replaced private parent")
            os.rmdir("cogs-runner-capability-probe", dir_fd=ledger.tmp_fd)
        except OSError: ledger.temporary_names_gone = False; ledger.uncertainty = True
    if ledger.tmp_fd >= 0:
        if generation(os.fstat(ledger.tmp_fd))[:5] != ledger.tmp_identity:
            ledger.temporary_names_gone = False; ledger.uncertainty = True
        ledger.close_fd(ledger.tmp_fd); ledger.tmp_fd = -1
def user_namespace_invocation(ledger: Ledger, combined: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    arguments = [UNSHARE, "--user", "--map-user=0", "--map-group=0"]
    if combined:
        arguments.extend(("--mount", "--pid", "--fork", f"--mount-proc={PRIVATE_PARENT}/proc"))
        created = "child-userns"
    else:
        created = "parent-userns"
    arguments.extend((PYTHON, "-I", "-c", FIXED_CASE_HELPER, created))
    command = ledger.run(tuple(arguments), NS_SECONDS)
    return parse_internal_output(command, {"maps", "ids", "pid_one", "proc_read_only", "proc_distinct"})
def sudo_noninteractive_and_maps(ledger: Ledger) -> tuple[dict[str, Any], dict[str, Any] | None]:
    command = ledger.run(
        (SUDO, "-n", "--", PYTHON, "-I", "-", "sudo-map"),
        input_bytes=FIXED_CASE_HELPER.encode("utf-8"),
    )
    return parse_internal_output(command, {"map"})
def probe_linux() -> dict[str, Any]:
    global ACTIVE_LEDGER
    baseline = fd_snapshot(); ledger = Ledger(time.monotonic() + GLOBAL_SECONDS, baseline, generation(os.stat("."))); ACTIVE_LEDGER = ledger
    source, envelope = source_and_envelope_metadata(); uname = os.uname()
    release_ok = bool(re.fullmatch(r"[ -~]{1,128}", uname.release)); linux_amd64 = uname.sysname == "Linux" and uname.machine == "x86_64"
    if not linux_amd64 or not release_ok: raise RuntimeError("unsupported bootstrap host")
    kernel = {"sysname": "Linux", "release": uname.release, "machine": "x86_64", "uname_status": status("ok")}
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE); ledger.transition("BASELINED"); ledger.transition("RUNNING")
    if PRCTL(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0): raise RuntimeError("subreaper unavailable")
    identities = {name: fixed_identity(path, ledger) for name, path in (("python3", PYTHON), ("gzip", GZIP), ("zstd", ZSTD), ("unshare", UNSHARE))}
    if identities["python3"]["observation"]["state"] != "ok": raise RuntimeError("bootstrap identity unavailable")
    sudo_identity = fixed_identity(SUDO, ledger); private_ready = create_private_parent(ledger)
    if private_ready:
        _, runner_payload = ledger.fork_case(lambda: tmpfile_case(f"{PRIVATE_PARENT}/runner-temp")); runner_tmp = runner_payload or empty_tmpfile_case(blocked=True)
        _, mount_batch = ledger.fork_case(mount_namespace_batch, NS_SECONDS)
    else:
        runner_tmp = empty_tmpfile_case(blocked=True); mount_batch = None
    mount_payload = mount_batch["private"] if mount_batch else None; mount_ns = mount_batch["namespace"] if mount_batch else {"create": status("error", errno.ECHILD), "distinct_from_parent": None}
    if mount_payload:
        private_tmp, same_opath, across_opath = mount_payload["private_tmpfs"], mount_payload["same"], mount_payload["across"]
        if not mount_payload["mounts_gone"]: ledger.mounts_gone = False; ledger.uncertainty = True
    else:
        private_tmp, same_opath, across_opath = empty_tmpfile_case(blocked=True, private=True), empty_opath_case(True), empty_opath_case(True, across=True)
    exec_case = descriptor_exec_case(ledger); _, close_payload = ledger.fork_case(lambda: {"low": close_range_case(198), "high": close_range_case(4096)})
    low = close_payload["low"] if close_payload else close_range_case_shape(198, status("error", errno.ECHILD))
    high = close_payload["high"] if close_payload else close_range_case_shape(4096, status("error", errno.ECHILD))
    _, network_payload = ledger.fork_case(lambda: basic_namespace("network")); _, pid_payload = ledger.fork_case(pid_namespace_case, NS_SECONDS)
    network = network_payload or {"create": status("error", errno.ECHILD), "distinct_from_parent": None}
    pid_ns = pid_payload or {"create": status("error", errno.ECHILD), "child_is_namespace_pid_1": None, "nspid_final_component_is_1": None}
    host_status, host_payload = parse_internal_output(ledger.run((PYTHON, "-I", "-c", FIXED_CASE_HELPER, "host-map")), {"map", "read_only"})
    host_map = host_payload["map"] if host_payload and "map" in host_payload else empty_map_case("host", False, "procfs.host_runner", host_payload["setup"] if host_payload else host_status)
    if sudo_identity["observation"]["state"] == "ok": sudo_noninteractive, sudo_payload = sudo_noninteractive_and_maps(ledger)
    else: sudo_noninteractive, sudo_payload = status("blocked", blocked_by="sudo.executable.observation"), None
    sudo_map = sudo_payload["map"] if sudo_payload and "map" in sudo_payload else empty_map_case("host", False, "procfs.host_sudo_root", sudo_payload["setup"] if sudo_payload else status("blocked", blocked_by="sudo.noninteractive"))
    user_ready = private_ready and identities["unshare"]["observation"]["state"] == "ok"
    user_failure = status("blocked", blocked_by="tools.unshare.observation") if private_ready else status("error", errno.EIO)
    user_create, user_payload = user_namespace_invocation(ledger, False) if user_ready else (user_failure, None)
    combined_create, combined_payload = user_namespace_invocation(ledger, True) if user_ready else (user_failure, None)
    blocked_user = status("blocked", blocked_by="namespaces.user_direct_root.create")
    if user_payload and "maps" in user_payload: user_maps, ids = user_payload["maps"], user_payload["ids"]
    else:
        user_maps = {"before": empty_map_case("parent-userns", False, "procfs.child_userns_parent_proc_before_cap_drop", blocked_user), "after": empty_map_case("parent-userns", True, "procfs.child_userns_parent_proc_after_cap_drop", blocked_user), "drop": blocked_user}
        ids = {"uid_map_status": blocked_user, "gid_map_status": blocked_user, "exact_root_mapping": None, "setgroups": "unexpected"}
    if combined_payload and "maps" in combined_payload and combined_payload.get("pid_one") is not True: combined_create = status("mismatch")
    blocked_combined = status("blocked", blocked_by="namespaces.combined_user_mount_pid_fork.create")
    child_maps = combined_payload["maps"] if combined_payload and "maps" in combined_payload else {"before": empty_map_case("child-userns", False, "procfs.child_owned_proc_before_cap_drop", blocked_combined), "after": empty_map_case("child-userns", True, "procfs.child_owned_proc_after_cap_drop", blocked_combined), "drop": blocked_combined}
    _, seccomp_payload = ledger.fork_case(seccomp_case)
    seccomp_result = seccomp_payload or {"initial_mode_status": status("error", errno.ECHILD), "initial_mode": None, "initial_no_new_privs_status": status("error", errno.ECHILD), "initial_no_new_privs": None, "set_no_new_privs": status("blocked", blocked_by="seccomp.initial_mode_status"), "install_filter": status("blocked", blocked_by="seccomp.set_no_new_privs"), "final_mode": None, "network_syscalls_policy": "filter-unavailable"}
    close3 = sudo_descriptor_case(3, ledger) if sudo_identity["observation"]["state"] == "ok" else empty_sudo_close(3)
    close4 = sudo_descriptor_case(4, ledger) if sudo_identity["observation"]["state"] == "ok" else empty_sudo_close(4)
    _, kvm_payload = ledger.fork_case(kvm_case)
    kvm = kvm_payload or {"device_present": False, "character_device": None, "open_read_write": status("error", errno.ECHILD), "get_api_version": status("blocked", blocked_by="kvm.open_read_write"), "api_version": None, "check_extension_user_memory": status("blocked", blocked_by="kvm.open_read_write"), "user_memory_extension": None}
    ledger.transition("CLEANING")
    if any(case["cleanup"]["state"] != "ok" for case in (runner_tmp, private_tmp, same_opath, across_opath)): ledger.uncertainty = True
    maps = (host_map, sudo_map, user_maps["before"], user_maps["after"], child_maps["before"], child_maps["after"])
    if any(not case["all_opened_descriptors_closed"] for case in maps): ledger.uncertainty = True
    cleanup_private_parent(ledger)
    if resource.getrlimit(resource.RLIMIT_NOFILE) != (soft, hard):
        try: resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        except OSError: ledger.uncertainty = True
    ledger.descriptors_restored = not ledger.tracked_fds and fd_snapshot() == ledger.fd_baseline
    if not ledger.descriptors_restored or generation(os.stat(".")) != ledger.cwd_baseline: ledger.uncertainty = True
    cleanup = {"children_reaped": ledger.children_reaped and not ledger.live_children, "descriptors_restored": ledger.descriptors_restored, "mounts_gone": ledger.mounts_gone, "temporary_names_gone": ledger.temporary_names_gone and not ledger.private_children, "namespace_handles_retained": False, "uncertainty": ledger.uncertainty}
    complete = all(cleanup[name] for name in ("children_reaped", "descriptors_restored", "mounts_gone", "temporary_names_gone")) and not cleanup["uncertainty"]
    high_possible = hard == resource.RLIM_INFINITY or hard >= 4097
    report = {
        "schema": SCHEMA, "authority": "none", "qualified": False, "outcome": "complete" if complete else "incomplete", "source": source, "envelope": envelope,
        "runner": runner_metadata(), "kernel": kernel,
        "rlimit_nofile": {"soft": limit_value(soft), "hard": limit_value(hard), "high_fd_4096_possible": high_possible, "high_fd_4096_status": status("ok") if high_possible else status("unsupported")},
        "sudo": {"executable": sudo_identity, "noninteractive": sudo_noninteractive, "close_from_3": close3, "close_from_4": close4},
        "descriptors": {"exec_cloexec": exec_case, "close_range_low": low, "close_range_high": high, "inherited_baseline_restored": ledger.descriptors_restored},
        "temporary_files": {"runner_temp": runner_tmp, "private_tmpfs": private_tmp}, "opath": {"same_mount_namespace": same_opath, "across_mount_namespace": across_opath},
        "namespaces": {"network": network, "mount": mount_ns, "pid": pid_ns, "user_direct_root": {"create": user_create, **ids}, "combined_user_mount_pid_fork": {"create": combined_create, "child_is_namespace_pid_1": combined_payload.get("pid_one") if combined_payload and "maps" in combined_payload else None, "proc_mount": combined_payload["maps"]["before"]["maps_read"] if combined_payload and "maps" in combined_payload else blocked_combined, "cleanup": status("ok") if combined_payload and "maps" in combined_payload else blocked_combined}},
        "procfs": {"host_runner": host_map, "host_sudo_root": sudo_map, "child_userns_parent_proc_before_cap_drop": user_maps["before"], "child_userns_parent_proc_after_cap_drop": user_maps["after"], "child_owned_proc_before_cap_drop": child_maps["before"], "child_owned_proc_after_cap_drop": child_maps["after"], "parent_proc_read_only": host_payload.get("read_only") if host_payload and "map" in host_payload else None, "child_proc_read_only": combined_payload.get("proc_read_only") if combined_payload and "maps" in combined_payload else None, "child_proc_distinct_from_parent": combined_payload.get("proc_distinct") if combined_payload and "maps" in combined_payload else None, "child_proc_distinct_from_parent_status": (status("ok") if combined_payload and combined_payload.get("proc_distinct") is True else status("mismatch") if combined_payload and combined_payload.get("proc_distinct") is False else status("error", errno.EIO) if combined_payload and "maps" in combined_payload else blocked_combined), "child_proc_view_has_pid_1": combined_payload.get("pid_one") if combined_payload and "maps" in combined_payload else None},
        "seccomp": seccomp_result, "kvm": kvm, "tools": identities, "cleanup": cleanup,
    }
    validate_report(report); ledger.transition("COMPLETE" if complete else "POISONED")
    if ledger.state == "POISONED": ledger.transition("FAILED")
    ACTIVE_LEDGER = None; return report
def close_range_case_shape(target: int, invocation: dict[str, Any]) -> dict[str, Any]:
    observed = True if invocation["state"] == "ok" else None
    return {"syscall_number_amd64": SYS_CLOSE_RANGE, "flags": 0, "first": target, "last": target, "invocation": invocation, "known_fd_closed": observed}
def empty_sudo_close(close_from: int, prerequisite: str = "sudo.executable.observation", upstream: Any = None) -> dict[str, Any]:
    fields = {"fd3_closed": None, "fd4_closed": None} if close_from == 3 else {"fd3_preserved": None, "fd4_closed": None}
    return {"invocation": upstream or status("blocked", blocked_by=prerequisite), **fields, "exit_code": None}
def validate_status(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"blocked_by", "errno", "state"}: raise ValueError("invalid status shape")
    state, number, prerequisite = value["state"], value["errno"], value["blocked_by"]
    if state == "blocked": valid = number is None and prerequisite in BLOCKED_BY
    elif prerequisite is not None: valid = False
    elif state in {"ok", "mismatch"}: valid = number is None
    elif state == "unsupported": valid = number is None or number in (errno.ENOSYS, errno.EOPNOTSUPP)
    elif state == "denied": valid = number in (errno.EPERM, errno.EACCES)
    elif state == "error": valid = isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= 4095 and number not in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES)
    else: valid = False
    if not valid: raise ValueError("invalid status coupling")
def validate_observation(operation: dict[str, Any], fields: tuple[Any, ...]) -> None:
    validate_status(operation); state = operation["state"]
    if state == "ok" and not all(value is True for value in fields): raise ValueError("successful operation lacks postcondition")
    if state == "mismatch" and (not fields or any(value is None for value in fields) or not any(value is False for value in fields)): raise ValueError("mismatch lacks false postcondition")
    if state not in {"ok", "mismatch"} and any(value is not None for value in fields): raise ValueError("unobserved postcondition")
def require_blocked(operation: dict[str, Any], prerequisite: str) -> None:
    if operation["state"] != "blocked" or operation["blocked_by"] != prerequisite: raise ValueError("downstream prerequisite coupling")
def validate_report(report: dict[str, Any]) -> None:
    """Validate every fixed status/prerequisite/postcondition relationship."""
    if report.get("authority") != "none" or report.get("qualified") is not False: raise ValueError("authority expansion")
    source, envelope = report.get("source", {}), report.get("envelope", {})
    if set(source) != {"pr_head_sha", "checkout_sha", "driver_sha256", "schema_sha256", "source_head_workflow_blob_sha256"} or source["checkout_sha"] != source["pr_head_sha"]: raise ValueError("source contract")
    if set(envelope) != {"repository", "workflow", "job", "event", "action", "run_id", "run_attempt", "pull_request_number", "base_sha", "github_sha", "github_workflow_sha", "event_merge_sha"}: raise ValueError("envelope contract")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", envelope["run_id"]) or envelope["run_attempt"] != 1 or not isinstance(envelope["pull_request_number"], int) or isinstance(envelope["pull_request_number"], bool) or not 1 <= envelope["pull_request_number"] <= 2_147_483_647: raise ValueError("envelope numeric domain")
    statuses = 0; blocked_paths: list[str] = []
    def visit(value: Any) -> None:
        nonlocal statuses
        if isinstance(value, dict):
            if set(value) == {"blocked_by", "errno", "state"}:
                validate_status(value); statuses += 1
                if value["state"] == "blocked": blocked_paths.append(value["blocked_by"])
            else:
                if "uid_map" in value or "gid_map" in value: raise ValueError("numeric ID map disclosure")
                for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(report)
    if statuses < 40: raise ValueError("unclassified report")
    for path in blocked_paths:
        prerequisite: Any = report
        for component in path.split("."): prerequisite = prerequisite[component]
        validate_status(prerequisite)
        if prerequisite["state"] == "ok": raise ValueError("blocked by successful prerequisite")
    if report["runner"]["image_metadata_status"]["state"] != "ok" or report["kernel"]["uname_status"]["state"] != "ok": raise ValueError("bootstrap metadata coupling")
    cleanup = report["cleanup"]; exact = all(cleanup[name] is True for name in ("children_reaped", "descriptors_restored", "mounts_gone", "temporary_names_gone")) and cleanup["namespace_handles_retained"] is False and cleanup["uncertainty"] is False
    if report["outcome"] != ("complete" if exact else "incomplete") or report["descriptors"]["inherited_baseline_restored"] != cleanup["descriptors_restored"]: raise ValueError("outcome/cleanup coupling")
    for identity in [report["sudo"]["executable"], *report["tools"].values()]:
        state = identity["observation"]["state"]; metadata = tuple(identity[name] for name in ("regular_file", "root_owned", "mode", "size", "sha256"))
        if state == "ok" and (not identity["present"] or metadata[:2] != (True, True) or any(value is None for value in metadata[2:])): raise ValueError("tool identity coupling")
        if not identity["present"] and (state != "unsupported" or any(value is not None for value in metadata)): raise ValueError("absent tool coupling")
    if not report["tools"]["python3"]["present"] or report["tools"]["python3"]["observation"]["state"] != "ok": raise ValueError("bootstrap Python")
    high = report["rlimit_nofile"]; validate_status(high["high_fd_4096_status"])
    if (high["high_fd_4096_status"]["state"] == "ok") != high["high_fd_4096_possible"]: raise ValueError("rlimit coupling")
    sudo = report["sudo"]
    validate_status(sudo["noninteractive"])
    for name, fields, expected in (("close_from_3", ("fd3_closed", "fd4_closed"), 40), ("close_from_4", ("fd3_preserved", "fd4_closed"), 41)):
        case = sudo[name]; validate_observation(case["invocation"], tuple(case[field] for field in fields))
        if case["invocation"]["state"] == "ok" and case["exit_code"] != expected: raise ValueError("sudo exit category")
        if case["invocation"]["state"] == "blocked" and case["exit_code"] is not None: raise ValueError("sudo unattempted exit")
    for name in ("close_range_low", "close_range_high"):
        case = report["descriptors"][name]; validate_observation(case["invocation"], (case["known_fd_closed"],))
    case = report["descriptors"]["exec_cloexec"]; validate_observation(case["invocation"], (case["non_cloexec_fd_198_survived"], case["cloexec_fd_199_closed"]))
    for name, case in report["temporary_files"].items():
        validate_observation(case["open_otmpfile"], (case["initial_nlink_zero"], case["owner_is_probe_identity"], case["initial_mode_0600"]))
        validate_observation(case["linkat_empty_path"], (case["linked_identity_matches"],)); validate_status(case["cleanup"])
        if case["open_otmpfile"]["state"] != "ok": require_blocked(case["linkat_empty_path"], f"temporary_files.{name}.open_otmpfile")
        if case["cleanup"]["state"] != "ok" and report["outcome"] == "complete": raise ValueError("tmpfile cleanup coupling")
    for name, case in report["opath"].items():
        validate_observation(case["open_opath_directory"], (case["fstat_stable"],)); validate_observation(case["bind_mount_from_proc_fd"], (case["bind_target_identity_matches"],)); validate_status(case["cleanup"])
        if case["open_opath_directory"]["state"] != "ok": require_blocked(case["bind_mount_from_proc_fd"], f"opath.{name}.open_opath_directory")
        if case["cleanup"]["state"] != "ok" and report["outcome"] == "complete": raise ValueError("O_PATH cleanup coupling")
    namespaces = report["namespaces"]
    for name in ("network", "mount"): validate_observation(namespaces[name]["create"], (namespaces[name]["distinct_from_parent"],))
    validate_observation(namespaces["pid"]["create"], (namespaces["pid"]["child_is_namespace_pid_1"], namespaces["pid"]["nspid_final_component_is_1"]))
    user = namespaces["user_direct_root"]; validate_status(user["create"])
    for prefix in ("uid", "gid"): validate_status(user[f"{prefix}_map_status"])
    exact_map = user["exact_root_mapping"]
    if all(user[f"{prefix}_map_status"]["state"] == "ok" for prefix in ("uid", "gid")):
        if exact_map is not True: raise ValueError("exact root-map coupling")
    elif exact_map is not None and not (exact_map is False and any(user[f"{prefix}_map_status"]["state"] == "mismatch" for prefix in ("uid", "gid"))): raise ValueError("unobserved root-map category")
    combined = namespaces["combined_user_mount_pid_fork"]; validate_observation(combined["create"], (combined["child_is_namespace_pid_1"],)); validate_status(combined["proc_mount"]); validate_status(combined["cleanup"])
    if combined["cleanup"]["state"] != "ok" and report["outcome"] == "complete": raise ValueError("namespace cleanup coupling")
    maps = report["procfs"]
    for key in ("host_runner", "host_sudo_root", "child_userns_parent_proc_before_cap_drop", "child_userns_parent_proc_after_cap_drop", "child_owned_proc_before_cap_drop", "child_owned_proc_after_cap_drop"):
        item = maps[key]; validate_status(item["setup"]); validate_status(item["maps_read"])
        expected_mount = "host" if key in {"host_runner", "host_sudo_root"} else "parent-userns" if "child_userns_parent" in key else "child-userns"
        if item["proc_mount_created_in"] != expected_mount: raise ValueError("proc mount category")
        if item["setup"]["state"] != "ok": require_blocked(item["maps_read"], key + ".setup")
        selected, opened, failure = item["executable_mappings_selected"], item["map_files_opened"], item["first_open_failure"]
        if item["maps_read"]["state"] == "ok":
            if not 0 <= opened <= selected <= 8 or (failure is None) != (opened == selected): raise ValueError("map count coupling")
            if failure is not None: validate_status(failure)
        elif selected or opened or failure is not None: raise ValueError("unobserved map count")
        if not item["all_opened_descriptors_closed"] and report["outcome"] == "complete": raise ValueError("map descriptor cleanup")
    proc_status = maps["child_proc_distinct_from_parent_status"]
    validate_observation(proc_status, (maps["child_proc_distinct_from_parent"],))
    seccomp = report["seccomp"]
    for status_name, value_name, allowed in (("initial_mode_status", "initial_mode", (0, 1, 2)), ("initial_no_new_privs_status", "initial_no_new_privs", (0, 1))):
        validate_status(seccomp[status_name]); value = seccomp[value_name]
        if (seccomp[status_name]["state"] == "ok") != (value in allowed if value is not None else False): raise ValueError("seccomp query coupling")
    validate_status(seccomp["set_no_new_privs"]); validate_status(seccomp["install_filter"])
    installed = seccomp["install_filter"]["state"] == "ok"
    if installed != (seccomp["set_no_new_privs"]["state"] == "ok" and seccomp["final_mode"] == 2 and seccomp["network_syscalls_policy"] == "fixed-eperm-filter-installed"): raise ValueError("seccomp installation coupling")
    if seccomp["install_filter"]["state"] not in {"ok", "mismatch"} and (seccomp["final_mode"] is not None or seccomp["network_syscalls_policy"] != "filter-unavailable"): raise ValueError("seccomp unobserved final state")
    if seccomp["set_no_new_privs"]["state"] != "ok" and seccomp["install_filter"]["state"] != "blocked": raise ValueError("seccomp prerequisite")
    kvm = report["kvm"]; validate_status(kvm["open_read_write"])
    if not kvm["device_present"] and (kvm["character_device"] is not None or kvm["open_read_write"]["state"] != "unsupported"): raise ValueError("KVM absence coupling")
    if (kvm["device_present"] and not isinstance(kvm["character_device"], bool)) or (kvm["open_read_write"]["state"] == "ok" and kvm["character_device"] is not True): raise ValueError("KVM type/open coupling")
    for status_name, value_name in (("get_api_version", "api_version"), ("check_extension_user_memory", "user_memory_extension")):
        operation, value = kvm[status_name], kvm[value_name]; validate_status(operation)
        if operation["state"] == "ok" and value is None or operation["state"] not in {"ok", "mismatch"} and value is not None: raise ValueError("KVM result coupling")
        if kvm["open_read_write"]["state"] != "ok": require_blocked(operation, "kvm.open_read_write")
def fake_report(inject_cleanup_failure: bool = False) -> dict[str, Any]:
    ok = status("ok")
    tool = lambda path: {"path": path, "present": True, "regular_file": True, "root_owned": True, "mode": "0755", "size": 1, "sha256": "1" * 64, "observation": ok}
    tmp = {"filesystem": "tmpfs", "open_otmpfile": ok, "initial_nlink_zero": True, "owner_is_probe_identity": True, "initial_mode_0600": True, "linkat_empty_path": ok, "linked_identity_matches": True, "cleanup": ok}
    opath = {"open_opath_directory": ok, "fstat_stable": True, "bind_mount_from_proc_fd": status("denied", errno.EPERM), "bind_target_identity_matches": None, "cleanup": ok}
    mapping = lambda created: {"setup": ok, "proc_mount_created_in": created, "capability_sets_zero": True, "maps_read": ok, "executable_mappings_selected": 1, "map_files_opened": 1, "first_open_failure": None, "all_opened_descriptors_closed": True}
    cleanup = {"children_reaped": True, "descriptors_restored": True, "mounts_gone": True, "temporary_names_gone": not inject_cleanup_failure, "namespace_handles_retained": False, "uncertainty": inject_cleanup_failure}
    report = {
        "schema": SCHEMA, "authority": "none", "qualified": False, "outcome": "incomplete" if inject_cleanup_failure else "complete",
        "source": {"pr_head_sha": "0" * 40, "checkout_sha": "0" * 40, "driver_sha256": "1" * 64, "schema_sha256": "2" * 64, "source_head_workflow_blob_sha256": "3" * 64},
        "envelope": {"repository": "nenb/cogs", "workflow": ".github/workflows/outcome-two-runner-capability.yml", "job": "runner-capability-probe", "event": "pull_request", "action": "labeled", "run_id": "1", "run_attempt": 1, "pull_request_number": 1, "base_sha": "4" * 40, "github_sha": "5" * 40, "github_workflow_sha": "6" * 40, "event_merge_sha": "7" * 40},
        "runner": {"requested_label": "ubuntu-24.04", "environment": "github-hosted", "image_os": "ubuntu24", "image_version": "fixed", "runner_arch": "X64", "image_metadata_status": ok}, "kernel": {"sysname": "Linux", "release": "fixed", "machine": "x86_64", "uname_status": ok},
        "rlimit_nofile": {"soft": 1024, "hard": 8192, "high_fd_4096_possible": True, "high_fd_4096_status": ok},
        "sudo": {"executable": tool(SUDO), "noninteractive": ok, "close_from_3": {"invocation": ok, "fd3_closed": True, "fd4_closed": True, "exit_code": 40}, "close_from_4": {"invocation": ok, "fd3_preserved": True, "fd4_closed": True, "exit_code": 41}},
        "descriptors": {"exec_cloexec": {"invocation": ok, "non_cloexec_fd_198_survived": True, "cloexec_fd_199_closed": True}, "close_range_low": close_range_case_shape(198, ok), "close_range_high": close_range_case_shape(4096, ok), "inherited_baseline_restored": True},
        "temporary_files": {"runner_temp": tmp, "private_tmpfs": tmp}, "opath": {"same_mount_namespace": opath, "across_mount_namespace": opath},
        "namespaces": {"network": {"create": ok, "distinct_from_parent": True}, "mount": {"create": ok, "distinct_from_parent": True}, "pid": {"create": ok, "child_is_namespace_pid_1": True, "nspid_final_component_is_1": True}, "user_direct_root": {"create": ok, "uid_map_status": ok, "gid_map_status": ok, "exact_root_mapping": True, "setgroups": "deny"}, "combined_user_mount_pid_fork": {"create": ok, "child_is_namespace_pid_1": True, "proc_mount": ok, "cleanup": ok}},
        "procfs": {"host_runner": mapping("host"), "host_sudo_root": mapping("host"), "child_userns_parent_proc_before_cap_drop": mapping("parent-userns"), "child_userns_parent_proc_after_cap_drop": mapping("parent-userns"), "child_owned_proc_before_cap_drop": mapping("child-userns"), "child_owned_proc_after_cap_drop": mapping("child-userns"), "parent_proc_read_only": True, "child_proc_read_only": True, "child_proc_distinct_from_parent": True, "child_proc_distinct_from_parent_status": ok, "child_proc_view_has_pid_1": True},
        "seccomp": {"initial_mode_status": ok, "initial_mode": 2, "initial_no_new_privs_status": ok, "initial_no_new_privs": 0, "set_no_new_privs": ok, "install_filter": ok, "final_mode": 2, "network_syscalls_policy": "fixed-eperm-filter-installed"},
        "kvm": {"device_present": False, "character_device": None, "open_read_write": status("unsupported"), "get_api_version": status("blocked", blocked_by="kvm.open_read_write"), "api_version": None, "check_extension_user_memory": status("blocked", blocked_by="kvm.open_read_write"), "user_memory_extension": None},
        "tools": {"python3": tool(PYTHON), "gzip": tool(GZIP), "zstd": tool(ZSTD), "unshare": tool(UNSHARE)}, "cleanup": cleanup,
    }
    return report

SCRIPT_RESOURCES = ("descriptor", "pipe", "child", "name", "mount", "limit")
class ScriptedAdapter:
    """In-memory effect script; self-test never reaches an OS-effect boundary."""
    def __init__(self, fault: str | None = None) -> None: self.fault, self.acquired, self.calls = fault, [], []
    def acquire(self, name: str) -> None:
        self.calls.append("acquire." + name)
        if self.fault == "acquire." + name: raise RuntimeError
        self.acquired.append(name)
    def release(self, name: str) -> None:
        self.calls.append("cleanup." + name)
        if self.fault == "cleanup." + name: raise RuntimeError
        self.acquired.remove(name)
class ScriptedOwner:
    def __init__(self, adapter: ScriptedAdapter) -> None: self.adapter, self.registry, self.poisoned, self.cleaned = adapter, [], False, False
    def run(self) -> bool:
        try:
            for name in SCRIPT_RESOURCES:
                self.adapter.acquire(name); self.registry.append(name)
                if self.adapter.fault == "after." + name: raise RuntimeError
        except RuntimeError: self.poisoned = True
        return self.cleanup()
    def cleanup(self) -> bool:
        if self.cleaned: return True
        failed = self.poisoned
        for name in reversed(tuple(self.registry)):
            try: self.adapter.release(name); self.registry.remove(name)
            except RuntimeError: failed = True
        self.poisoned = failed
        if not failed and not self.registry: self.cleaned = True
        return self.cleaned

def self_test() -> None:
    first_report = fake_report(); second_report = fake_report(); validate_report(first_report); validate_report(second_report)
    first, second = canonical_bytes(first_report), canonical_bytes(second_report)
    assert first == second and first.endswith(b"\n") and first.count(b"\n") == 1
    failed = fake_report(True); validate_report(failed); assert failed["outcome"] == "incomplete"
    acquisition_faults = tuple(f"{cut}.{name}" for name in SCRIPT_RESOURCES for cut in ("acquire", "after"))
    cleanup_faults = tuple("cleanup." + name for name in SCRIPT_RESOURCES)
    for fault in acquisition_faults:
        owner = ScriptedOwner(ScriptedAdapter(fault)); assert not owner.run() and not owner.registry and not owner.adapter.acquired
    for fault in cleanup_faults:
        owner = ScriptedOwner(ScriptedAdapter(fault)); assert not owner.run() and owner.poisoned and not owner.cleanup()
    success = ScriptedOwner(ScriptedAdapter()); assert success.run() and success.cleanup()
    for invalid in ({"state": "ok", "errno": errno.EPERM, "blocked_by": None}, {"state": "blocked", "errno": None, "blocked_by": None}, {"state": "denied", "errno": errno.ENOENT, "blocked_by": None}):
        try: validate_status(invalid); raise AssertionError("invalid status accepted")
        except ValueError: pass
    try: canonical_bytes({"bad": 1.5}); raise AssertionError("float accepted")
    except ValueError: pass
    for canary in (b'"uid_map":', b'"gid_map":', b"1000 1000 1", b"secret-canary", b"child-stderr-canary"): assert canary not in first
    summary = {"acquisition_faults": list(acquisition_faults), "cleanup_faults": list(cleanup_faults), "disclosure_canaries": ["old-id-map-keys", "numeric-id-row", "secret", "child-output"], "fake_report_bytes": len(first), "fake_report_sha256": hashlib.sha256(first).hexdigest(), "real_effects": 0, "repeatability": 2}
    text = json.dumps(summary, sort_keys=True, separators=(",", ":")); assert len(text) <= MAX_OUTPUT
    sys.stdout.write("runner-capability-probe self-test: ok acquisition=%d cleanup=%d real.effects=0 repeatability=2 summary=%s\n" % (len(acquisition_faults), len(cleanup_faults), text))
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
