"""Trusted, fixed host runtime-closure preparation for Outcome 2.
Host discovery is completed here, while trusted fixed paths and procfs are
available.  The only production result is three sealed, CLOEXEC descriptors;
callers cannot select paths, commands, policy, descriptor numbers, or report
fields.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import ctypes
import fcntl
import hashlib
import json
import os
import select
import signal
import stat
import time
from typing import Any, Iterable, NoReturn, Sequence
from completion_elf import ElfMetadata, parse_elf64
FIXED_TOOL_TABLE = (
    ("python3-parser", "/usr/bin/python3"),
    ("zstd", "/usr/bin/zstd"),
    ("gzip", "/usr/bin/gzip"),
)
_VERSION = "cogs.trusted-runtime-closure/v1"
_INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
_LIBRARY_ROOTS = (
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
)
_MAX_OBJECT_SIZE = 128 * 1024 * 1024
_MAX_OBJECTS = 128
_MAX_TOOL_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_REPORT = 128 * 1024
_MAX_MAP_BYTES = 4 * 1024 * 1024
_MAX_MAP_LINES = 4096
_MAX_COMPONENTS = 256
_MAX_SYMLINKS = 40
_IO_CHUNK = 1024 * 1024
_HELPER_START_SECONDS = 5.0
_HELPER_TERM_SECONDS = 1.0
_HELPER_KILL_SECONDS = 1.0
_SEAL_PROFILE = "linux-memfd-exec-seals-v1"
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_MFD_CLOEXEC = 0x0001
_MFD_ALLOW_SEALING = 0x0002
_MFD_EXEC = 0x0010
_F_ADD_SEALS = 1033
_F_GET_SEALS = 1034
_F_SEAL_SEAL = 0x0001
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008
_F_SEAL_FUTURE_WRITE = 0x0010
_F_SEAL_EXEC = 0x0020
_DATA_SEALS = (
    _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK |
    _F_SEAL_FUTURE_WRITE | _F_SEAL_SEAL
)
_EXEC_SEALS = _DATA_SEALS | _F_SEAL_EXEC
_PR_SET_PDEATHSIG = 1
_KERNEL_EXECUTABLE_MAPPINGS = frozenset(("[vdso]", "[vsyscall]"))

class RuntimeClosureError(RuntimeError):
    """A fixed closure requirement was not satisfied."""

class RuntimeClosureCleanupError(RuntimeClosureError):
    """Cleanup was incomplete or uncertain."""
    def __init__(self, failures: Sequence[BaseException]):
        self.failures = tuple(failures)
        super().__init__(f"runtime closure cleanup failed ({len(self.failures)} errors)")

@dataclass(frozen=True)
class RuntimeClosureHandoff:
    gzip_executable_fd: int
    zstd_executable_fd: int
    report_fd: int

@dataclass(frozen=True)
class SourceGeneration:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    mode: int
    uid: int
    gid: int

@dataclass(frozen=True)
class AuthenticatedObject:
    role: str
    logical_path: str
    held_fd: int
    generation: SourceGeneration
    size: int
    sha256: str
    elf: ElfMetadata
    @property
    def identity(self) -> tuple[int, int]:
        return (self.generation.device, self.generation.inode)

@dataclass(frozen=True)
class ResolvedToolClosure:
    tool: str
    executable: AuthenticatedObject
    loader: AuthenticatedObject
    libraries: tuple[AuthenticatedObject, ...]
    @property
    def objects(self) -> tuple[AuthenticatedObject, ...]:
        return (self.executable, self.loader, *self.libraries)

@dataclass(frozen=True)
class MappedToolClosure:
    tool: str
    mapped: tuple[tuple[str, str], ...]
    mapping_sha256: str

@dataclass(frozen=True)
class SealedExecutable:
    tool: str
    fd: int
    source_generation: SourceGeneration
    size: int
    sha256: str
    seals: int

@dataclass(frozen=True)
class _PathObservation:
    kind: str
    generation: SourceGeneration
    link: str | None

@dataclass
class _Child:
    pid: int
    pidfd: int
    start_time: int
    session: int
    process_group: int
    executable_identity: tuple[int, int]
    reaped: bool = False

class _State(Enum):
    NEW = "NEW"
    PREPARING = "PREPARING"
    READY = "READY"
    HANDED_OFF = "HANDED_OFF"
    CLOSED = "CLOSED"
    POISONED = "POISONED"

class _Ops:
    """Private syscall/fault adapter; production constructs the system form only."""
    cut_names = (
        "state.preparing", "resolve.<tool>.before", "resolve.<tool>.after",
        "mapping.<tool>.before-spawn", "mapping.<tool>.before-capture",
        "mapping.<tool>.after-capture", "mapping.<tool>.after-cleanup",
        "seal.<gzip|zstd>.before", "seal.<gzip|zstd>.after",
        "report.before-seal", "report.after-seal", "report.before-publish",
        "state.ready", "handoff.before-revalidate", "handoff.before-transfer",
        "cleanup.before", "cleanup.after",
    )
    def checkpoint(self, name: str) -> None:
        del name
    def order(self, name: str, values: Sequence[Any]) -> tuple[Any, ...]:
        del name
        return tuple(values)
    def report_candidate(self, data: bytes) -> bytes:
        return data
    def open(self, path: str, flags: int, mode: int = 0o600,
             *, dir_fd: int | None = None) -> int:
        return os.open(path, flags, mode, dir_fd=dir_fd)
    def close(self, fd: int) -> None:
        os.close(fd)
    def dup(self, fd: int) -> int:
        return os.dup(fd)
    def fstat(self, fd: int) -> os.stat_result:
        return os.fstat(fd)
    def stat(self, path: str, *, dir_fd: int, follow_symlinks: bool) -> os.stat_result:
        return os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
    def readlink(self, path: str, *, dir_fd: int) -> str:
        return os.readlink(path, dir_fd=dir_fd)
    def pread(self, fd: int, size: int, offset: int) -> bytes:
        return os.pread(fd, size, offset)
    def pwrite(self, fd: int, data: bytes, offset: int) -> int:
        return os.pwrite(fd, data, offset)
    def read(self, fd: int, size: int) -> bytes:
        return os.read(fd, size)
    def write(self, fd: int, data: bytes) -> int:
        return os.write(fd, data)
    def fchmod(self, fd: int, mode: int) -> None:
        os.fchmod(fd, mode)
    def fsync(self, fd: int) -> None:
        os.fsync(fd)
    def fcntl(self, fd: int, command: int, argument: int = 0) -> int:
        return fcntl.fcntl(fd, command, argument)
    def memfd_create(self, name: str, flags: int) -> int:
        return os.memfd_create(name, flags)
    def pipe(self) -> tuple[int, int]:
        return os.pipe2(_O_CLOEXEC)
    def fork(self) -> int:
        return os.fork()
    def dup2(self, source: int, target: int) -> None:
        os.dup2(source, target, inheritable=True)
    def execve(self, fd: int, argv: Sequence[str], environment: dict[str, str]) -> NoReturn:
        os.execve(fd, list(argv), environment)
    def exit_child(self, status: int) -> NoReturn:
        os._exit(status)
    def pidfd_open(self, pid: int) -> int:
        return os.pidfd_open(pid, 0)
    def pidfd_signal(self, pidfd: int, signum: int) -> None:
        signal.pidfd_send_signal(pidfd, signum)
    def kill(self, pid: int, signum: int) -> None:
        os.kill(pid, signum)
    def waitpid(self, pid: int, options: int) -> tuple[int, int]:
        return os.waitpid(pid, options)
    def getsid(self, pid: int) -> int:
        return os.getsid(pid)
    def getpgid(self, pid: int) -> int:
        return os.getpgid(pid)
    def setsid(self) -> None:
        os.setsid()
    def getppid(self) -> int:
        return os.getppid()
    def getpid(self) -> int:
        return os.getpid()
    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
    def poll_readable(self, fd: int, seconds: float) -> bool:
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return bool(poller.poll(max(0, int(seconds * 1000))))
    def monotonic(self) -> float:
        return time.monotonic()
    def list_fds(self) -> frozenset[int]:
        values = os.listdir("/proc/self/fd")
        if len(values) > 16384:
            raise RuntimeClosureError("descriptor baseline bound")
        return frozenset(int(value) for value in values)
    def child_baseline(self) -> bytes:
        fd = self.open("/proc/self/task/self/children", os.O_RDONLY | _O_CLOEXEC)
        try:
            data = self.read(fd, 65537)
            if len(data) > 65536 or self.read(fd, 1):
                raise RuntimeClosureError("child baseline bound")
            return data
        finally:
            self.close(fd)

class _Registry:
    def __init__(self, ops: _Ops) -> None:
        self._ops = ops
        self._fds: list[int] = []
    def add(self, fd: int) -> int:
        if type(fd) is not int or fd < 0 or fd in self._fds:
            raise RuntimeClosureError("invalid descriptor registration")
        self._fds.append(fd)
        return fd
    def remove(self, fd: int) -> None:
        if fd not in self._fds:
            raise RuntimeClosureError("descriptor ownership mismatch")
        self._fds.remove(fd)
    def close_all(self) -> tuple[BaseException, ...]:
        failures: list[BaseException] = []
        while self._fds:
            fd = self._fds.pop()
            try:
                self._ops.close(fd)
            except BaseException as error:
                failures.append(error)
        return tuple(failures)
    def values(self) -> tuple[int, ...]:
        return tuple(self._fds)
def _generation(value: os.stat_result) -> SourceGeneration:
    return SourceGeneration(
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns, value.st_mode, value.st_uid, value.st_gid,
    )
def _require_component(value: os.stat_result, *, directory: bool = False) -> None:
    if value.st_uid != 0 or value.st_mode & 0o022:
        raise RuntimeClosureError("insecure fixed path component")
    if directory and not stat.S_ISDIR(value.st_mode):
        raise RuntimeClosureError("fixed path component is not a directory")
def _require_source(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise RuntimeClosureError("runtime object is not regular")
    if value.st_uid != 0 or value.st_mode & 0o022:
        raise RuntimeClosureError("runtime object has insecure ownership or mode")
    if not 1 <= value.st_size <= _MAX_OBJECT_SIZE:
        raise RuntimeClosureError("runtime object size bound")
def _close_local(ops: _Ops, descriptors: Iterable[int], primary: BaseException | None = None) -> None:
    failures: list[BaseException] = []
    for fd in reversed(tuple(descriptors)):
        try:
            ops.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        if primary is not None:
            failures.insert(0, primary)
        raise RuntimeClosureCleanupError(failures)
    if primary is not None:
        raise primary
def _split_path(path: str) -> list[str]:
    if type(path) is not str or not path.startswith("/") or "\0" in path:
        raise RuntimeClosureError("invalid fixed absolute path")
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".") for part in parts):
        raise RuntimeClosureError("invalid fixed path components")
    return parts
def _resolve_once(ops: _Ops, path: str, *, open_source: bool = True) -> tuple[int | None, SourceGeneration, tuple[_PathObservation, ...]]:
    queue = _split_path(path)
    directories: list[int] = []
    observations: list[_PathObservation] = []
    final_fd: int | None = None
    primary: BaseException | None = None
    try:
        root = ops.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
        directories.append(root)
        root_before = ops.fstat(root)
        _require_component(root_before, directory=True)
        observations.append(_PathObservation("directory", _generation(root_before), None))
        symlinks = 0
        components = 0
        while queue:
            components += 1
            if components > _MAX_COMPONENTS:
                raise RuntimeClosureError("fixed path component bound")
            part = queue.pop(0)
            if part == "..":
                if len(directories) == 1:
                    raise RuntimeClosureError("fixed path escapes root")
                ops.close(directories[-1])
                directories.pop()
                continue
            if part in ("", ".") or "/" in part:
                raise RuntimeClosureError("invalid resolved path component")
            before = ops.stat(part, dir_fd=directories[-1], follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                if before.st_uid != 0:
                    raise RuntimeClosureError("fixed symlink is not root owned")
                symlinks += 1
                if symlinks > _MAX_SYMLINKS:
                    raise RuntimeClosureError("fixed symlink bound")
                target = ops.readlink(part, dir_fd=directories[-1])
                after = ops.stat(part, dir_fd=directories[-1], follow_symlinks=False)
                if _generation(before) != _generation(after) or not target or "\0" in target:
                    raise RuntimeClosureError("fixed symlink changed")
                observations.append(_PathObservation("symlink", _generation(after), target))
                target_parts = target.split("/")
                if target.startswith("/"):
                    while len(directories) > 1:
                        ops.close(directories[-1])
                        directories.pop()
                    target_parts = target_parts[1:]
                if any(value in ("", ".") for value in target_parts):
                    raise RuntimeClosureError("invalid fixed symlink target")
                queue = target_parts + queue
                continue
            if queue:
                _require_component(before, directory=True)
                opened = ops.open(
                    part, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                    dir_fd=directories[-1],
                )
                directories.append(opened)
                after = ops.fstat(opened)
                _require_component(after, directory=True)
                if _generation(before) != _generation(after):
                    raise RuntimeClosureError("fixed directory changed")
                observations.append(_PathObservation("directory", _generation(after), None))
            else:
                _require_source(before)
                final_generation = _generation(before)
                if open_source:
                    final_fd = ops.open(part, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW,
                                        dir_fd=directories[-1])
                    after = ops.fstat(final_fd)
                    _require_source(after)
                    if _generation(after) != final_generation:
                        raise RuntimeClosureError("fixed runtime object changed")
        if open_source and final_fd is None:
            raise RuntimeClosureError("fixed path has no final object")
        root_after = ops.fstat(directories[0])
        _require_component(root_after, directory=True)
        if _generation(root_before) != _generation(root_after):
            raise RuntimeClosureError("fixed root changed")
    except BaseException as error:
        primary = error
    try:
        _close_local(ops, directories, primary)
    except BaseException as cleanup:
        if final_fd is None:
            raise
        try:
            ops.close(final_fd)
        except BaseException as final_error:
            raise RuntimeClosureCleanupError((cleanup, final_error)) from cleanup
        raise
    return final_fd, final_generation, tuple(observations)
def _read_complete(ops: _Ops, fd: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        chunk = ops.pread(fd, min(_IO_CHUNK, expected_size - offset), offset)
        if not chunk:
            raise RuntimeClosureError("short runtime object read")
        chunks.append(chunk)
        offset += len(chunk)
    if ops.pread(fd, 1, expected_size):
        raise RuntimeClosureError("runtime object grew during read")
    return b"".join(chunks)
def _authenticate(ops: _Ops, path: str, role: str) -> AuthenticatedObject:
    fd: int | None = None
    second_fd: int | None = None
    try:
        fd, generation, observations = _resolve_once(ops, path)
        assert fd is not None
        raw = _read_complete(ops, fd, generation.size)
        after = ops.fstat(fd)
        _require_source(after)
        if _generation(after) != generation:
            raise RuntimeClosureError("runtime source generation changed")
        metadata = parse_elf64(raw)
        second_fd, second_generation, second_observations = _resolve_once(
            ops, path, open_source=False,
        )
        assert second_fd is None
        if second_generation != generation or second_observations != observations:
            raise RuntimeClosureError("fixed logical path changed")
        return AuthenticatedObject(
            role, path, fd, generation, len(raw), hashlib.sha256(raw).hexdigest(), metadata,
        )
    except BaseException as primary:
        descriptors = [value for value in (second_fd, fd) if value is not None]
        _close_local(ops, descriptors, primary)
        raise AssertionError("unreachable")
def _metadata(object_: AuthenticatedObject) -> tuple[str | None, str | None, tuple[str, ...]]:
    interpreter = object_.elf.interpreter
    soname = object_.elf.soname
    needed = tuple(object_.elf.needed)
    if len(needed) != len(set(needed)) or len(needed) > _MAX_OBJECTS:
        raise RuntimeClosureError("invalid ordered dependency metadata")
    return interpreter, soname, needed
def _close_object(ops: _Ops, object_: AuthenticatedObject) -> None:
    ops.close(object_.held_fd)
def _resolve_library(ops: _Ops, soname: str) -> AuthenticatedObject:
    if type(soname) is not str or not soname or "/" in soname or len(soname.encode("ascii")) > 255:
        raise RuntimeClosureError("invalid dependency SONAME")
    candidates: list[AuthenticatedObject] = []
    primary: BaseException | None = None
    try:
        roots = ops.order("library-roots", _LIBRARY_ROOTS)
        if set(roots) != set(_LIBRARY_ROOTS) or len(roots) != len(_LIBRARY_ROOTS):
            raise RuntimeClosureError("library root enumeration changed")
        for root in roots:
            try:
                candidate = _authenticate(ops, f"{root}/{soname}", "library")
            except FileNotFoundError:
                continue
            if _metadata(candidate)[1] != soname:
                _close_object(ops, candidate)
                raise RuntimeClosureError("dependency SONAME mismatch")
            if any(item.identity == candidate.identity for item in candidates):
                _close_object(ops, candidate)
            else:
                candidates.append(candidate)
        if len(candidates) != 1:
            raise RuntimeClosureError("missing or ambiguous library provider")
        return candidates.pop()
    except BaseException as error:
        primary = error
    failures: list[BaseException] = [primary] if primary is not None else []
    for candidate in reversed(candidates):
        try:
            _close_object(ops, candidate)
        except BaseException as error:
            failures.append(error)
    if len(failures) > 1:
        raise RuntimeClosureCleanupError(failures)
    raise failures[0]
def _resolve_tool(ops: _Ops, tool: str, path: str) -> ResolvedToolClosure:
    owned: list[AuthenticatedObject] = []
    try:
        executable = _authenticate(ops, path, "executable")
        owned.append(executable)
        interpreter, _soname, _needed = _metadata(executable)
        if interpreter != _INTERPRETER:
            raise RuntimeClosureError("unknown or missing interpreter")
        loader = _authenticate(ops, _INTERPRETER, "loader")
        owned.append(loader)
        if loader.identity == executable.identity or _metadata(loader)[0] is not None:
            raise RuntimeClosureError("loader role ambiguity")
        objects: dict[tuple[int, int], AuthenticatedObject] = {
            executable.identity: executable,
            loader.identity: loader,
        }
        providers: dict[str, AuthenticatedObject] = {}
        for object_ in (executable, loader):
            soname = _metadata(object_)[1]
            if soname is not None:
                if soname in providers and providers[soname].identity != object_.identity:
                    raise RuntimeClosureError("duplicate SONAME provider")
                providers[soname] = object_
        pending = list(_metadata(executable)[2]) + list(_metadata(loader)[2])
        examined: set[tuple[int, int]] = set()
        while pending:
            needed = pending.pop(0)
            if needed in providers:
                provider = providers[needed]
            else:
                provider = _resolve_library(ops, needed)
                if provider.identity in objects:
                    _close_object(ops, provider)
                    provider = objects[provider.identity]
                else:
                    if _metadata(provider)[0] is not None:
                        _close_object(ops, provider)
                        raise RuntimeClosureError("library declares an interpreter")
                    owned.append(provider)
                    objects[provider.identity] = provider
                declared = _metadata(provider)[1]
                if declared != needed:
                    raise RuntimeClosureError("library provider mismatch")
                if needed in providers and providers[needed].identity != provider.identity:
                    raise RuntimeClosureError("ambiguous SONAME provider")
                providers[needed] = provider
            if provider.identity not in examined:
                examined.add(provider.identity)
                pending.extend(_metadata(provider)[2])
            if len(objects) > _MAX_OBJECTS:
                raise RuntimeClosureError("tool closure object bound")
            if sum(item.size for item in objects.values()) > _MAX_TOOL_BYTES:
                raise RuntimeClosureError("tool closure byte bound")
        for object_ in objects.values():
            for needed in _metadata(object_)[2]:
                if needed not in providers:
                    raise RuntimeClosureError("unresolved closure dependency")
        libraries = tuple(sorted(
            (item for item in objects.values() if item.identity not in
             (executable.identity, loader.identity)),
            key=lambda item: ((_metadata(item)[1] or "").encode("utf-8"), item.sha256),
        ))
        return ResolvedToolClosure(tool, executable, loader, libraries)
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        for object_ in reversed(owned):
            try:
                _close_object(ops, object_)
            except BaseException as error:
                failures.append(error)
        if len(failures) > 1:
            raise RuntimeClosureCleanupError(failures)
        raise
def _read_stream_bounded(ops: _Ops, fd: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = ops.read(fd, min(65536, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise RuntimeClosureError("proc stream byte bound")
def _proc_start_time(raw: bytes) -> int:
    close = raw.rfind(b")")
    fields = raw[close + 2:].split() if close >= 0 else []
    if len(fields) < 20:
        raise RuntimeClosureError("malformed process stat")
    try:
        return int(fields[19])
    except ValueError as error:
        raise RuntimeClosureError("malformed process start time") from error
def _read_proc(ops: _Ops, path: str, maximum: int) -> bytes:
    fd = ops.open(path, os.O_RDONLY | _O_CLOEXEC)
    try:
        return _read_stream_bounded(ops, fd, maximum)
    finally:
        ops.close(fd)
def _child_argv(tool: str) -> tuple[str, ...]:
    if tool == "python3-parser":
        return ("python3", "-I", "-B", "-c", "import os;os.read(0,1)")
    if tool == "gzip":
        return ("gzip", "-dc")
    if tool == "zstd":
        return ("zstd", "-dc", "--no-progress")
    raise RuntimeClosureError("unknown fixed helper")
def _child_fail(ops: _Ops, status_fd: int) -> NoReturn:
    try:
        ops.write(status_fd, b"E")
    except BaseException:
        pass
    ops.exit_child(127)
def _spawn_helper(ops: _Ops, closure: ResolvedToolClosure) -> tuple[_Child, int]:
    gate_read = gate_write = status_read = status_write = devnull = pidfd = None
    pid: int | None = None
    try:
        gate_read, gate_write = ops.pipe()
        status_read, status_write = ops.pipe()
        devnull = ops.open("/dev/null", os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW)
        parent_before = ops.getpid()
        pid = ops.fork()
        if pid == 0:
            try:
                ops.close(gate_write)
                ops.close(status_read)
                ops.setsid()
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
                    _child_fail(ops, status_write)
                if ops.getppid() != parent_before:
                    _child_fail(ops, status_write)
                ops.dup2(gate_read, 0)
                ops.dup2(devnull, 1)
                ops.dup2(devnull, 2)
                for fd in (gate_read, devnull):
                    if fd not in (0, 1, 2, closure.executable.held_fd, status_write):
                        ops.close(fd)
                ops.execve(closure.executable.held_fd, _child_argv(closure.tool), {})
            except BaseException:
                _child_fail(ops, status_write)
        ops.close(gate_read)
        gate_read = None
        ops.close(status_write)
        status_write = None
        ops.close(devnull)
        devnull = None
        pidfd = ops.pidfd_open(pid)
        deadline = ops.monotonic() + _HELPER_START_SECONDS
        if not ops.poll_readable(status_read, deadline - ops.monotonic()):
            raise RuntimeClosureError("helper exec handshake timeout")
        status = _read_stream_bounded(ops, status_read, 1)
        if status:
            raise RuntimeClosureError("fixed helper exec failed")
        ops.close(status_read)
        status_read = None
        stat_raw = _read_proc(ops, f"/proc/{pid}/stat", 4096)
        child = _Child(
            pid, pidfd, _proc_start_time(stat_raw), ops.getsid(pid), ops.getpgid(pid),
            closure.executable.identity,
        )
        if child.session != pid or child.process_group != pid:
            raise RuntimeClosureError("helper does not own its session")
        pidfd = None
        return child, gate_write
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        for fd in (pidfd, status_write, status_read, gate_write, gate_read, devnull):
            if fd is not None:
                try:
                    ops.close(fd)
                except BaseException as error:
                    failures.append(error)
        if pid not in (None, 0):
            try:
                ops.kill(pid, signal.SIGKILL)
                ops.waitpid(pid, 0)
            except BaseException as error:
                failures.append(error)
        if len(failures) > 1:
            raise RuntimeClosureCleanupError(failures)
        raise
def _matching_child(ops: _Ops, child: _Child) -> bool:
    if child.reaped:
        return False
    try:
        if _proc_start_time(_read_proc(ops, f"/proc/{child.pid}/stat", 4096)) != child.start_time:
            return False
        if ops.getsid(child.pid) != child.session or ops.getpgid(child.pid) != child.process_group:
            return False
        fd = ops.open(f"/proc/{child.pid}/exe", os.O_RDONLY | _O_CLOEXEC)
        try:
            value = ops.fstat(fd)
            return (value.st_dev, value.st_ino) == child.executable_identity
        finally:
            ops.close(fd)
    except (FileNotFoundError, ProcessLookupError):
        return False
def _wait_child(ops: _Ops, child: _Child, deadline: float) -> bool:
    while True:
        waited, _status = ops.waitpid(child.pid, os.WNOHANG)
        if waited == child.pid:
            child.reaped = True
            return True
        if waited != 0:
            raise RuntimeClosureError("unexpected helper wait result")
        if ops.monotonic() >= deadline:
            return False
        ops.sleep(0.01)
def _stop_helper(ops: _Ops, child: _Child, gate_write: int) -> None:
    failures: list[BaseException] = []
    try:
        children = _read_proc(ops, f"/proc/{child.pid}/task/{child.pid}/children", 65536)
        if children.strip() or not _matching_child(ops, child):
            raise RuntimeClosureError("helper identity or descendants changed")
        ops.close(gate_write)
        gate_write = -1
        ops.pidfd_signal(child.pidfd, signal.SIGTERM)
        if not _wait_child(ops, child, ops.monotonic() + _HELPER_TERM_SECONDS):
            if not _matching_child(ops, child):
                raise RuntimeClosureError("helper identity changed before KILL")
            ops.pidfd_signal(child.pidfd, signal.SIGKILL)
            if not _wait_child(ops, child, ops.monotonic() + _HELPER_KILL_SECONDS):
                raise RuntimeClosureError("helper reap timeout")
    except ChildProcessError:
        failures.append(RuntimeClosureError("helper reap ownership lost"))
    except BaseException as error:
        failures.append(error)
    if gate_write >= 0:
        try:
            ops.close(gate_write)
        except BaseException as error:
            failures.append(error)
    if failures and not child.reaped:
        try:
            ops.pidfd_signal(child.pidfd, signal.SIGKILL)
            if not _wait_child(ops, child, ops.monotonic() + _HELPER_KILL_SECONDS):
                failures.append(RuntimeClosureError("emergency helper reap timeout"))
        except BaseException as error:
            failures.append(error)
    try:
        ops.close(child.pidfd)
    except BaseException as error:
        failures.append(error)
    if failures:
        raise RuntimeClosureCleanupError(failures)
def _maps_snapshot(ops: _Ops, pid: int) -> bytes:
    raw = _read_proc(ops, f"/proc/{pid}/maps", _MAX_MAP_BYTES)
    lines = raw.splitlines()
    if not raw.endswith(b"\n") or len(lines) > _MAX_MAP_LINES:
        raise RuntimeClosureError("incomplete or oversized maps snapshot")
    return raw
def _mapped_closure(ops: _Ops, child: _Child,
                    closure: ResolvedToolClosure) -> MappedToolClosure:
    expected = {item.identity: item for item in closure.objects}
    before = _maps_snapshot(ops, child.pid)
    seen: set[tuple[int, int]] = set()
    for line in before.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise RuntimeClosureError("malformed maps row")
        address, permissions, _offset, _device, inode_raw = fields[:5]
        path = fields[5].decode("utf-8", "strict") if len(fields) == 6 else ""
        try:
            inode = int(inode_raw)
            start_raw, end_raw = address.split(b"-", 1)
            start, end = int(start_raw, 16), int(end_raw, 16)
        except (ValueError, TypeError) as error:
            raise RuntimeClosureError("malformed maps identity") from error
        if start >= end or len(permissions) != 4:
            raise RuntimeClosureError("malformed maps extent")
        if b"x" not in permissions:
            continue
        if inode == 0:
            if path not in _KERNEL_EXECUTABLE_MAPPINGS:
                raise RuntimeClosureError("unknown synthetic executable mapping")
            continue
        mapped_fd = ops.open(
            f"/proc/{child.pid}/map_files/{start:x}-{end:x}",
            os.O_RDONLY | _O_CLOEXEC,
        )
        try:
            before_stat = ops.fstat(mapped_fd)
            _require_source(before_stat)
            generation = _generation(before_stat)
            raw = _read_complete(ops, mapped_fd, generation.size)
            after_stat = ops.fstat(mapped_fd)
            _require_source(after_stat)
            if _generation(after_stat) != generation:
                raise RuntimeClosureError("mapped object generation changed")
            identity = (generation.device, generation.inode)
            object_ = expected.get(identity)
            digest = hashlib.sha256(raw).hexdigest()
            if object_ is None or object_.generation != generation or object_.sha256 != digest:
                raise RuntimeClosureError("unknown or changed executable mapping")
            parsed = parse_elf64(raw)
            if parsed != object_.elf:
                raise RuntimeClosureError("mapped ELF metadata changed")
            if identity not in seen:
                seen.add(identity)
        finally:
            ops.close(mapped_fd)
    after = _maps_snapshot(ops, child.pid)
    if before != after:
        raise RuntimeClosureError("helper mappings drifted")
    if seen != set(expected):
        raise RuntimeClosureError("resolved and mapped closures differ")
    sequence = tuple((item.role, item.sha256) for item in closure.objects)
    digest = hashlib.sha256(_canonical(sequence)).hexdigest()
    return MappedToolClosure(closure.tool, sequence, digest)
def _seal_source(ops: _Ops, source: AuthenticatedObject, tool: str) -> SealedExecutable:
    fd = ops.memfd_create("cogs-runtime", _MFD_CLOEXEC | _MFD_ALLOW_SEALING | _MFD_EXEC)
    try:
        if _generation(ops.fstat(source.held_fd)) != source.generation:
            raise RuntimeClosureError("source changed before sealing")
        offset = 0
        while offset < source.size:
            chunk = ops.pread(source.held_fd, min(_IO_CHUNK, source.size - offset), offset)
            if not chunk:
                raise RuntimeClosureError("short source read while sealing")
            written = 0
            while written < len(chunk):
                count = ops.pwrite(fd, chunk[written:], offset + written)
                if count <= 0:
                    raise RuntimeClosureError("short sealed executable write")
                written += count
            offset += len(chunk)
        if ops.pread(source.held_fd, 1, source.size):
            raise RuntimeClosureError("source grew while sealing")
        ops.fchmod(fd, 0o555)
        ops.fsync(fd)
        copied = _read_complete(ops, fd, source.size)
        if hashlib.sha256(copied).hexdigest() != source.sha256:
            raise RuntimeClosureError("sealed executable readback mismatch")
        if _generation(ops.fstat(source.held_fd)) != source.generation:
            raise RuntimeClosureError("source changed during sealing")
        ops.fcntl(fd, _F_ADD_SEALS, _EXEC_SEALS)
        seals = ops.fcntl(fd, _F_GET_SEALS)
        if seals != _EXEC_SEALS:
            raise RuntimeClosureError("exact executable seal profile unavailable")
        value = ops.fstat(fd)
        if not stat.S_ISREG(value.st_mode) or value.st_size != source.size or value.st_mode & 0o777 != 0o555:
            raise RuntimeClosureError("sealed executable metadata mismatch")
        return SealedExecutable(tool, fd, source.generation, source.size, source.sha256, seals)
    except BaseException as primary:
        _close_local(ops, (fd,), primary)
        raise AssertionError("unreachable")

def _seal_report(ops: _Ops, report: bytes) -> int:
    fd = ops.memfd_create("cogs-runtime-report", _MFD_CLOEXEC | _MFD_ALLOW_SEALING)
    read_fd: int | None = None
    try:
        offset = 0
        while offset < len(report):
            count = ops.pwrite(fd, report[offset:], offset)
            if count <= 0:
                raise RuntimeClosureError("short report write")
            offset += count
        ops.fchmod(fd, 0o444)
        ops.fsync(fd)
        if _read_complete(ops, fd, len(report)) != report:
            raise RuntimeClosureError("report readback mismatch")
        ops.fcntl(fd, _F_ADD_SEALS, _DATA_SEALS)
        if ops.fcntl(fd, _F_GET_SEALS) != _DATA_SEALS:
            raise RuntimeClosureError("exact report seal profile unavailable")
        read_fd = ops.open(f"/proc/self/fd/{fd}", os.O_RDONLY | _O_CLOEXEC)
        if _generation(ops.fstat(read_fd)) != _generation(ops.fstat(fd)):
            raise RuntimeClosureError("read-only report descriptor identity mismatch")
        if ops.fcntl(read_fd, _F_GET_SEALS) != _DATA_SEALS:
            raise RuntimeClosureError("read-only report seals mismatch")
        ops.close(fd)
        return read_fd
    except BaseException as primary:
        _close_local(ops, (value for value in (read_fd, fd) if value is not None), primary)
        raise AssertionError("unreachable")

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def _object_report(object_: AuthenticatedObject) -> dict[str, Any]:
    _interpreter, soname, needed = _metadata(object_)
    return {
        "needed": list(needed),
        "role": object_.role,
        "sha256": object_.sha256,
        "size": object_.size,
        "soname": soname,
    }

def _encode_report(closures: Sequence[ResolvedToolClosure],
                   mappings: Sequence[MappedToolClosure]) -> bytes:
    mapping_by_tool = {item.tool: item for item in mappings}
    tools: list[dict[str, Any]] = []
    for closure in closures:
        objects = [_object_report(item) for item in closure.objects]
        tools.append({
            "closure_sha256": hashlib.sha256(_canonical(objects)).hexdigest(),
            "mapping_sha256": mapping_by_tool[closure.tool].mapping_sha256,
            "objects": objects,
            "seal_profile": None if closure.tool == "python3-parser" else _SEAL_PROFILE,
            "sealed_executable": closure.tool != "python3-parser",
            "tool": closure.tool,
        })
    digest_view = [
        {key: value for key, value in tool.items() if key != "mapping_sha256"}
        for tool in tools
    ]
    value = {
        "closure_sha256": hashlib.sha256(_canonical(digest_view)).hexdigest(),
        "tools": tools,
        "version": _VERSION,
    }
    return _canonical(value) + b"\n"

def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeClosureError("duplicate report key")
        result[key] = value
    return result

def _hex(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)

def _validate_report_value(value: Any) -> None:
    if type(value) is not dict or set(value) != {"closure_sha256", "tools", "version"}:
        raise RuntimeClosureError("invalid closure report object")
    if value["version"] != _VERSION or not _hex(value["closure_sha256"]):
        raise RuntimeClosureError("invalid closure report identity")
    tools = value["tools"]
    if type(tools) is not list or [item.get("tool") for item in tools if type(item) is dict] != [
        "python3-parser", "zstd", "gzip",
    ]:
        raise RuntimeClosureError("invalid closure report tool order")
    expected_keys = {
        "closure_sha256", "mapping_sha256", "objects", "seal_profile",
        "sealed_executable", "tool",
    }
    for index, tool in enumerate(tools):
        if type(tool) is not dict or set(tool) != expected_keys:
            raise RuntimeClosureError("invalid tool report")
        if not _hex(tool["closure_sha256"]) or not _hex(tool["mapping_sha256"]):
            raise RuntimeClosureError("invalid tool digest")
        sealed = index != 0
        if type(tool["sealed_executable"]) is not bool or tool["sealed_executable"] != sealed:
            raise RuntimeClosureError("invalid sealed executable declaration")
        if tool["seal_profile"] != (_SEAL_PROFILE if sealed else None):
            raise RuntimeClosureError("invalid seal profile")
        objects = tool["objects"]
        if type(objects) is not list or not 2 <= len(objects) <= _MAX_OBJECTS:
            raise RuntimeClosureError("invalid report object count")
        if [item.get("role") for item in objects[:2] if type(item) is dict] != ["executable", "loader"]:
            raise RuntimeClosureError("invalid object role order")
        providers: dict[str, int] = {}
        identities: set[tuple[str, int]] = set()
        previous_library: tuple[bytes, str] | None = None
        for object_index, object_ in enumerate(objects):
            if type(object_) is not dict or set(object_) != {"needed", "role", "sha256", "size", "soname"}:
                raise RuntimeClosureError("invalid reported runtime object")
            role = object_["role"]
            if role not in ("executable", "loader", "library") or (object_index >= 2) != (role == "library"):
                raise RuntimeClosureError("invalid reported role")
            if type(object_["size"]) is not int or not 1 <= object_["size"] <= _MAX_OBJECT_SIZE:
                raise RuntimeClosureError("invalid reported size")
            if not _hex(object_["sha256"]):
                raise RuntimeClosureError("invalid object digest")
            soname = object_["soname"]
            if soname is not None and (type(soname) is not str or not soname or "/" in soname):
                raise RuntimeClosureError("invalid reported SONAME")
            needed = object_["needed"]
            if type(needed) is not list or any(type(item) is not str or not item or "/" in item for item in needed):
                raise RuntimeClosureError("invalid reported dependencies")
            if len(needed) != len(set(needed)):
                raise RuntimeClosureError("duplicate reported dependency")
            identity = (object_["sha256"], object_["size"])
            if identity in identities:
                raise RuntimeClosureError("duplicate reported object")
            identities.add(identity)
            if soname is not None:
                if soname in providers:
                    raise RuntimeClosureError("duplicate reported provider")
                providers[soname] = object_index
            if role == "library":
                order = ((soname or "").encode("utf-8"), object_["sha256"])
                if previous_library is not None and order <= previous_library:
                    raise RuntimeClosureError("invalid library order")
                previous_library = order
        if any(needed not in providers for object_ in objects for needed in object_["needed"]):
            raise RuntimeClosureError("unresolved reported dependency")
        if hashlib.sha256(_canonical(objects)).hexdigest() != tool["closure_sha256"]:
            raise RuntimeClosureError("tool closure digest mismatch")
        mapped = [[item["role"], item["sha256"]] for item in objects]
        if hashlib.sha256(_canonical(mapped)).hexdigest() != tool["mapping_sha256"]:
            raise RuntimeClosureError("tool mapping digest mismatch")
    digest_view = [
        {key: item for key, item in tool.items() if key != "mapping_sha256"}
        for tool in tools
    ]
    if hashlib.sha256(_canonical(digest_view)).hexdigest() != value["closure_sha256"]:
        raise RuntimeClosureError("aggregate closure digest mismatch")

def _decode_report(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes or not data.endswith(b"\n") or data.endswith(b"\n\n") or len(data) > _MAX_REPORT:
        raise RuntimeClosureError("invalid canonical report framing")
    try:
        text = data[:-1].decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_strict_object,
                           parse_float=lambda _value: (_ for _ in ()).throw(RuntimeClosureError("float in report")),
                           parse_constant=lambda _value: (_ for _ in ()).throw(RuntimeClosureError("constant in report")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeClosureError("invalid report JSON") from error
    _validate_report_value(value)
    if _canonical(value) + b"\n" != data:
        raise RuntimeClosureError("noncanonical closure report")
    return value

def _validate_report_bytes(data: bytes) -> bytes:
    _decode_report(data)
    return data

def _canonical_report_for_tests(tool_records: Sequence[dict[str, Any]]) -> bytes:
    """Private deterministic codec seam; recompute all closure digests."""
    tools = json.loads(json.dumps(list(tool_records)))
    if type(tools) is not list:
        raise RuntimeClosureError("test tool records must be a sequence")
    for tool in tools:
        tool["closure_sha256"] = hashlib.sha256(_canonical(tool["objects"])).hexdigest()
    digest_view = [
        {key: value for key, value in tool.items() if key != "mapping_sha256"}
        for tool in tools
    ]
    report = _canonical({
        "closure_sha256": hashlib.sha256(_canonical(digest_view)).hexdigest(),
        "tools": tools,
        "version": _VERSION,
    }) + b"\n"
    return _validate_report_bytes(report)

class PreparedRuntimeClosure:
    def __init__(self, token: object, ops: _Ops) -> None:
        if token is not _PRIVATE_CONSTRUCTOR:
            raise RuntimeClosureError("use prepare_fixed_runtime_closure")
        self._ops = ops
        self._state = _State.NEW
        self._sources = _Registry(ops)
        self._outputs = _Registry(ops)
        self._children: list[_Child] = []
        self._report: bytes | None = None
        self._sealed: dict[str, SealedExecutable] = {}
        self._poison: BaseException | None = None
        self._fd_baseline: frozenset[int] = frozenset()
        self._child_baseline = b""
    @property
    def canonical_report(self) -> bytes:
        if self._state is not _State.READY or self._report is None:
            raise RuntimeClosureError("canonical report is available only in READY")
        return self._report
    def settle_fixed_handoff(self) -> RuntimeClosureHandoff:
        if self._state is not _State.READY:
            raise RuntimeClosureError("runtime closure is not ready for handoff")
        self._ops.checkpoint("handoff.before-revalidate")
        gzip = self._sealed["gzip"]
        zstd = self._sealed["zstd"]
        report_fd = next(fd for fd in self._outputs.values() if fd not in (gzip.fd, zstd.fd))
        if self._ops.fcntl(gzip.fd, _F_GET_SEALS) != _EXEC_SEALS:
            raise RuntimeClosureError("gzip seals changed before handoff")
        if self._ops.fcntl(zstd.fd, _F_GET_SEALS) != _EXEC_SEALS:
            raise RuntimeClosureError("zstd seals changed before handoff")
        if self._ops.fcntl(report_fd, _F_GET_SEALS) != _DATA_SEALS:
            raise RuntimeClosureError("report seals changed before handoff")
        if _read_complete(self._ops, report_fd, len(self.canonical_report)) != self.canonical_report:
            raise RuntimeClosureError("report changed before handoff")
        self._prove_ready_baseline()
        self._ops.checkpoint("handoff.before-transfer")
        handoff = RuntimeClosureHandoff(gzip.fd, zstd.fd, report_fd)
        for fd in (gzip.fd, zstd.fd, report_fd):
            self._outputs.remove(fd)
        self._state = _State.HANDED_OFF
        return handoff
    def close(self) -> None:
        if self._state is _State.CLOSED:
            return
        if self._state is _State.POISONED:
            assert self._poison is not None
            raise self._poison
        self._ops.checkpoint("cleanup.before")
        failures = list(self._outputs.close_all()) + list(self._sources.close_all())
        if self._children:
            failures.append(RuntimeClosureError("registered helper remains during close"))
        if self._state is not _State.HANDED_OFF:
            try:
                if self._ops.list_fds() != self._fd_baseline:
                    failures.append(RuntimeClosureError("descriptor baseline not restored"))
                if self._ops.child_baseline() != self._child_baseline:
                    failures.append(RuntimeClosureError("child baseline not restored"))
            except BaseException as error:
                failures.append(error)
        if failures:
            self._poison = RuntimeClosureCleanupError(failures)
            self._state = _State.POISONED
            raise self._poison
        self._state = _State.CLOSED
        self._ops.checkpoint("cleanup.after")
    def __enter__(self) -> "PreparedRuntimeClosure":
        if self._state is not _State.READY:
            raise RuntimeClosureError("runtime closure context is not ready")
        return self
    def __exit__(self, exc_type: Any, exc: BaseException | None, traceback: Any) -> None:
        del exc_type, traceback
        try:
            self.close()
        except BaseException as cleanup:
            if exc is not None:
                raise RuntimeClosureCleanupError((exc, cleanup)) from exc
            raise
    def _prove_ready_baseline(self) -> None:
        expected = self._fd_baseline | frozenset(self._outputs.values())
        if self._sources.values() or self._children:
            raise RuntimeClosureError("preparation authority remains at readiness")
        if self._ops.list_fds() != expected:
            raise RuntimeClosureError("unexpected descriptor at readiness")
        if self._ops.child_baseline() != self._child_baseline:
            raise RuntimeClosureError("helper baseline not restored")

_PRIVATE_CONSTRUCTOR = object()

def _prepare(ops: _Ops) -> PreparedRuntimeClosure:
    owner = PreparedRuntimeClosure(_PRIVATE_CONSTRUCTOR, ops)
    owner._fd_baseline = ops.list_fds()
    owner._child_baseline = ops.child_baseline()
    owner._state = _State.PREPARING
    ops.checkpoint("state.preparing")
    primary: BaseException | None = None
    try:
        closures: list[ResolvedToolClosure] = []
        for tool, path in FIXED_TOOL_TABLE:
            ops.checkpoint(f"resolve.{tool}.before")
            closure = _resolve_tool(ops, tool, path)
            closures.append(closure)
            for object_ in closure.objects:
                if object_.held_fd not in owner._sources.values():
                    owner._sources.add(object_.held_fd)
            ops.checkpoint(f"resolve.{tool}.after")
        unique = {
            item.identity: item.size for closure in closures for item in closure.objects
        }
        if sum(unique.values()) > _MAX_TOTAL_BYTES:
            raise RuntimeClosureError("deduplicated fixed closure byte bound")
        mappings: list[MappedToolClosure] = []
        for closure in closures:
            ops.checkpoint(f"mapping.{closure.tool}.before-spawn")
            child, gate = _spawn_helper(ops, closure)
            owner._children.append(child)
            mapping_error: BaseException | None = None
            try:
                ops.checkpoint(f"mapping.{closure.tool}.before-capture")
                mappings.append(_mapped_closure(ops, child, closure))
                ops.checkpoint(f"mapping.{closure.tool}.after-capture")
            except BaseException as error:
                mapping_error = error
            try:
                _stop_helper(ops, child, gate)
            except BaseException as cleanup_error:
                if mapping_error is not None:
                    raise RuntimeClosureCleanupError((mapping_error, cleanup_error)) from mapping_error
                raise
            finally:
                if child.reaped and child in owner._children:
                    owner._children.remove(child)
            if mapping_error is not None:
                raise mapping_error
            ops.checkpoint(f"mapping.{closure.tool}.after-cleanup")
        for tool in ("gzip", "zstd"):
            source = next(item.executable for item in closures if item.tool == tool)
            ops.checkpoint(f"seal.{tool}.before")
            sealed = _seal_source(ops, source, tool)
            owner._outputs.add(sealed.fd)
            owner._sealed[tool] = sealed
            ops.checkpoint(f"seal.{tool}.after")
        candidate = _encode_report(closures, mappings)
        candidate = ops.report_candidate(candidate)
        first = _validate_report_bytes(candidate)
        second = _validate_report_bytes(bytes(first))
        if first != second:
            raise RuntimeClosureError("independent report validation changed bytes")
        owner._report = first
        ops.checkpoint("report.before-seal")
        owner._outputs.add(_seal_report(ops, first))
        ops.checkpoint("report.after-seal")
        source_failures = owner._sources.close_all()
        if source_failures:
            raise RuntimeClosureCleanupError(source_failures)
        owner._prove_ready_baseline()
        ops.checkpoint("report.before-publish")
        owner._state = _State.READY
        ops.checkpoint("state.ready")
        return owner
    except BaseException as error:
        primary = error
    failures: list[BaseException] = [primary] if primary is not None else []
    failures.extend(owner._outputs.close_all())
    failures.extend(owner._sources.close_all())
    if owner._children:
        failures.append(RuntimeClosureError("helper cleanup remained after preparation failure"))
    try:
        if ops.list_fds() != owner._fd_baseline:
            failures.append(RuntimeClosureError("failure descriptor baseline not restored"))
        if ops.child_baseline() != owner._child_baseline:
            failures.append(RuntimeClosureError("failure child baseline not restored"))
    except BaseException as error:
        failures.append(error)
    owner._poison = RuntimeClosureCleanupError(failures)
    owner._state = _State.POISONED
    raise owner._poison from primary

def _prepare_with_adapter_for_tests(adapter: _Ops) -> PreparedRuntimeClosure:
    """Private scripted-adapter constructor for portable tests only."""
    if not isinstance(adapter, _Ops):
        raise TypeError("private test constructor requires _Ops")
    return _prepare(adapter)
_prepare_fixed_runtime_closure_for_test = _prepare_with_adapter_for_tests

def prepare_fixed_runtime_closure() -> PreparedRuntimeClosure:
    """Authenticate and prepare the one compile-time runtime closure."""
    return _prepare(_Ops())

__all__ = (
    "PreparedRuntimeClosure",
    "RuntimeClosureHandoff",
    "prepare_fixed_runtime_closure",
)
