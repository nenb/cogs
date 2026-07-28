"""Admitted fixed runtime-closure preparation.
This module is inert when imported normally.  The launcher bootstrap loads its exact
bytes in an authenticated private package and calls only the private admitted entry.
All authority remains behind private adapters and one issuer transaction.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import ctypes
import fcntl
import hashlib
import json
import os
import platform
import re
import resource
import select
import signal
import socket
import stat
import struct
import time
from typing import Any, NoReturn, Sequence
try:
    from .completion_elf import ElfMetadata, parse_elf64
except (ImportError, ValueError):
    from completion_elf import ElfMetadata, parse_elf64
FIXED_TOOL_TABLE = (('python3-parser', '/usr/bin/python3'), ('zstd', '/usr/bin/zstd'), ('gzip', '/usr/bin/gzip'))
_VERSION = 'cogs.trusted-runtime-closure/v1'
_HANDOFF_VERSION = 'cogs.runtime-handoff/v1'
_INTERPRETER = '/lib64/ld-linux-x86-64.so.2'
_LIBRARY_ROOTS = ('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/lib64', '/usr/lib64')
_MAX_OBJECT_SIZE = 128 * 1024 * 1024
_MAX_OBJECTS = 128
_MAX_TOOL_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_REPORT = 128 * 1024
_MAX_MAP_BYTES = 4 * 1024 * 1024
_MAX_MAP_LINES = 4096
_MAX_COMPONENTS = 256
_MAX_SYMLINKS = 40
_MAX_FDS = 16384
_GETDENTS_CALL_LIMIT = 32
_GETDENTS_BYTE_LIMIT = 1048576
_GETDENTS_CHUNK = 32768
_DIRENT_ALIGNMENT = 8
_IO_CHUNK = 1024 * 1024
_HELPER_START_SECONDS = 5.0
_HELPER_TERM_SECONDS = 1.0
_HELPER_KILL_SECONDS = 1.0
_SEAL_PROFILE = 'linux-memfd-exec-seals-v1'
_O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_O_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)
_MFD_CLOEXEC = 1
_MFD_ALLOW_SEALING = 2
_MFD_EXEC = 16
_F_ADD_SEALS = 1033
_F_GET_SEALS = 1034
_F_GETFD = 1
_F_GETFL = 3
_FD_CLOEXEC = 1
_F_SEAL_SEAL = 1
_F_SEAL_SHRINK = 2
_F_SEAL_GROW = 4
_F_SEAL_WRITE = 8
_F_SEAL_FUTURE_WRITE = 16
_F_SEAL_EXEC = 32
_DATA_SEALS = _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK | _F_SEAL_FUTURE_WRITE | _F_SEAL_SEAL
_EXEC_SEALS = _DATA_SEALS | _F_SEAL_EXEC
_PR_SET_PDEATHSIG = 1
_CLONE_PIDFD = 4096
_SYS_CLONE3 = 435
_SYS_CLOSE_RANGE = 436
_SYS_GETDENTS64 = 217
_UINT_MAX = (1 << 32) - 1
_KERNEL_EXECUTABLE_MAPPINGS = frozenset(('[vdso]', '[vsyscall]'))
_SONAME = re.compile('^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$')
_PACKAGE = re.compile(r'_cogs_o2_[0-9a-f]{16}')
class RuntimeClosureError(RuntimeError):
    """A fixed closure requirement was not satisfied."""
class RuntimeClosureUnavailable(RuntimeClosureError):
    """The exact fixed Linux primitive is unavailable."""
class RuntimeClosureCleanupError(RuntimeClosureError):
    """Cleanup failed or ownership became uncertain."""
    def __init__(self, failures: Sequence[BaseException]):
        if not failures:
            raise ValueError('cleanup failure aggregate cannot be empty')
        self.failures = tuple(failures)
        super().__init__(f'runtime closure cleanup failed ({len(self.failures)} errors)')
@dataclass(frozen=True)
class RuntimeObjectObservation:
    role: str
    size_bytes: int
    sha256: str
    soname: str | None
    needed: tuple[str, ...]
@dataclass(frozen=True)
class MappedObjectObservation:
    role: str
    sha256: str
@dataclass(frozen=True)
class RuntimeMappingQualificationResult:
    version: str
    source_revision: str
    source_set_sha256: str
    closure_sha256: str
    mapping_sha256: str
    objects: tuple[RuntimeObjectObservation, ...]
    mapped: tuple[MappedObjectObservation, ...]
    mapped_generations_exact: bool
    mapping_stable: bool
    helper_reaped: bool
    descriptors_restored: bool
    children_reaped: bool
@dataclass(frozen=True)
class DescriptorQualificationResult:
    version: str
    source_revision: str
    source_set_sha256: str
    nofile_measured: bool
    nofile_normalized: bool
    fd_198_exact: bool
    fd_4096_exact: bool
    close_range_exact: bool
    cloexec_exact: bool
    inheritance_exact: bool
    limit_restored: bool
    descriptors_restored: bool
    children_reaped: bool
@dataclass
class _LimitLease:
    original: tuple[int, int]
    restored: bool = False
@dataclass
class _DescriptorChildLease:
    pid: int
    pidfd: 'FdLease'
    target_identity: tuple[int, int]
    start_time: int | None = None
    session: int | None = None
    process_group: int | None = None
    executable_identity: tuple[int, int] | None = None
    released: bool = False
    reaped: bool = False
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
class _PathObservation:
    parent: tuple[int, int]
    component: str
    kind: str
    generation: SourceGeneration
    link: str | None = None
@dataclass(frozen=True)
class AuthenticatedObject:
    role: str
    logical_path: str
    held_fd: int
    generation: SourceGeneration
    transcript: tuple[_PathObservation, ...]
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
class SealedObject:
    fd: int
    source_generation: SourceGeneration
    size: int
    sha256: str
    elf: ElfMetadata
    seals: int
@dataclass(frozen=True)
class _PrivateGenerationRow:
    tool_index: int
    object_index: int
    role: str
    descriptor_index: int
    source_generation: SourceGeneration
    size: int
    sha256: str
    soname: str | None
    needed: tuple[str, ...]
    seal_profile: str = _SEAL_PROFILE
@dataclass(frozen=True)
class _IssuanceReceipt:
    version: str
    report_sha256: str
    closure_sha256: str
    binding_sha256: str
    generation_sha256: str
    descriptor_count: int
    issuer_pid: int
    consumer_pid: int
@dataclass
class _LiveIssuerCapability:
    admission: object
    endpoint: socket.socket
    package_name: str
    worker_pid: int
    peer_credentials: tuple[int, int, int]
    consumed: bool = False
    def consume(self, admission: object) -> None:
        if self.consumed:
            raise RuntimeClosureError('runtime closure capability was replayed')
        self.consumed = True
        if admission is not self.admission:
            raise RuntimeClosureError('runtime closure capability admission mismatch')
        if type(__package__) is not str or _PACKAGE.fullmatch(__package__) is None:
            raise RuntimeClosureError('runtime closure constructor is outside admitted package')
        if self.package_name != __package__ or self.worker_pid != os.getpid():
            raise RuntimeClosureError('runtime closure capability topology changed')
        if self.endpoint.fileno() < 0:
            raise RuntimeClosureError('runtime closure capability endpoint closed')
        observed = self.endpoint.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize('3i'),
        )
        peer = struct.unpack('3i', observed)
        if peer != self.peer_credentials:
            raise RuntimeClosureError('runtime closure capability peer changed')
        peer_pid, peer_uid, peer_gid = peer
        if peer_pid <= 0 or peer_pid == self.worker_pid:
            raise RuntimeClosureError('runtime closure capability peer topology changed')
        if peer_uid != os.getuid() or peer_gid != os.getgid():
            raise RuntimeClosureError('runtime closure capability credentials changed')
class _FdState(Enum):
    OWNED = 'OWNED'
    TRANSFERRED = 'TRANSFERRED'
    CLOSED = 'CLOSED'
    CLOSE_UNCERTAIN = 'CLOSE_UNCERTAIN'
@dataclass
class FdLease:
    fd: int
    purpose: str
    state: _FdState = _FdState.OWNED
    close_error: BaseException | None = None
    def close(self, ops: '_Ops') -> None:
        if self.state is _FdState.CLOSED:
            return
        if self.state is _FdState.CLOSE_UNCERTAIN:
            if self.close_error is None:
                raise RuntimeClosureError('uncertain descriptor lost its error')
            raise self.close_error
        if self.state is not _FdState.OWNED:
            raise RuntimeClosureError('transferred descriptor cannot be closed by former owner')
        try:
            ops.close(self.fd)
        except BaseException as error:
            self.state = _FdState.CLOSE_UNCERTAIN
            self.close_error = error
            raise
        self.state = _FdState.CLOSED
    def transfer(self) -> None:
        if self.state is not _FdState.OWNED:
            raise RuntimeClosureError('descriptor is not transferable')
        self.state = _FdState.TRANSFERRED
class _HelperState(Enum):
    SPAWNED = 'SPAWNED'
    REGISTERED = 'REGISTERED'
    PREEXEC_IDENTIFIED = 'PREEXEC_IDENTIFIED'
    EXEC_IDENTIFIED = 'EXEC_IDENTIFIED'
    STOPPING = 'STOPPING'
    REAPED = 'REAPED'
    UNCERTAIN = 'UNCERTAIN'
@dataclass
class HelperLease:
    pid: int
    pidfd: FdLease
    input_gate: FdLease
    registration_gate: FdLease
    release_gate: FdLease
    status_gate: FdLease
    state: _HelperState = _HelperState.SPAWNED
    start_time: int | None = None
    session: int | None = None
    process_group: int | None = None
    executable_identity: tuple[int, int] | None = None
    target_executable_identity: tuple[int, int] | None = None
    release_attempted: bool = False
    outer_registration_attempted: bool = False
    outer_token: object | None = None
    descendants: tuple[int, ...] = ()
    cleanup_error: BaseException | None = None
    @property
    def reaped(self) -> bool:
        return self.state is _HelperState.REAPED
@dataclass
class PreparationLease:
    ops: '_Ops'
    fd_baseline: frozenset[int]
    child_baseline: tuple[int, ...]
    fds: list[FdLease] = field(default_factory=list)
    helpers: list[HelperLease] = field(default_factory=list)
    outer: object | None = None
    def register_fd(self, fd: int, purpose: str) -> FdLease:
        if type(fd) is not int or fd < 0:
            raise RuntimeClosureError('invalid descriptor registration')
        if any((item.fd == fd and item.state is _FdState.OWNED for item in self.fds)):
            raise RuntimeClosureError('duplicate owned descriptor registration')
        lease = FdLease(fd, purpose)
        self.fds.append(lease)
        return lease
    def owned_fds(self) -> tuple[int, ...]:
        return tuple((item.fd for item in self.fds if item.state is _FdState.OWNED))
    def close_many(self, leases: Sequence[FdLease], primary: BaseException | None=None) -> None:
        failures: list[BaseException] = []
        if primary is not None:
            failures.append(primary)
        for lease in reversed(tuple(leases)):
            if lease.state is _FdState.CLOSE_UNCERTAIN:
                if lease.close_error is None:
                    failures.append(RuntimeClosureError('uncertain descriptor lost its error'))
                else:
                    in_aggregate = (
                        isinstance(primary, RuntimeClosureCleanupError)
                        and lease.close_error in primary.failures
                    )
                    if lease.close_error is not primary and not in_aggregate:
                        failures.append(lease.close_error)
                continue
            if lease.state is not _FdState.OWNED:
                continue
            try:
                lease.close(self.ops)
            except BaseException as error:
                failures.append(error)
        if len(failures) > 1 or (failures and primary is None):
            raise RuntimeClosureCleanupError(failures)
        if failures:
            raise failures[0]
class _OwnerState(Enum):
    PREPARING = 'PREPARING'
    READY = 'READY'
    ISSUING = 'ISSUING'
    CONSUMED = 'CONSUMED'
    CLOSED = 'CLOSED'
    POISONED = 'POISONED'
class _Ops:
    """Private primitive adapter.  Public production never accepts an instance."""
    def checkpoint(self, name: str) -> None:
        del name
    def order(self, name: str, values: Sequence[Any]) -> tuple[Any, ...]:
        del name
        return tuple(values)
    def report_candidate(self, data: bytes) -> bytes:
        return data
    def open(self, path: str, flags: int, mode: int=384, *, dir_fd: int | None=None) -> int:
        return os.open(path, flags, mode, dir_fd=dir_fd)
    def close(self, fd: int) -> None:
        os.close(fd)
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
    def fcntl(self, fd: int, command: int, argument: int=0) -> int:
        return fcntl.fcntl(fd, command, argument)
    def getrlimit(self) -> tuple[int, int]:
        return resource.getrlimit(resource.RLIMIT_NOFILE)
    def setrlimit(self, value: tuple[int, int]) -> None:
        resource.setrlimit(resource.RLIMIT_NOFILE, value)
    def memfd_create(self, name: str, flags: int) -> int:
        return os.memfd_create(name, flags)
    def pipe(self) -> tuple[int, int]:
        return os.pipe2(_O_CLOEXEC)
    def dup2(self, source: int, target: int, inheritable: bool=True) -> None:
        os.dup2(source, target, inheritable=inheritable)
    def getsid(self, pid: int) -> int:
        return os.getsid(pid)
    def getpgid(self, pid: int) -> int:
        return os.getpgid(pid)
    def getpid(self) -> int:
        return os.getpid()
    def getppid(self) -> int:
        return os.getppid()
    def getuid(self) -> int:
        return os.getuid()
    def setsid(self) -> None:
        os.setsid()
    def monotonic(self) -> float:
        return time.monotonic()
    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
    def poll_readable(self, fd: int, seconds: float) -> bool:
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return bool(poller.poll(max(0, int(seconds * 1000))))

    def pidfd_signal(self, pidfd: int, signum: int) -> None:
        signal.pidfd_send_signal(pidfd, signum)

    def wait_pidfd_nohang(self, pidfd: int) -> bool:
        result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
        return result is not None

    def waitid_pidfd_nohang(self, pidfd: int) -> os.waitid_result | None:
        options = os.WEXITED | os.WNOHANG | os.WNOWAIT
        return os.waitid(os.P_PIDFD, pidfd, options)

    def reap_pid_nohang(self, pid: int) -> tuple[int, int]:
        return os.waitpid(pid, os.WNOHANG)

    def execve(self, fd: int, argv: Sequence[str], environment: dict[str, str]) -> NoReturn:
        os.execve(fd, list(argv), environment)

    def exit_child(self, status: int) -> NoReturn:
        os._exit(status)

    def architecture_gate(self) -> None:
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise RuntimeClosureUnavailable('fixed closure requires Linux x86-64')

    def _syscall(self, number: int, *arguments: Any) -> int:
        self.architecture_gate()
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.syscall(number, *arguments)
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return int(result)

    def getdents(self, fd: int, maximum: int=32768) -> bytes:
        buffer = ctypes.create_string_buffer(maximum)
        count = self._syscall(_SYS_GETDENTS64, fd, ctypes.byref(buffer), maximum)
        return bytes(buffer.raw[:count])

    def close_range(self, first: int, last: int) -> None:
        self._syscall(_SYS_CLOSE_RANGE, first, last, 0)

    def clone3_pidfd(self) -> tuple[int, int]:
        pidfd = ctypes.c_int(-1)
        raw = struct.pack('=11Q', *_clone3_arguments(ctypes.addressof(pidfd)))
        arguments = ctypes.create_string_buffer(raw)
        pid = self._syscall(_SYS_CLONE3, ctypes.byref(arguments), len(raw))
        return (pid, int(pidfd.value))

    def set_parent_death_signal(self, signum: int) -> None:
        self.architecture_gate()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_PDEATHSIG, signum, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

def _clone3_arguments(pidfd_address: int) -> tuple[int, ...]:
    return (_CLONE_PIDFD, pidfd_address, 0, 0, signal.SIGCHLD, 0, 0, 0, 0, 0, 0)

def _generation(value: os.stat_result) -> SourceGeneration:
    return SourceGeneration(
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )

def _require_component(value: os.stat_result, *, directory: bool=False) -> None:
    if value.st_uid != 0 or value.st_mode & 18:
        raise RuntimeClosureError('insecure fixed path component')
    if directory and (not stat.S_ISDIR(value.st_mode)):
        raise RuntimeClosureError('fixed path component is not a directory')

def _require_source(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise RuntimeClosureError('runtime object is not regular')
    if value.st_uid != 0 or value.st_mode & 18:
        raise RuntimeClosureError('runtime object has insecure ownership or mode')
    if not 1 <= value.st_size <= _MAX_OBJECT_SIZE:
        raise RuntimeClosureError('runtime object size bound')

def _finish_fds(ops: _Ops, leases: Sequence[FdLease], primary: BaseException | None=None) -> None:
    failures: list[BaseException] = []
    if primary is not None:
        failures.append(primary)
    for lease in reversed(tuple(leases)):
        if lease.state is _FdState.CLOSE_UNCERTAIN:
            if lease.close_error is None:
                failures.append(RuntimeClosureError('uncertain descriptor lost its error'))
            else:
                in_aggregate = (
                    isinstance(primary, RuntimeClosureCleanupError)
                    and lease.close_error in primary.failures
                )
                if lease.close_error is not primary and not in_aggregate:
                    failures.append(lease.close_error)
            continue
        if lease.state is not _FdState.OWNED:
            continue
        try:
            lease.close(ops)
        except BaseException as error:
            failures.append(error)
    if len(failures) > 1 or (failures and primary is None):
        raise RuntimeClosureCleanupError(failures)
    if failures:
        raise failures[0]

def _read_complete(ops: _Ops, fd: int, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        chunk = ops.pread(fd, min(_IO_CHUNK, expected_size - offset), offset)
        if not chunk:
            raise RuntimeClosureError('short runtime object read')
        chunks.append(chunk)
        offset += len(chunk)
    if ops.pread(fd, 1, expected_size):
        raise RuntimeClosureError('runtime object grew during read')
    return b''.join(chunks)

def _split_path(path: str) -> list[str]:
    if type(path) is not str or not path.startswith('/') or '\x00' in path:
        raise RuntimeClosureError('invalid fixed absolute path')
    parts = path.split('/')[1:]
    if not parts or any((part in ('', '.', '..') for part in parts)):
        raise RuntimeClosureError('invalid fixed path components')
    return parts

def _resolve_once(ops: _Ops, path: str, *, open_source: bool=True) -> tuple[int | None, SourceGeneration, tuple[_PathObservation, ...]]:
    queue = _split_path(path)
    directories: list[FdLease] = []
    transcript: list[_PathObservation] = []
    final: FdLease | None = None
    primary: BaseException | None = None
    final_generation: SourceGeneration | None = None
    try:
        root = FdLease(ops.open('/', os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW), 'resolution-root')
        directories.append(root)
        root_stat = ops.fstat(root.fd)
        _require_component(root_stat, directory=True)
        root_generation = _generation(root_stat)
        transcript.append(_PathObservation((root_stat.st_dev, root_stat.st_ino), '/', 'directory', root_generation))
        symlinks = 0
        components = 0
        while queue:
            components += 1
            if components > _MAX_COMPONENTS:
                raise RuntimeClosureError('fixed path component bound')
            component = queue.pop(0)
            if component == '..':
                if len(directories) == 1:
                    raise RuntimeClosureError('fixed path escapes root')
                closing = directories.pop()
                closing.close(ops)
                continue
            if component in ('', '.') or '/' in component:
                raise RuntimeClosureError('invalid resolved path component')
            parent_stat = ops.fstat(directories[-1].fd)
            parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
            before = ops.stat(component, dir_fd=directories[-1].fd, follow_symlinks=False)
            before_generation = _generation(before)
            if stat.S_ISLNK(before.st_mode):
                if before.st_uid != 0:
                    raise RuntimeClosureError('fixed symlink is not root owned')
                symlinks += 1
                if symlinks > _MAX_SYMLINKS:
                    raise RuntimeClosureError('fixed symlink bound')
                target = ops.readlink(component, dir_fd=directories[-1].fd)
                after = ops.stat(component, dir_fd=directories[-1].fd, follow_symlinks=False)
                if _generation(after) != before_generation or not target or '\x00' in target:
                    raise RuntimeClosureError('fixed symlink changed')
                transcript.append(_PathObservation(parent_identity, component, 'symlink', before_generation, target))
                target_parts = target.split('/')
                if target.startswith('/'):
                    while len(directories) > 1:
                        directories.pop().close(ops)
                    target_parts = target_parts[1:]
                if any((part in ('', '.') for part in target_parts)):
                    raise RuntimeClosureError('invalid fixed symlink target')
                queue = target_parts + queue
                continue
            if queue:
                _require_component(before, directory=True)
                component_fd = ops.open(
                    component,
                    os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                    dir_fd=directories[-1].fd,
                )
                opened = FdLease(component_fd, 'path-component')
                directories.append(opened)
                after = ops.fstat(opened.fd)
                _require_component(after, directory=True)
                if _generation(after) != before_generation:
                    raise RuntimeClosureError('fixed directory changed')
                transcript.append(_PathObservation(parent_identity, component, 'directory', before_generation))
                continue
            _require_source(before)
            final_generation = before_generation
            transcript.append(_PathObservation(parent_identity, component, 'file', before_generation))
            if open_source:
                final = FdLease(ops.open(component, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=directories[-1].fd), 'runtime-source')
                after = ops.fstat(final.fd)
                _require_source(after)
                if _generation(after) != final_generation:
                    raise RuntimeClosureError('fixed runtime object changed')
        if final_generation is None or (open_source and final is None):
            raise RuntimeClosureError('fixed path has no final object')
        if _generation(ops.fstat(directories[0].fd)) != root_generation:
            raise RuntimeClosureError('fixed root changed')
    except BaseException as error:
        primary = error
    try:
        _finish_fds(ops, directories, primary)
    except BaseException as error:
        if final is None:
            raise
        _finish_fds(ops, (final,), error)
        raise RuntimeClosureError('unreachable')
    if final_generation is None:
        raise RuntimeClosureError('missing final path generation')
    return (None if final is None else final.fd, final_generation, tuple(transcript))

def _authenticate(ops: _Ops, path: str, role: str) -> AuthenticatedObject:
    fd: int | None = None
    try:
        (fd, generation, transcript) = _resolve_once(ops, path)
        if fd is None:
            raise RuntimeClosureError('authenticated source descriptor missing')
        raw = _read_complete(ops, fd, generation.size)
        after = ops.fstat(fd)
        _require_source(after)
        if _generation(after) != generation:
            raise RuntimeClosureError('runtime source generation changed')
        metadata = parse_elf64(raw)
        (second_fd, second_generation, second_transcript) = _resolve_once(ops, path, open_source=False)
        if second_fd is not None:
            raise RuntimeClosureError('observation traversal opened final source')
        if second_generation != generation or second_transcript != transcript:
            raise RuntimeClosureError('fixed logical path transcript changed')
        return AuthenticatedObject(role, path, fd, generation, transcript, len(raw), hashlib.sha256(raw).hexdigest(), metadata)
    except BaseException as primary:
        if fd is not None:
            _finish_fds(ops, (FdLease(fd, 'failed-authentication'),), primary)
        raise

def _metadata(value: AuthenticatedObject) -> tuple[str | None, str | None, tuple[str, ...]]:
    needed = tuple(value.elf.needed)
    if len(needed) > _MAX_OBJECTS or len(needed) != len(set(needed)):
        raise RuntimeClosureError('invalid ordered dependency metadata')
    for name in needed:
        _require_soname(name)
    if value.elf.soname is not None:
        _require_soname(value.elf.soname)
    return (value.elf.interpreter, value.elf.soname, needed)

def _require_soname(value: str) -> None:
    if type(value) is not str or _SONAME.fullmatch(value) is None:
        raise RuntimeClosureError('invalid dependency SONAME')

def _close_objects(ops: _Ops, values: Sequence[AuthenticatedObject], primary: BaseException | None=None) -> None:
    leases = tuple((FdLease(value.held_fd, f'source:{value.role}') for value in values))
    _finish_fds(ops, leases, primary)

def _resolve_library(ops: _Ops, soname: str) -> AuthenticatedObject:
    _require_soname(soname)
    candidates: list[AuthenticatedObject] = []
    try:
        roots = ops.order('library-roots', _LIBRARY_ROOTS)
        if len(roots) != len(_LIBRARY_ROOTS) or set(roots) != set(_LIBRARY_ROOTS):
            raise RuntimeClosureError('library root enumeration changed')
        for root in roots:
            try:
                candidate = _authenticate(ops, f'{root}/{soname}', 'library')
            except FileNotFoundError:
                continue
            if _metadata(candidate)[1] != soname:
                _close_objects(ops, (candidate,))
                raise RuntimeClosureError('dependency SONAME mismatch')
            duplicate = next((value for value in candidates if value.identity == candidate.identity), None)
            if duplicate is None:
                candidates.append(candidate)
                continue
            if duplicate.generation != candidate.generation or duplicate.sha256 != candidate.sha256 or duplicate.elf != candidate.elf:
                _close_objects(ops, (candidate,))
                raise RuntimeClosureError('same-identity provider changed')
            _close_objects(ops, (candidate,))
        if len(candidates) != 1:
            raise RuntimeClosureError('missing or distinct-identity ambiguous provider')
        return candidates.pop()
    except BaseException as primary:
        _close_objects(ops, candidates, primary)
        raise

def _resolve_tool(ops: _Ops, tool: str, path: str) -> ResolvedToolClosure:
    owned: list[AuthenticatedObject] = []
    try:
        executable = _authenticate(ops, path, 'executable')
        owned.append(executable)
        if _metadata(executable)[0] != _INTERPRETER:
            raise RuntimeClosureError('unknown or missing interpreter')
        loader = _authenticate(ops, _INTERPRETER, 'loader')
        owned.append(loader)
        if loader.identity == executable.identity or _metadata(loader)[0] is not None:
            raise RuntimeClosureError('loader role ambiguity')
        objects: dict[tuple[int, int], AuthenticatedObject] = {executable.identity: executable, loader.identity: loader}
        providers: dict[str, AuthenticatedObject] = {}
        pending: list[str] = []
        for value in (executable, loader):
            (_interpreter, soname, needed) = _metadata(value)
            pending.extend(needed)
            if soname is not None:
                if soname in providers and providers[soname].identity != value.identity:
                    raise RuntimeClosureError('duplicate SONAME provider')
                providers[soname] = value
        examined: set[tuple[int, int]] = set()
        while pending:
            name = pending.pop(0)
            provider = providers.get(name)
            if provider is None:
                provider = _resolve_library(ops, name)
                existing = objects.get(provider.identity)
                if existing is not None:
                    if existing.role != 'library':
                        _close_objects(ops, (provider,))
                        raise RuntimeClosureError('cross-role identity alias')
                    _close_objects(ops, (provider,))
                    provider = existing
                else:
                    if _metadata(provider)[0] is not None:
                        _close_objects(ops, (provider,))
                        raise RuntimeClosureError('library declares an interpreter')
                    owned.append(provider)
                    objects[provider.identity] = provider
                if _metadata(provider)[1] != name:
                    raise RuntimeClosureError('library provider mismatch')
                providers[name] = provider
            if provider.identity not in examined:
                examined.add(provider.identity)
                pending.extend(_metadata(provider)[2])
            if len(objects) > _MAX_OBJECTS:
                raise RuntimeClosureError('tool closure object bound')
            if sum((value.size for value in objects.values())) > _MAX_TOOL_BYTES:
                raise RuntimeClosureError('tool closure byte bound')
        for value in objects.values():
            if any((name not in providers for name in _metadata(value)[2])):
                raise RuntimeClosureError('unresolved closure dependency')
        library_values = (
            value
            for value in objects.values()
            if value.identity not in (executable.identity, loader.identity)
        )
        libraries = tuple(sorted(
            library_values,
            key=lambda value: ((_metadata(value)[1] or '').encode(), value.sha256),
        ))
        return ResolvedToolClosure(tool, executable, loader, libraries)
    except BaseException as primary:
        _close_objects(ops, owned, primary)
        raise

def _parse_dirent_chunk(raw: bytes) -> tuple[tuple[int, ...], int]:
    if type(raw) is not bytes:
        raise RuntimeClosureError('invalid descriptor dirent chunk')
    if len(raw) > _GETDENTS_CHUNK:
        raise RuntimeClosureError('descriptor baseline bound')
    offset = 0
    records = 0
    names: list[int] = []
    while offset < len(raw):
        if len(raw) - offset < 19:
            raise RuntimeClosureError('truncated descriptor dirent')
        if offset % _DIRENT_ALIGNMENT:
            raise RuntimeClosureError('unaligned descriptor dirent')
        (_inode, _position, record_length, _kind) = struct.unpack_from('=QqHB', raw, offset)
        end = offset + record_length
        if record_length < 24 or record_length % _DIRENT_ALIGNMENT or end > len(raw):
            raise RuntimeClosureError('malformed descriptor dirent')
        field = raw[offset + 19:end]
        nul = field.find(b'\x00')
        if nul < 0 or any(field[nul + 1:]):
            raise RuntimeClosureError('unterminated or nonzero-tail descriptor dirent name')
        name = field[:nul]
        if name not in (b'.', b'..'):
            canonical = bool(name) and name.isdigit()
            canonical = canonical and (len(name) == 1 or not name.startswith(b'0'))
            if not canonical:
                raise RuntimeClosureError('invalid descriptor name')
            value = int(name)
            if value > 2147483647 or value in names:
                raise RuntimeClosureError('duplicate or out-of-range descriptor')
            names.append(value)
        offset = end
        records += 1
    return (tuple(names), records)

def _parse_dirents(raw: bytes) -> tuple[int, ...]:
    return _parse_dirent_chunk(raw)[0]

def _snapshot_fd_directory(
    ops: _Ops,
    path: str,
    expected_enumerator: bool,
) -> frozenset[int]:
    flags = os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW
    directory = FdLease(ops.open(path, flags), 'fd-enumerator')
    values: list[int] = []
    seen: set[int] = set()
    calls = 0
    total = 0
    entries = 0
    primary: BaseException | None = None
    try:
        while calls < _GETDENTS_CALL_LIMIT:
            calls += 1
            chunk = ops.getdents(directory.fd, _GETDENTS_CHUNK)
            total += len(chunk)
            if total > _GETDENTS_BYTE_LIMIT:
                raise RuntimeClosureError('descriptor enumeration byte bound')
            if not chunk:
                break
            parsed, record_count = _parse_dirent_chunk(chunk)
            entries += record_count
            if entries > _MAX_FDS:
                raise RuntimeClosureError('descriptor baseline bound')
            if seen.intersection(parsed):
                raise RuntimeClosureError('duplicate descriptor across dirent chunks')
            seen.update(parsed)
            values.extend(parsed)
        else:
            raise RuntimeClosureError('descriptor enumeration call bound before EOF')
        enumerator_count = values.count(directory.fd)
        if expected_enumerator and enumerator_count != 1:
            raise RuntimeClosureError('descriptor enumerator was not observed exactly once')
    except BaseException as error:
        primary = error
    _finish_fds(ops, (directory,), primary)
    if expected_enumerator:
        seen.remove(directory.fd)
    return frozenset(seen)

def _snapshot_fds(ops: _Ops) -> frozenset[int]:
    return _snapshot_fd_directory(ops, '/proc/self/fd', True)

def _read_stream_bounded(ops: _Ops, fd: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = ops.read(fd, min(65536, maximum + 1 - total))
        if not chunk:
            return b''.join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise RuntimeClosureError('proc stream byte bound')

def _read_proc(ops: _Ops, path: str, maximum: int) -> bytes:
    lease = FdLease(ops.open(path, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW), f'proc:{path}')
    primary: BaseException | None = None
    result = b''
    try:
        result = _read_stream_bounded(ops, lease.fd, maximum)
    except BaseException as error:
        primary = error
    _finish_fds(ops, (lease,), primary)
    return result

def _parse_proc_stat(raw: bytes, expected_pid: int) -> int:
    if not raw.endswith(b'\n') or raw.count(b'\n') != 1 or b'\x00' in raw:
        raise RuntimeClosureError('malformed process stat framing')
    prefix = str(expected_pid).encode() + b' ('
    if not raw.startswith(prefix):
        raise RuntimeClosureError('process stat PID mismatch')
    close = raw.rfind(b') ')
    if close < len(prefix) - 1:
        raise RuntimeClosureError('malformed process stat command')
    fields = raw[close + 2:-1].split(b' ')
    if len(fields) < 20 or any((not field for field in fields)):
        raise RuntimeClosureError('truncated process stat')
    if len(fields[0]) != 1 or fields[0] not in b'RSDZTWtXxKPI':
        raise RuntimeClosureError('invalid process state')
    for field in fields[1:19]:
        lexical = field[1:] if field.startswith(b'-') else field
        if not lexical.isdigit():
            raise RuntimeClosureError('malformed process stat field')
    if not fields[19].isdigit():
        raise RuntimeClosureError('malformed process start time')
    start = int(fields[19])
    if start < 0 or start >= 1 << 64:
        raise RuntimeClosureError('process start time bound')
    return start

def _parse_children(raw: bytes) -> tuple[int, ...]:
    if b'\x00' in raw or raw.count(b'\n') > 1 or (b'\n' in raw and (not raw.endswith(b'\n'))):
        raise RuntimeClosureError('malformed children framing')
    body = raw[:-1] if raw.endswith(b'\n') else raw
    if body.endswith(b' '):
        body = body[:-1]
    if not body:
        return ()
    fields = body.split(b' ')
    if any((not value or not value.isdigit() for value in fields)):
        raise RuntimeClosureError('malformed children record')
    values = tuple((int(value) for value in fields))
    if any((value <= 0 or value > 2147483647 for value in values)) or len(set(values)) != len(values):
        raise RuntimeClosureError('invalid child identity')
    return values

@dataclass(frozen=True)
class _MapRow:
    start: int
    end: int
    permissions: bytes
    offset: int
    major: int
    minor: int
    inode: int
    path: str

def _parse_maps(raw: bytes) -> tuple[_MapRow, ...]:
    if not raw.endswith(b'\n') or len(raw.splitlines()) > _MAX_MAP_LINES:
        raise RuntimeClosureError('incomplete or oversized maps snapshot')
    rows: list[_MapRow] = []
    previous_end = 0
    for line in raw.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise RuntimeClosureError('malformed maps row')
        (address, permissions, offset_raw, device_raw, inode_raw) = fields[:5]
        try:
            (start_raw, end_raw) = address.split(b'-', 1)
            (major_raw, minor_raw) = device_raw.split(b':', 1)
            start = int(start_raw, 16)
            end = int(end_raw, 16)
            file_offset = int(offset_raw, 16)
            major = int(major_raw, 16)
            minor = int(minor_raw, 16)
            inode = int(inode_raw, 10)
        except (ValueError, TypeError) as error:
            raise RuntimeClosureError('malformed maps identity') from error
        valid_permissions = (
            len(permissions) == 4
            and permissions[0:1] in (b'r', b'-')
            and permissions[1:2] in (b'w', b'-')
            and permissions[2:3] in (b'x', b'-')
            and permissions[3:4] in (b'p', b's')
        )
        valid_extent = start > 0 and start < end and start >= previous_end
        valid_identity = major >= 0 and minor >= 0 and inode >= 0
        if not valid_extent or not valid_permissions or not valid_identity or file_offset % 4096:
            raise RuntimeClosureError('invalid maps extent or metadata')
        path = fields[5].decode('utf-8', 'strict') if len(fields) == 6 else ''
        rows.append(_MapRow(start, end, permissions, file_offset, major, minor, inode, path))
        previous_end = end
    return tuple(rows)

def _child_argv(tool: str) -> tuple[str, ...]:
    if tool == 'python3-parser':
        return ('python3', '-I', '-B', '-c', "__import__('os').read(0,1)")
    if tool == 'gzip':
        return ('gzip', '-dc')
    if tool == 'zstd':
        return ('zstd', '-dc', '--no-progress')
    raise RuntimeClosureError('unknown fixed helper')

def _descriptor_child_argv() -> tuple[str, ...]:
    program = "import os\nos.write(197,b'R')\nos.read(0,1)\n"
    return ('python3', '-I', '-B', '-c', program)

def _reserve_stdio(ops: _Ops) -> None:
    for target in range(3):
        try:
            ops.fstat(target)
            continue
        except OSError as error:
            if error.errno != 9:
                raise
        opened = FdLease(ops.open('/dev/null', os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW), f'stdio-{target}')
        if opened.fd == target:
            opened.state = _FdState.TRANSFERRED
            continue
        try:
            ops.dup2(opened.fd, target, inheritable=True)
        except BaseException as primary:
            _finish_fds(ops, (opened,), primary)
        opened.close(ops)

def _close_complement(ops: _Ops, allowed: Sequence[int]) -> None:
    keep = sorted(set(allowed))
    if any((value < 0 for value in keep)):
        raise RuntimeClosureError('invalid child descriptor allowlist')
    first = 0
    for value in keep:
        if first < value:
            ops.close_range(first, value - 1)
        first = value + 1
    if first <= _UINT_MAX:
        ops.close_range(first, _UINT_MAX)

def _child_fail(ops: _Ops, status_fd: int, code: bytes) -> NoReturn:
    try:
        if len(code) != 2 or not code.endswith(b'\n'):
            code = b'E\n'
        ops.write(status_fd, code)
    except BaseException:
        pass
    ops.exit_child(127)

def _outer_helper_call(preparation: PreparationLease, name: str, value: object, deadline: float) -> object:
    callback = getattr(preparation.outer, name, None)
    if not callable(callback) or preparation.ops.monotonic() >= deadline:
        raise RuntimeClosureError('outer helper authority unavailable or late')
    result = callback(value, deadline)
    if preparation.ops.monotonic() > deadline:
        raise RuntimeClosureError('outer helper authority deadline')
    return result

def _spawn_helper(
    ops: _Ops,
    preparation: PreparationLease,
    closure: ResolvedToolClosure,
) -> HelperLease:
    deadline = ops.monotonic() + _HELPER_START_SECONDS
    input_read = input_write = None
    registration_read = registration_write = None
    release_read = release_write = None
    status_read = status_write = devnull = None
    created: list[FdLease] = []
    pid: int | None = None
    try:
        for purpose in ('input', 'registration', 'release', 'status'):
            read_fd, write_fd = ops.pipe()
            read_lease = preparation.register_fd(read_fd, f'helper-{purpose}-read')
            write_lease = preparation.register_fd(write_fd, f'helper-{purpose}-write')
            created.extend((read_lease, write_lease))
            if purpose == 'input':
                input_read, input_write = read_lease, write_lease
            elif purpose == 'registration':
                registration_read, registration_write = read_lease, write_lease
            elif purpose == 'release':
                release_read, release_write = read_lease, write_lease
            else:
                status_read, status_write = read_lease, write_lease
        devnull_fd = ops.open(
            '/dev/null',
            os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW,
        )
        devnull = preparation.register_fd(devnull_fd, 'helper-devnull')
        created.append(devnull)
        parent = ops.getpid()
        pid, pidfd_number = ops.clone3_pidfd()
        if pid == 0:
            try:
                gates = (
                    input_read,
                    input_write,
                    registration_read,
                    registration_write,
                    release_read,
                    release_write,
                    status_read,
                    status_write,
                )
                if None in gates:
                    _child_fail(ops, -1, b'E\n')
                if ops.read(registration_read.fd, 2) != b'G\n':
                    _child_fail(ops, status_write.fd, b'G\n')
                input_write.close(ops)
                registration_write.close(ops)
                release_write.close(ops)
                status_read.close(ops)
                ops.setsid()
                ops.set_parent_death_signal(signal.SIGKILL)
                if ops.getppid() != parent:
                    _child_fail(ops, status_write.fd, b'P\n')
                ops.dup2(input_read.fd, 0, inheritable=True)
                ops.dup2(devnull.fd, 1, inheritable=True)
                ops.dup2(devnull.fd, 2, inheritable=True)
                allowed = (
                    0,
                    1,
                    2,
                    release_read.fd,
                    status_write.fd,
                    closure.executable.held_fd,
                )
                _close_complement(ops, allowed)
                if ops.write(status_write.fd, b'R\n') != 2:
                    _child_fail(ops, status_write.fd, b'W\n')
                if ops.read(release_read.fd, 2) != b'G\n':
                    _child_fail(ops, status_write.fd, b'G\n')
                ops.execve(closure.executable.held_fd, _child_argv(closure.tool), {})
            except BaseException:
                status_fd = status_write.fd if status_write is not None else -1
                _child_fail(ops, status_fd, b'E\n')
        if type(pid) is not int or pid <= 0 or pidfd_number < 0:
            raise RuntimeClosureError('invalid atomic helper spawn result')
        pidfd = preparation.register_fd(pidfd_number, 'helper-pidfd')
        helper = HelperLease(
            pid,
            pidfd,
            input_write,
            registration_write,
            release_write,
            status_read,
            target_executable_identity=closure.executable.identity,
        )
        preparation.helpers.append(helper)
        helper.start_time = _parse_proc_stat(
            _read_proc(ops, f'/proc/{pid}/stat', 4096),
            pid,
        )
        helper.session = ops.getsid(pid)
        helper.process_group = ops.getpgid(pid)
        helper.executable_identity = _proc_executable_identity(ops, pid)
        helper.outer_registration_attempted = True
        helper.outer_token = _outer_helper_call(preparation, '_register_runtime_helper', helper, deadline)
        if helper.outer_token is None:
            raise RuntimeClosureError('outer helper registration token missing')
        helper.state = _HelperState.REGISTERED
        if ops.write(registration_write.fd, b'G\n') != 2:
            raise RuntimeClosureError('helper registration release failed')
        registration_write.close(ops)
        for lease in (
            input_read,
            registration_read,
            release_read,
            status_write,
            devnull,
        ):
            if lease is not None:
                lease.close(ops)
        if not ops.poll_readable(status_read.fd, deadline - ops.monotonic()):
            raise RuntimeClosureError('helper pre-exec readiness timeout')
        if _read_exact_status(ops, status_read.fd) != b'R\n':
            raise RuntimeClosureError('helper pre-exec readiness failed')
        observed_start = _parse_proc_stat(
            _read_proc(ops, f'/proc/{pid}/stat', 4096),
            pid,
        )
        if observed_start != helper.start_time:
            raise RuntimeClosureError('helper identity changed after registration')
        helper.session = ops.getsid(pid)
        helper.process_group = ops.getpgid(pid)
        observed_executable = _proc_executable_identity(ops, pid)
        if observed_executable != helper.executable_identity:
            raise RuntimeClosureError('helper executable changed before fixed exec')
        if helper.session != pid or helper.process_group != pid:
            raise RuntimeClosureError('helper does not own its session')
        helper.state = _HelperState.PREEXEC_IDENTIFIED
        helper.release_attempted = True
        _outer_helper_call(preparation, '_release_runtime_helper', helper.outer_token, deadline)
        if ops.write(release_write.fd, b'G\n') != 2:
            raise RuntimeClosureError('helper release write failed')
        release_write.close(ops)
        if not ops.poll_readable(status_read.fd, deadline - ops.monotonic()):
            raise RuntimeClosureError('helper exec handshake timeout')
        if _read_stream_bounded(ops, status_read.fd, 2):
            raise RuntimeClosureError('fixed helper exec failed')
        status_read.close(ops)
        helper.executable_identity = closure.executable.identity
        if not _observe_helper(ops, helper):
            raise RuntimeClosureError('helper post-exec identity mismatch')
        helper.state = _HelperState.EXEC_IDENTIFIED
        return helper
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        helper = preparation.helpers[-1] if preparation.helpers and preparation.helpers[-1].pid == pid else None
        if helper is not None:
            try:
                _stop_helper(ops, preparation, helper)
            except BaseException as cleanup:
                failures.append(cleanup)
        else:
            for lease in reversed(created):
                if lease.state is _FdState.OWNED:
                    try:
                        lease.close(ops)
                    except BaseException as cleanup:
                        failures.append(cleanup)
        if len(failures) > 1:
            raise RuntimeClosureCleanupError(failures) from primary
        raise

def _read_exact_status(ops: _Ops, fd: int) -> bytes:
    raw = ops.read(fd, 3)
    if raw not in (b'R\n', b'E\n', b'P\n', b'W\n', b'G\n'):
        raise RuntimeClosureError('malformed helper status record')
    return raw

def _proc_executable_identity(ops: _Ops, pid: int) -> tuple[int, int]:
    lease = FdLease(ops.open(f'/proc/{pid}/exe', os.O_RDONLY | _O_CLOEXEC), 'proc-exe')
    primary: BaseException | None = None
    identity = (-1, -1)
    try:
        value = ops.fstat(lease.fd)
        identity = (value.st_dev, value.st_ino)
    except BaseException as error:
        primary = error
    _finish_fds(ops, (lease,), primary)
    return identity

def _descendant_census(ops: _Ops, root_pid: int) -> tuple[int, ...]:

    def capture() -> tuple[int, ...]:
        pending = [root_pid]
        observed: list[int] = []
        while pending:
            parent = pending.pop(0)
            children = _parse_children(_read_proc(ops, f'/proc/{parent}/task/{parent}/children', 65536))
            for child in children:
                if child == root_pid or child in observed:
                    raise RuntimeClosureError('duplicate or cyclic descendant identity')
                observed.append(child)
                pending.append(child)
                if len(observed) > _MAX_OBJECTS:
                    raise RuntimeClosureError('helper descendant bound')
        return tuple(observed)
    first = capture()
    second = capture()
    if first != second:
        raise RuntimeClosureError('helper descendant census changed')
    return first

def _observe_helper(ops: _Ops, helper: HelperLease) -> bool:
    if helper.reaped or helper.start_time is None or helper.executable_identity is None:
        return False
    try:
        start = _parse_proc_stat(_read_proc(ops, f'/proc/{helper.pid}/stat', 4096), helper.pid)
        if start != helper.start_time:
            return False
        if ops.getsid(helper.pid) != helper.session or ops.getpgid(helper.pid) != helper.process_group:
            return False
        observed_executable = _proc_executable_identity(ops, helper.pid)
        allowed_executables = {helper.executable_identity}
        if helper.release_attempted and helper.target_executable_identity is not None:
            allowed_executables.add(helper.target_executable_identity)
        if observed_executable not in allowed_executables:
            return False
        helper.descendants = _descendant_census(ops, helper.pid)
        return not helper.descendants
    except (FileNotFoundError, ProcessLookupError):
        return False

def _wait_helper(ops: _Ops, helper: HelperLease, deadline: float) -> bool:
    while True:
        try:
            if ops.wait_pidfd_nohang(helper.pidfd.fd):
                helper.state = _HelperState.REAPED
                return True
        except ChildProcessError as error:
            raise RuntimeClosureError('helper reap ownership lost') from error
        now = ops.monotonic()
        if now >= deadline:
            return False
        ops.sleep(min(0.01, deadline - now))

def _stop_helper(ops: _Ops, preparation: PreparationLease, helper: HelperLease) -> None:
    if helper.cleanup_error is not None:
        raise helper.cleanup_error
    failures: list[BaseException] = []
    identity_complete = all(value is not None for value in (
        helper.start_time,
        helper.session,
        helper.process_group,
        helper.executable_identity,
    ))
    helper.state = _HelperState.STOPPING
    for gate in (
        helper.registration_gate,
        helper.release_gate,
        helper.status_gate,
        helper.input_gate,
    ):
        if gate.state is _FdState.OWNED:
            try:
                gate.close(ops)
            except BaseException as error:
                failures.append(error)
    try:
        graceful_deadline = ops.monotonic() + _HELPER_TERM_SECONDS
        if not _wait_helper(ops, helper, graceful_deadline):
            if not identity_complete:
                raise RuntimeClosureError('unregistered helper retained behind closed gate')
            if not _observe_helper(ops, helper):
                raise RuntimeClosureError('helper identity or descendants changed before TERM')
            ops.pidfd_signal(helper.pidfd.fd, signal.SIGTERM)
            term_deadline = ops.monotonic() + _HELPER_TERM_SECONDS
            if not _wait_helper(ops, helper, term_deadline):
                if not _observe_helper(ops, helper):
                    raise RuntimeClosureError('helper identity changed before KILL')
                ops.pidfd_signal(helper.pidfd.fd, signal.SIGKILL)
                kill_deadline = ops.monotonic() + _HELPER_KILL_SECONDS
                if not _wait_helper(ops, helper, kill_deadline):
                    raise RuntimeClosureError('helper bounded reap timeout')
    except BaseException as error:
        failures.append(error)
    outer_retired = not helper.outer_registration_attempted
    if helper.reaped and helper.outer_token is not None:
        try:
            _outer_helper_call(preparation, '_retire_runtime_helper', helper.outer_token, ops.monotonic() + _HELPER_KILL_SECONDS)
            outer_retired = True
        except BaseException as error:
            failures.append(error)
    elif helper.reaped and helper.outer_registration_attempted:
        failures.append(RuntimeClosureError('outer helper registration uncertain'))
    if helper.reaped and outer_retired and helper.pidfd.state is _FdState.OWNED:
        try:
            helper.pidfd.close(ops)
        except BaseException as error:
            failures.append(error)
    if helper.reaped and outer_retired and helper in preparation.helpers:
        preparation.helpers.remove(helper)
    if failures:
        helper.state = _HelperState.UNCERTAIN
        helper.cleanup_error = RuntimeClosureCleanupError(failures)
        raise helper.cleanup_error

def _maps_snapshot(ops: _Ops, pid: int) -> tuple[bytes, tuple[_MapRow, ...]]:
    raw = _read_proc(ops, f'/proc/{pid}/maps', _MAX_MAP_BYTES)
    return (raw, _parse_maps(raw))

def _mapped_closure(ops: _Ops, helper: HelperLease, closure: ResolvedToolClosure) -> MappedToolClosure:
    expected = {value.identity: value for value in closure.objects}
    if len(expected) > _MAX_OBJECTS:
        raise RuntimeClosureError('mapped closure object bound')
    (before, rows) = _maps_snapshot(ops, helper.pid)
    seen: set[tuple[int, int]] = set()
    fingerprints: dict[tuple[str, int], tuple[int, int]] = {}
    for row in rows:
        if row.permissions[2:3] != b'x':
            continue
        if row.inode == 0:
            if row.path not in _KERNEL_EXECUTABLE_MAPPINGS:
                raise RuntimeClosureError('unknown synthetic executable mapping')
            continue
        lease = FdLease(ops.open(f'/proc/{helper.pid}/map_files/{row.start:x}-{row.end:x}', os.O_RDONLY | _O_CLOEXEC), 'map-file')
        primary: BaseException | None = None
        try:
            before_stat = ops.fstat(lease.fd)
            _require_source(before_stat)
            generation = _generation(before_stat)
            if os.major(generation.device) != row.major or os.minor(generation.device) != row.minor:
                raise RuntimeClosureError('maps device differs from map_files')
            if generation.inode != row.inode:
                raise RuntimeClosureError('maps inode differs from map_files')
            raw = _read_complete(ops, lease.fd, generation.size)
            after_stat = ops.fstat(lease.fd)
            _require_source(after_stat)
            if _generation(after_stat) != generation:
                raise RuntimeClosureError('mapped object generation changed')
            identity = (generation.device, generation.inode)
            object_ = expected.get(identity)
            digest = hashlib.sha256(raw).hexdigest()
            fingerprint = (digest, len(raw))
            other = fingerprints.get(fingerprint)
            if other is not None and other != identity:
                raise RuntimeClosureError('ambiguous mapped fingerprint')
            fingerprints[fingerprint] = identity
            if object_ is None or object_.generation != generation or object_.sha256 != digest or (parse_elf64(raw) != object_.elf):
                raise RuntimeClosureError('unknown or changed executable mapping')
            seen.add(identity)
        except BaseException as error:
            primary = error
        _finish_fds(ops, (lease,), primary)
    (after, _after_rows) = _maps_snapshot(ops, helper.pid)
    if before != after:
        raise RuntimeClosureError('helper mappings drifted')
    if seen != set(expected):
        raise RuntimeClosureError('resolved and mapped closures differ')
    sequence = tuple(((value.role, value.sha256) for value in closure.objects))
    return MappedToolClosure(closure.tool, sequence, hashlib.sha256(_canonical(sequence)).hexdigest())

def _seal_object(ops: _Ops, source: AuthenticatedObject) -> SealedObject:
    writable = FdLease(
        ops.memfd_create(
            'cogs-runtime-object',
            _MFD_CLOEXEC | _MFD_ALLOW_SEALING | _MFD_EXEC,
        ),
        'sealed-object-writable',
    )
    readable: FdLease | None = None
    try:
        if _generation(ops.fstat(source.held_fd)) != source.generation:
            raise RuntimeClosureError('source changed before sealing')
        offset = 0
        while offset < source.size:
            chunk = ops.pread(source.held_fd, min(_IO_CHUNK, source.size - offset), offset)
            if not chunk:
                raise RuntimeClosureError('short source read while sealing')
            written = 0
            while written < len(chunk):
                count = ops.pwrite(writable.fd, chunk[written:], offset + written)
                if count <= 0:
                    raise RuntimeClosureError('short sealed object write')
                written += count
            offset += len(chunk)
        if ops.pread(source.held_fd, 1, source.size):
            raise RuntimeClosureError('source grew while sealing')
        ops.fchmod(writable.fd, 365)
        ops.fsync(writable.fd)
        copied = _read_complete(ops, writable.fd, source.size)
        if hashlib.sha256(copied).hexdigest() != source.sha256:
            raise RuntimeClosureError('sealed object readback mismatch')
        if parse_elf64(copied) != source.elf:
            raise RuntimeClosureError('sealed object ELF mismatch')
        if _generation(ops.fstat(source.held_fd)) != source.generation:
            raise RuntimeClosureError('source changed during sealing')
        ops.fcntl(writable.fd, _F_ADD_SEALS, _EXEC_SEALS)
        seals = ops.fcntl(writable.fd, _F_GET_SEALS)
        writable_stat = ops.fstat(writable.fd)
        exact_mode = writable_stat.st_mode & 511 == 365
        exact_shape = stat.S_ISREG(writable_stat.st_mode) and writable_stat.st_size == source.size
        if seals != _EXEC_SEALS or not exact_mode or not exact_shape:
            raise RuntimeClosureError('sealed object metadata or seals mismatch')
        readable = FdLease(
            ops.open(
                f'/proc/self/fd/{writable.fd}',
                os.O_RDONLY | _O_CLOEXEC,
            ),
            'sealed-object-readable',
        )
        if _generation(ops.fstat(readable.fd)) != _generation(writable_stat):
            raise RuntimeClosureError('read-only sealed object identity mismatch')
        if ops.fcntl(readable.fd, _F_GET_SEALS) != _EXEC_SEALS:
            raise RuntimeClosureError('read-only sealed object seals mismatch')
        access_mode = ops.fcntl(readable.fd, _F_GETFL) & os.O_ACCMODE
        if access_mode != os.O_RDONLY:
            raise RuntimeClosureError('sealed object transfer descriptor is not read-only')
        if ops.fcntl(readable.fd, _F_GETFD) & _FD_CLOEXEC == 0:
            raise RuntimeClosureError('sealed object transfer descriptor is inheritable')
        try:
            writable.close(ops)
        except BaseException as close_error:
            _finish_fds(ops, (readable,), close_error)
        return SealedObject(
            readable.fd,
            source.generation,
            source.size,
            source.sha256,
            source.elf,
            seals,
        )
    except BaseException as primary:
        leases = tuple(value for value in (readable, writable) if value is not None)
        _finish_fds(ops, leases, primary)
        raise

def _seal_report(ops: _Ops, report: bytes) -> int:
    writable = FdLease(ops.memfd_create('cogs-runtime-report', _MFD_CLOEXEC | _MFD_ALLOW_SEALING), 'report-writable')
    readable: FdLease | None = None
    try:
        offset = 0
        while offset < len(report):
            count = ops.pwrite(writable.fd, report[offset:], offset)
            if count <= 0:
                raise RuntimeClosureError('short report write')
            offset += count
        ops.fchmod(writable.fd, 292)
        ops.fsync(writable.fd)
        if _read_complete(ops, writable.fd, len(report)) != report:
            raise RuntimeClosureError('report readback mismatch')
        ops.fcntl(writable.fd, _F_ADD_SEALS, _DATA_SEALS)
        if ops.fcntl(writable.fd, _F_GET_SEALS) != _DATA_SEALS:
            raise RuntimeClosureError('exact report seal profile unavailable')
        readable = FdLease(ops.open(f'/proc/self/fd/{writable.fd}', os.O_RDONLY | _O_CLOEXEC), 'report-readable')
        writable_generation = _generation(ops.fstat(writable.fd))
        if _generation(ops.fstat(readable.fd)) != writable_generation:
            raise RuntimeClosureError('read-only report descriptor identity mismatch')
        if ops.fcntl(readable.fd, _F_GET_SEALS) != _DATA_SEALS:
            raise RuntimeClosureError('read-only report seals mismatch')
        if ops.fcntl(readable.fd, _F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise RuntimeClosureError('report descriptor is not read-only')
        if ops.fcntl(readable.fd, _F_GETFD) & _FD_CLOEXEC == 0:
            raise RuntimeClosureError('report descriptor is not close-on-exec')
        try:
            writable.close(ops)
        except BaseException as close_error:
            _finish_fds(ops, (readable,), close_error)
        return readable.fd
    except BaseException as primary:
        leases = tuple((value for value in (readable, writable) if value is not None))
        _finish_fds(ops, leases, primary)
        raise

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def _object_report(value: AuthenticatedObject) -> dict[str, Any]:
    (_interpreter, soname, needed) = _metadata(value)
    return {'needed': list(needed), 'role': value.role, 'sha256': value.sha256, 'size': value.size, 'soname': soname}

def _encode_report(closures: Sequence[ResolvedToolClosure], mappings: Sequence[MappedToolClosure]) -> bytes:
    mapping_by_tool = {value.tool: value for value in mappings}
    tools: list[dict[str, Any]] = []
    for closure in closures:
        objects = [_object_report(value) for value in closure.objects]
        tools.append({
            'closure_sha256': hashlib.sha256(_canonical(objects)).hexdigest(),
            'mapping_sha256': mapping_by_tool[closure.tool].mapping_sha256,
            'objects': objects,
            'seal_profile': None if closure.tool == 'python3-parser' else _SEAL_PROFILE,
            'sealed_executable': closure.tool != 'python3-parser',
            'tool': closure.tool,
        })
    digest_view = [{key: value for (key, value) in tool.items() if key != 'mapping_sha256'} for tool in tools]
    return _canonical({'closure_sha256': hashlib.sha256(_canonical(digest_view)).hexdigest(), 'tools': tools, 'version': _VERSION}) + b'\n'

def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for (key, value) in pairs:
        if key in result:
            raise RuntimeClosureError('duplicate report key')
        result[key] = value
    return result

def _hex(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all((character in '0123456789abcdef' for character in value))

def _validate_report_value(value: Any) -> None:
    if type(value) is not dict or set(value) != {'closure_sha256', 'tools', 'version'}:
        raise RuntimeClosureError('invalid closure report object')
    if value['version'] != _VERSION or not _hex(value['closure_sha256']):
        raise RuntimeClosureError('invalid closure report identity')
    tools = value['tools']
    expected_tools = ['python3-parser', 'zstd', 'gzip']
    if type(tools) is not list or [item.get('tool') for item in tools if type(item) is dict] != expected_tools:
        raise RuntimeClosureError('invalid closure report tool order')
    tool_keys = {'closure_sha256', 'mapping_sha256', 'objects', 'seal_profile', 'sealed_executable', 'tool'}
    global_roles: dict[str, str] = {}
    for (tool_index, tool) in enumerate(tools):
        if type(tool) is not dict or set(tool) != tool_keys:
            raise RuntimeClosureError('invalid tool report')
        if not _hex(tool['closure_sha256']) or not _hex(tool['mapping_sha256']):
            raise RuntimeClosureError('invalid tool digest')
        sealed = tool_index != 0
        if type(tool['sealed_executable']) is not bool or tool['sealed_executable'] != sealed:
            raise RuntimeClosureError('invalid sealed executable declaration')
        if tool['seal_profile'] != (_SEAL_PROFILE if sealed else None):
            raise RuntimeClosureError('invalid seal profile')
        objects = tool['objects']
        if type(objects) is not list or not 2 <= len(objects) <= _MAX_OBJECTS:
            raise RuntimeClosureError('invalid report object count')
        if [item.get('role') for item in objects[:2] if type(item) is dict] != ['executable', 'loader']:
            raise RuntimeClosureError('invalid object role order')
        providers: set[str] = set()
        identities: set[tuple[str, int]] = set()
        previous_library: tuple[bytes, str] | None = None
        for (index, object_) in enumerate(objects):
            if type(object_) is not dict or set(object_) != {'needed', 'role', 'sha256', 'size', 'soname'}:
                raise RuntimeClosureError('invalid reported runtime object')
            role = object_['role']
            if role not in ('executable', 'loader', 'library') or (index >= 2) != (role == 'library'):
                raise RuntimeClosureError('invalid reported role')
            if type(object_['size']) is not int or not 1 <= object_['size'] <= _MAX_OBJECT_SIZE:
                raise RuntimeClosureError('invalid reported size')
            if not _hex(object_['sha256']):
                raise RuntimeClosureError('invalid object digest')
            soname = object_['soname']
            if soname is not None:
                _require_soname(soname)
            if role == 'library' and soname is None:
                raise RuntimeClosureError('reported library lacks SONAME')
            prior_role = global_roles.setdefault(object_['sha256'], role)
            if prior_role != role:
                raise RuntimeClosureError('cross-tool reported role alias')
            needed = object_['needed']
            if type(needed) is not list or len(needed) > _MAX_OBJECTS:
                raise RuntimeClosureError('invalid reported dependencies')
            for name in needed:
                _require_soname(name)
            if len(needed) != len(set(needed)):
                raise RuntimeClosureError('duplicate reported dependency')
            identity = (object_['sha256'], object_['size'])
            if identity in identities:
                raise RuntimeClosureError('duplicate reported object')
            identities.add(identity)
            if soname is not None:
                if soname in providers:
                    raise RuntimeClosureError('duplicate reported provider')
                providers.add(soname)
            if role == 'library':
                order = ((soname or '').encode(), object_['sha256'])
                if previous_library is not None and order <= previous_library:
                    raise RuntimeClosureError('invalid library order')
                previous_library = order
        if any((name not in providers for object_ in objects for name in object_['needed'])):
            raise RuntimeClosureError('unresolved reported dependency')
        if hashlib.sha256(_canonical(objects)).hexdigest() != tool['closure_sha256']:
            raise RuntimeClosureError('tool closure digest mismatch')
        mapped = [[item['role'], item['sha256']] for item in objects]
        if hashlib.sha256(_canonical(mapped)).hexdigest() != tool['mapping_sha256']:
            raise RuntimeClosureError('tool mapping digest mismatch')
    digest_view = [{key: item for (key, item) in tool.items() if key != 'mapping_sha256'} for tool in tools]
    if hashlib.sha256(_canonical(digest_view)).hexdigest() != value['closure_sha256']:
        raise RuntimeClosureError('aggregate closure digest mismatch')

def _producer_decode_report(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes or not data.endswith(b'\n') or data.endswith(b'\n\n') or (len(data) > _MAX_REPORT):
        raise RuntimeClosureError('invalid canonical report framing')
    try:
        value = json.loads(
            data[:-1].decode('utf-8', 'strict'),
            object_pairs_hook=_strict_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                RuntimeClosureError('float in report')
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                RuntimeClosureError('constant in report')
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeClosureError('invalid report JSON') from error
    _validate_report_value(value)
    if _canonical(value) + b'\n' != data:
        raise RuntimeClosureError('noncanonical closure report')
    return value

def _producer_reencode_report(value: dict[str, Any]) -> bytes:
    return _canonical(value) + b'\n'

def _apply_schema_validator(admission: object, candidate: bytes) -> None:
    validator = getattr(admission, '_validate_tracked_schema', None)
    if not callable(validator):
        raise RuntimeClosureError('admission lacks independent schema validator')
    if validator(candidate) is not None:
        raise RuntimeClosureError('independent schema validator returned data')

def _construct_report(
    ops: _Ops,
    admission: object,
    closures: Sequence[ResolvedToolClosure],
    mappings: Sequence[MappedToolClosure],
) -> tuple[bytes, dict[str, Any]]:
    candidate = ops.report_candidate(_encode_report(closures, mappings))
    value = _producer_decode_report(candidate)
    if _producer_reencode_report(value) != candidate:
        raise RuntimeClosureError('producer report codec disagreement')
    _apply_schema_validator(admission, candidate)
    return candidate, value

def _binding_digest(rows: Sequence[_PrivateGenerationRow]) -> str:
    value = [{
        'descriptor_index': row.descriptor_index,
        'needed': list(row.needed),
        'object_index': row.object_index,
        'role': row.role,
        'seal_profile': row.seal_profile,
        'sha256': row.sha256,
        'size': row.size,
        'soname': row.soname,
        'tool_index': row.tool_index,
    } for row in rows]
    return hashlib.sha256(_canonical(value)).hexdigest()

def _generation_digest(rows: Sequence[_PrivateGenerationRow]) -> str:
    framed = []
    for row in rows:
        value = row.source_generation
        framed.append([
            row.tool_index,
            row.object_index,
            row.descriptor_index,
            value.device,
            value.inode,
            value.size,
            value.mtime_ns,
            value.ctime_ns,
            value.mode,
            value.uid,
            value.gid,
        ])
    return hashlib.sha256(_canonical(framed)).hexdigest()

def _validate_generation_rows(
    report: dict[str, Any],
    rows: Sequence[_PrivateGenerationRow],
    object_descriptor_count: int,
) -> None:
    expected_positions = tuple(
        (tool_index, object_index)
        for tool_index in (1, 2)
        for object_index in range(len(report['tools'][tool_index]['objects']))
    )
    positions = tuple((row.tool_index, row.object_index) for row in rows)
    if positions != expected_positions or len(set(positions)) != len(positions):
        raise RuntimeClosureError('generation rows do not exactly cover sealed objects')
    aliases: dict[int, tuple[Any, ...]] = {}
    referenced: set[int] = set()
    for row in rows:
        if not 1 <= row.descriptor_index <= object_descriptor_count:
            raise RuntimeClosureError('generation descriptor index out of range')
        item = report['tools'][row.tool_index]['objects'][row.object_index]
        report_binding = (
            item['role'],
            item['size'],
            item['sha256'],
            item['soname'],
            tuple(item['needed']),
        )
        row_binding = (
            row.role,
            row.size,
            row.sha256,
            row.soname,
            row.needed,
        )
        if row_binding != report_binding:
            raise RuntimeClosureError('generation row report binding mismatch')
        alias_binding = (
            row.source_generation,
            row.size,
            row.sha256,
            row.soname,
            row.needed,
        )
        prior = aliases.setdefault(row.descriptor_index, alias_binding)
        if prior != alias_binding:
            raise RuntimeClosureError('conflicting generation descriptor alias')
        referenced.add(row.descriptor_index)
    expected_descriptors = set(range(1, object_descriptor_count + 1))
    if referenced != expected_descriptors:
        raise RuntimeClosureError('generation rows leave an unbound descriptor')

def _validate_issuance_receipt(
    receipt: object,
    report: bytes,
    rows: Sequence[_PrivateGenerationRow],
    descriptor_count: int,
) -> None:
    report_value = _producer_decode_report(report)
    _validate_generation_rows(report_value, rows, descriptor_count - 1)
    checks = (
        getattr(receipt, 'version', None) == _HANDOFF_VERSION,
        getattr(receipt, 'report_sha256', None) == hashlib.sha256(report).hexdigest(),
        getattr(receipt, 'closure_sha256', None) == report_value['closure_sha256'],
        getattr(receipt, 'binding_sha256', None) == _binding_digest(rows),
        getattr(receipt, 'generation_sha256', None) == _generation_digest(rows),
        getattr(receipt, 'descriptor_count', None) == descriptor_count,
        type(getattr(receipt, 'issuer_pid', None)) is int,
        getattr(receipt, 'issuer_pid', 0) > 0,
        type(getattr(receipt, 'consumer_pid', None)) is int,
        getattr(receipt, 'consumer_pid', 0) > 0,
    )
    if not all(checks):
        raise RuntimeClosureError('private issuer receipt mismatch')

class PreparedRuntimeClosure:
    """The sole admitted owner of full and mapping-only closure transactions."""

    def __init__(
        self,
        capability: object,
        admission: object,
        ops: _Ops,
        preparation: PreparationLease,
    ):
        if type(capability) is not _LiveIssuerCapability:
            raise RuntimeClosureError('runtime closure owner requires live issuer capability')
        capability.consume(admission)
        self._ops = ops
        self._preparation = preparation
        self._state = _OwnerState.PREPARING
        self._report: bytes | None = None
        self._bundle: list[FdLease] = []
        self._rows: tuple[_PrivateGenerationRow, ...] = ()
        self._poison: BaseException | None = None
        self._operation_helpers: dict[object, HelperLease] = {}

    @classmethod
    def _for_fixed_operation(
        cls,
        admission: object,
        operation: str,
        ops: _Ops,
        preparation: PreparationLease,
    ) -> 'PreparedRuntimeClosure':
        _fixed_operation_admitted(admission, operation)
        owner = object.__new__(cls)
        owner._ops = ops
        owner._preparation = preparation
        owner._state = _OwnerState.PREPARING
        owner._report = None
        owner._bundle = []
        owner._rows = ()
        owner._poison = None
        owner._operation_helpers = {}
        owner._fixed_operation = operation
        preparation.outer = owner
        return owner

    @classmethod
    def _for_fixed_mapping(
        cls,
        admission: object,
        ops: _Ops,
        preparation: PreparationLease,
    ) -> 'PreparedRuntimeClosure':
        return cls._for_fixed_operation(admission, 'mapping', ops, preparation)

    def _complete_fixed_operation(self) -> None:
        if self._state is not _OwnerState.PREPARING:
            raise RuntimeClosureError('fixed operation owner state changed')
        if self._operation_helpers or self._preparation.helpers:
            raise RuntimeClosureError('fixed operation helper remains registered')
        self._state = _OwnerState.CLOSED

    def _register_runtime_helper(self, helper: object, deadline: float) -> object:
        if type(helper) is not HelperLease or deadline <= self._ops.monotonic():
            raise RuntimeClosureError('mapping helper registration rejected')
        token = object()
        self._operation_helpers[token] = helper
        return token

    def _release_runtime_helper(self, token: object, deadline: float) -> None:
        helper = self._operation_helpers.get(token)
        if helper is None or helper.state is not _HelperState.PREEXEC_IDENTIFIED:
            raise RuntimeClosureError('mapping helper release rejected')
        if deadline <= self._ops.monotonic():
            raise RuntimeClosureError('mapping helper release deadline')

    def _retire_runtime_helper(self, token: object, deadline: float) -> None:
        helper = self._operation_helpers.get(token)
        if helper is None or not helper.reaped or deadline <= self._ops.monotonic():
            raise RuntimeClosureError('mapping helper retirement rejected')
        del self._operation_helpers[token]

    def _prove_ready_baseline(self) -> None:
        expected = self._preparation.fd_baseline | frozenset((lease.fd for lease in self._bundle if lease.state is _FdState.OWNED))
        other_owned = set(self._preparation.owned_fds()) - set(expected)
        if other_owned or self._preparation.helpers:
            raise RuntimeClosureError('preparation authority remains at readiness')
        if _snapshot_fds(self._ops) != expected:
            raise RuntimeClosureError('unexpected descriptor at readiness')
        if _child_baseline(self._ops) != self._preparation.child_baseline:
            raise RuntimeClosureError('helper baseline not restored')

    def _issue_once(self, issuer: object) -> _IssuanceReceipt:
        if self._state is not _OwnerState.READY:
            raise RuntimeClosureError('runtime closure is not ready for issuance')
        accept = getattr(issuer, '_accept_runtime_closure', None)
        if not callable(accept):
            raise RuntimeClosureError('private issuer endpoint is unavailable')
        self._state = _OwnerState.ISSUING
        try:
            self._ops.checkpoint('issue.before-revalidate')
            for lease in self._bundle:
                expected_seals = _DATA_SEALS if lease.purpose == 'sealed-report' else _EXEC_SEALS
                if self._ops.fcntl(lease.fd, _F_GET_SEALS) != expected_seals:
                    raise RuntimeClosureError('issued descriptor seals changed')
                access_mode = self._ops.fcntl(lease.fd, _F_GETFL) & os.O_ACCMODE
                if access_mode != os.O_RDONLY:
                    raise RuntimeClosureError('issued descriptor is not read-only')
                descriptor_flags = self._ops.fcntl(lease.fd, _F_GETFD)
                if descriptor_flags & _FD_CLOEXEC == 0:
                    raise RuntimeClosureError('issued descriptor is not close-on-exec')
            report_lease = self._bundle[0]
            report = self._report
            if report is None or _read_complete(self._ops, report_lease.fd, len(report)) != report:
                raise RuntimeClosureError('issued report bytes changed')
            self._prove_ready_baseline_for_issue()
            self._ops.checkpoint('issue.before-transfer')
            descriptors = tuple((lease.fd for lease in self._bundle))
            receipt = accept(report, descriptors, self._rows)
            _validate_issuance_receipt(receipt, report, self._rows, len(descriptors))
            for lease in self._bundle:
                lease.transfer()
            self._state = _OwnerState.CONSUMED
            return receipt
        except BaseException as error:
            self._poison_owner(error)
            raise self._poison if self._poison is not None else error

    def _prove_ready_baseline_for_issue(self) -> None:
        expected = self._preparation.fd_baseline | frozenset((lease.fd for lease in self._bundle if lease.state is _FdState.OWNED))
        if _snapshot_fds(self._ops) != expected:
            raise RuntimeClosureError('issuer descriptor baseline changed')
        if _child_baseline(self._ops) != self._preparation.child_baseline:
            raise RuntimeClosureError('issuer child baseline changed')

    def _poison_owner(self, primary: BaseException) -> None:
        failures: list[BaseException] = [primary]
        for lease in reversed(self._bundle):
            if lease.state is _FdState.OWNED:
                try:
                    lease.close(self._ops)
                except BaseException as error:
                    failures.append(error)
        self._poison = RuntimeClosureCleanupError(failures)
        self._state = _OwnerState.POISONED

    def close(self) -> None:
        if self._state is _OwnerState.CLOSED:
            return
        if self._state is _OwnerState.POISONED:
            if self._poison is None:
                raise RuntimeClosureError('poisoned owner lost its failure')
            raise self._poison
        self._ops.checkpoint('cleanup.before')
        failures: list[BaseException] = []
        for lease in reversed(self._bundle):
            if lease.state is _FdState.OWNED:
                try:
                    lease.close(self._ops)
                except BaseException as error:
                    failures.append(error)
        if self._preparation.helpers:
            failures.append(RuntimeClosureError('registered helper remains during close'))
        if self._state is not _OwnerState.CONSUMED:
            try:
                if _snapshot_fds(self._ops) != self._preparation.fd_baseline:
                    failures.append(RuntimeClosureError('descriptor baseline not restored'))
                if _child_baseline(self._ops) != self._preparation.child_baseline:
                    failures.append(RuntimeClosureError('child baseline not restored'))
            except BaseException as error:
                failures.append(error)
        try:
            self._ops.checkpoint('cleanup.after')
        except BaseException as error:
            failures.append(error)
        if failures:
            self._poison = RuntimeClosureCleanupError(failures)
            self._state = _OwnerState.POISONED
            raise self._poison
        self._state = _OwnerState.CLOSED

    def __enter__(self) -> 'PreparedRuntimeClosure':
        if self._state is not _OwnerState.READY:
            raise RuntimeClosureError('runtime closure context is not ready')
        return self

    def __exit__(self, exc_type: Any, exc: BaseException | None, traceback: Any) -> None:
        del exc_type, traceback
        try:
            self.close()
        except BaseException as cleanup:
            if exc is not None:
                raise RuntimeClosureCleanupError((exc, cleanup)) from exc
            raise

def _child_baseline(ops: _Ops) -> tuple[int, ...]:
    return _parse_children(_read_proc(ops, '/proc/self/task/self/children', 65536))

def _descriptor_child_matches(ops: _Ops, child: _DescriptorChildLease) -> bool:
    registered = (
        child.start_time is not None
        and child.session is not None
        and child.process_group is not None
        and child.executable_identity is not None
    )
    if not registered:
        return False
    try:
        start = _parse_proc_stat(_read_proc(ops, f'/proc/{child.pid}/stat', 4096), child.pid)
        executable = _proc_executable_identity(ops, child.pid)
        session = ops.getsid(child.pid)
        process_group = ops.getpgid(child.pid)
    except (FileNotFoundError, ProcessLookupError):
        return False
    allowed = {child.executable_identity}
    if child.released:
        allowed.add(child.target_identity)
    return (
        start == child.start_time
        and executable in allowed
        and session == child.session
        and process_group == child.process_group
    )

def _wait_descriptor_child(
    ops: _Ops,
    child: _DescriptorChildLease,
    deadline: float,
    expected: tuple[int, int] | None,
) -> tuple[int, int]:
    observation = None
    while observation is None:
        observation = ops.waitid_pidfd_nohang(child.pidfd.fd)
        if observation is not None:
            break
        now = ops.monotonic()
        if now >= deadline:
            raise RuntimeClosureError('descriptor child waitid deadline')
        ops.sleep(min(0.001, deadline - now))
    if observation.si_pid != child.pid or observation.si_uid != ops.getuid():
        raise RuntimeClosureError('descriptor child siginfo identity mismatch')
    pair = (observation.si_code, observation.si_status)
    if expected is not None and pair != expected:
        raise RuntimeClosureError('descriptor child siginfo outcome mismatch')
    ops.checkpoint('descriptor.waitid.after-observe')
    reaped_pid, wait_status = ops.reap_pid_nohang(child.pid)
    if reaped_pid != child.pid:
        raise RuntimeClosureError('descriptor child was not exactly reaped')
    child.reaped = True
    ops.checkpoint('descriptor.reap.after')
    if pair[0] == os.CLD_EXITED:
        matches = os.WIFEXITED(wait_status) and os.WEXITSTATUS(wait_status) == pair[1]
    else:
        matches = os.WIFSIGNALED(wait_status) and os.WTERMSIG(wait_status) == pair[1]
    if not matches:
        raise RuntimeClosureError('waitid and reap status disagree')
    return pair

def _claim_admission(admission: object, issuer: object) -> _LiveIssuerCapability:
    package_name = __package__
    worker_pid = os.getpid()
    exact_topology = (
        type(admission) is globals().get('_ADMISSION_TYPE')
        and type(package_name) is str
        and _PACKAGE.fullmatch(package_name) is not None
        and getattr(admission, '_package', None) == package_name
        and getattr(admission, '_worker_pid', None) == worker_pid
        and getattr(admission, '_issuer', None) is issuer
    )
    if not exact_topology:
        raise RuntimeClosureError('runtime source admission topology mismatch')
    for name in ('revision', 'source_set_sha256', 'bootstrap_sha256'):
        value = getattr(admission, name, None)
        length = 40 if name == 'revision' else 64
        if type(value) is not str or len(value) != length:
            raise RuntimeClosureError('invalid runtime source admission identity')
        if any(character not in '0123456789abcdef' for character in value):
            raise RuntimeClosureError('invalid runtime source admission encoding')
    consume = getattr(issuer, '_consume_runtime_closure_capability', None)
    if not callable(consume):
        raise RuntimeClosureError('live runtime issuer capability is unavailable')
    result = consume(admission, package_name, worker_pid)
    if type(result) is not tuple or len(result) != 2:
        raise RuntimeClosureError('invalid runtime issuer capability result')
    endpoint, expected_peer = result
    if type(endpoint) is not socket.socket:
        raise RuntimeClosureError('runtime issuer capability is not a kernel socket')
    if type(expected_peer) is not tuple or len(expected_peer) != 3:
        raise RuntimeClosureError('runtime issuer peer credential shape')
    if endpoint.fileno() < 0:
        raise RuntimeClosureError('runtime issuer capability endpoint is closed')
    if endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
        raise RuntimeClosureError('runtime issuer endpoint type mismatch')
    if endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
        raise RuntimeClosureError('runtime issuer endpoint is not live')
    if fcntl.fcntl(endpoint.fileno(), _F_GETFD) & _FD_CLOEXEC == 0:
        raise RuntimeClosureError('runtime issuer endpoint is inheritable')
    raw_peer = endpoint.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize('3i'),
    )
    peer = struct.unpack('3i', raw_peer)
    if peer != expected_peer:
        raise RuntimeClosureError('runtime issuer endpoint peer mismatch')
    peer_pid, peer_uid, peer_gid = peer
    if peer_pid <= 0 or peer_pid == worker_pid:
        raise RuntimeClosureError('runtime issuer endpoint process topology mismatch')
    if peer_uid != os.getuid() or peer_gid != os.getgid():
        raise RuntimeClosureError('runtime issuer endpoint credential mismatch')
    return _LiveIssuerCapability(
        admission,
        endpoint,
        package_name,
        worker_pid,
        peer,
    )

def _validate_closure_bounds(tool_objects: Sequence[Sequence[tuple[tuple[int, int], int]]]) -> None:
    """Pure object-count/per-tool/deduplicated aggregate bound gate."""
    global_sizes: dict[tuple[int, int], int] = {}
    for objects in tool_objects:
        if len(objects) > _MAX_OBJECTS:
            raise RuntimeClosureError('tool closure object bound')
        identities: set[tuple[int, int]] = set()
        total = 0
        for (identity, size) in objects:
            if type(identity) is not tuple or len(identity) != 2 or type(size) is not int:
                raise RuntimeClosureError('invalid closure bound record')
            if identity in identities or not 1 <= size <= _MAX_OBJECT_SIZE:
                raise RuntimeClosureError('duplicate identity or object size bound')
            identities.add(identity)
            total += size
            previous = global_sizes.setdefault(identity, size)
            if previous != size:
                raise RuntimeClosureError('same identity has conflicting sizes')
        if total > _MAX_TOOL_BYTES:
            raise RuntimeClosureError('tool closure byte bound')
    if sum(global_sizes.values()) > _MAX_TOTAL_BYTES:
        raise RuntimeClosureError('deduplicated fixed closure byte bound')

def _enforce_global_alias_policy(closures: Sequence[ResolvedToolClosure]) -> None:
    roles: dict[tuple[int, int], str] = {}
    generations: dict[tuple[int, int], tuple[SourceGeneration, str, ElfMetadata]] = {}
    executable_identities: set[tuple[int, int]] = set()
    for closure in closures:
        for value in closure.objects:
            prior_role = roles.get(value.identity)
            if prior_role is not None and prior_role != value.role:
                raise RuntimeClosureError('global cross-role identity alias')
            prior = generations.get(value.identity)
            current = (value.generation, value.sha256, value.elf)
            if prior is not None and prior != current:
                raise RuntimeClosureError('global same-identity generation drift')
            roles[value.identity] = value.role
            generations[value.identity] = current
        if closure.executable.identity in executable_identities:
            raise RuntimeClosureError('fixed executable identities must be distinct')
        executable_identities.add(closure.executable.identity)

def _build_bundle(
    ops: _Ops,
    preparation: PreparationLease,
    closures: Sequence[ResolvedToolClosure],
) -> tuple[list[FdLease], tuple[_PrivateGenerationRow, ...]]:
    bundle: list[FdLease] = []
    rows: list[_PrivateGenerationRow] = []
    sealed_by_identity: dict[tuple[int, int], tuple[int, SealedObject]] = {}
    for (tool_index, closure) in enumerate(closures):
        if closure.tool == 'python3-parser':
            continue
        for (object_index, source) in enumerate(closure.objects):
            existing = sealed_by_identity.get(source.identity)
            if existing is None:
                sealed = _seal_object(ops, source)
                try:
                    lease = preparation.register_fd(sealed.fd, 'sealed-object')
                except BaseException as primary:
                    orphan = FdLease(sealed.fd, 'unregistered-sealed-object')
                    _finish_fds(ops, (orphan,), primary)
                    raise RuntimeClosureError('unreachable')
                bundle.append(lease)
                descriptor_index = len(bundle)
                sealed_by_identity[source.identity] = (descriptor_index, sealed)
            else:
                (descriptor_index, sealed) = existing
                if sealed.source_generation != source.generation or sealed.sha256 != source.sha256:
                    raise RuntimeClosureError('shared sealed generation mismatch')
            (_interpreter, soname, needed) = _metadata(source)
            rows.append(_PrivateGenerationRow(
                tool_index,
                object_index,
                source.role,
                descriptor_index,
                source.generation,
                source.size,
                source.sha256,
                soname,
                needed,
            ))
    return (bundle, tuple(rows))

def _fixed_operation_admitted(admission: object, operation: str) -> None:
    module = __import__(__name__, fromlist=('__name__',))
    consume = getattr(admission, '_consume_fixed_operation', None)
    if not callable(consume) or consume(operation, module) is not True:
        raise RuntimeClosureError('fixed closure operation admission rejected')

def _mapping_observations(closure: ResolvedToolClosure) -> tuple[RuntimeObjectObservation, ...]:
    return tuple(RuntimeObjectObservation(
        value.role,
        value.size,
        value.sha256,
        _metadata(value)[1],
        _metadata(value)[2],
    ) for value in closure.objects)

def _qualify_fixed_python_mapping_with_ops(admission: object, ops: _Ops) -> RuntimeMappingQualificationResult:
    preparation = PreparationLease(ops, frozenset(), ())
    owner = PreparedRuntimeClosure._for_fixed_mapping(
        admission,
        ops,
        preparation,
    )
    ops.architecture_gate()
    _reserve_stdio(ops)
    baseline = _snapshot_fds(ops)
    children = _child_baseline(ops)
    preparation.fd_baseline = baseline
    preparation.child_baseline = children
    resolved: ResolvedToolClosure | None = None
    helper: HelperLease | None = None
    primary: BaseException | None = None
    mapped: MappedToolClosure | None = None
    try:
        resolved = _resolve_tool(ops, 'python3-parser', '/usr/bin/python3')
        sources = [preparation.register_fd(item.held_fd, f'mapping-source:{item.role}') for item in resolved.objects]
        helper = _spawn_helper(ops, preparation, resolved)
        mapped = _mapped_closure(ops, helper, resolved)
        _stop_helper(ops, preparation, helper)
        preparation.close_many(sources)
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    if helper is not None and helper in preparation.helpers:
        try:
            _stop_helper(ops, preparation, helper)
        except BaseException as error:
            failures.append(error)
    for lease in reversed(preparation.fds):
        if lease.state is _FdState.OWNED:
            try:
                lease.close(ops)
            except BaseException as error:
                failures.append(error)
    try:
        descriptors_restored = _snapshot_fds(ops) == baseline
        children_reaped = _child_baseline(ops) == children and not owner._operation_helpers
    except BaseException as error:
        failures.append(error)
        descriptors_restored = children_reaped = False
    if failures:
        raise RuntimeClosureCleanupError(([primary] if primary else []) + failures) from (primary or failures[0])
    if primary is not None:
        raise primary
    if resolved is None or mapped is None:
        raise RuntimeClosureError('mapping qualification result missing')
    objects = _mapping_observations(resolved)
    mapped_rows = tuple(MappedObjectObservation(*row) for row in mapped.mapped)
    canonical_objects = [_object_report(value) for value in resolved.objects]
    expected_mapped = tuple((item.role, item.sha256) for item in resolved.objects)
    result = RuntimeMappingQualificationResult(
        'cogs.runtime-mapping-qualification/v1',
        admission.revision,
        admission.source_set_sha256,
        hashlib.sha256(_canonical(canonical_objects)).hexdigest(),
        mapped.mapping_sha256,
        objects,
        mapped_rows,
        mapped.mapped == expected_mapped,
        True,
        helper.reaped,
        descriptors_restored,
        children_reaped,
    )
    owner._complete_fixed_operation()
    return result

def _qualify_fixed_descriptor_primitives_with_ops(
    admission: object,
    ops: _Ops,
) -> DescriptorQualificationResult:
    preparation = PreparationLease(ops, frozenset(), ())
    owner = PreparedRuntimeClosure._for_fixed_operation(
        admission,
        'descriptor',
        ops,
        preparation,
    )
    ops.architecture_gate()
    _reserve_stdio(ops)
    baseline = _snapshot_fds(ops)
    children = _child_baseline(ops)
    preparation.fd_baseline = baseline
    preparation.child_baseline = children
    original = ops.getrlimit()
    limit = _LimitLease(original)
    leases: list[FdLease] = []
    child: _DescriptorChildLease | None = None
    resolved: ResolvedToolClosure | None = None
    measured = original[1] == resource.RLIM_INFINITY or original[1] >= 8193
    normalized = False
    low_exact = False
    high_exact = False
    close_exact = False
    flags_exact = False
    inheritance_exact = False
    primary: BaseException | None = None
    try:
        if not measured:
            raise RuntimeClosureUnavailable('fixed descriptor capacity unavailable')
        ops.checkpoint('descriptor.limit.before-normalize')
        ops.setrlimit((8193, original[1]))
        ops.checkpoint('descriptor.limit.after-normalize')
        normalized = ops.getrlimit() == (8193, original[1])
        if not normalized:
            raise RuntimeClosureError('descriptor limit normalization mismatch')
        ops.checkpoint('descriptor.python.before-resolve')
        resolved = _resolve_tool(ops, 'python3-parser', '/usr/bin/python3')
        for value in resolved.objects:
            lease = FdLease(value.held_fd, f'descriptor-python:{value.role}')
            leases.append(lease)
        ops.checkpoint('descriptor.python.after-register')
        ops.checkpoint('descriptor.source-pipe.before')
        source_fd, spare_fd = ops.pipe()
        source = FdLease(source_fd, 'descriptor-source')
        spare = FdLease(spare_fd, 'descriptor-spare')
        leases.extend((source, spare))
        ops.checkpoint('descriptor.source-pipe.after-register')
        ops.checkpoint('descriptor.dup-198.before')
        low_fd = ops.fcntl(source.fd, fcntl.F_DUPFD_CLOEXEC, 198)
        low = FdLease(low_fd, 'descriptor-198')
        leases.append(low)
        ops.checkpoint('descriptor.dup-198.after-register')
        low_exact = low.fd == 198
        if not low_exact:
            raise RuntimeClosureError('fixed descriptor 198 allocation mismatch')
        ops.checkpoint('descriptor.dup-4096.before')
        high_fd = ops.fcntl(source.fd, fcntl.F_DUPFD, 4096)
        high = FdLease(high_fd, 'descriptor-4096')
        leases.append(high)
        ops.checkpoint('descriptor.dup-4096.after-register')
        high_exact = high.fd == 4096
        if not high_exact:
            raise RuntimeClosureError('fixed descriptor 4096 allocation mismatch')
        low_flags = ops.fcntl(low.fd, _F_GETFD)
        high_flags = ops.fcntl(high.fd, _F_GETFD)
        flags_exact = bool(low_flags & _FD_CLOEXEC)
        flags_exact = flags_exact and not bool(high_flags & _FD_CLOEXEC)
        if not flags_exact:
            raise RuntimeClosureError('fixed descriptor inheritance flags mismatch')
        ops.checkpoint('descriptor.status-pipe.before')
        status_read_fd, status_write_fd = ops.pipe()
        status_read = FdLease(status_read_fd, 'descriptor-status-read')
        status_write = FdLease(status_write_fd, 'descriptor-status-write')
        leases.extend((status_read, status_write))
        ops.checkpoint('descriptor.status-pipe.after-register')
        ops.checkpoint('descriptor.release-pipe.before')
        release_read_fd, release_write_fd = ops.pipe()
        release_read = FdLease(release_read_fd, 'descriptor-release-read')
        release_write = FdLease(release_write_fd, 'descriptor-release-write')
        leases.extend((release_read, release_write))
        ops.checkpoint('descriptor.release-pipe.after-register')
        ops.checkpoint('descriptor.clone.before')
        child_pid, pidfd_number = ops.clone3_pidfd()
        if child_pid == 0:
            try:
                status_read.close(ops)
                release_write.close(ops)
                spare.close(ops)
                if ops.read(release_read.fd, 1) != b'G':
                    ops.exit_child(125)
                release_read.close(ops)
                ops.dup2(source.fd, 0, inheritable=True)
                ops.dup2(status_write.fd, 197, inheritable=True)
                allowed = (0, 1, 2, 197, 198, 4096, resolved.executable.held_fd)
                _close_complement(ops, allowed)
                argv = _descriptor_child_argv()
                ops.execve(resolved.executable.held_fd, argv, {})
            except BaseException:
                ops.exit_child(126)
        if pidfd_number < 0:
            raise RuntimeClosureError('descriptor child pidfd registration')
        child_pidfd = FdLease(pidfd_number, 'descriptor-child-pidfd')
        leases.append(child_pidfd)
        if child_pid <= 0:
            raise RuntimeClosureError('descriptor child atomic registration')
        child = _DescriptorChildLease(
            child_pid,
            child_pidfd,
            resolved.executable.identity,
        )
        stat_record = _read_proc(ops, f'/proc/{child_pid}/stat', 4096)
        child.start_time = _parse_proc_stat(stat_record, child_pid)
        child.session = ops.getsid(child_pid)
        child.process_group = ops.getpgid(child_pid)
        child.executable_identity = _proc_executable_identity(ops, child_pid)
        ops.checkpoint('descriptor.clone.after-register')
        if not _descriptor_child_matches(ops, child):
            raise RuntimeClosureError('descriptor child registration identity mismatch')
        status_write.close(ops)
        release_read.close(ops)
        ops.checkpoint('descriptor.release.before')
        child.released = True
        if ops.write(release_write.fd, b'G') != 1:
            raise RuntimeClosureError('descriptor child release write')
        release_write.close(ops)
        ops.checkpoint('descriptor.release.after')
        deadline = ops.monotonic() + _HELPER_START_SECONDS
        remaining = deadline - ops.monotonic()
        if not ops.poll_readable(status_read.fd, remaining):
            raise RuntimeClosureError('descriptor exec readiness deadline')
        if ops.read(status_read.fd, 1) != b'R':
            raise RuntimeClosureError('descriptor exec readiness record')
        if _proc_executable_identity(ops, child.pid) != resolved.executable.identity:
            raise RuntimeClosureError('descriptor child did not exec admitted Python')
        expected_fds = frozenset((0, 1, 2, 197, 4096))
        first = _snapshot_fd_directory(ops, f'/proc/{child.pid}/fd', False)
        second = _snapshot_fd_directory(ops, f'/proc/{child.pid}/fd', False)
        inheritance_exact = first == expected_fds and second == expected_fds
        if not inheritance_exact:
            raise RuntimeClosureError('descriptor exec inheritance mismatch')
        if ops.write(spare.fd, b'G') != 1:
            raise RuntimeClosureError('descriptor child completion write')
        remaining = deadline - ops.monotonic()
        if not ops.poll_readable(status_read.fd, remaining):
            raise RuntimeClosureError('descriptor exec status EOF deadline')
        if ops.read(status_read.fd, 1):
            raise RuntimeClosureError('descriptor exec emitted trailing status')
        status_read.close(ops)
        expected_exit = (os.CLD_EXITED, 0)
        ops.checkpoint('descriptor.wait.before')
        _wait_descriptor_child(ops, child, deadline, expected_exit)
        ops.checkpoint('descriptor.wait.after-reap')
        child_pidfd.close(ops)
        ops.checkpoint('descriptor.close-range.before')
        high.state = _FdState.CLOSE_UNCERTAIN
        try:
            ops.close_range(high.fd, high.fd)
        except BaseException as error:
            high.close_error = error
            raise
        high.close_error = None
        high.state = _FdState.CLOSED
        ops.checkpoint('descriptor.close-range.after')
        try:
            ops.fcntl(high.fd, _F_GETFD)
        except OSError as error:
            close_exact = error.errno == 9
        if not close_exact:
            raise RuntimeClosureError('descriptor close_range readback mismatch')
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try:
        ops.checkpoint('descriptor.cleanup.before')
    except BaseException as error:
        failures.append(error)
    if child is not None and not child.reaped:
        reverse_leases = tuple(reversed(leases))
        for gate in reverse_leases:
            if gate.purpose not in ('descriptor-release-write', 'descriptor-spare'):
                continue
            if gate.state is _FdState.OWNED:
                try:
                    gate.close(ops)
                except BaseException as error:
                    failures.append(error)
        close_uncertain = any(
            lease.state is _FdState.CLOSE_UNCERTAIN for lease in leases
        )
        try:
            grace = _HELPER_TERM_SECONDS if close_uncertain else 0.01
            short_deadline = ops.monotonic() + grace
            _wait_descriptor_child(ops, child, short_deadline, None)
        except RuntimeClosureError:
            if close_uncertain or not _descriptor_child_matches(ops, child):
                failures.append(RuntimeClosureError('descriptor child identity changed before KILL'))
            else:
                try:
                    ops.checkpoint('descriptor.kill.before')
                    ops.pidfd_signal(child.pidfd.fd, signal.SIGKILL)
                    ops.checkpoint('descriptor.kill.after')
                except BaseException as error:
                    failures.append(error)
            try:
                kill_deadline = ops.monotonic() + _HELPER_KILL_SECONDS
                _wait_descriptor_child(ops, child, kill_deadline, None)
            except BaseException as error:
                failures.append(error)
        except BaseException as error:
            failures.append(error)
    for lease in reversed(leases):
        if lease.state is not _FdState.OWNED:
            continue
        if child is not None and lease is child.pidfd and not child.reaped:
            failures.append(RuntimeClosureError('descriptor child pidfd remains authoritative'))
            continue
        try:
            lease.close(ops)
        except BaseException as error:
            failures.append(error)
    try:
        ops.checkpoint('descriptor.limit.before-restore')
    except BaseException as error:
        failures.append(error)
    try:
        ops.setrlimit(limit.original)
        limit.restored = ops.getrlimit() == limit.original
        ops.checkpoint('descriptor.limit.after-restore')
        if not limit.restored:
            raise RuntimeClosureError('descriptor limit restoration mismatch')
    except BaseException as error:
        failures.append(error)
    uncertain = any(lease.state is _FdState.CLOSE_UNCERTAIN for lease in leases)
    descriptors_restored = False
    children_reaped = False
    if not uncertain:
        try:
            descriptors_restored = _snapshot_fds(ops) == baseline
            children_reaped = _child_baseline(ops) == children
            if not descriptors_restored or not children_reaped:
                raise RuntimeClosureError('descriptor transaction baseline mismatch')
        except BaseException as error:
            failures.append(error)
    try:
        ops.checkpoint('descriptor.cleanup.after-baselines')
    except BaseException as error:
        failures.append(error)
    if failures:
        ordered = ([primary] if primary is not None else []) + failures
        raise RuntimeClosureCleanupError(ordered) from (primary or failures[0])
    if primary is not None:
        raise primary
    result = DescriptorQualificationResult(
        'cogs.runtime-descriptor-qualification/v1',
        admission.revision,
        admission.source_set_sha256,
        measured,
        normalized,
        low_exact,
        high_exact,
        close_exact,
        flags_exact,
        inheritance_exact,
        limit.restored,
        descriptors_restored,
        children_reaped,
    )
    owner._complete_fixed_operation()
    return result

def _prepare_state_machine(ops: _Ops, admission: object, issuer: object) -> PreparedRuntimeClosure:
    capability = _claim_admission(admission, issuer)
    preparation = PreparationLease(ops, frozenset(), (), outer=issuer)
    owner = PreparedRuntimeClosure(capability, admission, ops, preparation)
    ops.architecture_gate()
    _reserve_stdio(ops)
    preparation.fd_baseline = _snapshot_fds(ops)
    preparation.child_baseline = _child_baseline(ops)
    ops.checkpoint('state.preparing')
    closures: list[ResolvedToolClosure] = []
    sources: list[FdLease] = []
    try:
        for (tool, path) in FIXED_TOOL_TABLE:
            ops.checkpoint(f'resolve.{tool}.before')
            closure = _resolve_tool(ops, tool, path)
            closures.append(closure)
            for value in closure.objects:
                lease = preparation.register_fd(value.held_fd, f'source:{tool}:{value.role}')
                sources.append(lease)
            ops.checkpoint(f'resolve.{tool}.after')
        _enforce_global_alias_policy(closures)
        _validate_closure_bounds(tuple((tuple(((value.identity, value.size) for value in closure.objects)) for closure in closures)))
        mappings: list[MappedToolClosure] = []
        for closure in closures:
            ops.checkpoint(f'mapping.{closure.tool}.before-spawn')
            helper = _spawn_helper(ops, preparation, closure)
            mapping_error: BaseException | None = None
            try:
                ops.checkpoint(f'mapping.{closure.tool}.before-capture')
                mappings.append(_mapped_closure(ops, helper, closure))
                ops.checkpoint(f'mapping.{closure.tool}.after-capture')
            except BaseException as error:
                mapping_error = error
            try:
                _stop_helper(ops, preparation, helper)
            except BaseException as cleanup:
                if mapping_error is not None:
                    raise RuntimeClosureCleanupError((mapping_error, cleanup)) from mapping_error
                raise
            if mapping_error is not None:
                raise mapping_error
            ops.checkpoint(f'mapping.{closure.tool}.after-cleanup')
        (bundle, rows) = _build_bundle(ops, preparation, closures)
        for lease in bundle:
            ops.checkpoint('seal.object.after')
        candidate, report_value = _construct_report(
            ops,
            admission,
            closures,
            mappings,
        )
        _validate_generation_rows(report_value, rows, len(bundle))
        owner._report = candidate
        owner._bundle = bundle
        owner._rows = rows
        ops.checkpoint('report.before-seal')
        report_fd = _seal_report(ops, candidate)
        try:
            report_lease = preparation.register_fd(report_fd, 'sealed-report')
        except BaseException as primary:
            orphan = FdLease(report_fd, 'unregistered-sealed-report')
            _finish_fds(ops, (orphan,), primary)
            raise RuntimeClosureError('unreachable')
        owner._bundle.insert(0, report_lease)
        ops.checkpoint('report.after-seal')
        preparation.close_many(sources)
        owner._prove_ready_baseline()
        ops.checkpoint('report.before-publish')
        owner._state = _OwnerState.READY
        ops.checkpoint('state.ready')
        return owner
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        for helper in tuple(preparation.helpers):
            try:
                _stop_helper(ops, preparation, helper)
            except BaseException as error:
                failures.append(error)
        for lease in reversed(preparation.fds):
            if lease.state is _FdState.OWNED:
                try:
                    lease.close(ops)
                except BaseException as error:
                    failures.append(error)
        try:
            if _snapshot_fds(ops) != preparation.fd_baseline:
                failures.append(RuntimeClosureError('failure descriptor baseline not restored'))
            if _child_baseline(ops) != preparation.child_baseline:
                failures.append(RuntimeClosureError('failure child baseline not restored'))
        except BaseException as error:
            failures.append(error)
        owner._poison = RuntimeClosureCleanupError(failures)
        owner._state = _OwnerState.POISONED
        raise owner._poison from primary

def _prepare_admitted_fixed_runtime_closure(admission: object, issuer: object) -> PreparedRuntimeClosure:
    """Private fixed entry called only by the authenticated launcher worker."""
    return _prepare_state_machine(_Ops(), admission, issuer)

def _qualify_admitted_fixed_python_mapping(admission: object) -> RuntimeMappingQualificationResult:
    return _qualify_fixed_python_mapping_with_ops(admission, _Ops())

def _qualify_admitted_fixed_descriptor_primitives(admission: object) -> DescriptorQualificationResult:
    return _qualify_fixed_descriptor_primitives_with_ops(admission, _Ops())

def prepare_fixed_runtime_closure() -> NoReturn:
    """Ambient preparation is forbidden and fails before any authority-bearing effect."""
    raise RuntimeClosureError('runtime closure requires the admitted private launcher entry')
__all__ = ()
