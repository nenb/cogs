#!/usr/bin/env python3
"""Operation ownership, recovery, process closure, and conservative deletion."""

from dataclasses import dataclass
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import secrets
import signal
import stat
import subprocess
import time

from completion_runtime_contract import _open_absolute_directory, _status_identity

LIFECYCLE_SECONDS = 1200.0
CLEANUP_RESERVE_SECONDS = 30.0
COMMAND_SECONDS = 300.0
TERM_SECONDS = 1.0
KILL_SECONDS = 1.0
MAX_COMMAND_OUTPUT = 65_536
RENAME_NOREPLACE = 1
SUPERVISOR_UID = 0
WORKLOAD_UID = 65_534
WORKLOAD_GID = 65_534
PROCESS_CONTAINMENT = "linux-subreaper-pidfd-or-start-time-no-cgroup-v2"
PROCESS_LIMITATION = "no-cgroup-proof-honest-supervisor-crash-only-not-hostile-process-closure"
_RACE_HOOK = None
_STATE_HOOK = None
_CLEANUP_HOOK = None
_HEX = frozenset("0123456789abcdef")


class WorkloadError(Exception):
    category = "invariant"


class WorkloadDeadline(WorkloadError):
    category = "deadline"


class WorkloadInterrupted(WorkloadError):
    category = "interrupted"


class CleanupUncertain(WorkloadError):
    category = "cleanup-uncertain"


class ChildUncertain(WorkloadError):
    category = "child-uncertain"


class OutputUncertain(WorkloadError):
    category = "output-uncertain"


def _require(condition, message="workload invariant failed"):
    if not condition:
        raise WorkloadError(message)


def _safe_relative(value):
    path = PurePosixPath(value)
    _require(not path.is_absolute() and value not in {"", ".", ".."} and ".." not in path.parts)
    return path.parts


def _write_all(descriptor, raw):
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OutputUncertain("short file write")
        view = view[written:]


def _read_fd(descriptor, maximum):
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65_536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    _require(len(raw) <= maximum)
    return raw


def _same_object(first, second):
    return (
        first.st_dev,
        first.st_ino,
        stat.S_IFMT(first.st_mode),
        stat.S_IMODE(first.st_mode),
        first.st_uid,
        first.st_gid,
        first.st_nlink,
    ) == (
        second.st_dev,
        second.st_ino,
        stat.S_IFMT(second.st_mode),
        stat.S_IMODE(second.st_mode),
        second.st_uid,
        second.st_gid,
        second.st_nlink,
    )


def _cleanup_cut(stage):
    hook = _CLEANUP_HOOK
    if hook is not None:
        hook(stage)


def _entry_exists(parent_fd, name):
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _open_checked(parent_fd, name, flags, expected=None):
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False) if expected is None else expected
    _cut("stat-open", parent_fd, name, "")
    descriptor = os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not _same_object(before, opened) or not _same_object(opened, current):
        os.close(descriptor)
        raise CleanupUncertain("opened descriptor identity differs")
    return descriptor


def _cut(stage, parent_fd, source, quarantine):
    hook = _RACE_HOOK
    if hook is not None:
        hook(stage, parent_fd, source, quarantine)


def _rename_noreplace(source_fd, source, destination_fd, destination):
    if platform.system() != "Linux":
        raise CleanupUncertain("Linux no-replace quarantine is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise CleanupUncertain("Linux no-replace quarantine is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    result = function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), RENAME_NOREPLACE)
    if result != 0:
        code = ctypes.get_errno()
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise CleanupUncertain("quarantine destination already exists")
        raise CleanupUncertain("no-replace quarantine failed")


@dataclass(frozen=True)
class Deadline:
    end_ns: int
    cleanup_ns: int

    @classmethod
    def start(cls, seconds=LIFECYCLE_SECONDS, cleanup_seconds=CLEANUP_RESERVE_SECONDS):
        _require(type(seconds) in {int, float} and type(cleanup_seconds) in {int, float})
        _require(seconds > cleanup_seconds > 0)
        now = time.monotonic_ns()
        return cls(now + int(seconds * 1_000_000_000), int(cleanup_seconds * 1_000_000_000))

    def effect_seconds(self, maximum=COMMAND_SECONDS):
        remaining = self.end_ns - self.cleanup_ns - time.monotonic_ns()
        if remaining <= 0:
            raise WorkloadDeadline("effect deadline expired")
        return min(maximum, remaining / 1_000_000_000)

    def cleanup_seconds(self, maximum):
        remaining = self.end_ns - time.monotonic_ns()
        if remaining <= 0:
            raise CleanupUncertain("cleanup deadline expired")
        return min(maximum, remaining / 1_000_000_000)

    def effect_check(self):
        self.effect_seconds()

    def cleanup_check(self):
        self.cleanup_seconds(1.0)


class SignalScope:
    def __enter__(self):
        self.previous = {}

        def interrupted(_signum, _frame):
            raise WorkloadInterrupted("transaction interrupted")

        for number in (signal.SIGTERM, signal.SIGINT):
            self.previous[number] = signal.getsignal(number)
            signal.signal(number, interrupted)
        return self

    def __exit__(self, _kind, _value, _traceback):
        for number, handler in self.previous.items():
            signal.signal(number, handler)


@dataclass
class ProcessIdentity:
    pid: int
    start_time: int
    pidfd: int = -1

    def close(self):
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1


def _proc_read(relative, maximum=65_536):
    descriptor = os.open(relative, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        raw = _read_fd(descriptor, maximum)
        after = os.fstat(descriptor)
        _require(_status_identity(before) == _status_identity(after))
        return raw
    finally:
        os.close(descriptor)


def _pid_start_time(process_id):
    try:
        raw = _proc_read(f"/proc/{process_id}/stat", 4096)
        suffix = raw[raw.rfind(b") ") + 2 :].split()
        _require(len(suffix) > 19)
        return int(suffix[19])
    except (OSError, ValueError, WorkloadError):
        return None


def _identity(process_id):
    start = _pid_start_time(process_id)
    if start is None:
        return None
    descriptor = -1
    if hasattr(os, "pidfd_open"):
        try:
            descriptor = os.pidfd_open(process_id, 0)
        except OSError:
            descriptor = -1
    if _pid_start_time(process_id) != start:
        if descriptor >= 0:
            os.close(descriptor)
        return None
    return ProcessIdentity(process_id, start, descriptor)


def _children_ids():
    try:
        raw = _proc_read(f"/proc/self/task/{os.getpid()}/children")
        return {int(value) for value in raw.split()}
    except (OSError, ValueError, WorkloadError) as error:
        raise ChildUncertain("child inventory unavailable") from error


def _children():
    return _children_ids()


def _enable_subreaper():
    if platform.system() != "Linux":
        raise WorkloadError("host workload requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise ChildUncertain("child ownership unavailable")
    _require(not _children_ids(), "host process already owns children")


def _signal_identity(identity, number):
    if _pid_start_time(identity.pid) != identity.start_time:
        return
    try:
        if identity.pidfd >= 0 and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(identity.pidfd, number)
        else:
            os.kill(identity.pid, number)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ChildUncertain("owned child could not be signaled") from error


def _reap_available():
    while True:
        try:
            process_id, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if process_id == 0:
            return


def _drain_descendants(deadline, fail_if_found=False):
    """Repeatedly discover, identity-check, signal, and reap until twice stable empty."""
    found = False
    for number, budget in ((signal.SIGTERM, TERM_SECONDS), (signal.SIGKILL, KILL_SECONDS)):
        end = time.monotonic() + deadline.cleanup_seconds(budget)
        stable = 0
        while time.monotonic() < end:
            _reap_available()
            identities = []
            for process_id in _children_ids():
                item = _identity(process_id)
                if item is not None:
                    identities.append(item)
            if identities:
                found = True
                stable = 0
                for item in identities:
                    try:
                        _signal_identity(item, number)
                    finally:
                        item.close()
            else:
                stable += 1
                if stable >= 2:
                    if fail_if_found and found:
                        raise ChildUncertain("child escaped the fixed command")
                    return found
            time.sleep(0.01)
    _reap_available()
    if _children_ids():
        raise ChildUncertain("descendant cleanup is uncertain")
    # Require two final stable observations even at the KILL boundary.
    time.sleep(min(0.01, deadline.cleanup_seconds(0.01)))
    if _children_ids():
        raise ChildUncertain("descendant cleanup is unstable")
    if fail_if_found and found:
        raise ChildUncertain("child escaped the fixed command")
    return found


def _signal_group(process, number):
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ChildUncertain("child process group could not be signaled") from error


def _wait_process(process, seconds):
    try:
        return process.wait(timeout=max(0.001, seconds))
    except subprocess.TimeoutExpired:
        return None


def _terminate_leader(process, deadline):
    _signal_group(process, signal.SIGTERM)
    result = _wait_process(process, deadline.cleanup_seconds(TERM_SECONDS))
    if result is None:
        _signal_group(process, signal.SIGKILL)
        result = _wait_process(process, deadline.cleanup_seconds(KILL_SECONDS))
    if result is None:
        raise ChildUncertain("command leader could not be reaped")


def _tagged_processes(generation):
    tag = b"COGS_HOST_OPERATION_GENERATION=" + generation
    identities = []
    try:
        names = os.listdir("/proc")
    except OSError as error:
        raise ChildUncertain("process inventory unavailable") from error
    for name in names:
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            raw = _proc_read(f"/proc/{name}/environ", 1_048_576)
        except (OSError, WorkloadError):
            continue
        if tag not in raw.split(b"\x00"):
            continue
        item = _identity(int(name))
        if item is not None:
            identities.append(item)
    return identities


def _drain_tagged(generation, deadline):
    for number, budget in ((signal.SIGTERM, TERM_SECONDS), (signal.SIGKILL, KILL_SECONDS)):
        end = time.monotonic() + deadline.cleanup_seconds(budget)
        stable = 0
        while time.monotonic() < end:
            identities = _tagged_processes(generation)
            if identities:
                stable = 0
                for item in identities:
                    try:
                        _signal_identity(item, number)
                    finally:
                        item.close()
            else:
                stable += 1
                if stable >= 2:
                    return
            time.sleep(0.01)
    if _tagged_processes(generation):
        raise ChildUncertain("recovery process cleanup is uncertain")


class _CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapabilityData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def _limit_output():
    """Enter the fixed nobody identity with zero capabilities before exec."""
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_COMMAND_OUTPUT, MAX_COMMAND_OUTPUT))
    libc = ctypes.CDLL(None, use_errno=True)
    for capability in range(64):
        if libc.prctl(24, capability, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
            if ctypes.get_errno() != errno.EINVAL:
                os._exit(126)
    if libc.prctl(47, 4, 0, 0, 0) != 0:  # PR_CAP_AMBIENT_CLEAR_ALL
        os._exit(126)
    securebits = 0x0F  # NOROOT, NOROOT_LOCKED, NO_SETUID_FIXUP, and its lock.
    if libc.prctl(28, securebits, 0, 0, 0) != 0:  # PR_SET_SECUREBITS
        os._exit(126)
    try:
        os.setgroups([])
        os.setresgid(WORKLOAD_GID, WORKLOAD_GID, WORKLOAD_GID)
        os.setresuid(WORKLOAD_UID, WORKLOAD_UID, WORKLOAD_UID)
    except OSError:
        os._exit(126)
    header = _CapabilityHeader(0x20080522, 0)
    data = (_CapabilityData * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        os._exit(126)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        os._exit(126)


_PHASES = (
    "intent",
    "parent-created",
    "running",
    "child-empty",
    "root-removing",
    "root-removed",
    "journal-retired",
    "parent-removing",
    "parent-removed",
    "uncertain",
)


class ExternalState:
    """Append-only root-owned tombstone retained until parent absence is durable."""

    def __init__(self, outer_fd, operation_name, descriptor, status, records):
        self.outer_fd = outer_fd
        self.operation_name = operation_name
        self.name = f".{operation_name}.recovery-v2"
        self.descriptor = descriptor
        self.status = status
        self.records = records
        self.value = records[-1] if records else None

    @classmethod
    def create(cls, outer_fd, operation_name, kind, generation):
        name = f".{operation_name}.recovery-v2"
        temporary = f".{operation_name}.recovery-build-{generation.decode('ascii')}"
        descriptor = os.open(temporary, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=outer_fd)
        status = os.fstat(descriptor)
        _require(stat.S_ISREG(status.st_mode) and status.st_uid == SUPERVISOR_UID and status.st_nlink == 1)
        os.fsync(outer_fd)
        _cleanup_cut("tombstone-created")
        instance = cls(outer_fd, operation_name, descriptor, status, [])
        instance.name = temporary
        staging = f".{operation_name}.build-{generation.decode('ascii')}"
        instance.append("intent", notify=False, kind=kind, generation=generation.decode("ascii"), staging_name=staging)
        _cleanup_cut("tombstone-durable")
        _rename_noreplace(outer_fd, temporary, outer_fd, name)
        os.fsync(outer_fd)
        instance.name = name
        hook = _STATE_HOOK
        if hook is not None:
            hook("intent")
        return instance

    @classmethod
    def load(cls, outer_fd, operation_name, kind):
        name = f".{operation_name}.recovery-v2"
        descriptor = _open_checked(outer_fd, name, os.O_RDWR | os.O_APPEND)
        status = os.fstat(descriptor)
        _require(stat.S_ISREG(status.st_mode) and status.st_uid == SUPERVISOR_UID and status.st_nlink == 1)
        raw = _read_fd(descriptor, 65_536)
        complete = raw[: raw.rfind(b"\n") + 1]
        _require(complete)
        records = []
        previous = "0" * 64
        for sequence, line in enumerate(complete.splitlines(keepends=True)):
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CleanupUncertain("external recovery state is invalid") from error
            _require(line == json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n")
            _require(type(value) is dict and value.get("sequence") == sequence and value.get("previous_sha256") == previous)
            _require(value.get("version") == "cogs.stage2-workload-external-recovery/v2")
            _require(value.get("operation_name") == operation_name and value.get("kind") == kind)
            _require(value.get("phase") in _PHASES)
            _require(value.get("process_containment") == PROCESS_CONTAINMENT and value.get("process_limitation") == PROCESS_LIMITATION)
            if records:
                _require(_PHASES.index(value["phase"]) >= _PHASES.index(records[-1]["phase"]))
                _require(value["generation"] == records[0]["generation"] and value["staging_name"] == records[0]["staging_name"])
            previous = hashlib.sha256(line).hexdigest()
            records.append(value)
        if len(complete) != len(raw):
            os.ftruncate(descriptor, len(complete))
            os.fsync(descriptor)
        return cls(outer_fd, operation_name, descriptor, status, records)

    def append(self, phase, notify=True, **changes):
        _require(phase in _PHASES)
        prior = self.records[-1] if self.records else {
            "kind": changes["kind"],
            "generation": changes["generation"],
            "staging_name": changes["staging_name"],
            "parent_dev": None,
            "parent_ino": None,
            "root_dev": None,
            "root_ino": None,
            "root_uid": None,
            "root_gid": None,
            "root_mode": None,
            "root_quarantine": None,
            "parent_quarantine": None,
            "process_containment": PROCESS_CONTAINMENT,
            "process_limitation": PROCESS_LIMITATION,
        }
        value = {
            **prior,
            **changes,
            "version": "cogs.stage2-workload-external-recovery/v2",
            "operation_name": self.operation_name,
            "phase": phase,
            "sequence": len(self.records),
            "previous_sha256": "0" * 64 if not self.records else hashlib.sha256(self._raw(self.records[-1])).hexdigest(),
        }
        raw = self._raw(value)
        _write_all(self.descriptor, raw)
        os.fsync(self.descriptor)
        current = os.stat(self.name, dir_fd=self.outer_fd, follow_symlinks=False)
        _require(_same_object(self.status, os.fstat(self.descriptor)) and _same_object(os.fstat(self.descriptor), current))
        self.records.append(value)
        self.value = value
        hook = _STATE_HOOK
        if notify and hook is not None:
            hook(phase)

    @staticmethod
    def _raw(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"

    def retire(self):
        for name in (self.operation_name, self.value["staging_name"], self.value.get("parent_quarantine")):
            if not name:
                continue
            try:
                os.stat(name, dir_fd=self.outer_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CleanupUncertain("parent absence is not proved")
        current = os.stat(self.name, dir_fd=self.outer_fd, follow_symlinks=False)
        _require(_same_object(self.status, os.fstat(self.descriptor)) and _same_object(os.fstat(self.descriptor), current))
        os.unlink(self.name, dir_fd=self.outer_fd)
        os.fsync(self.outer_fd)
        os.close(self.descriptor)
        self.descriptor = -1


class OwnedRoot:
    """A durable retained root inside a fixed root-owned mode-0700 parent."""

    ROOT_NAME = "retained"
    JOURNAL_NAME = "recovery.json"

    def __init__(self, path, deadline, kind="host-candidate"):
        self.path = Path(path)
        _require(self.path.is_absolute() and self.path.name not in {"", ".", ".."})
        _require(kind in {"host-candidate", "host-post-pin"})
        self.kind = kind
        self.deadline = deadline
        self.outer_fd = _open_absolute_directory(self.path.parent)
        self.parent_fd = -1
        self.fd = -1
        self.closed = False
        self.uncertain = False
        self.generation = secrets.token_hex(16).encode("ascii")
        self.state = None
        try:
            try:
                os.stat(self.path.name, dir_fd=self.outer_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise WorkloadError("operation recovery is required")
            self.state = ExternalState.create(self.outer_fd, self.path.name, kind, self.generation)
            staging = self.state.value["staging_name"]
            os.mkdir(staging, 0o700, dir_fd=self.outer_fd)
            os.fsync(self.outer_fd)
            _cleanup_cut("parent-staging-created")
            staging_fd = _open_checked(self.outer_fd, staging, os.O_RDONLY | os.O_DIRECTORY)
            try:
                parent_marker = os.open(".parent-generation", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=staging_fd)
                try:
                    _write_all(parent_marker, self.generation)
                    os.fsync(parent_marker)
                finally:
                    os.close(parent_marker)
                os.fsync(staging_fd)
                _cleanup_cut("parent-marker-durable")
            finally:
                os.close(staging_fd)
            os.fsync(self.outer_fd)
            _rename_noreplace(self.outer_fd, staging, self.outer_fd, self.path.name)
            os.fsync(self.outer_fd)
            _cleanup_cut("parent-published")
            self.parent_fd = _open_checked(self.outer_fd, self.path.name, os.O_RDONLY | os.O_DIRECTORY)
            parent_status = os.fstat(self.parent_fd)
            _require(stat.S_ISDIR(parent_status.st_mode) and parent_status.st_uid == SUPERVISOR_UID)
            _require(stat.S_IMODE(parent_status.st_mode) == 0o700 and parent_status.st_nlink == 2)
            self.state.append("parent-created", parent_dev=parent_status.st_dev, parent_ino=parent_status.st_ino)
            os.mkdir(self.ROOT_NAME, 0o700, dir_fd=self.parent_fd)
            os.fsync(self.parent_fd)
            _cleanup_cut("root-created")
            os.chown(self.ROOT_NAME, WORKLOAD_UID, WORKLOAD_GID, dir_fd=self.parent_fd, follow_symlinks=False)
            self.fd = _open_checked(self.parent_fd, self.ROOT_NAME, os.O_RDONLY | os.O_DIRECTORY)
            status = os.fstat(self.fd)
            _require(stat.S_ISDIR(status.st_mode) and status.st_uid == WORKLOAD_UID and status.st_gid == WORKLOAD_GID)
            _require(stat.S_IMODE(status.st_mode) == 0o700 and status.st_nlink == 2)
            self.identity = status
            marker = os.open(".owner-generation", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            try:
                _write_all(marker, self.generation)
                os.fsync(marker)
                marker_status = os.fstat(marker)
                _require(stat.S_ISREG(marker_status.st_mode) and marker_status.st_nlink == 1)
                _require(marker_status.st_uid == SUPERVISOR_UID and stat.S_IMODE(marker_status.st_mode) == 0o600)
                self.marker_identity = marker_status
            finally:
                os.close(marker)
            os.fsync(self.fd)
            os.fsync(self.parent_fd)
            _cleanup_cut("root-marker-durable")
            self._write_journal()
            _cleanup_cut("journal-durable")
            self.state.append(
                "running",
                root_dev=status.st_dev,
                root_ino=status.st_ino,
                root_uid=status.st_uid,
                root_gid=status.st_gid,
                root_mode=stat.S_IMODE(status.st_mode),
            )
        except BaseException:
            for descriptor_name in ("fd", "parent_fd"):
                descriptor = getattr(self, descriptor_name)
                if descriptor >= 0:
                    os.close(descriptor)
                    setattr(self, descriptor_name, -1)
            if self.state is not None and self.state.descriptor >= 0:
                os.close(self.state.descriptor)
                self.state.descriptor = -1
            os.close(self.outer_fd)
            raise CleanupUncertain("operation construction requires cleanup-only recovery") from None

    def _journal_value(self):
        return {
            "version": "cogs.stage2-workload-recovery/v1",
            "kind": self.kind,
            "generation": self.generation.decode("ascii"),
            "root_name": self.ROOT_NAME,
            "root_dev": self.identity.st_dev,
            "root_ino": self.identity.st_ino,
            "root_uid": self.identity.st_uid,
            "root_mode": stat.S_IMODE(self.identity.st_mode),
            "marker_sha256": hashlib.sha256(self.generation).hexdigest(),
            "process_containment": PROCESS_CONTAINMENT,
            "process_limitation": PROCESS_LIMITATION,
        }

    def _write_journal(self):
        raw = json.dumps(self._journal_value(), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        descriptor = os.open(self.JOURNAL_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self.parent_fd)
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
            status = os.fstat(descriptor)
            _require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1 and status.st_uid == SUPERVISOR_UID)
            _require(stat.S_IMODE(status.st_mode) == 0o600)
        finally:
            os.close(descriptor)
        os.fsync(self.parent_fd)
        os.fsync(self.outer_fd)

    def _checked_open(self, parent_fd, name, flags, expected=None):
        try:
            return _open_checked(parent_fd, name, flags, expected)
        except CleanupUncertain:
            self.uncertain = True
            raise

    def _open_dir(self, relative="."):
        descriptor = os.dup(self.fd)
        try:
            if relative not in {"", "."}:
                for component in _safe_relative(relative):
                    next_descriptor = self._checked_open(descriptor, component, os.O_RDONLY | os.O_DIRECTORY)
                    os.close(descriptor)
                    descriptor = next_descriptor
            status = os.fstat(descriptor)
            _require(stat.S_ISDIR(status.st_mode) and status.st_uid == WORKLOAD_UID and status.st_gid == WORKLOAD_GID and status.st_nlink >= 2)
            _require(not stat.S_IMODE(status.st_mode) & 0o022)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def mkdir(self, relative, mode=0o700, parents=False, exist_ok=False):
        self.deadline.effect_check()
        parts = _safe_relative(relative)
        descriptor = os.dup(self.fd)
        try:
            for index, component in enumerate(parts):
                final = index == len(parts) - 1
                if not final:
                    try:
                        next_descriptor = self._checked_open(descriptor, component, os.O_RDONLY | os.O_DIRECTORY)
                    except FileNotFoundError:
                        if not parents:
                            raise
                        os.mkdir(component, 0o700, dir_fd=descriptor)
                        os.chown(component, WORKLOAD_UID, WORKLOAD_GID, dir_fd=descriptor, follow_symlinks=False)
                        next_descriptor = self._checked_open(descriptor, component, os.O_RDONLY | os.O_DIRECTORY)
                else:
                    try:
                        os.mkdir(component, mode, dir_fd=descriptor)
                        os.chown(component, WORKLOAD_UID, WORKLOAD_GID, dir_fd=descriptor, follow_symlinks=False)
                    except FileExistsError:
                        if not exist_ok:
                            raise
                    next_descriptor = self._checked_open(descriptor, component, os.O_RDONLY | os.O_DIRECTORY)
                status = os.fstat(next_descriptor)
                _require(stat.S_ISDIR(status.st_mode) and status.st_uid == WORKLOAD_UID and status.st_gid == WORKLOAD_GID)
                os.close(descriptor)
                descriptor = next_descriptor
            os.fchmod(descriptor, mode)
        except OSError as error:
            raise WorkloadError("directory creation failed") from error
        finally:
            os.close(descriptor)

    def write_file(self, relative, raw, mode=0o600, mtime=None, append=False):
        self.deadline.effect_check()
        parts = _safe_relative(relative)
        parent = self._open_dir("/".join(parts[:-1]) or ".")
        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            flags |= os.O_APPEND if append else os.O_CREAT | os.O_EXCL
            descriptor = os.open(parts[-1], flags, mode, dir_fd=parent)
            if not append:
                os.fchown(descriptor, WORKLOAD_UID, WORKLOAD_GID)
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == WORKLOAD_UID and before.st_gid == WORKLOAD_GID)
            _write_all(descriptor, raw)
            os.fchmod(descriptor, mode)
            if mtime is not None:
                os.utime(descriptor, (mtime, mtime))
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            _require((after.st_dev, after.st_ino, after.st_nlink) == (before.st_dev, before.st_ino, 1))
        except OSError as error:
            raise WorkloadError("file write failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)

    def read_file(self, relative, maximum, require_owner=True):
        parts = _safe_relative(relative)
        parent = self._open_dir("/".join(parts[:-1]) or ".")
        descriptor = -1
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum)
            _require(not stat.S_IMODE(before.st_mode) & 0o022)
            if require_owner:
                _require(before.st_uid == WORKLOAD_UID and before.st_gid == WORKLOAD_GID)
            raw = _read_fd(descriptor, maximum)
            after = os.fstat(descriptor)
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            _require(_status_identity(before) == _status_identity(after) == _status_identity(current))
            _require(len(raw) == before.st_size)
            return raw, before
        except OSError as error:
            raise WorkloadError("file read failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)

    def unlink(self, relative):
        parts = _safe_relative(relative)
        parent = self._open_dir("/".join(parts[:-1]) or ".")
        descriptor = -1
        try:
            descriptor = self._checked_open(parent, parts[-1], os.O_RDONLY)
            self._quarantine_file(parent, parts[-1], descriptor, "owned-file")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)

    def proc_path(self, relative=""):
        if relative:
            _safe_relative(relative)
            return f"/proc/self/fd/{self.fd}/{relative}"
        return f"/proc/self/fd/{self.fd}"

    def child_environment(self, environment):
        return {**environment, "COGS_HOST_OPERATION_GENERATION": self.generation.decode("ascii")}

    def _quarantine(self, parent_fd, name, retained, stage):
        expected = os.fstat(retained)
        quarantine = f".q-{self.generation.decode()}-{secrets.token_hex(8)}"
        _cut(stage, parent_fd, name, quarantine)
        try:
            _rename_noreplace(parent_fd, name, parent_fd, quarantine)
        except CleanupUncertain:
            self.uncertain = True
            raise
        observed = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        current = os.fstat(retained)
        if not _same_object(expected, current) or not _same_object(current, observed):
            # Both the source-side racer and quarantine name are preserved. No rollback.
            self.uncertain = True
            raise CleanupUncertain("quarantined identity differs")
        return quarantine, current

    def _quarantine_file(self, parent_fd, name, retained, stage):
        quarantine, expected = self._quarantine(parent_fd, name, retained, stage)
        if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
            self.uncertain = True
            raise CleanupUncertain("owned file identity is invalid")
        _cut(f"{stage}-delete", parent_fd, quarantine, "")
        current = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_object(expected, current) or not _same_object(os.fstat(retained), current):
            self.uncertain = True
            raise CleanupUncertain("quarantined file was replaced")
        os.unlink(quarantine, dir_fd=parent_fd)

    def _delete_contents(self, descriptor):
        self.deadline.cleanup_check()
        for name in sorted(os.listdir(descriptor)):
            self.deadline.cleanup_check()
            status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            owned = status.st_uid == SUPERVISOR_UID or (status.st_uid, status.st_gid) == (WORKLOAD_UID, WORKLOAD_GID)
            if not owned or stat.S_IMODE(status.st_mode) & 0o022:
                self.uncertain = True
                raise CleanupUncertain("owned entry owner or mode changed")
            if stat.S_ISDIR(status.st_mode):
                child = self._checked_open(descriptor, name, os.O_RDONLY | os.O_DIRECTORY, status)
                try:
                    quarantine, expected = self._quarantine(descriptor, name, child, "inner-directory")
                    self._delete_contents(child)
                    emptied = os.fstat(child)
                    current = os.stat(quarantine, dir_fd=descriptor, follow_symlinks=False)
                    if emptied.st_nlink != 2 or not _same_object(emptied, current):
                        self.uncertain = True
                        raise CleanupUncertain("quarantined directory changed")
                    _cut("inner-directory-delete", descriptor, quarantine, "")
                    current = os.stat(quarantine, dir_fd=descriptor, follow_symlinks=False)
                    if not _same_object(emptied, current):
                        self.uncertain = True
                        raise CleanupUncertain("quarantined directory was replaced")
                    os.rmdir(quarantine, dir_fd=descriptor)
                finally:
                    os.close(child)
            else:
                child = self._checked_open(descriptor, name, os.O_RDONLY, status)
                try:
                    self._quarantine_file(descriptor, name, child, "inner-file")
                finally:
                    os.close(child)

    def remove_tree(self, relative, stage="owned-directory"):
        parts = _safe_relative(relative)
        parent = self._open_dir("/".join(parts[:-1]) or ".")
        child = -1
        try:
            status = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            child = self._checked_open(parent, parts[-1], os.O_RDONLY | os.O_DIRECTORY, status)
            quarantine, _expected = self._quarantine(parent, parts[-1], child, stage)
            self._delete_contents(child)
            emptied = os.fstat(child)
            current = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
            if emptied.st_nlink != 2 or not _same_object(emptied, current):
                self.uncertain = True
                raise CleanupUncertain("quarantined tree changed")
            _cut(f"{stage}-delete", parent, quarantine, "")
            current = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
            if not _same_object(emptied, current):
                self.uncertain = True
                raise CleanupUncertain("quarantined tree was replaced")
            os.rmdir(quarantine, dir_fd=parent)
        finally:
            if child >= 0:
                os.close(child)
            os.close(parent)

    def remove_output(self, descriptor):
        self._quarantine_file(self.fd, "command.out", descriptor, "command-output")

    def verify_generation(self):
        status = os.fstat(self.fd)
        _require((status.st_dev, status.st_ino) == (self.identity.st_dev, self.identity.st_ino))
        raw, marker = self.read_file(".owner-generation", 32, require_owner=False)
        _require(marker.st_uid == SUPERVISOR_UID and raw == self.generation and _same_object(marker, self.marker_identity))

    def _before_phase(self, phase):
        return _PHASES.index(self.state.value["phase"]) < _PHASES.index(phase)

    def _retire_parent_file(self, source, quarantine):
        source_exists = _entry_exists(self.parent_fd, source)
        quarantine_exists = _entry_exists(self.parent_fd, quarantine)
        if source_exists and quarantine_exists:
            raise CleanupUncertain("journal generations conflict")
        if source_exists:
            descriptor = self._checked_open(self.parent_fd, source, os.O_RDONLY)
            try:
                status = os.fstat(descriptor)
                _require(stat.S_ISREG(status.st_mode) and status.st_uid == SUPERVISOR_UID and status.st_nlink == 1)
                _rename_noreplace(self.parent_fd, source, self.parent_fd, quarantine)
                _cleanup_cut(f"{source}-quarantined")
                current = os.stat(quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
                _require(_same_object(status, os.fstat(descriptor)) and _same_object(os.fstat(descriptor), current))
            finally:
                os.close(descriptor)
            quarantine_exists = True
        if quarantine_exists:
            descriptor = self._checked_open(self.parent_fd, quarantine, os.O_RDONLY)
            try:
                status = os.fstat(descriptor)
                _require(stat.S_ISREG(status.st_mode) and status.st_uid == SUPERVISOR_UID and status.st_nlink == 1)
                current = os.stat(quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
                _require(_same_object(status, current))
                os.unlink(quarantine, dir_fd=self.parent_fd)
                _cleanup_cut(f"{source}-removed")
            finally:
                os.close(descriptor)

    def cleanup(self, process_check=True):
        if self.closed:
            return
        if self.uncertain:
            if self.state is not None and self.state.descriptor >= 0 and self.state.value["phase"] != "uncertain":
                self.state.append("uncertain")
            raise CleanupUncertain("operation was previously uncertain")
        try:
            if self._before_phase("child-empty"):
                if process_check:
                    _drain_descendants(self.deadline, fail_if_found=True)
                    if _tagged_processes(self.generation):
                        raise CleanupUncertain("tagged process remains")
                self.state.append("child-empty")
            # No same-transaction workload writer exists beyond child-empty.
            root_quarantine = self.state.value.get("root_quarantine") or f".root-{self.generation.decode('ascii')}"
            if self._before_phase("root-removing"):
                self.state.append("root-removing", root_quarantine=root_quarantine)
            if self.fd >= 0:
                self.verify_generation()
                retained_status = os.fstat(self.fd)
                if _entry_exists(self.parent_fd, self.ROOT_NAME):
                    if _entry_exists(self.parent_fd, root_quarantine):
                        raise CleanupUncertain("root generations conflict")
                    _cut("source-root", self.parent_fd, self.ROOT_NAME, root_quarantine)
                    _rename_noreplace(self.parent_fd, self.ROOT_NAME, self.parent_fd, root_quarantine)
                    _cleanup_cut("root-quarantined")
                current = os.stat(root_quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
                if not _same_object(retained_status, os.fstat(self.fd)) or not _same_object(os.fstat(self.fd), current):
                    self.uncertain = True
                    raise CleanupUncertain("root replacement was quarantined but not owned")
                self._delete_contents(self.fd)
                _cleanup_cut("root-contents-removed")
                emptied = os.fstat(self.fd)
                current = os.stat(root_quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
                _require(emptied.st_nlink == 2 and _same_object(emptied, current))
                os.close(self.fd)
                self.fd = -1
                os.rmdir(root_quarantine, dir_fd=self.parent_fd)
                os.fsync(self.parent_fd)
                _cleanup_cut("root-directory-removed")
            elif _entry_exists(self.parent_fd, self.ROOT_NAME) or _entry_exists(self.parent_fd, root_quarantine):
                raise CleanupUncertain("root identity is unavailable")
            if self._before_phase("root-removed"):
                self.state.append("root-removed", root_quarantine=root_quarantine)

            self._retire_parent_file(self.JOURNAL_NAME, f".journal-{self.generation.decode('ascii')}")
            self._retire_parent_file(".parent-generation", f".parent-marker-{self.generation.decode('ascii')}")
            os.fsync(self.parent_fd)
            if self._before_phase("journal-retired"):
                self.state.append("journal-retired")

            parent_status = os.fstat(self.parent_fd)
            if parent_status.st_nlink != 2 or os.listdir(self.parent_fd):
                raise CleanupUncertain("operation parent is not empty")
            parent_quarantine = self.state.value.get("parent_quarantine") or f".{self.path.name}.parent-{self.generation.decode('ascii')}"
            if self._before_phase("parent-removing"):
                self.state.append("parent-removing", parent_quarantine=parent_quarantine)
            if _entry_exists(self.outer_fd, self.path.name):
                if _entry_exists(self.outer_fd, parent_quarantine):
                    raise CleanupUncertain("parent generations conflict")
                _rename_noreplace(self.outer_fd, self.path.name, self.outer_fd, parent_quarantine)
                _cleanup_cut("parent-quarantined")
            current = os.stat(parent_quarantine, dir_fd=self.outer_fd, follow_symlinks=False)
            _require(_same_object(os.fstat(self.parent_fd), current))
            os.close(self.parent_fd)
            self.parent_fd = -1
            os.rmdir(parent_quarantine, dir_fd=self.outer_fd)
            os.fsync(self.outer_fd)
            _cleanup_cut("parent-directory-removed")
            if self._before_phase("parent-removed"):
                self.state.append("parent-removed", parent_quarantine=parent_quarantine)
            self.state.retire()
            os.close(self.outer_fd)
            self.outer_fd = -1
            self.closed = True
        except CleanupUncertain:
            self.uncertain = True
            if self.state is not None and self.state.descriptor >= 0 and self.state.value["phase"] != "uncertain":
                self.state.append("uncertain")
            raise
        except (OSError, WorkloadError) as error:
            self.uncertain = True
            if self.state is not None and self.state.descriptor >= 0 and self.state.value["phase"] != "uncertain":
                self.state.append("uncertain")
            raise CleanupUncertain("owned cleanup could not prove identity") from error
        finally:
            if not self.closed:
                for descriptor_name in ("fd", "parent_fd", "outer_fd"):
                    descriptor = getattr(self, descriptor_name, -1)
                    if descriptor >= 0:
                        os.close(descriptor)
                        setattr(self, descriptor_name, -1)
                if self.state is not None and self.state.descriptor >= 0:
                    os.close(self.state.descriptor)
                    self.state.descriptor = -1

    @classmethod
    def open_recovery(cls, path, deadline, kind):
        if platform.system() != "Linux" or os.geteuid() != SUPERVISOR_UID:
            raise CleanupUncertain("recovery requires Linux root")
        instance = cls.__new__(cls)
        instance.path = Path(path)
        instance.kind = kind
        instance.deadline = deadline
        instance.closed = False
        instance.uncertain = False
        instance.outer_fd = _open_absolute_directory(instance.path.parent)
        instance.state = ExternalState.load(instance.outer_fd, instance.path.name, kind)
        _require(instance.state.value["phase"] != "uncertain")
        instance.generation = instance.state.value["generation"].encode("ascii")
        instance.parent_fd = -1
        instance.fd = -1
        parent_quarantine = instance.state.value.get("parent_quarantine")
        candidates = [instance.path.name, instance.state.value["staging_name"], parent_quarantine]
        present = [name for name in candidates if name and _entry_exists(instance.outer_fd, name)]
        if not present:
            if instance._before_phase("parent-removed"):
                instance.state.append("parent-removed")
            instance.state.retire()
            os.close(instance.outer_fd)
            instance.outer_fd = -1
            instance.closed = True
            return instance
        _require(len(present) == 1)
        parent_name = present[0]
        parent_status = os.stat(parent_name, dir_fd=instance.outer_fd, follow_symlinks=False)
        instance.parent_fd = _open_checked(instance.outer_fd, parent_name, os.O_RDONLY | os.O_DIRECTORY, parent_status)
        parent_status = os.fstat(instance.parent_fd)
        _require(parent_status.st_uid == SUPERVISOR_UID and stat.S_IMODE(parent_status.st_mode) == 0o700)
        if not _entry_exists(instance.parent_fd, ".parent-generation") and instance.state.value["phase"] == "intent" and parent_name == instance.state.value["staging_name"]:
            _require(not os.listdir(instance.parent_fd))
            marker = os.open(".parent-generation", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=instance.parent_fd)
            try:
                _write_all(marker, instance.generation)
                os.fsync(marker)
            finally:
                os.close(marker)
            os.fsync(instance.parent_fd)
            os.fsync(instance.outer_fd)
        if _entry_exists(instance.parent_fd, ".parent-generation"):
            marker = _open_checked(instance.parent_fd, ".parent-generation", os.O_RDONLY)
            try:
                _require(_read_fd(marker, 32) == instance.generation and os.fstat(marker).st_uid == SUPERVISOR_UID)
            finally:
                os.close(marker)
        else:
            _require(not instance._before_phase("root-removed"))
        if parent_name == instance.state.value["staging_name"]:
            _require(not _entry_exists(instance.outer_fd, instance.path.name))
            os.close(instance.parent_fd)
            instance.parent_fd = -1
            _rename_noreplace(instance.outer_fd, parent_name, instance.outer_fd, instance.path.name)
            os.fsync(instance.outer_fd)
            parent_name = instance.path.name
            instance.parent_fd = _open_checked(instance.outer_fd, parent_name, os.O_RDONLY | os.O_DIRECTORY)
            parent_status = os.fstat(instance.parent_fd)
        if instance.state.value["parent_dev"] is None:
            instance.state.append("parent-created", parent_dev=parent_status.st_dev, parent_ino=parent_status.st_ino)
        else:
            _require((parent_status.st_dev, parent_status.st_ino) == (instance.state.value["parent_dev"], instance.state.value["parent_ino"]))

        root_quarantine = instance.state.value.get("root_quarantine")
        root_candidates = [cls.ROOT_NAME, root_quarantine]
        roots = [name for name in root_candidates if name and _entry_exists(instance.parent_fd, name)]
        _require(len(roots) <= 1)
        if roots:
            root_name = roots[0]
            root_status = os.stat(root_name, dir_fd=instance.parent_fd, follow_symlinks=False)
            instance.fd = _open_checked(instance.parent_fd, root_name, os.O_RDONLY | os.O_DIRECTORY, root_status)
            if instance.state.value["root_dev"] is None:
                _require(root_name == cls.ROOT_NAME and root_status.st_uid in {SUPERVISOR_UID, WORKLOAD_UID})
                entries = os.listdir(instance.fd)
                _require(not entries or entries == [".owner-generation"])
                if root_status.st_uid == SUPERVISOR_UID:
                    os.chown(root_name, WORKLOAD_UID, WORKLOAD_GID, dir_fd=instance.parent_fd, follow_symlinks=False)
                if ".owner-generation" not in entries:
                    marker = os.open(".owner-generation", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=instance.fd)
                    try:
                        _write_all(marker, instance.generation)
                        os.fsync(marker)
                    finally:
                        os.close(marker)
                os.fsync(instance.fd)
                os.fsync(instance.parent_fd)
            instance.identity = os.fstat(instance.fd)
            _require((instance.identity.st_uid, instance.identity.st_gid, stat.S_IMODE(instance.identity.st_mode)) == (WORKLOAD_UID, WORKLOAD_GID, 0o700))
            marker_raw, instance.marker_identity = instance.read_file(".owner-generation", 32, require_owner=False)
            _require(instance.marker_identity.st_uid == SUPERVISOR_UID and marker_raw == instance.generation)
            if instance.state.value["root_dev"] is None:
                instance.state.append(
                    "running",
                    root_dev=instance.identity.st_dev,
                    root_ino=instance.identity.st_ino,
                    root_uid=instance.identity.st_uid,
                    root_gid=instance.identity.st_gid,
                    root_mode=stat.S_IMODE(instance.identity.st_mode),
                )
            else:
                _require((instance.identity.st_dev, instance.identity.st_ino) == (instance.state.value["root_dev"], instance.state.value["root_ino"]))
        return instance


def _retire_partial_tombstone(path):
    outer_fd = _open_absolute_directory(Path(path).parent)
    try:
        fixed = f".{Path(path).name}.recovery-v2"
        if _entry_exists(outer_fd, fixed):
            return False
        prefix = f".{Path(path).name}.recovery-build-"
        names = [name for name in os.listdir(outer_fd) if name.startswith(prefix)]
        if not names:
            return False
        _require(len(names) == 1 and not _entry_exists(outer_fd, Path(path).name))
        generation = names[0].removeprefix(prefix)
        _require(len(generation) == 32 and set(generation) <= _HEX)
        descriptor = _open_checked(outer_fd, names[0], os.O_RDONLY)
        try:
            status = os.fstat(descriptor)
            _require(stat.S_ISREG(status.st_mode) and status.st_uid == SUPERVISOR_UID and status.st_nlink == 1)
            current = os.stat(names[0], dir_fd=outer_fd, follow_symlinks=False)
            _require(_same_object(status, current))
            os.unlink(names[0], dir_fd=outer_fd)
            os.fsync(outer_fd)
        finally:
            os.close(descriptor)
        return True
    finally:
        os.close(outer_fd)


def recover_workload_root(path, kind):
    """Fixed one-pass cleanup-only recovery; no workload function is reachable."""
    deadline = Deadline.start(30.0, 25.0)
    _enable_subreaper()
    if _retire_partial_tombstone(path):
        return
    root = OwnedRoot.open_recovery(path, deadline, kind)
    if root.closed:
        return
    try:
        _drain_tagged(root.generation, deadline)
        _drain_descendants(deadline)
        root.cleanup(process_check=False)
    except BaseException:
        if not root.closed:
            for descriptor_name in ("fd", "parent_fd", "outer_fd"):
                descriptor = getattr(root, descriptor_name, -1)
                if descriptor >= 0:
                    os.close(descriptor)
                    setattr(root, descriptor_name, -1)
            if root.state.descriptor >= 0:
                os.close(root.state.descriptor)
                root.state.descriptor = -1
        raise


def _run(argv, root, deadline, expected=None, environment=None, pass_fds=()):
    """Run once, then prove repeated empty descendant observations before output cleanup."""
    _require(type(argv) is tuple and argv and all(type(item) is str and item for item in argv))
    output_fd = -1
    process = None
    raw = b""
    failure = None
    try:
        output_fd = os.open("command.out", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=root.fd)
        os.fchown(output_fd, WORKLOAD_UID, WORKLOAD_GID)
        output_status = os.fstat(output_fd)
        _require(stat.S_ISREG(output_status.st_mode) and output_status.st_nlink == 1 and output_status.st_uid == WORKLOAD_UID and output_status.st_gid == WORKLOAD_GID)
        _require(stat.S_IMODE(output_status.st_mode) == 0o600)
        base_environment = {} if environment is None else dict(environment)
        process = subprocess.Popen(
            argv,
            cwd=root.proc_path(),
            env=root.child_environment(base_environment),
            stdin=subprocess.DEVNULL,
            stdout=output_fd,
            stderr=subprocess.STDOUT,
            close_fds=True,
            pass_fds=tuple({root.fd, *pass_fds}),
            start_new_session=True,
            preexec_fn=_limit_output,
        )
        return_code = _wait_process(process, deadline.effect_seconds())
        if return_code is None:
            raise WorkloadDeadline("fixed child exceeded parent deadline")
        _drain_descendants(deadline, fail_if_found=True)
        os.fsync(output_fd)
        raw = _read_fd(output_fd, MAX_COMMAND_OUTPUT)
        after = os.fstat(output_fd)
        current = os.stat("command.out", dir_fd=root.fd, follow_symlinks=False)
        _require(after.st_nlink == 1 and _status_identity(after) == _status_identity(current))
        _require(return_code == 0 and b"warning" not in raw.lower() and b"error" not in raw.lower())
        if expected is not None:
            _require(raw == expected)
    except BaseException as error:
        failure = error
        if process is not None and process.poll() is None:
            try:
                _terminate_leader(process, deadline)
            except BaseException as cleanup_error:
                failure = cleanup_error
        try:
            _drain_descendants(deadline)
        except BaseException as cleanup_error:
            failure = cleanup_error
    finally:
        if output_fd >= 0:
            try:
                root.remove_output(output_fd)
            except BaseException as cleanup_error:
                failure = cleanup_error
            os.close(output_fd)
    if failure is not None:
        if isinstance(failure, WorkloadError):
            raise failure
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise WorkloadInterrupted("transaction interrupted") from None
        raise WorkloadError("fixed command failed") from None
    return raw
