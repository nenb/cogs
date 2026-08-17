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
OPERATION_PARENT_UID = 65_534
PROCESS_CONTAINMENT = "linux-subreaper-pidfd-or-start-time-no-cgroup-v2"
PROCESS_LIMITATION = "no-cgroup-proof-after-supervisor-crash-or-hostile-environment-rewrite"
_RACE_HOOK = None
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
    """Keep uid 0 file ownership while making the uid-65534 parent unreachable."""
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_COMMAND_OUTPUT, MAX_COMMAND_OUTPUT))
    libc = ctypes.CDLL(None, use_errno=True)
    securebits = 0x0F  # NOROOT, NOROOT_LOCKED, NO_SETUID_FIXUP, and its lock.
    if libc.prctl(28, securebits, 0, 0, 0) != 0:  # PR_SET_SECUREBITS
        os._exit(126)
    header = _CapabilityHeader(0x20080522, 0)
    data = (_CapabilityData * 2)()
    data[0].effective = 1  # CAP_CHOWN for dpkg's root-owner restoration only.
    data[0].permitted = 1
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        os._exit(126)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        os._exit(126)


class OwnedRoot:
    """A durable retained root inside a fixed mode-0700 operation parent."""

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
        created_parent = False
        try:
            try:
                os.stat(self.path.name, dir_fd=self.outer_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise WorkloadError("operation recovery is required")
            os.mkdir(self.path.name, 0o700, dir_fd=self.outer_fd)
            os.chown(self.path.name, OPERATION_PARENT_UID, -1, dir_fd=self.outer_fd, follow_symlinks=False)
            created_parent = True
            self.parent_fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.outer_fd)
            parent_status = os.fstat(self.parent_fd)
            _require(stat.S_ISDIR(parent_status.st_mode) and parent_status.st_uid == OPERATION_PARENT_UID)
            _require(stat.S_IMODE(parent_status.st_mode) == 0o700 and parent_status.st_nlink == 2)
            os.mkdir(self.ROOT_NAME, 0o700, dir_fd=self.parent_fd)
            self.fd = os.open(self.ROOT_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            status = os.fstat(self.fd)
            _require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid())
            _require(stat.S_IMODE(status.st_mode) == 0o700 and status.st_nlink == 2)
            self.identity = status
            marker = os.open(".owner-generation", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            try:
                _write_all(marker, self.generation)
                os.fsync(marker)
                marker_status = os.fstat(marker)
                _require(stat.S_ISREG(marker_status.st_mode) and marker_status.st_nlink == 1)
                _require(marker_status.st_uid == os.geteuid() and stat.S_IMODE(marker_status.st_mode) == 0o600)
                self.marker_identity = marker_status
            finally:
                os.close(marker)
            self._write_journal()
        except BaseException as error:
            if self.fd >= 0:
                os.close(self.fd)
            if self.parent_fd >= 0:
                os.close(self.parent_fd)
            if created_parent:
                # Construction failures leave the exact parent for cleanup-only recovery.
                try:
                    os.fsync(self.outer_fd)
                except OSError:
                    pass
            os.close(self.outer_fd)
            if created_parent:
                raise CleanupUncertain("operation creation requires recovery") from None
            raise error

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
            _require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1 and status.st_uid == os.geteuid())
            _require(stat.S_IMODE(status.st_mode) == 0o600)
        finally:
            os.close(descriptor)
        os.fsync(self.parent_fd)
        os.fsync(self.outer_fd)

    def _open_dir(self, relative="."):
        descriptor = os.dup(self.fd)
        try:
            if relative not in {"", "."}:
                for component in _safe_relative(relative):
                    next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = next_descriptor
            status = os.fstat(descriptor)
            _require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid() and status.st_nlink >= 2)
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
                try:
                    os.mkdir(component, mode if final else 0o700, dir_fd=descriptor)
                except FileExistsError:
                    if final and not exist_ok:
                        raise
                    if not parents and not final:
                        raise
                next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                status = os.fstat(next_descriptor)
                _require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid())
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
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid())
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
                _require(before.st_uid == os.geteuid())
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
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
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
            if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & 0o022:
                self.uncertain = True
                raise CleanupUncertain("owned entry owner or mode changed")
            if stat.S_ISDIR(status.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
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
                child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    self._quarantine_file(descriptor, name, child, "inner-file")
                finally:
                    os.close(child)

    def remove_tree(self, relative, stage="owned-directory"):
        parts = _safe_relative(relative)
        parent = self._open_dir("/".join(parts[:-1]) or ".")
        child = -1
        try:
            child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
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
        raw, marker = self.read_file(".owner-generation", 32)
        _require(raw == self.generation and _same_object(marker, self.marker_identity))

    def cleanup(self, process_check=True):
        if self.closed:
            return
        if self.uncertain:
            raise CleanupUncertain("operation was previously uncertain")
        if process_check:
            _drain_descendants(self.deadline, fail_if_found=True)
            if _tagged_processes(self.generation):
                raise CleanupUncertain("tagged process remains")
        try:
            self.verify_generation()
            root_quarantine, _expected = self._quarantine(self.parent_fd, self.ROOT_NAME, self.fd, "source-root")
            self._delete_contents(self.fd)
            emptied = os.fstat(self.fd)
            current = os.stat(root_quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
            if emptied.st_nlink != 2 or not _same_object(emptied, current):
                raise CleanupUncertain("retained root changed")
            _cut("source-root-delete", self.parent_fd, root_quarantine, "")
            current = os.stat(root_quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
            if not _same_object(emptied, current):
                raise CleanupUncertain("retained root was replaced")
            os.close(self.fd)
            self.fd = -1
            os.rmdir(root_quarantine, dir_fd=self.parent_fd)

            journal = os.open(self.JOURNAL_NAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            try:
                self._quarantine_file(self.parent_fd, self.JOURNAL_NAME, journal, "recovery-record")
            finally:
                os.close(journal)
            os.fsync(self.parent_fd)

            parent_status = os.fstat(self.parent_fd)
            if parent_status.st_nlink != 2 or os.listdir(self.parent_fd):
                raise CleanupUncertain("operation parent is not empty")
            parent_quarantine, _expected = self._quarantine(self.outer_fd, self.path.name, self.parent_fd, "operation-parent")
            _cut("operation-parent-delete", self.outer_fd, parent_quarantine, "")
            current = os.stat(parent_quarantine, dir_fd=self.outer_fd, follow_symlinks=False)
            if not _same_object(os.fstat(self.parent_fd), current):
                raise CleanupUncertain("operation parent was replaced")
            os.close(self.parent_fd)
            self.parent_fd = -1
            os.rmdir(parent_quarantine, dir_fd=self.outer_fd)
            os.fsync(self.outer_fd)
            os.close(self.outer_fd)
            self.outer_fd = -1
            self.closed = True
        except CleanupUncertain:
            self.uncertain = True
            raise
        except (OSError, WorkloadError) as error:
            self.uncertain = True
            raise CleanupUncertain("owned cleanup could not prove identity") from error
        finally:
            if not self.closed:
                for descriptor_name in ("fd", "parent_fd", "outer_fd"):
                    descriptor = getattr(self, descriptor_name)
                    if descriptor >= 0:
                        os.close(descriptor)
                        setattr(self, descriptor_name, -1)

    @classmethod
    def open_recovery(cls, path, deadline, kind):
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise CleanupUncertain("recovery requires Linux root")
        instance = cls.__new__(cls)
        instance.path = Path(path)
        instance.kind = kind
        instance.deadline = deadline
        instance.closed = False
        instance.uncertain = False
        instance.outer_fd = _open_absolute_directory(instance.path.parent)
        instance.parent_fd = os.open(instance.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=instance.outer_fd)
        parent_status = os.fstat(instance.parent_fd)
        _require(parent_status.st_uid == OPERATION_PARENT_UID and stat.S_IMODE(parent_status.st_mode) == 0o700)
        journal = os.open(cls.JOURNAL_NAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=instance.parent_fd)
        try:
            status = os.fstat(journal)
            _require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1 and status.st_uid == os.geteuid())
            raw = _read_fd(journal, 4096)
            current = os.stat(cls.JOURNAL_NAME, dir_fd=instance.parent_fd, follow_symlinks=False)
            _require(_status_identity(status) == _status_identity(os.fstat(journal)) == _status_identity(current))
        finally:
            os.close(journal)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CleanupUncertain("recovery record is invalid") from error
        expected_keys = {"version", "kind", "generation", "root_name", "root_dev", "root_ino", "root_uid", "root_mode", "marker_sha256", "process_containment", "process_limitation"}
        _require(type(value) is dict and set(value) == expected_keys)
        _require(value["version"] == "cogs.stage2-workload-recovery/v1" and value["kind"] == kind)
        _require(value["process_containment"] == PROCESS_CONTAINMENT and value["process_limitation"] == PROCESS_LIMITATION)
        _require(value["root_name"] == cls.ROOT_NAME and type(value["generation"]) is str and len(value["generation"]) == 32)
        _require(set(value["generation"]) <= _HEX)
        for field in ("root_dev", "root_ino", "root_uid", "root_mode"):
            _require(type(value[field]) is int and not isinstance(value[field], bool) and value[field] >= 0)
        _require(value["root_ino"] > 0 and value["root_mode"] == 0o700)
        _require(type(value["marker_sha256"]) is str and len(value["marker_sha256"]) == 64 and set(value["marker_sha256"]) <= _HEX)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        _require(raw == canonical)
        instance.generation = value["generation"].encode("ascii")
        instance.fd = os.open(cls.ROOT_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=instance.parent_fd)
        instance.identity = os.fstat(instance.fd)
        _require((instance.identity.st_dev, instance.identity.st_ino, instance.identity.st_uid, stat.S_IMODE(instance.identity.st_mode)) == (value["root_dev"], value["root_ino"], value["root_uid"], value["root_mode"]))
        marker_raw, instance.marker_identity = instance.read_file(".owner-generation", 32)
        _require(marker_raw == instance.generation and hashlib.sha256(marker_raw).hexdigest() == value["marker_sha256"])
        return instance


def recover_owned_root(path, kind):
    """Fixed cleanup-only recovery: authenticate, terminate, clean once, never run work."""
    deadline = Deadline.start(30.0, 25.0)
    _enable_subreaper()
    root = OwnedRoot.open_recovery(path, deadline, kind)
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
        output_status = os.fstat(output_fd)
        _require(stat.S_ISREG(output_status.st_mode) and output_status.st_nlink == 1 and output_status.st_uid == os.geteuid())
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
