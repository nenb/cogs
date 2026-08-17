#!/usr/bin/env python3
"""Descriptor-owned, non-authoritative host workloads for ADR 0099."""

from dataclasses import dataclass
import ctypes
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import secrets
import signal
import stat
import subprocess
import time

from completion_fixtures import SOURCE_EPOCH, fixed_fixtures
from completion_runtime_contract import PackageIdentity, WorkloadContractError, _open_absolute_directory, _open_regular, _read_open_regular, _status_identity

GIT = "/usr/bin/git"
DPKG_DEB = "/usr/bin/dpkg-deb"
DPKG = "/usr/bin/dpkg"
LIFECYCLE_SECONDS = 1200.0
CLEANUP_RESERVE_SECONDS = 30.0
COMMAND_SECONDS = 300.0
TERM_SECONDS = 1.0
KILL_SECONDS = 1.0
MAX_COMMAND_OUTPUT = 65_536
_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SOURCE_DATE_EPOCH": str(SOURCE_EPOCH),
    "TZ": "UTC",
    "TMPDIR": "/nonexistent",
}


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
    """Install categorical TERM/INT handling before any owned effect."""

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


class OwnedRoot:
    """An fd-retained generation whose pathname is never trusted after creation."""

    def __init__(self, path, deadline):
        self.path = Path(path)
        _require(self.path.is_absolute() and self.path.name not in {"", ".", ".."})
        self.deadline = deadline
        self.parent_fd = _open_absolute_directory(self.path.parent)
        self.fd = -1
        self.closed = False
        created = False
        self.generation = secrets.token_hex(16).encode("ascii")
        try:
            try:
                os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise WorkloadError("owned root already exists")
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent_fd)
            created = True
            self.fd = os.open(
                self.path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self.parent_fd,
            )
            self.identity = _status_identity(os.fstat(self.fd))
            status = os.fstat(self.fd)
            _require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid() and status.st_nlink == 2)
            _require(stat.S_IMODE(status.st_mode) == 0o700)
            marker = os.open(".owner-generation", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            try:
                _write_all(marker, self.generation)
                os.fsync(marker)
                marker_status = os.fstat(marker)
                _require(stat.S_ISREG(marker_status.st_mode) and marker_status.st_nlink == 1)
                _require(marker_status.st_uid == os.geteuid() and stat.S_IMODE(marker_status.st_mode) == 0o600)
                self.marker_identity = _status_identity(marker_status)
            finally:
                os.close(marker)
        except BaseException as error:
            cleanup_failed = False
            if self.fd >= 0:
                try:
                    _remove_directory_contents(self.fd, self.deadline)
                except BaseException:
                    cleanup_failed = True
                os.close(self.fd)
            if created and not cleanup_failed:
                try:
                    os.rmdir(self.path.name, dir_fd=self.parent_fd)
                except OSError:
                    cleanup_failed = True
            os.close(self.parent_fd)
            if cleanup_failed:
                raise CleanupUncertain("owned root creation cleanup is uncertain") from None
            raise error

    def _open_dir(self, relative="."):
        descriptor = os.dup(self.fd)
        try:
            if relative not in {"", "."}:
                for component in _safe_relative(relative):
                    next_descriptor = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
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
                _require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid() and status.st_nlink >= 2)
                os.close(descriptor)
                descriptor = next_descriptor
            if parts:
                os.fchmod(descriptor, mode)
        except OSError as error:
            raise WorkloadError("directory creation failed") from error
        finally:
            os.close(descriptor)

    def write_file(self, relative, raw, mode=0o600, mtime=None, append=False):
        self.deadline.effect_check()
        parts = _safe_relative(relative)
        parent = self._open_dir("/".join(parts[:-1]) or ".")
        flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        flags |= os.O_APPEND if append else os.O_CREAT | os.O_EXCL
        descriptor = -1
        try:
            descriptor = os.open(parts[-1], flags, mode, dir_fd=parent)
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid())
            _write_all(descriptor, raw)
            os.fchmod(descriptor, mode)
            if mtime is not None:
                os.utime(descriptor, (mtime, mtime))
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            _require(after.st_dev == before.st_dev and after.st_ino == before.st_ino and after.st_nlink == 1)
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
        try:
            before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            _require(not stat.S_ISDIR(before.st_mode) and before.st_nlink == 1)
            os.unlink(parts[-1], dir_fd=parent)
        except OSError as error:
            raise WorkloadError("file unlink failed") from error
        finally:
            os.close(parent)

    def proc_path(self, relative=""):
        if relative:
            _safe_relative(relative)
            return f"/proc/self/fd/{self.fd}/{relative}"
        return f"/proc/self/fd/{self.fd}"

    def verify_generation(self):
        status = os.fstat(self.fd)
        _require(status.st_dev == self.identity[0] and status.st_ino == self.identity[1])
        _require(status.st_uid == os.geteuid() and stat.S_IMODE(status.st_mode) == 0o700 and status.st_nlink >= 2)
        raw, marker = self.read_file(".owner-generation", 32)
        _require(raw == self.generation and _status_identity(marker) == self.marker_identity)

    def cleanup(self):
        """Delete only the retained root generation; preserve every replacement."""
        if self.closed:
            return
        quarantine = f".{self.path.name}.cleanup-{os.getpid()}-{self.generation.decode()}"
        moved = False
        try:
            self.deadline.cleanup_check()
            self.verify_generation()
            current = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            retained = os.fstat(self.fd)
            if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
                raise CleanupUncertain("owned root pathname was replaced")
            try:
                os.stat(quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CleanupUncertain("cleanup generation already exists")
            os.rename(self.path.name, quarantine, src_dir_fd=self.parent_fd, dst_dir_fd=self.parent_fd)
            moved = True
            observed = os.stat(quarantine, dir_fd=self.parent_fd, follow_symlinks=False)
            if (observed.st_dev, observed.st_ino) != (retained.st_dev, retained.st_ino):
                try:
                    os.rename(quarantine, self.path.name, src_dir_fd=self.parent_fd, dst_dir_fd=self.parent_fd)
                except OSError:
                    pass
                raise CleanupUncertain("cleanup rename selected a replacement")
            _remove_directory_contents(self.fd, self.deadline)
            emptied = os.fstat(self.fd)
            if emptied.st_nlink != 2 or emptied.st_uid != os.geteuid() or stat.S_IMODE(emptied.st_mode) != 0o700:
                raise CleanupUncertain("emptied root identity changed")
            os.close(self.fd)
            self.fd = -1
            os.rmdir(quarantine, dir_fd=self.parent_fd)
            moved = False
            try:
                os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CleanupUncertain("replacement appeared after cleanup")
            self.closed = True
            os.close(self.parent_fd)
        except CleanupUncertain:
            raise
        except (OSError, WorkloadError) as error:
            raise CleanupUncertain("owned cleanup could not prove identity") from error
        finally:
            if self.closed:
                return
            # Never guess at a pathname after uncertainty. Open descriptors are closed,
            # while replacement and renamed paths are deliberately preserved.
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            os.close(self.parent_fd)
            if moved:
                pass


def _remove_directory_contents(descriptor, deadline):
    deadline.cleanup_check()
    try:
        names = sorted(os.listdir(descriptor))
    except OSError as error:
        raise CleanupUncertain("owned inventory could not be listed") from error
    for name in names:
        deadline.cleanup_check()
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o022:
            raise CleanupUncertain("owned entry owner or mode changed")
        if stat.S_ISDIR(before.st_mode):
            if before.st_nlink < 2:
                raise CleanupUncertain("owned directory link count changed")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if _status_identity(opened) != _status_identity(before):
                    raise CleanupUncertain("owned directory generation changed")
                _remove_directory_contents(child, deadline)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                    raise CleanupUncertain("owned directory was replaced")
                if current.st_uid != before.st_uid or stat.S_IMODE(current.st_mode) != stat.S_IMODE(before.st_mode) or current.st_nlink != 2:
                    raise CleanupUncertain("owned directory identity changed")
                os.rmdir(name, dir_fd=descriptor)
            finally:
                os.close(child)
        else:
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CleanupUncertain("owned file type or link count changed")
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _status_identity(current) != _status_identity(before):
                raise CleanupUncertain("owned file generation changed")
            os.unlink(name, dir_fd=descriptor)


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


def _limit_output():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_COMMAND_OUTPUT, MAX_COMMAND_OUTPUT))


def _children():
    try:
        descriptor = os.open(f"/proc/self/task/{os.getpid()}/children", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid():
                raise ChildUncertain("child inventory identity invalid")
            raw = _read_fd(descriptor, 65_536)
            after = os.fstat(descriptor)
            if _status_identity(before) != _status_identity(after):
                raise ChildUncertain("child inventory generation changed")
        finally:
            os.close(descriptor)
        return {int(value) for value in raw.split()}
    except (OSError, ValueError):
        raise ChildUncertain("child inventory unavailable")


def _enable_subreaper():
    if platform.system() != "Linux":
        raise WorkloadError("host workload requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise ChildUncertain("child ownership unavailable")
    _require(not _children(), "host process already owns children")


def _signal_process(process, number):
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


def _terminate_process(process, deadline):
    _signal_process(process, signal.SIGTERM)
    result = _wait_process(process, deadline.cleanup_seconds(TERM_SECONDS))
    if result is None:
        _signal_process(process, signal.SIGKILL)
        result = _wait_process(process, deadline.cleanup_seconds(KILL_SECONDS))
    if result is None:
        raise ChildUncertain("child could not be reaped")


def _reap_escaped(deadline):
    escaped = _children()
    for process_id in escaped:
        try:
            os.kill(process_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
    end = time.monotonic() + deadline.cleanup_seconds(TERM_SECONDS)
    while escaped and time.monotonic() < end:
        for process_id in tuple(escaped):
            try:
                waited, _status = os.waitpid(process_id, os.WNOHANG)
            except ChildProcessError:
                waited = process_id
            if waited:
                escaped.discard(process_id)
        if escaped:
            time.sleep(0.01)
    for process_id in escaped:
        try:
            os.kill(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
    end = time.monotonic() + deadline.cleanup_seconds(KILL_SECONDS)
    while escaped and time.monotonic() < end:
        for process_id in tuple(escaped):
            try:
                waited, _status = os.waitpid(process_id, os.WNOHANG)
            except ChildProcessError:
                waited = process_id
            if waited:
                escaped.discard(process_id)
        if escaped:
            time.sleep(0.01)
    if escaped or _children():
        raise ChildUncertain("escaped child cleanup is uncertain")


def _run(argv, root, deadline, expected=None, environment=None, pass_fds=()):
    """Run once under the one lifecycle deadline; TERM, KILL, reap, and output are bounded."""
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
        process = subprocess.Popen(
            argv,
            cwd=root.proc_path(),
            env=dict(_ENV if environment is None else environment),
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
        _reap_escaped(deadline)
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
                _terminate_process(process, deadline)
            except BaseException as cleanup_error:
                failure = cleanup_error
        try:
            _reap_escaped(deadline)
        except BaseException as cleanup_error:
            failure = cleanup_error
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        try:
            status = os.stat("command.out", dir_fd=root.fd, follow_symlinks=False)
        except FileNotFoundError:
            status = None
        except OSError as cleanup_error:
            failure = CleanupUncertain("command output cleanup uncertain")
            status = None
        if status is not None:
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                failure = CleanupUncertain("command output identity changed")
            else:
                try:
                    os.unlink("command.out", dir_fd=root.fd)
                except OSError:
                    failure = CleanupUncertain("command output cleanup uncertain")
    if failure is not None:
        if isinstance(failure, WorkloadError):
            raise failure
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise WorkloadInterrupted("transaction interrupted") from None
        raise WorkloadError("fixed command failed") from None
    return raw


@dataclass
class Tool:
    name: str
    opened: object
    version: str = ""

    @property
    def executable(self):
        return f"/proc/self/fd/{self.opened.descriptor}"

    def observation(self):
        raw = _read_open_regular(self.opened, 32 * 1024 * 1024)
        return {"name": self.name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "version": self.version}

    def close(self):
        self.opened.close()


class ToolSet:
    def __init__(self):
        self.tools = []
        try:
            self.tools.append(Tool("git", _open_regular(Path(GIT), 32 * 1024 * 1024, executable=True)))
            self.tools.append(Tool("dpkg-deb", _open_regular(Path(DPKG_DEB), 32 * 1024 * 1024, executable=True)))
            self.tools.append(Tool("dpkg", _open_regular(Path(DPKG), 32 * 1024 * 1024, executable=True)))
        except BaseException:
            self.close()
            raise
        self.git, self.dpkg_deb, self.dpkg = self.tools

    @property
    def descriptors(self):
        return tuple(tool.opened.descriptor for tool in self.tools)

    def observations(self):
        return [tool.observation() for tool in self.tools]

    def close(self):
        for tool in self.tools:
            tool.close()


def _check_versions(root, tools, deadline):
    git = _run((tools.git.executable, "--version"), root, deadline, pass_fds=tools.descriptors)
    dpkg_deb = _run((tools.dpkg_deb.executable, "--version"), root, deadline, pass_fds=tools.descriptors)
    dpkg = _run((tools.dpkg.executable, "--version"), root, deadline, pass_fds=tools.descriptors)
    _require(git == b"git version 2.47.3\n")
    _require(dpkg_deb.splitlines()[0] == b"Debian 'dpkg-deb' package archive backend version 1.22.22 (amd64).")
    _require(dpkg.splitlines()[0] == b"Debian 'dpkg' package management program version 1.22.22 (amd64).")
    tools.git.version = git.decode("ascii").strip()
    tools.dpkg_deb.version = dpkg_deb.splitlines()[0].decode("ascii")
    tools.dpkg.version = dpkg.splitlines()[0].decode("ascii")


def _materialize(records, root, prefix):
    root.mkdir(prefix, 0o700)
    directories = []
    for record in records:
        root.deadline.effect_check()
        relative = prefix if record.path == "." else f"{prefix}/{record.path}"
        _require(record.kind in {"directory", "file"})
        if record.kind == "directory":
            if record.path != ".":
                root.mkdir(relative, record.mode)
            directories.append((relative, record))
        else:
            _require(type(record.content) is bytes)
            root.write_file(relative, record.content, record.mode, record.mtime)
    for relative, record in reversed(directories):
        descriptor = root._open_dir(relative)
        try:
            os.fchmod(descriptor, record.mode)
            os.utime(descriptor, (record.mtime, record.mtime))
        finally:
            os.close(descriptor)


def _git_environment(root):
    return {
        **_ENV,
        "HOME": root.proc_path("private-home"),
        "TMPDIR": root.proc_path("private-tmp"),
        "GIT_AUTHOR_DATE": f"{SOURCE_EPOCH} +0000",
        "GIT_AUTHOR_EMAIL": "cogs-stage2",
        "GIT_AUTHOR_NAME": "Cogs Stage 2",
        "GIT_COMMITTER_DATE": f"{SOURCE_EPOCH} +0000",
        "GIT_COMMITTER_EMAIL": "cogs-stage2",
        "GIT_COMMITTER_NAME": "Cogs Stage 2",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _prepare_git_fixture(root, tools, deadline):
    fixture = fixed_fixtures().git
    _materialize(fixture.source.records, root, "git-source")
    env = _git_environment(root)
    source = root.proc_path("git-source")
    bare = root.proc_path("git-fixture.git")
    try:
        _run((tools.git.executable, "-c", "init.templateDir=", "init", "--quiet", "--initial-branch=main", source), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", source, "add", "--all"), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", source, "commit", "--quiet", "--message=cogs stage2 fixture v1"), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", source, "rev-parse", "HEAD"), root, deadline, fixture.commit_oid.encode() + b"\n", env, tools.descriptors)
        _run((tools.git.executable, "-c", "init.templateDir=", "clone", "--quiet", "--bare", "--no-hardlinks", source, bare), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, f"--git-dir={bare}", "rev-parse", "refs/heads/main"), root, deadline, fixture.commit_oid.encode() + b"\n", env, tools.descriptors)
    finally:
        _remove_relative(root, "git-source", deadline)
    return "git-fixture.git"


def _remove_relative(root, relative, deadline):
    parts = _safe_relative(relative)
    parent = root._open_dir("/".join(parts[:-1]) or ".")
    try:
        child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        try:
            retained = os.fstat(child)
            _remove_directory_contents(child, deadline)
        finally:
            os.close(child)
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
            raise CleanupUncertain("owned subdirectory was replaced")
        os.rmdir(parts[-1], dir_fd=parent)
    finally:
        os.close(parent)


def _run_git_sample(root, bare_relative, sample, tools, deadline):
    _require(type(sample) is int and 1 <= sample <= 7)
    fixture = fixed_fixtures().git
    relative = f"git-{sample:02d}"
    env = _git_environment(root)
    start = time.monotonic_ns()
    try:
        _run((tools.git.executable, "-c", "init.templateDir=", "clone", "--quiet", "--no-hardlinks", "--no-tags", root.proc_path(bare_relative), root.proc_path(relative)), root, deadline, b"", env, tools.descriptors)
        _run((tools.git.executable, "-C", root.proc_path(relative), "checkout", "--quiet", "--detach", fixture.commit_oid), root, deadline, b"", env, tools.descriptors)
        for mutation in fixture.mutations:
            destination = f"{relative}/{mutation.path}"
            if mutation.operation == "append":
                root.write_file(destination, mutation.payload, 0o644, append=True)
            else:
                _require(mutation.operation == "create")
                parent = str(PurePosixPath(destination).parent)
                root.mkdir(parent, 0o755, parents=True, exist_ok=True)
                root.write_file(destination, mutation.payload, 0o644)
        _run((tools.git.executable, "-C", root.proc_path(relative), "status", "--porcelain=v1", "--untracked-files=all"), root, deadline, fixture.porcelain, env, tools.descriptors)
        duration = (time.monotonic_ns() - start) // 1_000_000
    finally:
        _remove_relative(root, relative, deadline)
    _require(0 <= duration <= LIFECYCLE_SECONDS * 1000)
    return duration


def _inventory_tree(root, relative):
    observed = {}

    def visit(descriptor, prefix):
        status = os.fstat(descriptor)
        observed[prefix] = (status, None)
        for name in sorted(os.listdir(descriptor)):
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            path = name if prefix == "." else f"{prefix}/{name}"
            if stat.S_ISDIR(current.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    _require((opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino))
                    visit(child, path)
                finally:
                    os.close(child)
            else:
                _require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1)
                descriptor_file = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    opened = os.fstat(descriptor_file)
                    raw = _read_fd(descriptor_file, 4_194_304)
                    after = os.fstat(descriptor_file)
                    again = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    _require(_status_identity(opened) == _status_identity(after) == _status_identity(again))
                    observed[path] = (opened, raw)
                finally:
                    os.close(descriptor_file)

    descriptor = root._open_dir(relative)
    try:
        visit(descriptor, ".")
    finally:
        os.close(descriptor)
    return observed


def _verify_installed(root, relative):
    expected = fixed_fixtures().package.installed
    observed = _inventory_tree(root, relative)
    expected_map = {record.path: record for record in expected.records}
    _require(tuple(sorted(observed)) == tuple(sorted(expected_map)))
    for path, record in expected_map.items():
        status, raw = observed[path]
        _require(status.st_uid == status.st_gid == 0)
        _require(stat.S_IMODE(status.st_mode) == record.mode)
        _require(status.st_mtime_ns == record.mtime * 1_000_000_000)
        _require(stat.S_ISDIR(status.st_mode) == (record.kind == "directory"))
        if record.kind == "file":
            _require(raw is not None and len(raw) == record.size and hashlib.sha256(raw).hexdigest() == record.content_sha256)
    return expected


def _status_fields(root, relative):
    raw, _status = root.read_file(relative, 4096)
    _require(0 < len(raw) <= 4096 and b"\x00" not in raw)
    fields = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise WorkloadError("status encoding invalid") from error
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            _require(key not in fields)
            fields[key] = value
    return fields


def _run_package_sample(root, label, tools, deadline):
    _require(label in {"candidate-a", "candidate-b"})
    fixture = fixed_fixtures().package
    prefix = f"package-{label}"
    source = f"{prefix}/source"
    deb = f"{prefix}/cogs-stage2-fixture_1.0_all.deb"
    admin = f"{prefix}/dpkg-admin"
    installed = f"{prefix}/installed"
    root.mkdir(prefix, 0o700)
    try:
        _materialize(fixture.source.records, root, source)
        build_start = time.monotonic_ns()
        _run(
            (
                tools.dpkg_deb.executable,
                "--build",
                "--root-owner-group",
                "--compression=xz",
                "--compression-level=6",
                "--threads-max=1",
                root.proc_path(source),
                root.proc_path(deb),
            ),
            root,
            deadline,
            pass_fds=tools.descriptors,
        )
        build_ms = (time.monotonic_ns() - build_start) // 1_000_000
        deb_raw, deb_status = root.read_file(deb, 4_194_304)
        _require(0 < len(deb_raw) == deb_status.st_size)
        root.mkdir(admin, 0o700)
        root.mkdir(f"{admin}/updates", 0o700)
        root.write_file(f"{admin}/status", b"", 0o600)
        root.mkdir(installed, 0o755)
        installed_fd = root._open_dir(installed)
        try:
            os.utime(installed_fd, (SOURCE_EPOCH, SOURCE_EPOCH))
        finally:
            os.close(installed_fd)
        install_start = time.monotonic_ns()
        _run(
            (
                tools.dpkg.executable,
                "--admindir",
                root.proc_path(admin),
                "--instdir",
                f"{root.proc_path(installed)}/",
                "--install",
                root.proc_path(deb),
            ),
            root,
            deadline,
            pass_fds=tools.descriptors,
        )
        install_ms = (time.monotonic_ns() - install_start) // 1_000_000
        observed = _verify_installed(root, installed)
        fields = _status_fields(root, f"{admin}/status")
        _require(
            (fields.get("Package"), fields.get("Version"), fields.get("Architecture"), fields.get("Status"))
            == (observed.package, observed.version, observed.architecture, observed.status)
        )
        identity = PackageIdentity(
            hashlib.sha256(deb_raw).hexdigest(),
            len(deb_raw),
            observed.logical_digest,
            observed.entry_count,
            observed.regular_bytes,
            observed.package,
            observed.version,
            observed.architecture,
        )
    finally:
        _remove_relative(root, prefix, deadline)
    _require(0 <= build_ms <= LIFECYCLE_SECONDS * 1000 and 0 <= install_ms <= LIFECYCLE_SECONDS * 1000)
    return identity, build_ms, install_ms


def require_linux_amd64_root():
    _require(platform.system() == "Linux")
    _require(platform.machine() in {"x86_64", "amd64"})
    _require(os.geteuid() == 0)
    _enable_subreaper()
