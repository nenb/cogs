"""Fixed consumer of a settled trusted-runtime closure handoff.

The public API deliberately has no policy or discovery arguments.  Portable tests use
only the private scripted adapter; production uses fixed Linux operations.
"""

from dataclasses import dataclass
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from completion_trusted_runtime_closure import RuntimeClosureHandoff

_VERSION = "cogs.trusted-runtime-closure/v1"
_MARKER = "cogs-runtime-qualification-v1"
_PAYLOAD = b"cogs-runtime-qualification-v1\n"
_GZIP_INPUT = bytes.fromhex(
    "1f8b08000000000002ff4bce4f2fd62d2acd2bc9cc4dd52d2c4dccc94ccb4c4e"
    "2cc9cccfd32d33e40200a9c9b5521e000000"
)
_ZSTD_INPUT = bytes.fromhex(
    "28b52ffd201ef10000636f67732d72756e74696d652d7175616c696669636174696f6e2d76310a"
)
_FIXED_FD_MAP = (("gzip", 198), ("zstd", 199), ("report", 200))
_MAX_REPORT = 131_072
_MAX_OUTPUT = 1_048_576
_DEADLINE_SECONDS = 10.0
_SOURCE_LIMIT = 2_000_000
_GIT = "/usr/bin/git"
_MODULE_NAME = "completion_trusted_runtime_closure"
_MODULE_RELATIVE = "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py"
_ROOT = Path(__file__).resolve().parents[3]
_MODULE_PATH = _ROOT / _MODULE_RELATIVE

_F_SEAL_SEAL = 0x0001
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008
_F_SEAL_FUTURE_WRITE = 0x0010
_F_SEAL_EXEC = 0x0020
_REPORT_SEALS = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE | _F_SEAL_FUTURE_WRITE
_EXECUTABLE_SEALS = _REPORT_SEALS | _F_SEAL_EXEC
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_UINT_MAX = (1 << 32) - 1


class RuntimeLauncherError(RuntimeError):
    """A fixed launch or its exact cleanup could not be proved."""


@dataclass(frozen=True)
class RuntimeQualificationResult:
    version: str
    marker: str
    closure_sha256: str
    source_revision: str
    gzip_output_sha256: str
    zstd_output_sha256: str
    report_read_only: bool
    descriptors_restored: bool
    children_reaped: bool


@dataclass(frozen=True)
class SandboxQualificationResult:
    version: str
    marker: str
    pid_one: bool
    capabilities_zero: bool
    no_new_privs: bool
    seccomp_denied: bool
    descriptors_restored: bool
    children_reaped: bool
    paths_restored: bool


@dataclass(frozen=True)
class _ToolOutcome:
    output: bytes
    reaped: bool


class _ScriptedLauncherAdapter:
    """Ordered, data-only fault seam; never reachable from a public argument."""

    def __init__(self, script: tuple[tuple[str, Any], ...]):
        self._script = list(script)
        self.events: list[str] = []

    def _take(self, name: str) -> Any:
        self.events.append(name)
        if not self._script or self._script[0][0] != name:
            raise RuntimeLauncherError("scripted launcher step mismatch")
        _name, value = self._script.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def authenticate_tracked_source(self, handoff: object) -> str:
        return self._take("authenticate_tracked_source")

    def baseline(self, owned: tuple[int, int, int]) -> object:
        return self._take("baseline")

    def inspect_descriptor(self, role: str, descriptor: int) -> None:
        self._take(f"inspect_descriptor:{role}")

    def read_report(self, descriptor: int) -> bytes:
        return self._take("read_report")

    def run_tool(self, role: str, descriptors: tuple[int, int, int], payload: bytes) -> _ToolOutcome:
        return self._take(f"run_tool:{role}")

    def close_descriptor(self, descriptor: int) -> None:
        self._take("close_descriptor")

    def prove_restored(self, baseline: object) -> None:
        self._take("prove_restored")

    def run_sandbox(self) -> SandboxQualificationResult:
        return self._take("run_sandbox")

    def finish(self) -> None:
        if self._script:
            raise RuntimeLauncherError("unused scripted launcher steps")


class _SystemLauncherAdapter:
    def authenticate_tracked_source(self, handoff: object) -> str:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            raise RuntimeLauncherError("trusted closure requires isolated no-bytecode Python")
        module = sys.modules.get(_MODULE_NAME)
        module_path = getattr(getattr(module, "__spec__", None), "origin", None)
        if type(handoff).__module__ != _MODULE_NAME or type(handoff).__name__ != "RuntimeClosureHandoff":
            raise RuntimeLauncherError("handoff type is not the tracked closure type")
        if module_path is None or Path(module_path).resolve() != _MODULE_PATH:
            raise RuntimeLauncherError("closure module import root mismatch")
        environment = {
            "LC_ALL": "C", "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0",
        }
        common = [_GIT, "-C", str(_ROOT)]
        revision = _run_fixed((*common, "rev-parse", "--verify", "HEAD^{commit}"), environment, 128).decode().strip()
        if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
            raise RuntimeLauncherError("invalid tracked source revision")
        row = _run_fixed((*common, "ls-tree", "-z", revision, "--", _MODULE_RELATIVE), environment, 256)
        if not row.endswith(b"\0") or row.count(b"\0") != 1:
            raise RuntimeLauncherError("closure module is not singular in the tracked revision")
        header, path = row[:-1].split(b"\t", 1)
        fields = header.split(b" ")
        if path.decode("utf-8", "strict") != _MODULE_RELATIVE or len(fields) != 3 or fields[:2] != [b"100644", b"blob"]:
            raise RuntimeLauncherError("closure module tracked identity mismatch")
        source = _read_fixed_source()
        blob = b"blob " + str(len(source)).encode("ascii") + b"\0" + source
        if hashlib.sha1(blob).hexdigest().encode("ascii") != fields[2]:
            raise RuntimeLauncherError("loaded closure module differs from tracked revision")
        return revision

    def baseline(self, owned: tuple[int, int, int]) -> tuple[int, ...]:
        return tuple(descriptor for descriptor in _descriptor_snapshot() if descriptor not in owned)

    def inspect_descriptor(self, role: str, descriptor: int) -> None:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            raise RuntimeLauncherError("handoff descriptor is not a bounded regular object")
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        seals = fcntl.fcntl(descriptor, _F_GET_SEALS)
        expected = _REPORT_SEALS if role == "report" else _EXECUTABLE_SEALS
        if seals != expected:
            raise RuntimeLauncherError("handoff descriptor seal profile mismatch")
        if os.get_inheritable(descriptor):
            raise RuntimeLauncherError("handoff descriptor is not CLOEXEC")
        if role == "report" and flags & os.O_ACCMODE != os.O_RDONLY:
            raise RuntimeLauncherError("report descriptor is not read-only")

    def read_report(self, descriptor: int) -> bytes:
        size = os.fstat(descriptor).st_size
        if not 0 < size <= _MAX_REPORT:
            raise RuntimeLauncherError("closure report size is outside the fixed bound")
        raw = os.pread(descriptor, size + 1, 0)
        if len(raw) != size:
            raise RuntimeLauncherError("closure report read was incomplete")
        return raw

    def run_tool(self, role: str, descriptors: tuple[int, int, int], payload: bytes) -> _ToolOutcome:
        return _run_fixed_tool(role, descriptors, payload)

    def close_descriptor(self, descriptor: int) -> None:
        os.close(descriptor)

    def prove_restored(self, baseline: tuple[int, ...]) -> None:
        if _descriptor_snapshot() != baseline:
            raise RuntimeLauncherError("launcher descriptor baseline was not restored")

    def run_sandbox(self) -> SandboxQualificationResult:
        return _run_fixed_sandbox()

    def finish(self) -> None:
        return None


def _run_fixed(arguments: tuple[str, ...], environment: dict[str, str], bound: int) -> bytes:
    try:
        completed = subprocess.run(arguments, env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeLauncherError("fixed tracked-source authentication failed") from error
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > bound:
        raise RuntimeLauncherError("fixed tracked-source authentication rejected")
    return completed.stdout


def _read_fixed_source() -> bytes:
    descriptor = os.open(_MODULE_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info_before = os.fstat(descriptor)
        if not stat.S_ISREG(info_before.st_mode) or not 0 < info_before.st_size <= _SOURCE_LIMIT:
            raise RuntimeLauncherError("closure source is not a bounded regular file")
        raw = os.pread(descriptor, info_before.st_size + 1, 0)
        info_after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(raw) != info_before.st_size or identity(info_before) != identity(info_after):
            raise RuntimeLauncherError("closure source generation changed")
        return raw
    finally:
        os.close(descriptor)


def _descriptor_snapshot() -> tuple[int, ...]:
    # Enumeration is trusted setup/cleanup evidence only, never child closure authority.
    directory = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return tuple(sorted(int(name) for name in os.listdir(directory) if name.isdecimal() and int(name) != directory))
    finally:
        os.close(directory)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_report(raw: bytes) -> dict[str, object]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or len(raw) > _MAX_REPORT:
        raise RuntimeLauncherError("closure report framing is not canonical")
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if key in result:
                raise RuntimeLauncherError("closure report has a duplicate key")
            result[key] = value
        return result
    try:
        value = json.loads(raw[:-1].decode("utf-8", "strict"), object_pairs_hook=pairs, parse_float=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeLauncherError("closure report is not strict JSON") from error
    if type(value) is not dict or _canonical(value) + b"\n" != raw:
        raise RuntimeLauncherError("closure report bytes are not canonical")
    _validate_report(value)
    if _canonical(value) + b"\n" != raw:
        raise RuntimeLauncherError("closure report independent encoding changed")
    return value


def _exact_keys(value: object, expected: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise RuntimeLauncherError("closure report object shape mismatch")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _validate_report(report: dict[str, object]) -> None:
    _exact_keys(report, {"closure_sha256", "tools", "version"})
    if report["version"] != _VERSION or not _sha(report["closure_sha256"]):
        raise RuntimeLauncherError("closure report header mismatch")
    tools = report["tools"]
    if type(tools) is not list or len(tools) != 3:
        raise RuntimeLauncherError("closure report tool cardinality mismatch")
    expected_tools = ("python3-parser", "zstd", "gzip")
    for index, (raw_tool, expected_tool) in enumerate(zip(tools, expected_tools, strict=True)):
        tool = _exact_keys(raw_tool, {"closure_sha256", "mapping_sha256", "objects", "seal_profile", "sealed_executable", "tool"})
        sealed = expected_tool != "python3-parser"
        if tool["tool"] != expected_tool or type(tool["sealed_executable"]) is not bool or tool["sealed_executable"] is not sealed:
            raise RuntimeLauncherError("closure report tool or sealed state mismatch")
        if tool["seal_profile"] != ("linux-memfd-exec-seals-v1" if sealed else None):
            raise RuntimeLauncherError("closure report seal profile mismatch")
        objects = tool["objects"]
        if type(objects) is not list or not 2 <= len(objects) <= 128:
            raise RuntimeLauncherError("closure report object cardinality mismatch")
        providers: dict[str, int] = {}
        identities: set[tuple[str, str]] = set()
        for object_index, raw_object in enumerate(objects):
            item = _exact_keys(raw_object, {"needed", "role", "sha256", "size", "soname"})
            role = "executable" if object_index == 0 else "loader" if object_index == 1 else "library"
            needed, soname = item["needed"], item["soname"]
            if item["role"] != role or not _sha(item["sha256"]):
                raise RuntimeLauncherError("closure report object role or digest mismatch")
            if type(item["size"]) is not int or not 1 <= item["size"] <= 134_217_728:
                raise RuntimeLauncherError("closure report object size mismatch")
            if type(needed) is not list or len(needed) > 128 or len(set(needed)) != len(needed):
                raise RuntimeLauncherError("closure report needed list mismatch")
            if any(type(name) is not str or not 1 <= len(name) <= 255 or not _safe_soname(name) for name in needed):
                raise RuntimeLauncherError("closure report needed name mismatch")
            if soname is not None and (type(soname) is not str or not _safe_soname(soname)):
                raise RuntimeLauncherError("closure report SONAME mismatch")
            if role == "library" and soname is None:
                raise RuntimeLauncherError("closure report library has no SONAME")
            identity = (role, item["sha256"])
            if identity in identities:
                raise RuntimeLauncherError("closure report duplicate object identity")
            identities.add(identity)
            if soname is not None:
                providers[soname] = providers.get(soname, 0) + 1
        libraries = objects[2:]
        if libraries != sorted(libraries, key=lambda item: (item["soname"].encode("utf-8"), item["sha256"])):
            raise RuntimeLauncherError("closure report library order mismatch")
        if any(providers.get(name) != 1 for item in objects for name in item["needed"]):
            raise RuntimeLauncherError("closure report dependency provider mismatch")
        mapped = [[item["role"], item["sha256"]] for item in objects]
        if tool["closure_sha256"] != _digest(objects) or tool["mapping_sha256"] != _digest(mapped):
            raise RuntimeLauncherError("closure report tool digest mismatch")
        if not _sha(tool["closure_sha256"]) or not _sha(tool["mapping_sha256"]):
            raise RuntimeLauncherError("closure report digest format mismatch")
    top = [{key: value for key, value in tool.items() if key != "mapping_sha256"} for tool in tools]
    if report["closure_sha256"] != _digest(top):
        raise RuntimeLauncherError("closure report aggregate digest mismatch")


def _safe_soname(value: str) -> bool:
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-"
    return 1 <= len(value.encode("utf-8")) <= 255 and all(character in allowed for character in value)


def _extract_handoff(handoff: object) -> tuple[int, int, int]:
    try:
        values = (handoff.gzip_executable_fd, handoff.zstd_executable_fd, handoff.report_fd)
    except AttributeError as error:
        raise RuntimeLauncherError("invalid settled handoff") from error
    if any(type(value) is not int or value < 3 for value in values) or len(set(values)) != 3:
        raise RuntimeLauncherError("invalid settled handoff descriptors")
    return values


def _close_range(first: int, last: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(436, ctypes.c_uint(first), ctypes.c_uint(last), ctypes.c_uint(0)) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))


def _close_except(allowed: set[int]) -> None:
    cursor = 0
    for descriptor in sorted(allowed):
        if cursor < descriptor:
            _close_range(cursor, descriptor - 1)
        cursor = descriptor + 1
    _close_range(cursor, _UINT_MAX)


def _execveat(descriptor: int, role: str) -> None:
    arguments = (ctypes.c_char_p * 4)(role.encode(), b"-q" if role == "zstd" else b"-d", b"-d" if role == "zstd" else b"-c", None)
    if role == "zstd":
        arguments = (ctypes.c_char_p * 5)(b"zstd", b"-q", b"-d", b"-c", None)
    else:
        arguments = (ctypes.c_char_p * 4)(b"gzip", b"-d", b"-c", None)
    environment = (ctypes.c_char_p * 2)(b"LC_ALL=C", None)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(322, descriptor, b"", arguments, environment, 0x1000) != 0:
        saved = ctypes.get_errno()
        raise OSError(saved, os.strerror(saved))


def _run_fixed_tool(role: str, descriptors: tuple[int, int, int], payload: bytes) -> _ToolOutcome:
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeLauncherError("fixed tool execution requires Linux x86_64")
    if (role, payload) not in (("gzip", _GZIP_INPUT), ("zstd", _ZSTD_INPUT)):
        raise RuntimeLauncherError("non-fixed tool invocation rejected")
    stdin_r = stdin_w = stdout_r = stdout_w = status_r = status_w = -1
    try:
        stdin_r, stdin_w = os.pipe2(os.O_CLOEXEC)
        stdout_r, stdout_w = os.pipe2(os.O_CLOEXEC)
        status_r, status_w = os.pipe2(os.O_CLOEXEC)
        parent_pid = os.getpid()
        pid = os.fork()
    except BaseException as primary:
        errors = []
        for descriptor in (stdin_r, stdin_w, stdout_r, stdout_w, status_r, status_w):
            if descriptor >= 0:
                try: os.close(descriptor)
                except OSError as error: errors.append(error)
        if errors:
            raise RuntimeLauncherError("fixed tool setup cleanup uncertain") from primary
        raise
    if pid == 0:
        error_fd = status_w
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "PDEATHSIG")
            if os.getppid() != parent_pid:
                raise OSError(errno.ESRCH, "parent changed")
            os.close(stdin_w); os.close(stdout_r); os.close(status_r)
            duplicates = tuple(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 256) for fd in (*descriptors, stdin_r, stdout_w, status_w))
            for source, (_name, target) in zip(duplicates[:3], _FIXED_FD_MAP, strict=True):
                os.dup2(source, target, inheritable=False)
            input_fd, output_fd, error_fd = duplicates[3:]
            os.dup2(input_fd, 0, inheritable=True); os.dup2(output_fd, 1, inheritable=True)
            os.set_inheritable(error_fd, False)
            _close_except({0, 1, error_fd, *[target for _name, target in _FIXED_FD_MAP]})
            _execveat(dict(_FIXED_FD_MAP)[role], role)
        except OSError as error:
            try: os.write(error_fd, struct.pack("!I", error.errno or errno.EIO))
            except OSError: pass
        os._exit(126)
    primary: BaseException | None = None
    output = bytearray(); status_raw = bytearray(); reaped = False
    deadline = time.monotonic() + _DEADLINE_SECONDS
    try:
        os.close(stdin_r); stdin_r = -1
        os.close(stdout_w); stdout_w = -1
        os.close(status_w); status_w = -1
        view = memoryview(payload)
        while view:
            written = os.write(stdin_w, view)
            view = view[written:]
        os.close(stdin_w); stdin_w = -1
        while stdout_r >= 0 or status_r >= 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeLauncherError("fixed tool deadline exceeded")
            ready, _, _ = select.select([fd for fd in (stdout_r, status_r) if fd >= 0], [], [], remaining)
            if not ready:
                raise RuntimeLauncherError("fixed tool deadline exceeded")
            for descriptor in ready:
                part = os.read(descriptor, 65536)
                if descriptor == stdout_r:
                    output += part
                    if len(output) > _MAX_OUTPUT: raise RuntimeLauncherError("fixed tool output exceeded bound")
                else:
                    status_raw += part
                    if len(status_raw) > 4: raise RuntimeLauncherError("fixed tool status exceeded bound")
                if not part:
                    os.close(descriptor)
                    if descriptor == stdout_r: stdout_r = -1
                    else: status_r = -1
        observed, wait_status = os.waitpid(pid, 0); reaped = observed == pid
        if not reaped or wait_status != 0 or status_raw or bytes(output) != _PAYLOAD:
            raise RuntimeLauncherError("fixed tool qualification failed")
        return _ToolOutcome(bytes(output), True)
    except BaseException as error:
        primary = error
        raise
    finally:
        errors: list[BaseException] = []
        for descriptor in (stdin_r, stdin_w, stdout_r, stdout_w, status_r, status_w):
            if descriptor >= 0:
                try: os.close(descriptor)
                except OSError as error: errors.append(error)
        if not reaped:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError as error: errors.append(error)
            try: os.waitpid(pid, 0); reaped = True
            except OSError as error: errors.append(error)
        if errors:
            raise RuntimeLauncherError("fixed tool cleanup uncertain") from (primary or errors[0])


def _run_fixed_sandbox() -> SandboxQualificationResult:
    """Inspect the fixed Job E child without discovering any host object."""
    if os.getpid() != 1 or os.getgroups():
        raise RuntimeLauncherError("sandbox PID or supplementary groups mismatch")
    libc = ctypes.CDLL(None, use_errno=True)
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)
    capabilities = (ctypes.c_uint32 * 6)()
    if libc.syscall(125, header, capabilities) != 0 or any(capabilities):
        raise RuntimeLauncherError("sandbox capabilities are not zero")
    no_new_privs = libc.prctl(39, 0, 0, 0, 0) == 1
    securebits = libc.prctl(27, 0, 0, 0, 0)
    if not no_new_privs or securebits < 0 or securebits & 0x0F != 0x0F:
        raise RuntimeLauncherError("sandbox privilege locks mismatch")
    for number, arguments in (
        (41, (2, 1, 0)),
        (272, (0x40000000,)),
        (425, (1, ctypes.byref((ctypes.c_ubyte * 256)()))),
    ):
        ctypes.set_errno(0)
        if libc.syscall(number, *arguments) != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeLauncherError("sandbox seccomp denial mismatch")
    for descriptor in range(3, 8193):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        raise RuntimeLauncherError("sandbox inherited an extra descriptor")
    if not os.statvfs("/").f_flag & getattr(os, "ST_RDONLY", 1):
        raise RuntimeLauncherError("sandbox root is not read-only")
    return SandboxQualificationResult(
        _VERSION, _MARKER, True, True, True, True, True, True, True,
    )


def _launch_with_adapter_for_tests(handoff: object, adapter: object) -> RuntimeQualificationResult:
    descriptors = _extract_handoff(handoff)
    if getattr(handoff, "_cogs_launcher_consumed", False):
        raise RuntimeLauncherError("settled handoff was already consumed")
    object.__setattr__(handoff, "_cogs_launcher_consumed", True)
    baseline = None
    primary: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    children_reaped = False
    try:
        baseline = adapter.baseline(descriptors)
        revision = adapter.authenticate_tracked_source(handoff)
        for (role, _target), descriptor in zip(_FIXED_FD_MAP, descriptors, strict=True):
            adapter.inspect_descriptor(role, descriptor)
        report = _decode_report(adapter.read_report(descriptors[2]))
        gzip = adapter.run_tool("gzip", descriptors, _GZIP_INPUT)
        zstd = adapter.run_tool("zstd", descriptors, _ZSTD_INPUT)
        children_reaped = gzip.reaped and zstd.reaped
        if gzip.output != _PAYLOAD or zstd.output != _PAYLOAD or not children_reaped:
            raise RuntimeLauncherError("fixed qualification result mismatch")
        result = RuntimeQualificationResult(
            _VERSION, _MARKER, report["closure_sha256"], revision,
            hashlib.sha256(gzip.output).hexdigest(), hashlib.sha256(zstd.output).hexdigest(), True, True, True,
        )
    except BaseException as error:
        primary = error
        result = None
    finally:
        for descriptor in reversed(descriptors):
            try: adapter.close_descriptor(descriptor)
            except BaseException as error: cleanup_errors.append(error)
        if baseline is not None:
            try: adapter.prove_restored(baseline)
            except BaseException as error: cleanup_errors.append(error)
        try: adapter.finish()
        except BaseException as error: cleanup_errors.append(error)
    if cleanup_errors:
        raise RuntimeLauncherError("runtime launcher cleanup uncertain") from (primary or cleanup_errors[0])
    if primary is not None:
        raise primary
    return result


def _launch_fixed_runtime_qualification_with_adapter(handoff: object, adapter: object) -> RuntimeQualificationResult:
    return _launch_with_adapter_for_tests(handoff, adapter)


def _launch_fixed_sandbox_probe_with_adapter(adapter: object) -> SandboxQualificationResult:
    baseline = adapter.baseline(())
    primary: BaseException | None = None
    try:
        result = adapter.run_sandbox()
    except BaseException as error:
        primary = error
        result = None
    cleanup_errors: list[BaseException] = []
    try:
        adapter.prove_restored(baseline)
    except BaseException as error:
        cleanup_errors.append(error)
    try:
        adapter.finish()
    except BaseException as error:
        cleanup_errors.append(error)
    if cleanup_errors:
        raise RuntimeLauncherError("sandbox launcher cleanup uncertain") from (primary or cleanup_errors[0])
    if primary is not None:
        raise primary
    return result


def launch_fixed_runtime_qualification(handoff: "RuntimeClosureHandoff") -> RuntimeQualificationResult:
    return _launch_fixed_runtime_qualification_with_adapter(handoff, _SystemLauncherAdapter())


def launch_fixed_sandbox_probe() -> SandboxQualificationResult:
    return _launch_fixed_sandbox_probe_with_adapter(_SystemLauncherAdapter())
