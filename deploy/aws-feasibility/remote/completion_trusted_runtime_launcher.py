from __future__ import annotations
from array import array
from dataclasses import dataclass, field
from enum import Enum
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
import time
import types
from typing import Any, NoReturn
_VERSION = "cogs.trusted-runtime-closure/v1"
_ADMISSION_VERSION = "cogs.runtime-source-admission/v1"
_HANDOFF_VERSION = "cogs.runtime-handoff/v1"
_RECEIPT_VERSION = _HANDOFF_VERSION
_RESULT_VERSION = "cogs.runtime-qualification/v1"
_MARKER = "cogs-runtime-qualification-v1"
_FIXED_SOURCE_SET = (
    "deploy/aws-feasibility/remote/completion_elf.py", "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", "schemas/trusted-runtime-closure-v1.json",
)
_MODULE_PATHS = _FIXED_SOURCE_SET[:3]
_SCHEMA_PATH = _FIXED_SOURCE_SET[3]
_TOOL_INDEX = {"zstd": 1, "gzip": 2}
_FIXED_INPUT = {
    "gzip": bytes.fromhex("1f8b08000000000002ff4bce4f2fd62d2acd2bc9cc4dd52d2c4dccc94ccb4c4e"
                          "2cc9cccfd32d33e40200a9c9b5521e000000"),
    "zstd": bytes.fromhex("28b52ffd201ef10000636f67732d72756e74696d652d7175616c696669636174696f6e2d76310a"),
}
_FIXED_OUTPUT = b"cogs-runtime-qualification-v1\n"
(_MAX_ADMISSION, _MAX_SOURCE, _MAX_REPORT, _MAX_PACKET) = (512, 2_000_000, 128 * 1024, 256 * 1024)
(_MAX_OBJECT, _MAX_OBJECTS, _MAX_MAPS, _MAX_MAP_LINES) = (128 * 1024 * 1024, 256, 4 * 1024 * 1024, 4096)
_MAX_OUTPUT, _IO_CHUNK = 1024 * 1024, 1024 * 1024
_SETUP_SECONDS, _RUN_SECONDS, _TERM_SECONDS, _KILL_SECONDS = 10.0, 10.0, 1.0, 1.0
_ROOT_PARENT, _ROOT_LEAF = "/run", "cogs-o2-runtime-v1"
_INTERPRETER, _LIBRARY_ROOT = "/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu"
_SEAL_PROFILE, _F_GET_SEALS = "linux-memfd-exec-seals-v1", 1034
(_F_SEAL_SEAL, _F_SEAL_SHRINK, _F_SEAL_GROW) = (0x0001, 0x0002, 0x0004)
(_F_SEAL_WRITE, _F_SEAL_FUTURE_WRITE, _F_SEAL_EXEC) = (0x0008, 0x0010, 0x0020)
_DATA_SEALS = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE | _F_SEAL_FUTURE_WRITE
_EXEC_SEALS = _DATA_SEALS | _F_SEAL_EXEC
(_CLONE_NEWNS, _CLONE_NEWUSER, _CLONE_NEWPID, _CLONE_NEWNET) = (0x00020000, 0x10000000, 0x20000000, 0x40000000)
(_MS_RDONLY, _MS_NOSUID, _MS_NODEV, _MS_NOEXEC) = (1, 2, 4, 8)
_MS_REMOUNT, _MS_PRIVATE, _MS_REC = 32, 1 << 18, 16384
(_PR_SET_PDEATHSIG, _PR_SET_DUMPABLE, _PR_GET_SECUREBITS, _PR_SET_SECUREBITS) = (1, 4, 27, 28)
(_PR_CAPBSET_DROP, _PR_CAPBSET_READ, _PR_SET_NO_NEW_PRIVS, _PR_GET_NO_NEW_PRIVS) = (24, 23, 38, 39)
_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL = 47, 4
_PR_SET_SECCOMP, _PR_GET_SECCOMP = 22, 21
_SECCOMP_MODE_FILTER, _SECBITS = 2, 0x0F
_AT_EMPTY_PATH, _UINT_MAX = 0x1000, (1 << 32) - 1
_SYS_GETDENTS64 = 217
_DENIED_SYSCALLS = {
    "execve": 59,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "bind": 49,
    "listen": 50,
    "socketpair": 53,
    "accept4": 288,
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "clone": 56,
    "fork": 57,
    "vfork": 58,
    "unshare": 272,
    "setns": 308,
    "mount": 165,
    "umount2": 166,
    "pivot_root": 155,
    "chroot": 161,
    "keyctl": 250,
    "add_key": 248,
    "request_key": 249,
    "perf_event_open": 298,
    "bpf": 321,
    "userfaultfd": 323,
    "clone3": 435,
    "ptrace": 101,
    "init_module": 175,
    "delete_module": 176,
    "finit_module": 313,
    "setuid": 105,
    "setgid": 106,
    "setresuid": 117,
    "setresgid": 119,
    "capset": 126,
    "seccomp": 317,
    "memfd_create": 319,
    "open_by_handle_at": 304,
    "pidfd_getfd": 438,
    "process_vm_writev": 311,
    "kexec_load": 246,
    "finit_module_legacy": 313,
    "dup": 32,
    "dup2": 33,
    "dup3": 292,
    "fcntl": 72,
}
_UNOBSERVED = object()

def _seccomp_digest() -> str:
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
            (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for number in _DENIED_SYSCALLS.values():
        rows.extend(((0x15, 0, 1, number), (0x06, 0, 0, 0x00050000 | errno.EPERM)))
    rows.append((0x06, 0, 0, 0x7FFF0000))
    return hashlib.sha256(b"".join(struct.pack("HBBI", *row) for row in rows)).hexdigest()

class RuntimeLauncherError(RuntimeError):
    def __init__(self, message: str, code: str = "launcher-rejected"):
        self.code = code
        super().__init__(message)

class RuntimeLauncherUnavailable(RuntimeLauncherError):
    status = "unavailable"

    def __init__(
        self,
        primitive: str,
        message: str | None = None,
        claims: dict[str, bool] | None = None,
        cleanup_restored: bool = False,
    ):
        self.primitive = primitive
        self.claims = claims or {}
        self.cleanup_restored = cleanup_restored
        detail = message or f"required primitive unavailable: {primitive}"
        super().__init__(detail, "primitive-unavailable")
class RuntimeLauncherCleanupError(RuntimeLauncherError):
    def __init__(self, primary: BaseException | None, failures: list[BaseException]):
        self.primary = primary
        self.failures = tuple(failures)
        super().__init__(
            f"launcher cleanup uncertain ({len(failures)} failures)",
            "cleanup-uncertain",
        )
def _require(condition: bool, message: str, code: str = "launcher-rejected") -> None:
    if not condition:
        raise RuntimeLauncherError(message, code)

class _FdState(Enum):
    OWNED = "OWNED"
    CLOSED = "CLOSED"
    TRANSFERRED = "TRANSFERRED"
    CLOSE_UNCERTAIN = "CLOSE_UNCERTAIN"

@dataclass
class _FdLease:
    fd: int
    purpose: str
    state: _FdState = _FdState.OWNED
    close_error: BaseException | None = None

    def close(self, ops: object) -> None:
        if self.state is _FdState.CLOSED:
            return
        if self.state is _FdState.CLOSE_UNCERTAIN:
            if self.close_error is None:
                raise RuntimeLauncherError("descriptor uncertainty lost", "fd-lease-poison")
            raise self.close_error
        if self.state is not _FdState.OWNED:
            raise RuntimeLauncherError("transferred descriptor close", "fd-lease-transferred")
        close = getattr(ops, "close", None)
        if not callable(close):
            raise TypeError("launcher Ops lacks close")
        try:
            close(self.fd)
        except BaseException as error:
            self.close_error = error
            self.state = _FdState.CLOSE_UNCERTAIN
            raise
        self.state = _FdState.CLOSED

    def transfer(self) -> int:
        if self.state is not _FdState.OWNED:
            raise RuntimeLauncherError("descriptor transfer state", "fd-lease-transfer")
        self.state = _FdState.TRANSFERRED
        return self.fd

def _close_leases(
    ops: object,
    leases: tuple[_FdLease, ...] | list[_FdLease],
    primary: BaseException | None = None,
) -> None:
    failures: list[BaseException] = []
    for lease in reversed(tuple(leases)):
        if lease.state is _FdState.CLOSE_UNCERTAIN:
            if lease.close_error is None:
                failures.append(RuntimeLauncherError(
                    "descriptor uncertainty lost",
                    "fd-lease-poison",
                ))
            else:
                failures.append(lease.close_error)
            continue
        if lease.state is not _FdState.OWNED:
            continue
        try:
            lease.close(ops)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
@dataclass
class _SourceAdmission:
    revision: str
    bootstrap_sha256: str
    source_set_sha256: str
    _schema_bytes: bytes
    _package: str
    _worker_pid: int
    _endpoint: socket.socket | None
    _issuer: object
    _consumer_pid: int
    _consumer_uid: int
    _consumer_gid: int
    _claimed: bool = False

    def _consume(
        self,
        issuer: object,
        package: object,
        worker_pid: object,
    ) -> bool:
        if self._claimed or issuer is not self._issuer:
            return False
        if package != self._package:
            return False
        if worker_pid != self._worker_pid or os.getpid() != self._worker_pid:
            return False
        peer = self._endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        peer_credentials = struct.unpack("3i", peer)
        expected = (self._consumer_pid, self._consumer_uid, self._consumer_gid)
        if peer_credentials != expected:
            return False
        self._claimed = True
        return True

    def _validate_tracked_schema(self, canonical_report: bytes) -> None:
        _validate_tracked_report(self._schema_bytes, canonical_report)
@dataclass(frozen=True)
class _GenerationRow:
    tool_index: int
    object_index: int
    role: str
    descriptor_index: int
    size: int
    sha256: str
    soname: str | None
    needed: tuple[str, ...]
    seal_profile: str
    source_generation: tuple[int, int, int, int, int, int, int, int]

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

@dataclass(frozen=True)
class RuntimeQualificationResult:
    version: str
    marker: str
    source_revision: str
    source_set_sha256: str
    closure_sha256: str
    gzip_output_sha256: str
    zstd_output_sha256: str
    mapped_generations_exact: bool
    user_namespace_exact: bool
    pid_namespace_exact: bool
    mount_namespace_exact: bool
    network_namespace_exact: bool
    pid_one: bool
    capabilities_zero: bool
    noroot_locked: bool
    no_new_privs: bool
    seccomp_installed: bool
    seccomp_mode_exact: bool
    seccomp_program_exact: bool
    seccomp_denials_exact: bool
    exec_descriptor_consumed: bool
    no_acquisition_route: bool
    root_readonly_noexec: bool
    root_has_no_proc: bool
    descriptors_restored: bool
    children_reaped: bool
    descendants_reaped: bool
    mounts_restored: bool
    paths_restored: bool
    namespaces_released: bool

class _ObservedFacts:
    def __init__(self, names: tuple[str, ...]):
        self._values = {name: _UNOBSERVED for name in names}

    def observe(self, name: str, observed: object, expected: object) -> None:
        if name not in self._values or self._values[name] is not _UNOBSERVED:
            raise RuntimeLauncherError(f"duplicate or unknown fact: {name}", "fact-cardinality")
        if observed != expected:
            raise RuntimeLauncherError(f"qualification fact mismatch: {name}", f"fact-{name}")
        self._values[name] = True

    def value(self, name: str) -> bool:
        value = self._values.get(name, _UNOBSERVED)
        if value is not True:
            raise RuntimeLauncherError(f"qualification fact unobserved: {name}", f"unobserved-{name}")
        return value

    def complete(self) -> None:
        missing = tuple(name for name, value in self._values.items() if value is not True)
        if missing:
            raise RuntimeLauncherError(f"qualification facts unobserved: {missing}", "facts-incomplete")
def _canonical(value: object, newline: bool = False) -> bytes:
    data = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    return data + (b"\n" if newline else b"")
def _strict_json(raw: bytes, newline: bool, bound: int, label: str, canonical: bool = True) -> Any:
    _require(bool(raw) and len(raw) <= bound, f"{label} byte bound")
    body = raw
    if newline:
        _require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"), f"{label} framing")
        body = raw[:-1]
    elif raw.endswith(b"\n"):
        body = raw[:-1]
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in rows:
            _require(key not in value, f"{label} duplicate key")
            value[key] = item
        return value
    def reject_number(_value: str) -> NoReturn:
        raise ValueError("non-integer number")
    try:
        value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeLauncherError(f"{label} strict JSON") from error
    _require(not canonical or _canonical(value) == body, f"{label} canonical bytes")
    return value
_JSON_TYPES = {"object": dict, "array": list, "string": str, "integer": int,
               "boolean": bool, "null": type(None)}
def _schema_matches(schema: object, value: object, root: dict[str, object], path: str, depth: int) -> bool:
    try:
        _apply_schema(schema, value, root, path, depth)
        return True
    except RuntimeLauncherError:
        return False
def _apply_schema(schema: object, value: object, root: dict[str, object], path: str, depth: int) -> None:
    _require(depth <= 64 and type(schema) is dict, "tracked schema unsupported shape")
    if "$ref" in schema:
        ref = schema["$ref"]
        _require(type(ref) is str and ref.startswith("#/"), "tracked schema external reference")
        target: object = root
        for part in ref[2:].split("/"):
            _require(type(target) is dict and part in target, "tracked schema reference")
            target = target[part]
        _apply_schema(target, value, root, path, depth + 1)
    for branch in schema.get("allOf", []):
        _apply_schema(branch, value, root, path, depth + 1)
    if "oneOf" in schema:
        matches = sum(_schema_matches(item, value, root, path, depth + 1) for item in schema["oneOf"])
        _require(matches == 1, f"tracked schema oneOf at {path}")
    expected = schema.get("type")
    if expected is not None:
        options = expected if type(expected) is list else [expected]
        matches = any(type(item) is str and type(value) is _JSON_TYPES.get(item) for item in options)
        _require(matches, f"tracked schema type at {path}")
    constant_ok = "const" not in schema or value == schema["const"]
    enum_ok = "enum" not in schema or value in schema["enum"]
    _require(constant_ok and enum_ok, f"tracked schema value at {path}")
    if type(value) is dict:
        properties = schema.get("properties", {})
        _require(not any(key not in value for key in schema.get("required", [])), f"tracked schema required at {path}")
        extras_ok = schema.get("additionalProperties") is not False or not any(key not in properties for key in value)
        _require(extras_ok, f"tracked schema extra property at {path}")
        for key in value.keys() & properties.keys():
            _apply_schema(properties[key], value[key], root, f"{path}.{key}", depth + 1)
    if type(value) is list:
        _require(schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 1 << 30), f"tracked schema cardinality at {path}")
        unique = len({_canonical(item) for item in value}) == len(value)
        _require(not schema.get("uniqueItems") or unique, f"tracked schema uniqueness at {path}")
        prefix = schema.get("prefixItems", [])
        for index, branch in enumerate(prefix[:len(value)]):
            _apply_schema(branch, value[index], root, f"{path}[{index}]", depth + 1)
        items = schema.get("items")
        _require(items is not False or len(value) <= len(prefix), f"tracked schema extra item at {path}")
        if type(items) is dict:
            for index, item in enumerate(value[len(prefix):], len(prefix)):
                _apply_schema(items, item, root, f"{path}[{index}]", depth + 1)
        if "contains" in schema:
            matches = sum(_schema_matches(schema["contains"], item, root, path, depth + 1) for item in value)
            _require(schema.get("minContains", 1) <= matches <= schema.get("maxContains", 1 << 30), f"tracked schema contains at {path}")
    if type(value) is str:
        _require(schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 1 << 30), f"tracked schema string length at {path}")
        _require("pattern" not in schema or re.fullmatch(schema["pattern"], value) is not None, f"tracked schema pattern at {path}")
    if type(value) is int:
        _require(schema.get("minimum", -(1 << 63)) <= value <= schema.get("maximum", 1 << 63), f"tracked schema integer range at {path}")
def _validate_tracked_report(schema_bytes: bytes, report_bytes: bytes) -> None:
    """Production tracked-schema gate, independently callable by its hostile corpus."""
    schema = _strict_json(schema_bytes, False, _MAX_SOURCE, "schema", canonical=False)
    report = _strict_json(report_bytes, True, _MAX_REPORT, "report")
    _apply_schema(schema, report, schema, "$", 0)


def _consumer_reencode_report(value: object) -> bytes:
    """Consumer-owned canonical re-encoder; it is not the producer codec."""
    return _canonical(value, True)


def _sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)
def _safe_name(value: object) -> bool:
    return type(value) is str and 1 <= len(value.encode()) <= 255 and re.fullmatch(r"[A-Za-z0-9._+\-]+", value) is not None
def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()
def _decode_report(raw: bytes) -> dict[str, object]:
    value = _strict_json(raw, True, _MAX_REPORT, "report consumer")
    _require(type(value) is dict and set(value) == {"closure_sha256", "tools", "version"}, "report top-level shape")
    _require(value["version"] == _VERSION and _sha(value["closure_sha256"]), "report header")
    tools = value["tools"]
    _require(type(tools) is list and len(tools) == 3, "report tool cardinality")
    global_roles: dict[str, str] = {}
    for tool_index, (tool, name) in enumerate(zip(tools, ("python3-parser", "zstd", "gzip"))):
        keys = {"closure_sha256", "mapping_sha256", "objects", "seal_profile", "sealed_executable", "tool"}
        _require(type(tool) is dict and set(tool) == keys and tool["tool"] == name, "report tool shape/order")
        sealed = tool_index != 0
        _require(tool["sealed_executable"] is sealed, "report sealed executable")
        _require(tool["seal_profile"] == (_SEAL_PROFILE if sealed else None), "report seal profile")
        objects = tool["objects"]
        _require(type(objects) is list and 2 <= len(objects) <= 128, "report object cardinality")
        providers: dict[str, int] = {}
        identities: set[tuple[str, str]] = set()
        for object_index, item in enumerate(objects):
            _require(type(item) is dict and set(item) == {"needed", "role", "sha256", "size", "soname"}, "report object shape")
            role = "executable" if object_index == 0 else "loader" if object_index == 1 else "library"
            _require(item["role"] == role and _sha(item["sha256"]), "report role/digest")
            _require(type(item["size"]) is int and 1 <= item["size"] <= _MAX_OBJECT, "report object size")
            needed = item["needed"]
            unique_needed = type(needed) is list and len({_canonical(item) for item in needed}) == len(needed)
            _require(unique_needed and len(needed) <= 128, "report needed cardinality")
            _require(all(_safe_name(item) for item in needed), "report needed name")
            soname = item["soname"]
            _require(soname is None or _safe_name(soname), "report SONAME")
            _require(role != "library" or soname is not None, "report library SONAME")
            identity = (role, item["sha256"])
            _require(identity not in identities, "report duplicate identity")
            identities.add(identity)
            _require(global_roles.setdefault(item["sha256"], role) == role, "report cross-tool role alias")
            if soname is not None:
                providers[soname] = providers.get(soname, 0) + 1
        libraries = objects[2:]
        _require(libraries == sorted(libraries, key=lambda item: (item["soname"].encode(), item["sha256"])), "report library order")
        _require(not any(providers.get(name) != 1 for item in objects for name in item["needed"]), "report dependency provider")
        mapped = [[item["role"], item["sha256"]] for item in objects]
        _require(tool["closure_sha256"] == _digest(objects) and tool["mapping_sha256"] == _digest(mapped), "report tool digest")
    aggregate = [{key: item for key, item in tool.items() if key != "mapping_sha256"} for tool in tools]
    _require(value["closure_sha256"] == _digest(aggregate), "report aggregate digest")
    _require(_consumer_reencode_report(value) == raw, "report independent encoding")
    return value
def _read_complete(fd: int, size: int, bound: int) -> bytes:
    _require(0 < size <= bound, "object byte bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        part = os.pread(fd, min(_IO_CHUNK, size - offset), offset)
        _require(bool(part), "object short read")
        chunks.append(part)
        offset += len(part)
    extra = os.pread(fd, 1, size)
    _require(not extra, "object grew during read")
    return b"".join(chunks)
def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_uid, value.st_gid)
def _parse_fd_dirents(raw: bytes) -> tuple[int, ...]:
    offset = 0
    values: list[int] = []
    while offset < len(raw):
        if len(raw) - offset < 20:
            raise RuntimeLauncherError("truncated fd dirent", "fd-dirent-truncated")
        _inode, _position, length, _kind = struct.unpack_from("=QqHB", raw, offset)
        if length < 20 or offset + length > len(raw):
            raise RuntimeLauncherError("malformed fd dirent", "fd-dirent-shape")
        name_field = raw[offset + 19:offset + length]
        end = name_field.find(b"\0")
        if end < 0:
            raise RuntimeLauncherError("unterminated fd dirent", "fd-dirent-name")
        name = name_field[:end]
        if name not in (b".", b".."):
            if not name.isdigit() or (len(name) > 1 and name.startswith(b"0")):
                raise RuntimeLauncherError("invalid fd dirent", "fd-dirent-value")
            value = int(name)
            if value > 2147483647 or value in values:
                raise RuntimeLauncherError("duplicate fd dirent", "fd-dirent-duplicate")
            values.append(value)
        offset += length
    return tuple(values)

def _descriptor_snapshot(
    ops: _LauncherOps | None = None,
    pid: int | str = "self",
) -> tuple[int, ...]:
    actual_ops = ops or _SystemOps()
    path = f"/proc/{pid}/fd"
    directory = _FdLease(
        actual_ops.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
        "fd-enumerator",
    )
    values: list[int] = []
    primary: BaseException | None = None
    try:
        while True:
            chunk = actual_ops.getdents(directory.fd)
            if not chunk:
                break
            values.extend(_parse_fd_dirents(chunk))
            _require(len(values) <= 16384, "descriptor snapshot bound", "fd-bound")
        _require(values.count(directory.fd) == (1 if pid == "self" else 0),
                 "descriptor enumerator cardinality", "fd-enumerator-cardinality")
        excluded = directory.fd if pid == "self" else -1
        result = tuple(sorted(value for value in values if value != excluded))
        _require(len(result) == len(set(result)), "descriptor snapshot duplicate", "fd-duplicate")
    except BaseException as error:
        primary = error
        result = ()
    try:
        directory.close(actual_ops)
    except BaseException as close_error:
        raise RuntimeLauncherCleanupError(primary, [close_error]) from (primary or close_error)
    if primary is not None:
        raise primary
    return result
def _platform_gate() -> None:
    if sys.platform != "linux" or not hasattr(os, "uname") or os.uname().machine != "x86_64":
        raise RuntimeLauncherUnavailable("fixed launcher requires Linux x86_64")
class _LauncherOps:
    """Primitive protocol shared by production and deterministic portable models."""

    def close(self, fd: int) -> None:
        raise NotImplementedError


class _SystemOps(_LauncherOps):
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)
    def _checked(self, result: int, name: str) -> int:
        if result == -1:
            saved = ctypes.get_errno()
            if saved in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EINVAL):
                raise RuntimeLauncherUnavailable(name)
            raise OSError(saved, os.strerror(saved))
        return result
    def close(self, fd: int) -> None:
        os.close(fd)

    def open(self, path: str, flags: int, mode: int = 0o600) -> int:
        return os.open(path, flags, mode)

    def getdents(self, fd: int, maximum: int = 32768) -> bytes:
        buffer = ctypes.create_string_buffer(maximum)
        count = self._checked(
            self.libc.syscall(_SYS_GETDENTS64, fd, ctypes.byref(buffer), maximum),
            "getdents64",
        )
        return bytes(buffer.raw[:count])

    def socketpair(self) -> tuple[socket.socket, socket.socket]:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return left, right
    def nonce(self) -> bytes:
        value = os.getrandom(32)
        if len(value) != 32:
            raise RuntimeLauncherUnavailable("getrandom returned incomplete nonce")
        return value
    def unshare_boundary(self) -> None:
        flags = _CLONE_NEWUSER | _CLONE_NEWNS | _CLONE_NEWPID | _CLONE_NEWNET
        self._checked(self.libc.unshare(flags), "unshare")
    def mount(self, source: bytes | None, target: bytes, kind: bytes | None, flags: int, data: bytes | None) -> None:
        self._checked(self.libc.mount(source, target, kind, flags, data), "mount")
    def umount(self, target: bytes) -> None:
        self._checked(self.libc.umount2(target, 0), "umount2")
    def chroot(self, root: bytes) -> None:
        self._checked(self.libc.chroot(root), "chroot")
    def prctl(self, option: int, value: int = 0) -> int:
        return self._checked(self.libc.prctl(option, value, 0, 0, 0), "prctl")
    def capset_zero(self) -> None:
        header = (ctypes.c_uint32 * 2)(0x20080522, 0)
        data = (ctypes.c_uint32 * 6)()
        self._checked(self.libc.syscall(126, header, data), "capset")
    def capget_zero(self) -> bool:
        header = (ctypes.c_uint32 * 2)(0x20080522, 0)
        data = (ctypes.c_uint32 * 6)()
        self._checked(self.libc.syscall(125, header, data), "capget")
        return not any(data)
    def drop_bounding(self) -> None:
        for capability in range(256):
            ctypes.set_errno(0)
            present = self.libc.prctl(_PR_CAPBSET_READ, capability, 0, 0, 0)
            if present == -1 and ctypes.get_errno() == errno.EINVAL:
                break
            self._checked(present, "PR_CAPBSET_READ")
            if present:
                self.prctl(_PR_CAPBSET_DROP, capability)
        else:
            raise RuntimeLauncherUnavailable("capability-enumeration", "capability range exceeded")
    def install_seccomp(self) -> str:
        instructions = [
            (0x20, 0, 0, 4),
            (0x15, 1, 0, 0xC000003E),
            (0x06, 0, 0, 0x80000000),
            (0x20, 0, 0, 0),
        ]
        for number in _DENIED_SYSCALLS.values():
            instructions.append((0x15, 0, 1, number))
            instructions.append((0x06, 0, 0, 0x00050000 | errno.EPERM))
        instructions.append((0x06, 0, 0, 0x7FFF0000))
        encoded = b"".join(struct.pack("HBBI", *row) for row in instructions)
        class Filter(ctypes.Structure):
            _fields_ = (("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32))
        program = (Filter * len(instructions))(*(Filter(*row) for row in instructions))
        class Program(ctypes.Structure):
            _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter)))
        descriptor = Program(len(program), program)
        self._checked(
            self.libc.prctl(
                _PR_SET_SECCOMP,
                _SECCOMP_MODE_FILTER,
                ctypes.byref(descriptor),
            ),
            "seccomp",
        )
        digest = hashlib.sha256(encoded).hexdigest()
        _require(digest == _seccomp_digest(), "seccomp assembly drift", "seccomp-digest")
        return digest

    def seccomp_mode(self) -> int:
        return self.prctl(_PR_GET_SECCOMP)

    def probe_seccomp_denials(self) -> dict[str, int]:
        probes = {
            "execve": (59, 0, 0, 0),
            "socket": (41, -1, -1, -1),
            "memfd_create": (319, 0, 0),
            "seccomp": (317, 0, 0, 0),
        }
        observed: dict[str, int] = {}
        for name, arguments in probes.items():
            ctypes.set_errno(0)
            result = self.libc.syscall(*arguments)
            saved = ctypes.get_errno()
            if result != -1 or saved != errno.EPERM:
                raise RuntimeLauncherError(
                    f"seccomp denial mismatch: {name}:{result}:{saved}",
                    f"seccomp-denial-{name}",
                )
            observed[name] = saved
        return observed
    def close_range(self, first: int, last: int) -> None:
        self._checked(self.libc.syscall(436, first, last, 0), "close_range")
    def execveat(self, fd: int, role: str) -> NoReturn:
        argv_values = (role, "-q", "-d", "-c") if role == "zstd" else (role, "-d", "-c")
        argv = (ctypes.c_char_p * (len(argv_values) + 1))(*(item.encode() for item in argv_values), None)
        environment = (ctypes.c_char_p * 2)(b"LC_ALL=C", None)
        self._checked(self.libc.syscall(322, fd, b"", argv, environment, _AT_EMPTY_PATH), "execveat")
        raise AssertionError("execveat returned")
def _checked_row(row: _GenerationRow) -> _GenerationRow:
    _require(type(row.tool_index) is int and row.tool_index in (1, 2), "generation tool index")
    _require(type(row.object_index) is int and row.object_index >= 0, "generation object index")
    _require(row.role in ("executable", "loader", "library"), "generation role")
    _require(type(row.descriptor_index) is int and row.descriptor_index >= 1, "generation descriptor index")
    _require(type(row.size) is int and 1 <= row.size <= _MAX_OBJECT and _sha(row.sha256), "generation bytes")
    _require(row.soname is None or _safe_name(row.soname), "generation SONAME")
    _require(all(_safe_name(name) for name in row.needed), "generation dependency")
    _require(row.seal_profile == _SEAL_PROFILE and len(row.source_generation) == 8, "generation profile")
    _require(all(type(item) is int and item >= 0 for item in row.source_generation), "generation identity")
    return row
def _row_from_object(value: object) -> _GenerationRow:
    try:
        generation = value.source_generation
        if hasattr(generation, "device"):
            generation = (generation.device, generation.inode, generation.size, generation.mtime_ns,
                          generation.ctime_ns, generation.mode, generation.uid, generation.gid)
        row = _GenerationRow(value.tool_index, value.object_index, value.role, value.descriptor_index,
                             value.size, value.sha256, value.soname, tuple(value.needed),
                             value.seal_profile, tuple(generation))
    except (AttributeError, TypeError) as error:
        raise RuntimeLauncherError("invalid private generation row") from error
    return _checked_row(row)
def _row_value(row: _GenerationRow) -> list[object]:
    return [row.tool_index, row.object_index, row.role, row.descriptor_index, row.size, row.sha256,
            row.soname, list(row.needed), row.seal_profile, list(row.source_generation)]
def _binding_value(row: _GenerationRow) -> dict[str, object]:
    return {"descriptor_index": row.descriptor_index, "needed": list(row.needed), "object_index": row.object_index,
            "role": row.role, "seal_profile": row.seal_profile, "sha256": row.sha256, "size": row.size,
            "soname": row.soname, "tool_index": row.tool_index}
def _generation_value(row: _GenerationRow) -> list[int]:
    return [row.tool_index, row.object_index, row.descriptor_index, *row.source_generation]
def _rows_from_packet(values: object) -> tuple[_GenerationRow, ...]:
    _require(type(values) is list and bool(values) and len(values) <= _MAX_OBJECTS, "handoff generation rows")
    rows: list[_GenerationRow] = []
    for value in values:
        _require(type(value) is list and len(value) == 10, "handoff generation row shape")
        _require(type(value[7]) is list and type(value[9]) is list, "handoff generation nested shape")
        row = _GenerationRow(value[0], value[1], value[2], value[3], value[4], value[5],
                             value[6], tuple(value[7]), value[8], tuple(value[9]))
        rows.append(_checked_row(row))
    return tuple(rows)
def _inspect_fd(fd: int, report: bool, expected_size: int | None, expected_sha: str | None) -> bytes:
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode), "issued descriptor type")
    expected_mode = 0o444 if report else 0o555
    _require(stat.S_IMODE(before.st_mode) == expected_mode, "issued descriptor mode")
    access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
    _require(access_mode == os.O_RDONLY, "issued descriptor access")
    inheritable = os.get_inheritable(fd)
    _require(not inheritable, "issued descriptor is inheritable")
    seals = fcntl.fcntl(fd, _F_GET_SEALS)
    _require(seals == (_DATA_SEALS if report else _EXEC_SEALS), "issued descriptor seals")
    bound = _MAX_REPORT if report else _MAX_OBJECT
    data = _read_complete(fd, before.st_size, bound)
    after = os.fstat(fd)
    _require(_stat_identity(before) == _stat_identity(after), "issued descriptor generation drift")
    _require(expected_size is None or before.st_size == expected_size, "issued descriptor size binding")
    _require(expected_sha is None or hashlib.sha256(data).hexdigest() == expected_sha, "issued descriptor digest binding")
    return data
def _verify_bundle(admission: _SourceAdmission, report_bytes: bytes, descriptors: tuple[int, ...],
                   rows: tuple[_GenerationRow, ...]) -> tuple[dict[str, object], str, str]:
    _require(2 <= len(descriptors) <= _MAX_OBJECTS and len(set(descriptors)) == len(descriptors), "issued descriptor cardinality")
    report_data = _inspect_fd(descriptors[0], True, len(report_bytes), hashlib.sha256(report_bytes).hexdigest())
    _require(report_data == report_bytes, "issued report bytes")
    admission._validate_tracked_schema(report_data)
    report = _decode_report(report_data)
    row_order = tuple((row.tool_index, row.object_index) for row in rows)
    expected_order = tuple(
        (tool_index, object_index)
        for tool_index in (1, 2)
        for object_index in range(len(report["tools"][tool_index]["objects"]))
    )
    _require(row_order == expected_order,
             "generation rows are not exact", "issuer-generation-rows")
    referenced = {0}
    for row in rows:
        _require(row.descriptor_index < len(descriptors), "generation descriptor index")
        referenced.add(row.descriptor_index)
        tool = report["tools"][row.tool_index]
        objects = tool["objects"]
        _require(row.object_index < len(objects), "generation object index")
        item = objects[row.object_index]
        expected_role = "executable" if row.object_index == 0 else "loader" if row.object_index == 1 else "library"
        _require(row.role == expected_role == item["role"], "generation role binding")
        _require(row.size == item["size"] and row.sha256 == item["sha256"], "generation report binding")
        _require(row.soname == item["soname"] and row.needed == tuple(item["needed"]), "generation ELF metadata binding")
    _require(referenced == set(range(len(descriptors))), "unbound issued descriptor")
    checked: dict[int, tuple[int, str]] = {}
    for row in rows:
        expected = (row.size, row.sha256)
        _require(row.descriptor_index not in checked or checked[row.descriptor_index] == expected, "conflicting descriptor alias")
        if row.descriptor_index not in checked:
            _inspect_fd(descriptors[row.descriptor_index], False, row.size, row.sha256)
            checked[row.descriptor_index] = expected
    return report, _digest([_binding_value(row) for row in rows]), _digest([_generation_value(row) for row in rows])
def _credentials(
    ancillary: list[tuple[int, int, bytes]],
    require_rights: bool = True,
) -> tuple[tuple[int, int, int], tuple[int, ...]]:
    credentials: tuple[int, int, int] | None = None
    descriptors: tuple[int, ...] | None = None
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET:
            raise RuntimeLauncherError("handoff ancillary level", "issuer-ancillary")
        if kind == socket.SCM_CREDENTIALS:
            size = struct.calcsize("3i")
            _require(credentials is None and len(data) == size,
                     "handoff credentials cardinality", "issuer-credentials-cardinality")
            credentials = struct.unpack("3i", data)
            continue
        if kind == socket.SCM_RIGHTS:
            _require(descriptors is None and bool(data),
                     "handoff rights cardinality", "issuer-rights-cardinality")
            _require(len(data) % array("i").itemsize == 0,
                     "handoff rights alignment", "issuer-rights-alignment")
            values = array("i")
            values.frombytes(data)
            descriptors = tuple(values)
            continue
        raise RuntimeLauncherError("handoff ancillary type", "issuer-ancillary")
    _require(credentials is not None, "handoff credentials missing", "issuer-credentials-missing")
    if require_rights:
        _require(descriptors is not None, "handoff rights missing", "issuer-rights-missing")
    else:
        _require(descriptors is None, "unexpected handoff rights", "issuer-rights-extra")
    return credentials, descriptors or ()
class _WorkerIssuer:
    def __init__(
        self,
        endpoint: socket.socket,
        nonce: bytes,
        admission: _SourceAdmission,
        consumer_pid: int,
        package_name: str,
    ):
        self._endpoint = endpoint
        self._nonce = nonce
        self._admission = admission
        self._consumer_pid = consumer_pid
        self._package_name = package_name
        self._capability_used = False
        self._used = False

    def _consume_runtime_closure_capability(
        self,
        admission: object,
        package_name: str,
        worker_pid: int,
    ) -> tuple[socket.socket, tuple[int, int, int]]:
        if self._capability_used:
            raise RuntimeLauncherError("admission capability replay", "admission-replay")
        if admission is not self._admission or type(admission) is not _SourceAdmission:
            raise RuntimeLauncherError("admission authority mismatch", "admission-authority")
        if package_name != self._package_name:
            raise RuntimeLauncherError("synthetic package mismatch", "admission-package")
        if worker_pid != os.getpid() or worker_pid != admission._worker_pid:
            raise RuntimeLauncherError("admission worker mismatch", "admission-worker")
        if not admission._consume(self, package_name, worker_pid):
            raise RuntimeLauncherError("admission capability rejected", "admission-capability")
        self._capability_used = True
        expected = (self._consumer_pid, os.getuid(), os.getgid())
        return self._endpoint, expected
    def _accept_runtime_closure(self, canonical_report: bytes, descriptors: tuple[int, ...],
                                generation_rows: tuple[object, ...]) -> _IssuanceReceipt:
        _require(not self._used, "issuer is one-shot")
        self._used = True
        _require(type(canonical_report) is bytes and type(descriptors) is tuple and type(generation_rows) is tuple, "issuer argument type")
        rows = tuple(_row_from_object(row) for row in generation_rows)
        report, binding_sha, generation_sha = _verify_bundle(self._admission, canonical_report, descriptors, rows)
        packet = {
            "binding_sha256": binding_sha, "closure_sha256": report["closure_sha256"],
            "descriptor_count": len(descriptors), "generation_rows": [_row_value(row) for row in rows],
            "generation_sha256": generation_sha, "nonce": self._nonce.hex(),
            "report_sha256": hashlib.sha256(canonical_report).hexdigest(), "revision": self._admission.revision,
            "source_set_sha256": self._admission.source_set_sha256, "version": _HANDOFF_VERSION,
        }
        raw = _canonical(packet)
        rights = array("i", descriptors)
        sent = self._endpoint.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        _require(sent == len(raw), "handoff packet partial send")
        ack_raw, ancillary, flags, _address = self._endpoint.recvmsg(_MAX_PACKET, 256)
        credentials, received = _credentials(ancillary, require_rights=False)
        expected_credentials = (self._consumer_pid, os.getuid(), os.getgid())
        _require(not flags and not received and credentials == expected_credentials,
                 "issuance acknowledgement authority", "issuer-ack-authority")
        ack = _strict_json(ack_raw, False, _MAX_PACKET, "issuance acknowledgement")
        expected = {
            "binding_sha256": binding_sha, "consumer_pid": self._consumer_pid,
            "generation_sha256": generation_sha, "nonce": self._nonce.hex(),
            "report_sha256": packet["report_sha256"], "version": _RECEIPT_VERSION,
        }
        _require(ack == expected, "issuance acknowledgement mismatch")
        trailing = self._endpoint.recv(1)
        _require(trailing == b"", "second consumer packet", "issuer-second-packet")
        self._endpoint.shutdown(socket.SHUT_WR)
        return _IssuanceReceipt(_RECEIPT_VERSION, packet["report_sha256"], report["closure_sha256"],
                                binding_sha, generation_sha, len(descriptors), os.getpid(), self._consumer_pid)
@dataclass
class _ProcessLease:
    pid: int
    pidfd: _FdLease
    start_time: int
    session: int
    process_group: int
    executable: tuple[int, int]
    release_gate: _FdLease | None = None
    reaped: bool = False
    descendants: tuple["_ProcessLease", ...] = ()

@dataclass
class _ProcessOwner:
    ops: _LauncherOps
    processes: list[_ProcessLease] = field(default_factory=list)
    poisoned: BaseException | None = None

    def register(self, pid: int, release_gate: _FdLease | None = None) -> _ProcessLease:
        lease = _register_process(pid, self.ops, release_gate)
        self.processes.append(lease)
        return lease

    def release(self, lease: _ProcessLease) -> None:
        gate = lease.release_gate
        if gate is None or gate.state is not _FdState.OWNED:
            raise RuntimeLauncherError("process release gate state", "process-release-gate")
        write = getattr(self.ops, "write", os.write)
        if write(gate.fd, b"G") != 1:
            raise RuntimeLauncherError("process release short write", "process-release-write")
        gate.close(self.ops)

    def stop(self, lease: _ProcessLease, primary: BaseException | None = None) -> None:
        _stop_process(lease, primary, self.ops)
        if lease in self.processes:
            self.processes.remove(lease)

    def cleanup(self, primary: BaseException | None = None) -> None:
        failures: list[BaseException] = []
        for lease in reversed(tuple(self.processes)):
            try:
                self.stop(lease, primary)
            except BaseException as error:
                failures.append(error)
        if failures:
            self.poisoned = RuntimeLauncherCleanupError(primary, failures)
            raise self.poisoned
def _proc_bytes(path: str, bound: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    primary: BaseException | None = None
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            part = os.read(fd, min(65536, bound + 1 - total))
            if not part:
                return b"".join(chunks)
            total += len(part)
            _require(total <= bound, "proc record bound")
            chunks.append(part)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            os.close(fd)
        except OSError as error:
            raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
def _start_time(pid: int) -> int:
    raw = _proc_bytes(f"/proc/{pid}/stat", 8192)
    marker = raw.rfind(b") ")
    _require(marker >= 0 and raw.endswith(b"\n"), "process stat framing")
    fields = raw[marker + 2:-1].split(b" ")
    _require(len(fields) >= 20 and fields[19].isdigit(), "process stat fields")
    return int(fields[19])
def _exe_identity(pid: int) -> tuple[int, int]:
    fd = os.open(f"/proc/{pid}/exe", os.O_PATH | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)
def _register_process(
    pid: int,
    ops: _LauncherOps | None = None,
    release_gate: _FdLease | None = None,
) -> _ProcessLease:
    actual_ops = ops or _SystemOps()
    pidfd = _FdLease(os.pidfd_open(pid, 0), f"pidfd:{pid}")
    try:
        return _ProcessLease(
            pid,
            pidfd,
            _start_time(pid),
            os.getsid(pid),
            os.getpgid(pid),
            _exe_identity(pid),
            release_gate,
        )
    except BaseException as primary:
        try:
            pidfd.close(actual_ops)
        except BaseException as cleanup:
            raise RuntimeLauncherCleanupError(primary, [cleanup]) from primary
        raise
def _process_matches(lease: _ProcessLease) -> bool:
    try:
        return (
            _start_time(lease.pid) == lease.start_time
            and os.getsid(lease.pid) == lease.session
            and os.getpgid(lease.pid) == lease.process_group
            and _exe_identity(lease.pid) == lease.executable
        )
    except (OSError, RuntimeLauncherError):
        return False
def _wait_bounded(lease: _ProcessLease, deadline: float) -> int | None:
    while time.monotonic() < deadline:
        observed, status = os.waitpid(lease.pid, os.WNOHANG)
        if observed == lease.pid:
            lease.reaped = True
            return status
        if observed != 0:
            raise RuntimeLauncherCleanupError(None, [RuntimeLauncherError("unexpected wait result")])
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    return None
def _stop_process(
    lease: _ProcessLease,
    primary: BaseException | None,
    ops: _LauncherOps | None = None,
) -> None:
    actual_ops = ops or _SystemOps()
    failures: list[BaseException] = []
    if not lease.reaped:
        try:
            if not _process_matches(lease):
                raise RuntimeLauncherError("owned process identity uncertain before TERM")
            signal.pidfd_send_signal(lease.pidfd.fd, signal.SIGTERM)
            if _wait_bounded(lease, time.monotonic() + _TERM_SECONDS) is None:
                if not _process_matches(lease):
                    raise RuntimeLauncherError("owned process identity uncertain before KILL")
                signal.pidfd_send_signal(lease.pidfd.fd, signal.SIGKILL)
                if _wait_bounded(lease, time.monotonic() + _KILL_SECONDS) is None:
                    raise RuntimeLauncherError("owned process reap deadline")
        except BaseException as error:
            failures.append(error)
    if lease.reaped and lease.pidfd.state is _FdState.OWNED:
        try:
            lease.pidfd.close(actual_ops)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
def _consume_issuance(endpoint: socket.socket, nonce: bytes, admission: _SourceAdmission, issuer_pid: int,
                      ) -> tuple[dict[str, object], tuple[int, ...], tuple[_GenerationRow, ...], _IssuanceReceipt]:
    ancillary_bound = socket.CMSG_SPACE(_MAX_OBJECTS * array("i").itemsize) + socket.CMSG_SPACE(struct.calcsize("3i"))
    raw, ancillary, flags, _address = endpoint.recvmsg(_MAX_PACKET, ancillary_bound, socket.MSG_CMSG_CLOEXEC)
    credentials, descriptors = _credentials(ancillary)
    expected_credentials = (issuer_pid, os.getuid(), os.getgid())
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or credentials != expected_credentials:
        for fd in descriptors:
            os.close(fd)
        raise RuntimeLauncherError("handoff packet authority/truncation")
    try:
        packet = _strict_json(raw, False, _MAX_PACKET, "handoff packet")
        keys = {"binding_sha256", "closure_sha256", "descriptor_count", "generation_rows", "generation_sha256",
                "nonce", "report_sha256", "revision", "source_set_sha256", "version"}
        _require(type(packet) is dict and set(packet) == keys, "handoff packet shape")
        _require(packet["version"] == _HANDOFF_VERSION and packet["nonce"] == nonce.hex(), "handoff nonce/version")
        bound_admission = packet["revision"] == admission.revision and packet["source_set_sha256"] == admission.source_set_sha256
        _require(bound_admission, "handoff admission binding")
        _require(packet["descriptor_count"] == len(descriptors), "handoff descriptor count")
        rows = _rows_from_packet(packet["generation_rows"])
        report_bytes = _inspect_fd(descriptors[0], True, None, packet["report_sha256"])
        report, binding_sha, generation_sha = _verify_bundle(admission, report_bytes, descriptors, rows)
        _require(packet["closure_sha256"] == report["closure_sha256"], "handoff closure digest")
        _require(packet["binding_sha256"] == binding_sha and packet["generation_sha256"] == generation_sha, "handoff table digest")
        ack = {"binding_sha256": binding_sha, "consumer_pid": os.getpid(),
               "generation_sha256": generation_sha, "nonce": nonce.hex(),
               "report_sha256": packet["report_sha256"], "version": _RECEIPT_VERSION}
        ack_bytes = _canonical(ack)
        sent = endpoint.send(ack_bytes)
        _require(sent == len(ack_bytes), "issuance acknowledgement partial")
        endpoint.shutdown(socket.SHUT_WR)
        trailing = endpoint.recv(1)
        _require(trailing == b"", "second issuer packet", "issuer-second-packet")
        receipt = _IssuanceReceipt(_RECEIPT_VERSION, packet["report_sha256"], report["closure_sha256"],
                                   binding_sha, generation_sha, len(descriptors), issuer_pid, os.getpid())
        return report, descriptors, rows, receipt
    except BaseException:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
def _mkdir_exact(path: str, mode: int) -> None:
    os.mkdir(path, mode)
    info = os.lstat(path)
    _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode, "private root directory mismatch")
def _copy_bound_object(source_fd: int, target: str, row: _GenerationRow) -> None:
    data = _inspect_fd(source_fd, False, row.size, row.sha256)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    target_fd = os.open(target, flags, 0o500)
    primary: BaseException | None = None
    try:
        offset = 0
        while offset < len(data):
            written = os.write(target_fd, data[offset:offset + _IO_CHUNK])
            if written <= 0:
                raise RuntimeLauncherError("private root short write")
            offset += written
        os.fsync(target_fd)
        os.fchmod(target_fd, 0o555)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            os.close(target_fd)
        except OSError as error:
            raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    read_fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(read_fd)
        _require(stat.S_IMODE(info.st_mode) == 0o555, "materialized mode")
        data = _read_complete(read_fd, info.st_size, _MAX_OBJECT)
        _require(hashlib.sha256(data).hexdigest() == row.sha256, "materialized digest")
    finally:
        os.close(read_fd)
def _materialize_root(ops: _SystemOps, role: str, descriptors: tuple[int, ...],
                      rows: tuple[_GenerationRow, ...], report: dict[str, object]) -> str:
    root = f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    _mkdir_exact(root, 0o700)
    ops.mount(b"tmpfs", root.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV, b"mode=0700,size=536870912,nr_inodes=512")
    for relative, mode in (("bin", 0o755), ("lib64", 0o755), ("lib", 0o755), ("lib/x86_64-linux-gnu", 0o755)):
        _mkdir_exact(f"{root}/{relative}", mode)
    selected = [row for row in rows if row.tool_index == _TOOL_INDEX[role]]
    objects = report["tools"][_TOOL_INDEX[role]]["objects"]
    _require(len(selected) == len(objects), "private root row cardinality")
    announced: set[str] = set()
    for row, item in zip(selected, objects):
        if row.object_index == 0:
            target, step = f"{root}/bin/{role}", "root.copy-executable"
        elif row.object_index == 1:
            target, step = root + _INTERPRETER, "root.copy-loader"
        else:
            target, step = f"{root}{_LIBRARY_ROOT}/{item['soname']}", "root.copy-libraries"
        if step not in announced:
            announced.add(step)
        _copy_bound_object(descriptors[row.descriptor_index], target, row)
    return root
def _write_map(path: str, value: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if os.write(fd, value) != len(value):
            raise RuntimeLauncherUnavailable("namespace identity map short write")
    finally:
        os.close(fd)
def _enter_boundary(ops: _SystemOps, root: str) -> dict[str, object]:
    ops.chroot(root.encode())
    os.chdir("/")
    ops.prctl(_PR_SET_DUMPABLE, 0)
    ops.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL)
    ops.drop_bounding()
    ops.prctl(_PR_SET_SECUREBITS, _SECBITS)
    ops.capset_zero()
    capabilities_zero = ops.capget_zero()
    _require(capabilities_zero, "capability sets are not zero", "capability-readback")
    securebits = ops.prctl(_PR_GET_SECUREBITS)
    _require(securebits == _SECBITS, "noroot securebits are not locked", "securebits-readback")
    ops.prctl(_PR_SET_NO_NEW_PRIVS, 1)
    no_new_privs = ops.prctl(_PR_GET_NO_NEW_PRIVS)
    _require(no_new_privs == 1, "no_new_privs not set", "nnp-readback")
    program_digest = ops.install_seccomp()
    mode = ops.seccomp_mode()
    denials = ops.probe_seccomp_denials()
    return {
        "capabilities_zero": capabilities_zero,
        "noroot_locked": securebits == _SECBITS,
        "no_new_privs": no_new_privs == 1,
        "seccomp_denials": denials,
        "seccomp_mode": mode,
        "seccomp_program_sha256": program_digest,
    }
def _child_fd_install(
    ops: _SystemOps,
    descriptors: tuple[int, ...],
    rows: tuple[_GenerationRow, ...],
    input_fd: int,
    output_fd: int,
    role: str,
    exec_status_fd: int,
    root: str,
    status: socket.socket,
) -> None:
    tool_index = _TOOL_INDEX[role]
    descriptor_index = next(
        row.descriptor_index
        for row in rows
        if row.tool_index == tool_index and row.object_index == 0
    )
    executable_copy = fcntl.fcntl(
        descriptors[descriptor_index],
        fcntl.F_DUPFD_CLOEXEC,
        256,
    )
    input_copy = fcntl.fcntl(input_fd, fcntl.F_DUPFD_CLOEXEC, 256)
    output_copy = fcntl.fcntl(output_fd, fcntl.F_DUPFD_CLOEXEC, 256)
    os.dup2(executable_copy, 198, inheritable=False)
    os.dup2(input_copy, 0, inheritable=True)
    os.dup2(output_copy, 1, inheritable=True)
    os.dup2(output_copy, 2, inheritable=True)
    observations = _enter_boundary(ops, root)
    status.send(_canonical({
        "event": "boundary", "observations": observations, "version": _RESULT_VERSION,
    }))
    allowed = {0, 1, 2, 198, exec_status_fd}
    cursor = 3
    for fd in sorted(value for value in allowed if value >= 3):
        if cursor < fd:
            ops.close_range(cursor, fd - 1)
        cursor = fd + 1
    ops.close_range(cursor, _UINT_MAX)
    ops.execveat(198, role)
def _namespace_owner(role: str, descriptors: tuple[int, ...], rows: tuple[_GenerationRow, ...],
                     report: dict[str, object], input_fd: int, output_fd: int, status_fd: int) -> NoReturn:
    status = socket.socket(fileno=status_fd)
    ops = _SystemOps()
    root: str | None = None
    child_owner = _ProcessOwner(ops)
    child_lease: _ProcessLease | None = None
    try:
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        original_uid = os.getuid()
        original_gid = os.getgid()
        os.setgroups([])
        ops.unshare_boundary()
        try:
            _write_map("/proc/self/setgroups", b"deny\n")
        except FileNotFoundError:
            pass
        _write_map("/proc/self/uid_map", f"0 {original_uid} 1\n".encode())
        _write_map("/proc/self/gid_map", f"0 {original_gid} 1\n".encode())
        ops.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None)
        root = _materialize_root(ops, role, descriptors, rows, report)
        release_read, release_write = os.pipe2(os.O_CLOEXEC)
        exec_status_read, exec_status_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            os.close(release_write)
            os.close(exec_status_read)
            try:
                if os.read(release_read, 1) != b"G":
                    raise RuntimeLauncherError("child release gate", "child-release")
                os.close(release_read)
                ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
                _child_fd_install(
                    ops, descriptors, rows, input_fd, output_fd, role,
                    exec_status_write, root, status,
                )
            except BaseException as error:
                code = getattr(error, "code", "child-setup")
                try:
                    os.write(exec_status_write, (code[:126] + "\n").encode())
                finally:
                    os._exit(126)
        os.close(release_read)
        os.close(exec_status_write)
        release_lease = _FdLease(release_write, "child-release")
        child_lease = child_owner.register(child, release_lease)
        child_owner.release(child_lease)
        status.send(_canonical({"event": "child", "pid": child, "version": _RESULT_VERSION}))
        ready, _write, _error = select.select([exec_status_read], [], [], _SETUP_SECONDS)
        if not ready:
            raise RuntimeLauncherError("exec status timeout", "exec-status-timeout")
        exec_status = os.read(exec_status_read, 128)
        os.close(exec_status_read)
        if exec_status:
            raise RuntimeLauncherError("exec setup failed", "exec-status-bytes")
        status.send(_canonical({"event": "exec-ready", "version": _RESULT_VERSION}))
        command = _recv_status(status, time.monotonic() + _SETUP_SECONDS)
        if command.get("event") != "finalize-root":
            raise RuntimeLauncherError("root finalization command", "root-finalize-command")
        final_flags = _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        ops.mount(None, root.encode(), None, final_flags, None)
        status.send(_canonical({"event": "root-final", "version": _RESULT_VERSION}))
        wait_status = _wait_bounded(child_lease, time.monotonic() + _RUN_SECONDS)
        if wait_status is None:
            raise RuntimeLauncherError("namespace child deadline", "child-reap-deadline")
        child_owner.stop(child_lease)
        child_lease = None
        ops.umount(root.encode())
        os.rmdir(root)
        root = None
        status.send(_canonical({"event": "exit", "status": wait_status, "version": _RESULT_VERSION}))
        os._exit(0)
    except BaseException as error:
        try:
            status.send(_canonical({"event": "error", "kind": type(error).__name__, "version": _RESULT_VERSION}))
        except BaseException:
            pass
        if child_lease is not None:
            try:
                child_owner.stop(child_lease, error)
            except BaseException:
                pass
        if root is not None:
            try:
                ops.umount(root.encode())
                os.rmdir(root)
            except BaseException:
                pass
        os._exit(125)
def _maps_snapshot(pid: int) -> bytes:
    raw = _proc_bytes(f"/proc/{pid}/maps", _MAX_MAPS)
    _require(raw.endswith(b"\n") and raw.count(b"\n") <= _MAX_MAP_LINES, "final maps framing/bound")
    return raw
def _final_mapping_check(
    ops: _SystemOps,
    pid: int,
    rows: tuple[_GenerationRow, ...],
    role: str,
    report: dict[str, object],
) -> bytes:
    first = _maps_snapshot(pid)
    expected_rows = [row for row in rows if row.tool_index == _TOOL_INDEX[role]]
    expected = {(row.role, row.sha256) for row in expected_rows}
    observed: set[tuple[str, str]] = set()
    digest_roles = {row.sha256: row.role for row in expected_rows}
    for line in first.splitlines():
        fields = line.split(None, 5)
        _require(len(fields) >= 5 and len(fields[0].split(b"-")) == 2, "final maps row")
        permissions = fields[1]
        inode = fields[4]
        path = fields[5] if len(fields) == 6 else b""
        if b"x" not in permissions:
            continue
        if inode == b"0":
            if path not in (b"[vdso]", b"[vsyscall]"):
                raise RuntimeLauncherError("unknown executable synthetic mapping")
            continue
        start, end = fields[0].split(b"-")
        map_fd = os.open(
            f"/proc/{pid}/map_files/{start.decode()}-{end.decode()}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        try:
            info = os.fstat(map_fd)
            data = _read_complete(map_fd, info.st_size, _MAX_OBJECT)
        finally:
            os.close(map_fd)
        digest = hashlib.sha256(data).hexdigest()
        _require(digest in digest_roles, "final mapping closure expansion")
        observed.add((digest_roles[digest], digest))
    second = _maps_snapshot(pid)
    _require(first == second and observed == expected, "final mapped generation equality")
    objects = report["tools"][_TOOL_INDEX[role]]["objects"]
    if _digest([[item["role"], item["sha256"]] for item in objects]) != report["tools"][_TOOL_INDEX[role]]["mapping_sha256"]:
        raise RuntimeLauncherError("final mapping digest", "mapping-report-digest")
    return first

def _final_mount_check(pid: int) -> tuple[bool, bool]:
    raw = _proc_bytes(f"/proc/{pid}/mountinfo", _MAX_MAPS)
    _require(raw.endswith(b"\n"), "mountinfo framing", "mountinfo-framing")
    root_exact = False
    no_proc = True
    for line in raw.splitlines():
        fields = line.split(b" ")
        _require(b"-" in fields and len(fields) >= 10,
                 "mountinfo record", "mountinfo-record")
        separator = fields.index(b"-")
        _require(separator + 3 < len(fields), "mountinfo shape", "mountinfo-shape")
        mountpoint = fields[4]
        options = set(fields[5].split(b","))
        filesystem = fields[separator + 1]
        if filesystem == b"proc":
            no_proc = False
        if mountpoint == b"/":
            required = {b"ro", b"nosuid", b"nodev", b"noexec"}
            root_exact = required <= options
    _require(root_exact, "root mount is not read-only noexec", "root-final-flags")
    _require(no_proc, "sandbox root contains proc", "root-proc-present")
    return root_exact, no_proc
def _namespace_facts(pid: int) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name, fact in (
        ("user", "user_namespace_exact"),
        ("pid", "pid_namespace_exact"),
        ("mnt", "mount_namespace_exact"),
        ("net", "network_namespace_exact"),
    ):
        baseline = os.stat(f"/proc/self/ns/{name}")
        observed = os.stat(f"/proc/{pid}/ns/{name}")
        result[fact] = (baseline.st_dev, baseline.st_ino) != (observed.st_dev, observed.st_ino)
    status = _proc_bytes(f"/proc/{pid}/status", 65536)
    nspid_rows = [line for line in status.splitlines() if line.startswith(b"NSpid:\t")]
    _require(len(nspid_rows) == 1, "NSpid cardinality", "pid-one-record")
    identities = nspid_rows[0].split(b"\t")[1:]
    result["pid_one"] = bool(identities) and identities[-1] == b"1"
    uid_map = _proc_bytes(f"/proc/{pid}/uid_map", 4096)
    gid_map = _proc_bytes(f"/proc/{pid}/gid_map", 4096)
    result["user_namespace_exact"] = result["user_namespace_exact"] and (
        len(uid_map.splitlines()) == 1 and len(gid_map.splitlines()) == 1
    )
    return result

def _recv_status(endpoint: socket.socket, deadline: float) -> dict[str, object]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeLauncherError("sandbox status deadline")
    ready, _write, _error = select.select([endpoint], [], [], remaining)
    if not ready:
        raise RuntimeLauncherError("sandbox status deadline")
    raw = endpoint.recv(4096)
    value = _strict_json(raw, False, 4096, "sandbox status")
    _require(type(value) is dict and value.get("version") == _RESULT_VERSION, "sandbox status shape")
    return value
def _run_tool_with_ops(
    ops: _SystemOps,
    role: str,
    report: dict[str, object],
    descriptors: tuple[int, ...],
    rows: tuple[_GenerationRow, ...],
) -> tuple[bytes, dict[str, object]]:
    input_read, input_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    parent_status, child_status = ops.socketpair()
    lease: _ProcessLease | None = None
    primary: BaseException | None = None
    failures: list[BaseException] = []
    namespace_pid = -1
    try:
        pid = os.fork()
        if pid == 0:
            parent_status.close()
            os.close(input_write)
            os.close(output_read)
            _namespace_owner(role, descriptors, rows, report, input_read, output_write, child_status.detach())
        child_status.close()
        os.close(input_read)
        input_read = -1
        os.close(output_write)
        output_write = -1
        lease = _register_process(pid)
        first = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS)
        if first.get("event") != "child" or type(first.get("pid")) is not int:
            raise RuntimeLauncherError("sandbox child creation status")
        namespace_pid = first["pid"]
        child_lease = _register_process(namespace_pid, ops)
        boundary = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS)
        if boundary.get("event") != "boundary":
            raise RuntimeLauncherError("boundary observations missing", "boundary-status")
        observations = boundary.get("observations")
        if type(observations) is not dict:
            raise RuntimeLauncherError("boundary observations malformed", "boundary-observations")
        exec_ready = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS)
        if exec_ready.get("event") != "exec-ready":
            raise RuntimeLauncherError("exec readiness missing", "exec-ready")
        post_fds = _descriptor_snapshot(ops, namespace_pid)
        _require(post_fds == (0, 1, 2), "post-exec descriptor table", "exec-fd-table")
        post_maps = _final_mapping_check(ops, namespace_pid, rows, role, report)
        command = _canonical({"event": "finalize-root", "version": _RESULT_VERSION})
        _require(parent_status.send(command) == len(command),
                 "root finalization send", "root-finalize-send")
        root_final = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS)
        if root_final.get("event") != "root-final":
            raise RuntimeLauncherError("root finalization missing", "root-final-status")
        root_exact, no_proc = _final_mount_check(namespace_pid)
        namespace_facts = _namespace_facts(namespace_pid)
        final_fds = _descriptor_snapshot(ops, namespace_pid)
        _require(final_fds == post_fds, "final descriptor drift", "final-fd-drift")
        final_maps = _final_mapping_check(ops, namespace_pid, rows, role, report)
        _require(final_maps == post_maps, "final mapping drift", "final-map-drift")
        payload = _FIXED_INPUT[role]
        offset = 0
        while offset < len(payload):
            written = os.write(input_write, payload[offset:])
            if written <= 0:
                raise RuntimeLauncherError("fixed input short write")
            offset += written
        os.close(input_write)
        input_write = -1
        output = bytearray()
        deadline = time.monotonic() + _RUN_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeLauncherError("fixed output deadline")
            ready, _write, _error = select.select([output_read], [], [], remaining)
            if not ready:
                raise RuntimeLauncherError("fixed output deadline")
            part = os.read(output_read, 65536)
            if not part:
                break
            output += part
            if len(output) > _MAX_OUTPUT:
                raise RuntimeLauncherError("fixed output bound")
        os.close(output_read)
        output_read = -1
        final = _recv_status(parent_status, deadline)
        if final.get("event") != "exit" or final.get("status") != 0:
            raise RuntimeLauncherError("sandbox child exit")
        child_lease.reaped = True
        child_lease.pidfd.close(ops)
        status = _wait_bounded(lease, deadline)
        if status != 0:
            raise RuntimeLauncherError("namespace owner exit")
        if bytes(output) != _FIXED_OUTPUT:
            raise RuntimeLauncherError("fixed output mismatch")
        denial_values = observations.get("seccomp_denials", {})
        acquisition_closed = (
            final_fds == (0, 1, 2)
            and root_exact
            and no_proc
            and type(denial_values) is dict
            and denial_values.get("execve") == errno.EPERM
            and denial_values.get("memfd_create") == errno.EPERM
        )
        return bytes(output), {
            "boundary": observations,
            "exec_descriptor_consumed": 198 not in final_fds,
            "fd_table": final_fds,
            "mapped_generations_exact": bool(final_maps),
            "maps": final_maps,
            "no_acquisition_route": acquisition_closed,
            "root_has_no_proc": no_proc,
            "root_readonly_noexec": root_exact,
            **namespace_facts,
        }
    except BaseException as error:
        primary = error
        raise
    finally:
        for fd in (input_read, input_write, output_read, output_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as error:
                    failures.append(error)
        try:
            parent_status.close()
        except OSError as error:
            failures.append(error)
        try:
            child_status.close()
        except OSError:
            pass
        if lease is not None:
            try:
                if not lease.reaped:
                    _stop_process(lease, primary)
                else:
                    os.close(lease.pidfd)
            except BaseException as error:
                failures.append(error)
        if namespace_pid > 0:
            try:
                os.waitpid(namespace_pid, os.WNOHANG)
            except ChildProcessError:
                pass
        if failures:
            raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
def _worker_main(
    endpoint_fd: int,
    release_fd: int,
    nonce: bytes,
    admission: _SourceAdmission,
    closure_module: types.ModuleType,
    consumer_pid: int,
) -> NoReturn:
    if os.read(release_fd, 1) != b"G":
        os._exit(123)
    os.close(release_fd)
    endpoint = socket.socket(fileno=endpoint_fd)
    owner: object | None = None
    try:
        _SystemOps().prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        package_name = str(closure_module.__package__)
        admission._package = package_name
        admission._worker_pid = os.getpid()
        admission._endpoint = endpoint
        admission._consumer_pid = consumer_pid
        admission._consumer_uid = os.getuid()
        admission._consumer_gid = os.getgid()
        issuer = _WorkerIssuer(
            endpoint,
            nonce,
            admission,
            consumer_pid,
            package_name,
        )
        admission._issuer = issuer
        constructor = getattr(closure_module, "_prepare_admitted_fixed_runtime_closure", None)
        _require(callable(constructor), "admitted closure constructor missing")
        owner = constructor(admission, issuer)
        issue = getattr(owner, "_issue_once", None)
        _require(callable(issue), "admitted closure issuer missing")
        receipt = issue(issuer)
        _require(type(receipt) is _IssuanceReceipt, "closure issuance receipt mismatch")
        close = getattr(owner, "close", None)
        _require(callable(close), "closure owner close missing")
        close()
        owner = None
        os._exit(0)
    except BaseException:
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                pass
        os._exit(124)
def _recover_transaction_with_ops(
    ops: _LauncherOps,
    process_owner: _ProcessOwner,
    fd_leases: list[_FdLease],
    primary: BaseException | None,
) -> None:
    failures: list[BaseException] = []
    try:
        process_owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    try:
        _close_leases(ops, fd_leases, primary)
    except BaseException as error:
        failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])

def _coordinate_with_ops(
    admission: _SourceAdmission,
    closure_module: types.ModuleType,
    ops: _SystemOps,
) -> RuntimeQualificationResult:
    fact_names = tuple(RuntimeQualificationResult.__dataclass_fields__)[7:]
    facts = _ObservedFacts(fact_names)
    baseline = _descriptor_snapshot(ops)
    child_baseline = _proc_bytes("/proc/self/task/self/children", 65536)
    nonce = ops.nonce()
    parent_endpoint, worker_endpoint = ops.socketpair()
    release_read, release_write = os.pipe2(os.O_CLOEXEC)
    process_owner = _ProcessOwner(ops)
    fd_leases: list[_FdLease] = [_FdLease(release_write, "worker-release")]
    descriptor_leases: list[_FdLease] = []
    primary: BaseException | None = None
    receipt: _IssuanceReceipt | None = None
    try:
        pid = os.fork()
        if pid == 0:
            os.close(release_write)
            parent_endpoint.close()
            _worker_main(
                worker_endpoint.detach(),
                release_read,
                nonce,
                admission,
                closure_module,
                os.getppid(),
            )
        os.close(release_read)
        worker_endpoint.close()
        worker = process_owner.register(pid, fd_leases[0])
        process_owner.release(worker)
        report, descriptors, rows, receipt = _consume_issuance(
            parent_endpoint, nonce, admission, pid,
        )
        descriptor_leases = [_FdLease(fd, "issued-object") for fd in descriptors]
        gzip_output, gzip_observed = _run_tool_with_ops(
            ops, "gzip", report, descriptors, rows,
        )
        zstd_output, zstd_observed = _run_tool_with_ops(
            ops, "zstd", report, descriptors, rows,
        )
        status = _wait_bounded(worker, time.monotonic() + _SETUP_SECONDS)
        _require(status == 0, "closure worker exit", "worker-exit")
        process_owner.stop(worker)
        _close_leases(ops, descriptor_leases)
        descriptor_leases.clear()
        parent_endpoint.close()
        boundary = gzip_observed["boundary"]
        _require(boundary == zstd_observed["boundary"], "boundary observation drift", "boundary-drift")
        facts.observe(
            "mapped_generations_exact",
            gzip_observed["mapped_generations_exact"]
            and zstd_observed["mapped_generations_exact"],
            True,
        )
        for name in ("user_namespace_exact", "pid_namespace_exact",
                     "mount_namespace_exact", "network_namespace_exact", "pid_one"):
            facts.observe(name, gzip_observed[name] and zstd_observed[name], True)
        facts.observe("capabilities_zero", boundary["capabilities_zero"], True)
        facts.observe("noroot_locked", boundary["noroot_locked"], True)
        facts.observe("no_new_privs", boundary["no_new_privs"], True)
        facts.observe("seccomp_installed", bool(boundary["seccomp_program_sha256"]), True)
        facts.observe("seccomp_mode_exact", boundary["seccomp_mode"], _SECCOMP_MODE_FILTER)
        facts.observe("seccomp_program_exact", boundary["seccomp_program_sha256"], _seccomp_digest())
        denials = boundary["seccomp_denials"]
        facts.observe("seccomp_denials_exact", set(denials) == {"execve", "socket", "memfd_create", "seccomp"} and set(denials.values()) == {errno.EPERM}, True)
        facts.observe("exec_descriptor_consumed", gzip_observed["exec_descriptor_consumed"] and zstd_observed["exec_descriptor_consumed"], True)
        facts.observe("no_acquisition_route", gzip_observed["no_acquisition_route"] and zstd_observed["no_acquisition_route"], True)
        facts.observe("root_readonly_noexec", gzip_observed["root_readonly_noexec"] and zstd_observed["root_readonly_noexec"], True)
        facts.observe("root_has_no_proc", gzip_observed["root_has_no_proc"] and zstd_observed["root_has_no_proc"], True)
        children = _proc_bytes("/proc/self/task/self/children", 65536)
        facts.observe("children_reaped", children, child_baseline)
        facts.observe("descendants_reaped", not process_owner.processes, True)
        facts.observe("descriptors_restored", _descriptor_snapshot(ops), baseline)
        root = f"{_ROOT_PARENT}/{_ROOT_LEAF}"
        facts.observe("mounts_restored", not os.path.ismount(root), True)
        facts.observe("paths_restored", not os.path.lexists(root), True)
        facts.observe("namespaces_released", not process_owner.processes, True)
        facts.complete()
        if receipt is None:
            raise RuntimeLauncherError("issuance receipt missing", "receipt-missing")
        return RuntimeQualificationResult(
            _RESULT_VERSION,
            _MARKER,
            admission.revision,
            admission.source_set_sha256,
            receipt.closure_sha256,
            hashlib.sha256(gzip_output).hexdigest(),
            hashlib.sha256(zstd_output).hexdigest(),
            *(facts.value(name) for name in fact_names),
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        fd_leases.extend(descriptor_leases)
        if primary is not None or process_owner.processes or fd_leases:
            _recover_transaction_with_ops(ops, process_owner, fd_leases, primary)
def _open_beneath(root_fd: int, path: str) -> int:
    components = path.split("/")
    _require(bool(components) and not any(not item or item in (".", "..") for item in components), "fixed source path components")
    directory = os.dup(root_fd)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = next_fd
            info = os.fstat(directory)
            secure = stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            _require(secure, "fixed source ancestor policy")
        return os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
def _held_sources(root_fd: int) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    for path in _FIXED_SOURCE_SET:
        fd = _open_beneath(root_fd, path)
        primary: BaseException | None = None
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o644, "fixed source file policy")
            data = _read_complete(fd, before.st_size, _MAX_SOURCE)
            after = os.fstat(fd)
            _require(_stat_identity(before) == _stat_identity(after), "fixed source generation drift")
            sources[path] = data
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                os.close(fd)
            except OSError as error:
                raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    return sources
def _git_tree(root_fd: int, revision: str) -> dict[str, tuple[str, str]]:
    arguments = (
        "/usr/bin/git", "-C", f"/proc/self/fd/{root_fd}", "-c", "core.hooksPath=/dev/null",
        "ls-tree", "-rz", "--full-tree", revision, "--", *_FIXED_SOURCE_SET,
    )
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C",
    }
    try:
        completed = __import__("subprocess").run(
            arguments, env=environment, stdin=-3, stdout=-1, stderr=-1,
            pass_fds=(root_fd,), close_fds=True, timeout=5, check=False,
        )
    except BaseException as error:
        raise RuntimeLauncherError("fixed git tree authentication failed") from error
    _require(not completed.returncode and not completed.stderr and len(completed.stdout) <= 16384, "fixed git tree authentication rejected")
    result: dict[str, tuple[str, str]] = {}
    for row in completed.stdout.split(b"\0"):
        if not row:
            continue
        try:
            header, raw_path = row.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8", "strict")
        except (ValueError, UnicodeError) as error:
            raise RuntimeLauncherError("fixed git tree row") from error
        _require(path not in result and mode == "100644" and kind == "blob", "fixed git tree identity")
        result[path] = mode, oid
    return result
def _source_set_digest(sources: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path in _FIXED_SOURCE_SET:
        encoded = path.encode()
        data = sources[path]
        framed = struct.pack("!I", len(encoded)) + encoded + struct.pack("!Q", len(data))
        digest.update(framed + hashlib.sha256(data).digest())
    return digest.hexdigest()
def _authenticate_sources(root_fd: int, admission: dict[str, object]) -> dict[str, bytes]:
    sources = _held_sources(root_fd)
    tree = _git_tree(root_fd, admission["revision"])
    _require(set(tree) == set(_FIXED_SOURCE_SET), "fixed source tree cardinality")
    for path, data in sources.items():
        oid = tree[path][1]
        _require(len(oid) in (40, 64) and all(character in "0123456789abcdef" for character in oid), "fixed source blob object id")
        algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
        blob = b"blob " + str(len(data)).encode() + b"\0" + data
        _require(algorithm(blob).hexdigest() == oid, "fixed source blob mismatch")
    digest = _source_set_digest(sources)
    _require(digest == admission["source_set_sha256"], "fixed source-set digest mismatch")
    launcher = sources[_MODULE_PATHS[2]]
    _require(hashlib.sha256(launcher).hexdigest() == admission["bootstrap_sha256"], "externally asserted bootstrap digest mismatch")
    return sources
def _load_private_closure(sources: dict[str, bytes], digest: str) -> types.ModuleType:
    package_name = f"_cogs_o2_{digest[:16]}"
    package = types.ModuleType(package_name)
    package.__path__ = ()
    sys.modules[package_name] = package
    modules: list[types.ModuleType] = []
    for logical, path in zip(("completion_elf", "completion_trusted_runtime_closure"), _MODULE_PATHS[:2]):
        name = f"{package_name}.{logical}"
        module = types.ModuleType(name)
        module.__package__ = package_name
        module.__file__ = f"cogs-fixed:{digest}/{logical}"
        module.__spec__ = __import__("importlib.machinery").machinery.ModuleSpec(name, loader=None, origin=module.__file__)
        module.__dict__["_ADMISSION_TYPE"] = _SourceAdmission
        sys.modules[name] = module
        modules.append(module)
    for module, path in zip(modules, _MODULE_PATHS):
        code = compile(sources[path], module.__file__, "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    return modules[1]
def _bootstrap_with_ops(ops: _SystemOps, request: object = None) -> int:
    del request
    _platform_gate()
    if len(sys.argv) != 1 or os.environ or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise RuntimeLauncherError("fixed bootstrap process envelope")
    executable = _FdLease(
        os.open("/proc/self/exe", os.O_PATH | os.O_CLOEXEC), "python-executable",
    )
    admitted = _FdLease(
        os.open("/usr/bin/python3", os.O_PATH | os.O_CLOEXEC), "admitted-python",
    )
    try:
        executable_identity = _stat_identity(os.fstat(executable.fd))[:2]
        admitted_identity = _stat_identity(os.fstat(admitted.fd))[:2]
        _require(executable_identity == admitted_identity,
                 "fixed Python executable identity", "python-identity")
    finally:
        _close_leases(ops, [executable, admitted])
    baseline = _descriptor_snapshot()
    _require(baseline == (0, 1, 2, 3, 4), "fixed bootstrap descriptor ABI")
    root = os.fstat(4)
    root_secure = stat.S_ISDIR(root.st_mode) and root.st_uid == 0 and not root.st_mode & 0o022
    _require(root_secure, "fixed checkout root authority")
    raw = bytearray()
    while len(raw) <= _MAX_ADMISSION:
        part = os.read(3, _MAX_ADMISSION + 1 - len(raw))
        if not part:
            break
        raw += part
    admission = _strict_json(bytes(raw), True, _MAX_ADMISSION, "source admission")
    expected = {"bootstrap_sha256", "revision", "source_set_sha256", "version"}
    _require(type(admission) is dict and set(admission) == expected and admission["version"] == _ADMISSION_VERSION, "source admission shape")
    _require(_sha(admission["bootstrap_sha256"]) and _sha(admission["source_set_sha256"]), "source admission digest")
    revision = admission["revision"]
    valid_revision = type(revision) is str and len(revision) == 40 and all(character in "0123456789abcdef" for character in revision)
    _require(valid_revision, "source admission revision")
    sources = _authenticate_sources(4, admission)
    os.close(3)
    os.close(4)
    __import__("platform")
    sys.path[:] = []
    closure_module = _load_private_closure(sources, admission["source_set_sha256"])
    source_admission = _SourceAdmission(
        revision, admission["bootstrap_sha256"], admission["source_set_sha256"],
        sources[_SCHEMA_PATH], "", 0, None, None, 0, 0, 0,
    )
    result = _coordinate_with_ops(source_admission, closure_module, ops)
    output = _canonical(result.__dict__, True)
    offset = 0
    while offset < len(output):
        written = os.write(1, output[offset:])
        if written <= 0:
            raise RuntimeLauncherError("result write failed")
        offset += written
    return 0

def _bootstrap_main() -> int:
    return _bootstrap_with_ops(_SystemOps())

if __name__ == "__main__":
    try:
        raise SystemExit(_bootstrap_main())
    except RuntimeLauncherUnavailable:
        os.write(2, b"runtime-launcher-unavailable\n")
        raise SystemExit(78)
    except BaseException:
        os.write(2, b"runtime-launcher-failed\n")
        raise SystemExit(1)
