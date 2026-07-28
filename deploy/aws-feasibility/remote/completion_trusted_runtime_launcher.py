from __future__ import annotations
from array import array
from dataclasses import dataclass, field, make_dataclass
from enum import Enum
import ctypes, errno, fcntl, hashlib, json
import os, re, select, signal, socket
import stat, struct, sys, time, types
from typing import Any, NoReturn, Optional
_VERSION = "cogs.trusted-runtime-closure/v1"
_ADMISSION_VERSION = "cogs.runtime-source-admission/v1"
_HANDOFF_VERSION = "cogs.runtime-handoff/v1"
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
(_PR_SET_CHILD_SUBREAPER, _PR_CAP_AMBIENT, _PR_CAP_AMBIENT_IS_SET) = (36, 47, 1)
_PR_CAP_AMBIENT_CLEAR_ALL, _PR_SET_SECCOMP, _PR_GET_SECCOMP = 4, 22, 21
_SECCOMP_MODE_FILTER, _SECBITS = 2, 0x0F
_AT_EMPTY_PATH, _UINT_MAX = 0x1000, (1 << 32) - 1
(_SYS_GETDENTS64, _SYS_CLONE3, _CLONE_PIDFD) = (217, 435, 0x00001000)
(_NS_GET_USERNS, _NS_GET_PARENT) = (0xB701, 0xB702)
# Complete fixed x86-64 acquisition/authority policy inventory.
_DENIED_SYSCALLS = {
    name: int(number)
    for entry in """
    execve:59 socket:41 connect:42 accept:43 sendto:44 recvfrom:45 sendmsg:46 recvmsg:47 shutdown:48 bind:49 listen:50 getsockname:51 getpeername:52 socketpair:53 setsockopt:54 getsockopt:55 accept4:288 recvmmsg:299 sendmmsg:307
    io_uring_setup:425 io_uring_enter:426 io_uring_register:427 clone:56 fork:57 vfork:58 clone3:435 unshare:272 setns:308
    mount:165 umount2:166 pivot_root:155 chroot:161 open_tree:428 move_mount:429 fsopen:430 fsconfig:431 fsmount:432 fspick:433 mount_setattr:442
    keyctl:250 add_key:248 request_key:249 perf_event_open:298 bpf:321 userfaultfd:323 ptrace:101 init_module:175 delete_module:176 finit_module:313
    setuid:105 setgid:106 setreuid:113 setregid:114 setgroups:116 setresuid:117 setresgid:119 setfsuid:122 setfsgid:123 capset:126 seccomp:317
    memfd_create:319 open_by_handle_at:304 name_to_handle_at:303 pidfd_open:434 pidfd_getfd:438 process_vm_readv:310 process_vm_writev:311 kexec_load:246 kexec_file_load:320 landlock_create_ruleset:444 landlock_add_rule:445 landlock_restrict_self:446 dup:32 dup2:33 dup3:292 fcntl:72
    """.split()
    for name, number in (entry.split(":"),)
}
def _seccomp_program() -> tuple[tuple[int, int, int, int], ...]:
    deny = 0x00050000 | errno.EPERM
    rows = [
        (0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0),
        (0x15, 0, 10, 322), (0x20, 0, 0, 16), (0x15, 0, 6, 198), (0x20, 0, 0, 20), (0x15, 0, 4, 0),
        (0x20, 0, 0, 48), (0x15, 0, 2, _AT_EMPTY_PATH), (0x20, 0, 0, 52), (0x15, 1, 0, 0), (0x06, 0, 0, deny),
        (0x06, 0, 0, 0x7FFF0000), (0x15, 0, 4, 157), (0x20, 0, 0, 16), (0x15, 1, 0, _PR_GET_SECCOMP),
        (0x06, 0, 0, deny), (0x06, 0, 0, 0x7FFF0000), (0x20, 0, 0, 0),
    ]
    for number in dict.fromkeys(_DENIED_SYSCALLS.values()):
        rows.extend(((0x15, 0, 1, number), (0x06, 0, 0, deny)))
    rows.append((0x06, 0, 0, 0x7FFF0000))
    return tuple(rows)
def _seccomp_digest() -> str:
    encoded = b"".join(struct.pack("HBBI", *row) for row in _seccomp_program())
    return hashlib.sha256(encoded).hexdigest()
class RuntimeLauncherError(RuntimeError):
    def __init__(self, message: str, code: str = "launcher-rejected"):
        self.code = code
        super().__init__(message)
class RuntimeLauncherUnavailable(RuntimeLauncherError):
    status = "unavailable"
    def __init__(self, primitive: str, message: str | None = None, claims: dict[str, bool] | None = None, cleanup_restored: bool = False):
        self.primitive = primitive
        self.claims = claims or {}
        self.cleanup_restored = cleanup_restored
        detail = message or f"required primitive unavailable: {primitive}"
        super().__init__(detail, "primitive-unavailable")
class RuntimeLauncherCleanupError(RuntimeLauncherError):
    def __init__(self, primary: BaseException | None, failures: list[BaseException]):
        self.primary = primary
        self.failures = tuple(failures)
        super().__init__(f"launcher cleanup uncertain ({len(failures)} failures)", "cleanup-uncertain")
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
def _close_leases(ops: object, leases: tuple[_FdLease, ...] | list[_FdLease], primary: BaseException | None = None) -> None:
    failures: list[BaseException] = []
    for lease in reversed(tuple(leases)):
        if lease.state is _FdState.CLOSE_UNCERTAIN:
            if lease.close_error is None:
                failures.append(RuntimeLauncherError(
                    "descriptor uncertainty lost", "fd-lease-poison"))
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
    def _consume(self, issuer: object, package: object, worker_pid: object) -> bool:
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
_GenerationRow = make_dataclass("_GenerationRow", [
    ("tool_index", int), ("object_index", int), ("role", str), ("descriptor_index", int), ("size", int), ("sha256", str),
    ("soname", Optional[str]), ("needed", tuple[str, ...]), ("seal_profile", str), ("source_generation", tuple[int, ...]),
], frozen=True, namespace={"__module__": __name__})
_IssuanceReceipt = make_dataclass("_IssuanceReceipt", [*((name, str) for name in "version report_sha256 closure_sha256 binding_sha256 generation_sha256".split()),
    *((name, int) for name in "descriptor_count issuer_pid consumer_pid".split())], frozen=True, namespace={"__module__": __name__})
_RuntimeHelperToken = make_dataclass("_RuntimeHelperToken", [("value", str)], frozen=True, namespace={"__module__": __name__})
_OBSERVATION_NAMES = """
    mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact
    namespace_handles_exact pid_one supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero inheritable_capabilities_zero
    bounding_capabilities_zero ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
    seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route root_readonly_noexec root_has_no_proc
    host_paths_absent checkout_absent limits_exact descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
    namespaces_released namespace_handles_released
""".split()
RuntimeQualificationResult = make_dataclass("RuntimeQualificationResult",
    [(name, str) for name in "version marker source_revision source_set_sha256 closure_sha256 gzip_output_sha256 zstd_output_sha256".split()] + [(name, bool) for name in _OBSERVATION_NAMES], frozen=True, namespace={"__module__": __name__})
def _build_observed_result(tool_observations: tuple[dict[str, object], dict[str, object]], cleanup_observations: dict[str, object]) -> dict[str, bool]:
    cleanup_keys = {"children_reaped", "descendants_reaped", "descriptors_restored",
                    "mounts_restored", "namespace_handles_released", "namespaces_released", "paths_restored"}
    expected = set(_OBSERVATION_NAMES)
    tool_keys = expected - cleanup_keys
    _require(type(tool_observations) is tuple and len(tool_observations) == 2, "tool observation cardinality", "observation-cardinality")
    _require(all(type(item) is dict and set(item) == tool_keys for item in tool_observations), "tool observation closed shape", "observation-shape")
    _require(type(cleanup_observations) is dict and set(cleanup_observations) == cleanup_keys, "cleanup observation closed shape", "cleanup-observation-shape")
    first, second = tool_observations
    _require(first == second, "cross-tool observation drift", "observation-drift")
    combined = {**first, **cleanup_observations}
    _require(all(type(value) is bool and value for value in combined.values()), "qualification observation mismatch", "observation-mismatch")
    _require(set(combined) == expected, "result observation cardinality", "result-observation-shape")
    return combined
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
_JSON_TYPES = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
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
def _descriptor_snapshot(ops: Any | None = None, pid: int | str = "self") -> tuple[int, ...]:
    actual_ops = ops or _SystemOps()
    path = f"/proc/{pid}/fd"
    directory = _FdLease(actual_ops.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), "fd-enumerator")
    values: list[int] = []
    primary: BaseException | None = None
    try:
        while True:
            chunk = actual_ops.getdents(directory.fd)
            if not chunk:
                break
            values.extend(_parse_fd_dirents(chunk))
            _require(len(values) <= 16384, "descriptor snapshot bound", "fd-bound")
        _require(values.count(directory.fd) == (1 if pid == "self" else 0), "descriptor enumerator cardinality", "fd-enumerator-cardinality")
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
class _SystemOps:
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)
    def _checked(self, result: int, name: str) -> int:
        if result == -1:
            saved = ctypes.get_errno()
            if saved in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EINVAL):
                raise RuntimeLauncherUnavailable(name)
            raise OSError(saved, os.strerror(saved))
        return result
    def close(self, fd: int) -> None: os.close(fd)
    def open(self, path: str, flags: int, mode: int = 0o600) -> int: return os.open(path, flags, mode)
    def read(self, fd: int, size: int) -> bytes: return os.read(fd, size)
    def write(self, fd: int, data: bytes) -> int: return os.write(fd, data)
    def clone_pidfd(self) -> tuple[int, int]:
        pidfd = ctypes.c_int(-1)
        values = (ctypes.c_uint64 * 11)(_CLONE_PIDFD, ctypes.addressof(pidfd), 0, 0, signal.SIGCHLD, 0, 0, 0, 0, 0, 0)
        pid = self._checked(self.libc.syscall(_SYS_CLONE3, ctypes.byref(values), ctypes.sizeof(values)), "clone3")
        if pid > 0 and pidfd.value < 0:
            raise RuntimeLauncherUnavailable("clone3-pidfd")
        return pid, pidfd.value
    def getdents(self, fd: int, maximum: int = 32768) -> bytes:
        buffer = ctypes.create_string_buffer(maximum)
        count = self._checked(self.libc.syscall(_SYS_GETDENTS64, fd, ctypes.byref(buffer), maximum), "getdents64")
        return bytes(buffer.raw[:count])
    def socketpair(self) -> tuple[socket.socket, socket.socket]:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return left, right
    def nonce(self) -> bytes:
        value = os.getrandom(32)
        if len(value) != 32: raise RuntimeLauncherUnavailable("getrandom")
        return value
    def unshare_boundary(self) -> None:
        self._checked(self.libc.unshare(_CLONE_NEWUSER | _CLONE_NEWNS | _CLONE_NEWPID | _CLONE_NEWNET), "unshare")
    def mount(self, source: bytes | None, target: bytes, kind: bytes | None, flags: int, data: bytes | None) -> None:
        self._checked(self.libc.mount(source, target, kind, flags, data), "mount")
    def umount(self, target: bytes) -> None: self._checked(self.libc.umount2(target, 0), "umount2")
    def chroot(self, root: bytes) -> None: self._checked(self.libc.chroot(root), "chroot")
    def prctl(self, option: int, value: int = 0, arg3: int = 0) -> int:
        return self._checked(self.libc.prctl(option, value, arg3, 0, 0), "prctl")
    def capset_zero(self) -> None:
        header = (ctypes.c_uint32 * 2)(0x20080522, 0)
        self._checked(self.libc.syscall(126, header, (ctypes.c_uint32 * 6)()), "capset")
    def capability_observations(self) -> dict[str, object]:
        header = (ctypes.c_uint32 * 2)(0x20080522, 0)
        data = (ctypes.c_uint32 * 6)()
        self._checked(self.libc.syscall(125, header, data), "capget")
        values = { "effective": data[0] | data[3] << 32, "permitted": data[1] | data[4] << 32, "inheritable": data[2] | data[5] << 32, }
        bounding: list[int] = []
        ambient: list[int] = []
        for capability in range(256):
            ctypes.set_errno(0)
            present = self.libc.prctl(_PR_CAPBSET_READ, capability, 0, 0, 0)
            if present == -1 and ctypes.get_errno() == errno.EINVAL: break
            self._checked(present, "PR_CAPBSET_READ")
            bounding.append(present)
            ambient.append(self.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_IS_SET, capability))
        else: raise RuntimeLauncherUnavailable("capability-enumeration")
        return {**values, "bounding": tuple(bounding), "ambient": tuple(ambient), "groups": tuple(os.getgroups())}
    def drop_bounding(self) -> None:
        for capability in range(256):
            ctypes.set_errno(0)
            present = self.libc.prctl(_PR_CAPBSET_READ, capability, 0, 0, 0)
            if present == -1 and ctypes.get_errno() == errno.EINVAL: return
            self._checked(present, "PR_CAPBSET_READ")
            if present: self.prctl(_PR_CAPBSET_DROP, capability)
        raise RuntimeLauncherUnavailable("capability-enumeration")
    def install_seccomp(self) -> str:
        instructions = _seccomp_program()
        class Filter(ctypes.Structure):
            _fields_ = (("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32))
        program = (Filter * len(instructions))(*(Filter(*row) for row in instructions))
        class Program(ctypes.Structure):
            _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter)))
        self._checked(self.libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(Program(len(program), program))), "seccomp")
        return _seccomp_digest()
    def seccomp_mode(self) -> int: return self.prctl(_PR_GET_SECCOMP)
    def probe_seccomp_denials(self) -> dict[str, int]:
        probes = {name: (number, -1, -1, -1, -1, -1, -1) for name, number in _DENIED_SYSCALLS.items()}
        probes["prctl:set"] = (157, _PR_SET_SECCOMP, 0, 0, 0, 0)
        probes["execveat:shape"] = (322, -1, 0, 0, 0, 0)
        observed: dict[str, int] = {}
        for name, arguments in probes.items():
            ctypes.set_errno(0)
            result = self.libc.syscall(*arguments)
            saved = ctypes.get_errno()
            if result == 0 and name in ("fork", "vfork"): os._exit(127)
            if result != -1 or saved != errno.EPERM:
                if result > 0 and name in ("fork", "vfork"):
                    deadline = time.monotonic() + _TERM_SECONDS
                    while os.waitpid(result, os.WNOHANG)[0] == 0:
                        _require(time.monotonic() < deadline, "seccomp probe child reap", "seccomp-probe-reap")
                        time.sleep(0.001)
                raise RuntimeLauncherError(f"seccomp denial mismatch: {name}:{result}:{saved}", f"seccomp-denial-{name}")
            observed[name] = saved
        return observed
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
            "role": row.role, "seal_profile": row.seal_profile, "sha256": row.sha256, "size": row.size, "soname": row.soname, "tool_index": row.tool_index}
def _generation_value(row: _GenerationRow) -> list[int]:
    return [row.tool_index, row.object_index, row.descriptor_index, *row.source_generation]
def _rows_from_packet(values: object) -> tuple[_GenerationRow, ...]:
    _require(type(values) is list and bool(values) and len(values) <= _MAX_OBJECTS, "handoff generation rows")
    rows: list[_GenerationRow] = []
    for value in values:
        _require(type(value) is list and len(value) == 10, "handoff generation row shape")
        _require(type(value[7]) is list and type(value[9]) is list, "handoff generation nested shape")
        row = _GenerationRow(value[0], value[1], value[2], value[3], value[4], value[5], value[6], tuple(value[7]), value[8], tuple(value[9]))
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
def _verify_bundle(admission: _SourceAdmission, report_bytes: bytes, descriptors: tuple[int, ...], rows: tuple[_GenerationRow, ...]) -> tuple[dict[str, object], str, str]:
    _require(2 <= len(descriptors) <= _MAX_OBJECTS and len(set(descriptors)) == len(descriptors), "issued descriptor cardinality")
    report_data = _inspect_fd(descriptors[0], True, len(report_bytes), hashlib.sha256(report_bytes).hexdigest())
    _require(report_data == report_bytes, "issued report bytes")
    admission._validate_tracked_schema(report_data)
    report = _decode_report(report_data)
    row_order = tuple((row.tool_index, row.object_index) for row in rows)
    expected_order = tuple((tool_index, object_index) for tool_index in (1, 2) for object_index in range(len(report["tools"][tool_index]["objects"])))
    _require(row_order == expected_order, "generation rows are not exact", "issuer-generation-rows")
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
class _WorkerIssuer:
    def __init__(
        self, endpoint: socket.socket, nonce: bytes, admission: _SourceAdmission, consumer_pid: int, package_name: str, helper_endpoint: socket.socket | None = None):
        self._endpoint = endpoint
        self._helper_endpoint = helper_endpoint
        self._nonce = nonce
        self._admission = admission
        self._consumer_pid = consumer_pid
        self._package_name = package_name
        self._capability_used = False
        self._used = False
        self._helper_sequence = 0
        self._helper_tokens: dict[_RuntimeHelperToken, str] = {}
    def _helper_exchange(self, value: dict[str, object], rights: tuple[int, ...], deadline: float) -> dict[str, object]:
        endpoint = self._helper_endpoint
        if endpoint is None: raise RuntimeLauncherError("helper control unavailable", "helper-control")
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([], [endpoint], [], remaining)[1], "helper control deadline", "helper-deadline")
        raw = _canonical(value)
        ancillary = [] if not rights else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", rights))]
        _require(endpoint.sendmsg([raw], ancillary) == len(raw), "helper control send", "helper-control-send")
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([endpoint], [], [], remaining)[0], "helper acknowledgement deadline", "helper-deadline")
        reply, ancillary, flags, _address = endpoint.recvmsg(1024, 256, socket.MSG_CMSG_CLOEXEC)
        credentials, leases = _leased_credentials(ancillary, _SystemOps(), require_rights=False)
        _require(not flags and not leases and credentials == (self._consumer_pid, os.getuid(), os.getgid()), "helper acknowledgement authority", "helper-ack-authority")
        result = _strict_json(reply, False, 1024, "helper acknowledgement")
        _require(type(result) is dict and result.get("version") == _RESULT_VERSION, "helper acknowledgement shape", "helper-ack-shape")
        return result
    def _register_runtime_helper(self, helper: object, absolute_deadline: float) -> _RuntimeHelperToken:
        self._helper_sequence += 1
        pidfd = getattr(getattr(helper, "pidfd", None), "fd", None)
        executable = tuple(getattr(helper, "executable_identity", ()))
        target = tuple(getattr(helper, "target_executable_identity", ()))
        gates = tuple(name for name in ("input_gate", "registration_gate", "release_gate", "status_gate") if getattr(helper, name, None) is not None)
        values = (getattr(helper, "pid", None), getattr(helper, "start_time", None), getattr(helper, "session", None), getattr(helper, "process_group", None))
        _require(all(type(item) is int and item >= 0 for item in (*values, pidfd)), "helper registration identity", "helper-register-identity")
        _require(len(executable) == 2 and len(target) == 2, "helper executable identity", "helper-register-executable")
        request = {"event": "register", "executable": list(executable), "gates": list(gates),
                   "pid": values[0], "process_group": values[3], "sequence": self._helper_sequence,
                   "session": values[2], "start_time": values[1], "target": list(target),
                   "version": _RESULT_VERSION}
        reply = self._helper_exchange(request, (pidfd,), absolute_deadline)
        _require(set(reply) == {"event", "sequence", "token", "version"} and reply["event"] == "registered"
                 and reply["sequence"] == self._helper_sequence and _sha(reply["token"]),
                 "helper registration acknowledgement", "helper-register-ack")
        token = _RuntimeHelperToken(reply["token"])
        self._helper_tokens[token] = "registered"
        return token
    def _helper_transition(self, token: _RuntimeHelperToken, event: str, deadline: float) -> None:
        expected = "registered" if event == "release" else "released"
        _require(type(token) is _RuntimeHelperToken and self._helper_tokens.get(token) == expected, "helper token state", "helper-token")
        self._helper_sequence += 1
        request = {"event": event, "sequence": self._helper_sequence, "token": token.value, "version": _RESULT_VERSION}
        reply = self._helper_exchange(request, (), deadline)
        _require(reply == {"event": event + "d", "sequence": self._helper_sequence,
                           "token": token.value, "version": _RESULT_VERSION},
                 "helper transition acknowledgement", "helper-transition-ack")
        if event == "retire": del self._helper_tokens[token]
        else: self._helper_tokens[token] = "released"
    def _release_runtime_helper(self, token: _RuntimeHelperToken, deadline: float) -> None:
        self._helper_transition(token, "release", deadline)
    def _retire_runtime_helper(self, token: _RuntimeHelperToken, deadline: float) -> None:
        self._helper_transition(token, "retire", deadline)
    def _consume_runtime_closure_capability(self, admission: object, package_name: str, worker_pid: int) -> tuple[socket.socket, tuple[int, int, int]]:
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
    def _accept_runtime_closure(self, canonical_report: bytes, descriptors: tuple[int, ...], generation_rows: tuple[object, ...]) -> _IssuanceReceipt:
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
        credentials, received = _leased_credentials(ancillary, _SystemOps(), require_rights=False)
        expected_credentials = (self._consumer_pid, os.getuid(), os.getgid())
        _require(not flags and not received and credentials == expected_credentials, "issuance acknowledgement authority", "issuer-ack-authority")
        ack = _strict_json(ack_raw, False, _MAX_PACKET, "issuance acknowledgement")
        expected = {
            "binding_sha256": binding_sha, "consumer_pid": self._consumer_pid,
            "generation_sha256": generation_sha, "nonce": self._nonce.hex(),
            "report_sha256": packet["report_sha256"], "version": _HANDOFF_VERSION,
        }
        _require(ack == expected, "issuance acknowledgement mismatch")
        trailing = self._endpoint.recv(1)
        _require(trailing == b"", "second consumer packet", "issuer-second-packet")
        self._endpoint.shutdown(socket.SHUT_WR)
        return _IssuanceReceipt(_HANDOFF_VERSION, packet["report_sha256"], report["closure_sha256"], binding_sha, generation_sha, len(descriptors), os.getpid(), self._consumer_pid)
@dataclass
class _ProcessLease:
    pid: int
    pidfd: _FdLease
    start_time: int = 0
    session: int = 0
    process_group: int = 0
    executable: tuple[int, int] = (0, 0)
    release_gate: _FdLease | None = None
    released: bool = False
    reaped: bool = False
    descendants: tuple["_ProcessLease", ...] = ()
    namespace_handles: tuple[_FdLease, ...] = ()
@dataclass
class _ProcessOwner:
    ops: Any
    processes: list[_ProcessLease] = field(default_factory=list)
    poisoned: BaseException | None = None
    def register(self, pid: int, release_gate: _FdLease | None = None, pidfd_fd: int | None = None) -> _ProcessLease:
        pidfd = _FdLease(pidfd_fd if pidfd_fd is not None else os.pidfd_open(pid, 0), f"pidfd:{pid}")
        lease = _ProcessLease(pid, pidfd, release_gate=release_gate)
        self.processes.append(lease)
        lease.start_time = _start_time(pid)
        lease.session = os.getsid(pid)
        lease.process_group = os.getpgid(pid)
        lease.executable = _exe_identity(pid)
        return lease
    def spawn(self) -> tuple[int, _ProcessLease | None, _FdLease | None]:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        read_lease = _FdLease(read_fd, "process-release-read")
        write_lease = _FdLease(write_fd, "process-release-write")
        pid, pidfd = self.ops.clone_pidfd()
        if pid == 0:
            write_lease.close(self.ops)
            return 0, None, read_lease
        read_lease.close(self.ops)
        return pid, self.register(pid, write_lease, pidfd), None
    def release(self, lease: _ProcessLease) -> None:
        gate = lease.release_gate
        if gate is None or gate.state is not _FdState.OWNED or lease.released:
            raise RuntimeLauncherError("process release gate state", "process-release-gate")
        if self.ops.write(gate.fd, b"G") != 1:
            raise RuntimeLauncherError("process release short write", "process-release-write")
        gate.close(self.ops)
        lease.released = True
    def stop(self, lease: _ProcessLease, primary: BaseException | None = None) -> None:
        _stop_process(lease, primary, self.ops)
        if lease in self.processes: self.processes.remove(lease)
    def cleanup(self, primary: BaseException | None = None) -> None:
        failures: list[BaseException] = []
        for lease in tuple(self.processes):
            try: self.stop(lease, primary)
            except BaseException as error: failures.append(error)
        if failures:
            self.poisoned = RuntimeLauncherCleanupError(primary, failures)
            raise self.poisoned
def _proc_bytes(path: str, bound: int, ops: Any | None = None) -> bytes:
    actual_ops = ops or _SystemOps()
    lease = _FdLease(actual_ops.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW), f"proc:{path}")
    primary: BaseException | None = None
    chunks: list[bytes] = []
    try:
        total = 0
        while True:
            part = actual_ops.read(lease.fd, min(65536, bound + 1 - total))
            if not part: break
            total += len(part)
            _require(total <= bound, "proc record bound", "record-bound")
            chunks.append(part)
    except BaseException as error:
        primary = error
    try: lease.close(actual_ops)
    except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    if primary is not None: raise primary
    return b"".join(chunks)
def _parse_proc_stat(raw: bytes, pid: int) -> int:
    prefix = f"{pid} (".encode()
    _require(raw.startswith(prefix) and raw.endswith(b"\n") and raw.count(b"\n") == 1,
             "process stat framing", "stat-framing")
    marker = raw.rfind(b") ")
    _require(marker >= len(prefix) and b"\0" not in raw[:marker], "process stat comm", "stat-comm")
    fields = raw[marker + 2:-1].split(b" ")
    _require(len(fields) == 50 and len(fields[0]) == 1 and fields[0] in b"RSDZTWtXxIKP", "process stat shape", "stat-shape")
    values: list[int] = []
    for field in fields[1:]:
        _require(re.fullmatch(rb"-?(0|[1-9][0-9]*)", field) is not None,
                 "process stat lexical field", "stat-lexical")
        value = int(field)
        _require(-(1 << 63) <= value <= (1 << 64) - 1, "process stat integer bound", "stat-integer")
        values.append(value)
    start_time = values[18]
    _require(0 < start_time <= (1 << 64) - 1, "process start time", "stat-start-time")
    return start_time
def _parse_proc_status(raw: bytes) -> dict[str, object]:
    _require(raw.endswith(b"\n") and raw.count(b"\0") == 0, "process status framing", "status-framing")
    records: dict[bytes, bytes] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(b":\t")
        _require(bool(separator) and re.fullmatch(rb"[A-Za-z][A-Za-z0-9_]*", key) is not None, "process status record", "status-record")
        _require(key not in records and not any(byte < 0x20 and byte != 0x09 for byte in value), "process status cardinality", "status-cardinality")
        records[key] = value
    required = (b"NSpid", b"Groups", b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb", b"NoNewPrivs", b"Seccomp")
    _require(all(key in records for key in required), "process status required fields", "status-required")
    nspid = records[b"NSpid"].split(b"\t")
    groups = records[b"Groups"].split()
    _require(bool(nspid) and all(item.isdigit() and 0 < int(item) <= 2147483647 for item in nspid), "NSpid field", "status-nspid")
    _require(all(item.isdigit() and int(item) <= _UINT_MAX for item in groups), "Groups field", "status-groups")
    result: dict[str, object] = {"nspid": tuple(int(item) for item in nspid), "groups": tuple(int(item) for item in groups)}
    for key, name in ((b"CapInh", "inheritable"), (b"CapPrm", "permitted"), (b"CapEff", "effective"), (b"CapBnd", "bounding"), (b"CapAmb", "ambient")):
        value = records[key]
        _require(re.fullmatch(rb"[0-9a-f]{16}", value) is not None, "capability status field", "status-capability")
        result[name] = int(value, 16)
    for key, name, maximum in ((b"NoNewPrivs", "no_new_privs", 1), (b"Seccomp", "seccomp", 2)):
        value = records[key]
        _require(value.isdigit() and int(value) <= maximum, "security status field", "status-security")
        result[name] = int(value)
    return result
def _start_time(pid: int, ops: Any | None = None) -> int:
    return _parse_proc_stat(_proc_bytes(f"/proc/{pid}/stat", 8192, ops), pid)
def _exe_identity(pid: int, ops: Any | None = None) -> tuple[int, int]:
    actual_ops = ops or _SystemOps()
    lease = _FdLease(actual_ops.open(f"/proc/{pid}/exe", os.O_PATH | os.O_CLOEXEC), f"exe:{pid}")
    try:
        info = os.fstat(lease.fd)
        result = (info.st_dev, info.st_ino)
    except BaseException as primary:
        try: lease.close(actual_ops)
        except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from primary
        raise
    lease.close(actual_ops)
    return result
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
def _stop_process(lease: _ProcessLease, primary: BaseException | None, ops: Any | None = None) -> None:
    actual_ops = ops or _SystemOps()
    failures: list[BaseException] = []
    if not lease.reaped and select.select([lease.pidfd.fd], [], [], 0)[0]:
        try:
            observed, _status = os.waitpid(lease.pid, os.WNOHANG)
            _require(observed == lease.pid, "owned process wait identity")
        except ChildProcessError:
            pass
        else:
            lease.reaped = True
    if not lease.reaped:
        try:
            identity_required = lease.start_time != 0
            if identity_required and not _process_matches(lease):
                raise RuntimeLauncherError("owned process identity uncertain before TERM")
            signal.pidfd_send_signal(lease.pidfd.fd, signal.SIGTERM)
            if _wait_bounded(lease, time.monotonic() + _TERM_SECONDS) is None:
                if identity_required and not _process_matches(lease):
                    raise RuntimeLauncherError("owned process identity uncertain before KILL")
                signal.pidfd_send_signal(lease.pidfd.fd, signal.SIGKILL)
                if _wait_bounded(lease, time.monotonic() + _KILL_SECONDS) is None:
                    raise RuntimeLauncherError("owned process reap deadline")
        except BaseException as error:
            failures.append(error)
    if lease.reaped:
        for handle in reversed(lease.namespace_handles):
            if handle.state is _FdState.OWNED:
                try: handle.close(actual_ops)
                except BaseException as error: failures.append(error)
        if lease.pidfd.state is _FdState.OWNED:
            try: lease.pidfd.close(actual_ops)
            except BaseException as error: failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
def _received_leases(descriptors: tuple[int, ...]) -> tuple[_FdLease, ...]:
    _require(type(descriptors) is tuple and all(type(fd) is int and fd >= 0 for fd in descriptors),
             "received descriptor shape", "issuer-rights-value")
    return tuple(_FdLease(fd, f"received:{index}") for index, fd in enumerate(descriptors))
def _leased_credentials(ancillary: list[tuple[int, int, bytes]], ops: Any, require_rights: bool | None = True) -> tuple[tuple[int, int, int], tuple[_FdLease, ...]]:
    credentials: tuple[int, int, int] | None = None
    leases: list[_FdLease] = []
    primary: BaseException | None = None
    try:
        for level, kind, data in ancillary:
            _require(level == socket.SOL_SOCKET, "handoff ancillary level", "issuer-ancillary")
            if kind == socket.SCM_CREDENTIALS:
                _require(credentials is None and len(data) == struct.calcsize("3i"),
                         "handoff credentials cardinality", "issuer-credentials-cardinality")
                credentials = struct.unpack("3i", data)
            elif kind == socket.SCM_RIGHTS:
                _require(bool(data) and len(data) % array("i").itemsize == 0,
                         "handoff rights alignment", "issuer-rights-alignment")
                values = array("i")
                values.frombytes(data)
                duplicate = bool(leases)
                leases.extend(_received_leases(tuple(values)))
                _require(not duplicate, "handoff rights cardinality", "issuer-rights-cardinality")
            else: raise RuntimeLauncherError("handoff ancillary type", "issuer-ancillary")
        _require(credentials is not None, "handoff credentials missing", "issuer-credentials-missing")
        if require_rights is not None:
            _require(bool(leases) if require_rights else not leases,
                     "handoff rights missing or extra", "issuer-rights-missing" if require_rights else "issuer-rights-extra")
        return credentials, tuple(leases)
    except BaseException as error: primary = error
    _close_leases(ops, leases, primary)
    raise primary
def _consume_issuance(endpoint: socket.socket, nonce: bytes, admission: _SourceAdmission,
                      issuer_pid: int, ops: Any | None = None,
                      ) -> tuple[dict[str, object], tuple[_FdLease, ...], tuple[_GenerationRow, ...], _IssuanceReceipt]:
    actual_ops = ops or _SystemOps()
    ancillary_bound = socket.CMSG_SPACE(_MAX_OBJECTS * array("i").itemsize) + socket.CMSG_SPACE(struct.calcsize("3i"))
    raw, ancillary, flags, _address = endpoint.recvmsg(_MAX_PACKET, ancillary_bound, socket.MSG_CMSG_CLOEXEC)
    credentials, leases = _leased_credentials(ancillary, actual_ops)
    descriptors = tuple(lease.fd for lease in leases)
    primary: BaseException | None = None
    try:
        expected_credentials = (issuer_pid, os.getuid(), os.getgid())
        _require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and credentials == expected_credentials, "handoff packet authority/truncation", "issuer-packet-authority")
        packet = _strict_json(raw, False, _MAX_PACKET, "handoff packet")
        keys = {"binding_sha256", "closure_sha256", "descriptor_count", "generation_rows", "generation_sha256",
                "nonce", "report_sha256", "revision", "source_set_sha256", "version"}
        _require(type(packet) is dict and set(packet) == keys, "handoff packet shape")
        _require(packet["version"] == _HANDOFF_VERSION and packet["nonce"] == nonce.hex(), "handoff nonce/version")
        _require(packet["revision"] == admission.revision and packet["source_set_sha256"] == admission.source_set_sha256, "handoff admission binding")
        _require(packet["descriptor_count"] == len(descriptors), "handoff descriptor count")
        rows = _rows_from_packet(packet["generation_rows"])
        report_bytes = _inspect_fd(descriptors[0], True, None, packet["report_sha256"])
        report, binding_sha, generation_sha = _verify_bundle(admission, report_bytes, descriptors, rows)
        _require(packet["closure_sha256"] == report["closure_sha256"], "handoff closure digest")
        _require(packet["binding_sha256"] == binding_sha and packet["generation_sha256"] == generation_sha, "handoff table digest")
        ack = {"binding_sha256": binding_sha, "consumer_pid": os.getpid(), "generation_sha256": generation_sha,
               "nonce": nonce.hex(), "report_sha256": packet["report_sha256"], "version": _HANDOFF_VERSION}
        ack_bytes = _canonical(ack)
        _require(endpoint.send(ack_bytes) == len(ack_bytes), "issuance acknowledgement partial")
        endpoint.shutdown(socket.SHUT_WR)
        _require(endpoint.recv(1) == b"", "second issuer packet", "issuer-second-packet")
        receipt = _IssuanceReceipt(_HANDOFF_VERSION, packet["report_sha256"], report["closure_sha256"], binding_sha, generation_sha, len(descriptors), issuer_pid, os.getpid())
        return report, leases, rows, receipt
    except BaseException as error: primary = error
    _close_leases(actual_ops, leases, primary)
    raise primary
def _consume_worker_handoff(endpoint: socket.socket, helper_endpoint: socket.socket,
                            nonce: bytes, admission: _SourceAdmission, issuer_pid: int,
                            ops: Any, process_owner: _ProcessOwner,
                            deadline: float) -> tuple[dict[str, object], tuple[_FdLease, ...], tuple[_GenerationRow, ...], _IssuanceReceipt]:
    sequence = 0
    helpers: dict[str, _ProcessLease] = {}
    while True:
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "worker handoff deadline", "worker-handoff-deadline")
        ready = select.select([endpoint, helper_endpoint], [], [], remaining)[0]
        _require(bool(ready), "worker handoff deadline", "worker-handoff-deadline")
        if helper_endpoint in ready:
            raw, ancillary, flags, _address = helper_endpoint.recvmsg(4096, 512, socket.MSG_CMSG_CLOEXEC)
            credentials, received = _leased_credentials(ancillary, ops, require_rights=None)
            primary: BaseException | None = None
            try:
                _require(not flags and credentials == (issuer_pid, os.getuid(), os.getgid()),
                         "helper control authority", "helper-control-authority")
                value = _strict_json(raw, False, 4096, "helper control")
                _require(type(value) is dict and value.get("version") == _RESULT_VERSION, "helper control shape", "helper-control-shape")
                sequence += 1
                _require(value.get("sequence") == sequence, "helper control sequence", "helper-control-sequence")
                event = value.get("event")
                if event == "register":
                    expected = {"event", "executable", "gates", "pid", "process_group", "sequence",
                                "session", "start_time", "target", "version"}
                    _require(set(value) == expected and len(received) == 1, "helper registration shape", "helper-register-shape")
                    pidfd = received[0].transfer()
                    lease = process_owner.register(value["pid"], pidfd_fd=pidfd)
                    observed = (lease.start_time, lease.session, lease.process_group, list(lease.executable))
                    asserted = (value["start_time"], value["session"], value["process_group"], value["executable"])
                    _require(observed == asserted and value["gates"] == ["input_gate", "registration_gate", "release_gate", "status_gate"],
                             "helper registration identity", "helper-register-identity")
                    token = hashlib.sha256(nonce + _canonical(value)).hexdigest()
                    _require(token not in helpers, "helper token collision", "helper-token")
                    helpers[token] = lease
                    reply_event = "registered"
                else:
                    expected = {"event", "sequence", "token", "version"}
                    _require(set(value) == expected and not received and event in ("release", "retire"), "helper transition shape", "helper-transition-shape")
                    token = value["token"]
                    _require(type(token) is str and token in helpers, "helper token unknown", "helper-token")
                    lease = helpers[token]
                    if event == "release":
                        _require(not lease.released, "helper release replay", "helper-release-replay")
                        lease.released = True
                        reply_event = "released"
                    else:
                        _require(lease.released and bool(select.select([lease.pidfd.fd], [], [], 0)[0]),
                                 "helper retire before reap", "helper-retire-live")
                        lease.reaped = True
                        process_owner.stop(lease)
                        del helpers[token]
                        reply_event = "retired"
                reply = _canonical({"event": reply_event, "sequence": sequence, "token": token, "version": _RESULT_VERSION})
                _require(helper_endpoint.send(reply) == len(reply), "helper acknowledgement send", "helper-ack-send")
            except BaseException as error: primary = error
            if primary is not None:
                _close_leases(ops, received, primary)
                raise primary
        if endpoint in ready:
            _require(not helpers, "helper authority still live at issuance", "helper-live-at-issuance")
            return _consume_issuance(endpoint, nonce, admission, issuer_pid, ops)
def _mkdir_exact(path: str, mode: int) -> None:
    os.mkdir(path, mode)
    info = os.lstat(path)
    _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode, "private root directory mismatch")
@dataclass
class _RootOwner:
    ops: Any
    parent: _FdLease | None = None
    root: _FdLease | None = None
    identity: tuple[int, int] | None = None
    create_intended: bool = False
    mount_intended: bool = False
    cleaned: bool = False
    def prepare(self) -> str:
        self.parent = _FdLease(self.ops.open(_ROOT_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), "root-parent")
        _require(not os.path.lexists(f"{_ROOT_PARENT}/{_ROOT_LEAF}"), "private root baseline", "root-baseline")
        self.create_intended = True
        os.mkdir(_ROOT_LEAF, 0o700, dir_fd=self.parent.fd)
        fd = os.open(_ROOT_LEAF, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent.fd)
        self.root = _FdLease(fd, "root-object")
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, "private root identity", "root-identity")
        self.identity = (info.st_dev, info.st_ino)
        self.mount_intended = True
        return f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    def cleanup(self, primary: BaseException | None = None) -> None:
        failures: list[BaseException] = []
        if self.root is not None:
            try: self.root.close(self.ops)
            except BaseException as error: failures.append(error)
        if self.create_intended and self.parent is not None and self.identity is not None:
            try:
                info = os.stat(_ROOT_LEAF, dir_fd=self.parent.fd, follow_symlinks=False)
                _require((info.st_dev, info.st_ino) == self.identity and stat.S_ISDIR(info.st_mode), "private root replacement", "root-replaced")
                os.rmdir(_ROOT_LEAF, dir_fd=self.parent.fd)
            except BaseException as error: failures.append(error)
        if self.parent is not None:
            try: self.parent.close(self.ops)
            except BaseException as error: failures.append(error)
        if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
        self.cleaned = True
def _copy_bound_object(ops: Any, source_fd: int, target: str, row: _GenerationRow) -> None:
    data = _inspect_fd(source_fd, False, row.size, row.sha256)
    target_lease = _FdLease(ops.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o500), "root-copy")
    primary: BaseException | None = None
    try:
        offset = 0
        while offset < len(data):
            written = ops.write(target_lease.fd, data[offset:offset + _IO_CHUNK])
            _require(written > 0, "private root short write")
            offset += written
        os.fsync(target_lease.fd)
        os.fchmod(target_lease.fd, 0o555)
    except BaseException as error: primary = error
    try: target_lease.close(ops)
    except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    if primary is not None: raise primary
    read_lease = _FdLease(ops.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW), "root-readback")
    try:
        info = os.fstat(read_lease.fd)
        observed = _read_complete(read_lease.fd, info.st_size, _MAX_OBJECT)
        _require(stat.S_IMODE(info.st_mode) == 0o555 and hashlib.sha256(observed).hexdigest() == row.sha256, "materialized readback")
    except BaseException as error: primary = error
    try: read_lease.close(ops)
    except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    if primary is not None: raise primary
def _materialize_root(ops: Any, role: str, descriptors: tuple[int, ...], rows: tuple[_GenerationRow, ...], report: dict[str, object], root: str | None = None) -> str:
    root = root or f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    ops.mount(b"tmpfs", root.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV, b"mode=0700,size=536870912,nr_inodes=512")
    for relative, mode in (("bin", 0o755), ("lib64", 0o755), ("lib", 0o755), ("lib/x86_64-linux-gnu", 0o755)):
        _mkdir_exact(f"{root}/{relative}", mode)
    selected = [row for row in rows if row.tool_index == _TOOL_INDEX[role]]
    objects = report["tools"][_TOOL_INDEX[role]]["objects"]
    _require(len(selected) == len(objects), "private root row cardinality")
    for row, item in zip(selected, objects):
        if row.object_index == 0:
            target = f"{root}/bin/{role}"
        elif row.object_index == 1:
            target = root + _INTERPRETER
        else:
            target = f"{root}{_LIBRARY_ROOT}/{item['soname']}"
        _copy_bound_object(ops, descriptors[row.descriptor_index], target, row)
    return root
def _write_map(ops: Any, path: str, value: bytes) -> None:
    lease = _FdLease(ops.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW), f"map:{path}")
    primary: BaseException | None = None
    try: _require(ops.write(lease.fd, value) == len(value), "namespace identity map short write", "map-short-write")
    except BaseException as error: primary = error
    try: lease.close(ops)
    except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    if primary is not None: raise primary
def _enter_boundary(ops: Any, root: str) -> dict[str, object]:
    ops.chroot(root.encode())
    os.chdir("/")
    ops.prctl(_PR_SET_DUMPABLE, 0)
    ops.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL)
    ops.drop_bounding()
    ops.prctl(_PR_SET_SECUREBITS, _SECBITS)
    ops.capset_zero()
    capabilities = ops.capability_observations()
    scalar_names = ("effective", "permitted", "inheritable")
    capabilities_zero = not any(capabilities[name] for name in scalar_names)
    capabilities_zero = capabilities_zero and not any(capabilities["bounding"]) and not any(capabilities["ambient"])
    groups_empty = capabilities["groups"] == ()
    _require(capabilities_zero and groups_empty, "capability/group sets are not empty", "capability-readback")
    securebits = ops.prctl(_PR_GET_SECUREBITS)
    _require(securebits == _SECBITS, "noroot securebits are not locked", "securebits-readback")
    ops.prctl(_PR_SET_NO_NEW_PRIVS, 1)
    no_new_privs = ops.prctl(_PR_GET_NO_NEW_PRIVS)
    _require(no_new_privs == 1, "no_new_privs not set", "nnp-readback")
    program_digest = ops.install_seccomp()
    mode = ops.seccomp_mode()
    denials = ops.probe_seccomp_denials()
    expected_denials = set(_DENIED_SYSCALLS) | {"prctl:set", "execveat:shape"}
    _require(set(denials) == expected_denials and all(value == errno.EPERM for value in denials.values()), "seccomp denial inventory", "seccomp-denials")
    return {"capability_sets": capabilities, "capabilities_zero": capabilities_zero,
            "groups_empty": groups_empty, "noroot_locked": securebits == _SECBITS,
            "no_new_privs": no_new_privs == 1, "seccomp_denials": denials,
            "seccomp_mode": mode, "seccomp_program_sha256": program_digest}
def _child_fd_install(ops: Any, input_fd: int, output_fd: int, role: str, exec_status_fd: int, root: str, status: socket.socket) -> None:
    _require(fcntl.fcntl(198, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
             "executable authority is not CLOEXEC", "exec-fd-cloexec")
    input_copy = _FdLease(fcntl.fcntl(input_fd, fcntl.F_DUPFD_CLOEXEC, 256), "stdin-copy")
    output_copy = _FdLease(fcntl.fcntl(output_fd, fcntl.F_DUPFD_CLOEXEC, 256), "stdout-copy")
    os.dup2(input_copy.fd, 0, inheritable=True)
    os.dup2(output_copy.fd, 1, inheritable=True)
    os.dup2(output_copy.fd, 2, inheritable=True)
    input_copy.close(ops)
    output_copy.close(ops)
    status_fd = status.fileno()
    allowed = {0, 1, 2, 198, exec_status_fd, status_fd}
    for fd in _descriptor_snapshot(ops):
        if fd not in allowed:
            _FdLease(fd, "preexec-complement").close(ops)
    observations = _enter_boundary(ops, root)
    status.send(_status("boundary", 3, observations=observations))
    _close_socket(status, ops, "boundary-status")
    ops.execveat(198, role)
def _namespace_owner(role: str, descriptors: tuple[int, ...], rows: tuple[_GenerationRow, ...],
                     report: dict[str, object], input_fd: int, output_fd: int,
                     status_fd: int, root: str | None = None) -> NoReturn:
    root = root or f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    status = socket.socket(fileno=status_fd)
    ops = _SystemOps()
    child_owner = _ProcessOwner(ops)
    child_lease: _ProcessLease | None = None
    mounted = False
    sequence = 0
    inherited = list(_received_leases(descriptors))
    exec_lease: _FdLease | None = None
    try:
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        original_uid, original_gid = os.getuid(), os.getgid()
        os.setgroups([])
        ops.unshare_boundary()
        try: _write_map(ops, "/proc/self/setgroups", b"deny\n")
        except FileNotFoundError: pass
        _write_map(ops, "/proc/self/uid_map", f"0 {original_uid} 1\n".encode())
        _write_map(ops, "/proc/self/gid_map", f"0 {original_gid} 1\n".encode())
        ops.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None)
        sequence = 1
        status.send(_status("namespace", sequence))
        _recv_status(status, time.monotonic() + _SETUP_SECONDS, "prepare-root", 1)
        _materialize_root(ops, role, descriptors, rows, report, root)
        mounted = True
        descriptor_index = next(row.descriptor_index for row in rows if row.tool_index == _TOOL_INDEX[role] and row.object_index == 0)
        selected = descriptors[descriptor_index]
        if selected == 198: os.set_inheritable(selected, False)
        else: os.dup2(selected, 198, inheritable=False)
        exec_lease = _FdLease(198, "sole-executable-authority")
        _close_leases(ops, inherited)
        inherited.clear()
        exec_status_read, exec_status_write = os.pipe2(os.O_CLOEXEC)
        exec_read_lease = _FdLease(exec_status_read, "exec-status-read")
        exec_write_lease = _FdLease(exec_status_write, "exec-status-write")
        child, child_lease, child_gate = child_owner.spawn()
        if child == 0:
            exec_read_lease.close(ops)
            try:
                _require(child_gate is not None and ops.read(child_gate.fd, 1) == b"G", "child release gate", "child-release")
                child_gate.close(ops)
                ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
                _child_fd_install(ops, input_fd, output_fd, role, exec_write_lease.fd, root, status)
            except BaseException as error:
                code = getattr(error, "code", "child-setup")
                try: ops.write(exec_write_lease.fd, (code[:126] + "\n").encode())
                finally: os._exit(126)
        _require(child_lease is not None, "child preregistration", "child-register")
        exec_write_lease.close(ops)
        exec_lease.close(ops)
        exec_lease = None
        sequence = 2
        status.send(_status("child", sequence, pid=child))
        _recv_status(status, time.monotonic() + _SETUP_SECONDS, "release-child", 2)
        child_owner.release(child_lease)
        ready = select.select([exec_read_lease.fd], [], [], _SETUP_SECONDS)[0]
        _require(bool(ready), "exec status timeout", "exec-status-timeout")
        exec_status = ops.read(exec_read_lease.fd, 128)
        exec_read_lease.close(ops)
        _require(not exec_status, "exec setup failed", "exec-status-bytes")
        sequence = 4
        status.send(_status("exec-ready", sequence))
        _recv_status(status, time.monotonic() + _SETUP_SECONDS, "finalize-root", 3)
        final_flags = _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        ops.mount(None, root.encode(), None, final_flags, None)
        sequence = 5
        status.send(_status("root-final", sequence))
        wait_status = _wait_bounded(child_lease, time.monotonic() + _RUN_SECONDS)
        _require(wait_status is not None, "namespace child deadline", "child-reap-deadline")
        child_owner.stop(child_lease)
        child_lease = None
        ops.umount(root.encode())
        mounted = False
        sequence = 6
        status.send(_status("exit", sequence, status=wait_status))
        os._exit(0)
    except BaseException as primary:
        failures: list[BaseException] = []
        try: child_owner.cleanup(primary)
        except BaseException as error: failures.append(error)
        if exec_lease is not None:
            try: exec_lease.close(ops)
            except BaseException as error: failures.append(error)
        if inherited:
            try: _close_leases(ops, inherited, primary)
            except BaseException as error: failures.append(error)
        if mounted:
            try: ops.umount(root.encode())
            except BaseException as error: failures.append(error)
        try:
            next_sequence = sequence + 1
            if failures:
                status.send(_status("error", next_sequence, code="cleanup-uncertain", kind="RuntimeLauncherCleanupError"))
            elif isinstance(primary, RuntimeLauncherUnavailable):
                status.send(_status("unavailable", next_sequence, primitive=primary.primitive, message=str(primary)))
            else:
                status.send(_status("error", next_sequence, code=getattr(primary, "code", "launcher-rejected"), kind=type(primary).__name__))
        except BaseException: pass
        os._exit(125)
def _parse_maps(raw: bytes) -> tuple[tuple[object, ...], ...]:
    _require(raw.endswith(b"\n") and 0 < raw.count(b"\n") <= _MAX_MAP_LINES,
             "maps framing/bound", "maps-framing")
    records: list[tuple[object, ...]] = []
    previous_end = 0
    pattern = re.compile(rb"([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) ([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: +(.*))?")
    for line in raw.splitlines():
        match = pattern.fullmatch(line)
        _require(match is not None, "maps lexical record", "maps-record")
        groups = match.groups()
        start, end, offset = (int(groups[index], 16) for index in (0, 1, 3))
        major, minor, inode = int(groups[4], 16), int(groups[5], 16), int(groups[6])
        path = groups[7] or b""
        _require(previous_end <= start < end <= (1 << 64) - 1 and offset <= (1 << 64) - 1, "maps ordered address bound", "maps-address")
        _require(start % 4096 == 0 and end % 4096 == 0 and offset % 4096 == 0, "maps page alignment", "maps-alignment")
        previous_end = end
        _require(major <= _UINT_MAX and minor <= _UINT_MAX and inode <= (1 << 64) - 1, "maps identity bound", "maps-identity")
        _require(not any(byte < 0x20 for byte in path), "maps path lexical", "maps-path")
        records.append((start, end, groups[2], offset, major, minor, inode, path))
    return tuple(records)
def _maps_snapshot(pid: int, ops: Any | None = None) -> bytes:
    raw = _proc_bytes(f"/proc/{pid}/maps", _MAX_MAPS, ops)
    _parse_maps(raw)
    return raw
def _final_mapping_check(ops: _SystemOps, pid: int, rows: tuple[_GenerationRow, ...], role: str, report: dict[str, object]) -> bytes:
    first = _maps_snapshot(pid)
    expected_rows = [row for row in rows if row.tool_index == _TOOL_INDEX[role]]
    expected = {(row.role, row.sha256) for row in expected_rows}
    observed: set[tuple[str, str]] = set()
    digest_roles = {row.sha256: row.role for row in expected_rows}
    for start, end, permissions, _offset, _major, _minor, inode, path in _parse_maps(first):
        if b"x" not in permissions: continue
        if inode == 0:
            _require(path in (b"[vdso]", b"[vsyscall]"), "unknown executable synthetic mapping")
            continue
        map_lease = _FdLease(ops.open(f"/proc/{pid}/map_files/{start:x}-{end:x}", os.O_RDONLY | os.O_CLOEXEC), "map-file")
        try:
            info = os.fstat(map_lease.fd)
            data = _read_complete(map_lease.fd, info.st_size, _MAX_OBJECT)
        except BaseException as primary:
            try: map_lease.close(ops)
            except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from primary
            raise
        map_lease.close(ops)
        digest = hashlib.sha256(data).hexdigest()
        _require(digest in digest_roles, "final mapping closure expansion")
        observed.add((digest_roles[digest], digest))
    second = _maps_snapshot(pid)
    _require(first == second and observed == expected, "final mapped generation equality")
    objects = report["tools"][_TOOL_INDEX[role]]["objects"]
    if _digest([[item["role"], item["sha256"]] for item in objects]) != report["tools"][_TOOL_INDEX[role]]["mapping_sha256"]:
        raise RuntimeLauncherError("final mapping digest", "mapping-report-digest")
    return first
def _parse_mountinfo(raw: bytes) -> tuple[tuple[object, ...], ...]:
    _require(raw.endswith(b"\n") and raw.count(b"\n") <= _MAX_MAP_LINES, "mountinfo framing", "mountinfo-framing")
    rows: list[tuple[object, ...]] = []
    token = rb"[^ \x00-\x1f]+"
    pattern = re.compile(rb"([1-9][0-9]*) ([0-9]+) ([0-9a-f]+):([0-9a-f]+) (" + token + rb") (" + token + rb") (" + token + rb")(.*?) - (" + token + rb") (" + token + rb") (" + token + rb")")
    for line in raw.splitlines():
        match = pattern.fullmatch(line)
        _require(match is not None, "mountinfo lexical record", "mountinfo-record")
        groups = match.groups()
        optional = groups[7]
        _require(not optional or optional.startswith(b" "), "mountinfo optional fields", "mountinfo-shape")
        rows.append((int(groups[0]), int(groups[1]), int(groups[2], 16), int(groups[3], 16),
                     groups[4], groups[5], frozenset(groups[6].split(b",")), groups[8], groups[9], groups[10]))
    return tuple(rows)
def _final_mount_check(pid: int, ops: Any | None = None) -> tuple[bool, bool, bool, bool]:
    rows = _parse_mountinfo(_proc_bytes(f"/proc/{pid}/mountinfo", _MAX_MAPS, ops))
    roots = [row for row in rows if row[5] == b"/"]
    _require(len(roots) == 1, "root mount cardinality", "root-mount-cardinality")
    required = {b"ro", b"nosuid", b"nodev", b"noexec"}
    root_exact = required <= roots[0][6]
    no_proc = not any(row[7] == b"proc" for row in rows)
    _require(root_exact, "root mount is not read-only noexec", "root-final-flags")
    _require(no_proc, "sandbox root contains proc", "root-proc-present")
    forbidden = ("proc", "workspace", "workspaces", "checkout", "usr/bin/python3", "run/cogs")
    exposed = tuple(path for path in forbidden if os.path.lexists(f"/proc/{pid}/root/{path}"))
    _require(not exposed, "host path exposed in sandbox root", "root-path-exposure")
    checkout_absent = not any("checkout" in path or "workspace" in path for path in exposed)
    return root_exact, no_proc, not exposed, checkout_absent
def _open_namespace_authority(lease: _ProcessLease, ops: Any) -> dict[str, bool]:
    names = ("user", "mnt", "net", "pid_for_children")
    handles = tuple(_FdLease(ops.open(f"/proc/{lease.pid}/ns/{name}", os.O_RDONLY | os.O_CLOEXEC), f"namespace:{name}") for name in names)
    lease.namespace_handles = handles
    identities = tuple((os.fstat(item.fd).st_dev, os.fstat(item.fd).st_ino) for item in handles)
    baseline_names = ("user", "mnt", "net", "pid")
    baselines = tuple((os.stat(f"/proc/self/ns/{name}").st_dev, os.stat(f"/proc/self/ns/{name}").st_ino) for name in baseline_names)
    _require(all(observed != baseline for observed, baseline in zip(identities, baselines)), "namespace object did not change", "namespace-object")
    owner_results: list[bool] = []
    for handle in handles[1:]:
        owner_lease = _FdLease(fcntl.ioctl(handle.fd, _NS_GET_USERNS), "namespace-user-owner")
        try:
            info = os.fstat(owner_lease.fd)
            owner_results.append((info.st_dev, info.st_ino) == identities[0])
        finally:
            owner_lease.close(ops)
    parent_lease = _FdLease(fcntl.ioctl(handles[3].fd, _NS_GET_PARENT), "pid-namespace-parent")
    try:
        info = os.fstat(parent_lease.fd)
        parent_exact = (info.st_dev, info.st_ino) == baselines[3]
    finally:
        parent_lease.close(ops)
    _require(all(owner_results) and parent_exact, "namespace ownership relation", "namespace-ownership")
    return {"namespace_handles_exact": len(set(identities)) == len(identities), "namespace_ownership_exact": all(owner_results) and parent_exact}
def _namespace_facts(pid: int, parent_uid: int | None = None, parent_gid: int | None = None, authority: _ProcessLease | None = None) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name, fact in (("user", "user_namespace_exact"), ("pid", "pid_namespace_exact"), ("mnt", "mount_namespace_exact"), ("net", "network_namespace_exact")):
        baseline = os.stat(f"/proc/self/ns/{name}")
        observed = os.stat(f"/proc/{pid}/ns/{name}")
        observed_identity = (observed.st_dev, observed.st_ino)
        result[fact] = (baseline.st_dev, baseline.st_ino) != observed_identity
        if authority is not None:
            index = {"user": 0, "mnt": 1, "net": 2, "pid": 3}[name]
            owner = os.fstat(authority.namespace_handles[index].fd)
            result[fact] = result[fact] and observed_identity == (owner.st_dev, owner.st_ino)
    status = _parse_proc_status(_proc_bytes(f"/proc/{pid}/status", 65536))
    result["pid_one"] = bool(status["nspid"]) and status["nspid"][-1] == 1
    uid = os.getuid() if parent_uid is None else parent_uid
    gid = os.getgid() if parent_gid is None else parent_gid
    uid_exact = _proc_bytes(f"/proc/{pid}/uid_map", 4096) == f"0 {uid} 1\n".encode()
    gid_exact = _proc_bytes(f"/proc/{pid}/gid_map", 4096) == f"0 {gid} 1\n".encode()
    _require(uid_exact and gid_exact, "exact singular identity maps", "identity-map")
    result["user_namespace_exact"] = result["user_namespace_exact"] and uid_exact and gid_exact
    result["groups_empty"] = status["groups"] == ()
    result["capability_sets_zero"] = all(status[name] == 0 for name in ("effective", "permitted", "inheritable", "bounding", "ambient"))
    result["nnp_exact"] = status["no_new_privs"] == 1
    result["seccomp_mode_exact"] = status["seccomp"] == _SECCOMP_MODE_FILTER
    return result
def _parse_limits(raw: bytes) -> tuple[tuple[str, int | None, int | None, str], ...]:
    lines = raw.splitlines(keepends=True)
    header = b"Limit                     Soft Limit           Hard Limit           Units\n"
    _require(bool(lines) and lines[0] == header and b"".join(lines) == raw, "limits framing", "limits-framing")
    rows: list[tuple[str, int | None, int | None, str]] = []
    for line in lines[1:]:
        _require(line.endswith(b"\n"), "limits trailing record", "limits-record")
        fields = re.split(rb" {2,}", line[:-1].rstrip())
        _require(len(fields) in (3, 4), "limits shape", "limits-shape")
        name = fields[0].decode("ascii", "strict")
        values = fields[1:3]
        _require(all(value == b"unlimited" or value.isdigit() for value in values), "limits lexical value", "limits-value")
        soft, hard = (None if value == b"unlimited" else int(value) for value in values)
        _require(all(item is None or item <= (1 << 64) - 1 for item in (soft, hard)), "limits integer bound", "limits-bound")
        unit = "" if len(fields) == 3 else fields[3].decode("ascii", "strict")
        rows.append((name, soft, hard, unit))
    _require(len(rows) == len({row[0] for row in rows}), "limits duplicate", "limits-cardinality")
    return tuple(rows)
def _parse_children(raw: bytes) -> tuple[int, ...]:
    _require(re.fullmatch(rb"(?:[1-9][0-9]* )*", raw) is not None,
             "children lexical record", "children-record")
    values = tuple(int(item) for item in raw.split())
    _require(len(values) == len(set(values)) and all(value <= 2147483647 for value in values), "children cardinality", "children-cardinality")
    return values
def _descendant_census(pid: int, ops: Any) -> tuple[int, ...]:
    pending = [pid]
    observed: list[int] = []
    while pending:
        parent = pending.pop()
        children = _parse_children(_proc_bytes(f"/proc/{parent}/task/{parent}/children", 65536, ops))
        _require(not any(child in observed or child in pending for child in children), "descendant census cycle/duplicate", "descendant-census")
        observed.extend(children)
        pending.extend(children)
        _require(len(observed) <= 4096, "descendant census bound", "descendant-bound")
    return tuple(sorted(observed))
def _close_socket(endpoint: socket.socket, ops: Any, purpose: str) -> None:
    if endpoint.fileno() >= 0:
        _FdLease(endpoint.detach(), purpose).close(ops)
def _parse_sandbox_status(raw: bytes, event: str, sequence: int) -> dict[str, object]:
    value = _strict_json(raw, False, 4096, "sandbox status")
    extras = {
        "namespace": set(), "child": {"pid"}, "boundary": {"observations"}, "exec-ready": set(), "root-final": set(), "exit": {"status"},
        "error": {"code", "kind"}, "unavailable": {"message", "primitive"}, "prepare-root": set(), "release-child": set(), "finalize-root": set(),
    }
    _require(type(value) is dict and event in extras and set(value) == {"event", "sequence", "version"} | extras[event], "sandbox status closed shape", "status-shape")
    _require(value["version"] == _RESULT_VERSION and value["event"] == event and value["sequence"] == sequence, "sandbox status identity/sequence", "status-sequence")
    if "pid" in value: _require(type(value["pid"]) is int and 0 < value["pid"] <= 2147483647, "sandbox status pid", "status-pid")
    if "status" in value: _require(type(value["status"]) is int and 0 <= value["status"] <= _UINT_MAX, "sandbox wait status", "status-wait")
    return value
def _status(event: str, sequence: int, **fields: object) -> bytes:
    return _canonical({"event": event, "sequence": sequence, "version": _RESULT_VERSION, **fields})
def _recv_status(endpoint: socket.socket, deadline: float, event: str = "", sequence: int = 0) -> dict[str, object]:
    remaining = deadline - time.monotonic()
    _require(remaining > 0 and bool(select.select([endpoint], [], [], remaining)[0]), "sandbox status deadline", "status-deadline")
    raw = endpoint.recv(4096)
    preliminary = _strict_json(raw, False, 4096, "sandbox status")
    observed_event = preliminary.get("event") if type(preliminary) is dict else None
    if observed_event == event:
        return _parse_sandbox_status(raw, event, sequence)
    if observed_event == "unavailable":
        unavailable = _parse_sandbox_status(raw, "unavailable", sequence)
        raise RuntimeLauncherUnavailable(unavailable["primitive"], unavailable["message"])
    if observed_event == "error":
        failure = _parse_sandbox_status(raw, "error", sequence)
        if failure["code"] == "cleanup-uncertain":
            raise RuntimeLauncherCleanupError(None, [RuntimeLauncherError("inner cleanup uncertain")])
        raise RuntimeLauncherError(f"sandbox setup failed: {failure['kind']}", failure["code"])
    return _parse_sandbox_status(raw, event, sequence)
def _run_tool_with_ops(
    ops: Any,
    role: str,
    report: dict[str, object],
    descriptors: tuple[int, ...],
    rows: tuple[_GenerationRow, ...],
) -> tuple[bytes, dict[str, object]]:
    input_pair = tuple(_FdLease(fd, f"{role}-input") for fd in os.pipe2(os.O_CLOEXEC))
    output_pair = tuple(_FdLease(fd, f"{role}-output") for fd in os.pipe2(os.O_CLOEXEC))
    input_read, input_write = input_pair
    output_read, output_write = output_pair
    parent_status, child_status = ops.socketpair()
    process_owner = _ProcessOwner(ops)
    root_owner = _RootOwner(ops)
    root = root_owner.prepare()
    namespace_lease: _ProcessLease | None = None
    child_lease: _ProcessLease | None = None
    primary: BaseException | None = None
    result: tuple[bytes, dict[str, object]] | None = None
    limits_baseline = _parse_limits(_proc_bytes("/proc/self/limits", 65536, ops))
    try:
        pid, namespace_lease, gate = process_owner.spawn()
        if pid == 0:
            _close_socket(parent_status, ops, "namespace-parent-status")
            input_write.close(ops)
            output_read.close(ops)
            _require(gate is not None and ops.read(gate.fd, 1) == b"G", "namespace prerelease gate", "namespace-release")
            gate.close(ops)
            if root_owner.root is not None:
                root_owner.root.close(ops)
            if root_owner.parent is not None:
                root_owner.parent.close(ops)
            status_fd = child_status.detach()
            _namespace_owner(role, descriptors, rows, report, input_read.fd, output_write.fd, status_fd, root)
        _require(namespace_lease is not None, "namespace owner registration", "namespace-register")
        _close_socket(child_status, ops, "namespace-child-status")
        input_read.close(ops)
        output_write.close(ops)
        process_owner.release(namespace_lease)
        _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "namespace", 1)
        namespace_authority = _open_namespace_authority(namespace_lease, ops)
        command = _status("prepare-root", 1)
        _require(parent_status.send(command) == len(command), "root preparation send", "root-prepare-send")
        child = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "child", 2)
        child_lease = process_owner.register(child["pid"])
        namespace_lease.descendants = (child_lease,)
        command = _status("release-child", 2)
        _require(parent_status.send(command) == len(command), "child release send", "child-release-send")
        boundary_packet = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "boundary", 3)
        boundary = boundary_packet["observations"]
        _require(type(boundary) is dict, "boundary observations malformed", "boundary-observations")
        _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "exec-ready", 4)
        post_fds = _descriptor_snapshot(ops, child["pid"])
        _require(post_fds == (0, 1, 2), "post-exec descriptor table", "exec-fd-table")
        post_maps = _final_mapping_check(ops, child["pid"], rows, role, report)
        _require(_descendant_census(namespace_lease.pid, ops) == (child["pid"],), "registered descendant census", "descendant-census")
        command = _status("finalize-root", 3)
        _require(parent_status.send(command) == len(command), "root finalization send", "root-finalize-send")
        _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "root-final", 5)
        root_exact, no_proc, host_absent, checkout_absent = _final_mount_check(child["pid"], ops)
        namespace_facts = _namespace_facts(child["pid"], os.getuid(), os.getgid(), namespace_lease)
        final_fds = _descriptor_snapshot(ops, child["pid"])
        _require(final_fds == post_fds, "final descriptor drift", "final-fd-drift")
        final_maps = _final_mapping_check(ops, child["pid"], rows, role, report)
        _require(final_maps == post_maps, "final mapping drift", "final-map-drift")
        limits_exact = _parse_limits(_proc_bytes(f"/proc/{child['pid']}/limits", 65536, ops)) == limits_baseline
        payload = _FIXED_INPUT[role]
        offset = 0
        while offset < len(payload):
            written = ops.write(input_write.fd, payload[offset:])
            _require(written > 0, "fixed input short write", "input-write")
            offset += written
        input_write.close(ops)
        output = bytearray()
        deadline = time.monotonic() + _RUN_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            _require(remaining > 0 and bool(select.select([output_read.fd], [], [], remaining)[0]), "fixed output deadline", "output-deadline")
            part = ops.read(output_read.fd, 65536)
            if not part:
                break
            output += part
            _require(len(output) <= _MAX_OUTPUT, "fixed output bound", "output-bound")
        output_read.close(ops)
        final = _recv_status(parent_status, deadline, "exit", 6)
        _require(final["status"] == 0, "sandbox child exit", "child-exit")
        _require(bool(select.select([child_lease.pidfd.fd], [], [], 0)[0]), "child pidfd live after reap", "child-pidfd-live")
        child_lease.reaped = True
        process_owner.stop(child_lease)
        child_lease = None
        owner_status = _wait_bounded(namespace_lease, deadline)
        _require(owner_status == 0, "namespace owner exit", "namespace-owner-exit")
        process_owner.stop(namespace_lease)
        namespace_lease = None
        _require(bytes(output) == _FIXED_OUTPUT, "fixed output mismatch", "output-mismatch")
        capability_sets = boundary.get("capability_sets")
        _require(type(capability_sets) is dict and set(capability_sets) ==
                 {"effective", "permitted", "inheritable", "bounding", "ambient", "groups"},
                 "capability observation shape", "capability-observation")
        denials = boundary.get("seccomp_denials")
        expected_denials = set(_DENIED_SYSCALLS) | {"prctl:set", "execveat:shape"}
        denial_exact = type(denials) is dict and set(denials) == expected_denials
        denial_exact = denial_exact and all(value == errno.EPERM for value in denials.values())
        tool = {
            "ambient_capabilities_zero": not any(capability_sets["ambient"]), "bounding_capabilities_zero": not any(capability_sets["bounding"]),
            "capabilities_zero": boundary.get("capabilities_zero") is True and namespace_facts["capability_sets_zero"], "checkout_absent": checkout_absent,
            "effective_capabilities_zero": capability_sets["effective"] == 0, "exec_descriptor_consumed": 198 not in final_fds,
            "host_paths_absent": host_absent, "inheritable_capabilities_zero": capability_sets["inheritable"] == 0, "limits_exact": limits_exact,
            "mapped_generations_exact": final_maps == post_maps, "mount_namespace_exact": namespace_facts["mount_namespace_exact"],
            "namespace_handles_exact": namespace_authority["namespace_handles_exact"], "namespace_ownership_exact": namespace_authority["namespace_ownership_exact"],
            "network_namespace_exact": namespace_facts["network_namespace_exact"],
            "no_acquisition_route": denial_exact and final_fds == (0, 1, 2) and root_exact and no_proc and host_absent,
            "no_new_privs": boundary.get("no_new_privs") is True and namespace_facts["nnp_exact"], "noroot_locked": boundary.get("noroot_locked") is True,
            "permitted_capabilities_zero": capability_sets["permitted"] == 0, "pid_namespace_exact": namespace_facts["pid_namespace_exact"],
            "pid_one": namespace_facts["pid_one"], "root_has_no_proc": no_proc, "root_readonly_noexec": root_exact, "seccomp_denials_exact": denial_exact,
            "seccomp_installed": boundary.get("seccomp_program_sha256") == _seccomp_digest(),
            "seccomp_mode_exact": boundary.get("seccomp_mode") == _SECCOMP_MODE_FILTER and namespace_facts["seccomp_mode_exact"],
            "seccomp_program_exact": boundary.get("seccomp_program_sha256") == _seccomp_digest(),
            "supplementary_groups_empty": capability_sets["groups"] == () and namespace_facts["groups_empty"], "user_namespace_exact": namespace_facts["user_namespace_exact"],
        }
        result = bytes(output), tool
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try: process_owner.cleanup(primary)
    except BaseException as error: failures.append(error)
    for lease in (*input_pair, *output_pair):
        if lease.state is _FdState.OWNED:
            try: lease.close(ops)
            except BaseException as error: failures.append(error)
    try: _close_socket(parent_status, ops, "namespace-parent-status")
    except BaseException as error: failures.append(error)
    try: _close_socket(child_status, ops, "namespace-child-status")
    except BaseException as error: failures.append(error)
    try: root_owner.cleanup(primary)
    except BaseException as error: failures.append(error)
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    if isinstance(primary, RuntimeLauncherUnavailable): primary.cleanup_restored = root_owner.cleaned
    if primary is not None: raise primary
    _require(result is not None, "tool result missing", "tool-result")
    return result
def _worker_main(endpoint_fd: int, helper_fd: int, release_fd: int, nonce: bytes, admission: _SourceAdmission, closure_module: types.ModuleType, consumer_pid: int) -> NoReturn:
    ops = _SystemOps()
    release = _FdLease(release_fd, "worker-release-read")
    if ops.read(release.fd, 1) != b"G": os._exit(123)
    release.close(ops)
    endpoint = socket.socket(fileno=endpoint_fd)
    helper_endpoint = socket.socket(fileno=helper_fd)
    owner: object | None = None
    try:
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        package_name = str(closure_module.__package__)
        admission._package = package_name
        admission._worker_pid = os.getpid()
        admission._endpoint = endpoint
        admission._consumer_pid = consumer_pid
        admission._consumer_uid = os.getuid()
        admission._consumer_gid = os.getgid()
        issuer = _WorkerIssuer(endpoint, nonce, admission, consumer_pid, package_name, helper_endpoint)
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
        _close_socket(helper_endpoint, ops, "worker-helper-control")
        _close_socket(endpoint, ops, "worker-issuance")
        os._exit(0)
    except BaseException:
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                pass
        os._exit(124)
def _recover_transaction_with_ops(ops: Any, process_owner: _ProcessOwner, fd_leases: list[_FdLease], primary: BaseException | None) -> None:
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
def _coordinate_with_ops(admission: _SourceAdmission, closure_module: types.ModuleType, ops: Any) -> RuntimeQualificationResult:
    fact_names = _OBSERVATION_NAMES
    fd_baseline = _descriptor_snapshot(ops)
    child_baseline = _parse_children(_proc_bytes("/proc/self/task/self/children", 65536, ops))
    root = f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    mount_baseline = os.path.ismount(root)
    path_baseline = os.path.lexists(root)
    nonce = ops.nonce()
    parent_endpoint, worker_endpoint = ops.socketpair()
    helper_parent, helper_worker = ops.socketpair()
    process_owner = _ProcessOwner(ops)
    descriptor_leases: list[_FdLease] = []
    primary: BaseException | None = None
    outputs: tuple[bytes, bytes] | None = None
    observed_tools: tuple[dict[str, object], dict[str, object]] | None = None
    receipt: _IssuanceReceipt | None = None
    try:
        ops.prctl(_PR_SET_CHILD_SUBREAPER, 1)
        pid, worker, gate = process_owner.spawn()
        if pid == 0:
            _close_socket(parent_endpoint, ops, "issuance-parent")
            _close_socket(helper_parent, ops, "helper-parent")
            _require(gate is not None, "worker prerelease gate", "worker-release")
            _worker_main(worker_endpoint.detach(), helper_worker.detach(), gate.fd, nonce, admission, closure_module, os.getppid())
        _require(worker is not None, "worker registration", "worker-register")
        _close_socket(worker_endpoint, ops, "issuance-worker")
        _close_socket(helper_worker, ops, "helper-worker")
        process_owner.release(worker)
        report, descriptor_tuple, rows, receipt = _consume_worker_handoff(
            parent_endpoint, helper_parent, nonce, admission, pid, ops,
            process_owner, time.monotonic() + _SETUP_SECONDS,
        )
        descriptor_leases = list(descriptor_tuple)
        descriptors = tuple(lease.fd for lease in descriptor_leases)
        gzip_output, gzip_observed = _run_tool_with_ops(ops, "gzip", report, descriptors, rows)
        zstd_output, zstd_observed = _run_tool_with_ops(ops, "zstd", report, descriptors, rows)
        outputs = (gzip_output, zstd_output)
        observed_tools = (gzip_observed, zstd_observed)
        status = _wait_bounded(worker, time.monotonic() + _SETUP_SECONDS)
        _require(status == 0, "closure worker exit", "worker-exit")
        process_owner.stop(worker)
        _close_leases(ops, descriptor_leases)
        descriptor_leases.clear()
        _close_socket(parent_endpoint, ops, "issuance-parent")
        _close_socket(helper_parent, ops, "helper-parent")
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try: _recover_transaction_with_ops(ops, process_owner, descriptor_leases, primary)
    except BaseException as error: failures.append(error)
    for endpoint, purpose in ((parent_endpoint, "issuance-parent"), (worker_endpoint, "issuance-worker"), (helper_parent, "helper-parent"), (helper_worker, "helper-worker")):
        try: _close_socket(endpoint, ops, purpose)
        except BaseException as error: failures.append(error)
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    cleanup = {
        "children_reaped": _parse_children(_proc_bytes("/proc/self/task/self/children", 65536, ops)) == child_baseline,
        "descendants_reaped": not process_owner.processes and _descendant_census(os.getpid(), ops) == child_baseline,
        "descriptors_restored": _descriptor_snapshot(ops) == fd_baseline,
        "mounts_restored": os.path.ismount(root) == mount_baseline,
        "namespace_handles_released": not any(lease.namespace_handles for lease in process_owner.processes),
        "namespaces_released": not process_owner.processes,
        "paths_restored": os.path.lexists(root) == path_baseline,
    }
    if isinstance(primary, RuntimeLauncherUnavailable):
        primary.cleanup_restored = all(cleanup.values())
    if primary is not None: raise primary
    _require(observed_tools is not None and outputs is not None and receipt is not None, "coordinator result missing", "coordinator-result")
    observed = _build_observed_result(observed_tools, cleanup)
    return RuntimeQualificationResult(
        _RESULT_VERSION, _MARKER, admission.revision, admission.source_set_sha256,
        receipt.closure_sha256, hashlib.sha256(outputs[0]).hexdigest(),
        hashlib.sha256(outputs[1]).hexdigest(), *(observed[name] for name in fact_names),
    )
def _open_beneath(root_fd: int, path: str) -> int:
    components = path.split("/")
    _require(bool(components) and not any(not item or item in (".", "..") for item in components), "fixed source path components")
    ops = _SystemOps()
    directory = _FdLease(os.dup(root_fd), "source-directory")
    try:
        for component in components[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory.fd)
            next_directory = _FdLease(next_fd, "source-directory")
            directory.close(ops)
            directory = next_directory
            info = os.fstat(directory.fd)
            secure = stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            _require(secure, "fixed source ancestor policy")
        return os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory.fd)
    finally:
        directory.close(ops)
def _held_sources(root_fd: int) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    ops = _SystemOps()
    for path in _FIXED_SOURCE_SET:
        lease = _FdLease(_open_beneath(root_fd, path), "held-source")
        primary: BaseException | None = None
        try:
            before = os.fstat(lease.fd)
            _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o644, "fixed source file policy")
            data = _read_complete(lease.fd, before.st_size, _MAX_SOURCE)
            after = os.fstat(lease.fd)
            _require(_stat_identity(before) == _stat_identity(after), "fixed source generation drift")
            sources[path] = data
        except BaseException as error:
            primary = error
        try: lease.close(ops)
        except BaseException as error: raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
        if primary is not None: raise primary
    return sources
def _git_tree(root_fd: int, revision: str) -> dict[str, tuple[str, str]]:
    arguments = (
        "/usr/bin/git", "-C", f"/proc/self/fd/{root_fd}", "-c", "core.hooksPath=/dev/null", "ls-tree", "-rz", "--full-tree", revision, "--", *_FIXED_SOURCE_SET)
    environment = { "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", }
    try:
        completed = __import__("subprocess").run(
            arguments, env=environment, stdin=-3, stdout=-1, stderr=-1, pass_fds=(root_fd,), close_fds=True, timeout=5, check=False)
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
def _bootstrap_with_ops(ops: _SystemOps) -> int:
    _platform_gate()
    if len(sys.argv) != 1 or os.environ or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise RuntimeLauncherError("fixed bootstrap process envelope")
    executable = _FdLease(os.open("/proc/self/exe", os.O_PATH | os.O_CLOEXEC), "python-executable")
    admitted = _FdLease(os.open("/usr/bin/python3", os.O_PATH | os.O_CLOEXEC), "admitted-python")
    try:
        executable_identity = _stat_identity(os.fstat(executable.fd))[:2]
        admitted_identity = _stat_identity(os.fstat(admitted.fd))[:2]
        _require(executable_identity == admitted_identity, "fixed Python executable identity", "python-identity")
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
    _close_leases(ops, [_FdLease(3, "admission-input"), _FdLease(4, "checkout-root")])
    __import__("platform")
    sys.path[:] = []
    closure_module = _load_private_closure(sources, admission["source_set_sha256"])
    source_admission = _SourceAdmission(revision, admission["bootstrap_sha256"], admission["source_set_sha256"], sources[_SCHEMA_PATH], "", 0, None, None, 0, 0, 0)
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
