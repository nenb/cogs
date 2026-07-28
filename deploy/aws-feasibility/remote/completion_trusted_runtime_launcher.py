from __future__ import annotations
from array import array
from dataclasses import asdict, dataclass, field, fields, is_dataclass, make_dataclass
from enum import Enum
import ctypes, errno, fcntl, hashlib, json
import os, re, resource, select, signal, socket
import stat, struct, sys, time, types
from typing import Any, NoReturn, Optional
_VERSION = "cogs.trusted-runtime-closure/v1"
_ADMISSION_VERSION = "cogs.runtime-source-admission/v1"
_ADMISSION_MODES = {
    _ADMISSION_VERSION: "runtime",
    "cogs.runtime-source-admission/mapping-v1": "mapping",
    "cogs.runtime-source-admission/compression-v1": "compression",
    "cogs.runtime-source-admission/descriptor-v1": "descriptor",
    "cogs.runtime-source-admission/lifecycle-v1": "lifecycle",
    "cogs.runtime-source-admission/sandbox-v1": "sandbox",
}
_OPERATION_CLIENTS = {
    "mapping": "scripts/native-qualification/job-a-runtime-mappings.py",
    "compression": "scripts/native-qualification/job-b-compression.py",
    "descriptor": "scripts/native-qualification/job-c-descriptors.py",
    "lifecycle": "scripts/native-qualification/job-d-process-lifecycle.py",
    "sandbox": "scripts/native-qualification/job-e-sandbox.py",
    "runtime": "scripts/native-qualification/thin-integration.py",
}
_HANDOFF_VERSION = "cogs.runtime-handoff/v1"
_RESULT_VERSION = "cogs.runtime-qualification/v1"
_MARKER = "cogs-runtime-qualification-v1"
_BOOTSTRAP_OPERATION_TOKEN = object()
_FIXED_SOURCE_SET = ( "deploy/aws-feasibility/remote/completion_elf.py", "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py", "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", "schemas/trusted-runtime-closure-v1.json", )
_MODULE_PATHS = _FIXED_SOURCE_SET[:3]
_SCHEMA_PATH = _FIXED_SOURCE_SET[3]
_TOOL_INDEX = {"zstd": 1, "gzip": 2}
_FIXED_INPUT = { "gzip": bytes.fromhex("1f8b08000000000002ff4bce4f2fd62d2acd2bc9cc4dd52d2c4dccc94ccb4c4e" "2cc9cccfd32d33e40200a9c9b5521e000000"), "zstd": bytes.fromhex("28b52ffd201ef10000636f67732d72756e74696d652d7175616c696669636174696f6e2d76310a"), }
_FIXED_OUTPUT = b"cogs-runtime-qualification-v1\n"
(_MAX_ADMISSION, _MAX_SOURCE, _MAX_REPORT, _MAX_PACKET) = (512, 2_000_000, 128 * 1024, 256 * 1024)
(_MAX_OBJECT, _MAX_OBJECTS, _MAX_MAPS, _MAX_MAP_LINES) = (128 * 1024 * 1024, 256, 4 * 1024 * 1024, 4096)
_MAX_OUTPUT, _IO_CHUNK = 1024 * 1024, 1024 * 1024
_SETUP_SECONDS, _RUN_SECONDS, _TERM_SECONDS, _KILL_SECONDS = 10.0, 10.0, 1.0, 1.0
_ROOT_PARENT, _ROOT_LEAF = "/tmp", "cogs-o2-runtime-v1"
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
(_PR_SET_CHILD_SUBREAPER, _PR_GET_CHILD_SUBREAPER, _PR_CAP_AMBIENT, _PR_CAP_AMBIENT_IS_SET) = (36, 37, 47, 1)
_PR_CAP_AMBIENT_CLEAR_ALL, _PR_SET_SECCOMP, _PR_GET_SECCOMP = 4, 22, 21
_SECCOMP_MODE_FILTER, _SECBITS = 2, 0x0F
_AT_EMPTY_PATH, _UINT_MAX = 0x1000, (1 << 32) - 1
(_SYS_GETDENTS64, _SYS_CLONE3, _CLONE_PIDFD) = (217, 435, 0x00001000)
(_NS_GET_USERNS, _NS_GET_PARENT) = (0xB701, 0xB702)
_DENIED_SYSCALLS = { name: int(number) for entry in """
    execve:59 socket:41 connect:42 accept:43 sendto:44 recvfrom:45 sendmsg:46 recvmsg:47 shutdown:48 bind:49 listen:50 getsockname:51 getpeername:52 socketpair:53 setsockopt:54 getsockopt:55 accept4:288 recvmmsg:299 sendmmsg:307
    io_uring_setup:425 io_uring_enter:426 io_uring_register:427 clone:56 fork:57 vfork:58 clone3:435 unshare:272 setns:308
    mount:165 umount2:166 pivot_root:155 chroot:161 open_tree:428 move_mount:429 fsopen:430 fsconfig:431 fsmount:432 fspick:433 mount_setattr:442
    keyctl:250 add_key:248 request_key:249 perf_event_open:298 bpf:321 userfaultfd:323 ptrace:101 init_module:175 delete_module:176 finit_module:313
    setuid:105 setgid:106 setreuid:113 setregid:114 setgroups:116 setresuid:117 setresgid:119 setfsuid:122 setfsgid:123 capset:126 seccomp:317
    memfd_create:319 open_by_handle_at:304 name_to_handle_at:303 pidfd_open:434 pidfd_getfd:438 process_vm_readv:310 process_vm_writev:311 kexec_load:246 kexec_file_load:320 landlock_create_ruleset:444 landlock_add_rule:445 landlock_restrict_self:446 dup:32 dup2:33 dup3:292 fcntl:72
    """.split() for name, number in (entry.split(":"),) }
def _seccomp_program() -> tuple[tuple[int, int, int, int], ...]:
    deny = 0x00050000 | errno.EPERM
    rows = [ (0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0), (0x15, 0, 10, 322), (0x20, 0, 0, 16), (0x15, 0, 6, 198), (0x20, 0, 0, 20), (0x15, 0, 4, 0), (0x20, 0, 0, 48), (0x15, 0, 2, _AT_EMPTY_PATH), (0x20, 0, 0, 52), (0x15, 1, 0, 0), (0x06, 0, 0, deny), (0x06, 0, 0, 0x7FFF0000), (0x15, 0, 4, 157), (0x20, 0, 0, 16), (0x15, 1, 0, _PR_GET_SECCOMP), (0x06, 0, 0, deny), (0x06, 0, 0, 0x7FFF0000), (0x20, 0, 0, 0), ]
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
    if not condition: raise RuntimeLauncherError(message, code)
class _FdState(Enum):
    OWNED = "OWNED"
    CLOSED = "CLOSED"
    TRANSFERRED = "TRANSFERRED"
    CLOSE_UNCERTAIN = "CLOSE_UNCERTAIN"
class _FdLease(make_dataclass("_FdLeaseData", [("fd", int), ("purpose", str), ("state", _FdState, field(default=_FdState.OWNED)), ("close_error", Optional[BaseException], field(default=None))])):
    def close(self, ops: object) -> None:
        if self.state is _FdState.CLOSED:
            return
        if self.state is _FdState.CLOSE_UNCERTAIN:
            if self.close_error is None: raise RuntimeLauncherError("descriptor uncertainty lost", "fd-lease-poison")
            raise self.close_error
        if self.state is not _FdState.OWNED: raise RuntimeLauncherError("transferred descriptor close", "fd-lease-transferred")
        close = getattr(ops, "close", None)
        if not callable(close): raise TypeError("launcher Ops lacks close")
        try:
            close(self.fd)
        except BaseException as error:
            self.close_error = error
            self.state = _FdState.CLOSE_UNCERTAIN
            raise
        self.state = _FdState.CLOSED
    def transfer(self) -> int:
        if self.state is not _FdState.OWNED: raise RuntimeLauncherError("descriptor transfer state", "fd-lease-transfer")
        self.state = _FdState.TRANSFERRED
        return self.fd
def _close_leases(ops: object, leases: tuple[_FdLease, ...] | list[_FdLease], primary: BaseException | None = None) -> None:
    failures: list[BaseException] = []
    for lease in reversed(tuple(leases)):
        if lease.state is _FdState.CLOSE_UNCERTAIN:
            if lease.close_error is None:
                failures.append(RuntimeLauncherError( "descriptor uncertainty lost", "fd-lease-poison"))
            else:
                failures.append(lease.close_error)
            continue
        if lease.state is not _FdState.OWNED: continue
        try:
            lease.close(ops)
        except BaseException as error:
            failures.append(error)
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
class _SourceAdmission(make_dataclass("_SourceAdmissionData", [(name, kind) for name, kind in zip("revision bootstrap_sha256 source_set_sha256 _schema_bytes _package _worker_pid _endpoint _issuer _consumer_pid _consumer_uid _consumer_gid _operation".split(), (str, str, str, bytes, str, int, Optional[socket.socket], object, int, int, int, str))] + [("_claimed", bool, field(default=False))])):
    def _consume_fixed_operation(self, operation: str, module: types.ModuleType) -> bool:
        package = f"_cogs_o2_{self.source_set_sha256[:16]}"
        closure_name = f"{package}.completion_trusted_runtime_closure"
        exact_module = module.__name__ == closure_name and module.__package__ == package
        exact_module = exact_module and sys.modules.get(closure_name) is module
        exact_module = exact_module and module.__dict__.get("_ADMISSION_TYPE") is _SourceAdmission
        exact = not self._claimed and operation == self._operation and type(module) is types.ModuleType and exact_module
        if exact:
            self._claimed = True
        return exact
    def _consume(self, issuer: object, package: object, worker_pid: object) -> bool:
        if self._claimed or issuer is not self._issuer: return False
        if package != self._package: return False
        if worker_pid != self._worker_pid or os.getpid() != self._worker_pid: return False
        peer = self._endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        peer_credentials = struct.unpack("3i", peer)
        expected = (self._consumer_pid, self._consumer_uid, self._consumer_gid)
        if peer_credentials != expected: return False
        self._claimed = True
        return True
    def _validate_tracked_schema(self, canonical_report: bytes) -> None:
        _validate_tracked_report(self._schema_bytes, canonical_report)
_GenerationRow = make_dataclass("_GenerationRow", [ ("tool_index", int), ("object_index", int), ("role", str), ("descriptor_index", int), ("size", int), ("sha256", str), ("soname", Optional[str]), ("needed", tuple[str, ...]), ("seal_profile", str), ("source_generation", tuple[int, ...]), ], frozen=True, namespace={"__module__": __name__})
_IssuanceReceipt = make_dataclass("_IssuanceReceipt", [*((name, str) for name in "version report_sha256 closure_sha256 binding_sha256 generation_sha256".split()), *((name, int) for name in "descriptor_count issuer_pid consumer_pid".split())], frozen=True, namespace={"__module__": __name__})
_RuntimeHelperToken = make_dataclass("_RuntimeHelperToken", [("value", str)], frozen=True, namespace={"__module__": __name__})
_OBSERVATION_NAMES = """
    mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact
    namespace_handles_exact pid_one supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero inheritable_capabilities_zero
    bounding_capabilities_zero ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
    seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route root_readonly_noexec root_has_no_proc
    host_paths_absent checkout_absent limits_exact descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
    namespaces_released namespace_handles_released
""".split()
RuntimeQualificationResult = make_dataclass("RuntimeQualificationResult", [(name, str) for name in "version marker source_revision source_set_sha256 closure_sha256 gzip_output_sha256 zstd_output_sha256".split()] + [(name, bool) for name in _OBSERVATION_NAMES], frozen=True, namespace={"__module__": __name__})
RuntimeObjectObservation = make_dataclass("RuntimeObjectObservation", [("role", str), ("size_bytes", int), ("sha256", str), ("soname", Optional[str]), ("needed", tuple)], frozen=True, namespace={"__module__": __name__})
MappedObjectObservation = make_dataclass("MappedObjectObservation", [("role", str), ("sha256", str)], frozen=True, namespace={"__module__": __name__})
RuntimeMappingQualificationResult = make_dataclass("RuntimeMappingQualificationResult", [
    *((name, str) for name in "version source_revision source_set_sha256 closure_sha256 mapping_sha256".split()),
    ("objects", tuple), ("mapped", tuple), *((name, bool) for name in "mapped_generations_exact mapping_stable helper_reaped descriptors_restored children_reaped".split()),
], frozen=True, namespace={"__module__": __name__})
RuntimeCompressionToolObservation = make_dataclass("RuntimeCompressionToolObservation", [
    ("id", str), ("objects", tuple), ("closure_sha256", str),
    ("mapping_sha256", str), ("source_sha256", str),
    ("source_size_bytes", int), ("sealed_sha256", str),
    ("sealed_size_bytes", int), ("seal_mask", int),
    ("execution_mapping_sha256", str), ("output_sha256", str),
], frozen=True, namespace={"__module__": __name__})
RuntimeCompressionParserObservation = make_dataclass(
    "RuntimeCompressionParserObservation",
    [("closure_sha256", str), ("objects", tuple)],
    frozen=True,
    namespace={"__module__": __name__},
)
RuntimeCompressionQualificationResult = make_dataclass("RuntimeCompressionQualificationResult", [
    ("version", str), ("source_revision", str), ("source_set_sha256", str),
    ("closure_sha256", str), ("parser", RuntimeCompressionParserObservation),
    ("tools", tuple), ("runtime", RuntimeQualificationResult),
], frozen=True, namespace={"__module__": __name__})
DescriptorQualificationResult = make_dataclass("DescriptorQualificationResult", [
    ("version", str), ("source_revision", str), ("source_set_sha256", str), *((name, bool) for name in "nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact inheritance_exact limit_restored descriptors_restored children_reaped".split()),
], frozen=True, namespace={"__module__": __name__})
SandboxQualificationResult = make_dataclass("SandboxQualificationResult", [
    *((name, str) for name in "version source_revision source_set_sha256 seccomp_program_sha256".split()), *((name, bool) for name in "user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact pid_one capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact seccomp_program_exact seccomp_denials_exact no_acquisition_route root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored namespaces_released namespace_handles_released".split()),
], frozen=True, namespace={"__module__": __name__})
LifecycleQualificationResult = make_dataclass("LifecycleQualificationResult", [
    ("version", str), ("source_revision", str), ("source_set_sha256", str), *((name, bool) for name in "pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated session_owned process_group_owned credentialed_pidfd_transfer stable_descendant_census adoption_exact term_kill_bounded siginfo_exact all_reaped subreaper_restored descriptors_restored".split()),
], frozen=True, namespace={"__module__": __name__})
def _build_observed_result(tool_observations: tuple[dict[str, object], dict[str, object]], cleanup_observations: dict[str, object]) -> dict[str, bool]:
    cleanup_keys = {"children_reaped", "descendants_reaped", "descriptors_restored", "mounts_restored", "namespace_handles_released", "namespaces_released", "paths_restored"}
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
        value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_float=reject_number, parse_constant=reject_number)
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
    """Consumer-owned canonical re-encoder independent of the producer codec."""
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
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode, value.st_uid, value.st_gid)
def _parse_fd_dirents(raw: bytes) -> tuple[int, ...]:
    offset = 0
    values: list[int] = []
    while offset < len(raw):
        if len(raw) - offset < 20: raise RuntimeLauncherError("truncated fd dirent", "fd-dirent-truncated")
        _inode, _position, length, _kind = struct.unpack_from("=QqHB", raw, offset)
        if length < 20 or offset + length > len(raw): raise RuntimeLauncherError("malformed fd dirent", "fd-dirent-shape")
        name_field = raw[offset + 19:offset + length]
        end = name_field.find(b"\0")
        if end < 0: raise RuntimeLauncherError("unterminated fd dirent", "fd-dirent-name")
        name = name_field[:end]
        if name not in (b".", b".."):
            if not name.isdigit() or (len(name) > 1 and name.startswith(b"0")): raise RuntimeLauncherError("invalid fd dirent", "fd-dirent-value")
            value = int(name)
            if value > 2147483647 or value in values: raise RuntimeLauncherError("duplicate fd dirent", "fd-dirent-duplicate")
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
            if not chunk: break
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
    if primary is not None: raise primary
    return result
def _platform_gate() -> None:
    if sys.platform != "linux" or not hasattr(os, "uname") or os.uname().machine != "x86_64": raise RuntimeLauncherUnavailable("fixed launcher requires Linux x86_64")
class _SystemOps:
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)
    def _checked(self, result: int, name: str) -> int:
        if result == -1:
            saved = ctypes.get_errno()
            if saved in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EINVAL): raise RuntimeLauncherUnavailable(name)
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
        # Return the complete atomic result.  The creator must retain a positive
        # PID even when the secondary pidfd result is unusable so it can close
        # the child's gate and reap that exact direct child.
        return pid, pidfd.value
    def getdents(self, fd: int, maximum: int = 32768) -> bytes:
        buffer = ctypes.create_string_buffer(maximum)
        count = self._checked(self.libc.syscall(_SYS_GETDENTS64, fd, ctypes.byref(buffer), maximum), "getdents64")
        return bytes(buffer.raw[:count])
    def socketpair(self) -> tuple[socket.socket, socket.socket]:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        adopted_sockets = ((left, "socketpair-left"), (right, "socketpair-right"))
        try:
            left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        except BaseException as primary:
            failures: list[BaseException] = []
            for endpoint, purpose in adopted_sockets:
                try:
                    _close_socket(endpoint, self, purpose)
                except BaseException as error:
                    failures.append(error)
            if failures:
                raise RuntimeLauncherCleanupError(primary, failures) from primary
            raise
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
            generation = (generation.device, generation.inode, generation.size, generation.mtime_ns, generation.ctime_ns, generation.mode, generation.uid, generation.gid)
        row = _GenerationRow(value.tool_index, value.object_index, value.role, value.descriptor_index, value.size, value.sha256, value.soname, tuple(value.needed), value.seal_profile, tuple(generation))
    except (AttributeError, TypeError) as error:
        raise RuntimeLauncherError("invalid private generation row") from error
    return _checked_row(row)
def _row_value(row: _GenerationRow) -> list[object]:
    return [row.tool_index, row.object_index, row.role, row.descriptor_index, row.size, row.sha256, row.soname, list(row.needed), row.seal_profile, list(row.source_generation)]
def _binding_value(row: _GenerationRow) -> dict[str, object]:
    return {"descriptor_index": row.descriptor_index, "needed": list(row.needed), "object_index": row.object_index, "role": row.role, "seal_profile": row.seal_profile, "sha256": row.sha256, "size": row.size, "soname": row.soname, "tool_index": row.tool_index}
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
    checked: dict[int, tuple[int, str, tuple[int, ...]]] = {}
    for row in rows:
        expected = (row.size, row.sha256, row.source_generation)
        _require(row.descriptor_index not in checked or checked[row.descriptor_index] == expected, "conflicting descriptor alias")
        if row.descriptor_index not in checked:
            _inspect_fd(descriptors[row.descriptor_index], False, row.size, row.sha256)
            checked[row.descriptor_index] = expected
    return report, _digest([_binding_value(row) for row in rows]), _digest([_generation_value(row) for row in rows])
def _closed_compression_objects(objects: list[dict[str, object]]) -> tuple[dict[str, object], ...]:
    return tuple({
        "needed": tuple(item["needed"]),
        "role": item["role"],
        "sha256": item["sha256"],
        "size_bytes": item["size"],
        "soname": item["soname"],
    } for item in objects)
def _runtime_metadata(report: dict[str, object], rows: tuple[_GenerationRow, ...], mapping_sha: tuple[str, str], outputs: tuple[bytes, bytes]) -> tuple[RuntimeCompressionToolObservation, RuntimeCompressionToolObservation]:
    compressed: list[RuntimeCompressionToolObservation] = []
    for name, index, observed_mapping, output in zip(("gzip", "zstd"), (2, 1), mapping_sha, outputs):
        objects = report["tools"][index]["objects"]
        source_rows = tuple((item["role"], item["sha256"], item["size"]) for item in objects)
        sealed_rows = tuple((row.role, row.sha256, row.size) for row in rows if row.tool_index == index)
        _require(source_rows == sealed_rows and objects[0]["role"] == "executable", "runtime metadata row binding", "runtime-metadata")
        _require(observed_mapping == report["tools"][index]["mapping_sha256"], "runtime metadata mapping observation", "runtime-metadata")
        _require(output == _FIXED_OUTPUT, "runtime metadata fixed output", "runtime-output")
        closed_objects = _closed_compression_objects(objects)
        compressed.append(RuntimeCompressionToolObservation(
            id=name,
            objects=closed_objects,
            closure_sha256=report["tools"][index]["closure_sha256"],
            mapping_sha256=report["tools"][index]["mapping_sha256"],
            source_sha256=objects[0]["sha256"],
            source_size_bytes=objects[0]["size"],
            sealed_sha256=sealed_rows[0][1],
            sealed_size_bytes=sealed_rows[0][2],
            seal_mask=_EXEC_SEALS,
            execution_mapping_sha256=observed_mapping,
            output_sha256=hashlib.sha256(output).hexdigest(),
        ))
    return compressed[0], compressed[1]
def _credential_ancillary(rights: tuple[int, ...] = ()) -> list[tuple[int, int, object]]:
    ancillary: list[tuple[int, int, object]] = [
        (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", os.getpid(), os.getuid(), os.getgid())),
    ]
    if rights:
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", rights)))
    return ancillary
class _WorkerIssuer:
    def __init__( self, endpoint: socket.socket, nonce: bytes, admission: _SourceAdmission, consumer_pid: int, package_name: str, helper_endpoint: socket.socket | None = None):
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
        ancillary = _credential_ancillary(rights)
        _require(endpoint.sendmsg([raw], ancillary, socket.MSG_DONTWAIT) == len(raw), "helper control send", "helper-control-send")
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([endpoint], [], [], remaining)[0], "helper acknowledgement deadline", "helper-deadline")
        reply, ancillary, flags, _address = endpoint.recvmsg(1024, 256, socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
        credentials, leases = _leased_credentials(ancillary, _SystemOps(), require_rights=False, missing_code="helper-ack-credentials-missing")
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
        request = {"event": "register", "executable": list(executable), "gates": list(gates), "pid": values[0], "process_group": values[3], "sequence": self._helper_sequence, "session": values[2], "start_time": values[1], "target": list(target), "version": _RESULT_VERSION}
        reply = self._helper_exchange(request, (pidfd,), absolute_deadline)
        _require(set(reply) == {"event", "sequence", "token", "version"} and reply["event"] == "registered" and reply["sequence"] == self._helper_sequence and _sha(reply["token"]), "helper registration acknowledgement", "helper-register-ack")
        token = _RuntimeHelperToken(reply["token"])
        self._helper_tokens[token] = "registered"
        return token
    def _helper_transition(self, token: _RuntimeHelperToken, event: str, deadline: float) -> None:
        expected = "registered" if event == "release" else "released"
        _require(type(token) is _RuntimeHelperToken and self._helper_tokens.get(token) == expected, "helper token state", "helper-token")
        self._helper_sequence += 1
        request = {"event": event, "sequence": self._helper_sequence, "token": token.value, "version": _RESULT_VERSION}
        reply = self._helper_exchange(request, (), deadline)
        _require(reply == {"event": event + "d", "sequence": self._helper_sequence, "token": token.value, "version": _RESULT_VERSION}, "helper transition acknowledgement", "helper-transition-ack")
        if event == "retire": del self._helper_tokens[token]
        else: self._helper_tokens[token] = "released"
    def _release_runtime_helper(self, token: _RuntimeHelperToken, deadline: float) -> None:
        self._helper_transition(token, "release", deadline)
    def _retire_runtime_helper(self, token: _RuntimeHelperToken, deadline: float) -> None:
        self._helper_transition(token, "retire", deadline)
    def _consume_runtime_closure_capability(self, admission: object, package_name: str, worker_pid: int) -> tuple[socket.socket, tuple[int, int, int]]:
        if self._capability_used: raise RuntimeLauncherError("admission capability replay", "admission-replay")
        if admission is not self._admission or type(admission) is not _SourceAdmission: raise RuntimeLauncherError("admission authority mismatch", "admission-authority")
        if package_name != self._package_name: raise RuntimeLauncherError("synthetic package mismatch", "admission-package")
        if worker_pid != os.getpid() or worker_pid != admission._worker_pid: raise RuntimeLauncherError("admission worker mismatch", "admission-worker")
        if not admission._consume(self, package_name, worker_pid): raise RuntimeLauncherError("admission capability rejected", "admission-capability")
        self._capability_used = True
        expected = (self._consumer_pid, os.getuid(), os.getgid())
        return self._endpoint, expected
    def _accept_runtime_closure(self, canonical_report: bytes, descriptors: tuple[int, ...], generation_rows: tuple[object, ...]) -> _IssuanceReceipt:
        _require(not self._used, "issuer is one-shot")
        self._used = True
        _require(type(canonical_report) is bytes and type(descriptors) is tuple and type(generation_rows) is tuple, "issuer argument type")
        rows = tuple(_row_from_object(row) for row in generation_rows)
        report, binding_sha, generation_sha = _verify_bundle(self._admission, canonical_report, descriptors, rows)
        packet = { "binding_sha256": binding_sha, "closure_sha256": report["closure_sha256"], "descriptor_count": len(descriptors), "generation_rows": [_row_value(row) for row in rows], "generation_sha256": generation_sha, "nonce": self._nonce.hex(), "report_sha256": hashlib.sha256(canonical_report).hexdigest(), "revision": self._admission.revision, "source_set_sha256": self._admission.source_set_sha256, "version": _HANDOFF_VERSION, }
        raw = _canonical(packet)
        deadline = time.monotonic() + _SETUP_SECONDS
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([], [self._endpoint], [], remaining)[1], "issuance send deadline", "issuer-deadline")
        sent = self._endpoint.sendmsg([raw], _credential_ancillary(descriptors), socket.MSG_DONTWAIT)
        _require(sent == len(raw), "handoff packet partial send")
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([self._endpoint], [], [], remaining)[0], "issuance acknowledgement deadline", "issuer-deadline")
        ack_raw, ancillary, flags, _address = self._endpoint.recvmsg(_MAX_PACKET, 256, socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
        credentials, received = _leased_credentials(ancillary, _SystemOps(), require_rights=False, missing_code="issuance-ack-credentials-missing")
        expected_credentials = (self._consumer_pid, os.getuid(), os.getgid())
        _require(not flags and not received and credentials == expected_credentials, "issuance acknowledgement authority", "issuer-ack-authority")
        ack = _strict_json(ack_raw, False, _MAX_PACKET, "issuance acknowledgement")
        expected = { "binding_sha256": binding_sha, "consumer_pid": self._consumer_pid, "generation_sha256": generation_sha, "nonce": self._nonce.hex(), "report_sha256": packet["report_sha256"], "version": _HANDOFF_VERSION, }
        _require(ack == expected, "issuance acknowledgement mismatch")
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([self._endpoint], [], [], remaining)[0], "issuance EOF deadline", "issuer-deadline")
        _require(self._endpoint.recv(1, socket.MSG_DONTWAIT) == b"", "second consumer packet", "issuer-second-packet")
        self._endpoint.shutdown(socket.SHUT_WR)
        return _IssuanceReceipt(
            version=_HANDOFF_VERSION,
            report_sha256=packet["report_sha256"],
            closure_sha256=report["closure_sha256"],
            binding_sha256=binding_sha,
            generation_sha256=generation_sha,
            descriptor_count=len(descriptors),
            issuer_pid=os.getpid(),
            consumer_pid=self._consumer_pid,
        )
_ProcessLease = make_dataclass("_ProcessLease", [
    ("pid", int), ("pidfd", Optional[_FdLease]),
    *((name, int, field(default=0)) for name in "start_time session process_group".split()),
    ("executable", tuple[int, int], field(default=(0, 0))),
    ("release_gate", Optional[_FdLease], field(default=None)),
    ("pending", tuple[_FdLease, ...], field(default=())),
    *((name, bool, field(default=False)) for name in "released reaped".split()),
    ("descendants", tuple, field(default=())),
    ("namespace_handles", tuple[_FdLease, ...], field(default=())),
    ("expected_uid", int, field(default=0)),
    ("waitable", bool, field(default=True)), ("identity_phase", str, field(default="BLOCKED")),
    ("planned_session", int, field(default=0)), ("planned_group", int, field(default=0)),
    ("planned_executable", tuple[int, int], field(default=(0, 0))),
], namespace={"__module__": __name__})
class _ProcessOwner(make_dataclass(
    "_ProcessOwnerData",
    [
        ("ops", Any),
        ("processes", list[_ProcessLease], field(default_factory=list)),
        ("poisoned", Optional[BaseException], field(default=None)),
        ("transfers", set[str], field(default_factory=set)),
    ],
)):
    def register(
        self,
        pid: int,
        release_gate: _FdLease | None = None,
        pidfd_fd: int | None = None,
        waitable: bool = True,
        bind_received_pidfd: bool = False,
    ) -> _ProcessLease:
        lease = _ProcessLease(pid, None, release_gate=release_gate, waitable=waitable)
        descriptor = pidfd_fd if pidfd_fd is not None else os.pidfd_open(pid, 0)
        lease.pidfd = _FdLease(descriptor, f"pidfd:{pid}")
        try:
            if bind_received_pidfd:
                target = _stable_pidfd_target(descriptor, self.ops)
                _require(target == pid, "received pidfd target", "process-transfer-pidfd")
        except BaseException as primary:
            try:
                lease.pidfd.close(self.ops)
            except BaseException as error:
                raise RuntimeLauncherCleanupError(primary, [error]) from primary
            raise
        lease.expected_uid = os.geteuid()
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
        lease = _ProcessLease(0, None, release_gate=write_lease, pending=(read_lease,))
        self.processes.append(lease)
        pid, pidfd = self.ops.clone_pidfd()
        if pid > 0:
            lease.pid = pid
            if pidfd < 0:
                primary = RuntimeLauncherUnavailable("clone3-pidfd")
                _settle_pidfdless_clone(lease, self.ops, primary)
                self.processes.remove(lease)
                primary.cleanup_restored = True
                raise primary
            lease.pidfd = _FdLease(pidfd, f"pidfd:{pid}")
        if pid == 0:
            self.processes.remove(lease)
            write_lease.close(self.ops)
            return 0, None, read_lease
        lease.expected_uid = os.geteuid()
        read_lease.close(self.ops)
        lease.pending = ()
        lease.start_time = _start_time(pid)
        lease.session = os.getsid(pid)
        lease.process_group = os.getpgid(pid)
        lease.executable = _exe_identity(pid)
        return pid, lease, None
    def plan_setsid(self, lease: _ProcessLease) -> None:
        planned = lease in self.processes
        planned = planned and not lease.released
        planned = planned and lease.identity_phase == "BLOCKED"
        _require(planned, "setsid plan state", "process-transition-state")
        lease.planned_session = lease.pid
        lease.planned_group = lease.pid
        lease.identity_phase = "PRE_SETSID"
    def release(self, lease: _ProcessLease) -> None:
        gate = lease.release_gate
        valid = gate is not None and gate.state is _FdState.OWNED
        valid = valid and not lease.released
        _require(valid, "process release gate state", "process-release-gate")
        written = self.ops.write(gate.fd, b"G")
        _require(written == 1, "process release short write", "process-release-write")
        lease.released = True
        gate.close(self.ops)
    def confirm_setsid(self, lease: _ProcessLease) -> None:
        immutable = (_start_time(lease.pid), _exe_identity(lease.pid))
        expected = (lease.start_time, lease.executable)
        observed = (os.getsid(lease.pid), os.getpgid(lease.pid))
        target = (lease.planned_session, lease.planned_group)
        phase_exact = lease.identity_phase == "PRE_SETSID"
        _require(phase_exact and immutable == expected, "setsid immutable identity", "process-transition-identity")
        target_exact = target == (lease.pid, lease.pid)
        _require(target_exact and observed == target, "setsid transition readback", "process-transition-readback")
        lease.session = observed[0]
        lease.process_group = observed[1]
        lease.identity_phase = "POST_SETSID"
    def plan_exec(self, lease: _ProcessLease, executable: tuple[int, int]) -> None:
        planned = lease in self.processes
        planned = planned and not lease.released
        planned = planned and lease.identity_phase == "BLOCKED"
        target_exact = type(executable) is tuple and len(executable) == 2
        target_exact = target_exact and all(type(value) is int and value > 0 for value in executable)
        _require(planned and target_exact, "exec plan state", "process-transition-state")
        lease.planned_executable = executable
        lease.identity_phase = "PRE_EXEC"
    def confirm_exec(self, lease: _ProcessLease) -> None:
        observed = (
            _start_time(lease.pid),
            os.getsid(lease.pid),
            os.getpgid(lease.pid),
            _exe_identity(lease.pid),
        )
        expected = (
            lease.start_time,
            lease.session,
            lease.process_group,
            lease.planned_executable,
        )
        phase_exact = lease.identity_phase == "PRE_EXEC"
        _require(phase_exact and observed == expected, "exec transition readback", "process-transition-readback")
        lease.executable = observed[3]
        lease.identity_phase = "POST_EXEC"
    def receive_descendant(
        self,
        endpoint: socket.socket,
        leader: _ProcessLease,
        nonce: bytes,
        sequence: int,
        deadline: float | None = None,
        case: str | None = None,
        role: str | None = None,
    ) -> _ProcessLease:
        # Non-socket endpoints exist only in portable adapters.  Production
        # transfers always bind the received kernel pidfd identity.
        modeled_endpoint = not isinstance(endpoint, socket.socket)
        portable = deadline is None and modeled_endpoint
        if not portable:
            _require(deadline is not None, "descendant transfer deadline missing", "process-transfer-deadline")
            remaining = deadline - time.monotonic()
            ready = remaining > 0 and bool(select.select([endpoint], [], [], remaining)[0])
            _require(ready, "descendant transfer deadline", "process-transfer-deadline")
        bound = socket.CMSG_SPACE(array("i").itemsize)
        bound += socket.CMSG_SPACE(struct.calcsize("3i"))
        flags_in = socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT
        raw, ancillary, flags, _address = endpoint.recvmsg(4096, bound, flags_in)
        credentials, rights = _leased_credentials(ancillary, self.ops)
        primary: BaseException | None = None
        lease: _ProcessLease | None = None
        try:
            truncated = flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            _require(not truncated and len(rights) == 1, "descendant transfer truncation", "process-transfer-shape")
            expected_credentials = (leader.pid, os.geteuid(), os.getegid())
            _require(credentials == expected_credentials, "descendant transfer credentials", "process-transfer-credentials")
            value = _strict_json(raw, False, 4096, "descendant transfer")
            legacy_keys = {
                "executable", "nonce", "parent", "pid", "process_group",
                "sequence", "session", "start_time", "version",
            }
            strict_keys = legacy_keys | {"case", "role", "transfer"}
            expected_keys = legacy_keys if portable else strict_keys
            valid_packet = type(value) is dict and set(value) == expected_keys
            valid_packet = valid_packet and value["version"] == "cogs.process-transfer/v1"
            _require(valid_packet, "descendant transfer packet", "process-transfer-packet")
            binding = value["nonce"] == nonce.hex()
            binding = binding and value["sequence"] == sequence
            binding = binding and value["parent"] == leader.pid
            if not portable:
                transfer = hashlib.sha256(nonce + _canonical([case, role, sequence])).hexdigest()
                binding = binding and value["case"] == case and value["role"] == role
                binding = binding and value["transfer"] == transfer
                _require(transfer not in self.transfers, "descendant transfer replay", "process-transfer-replay")
            _require(binding, "descendant transfer binding", "process-transfer-binding")
            pidfd = rights[0].transfer()
            lease = self.register(
                value["pid"],
                pidfd_fd=pidfd,
                waitable=False,
                bind_received_pidfd=not modeled_endpoint,
            )
            observed = (
                lease.start_time,
                lease.session,
                lease.process_group,
                list(lease.executable),
            )
            asserted = (
                value["start_time"],
                value["session"],
                value["process_group"],
                value["executable"],
            )
            _require(observed == asserted, "descendant transfer identity", "process-transfer-identity")
            if not portable:
                remaining = deadline - time.monotonic()
                ready = remaining > 0 and bool(select.select([endpoint], [], [], remaining)[0])
                _require(ready, "descendant transfer EOF deadline", "process-transfer-deadline")
                trailing = endpoint.recv(1, socket.MSG_DONTWAIT)
                _require(trailing == b"", "descendant transfer replay", "process-transfer-replay")
                self.transfers.add(value["transfer"])
            leader.descendants = (*leader.descendants, lease)
            return lease
        except BaseException as error:
            primary = error
        failures: list[BaseException] = []
        if not modeled_endpoint and lease is not None and lease in self.processes and lease not in leader.descendants:
            try:
                _require(lease.pidfd is not None, "rejected transfer pidfd", "process-authority")
                lease.pidfd.close(self.ops)
                self.processes.remove(lease)
            except BaseException as error:
                failures.append(error)
        try:
            _close_leases(self.ops, rights, primary)
        except BaseException as error:
            failures.append(error)
        if failures:
            raise RuntimeLauncherCleanupError(primary, failures) from primary
        raise primary
    def stable_census(self, root: _ProcessLease) -> tuple[int, ...]:
        first = _descendant_census(root.pid, self.ops)
        second = _descendant_census(root.pid, self.ops)
        expected = tuple(sorted(item.pid for item in root.descendants if not item.reaped))
        _require(first == second == expected, "stable registered descendant census", "process-census")
        return first
    def stable_identity_census(self, root: _ProcessLease) -> tuple[tuple[object, ...], ...]:
        first = _descendant_identity_edges(root.pid, self.ops)
        second = _descendant_identity_edges(root.pid, self.ops)
        expected = tuple(
            sorted(
                (root.pid, item.pid, item.start_time, *item.executable)
                for item in root.descendants
                if not item.reaped
            )
        )
        _require(first == second == expected, "stable descendant identity graph", "process-census")
        return first
    def stop(self, lease: _ProcessLease, primary: BaseException | None = None) -> None:
        _stop_process(lease, primary, self.ops)
        if lease in self.processes:
            self.processes.remove(lease)
    def cleanup(self, primary: BaseException | None = None) -> None:
        if self.poisoned is not None:
            raise self.poisoned
        failures: list[BaseException] = []
        for lease in tuple(self.processes):
            try:
                self.stop(lease, primary)
            except BaseException as error:
                failures.append(error)
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
    _require(raw.startswith(prefix) and raw.endswith(b"\n") and raw.count(b"\n") == 1, "process stat framing", "stat-framing")
    marker = raw.rfind(b") ")
    command = raw[len(prefix):marker]
    _require(marker > len(prefix) and len(command) <= 15 and not any(byte < 0x20 or byte == 0x7f for byte in command), "process stat comm", "stat-comm")
    fields = raw[marker + 2:-1].split(b" ")
    _require(len(fields) == 50 and len(fields[0]) == 1 and fields[0] in b"RSDZTWtXxIKP", "process stat shape", "stat-shape")
    values: list[int] = []
    for field in fields[1:]:
        _require(re.fullmatch(rb"(?:0|-?[1-9][0-9]*)", field) is not None, "process stat lexical field", "stat-lexical")
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
    _require(bool(nspid) and all(re.fullmatch(rb"[1-9][0-9]*", item) and int(item) <= 2147483647 for item in nspid), "NSpid field", "status-nspid")
    _require(all(re.fullmatch(rb"0|[1-9][0-9]*", item) and int(item) <= _UINT_MAX for item in groups), "Groups field", "status-groups")
    result: dict[str, object] = {"nspid": tuple(int(item) for item in nspid), "groups": tuple(int(item) for item in groups)}
    for key, name in ((b"CapInh", "inheritable"), (b"CapPrm", "permitted"), (b"CapEff", "effective"), (b"CapBnd", "bounding"), (b"CapAmb", "ambient")):
        value = records[key]
        _require(re.fullmatch(rb"[0-9a-f]{16}", value) is not None, "capability status field", "status-capability")
        result[name] = int(value, 16)
    for key, name, maximum in ((b"NoNewPrivs", "no_new_privs", 1), (b"Seccomp", "seccomp", 2)):
        value = records[key]
        _require(re.fullmatch(rb"0|[1-9][0-9]*", value) is not None and int(value) <= maximum, "security status field", "status-security")
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

def _pidfd_target(fd: int, ops: Any) -> int:
    raw = _proc_bytes(f"/proc/self/fdinfo/{fd}", 4096, ops)
    targets: list[int] = []
    for line in raw.splitlines():
        key, separator, value = line.partition(b":")
        if key != b"Pid":
            continue
        _require(bool(separator) and value.startswith(b"\t"), "pidfd fdinfo shape", "process-transfer-pidfd")
        lexical = value[1:]
        _require(re.fullmatch(rb"[1-9][0-9]*", lexical) is not None, "pidfd target value", "process-transfer-pidfd")
        targets.append(int(lexical))
    _require(len(targets) == 1, "pidfd target cardinality", "process-transfer-pidfd")
    return targets[0]

def _stable_pidfd_target(fd: int, ops: Any) -> int:
    descriptor_identity = _stat_identity(os.fstat(fd))
    observations: list[int] = []
    for _attempt in range(3):
        before = _stat_identity(os.fstat(fd))
        observations.append(_pidfd_target(fd, ops))
        after = _stat_identity(os.fstat(fd))
        _require(
            before == after == descriptor_identity,
            "pidfd descriptor generation drift",
            "process-transfer-pidfd",
        )
    _require(
        observations[0] == observations[1] == observations[2],
        "pidfd target drift",
        "process-transfer-pidfd",
    )
    return observations[0]

def _settle_pidfdless_clone(lease: _ProcessLease, ops: Any, primary: BaseException) -> None:
    failures: list[BaseException] = []
    for descriptor in (*lease.pending, lease.release_gate):
        if descriptor is None or descriptor.state is not _FdState.OWNED:
            continue
        try:
            descriptor.close(ops)
        except BaseException as error:
            failures.append(error)
    graceful_deadline = time.monotonic() + _TERM_SECONDS
    while time.monotonic() < graceful_deadline:
        try:
            observed, _status = os.waitpid(lease.pid, os.WNOHANG)
        except BaseException as error:
            failures.append(error)
            break
        if observed == lease.pid:
            lease.reaped = True
            break
        if observed != 0:
            failures.append(RuntimeLauncherError("pidfdless child wait identity", "process-reap"))
            break
        time.sleep(min(0.001, max(0.0, graceful_deadline - time.monotonic())))
    if not lease.reaped:
        # The positive clone result is still an unreaped direct child, so its
        # numeric PID cannot have been recycled.  This is the sole safe
        # pidfdless signal path and exists only to settle malformed clone3
        # secondary results.
        try:
            os.kill(lease.pid, signal.SIGKILL)
            kill_deadline = time.monotonic() + _KILL_SECONDS
            while time.monotonic() < kill_deadline:
                observed, _status = os.waitpid(lease.pid, os.WNOHANG)
                if observed == lease.pid:
                    lease.reaped = True
                    break
                _require(observed == 0, "pidfdless child wait identity", "process-reap")
                time.sleep(min(0.001, max(0.0, kill_deadline - time.monotonic())))
        except BaseException as error:
            failures.append(error)
    if not lease.reaped:
        failures.append(RuntimeLauncherError("pidfdless child reap deadline", "process-reap"))
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from primary
def _process_matches(lease: _ProcessLease) -> bool:
    try:
        start_time = _start_time(lease.pid)
        executable = _exe_identity(lease.pid)
        observed = (os.getsid(lease.pid), os.getpgid(lease.pid))
        if start_time != lease.start_time:
            return False
        if lease.identity_phase == "PRE_EXEC":
            if observed != (lease.session, lease.process_group):
                return False
            if executable == lease.executable:
                return True
            if executable != lease.planned_executable:
                return False
            # Cleanup may observe the preregistered exec before the happy-path
            # confirmation. Commit only that exact executable transition.
            lease.executable = executable
            lease.identity_phase = "POST_EXEC"
            return True
        if executable != lease.executable:
            return False
        if lease.identity_phase != "PRE_SETSID":
            return observed == (lease.session, lease.process_group)
        before = (lease.session, lease.process_group)
        after = (lease.planned_session, lease.planned_group)
        if observed == before:
            return True
        if after != (lease.pid, lease.pid) or observed != after:
            return False
        # Cleanup may observe the preregistered transition before the happy-path
        # confirmation. Commit only the planned, immutable transition.
        lease.session = observed[0]
        lease.process_group = observed[1]
        lease.identity_phase = "POST_SETSID"
        return True
    except (OSError, RuntimeLauncherError):
        return False
def _wait_bounded(lease: _ProcessLease, deadline: float) -> int | None:
    while time.monotonic() < deadline:
        try:
            observed, status = os.waitpid(lease.pid, os.WNOHANG)
        except ChildProcessError:
            if lease.waitable:
                raise RuntimeLauncherCleanupError(
                    None,
                    [RuntimeLauncherError("owned direct child is not waitable", "process-reap")],
                )
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
            continue
        # A successful waitpid call, including a live zero result, is the
        # kernel proof that a transferred descendant is now our direct child.
        lease.waitable = True
        if observed == lease.pid:
            lease.reaped = True
            return status
        if observed != 0: raise RuntimeLauncherCleanupError(None, [RuntimeLauncherError("unexpected wait result", "unexpected-wait")])
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    return None
def _stop_process(lease: _ProcessLease, primary: BaseException | None, ops: Any | None = None) -> None:
    actual_ops = ops or _SystemOps()
    failures: list[BaseException] = []
    for descriptor in (*lease.pending, lease.release_gate):
        if descriptor is None: continue
        if descriptor.state is _FdState.CLOSE_UNCERTAIN:
            failures.append(descriptor.close_error or RuntimeLauncherError("process descriptor poison"))
        elif descriptor.state is _FdState.OWNED:
            try: descriptor.close(actual_ops)
            except BaseException as error: failures.append(error)
    pidfd = lease.pidfd
    death_ready = False
    if lease.pid == 0:
        lease.reaped = True
    elif pidfd is None:
        failures.append(RuntimeLauncherError("owned process lacks pidfd", "process-authority"))
    elif pidfd.state is not _FdState.OWNED:
        failures.append(
            pidfd.close_error
            or RuntimeLauncherError("owned process pidfd is not authoritative", "process-authority")
        )
    elif not lease.reaped:
        death_ready = bool(select.select([pidfd.fd], [], [], 0)[0])
    if not lease.reaped and death_ready:
        try:
            observed, _status = os.waitpid(lease.pid, os.WNOHANG)
        except ChildProcessError as error:
            failures.append(RuntimeLauncherError(str(error), "process-reap"))
        else:
            if observed != lease.pid:
                failures.append(RuntimeLauncherError("owned process wait identity", "process-reap"))
            else:
                lease.waitable = True
                lease.reaped = True
    if lease.pid and pidfd is not None and pidfd.state is _FdState.OWNED and not lease.reaped and not death_ready:
        try:
            identity_required = lease.start_time != 0
            if identity_required and not _process_matches(lease): raise RuntimeLauncherError("owned process identity uncertain before TERM", "process-identity")
            signal.pidfd_send_signal(pidfd.fd, signal.SIGTERM)
            if _wait_bounded(lease, time.monotonic() + _TERM_SECONDS) is None:
                if identity_required and not _process_matches(lease): raise RuntimeLauncherError("owned process identity uncertain before KILL", "process-identity")
                signal.pidfd_send_signal(pidfd.fd, signal.SIGKILL)
                if _wait_bounded(lease, time.monotonic() + _KILL_SECONDS) is None: raise RuntimeLauncherError("owned process reap deadline")
        except BaseException as error:
            failures.append(error)
    if lease.reaped:
        for handle in reversed(lease.namespace_handles):
            if handle.state is _FdState.OWNED:
                try: handle.close(actual_ops)
                except BaseException as error: failures.append(error)
        if pidfd is not None and pidfd.state is _FdState.CLOSE_UNCERTAIN:
            failures.append(pidfd.close_error or RuntimeLauncherError("pidfd poison", "pidfd-poison"))
        elif pidfd is not None and pidfd.state is _FdState.OWNED:
            try: pidfd.close(actual_ops)
            except BaseException as error: failures.append(error)
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
def _received_leases(descriptors: tuple[int, ...]) -> tuple[_FdLease, ...]:
    _require(type(descriptors) is tuple and all(type(fd) is int and fd >= 0 for fd in descriptors), "received descriptor shape", "issuer-rights-value")
    return tuple(_FdLease(fd, f"received:{index}") for index, fd in enumerate(descriptors))
def _leased_credentials(ancillary: list[tuple[int, int, bytes]], ops: Any, require_rights: bool | None = True, missing_code: str = "issuer-credentials-missing") -> tuple[tuple[int, int, int], tuple[_FdLease, ...]]:
    credentials: tuple[int, int, int] | None = None
    leases: list[_FdLease] = []
    primary: BaseException | None = None
    item_size = array("i").itemsize
    try:
        # Lease every kernel-installed right before any ordered semantic rejection.
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array("i")
                values.frombytes(data[:len(data) - len(data) % item_size])
                leases.extend(_received_leases(tuple(values)))
        rights_seen = False
        for level, kind, data in ancillary:
            _require(level == socket.SOL_SOCKET, "handoff ancillary level", "issuer-ancillary")
            if kind == socket.SCM_CREDENTIALS:
                _require(credentials is None and len(data) == struct.calcsize("3i"), "handoff credentials cardinality", "issuer-credentials-cardinality")
                credentials = struct.unpack("3i", data)
            elif kind == socket.SCM_RIGHTS:
                _require(bool(data) and len(data) % item_size == 0, "handoff rights alignment", "issuer-rights-alignment")
                _require(not rights_seen, "handoff rights cardinality", "issuer-rights-cardinality")
                rights_seen = True
            else: raise RuntimeLauncherError("handoff ancillary type", "issuer-ancillary")
        _require(credentials is not None, "handoff credentials missing", missing_code)
        if require_rights is not None:
            _require(bool(leases) if require_rights else not leases, "handoff rights missing or extra", "issuer-rights-missing" if require_rights else "issuer-rights-extra")
        return credentials, tuple(leases)
    except BaseException as error: primary = error
    _close_leases(ops, leases, primary)
    raise primary
def _consume_issuance(endpoint: socket.socket, nonce: bytes, admission: _SourceAdmission, issuer_pid: int, ops: Any | None = None, deadline: float | None = None, ) -> tuple[dict[str, object], tuple[_FdLease, ...], tuple[_GenerationRow, ...], _IssuanceReceipt]:
    actual_ops = ops or _SystemOps()
    deadline = deadline if deadline is not None else time.monotonic() + _SETUP_SECONDS
    remaining = deadline - time.monotonic()
    _require(remaining > 0 and select.select([endpoint], [], [], remaining)[0], "issuance packet deadline", "issuer-deadline")
    ancillary_bound = socket.CMSG_SPACE(_MAX_OBJECTS * array("i").itemsize) + socket.CMSG_SPACE(struct.calcsize("3i"))
    raw, ancillary, flags, _address = endpoint.recvmsg(_MAX_PACKET, ancillary_bound, socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
    credentials, leases = _leased_credentials(ancillary, actual_ops, missing_code="issuer-packet-credentials-missing")
    descriptors = tuple(lease.fd for lease in leases)
    primary: BaseException | None = None
    try:
        expected_credentials = (issuer_pid, os.getuid(), os.getgid())
        _require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and credentials == expected_credentials, "handoff packet authority/truncation", "issuer-packet-authority")
        packet = _strict_json(raw, False, _MAX_PACKET, "handoff packet")
        keys = {"binding_sha256", "closure_sha256", "descriptor_count", "generation_rows", "generation_sha256", "nonce", "report_sha256", "revision", "source_set_sha256", "version"}
        _require(type(packet) is dict and set(packet) == keys, "handoff packet shape")
        _require(packet["version"] == _HANDOFF_VERSION and packet["nonce"] == nonce.hex(), "handoff nonce/version")
        _require(packet["revision"] == admission.revision and packet["source_set_sha256"] == admission.source_set_sha256, "handoff admission binding")
        _require(packet["descriptor_count"] == len(descriptors), "handoff descriptor count")
        rows = _rows_from_packet(packet["generation_rows"])
        report_bytes = _inspect_fd(descriptors[0], True, None, packet["report_sha256"])
        report, binding_sha, generation_sha = _verify_bundle(admission, report_bytes, descriptors, rows)
        _require(packet["closure_sha256"] == report["closure_sha256"], "handoff closure digest")
        _require(packet["binding_sha256"] == binding_sha and packet["generation_sha256"] == generation_sha, "handoff table digest")
        ack = {"binding_sha256": binding_sha, "consumer_pid": os.getpid(), "generation_sha256": generation_sha, "nonce": nonce.hex(), "report_sha256": packet["report_sha256"], "version": _HANDOFF_VERSION}
        ack_bytes = _canonical(ack)
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([], [endpoint], [], remaining)[1], "issuance acknowledgement deadline", "issuer-deadline")
        sent = endpoint.sendmsg([ack_bytes], _credential_ancillary(), socket.MSG_DONTWAIT)
        _require(sent == len(ack_bytes), "issuance acknowledgement partial")
        endpoint.shutdown(socket.SHUT_WR)
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([endpoint], [], [], remaining)[0], "issuance EOF deadline", "issuer-deadline")
        _require(endpoint.recv(1, socket.MSG_DONTWAIT) == b"", "second issuer packet", "issuer-second-packet")
        receipt = _IssuanceReceipt(
            version=_HANDOFF_VERSION,
            report_sha256=packet["report_sha256"],
            closure_sha256=report["closure_sha256"],
            binding_sha256=binding_sha,
            generation_sha256=generation_sha,
            descriptor_count=len(descriptors),
            issuer_pid=issuer_pid,
            consumer_pid=os.getpid(),
        )
        return report, leases, rows, receipt
    except BaseException as error: primary = error
    _close_leases(actual_ops, leases, primary)
    raise primary
def _consume_worker_handoff(endpoint: socket.socket, helper_endpoint: socket.socket, nonce: bytes, admission: _SourceAdmission, issuer_pid: int, ops: Any, process_owner: _ProcessOwner, deadline: float) -> tuple[dict[str, object], tuple[_FdLease, ...], tuple[_GenerationRow, ...], _IssuanceReceipt]:
    sequence = 0
    helpers: dict[str, _ProcessLease] = {}
    while True:
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "worker handoff deadline", "worker-handoff-deadline")
        ready = select.select([endpoint, helper_endpoint], [], [], remaining)[0]
        _require(bool(ready), "worker handoff deadline", "worker-handoff-deadline")
        if helper_endpoint in ready:
            raw, ancillary, flags, _address = helper_endpoint.recvmsg(4096, 512, socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT)
            credentials, received = _leased_credentials(ancillary, ops, require_rights=None, missing_code="helper-control-credentials-missing")
            primary: BaseException | None = None
            try:
                _require(not flags and credentials == (issuer_pid, os.getuid(), os.getgid()), "helper control authority", "helper-control-authority")
                value = _strict_json(raw, False, 4096, "helper control")
                _require(type(value) is dict and value.get("version") == _RESULT_VERSION, "helper control shape", "helper-control-shape")
                sequence += 1
                _require(value.get("sequence") == sequence, "helper control sequence", "helper-control-sequence")
                event = value.get("event")
                if event == "register":
                    expected = {"event", "executable", "gates", "pid", "process_group", "sequence", "session", "start_time", "target", "version"}
                    _require(set(value) == expected and len(received) == 1, "helper registration shape", "helper-register-shape")
                    pidfd = received[0].transfer()
                    lease = process_owner.register(
                        value["pid"],
                        pidfd_fd=pidfd,
                        waitable=False,
                        bind_received_pidfd=isinstance(helper_endpoint, socket.socket),
                    )
                    observed = (lease.start_time, lease.session, lease.process_group, list(lease.executable))
                    asserted = (value["start_time"], value["session"], value["process_group"], value["executable"])
                    _require(observed == asserted and value["gates"] == ["input_gate", "registration_gate", "release_gate", "status_gate"], "helper registration identity", "helper-register-identity")
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
                        _require(lease.released and bool(select.select([lease.pidfd.fd], [], [], 0)[0]), "helper retire before reap", "helper-retire-live")
                        lease.reaped = True
                        process_owner.stop(lease)
                        del helpers[token]
                        reply_event = "retired"
                reply = _canonical({"event": reply_event, "sequence": sequence, "token": token, "version": _RESULT_VERSION})
                sent = helper_endpoint.sendmsg([reply], _credential_ancillary(), socket.MSG_DONTWAIT)
                _require(sent == len(reply), "helper acknowledgement send", "helper-ack-send")
            except BaseException as error: primary = error
            if primary is not None:
                _close_leases(ops, received, primary)
                raise primary
        if endpoint in ready:
            _require(not helpers, "helper authority still live at issuance", "helper-live-at-issuance")
            return _consume_issuance(endpoint, nonce, admission, issuer_pid, ops, deadline)
def _mkdir_exact(path: str, mode: int) -> None:
    os.mkdir(path, mode)
    info = os.lstat(path)
    _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode, "private root directory mismatch")
class _RootOwner(make_dataclass(
    "_RootOwnerData",
    [
        ("ops", Any),
        ("parent", Optional[_FdLease], field(default=None)),
        ("root", Optional[_FdLease], field(default=None)),
        ("parent_identity", Optional[tuple[int, int]], field(default=None)),
        ("identity", Optional[tuple[int, int]], field(default=None)),
        ("create_intended", bool, field(default=False)),
        ("cleaned", bool, field(default=False)),
    ],
)):
    def prepare(self) -> str:
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            self.parent = _FdLease(self.ops.open(_ROOT_PARENT, flags), "root-parent")
            parent_info = os.fstat(self.parent.fd)
            _require(stat.S_ISDIR(parent_info.st_mode), "private root parent", "root-parent")
            self.parent_identity = (parent_info.st_dev, parent_info.st_ino)
            try:
                os.stat(_ROOT_LEAF, dir_fd=self.parent.fd, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise RuntimeLauncherError("private root baseline", "root-baseline")
            self.create_intended = True
            os.mkdir(_ROOT_LEAF, 0o700, dir_fd=self.parent.fd)
            created_info = os.stat(_ROOT_LEAF, dir_fd=self.parent.fd, follow_symlinks=False)
            exact = stat.S_ISDIR(created_info.st_mode) and stat.S_IMODE(created_info.st_mode) == 0o700
            _require(exact and created_info.st_uid == os.geteuid(), "private root identity", "root-identity")
            self.identity = (created_info.st_dev, created_info.st_ino)
            descriptor = os.open(_ROOT_LEAF, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent.fd)
            self.root = _FdLease(descriptor, "root-object")
            info = os.fstat(descriptor)
            _require((info.st_dev, info.st_ino) == self.identity, "private root open identity", "root-identity")
            return f"{_ROOT_PARENT}/{_ROOT_LEAF}"
        except BaseException as primary:
            self.cleanup(primary)
            raise
    def cleanup(self, primary: BaseException | None = None) -> None:
        if self.cleaned: return
        failures: list[BaseException] = []
        if self.create_intended and self.parent is not None:
            try:
                parent = os.fstat(self.parent.fd)
                _require((parent.st_dev, parent.st_ino) == self.parent_identity, "private root parent replacement", "root-parent-replaced")
                try:
                    info = os.stat(_ROOT_LEAF, dir_fd=self.parent.fd, follow_symlinks=False)
                except FileNotFoundError: info = None
                if info is not None:
                    exact_shape = stat.S_ISDIR(info.st_mode)
                    exact_shape = exact_shape and stat.S_IMODE(info.st_mode) == 0o700
                    exact_shape = exact_shape and info.st_uid == os.geteuid()
                    # Never infer deletion authority from shape alone.  The
                    # post-mkdir generation is recorded before the fallible
                    # O_PATH open and must still identify the exact object.
                    exact_generation = self.identity is not None
                    exact_generation = exact_generation and (info.st_dev, info.st_ino) == self.identity
                    _require(exact_shape and exact_generation, "private root replacement", "root-replaced")
                    os.rmdir(_ROOT_LEAF, dir_fd=self.parent.fd)
            except BaseException as error: failures.append(error)
        # Keep the O_PATH lease live through pathname validation and removal.
        # Closing it first permits immediate inode reuse to counterfeit the
        # recorded (device, inode) generation after a same-name replacement.
        if self.root is not None:
            try: self.root.close(self.ops)
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
    try:
        _require(ops.write(lease.fd, value) == len(value), "namespace identity map short write", "map-short-write")
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
    return {"capability_sets": capabilities, "securebits": securebits, "no_new_privs": no_new_privs, "seccomp_installed": True, "seccomp_denials": denials, "seccomp_mode": mode, "seccomp_program_sha256": program_digest}
def _child_fd_install(ops: Any, input_fd: int, output_fd: int, role: str, exec_status_fd: int, root: str) -> None:
    _require(fcntl.fcntl(198, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, "executable authority is not CLOEXEC", "exec-fd-cloexec")
    _require(fcntl.fcntl(exec_status_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, "exec status pipe is not CLOEXEC", "exec-status-cloexec")
    input_copy = _FdLease(fcntl.fcntl(input_fd, fcntl.F_DUPFD_CLOEXEC, 256), "stdin-copy")
    output_copy = _FdLease(fcntl.fcntl(output_fd, fcntl.F_DUPFD_CLOEXEC, 256), "stdout-copy")
    os.dup2(input_copy.fd, 0, inheritable=True)
    os.dup2(output_copy.fd, 1, inheritable=True)
    os.dup2(output_copy.fd, 2, inheritable=True)
    input_copy.close(ops)
    output_copy.close(ops)
    allowed = {0, 1, 2, 198, exec_status_fd}
    for fd in _descriptor_snapshot(ops):
        if fd not in allowed:
            _FdLease(fd, "preexec-complement").close(ops)
    observations = _enter_boundary(ops, root)
    boundary = _status("boundary", 3, observations=observations)
    _require(len(boundary) <= 16384 and ops.write(exec_status_fd, boundary) == len(boundary), "exec boundary pipe write", "exec-boundary-write")
    ops.execveat(198, role)
def _read_exec_boundary(ops: Any, descriptor: int, deadline: float) -> bytes:
    raw = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        _require(remaining > 0 and select.select([descriptor], [], [], remaining)[0], "exec status timeout", "exec-status-timeout")
        part = ops.read(descriptor, 16385 - len(raw))
        if not part: return bytes(raw)
        raw += part
        _require(len(raw) <= 16384, "exec status bound", "exec-status-bound")
def _namespace_owner(
    role: str,
    descriptors: tuple[int, ...],
    rows: tuple[_GenerationRow, ...],
    report: dict[str, object],
    input_fd: int,
    output_fd: int,
    status_fd: int,
    transfer_fd: int,
    transfer_nonce: bytes,
    root: str | None = None,
) -> NoReturn:
    root = root or f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    status = socket.socket(fileno=status_fd)
    transfer = socket.socket(fileno=transfer_fd)
    ops = _SystemOps()
    child_owner = _ProcessOwner(ops)
    child_lease: _ProcessLease | None = None
    mount_intents: set[str] = set()
    sequence = 0
    inherited = list(_received_leases(descriptors))
    exec_lease: _FdLease | None = None
    try:
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        original_uid, original_gid = os.getuid(), os.getgid()
        os.setgroups([])
        ops.unshare_boundary()
        try:
            _write_map(ops, "/proc/self/setgroups", b"deny\n")
        except FileNotFoundError: pass
        _write_map(ops, "/proc/self/uid_map", f"0 {original_uid} 1\n".encode())
        _write_map(ops, "/proc/self/gid_map", f"0 {original_gid} 1\n".encode())
        mount_intents.add("private-root")
        ops.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None)
        sequence = 1
        status.send(_status("namespace", sequence))
        _recv_status(status, time.monotonic() + _SETUP_SECONDS, "prepare-root", 1)
        mount_intents.add("materialized-root")
        _materialize_root(ops, role, descriptors, rows, report, root)
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
        _require(all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC for fd in (exec_status_read, exec_status_write)), "exec status pipe flags", "exec-status-cloexec")
        child, child_lease, child_gate = child_owner.spawn()
        if child == 0:
            transfer.close()
            exec_read_lease.close(ops)
            try:
                _require(child_gate is not None and ops.read(child_gate.fd, 1) == b"G", "child release gate", "child-release")
                child_gate.close(ops)
                ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
                _child_fd_install(ops, input_fd, output_fd, role, exec_write_lease.fd, root)
            except BaseException as error:
                code = getattr(error, "code", "child-setup")
                try: ops.write(exec_write_lease.fd, (code[:126] + "\n").encode())
                finally: os._exit(126)
        _require(child_lease is not None, "child preregistration", "child-register")
        exec_write_lease.close(ops)
        exec_lease.close(ops)
        exec_lease = None
        transfer_case = f"tool:{role}"
        packet = _lifecycle_transfer_packet(
            child_lease,
            os.getpid(),
            transfer_nonce,
            transfer_case,
            "tool",
        )
        rights = array("i", (child_lease.pidfd.fd,))
        ancillary = ((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),)
        written = transfer.sendmsg((packet,), ancillary, socket.MSG_DONTWAIT)
        _require(written == len(packet), "tool child transfer", "process-transfer-send")
        transfer.shutdown(socket.SHUT_WR)
        _lifecycle_control_recv(
            transfer,
            time.monotonic() + _SETUP_SECONDS,
            b"A",
        )
        child_owner.release(child_lease)
        child_lease.pidfd.close(ops)
        child_lease.pidfd = None
        child_owner.processes.remove(child_lease)
        transfer.close()
        sequence = 2
        status.send(_status("child", sequence, pid=child))
        _recv_status(status, time.monotonic() + _SETUP_SECONDS, "release-child", 2)
        exec_status = _read_exec_boundary(ops, exec_read_lease.fd, time.monotonic() + _SETUP_SECONDS)
        exec_read_lease.close(ops)
        boundary = _parse_sandbox_status(exec_status, "boundary", 3)
        _require(status.send(exec_status) == len(exec_status), "boundary observation send", "boundary-send")
        sequence = 4
        status.send(_status("exec-ready", sequence))
        _recv_status(status, time.monotonic() + _SETUP_SECONDS, "finalize-root", 3)
        final_flags = _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        mount_intents.add("readonly-root")
        ops.mount(None, root.encode(), None, final_flags, None)
        sequence = 5
        status.send(_status("root-final", sequence))
        wait_status = _wait_bounded(child_lease, time.monotonic() + _RUN_SECONDS)
        _require(wait_status is not None, "namespace child deadline", "child-reap-deadline")
        _require(child_lease.reaped, "namespace child exact reap", "child-reap")
        child_lease = None
        if os.path.ismount(root): ops.umount(root.encode())
        _require(not os.path.ismount(root), "materialized mount remains", "mount-cleanup")
        mount_intents.remove("materialized-root")
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
            try:
                _close_leases(ops, inherited, primary)
            except BaseException as error: failures.append(error)
        if "materialized-root" in mount_intents:
            try:
                if os.path.ismount(root): ops.umount(root.encode())
                _require(not os.path.ismount(root), "materialized mount remains", "mount-cleanup")
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
    _require(raw.endswith(b"\n") and 0 < raw.count(b"\n") <= _MAX_MAP_LINES, "maps framing/bound", "maps-framing")
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
def _final_mapping_check(ops: _SystemOps, pid: int, rows: tuple[_GenerationRow, ...], role: str, report: dict[str, object]) -> tuple[bytes, str]:
    first = _maps_snapshot(pid)
    expected_rows = [row for row in rows if row.tool_index == _TOOL_INDEX[role]]
    expected = {(row.role, row.sha256) for row in expected_rows}
    observed: set[tuple[str, str]] = set()
    digest_roles = {row.sha256: row.role for row in expected_rows}
    for start, end, permissions, _offset, major, minor, inode, path in _parse_maps(first):
        if b"x" not in permissions: continue
        if inode == 0:
            _require(path in (b"[vdso]", b"[vsyscall]"), "unknown executable synthetic mapping")
            continue
        map_lease = _FdLease(ops.open(f"/proc/{pid}/map_files/{start:x}-{end:x}", os.O_RDONLY | os.O_CLOEXEC), "map-file")
        try:
            info = os.fstat(map_lease.fd)
            identity = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
            _require(identity == (major, minor, inode), "map_files identity mismatch", "maps-object-identity")
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
    mapping_digest = _digest([[row.role, row.sha256] for row in expected_rows])
    if mapping_digest != report["tools"][_TOOL_INDEX[role]]["mapping_sha256"]: raise RuntimeLauncherError("final mapping digest", "mapping-report-digest")
    return first, mapping_digest
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
        rows.append((int(groups[0]), int(groups[1]), int(groups[2], 16), int(groups[3], 16), groups[4], groups[5], frozenset(groups[6].split(b",")), groups[8], groups[9], groups[10]))
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
    handles: list[_FdLease] = []
    for name in names:
        descriptor = ops.open(f"/proc/{lease.pid}/ns/{name}", os.O_RDONLY | os.O_CLOEXEC)
        handles.append(_FdLease(descriptor, f"namespace:{name}"))
        lease.namespace_handles = tuple(handles)
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
    _require(re.fullmatch(rb"(?:[1-9][0-9]* )*", raw) is not None, "children lexical record", "children-record")
    values = tuple(int(item) for item in raw.split())
    _require(len(values) == len(set(values)) and all(value <= 2147483647 for value in values), "children cardinality", "children-cardinality")
    return values
def _descendant_census(pid: int, ops: Any) -> tuple[int, ...]:
    pending = [pid]
    observed: list[int] = []
    while pending:
        parent = pending.pop()
        path = f"/proc/{parent}/task/{parent}/children"
        children = _parse_children(_proc_bytes(path, 65536, ops))
        duplicate = any(child in observed or child in pending for child in children)
        _require(not duplicate, "descendant census cycle/duplicate", "descendant-census")
        observed.extend(children)
        pending.extend(children)
        _require(len(observed) <= 4096, "descendant census bound", "descendant-bound")
    return tuple(sorted(observed))
def _descendant_identity_edges(pid: int, ops: Any) -> tuple[tuple[object, ...], ...]:
    pending = [pid]
    visited = {pid}
    edges: list[tuple[object, ...]] = []
    reads = 0
    while pending:
        parent = pending.pop()
        path = f"/proc/{parent}/task/{parent}/children"
        before = _parse_children(_proc_bytes(path, 65536, ops))
        reads += 1
        _require(reads <= 8192, "descendant census read bound", "descendant-bound")
        for child in before:
            _require(child not in visited, "descendant census cycle/duplicate", "descendant-census")
            start_before = _start_time(child, ops)
            executable = _exe_identity(child, ops)
            start_after = _start_time(child, ops)
            _require(start_before == start_after, "descendant identity drift", "process-census")
            edges.append((parent, child, start_before, *executable))
            visited.add(child)
            pending.append(child)
            _require(len(edges) <= 4096, "descendant census bound", "descendant-bound")
        after = _parse_children(_proc_bytes(path, 65536, ops))
        reads += 1
        _require(before == after, "descendant edge drift", "process-census")
    return tuple(sorted(edges))
def _adopt_unregistered_children(
    owner: _ProcessOwner,
    baseline: tuple[int, ...],
    ops: Any,
) -> None:
    path = "/proc/thread-self/children"
    first = _parse_children(_proc_bytes(path, 65536, ops))
    second = _parse_children(_proc_bytes(path, 65536, ops))
    _require(first == second, "adopted child census drift", "process-adoption")
    known = {lease.pid for lease in owner.processes}
    candidates = tuple(pid for pid in first if pid not in baseline and pid not in known)
    for pid in candidates:
        descriptor = os.pidfd_open(pid, 0)
        lease = _ProcessLease(pid, _FdLease(descriptor, f"adopted-pidfd:{pid}"))
        try:
            _require(_stable_pidfd_target(descriptor, ops) == pid, "adopted pidfd target", "process-adoption")
            lease.expected_uid = os.geteuid()
            owner.processes.append(lease)
            lease.start_time = _start_time(pid, ops)
            lease.session = os.getsid(pid)
            lease.process_group = os.getpgid(pid)
            try:
                lease.executable = _exe_identity(pid, ops)
            except (FileNotFoundError, ProcessLookupError):
                _require(bool(select.select([descriptor], [], [], 0)[0]), "adopted executable identity", "process-adoption")
                lease.executable = (0, 0)
        except BaseException as primary:
            if lease in owner.processes:
                owner.processes.remove(lease)
            try:
                lease.pidfd.close(ops)
            except BaseException as error:
                raise RuntimeLauncherCleanupError(primary, [error]) from primary
            raise

def _close_socket(endpoint: socket.socket | None, ops: Any, purpose: str) -> None:
    if endpoint is not None and endpoint.fileno() >= 0:
        _FdLease(endpoint.detach(), purpose).close(ops)
def _parse_sandbox_status(raw: bytes, event: str, sequence: int) -> dict[str, object]:
    value = _strict_json(raw, False, 16384, "sandbox status")
    extras = { "namespace": set(), "child": {"pid"}, "boundary": {"observations"}, "exec-ready": set(), "root-final": set(), "exit": {"status"}, "error": {"code", "kind"}, "unavailable": {"message", "primitive"}, "prepare-root": set(), "release-child": set(), "finalize-root": set(), }
    _require(type(value) is dict and event in extras and set(value) == {"event", "sequence", "version"} | extras[event], "sandbox status closed shape", "status-shape")
    identity = value["version"] == _RESULT_VERSION and value["event"] == event
    _require(identity and type(value["sequence"]) is int and value["sequence"] == sequence, "sandbox status identity/sequence", "status-sequence")
    if "pid" in value: _require(type(value["pid"]) is int and 0 < value["pid"] <= 2147483647, "sandbox status pid", "status-pid")
    if "status" in value: _require(type(value["status"]) is int and 0 <= value["status"] <= _UINT_MAX, "sandbox wait status", "status-wait")
    if event == "error":
        _require(all(type(value[name]) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,127}", value[name]) for name in ("code", "kind")), "sandbox error fields", "status-error")
    if event == "unavailable":
        _require(type(value["primitive"]) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,127}", value["primitive"]) and type(value["message"]) is str and 1 <= len(value["message"].encode()) <= 1024, "sandbox unavailable fields", "status-unavailable")
    if event == "boundary":
        observations = value["observations"]
        keys = {"capability_sets", "no_new_privs", "seccomp_denials", "seccomp_installed", "seccomp_mode", "seccomp_program_sha256", "securebits"}
        _require(type(observations) is dict and set(observations) == keys, "boundary observation shape", "boundary-observations")
        capabilities = observations["capability_sets"]
        capability_keys = {"effective", "permitted", "inheritable", "bounding", "ambient", "groups"}
        _require(type(capabilities) is dict and set(capabilities) == capability_keys, "capability observation shape", "capability-observation")
        _require(all(type(capabilities[name]) is int and 0 <= capabilities[name] <= (1 << 64) - 1 for name in ("effective", "permitted", "inheritable")), "capability scalar observation", "capability-observation")
        _require(all(type(capabilities[name]) is list and 0 < len(capabilities[name]) <= 256 and all(type(item) is int and item in (0, 1) for item in capabilities[name]) for name in ("bounding", "ambient")) and len(capabilities["bounding"]) == len(capabilities["ambient"]) and type(capabilities["groups"]) is list and all(type(item) is int and 0 <= item <= _UINT_MAX for item in capabilities["groups"]), "capability vector observation", "capability-observation")
        denials = observations["seccomp_denials"]
        _require(type(denials) is dict and all(type(name) is str and type(code) is int for name, code in denials.items()), "seccomp denial observation", "seccomp-observations")
        _require(observations["seccomp_installed"] is True and type(observations["seccomp_mode"]) is int and type(observations["no_new_privs"]) is int and type(observations["securebits"]) is int and _sha(observations["seccomp_program_sha256"]), "boundary scalar observation", "boundary-observations")
    return value
def _status(event: str, sequence: int, **fields: object) -> bytes:
    return _canonical({"event": event, "sequence": sequence, "version": _RESULT_VERSION, **fields})
def _recv_status(endpoint: socket.socket, deadline: float, event: str = "", sequence: int = 0) -> dict[str, object]:
    remaining = deadline - time.monotonic()
    _require(remaining > 0 and bool(select.select([endpoint], [], [], remaining)[0]), "sandbox status deadline", "status-deadline")
    raw = endpoint.recv(16384)
    preliminary = _strict_json(raw, False, 16384, "sandbox status")
    observed_event = preliminary.get("event") if type(preliminary) is dict else None
    if observed_event == event: return _parse_sandbox_status(raw, event, sequence)
    if observed_event == "unavailable":
        unavailable = _parse_sandbox_status(raw, "unavailable", sequence)
        raise RuntimeLauncherUnavailable(unavailable["primitive"], unavailable["message"])
    if observed_event == "error":
        failure = _parse_sandbox_status(raw, "error", sequence)
        if failure["code"] == "cleanup-uncertain": raise RuntimeLauncherCleanupError(None, [RuntimeLauncherError("inner cleanup uncertain", "inner-cleanup")])
        raise RuntimeLauncherError(f"sandbox setup failed: {failure['kind']}", failure["code"])
    return _parse_sandbox_status(raw, event, sequence)
def _tool_creator_settlement_packet(
    endpoint: socket.socket,
    deadline: float,
) -> None:
    _deadline_ready(endpoint, deadline, "creator-settlement-deadline")
    raw = endpoint.recv(16384, socket.MSG_DONTWAIT)
    value = _parse_sandbox_status(raw, "error", 2)
    _require(
        value["code"] != "cleanup-uncertain",
        "tool creator cleanup uncertain",
        "cleanup-uncertain",
    )

def _settle_rejected_tool_transfer(
    owner: _ProcessOwner,
    creator: _ProcessLease,
    transfer: socket.socket,
    status: socket.socket,
    child_baseline: tuple[int, ...],
    ops: Any,
    primary: BaseException,
) -> None:
    failures: list[BaseException] = []
    settlement_deadline = time.monotonic() + _SETUP_SECONDS
    if not select.select([creator.pidfd.fd], [], [], 0)[0]:
        try:
            _lifecycle_control_send(transfer, b"N")
        except BaseException as error:
            failures.append(error)
        try:
            _tool_creator_settlement_packet(status, settlement_deadline)
        except BaseException as error:
            failures.append(error)
    try:
        owner.stop(creator, primary)
    except BaseException as error:
        failures.append(error)
    try:
        _adopt_unregistered_children(owner, child_baseline, ops)
        for lease in tuple(owner.processes):
            if lease is not creator:
                owner.stop(lease, primary)
    except BaseException as error:
        failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from primary

def _run_tool_with_ops( ops: Any, role: str, report: dict[str, object], descriptors: tuple[int, ...], rows: tuple[_GenerationRow, ...], ) -> tuple[bytes, dict[str, object]]:
    child_baseline = _parse_children(_proc_bytes("/proc/thread-self/children", 65536, ops))
    process_owner = _ProcessOwner(ops)
    root_owner = _RootOwner(ops)
    input_pair = output_pair = ()
    parent_status = child_status = None
    transfer_parent = transfer_child = None
    socket_recovery: list[tuple[socket.socket, str]] = []
    namespace_lease = child_lease = None
    primary: BaseException | None = None
    result: tuple[bytes, dict[str, object]] | None = None
    try:
        input_pair = tuple(_FdLease(fd, f"{role}-input") for fd in os.pipe2(os.O_CLOEXEC))
        output_pair = tuple(_FdLease(fd, f"{role}-output") for fd in os.pipe2(os.O_CLOEXEC))
        input_read, input_write = input_pair
        output_read, output_write = output_pair
        parent_status, child_status = ops.socketpair()
        socket_recovery.extend(((parent_status, "namespace-parent-status"), (child_status, "namespace-child-status")))
        transfer_parent, transfer_child = ops.socketpair()
        socket_recovery.extend(((transfer_parent, "tool-transfer-parent"), (transfer_child, "tool-transfer-child")))
        transfer_nonce = ops.nonce()
        root = root_owner.prepare()
        limits_baseline = _parse_limits(_proc_bytes("/proc/self/limits", 65536, ops))
        pid, namespace_lease, gate = process_owner.spawn()
        if pid == 0:
            _close_socket(parent_status, ops, "namespace-parent-status")
            _close_socket(transfer_parent, ops, "tool-transfer-parent")
            input_write.close(ops)
            output_read.close(ops)
            _require(gate is not None and ops.read(gate.fd, 1) == b"G", "namespace prerelease gate", "namespace-release")
            gate.close(ops)
            if root_owner.root is not None:
                root_owner.root.close(ops)
            if root_owner.parent is not None:
                root_owner.parent.close(ops)
            status_fd = child_status.detach()
            transfer_fd = transfer_child.detach()
            _namespace_owner(
                role,
                descriptors,
                rows,
                report,
                input_read.fd,
                output_write.fd,
                status_fd,
                transfer_fd,
                transfer_nonce,
                root,
            )
        _require(namespace_lease is not None, "namespace owner registration", "namespace-register")
        _close_socket(child_status, ops, "namespace-child-status")
        _close_socket(transfer_child, ops, "tool-transfer-child")
        input_read.close(ops)
        output_write.close(ops)
        # The namespace owner terminally calls setsid() before its first status
        # packet.  Record that only permissible identity transition before
        # release, then authenticate it before accepting further handoff.  If a
        # later Linux proc/map_files operation fails, cleanup can still signal
        # the exact owner rather than poisoning the primary failure because its
        # recorded pre-release session no longer matches.
        process_owner.plan_setsid(namespace_lease)
        process_owner.release(namespace_lease)
        _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "namespace", 1)
        process_owner.confirm_setsid(namespace_lease)
        namespace_authority = _open_namespace_authority(namespace_lease, ops)
        command = _status("prepare-root", 1)
        _require(parent_status.send(command) == len(command), "root preparation send", "root-prepare-send")
        transfer_case = f"tool:{role}"
        try:
            child_lease = process_owner.receive_descendant(
                transfer_parent,
                namespace_lease,
                transfer_nonce,
                1,
                time.monotonic() + _SETUP_SECONDS,
                transfer_case,
                "tool",
            )
        except BaseException as transfer_error:
            if isinstance(transfer_parent, socket.socket):
                _settle_rejected_tool_transfer(
                    process_owner,
                    namespace_lease,
                    transfer_parent,
                    parent_status,
                    child_baseline,
                    ops,
                    transfer_error,
                )
                namespace_lease = None
            raise
        process_owner.stable_identity_census(namespace_lease)
        executable_row = next(
            row
            for row in rows
            if row.tool_index == _TOOL_INDEX[role] and row.object_index == 0
        )
        executable_info = os.fstat(descriptors[executable_row.descriptor_index])
        process_owner.plan_exec(
            child_lease,
            (executable_info.st_dev, executable_info.st_ino),
        )
        _lifecycle_control_send(transfer_parent, b"A")
        _close_socket(transfer_parent, ops, "tool-transfer-parent")
        transfer_parent = None
        child = _recv_status(
            parent_status,
            time.monotonic() + _SETUP_SECONDS,
            "child",
            2,
        )
        _require(
            child["pid"] == child_lease.pid,
            "tool child transfer identity",
            "process-transfer-identity",
        )
        command = _status("release-child", 2)
        _require(parent_status.send(command) == len(command), "child release send", "child-release-send")
        boundary_packet = _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "boundary", 3)
        boundary = boundary_packet["observations"]
        _require(type(boundary) is dict, "boundary observations malformed", "boundary-observations")
        _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "exec-ready", 4)
        process_owner.confirm_exec(child_lease)
        post_fds = _descriptor_snapshot(ops, child["pid"])
        _require(post_fds == (0, 1, 2), "post-exec descriptor table", "exec-fd-table")
        post_maps, post_mapping = _final_mapping_check(ops, child["pid"], rows, role, report)
        _require(_descendant_census(namespace_lease.pid, ops) == (child["pid"],), "registered descendant census", "descendant-census")
        command = _status("finalize-root", 3)
        _require(parent_status.send(command) == len(command), "root finalization send", "root-finalize-send")
        _recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "root-final", 5)
        root_exact, no_proc, host_absent, checkout_absent = _final_mount_check(child["pid"], ops)
        namespace_facts = _namespace_facts(child["pid"], os.getuid(), os.getgid(), namespace_lease)
        final_fds = _descriptor_snapshot(ops, child["pid"])
        _require(final_fds == post_fds, "final descriptor drift", "final-fd-drift")
        final_maps, final_mapping = _final_mapping_check(ops, child["pid"], rows, role, report)
        _require((final_maps, final_mapping) == (post_maps, post_mapping), "final mapping drift", "final-map-drift")
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
            if not part: break
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
        _require(type(capability_sets) is dict and set(capability_sets) == {"effective", "permitted", "inheritable", "bounding", "ambient", "groups"}, "capability observation shape", "capability-observation")
        denials = boundary.get("seccomp_denials")
        expected_denials = set(_DENIED_SYSCALLS) | {"prctl:set", "execveat:shape"}
        denial_exact = type(denials) is dict and set(denials) == expected_denials
        denial_exact = denial_exact and all(type(value) is int and value == errno.EPERM for value in denials.values())
        installed = boundary.get("seccomp_installed") is True
        mode_exact = boundary.get("seccomp_mode") == _SECCOMP_MODE_FILTER and namespace_facts["seccomp_mode_exact"]
        program_exact = boundary.get("seccomp_program_sha256") == _seccomp_digest()
        authority_absent = final_fds == (0, 1, 2) and final_maps == post_maps and root_exact and no_proc and host_absent
        tool = { "ambient_capabilities_zero": not any(capability_sets["ambient"]), "bounding_capabilities_zero": not any(capability_sets["bounding"]), "capabilities_zero": not any(capability_sets[name] for name in ("effective", "permitted", "inheritable")) and not any(capability_sets["bounding"]) and not any(capability_sets["ambient"]) and namespace_facts["capability_sets_zero"], "checkout_absent": checkout_absent, "effective_capabilities_zero": capability_sets["effective"] == 0, "exec_descriptor_consumed": 198 not in final_fds, "host_paths_absent": host_absent, "inheritable_capabilities_zero": capability_sets["inheritable"] == 0, "limits_exact": limits_exact, "mapped_generations_exact": final_maps == post_maps, "mount_namespace_exact": namespace_facts["mount_namespace_exact"], "namespace_handles_exact": namespace_authority["namespace_handles_exact"], "namespace_ownership_exact": namespace_authority["namespace_ownership_exact"], "network_namespace_exact": namespace_facts["network_namespace_exact"], "no_acquisition_route": denial_exact and installed and mode_exact and program_exact and authority_absent, "no_new_privs": boundary.get("no_new_privs") == 1 and namespace_facts["nnp_exact"], "noroot_locked": boundary.get("securebits") == _SECBITS, "permitted_capabilities_zero": capability_sets["permitted"] == 0, "pid_namespace_exact": namespace_facts["pid_namespace_exact"], "pid_one": namespace_facts["pid_one"], "root_has_no_proc": no_proc, "root_readonly_noexec": root_exact, "seccomp_denials_exact": denial_exact, "seccomp_installed": installed, "seccomp_mode_exact": mode_exact, "seccomp_program_exact": program_exact, "supplementary_groups_empty": capability_sets["groups"] == [] and namespace_facts["groups_empty"], "user_namespace_exact": namespace_facts["user_namespace_exact"], }
        result = bytes(output), tool
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try: process_owner.cleanup(primary)
    except BaseException as error: failures.append(error)
    try:
        _adopt_unregistered_children(process_owner, child_baseline, ops)
        for lease in tuple(process_owner.processes):
            process_owner.stop(lease, primary)
    except BaseException as error:
        failures.append(error)
    for lease in (*input_pair, *output_pair):
        if lease.state is _FdState.OWNED:
            try: lease.close(ops)
            except BaseException as error: failures.append(error)
    for endpoint, purpose in socket_recovery:
        try:
            _close_socket(endpoint, ops, purpose)
        except BaseException as error:
            failures.append(error)
    try: root_owner.cleanup(primary)
    except BaseException as error: failures.append(error)
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    if isinstance(primary, RuntimeLauncherUnavailable): primary.cleanup_restored = root_owner.cleaned
    if primary is not None: raise primary
    _require(result is not None, "tool result missing", "tool-result")
    result[1]["_execution_mapping_sha256"] = final_mapping
    return result
def _consume_launcher_operation(admission: _SourceAdmission, operation: str) -> None:
    exact = type(admission) is _SourceAdmission and admission._operation == operation
    exact = exact and admission._issuer is _BOOTSTRAP_OPERATION_TOKEN and not admission._claimed
    _require(exact, "launcher operation admission", "operation-admission")
    admission._claimed = True
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
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
def _coordinate_with_ops(admission: _SourceAdmission, closure_module: types.ModuleType, ops: Any) -> tuple[RuntimeQualificationResult, tuple[RuntimeCompressionToolObservation, RuntimeCompressionToolObservation], dict[str, object]]:
    fd_baseline = _descriptor_snapshot(ops)
    child_baseline = _parse_children(_proc_bytes("/proc/thread-self/children", 65536, ops))
    root = f"{_ROOT_PARENT}/{_ROOT_LEAF}"
    mount_baseline = os.path.ismount(root)
    path_baseline = os.path.lexists(root)
    nonce = ops.nonce()
    process_owner = _ProcessOwner(ops)
    parent_endpoint = worker_endpoint = None
    helper_parent = helper_worker = None
    socket_recovery: list[tuple[socket.socket, str]] = []
    descriptor_leases = []
    primary = None
    outputs = observed_tools = None
    receipt = report = None
    rows = ()
    execution_mappings = None
    try:
        parent_endpoint, worker_endpoint = ops.socketpair()
        socket_recovery.extend(((parent_endpoint, "issuance-parent"), (worker_endpoint, "issuance-worker")))
        helper_parent, helper_worker = ops.socketpair()
        socket_recovery.extend(((helper_parent, "helper-parent"), (helper_worker, "helper-worker")))
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
        report, descriptor_tuple, rows, receipt = _consume_worker_handoff( parent_endpoint, helper_parent, nonce, admission, pid, ops, process_owner, time.monotonic() + _SETUP_SECONDS, )
        descriptor_leases = list(descriptor_tuple)
        descriptors = tuple(lease.fd for lease in descriptor_leases)
        gzip_output, gzip_observed = _run_tool_with_ops(ops, "gzip", report, descriptors, rows)
        zstd_output, zstd_observed = _run_tool_with_ops(ops, "zstd", report, descriptors, rows)
        outputs = (gzip_output, zstd_output)
        execution_mappings = (gzip_observed.pop("_execution_mapping_sha256"), zstd_observed.pop("_execution_mapping_sha256"))
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
    for endpoint, purpose in socket_recovery:
        try: _close_socket(endpoint, ops, purpose)
        except BaseException as error: failures.append(error)
    if failures: raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    try:
        cleanup = { "children_reaped": _parse_children(_proc_bytes("/proc/thread-self/children", 65536, ops)) == child_baseline, "descendants_reaped": not process_owner.processes and _descendant_census(os.getpid(), ops) == child_baseline, "descriptors_restored": _descriptor_snapshot(ops) == fd_baseline, "mounts_restored": os.path.ismount(root) == mount_baseline, "namespace_handles_released": not any(lease.namespace_handles for lease in process_owner.processes), "namespaces_released": not process_owner.processes, "paths_restored": os.path.lexists(root) == path_baseline, }
    except BaseException as error:
        raise RuntimeLauncherCleanupError(primary, [error]) from (primary or error)
    cleanup_restored = all(type(value) is bool and value for value in cleanup.values())
    if not cleanup_restored: raise RuntimeLauncherCleanupError(primary, [RuntimeLauncherError("cleanup baseline mismatch", "cleanup-baseline")]) from primary
    if isinstance(primary, RuntimeLauncherUnavailable):
        primary.cleanup_restored = True
    if primary is not None: raise primary
    _require(observed_tools is not None and outputs is not None and receipt is not None and report is not None and execution_mappings is not None, "coordinator result missing", "coordinator-result")
    observed = _build_observed_result(observed_tools, cleanup)
    result = RuntimeQualificationResult(
        version=_RESULT_VERSION,
        marker=_MARKER,
        source_revision=admission.revision,
        source_set_sha256=admission.source_set_sha256,
        closure_sha256=receipt.closure_sha256,
        gzip_output_sha256=hashlib.sha256(outputs[0]).hexdigest(),
        zstd_output_sha256=hashlib.sha256(outputs[1]).hexdigest(),
        **observed,
    )
    metadata = _runtime_metadata(report, rows, execution_mappings, outputs)
    return result, metadata, report
def _launch_admitted_fixed_runtime_qualification(admission: _SourceAdmission, closure_module: types.ModuleType, ops: Any) -> RuntimeQualificationResult:
    result, _metadata, _report = _coordinate_with_ops(admission, closure_module, ops)
    return result
def _launch_admitted_fixed_compression_qualification(admission: _SourceAdmission, closure_module: types.ModuleType, ops: Any) -> RuntimeCompressionQualificationResult:
    result, tools, report = _coordinate_with_ops(admission, closure_module, ops)
    tool_order = tuple(item.id for item in tools)
    _require(tool_order == ("gzip", "zstd"), "compression tool order", "compression-order")
    expected_output = hashlib.sha256(_FIXED_OUTPUT).hexdigest()
    exact_outputs = all(
        item.seal_mask == 63 and item.output_sha256 == expected_output
        for item in tools
    )
    _require(exact_outputs, "compression exact observation", "compression-observation")
    parser_report = report["tools"][0]
    parser = RuntimeCompressionParserObservation(
        closure_sha256=parser_report["closure_sha256"],
        objects=_closed_compression_objects(parser_report["objects"]),
    )
    return RuntimeCompressionQualificationResult(
        version="cogs.runtime-compression-qualification/v1",
        source_revision=admission.revision,
        source_set_sha256=admission.source_set_sha256,
        closure_sha256=result.closure_sha256,
        parser=parser,
        tools=tools,
        runtime=result,
    )
def _result_value(value: object) -> dict[str, object]:
    _require(is_dataclass(value) and not isinstance(value, type), "fixed result dataclass", "result-type")
    result = asdict(value)
    _require(type(result) is dict and tuple(result) == tuple(item.name for item in fields(value)), "fixed result inventory", "result-inventory")
    return result
def _validate_git_blob(data: bytes, oid: str, label: str) -> None:
    valid_oid = len(oid) in (40, 64)
    valid_oid = valid_oid and all(character in "0123456789abcdef" for character in oid)
    _require(valid_oid, f"{label} object id", f"{label}-blob")
    algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
    blob = b"blob " + str(len(data)).encode() + b"\0" + data
    _require(algorithm(blob).hexdigest() == oid, f"{label} blob", f"{label}-blob")
def _validate_client_bytes(mode: str, data: bytes, tree: dict[str, tuple[str, str]]) -> str:
    path = _OPERATION_CLIENTS[mode]
    policy = type(data) is bytes and 0 < len(data) <= _MAX_SOURCE
    _require(policy, "operation client file policy", "client-policy")
    _require(set(tree) == {path}, "operation client tree cardinality", "client-tree")
    mode_value, oid = tree[path]
    _require(mode_value == "100644", "operation client tree mode", "client-tree")
    _validate_git_blob(data, oid, "client")
    return hashlib.sha256(data).hexdigest()
def _source_set_digest(sources: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path in _FIXED_SOURCE_SET:
        encoded = path.encode()
        data = sources[path]
        framed = struct.pack("!I", len(encoded)) + encoded + struct.pack("!Q", len(data))
        digest.update(framed + hashlib.sha256(data).digest())
    return digest.hexdigest()
def _validate_source_tree(sources: dict[str, bytes], tree: dict[str, tuple[str, str]]) -> None:
    _require(set(tree) == set(_FIXED_SOURCE_SET), "fixed source tree cardinality")
    _require(set(sources) == set(_FIXED_SOURCE_SET), "fixed held source cardinality")
    for path in _FIXED_SOURCE_SET:
        mode, oid = tree[path]
        _require(mode == "100644", "fixed source tree mode")
        _validate_git_blob(sources[path], oid, "fixed-source")
def _read_held_capsule_fd(fd: int) -> bytes:
    before = os.fstat(fd)
    regular = stat.S_ISREG(before.st_mode) and 0 < before.st_size <= _HELD_SOURCE_LIMIT
    _require(regular, "held source descriptor policy", "held-source-policy")
    data = _read_complete(fd, before.st_size, _HELD_SOURCE_LIMIT)
    after = os.fstat(fd)
    _require(_stat_identity(before) == _stat_identity(after), "held source generation drift", "held-source-generation")
    seals = fcntl.fcntl(fd, _F_GET_SEALS)
    _require(seals == _DATA_SEALS, "held source descriptor seals", "held-source-seals")
    return data
def _authenticate_sources(source_fd: int, admission: dict[str, object]) -> dict[str, bytes]:
    capsule = _read_held_capsule_fd(source_fd)
    sources, _driver = _decode_held_source_capsule(capsule, admission)
    return sources
_HELD_SOURCE_VERSION = "cogs.held-source-set/v1"
_HELD_SOURCE_LIMIT = 12_000_000
def _held_source_capsule(
    operation: str,
    revision: str,
    sources: dict[str, bytes],
    source_tree: dict[str, tuple[str, str]],
    driver: bytes,
    driver_tree: dict[str, tuple[str, str]],
) -> bytes:
    client_path = _OPERATION_CLIENTS[operation]
    source_rows = []
    for path in _FIXED_SOURCE_SET:
        source_rows.append({
            "oid": source_tree[path][1],
            "path": path,
            "sha256": hashlib.sha256(sources[path]).hexdigest(),
            "size": len(sources[path]),
        })
    client = {
        "oid": driver_tree[client_path][1],
        "path": client_path,
        "sha256": hashlib.sha256(driver).hexdigest(),
        "size": len(driver),
    }
    header = {
        "client": client,
        "operation": operation,
        "revision": revision,
        "sources": source_rows,
        "version": _HELD_SOURCE_VERSION,
    }
    payload = b"".join(sources[path] for path in _FIXED_SOURCE_SET) + driver
    capsule = _canonical(header, True) + payload
    _require(len(capsule) <= _HELD_SOURCE_LIMIT, "held source capsule bound", "held-source-bound")
    return capsule
def _decode_held_source_capsule(raw: bytes, admission: dict[str, object]) -> tuple[dict[str, bytes], bytes]:
    _require(type(raw) is bytes and b"\n" in raw, "held source capsule framing", "held-source-framing")
    _require(0 < len(raw) <= _HELD_SOURCE_LIMIT, "held source capsule bound", "held-source-bound")
    header_raw, payload = raw.split(b"\n", 1)
    header = _strict_json(header_raw, False, 65536, "held source header")
    keys = {"client", "operation", "revision", "sources", "version"}
    _require(type(header) is dict and set(header) == keys, "held source header shape", "held-source-shape")
    mode = _ADMISSION_MODES[admission["version"]]
    identity = header["version"] == _HELD_SOURCE_VERSION
    identity = identity and header["operation"] == mode
    identity = identity and header["revision"] == admission["revision"]
    _require(identity, "held source identity", "held-source-identity")
    rows = header["sources"]
    paths = [row.get("path") for row in rows if type(row) is dict]
    _require(type(rows) is list and paths == list(_FIXED_SOURCE_SET), "held source rows", "held-source-shape")
    sources: dict[str, bytes] = {}
    source_tree: dict[str, tuple[str, str]] = {}
    offset = 0
    row_keys = {"oid", "path", "sha256", "size"}
    for row in rows:
        valid = set(row) == row_keys and type(row["size"]) is int
        valid = valid and 0 < row["size"] <= _MAX_SOURCE and _sha(row["sha256"])
        _require(valid, "held source row", "held-source-shape")
        data = payload[offset:offset + row["size"]]
        offset += row["size"]
        _require(hashlib.sha256(data).hexdigest() == row["sha256"], "held source digest", "held-source-digest")
        sources[row["path"]] = data
        source_tree[row["path"]] = ("100644", row["oid"])
    _validate_source_tree(sources, source_tree)
    client = header["client"]
    client_path = _OPERATION_CLIENTS[mode]
    valid_client = type(client) is dict and set(client) == row_keys
    valid_client = valid_client and client["path"] == client_path
    valid_client = valid_client and type(client["size"]) is int
    _require(valid_client and 0 < client["size"] <= _MAX_SOURCE, "held client row", "client-policy")
    driver = payload[offset:offset + client["size"]]
    offset += client["size"]
    _require(offset == len(payload), "held source trailing bytes", "held-source-framing")
    driver_tree = {client_path: ("100644", client["oid"])}
    client_sha = _validate_client_bytes(mode, driver, driver_tree)
    _require(client_sha == client["sha256"] == admission["client_sha256"], "held client digest", "client-digest")
    source_digest = _source_set_digest(sources)
    _require(source_digest == admission["source_set_sha256"], "held source-set digest", "held-source-digest")
    launcher_sha = hashlib.sha256(sources[_MODULE_PATHS[2]]).hexdigest()
    _require(launcher_sha == admission["bootstrap_sha256"], "held launcher digest", "held-source-digest")
    return sources, driver
def _prepare_client_from_admitted_bytes(
    operation: str,
    revision: str,
    sources: dict[str, bytes],
    source_tree: dict[str, tuple[str, str]],
    driver: bytes,
    driver_tree: dict[str, tuple[str, str]],
) -> tuple[bytes, bytes, bytes, str]:
    valid_revision = type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision) is not None
    _require(operation in _OPERATION_CLIENTS and valid_revision, "held client identity", "client-identity")
    _validate_source_tree(sources, source_tree)
    client_sha = _validate_client_bytes(operation, driver, driver_tree)
    source_digest = _source_set_digest(sources)
    launcher = sources[_MODULE_PATHS[2]]
    version = next(key for key, value in _ADMISSION_MODES.items() if value == operation)
    admission = _canonical({
        "bootstrap_sha256": hashlib.sha256(launcher).hexdigest(),
        "client_sha256": client_sha,
        "revision": revision,
        "source_set_sha256": source_digest,
        "version": version,
    }, True)
    capsule = _held_source_capsule(
        operation,
        revision,
        sources,
        source_tree,
        driver,
        driver_tree,
    )
    return launcher, admission, capsule, source_digest
def _decode_runtime_result(value: object) -> RuntimeQualificationResult:
    names = tuple(item.name for item in fields(RuntimeQualificationResult))
    _require(type(value) is dict and set(value) == set(names), "ordinary result shape", "result-shape")
    result = RuntimeQualificationResult(**value)
    _require(all(type(getattr(result, name)) is str for name in names[:7]), "ordinary result strings", "result-type")
    _require(all(type(getattr(result, name)) is bool and getattr(result, name) for name in names[7:]), "ordinary result observations", "result-observation")
    return result
def _decode_mapping_result(value: object) -> RuntimeMappingQualificationResult:
    names = tuple(item.name for item in fields(RuntimeMappingQualificationResult))
    _require(type(value) is dict and set(value) == set(names), "mapping result shape", "result-shape")
    objects, mapped = value["objects"], value["mapped"]
    object_names, mapped_names = tuple(item.name for item in fields(RuntimeObjectObservation)), tuple(item.name for item in fields(MappedObjectObservation))
    _require(type(objects) is list and type(mapped) is list, "mapping row arrays", "result-shape")
    object_rows = tuple(RuntimeObjectObservation(
        role=item["role"],
        size_bytes=item["size_bytes"],
        sha256=item["sha256"],
        soname=item["soname"],
        needed=tuple(item["needed"]),
    ) for item in objects if type(item) is dict and set(item) == set(object_names))
    mapped_rows = tuple(MappedObjectObservation(
        role=item["role"],
        sha256=item["sha256"],
    ) for item in mapped if type(item) is dict and set(item) == set(mapped_names))
    _require(len(object_rows) == len(objects) == len(mapped_rows) == len(mapped), "mapping row shape", "result-shape")
    arguments = dict(value)
    arguments["objects"] = object_rows
    arguments["mapped"] = mapped_rows
    result = RuntimeMappingQualificationResult(**arguments)
    _require(all(getattr(result, name) is True for name in names[-5:]), "mapping observations", "result-observation")
    return result
def _decode_observation_result(value: object, result_type: type, string_count: int, version: str) -> object:
    names = tuple(item.name for item in fields(result_type))
    _require(type(value) is dict and set(value) == set(names), "observation result shape", "result-shape")
    result = result_type(**value)
    _require(all(type(getattr(result, name)) is str for name in names[:string_count]), "observation result strings", "result-type")
    _require(result.version == version and all(getattr(result, name) is True for name in names[string_count:]), "observation result values", "result-observation")
    return result
def _decode_sandbox_result(value: object) -> SandboxQualificationResult: return _decode_observation_result(value, SandboxQualificationResult, 4, "cogs.sandbox-qualification/v1")
def _decode_compression_objects(value: object) -> tuple[dict[str, object], ...]:
    _require(type(value) is list, "compression object rows", "result-shape")
    rows: list[dict[str, object]] = []
    expected = {"needed", "role", "sha256", "size_bytes", "soname"}
    for item in value:
        _require(type(item) is dict and set(item) == expected, "compression object row", "result-shape")
        needed = item["needed"]
        _require(type(needed) is list, "compression needed rows", "result-shape")
        rows.append({**item, "needed": tuple(needed)})
    return tuple(rows)
def _decode_compression_result(value: object) -> RuntimeCompressionQualificationResult:
    names = tuple(item.name for item in fields(RuntimeCompressionQualificationResult))
    valid = type(value) is dict and set(value) == set(names)
    valid = valid and type(value["tools"]) is list
    _require(valid, "compression result shape", "result-shape")
    parser_value = value["parser"]
    parser_keys = {"closure_sha256", "objects"}
    _require(type(parser_value) is dict and set(parser_value) == parser_keys, "parser result shape", "result-shape")
    parser = RuntimeCompressionParserObservation(
        closure_sha256=parser_value["closure_sha256"],
        objects=_decode_compression_objects(parser_value["objects"]),
    )
    tool_names = tuple(item.name for item in fields(RuntimeCompressionToolObservation))
    tools: list[RuntimeCompressionToolObservation] = []
    for item in value["tools"]:
        _require(type(item) is dict and set(item) == set(tool_names), "compression tool row", "result-shape")
        arguments = dict(item)
        arguments["objects"] = _decode_compression_objects(item["objects"])
        tools.append(RuntimeCompressionToolObservation(**arguments))
    closed_tools = tuple(tools)
    tool_order = tuple(item.id for item in closed_tools)
    _require(len(closed_tools) == 2 and tool_order == ("gzip", "zstd"), "compression tool shape", "result-shape")
    runtime = _decode_runtime_result(value["runtime"])
    result = RuntimeCompressionQualificationResult(
        version=value["version"],
        source_revision=value["source_revision"],
        source_set_sha256=value["source_set_sha256"],
        closure_sha256=value["closure_sha256"],
        parser=parser,
        tools=closed_tools,
        runtime=runtime,
    )
    expected = hashlib.sha256(_FIXED_OUTPUT).hexdigest()
    exact = all(item.seal_mask == 63 and item.output_sha256 == expected for item in closed_tools)
    _require(exact, "compression observations", "result-observation")
    return result
_ROOT_CAPSULE_VERSION = "cogs.runtime-source-admission/sandbox-v1"
_ROOT_CAPSULE_LIMIT, _ROOT_BOOTSTRAP_LIMIT = 8_000_000, 65_536
_ROOT_BOOTSTRAP_PATH = "/usr/local/libexec/cogs-native-root-bootstrap-v1.py"
_ROOT_AUTHORITY_PATH = "/etc/cogs/native-root-authority-v1.json"
_ROOT_BOOTSTRAP = r'''import ctypes
import hashlib
import json
import os
import struct
import sys
def bootstrap_failure(kind, value, trace):
    while trace.tb_next is not None:
        trace = trace.tb_next
    code = 'bootstrap-line-' + str(trace.tb_lineno)
    digest = hashlib.sha256(kind.__name__.encode()).hexdigest()[:16]
    os.write(2, ('root-launcher-' + code + '-' + digest + '\n').encode())
sys.excepthook = bootstrap_failure
bootstrap_path = '/usr/local/libexec/cogs-native-root-bootstrap-v1.py'
authority_path = '/etc/cogs/native-root-authority-v1.json'
# CPython may synthesize this sole locale entry after execve. The other two
# values are fixed by the already-registered launcher child before sudo exec.
environment = dict(os.environ)
if environment.get('LC_CTYPE') == 'C.UTF-8':
    del environment['LC_CTYPE']
assert set(environment) == {'COGS_LAUNCHER_PID', 'COGS_SUDO_PID'}
def fixed_pid(name):
    value = environment[name]
    assert value.isdigit() and (len(value) == 1 or not value.startswith('0'))
    result = int(value)
    assert 1 < result < 1 << 31
    return result
launcher_pid = fixed_pid('COGS_LAUNCHER_PID')
sudo_pid = fixed_pid('COGS_SUDO_PID')
os.environ.clear()
assert os.geteuid() == 0 and not os.environ and sys.argv == [bootstrap_path]
parent = os.getppid()
libc = ctypes.CDLL(None, use_errno=True)
direct = os.getpid() == sudo_pid and parent == launcher_pid
monitored = os.getpid() != sudo_pid and parent == sudo_pid
assert (direct or monitored) and libc.prctl(1, 9, 0, 0, 0) == 0 and os.getppid() == parent
directory = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
buffer = ctypes.create_string_buffer(32768)
numbers = []
calls = 0
while True:
    count = libc.syscall(217, directory, ctypes.byref(buffer), 32768)
    assert count >= 0
    calls += 1
    assert calls <= 33
    if count == 0:
        break
    offset = 0
    while offset < count:
        assert count - offset >= 19
        length = struct.unpack_from('=QqHB', buffer.raw, offset)[2]
        assert length >= 24 and length % 8 == 0 and offset + length <= count
        field = buffer.raw[offset + 19:offset + length]
        end = field.find(b'\0')
        assert end >= 0
        name = field[:end]
        if name not in (b'.', b'..'):
            assert name.isdigit() and (len(name) == 1 or not name.startswith(b'0'))
            numbers.append(int(name))
        offset += length
assert len(numbers) == len(set(numbers)) and numbers.count(directory) == 1 and sorted(number for number in numbers if number != directory) == [0, 1, 2]
os.close(directory)
running = os.stat('/proc/self/exe')
admitted = os.stat('/usr/bin/python3')
assert (running.st_dev, running.st_ino) == (admitted.st_dev, admitted.st_ino)
def read_fixed(path, bound):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    before = os.fstat(descriptor)
    assert before.st_uid == 0 and before.st_mode & 0o170000 == 0o100000
    assert before.st_mode & 0o022 == 0 and 0 < before.st_size <= bound
    value = b''
    while len(value) < before.st_size:
        part = os.read(descriptor, before.st_size - len(value))
        assert part
        value += part
    assert not os.read(descriptor, 1)
    after = os.fstat(descriptor)
    os.close(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns, item.st_mode, item.st_uid, item.st_gid)
    assert identity(before) == identity(after)
    return value
authority_raw = read_fixed(authority_path, 65536)
bootstrap_raw = read_fixed(bootstrap_path, 65536)
raw = b''
while len(raw) <= 8000000:
    part = os.read(0, min(65536, 8000001 - len(raw)))
    if not part:
        break
    raw += part
assert 0 < len(raw) <= 8000000 and b'\n' in raw
header_raw, payload = raw.split(b'\n', 1)
assert 0 < len(header_raw) <= 65536
def pairs(items):
    value = {}
    for key, item in items:
        assert key not in value
        value[key] = item
    return value
header = json.loads(header_raw.decode('utf-8', 'strict'), object_pairs_hook=pairs)
assert json.dumps(header, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == header_raw
authority = json.loads(authority_raw.decode('utf-8', 'strict'), object_pairs_hook=pairs)
assert json.dumps(authority, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == authority_raw
assert set(authority) == {'bootstrap_sha256', 'revision', 'root_bootstrap_sha256', 'source_set_sha256', 'sources', 'version'}
assert authority['version'] == 'cogs.root-capsule-authority/v1'
assert hashlib.sha256(bootstrap_raw).hexdigest() == authority['root_bootstrap_sha256']
keys = {'bootstrap_sha256', 'parent_pid', 'profile', 'revision', 'source_set_sha256', 'sources', 'version'}
assert type(header) is dict and set(header) == keys
assert header['version'] == 'cogs.runtime-source-admission/sandbox-v1' and header['profile'] == 'sandbox' and header['parent_pid'] == launcher_pid
paths = ('deploy/aws-feasibility/remote/completion_elf.py', 'deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py', 'deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py', 'schemas/trusted-runtime-closure-v1.json')
rows = header['sources']
assert type(rows) is list and len(rows) == 4 and tuple(row.get('path') for row in rows if type(row) is dict) == paths
assert header['revision'] == authority['revision']
assert header['bootstrap_sha256'] == authority['bootstrap_sha256']
assert header['source_set_sha256'] == authority['source_set_sha256']
assert rows == authority['sources']
offset = 0
sources = {}
digest = hashlib.sha256()
for row in rows:
    assert set(row) == {'path', 'sha256', 'size'} and type(row['size']) is int and 0 < row['size'] <= 2000000
    data = payload[offset:offset + row['size']]
    offset += row['size']
    assert len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256']
    encoded = row['path'].encode()
    digest.update(struct.pack('!I', len(encoded)) + encoded + struct.pack('!Q', len(data)) + hashlib.sha256(data).digest())
    sources[row['path']] = data
assert offset == len(payload) and digest.hexdigest() == header['source_set_sha256']
launcher = sources[paths[2]]
assert hashlib.sha256(launcher).hexdigest() == header['bootstrap_sha256']
globals_ = {'__name__': 'cogs_root_capsule'}
exec(compile(launcher, 'cogs-held:root-launcher', 'exec'), globals_)
try:
    root_status = globals_['_root_capsule_entry'](raw, authority)
except globals_['RuntimeLauncherUnavailable'] as error:
    root_code = 'unavailable'
    root_detail = str(error)
except globals_['RuntimeLauncherError'] as error:
    candidate = error.code
    root_code = candidate if type(candidate) is str and len(candidate) <= 40 and all(character.isalnum() or character in '._-' for character in candidate) else 'invalid-code'
    root_detail = str(error)
except Exception as error:
    label = ''.join(character if character.isalnum() or character in '._-' else '-' for character in type(error).__name__)[:20]
    root_code = 'exception-' + label + '-' + str(getattr(error, 'errno', 0))
    root_detail = type(error).__name__
else:
    raise SystemExit(root_status)
digest = hashlib.sha256(root_detail.encode('utf-8', 'backslashreplace')).hexdigest()[:16]
os.write(2, ('root-launcher-' + root_code + '-' + digest + '\n').encode('ascii'))
raise SystemExit(1)'''
def _encode_root_capsule(sources: dict[str, bytes], admission: _SourceAdmission) -> bytes:
    rows = [{"path": path, "sha256": hashlib.sha256(sources[path]).hexdigest(), "size": len(sources[path])} for path in _FIXED_SOURCE_SET]
    header = {"bootstrap_sha256": admission.bootstrap_sha256, "parent_pid": os.getpid(), "profile": "sandbox", "revision": admission.revision, "source_set_sha256": admission.source_set_sha256, "sources": rows, "version": _ROOT_CAPSULE_VERSION}
    result = _canonical(header, True) + b"".join(sources[path] for path in _FIXED_SOURCE_SET)
    _require(len(_ROOT_BOOTSTRAP.encode()) <= _ROOT_BOOTSTRAP_LIMIT and len(result) <= _ROOT_CAPSULE_LIMIT, "root capsule bound", "root-capsule-bound")
    return result
def _decode_root_capsule(
    raw: bytes,
    authority: dict[str, object] | None = None,
) -> tuple[dict[str, bytes], dict[str, object]]:
    _require(type(raw) is bytes and 0 < len(raw) <= _ROOT_CAPSULE_LIMIT and b"\n" in raw, "root capsule framing", "root-capsule-framing")
    header_raw, payload = raw.split(b"\n", 1)
    header = _strict_json(header_raw, False, _ROOT_BOOTSTRAP_LIMIT, "root capsule header")
    keys = {"bootstrap_sha256", "parent_pid", "profile", "revision", "source_set_sha256", "sources", "version"}
    identity = header["version"] == _ROOT_CAPSULE_VERSION and header["profile"] == "sandbox"
    identity = identity and type(header["parent_pid"]) is int and header["parent_pid"] > 1
    _require(type(header) is dict and set(header) == keys and identity, "root capsule identity", "root-capsule-identity")
    rows = header["sources"]
    _require(type(rows) is list and [row.get("path") for row in rows if type(row) is dict] == list(_FIXED_SOURCE_SET), "root capsule source order", "root-capsule-sources")
    sources: dict[str, bytes] = {}
    offset = 0
    for row in rows:
        _require(set(row) == {"path", "sha256", "size"} and _sha(row["sha256"]) and type(row["size"]) is int and 0 < row["size"] <= _MAX_SOURCE, "root capsule source row", "root-capsule-source")
        data = payload[offset:offset + row["size"]]
        offset += row["size"]
        _require(len(data) == row["size"] and hashlib.sha256(data).hexdigest() == row["sha256"], "root capsule source digest", "root-capsule-digest")
        sources[row["path"]] = data
    _require(offset == len(payload) and _source_set_digest(sources) == header["source_set_sha256"], "root capsule aggregate", "root-capsule-aggregate")
    launcher_sha256 = hashlib.sha256(sources[_MODULE_PATHS[2]]).hexdigest()
    _require(launcher_sha256 == header["bootstrap_sha256"], "root capsule launcher", "root-capsule-launcher")
    if authority is not None:
        authority_value = _strict_json(
            _canonical(authority),
            False,
            65536,
            "root authority",
        )
        _require(type(authority_value) is dict, "root authority shape", "root-authority")
        root_bootstrap_sha256 = authority_value.get("root_bootstrap_sha256")
        _require(_sha(root_bootstrap_sha256), "root bootstrap authority", "root-authority")
        expected = {
            "bootstrap_sha256": header["bootstrap_sha256"],
            "revision": header["revision"],
            "root_bootstrap_sha256": root_bootstrap_sha256,
            "source_set_sha256": header["source_set_sha256"],
            "sources": header["sources"],
            "version": "cogs.root-capsule-authority/v1",
        }
        _require(authority_value == expected, "root capsule independent authority", "root-authority")
    return sources, header
def _root_capsule_failure_code(input_complete: bool, status: int | None, errors: bytes) -> str:
    diagnostic = re.fullmatch(rb"root-launcher-([A-Za-z0-9._-]{1,40})-[0-9a-f]{16}\n", errors)
    if diagnostic is not None:
        root_code = diagnostic.group(1).decode("ascii")
        return f"root-{root_code}"[:40]
    error_digest = hashlib.sha256(errors).hexdigest()[:12]
    phase = "complete" if input_complete else "early"
    return f"sudo-{phase}-{status}-{error_digest}"

def _run_root_capsule_with_ops(ops: Any, capsule: bytes) -> bytes:
    command = (
        "/usr/bin/sudo",
        "-n",
        "--close-from=3",
        "/usr/bin/env",
        "-i",
        "/usr/bin/python3",
        "-I",
        "-B",
        _ROOT_BOOTSTRAP_PATH,
    )
    owner = _ProcessOwner(ops)
    leases: list[_FdLease] = []
    primary: BaseException | None = None
    output = bytearray()
    errors = bytearray()
    try:
        pairs = []
        for purpose in ("input", "output", "error", "transition", "ack"):
            pair = tuple(_FdLease(fd, f"sudo-{purpose}") for fd in os.pipe2(os.O_CLOEXEC))
            leases.extend(pair)
            pairs.append(pair)
        input_read, input_write = pairs[0]
        output_read, output_write = pairs[1]
        error_read, error_write = pairs[2]
        transition_read, transition_write = pairs[3]
        ack_read, ack_write = pairs[4]
        pid, process, gate = owner.spawn()
        if pid == 0:
            try:
                launcher_pid = os.getppid()
                for lease in (input_write, output_read, error_read, transition_read, ack_write):
                    lease.close(ops)
                _require(gate is not None and ops.read(gate.fd, 1) == b"G", "sudo release", "sudo-release")
                gate.close(ops)
                os.setsid()
                _require(ops.write(transition_write.fd, b"S") == 1 and ops.read(ack_read.fd, 1) == b"A", "sudo transition", "sudo-transition")
                duplicates = tuple(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128) for fd in (input_read.fd, output_write.fd, error_write.fd))
                for original, target in zip(duplicates, (0, 1, 2)):
                    os.dup2(original, target, inheritable=True)
                for fd in _descriptor_snapshot(ops):
                    if fd not in (0, 1, 2):
                        _FdLease(fd, "sudo-complement").close(ops)
                _require(os.getppid() == launcher_pid, "sudo parent identity", "sudo-parent")
                identity = (f"COGS_LAUNCHER_PID={launcher_pid}", f"COGS_SUDO_PID={os.getpid()}")
                child_command = (*command[:5], *identity, *command[5:])
                os.execve(child_command[0], child_command, {})
            except BaseException:
                os._exit(125)
        _require(process is not None, "sudo process registration", "sudo-register")
        for lease in (input_read, output_write, error_write, transition_write, ack_read):
            lease.close(ops)
        owner.plan_setsid(process)
        owner.release(process)
        _require(ops.read(transition_read.fd, 1) == b"S", "sudo transition read", "sudo-transition")
        owner.confirm_setsid(process)
        _require(ops.write(ack_write.fd, b"A") == 1, "sudo transition ack", "sudo-transition")
        transition_read.close(ops)
        ack_write.close(ops)
        offset = 0
        input_complete = True
        try:
            while offset < len(capsule):
                written = ops.write(input_write.fd, capsule[offset:])
                _require(written > 0, "root capsule write", "root-capsule-write")
                offset += written
        except OSError as error:
            if error.errno != errno.EPIPE:
                raise
            # The fixed bootstrap can reject before consuming its complete
            # input.  Close our writer, drain its diagnostic pipes, and reap
            # it below so EPIPE cannot bypass the owned-child settlement.
            input_complete = False
        input_write.close(ops)
        deadline = time.monotonic() + 30.0
        active = {output_read.fd: output, error_read.fd: errors}
        while active:
            ready = select.select(tuple(active), (), (), max(0.0, deadline - time.monotonic()))[0]
            _require(bool(ready), "sudo output deadline", "sudo-deadline")
            for fd in ready:
                part = ops.read(fd, _MAX_REPORT + 1 - len(active[fd]))
                if part:
                    active[fd] += part
                    _require(len(active[fd]) <= _MAX_REPORT, "sudo output bound", "sudo-output-bound")
                else:
                    next(item for item in leases if item.fd == fd).close(ops)
                    del active[fd]
        status = _wait_bounded(process, deadline)
        exit_code = _root_capsule_failure_code(input_complete, status, bytes(errors))
        _require(input_complete and status == 0 and not errors, "sudo capsule exit", exit_code)
        owner.stop(process)
    except BaseException as error:
        primary = error
    failures = []
    try:
        owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    try:
        _close_leases(ops, leases, primary)
    except BaseException as error:
        failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    if primary is not None:
        raise primary
    return bytes(output)
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
def _sandbox_inner(
    ops: Any,
    root: str,
    leader_pid: int,
    baseline_namespaces: tuple[tuple[int, int], ...],
    gate: _FdLease,
    result_write: _FdLease,
    final_read: _FdLease,
) -> NoReturn:
    try:
        released = ops.read(gate.fd, 1)
        _require(released == b"G", "sandbox inner release", "sandbox-inner-release")
        gate.close(ops)
        parent_before = os.getppid()
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        _require(parent_before == leader_pid and os.getppid() == leader_pid, "sandbox inner parent", "sandbox-inner-parent")
        allowed = {0, 1, 2, result_write.fd, final_read.fd}
        for descriptor in _descriptor_snapshot(ops):
            if descriptor not in allowed:
                _FdLease(descriptor, "sandbox-inner-complement").close(ops)
        current_namespaces = tuple(
            (info.st_dev, info.st_ino)
            for name in ("user", "pid", "mnt", "net")
            for info in (os.stat(f"/proc/self/ns/{name}"),)
        )
        status = _parse_proc_status(_proc_bytes("/proc/self/status", 65536, ops))
        changed = tuple(
            current != prior
            for current, prior in zip(current_namespaces, baseline_namespaces)
        )
        facts = {
            "mount_namespace_exact": changed[2],
            "network_namespace_exact": changed[3],
            "pid_namespace_exact": changed[1],
            "pid_one": status["nspid"][-1] == 1,
            "user_namespace_exact": changed[0],
        }
        final_flags = _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
        ops.mount(None, root.encode(), None, final_flags, None)
        boundary = _enter_boundary(ops, root)
        packet = _canonical({"boundary": boundary, "facts": facts})
        written = ops.write(result_write.fd, packet)
        _require(written == len(packet), "sandbox inner result", "sandbox-inner-result")
        result_write.close(ops)
        finalized = ops.read(final_read.fd, 1)
        _require(finalized == b"F", "sandbox inner final gate", "sandbox-inner-final")
        final_read.close(ops)
        os._exit(0)
    except BaseException:
        os._exit(125)
def _sandbox_leader(
    ops: Any,
    root: str,
    nonce: bytes,
    control: socket.socket,
    transfer: socket.socket,
    gate: _FdLease,
) -> NoReturn:
    local_owner = _ProcessOwner(ops)
    leases: list[_FdLease] = []
    primary: BaseException | None = None
    mounted = False
    try:
        released = ops.read(gate.fd, 1)
        _require(released == b"G", "sandbox leader release", "sandbox-release")
        gate.close(ops)
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        _lifecycle_control_send(control, b"S:sandbox")
        _lifecycle_control_recv(control, time.monotonic() + _SETUP_SECONDS, b"C:sandbox")
        original_uid = os.getuid()
        original_gid = os.getgid()
        baseline_namespaces = tuple(
            (info.st_dev, info.st_ino)
            for name in ("user", "pid", "mnt", "net")
            for info in (os.stat(f"/proc/self/ns/{name}"),)
        )
        os.setgroups([])
        ops.unshare_boundary()
        try:
            _write_map(ops, "/proc/self/setgroups", b"deny\n")
        except FileNotFoundError:
            pass
        _write_map(ops, "/proc/self/uid_map", f"0 {original_uid} 1\n".encode())
        _write_map(ops, "/proc/self/gid_map", f"0 {original_gid} 1\n".encode())
        ops.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None)
        mount_data = b"mode=0700,size=1048576,nr_inodes=16"
        ops.mount(b"tmpfs", root.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV, mount_data)
        mounted = True
        result_pair = tuple(
            _FdLease(fd, "sandbox-inner-result")
            for fd in os.pipe2(os.O_CLOEXEC)
        )
        final_pair = tuple(
            _FdLease(fd, "sandbox-inner-final")
            for fd in os.pipe2(os.O_CLOEXEC)
        )
        leases.extend((*result_pair, *final_pair))
        result_read, result_write = result_pair
        final_read, final_write = final_pair
        pid, inner, inner_gate = local_owner.spawn()
        if pid == 0:
            control.close()
            transfer.close()
            result_read.close(ops)
            final_write.close(ops)
            _require(inner_gate is not None, "sandbox inner gate", "sandbox-inner-register")
            _sandbox_inner(
                ops,
                root,
                os.getppid(),
                baseline_namespaces,
                inner_gate,
                result_write,
                final_read,
            )
        _require(inner is not None, "sandbox inner registration", "sandbox-inner-register")
        result_write.close(ops)
        final_read.close(ops)
        packet = _lifecycle_transfer_packet(inner, os.getpid(), nonce, "sandbox", "inner")
        rights = array("i", (inner.pidfd.fd,))
        ancillary = ((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),)
        written = transfer.sendmsg((packet,), ancillary, socket.MSG_DONTWAIT)
        _require(written == len(packet), "sandbox inner transfer", "process-transfer-send")
        transfer.shutdown(socket.SHUT_WR)
        _lifecycle_control_recv(transfer, time.monotonic() + _SETUP_SECONDS, b"A")
        local_owner.release(inner)
        inner.pidfd.close(ops)
        inner.pidfd = None
        local_owner.processes.remove(inner)
        _deadline_ready(result_read.fd, time.monotonic() + _SETUP_SECONDS, "sandbox-inner-result")
        raw = ops.read(result_read.fd, 65536)
        result_read.close(ops)
        entered = _canonical({
            "event": "entered",
            "result": _strict_json(raw, False, 65536, "sandbox inner result"),
            "version": _RESULT_VERSION,
        })
        _lifecycle_control_send(control, entered)
        _lifecycle_control_recv(control, time.monotonic() + _SETUP_SECONDS, b"F:sandbox")
        written = ops.write(final_write.fd, b"F")
        _require(written == 1, "sandbox inner final release", "sandbox-inner-final")
        final_write.close(ops)
        reap_deadline = time.monotonic() + _SETUP_SECONDS
        while True:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed == pid:
                break
            remaining = reap_deadline - time.monotonic()
            _require(observed == 0 and remaining > 0, "sandbox inner bounded reap", "sandbox-inner-reap")
            time.sleep(min(0.001, remaining))
        _require(status == 0, "sandbox inner exact reap", "sandbox-inner-reap")
        _lifecycle_control_send(control, b"E:sandbox")
        ops.umount(root.encode())
        mounted = False
        os._exit(0)
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try:
        local_owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    try:
        _close_leases(ops, leases, primary)
    except BaseException as error:
        failures.append(error)
    if mounted:
        try:
            ops.umount(root.encode())
        except BaseException as error:
            failures.append(error)
    code = "cleanup-uncertain" if failures else getattr(
        primary,
        "code",
        "launcher-rejected",
    )
    try:
        _lifecycle_control_send(
            control,
            b"Z:sandbox:" + code.encode("ascii"),
        )
    except BaseException:
        pass
    os._exit(125)
def _sandbox_only_transaction(ops: Any) -> dict[str, bool]:
    fd_baseline = _descriptor_snapshot(ops)
    child_baseline = _parse_children(_proc_bytes("/proc/thread-self/children", 65536, ops))
    root_owner = _RootOwner(ops)
    process_owner = _ProcessOwner(ops)
    control_parent = control_child = None
    transfer_parent = transfer_child = None
    socket_recovery: list[tuple[socket.socket, str]] = []
    leader: _ProcessLease | None = None
    inner: _ProcessLease | None = None
    primary: BaseException | None = None
    boundary: dict[str, object] | None = None
    namespace_authority: dict[str, bool] | None = None
    original_subreaper = ctypes.c_int()
    subreaper_changed = False
    try:
        read_result = ops.libc.prctl(
            _PR_GET_CHILD_SUBREAPER,
            ctypes.byref(original_subreaper),
            0,
            0,
            0,
        )
        _require(read_result == 0, "sandbox subreaper baseline", "subreaper-read")
        ops.prctl(_PR_SET_CHILD_SUBREAPER, 1)
        subreaper_changed = True
        root = root_owner.prepare()
        control_parent, control_child = ops.socketpair()
        socket_recovery.extend(((control_parent, "sandbox-control-parent"), (control_child, "sandbox-control-child")))
        transfer_parent, transfer_child = ops.socketpair()
        socket_recovery.extend(((transfer_parent, "sandbox-transfer-parent"), (transfer_child, "sandbox-transfer-child")))
        nonce = ops.nonce()
        pid, leader, gate = process_owner.spawn()
        if pid == 0:
            _close_socket(control_parent, ops, "sandbox-control-parent")
            _close_socket(transfer_parent, ops, "sandbox-transfer-parent")
            _require(gate is not None, "sandbox leader gate", "sandbox-register")
            _sandbox_leader(ops, root, nonce, control_child, transfer_child, gate)
        _require(leader is not None, "sandbox leader registration", "sandbox-register")
        _close_socket(control_child, ops, "sandbox-control-child")
        control_child = None
        _close_socket(transfer_child, ops, "sandbox-transfer-child")
        transfer_child = None
        process_owner.plan_setsid(leader)
        process_owner.release(leader)
        deadline = time.monotonic() + _SETUP_SECONDS
        _lifecycle_control_recv(control_parent, deadline, b"S:sandbox")
        process_owner.confirm_setsid(leader)
        _lifecycle_control_send(control_parent, b"C:sandbox")
        try:
            inner = process_owner.receive_descendant(
                transfer_parent,
                leader,
                nonce,
                1,
                deadline,
                "sandbox",
                "inner",
            )
        except BaseException as transfer_error:
            _settle_rejected_transfer(
                process_owner,
                leader,
                transfer_parent,
                control_parent,
                "sandbox",
                child_baseline,
                ops,
                transfer_error,
            )
            leader = None
            raise
        process_owner.stable_identity_census(leader)
        _lifecycle_control_send(transfer_parent, b"A")
        _deadline_ready(control_parent, deadline, "sandbox-inner-result")
        raw = control_parent.recv(65536, socket.MSG_DONTWAIT)
        packet = _strict_json(raw, False, 65536, "sandbox entered result")
        expected = {"event", "result", "version"}
        valid = type(packet) is dict and set(packet) == expected
        valid = valid and packet["event"] == "entered"
        valid = valid and packet["version"] == _RESULT_VERSION
        _require(valid, "sandbox entered packet", "sandbox-inner-result")
        boundary = packet["result"]
        _require(type(boundary) is dict and set(boundary) == {"boundary", "facts"}, "sandbox probe shape", "sandbox-shape")
        namespace_authority = _open_namespace_authority(inner, ops)
        mount_facts = _final_mount_check(inner.pid, ops)
        boundary["mount"] = mount_facts
        _lifecycle_control_send(control_parent, b"F:sandbox")
        _lifecycle_control_recv(control_parent, deadline, b"E:sandbox")
        _deadline_ready(inner.pidfd.fd, deadline, "sandbox-inner-reap")
        inner.reaped = True
        process_owner.stop(inner)
        inner = None
        leader_status = _wait_bounded(leader, deadline)
        _require(leader_status == 0, "sandbox leader exit", "sandbox-exit")
        process_owner.stop(leader)
        leader = None
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try:
        process_owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    for endpoint, purpose in socket_recovery:
        try:
            _close_socket(endpoint, ops, purpose)
        except BaseException as error:
            failures.append(error)
    try:
        root_owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    if subreaper_changed:
        try:
            ops.prctl(_PR_SET_CHILD_SUBREAPER, original_subreaper.value)
            observed_subreaper = ctypes.c_int(-1)
            read_result = ops.libc.prctl(
                _PR_GET_CHILD_SUBREAPER,
                ctypes.byref(observed_subreaper),
                0,
                0,
                0,
            )
            _require(read_result == 0, "sandbox subreaper readback", "subreaper-read")
            _require(observed_subreaper.value == original_subreaper.value, "sandbox subreaper restore", "subreaper-restore")
        except BaseException as error:
            failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    if primary is not None:
        raise primary
    _require(boundary is not None, "sandbox observations missing", "sandbox-result")
    _require(namespace_authority is not None, "sandbox namespace authority missing", "sandbox-result")
    facts = boundary["facts"]
    observed = boundary["boundary"]
    mount = boundary["mount"]
    capability = observed["capability_sets"]
    denials = observed["seccomp_denials"]
    capability_scalars_zero = not any(
        capability[name]
        for name in ("effective", "permitted", "inheritable")
    )
    capabilities_zero = capability_scalars_zero
    capabilities_zero = capabilities_zero and not any(capability["bounding"])
    capabilities_zero = capabilities_zero and not any(capability["ambient"])
    expected_denials = set(_DENIED_SYSCALLS) | {"prctl:set", "execveat:shape"}
    seccomp_denials_exact = set(denials) == expected_denials
    no_acquisition_route = seccomp_denials_exact
    no_acquisition_route = no_acquisition_route and all(
        value == errno.EPERM for value in denials.values()
    )
    descriptors_restored = _descriptor_snapshot(ops) == fd_baseline
    children_reaped = _parse_children(
        _proc_bytes("/proc/thread-self/children", 65536, ops),
    ) == child_baseline
    processes_retired = not process_owner.processes
    root_restored = root_owner.cleaned
    return {
        "user_namespace_exact": facts["user_namespace_exact"],
        "pid_namespace_exact": facts["pid_namespace_exact"],
        "mount_namespace_exact": facts["mount_namespace_exact"],
        "network_namespace_exact": facts["network_namespace_exact"],
        "namespace_ownership_exact": namespace_authority["namespace_ownership_exact"],
        "pid_one": facts["pid_one"],
        "capabilities_zero": capabilities_zero,
        "noroot_locked": observed["securebits"] == _SECBITS,
        "no_new_privs": observed["no_new_privs"] == 1,
        "seccomp_installed": observed["seccomp_installed"] is True,
        "seccomp_mode_exact": observed["seccomp_mode"] == _SECCOMP_MODE_FILTER,
        "seccomp_program_exact": observed["seccomp_program_sha256"] == _seccomp_digest(),
        "seccomp_denials_exact": seccomp_denials_exact,
        "no_acquisition_route": no_acquisition_route,
        "root_readonly_noexec": mount[0],
        "root_has_no_proc": mount[1],
        "host_paths_absent": mount[2],
        "checkout_absent": mount[3],
        "descriptors_restored": descriptors_restored,
        "children_reaped": children_reaped,
        "descendants_reaped": processes_retired,
        "mounts_restored": root_restored,
        "paths_restored": root_restored,
        "namespaces_released": processes_retired,
        "namespace_handles_released": processes_retired,
    }
def _launch_admitted_fixed_sandbox_qualification(admission: _SourceAdmission, sources: dict[str, bytes], ops: Any) -> SandboxQualificationResult:
    _consume_launcher_operation(admission, "sandbox")
    capsule = _encode_root_capsule(sources, admission)
    raw = _run_root_capsule_with_ops(ops, capsule)
    value = _strict_json(raw, True, _MAX_REPORT, "sandbox root result")
    return _decode_sandbox_result(value)
def _root_capsule_entry(raw: bytes, authority: dict[str, object]) -> int:
    _require(os.geteuid() == 0 and not os.environ and len(sys.argv) == 1, "root capsule envelope", "root-envelope")
    _require(_descriptor_snapshot() == (0, 1, 2), "root capsule descriptors", "root-descriptors")
    sources, header = _decode_root_capsule(raw, authority)
    observations = _sandbox_only_transaction(_SystemOps())
    result = SandboxQualificationResult(
        version="cogs.sandbox-qualification/v1",
        source_revision=header["revision"],
        source_set_sha256=header["source_set_sha256"],
        seccomp_program_sha256=_seccomp_digest(),
        **observations,
    )
    output = _canonical(_result_value(result), True)
    _require(os.write(1, output) == len(output), "root result write", "root-result-write")
    return 0
_LifecycleCaseObservation = make_dataclass("_LifecycleCaseObservation", [
    ("case", str),
    *((name, bool) for name in """
        pdeathsig_armed parent_handshake_exact death_exact starttime_revalidated
        session_owned process_group_owned credentialed_pidfd_transfer
        stable_descendant_census adoption_exact term_kill_bounded siginfo_exact all_reaped
    """.split()),
], frozen=True, namespace={"__module__": __name__})
def _deadline_ready(endpoint: object, deadline: float, code: str) -> None:
    remaining = deadline - time.monotonic()
    ready = remaining > 0 and bool(select.select([endpoint], [], [], remaining)[0])
    _require(ready, "process protocol deadline", code)
def _lifecycle_control_recv(endpoint: socket.socket, deadline: float, expected: bytes) -> None:
    _deadline_ready(endpoint, deadline, "lifecycle-deadline")
    observed = endpoint.recv(256, socket.MSG_DONTWAIT)
    if observed.startswith(b"Z:"):
        parts = observed.split(b":", 2)
        valid = len(parts) == 3
        valid = valid and re.fullmatch(rb"[a-z-]{1,32}", parts[1]) is not None
        valid = valid and re.fullmatch(rb"[A-Za-z0-9._-]{1,127}", parts[2]) is not None
        _require(valid, "lifecycle failure packet", "lifecycle-control")
        code = parts[2].decode("ascii")
        if code == "cleanup-uncertain":
            failure = RuntimeLauncherError("creator cleanup uncertain", code)
            raise RuntimeLauncherCleanupError(None, [failure])
        raise RuntimeLauncherError("creator transaction failed", code)
    _require(observed == expected, "lifecycle control packet", "lifecycle-control")
def _lifecycle_control_send(endpoint: socket.socket, value: bytes) -> None:
    written = endpoint.send(value, socket.MSG_DONTWAIT)
    _require(written == len(value), "lifecycle control send", "lifecycle-control")

def _creator_settlement_packet(endpoint: socket.socket, deadline: float, case: str) -> None:
    _deadline_ready(endpoint, deadline, "creator-settlement-deadline")
    observed = endpoint.recv(256, socket.MSG_DONTWAIT)
    parts = observed.split(b":", 2)
    valid = len(parts) == 3 and parts[0] == b"Z"
    valid = valid and parts[1] == case.encode("ascii")
    valid = valid and re.fullmatch(rb"[A-Za-z0-9._-]{1,127}", parts[2]) is not None
    _require(valid, "creator settlement packet", "creator-settlement")
    _require(parts[2] != b"cleanup-uncertain", "creator cleanup uncertain", "cleanup-uncertain")

def _settle_rejected_transfer(
    owner: _ProcessOwner,
    leader: _ProcessLease,
    transfer: socket.socket,
    control: socket.socket,
    case: str,
    child_baseline: tuple[int, ...],
    ops: Any,
    primary: BaseException,
) -> None:
    failures: list[BaseException] = []
    leader_dead = bool(select.select([leader.pidfd.fd], [], [], 0)[0])
    settlement_deadline = time.monotonic() + _SETUP_SECONDS
    if not leader_dead:
        try:
            _lifecycle_control_send(transfer, b"N")
        except BaseException as error:
            failures.append(error)
        try:
            _creator_settlement_packet(control, settlement_deadline, case)
        except BaseException as error:
            failures.append(error)
    # Cooperative rejection gives the creator the first opportunity to close
    # the registration gate and exactly reap its child.  Regardless of packet
    # or deadline failure, the surviving owner then terminates and waitpid-
    # reaps the creator before looking for children exposed by reparenting.
    try:
        owner.stop(leader, primary)
    except BaseException as error:
        failures.append(error)
    try:
        _adopt_unregistered_children(owner, child_baseline, ops)
        for lease in tuple(owner.processes):
            if lease is not leader:
                owner.stop(lease, primary)
    except BaseException as error:
        failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from primary

def _lifecycle_descendant(
    ops: Any,
    leader_pid: int,
    case: str,
    registration_read: _FdLease,
    release_read: _FdLease,
    status_write: _FdLease,
) -> NoReturn:
    try:
        registered = ops.read(registration_read.fd, 1)
        _require(
            registered == b"G",
            "descendant registration release",
            "descendant-registration-release",
        )
        registration_read.close(ops)
        parent_before = os.getppid()
        _require(parent_before == leader_pid, "descendant initial parent", "descendant-parent")
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        parent_after = os.getppid()
        _require(parent_after == parent_before, "descendant parent race", "descendant-parent")
        if case == "term-kill":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        armed = b"A:" + case.encode()
        written = ops.write(status_write.fd, armed)
        _require(written == len(armed), "descendant armed status", "pdeath-status")
        if case == "before-release":
            while True:
                signal.pause()
        released = ops.read(release_read.fd, 1)
        _require(released == b"G", "descendant release", "descendant-release")
        ready = b"R:" + case.encode()
        written = ops.write(status_write.fd, ready)
        _require(written == len(ready), "descendant release status", "descendant-release")
        while True:
            signal.pause()
    except BaseException:
        os._exit(125)
def _lifecycle_transfer_packet(
    descendant: _ProcessLease,
    leader_pid: int,
    nonce: bytes,
    case: str,
    role: str = "descendant",
) -> bytes:
    transfer = hashlib.sha256(nonce + _canonical([case, role, 1])).hexdigest()
    return _canonical({
        "case": case,
        "executable": list(descendant.executable),
        "nonce": nonce.hex(),
        "parent": leader_pid,
        "pid": descendant.pid,
        "process_group": descendant.process_group,
        "role": role,
        "sequence": 1,
        "session": descendant.session,
        "start_time": descendant.start_time,
        "transfer": transfer,
        "version": "cogs.process-transfer/v1",
    })

def _lifecycle_leader(
    ops: Any,
    case: str,
    nonce: bytes,
    control: socket.socket,
    transfer: socket.socket,
    gate: _FdLease,
) -> NoReturn:
    descendant: _ProcessLease | None = None
    local_owner = _ProcessOwner(ops)
    local_leases: list[_FdLease] = []
    primary: BaseException | None = None
    try:
        released = ops.read(gate.fd, 1)
        _require(released == b"G", "lifecycle leader release", "lifecycle-release")
        gate.close(ops)
        ops.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        _lifecycle_control_send(control, b"S:" + case.encode())
        _lifecycle_control_recv(control, time.monotonic() + _SETUP_SECONDS, b"C:" + case.encode())
        release_pair = tuple(
            _FdLease(fd, "lifecycle-descendant-release")
            for fd in os.pipe2(os.O_CLOEXEC)
        )
        status_pair = tuple(
            _FdLease(fd, "lifecycle-descendant-status")
            for fd in os.pipe2(os.O_CLOEXEC)
        )
        local_leases.extend((*release_pair, *status_pair))
        release_read, release_write = release_pair
        status_read, status_write = status_pair
        pid, descendant, registration_gate = local_owner.spawn()
        if pid == 0:
            transfer.close()
            control.close()
            release_write.close(ops)
            status_read.close(ops)
            _require(
                registration_gate is not None,
                "descendant registration gate",
                "descendant-registration",
            )
            _lifecycle_descendant(
                ops,
                os.getppid(),
                case,
                registration_gate,
                release_read,
                status_write,
            )
        _require(descendant is not None, "descendant preregistration", "descendant-registration")
        release_read.close(ops)
        status_write.close(ops)
        packet = _lifecycle_transfer_packet(descendant, os.getpid(), nonce, case)
        rights = array("i", (descendant.pidfd.fd,))
        ancillary = ((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),)
        written = transfer.sendmsg((packet,), ancillary, socket.MSG_DONTWAIT)
        _require(written == len(packet), "descendant transfer send", "process-transfer-send")
        transfer.shutdown(socket.SHUT_WR)
        _lifecycle_control_recv(transfer, time.monotonic() + _SETUP_SECONDS, b"A")
        local_owner.release(descendant)
        descendant.pidfd.close(ops)
        descendant.pidfd = None
        local_owner.processes.remove(descendant)
        _deadline_ready(
            status_read.fd,
            time.monotonic() + _SETUP_SECONDS,
            "pdeath-status",
        )
        armed = ops.read(status_read.fd, 64)
        _require(
            armed == b"A:" + case.encode(),
            "descendant armed readback",
            "pdeath-status",
        )
        _lifecycle_control_send(control, b"T:" + case.encode())
        if case != "before-release":
            written = ops.write(release_write.fd, b"G")
            _require(written == 1, "descendant release write", "descendant-release")
            release_write.close(ops)
            _deadline_ready(status_read.fd, time.monotonic() + _SETUP_SECONDS, "descendant-release")
            ready = ops.read(status_read.fd, 64)
            _require(ready == b"R:" + case.encode(), "descendant release readback", "descendant-release")
            _lifecycle_control_send(control, b"R:" + case.encode())
        _lifecycle_control_recv(control, time.monotonic() + _SETUP_SECONDS, b"X:" + case.encode())
        os._exit(0)
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try:
        local_owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    try:
        _close_leases(ops, local_leases, primary)
    except BaseException as error:
        failures.append(error)
    code = "cleanup-uncertain" if failures else getattr(
        primary,
        "code",
        "launcher-rejected",
    )
    try:
        _lifecycle_control_send(
            control,
            b"Z:" + case.encode() + b":" + code.encode("ascii"),
        )
    except BaseException:
        pass
    os._exit(125)

def _stable_adoption(descendant: _ProcessLease, ops: Any) -> bool:
    path = "/proc/thread-self/children"
    first = _parse_children(_proc_bytes(path, 65536, ops))
    start = _start_time(descendant.pid, ops)
    second = _parse_children(_proc_bytes(path, 65536, ops))
    identity = start == descendant.start_time
    return first == second and descendant.pid in first and identity

def _exact_signal_reap(descendant: _ProcessLease, deadline: float) -> tuple[bool, bool]:
    _deadline_ready(descendant.pidfd.fd, deadline, "process-death-deadline")
    options = os.WEXITED | os.WNOHANG | os.WNOWAIT
    info = os.waitid(os.P_PIDFD, descendant.pidfd.fd, options)
    siginfo_exact = info is not None
    siginfo_exact = siginfo_exact and info.si_pid == descendant.pid
    siginfo_exact = siginfo_exact and info.si_uid == descendant.expected_uid
    siginfo_exact = siginfo_exact and info.si_code == os.CLD_KILLED
    siginfo_exact = siginfo_exact and info.si_status == signal.SIGKILL
    observed, status = os.waitpid(descendant.pid, os.WNOHANG)
    wait_exact = observed == descendant.pid
    wait_exact = wait_exact and os.WIFSIGNALED(status)
    wait_exact = wait_exact and os.WTERMSIG(status) == signal.SIGKILL
    _require(siginfo_exact and wait_exact, "descendant exact signal reap", "process-reap")
    descendant.reaped = True
    return siginfo_exact, wait_exact

def _run_lifecycle_case(
    case: str,
    ops: Any,
    owner: _ProcessOwner,
) -> _LifecycleCaseObservation:
    child_baseline = _parse_children(
        _proc_bytes("/proc/thread-self/children", 65536, ops),
    )
    control_parent = control_leader = None
    transfer_parent = transfer_leader = None
    socket_recovery: list[tuple[socket.socket, str]] = []
    leader: _ProcessLease | None = None
    descendant: _ProcessLease | None = None
    primary: BaseException | None = None
    result: _LifecycleCaseObservation | None = None
    try:
        control_parent, control_leader = ops.socketpair()
        socket_recovery.extend(((control_parent, "lifecycle-control-parent"), (control_leader, "lifecycle-control-leader")))
        transfer_parent, transfer_leader = ops.socketpair()
        socket_recovery.extend(((transfer_parent, "lifecycle-transfer-parent"), (transfer_leader, "lifecycle-transfer-leader")))
        nonce = ops.nonce()
        pid, leader, gate = owner.spawn()
        if pid == 0:
            _close_socket(control_parent, ops, "lifecycle-control-parent")
            _close_socket(transfer_parent, ops, "lifecycle-transfer-parent")
            _require(gate is not None, "lifecycle leader gate", "lifecycle-release")
            _lifecycle_leader(ops, case, nonce, control_leader, transfer_leader, gate)
        _require(leader is not None, "lifecycle leader registration", "lifecycle-register")
        _close_socket(control_leader, ops, "lifecycle-control-leader")
        control_leader = None
        _close_socket(transfer_leader, ops, "lifecycle-transfer-leader")
        transfer_leader = None
        owner.plan_setsid(leader)
        owner.release(leader)
        deadline = time.monotonic() + _SETUP_SECONDS
        _lifecycle_control_recv(control_parent, deadline, b"S:" + case.encode())
        owner.confirm_setsid(leader)
        second_gate_exact = leader.identity_phase == "POST_SETSID"
        _lifecycle_control_send(control_parent, b"C:" + case.encode())
        try:
            descendant = owner.receive_descendant(
                transfer_parent,
                leader,
                nonce,
                1,
                deadline,
                case,
                "descendant",
            )
        except BaseException as transfer_error:
            if isinstance(transfer_parent, socket.socket):
                _settle_rejected_transfer(
                    owner,
                    leader,
                    transfer_parent,
                    control_parent,
                    case,
                    child_baseline,
                    ops,
                    transfer_error,
                )
                leader = None
            raise
        census = owner.stable_identity_census(leader)
        transfer_id = hashlib.sha256(nonce + _canonical([case, "descendant", 1])).hexdigest()
        transfer_exact = transfer_id in owner.transfers and descendant in leader.descendants
        _lifecycle_control_send(transfer_parent, b"A")
        _lifecycle_control_recv(control_parent, deadline, b"T:" + case.encode())
        pdeath_armed = transfer_exact
        released = case != "before-release"
        if released:
            _lifecycle_control_recv(control_parent, deadline, b"R:" + case.encode())
        survived_term = False
        if case == "term-kill":
            _require(_process_matches(descendant), "descendant identity before TERM", "process-signal-identity")
            signal.pidfd_send_signal(descendant.pidfd.fd, signal.SIGTERM)
            term_deadline = time.monotonic() + _TERM_SECONDS
            while time.monotonic() < term_deadline:
                if select.select([descendant.pidfd.fd], [], [], 0)[0]:
                    break
                time.sleep(0.001)
            survived_term = not bool(select.select([descendant.pidfd.fd], [], [], 0)[0])
            _require(survived_term, "descendant did not survive TERM", "process-term")
            _require(_process_matches(descendant), "descendant identity before KILL", "process-signal-identity")
            signal.pidfd_send_signal(descendant.pidfd.fd, signal.SIGKILL)
        session_owned = leader.identity_phase == "POST_SETSID" and leader.session == leader.pid
        group_owned = leader.process_group == leader.pid
        _lifecycle_control_send(control_parent, b"X:" + case.encode())
        deadline = time.monotonic() + _SETUP_SECONDS
        leader_status = _wait_bounded(leader, deadline)
        _require(leader_status == 0, "lifecycle leader exit", "lifecycle-exit")
        owner.stop(leader)
        leader = None
        adoption = _stable_adoption(descendant, ops)
        _require(adoption, "descendant stable adoption", "process-adoption")
        descendant.waitable = True
        siginfo_exact, wait_exact = _exact_signal_reap(descendant, deadline)
        owner.stop(descendant)
        descendant = None
        result = _LifecycleCaseObservation(
            case=case,
            pdeathsig_armed=pdeath_armed,
            parent_handshake_exact=second_gate_exact,
            death_exact=siginfo_exact and wait_exact,
            starttime_revalidated=adoption,
            session_owned=session_owned,
            process_group_owned=group_owned,
            credentialed_pidfd_transfer=transfer_exact,
            stable_descendant_census=len(census) == 1,
            adoption_exact=adoption,
            term_kill_bounded=case == "term-kill" and survived_term,
            siginfo_exact=siginfo_exact,
            all_reaped=not owner.processes,
        )
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try:
        owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    for endpoint, purpose in socket_recovery:
        try:
            _close_socket(endpoint, ops, purpose)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    if primary is not None:
        raise primary
    _require(result is not None, "lifecycle case result", "lifecycle-result")
    return result

def _qualify_admitted_fixed_process_lifecycle(admission: _SourceAdmission, ops: Any) -> LifecycleQualificationResult:
    _consume_launcher_operation(admission, "lifecycle")
    baseline = _descriptor_snapshot(ops)
    children = _parse_children(_proc_bytes("/proc/thread-self/children", 65536, ops))
    owner = _ProcessOwner(ops)
    original_subreaper = ctypes.c_int()
    observed_subreaper = ctypes.c_int(-1)
    primary: BaseException | None = None
    cases: tuple[_LifecycleCaseObservation, ...] = ()
    restored = False
    read_result = ops.libc.prctl(
        _PR_GET_CHILD_SUBREAPER,
        ctypes.byref(original_subreaper),
        0,
        0,
        0,
    )
    _require(read_result == 0, "subreaper baseline", "subreaper-read")
    try:
        ops.prctl(_PR_SET_CHILD_SUBREAPER, 1)
        cases = tuple(
            _run_lifecycle_case(case, ops, owner)
            for case in ("before-release", "after-release", "term-kill")
        )
    except BaseException as error:
        primary = error
    failures: list[BaseException] = []
    try:
        owner.cleanup(primary)
    except BaseException as error:
        failures.append(error)
    try:
        ops.prctl(_PR_SET_CHILD_SUBREAPER, original_subreaper.value)
        read_result = ops.libc.prctl(
            _PR_GET_CHILD_SUBREAPER,
            ctypes.byref(observed_subreaper),
            0,
            0,
            0,
        )
        _require(read_result == 0, "subreaper restoration read", "subreaper-read")
        restored = observed_subreaper.value == original_subreaper.value
        _require(restored, "subreaper restoration", "subreaper-restore")
    except BaseException as error:
        failures.append(error)
    try:
        descriptors_exact = _descriptor_snapshot(ops) == baseline
        children_exact = _parse_children(
            _proc_bytes("/proc/thread-self/children", 65536, ops),
        ) == children
        _require(descriptors_exact and children_exact, "lifecycle baseline restoration", "lifecycle-baseline")
    except BaseException as error:
        failures.append(error)
        descriptors_exact = False
        children_exact = False
    if failures:
        raise RuntimeLauncherCleanupError(primary, failures) from (primary or failures[0])
    if primary is not None:
        raise primary
    _require(len(cases) == 3, "lifecycle case cardinality", "lifecycle-result")
    before, after, term = cases
    pdeathsig_armed = before.pdeathsig_armed and after.pdeathsig_armed
    parent_handshake_exact = all(item.parent_handshake_exact for item in cases)
    before_release_death = before.death_exact and before.case == "before-release"
    after_release_death = after.death_exact and after.case == "after-release"
    starttime_revalidated = all(item.starttime_revalidated for item in cases)
    session_owned = all(item.session_owned for item in cases)
    process_group_owned = all(item.process_group_owned for item in cases)
    credentialed_transfer = all(item.credentialed_pidfd_transfer for item in cases)
    stable_census = all(item.stable_descendant_census for item in cases)
    adoption_exact = all(item.adoption_exact for item in cases)
    term_kill_bounded = term.term_kill_bounded and term.case == "term-kill"
    siginfo_exact = all(item.siginfo_exact for item in cases)
    all_reaped = all(item.all_reaped for item in cases) and children_exact
    return LifecycleQualificationResult(
        version="cogs.runtime-lifecycle-qualification/v1",
        source_revision=admission.revision,
        source_set_sha256=admission.source_set_sha256,
        pdeathsig_armed=pdeathsig_armed,
        parent_handshake_exact=parent_handshake_exact,
        before_release_death=before_release_death,
        after_release_death=after_release_death,
        starttime_revalidated=starttime_revalidated,
        session_owned=session_owned,
        process_group_owned=process_group_owned,
        credentialed_pidfd_transfer=credentialed_transfer,
        stable_descendant_census=stable_census,
        adoption_exact=adoption_exact,
        term_kill_bounded=term_kill_bounded,
        siginfo_exact=siginfo_exact,
        all_reaped=all_reaped,
        subreaper_restored=restored,
        descriptors_restored=descriptors_exact,
    )
def _bootstrap_with_ops(ops: _SystemOps) -> int:
    _platform_gate()
    # With an empty execve environment, CPython 3.11+ may still synthesize
    # LC_CTYPE while coercing the C locale. Normalize only that exact internal
    # state; the tracked caller structurally fixes execve's environment to {}.
    if dict(os.environ) == {"LC_CTYPE": "C.UTF-8"}: os.environ.clear()
    if len(sys.argv) != 1 or os.environ or not sys.flags.isolated or not sys.flags.dont_write_bytecode: raise RuntimeLauncherError("fixed bootstrap process envelope")
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
    source_before = os.fstat(4)
    raw = bytearray()
    while len(raw) <= _MAX_ADMISSION:
        part = os.read(3, _MAX_ADMISSION + 1 - len(raw))
        if not part: break
        raw += part
    admission = _strict_json(bytes(raw), True, _MAX_ADMISSION, "source admission")
    expected = {"bootstrap_sha256", "client_sha256", "revision", "source_set_sha256", "version"}
    mode = _ADMISSION_MODES.get(admission.get("version")) if type(admission) is dict else None
    _require(type(admission) is dict and set(admission) == expected and mode is not None, "source admission shape")
    _require(_sha(admission["bootstrap_sha256"]) and _sha(admission["client_sha256"]) and _sha(admission["source_set_sha256"]), "source admission digest")
    revision = admission["revision"]
    valid_revision = type(revision) is str and len(revision) == 40 and all(character in "0123456789abcdef" for character in revision)
    _require(valid_revision, "source admission revision")
    sources = _authenticate_sources(4, admission)
    source_after = os.fstat(4)
    retained = _stat_identity(source_after) == _stat_identity(source_before)
    _require(retained, "held source descriptor generation", "held-source-generation")
    _close_leases(ops, [
        _FdLease(3, "admission-input"),
        _FdLease(4, "held-source-capsule"),
    ])
    __import__("platform")
    sys.path[:] = []
    closure_module = None if mode in ("lifecycle", "sandbox") else _load_private_closure(sources, admission["source_set_sha256"])
    issuer = _BOOTSTRAP_OPERATION_TOKEN if mode in ("lifecycle", "sandbox") else None
    source_admission = _SourceAdmission(revision, admission["bootstrap_sha256"], admission["source_set_sha256"], sources[_SCHEMA_PATH], "", 0, None, issuer, 0, 0, 0, mode)
    if mode == "mapping":
        entry = getattr(closure_module, "_qualify_admitted_fixed_python_mapping", None)
        _require(callable(entry), "mapping owner entry", "operation-entry")
        result = entry(source_admission)
    elif mode == "descriptor":
        entry = getattr(closure_module, "_qualify_admitted_fixed_descriptor_primitives", None)
        _require(callable(entry), "descriptor owner entry", "operation-entry")
        result = entry(source_admission)
    elif mode == "compression":
        result = _launch_admitted_fixed_compression_qualification(source_admission, closure_module, ops)
    elif mode == "runtime":
        result = _launch_admitted_fixed_runtime_qualification(source_admission, closure_module, ops)
    elif mode == "lifecycle":
        result = _qualify_admitted_fixed_process_lifecycle(source_admission, ops)
    else:
        result = _launch_admitted_fixed_sandbox_qualification(source_admission, sources, ops)
    output = _canonical(_result_value(result), True)
    offset = 0
    while offset < len(output):
        written = os.write(1, output[offset:])
        if written <= 0: raise RuntimeLauncherError("result write failed")
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
    except RuntimeLauncherError as error:
        code = error.code if type(error.code) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", error.code) else "invalid-code"
        if isinstance(error, RuntimeLauncherCleanupError):
            nested: BaseException = error
            for _depth in range(8):
                failures = getattr(nested, "failures", ())
                if not failures:
                    break
                nested = failures[0]
            stage = getattr(nested, "code", type(nested).__name__)
            safe_stage = re.sub(r"[^A-Za-z0-9_.-]", "-", stage) if type(stage) is str else "invalid"
            code = f"cleanup-uncertain-{safe_stage}"[:40]
        digest = hashlib.sha256(str(error).encode("utf-8", "backslashreplace")).hexdigest()[:16]
        os.write(2, f"runtime-launcher-{code}-{digest}\n".encode())
        raise SystemExit(1)
    except Exception as error:
        label = re.sub(r"[^A-Za-z0-9_.-]", "-", type(error).__name__)[:32]
        if label == "RuntimeClosureError":
            digest = hashlib.sha256(str(error).encode("utf-8", "backslashreplace")).hexdigest()[:16]
            os.write(2, f"runtime-launcher-closure-{digest}\n".encode())
        else:
            os.write(2, f"runtime-launcher-exception-{label}-{getattr(error, 'errno', 0)}\n".encode())
        raise SystemExit(1)
