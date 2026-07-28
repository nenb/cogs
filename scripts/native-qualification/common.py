#!/usr/bin/python3
from __future__ import annotations
import ctypes, fcntl, hashlib, json, os, platform, re, resource, socket, stat, struct, subprocess, sys, types
from dataclasses import dataclass, fields
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Mapping
VERSION, AUTHORITY = "cogs.native-qualification/v1alpha1", "exact-run-native-qualification"
ROOT = Path(__file__).resolve().parents[2]
WORKFLOW, COMMON = ROOT / ".github/workflows/ci.yml", ROOT / "scripts/native-qualification/common.py"
SCHEMA = ROOT / "schemas/native-qualification-report-v1alpha1.json"
REPORT_LIMIT, OBJECT_LIMIT = 32_768, 134_217_728
MARKER_SHA256 = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8"
CLEANUP_KEYS = ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")
DRIVERS = dict(zip(("A", "B", "C", "D", "E", "integration"), ("job-a-runtime-mappings.py", "job-b-compression.py",
    "job-c-descriptors.py", "job-d-process-lifecycle.py", "job-e-sandbox.py", "thin-integration.py")))
JOB_IDS = {**{job: f"native-qualification-{job.lower()}" for job in "ABCDE"}, "integration": "native-closure-integration"}
CHECK_IDS = {
    "A": tuple("elf_real python_closure_exact map_files_trusted mapped_closure_equal mapping_stable helper_reaped cleanup_restored".split()),
    "B": tuple(("gzip_source_exact gzip_sealed_exec zstd_source_exact zstd_sealed_exec decompression_deterministic "
                "network_denied children_exact cleanup_restored").split()),
    "C": tuple(("nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact "
                "inheritance_exact limit_restored cleanup_restored").split()),
    "D": tuple(("pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated "
                "session_owned process_group_owned term_kill_bounded all_reaped cleanup_restored").split()),
    "E": tuple(("mount_view_exact checkout_read_only user_namespace_exact pid_namespace_exact mount_namespace_exact "
                "network_namespace_exact pid_one capabilities_zero noroot_locked nnp_set seccomp_socket_denied "
                "seccomp_io_uring_denied no_acquisition_route checkout_unchanged all_reaped mounts_restored cleanup_restored").split()),
    "integration": tuple("closure_prepared handoff_exact gzip_deterministic zstd_deterministic marker_exact no_linked_evidence cleanup_restored".split()),
}
COMMON_CHECKS = {job: ({"cleanup_restored", "checkout_unchanged"} if job == "E" else {"cleanup_restored"}) for job in DRIVERS}
PRODUCTION_CHECK_IDS = {job: tuple(name for name in checks if name not in COMMON_CHECKS[job]) for job, checks in CHECK_IDS.items()}
ENV_KEYS = frozenset(("LC_ALL PYTHONDONTWRITEBYTECODE PYTHONHASHSEED NQ_EVENT_NAME NQ_REPOSITORY NQ_HEAD_REPOSITORY "
                      "NQ_HEAD_SHA NQ_ENVELOPE_SHA NQ_WORKFLOW_SHA NQ_MERGE_SHA NQ_BASE_SHA NQ_JOB_ID NQ_RUN_ID "
                      "NQ_RUN_ATTEMPT NQ_PR_NUMBER NQ_RUNNER_VERSION").split())
ELIGIBILITY_KEYS = frozenset("LC_ALL PYTHONCOERCECLOCALE EVENT_NAME RUN_ATTEMPT REPOSITORY HEAD_REPOSITORY HEAD_SHA MERGE_SHA BASE_SHA PR_NUMBER".split())
RESULT_JOBS = ("QUALITY", "ELIGIBILITY", "A", "B", "C", "D", "E", "INTEGRATION")
FINAL_KEYS = frozenset(["LC_ALL", "PYTHONCOERCECLOCALE"] + [f"{name}_RESULT" for name in RESULT_JOBS]
                       + [f"{name}_{phase}" for name in RESULT_JOBS[2:] for phase in ("UPLOAD", "CLEANUP")])
HEX40, HEX64 = re.compile(r"[0-9a-f]{40}\Z"), re.compile(r"[0-9a-f]{64}\Z")
SAFE, REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z"), re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
class QualificationError(RuntimeError): pass
def _require(condition: bool, message: str) -> None:
    if not condition: raise QualificationError(message)
def _integer(value: str, name: str) -> int:
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None, name); return int(value)
def _generation(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_mode, value.st_uid, value.st_gid, value.st_dev, value.st_ino, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
def _sha256(path: Path) -> str:
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= 2_000_000, "source object")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _require(_generation(before) == _generation(path.lstat()), "source generation")
    return digest
def _canonical(value: object, newline: bool = False) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + (b"\n" if newline else b"")
@dataclass(frozen=True)
class WorkflowContext:
    job: str; repository: str; head_repository: str; head_sha: str
    envelope_sha: str; workflow_sha: str; merge_sha: str; base_sha: str; job_id: str
    run_id: int; run_attempt: int; pull_request_number: int; runner_version: str; kernel_release: str; architecture: str
    workflow_blob_sha256: str; driver_blob_sha256: str; common_blob_sha256: str
    @classmethod
    def from_environ(cls, expected_job: str, driver_file: str | Path) -> "WorkflowContext":
        environment = dict(os.environ); _require(expected_job in DRIVERS and set(environment) == ENV_KEYS, "fixed environment")
        _require(environment["LC_ALL"] == "C" and environment["PYTHONDONTWRITEBYTECODE"] == "1", "runtime environment")
        _require(environment["PYTHONHASHSEED"] == "0" and environment["NQ_EVENT_NAME"] == "pull_request", "event environment")
        expected_driver = COMMON.parent / DRIVERS[expected_job]
        _require(Path(driver_file).absolute() == expected_driver and expected_driver.is_file(), "fixed driver")
        hashes = [environment[name] for name in ("NQ_HEAD_SHA", "NQ_ENVELOPE_SHA", "NQ_WORKFLOW_SHA", "NQ_MERGE_SHA", "NQ_BASE_SHA")]
        _require(all(HEX40.fullmatch(value) for value in hashes), "source identity")
        _require(environment["NQ_WORKFLOW_SHA"] in {environment["NQ_HEAD_SHA"], environment["NQ_MERGE_SHA"]}, "workflow source")
        repository = environment["NQ_REPOSITORY"]
        _require(REPOSITORY.fullmatch(repository) is not None and environment["NQ_HEAD_REPOSITORY"] == repository, "same repository")
        _require(environment["NQ_JOB_ID"] == JOB_IDS[expected_job] and SAFE.fullmatch(environment["NQ_RUNNER_VERSION"]) is not None, "workflow job")
        attempt = _integer(environment["NQ_RUN_ATTEMPT"], "run attempt"); _require(attempt == 1, "first attempt")
        kernel, architecture = platform.release(), platform.machine()
        _require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.+]*", kernel) is not None and architecture == "x86_64", "runner platform")
        return cls(
            expected_job, repository, repository, *hashes, environment["NQ_JOB_ID"],
            _integer(environment["NQ_RUN_ID"], "run id"), attempt, _integer(environment["NQ_PR_NUMBER"], "pull request"),
            environment["NQ_RUNNER_VERSION"], kernel, architecture, _sha256(WORKFLOW), _sha256(expected_driver), _sha256(COMMON),
        )
def _context_value(context: WorkflowContext) -> dict[str, object]:
    source = {"checkout_sha": context.head_sha, "driver_blob_sha256": context.driver_blob_sha256,
              "head_sha": context.head_sha, "common_blob_sha256": context.common_blob_sha256}
    envelope = {"base_sha": context.base_sha, "event_merge_sha": context.merge_sha, "event_name": "pull_request",
                "github_sha": context.envelope_sha, "head_repository": context.head_repository,
                "pull_request_number": context.pull_request_number, "repository": context.repository,
                "run_attempt": context.run_attempt, "run_id": context.run_id}
    workflow = {"blob_sha256": context.workflow_blob_sha256, "job_id": context.job_id, "path": ".github/workflows/ci.yml", "workflow_sha": context.workflow_sha}
    runner = {"architecture": context.architecture, "image": "ubuntu-24.04", "image_version": context.runner_version, "kernel_release": context.kernel_release}
    return {"source": source, "envelope": envelope, "workflow": workflow, "runner": runner}
def evaluate_eligibility(environment: Mapping[str, str]) -> None:
    _require(set(environment) == ELIGIBILITY_KEYS and environment["LC_ALL"] == "C" and environment["PYTHONCOERCECLOCALE"] == "0", "eligibility environment")
    _require(environment["EVENT_NAME"] == "pull_request" and environment["RUN_ATTEMPT"] == "1", "eligible event")
    repository = environment["REPOSITORY"]
    _require(REPOSITORY.fullmatch(repository) is not None and environment["HEAD_REPOSITORY"] == repository, "eligible repository")
    _require(all(HEX40.fullmatch(environment[name]) for name in ("HEAD_SHA", "MERGE_SHA", "BASE_SHA")), "eligible source")
    _integer(environment["PR_NUMBER"], "eligible pull request")
def require_final_results(environment: Mapping[str, str]) -> None:
    _require(set(environment) == FINAL_KEYS and environment["LC_ALL"] == "C" and environment["PYTHONCOERCECLOCALE"] == "0", "final-result environment")
    _require(all(value == "success" for key, value in environment.items()
                 if key.endswith(("_RESULT", "_UPLOAD", "_CLEANUP"))), "native transaction did not succeed")
class FdState(Enum):
    OWNED, TRANSFERRED, CLOSED, CLOSE_UNCERTAIN = auto(), auto(), auto(), auto()
class FdRegistry:
    def __init__(self, closer: Callable[[int], None] = os.close):
        self._closer, self._allocation_blocked = closer, False
        self._leases, self._numbers, self._retired = [], set(), set()
    def adopt(self, number: int, purpose: str) -> "FdLease":
        _require(type(number) is int and number >= 0 and not self._allocation_blocked, "fd allocation after uncertainty")
        _require(number not in self._numbers and number not in self._retired, "fd reuse")
        lease = FdLease(number, purpose, self)
        self._numbers.add(number); self._leases.append(lease)
        return lease
    def open(self, purpose: str, opener: Callable[[], int]) -> "FdLease":
        _require(not self._allocation_blocked, "fd allocation after uncertainty")
        return self.adopt(opener(), purpose)
    def _close(self, lease: "FdLease") -> None:
        if lease.state is FdState.CLOSED: return
        if lease.state is FdState.CLOSE_UNCERTAIN:
            assert lease.close_error is not None; raise lease.close_error
        try:
            self._closer(lease.number)
        except BaseException as error:
            lease.state = FdState.CLOSE_UNCERTAIN
            lease.close_error = error
            self._retired.add(lease.number)
            self._allocation_blocked = True
            raise
        lease.state = FdState.CLOSED
        self._numbers.remove(lease.number)
    def close_reverse(self, primary: BaseException | None = None, leases: list["FdLease"] | None = None) -> None:
        failures = [] if primary is None else [primary]
        for lease in reversed(self._leases if leases is None else leases):
            if lease.state is FdState.OWNED:
                try:
                    lease.close()
                except BaseException as error:
                    failures.append(error)
        if failures:
            raise ExceptionGroup("fd cleanup", failures)
    @property
    def uncertain(self) -> bool: return self._allocation_blocked
@dataclass
class FdLease:
    number: int; purpose: str; registry: FdRegistry
    state: FdState = FdState.OWNED; close_error: BaseException | None = None
    def close(self) -> None: self.registry._close(self)
_SYS_GETDENTS64, _GETDENTS_CHUNK = 217, 32_768
_GETDENTS_CALLS, _GETDENTS_BYTES, _GETDENTS_ENTRIES = 32, 1_048_576, 16_384
def _getdents(descriptor: int) -> bytes:
    buffer = ctypes.create_string_buffer(_GETDENTS_CHUNK)
    libc = ctypes.CDLL(None, use_errno=True)
    count = libc.syscall(_SYS_GETDENTS64, descriptor, ctypes.byref(buffer), _GETDENTS_CHUNK)
    if count < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return buffer.raw[:count]
def _parse_dirents(raw: bytes, numeric: bool) -> list[str]:
    names: list[str] = []; offset = 0
    while offset < len(raw):
        _require(len(raw) - offset >= 19, "dirent header")
        record_length = int.from_bytes(raw[offset + 16:offset + 18], sys.byteorder)
        _require(record_length >= 24 and record_length % 8 == 0 and offset + record_length <= len(raw), "dirent record")
        name_field = raw[offset + 19:offset + record_length]
        terminator = name_field.find(b"\0")
        _require(terminator >= 0 and not any(name_field[terminator + 1:]), "dirent name")
        name_bytes = name_field[:terminator]
        _require(name_bytes and b"/" not in name_bytes, "dirent spelling")
        name = name_bytes.decode("ascii")
        if name not in (".", ".."):
            if numeric:
                _require(re.fullmatch(r"0|[1-9][0-9]*", name) is not None and int(name) <= 2_147_483_647, "fd name")
            names.append(name)
        offset += record_length
    _require(offset == len(raw), "dirent framing")
    return names
def _enumerate_directory(descriptor: int, numeric: bool) -> tuple[str, ...]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    names: list[str] = []; total = 0
    for calls in range(_GETDENTS_CALLS + 1):
        raw = _getdents(descriptor)
        if not raw:
            _require(calls <= _GETDENTS_CALLS, "getdents call bound")
            _require(len(names) <= _GETDENTS_ENTRIES and len(names) == len(set(names)), "directory entries")
            return tuple(names)
        _require(calls < _GETDENTS_CALLS, "getdents EOF bound")
        total += len(raw); _require(total <= _GETDENTS_BYTES, "getdents byte bound")
        names.extend(_parse_dirents(raw, numeric))
        _require(len(names) <= _GETDENTS_ENTRIES, "getdents entry bound")
    raise QualificationError("getdents64 incomplete")
class SystemCommonOps:
    def __init__(self, fds: FdRegistry):
        self.fds, self.source_set_sha256 = fds, ""
    def _launcher(self, root: FdLease) -> types.ModuleType:
        path = "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
        held = self.fds.open("held-production-launcher", lambda: os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root.number))
        try:
            before = os.fstat(held.number)
            raw = os.pread(held.number, before.st_size, 0)
            _require(0 < len(raw) == before.st_size <= 2_000_000 and _generation(os.fstat(held.number)) == _generation(before), "held launcher generation")
            digest = hashlib.sha256(raw).hexdigest()
            module = types.ModuleType(f"_cogs_held_launcher_{digest}")
            module.__file__, module.__package__ = f"cogs-held:{digest}", ""
            exec(compile(raw, module.__file__, "exec", dont_inherit=True, optimize=0), module.__dict__)
            return module
        finally: held.close()
    @staticmethod
    def _result_type(module: types.ModuleType, operation: str) -> type:
        names = ("RuntimeMappingQualificationResult RuntimeCompressionQualificationResult DescriptorQualificationResult "
                 "LifecycleQualificationResult SandboxQualificationResult RuntimeQualificationResult").split()
        return getattr(module, dict(zip(DRIVERS, names))[operation])
    @classmethod
    def _closed_result(cls, module: types.ModuleType, operation: str, result: object) -> dict[str, object]:
        expected = cls._result_type(module, operation)
        nested = "RuntimeObjectObservation MappedObjectObservation RuntimeCompressionToolObservation RuntimeQualificationResult".split()
        allowed = {expected, *(getattr(module, name) for name in nested)}
        def primitive(value: object) -> object:
            if type(value) in (str, int, bool, type(None)): return value
            if type(value) is tuple: return [primitive(item) for item in value]
            if type(value) is dict:
                _require(all(type(key) is str for key in value), "production result map keys")
                return {key: primitive(item) for key, item in value.items()}
            _require(type(value) in allowed, "production result dataclass substitution")
            return {item.name: primitive(getattr(value, item.name)) for item in fields(value)}
        _require(type(result) is expected, "production result type substitution")
        closed = primitive(result)
        _require(type(closed) is dict, "production result primitive shape")
        return closed
    def run_fixed_operation(self, context: WorkflowContext, operation: str) -> dict[str, object]:
        root = self.fds.open("held-source-root", lambda: os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
        try:
            path = f"scripts/native-qualification/{DRIVERS[context.job]}"
            client = self.fds.open("held-operation-client", lambda: os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root.number))
            module = self._launcher(root)
            clients = dict(zip("ABCD", ("invoke_fixed_mapping_qualification", "invoke_fixed_compression_qualification",
                                         "invoke_fixed_descriptor_qualification", "invoke_fixed_lifecycle_qualification")))
            expected = self._result_type(module, operation)
            if operation in clients:
                result = getattr(module, clients[operation])(root.number, context.head_sha, client.number)
                digest = result.source_set_sha256
            else:
                factory = "_admit_job_e_sandbox_with_held_sources" if operation == "E" else "_admit_complete_runtime_with_held_sources"
                invocation = getattr(module, factory)(root.number, context.head_sha, client.number)
                exact = type(invocation) is module._AdmittedProductionInvocation and invocation.result_type is expected
                _require(exact and invocation.source_revision == context.head_sha, "production invocation type")
                digest, result = invocation.source_set_sha256, invocation.invoke()
            exact = type(result) is expected and result.source_revision == context.head_sha and result.source_set_sha256 == digest
            _require(exact and HEX64.fullmatch(digest) is not None, "production result admission")
            self.source_set_sha256 = digest
            return self._closed_result(module, operation, result)
        finally: self.fds.close_reverse(leases=[root] + ([client] if "client" in locals() else []))
    def _read(self, path: str | Path, limit: int) -> bytes:
        lease = self.fds.open("baseline-read", lambda: os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW))
        value = bytearray()
        try:
            while True:
                block = os.read(lease.number, min(65_536, limit + 1 - len(value)))
                if not block:
                    return bytes(value)
                value.extend(block)
                _require(len(value) <= limit, "baseline read bound")
        finally:
            lease.close()
    def _descriptor_snapshot(self) -> tuple[tuple[object, ...], ...]:
        lease = self.fds.open(
            "fd-enumerator",
            lambda: os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW),
        )
        try:
            names = _enumerate_directory(lease.number, True)
            _require(names.count(str(lease.number)) == 1, "fd enumerator identity")
            rows = []
            for name in names:
                number = int(name)
                if number == lease.number:
                    continue
                flags = fcntl.fcntl(number, fcntl.F_GETFD)
                status_flags = fcntl.fcntl(number, fcntl.F_GETFL)
                current = os.fstat(number)
                rows.append((number, flags, status_flags, stat.S_IFMT(current.st_mode), current.st_dev, current.st_ino, current.st_rdev, current.st_mode))
            return tuple(sorted(rows))
        finally:
            lease.close()
    def _process(self, pid: int) -> tuple[object, ...]:
        raw = self._read(f"/proc/{pid}/stat", 65_536).decode("ascii")
        close = raw.rfind(")")
        _require(close > 1 and raw[close + 1:close + 2] == " ", "process stat")
        fields = raw[close + 2:].split()
        _require(len(fields) >= 20, "process stat fields")
        executable = os.stat(f"/proc/{pid}/exe", follow_symlinks=True)
        return pid, int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]), executable.st_dev, executable.st_ino
    def _children(self) -> tuple[object, ...]:
        pending, edges, rows, seen = [os.getpid()], [], [], set()
        while pending:
            parent = pending.pop(0)
            raw = self._read(f"/proc/{parent}/task/{parent}/children", 65_536).decode("ascii").strip()
            children = [] if not raw else [int(item) for item in raw.split()]
            _require(len(children) == len(set(children)) and len(seen) + len(children) <= 16, "descendant census")
            for child in children:
                _require(child > 0 and child not in seen, "descendant identity")
                seen.add(child)
                edges.append((parent, child))
                rows.append(self._process(child))
                pending.append(child)
        subreaper = ctypes.c_int()
        result = ctypes.CDLL(None, use_errno=True).prctl(37, ctypes.byref(subreaper), 0, 0, 0)
        _require(result == 0, "subreaper observation")
        return os.getpgrp(), os.getsid(0), subreaper.value, tuple(edges), tuple(rows)
    def _git(self, arguments: list[str], limit: int = 262_144) -> bytes:
        environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent"}
        result = subprocess.run(["/usr/bin/git", "-C", str(ROOT), *arguments], env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=False)
        _require(result.returncode == 0 and not result.stderr and len(result.stdout) <= limit, "checkout observation")
        return result.stdout
    def _checkout(self, context: WorkflowContext) -> tuple[bytes, ...]:
        head = self._git(["rev-parse", "--verify", "HEAD^{commit}"])
        status_value = self._git(["status", "--porcelain=v2", "--untracked-files=all"])
        config = self._git(["config", "--local", "--null", "--list"])
        remote = self._git(["remote", "get-url", "origin"])
        _require(head == f"{context.head_sha}\n".encode() and status_value == b"", "checkout source")
        lowered = config.lower()
        _require(b"credential.helper" not in lowered and b"extraheader" not in lowered, "checkout credentials")
        _require(re.search(rb"://[^/\n]*@", remote) is None, "checkout remote")
        return head, status_value, config, remote
    @staticmethod
    def _path(path: Path) -> tuple[int, ...] | None:
        try:
            return _generation(path.lstat())
        except FileNotFoundError:
            return None
    def observe(self, context: WorkflowContext) -> Mapping[str, object]:
        mountinfo = self._read("/proc/self/mountinfo", 1_048_576)
        namespaces = tuple((name, _generation(os.stat(f"/proc/self/ns/{name}", follow_symlinks=True))) for name in ("user", "pid", "mnt", "net"))
        paths = (self._path(Path("/tmp/cogs-o2-runtime-v1")), self._path(report_path(context.job).parent))
        checkout = self._checkout(context)
        children = self._children()
        descriptors = self._descriptor_snapshot()
        return dict(descriptors=descriptors, children=children, paths=paths, mounts=hashlib.sha256(mountinfo).digest(),
                    namespaces=namespaces, limits=resource.getrlimit(resource.RLIMIT_NOFILE), checkout=checkout)
@dataclass(frozen=True)
class CleanupEvidence:
    _session_nonce: bytes; values: Mapping[str, bool]
    @property
    def restored(self) -> bool: return all(self.values.values())
@dataclass(frozen=True)
class ReportCandidate:
    production_checks: Mapping[str, str]; metadata: list[Mapping[str, object]]
    failure_phase: str | None = None; diagnostics: bytes | None = None; primary_error: BaseException | None = None
def _schema_error(node: object, value: object, root: Mapping[str, object], place: str = "$") -> None:
    if node is True: return
    _require(node is not False and type(node) is dict, f"schema {place}"); rule = node
    if "$ref" in rule:
        target: object = root
        for part in str(rule["$ref"]).removeprefix("#/").split("/"): target = target[part]  # type: ignore[index]
        _schema_error(target, value, root, place)
    for child in rule.get("allOf", []): _schema_error(child, value, root, place)
    for keyword, predicate in (("anyOf", lambda hits: hits >= 1), ("oneOf", lambda hits: hits == 1)):
        if keyword in rule: _require(predicate(sum(_schema_matches(child, value, root) for child in rule[keyword])), f"schema {keyword} {place}")
    if "if" in rule:
        selected = rule.get("then") if _schema_matches(rule["if"], value, root) else rule.get("else")
        if selected is not None: _schema_error(selected, value, root, place)
    if "const" in rule: _require(type(value) is type(rule["const"]) and value == rule["const"], f"schema const {place}")
    if "enum" in rule: _require(any(type(value) is type(item) and value == item for item in rule["enum"]), f"schema enum {place}")
    kind = rule.get("type")
    types = kind if type(kind) is list else [kind] if kind else []
    mapping = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
    if types: _require(any(type(value) is mapping[name] for name in types), f"schema type {place}")
    if type(value) is dict:
        required, properties = rule.get("required", []), rule.get("properties", {})
        _require(all(name in value for name in required), f"schema required {place}")
        if rule.get("additionalProperties") is False: _require(set(value) <= set(properties), f"schema property {place}")
        for name, child in properties.items():
            if name in value: _schema_error(child, value[name], root, f"{place}.{name}")
    if type(value) is list:
        _require(rule.get("minItems", 0) <= len(value) <= rule.get("maxItems", len(value)), f"schema items {place}")
        prefix = rule.get("prefixItems", [])
        for index, child in enumerate(prefix):
            _require(index < len(value), f"schema prefix {place}"); _schema_error(child, value[index], root, f"{place}[{index}]")
        for index in range(len(prefix), len(value)): _schema_error(rule.get("items", True), value[index], root, f"{place}[{index}]")
        if rule.get("uniqueItems"):
            encoded = [_canonical(item) for item in value]; _require(len(encoded) == len(set(encoded)), f"schema unique {place}")
        if "contains" in rule:
            hits = sum(_schema_matches(rule["contains"], item, root) for item in value)
            _require(rule.get("minContains", 1) <= hits <= rule.get("maxContains", len(value)), f"schema contains {place}")
    if type(value) is str and "pattern" in rule: _require(re.search(rule["pattern"], value) is not None, f"schema pattern {place}")
    if type(value) is int and not isinstance(value, bool): _require(rule.get("minimum", value) <= value <= rule.get("maximum", value), f"schema number {place}")
def _schema_matches(node: object, value: object, root: Mapping[str, object]) -> bool:
    try: _schema_error(node, value, root)
    except QualificationError: return False
    return True
def _decode(raw: bytes) -> object:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for name, item in rows:
            _require(name not in value, "duplicate JSON key"); value[name] = item
        return value
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    _require(raw == _canonical(value, True) and len(raw) <= REPORT_LIMIT, "canonical report")
    return value
def _validate_schema(value: object) -> None:
    before = SCHEMA.lstat()
    raw = SCHEMA.read_bytes()
    _require(len(raw) <= 100_000 and _generation(before) == _generation(SCHEMA.lstat()), "schema generation")
    schema_value = json.loads(raw); _require(type(schema_value) is dict, "tracked schema")
    _schema_error(schema_value, value, schema_value)
def _normalize_objects(objects: list[Mapping[str, object]], label: str) -> list[dict[str, object]]:
    roles = [row["role"] for row in objects]; _require(2 <= len(objects) <= 127 and roles[:2] == ["executable", "loader"], f"{label} object order")
    _require(all(role == "library" for role in roles[2:]), f"{label} library roles")
    identities = [(row["sha256"], row["size_bytes"]) for row in objects]; _require(len(identities) == len(set(identities)), f"{label} object identity")
    providers = [row["soname"] for row in objects if row["soname"] is not None]; _require(len(providers) == len(set(providers)), f"{label} provider identity")
    needed = [name for row in objects for name in row["needed"]]
    _require(all(1 <= row["size_bytes"] <= OBJECT_LIMIT for row in objects), f"{label} object bounds")
    _require(all(len(row["needed"]) == len(set(row["needed"])) for row in objects), f"{label} needed uniqueness")
    _require(all(name in providers for name in needed) and all(row["soname"] in needed for row in objects[2:]), f"{label} closure")
    libraries = [(row["soname"].encode("ascii"), row["sha256"]) for row in objects[2:]]
    _require(libraries == sorted(libraries), f"{label} library order")
    return [{"needed": row["needed"], "role": row["role"], "sha256": row["sha256"],
             "size": row["size_bytes"], "soname": row["soname"]} for row in objects]
def _validate_a(metadata: list[object]) -> None:
    _require(3 <= len(metadata) <= 128 and type(metadata[-1]) is dict, "A metadata"); objects, summary = metadata[:-1], metadata[-1]
    _require([row["id"] for row in objects] == [f"python-object-{index}" for index in range(len(objects))], "A object ids")
    normalized = _normalize_objects(objects, "A"); mapped = summary["mapped_sequence"]
    expected_mapped = [{"role": row["role"], "sha256": row["sha256"]} for row in objects]; _require(mapped == expected_mapped, "A mapped sequence")
    _require(summary["closure_sha256"] == hashlib.sha256(_canonical(normalized)).hexdigest(), "A closure summary")
    digest_rows = [[row["role"], row["sha256"]] for row in mapped]
    _require(summary["mapping_sha256"] == hashlib.sha256(_canonical(digest_rows)).hexdigest(), "A mapping summary")
def _validate_semantics(value: object, context: WorkflowContext | None = None) -> None:
    _require(type(value) is dict and value.get("job") in DRIVERS, "semantic report")
    report, job = value, str(value["job"]); _require(tuple(row["id"] for row in report["checks"]) == CHECK_IDS[job], "semantic checks")
    passing = all(row["outcome"] == "pass" for row in report["checks"]) and all(report["cleanup"].values())
    _require((report["result"] == "pass") == passing, "semantic result")
    _require((report["failure_phase"] is None) == passing and (report["diagnostics_sha256"] is None) == passing, "semantic failure")
    source, envelope, workflow = report["source"], report["envelope"], report["workflow"]
    _require(source["checkout_sha"] == source["head_sha"], "semantic checkout")
    _require(envelope["repository"] == envelope["head_repository"] and envelope["github_sha"] == envelope["event_merge_sha"], "semantic repository")
    _require(envelope["event_name"] == "pull_request" and envelope["run_attempt"] == 1, "semantic event")
    workflow_matches = workflow["job_id"] == JOB_IDS[job] and workflow["workflow_sha"] in {source["head_sha"], envelope["event_merge_sha"]}
    _require(workflow_matches and workflow["blob_sha256"] == _sha256(WORKFLOW), "semantic workflow")
    _require(source["common_blob_sha256"] == _sha256(COMMON), "semantic common")
    _require(source["driver_blob_sha256"] == _sha256(COMMON.parent / DRIVERS[job]), "semantic driver")
    metadata = report["metadata"]
    if job == "A" and passing:
        _validate_a(metadata)
    if job == "B" and passing:
        _require([row["id"] for row in metadata] == ["gzip", "zstd"], "B order")
        for row in metadata:
            objects = row["objects"]
            normalized = _normalize_objects(objects, "B")
            mapped = [[item["role"], item["sha256"]] for item in objects]
            _require(row["closure_sha256"] == hashlib.sha256(_canonical(normalized)).hexdigest(), "B closure summary")
            _require(row["mapping_sha256"] == hashlib.sha256(_canonical(mapped)).hexdigest(), "B mapping summary")
            _require(row["execution_mapping_sha256"] == row["mapping_sha256"], "B execution mapping")
            _require(row["seal_mask"] == 63 and row["source_sha256"] == row["sealed_sha256"] == objects[0]["sha256"], "B sealed source")
            _require(row["source_size_bytes"] == row["sealed_size_bytes"] == objects[0]["size_bytes"], "B sealed size")
            _require(row["output_sha256"] == MARKER_SHA256, "B exact output")
        _require(metadata[0]["source_sha256"] != metadata[1]["source_sha256"], "B source substitution")
        _require(metadata[0]["mapping_sha256"] != metadata[1]["mapping_sha256"], "B mapping substitution")
    if context is not None:
        observed = {name: report[name] for name in ("source", "envelope", "workflow", "runner")}
        _require(job == context.job and observed == _context_value(context), "semantic context")
def _validate(value: object, context: WorkflowContext | None = None) -> None:
    _validate_schema(value); _validate_semantics(value, context)
def report_path(job: str) -> Path:
    _require(job in DRIVERS, "report job"); return Path(f"/tmp/cogs-native-qualification-{job}/report.json")
def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            count = os.write(descriptor, raw[offset:])
        except InterruptedError: continue
        _require(count > 0, "report zero write")
        offset += count
def _read_all(descriptor: int, limit: int) -> bytes:
    value = bytearray()
    while True:
        try:
            block = os.read(descriptor, min(65_536, limit + 1 - len(value)))
        except InterruptedError: continue
        if not block:
            return bytes(value)
        value.extend(block)
        _require(len(value) <= limit, "report read bound")
def _rename_noreplace(directory_fd: int, source: bytes, target: bytes) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    _require(renameat2 is not None, "renameat2 unavailable")
    if renameat2(directory_fd, source, directory_fd, target, 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
def _socket_name(context: object) -> bytes:
    identity = f"{context.job}:{context.run_id}:{context.run_attempt}".encode()  # type: ignore[attr-defined]
    return b"\0cogs-nq-" + hashlib.sha256(identity).hexdigest()[:48].encode()
class _CustodianClient:
    def __init__(self, control: FdLease, pidfd: FdLease): self.control, self.pidfd = control, pidfd
    def publish(self, raw: bytes) -> None:
        endpoint = socket.socket(fileno=self.control.number)
        try:
            _require(endpoint.send(raw) == len(raw), "custodian report send")
            reply = endpoint.recv(128)
        finally:
            endpoint.detach()
        _require(reply == b"PUBLISHED", "custodian publication")
        self.control.close()
        self.pidfd.close()
def _start_custodian(context: WorkflowContext, registry: FdRegistry) -> _CustodianClient:
    left_socket, right_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    left = registry.adopt(left_socket.detach(), "report-custodian-control")
    right = registry.adopt(right_socket.detach(), "report-custodian-child")
    nonce = os.urandom(32)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(left.number)
            _custodian_main(right.number, context, nonce)
        except BaseException: os._exit(1)
        os._exit(0)
    pidfd = registry.open("report-custodian-pidfd", lambda: os.pidfd_open(pid, 0))
    right.close()
    endpoint = socket.socket(fileno=left.number)
    try:
        endpoint.send(b"START")
        ready = endpoint.recv(64)
    finally:
        endpoint.detach()
    _require(ready == b"READY", "custodian preregistration")
    return _CustodianClient(left, pidfd)
def _name_matches(directory_fd: int, name: str, expected: os.stat_result) -> bool:
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError: return False
    return _generation(current) == _generation(expected)
def _custodian_main(control_fd: int, context: WorkflowContext, nonce: bytes) -> None:
    control = socket.socket(fileno=control_fd)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    listener.bind(_socket_name(context))
    listener.listen(1)
    _require(control.recv(16) == b"START", "custodian release")
    control.send(b"READY")
    raw = control.recv(REPORT_LIMIT + 1)
    if not raw:
        listener.close()
        control.close()
        return
    registry = FdRegistry()
    parent = directory = report = receipt = None
    target = report_path(context.job)
    try:
        value = _decode(raw)
        _validate(value, context)
        parent = registry.open("report-parent", lambda: os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
        _require(not os.path.lexists(target.parent), "report baseline")
        os.mkdir(target.parent.name, 0o700, dir_fd=parent.number)
        os.fsync(parent.number)
        directory = registry.open(
            "report-directory",
            lambda: os.open(target.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent.number),
        )
        directory_status = os.fstat(directory.number)
        _require(stat.S_ISDIR(directory_status.st_mode) and stat.S_IMODE(directory_status.st_mode) == 0o700, "report directory")
        _require(directory_status.st_uid == os.geteuid() and directory_status.st_gid == os.getegid(), "report directory owner")
        report = registry.open(
            "staged-report",
            lambda: os.open(".report.stage", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory.number),
        )
        _write_all(report.number, raw)
        os.fsync(report.number)
        report_status = os.fstat(report.number)
        _require(stat.S_ISREG(report_status.st_mode) and report_status.st_size == len(raw) and report_status.st_nlink == 1, "staged report")
        os.lseek(report.number, 0, os.SEEK_SET)
        _require(_read_all(report.number, REPORT_LIMIT) == raw, "staged report bytes")
        _validate(_decode(raw), context)
        receipt_value = {
            "version": "cogs.native-report-custodian/v1", "job": context.job, "run_id": context.run_id,
            "run_attempt": context.run_attempt, "head_sha": context.head_sha, "nonce": nonce.hex(),
            "socket": _socket_name(context)[1:].decode(), "report_sha256": hashlib.sha256(raw).hexdigest(), "report_size": len(raw),
        }
        receipt_raw = _canonical(receipt_value, True)
        receipt = registry.open(
            "custodian-receipt",
            lambda: os.open(".owner.json", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory.number),
        )
        _write_all(receipt.number, receipt_raw)
        os.fsync(receipt.number)
        os.fsync(directory.number)
        _rename_noreplace(directory.number, b".report.stage", b"report.json")
        os.fsync(directory.number)
        report_status = os.fstat(report.number)
        receipt_status = os.fstat(receipt.number)
        _require(_name_matches(directory.number, "report.json", report_status), "published report identity")
        _require(set(_enumerate_directory(directory.number, False)) == {".owner.json", "report.json"}, "published inventory")
        control.send(b"PUBLISHED")
        control.close()
        client, _ = listener.accept()
        client_fd = client.detach()
        endpoint = socket.socket(fileno=client_fd)
        peer = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        request = endpoint.recv(128)
        _require(peer[1:] == (os.geteuid(), os.getegid()) and request == b"CLEANUP", "custodian cleanup peer")
        directory_name = os.stat(target.parent.name, dir_fd=parent.number, follow_symlinks=False)
        key = lambda item: (stat.S_IFMT(item.st_mode), item.st_uid, item.st_gid, item.st_dev, item.st_ino)
        _require(key(directory_name) == key(directory_status), "report directory replacement")
        _require(set(_enumerate_directory(directory.number, False)) == {".owner.json", "report.json"}, "cleanup inventory")
        _require(_name_matches(directory.number, "report.json", report_status), "cleanup report replacement")
        os.unlink("report.json", dir_fd=directory.number)
        os.fsync(directory.number)
        _require(_name_matches(directory.number, ".owner.json", receipt_status), "cleanup receipt replacement")
        os.unlink(".owner.json", dir_fd=directory.number)
        os.fsync(directory.number)
        _require(_enumerate_directory(directory.number, False) == (), "cleanup directory empty")
        report.close()
        receipt.close()
        os.rmdir(target.parent.name, dir_fd=parent.number)
        os.fsync(parent.number)
        _require(not os.path.lexists(target.parent), "report baseline restoration")
        directory.close()
        parent.close()
        listener.close()
        endpoint.send(b"CLEAN")
        endpoint.close()
    except BaseException:
        try:
            control.send(b"FAILED")
        except BaseException:
            pass
        try:
            if directory is not None:
                for name, lease in ((".report.stage", report), ("report.json", report), (".owner.json", receipt)):
                    if lease is not None:
                        expected = os.fstat(lease.number)
                        if _name_matches(directory.number, name, expected):
                            os.unlink(name, dir_fd=directory.number)
                os.fsync(directory.number)
        except BaseException:
            pass
        os._exit(1)
def cleanup_report(job: str) -> None:
    target = report_path(job)
    socket_name: bytes | None = None
    if target.parent.is_dir():
        receipt = target.parent / ".owner.json"
        before = receipt.lstat()
        raw = receipt.read_bytes()
        _require(len(raw) <= 4096 and _generation(before) == _generation(receipt.lstat()), "custodian receipt generation")
        value = _decode(raw)
        required = {"version", "job", "run_id", "run_attempt", "head_sha", "nonce", "socket", "report_sha256", "report_size"}
        _require(type(value) is dict and set(value) == required, "custodian receipt")
        _require(value["version"] == "cogs.native-report-custodian/v1" and value["job"] == job, "custodian receipt context")
        _require(HEX40.fullmatch(value["head_sha"]) is not None and HEX64.fullmatch(value["report_sha256"]) is not None, "custodian receipt digest")
        _require(re.fullmatch(r"cogs-nq-[0-9a-f]{48}", value["socket"]) is not None, "custodian socket")
        socket_name = b"\0" + value["socket"].encode()
    elif {"GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"} <= set(os.environ):
        context = type("CleanupContext", (), {"job": job,
            "run_id": _integer(os.environ["GITHUB_RUN_ID"], "cleanup run"),
            "run_attempt": _integer(os.environ["GITHUB_RUN_ATTEMPT"], "cleanup attempt")})()
        socket_name = _socket_name(context)
    else:
        return
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    endpoint.settimeout(10)
    endpoint.connect(socket_name)
    endpoint.send(b"CLEANUP")
    _require(endpoint.recv(64) == b"CLEAN", "custodian cleanup")
    endpoint.close()
    _require(not os.path.lexists(target.parent), "report cleanup baseline")
class NativeSession:
    def __init__(self, context: WorkflowContext, ops: object, custodian: _CustodianClient, nonce: bytes):
        self.context, self.fds, self._ops, self._custodian = context, ops.fds, ops, custodian
        self.source_set_sha256, self._nonce, self._operation_used = ops.source_set_sha256, nonce, False
        self._before = dict(ops.observe(context))
        _require(tuple(self._before) == CLEANUP_KEYS, "baseline domains")
        _require(self._before["paths"] == (None, None), "named path baseline")
        self._poisoned: set[str] = set(); self._evidence, self._published = None, False
    @classmethod
    def begin(cls, expected_job: str, driver_file: str | Path) -> "NativeSession":
        context = WorkflowContext.from_environ(expected_job, driver_file)
        registry = FdRegistry()
        custodian = _start_custodian(context, registry)
        return cls(context, SystemCommonOps(registry), custodian, os.urandom(32))
    @classmethod
    def _begin_with_ops(cls, context: WorkflowContext, ops: object, custodian: _CustodianClient) -> "NativeSession":
        return cls(context, ops, custodian, os.urandom(32))
    def run_fixed_operation(self, operation: str) -> dict[str, object]:
        expected = self.context.job
        _require(operation == expected and not self._operation_used and self._evidence is None, "fixed operation binding")
        self._operation_used = True
        result = self._ops.run_fixed_operation(self.context, operation)
        self.source_set_sha256 = self._ops.source_set_sha256
        _require(type(result) is dict and HEX64.fullmatch(self.source_set_sha256) is not None, "closed production operation")
        return result
    def qualify_fixed_descriptor_primitives(self) -> dict[str, object]: return self.run_fixed_operation("C")
    def qualify_fixed_process_lifecycle(self) -> dict[str, object]: return self.run_fixed_operation("D")
    def mark_uncertain(self, domains: tuple[str, ...], error: BaseException) -> None:
        _require(self._evidence is None and domains and all(domain in CLEANUP_KEYS for domain in domains), "cleanup uncertainty")
        _require(isinstance(error, BaseException), "cleanup uncertainty error")
        self._poisoned.update(domains)
    def settle_native_phase(self) -> CleanupEvidence:
        _require(self._evidence is None and not self._published, "native settlement state")
        after: Mapping[str, object] = {}; observation_error: BaseException | None = None
        try:
            after = self._ops.observe(self.context)
        except BaseException as error:
            observation_error = error
        values = {key: observation_error is None and key not in self._poisoned and after.get(key) == self._before[key] for key in CLEANUP_KEYS}
        if self.fds.uncertain: values["descriptors"] = False
        self._evidence = CleanupEvidence(self._nonce, values)
        return self._evidence
    def publish(self, candidate: ReportCandidate) -> Path:
        _require(self._evidence is not None and self._evidence._session_nonce == self._nonce and not self._published, "report session state")
        _require(type(candidate) is ReportCandidate, "typed report candidate")
        production = dict(candidate.production_checks)
        _require(tuple(production) == PRODUCTION_CHECK_IDS[self.context.job] and set(production.values()) <= {"pass", "fail"}, "production check inventory")
        cleanup = dict(self._evidence.values)
        derived = {"cleanup_restored": all(cleanup.values()), "checkout_unchanged": cleanup["checkout"]}
        checks = {name: ("pass" if derived[name] else "fail") if name in derived else production[name]
                  for name in CHECK_IDS[self.context.job]}
        passing = candidate.primary_error is None and all(value == "pass" for value in checks.values()) and all(cleanup.values())
        _require(passing or any(value == "fail" for value in checks.values()) or not all(cleanup.values()), "failed observation")
        phase, diagnostics = candidate.failure_phase, candidate.diagnostics
        if not passing:
            _require(type(phase) is str and SAFE.fullmatch(phase) is not None, "failure phase")
            if diagnostics is None and candidate.primary_error is not None:
                diagnostics = f"{type(candidate.primary_error).__name__}:{candidate.primary_error}".encode()[:REPORT_LIMIT]
            _require(type(diagnostics) is bytes and 0 < len(diagnostics) <= REPORT_LIMIT, "failure diagnostics")
        else: _require(phase is None and diagnostics is None, "passing diagnostics")
        report = {
            "authority": AUTHORITY, "checks": [{"id": key, "outcome": value} for key, value in checks.items()],
            "cleanup": cleanup, "diagnostics_sha256": None if diagnostics is None else hashlib.sha256(diagnostics).hexdigest(),
            "failure_phase": phase, "job": self.context.job, "metadata": [dict(row) for row in candidate.metadata] if passing else [],
            "result": "pass" if passing else "fail", "version": VERSION, **_context_value(self.context),
        }
        raw = _canonical(report, True)
        _require(len(raw) <= REPORT_LIMIT and _decode(raw) == report, "report encoding")
        _validate(report, self.context)
        self._custodian.publish(raw)
        self._published = True
        return report_path(self.context.job)
def _main(arguments: list[str]) -> int:
    if arguments == ["--eligibility"]: evaluate_eligibility(os.environ)
    elif arguments == ["--require-final-results"]: require_final_results(os.environ)
    elif len(arguments) == 2 and arguments[0] == "--cleanup" and arguments[1] in DRIVERS: cleanup_report(arguments[1])
    else: raise QualificationError("common entry")
    return 0
if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except BaseException:
        os.write(2, b"native-common-failed\n")
        raise SystemExit(1)
