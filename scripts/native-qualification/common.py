#!/usr/bin/python3
from __future__ import annotations
import ctypes, fcntl, hashlib, json, os, platform, re, resource, signal, socket, stat, struct, subprocess, sys, types
from dataclasses import dataclass, fields; from enum import Enum, auto; from pathlib import Path; from types import MappingProxyType
from typing import Callable, Mapping
VERSION, AUTHORITY = "cogs.native-qualification/v1alpha1", "exact-run-native-qualification"; ROOT = Path(__file__).resolve().parents[2]
WORKFLOW, COMMON = ROOT / ".github/workflows/ci.yml", ROOT / "scripts/native-qualification/common.py"
SCHEMA = ROOT / "schemas/native-qualification-report-v1alpha1.json"
REPORT_LIMIT, OBJECT_LIMIT = 32_768, 134_217_728; MARKER_SHA256 = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8"
POLICY_SHA256 = "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2"
SOURCE_PATHS = (
    "deploy/aws-feasibility/remote/completion_elf.py", "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", "schemas/trusted-runtime-closure-v1.json")
LAUNCHER_PATH = SOURCE_PATHS[2]; CLEANUP_KEYS = ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")
DRIVERS = dict(zip(("A", "B", "C", "D", "E", "integration"), ("job-a-runtime-mappings.py", "job-b-compression.py",
    "job-c-descriptors.py", "job-d-process-lifecycle.py", "job-e-sandbox.py", "thin-integration.py")))
JOB_IDS = {**{job: f"native-qualification-{job.lower()}" for job in "ABCDE"}, "integration": "native-closure-integration"}
CHECK_IDS = {
    "A": tuple("elf_real python_closure_exact map_files_trusted mapped_closure_equal mapping_stable helper_reaped cleanup_restored".split()),
    "B": tuple(("gzip_source_exact gzip_sealed_exec zstd_source_exact zstd_sealed_exec decompression_deterministic "
                "network_denied children_exact cleanup_restored").split()),
    "C": tuple(("nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact "
                "inheritance_exact limit_restored cleanup_restored").split()),
    "D": tuple(("pdeathsig_armed parent_handshake_exact before_release_death after_release_death "
                "starttime_revalidated session_owned process_group_owned term_kill_bounded all_reaped cleanup_restored").split()),
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
    if not condition:
        raise QualificationError(message)
def _integer(value: str, name: str) -> int:
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None, name)
    return int(value)
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
    job: str; repository: str; head_repository: str; head_sha: str; envelope_sha: str; workflow_sha: str; merge_sha: str; base_sha: str; job_id: str
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
        number = opener()
        try:
            return self.adopt(number, purpose)
        except BaseException:
            self._closer(number)
            raise
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
            raise __import__("builtins").ExceptionGroup("fd cleanup", failures)
    @property
    def uncertain(self) -> bool: return self._allocation_blocked
@dataclass
class FdLease:
    number: int; purpose: str; registry: FdRegistry
    state: FdState = FdState.OWNED; close_error: BaseException | None = None
    def close(self) -> None: self.registry._close(self)
_SYS_GETDENTS64, _GETDENTS_CHUNK = 217, 32_768; _GETDENTS_CALLS, _GETDENTS_BYTES, _GETDENTS_ENTRIES = 32, 1_048_576, 16_384
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
@dataclass(frozen=True)
class _HeldSource:
    path: str
    lease: FdLease
    raw: bytes
    generation: tuple[int, ...]
class SystemCommonOps:
    def __init__(self, fds: FdRegistry):
        self.fds = fds
        self.source_set_sha256 = ""
    def _open_beneath(self, root: FdLease, path: str, purpose: str) -> FdLease:
        parts = path.split("/")
        _require(parts and all(part not in ("", ".", "..") for part in parts), "held source path")
        directory = self.fds.open("held-source-directory", lambda: os.dup(root.number))
        try:
            for part in parts[:-1]:
                next_directory = self.fds.open(
                    "held-source-directory",
                    lambda part=part, directory=directory: os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory.number,
                    ),
                )
                directory.close()
                directory = next_directory
            return self.fds.open(
                purpose,
                lambda: os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory.number),
            )
        finally:
            directory.close()
    @staticmethod
    def _read_held(lease: FdLease) -> tuple[bytes, tuple[int, ...]]:
        before = os.fstat(lease.number)
        _require(stat.S_ISREG(before.st_mode), "held source type")
        _require(stat.S_IMODE(before.st_mode) == 0o644, "held source mode")
        _require(0 < before.st_size <= 2_000_000, "held source size")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.pread(lease.number, min(65_536, before.st_size - len(raw)), len(raw))
            _require(bool(block), "held source short read")
            raw.extend(block)
        generation = _generation(before)
        _require(generation == _generation(os.fstat(lease.number)), "held source generation")
        return bytes(raw), generation
    @staticmethod
    def _git_tree(root: FdLease, revision: str, paths: tuple[str, ...]) -> dict[str, str]:
        command = (
            "/usr/bin/git",
            "-C",
            f"/proc/self/fd/{root.number}",
            "-c",
            "core.hooksPath=/dev/null",
            "ls-tree",
            "-rz",
            "--full-tree",
            revision,
            "--",
            *paths,
        )
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
        completed = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            pass_fds=(root.number,),
            timeout=5,
            check=False,
        )
        _require(completed.returncode == 0 and not completed.stderr, "held source Git admission")
        _require(len(completed.stdout) <= 32_768, "held source Git output")
        rows: dict[str, str] = {}
        for encoded in completed.stdout.split(b"\0"):
            if not encoded:
                continue
            header, raw_path = encoded.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8", "strict")
            _require(path not in rows and mode == "100644" and kind == "blob", "held source Git row")
            rows[path] = oid
        _require(set(rows) == set(paths), "held source Git cardinality")
        return rows
    @staticmethod
    def _blob_matches(raw: bytes, oid: str) -> bool:
        framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        if len(oid) == 40:
            return hashlib.sha1(framed).hexdigest() == oid
        if len(oid) == 64:
            return hashlib.sha256(framed).hexdigest() == oid
        return False
    def _admit_sources(self, context: WorkflowContext, root: FdLease) -> tuple[dict[str, _HeldSource], str]:
        client_path = f"scripts/native-qualification/{DRIVERS[context.job]}"
        paths = (*SOURCE_PATHS, client_path)
        held: dict[str, _HeldSource] = {}
        try:
            for path in paths:
                lease = self._open_beneath(root, path, f"held:{path}")
                raw, generation = self._read_held(lease)
                held[path] = _HeldSource(path, lease, raw, generation)
            tree = self._git_tree(root, context.head_sha, paths)
            for path, source in held.items():
                _require(self._blob_matches(source.raw, tree[path]), "held source Git blob")
                _require(source.generation == _generation(os.fstat(source.lease.number)), "held source admission drift")
            digest = hashlib.sha256()
            for path in SOURCE_PATHS:
                encoded = path.encode("utf-8")
                raw = held[path].raw
                digest.update(struct.pack("!I", len(encoded)))
                digest.update(encoded)
                digest.update(struct.pack("!Q", len(raw)))
                digest.update(hashlib.sha256(raw).digest())
            return held, digest.hexdigest()
        except BaseException as primary:
            self.fds.close_reverse(primary, [source.lease for source in held.values()])
            raise
    @staticmethod
    def _launcher(source: _HeldSource) -> types.ModuleType:
        digest = hashlib.sha256(source.raw).hexdigest()
        module = types.ModuleType(f"_cogs_admitted_launcher_{digest}")
        module.__file__ = f"cogs-git-admitted:{digest}"
        module.__package__ = ""
        code = compile(source.raw, module.__file__, "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
        return module
    @staticmethod
    def _result_type(module: types.ModuleType, operation: str) -> type:
        names = (
            "RuntimeMappingQualificationResult RuntimeCompressionQualificationResult DescriptorQualificationResult "
            "LifecycleQualificationResult SandboxQualificationResult RuntimeQualificationResult"
        ).split()
        return getattr(module, dict(zip(DRIVERS, names))[operation])
    @classmethod
    def _closed_result(cls, module: types.ModuleType, operation: str, result: object) -> dict[str, object]:
        expected = cls._result_type(module, operation)
        def primitive(value: object) -> object:
            if type(value) in (str, int, bool, type(None)):
                return value
            if type(value) is tuple:
                return [primitive(item) for item in value]
            if type(value) is dict:
                _require(all(type(key) is str for key in value), "production result map keys")
                return {key: primitive(item) for key, item in value.items()}
            _require(type(value).__module__ == module.__name__, "production result dataclass module")
            return {item.name: primitive(getattr(value, item.name)) for item in fields(value)}
        _require(type(result) is expected, "production result type substitution")
        closed = primitive(result)
        _require(type(closed) is dict, "production result primitive shape")
        return closed
    def run_fixed_operation(self, context: WorkflowContext, operation: str) -> dict[str, object]:
        root = self.fds.open(
            "held-source-root",
            lambda: os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW),
        )
        held: dict[str, _HeldSource] = {}
        primary: BaseException | None = None
        try:
            held, digest = self._admit_sources(context, root)
            module = self._launcher(held[LAUNCHER_PATH])
            admitted_bytes = MappingProxyType({path: held[path].raw for path in SOURCE_PATHS})
            client_path = f"scripts/native-qualification/{DRIVERS[context.job]}"
            invoke = getattr(module, "invoke_fixed_admitted_operation")
            result = invoke(operation, context.head_sha, admitted_bytes, held[client_path].raw, digest)
            expected = self._result_type(module, operation)
            exact = type(result) is expected
            exact = exact and result.source_revision == context.head_sha
            exact = exact and result.source_set_sha256 == digest
            _require(exact and HEX64.fullmatch(digest) is not None, "production result admission")
            self.source_set_sha256 = digest
            return self._closed_result(module, operation, result)
        except BaseException as error:
            primary = error
            raise
        finally:
            leases = [source.lease for source in held.values()]
            leases.append(root)
            self.fds.close_reverse(primary, leases)
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
    @staticmethod
    def _stable(reader: Callable[[], object], label: str) -> object:
        prior = reader()
        for _attempt in range(4):
            current = reader()
            if current == prior:
                return current
            prior = current
        raise QualificationError(f"unstable {label}")
    def _descriptor_snapshot_once(self) -> tuple[tuple[object, ...], ...]:
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
                before = os.fstat(number)
                descriptor_flags = fcntl.fcntl(number, fcntl.F_GETFD)
                status_flags = fcntl.fcntl(number, fcntl.F_GETFL)
                after = os.fstat(number)
                _require(_generation(before) == _generation(after), "fd generation drift")
                rows.append((
                    number,
                    descriptor_flags,
                    status_flags,
                    stat.S_IFMT(after.st_mode),
                    after.st_dev,
                    after.st_ino,
                    after.st_rdev,
                    after.st_mode,
                ))
            return tuple(sorted(rows))
        finally:
            lease.close()
    def _descriptor_snapshot(self) -> tuple[tuple[object, ...], ...]:
        value = self._stable(self._descriptor_snapshot_once, "descriptor census")
        _require(type(value) is tuple, "descriptor census type")
        return value
    def _process(self, pid: int) -> tuple[object, ...]:
        first = self._read(f"/proc/{pid}/stat", 65_536)
        executable = os.stat(f"/proc/{pid}/exe", follow_symlinks=True)
        second = self._read(f"/proc/{pid}/stat", 65_536)
        _require(first == second, "process identity drift")
        raw = second.decode("ascii")
        close = raw.rfind(")")
        _require(close > 1 and raw[close + 1:close + 2] == " ", "process stat")
        values = raw[close + 2:].split()
        _require(len(values) >= 20, "process stat fields")
        return (
            pid,
            int(values[1]),
            int(values[2]),
            int(values[3]),
            int(values[19]),
            executable.st_dev,
            executable.st_ino,
        )
    def _children_once(self) -> tuple[object, ...]:
        pending = [os.getpid()]
        edges: list[tuple[int, int]] = []
        rows: list[tuple[object, ...]] = []
        seen: set[int] = set()
        while pending:
            parent = pending.pop(0)
            raw = self._read(f"/proc/{parent}/task/{parent}/children", 65_536).decode("ascii").strip()
            children = [] if not raw else [int(item) for item in raw.split()]
            _require(len(children) == len(set(children)), "duplicate descendant")
            _require(len(seen) + len(children) <= 16, "descendant census bound")
            for child in children:
                _require(child > 0 and child not in seen, "descendant identity")
                identity = self._process(child)
                confirm = self._read(f"/proc/{parent}/task/{parent}/children", 65_536).decode("ascii").split()
                _require(str(child) in confirm, "descendant edge drift")
                seen.add(child)
                edges.append((parent, child))
                rows.append(identity)
                pending.append(child)
        subreaper = ctypes.c_int()
        result = ctypes.CDLL(None, use_errno=True).prctl(37, ctypes.byref(subreaper), 0, 0, 0)
        _require(result == 0, "subreaper observation")
        return os.getpgrp(), os.getsid(0), subreaper.value, tuple(edges), tuple(rows)
    def _children(self) -> tuple[object, ...]:
        value = self._stable(self._children_once, "recursive process census")
        _require(type(value) is tuple, "process census type")
        return value
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
        def namespaces() -> tuple[tuple[str, tuple[int, ...]], ...]:
            return tuple(
                (name, _generation(os.stat(f"/proc/self/ns/{name}", follow_symlinks=True)))
                for name in ("user", "pid", "mnt", "net")
            )
        def paths() -> tuple[tuple[int, ...] | None, tuple[int, ...] | None]:
            return self._path(Path("/tmp/cogs-o2-runtime-v1")), self._path(report_path(context.job).parent)
        readers: dict[str, Callable[[], object]] = {
            "descriptors": self._descriptor_snapshot,
            "children": self._children,
            "paths": paths,
            "mounts": lambda: hashlib.sha256(self._read("/proc/self/mountinfo", 1_048_576)).digest(),
            "namespaces": namespaces,
            "limits": lambda: resource.getrlimit(resource.RLIMIT_NOFILE),
            "checkout": lambda: self._checkout(context),
        }
        observed: dict[str, object] = {}
        failures: list[BaseException] = []
        for name in CLEANUP_KEYS:
            try:
                observed[name] = self._stable(readers[name], name)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise __import__("builtins").ExceptionGroup("common baseline uncertainty", failures)
        return observed
@dataclass(frozen=True)
class CleanupEvidence:
    _session_nonce: bytes; _items: tuple[tuple[str, bool], ...]
    @property
    def values(self) -> Mapping[str, bool]:
        return MappingProxyType(dict(self._items))
    @property
    def restored(self) -> bool:
        return all(value for _name, value in self._items)
@dataclass(frozen=True)
class OperationReceipt:
    _session_nonce: bytes; job: str; source_set_sha256: str
    result_sha256: str; _result: Mapping[str, object]
@dataclass(frozen=True)
class ReportCandidate:
    production_checks: Mapping[str, str]; metadata: list[Mapping[str, object]]
    failure_phase: str | None = None; diagnostics: bytes | None = None
    primary_error: BaseException | None = None
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
    roles = [row["role"] for row in objects]
    _require(2 <= len(objects) <= 127 and roles[:2] == ["executable", "loader"], f"{label} object order")
    _require(all(role == "library" for role in roles[2:]), f"{label} library roles")
    identities = [(row["sha256"], row["size_bytes"]) for row in objects]
    _require(len(identities) == len(set(identities)), f"{label} object identity")
    digest_roles: dict[object, object] = {}
    for row in objects:
        prior = digest_roles.setdefault(row["sha256"], row["role"])
        _require(prior == row["role"], f"{label} digest role conflict")
    providers = [row["soname"] for row in objects if row["soname"] is not None]
    _require(len(providers) == len(set(providers)), f"{label} provider identity")
    needed = [name for row in objects for name in row["needed"]]
    _require(all(1 <= row["size_bytes"] <= OBJECT_LIMIT for row in objects), f"{label} object bounds")
    _require(all(len(row["needed"]) == len(set(row["needed"])) for row in objects), f"{label} needed uniqueness")
    _require(all(name in providers for name in needed), f"{label} unresolved dependency")
    _require(all(row["soname"] in needed for row in objects[2:]), f"{label} extra library")
    libraries = [(row["soname"].encode("ascii"), row["sha256"]) for row in objects[2:]]
    _require(libraries == sorted(libraries), f"{label} library order")
    return [{"needed": row["needed"], "role": row["role"], "sha256": row["sha256"],
             "size": row["size_bytes"], "soname": row["soname"]} for row in objects]
def _validate_a(metadata: list[object]) -> None:
    _require(3 <= len(metadata) <= 128 and type(metadata[-1]) is dict, "A metadata")
    objects, summary = metadata[:-1], metadata[-1]
    expected_ids = [f"python-object-{index}" for index in range(len(objects))]
    _require([row["id"] for row in objects] == expected_ids, "A object ids")
    normalized = _normalize_objects(objects, "A")
    mapped = summary["mapped_sequence"]
    expected_mapped = [{"role": row["role"], "sha256": row["sha256"]} for row in objects]
    _require(mapped == expected_mapped, "A mapped sequence")
    expected_closure = hashlib.sha256(_canonical(normalized)).hexdigest()
    _require(summary["closure_sha256"] == expected_closure, "A closure summary")
    digest_rows = [[row["role"], row["sha256"]] for row in mapped]
    expected_mapping = hashlib.sha256(_canonical(digest_rows)).hexdigest()
    _require(summary["mapping_sha256"] == expected_mapping, "A mapping summary")
def _validate_b(metadata: list[object]) -> None:
    _require(len(metadata) == 3, "B metadata count")
    gzip, zstd, summary = metadata
    _require([gzip["id"], zstd["id"], summary["id"]] == ["gzip", "zstd", "trusted-closure"], "B order")
    tool_views: dict[str, dict[str, object]] = {}
    for row in (gzip, zstd):
        objects = row["objects"]
        normalized = _normalize_objects(objects, f"B {row['id']}")
        mapped = [[item["role"], item["sha256"]] for item in normalized]
        closure = hashlib.sha256(_canonical(normalized)).hexdigest()
        mapping = hashlib.sha256(_canonical(mapped)).hexdigest()
        _require(row["closure_sha256"] == closure, "B closure summary")
        _require(row["mapping_sha256"] == mapping, "B mapping summary")
        _require(row["execution_mapping_sha256"] == mapping, "B execution mapping")
        _require(row["seal_mask"] == 63, "B seal profile")
        executable = objects[0]
        _require(row["source_sha256"] == row["sealed_sha256"] == executable["sha256"], "B sealed source")
        _require(row["source_size_bytes"] == row["sealed_size_bytes"] == executable["size_bytes"], "B sealed size")
        _require(row["output_sha256"] == MARKER_SHA256, "B exact output")
        tool_views[row["id"]] = {"closure_sha256": closure, "objects": normalized,
            "seal_profile": "linux-memfd-exec-seals-v1", "sealed_executable": True, "tool": row["id"]}
    parser = summary["parser"]
    parser_objects = _normalize_objects(parser["objects"], "B parser")
    parser_closure = hashlib.sha256(_canonical(parser_objects)).hexdigest()
    _require(parser["closure_sha256"] == parser_closure, "B parser closure")
    parser_view = {"closure_sha256": parser_closure, "objects": parser_objects, "seal_profile": None,
                   "sealed_executable": False, "tool": "python3-parser"}
    digest_view = [parser_view, tool_views["zstd"], tool_views["gzip"]]
    aggregate = hashlib.sha256(_canonical(digest_view)).hexdigest()
    _require(summary["closure_sha256"] == aggregate, "B aggregate closure")
    _require(gzip["source_sha256"] != zstd["source_sha256"], "B source substitution")
    _require(gzip["mapping_sha256"] != zstd["mapping_sha256"], "B mapping substitution")
def _validate_semantics(value: object, context: WorkflowContext | None = None) -> None:
    _require(type(value) is dict and value.get("job") in DRIVERS, "semantic report")
    report = value
    job = str(value["job"])
    check_ids = tuple(row["id"] for row in report["checks"])
    _require(check_ids == CHECK_IDS[job], "semantic checks")
    passing = all(row["outcome"] == "pass" for row in report["checks"])
    passing = passing and all(report["cleanup"].values())
    _require((report["result"] == "pass") == passing, "semantic result")
    _require((report["failure_phase"] is None) == passing, "semantic failure phase")
    _require((report["diagnostics_sha256"] is None) == passing, "semantic diagnostics")
    source = report["source"]
    envelope = report["envelope"]
    workflow = report["workflow"]
    _require(source["checkout_sha"] == source["head_sha"], "semantic checkout")
    _require(envelope["repository"] == envelope["head_repository"], "semantic repository")
    _require(envelope["github_sha"] == envelope["event_merge_sha"], "semantic envelope")
    _require(envelope["event_name"] == "pull_request" and envelope["run_attempt"] == 1, "semantic event")
    workflow_matches = workflow["job_id"] == JOB_IDS[job]
    workflow_matches = workflow_matches and workflow["workflow_sha"] in {
        source["head_sha"],
        envelope["event_merge_sha"],
    }
    _require(workflow_matches and workflow["blob_sha256"] == _sha256(WORKFLOW), "semantic workflow")
    _require(source["common_blob_sha256"] == _sha256(COMMON), "semantic common")
    driver_path = COMMON.parent / DRIVERS[job]
    _require(source["driver_blob_sha256"] == _sha256(driver_path), "semantic driver")
    metadata = report["metadata"]
    if job == "A" and passing:
        _validate_a(metadata)
    if job == "B" and passing:
        _validate_b(metadata)
    if job == "E" and passing:
        _require(metadata[0]["sha256"] == POLICY_SHA256, "E fixed policy digest")
    if job == "integration" and passing:
        expected_ids = ["closure", "gzip_output", "source_set", "zstd_output"]
        _require([row["id"] for row in metadata] == expected_ids, "integration digest order")
        by_id = {row["id"]: row["sha256"] for row in metadata}
        _require(by_id["gzip_output"] == MARKER_SHA256, "integration gzip output")
        _require(by_id["zstd_output"] == MARKER_SHA256, "integration zstd output")
        _require(by_id["closure"] != by_id["source_set"], "integration digest role substitution")
        _require(MARKER_SHA256 not in {by_id["closure"], by_id["source_set"]}, "integration output substitution")
    if context is not None:
        observed = {name: report[name] for name in ("source", "envelope", "workflow", "runner")}
        _require(job == context.job and observed == _context_value(context), "semantic context")
def _validate(value: object, context: WorkflowContext | None = None) -> None:
    _validate_schema(value)
    _validate_semantics(value, context)
def report_path(job: str) -> Path:
    _require(job in DRIVERS, "report job")
    return Path(f"/tmp/cogs-native-qualification-{job}/report.json")
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
def _rename(directory_fd: int, source: bytes, target: bytes, flags: int) -> None:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    _require(renameat2 is not None, "renameat2 unavailable")
    if renameat2(directory_fd, source, directory_fd, target, flags) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
def _link_held(descriptor: int, directory_fd: int, name: bytes) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.linkat(descriptor, b"", directory_fd, name, 0x1000) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
def _identity(value: os.stat_result) -> dict[str, int]:
    return {"device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode, "owner": value.st_uid,
            "group": value.st_gid, "size": value.st_size}
def _identity_at(directory_fd: int, name: str) -> dict[str, int] | None:
    try:
        return _identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None
def _socket_name(context: object, capability: bytes) -> bytes:
    identity = f"{context.job}:{context.run_id}:{context.run_attempt}:{context.head_sha}".encode()  # type: ignore[attr-defined]
    return b"\0cogs-nq-" + hashlib.sha256(capability + identity).hexdigest()[:48].encode()
class _CustodianClient:
    def __init__(self, control: FdLease, pidfd: FdLease, pid: int):
        self.control = control; self.pidfd = pidfd; self.pid = pid
    def abort(self, primary: BaseException) -> None:
        try:
            self.control.close()
        except BaseException as error:
            primary = __import__("builtins").BaseExceptionGroup("custodian control close", [primary, error])
            _retire_child(self.pid, self.pidfd, primary)
        _retire_child(self.pid, self.pidfd, primary, False)
    def publish(self, raw: bytes) -> None:
        endpoint = socket.socket(fileno=self.control.number)
        try:
            _require(endpoint.send(raw) == len(raw), "custodian report send")
            _require(endpoint.recv(128) == b"PUBLISHED", "custodian publication")
        finally:
            endpoint.detach()
        self.control.close()
def _retire_child(pid: int, pidfd: FdLease, primary: BaseException, terminate: bool = True) -> None:
    failures: list[BaseException] = [primary]
    if terminate:
        try:
            signal.pidfd_send_signal(pidfd.number, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            failures.append(error)
    try:
        waited, _status = os.waitpid(pid, 0)
        _require(waited == pid, "custodian reap")
    except BaseException as error:
        failures.append(error)
    try:
        pidfd.close()
    except BaseException as error:
        failures.append(error)
    raise __import__("builtins").ExceptionGroup("custodian startup", failures)
def _start_custodian(context: WorkflowContext, registry: FdRegistry) -> _CustodianClient:
    left_socket, right_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    left = registry.adopt(left_socket.detach(), "report-custodian-control")
    right = registry.adopt(right_socket.detach(), "report-custodian-child")
    capability = os.urandom(32)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(left.number)
            _custodian_main(right.number, context, capability)
        except BaseException:
            os._exit(1)
        os._exit(0)
    try:
        pidfd = registry.open("report-custodian-pidfd", lambda: os.pidfd_open(pid, 0))
        right.close()
        endpoint = socket.socket(fileno=left.number)
        try:
            _require(endpoint.send(b"RELEASE") == 7, "custodian release send")
            _require(endpoint.recv(64) == b"READY", "custodian preregistration")
        finally:
            endpoint.detach()
        return _CustodianClient(left, pidfd, pid)
    except BaseException as error:
        if "pidfd" in locals():
            _retire_child(pid, pidfd, error)
        try:
            os.kill(pid, signal.SIGKILL)
        finally:
            os.waitpid(pid, 0)
        raise
def _anonymous(registry: FdRegistry, directory: FdLease, purpose: str) -> FdLease:
    temporary = getattr(os, "O_TMPFILE", 0)
    _require(temporary != 0, "O_TMPFILE unavailable")
    return registry.open(purpose, lambda: os.open(".", os.O_RDWR | os.O_CLOEXEC | temporary, 0o600, dir_fd=directory.number))
def _receipt(context: WorkflowContext, capability: bytes, raw: bytes, directory: FdLease, report: FdLease, slot: FdLease) -> dict[str, object]:
    return {
        "version": "cogs.native-report-publication/v1", "state": "publish-intent", "job": context.job,
        "job_id": context.job_id, "run_id": context.run_id, "run_attempt": context.run_attempt,
        "head_sha": context.head_sha, "capability": capability.hex(),
        "capability_sha256": hashlib.sha256(capability).hexdigest(), "socket": _socket_name(context, capability)[1:].decode(),
        "directory": _identity(os.fstat(directory.number)), "report": _identity(os.fstat(report.number)),
        "slot": _identity(os.fstat(slot.number)), "report_sha256": hashlib.sha256(raw).hexdigest(),
        "report_size": len(raw), "workflow_sha256": context.workflow_blob_sha256, "schema_sha256": _sha256(SCHEMA),
        "common_sha256": context.common_blob_sha256, "driver_sha256": context.driver_blob_sha256,
    }
def _open_report_directory(job: str, create: bool) -> tuple[FdRegistry, FdLease, FdLease]:
    registry = FdRegistry()
    parent = registry.open("report-parent",
        lambda: os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
    name = report_path(job).parent.name
    if create:
        os.mkdir(name, 0o700, dir_fd=parent.number)
        os.fsync(parent.number)
    directory = registry.open("report-directory",
        lambda: os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent.number))
    status = os.fstat(directory.number)
    policy = stat.S_ISDIR(status.st_mode) and stat.S_IMODE(status.st_mode) == 0o700
    policy = policy and status.st_uid == os.geteuid() and status.st_gid == os.getegid()
    _require(policy, "report directory policy")
    return registry, parent, directory
def _publish_transaction(context: WorkflowContext, capability: bytes, raw: bytes) -> tuple[FdRegistry, FdLease, FdLease]:
    _validate(_decode(raw), context)
    target = report_path(context.job)
    _require(not os.path.lexists(target.parent), "report baseline")
    registry, parent, directory = _open_report_directory(context.job, True)
    report = _anonymous(registry, directory, "anonymous-report")
    slot = _anonymous(registry, directory, "anonymous-slot")
    receipt = _anonymous(registry, directory, "anonymous-receipt")
    _write_all(report.number, raw)
    os.fsync(report.number)
    _require(_identity(os.fstat(report.number))["size"] == len(raw), "report size")
    os.lseek(report.number, 0, os.SEEK_SET)
    _require(_read_all(report.number, REPORT_LIMIT) == raw, "report readback")
    _write_all(slot.number, capability)
    os.fsync(slot.number)
    intent = _receipt(context, capability, raw, directory, report, slot)
    receipt_raw = _canonical(intent, True)
    _write_all(receipt.number, receipt_raw)
    os.fsync(receipt.number)
    _link_held(receipt.number, directory.number, b".owner.json")
    os.fsync(directory.number)
    _link_held(slot.number, directory.number, b".cleanup.slot")
    os.fsync(directory.number)
    _link_held(report.number, directory.number, b".report.stage")
    os.fsync(directory.number)
    _rename(directory.number, b".report.stage", b"report.json", 1)
    os.fsync(directory.number)
    _require(_identity_at(directory.number, "report.json") == intent["report"], "published report identity")
    _require(set(_enumerate_directory(directory.number, False)) == {".owner.json", ".cleanup.slot", "report.json"}, "published inventory")
    report.close()
    slot.close()
    receipt.close()
    return registry, parent, directory
def _read_receipt(directory: FdLease, job: str) -> dict[str, object]:
    descriptor = os.open(".owner.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory.number)
    try:
        status = os.fstat(descriptor)
        raw = _read_all(descriptor, 16_384)
        _require(_generation(status) == _generation(os.fstat(descriptor)), "receipt generation")
    finally:
        os.close(descriptor)
    value = _decode(raw)
    required = {"version", "state", "job", "job_id", "run_id", "run_attempt", "head_sha", "capability",
        "capability_sha256", "socket", "directory", "report", "slot", "report_sha256", "report_size",
        "workflow_sha256", "common_sha256", "driver_sha256", "schema_sha256"}
    _require(type(value) is dict and set(value) == required, "closed publication receipt")
    receipt_context = value["version"] == "cogs.native-report-publication/v1" and value["job"] == job
    _require(receipt_context and value["job_id"] == JOB_IDS[job], "receipt context")
    capability = bytes.fromhex(value["capability"])
    _require(len(capability) == 32, "receipt capability")
    _require(hashlib.sha256(capability).hexdigest() == value["capability_sha256"], "receipt capability digest")
    _require(_identity(os.fstat(directory.number)) == value["directory"], "receipt directory identity")
    code = (value["workflow_sha256"], value["common_sha256"], value["driver_sha256"], value["schema_sha256"])
    expected = (_sha256(WORKFLOW), _sha256(COMMON), _sha256(COMMON.parent / DRIVERS[job]), _sha256(SCHEMA))
    _require(code == expected, "receipt code identities")
    return value
def _exchange_verified(directory: FdLease, left: str, right: str, expected_left: dict[str, int], expected_right: dict[str, int]) -> None:
    _rename(directory.number, left.encode(), right.encode(), 2)
    left_after = _identity_at(directory.number, left)
    right_after = _identity_at(directory.number, right)
    if left_after == expected_right and right_after == expected_left:
        return
    reversible = left_after is not None and right_after is not None
    reversible = reversible and _identity_at(directory.number, left) == left_after
    reversible = reversible and _identity_at(directory.number, right) == right_after
    if reversible:
        try:
            _rename(directory.number, left.encode(), right.encode(), 2)
        except BaseException:
            pass
    raise QualificationError("report exchange identity uncertainty")
def _finish_owner(directory: FdLease, slot_name: str, slot_identity: dict[str, int]) -> None:
    owner_identity = _identity_at(directory.number, ".owner.json")
    _require(owner_identity is not None, "cleanup owner")
    _exchange_verified(directory, ".owner.json", slot_name, owner_identity, slot_identity)
    os.unlink(slot_name, dir_fd=directory.number)
    os.fsync(directory.number)
    os.unlink(".owner.json", dir_fd=directory.number)
    os.fsync(directory.number)
def _remove_report_directory(job: str, parent: FdLease, directory: FdLease) -> None:
    _require(_enumerate_directory(directory.number, False) == (), "cleanup empty")
    directory.close()
    os.rmdir(report_path(job).parent.name, dir_fd=parent.number)
    os.fsync(parent.number)
    parent.close()
    _require(not os.path.lexists(report_path(job).parent), "report cleanup baseline")
def _cleanup_owned(job: str, registry: FdRegistry, parent: FdLease, directory: FdLease, receipt: dict[str, object]) -> None:
    names = set(_enumerate_directory(directory.number, False))
    report_identity = receipt["report"]
    slot_identity = receipt["slot"]
    if names == {".owner.json", ".cleanup.slot", "report.json"}:
        final = _identity_at(directory.number, "report.json")
        slot = _identity_at(directory.number, ".cleanup.slot")
        if final == report_identity and slot == slot_identity:
            _exchange_verified(directory, "report.json", ".cleanup.slot", report_identity, slot_identity)
        else:
            _require(final == slot_identity and slot == report_identity, "cleanup exchange classification")
        os.unlink(".cleanup.slot", dir_fd=directory.number)
        os.fsync(directory.number)
        _finish_owner(directory, "report.json", slot_identity)
    elif names == {".owner.json", ".cleanup.slot", ".report.stage"}:
        _require(_identity_at(directory.number, ".report.stage") == report_identity, "recovery stage identity")
        _require(_identity_at(directory.number, ".cleanup.slot") == slot_identity, "recovery slot identity")
        _exchange_verified(directory, ".report.stage", ".cleanup.slot", report_identity, slot_identity)
        os.unlink(".cleanup.slot", dir_fd=directory.number)
        os.fsync(directory.number)
        _finish_owner(directory, ".report.stage", slot_identity)
    elif names == {".owner.json", ".cleanup.slot"}:
        _require(_identity_at(directory.number, ".cleanup.slot") == slot_identity, "recovery intent slot")
        _finish_owner(directory, ".cleanup.slot", slot_identity)
    elif names == {".owner.json"}:
        quarantine = _anonymous(registry, directory, "recovery-quarantine")
        quarantine_identity = _identity(os.fstat(quarantine.number))
        _link_held(quarantine.number, directory.number, b".cleanup.slot")
        os.fsync(directory.number)
        quarantine.close()
        _finish_owner(directory, ".cleanup.slot", quarantine_identity)
    elif names == {".owner.json", "report.json"}:
        _require(_identity_at(directory.number, "report.json") == slot_identity, "recovery retired slot")
        _finish_owner(directory, "report.json", slot_identity)
    else:
        raise QualificationError("unclassified publication state")
    _remove_report_directory(job, parent, directory)
def _custodian_main(control_fd: int, context: WorkflowContext, capability: bytes) -> None:
    control = socket.socket(fileno=control_fd)
    _require(control.recv(16) == b"RELEASE", "custodian release")
    parent_gate, child_gate = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    supervisor_pid = os.getpid()
    worker_pid = os.fork()
    if worker_pid == 0:
        parent_gate.close()
        libc = ctypes.CDLL(None, use_errno=True)
        _require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == supervisor_pid, "custodian worker parent")
        _require(child_gate.recv(16) == b"ADMITTED", "custodian worker release")
        child_gate.close()
        _custodian_worker(control, context, capability)
        os._exit(0)
    child_gate.close()
    control.close()
    registry = FdRegistry()
    try:
        worker_pidfd = registry.open("report-worker-pidfd", lambda: os.pidfd_open(worker_pid, 0))
        _require(parent_gate.send(b"ADMITTED") == 8, "custodian worker release send")
        parent_gate.close()
    except BaseException as error:
        if "worker_pidfd" in locals():
            _retire_child(worker_pid, worker_pidfd, error)
        os.kill(worker_pid, signal.SIGKILL)
        os.waitpid(worker_pid, 0)
        raise
    waited, status = os.waitpid(worker_pid, 0)
    worker_pidfd.close()
    _require(waited == worker_pid and status == 0, "custodian worker reap")
def _custodian_worker(control: socket.socket, context: WorkflowContext, capability: bytes) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    listener.bind(_socket_name(context, capability))
    listener.listen(1)
    control.send(b"READY")
    raw = control.recv(REPORT_LIMIT + 1)
    registry, parent, directory = _publish_transaction(context, capability, raw)
    control.send(b"PUBLISHED")
    control.close()
    endpoint, _address = listener.accept()
    peer = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    request = _decode(endpoint.recv(4096))
    expected = {"capability": capability.hex(), "head_sha": context.head_sha, "job": context.job,
                "run_attempt": context.run_attempt, "run_id": context.run_id}
    _require(peer[1:] == (os.geteuid(), os.getegid()) and request == expected, "authenticated cleanup")
    receipt = _read_receipt(directory, context.job)
    _cleanup_owned(context.job, registry, parent, directory, receipt)
    endpoint.send(b"CLEAN")
    endpoint.close()
    listener.close()
def cleanup_report(job: str) -> None:
    target = report_path(job)
    if not target.parent.exists():
        return
    registry, parent, directory = _open_report_directory(job, False)
    if _enumerate_directory(directory.number, False) == ():
        _remove_report_directory(job, parent, directory)
        return
    receipt = _read_receipt(directory, job)
    environment = dict(os.environ)
    expected_keys = {"LC_ALL", "NQ_CLEANUP_RUN_ID", "NQ_CLEANUP_RUN_ATTEMPT", "NQ_CLEANUP_HEAD_SHA"}
    _require(set(environment) == expected_keys and environment["LC_ALL"] == "C", "cleanup environment")
    _require(receipt["run_id"] == _integer(environment["NQ_CLEANUP_RUN_ID"], "cleanup run"), "cleanup run identity")
    _require(receipt["run_attempt"] == _integer(environment["NQ_CLEANUP_RUN_ATTEMPT"], "cleanup attempt"), "cleanup attempt identity")
    _require(receipt["head_sha"] == environment["NQ_CLEANUP_HEAD_SHA"], "cleanup head identity")
    capability = bytes.fromhex(receipt["capability"])
    context = type("CleanupContext", (), {"job": job, "run_id": receipt["run_id"],
        "run_attempt": receipt["run_attempt"], "head_sha": receipt["head_sha"]})()
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    endpoint.settimeout(10)
    try:
        endpoint.connect(_socket_name(context, capability))
    except OSError:
        endpoint.close()
        _cleanup_owned(job, registry, parent, directory, receipt)
        return
    peer_pid = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
    pidfd = os.pidfd_open(peer_pid, 0)
    request = _canonical({
        "capability": capability.hex(), "head_sha": receipt["head_sha"], "job": job,
        "run_attempt": receipt["run_attempt"], "run_id": receipt["run_id"],
    }, True)
    endpoint.send(request)
    try:
        reply = endpoint.recv(64)
    except OSError:
        reply = b""
    endpoint.close()
    poller = __import__("select").poll()
    poller.register(pidfd, 1)
    _require(bool(poller.poll(10_000)), "custodian bounded retirement")
    os.close(pidfd)
    if reply != b"CLEAN":
        _cleanup_owned(job, registry, parent, directory, receipt)
        return
    directory.state = FdState.TRANSFERRED
    parent.state = FdState.TRANSFERRED
    _require(not os.path.lexists(target.parent), "report cleanup baseline")
class NativeSession:
    def __init__(self, context: WorkflowContext, ops: object, custodian: _CustodianClient, nonce: bytes):
        self.context = context
        self.fds = ops.fds
        self._ops = ops
        self._custodian = custodian
        self.source_set_sha256 = ops.source_set_sha256
        self._nonce = nonce
        self._operation_started = False
        self._receipt: OperationReceipt | None = None
        self._before = dict(ops.observe(context))
        _require(tuple(self._before) == CLEANUP_KEYS, "baseline domains")
        _require(self._before["paths"] == (None, None), "named path baseline")
        self._poisoned: set[str] = set()
        self._evidence: CleanupEvidence | None = None
        self._published = False
    @classmethod
    def begin(cls, expected_job: str, driver_file: str | Path) -> "NativeSession":
        context = WorkflowContext.from_environ(expected_job, driver_file)
        registry = FdRegistry()
        custodian = _start_custodian(context, registry)
        try:
            return cls(context, SystemCommonOps(registry), custodian, os.urandom(32))
        except BaseException as error:
            custodian.abort(error)
    @classmethod
    def _begin_with_ops(cls, context: WorkflowContext, ops: object, custodian: _CustodianClient) -> "NativeSession":
        return cls(context, ops, custodian, os.urandom(32))
    @staticmethod
    def _freeze(value: object) -> object:
        if type(value) is dict:
            return MappingProxyType({key: NativeSession._freeze(item) for key, item in value.items()})
        if type(value) is list:
            return tuple(NativeSession._freeze(item) for item in value)
        _require(type(value) in (str, int, bool, type(None)), "operation receipt value")
        return value
    @staticmethod
    def _thaw(value: object) -> object:
        if isinstance(value, Mapping):
            return {key: NativeSession._thaw(item) for key, item in value.items()}
        if type(value) is tuple:
            return [NativeSession._thaw(item) for item in value]
        return value
    def run_fixed_operation(self, operation: str) -> dict[str, object]:
        exact = operation == self.context.job and not self._operation_started
        exact = exact and self._evidence is None and not self._published
        _require(exact, "fixed operation binding")
        self._operation_started = True
        try:
            result = self._ops.run_fixed_operation(self.context, operation)
        except BaseException as error:
            self._custodian.abort(error)
            raise
        source_digest = self._ops.source_set_sha256
        _require(type(result) is dict and HEX64.fullmatch(source_digest) is not None, "closed production operation")
        frozen = self._freeze(result)
        _require(isinstance(frozen, Mapping), "operation result receipt")
        self._receipt = OperationReceipt(
            self._nonce, operation, source_digest, hashlib.sha256(_canonical(result)).hexdigest(), frozen,
        )
        self.source_set_sha256 = source_digest
        return result
    def qualify_fixed_descriptor_primitives(self) -> dict[str, object]:
        return self.run_fixed_operation("C")
    def qualify_fixed_process_lifecycle(self) -> dict[str, object]:
        return self.run_fixed_operation("D")
    def mark_uncertain(self, domains: tuple[str, ...], error: BaseException) -> None:
        exact = self._evidence is None and domains and all(domain in CLEANUP_KEYS for domain in domains)
        _require(bool(exact), "cleanup uncertainty")
        _require(isinstance(error, BaseException), "cleanup uncertainty error")
        self._poisoned.update(domains)
    def settle_native_phase(self) -> CleanupEvidence:
        _require(self._receipt is not None, "operation receipt required for settlement")
        _require(self._evidence is None and not self._published, "native settlement state")
        after: Mapping[str, object] = {}
        observation_error: BaseException | None = None
        try:
            after = self._ops.observe(self.context)
        except BaseException as error:
            observation_error = error
        values = tuple(
            (key, observation_error is None and key not in self._poisoned and after.get(key) == self._before[key])
            for key in CLEANUP_KEYS
        )
        if self.fds.uncertain:
            values = tuple((key, False if key == "descriptors" else value) for key, value in values)
        self._evidence = CleanupEvidence(self._nonce, values)
        return self._evidence
    def _bind_candidate(self, candidate: ReportCandidate) -> None:
        _require(self._receipt is not None and self._receipt.job == self.context.job, "operation receipt profile")
        result = self._thaw(self._receipt._result)
        _require(type(result) is dict and hashlib.sha256(_canonical(result)).hexdigest() == self._receipt.result_sha256, "operation receipt integrity")
        checks = dict(candidate.production_checks)
        _require(tuple(checks) == PRODUCTION_CHECK_IDS[self.context.job], "production check inventory")
        _require(set(checks.values()) == {"pass"}, "operation result check binding")
        metadata = [dict(row) for row in candidate.metadata]
        job = self.context.job
        if job == "A":
            objects = [{key: value for key, value in row.items() if key not in {"kind", "id"}} for row in metadata[:-1]]
            summary = metadata[-1]
            expected = (result["objects"], result["closure_sha256"], result["mapping_sha256"], result["mapped"])
            _require((objects, summary["closure_sha256"], summary["mapping_sha256"], summary["mapped_sequence"]) == expected, "A operation binding")
        elif job == "B":
            expected_summary = {"kind": "summary", "id": "trusted-closure", "closure_sha256": result["closure_sha256"], "parser": result["parser"]}
            _require(metadata[:2] == result["tools"] and metadata[2] == expected_summary, "B operation binding")
        elif job == "E":
            expected = [{"id": "sandbox-policy", "role": "policy", "sha256": result["seccomp_program_sha256"], "size_bytes": 0}]
            _require(metadata == expected and result["seccomp_program_sha256"] == POLICY_SHA256, "E operation binding")
        elif job == "integration":
            names = ("closure_sha256", "gzip_output_sha256", "source_set_sha256", "zstd_output_sha256")
            expected = [{"id": name.removesuffix("_sha256"), "role": "digest", "sha256": result[name], "size_bytes": 0} for name in names]
            _require(metadata == expected and result["source_set_sha256"] == self._receipt.source_set_sha256, "integration operation binding")
        else:
            observations = [value for name, value in result.items() if name not in {"version", "source_revision", "source_set_sha256"}]
            _require(metadata == [] and observations and all(value is True for value in observations), "metadata-free operation binding")
        _require(candidate.primary_error is None and candidate.failure_phase is None, "operation candidate failure substitution")
        _require(candidate.diagnostics is None, "operation candidate diagnostics substitution")
    def publish(self, candidate: ReportCandidate) -> Path:
        exact = self._evidence is not None and self._evidence._session_nonce == self._nonce
        _require(exact and not self._published and type(candidate) is ReportCandidate, "report session state")
        self._bind_candidate(candidate)
        cleanup = dict(self._evidence.values)
        derived = {"cleanup_restored": all(cleanup.values()), "checkout_unchanged": cleanup["checkout"]}
        production = dict(candidate.production_checks)
        checks = {
            name: ("pass" if derived[name] else "fail") if name in derived else production[name]
            for name in CHECK_IDS[self.context.job]
        }
        passing = all(value == "pass" for value in checks.values()) and all(cleanup.values())
        _require(passing, "exact operation report cannot publish pass substitution")
        report = {
            "authority": AUTHORITY,
            "checks": [{"id": key, "outcome": value} for key, value in checks.items()],
            "cleanup": cleanup,
            "diagnostics_sha256": None,
            "failure_phase": None,
            "job": self.context.job,
            "metadata": [dict(row) for row in candidate.metadata],
            "result": "pass",
            "version": VERSION,
            **_context_value(self.context),
        }
        raw = _canonical(report, True)
        _require(len(raw) <= REPORT_LIMIT and _decode(raw) == report, "report encoding")
        _validate(report, self.context)
        self._custodian.publish(raw)
        self._published = True
        return report_path(self.context.job)
def _main(arguments: list[str]) -> int:
    if arguments == ["--eligibility"]:
        evaluate_eligibility(os.environ)
    elif arguments == ["--require-final-results"]:
        require_final_results(os.environ)
    elif len(arguments) == 2 and arguments[0] == "--cleanup" and arguments[1] in DRIVERS:
        cleanup_report(arguments[1])
    else:
        raise QualificationError("common entry")
    return 0
if __name__ == "__main__":
    try:
        exit_code = _main(sys.argv[1:])
    except Exception:
        os.write(2, b"native-common-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)
