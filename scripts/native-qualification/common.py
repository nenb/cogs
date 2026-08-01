#!/usr/bin/python3
from __future__ import annotations
import ctypes, fcntl, hashlib, hmac, json, os, platform, re, resource, select, signal, socket, stat, struct, subprocess, sys, time
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping
VERSION, AUTHORITY = "cogs.native-qualification/v1alpha1", "exact-run-native-qualification"
ROOT = Path(__file__).resolve().parents[2]
WORKFLOW, FAST_B_WORKFLOW = ROOT / ".github/workflows/ci.yml", ROOT / ".github/workflows/outcome-two-native-b.yml"
COMMON = ROOT / "scripts/native-qualification/common.py"
SCHEMA, REPORT_LIMIT, OBJECT_LIMIT = ROOT / "schemas/native-qualification-report-v1alpha1.json", 32_768, 134_217_728
MARKER_SHA256 = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8"
POLICY_SHA256 = "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2"
SOURCE_PATHS = ("deploy/aws-feasibility/remote/completion_elf.py", "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", "schemas/trusted-runtime-closure-v1.json")
LAUNCHER_PATH = SOURCE_PATHS[2]
CLEANUP_KEYS = ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")
DRIVERS = dict(zip(("A", "B", "C", "D", "E", "integration"), ("job-a-runtime-mappings.py", "job-b-compression.py",
    "job-c-descriptors.py", "job-d-process-lifecycle.py", "job-e-sandbox.py", "thin-integration.py")))
OPERATION_MODES = dict(zip(DRIVERS, ("mapping", "compression", "descriptor", "lifecycle", "sandbox", "runtime")))
ADMISSION_VERSIONS = dict(zip(DRIVERS, (
    "cogs.runtime-source-admission/mapping-v1", "cogs.runtime-source-admission/compression-v1",
    "cogs.runtime-source-admission/descriptor-v1", "cogs.runtime-source-admission/lifecycle-v1",
    "cogs.runtime-source-admission/sandbox-v1", "cogs.runtime-source-admission/v1",
)))
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
RUNTIME_OBSERVATIONS = tuple((
    "mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact "
    "namespace_handles_exact pid_one supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero inheritable_capabilities_zero "
    "bounding_capabilities_zero ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact "
    "seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route root_readonly_noexec root_has_no_proc host_paths_absent "
    "checkout_absent limits_exact descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored namespaces_released "
    "namespace_handles_released").split())
DESCRIPTOR_OBSERVATIONS = tuple((
    "nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact inheritance_exact "
    "limit_restored descriptors_restored children_reaped"
).split())
LIFECYCLE_OBSERVATIONS = tuple((
    "pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated "
    "session_owned process_group_owned credentialed_pidfd_transfer stable_descendant_census adoption_exact "
    "term_kill_bounded siginfo_exact all_reaped subreaper_restored descriptors_restored"
).split())
SANDBOX_OBSERVATIONS = tuple((
    "user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact pid_one capabilities_zero "
    "noroot_locked no_new_privs seccomp_installed seccomp_mode_exact seccomp_program_exact seccomp_denials_exact no_acquisition_route "
    "root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent descriptors_restored children_reaped descendants_reaped mounts_restored "
    "paths_restored namespaces_released namespace_handles_released").split())
ENV_KEYS = frozenset(("LC_ALL PYTHONDONTWRITEBYTECODE PYTHONHASHSEED NQ_EVENT_NAME NQ_REPOSITORY NQ_HEAD_REPOSITORY "
                      "NQ_HEAD_SHA NQ_ENVELOPE_SHA NQ_WORKFLOW_SHA NQ_REF NQ_DEFAULT_BRANCH NQ_REF_PROTECTED NQ_JOB_ID "
                      "NQ_RUN_ID NQ_RUN_ATTEMPT NQ_RUNNER_VERSION").split())
RESULT_JOBS = ("QUALITY", "ELIGIBILITY", "A", "B", "C", "D", "E", "INTEGRATION")
FINAL_KEYS = frozenset(["LC_ALL", "PYTHONCOERCECLOCALE"] + [f"{name}_RESULT" for name in RESULT_JOBS]
                       + [f"{name}_{phase}" for name in RESULT_JOBS[2:] for phase in ("UPLOAD", "CLEANUP")])
HEX40, HEX64 = re.compile(r"[0-9a-f]{40}\Z"), re.compile(r"[0-9a-f]{64}\Z")
SAFE, REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z"), re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
class QualificationError(RuntimeError): pass
def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)
def _error_label(error: BaseException, limit: int = 480) -> str:
    pending, labels = [error], []
    while pending and len(labels) < 8:
        current = pending.pop(0)
        nested = getattr(current, "exceptions", ())
        if nested: pending[:0] = list(nested[:8 - len(labels)])
        else:
            detail = str(current) if isinstance(current, QualificationError) else f"{type(current).__name__}-{getattr(current, 'errno', 0)}"
            labels.append(re.sub(r"[^A-Za-z0-9_.-]", "-", detail)[:96])
    return "--".join(labels)[:limit] or "unknown"
def _integer(value: str, name: str) -> int:
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None, name)
    return int(value)
def _generation(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_mode, value.st_uid, value.st_gid, value.st_dev, value.st_ino, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
def _read_source(path: Path, limit: int) -> tuple[bytes, tuple[int, ...]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "source object")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.pread(descriptor, min(65_536, before.st_size - len(raw)), len(raw))
            _require(bool(block), "source short read")
            raw.extend(block)
        generation = _generation(before)
        _require(generation == _generation(os.fstat(descriptor)), "source generation")
        return bytes(raw), generation
    finally:
        os.close(descriptor)
def _sha256(path: Path) -> str:
    return hashlib.sha256(_read_source(path, 2_000_000)[0]).hexdigest()
def _canonical(value: object, newline: bool = False) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + (b"\n" if newline else b"")
@dataclass(frozen=True)
class WorkflowContext:
    job: str
    repository: str
    head_repository: str
    head_sha: str
    envelope_sha: str
    workflow_sha: str
    ref: str
    default_branch: str
    job_id: str
    run_id: int
    run_attempt: int
    ref_protected: bool
    runner_version: str
    kernel_release: str
    architecture: str
    workflow_blob_sha256: str
    driver_blob_sha256: str
    common_blob_sha256: str
    schema_blob_sha256: str
    schema_bytes: bytes
    source_generations: tuple[tuple[int, ...], ...] = ()
    workflow_path: str = ".github/workflows/ci.yml"
    @classmethod
    def from_environ(cls, expected_job: str, driver_file: str | Path) -> "WorkflowContext":
        environment = dict(os.environ)
        fast_keys = ENV_KEYS | {"NQ_WORKFLOW_PATH"}
        fast = expected_job == "B" and set(environment) == fast_keys
        _require(expected_job in DRIVERS and (set(environment) == ENV_KEYS or fast), "fixed environment")
        workflow_path = FAST_B_WORKFLOW if fast else WORKFLOW
        if fast:
            _require(environment["NQ_WORKFLOW_PATH"] == ".github/workflows/outcome-two-native-b.yml", "fixed workflow path")
        _require(environment["LC_ALL"] == "C" and environment["PYTHONDONTWRITEBYTECODE"] == "1", "runtime environment")
        _require(environment["PYTHONHASHSEED"] == "0" and environment["NQ_EVENT_NAME"] == "workflow_dispatch", "event environment")
        expected_driver = COMMON.parent / DRIVERS[expected_job]
        _require(Path(driver_file).absolute() == expected_driver and expected_driver.is_file(), "fixed driver")
        hashes = [environment[name] for name in ("NQ_HEAD_SHA", "NQ_ENVELOPE_SHA", "NQ_WORKFLOW_SHA")]
        _require(all(HEX40.fullmatch(value) for value in hashes), "source identity")
        _require(environment["NQ_WORKFLOW_SHA"] == environment["NQ_ENVELOPE_SHA"], "workflow source")
        repository = environment["NQ_REPOSITORY"]
        _require(REPOSITORY.fullmatch(repository) is not None and environment["NQ_HEAD_REPOSITORY"] == repository, "same repository")
        default_branch, protected = environment["NQ_DEFAULT_BRANCH"], environment["NQ_REF_PROTECTED"] == "true"
        _require(SAFE.fullmatch(default_branch) is not None and protected, "protected default branch")
        _require(environment["NQ_REF"] == f"refs/heads/{default_branch}", "dispatch ref")
        _require(environment["NQ_JOB_ID"] == JOB_IDS[expected_job] and SAFE.fullmatch(environment["NQ_RUNNER_VERSION"]) is not None, "workflow job")
        _require((attempt := _integer(environment["NQ_RUN_ATTEMPT"], "run attempt")) == 1, "first attempt")
        kernel, architecture = platform.release(), platform.machine()
        _require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.+]*", kernel) is not None and architecture == "x86_64", "runner platform")
        schema_bytes, schema_generation = _read_source(SCHEMA, 100_000)
        source_receipts = tuple(_read_source(path, 2_000_000) for path in (workflow_path, expected_driver, COMMON))
        source_digests = tuple(hashlib.sha256(raw).hexdigest() for raw, _generation_receipt in source_receipts)
        return cls(
            expected_job, repository, repository, *hashes, environment["NQ_REF"], default_branch,
            environment["NQ_JOB_ID"], _integer(environment["NQ_RUN_ID"], "run id"), attempt, protected,
            environment["NQ_RUNNER_VERSION"], kernel, architecture, *source_digests, hashlib.sha256(schema_bytes).hexdigest(), schema_bytes,
            tuple(generation for _raw, generation in source_receipts) + (schema_generation,), workflow_path.relative_to(ROOT).as_posix())
def _context_value(context: WorkflowContext) -> dict[str, object]:
    source = {"checkout_sha": context.head_sha, "driver_blob_sha256": context.driver_blob_sha256,
              "head_sha": context.head_sha, "common_blob_sha256": context.common_blob_sha256}
    envelope = {"default_branch": context.default_branch, "event_name": "workflow_dispatch",
                "github_sha": context.envelope_sha, "head_repository": context.head_repository,
                "ref": context.ref, "ref_protected": context.ref_protected, "repository": context.repository,
                "run_attempt": context.run_attempt, "run_id": context.run_id}
    workflow = {"blob_sha256": context.workflow_blob_sha256, "job_id": context.job_id, "path": context.workflow_path, "workflow_sha": context.workflow_sha}
    runner = {"architecture": context.architecture, "image": "ubuntu-24.04", "image_version": context.runner_version, "kernel_release": context.kernel_release}
    return {"source": source, "envelope": envelope, "workflow": workflow, "runner": runner}
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
        self._numbers.add(number)
        try:
            self._leases.append(lease)
        except BaseException:
            self._numbers.remove(number)
            raise
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
        if lease.state is FdState.CLOSED:
            return
        if lease.state is FdState.CLOSE_UNCERTAIN:
            assert lease.close_error is not None
            raise lease.close_error
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
    number: int
    purpose: str
    registry: FdRegistry
    state: FdState = FdState.OWNED
    close_error: BaseException | None = None
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
    names: list[str] = []
    offset = 0
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
    names: list[str] = []
    total = 0
    for calls in range(_GETDENTS_CALLS + 1):
        raw = _getdents(descriptor)
        if not raw:
            _require(calls <= _GETDENTS_CALLS, "getdents call bound")
            _require(len(names) <= _GETDENTS_ENTRIES and len(names) == len(set(names)), "directory entries")
            return tuple(names)
        _require(calls < _GETDENTS_CALLS, "getdents EOF bound")
        total += len(raw)
        _require(total <= _GETDENTS_BYTES, "getdents byte bound")
        names.extend(_parse_dirents(raw, numeric))
        _require(len(names) <= _GETDENTS_ENTRIES, "getdents entry bound")
    raise QualificationError("getdents64 incomplete")
@dataclass(frozen=True)
class _HeldSource:
    path: str
    lease: FdLease
    raw: bytes
    generation: tuple[int, ...]
    oid: str = ""
class SystemCommonOps:
    def __init__(self, fds: FdRegistry):
        self.fds = fds
        self.source_set_sha256 = ""
        self._descriptor_anchors: dict[int, FdLease] | None = None
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
                _require(next_directory.state is FdState.OWNED, "held source directory Lease adoption")
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
            for path, source in tuple(held.items()):
                _require(self._blob_matches(source.raw, tree[path]), "held source Git blob")
                _require(source.generation == _generation(os.fstat(source.lease.number)), "held source admission drift")
                held[path] = _HeldSource(source.path, source.lease, source.raw, source.generation, tree[path])
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
    def _sealed(self, raw: bytes, purpose: str) -> FdLease:
        lease = self.fds.open(purpose, lambda: os.memfd_create(purpose, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING))
        try:
            _write_all(lease.number, raw)
            os.lseek(lease.number, 0, os.SEEK_SET)
            fcntl.fcntl(lease.number, fcntl.F_ADD_SEALS, 0x1f)
            _require(fcntl.fcntl(lease.number, fcntl.F_GET_SEALS) == 0x1f, "sealed launcher input")
            return lease
        except BaseException as primary:
            self.fds.close_reverse(primary, [lease])
            raise
    def _pipe(self, left: str, right: str) -> tuple[FdLease, FdLease]:
        numbers = os.pipe2(os.O_CLOEXEC)
        try:
            first = self.fds.adopt(numbers[0], left)
        except BaseException:
            os.close(numbers[0])
            os.close(numbers[1])
            raise
        try:
            return first, self.fds.adopt(numbers[1], right)
        except BaseException as error:
            os.close(numbers[1])
            self.fds.close_reverse(error, [first])
            raise
    @staticmethod
    def _capsule(context: WorkflowContext, held: Mapping[str, _HeldSource], digest: str) -> tuple[bytes, bytes]:
        client_path = f"scripts/native-qualification/{DRIVERS[context.job]}"
        rows = [{"oid": held[path].oid, "path": path, "sha256": hashlib.sha256(held[path].raw).hexdigest(),
                 "size": len(held[path].raw)} for path in SOURCE_PATHS]
        client = held[client_path]
        admission = _canonical({
            "bootstrap_sha256": hashlib.sha256(held[LAUNCHER_PATH].raw).hexdigest(),
            "client_sha256": hashlib.sha256(client.raw).hexdigest(), "revision": context.head_sha,
            "source_set_sha256": digest, "version": ADMISSION_VERSIONS[context.job],
        }, True)
        header = {"client": {"oid": client.oid, "path": client_path, "sha256": hashlib.sha256(client.raw).hexdigest(),
                             "size": len(client.raw)}, "operation": OPERATION_MODES[context.job], "revision": context.head_sha,
                  "sources": rows, "version": "cogs.held-source-set/v1"}
        payload = b"".join(held[path].raw for path in SOURCE_PATHS) + client.raw
        return admission, _canonical(header, True) + payload
    def _issue_cli(self, launcher_raw: bytes, admission_raw: bytes, capsule_raw: bytes) -> bytes:
        allocated: list[FdLease] = []
        try:
            launcher = self._sealed(launcher_raw, "held-launcher")
            allocated.append(launcher)
            admission = self._sealed(admission_raw, "fixed-admission")
            allocated.append(admission)
            capsule = self._sealed(capsule_raw, "sealed-capsule")
            allocated.append(capsule)
            output_read, output_write = self._pipe("launcher-output", "launcher-child-output")
            allocated.extend((output_read, output_write))
            error_read, error_write = self._pipe("launcher-error", "launcher-child-error")
            allocated.extend((error_read, error_write))
            gate_read, gate_write = self._pipe("launcher-child-gate", "launcher-gate")
            allocated.extend((gate_read, gate_write))
        except BaseException as primary:
            self.fds.close_reverse(primary, allocated)
            raise
        try:
            pid = os.fork()
        except BaseException as primary:
            self.fds.close_reverse(primary, allocated)
            raise
        if pid == 0:
            try:
                _require(os.read(gate_read.number, 1) == b"A", "launcher admission gate")
                sources = ((launcher.number, 0), (output_write.number, 1), (error_write.number, 2),
                           (admission.number, 3), (capsule.number, 4))
                for source, target in sources:
                    os.dup2(source, target, inheritable=True)
                os.closerange(5, min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 1_048_576))
                os.execve("/usr/bin/python3", ("/usr/bin/python3", "-I", "-B", "-"), {})
            except BaseException as error:
                os.write(2, f"common-launcher-bootstrap-{_error_label(error, 96)}\n".encode())
                os._exit(127)
        pidfd: FdLease | None = None
        reaped = False
        try:
            pidfd = self.fds.open("held-launcher-pidfd", lambda: os.pidfd_open(pid, 0))
            _require(pidfd.state is FdState.OWNED, "held launcher pidfd Lease adoption")
            self.fds.close_reverse(None, [gate_read, output_write, error_write])
            _write_all(gate_write.number, b"A")
            gate_write.close()
            for lease in (output_read, error_read):
                os.set_blocking(lease.number, False)
            buffers = {output_read.number: bytearray(), error_read.number: bytearray()}
            active = set(buffers)
            deadline = time.monotonic() + 600
            while active and time.monotonic() < deadline:
                ready, _, _ = select.select(tuple(active), (), (), 0.1)
                for descriptor in ready:
                    try:
                        block = os.read(descriptor, 65_536)
                    except BlockingIOError:
                        continue
                    if block:
                        buffers[descriptor].extend(block)
                        _require(len(buffers[descriptor]) <= 131_072, "launcher output bound")
                    else:
                        active.remove(descriptor)
            _require(not active, "launcher output EOF")
            status = _bounded_reap(pid, pidfd.number)
            reaped = True
            output, diagnostics = bytes(buffers[output_read.number]), bytes(buffers[error_read.number])
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                token = diagnostics.removesuffix(b"\n") if re.fullmatch(rb"[A-Za-z0-9_.-]{1,96}\n", diagnostics) else (
                    b"sha256-" + hashlib.sha256(diagnostics).hexdigest().encode())
                state = f"exit-{os.WEXITSTATUS(status)}" if os.WIFEXITED(status) else f"signal-{os.WTERMSIG(status)}"
                detail = f"held-launcher-{state}-stdout-{len(output)}-stderr-{len(diagnostics)}-{token.decode()}"
                fixed_token = token.startswith((b"runtime-launcher-root-", b"runtime-launcher-closure-", b"runtime-launcher-cleanup-"))
                expose_token = fixed_token or (len(detail) > 96 and token.startswith(b"runtime-launcher-"))
                raise QualificationError(token.decode() if expose_token else detail)
            _require(not diagnostics, "held launcher diagnostics")
            return output
        except BaseException as primary:
            failures = [primary]
            if not reaped:
                _creator_retire(pid, pidfd, failures)
            raise BaseExceptionGroup("held launcher transaction", failures)
        finally:
            self.fds.close_reverse(None, [error_read, output_read, gate_write, gate_read, error_write, output_write,
                                          capsule, admission, launcher])
            if pidfd is not None and pidfd.state is FdState.OWNED:
                pidfd.close()
    @staticmethod
    def _decode_cli(raw: bytes) -> dict[str, object]:
        def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
            value: dict[str, object] = {}
            for name, item in rows:
                _require(name not in value, "duplicate operation result key")
                value[name] = item
            return value
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
        _require(type(value) is dict and len(raw) <= 131_072 and raw == _canonical(value, True), "canonical operation result")
        return value
    def run_fixed_operation(self, context: WorkflowContext, operation: str) -> dict[str, object]:
        _require(operation == context.job, "fixed CLI operation")
        root = self.fds.open("held-source-root",
            lambda: os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
        _require(root.state is FdState.OWNED, "held source root Lease adoption")
        held: dict[str, _HeldSource] = {}
        primary, stage = None, "held-source-admission"
        try:
            stage, (held, digest) = "held-source-admission", self._admit_sources(context, root)
            stage, (admission, capsule) = "capsule-build", self._capsule(context, held, digest)
            stage, result = "launcher-transaction", self._decode_cli(self._issue_cli(held[LAUNCHER_PATH].raw, admission, capsule))
            stage = "result-admission"
            exact = result.get("source_revision") == context.head_sha and result.get("source_set_sha256") == digest
            _require(exact and HEX64.fullmatch(digest) is not None, "production result admission")
            self.source_set_sha256 = digest
            return result
        except BaseException as error:
            primary = QualificationError(f"production-{stage}-{_error_label(error, 320)}")
            raise primary from error
        finally:
            self.fds.close_reverse(primary, [*[source.lease for source in held.values()], root])
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
        observations = tuple(reader() for _attempt in range(3))
        _require(all(current == observations[0] for current in observations[1:]), f"unstable {label}")
        return observations[0]
    def _descriptor_snapshot_once(self) -> tuple[tuple[object, ...], ...]:
        lease = self.fds.open("fd-enumerator",
            lambda: os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
        try:
            names = _enumerate_directory(lease.number, True)
            _require(names.count(str(lease.number)) == 1, "fd enumerator identity")
            anchor_numbers = set() if self._descriptor_anchors is None else {
                anchor.number for anchor in self._descriptor_anchors.values()
            }
            numbers = tuple(sorted(int(name) for name in names if int(name) != lease.number and int(name) not in anchor_numbers))
            if self._descriptor_anchors is None:
                self._descriptor_anchors = {}
                for number in numbers:
                    anchor = self.fds.open("descriptor-generation-anchor",
                        lambda number=number: fcntl.fcntl(number, fcntl.F_DUPFD_CLOEXEC, 10_000))
                    _require(anchor.state is FdState.OWNED, "descriptor anchor Lease adoption")
                    self._descriptor_anchors[number] = anchor
            _require(tuple(self._descriptor_anchors) == numbers, "descriptor number generation")
            rows = []
            for number in numbers:
                before = os.fstat(number)
                descriptor_flags = fcntl.fcntl(number, fcntl.F_GETFD)
                status_flags = fcntl.fcntl(number, fcntl.F_GETFL)
                after = os.fstat(number)
                anchor = self._descriptor_anchors[number]
                anchor_generation = _generation(os.fstat(anchor.number))
                exact = _generation(before) == _generation(after) == anchor_generation
                _require(exact and fcntl.fcntl(anchor.number, fcntl.F_GETFL) == status_flags, "open descriptor generation drift")
                rows.append((number, anchor.number, _generation(after), after.st_rdev, descriptor_flags, status_flags))
            return tuple(rows)
        finally:
            lease.close()
    def _descriptor_snapshot(self) -> tuple[tuple[object, ...], ...]:
        value = self._stable(self._descriptor_snapshot_once, "descriptor census")
        _require(type(value) is tuple, "descriptor census type")
        return value
    def release_descriptor_anchors(self) -> None:
        if self._descriptor_anchors is not None:
            self.fds.close_reverse(None, list(self._descriptor_anchors.values()))
            self._descriptor_anchors = {}
    def _process(self, pid: int) -> tuple[object, ...]:
        raw = self._read(f"/proc/{pid}/stat", 65_536).decode("ascii")
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
                (name, (info.st_mode, info.st_dev, info.st_ino, info.st_rdev))
                for name in ("user", "pid", "mnt", "net") for info in (os.stat(f"/proc/self/ns/{name}", follow_symlinks=True),)
            )
        def paths() -> tuple[tuple[int, ...] | None, tuple[int, ...] | None, tuple[int, ...] | None]:
            return (
                self._path(Path("/tmp/cogs-o2-runtime-v1")),
                self._path(report_path(context.job).parent),
                self._path(_retired_report_path(context.job)),
            )
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
                failures.append(QualificationError(f"{name} baseline {type(error).__name__}-{getattr(error, 'errno', 0)}"))
        if failures:
            raise __import__("builtins").ExceptionGroup("common baseline uncertainty", failures)
        return observed
@dataclass(frozen=True)
class CleanupEvidence:
    _session_nonce: bytes
    _items: tuple[tuple[str, bool], ...]
    @property
    def values(self) -> Mapping[str, bool]:
        return MappingProxyType(dict(self._items))
    @property
    def restored(self) -> bool:
        return all(value for _name, value in self._items)
@dataclass(frozen=True)
class OperationReceipt:
    _session_nonce: bytes
    _seal: object
    job: str
    source_set_sha256: str
    result_sha256: str
    _result: Mapping[str, object]
    _checks: tuple[tuple[str, str], ...]
    _metadata: tuple[Mapping[str, object], ...]
@dataclass(frozen=True)
class ReportCandidate:
    failure_phase: str | None = None
    diagnostics: bytes | None = None
    primary_error: BaseException | None = None
def _schema_error(node: object, value: object, root: Mapping[str, object], place: str = "$") -> None:
    if node is True: return
    _require(node is not False and type(node) is dict, f"schema {place}")
    rule = node
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
            _require(index < len(value), f"schema prefix {place}")
            _schema_error(child, value[index], root, f"{place}[{index}]")
        for index in range(len(prefix), len(value)): _schema_error(rule.get("items", True), value[index], root, f"{place}[{index}]")
        if rule.get("uniqueItems"):
            encoded = [_canonical(item) for item in value]
            _require(len(encoded) == len(set(encoded)), f"schema unique {place}")
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
            _require(name not in value, "duplicate JSON key")
            value[name] = item
        return value
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    _require(raw == _canonical(value, True) and len(raw) <= REPORT_LIMIT, "canonical report")
    return value
def _validate_schema(value: object, admitted_schema: bytes | None = None) -> None:
    if admitted_schema is None:
        raw, _schema_generation = _read_source(SCHEMA, 100_000)
    else:
        raw = admitted_schema
        _require(len(raw) <= 100_000, "admitted schema bound")
    schema_value = json.loads(raw)
    _require(type(schema_value) is dict, "tracked schema")
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
def _closed_fields(result: object, names: tuple[str, ...], version: str, receipt: OperationReceipt) -> dict[str, object]:
    _require(type(result) is dict and set(result) == set(names), "operation result inventory")
    value = result
    identity = value["version"], value["source_revision"], value["source_set_sha256"]
    expected = version, value["source_revision"], receipt.source_set_sha256
    _require(identity == expected, "operation result identity")
    _require(HEX40.fullmatch(str(identity[1])) is not None, "operation result revision")
    return value
def _true_observations(result: Mapping[str, object], names: tuple[str, ...]) -> None:
    _require(all(type(result[name]) is bool and result[name] is True for name in names), "operation observation")
def _derive_operation(receipt: OperationReceipt, head_sha: str) -> tuple[tuple[tuple[str, str], ...], tuple[Mapping[str, object], ...]]:
    result = NativeSession._thaw(receipt._result)
    _require(type(result) is dict, "operation result receipt")
    _require(result.get("source_revision") == head_sha, "operation result head")
    metadata: list[Mapping[str, object]] = []
    job = receipt.job
    if job == "A":
        names = (
            "version", "source_revision", "source_set_sha256", "closure_sha256", "mapping_sha256", "objects", "mapped",
            "mapped_generations_exact", "mapping_stable", "helper_reaped", "descriptors_restored", "children_reaped",
        )
        value = _closed_fields(result, names, "cogs.runtime-mapping-qualification/v1", receipt)
        _true_observations(value, names[-5:])
        objects = value["objects"]
        _require(type(objects) is list, "A operation objects")
        metadata = [{"kind": "object", "id": f"python-object-{index}", **row} for index, row in enumerate(objects)]
        metadata.append({
            "kind": "summary",
            "closure_sha256": value["closure_sha256"],
            "mapping_sha256": value["mapping_sha256"],
            "mapped_sequence": value["mapped"],
        })
        _validate_a(metadata)
    elif job == "B":
        names = "version source_revision source_set_sha256 closure_sha256 parser tools runtime".split()
        value = _closed_fields(result, tuple(names), "cogs.runtime-compression-qualification/v1", receipt)
        runtime_names = (
            "version", "marker", "source_revision", "source_set_sha256", "closure_sha256", "gzip_output_sha256",
            "zstd_output_sha256", *RUNTIME_OBSERVATIONS,
        )
        runtime = value["runtime"]
        _require(type(runtime) is dict and set(runtime) == set(runtime_names), "B runtime inventory")
        runtime_identity = tuple(runtime[name] for name in runtime_names[:4])
        _require(runtime_identity == ("cogs.runtime-qualification/v1", "cogs-runtime-qualification-v1", head_sha,
                                      receipt.source_set_sha256), "B runtime identity")
        _true_observations(runtime, RUNTIME_OBSERVATIONS)
        _require(runtime["closure_sha256"] == value["closure_sha256"], "B runtime closure")
        _require(runtime["gzip_output_sha256"] == runtime["zstd_output_sha256"] == MARKER_SHA256, "B outputs")
        tools = value["tools"]
        _require(type(tools) is list and len(tools) == 2 and type(value["parser"]) is dict, "B operation metadata")
        metadata = [*tools, {
            "kind": "summary", "id": "trusted-closure", "closure_sha256": value["closure_sha256"],
            "parser": value["parser"],
        }]
        _validate_b(metadata)
    elif job == "C":
        names = ("version", "source_revision", "source_set_sha256", *DESCRIPTOR_OBSERVATIONS)
        value = _closed_fields(result, names, "cogs.runtime-descriptor-qualification/v1", receipt)
        _true_observations(value, DESCRIPTOR_OBSERVATIONS)
    elif job == "D":
        names = ("version", "source_revision", "source_set_sha256", *LIFECYCLE_OBSERVATIONS)
        value = _closed_fields(result, names, "cogs.runtime-lifecycle-qualification/v1", receipt)
        _true_observations(value, LIFECYCLE_OBSERVATIONS)
    elif job == "E":
        names = ("version", "source_revision", "source_set_sha256", "seccomp_program_sha256", *SANDBOX_OBSERVATIONS)
        value = _closed_fields(result, names, "cogs.sandbox-qualification/v1", receipt)
        _true_observations(value, SANDBOX_OBSERVATIONS)
        _require(value["seccomp_program_sha256"] == POLICY_SHA256, "E operation policy")
        metadata = [{"id": "sandbox-policy", "role": "policy", "sha256": POLICY_SHA256, "size_bytes": 0}]
    else:
        names = (
            "version", "marker", "source_revision", "source_set_sha256", "closure_sha256", "gzip_output_sha256",
            "zstd_output_sha256", *RUNTIME_OBSERVATIONS,
        )
        value = _closed_fields(result, names, "cogs.runtime-qualification/v1", receipt)
        _require(value["marker"] == "cogs-runtime-qualification-v1", "integration marker")
        _true_observations(value, RUNTIME_OBSERVATIONS)
        _require(value["gzip_output_sha256"] == value["zstd_output_sha256"] == MARKER_SHA256, "integration outputs")
        digest_names = ("closure_sha256", "gzip_output_sha256", "source_set_sha256", "zstd_output_sha256")
        metadata = [
            {"id": name.removesuffix("_sha256"), "role": "digest", "sha256": value[name], "size_bytes": 0}
            for name in digest_names
        ]
    checks = tuple((name, "pass") for name in PRODUCTION_CHECK_IDS[job])
    frozen = tuple(NativeSession._freeze(dict(row)) for row in metadata)
    _require(all(isinstance(row, Mapping) for row in frozen), "frozen operation metadata")
    return checks, frozen  # type: ignore[return-value]
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
    default_ref = f"refs/heads/{envelope['default_branch']}"
    _require(envelope["event_name"] == "workflow_dispatch" and envelope["run_attempt"] == 1, "semantic event")
    _require(envelope["ref_protected"] is True and envelope["ref"] == default_ref, "semantic dispatch ref")
    workflow_matches = workflow["job_id"] == JOB_IDS[job]
    workflow_matches = workflow_matches and workflow["workflow_sha"] == envelope["github_sha"]
    workflow_path = workflow["path"]
    valid_fast = job == "B" and workflow_path == ".github/workflows/outcome-two-native-b.yml"
    _require(workflow_path == ".github/workflows/ci.yml" or valid_fast, "semantic workflow path")
    expected_path = FAST_B_WORKFLOW if valid_fast else WORKFLOW
    expected_workflow = _sha256(expected_path) if context is None else context.workflow_blob_sha256
    expected_common = _sha256(COMMON) if context is None else context.common_blob_sha256
    driver_path = COMMON.parent / DRIVERS[job]
    expected_driver = _sha256(driver_path) if context is None else context.driver_blob_sha256
    _require(workflow_matches and workflow["blob_sha256"] == expected_workflow, "semantic workflow")
    _require(source["common_blob_sha256"] == expected_common, "semantic common")
    _require(source["driver_blob_sha256"] == expected_driver, "semantic driver")
    operation = report["operation"]
    _require(HEX64.fullmatch(operation["result_sha256"]) is not None, "semantic operation digest")
    _require(HEX64.fullmatch(operation["source_set_sha256"]) is not None, "semantic operation source")
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
        _require(by_id["source_set"] == operation["source_set_sha256"], "integration operation source")
        _require(by_id["closure"] != by_id["source_set"], "integration digest role substitution")
        _require(MARKER_SHA256 not in {by_id["closure"], by_id["source_set"]}, "integration output substitution")
    if context is not None:
        observed = {name: report[name] for name in ("source", "envelope", "workflow", "runner")}
        _require(job == context.job and observed == _context_value(context), "semantic context")
def _validate(value: object, context: WorkflowContext | None = None) -> None:
    _validate_schema(value, None if context is None else context.schema_bytes)
    _validate_semantics(value, context)
def report_path(job: str) -> Path:
    _require(job in DRIVERS, "report job")
    return Path(f"/tmp/cogs-native-qualification-{job}/report.json")
def _retired_report_path(job: str) -> Path:
    _require(job in DRIVERS, "retired report job")
    return Path(f"/tmp/.cogs-native-qualification-{job}.retired")
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
def _rename(directory_fd: int, source: bytes, target: bytes, flags: int, target_fd: int | None = None) -> None:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    _require(renameat2 is not None, "renameat2 unavailable")
    if renameat2(directory_fd, source, directory_fd if target_fd is None else target_fd, target, flags) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
def _link_held(descriptor: int, directory_fd: int, name: bytes) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.linkat(descriptor, b"", directory_fd, name, 0x1000) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
def _identity(value: os.stat_result) -> dict[str, int]:
    names = ("mode", "uid", "gid", "device", "inode", "links", "size", "mtime_ns", "ctime_ns", "rdevice")
    values = (*_generation(value), value.st_rdev)
    return dict(zip(names, values))
def _directory_identity(value: os.stat_result) -> dict[str, int]:
    return {
        "mode": value.st_mode,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "device": value.st_dev,
        "inode": value.st_ino,
    }
def _identity_at(directory_fd: int, name: str) -> dict[str, int] | None:
    try:
        return _identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None
def _socket_name(context: object) -> bytes:
    identity = f"{context.job}:{context.run_id}:{context.run_attempt}:{context.head_sha}".encode()  # type: ignore[attr-defined]
    return b"\0cogs-nq-fixed-" + hashlib.sha256(identity).hexdigest()[:48].encode()
class _CustodianClient:
    def __init__(self, control: FdLease, pidfd: FdLease, pid: int):
        self.control = control
        self.pidfd = pidfd
        self.pid = pid
    def abort(self, primary: BaseException) -> None:
        failures: list[BaseException] = [primary]
        try:
            self.control.close()
        except BaseException as error:
            failures.append(error)
        _retire_child(self.pid, self.pidfd, failures, terminate=True)
        raise BaseExceptionGroup("custodian abort", failures)
    def publish(self, raw: bytes) -> None:
        endpoint = socket.socket(fileno=self.control.number)
        endpoint.settimeout(10)
        try:
            _require(endpoint.send(raw) == len(raw), "custodian report send")
            _require(endpoint.recv(128) == b"PUBLISHED", "custodian publication")
        finally:
            endpoint.detach()
        self.control.close()
def _bounded_reap(pid: int, pidfd_number: int) -> int:
    poller = select.poll()
    poller.register(pidfd_number, select.POLLIN)
    _require(bool(poller.poll(10_000)), "custodian bounded exit")
    waited, status = os.waitpid(pid, os.WNOHANG)
    _require(waited == pid, "custodian exact waitpid reap")
    return status
def _retire_child(
    pid: int,
    pidfd: FdLease,
    failures: list[BaseException],
    terminate: bool,
) -> None:
    if terminate:
        try:
            signal.pidfd_send_signal(pidfd.number, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            failures.append(error)
    try:
        _bounded_reap(pid, pidfd.number)
    except BaseException as error:
        failures.append(error)
    try:
        pidfd.close()
    except BaseException as error:
        failures.append(error)
def _adopt_socketpair(registry: FdRegistry, left_purpose: str, right_purpose: str) -> tuple[FdLease, FdLease]:
    left_socket, right_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    try:
        left_number = left_socket.detach()
        try:
            left = registry.adopt(left_number, left_purpose)
        except BaseException:
            os.close(left_number)
            raise
        right_number = right_socket.detach()
        try:
            right = registry.adopt(right_number, right_purpose)
        except BaseException as error:
            os.close(right_number)
            registry.close_reverse(error, [left])
            raise
        return left, right
    finally:
        left_socket.close()
        right_socket.close()
def _creator_retire(pid: int, pidfd: FdLease | None, failures: list[BaseException]) -> None:
    if pidfd is None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            failures.append(error)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                waited, _status = os.waitpid(pid, os.WNOHANG)
            except BaseException as error:
                failures.append(error)
                return
            if waited == pid:
                return
            time.sleep(0.01)
        failures.append(QualificationError("custodian creator reap timeout"))
        return
    _retire_child(pid, pidfd, failures, terminate=True)
def _start_custodian(context: WorkflowContext, registry: FdRegistry) -> _CustodianClient:
    left, right = _adopt_socketpair(registry, "report-custodian-control", "report-custodian-child")
    pid = -1
    pidfd: FdLease | None = None
    try:
        capability = os.urandom(32)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(left.number)
                _custodian_main(right.number, context, capability)
            except BaseException as error:
                os.write(2, f"native-custodian-supervisor-{_error_label(error, 96)}\n".encode())
                os._exit(1)
            os._exit(0)
        pidfd = registry.open("report-custodian-pidfd", lambda: os.pidfd_open(pid, 0))
        _require(pidfd.state is FdState.OWNED, "report custodian pidfd Lease adoption")
        right.close()
        endpoint = socket.socket(fileno=left.number)
        endpoint.settimeout(10)
        try:
            _require(endpoint.send(b"RELEASE") == 7, "custodian release send")
            _require(endpoint.recv(64) == b"READY", "custodian preregistration")
        finally:
            endpoint.detach()
        return _CustodianClient(left, pidfd, pid)
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        if pid > 0:
            _creator_retire(pid, pidfd, failures)
        try:
            registry.close_reverse(None, [right, left])
        except BaseException as error:
            failures.append(error)
        raise BaseExceptionGroup("custodian startup", failures)
def _anonymous(registry: FdRegistry, directory: FdLease, purpose: str) -> FdLease:
    temporary = getattr(os, "O_TMPFILE", 0)
    _require(temporary != 0, "O_TMPFILE unavailable")
    return registry.open(purpose, lambda: os.open(".", os.O_RDWR | os.O_CLOEXEC | temporary, 0o600, dir_fd=directory.number))
def _process_start(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    close = raw.rfind(")")
    _require(close > 1, "custodian process stat")
    values = raw[close + 2:].split()
    _require(len(values) >= 20, "custodian process fields")
    return int(values[19])
def _authority(context: WorkflowContext, capability: bytes, raw: bytes, directory: FdLease, report: FdLease) -> dict[str, object]:
    body = {
        "version": "cogs.native-report-cleanup-authority/v1", "job": context.job,
        "job_id": context.job_id, "run_id": context.run_id,
        "run_attempt": context.run_attempt, "head_sha": context.head_sha,
        "capability_sha256": hashlib.sha256(capability).hexdigest(), "directory": _directory_identity(os.fstat(directory.number)),
        "report_generation": _identity(os.fstat(report.number)), "report_sha256": hashlib.sha256(raw).hexdigest(),
        "report_size": len(raw), "custodian_pid": os.getpid(),
        "custodian_start": _process_start(os.getpid()),
    }
    return {**body, "authentication_sha256": hmac.new(capability, _canonical(body), hashlib.sha256).hexdigest()}
def _receipt(context: WorkflowContext, capability: bytes, raw: bytes, directory: FdLease,
             report: FdLease) -> dict[str, object]:
    body = {
        "version": "cogs.native-report-publication/v3", "state": "stable-upload-window",
        "job": context.job, "job_id": context.job_id,
        "run_id": context.run_id, "run_attempt": context.run_attempt,
        "head_sha": context.head_sha, "capability_sha256": hashlib.sha256(capability).hexdigest(),
        "directory": _directory_identity(os.fstat(directory.number)),
        "report_generation": _identity(os.fstat(report.number)), "report_sha256": hashlib.sha256(raw).hexdigest(),
        "report_size": len(raw), "workflow_sha256": context.workflow_blob_sha256,
        "schema_sha256": context.schema_blob_sha256, "common_sha256": context.common_blob_sha256,
        "driver_sha256": context.driver_blob_sha256,
        "source_generations_sha256": hashlib.sha256(_canonical(context.source_generations)).hexdigest(),
    }
    authentication = hmac.new(capability, _canonical(body), hashlib.sha256).hexdigest()
    return {**body, "authentication_sha256": authentication}
def _open_report_directory(job: str, create: bool) -> tuple[FdRegistry, FdLease, FdLease]:
    registry = FdRegistry()
    parent = registry.open("report-parent",
        lambda: os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
    _require(parent.state is FdState.OWNED, "report parent Lease adoption")
    name = report_path(job).parent.name
    if create:
        os.mkdir(name, 0o700, dir_fd=parent.number)
        os.fsync(parent.number)
    directory = registry.open("report-directory",
        lambda: os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent.number))
    _require(directory.state is FdState.OWNED, "report directory Lease adoption")
    status = os.fstat(directory.number)
    policy = stat.S_ISDIR(status.st_mode) and stat.S_IMODE(status.st_mode) == 0o700
    policy = policy and status.st_uid == os.geteuid() and status.st_gid == os.getegid()
    _require(policy, "report directory policy")
    return registry, parent, directory
def _publish_transaction(context: WorkflowContext, capability: bytes, raw: bytes,
                         supervisor_fd: int | None = None) -> tuple[FdRegistry, FdLease, FdLease]:
    _validate(_decode(raw), context)
    target = report_path(context.job)
    _require(not os.path.lexists(target.parent) and not os.path.lexists(_retired_report_path(context.job)), "report baseline")
    registry, parent, directory = _open_report_directory(context.job, True)
    if supervisor_fd is not None:
        supervisor = socket.socket(fileno=supervisor_fd)
        sent = supervisor.sendmsg([b"LEASE"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                struct.pack("2i", parent.number, directory.number))])
        _require(sent == 5, "custodian recovery authority transfer")
        supervisor.detach()
    authority = _anonymous(registry, directory, "anonymous-cleanup-authority")
    report = _anonymous(registry, directory, "anonymous-report")
    receipt = _anonymous(registry, directory, "anonymous-receipt")
    _write_all(report.number, raw)
    os.fsync(report.number)
    os.lseek(report.number, 0, os.SEEK_SET)
    _require(_read_all(report.number, REPORT_LIMIT) == raw, "report readback")
    _link_held(report.number, directory.number, b".report.stage")
    os.fsync(directory.number)
    _rename(directory.number, b".report.stage", b"report.json", 1)
    os.fsync(directory.number)
    authority_raw = _canonical(_authority(context, capability, raw, directory, report), True)
    _write_all(authority.number, authority_raw)
    os.fsync(authority.number)
    _link_held(authority.number, directory.number, b".authority.json")
    os.fsync(directory.number)
    intent = _receipt(context, capability, raw, directory, report)
    receipt_raw = _canonical(intent, True)
    _write_all(receipt.number, receipt_raw)
    os.fsync(receipt.number)
    _link_held(receipt.number, directory.number, b".owner.json")
    os.fsync(directory.number)
    _require(_identity_at(directory.number, "report.json") == intent["report_generation"], "published report generation")
    expected = {".owner.json", ".authority.json", "report.json"}
    _require(set(_enumerate_directory(directory.number, False)) == expected, "published inventory")
    registry.close_reverse(None, [receipt, report, authority])
    return registry, parent, directory
def _read_named(directory: FdLease, name: str, limit: int) -> tuple[bytes, dict[str, int]]:
    lease = directory.registry.open(
        f"retained:{name}",
        lambda: os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory.number),
    )
    try:
        before = os.fstat(lease.number)
        raw = _read_all(lease.number, limit)
        after = os.fstat(lease.number)
        _require(_generation(before) == _generation(after), f"{name} generation")
        return raw, _identity(after)
    finally:
        lease.close()
def _read_authority(directory: FdLease, job: str, capability: bytes | None = None) -> tuple[dict[str, object], dict[str, int]]:
    names = set(_enumerate_directory(directory.number, False))
    authority_name = ".authority.json"
    raw, generation = _read_named(directory, authority_name, 16_384)
    value = _decode(raw)
    required = {
        "version", "job", "job_id", "run_id", "run_attempt", "head_sha", "capability_sha256",
        "directory", "report_generation", "report_sha256", "report_size", "custodian_pid", "custodian_start",
        "authentication_sha256",
    }
    _require(type(value) is dict and set(value) == required, "closed cleanup authority")
    authentication = value.pop("authentication_sha256")
    if capability is not None:
        expected = hmac.new(capability, _canonical(value), hashlib.sha256).hexdigest()
        _require(hmac.compare_digest(str(authentication), expected), "cleanup authority authentication")
    value["authentication_sha256"] = authentication
    _require(value["version"] == "cogs.native-report-cleanup-authority/v1", "cleanup authority version")
    _require(value["job"] == job and value["job_id"] == JOB_IDS[job], "cleanup authority job")
    _require(value["directory"] == _directory_identity(os.fstat(directory.number)), "cleanup authority directory")
    _require(HEX64.fullmatch(str(value["capability_sha256"])) is not None, "cleanup capability digest")
    _require(type(value["report_size"]) is int and 0 < value["report_size"] <= REPORT_LIMIT, "authority report size")
    _require(HEX64.fullmatch(str(value["report_sha256"])) is not None, "authority report digest")
    _require(type(value["run_id"]) is int and value["run_id"] > 0, "authority run")
    _require(value["run_attempt"] == 1 and HEX40.fullmatch(str(value["head_sha"])) is not None, "authority source")
    _require(type(value["custodian_pid"]) is int and value["custodian_pid"] > 0, "authority custodian")
    _require(type(value["custodian_start"]) is int and value["custodian_start"] > 0, "authority custodian start")
    return value, generation
def _read_receipt(directory: FdLease, job: str, authority: Mapping[str, object], capability: bytes) -> tuple[dict[str, object], dict[str, int]]:
    names = set(_enumerate_directory(directory.number, False))
    _require(".owner.json" in names, "publication receipt present")
    receipt_name = ".owner.json"
    raw, generation = _read_named(directory, receipt_name, 16_384)
    value = _decode(raw)
    required = {
        "version", "state", "job", "job_id", "run_id", "run_attempt", "head_sha", "capability_sha256",
        "directory", "report_generation", "report_sha256", "report_size", "workflow_sha256", "common_sha256",
        "driver_sha256", "schema_sha256", "source_generations_sha256", "authentication_sha256",
    }
    _require(type(value) is dict and set(value) == required, "closed publication receipt")
    authentication = value.pop("authentication_sha256")
    expected_authentication = hmac.new(capability, _canonical(value), hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(str(authentication), expected_authentication), "receipt authentication")
    value["authentication_sha256"] = authentication
    context = value["version"] == "cogs.native-report-publication/v3"
    context = context and value["state"] == "stable-upload-window"
    context = context and value["job"] == job and value["job_id"] == JOB_IDS[job]
    _require(context, "receipt context")
    for name in ("run_id", "run_attempt", "head_sha", "capability_sha256", "directory", "report_generation", "report_sha256", "report_size"):
        _require(value[name] == authority[name], f"receipt authority {name}")
    code = (value["workflow_sha256"], value["common_sha256"], value["driver_sha256"], value["schema_sha256"],
            value["source_generations_sha256"])
    _require(all(HEX64.fullmatch(str(identity)) is not None for identity in code), "retained receipt code identities")
    return value, generation
def _file_digest_at(directory: FdLease, name: str, limit: int) -> tuple[str, int, dict[str, int]]:
    raw, generation = _read_named(directory, name, limit)
    return hashlib.sha256(raw).hexdigest(), len(raw), generation
def _retain_quarantine(job: str, parent: FdLease, directory: FdLease, capability: bytes) -> None:
    expected = _directory_identity(os.fstat(directory.number))
    source = report_path(job).parent.name
    target = ".cogs-nq-" + hmac.new(capability, f"quarantine:{job}".encode(), hashlib.sha256).hexdigest()
    source_identity = _identity_at(parent.number, source)
    target_identity_at = _identity_at(parent.number, target)
    if source_identity is None and target_identity_at is None:
        return
    if target_identity_at is None and source_identity is not None and source_identity["inode"] != expected["inode"]:
        os.rmdir(source, dir_fd=parent.number)
        os.fsync(parent.number)
        return
    try:
        os.mkdir(target, 0o700, dir_fd=parent.number)
    except FileExistsError:
        pass
    target_identity = _directory_identity(os.stat(target, dir_fd=parent.number, follow_symlinks=False))
    exchanged = target_identity == expected
    placeholder_name = source if exchanged else target
    placeholder = directory.registry.open("quarantine-exchange",
        lambda: os.open(placeholder_name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent.number))
    _require(placeholder.state is FdState.OWNED, "quarantine exchange Lease adoption")
    placeholder_identity = _directory_identity(os.fstat(placeholder.number))
    if not exchanged:
        _require(not _enumerate_directory(placeholder.number, False), "quarantine placeholder inventory")
        _rename(parent.number, source.encode(), target.encode(), 2)
    _require(_directory_identity(os.stat(target, dir_fd=parent.number, follow_symlinks=False)) == expected, "quarantine retained generation")
    _require(_directory_identity(os.stat(source, dir_fd=parent.number, follow_symlinks=False)) == placeholder_identity, "quarantine exchange generation")
    names = _enumerate_directory(directory.number, False)
    for name in names:
        retained = directory.registry.open(f"quarantine-retained:{name}",
            lambda name=name: os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory.number))
        _require(retained.state is FdState.OWNED, "quarantine retained Lease adoption")
        replacement = _anonymous(directory.registry, placeholder, f"quarantine-placeholder:{name}")
        slot = hmac.new(capability, f"slot:{name}".encode(), hashlib.sha256).hexdigest().encode()
        _link_held(replacement.number, placeholder.number, slot)
        _rename(directory.number, name.encode(), slot, 2, placeholder.number)
        retained_identity = _identity(os.fstat(retained.number))
        replacement_identity = _identity(os.fstat(replacement.number))
        _require(_identity_at(placeholder.number, slot.decode()) == retained_identity, "retained quarantine file generation")
        _require(_identity_at(directory.number, name) == replacement_identity, "quarantine placeholder generation")
        os.unlink(slot, dir_fd=placeholder.number)
        os.unlink(name, dir_fd=directory.number)
        directory.registry.close_reverse(None, [replacement, retained])
    allowed_slots = {hmac.new(capability, f"slot:{name}".encode(), hashlib.sha256).hexdigest()
                     for name in (".authority.json", ".owner.json", ".report.stage", "report.json")}
    for slot in _enumerate_directory(placeholder.number, False):
        _require(slot in allowed_slots, "quarantine recovery slot")
        retained = directory.registry.open("quarantine-recovery-slot",
            lambda slot=slot: os.open(slot, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=placeholder.number))
        _require(retained.state is FdState.OWNED, "quarantine recovery Lease adoption")
        os.unlink(slot, dir_fd=placeholder.number)
        retained.close()
    os.fsync(directory.number)
    os.rmdir(target, dir_fd=parent.number)
    os.rmdir(source, dir_fd=parent.number)
    os.fsync(parent.number)
    placeholder.close()
def _cleanup_owned(job: str, registry: FdRegistry, parent: FdLease, directory: FdLease,
    authority: Mapping[str, object],
    authority_generation: dict[str, int],
    receipt: Mapping[str, object] | None,
    receipt_generation: dict[str, int] | None,
    capability: bytes,
) -> None:
    del registry
    names = set(_enumerate_directory(directory.number, False))
    allowed = {".authority.json", ".owner.json", ".report.stage", "report.json"}
    _require(names <= allowed and ".authority.json" in names, "unclassified publication state")
    _require(_identity_at(directory.number, ".authority.json") == authority_generation, "authority generation")
    report_name = "report.json" if "report.json" in names else ".report.stage" if ".report.stage" in names else None
    if report_name is not None:
        digest, size, generation = _file_digest_at(directory, report_name, REPORT_LIMIT)
        _require(digest == authority["report_sha256"] and size == authority["report_size"], "uploaded report bytes")
        _require(generation == authority["report_generation"], "durable report generation")
        if receipt is not None:
            _require(generation == receipt["report_generation"], "uploaded report generation")
    if receipt_generation is not None:
        _require(_identity_at(directory.number, ".owner.json") == receipt_generation, "receipt generation")
    _retain_quarantine(job, parent, directory, capability)
def _recover_quarantine(job: str, parent: FdLease, directory: FdLease, capability: bytes) -> None:
    names = set(_enumerate_directory(directory.number, False))
    if ".authority.json" not in names:
        _retain_quarantine(job, parent, directory, capability)
        return
    authority, authority_generation = _read_authority(directory, job, capability)
    receipt = receipt_generation = None
    if ".owner.json" in names:
        receipt, receipt_generation = _read_receipt(directory, job, authority, capability)
    _cleanup_owned(job, directory.registry, parent, directory, authority, authority_generation, receipt, receipt_generation, capability)
def _custodian_main(control_fd: int, context: WorkflowContext, capability: bytes) -> None:
    supervisor, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    _require(supervisor.fileno() >= 0 and worker.fileno() >= 0, "custodian socket object adoption")
    owner_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        supervisor.close()
        try:
            prctl = ctypes.CDLL(None, use_errno=True).prctl
            _require(prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == owner_pid, "custodian supervisor ownership")
            _require(worker.recv(1) == b"G", "custodian worker gate")
            worker_call = worker.dup()
            _require(worker_call.fileno() >= 0, "custodian worker call socket adoption")
            _custodian_worker(control_fd, context, capability, worker_call.detach())
        except BaseException as error:
            os.write(2, f"native-custodian-worker-{_error_label(error, 96)}\n".encode())
            try:
                if os.path.lexists(report_path(context.job).parent / ".owner.json"):
                    worker.send(b"PRESERVE")
            except BaseException:
                pass
            os._exit(1)
        os._exit(0)
    worker.close()
    registry = FdRegistry()
    pidfd = registry.open("capability-custodian-pidfd", lambda: os.pidfd_open(pid, 0))
    _require(pidfd.state is FdState.OWNED, "capability custodian pidfd Lease adoption")
    _require(supervisor.send(b"G") == 1, "custodian worker release")
    lease_packet, lease_rights, _flags, _address = supervisor.recvmsg(64, socket.CMSG_SPACE(struct.calcsize("2i")))
    lease_numbers = [number for level, kind, data in lease_rights if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS
                     for number in struct.unpack(f"{len(data) // 4}i", data)]
    if not lease_packet:
        _bounded_reap(pid, pidfd.number)
        if os.path.lexists(report_path(context.job).parent):
            recovery_registry, recovery_parent, recovery_directory = _open_report_directory(context.job, False)
            _recover_quarantine(context.job, recovery_parent, recovery_directory, capability)
            recovery_registry.close_reverse()
        registry.close_reverse()
        os.close(control_fd)
        return
    retained = [registry.adopt(number, "custodian-recovery-authority") for number in lease_numbers]
    _require(lease_packet == b"LEASE" and len(retained) == 2, "custodian recovery authority")
    packet, rights, _flags, _address = supervisor.recvmsg(4096, socket.CMSG_SPACE(struct.calcsize("i")))
    phase = packet
    if phase == b"STABLE":
        packet, rights, _flags, _address = supervisor.recvmsg(4096, socket.CMSG_SPACE(struct.calcsize("i")))
        if packet == b"AUTHORIZED":
            phase = packet
            packet, rights, _flags, _address = supervisor.recvmsg(4096, socket.CMSG_SPACE(struct.calcsize("i")))
    if packet == b"PRESERVE":
        _bounded_reap(pid, pidfd.number)
        # STABLE means the authenticated publication is durable, not that an
        # exceptional worker owns future cleanup. Recover it through the held
        # parent/directory capabilities before retiring the custodian.
        _recover_quarantine(context.job, retained[0], retained[1], capability)
        registry.close_reverse()
        os.close(control_fd)
        return
    descriptors = [struct.unpack("i", data[:4])[0] for level, kind, data in rights
                   if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS]
    terminal_leases = [registry.adopt(number, "custodian-terminal-endpoint") for number in descriptors]
    status = _bounded_reap(pid, pidfd.number)
    if not packet:
        _recover_quarantine(context.job, retained[0], retained[1], capability)
        registry.close_reverse()
        os.close(control_fd)
        return
    _require(len(terminal_leases) == 1 and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
             "capability custodian terminal exit")
    response = _decode(packet)
    _require(type(response) is dict and response.get("custodian_pid") == pid, "capability custodian terminal receipt")
    response["waitpid_reaped"] = pid
    endpoint = socket.socket(fileno=terminal_leases[0].number)
    reply = _canonical(response, True)
    _require(endpoint.send(reply) == len(reply), "custodian terminal reply")
    endpoint.detach()
    terminal_leases[0].close()
    supervisor.close()
    registry.close_reverse()
def _mutation_watch(registry: FdRegistry, directory: FdLease) -> FdLease:
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    try:
        watch = registry.adopt(descriptor, "uploaded-generation-watch")
    except BaseException:
        os.close(descriptor)
        raise
    mask = 0x00000fce
    added = libc.inotify_add_watch(watch.number, f"/proc/self/fd/{directory.number}".encode(), mask)
    _require(added >= 0, "uploaded generation watch")
    return watch
def _watch_clean(watch: FdLease) -> None:
    try:
        changed = os.read(watch.number, 65_536)
    except BlockingIOError:
        changed = b""
    _require(not changed, "uploaded report generation exchanged")
def _custodian_worker(control_fd: int, context: WorkflowContext, capability: bytes, supervisor_fd: int) -> None:
    registry = FdRegistry()
    control_lease = registry.adopt(control_fd, "custodian-worker-control")
    listener_lease = registry.open(
        "custodian-listener",
        lambda: socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC).detach(),
    )
    control = socket.socket(fileno=control_lease.number)
    listener = socket.socket(fileno=listener_lease.number)
    control.settimeout(10)
    listener.settimeout(600)
    listener.bind(_socket_name(context))
    listener.listen(1)
    _require(control.recv(7) == b"RELEASE", "custodian release")
    _require(control.send(b"READY") == 5, "custodian ready")
    control.settimeout(600)
    raw = control.recv(REPORT_LIMIT + 1)
    if not raw:
        control.detach()
        listener.detach()
        registry.close_reverse()
        return
    transaction_registry, parent, directory = _publish_transaction(context, capability, raw, supervisor_fd)
    watch = _mutation_watch(transaction_registry, directory)
    authority_probe, _authority_probe_generation = _read_authority(directory, context.job, capability)
    receipt_probe, _receipt_probe_generation = _read_receipt(directory, context.job, authority_probe, capability)
    _require(receipt_probe["report_generation"] == _identity_at(directory.number, "report.json"), "watched report generation")
    supervisor = socket.socket(fileno=supervisor_fd)
    _require(supervisor.send(b"STABLE") == 6, "custodian stable handoff")
    supervisor.detach()
    _require(control.send(b"PUBLISHED") == 9, "custodian published")
    control.detach()
    control_lease.close()
    accepted = listener.accept()
    endpoint_socket, _address = accepted  # Python socket retains the allocation until registry adoption.
    endpoint_number = endpoint_socket.detach()
    try:
        endpoint_lease = registry.adopt(endpoint_number, "custodian-cleanup-endpoint")
    except BaseException:
        os.close(endpoint_number)
        raise
    endpoint = socket.socket(fileno=endpoint_lease.number)
    endpoint.settimeout(10)
    peer = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    request = _decode(endpoint.recv(4096))
    nonce = request.get("nonce") if type(request) is dict else None
    upload = request.get("upload") if type(request) is dict else None
    expected = {"head_sha": context.head_sha, "job": context.job, "nonce": nonce,
                "run_attempt": context.run_attempt, "run_id": context.run_id, "upload": upload}
    valid_nonce = type(nonce) is str and HEX64.fullmatch(nonce) is not None
    upload_shape = type(upload) is dict and set(upload) == {"artifact_id", "artifact_sha256", "report_generation",
                                                             "report_sha256", "report_size"}
    _require(peer[1:] == (os.geteuid(), os.getegid()) and valid_nonce and request == expected and upload_shape,
             "authenticated upload cleanup")
    authority, authority_generation = _read_authority(directory, context.job, capability)
    retained = hashlib.sha256(capability).hexdigest()
    _require(hmac.compare_digest(str(authority["capability_sha256"]), retained), "retained cleanup capability")
    receipt, receipt_generation = _read_receipt(directory, context.job, authority, capability)
    digest, size, generation = _file_digest_at(directory, "report.json", REPORT_LIMIT)
    exact_upload = upload["report_sha256"] == digest and upload["report_size"] == size  # type: ignore[index]
    exact_upload = exact_upload and upload["report_generation"] == generation  # type: ignore[index]
    exact_upload = exact_upload and type(upload["artifact_id"]) is int and upload["artifact_id"] > 0  # type: ignore[index]
    exact_upload = exact_upload and HEX64.fullmatch(str(upload["artifact_sha256"])) is not None  # type: ignore[index]
    _require(exact_upload, "uploader acknowledgement binding")
    _watch_clean(watch)
    supervisor = socket.socket(fileno=supervisor_fd)
    _require(supervisor.send(b"AUTHORIZED") == 10, "custodian cleanup authorization")
    supervisor.detach()
    _cleanup_owned(
        context.job,
        transaction_registry,
        parent,
        directory,
        authority,
        authority_generation,
        receipt,
        receipt_generation,
        capability,
    )
    terminal = _canonical({"capability": capability.hex(), "custodian_pid": os.getpid(), "nonce": nonce,
                           "upload": upload}, True)
    supervisor = socket.socket(fileno=supervisor_fd)
    sent = supervisor.sendmsg([terminal], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", endpoint_lease.number))])
    _require(sent == len(terminal), "custodian terminal handoff")
    supervisor.close()
    endpoint.detach()
    endpoint_lease.close()
    listener.detach()
    listener_lease.close()
@dataclass(frozen=True)
class _CleanupContext:
    job: str
    run_id: int
    run_attempt: int
    head_sha: str
def cleanup_report(job: str) -> None:
    environment = dict(os.environ)
    expected_keys = {"LC_ALL", "NQ_CLEANUP_RUN_ID", "NQ_CLEANUP_RUN_ATTEMPT", "NQ_CLEANUP_HEAD_SHA",
                     "NQ_UPLOAD_ARTIFACT_ID", "NQ_UPLOAD_ARTIFACT_SHA256"}
    _require(set(environment) == expected_keys and environment["LC_ALL"] == "C", "cleanup environment")
    run_id = _integer(environment["NQ_CLEANUP_RUN_ID"], "cleanup run")
    run_attempt = _integer(environment["NQ_CLEANUP_RUN_ATTEMPT"], "cleanup attempt")
    head_sha = environment["NQ_CLEANUP_HEAD_SHA"]
    _require(run_attempt == 1 and HEX40.fullmatch(head_sha) is not None, "cleanup source")
    artifact_id = _integer(environment["NQ_UPLOAD_ARTIFACT_ID"], "upload artifact id")
    artifact_sha256 = environment["NQ_UPLOAD_ARTIFACT_SHA256"]
    _require(HEX64.fullmatch(artifact_sha256) is not None, "upload artifact digest")
    context = _CleanupContext(job=job, run_id=run_id, run_attempt=run_attempt, head_sha=head_sha)
    registry = FdRegistry()
    endpoint_lease = registry.open("cleanup-custodian-endpoint",
        lambda: socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC).detach())
    endpoint = socket.socket(fileno=endpoint_lease.number)
    endpoint.settimeout(10)
    endpoint.connect(_socket_name(context))
    peer = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    peer_pid = peer[0]
    pidfd = registry.open("cleanup-custodian-pidfd", lambda: os.pidfd_open(peer_pid, 0))
    _require(pidfd.state is FdState.OWNED, "cleanup custodian pidfd Lease adoption")
    peer_start = _process_start(peer_pid)
    peer_exact = peer[1:] == (os.geteuid(), os.getegid()) and peer_start > 0
    peer_exact = peer_exact and struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == peer
    _require(peer_exact, "retained custodian peer generation")
    transaction_registry, parent, directory = _open_report_directory(job, False)
    authority, _authority_generation = _read_authority(directory, job)
    identity = (authority["run_id"], authority["run_attempt"], authority["head_sha"],
                authority["custodian_pid"], authority["custodian_start"])
    _require(identity == (run_id, run_attempt, head_sha, peer_pid, peer_start), "cleanup authority identity")
    digest, size, generation = _file_digest_at(directory, "report.json", REPORT_LIMIT)
    upload = {"artifact_id": artifact_id, "artifact_sha256": artifact_sha256, "report_generation": generation,
              "report_sha256": digest, "report_size": size}
    nonce = os.urandom(32).hex()
    request = _canonical({"head_sha": head_sha, "job": job, "nonce": nonce, "run_attempt": run_attempt,
                          "run_id": run_id, "upload": upload}, True)
    _require(endpoint.send(request) == len(request), "cleanup request send")
    response = _decode(endpoint.recv(4096))
    endpoint.detach()
    endpoint_lease.close()
    _require(type(response) is dict and set(response) == {"capability", "custodian_pid", "nonce", "upload", "waitpid_reaped"},
             "private cleanup terminal receipt")
    capability = bytes.fromhex(str(response["capability"]))
    exact = len(capability) == 32 and hmac.compare_digest(hashlib.sha256(capability).hexdigest(),
                                                          str(authority["capability_sha256"]))
    exact = exact and response == {"capability": capability.hex(), "custodian_pid": peer_pid, "nonce": nonce,
                                   "upload": upload, "waitpid_reaped": peer_pid}
    _require(exact, "retained private cleanup capability")
    poller = select.poll()
    poller.register(pidfd.number, select.POLLIN)
    _require(bool(poller.poll(10_000)), "reaped custodian pidfd terminal")
    pidfd.close()
    transaction_registry.close_reverse(None, [directory, parent])
    registry.close_reverse()
    _require(not os.path.lexists(report_path(job).parent) and not os.path.lexists(_retired_report_path(job)),
             "report baseline restored")
class NativeSession:
    def __init__(self, context: WorkflowContext, ops: object, custodian: _CustodianClient, nonce: bytes):
        self.context = context
        self.fds = ops.fds
        self._ops = ops
        self._custodian = custodian
        self.source_set_sha256 = ops.source_set_sha256
        self._nonce = nonce
        self.__receipt_seal = object()
        self._operation_started = False
        self.__receipt: OperationReceipt | None = None
        self._before = dict(ops.observe(context))
        _require(tuple(self._before) == CLEANUP_KEYS, "baseline domains")
        allowed_path_baselines = ((None, None, None),) if type(ops) is SystemCommonOps else ((None, None), (None, None, None))
        _require(self._before["paths"] in allowed_path_baselines, "named path baseline")
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
            os.write(2, f"native-baseline-{_error_label(error)}\n".encode())
            custodian.abort(error)
    @classmethod
    def _begin_with_ops(cls, context: WorkflowContext, ops: object, custodian: _CustodianClient) -> "NativeSession":
        _require(set(os.environ) != ENV_KEYS and type(ops) is not SystemCommonOps, "test seam unavailable in production")
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
            source_digest = self._ops.source_set_sha256
            closed = type(result) is dict and HEX64.fullmatch(source_digest) is not None
            _require(closed, "closed production operation")
            frozen = self._freeze(result)
            _require(isinstance(frozen, Mapping), "operation result receipt")
            digest = hashlib.sha256(_canonical(result)).hexdigest()
            draft = OperationReceipt(
                _session_nonce=self._nonce,
                _seal=self.__receipt_seal,
                job=operation,
                source_set_sha256=source_digest,
                result_sha256=digest,
                _result=frozen,
                _checks=(),
                _metadata=(),
            )
            checks, metadata = _derive_operation(draft, self.context.head_sha)
            self.__receipt = OperationReceipt(
                _session_nonce=self._nonce,
                _seal=self.__receipt_seal,
                job=operation,
                source_set_sha256=source_digest,
                result_sha256=digest,
                _result=frozen,
                _checks=checks,
                _metadata=metadata,
            )
            self.source_set_sha256 = source_digest
            return result
        except BaseException as error:
            os.write(2, f"native-operation-{_error_label(error)}\n".encode())
            self._custodian.abort(error)
            raise
    def mark_uncertain(self, domains: tuple[str, ...], error: BaseException) -> None:
        exact = self._evidence is None and domains and all(domain in CLEANUP_KEYS for domain in domains)
        _require(bool(exact), "cleanup uncertainty")
        _require(isinstance(error, BaseException), "cleanup uncertainty error")
        self._poisoned.update(domains)
    def settle_native_phase(self) -> CleanupEvidence:
        _require(self.__receipt is not None, "operation receipt required for settlement")
        _require(self._evidence is None and not self._published, "native settlement state")
        after: Mapping[str, object] = {}
        observation_error: BaseException | None = None
        try:
            after = self._ops.observe(self.context)
        except BaseException as error:
            observation_error = error
        finally:
            release = getattr(self._ops, "release_descriptor_anchors", None)
            if callable(release):
                try:
                    release()
                except BaseException as error:
                    observation_error = error
        values = tuple(
            (key, observation_error is None and key not in self._poisoned and after.get(key) == self._before[key])
            for key in CLEANUP_KEYS
        )
        if self.fds.uncertain:
            values = tuple((key, False if key == "descriptors" else value) for key, value in values)
        self._evidence = CleanupEvidence(_session_nonce=self._nonce, _items=values)
        return self._evidence
    def _receipt_claims(self) -> tuple[dict[str, str], list[dict[str, object]], dict[str, str]]:
        receipt = self.__receipt
        exact = receipt is not None and receipt._session_nonce == self._nonce
        exact = exact and receipt._seal is self.__receipt_seal and receipt.job == self.context.job
        _require(exact, "private operation receipt profile")
        result = self._thaw(receipt._result)
        _require(type(result) is dict, "operation receipt result")
        _require(hashlib.sha256(_canonical(result)).hexdigest() == receipt.result_sha256, "operation receipt integrity")
        derived_checks, derived_metadata = _derive_operation(receipt, self.context.head_sha)
        _require(receipt._checks == derived_checks and receipt._metadata == derived_metadata, "operation receipt derivation")
        checks = dict(derived_checks)
        metadata = [self._thaw(row) for row in derived_metadata]
        _require(tuple(checks) == PRODUCTION_CHECK_IDS[self.context.job], "operation receipt checks")
        _require(all(type(row) is dict for row in metadata), "operation receipt metadata")
        operation = {"result_sha256": receipt.result_sha256, "source_set_sha256": receipt.source_set_sha256}
        return checks, metadata, operation
    def publish(self, candidate: ReportCandidate) -> Path:
        exact = self._evidence is not None and self._evidence._session_nonce == self._nonce
        _require(exact and not self._published and type(candidate) is ReportCandidate, "report session state")
        production, metadata, operation = self._receipt_claims()
        failure_phase = candidate.failure_phase
        diagnostics = candidate.diagnostics
        primary_error = candidate.primary_error
        _require(failure_phase is None or SAFE.fullmatch(failure_phase) is not None, "candidate failure phase")
        _require(diagnostics is None or type(diagnostics) is bytes and len(diagnostics) <= REPORT_LIMIT, "candidate diagnostics")
        _require(primary_error is None or isinstance(primary_error, BaseException), "candidate primary error")
        caller_failed = primary_error is not None or failure_phase is not None or diagnostics is not None
        _require(caller_failed or (failure_phase, diagnostics, primary_error) == (None, None, None), "candidate failure tuple")
        cleanup = dict(self._evidence.values)
        derived = {"cleanup_restored": all(cleanup.values()), "checkout_unchanged": cleanup["checkout"]}
        checks = {
            name: "fail" if caller_failed and name in production else (
                "pass" if derived[name] else "fail"
            ) if name in derived else production[name]
            for name in CHECK_IDS[self.context.job]
        }
        passing = not caller_failed and all(value == "pass" for value in checks.values()) and all(cleanup.values())
        if passing:
            phase = None
            diagnostic_sha256 = None
        else:
            phase = failure_phase or "common-settlement"
            if diagnostics is not None:
                diagnostic_raw = diagnostics
            elif primary_error is not None:
                diagnostic_raw = type(primary_error).__name__.encode()
            else:
                diagnostic_raw = b"common baseline not restored"
            diagnostic_sha256 = hashlib.sha256(diagnostic_raw).hexdigest()
        report = {
            "authority": AUTHORITY,
            "checks": [{"id": key, "outcome": value} for key, value in checks.items()],
            "cleanup": cleanup,
            "diagnostics_sha256": diagnostic_sha256,
            "failure_phase": phase,
            "job": self.context.job,
            "metadata": metadata if passing else [],
            "operation": operation,
            "result": "pass" if passing else "fail",
            "version": VERSION,
            **_context_value(self.context),
        }
        raw = _canonical(report, True)
        _require(len(raw) <= REPORT_LIMIT and _decode(raw) == report, "report encoding")
        _validate(report, self.context)
        try:
            self._custodian.publish(raw)
        except BaseException as error:
            self._custodian.abort(error)
        self._published = True
        return report_path(self.context.job)
def _main(arguments: list[str]) -> int:
    if arguments == ["--require-final-results"]:
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
