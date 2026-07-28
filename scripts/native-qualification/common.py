#!/usr/bin/python3
"""Shared admission, validation, and atomic report ownership for native jobs."""
from __future__ import annotations
from dataclasses import dataclass
import ctypes, hashlib, json, os, platform, re, stat, sys
from pathlib import Path
from typing import Mapping
VERSION = "cogs.native-qualification/v1alpha1"; AUTHORITY = "exact-run-native-qualification"
ROOT = Path(__file__).resolve().parents[2]; WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMMON = ROOT / "scripts/native-qualification/common.py"; SCHEMA = ROOT / "schemas/native-qualification-report-v1alpha1.json"
REPORT_LIMIT = 32_768
CLEANUP_KEYS = ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")
DRIVERS = {
    "A": "job-a-runtime-mappings.py", "B": "job-b-compression.py",
    "C": "job-c-descriptors.py", "D": "job-d-process-lifecycle.py",
    "E": "job-e-sandbox.py", "integration": "thin-integration.py",
}
JOB_IDS = {**{job: f"native-qualification-{job.lower()}" for job in "ABCDE"}, "integration": "native-closure-integration"}
CHECK_IDS = {
    "A": tuple("elf_real python_closure_exact map_files_trusted mapped_closure_equal mapping_stable helper_reaped cleanup_restored".split()),
    "B": tuple(("gzip_source_exact gzip_sealed_exec zstd_source_exact zstd_sealed_exec "
                "decompression_deterministic network_denied children_exact cleanup_restored").split()),
    "C": tuple(("nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact "
                "cloexec_exact inheritance_exact limit_restored cleanup_restored").split()),
    "D": tuple(("pdeathsig_armed parent_handshake_exact before_release_death after_release_death "
                "starttime_revalidated session_owned process_group_owned term_kill_bounded "
                "all_reaped cleanup_restored").split()),
    "E": tuple(("mount_view_exact checkout_read_only user_namespace_exact pid_namespace_exact "
                "mount_namespace_exact network_namespace_exact pid_one capabilities_zero noroot_locked nnp_set "
                "seccomp_socket_denied seccomp_io_uring_denied no_acquisition_route checkout_unchanged "
                "all_reaped mounts_restored cleanup_restored").split()),
    "integration": tuple("closure_prepared handoff_exact gzip_deterministic zstd_deterministic marker_exact no_linked_evidence cleanup_restored".split()),
}
ENV_KEYS = frozenset({
    "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "NQ_EVENT_NAME",
    "NQ_REPOSITORY", "NQ_HEAD_REPOSITORY", "NQ_HEAD_SHA", "NQ_ENVELOPE_SHA",
    "NQ_WORKFLOW_SHA", "NQ_MERGE_SHA", "NQ_BASE_SHA", "NQ_JOB_ID", "NQ_RUN_ID",
    "NQ_RUN_ATTEMPT", "NQ_PR_NUMBER", "NQ_RUNNER_VERSION",
})
HEX40 = re.compile(r"[0-9a-f]{40}\Z"); SAFE = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")
class QualificationError(RuntimeError):
    """A fixed qualification contract was not met."""
def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)
def _generation(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_mode, value.st_uid, value.st_gid, value.st_dev, value.st_ino,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
def _sha256(path: Path) -> str:
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= 2_000_000, "source object")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65_536):
            digest.update(block)
    _require(_generation(before) == _generation(path.lstat()), "source generation")
    return digest.hexdigest()
def _integer(value: str, name: str) -> int:
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None, name)
    return int(value)
@dataclass(frozen=True)
class WorkflowContext:
    job: str
    repository: str
    head_repository: str
    head_sha: str
    envelope_sha: str
    workflow_sha: str
    merge_sha: str
    base_sha: str
    job_id: str
    run_id: int
    run_attempt: int
    pull_request_number: int
    runner_version: str
    kernel_release: str
    architecture: str
    workflow_blob_sha256: str
    driver_blob_sha256: str
    common_blob_sha256: str
    @classmethod
    def from_environ(cls, expected_job: str, driver_file: str | Path) -> "WorkflowContext":
        environment = dict(os.environ)
        _require(expected_job in DRIVERS and set(environment) == ENV_KEYS, "fixed environment")
        _require(not os.path.lexists(report_path(expected_job).parent), "report baseline")
        _require(environment["LC_ALL"] == "C" and environment["PYTHONDONTWRITEBYTECODE"] == "1", "runtime environment")
        _require(environment["PYTHONHASHSEED"] == "0" and environment["NQ_EVENT_NAME"] == "pull_request", "event environment")
        driver = Path(driver_file).absolute()
        expected_driver = COMMON.parent / DRIVERS[expected_job]
        _require(driver == expected_driver and driver.is_file(), "fixed driver")
        hashes = [environment[name] for name in ("NQ_HEAD_SHA", "NQ_ENVELOPE_SHA", "NQ_WORKFLOW_SHA", "NQ_MERGE_SHA", "NQ_BASE_SHA")]
        _require(all(HEX40.fullmatch(value) for value in hashes), "source identity")
        _require(environment["NQ_WORKFLOW_SHA"] in {environment["NQ_HEAD_SHA"], environment["NQ_MERGE_SHA"]}, "workflow source")
        repository = environment["NQ_REPOSITORY"]
        _require(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository) is not None, "repository")
        _require(environment["NQ_HEAD_REPOSITORY"] == repository, "same repository")
        _require(environment["NQ_JOB_ID"] == JOB_IDS[expected_job], "workflow job")
        _require(SAFE.fullmatch(environment["NQ_RUNNER_VERSION"]) is not None, "runner version")
        attempt = _integer(environment["NQ_RUN_ATTEMPT"], "run attempt")
        _require(attempt == 1, "first attempt")
        kernel, architecture = platform.release(), platform.machine()
        _require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.+]*", kernel) is not None, "kernel release")
        _require(architecture == "x86_64", "architecture")
        return cls(
            expected_job, repository, repository, *hashes, environment["NQ_JOB_ID"],
            _integer(environment["NQ_RUN_ID"], "run id"), attempt,
            _integer(environment["NQ_PR_NUMBER"], "pull request"), environment["NQ_RUNNER_VERSION"],
            kernel, architecture, _sha256(WORKFLOW), _sha256(driver), _sha256(COMMON),
        )
def _context_value(context: WorkflowContext) -> dict[str, object]:
    return {
        "source": {"checkout_sha": context.head_sha, "driver_blob_sha256": context.driver_blob_sha256,
                   "head_sha": context.head_sha, "common_blob_sha256": context.common_blob_sha256},
        "envelope": {"base_sha": context.base_sha, "event_merge_sha": context.merge_sha,
                     "event_name": "pull_request", "github_sha": context.envelope_sha,
                     "head_repository": context.head_repository, "pull_request_number": context.pull_request_number,
                     "repository": context.repository, "run_attempt": context.run_attempt, "run_id": context.run_id},
        "workflow": {"blob_sha256": context.workflow_blob_sha256, "job_id": context.job_id,
                     "path": ".github/workflows/ci.yml", "workflow_sha": context.workflow_sha},
        "runner": {"architecture": context.architecture, "image": "ubuntu-24.04",
                   "image_version": context.runner_version, "kernel_release": context.kernel_release},
    }
def _schema_error(node: object, value: object, root: Mapping[str, object], place: str = "$") -> None:
    if node is True:
        return
    _require(node is not False and type(node) is dict, f"schema {place}")
    rule = node
    if "$ref" in rule:
        target: object = root
        for part in str(rule["$ref"]).removeprefix("#/").split("/"):
            target = target[part]  # type: ignore[index]
        _schema_error(target, value, root, place)
    for keyword in ("allOf",):
        for child in rule.get(keyword, []):
            _schema_error(child, value, root, place)
    for keyword, count in (("anyOf", lambda hits: hits >= 1), ("oneOf", lambda hits: hits == 1)):
        if keyword in rule:
            hits = sum(_schema_matches(child, value, root) for child in rule[keyword])
            _require(count(hits), f"schema {keyword} {place}")
    if "if" in rule:
        selected = rule.get("then") if _schema_matches(rule["if"], value, root) else rule.get("else")
        if selected is not None:
            _schema_error(selected, value, root, place)
    if "const" in rule:
        _require(type(value) is type(rule["const"]) and value == rule["const"], f"schema const {place}")
    if "enum" in rule:
        _require(any(type(value) is type(item) and value == item for item in rule["enum"]), f"schema enum {place}")
    kind = rule.get("type")
    types = kind if type(kind) is list else [kind] if kind else []
    mapping = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
    if types:
        _require(any(type(value) is mapping[name] for name in types), f"schema type {place}")
    if type(value) is dict:
        required, properties = rule.get("required", []), rule.get("properties", {})
        _require(all(name in value for name in required), f"schema required {place}")
        if rule.get("additionalProperties") is False:
            _require(set(value) <= set(properties), f"schema property {place}")
        for name, child in properties.items():
            if name in value:
                _schema_error(child, value[name], root, f"{place}.{name}")
    if type(value) is list:
        _require(rule.get("minItems", 0) <= len(value) <= rule.get("maxItems", len(value)), f"schema items {place}")
        prefix = rule.get("prefixItems", [])
        for index, child in enumerate(prefix):
            _require(index < len(value), f"schema prefix {place}")
            _schema_error(child, value[index], root, f"{place}[{index}]")
        items = rule.get("items", True)
        for index in range(len(prefix), len(value)):
            _schema_error(items, value[index], root, f"{place}[{index}]")
        if rule.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            _require(len(encoded) == len(set(encoded)), f"schema unique {place}")
        if "contains" in rule:
            hits = sum(_schema_matches(rule["contains"], item, root) for item in value)
            _require(rule.get("minContains", 1) <= hits <= rule.get("maxContains", len(value)), f"schema contains {place}")
    if type(value) is str and "pattern" in rule:
        _require(re.search(rule["pattern"], value) is not None, f"schema pattern {place}")
    if type(value) is int and not isinstance(value, bool):
        _require(rule.get("minimum", value) <= value <= rule.get("maximum", value), f"schema number {place}")
def _schema_matches(node: object, value: object, root: Mapping[str, object]) -> bool:
    try:
        _schema_error(node, value, root)
        return True
    except QualificationError:
        return False
def _decode(raw: bytes) -> object:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for name, item in rows:
            _require(name not in value, "duplicate JSON key")
            value[name] = item
        return value
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    canonical = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _require(raw == canonical and len(raw) <= REPORT_LIMIT, "canonical report")
    return value
def _validate_schema(value: object) -> None:
    before = SCHEMA.lstat()
    raw = SCHEMA.read_bytes()
    _require(len(raw) <= 100_000 and _generation(before) == _generation(SCHEMA.lstat()), "schema generation")
    schema_value = json.loads(raw)
    _require(type(schema_value) is dict, "tracked schema")
    _schema_error(schema_value, value, schema_value)
def _validate_semantics(value: object, context: WorkflowContext | None = None) -> None:
    _require(type(value) is dict and value.get("job") in DRIVERS, "semantic report")
    report, job = value, str(value["job"])
    _require(tuple(row["id"] for row in report["checks"]) == CHECK_IDS[job], "semantic checks")
    passing = all(row["outcome"] == "pass" for row in report["checks"]) and all(report["cleanup"].values())
    _require((report["result"] == "pass") == passing, "semantic result")
    _require((report["failure_phase"] is None) == passing and (report["diagnostics_sha256"] is None) == passing, "semantic failure")
    source, envelope, workflow = report["source"], report["envelope"], report["workflow"]
    _require(source["checkout_sha"] == source["head_sha"], "semantic checkout")
    _require(envelope["event_name"] == "pull_request" and envelope["run_attempt"] == 1, "semantic event")
    _require(envelope["repository"] == envelope["head_repository"] and envelope["github_sha"] == envelope["event_merge_sha"], "semantic repository")
    workflow_matches = workflow["job_id"] == JOB_IDS[job] and workflow["workflow_sha"] in {source["head_sha"], envelope["event_merge_sha"]}
    workflow_matches &= workflow["blob_sha256"] == _sha256(WORKFLOW)
    _require(workflow_matches, "semantic workflow")
    code_matches = source["common_blob_sha256"] == _sha256(COMMON)
    code_matches &= source["driver_blob_sha256"] == _sha256(COMMON.parent / DRIVERS[job])
    _require(code_matches, "semantic code")
    metadata = report["metadata"]
    if job == "A" and report["result"] == "pass":
        objects = metadata[:-1]
        _require(metadata[-1]["kind"] == "summary" and [row["role"] for row in objects].count("executable") == 1, "A objects")
        _require([row["role"] for row in objects].count("loader") == 1, "A loader")
        _require(len({row["id"] for row in objects}) == len(objects) and len({row["sha256"] for row in objects}) == len(objects), "A identity")
    if job == "B" and report["result"] == "pass":
        _require(all(row["source_sha256"] == row["sealed_sha256"] for row in metadata), "B sealed digest")
        _require(all(row["source_size_bytes"] == row["sealed_size_bytes"] for row in metadata), "B sealed size")
        _require(metadata[0]["output_sha256"] == metadata[1]["output_sha256"], "B deterministic output")
    if context is not None:
        observed = {name: report[name] for name in ("source", "envelope", "workflow", "runner")}
        _require(job == context.job and observed == _context_value(context), "semantic context")
def _validate(value: object, context: WorkflowContext | None = None) -> None:
    _validate_schema(value)
    _validate_semantics(value, context)
def report_path(job: str) -> Path:
    _require(job in DRIVERS, "report job")
    return Path(f"/tmp/cogs-native-qualification-{job}/report.json")
def _publish(directory_fd: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    _require(renameat2 is not None, "renameat2 unavailable")
    result = renameat2(directory_fd, b".report.tmp", directory_fd, b"report.json", 1)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
def _read_exact(descriptor: int, size: int) -> bytes:
    value = os.read(descriptor, size)
    _require(len(value) == size and os.read(descriptor, 1) == b"", "report short read")
    return value
def _remove_owned(directory: Path, directory_fd: int, parent_fd: int) -> None:
    failures: list[BaseException] = []
    for name in (".report.tmp", "report.json"):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except BaseException as error:
            failures.append(error)
    try:
        os.fsync(directory_fd)
    except BaseException as error:
        failures.append(error)
    try:
        os.close(directory_fd)
    except BaseException as error:
        failures.append(error)
    try:
        os.rmdir(directory.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except BaseException as error:
        failures.append(error)
    try:
        os.close(parent_fd)
    except BaseException as error:
        failures.append(error)
    if os.path.lexists(directory):
        failures.append(QualificationError("report baseline not restored"))
    if failures:
        raise ExceptionGroup("report cleanup", failures)
def finalize_report(
    context: WorkflowContext, result: str, checks: Mapping[str, str],
    metadata: list[Mapping[str, object]], cleanup: Mapping[str, bool],
    failure_phase: str | None = None, diagnostics: bytes | None = None,
) -> Path:
    _require(tuple(checks) == CHECK_IDS[context.job] and set(checks.values()) <= {"pass", "fail"}, "check inventory")
    _require(tuple(cleanup) == CLEANUP_KEYS and all(type(item) is bool for item in cleanup.values()), "cleanup")
    passing = all(item == "pass" for item in checks.values()) and all(cleanup.values())
    _require(result in {"pass", "fail"} and (result == "pass") == passing, "result coupling")
    _require((failure_phase is None and diagnostics is None) == passing, "failure coupling")
    if failure_phase is not None:
        _require(type(failure_phase) is str and SAFE.fullmatch(failure_phase) is not None, "failure phase")
    if diagnostics is not None:
        _require(type(diagnostics) is bytes and len(diagnostics) <= REPORT_LIMIT, "diagnostics bound")
    report = {
        "authority": AUTHORITY, "checks": [{"id": key, "outcome": item} for key, item in checks.items()],
        "cleanup": dict(cleanup), "diagnostics_sha256": None if diagnostics is None else hashlib.sha256(diagnostics).hexdigest(),
        "failure_phase": failure_phase, "job": context.job, "metadata": [dict(row) for row in metadata],
        "result": result, "version": VERSION, **_context_value(context),
    }
    raw = json.dumps(report, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _require(len(raw) <= REPORT_LIMIT and _decode(raw) == report, "report encoding")
    _validate(report, context)
    target, descriptor, directory_fd, parent_fd = report_path(context.job), -1, -1, -1
    try:
        _require(not os.path.lexists(target.parent), "report baseline")
        parent_fd = os.open(target.parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        os.mkdir(target.parent.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        directory_fd = os.open(target.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        directory_status = os.fstat(directory_fd)
        directory_owner = directory_status.st_uid == os.geteuid() and directory_status.st_gid == os.getegid()
        _require(stat.S_IMODE(directory_status.st_mode) == 0o700 and directory_owner, "report directory")
        descriptor = os.open(".report.tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        _require(os.write(descriptor, raw) == len(raw), "report short write")
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        written_owner = written.st_uid == os.geteuid() and written.st_gid == os.getegid()
        _require(stat.S_ISREG(written.st_mode) and stat.S_IMODE(written.st_mode) == 0o600 and written_owner, "report identity")
        _require(written.st_nlink == 1 and written.st_size == len(raw), "report generation")
        closing, descriptor = descriptor, -1
        os.close(closing)
        descriptor = os.open(".report.tmp", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
        reopened = os.fstat(descriptor)
        reread = _read_exact(descriptor, len(raw))
        _require(_generation(reopened) == _generation(written) and reread == raw, "staged generation")
        _validate(_decode(reread), context)
        closing, descriptor = descriptor, -1
        os.close(closing)
        _publish(directory_fd)
        os.fsync(directory_fd)
        descriptor = os.open("report.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
        published = os.fstat(descriptor)
        _require(_generation(published) == _generation(written) and _read_exact(descriptor, len(raw)) == raw, "published generation")
        closing, descriptor = descriptor, -1
        os.close(closing)
        closing, directory_fd = directory_fd, -1
        os.close(closing)
        closing, parent_fd = parent_fd, -1
        os.close(closing)
        return target
    except BaseException as primary:
        failures: list[BaseException] = [primary]
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(error)
        if parent_fd < 0: parent_fd = os.open(target.parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        if directory_fd < 0 and os.path.lexists(target.parent):
            directory_fd = os.open(target.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        if directory_fd >= 0 and parent_fd >= 0:
            try:
                _remove_owned(target.parent, directory_fd, parent_fd)
                directory_fd = parent_fd = -1
            except BaseException as error:
                failures.append(error)
        else:
            for current in (directory_fd, parent_fd):
                if current >= 0:
                    try:
                        os.close(current)
                    except BaseException as error:
                        failures.append(error)
        _require(not os.path.lexists(target), "failed report publication")
        raise ExceptionGroup("report publication", failures)
def cleanup_report(job: str) -> None:
    target = report_path(job)
    if not os.path.lexists(target.parent):
        return
    parent_fd = os.open(target.parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    directory_fd = os.open(target.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    descriptor = os.open(target.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    failures: list[BaseException] = []
    try:
        status = os.fstat(descriptor)
        identity = stat.S_ISREG(status.st_mode) and stat.S_IMODE(status.st_mode) == 0o600
        owner = status.st_uid == os.geteuid() and status.st_gid == os.getegid()
        _require(identity and owner and status.st_nlink == 1 and status.st_size <= REPORT_LIMIT, "cleanup report identity")
        _validate(_decode(_read_exact(descriptor, status.st_size)))
        current = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
        _require(_generation(current) == _generation(status), "cleanup report replacement")
    except BaseException as error: failures.append(error)
    try:
        os.close(descriptor)
    except BaseException as error: failures.append(error)
    try:
        _remove_owned(target.parent, directory_fd, parent_fd)
    except BaseException as error: failures.append(error)
    if failures: raise ExceptionGroup("uploaded report cleanup", failures)
def _main(arguments: list[str]) -> int:
    _require(len(arguments) == 2 and arguments[0] == "--cleanup" and arguments[1] in DRIVERS, "common entry")
    cleanup_report(arguments[1]); return 0
if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except BaseException:
        os.write(2, b"native-report-cleanup-failed\n")
        raise SystemExit(1)
