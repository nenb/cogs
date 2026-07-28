#!/usr/bin/python3
"""Shared metadata utilities for the six fixed Outcome 2 native jobs."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import time
from typing import Callable, Mapping

VERSION = "cogs.native-qualification/v1alpha1"
AUTHORITY = "exact-run-native-qualification"
ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMMON = ROOT / "scripts/native-qualification/common.py"
REPORT_LIMIT = 32_768
CLEANUP_KEYS = ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")
DRIVERS = {
    "A": "job-a-runtime-mappings.py",
    "B": "job-b-compression.py",
    "C": "job-c-descriptors.py",
    "D": "job-d-process-lifecycle.py",
    "E": "job-e-sandbox.py",
    "integration": "thin-integration.py",
}
CHECK_IDS = {
    "A": ("elf_real", "python_closure_exact", "map_files_trusted", "mapped_closure_equal", "mapping_stable", "helper_reaped", "cleanup_restored"),
    "B": ("gzip_source_exact", "gzip_sealed_exec", "zstd_source_exact", "zstd_sealed_exec", "decompression_deterministic", "network_denied", "children_exact", "cleanup_restored"),
    "C": ("nofile_measured", "nofile_normalized", "fd_198_exact", "fd_4096_exact", "close_range_exact", "cloexec_exact", "inheritance_exact", "limit_restored", "cleanup_restored"),
    "D": ("pdeathsig_armed", "parent_handshake_exact", "before_release_death", "after_release_death", "starttime_revalidated", "session_owned", "process_group_owned", "term_kill_bounded", "all_reaped", "cleanup_restored"),
    "E": ("mount_view_exact", "checkout_read_only", "user_namespace_exact", "pid_namespace_exact", "mount_namespace_exact", "network_namespace_exact", "pid_one", "capabilities_zero", "noroot_locked", "nnp_set", "seccomp_socket_denied", "seccomp_io_uring_denied", "no_acquisition_route", "checkout_unchanged", "all_reaped", "mounts_restored", "cleanup_restored"),
    "integration": ("closure_prepared", "handoff_exact", "gzip_deterministic", "zstd_deterministic", "marker_exact", "no_linked_evidence", "cleanup_restored"),
}
ENV_KEYS = frozenset({
    "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "NQ_REPOSITORY", "NQ_HEAD_SHA",
    "NQ_ENVELOPE_SHA", "NQ_WORKFLOW_SHA", "NQ_MERGE_SHA", "NQ_BASE_SHA", "NQ_JOB_ID",
    "NQ_RUN_ID", "NQ_RUN_ATTEMPT", "NQ_PR_NUMBER", "NQ_RUNNER_VERSION",
})
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")


class QualificationError(RuntimeError):
    """A fixed qualification contract was not met."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _sha256(path: Path) -> str:
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= 1_048_576, "source object")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65_536):
            digest.update(block)
    after = path.lstat()
    generation = lambda value: (
        value.st_mode, value.st_uid, value.st_gid, value.st_dev, value.st_ino,
        value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    _require(generation(before) == generation(after), "source generation")
    return digest.hexdigest()


def _integer(value: str, name: str) -> int:
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None, name)
    return int(value)


@dataclass(frozen=True)
class WorkflowContext:
    job: str
    repository: str
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
        _require(expected_job in DRIVERS, "job")
        _require(set(environment) == ENV_KEYS, "environment allowlist")
        _require(environment["LC_ALL"] == "C", "locale")
        _require(environment["PYTHONDONTWRITEBYTECODE"] == "1", "bytecode")
        _require(environment["PYTHONHASHSEED"] == "0", "hash seed")
        driver = Path(driver_file).absolute()
        expected_driver = COMMON.parent / DRIVERS[expected_job]
        _require(driver == expected_driver and driver.is_file(), "fixed driver")
        values = [environment[name] for name in ("NQ_HEAD_SHA", "NQ_ENVELOPE_SHA", "NQ_WORKFLOW_SHA", "NQ_MERGE_SHA", "NQ_BASE_SHA")]
        _require(all(HEX40.fullmatch(value) for value in values), "source identity")
        _require(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", environment["NQ_REPOSITORY"]) is not None, "repository")
        _require(SAFE.fullmatch(environment["NQ_JOB_ID"]) is not None, "job id")
        _require(SAFE.fullmatch(environment["NQ_RUNNER_VERSION"]) is not None, "runner version")
        kernel = platform.release()
        architecture = platform.machine()
        _require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.+]*", kernel) is not None, "kernel release")
        _require(architecture == "x86_64", "architecture")
        return cls(
            expected_job, environment["NQ_REPOSITORY"], *values,
            environment["NQ_JOB_ID"], _integer(environment["NQ_RUN_ID"], "run id"),
            _integer(environment["NQ_RUN_ATTEMPT"], "run attempt"),
            _integer(environment["NQ_PR_NUMBER"], "pull request"), environment["NQ_RUNNER_VERSION"],
            kernel, architecture, _sha256(WORKFLOW), _sha256(driver), _sha256(COMMON),
        )


class Deadline:
    def __init__(self, seconds: int, clock: Callable[[], int] = time.monotonic_ns):
        _require(type(seconds) is int and 1 <= seconds <= 30, "deadline bound")
        self._clock = clock
        self._end = clock() + seconds * 1_000_000_000

    def remaining(self) -> float:
        return max(0, self._end - self._clock()) / 1_000_000_000

    def check(self) -> None:
        _require(self._clock() < self._end, "deadline expired")


@dataclass(frozen=True)
class Baseline:
    values: tuple[tuple[str, object], ...]

    @classmethod
    def capture(cls, values: Mapping[str, object]) -> "Baseline":
        _require(bool(values) and all(SAFE.fullmatch(key) for key in values), "baseline names")
        canonical = json.loads(json.dumps(values, allow_nan=False, sort_keys=True, separators=(",", ":")))
        return cls(tuple(sorted(canonical.items())))

    def require_restored(self, values: Mapping[str, object]) -> None:
        _require(self == Baseline.capture(values), "baseline not restored")


def _context_value(context: WorkflowContext) -> dict[str, object]:
    return {
        "source": {"checkout_sha": context.head_sha, "driver_blob_sha256": context.driver_blob_sha256, "head_sha": context.head_sha, "common_blob_sha256": context.common_blob_sha256},
        "envelope": {"base_sha": context.base_sha, "event_merge_sha": context.merge_sha, "github_sha": context.envelope_sha, "pull_request_number": context.pull_request_number, "repository": context.repository, "run_attempt": context.run_attempt, "run_id": context.run_id},
        "workflow": {"blob_sha256": context.workflow_blob_sha256, "job_id": context.job_id, "path": ".github/workflows/ci.yml", "workflow_sha": context.workflow_sha},
        "runner": {"architecture": context.architecture, "image": "ubuntu-24.04", "image_version": context.runner_version, "kernel_release": context.kernel_release},
    }


def finalize_report(
    context: WorkflowContext,
    result: str,
    checks: Mapping[str, str],
    metadata: list[Mapping[str, object]],
    cleanup: Mapping[str, bool],
    failure_phase: str | None = None,
    diagnostics: bytes | None = None,
) -> Path:
    _require(tuple(checks) == CHECK_IDS[context.job], "check order")
    _require(set(checks.values()) <= {"pass", "fail"}, "check outcome")
    _require(tuple(cleanup) == CLEANUP_KEYS and all(type(value) is bool for value in cleanup.values()), "cleanup")
    _require(result in {"pass", "fail"}, "result")
    passing = all(value == "pass" for value in checks.values()) and all(cleanup.values())
    _require((result == "pass") == passing, "result coupling")
    _require((failure_phase is None and diagnostics is None) == passing, "failure coupling")
    if failure_phase is not None:
        _require(type(failure_phase) is str and SAFE.fullmatch(failure_phase) is not None, "failure phase")
    if diagnostics is not None:
        _require(type(diagnostics) is bytes and len(diagnostics) <= REPORT_LIMIT, "diagnostics bound")
    rows = [dict(row) for row in metadata]
    _require(len(rows) <= 128, "metadata bound")
    for row in rows:
        _require(set(row) == {"id", "role", "sha256", "size_bytes"}, "metadata shape")
        _require(SAFE.fullmatch(str(row["id"])) is not None and SAFE.fullmatch(str(row["role"])) is not None, "metadata label")
        _require(type(row["size_bytes"]) is int and 0 <= row["size_bytes"] <= 536_870_912, "metadata size")
        _require(HEX64.fullmatch(str(row["sha256"])) is not None, "metadata digest")
    report = {
        "authority": AUTHORITY,
        "checks": [{"id": key, "outcome": value} for key, value in checks.items()],
        "cleanup": dict(cleanup),
        "diagnostics_sha256": None if diagnostics is None else hashlib.sha256(diagnostics).hexdigest(),
        "failure_phase": failure_phase,
        "job": context.job,
        "metadata": rows,
        "result": result,
        "version": VERSION,
        **_context_value(context),
    }
    raw = json.dumps(
        report, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode() + b"\n"
    reencoded = json.dumps(
        json.loads(raw), sort_keys=True, separators=(",", ":"),
    ).encode() + b"\n"
    _require(len(raw) <= REPORT_LIMIT and reencoded == raw, "canonical report")
    target = Path(f"/tmp/cogs-native-qualification-{context.job}.json")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        _require(os.write(descriptor, raw) == len(raw), "report short write")
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        _require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1 and status.st_size == len(raw), "report identity")
    finally:
        os.close(descriptor)
    return target
