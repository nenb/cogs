#!/usr/bin/python3
"""Thin client of the ordinary admitted production runtime owner."""
from __future__ import annotations

import os
from pathlib import Path
import sys

REPORT_CHECK_IDS = (
    "closure_prepared", "handoff_exact", "gzip_deterministic",
    "zstd_deterministic", "marker_exact", "no_linked_evidence",
    "cleanup_restored",
)
# Common alone derives the report's cleanup_restored check and cleanup object.
PRODUCTION_CHECK_IDS = REPORT_CHECK_IDS[:-1]
RESULT_STRINGS = (
    "version", "marker", "source_revision", "source_set_sha256",
    "closure_sha256", "gzip_output_sha256", "zstd_output_sha256",
)
RESULT_BOOLEANS = tuple("""
mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact
network_namespace_exact namespace_ownership_exact namespace_handles_exact pid_one
supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero
inheritable_capabilities_zero bounding_capabilities_zero ambient_capabilities_zero
capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route
root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent limits_exact
descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
namespaces_released namespace_handles_released
""".split())
RESULT_FIELDS = RESULT_STRINGS + RESULT_BOOLEANS
RESULT_VERSION = "cogs.runtime-qualification/v1"
MARKER = "cogs-runtime-qualification-v1"
OUTPUT_SHA256 = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _hex(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def qualify(result: object, revision: str, source_digest: str) -> dict[str, object]:
    """Independently close the ordinary complete production result."""
    _require(type(result) is dict and tuple(result) == RESULT_FIELDS, "production result shape")
    _require(all(type(result[name]) is str for name in RESULT_STRINGS), "production string fields")
    _require(all(type(result[name]) is bool for name in RESULT_BOOLEANS), "production boolean fields")
    identity = tuple(result[name] for name in ("version", "marker", "source_revision", "source_set_sha256"))
    _require(identity == (RESULT_VERSION, MARKER, revision, source_digest), "production result identity")
    digest_names = (
        "source_set_sha256",
        "closure_sha256",
        "gzip_output_sha256",
        "zstd_output_sha256",
    )
    digests = tuple(result[name] for name in digest_names)
    _require(all(_hex(value) for value in digests), "production result digests")
    _require(
        all(result[name] is True for name in RESULT_BOOLEANS),
        "production observation failed",
    )
    outputs_exact = (
        result["gzip_output_sha256"] == OUTPUT_SHA256
        and result["zstd_output_sha256"] == OUTPUT_SHA256
    )
    _require(outputs_exact, "fixed production output")
    closure_prepared = (
        result["source_revision"] == revision
        and result["source_set_sha256"] == source_digest
        and _hex(result["closure_sha256"])
    )
    handoff_exact = (
        result["mapped_generations_exact"]
        and result["exec_descriptor_consumed"]
        and result["no_acquisition_route"]
    )
    checks = {
        "closure_prepared": closure_prepared,
        "handoff_exact": handoff_exact,
        "gzip_deterministic": result["gzip_output_sha256"] == OUTPUT_SHA256,
        "zstd_deterministic": result["zstd_output_sha256"] == OUTPUT_SHA256,
        "marker_exact": result["version"] == RESULT_VERSION and result["marker"] == MARKER,
        "no_linked_evidence": tuple(result) == RESULT_FIELDS,
    }
    _require(tuple(checks) == PRODUCTION_CHECK_IDS, "integration check inventory")
    _require(all(type(value) is bool and value for value in checks.values()), "integration checks")
    metadata = {name: result[name] for name in (
        "closure_sha256", "gzip_output_sha256", "source_set_sha256", "zstd_output_sha256",
    )}
    return {"checks": checks, "metadata": metadata}


def _invoke_complete_runtime(session: object) -> tuple[dict[str, object], str, str]:
    """W1/W2 adapter: one exact held-byte ordinary production operation."""
    result = session.run_fixed_operation("integration")
    source_digest = session.source_set_sha256
    _require(type(result) is dict and _hex(source_digest), "admitted runtime identity")
    return result, session.context.head_sha, source_digest


def _load_common() -> object:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    try:
        return __import__("common")
    finally:
        del sys.path[0]


def _combine(primary: BaseException | None, error: BaseException) -> BaseException:
    if primary is None:
        return error
    return BaseExceptionGroup("integration failure and cleanup", [primary, error])


def _run(common: object) -> int:
    session = common.NativeSession.begin("integration", __file__)
    primary: BaseException | None = None
    qualified: dict[str, object] | None = None
    try:
        result, revision, source_digest = _invoke_complete_runtime(session)
        qualified = qualify(result, revision, source_digest)
    except BaseException as error:
        primary = error

    try:
        evidence = session.settle_native_phase()
    except BaseException as error:
        primary = _combine(primary, error)
        evidence = None

    observations = (
        dict.fromkeys(PRODUCTION_CHECK_IDS, False)
        if qualified is None
        else qualified["checks"]
    )
    checks = {
        name: "pass" if value is True else "fail"
        for name, value in observations.items()
    }
    metadata = []
    if qualified is not None and primary is None:
        metadata = [
            {
                "id": name.removesuffix("_sha256"),
                "role": "digest",
                "sha256": value,
                "size_bytes": 0,
            }
            for name, value in qualified["metadata"].items()
        ]
    restored = evidence is not None and evidence.restored is True
    failed = primary is not None or not restored
    phase = "integration" if failed else None
    diagnostic = (
        (type(primary).__name__ if primary is not None else "CleanupEvidence").encode()
        if failed else None
    )
    candidate = common.ReportCandidate(
        production_checks=checks,
        metadata=metadata,
        failure_phase=phase,
        diagnostics=diagnostic,
        primary_error=primary,
    )
    session.publish(candidate)
    return 0 if primary is None and restored else 1


def _main() -> int:
    if sys.argv != [sys.argv[0], "--workflow-bound"] or os.geteuid() == 0:
        raise RuntimeError("integration requires fixed unprivileged workflow entry")
    return _run(_load_common())


if __name__ == "__main__":
    try:
        exit_code = _main()
    except Exception:
        os.write(2, b"native-integration-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)
