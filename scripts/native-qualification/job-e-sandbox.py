#!/usr/bin/python3
"""Job E: narrow client of the admitted production sandbox owner."""
from __future__ import annotations

import os
from pathlib import Path
import sys

REPORT_CHECK_IDS = (
    "mount_view_exact", "checkout_read_only", "user_namespace_exact",
    "pid_namespace_exact", "mount_namespace_exact", "network_namespace_exact",
    "pid_one", "capabilities_zero", "noroot_locked", "nnp_set",
    "seccomp_socket_denied", "seccomp_io_uring_denied",
    "no_acquisition_route", "checkout_unchanged", "all_reaped",
    "mounts_restored", "cleanup_restored",
)
# The two omitted report checks are derived by common from its retained baseline.
PRODUCTION_CHECK_IDS = tuple(
    name for name in REPORT_CHECK_IDS
    if name not in {"checkout_unchanged", "cleanup_restored"}
)
SANDBOX_RESULT_STRINGS = (
    "version", "source_revision", "source_set_sha256",
    "seccomp_program_sha256",
)
SANDBOX_RESULT_BOOLEANS = tuple("""
user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact
namespace_ownership_exact pid_one capabilities_zero noroot_locked no_new_privs
seccomp_installed seccomp_mode_exact seccomp_program_exact seccomp_denials_exact
no_acquisition_route root_readonly_noexec root_has_no_proc host_paths_absent
checkout_absent descriptors_restored children_reaped descendants_reaped mounts_restored
paths_restored namespaces_released namespace_handles_released
""".split())
SANDBOX_RESULT_FIELDS = SANDBOX_RESULT_STRINGS + SANDBOX_RESULT_BOOLEANS
SANDBOX_RESULT_VERSION = "cogs.sandbox-qualification/v1"
POLICY_SHA256 = "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2"


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
    """Independently close and map one primitive-only sandbox result."""
    _require(type(result) is dict and tuple(result) == SANDBOX_RESULT_FIELDS, "sandbox result shape")
    _require(all(type(result[name]) is str for name in SANDBOX_RESULT_STRINGS), "sandbox string fields")
    _require(all(type(result[name]) is bool for name in SANDBOX_RESULT_BOOLEANS), "sandbox boolean fields")
    identity = (result["version"], result["source_revision"], result["source_set_sha256"])
    _require(identity == (SANDBOX_RESULT_VERSION, revision, source_digest), "sandbox result identity")
    _require(_hex(result["source_set_sha256"]), "sandbox source digest")
    _require(
        result["seccomp_program_sha256"] == POLICY_SHA256,
        "sandbox policy digest",
    )
    _require(
        all(result[name] is True for name in SANDBOX_RESULT_BOOLEANS),
        "sandbox observation failed",
    )
    mount_view_exact = all(
        result[name]
        for name in ("root_readonly_noexec", "root_has_no_proc", "host_paths_absent")
    )
    seccomp_exact = all(
        result[name]
        for name in (
            "seccomp_installed",
            "seccomp_mode_exact",
            "seccomp_program_exact",
            "seccomp_denials_exact",
        )
    )
    checks = {
        "mount_view_exact": mount_view_exact,
        "checkout_read_only": result["checkout_absent"] and result["no_acquisition_route"],
        "user_namespace_exact": result["user_namespace_exact"] and result["namespace_ownership_exact"],
        "pid_namespace_exact": result["pid_namespace_exact"],
        "mount_namespace_exact": result["mount_namespace_exact"],
        "network_namespace_exact": result["network_namespace_exact"],
        "pid_one": result["pid_one"],
        "capabilities_zero": result["capabilities_zero"],
        "noroot_locked": result["noroot_locked"],
        "nnp_set": result["no_new_privs"],
        "seccomp_socket_denied": seccomp_exact,
        "seccomp_io_uring_denied": seccomp_exact,
        "no_acquisition_route": result["no_acquisition_route"],
        "all_reaped": result["children_reaped"] and result["descendants_reaped"],
        "mounts_restored": result["mounts_restored"],
    }
    _require(tuple(checks) == PRODUCTION_CHECK_IDS, "sandbox check inventory")
    _require(all(type(value) is bool and value for value in checks.values()), "Job E checks")
    return {"checks": checks, "policy_sha256": result["seccomp_program_sha256"]}


def _invoke_sandbox(session: object) -> tuple[dict[str, object], str, str]:
    """W1/W2 adapter: one exact held-byte, job-bound production operation."""
    result = session.run_fixed_operation("E")
    source_digest = session.source_set_sha256
    _require(type(result) is dict and _hex(source_digest), "admitted sandbox identity")
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
    return BaseExceptionGroup("Job E failure and cleanup", [primary, error])


def _run(common: object) -> int:
    session = common.NativeSession.begin("E", __file__)
    primary: BaseException | None = None
    qualified: dict[str, object] | None = None
    try:
        result, revision, source_digest = _invoke_sandbox(session)
        qualified = qualify(result, revision, source_digest)
    except Exception as error:
        primary = error

    try:
        evidence = session.settle_native_phase()
    except Exception as error:
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
        metadata = [{
            "id": "sandbox-policy",
            "role": "policy",
            "sha256": qualified["policy_sha256"],
            "size_bytes": 0,
        }]
    restored = evidence is not None and evidence.restored is True
    failed = primary is not None or not restored
    phase = "sandbox" if failed else None
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
        raise RuntimeError("Job E requires fixed unprivileged workflow entry")
    return _run(_load_common())


if __name__ == "__main__":
    try:
        exit_code = _main()
    except Exception:
        os.write(2, b"native-job-e-failed\n")
        exit_code = 1
    raise SystemExit(exit_code)
