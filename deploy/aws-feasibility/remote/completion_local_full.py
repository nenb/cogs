"""Strict local Kata result codec and deliberately blocked production entry.

A decoded report is data, never authority.  The future coordinator must provide
an in-process private typed receipt; this slice intentionally defines no public
receipt constructor or report-to-receipt adaptation.
"""
import hashlib
import json
import sys

VERSION = "cogs.stage2-workload-local-qualification/v2"
SCHEMA_REGISTRY = ((VERSION, "schemas/stage2-workload-local-qualification-v2.json"),)
MAX_RESULT_BYTES = 32 * 1024
AUTHORITY = "local-only-standalone-kata-stopped-before-step5"
LIMITATIONS = (
    "not-aws-evidence",
    "not-production-evidence",
    "not-release-evidence",
    "no-seven-cycle-controller-authority",
    "no-retry-or-promotion-authority",
)
DIGEST_FIELDS = (
    "source_manifest_sha256", "host_attestation_sha256", "runtime_attestation_sha256",
    "rootfs_sha256", "artifact_sha256", "candidate_sha256", "final_pin_sha256",
    "guest_program_sha256", "owner_implementation_sha256",
)
TEARDOWN_PHASES = (
    "READINESS_REVOKED", "TASK_STOPPED", "NETWORK_ABSENT", "TASK_ABSENT",
    "CONTAINER_ABSENT", "RUNTIME_PROCESSES_ABSENT", "SHARE_AND_MOUNTS_ABSENT",
    "FIREWALL_ABSENT", "CONTAINERD_ABSENT", "INPUTS_ABSENT", "ROOTFS_ABSENT",
    "FINAL_BASELINES", "RETIRED",
)
RESIDUE_FACTS = (
    "tasks", "containers", "shim_processes", "qemu_processes", "virtiofsd_processes",
    "containerd_processes", "child_processes", "cgroups", "namespaces", "veth_devices",
    "tap_devices", "traffic_control", "firewall", "shares", "mounts", "inputs",
    "operation_state", "runtime_state", "runtime_cache", "rootfs_lease", "rootfs_build",
    "rootfs_publication", "unexpected_descriptors", "network_state", "network_routes",
    "network_addresses", "firewall_baseline", "mount_baseline", "source_identity",
    "input_control", "share_paths", "runtime_staging", "report_staging",
    "descriptor_baseline", "process_baseline", "cgroup_baseline", "namespace_baseline",
)
FAILURE_CODES = frozenset({
    "preflight", "source-binding", "attestation", "kvm", "lifecycle-start", "ssh",
    "git-sample", "build-sample", "install-sample", "deletion", "cleanup", "residue",
    "deadline", "interrupted", "uncertain",
})
ROOT_KEYS = {
    "version", "result", "failure_code", "qualified", "authority", "limitations",
    "bindings", "platform", "lifecycle", "operation", "timings", "timing_summaries",
    "teardown", "zero_residue",
}


class LocalResultError(Exception):
    pass


class LocalResultBlocked(Exception):
    pass


def _require(condition):
    if not condition:
        raise LocalResultError()


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names))


def _integer(value, low, high=None):
    _require(type(value) is int and value >= low and (high is None or value <= high))


def _digest(value):
    _require(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value))


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise LocalResultError() from error


def _binding_digest(bindings, operation_sha256, journal_sha256):
    view = dict(bindings)
    view.update(operation_sha256=operation_sha256, journal_sha256=journal_sha256)
    return hashlib.sha256(_canonical(view)).hexdigest()


def _summary(rows):
    durations = [row["duration_ns"] for row in rows]
    return {
        "count": len(durations),
        "total_ns": sum(durations),
        "minimum_ns": min(durations) if durations else None,
        "maximum_ns": max(durations) if durations else None,
    }


def _validate_rows(rows, binding):
    _require(type(rows) is list and len(rows) <= 7)
    failed = False
    for index, row in enumerate(rows, 1):
        _keys(row, {"ordinal", "duration_ns", "outcome", "deletion", "binding_sha256"})
        _integer(row["ordinal"], 1, 7)
        _integer(row["duration_ns"], 1, 3_600_000_000_000)
        _require(row["ordinal"] == index and row["outcome"] in ("pass", "failure"))
        _require(row["deletion"] in ("absent", "not-proved") and row["binding_sha256"] == binding)
        _require(not failed)
        failed = row["outcome"] == "failure" or row["deletion"] != "absent"
    return failed


def validate_result(value):
    """Independently validate all report semantics; return recomputed qualification."""
    _keys(value, ROOT_KEYS)
    _require(value["version"] == VERSION and value["result"] in ("pass", "failure"))
    _require(type(value["qualified"]) is bool and value["authority"] == AUTHORITY)
    _require(type(value["limitations"]) is list and tuple(value["limitations"]) == LIMITATIONS)

    bindings = value["bindings"]
    _keys(bindings, {"source_head", *DIGEST_FIELDS})
    head = bindings["source_head"]
    _require(type(head) is str and len(head) == 40 and all(c in "0123456789abcdef" for c in head))
    for name in DIGEST_FIELDS:
        _digest(bindings[name])

    platform = value["platform"]
    _keys(platform, {"kvm_api", "qmp_present", "qmp_enabled"})
    _require(platform["kvm_api"] is None or (type(platform["kvm_api"]) is int and platform["kvm_api"] == 12))
    _require(type(platform["qmp_present"]) is bool and type(platform["qmp_enabled"]) is bool)
    _require(not platform["qmp_enabled"] or platform["qmp_present"])

    lifecycle = value["lifecycle"]
    _keys(lifecycle, {"attempts", "outcome", "ssh_attempts", "ssh_outcome"})
    _integer(lifecycle["attempts"], 0, 1)
    _integer(lifecycle["ssh_attempts"], 0, 1)
    _require(lifecycle["ssh_attempts"] <= lifecycle["attempts"])
    for attempts, outcome in ((lifecycle["attempts"], lifecycle["outcome"]),
                              (lifecycle["ssh_attempts"], lifecycle["ssh_outcome"])):
        _require(outcome in ("pass", "failure", "not-reached"))
        _require((attempts == 0) == (outcome == "not-reached"))
    _require(not platform["qmp_present"] or lifecycle["attempts"] == 1)

    operation = value["operation"]
    _keys(operation, {"operation_sha256", "journal_sha256", "binding_sha256", "source_head",
                      "source_manifest_sha256", "final_pin_sha256", "status"})
    _require(operation["source_head"] == head)
    _require(operation["source_manifest_sha256"] == bindings["source_manifest_sha256"])
    _require(operation["final_pin_sha256"] == bindings["final_pin_sha256"])
    _require(operation["status"] in ("not-created", "uncertain", "retired"))
    operation_digests = [operation[name] for name in
                         ("operation_sha256", "journal_sha256", "binding_sha256")]
    if operation["status"] == "not-created":
        _require(operation_digests == [None, None, None] and lifecycle["attempts"] == 0)
        binding = None
    else:
        for digest in operation_digests:
            _digest(digest)
        binding = _binding_digest(bindings, operation["operation_sha256"], operation["journal_sha256"])
        _require(operation["binding_sha256"] == binding)

    timings = value["timings"]
    summaries = value["timing_summaries"]
    _keys(timings, {"git", "build", "install"})
    _keys(summaries, {"git", "build", "install"})
    timing_failed = False
    for name in ("git", "build", "install"):
        timing_failed = _validate_rows(timings[name], binding) or timing_failed
        summary = summaries[name]
        _keys(summary, {"count", "total_ns", "minimum_ns", "maximum_ns"})
        _require(summary == _summary(timings[name]))
        for number in summary.values():
            _require(number is None or type(number) is int)
    git_rows, build_rows, install_rows = timings["git"], timings["build"], timings["install"]
    if len(git_rows) < 7 or any(row["outcome"] != "pass" for row in git_rows):
        _require(not build_rows and not install_rows)
    _require(len(install_rows) <= len(build_rows) <= len(install_rows) + 1)

    teardown = value["teardown"]
    _require(type(teardown) is list and len(teardown) == len(TEARDOWN_PHASES))
    for expected, row in zip(TEARDOWN_PHASES, teardown, strict=True):
        _keys(row, {"phase", "outcome", "binding_sha256"})
        _require(row["phase"] == expected and row["outcome"] in ("pass", "failure", "not-reached"))
        _require(row["binding_sha256"] == binding)

    residue = value["zero_residue"]
    _keys(residue, RESIDUE_FACTS)
    _require(all(item in ("absent", "not-proved") for item in residue.values()))

    complete_rows = all(len(timings[name]) == 7 for name in timings)
    rows_pass = complete_rows and not timing_failed and all(
        row["outcome"] == "pass" and row["deletion"] == "absent"
        for rows in timings.values() for row in rows)
    qualified = (
        platform == {"kvm_api": 12, "qmp_present": True, "qmp_enabled": True}
        and lifecycle == {"attempts": 1, "outcome": "pass", "ssh_attempts": 1, "ssh_outcome": "pass"}
        and operation["status"] == "retired" and rows_pass
        and all(row["outcome"] == "pass" for row in teardown)
        and all(item == "absent" for item in residue.values())
    )
    _require(value["qualified"] == qualified)
    if value["result"] == "pass":
        _require(qualified and value["failure_code"] is None)
    else:
        _require(not qualified and value["failure_code"] in FAILURE_CODES)
    return qualified


def canonical_result(value):
    validate_result(value)
    raw = _canonical(value) + b"\n"
    _require(len(raw) <= MAX_RESULT_BYTES)
    return raw


def load_result(raw):
    """Load only canonical ASCII JSON.  The returned dictionary grants no authority."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RESULT_BYTES and raw.endswith(b"\n"))
    try:
        text = raw.decode("ascii")
        def unique(rows):
            value = {}
            for key, item in rows:
                _require(type(key) is str and key not in value)
                value[key] = item
            return value
        value = json.loads(text, object_pairs_hook=unique,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except LocalResultError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise LocalResultError() from error
    _require(canonical_result(value) == raw)
    return value


def main():
    """Zero-argument stub: no report, JSON, path, or environment can open production."""
    if len(sys.argv) != 1:
        raise LocalResultBlocked()
    # Deliberately no coordinator import and no receipt adaptation in this slice.
    raise LocalResultBlocked()


if __name__ == "__main__":
    try:
        main()
    except LocalResultBlocked:
        raise SystemExit(3)
    except LocalResultError:
        raise SystemExit(2)
