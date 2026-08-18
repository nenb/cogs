"""Strict non-authoritative local Kata result data and a blocked entry.

Decoded or canonical report bytes never grant authority.  A future coordinator
must privately type and custody-bind the complete bytes plus independently
verified source and journal facts; no report-to-receipt adaptation exists here.
"""
import hashlib
import json
import sys

VERSION = "cogs.stage2-workload-local-qualification/v2"
SCHEMA_REGISTRY = ((VERSION, "schemas/stage2-workload-local-qualification-v2.json"),)
MAX_RESULT_BYTES = 32 * 1024
AUTHORITY = "non-authoritative-local-qualification-report-data"
VALIDATION_CLASSIFICATION = "schema-insufficient-independent-semantics-and-private-receipt-required"
LIMITATIONS = (
    "report-data-does-not-establish-local-qualification-authority",
    "requires-exact-private-receipt-and-custody-validation",
    "not-aws-evidence", "not-production-evidence", "not-release-evidence",
    "no-seven-cycle-controller-authority", "no-retry-or-promotion-authority",
)
DIGEST_FIELDS = (
    "source_manifest_sha256", "host_attestation_sha256", "runtime_attestation_sha256",
    "rootfs_sha256", "artifact_sha256", "candidate_sha256", "final_pin_sha256",
    "guest_program_sha256", "owner_implementation_sha256",
)
ADMISSION_PHASES = ("preflight", "source_binding", "attestation", "kvm")
ADMISSION_CODES = ("preflight", "source-binding", "attestation", "kvm")
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
FAILURE_CODES = frozenset((*ADMISSION_CODES, "lifecycle-start", "ssh", "git-sample",
                           "build-sample", "install-sample", "deletion", "cleanup",
                           "residue", "uncertain"))
ROOT_KEYS = {
    "version", "result", "failure_code", "qualified", "authority", "limitations",
    "validation_classification", "bindings", "admission", "platform", "lifecycle",
    "operation", "timings", "timing_summaries", "teardown", "zero_residue",
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
    durations = [row["duration_ns"] for row in rows if row["duration_ns"] is not None]
    return {"count": len(durations), "total_ns": sum(durations),
            "minimum_ns": min(durations) if durations else None,
            "maximum_ns": max(durations) if durations else None}


def _validate_rows(rows, binding):
    _require(type(rows) is list and len(rows) == 7)
    for ordinal, row in enumerate(rows, 1):
        _keys(row, {"ordinal", "duration_ns", "outcome", "deletion", "binding_sha256"})
        _integer(row["ordinal"], 1, 7)
        _require(row["ordinal"] == ordinal and row["outcome"] in ("pass", "failure", "not-reached"))
        _require(row["binding_sha256"] == binding)
        if row["outcome"] == "not-reached":
            _require(row["duration_ns"] is None and row["deletion"] == "not-reached")
        else:
            _integer(row["duration_ns"], 1, 3_600_000_000_000)
            _require(row["deletion"] in ("absent", "not-proved"))


def _admission_failure(admission):
    _keys(admission, ADMISSION_PHASES)
    first = None
    blocked = False
    for phase, code in zip(ADMISSION_PHASES, ADMISSION_CODES, strict=True):
        outcome = admission[phase]
        _require(outcome in ("pass", "failure", "not-reached"))
        if blocked:
            _require(outcome == "not-reached")
        elif outcome == "failure":
            first, blocked = code, True
        else:
            _require(outcome == "pass")
    return first


def _not_reached(rows, start=0):
    return all(row["outcome"] == "not-reached" for row in rows[start:])


def _phase_failure(rows, later, code):
    for index, row in enumerate(rows):
        if row["outcome"] == "not-reached":
            _require(_not_reached(rows, index) and all(_not_reached(group) for group in later))
            return code
        if row["outcome"] == "failure":
            _require(_not_reached(rows, index + 1) and all(_not_reached(group) for group in later))
            return code
        if row["deletion"] != "absent":
            _require(_not_reached(rows, index + 1) and all(_not_reached(group) for group in later))
            return "deletion"
    return None


def _work_failure(timings):
    git, build, install = timings["git"], timings["build"], timings["install"]
    return (_phase_failure(git, (build, install), "git-sample")
            or _phase_failure(build, (install,), "build-sample")
            or _phase_failure(install, (), "install-sample"))


def _teardown_failure(teardown, binding, operation_status, residue):
    _require(type(teardown) is list and len(teardown) == len(TEARDOWN_PHASES))
    first_bad = None
    unreachable = False
    for index, (expected, row) in enumerate(zip(TEARDOWN_PHASES, teardown, strict=True)):
        _keys(row, {"phase", "outcome", "binding_sha256"})
        _require(row["phase"] == expected and row["outcome"] in ("pass", "failure", "not-reached"))
        _require(row["binding_sha256"] == binding)
        if unreachable:
            _require(row["outcome"] == "not-reached")
        elif row["outcome"] == "not-reached":
            first_bad, unreachable = first_bad if first_bad is not None else index, True
        elif row["outcome"] == "failure" and first_bad is None:
            first_bad = index
    all_absent = all(item == "absent" for item in residue.values())
    all_pass = first_bad is None
    if operation_status == "not-created":
        _require(all(row["outcome"] == "not-reached" for row in teardown) and binding is None)
    elif operation_status == "retired":
        _require(all_pass and all_absent)
    else:
        _require(not all_pass and teardown[-1]["outcome"] != "pass" and not all_absent)
    if first_bad is None:
        return None
    if first_bad >= TEARDOWN_PHASES.index("FINAL_BASELINES") and not all_absent:
        return "residue"
    return "cleanup"


def validate_result(value):
    """Validate one closed execution history and recompute its first failure."""
    _keys(value, ROOT_KEYS)
    _require(value["version"] == VERSION and value["result"] in ("pass", "failure"))
    _require(type(value["qualified"]) is bool and value["authority"] == AUTHORITY)
    _require(value["validation_classification"] == VALIDATION_CLASSIFICATION)
    _require(type(value["limitations"]) is list and tuple(value["limitations"]) == LIMITATIONS)

    bindings = value["bindings"]
    _keys(bindings, {"source_head", *DIGEST_FIELDS})
    head = bindings["source_head"]
    _require(type(head) is str and len(head) == 40 and all(c in "0123456789abcdef" for c in head))
    for name in DIGEST_FIELDS:
        _digest(bindings[name])
    first_failure = _admission_failure(value["admission"])

    platform = value["platform"]
    _keys(platform, {"observation", "kvm_api", "qmp_present", "qmp_enabled"})
    _require(platform["observation"] in ("not-reached", "failure", "pass"))
    _require(platform["kvm_api"] is None or (type(platform["kvm_api"]) is int and platform["kvm_api"] == 12))
    _require(type(platform["qmp_present"]) is bool and type(platform["qmp_enabled"]) is bool)
    _require(not platform["qmp_enabled"] or platform["qmp_present"])
    platform_pass = {"observation": "pass", "kvm_api": 12,
                     "qmp_present": True, "qmp_enabled": True}
    platform_unobserved = {"observation": "not-reached", "kvm_api": None,
                           "qmp_present": False, "qmp_enabled": False}
    kvm_outcome = value["admission"]["kvm"]
    if kvm_outcome == "pass":
        _require(platform == platform_pass)
    elif kvm_outcome == "not-reached":
        _require(platform == platform_unobserved)
    else:
        favorable = platform["kvm_api"] == 12 and platform["qmp_present"] and platform["qmp_enabled"]
        _require(platform["observation"] == "failure" and not favorable)

    lifecycle = value["lifecycle"]
    _keys(lifecycle, {"attempts", "outcome", "ssh_attempts", "ssh_outcome"})
    for attempts_name, outcome_name in (("attempts", "outcome"), ("ssh_attempts", "ssh_outcome")):
        attempts, outcome = lifecycle[attempts_name], lifecycle[outcome_name]
        _integer(attempts, 0, 1)
        _require(outcome in ("pass", "failure", "not-reached"))
        _require((attempts == 0) == (outcome == "not-reached"))

    operation = value["operation"]
    _keys(operation, {"operation_sha256", "journal_sha256", "binding_sha256", "source_head",
                      "source_manifest_sha256", "final_pin_sha256", "status"})
    _require(operation["source_head"] == head)
    _require(operation["source_manifest_sha256"] == bindings["source_manifest_sha256"])
    _require(operation["final_pin_sha256"] == bindings["final_pin_sha256"])
    _require(operation["status"] in ("not-created", "uncertain", "retired"))
    digests = [operation[name] for name in ("operation_sha256", "journal_sha256", "binding_sha256")]
    if operation["status"] == "not-created":
        _require(digests == [None, None, None] and lifecycle["attempts"] == lifecycle["ssh_attempts"] == 0)
        binding = None
    else:
        _require(first_failure is None)
        for digest in digests:
            _digest(digest)
        binding = _binding_digest(bindings, operation["operation_sha256"], operation["journal_sha256"])
        _require(operation["binding_sha256"] == binding)

    timings, summaries = value["timings"], value["timing_summaries"]
    _keys(timings, {"git", "build", "install"})
    _keys(summaries, {"git", "build", "install"})
    for name in ("git", "build", "install"):
        _validate_rows(timings[name], binding)
        _keys(summaries[name], {"count", "total_ns", "minimum_ns", "maximum_ns"})
        _require(summaries[name] == _summary(timings[name]))
        _require(all(number is None or type(number) is int for number in summaries[name].values()))

    work_started = any(not _not_reached(rows) for rows in timings.values())
    platform_succeeded = platform == platform_pass
    if lifecycle["attempts"]:
        _require(operation["status"] != "not-created" and first_failure is None and platform_succeeded)
    if lifecycle["ssh_attempts"]:
        _require(lifecycle["attempts"] == 1 and lifecycle["outcome"] == "pass" and platform_succeeded)
    _require(lifecycle["ssh_attempts"] <= lifecycle["attempts"])
    if work_started:
        _require(lifecycle["ssh_attempts"] == 1 and lifecycle["ssh_outcome"] == "pass")

    if first_failure is None:
        if operation["status"] == "not-created":
            first_failure = "lifecycle-start"
        elif lifecycle["attempts"] == 0:
            first_failure = "uncertain" if operation["status"] == "uncertain" else "lifecycle-start"
        elif lifecycle["outcome"] == "failure":
            _require(lifecycle["ssh_attempts"] == 0 and not work_started)
            first_failure = "lifecycle-start"
        elif lifecycle["ssh_attempts"] == 0 or lifecycle["ssh_outcome"] == "failure":
            _require(not work_started)
            first_failure = "ssh"
        else:
            first_failure = _work_failure(timings)

    residue = value["zero_residue"]
    _keys(residue, RESIDUE_FACTS)
    _require(all(item in ("absent", "not-proved") for item in residue.values()))
    teardown_failure = _teardown_failure(value["teardown"], binding, operation["status"], residue)
    if first_failure is None:
        first_failure = teardown_failure

    qualified = first_failure is None
    _require(value["qualified"] == qualified)
    if value["result"] == "pass":
        _require(qualified and value["failure_code"] is None)
    else:
        _require(not qualified and value["failure_code"] in FAILURE_CODES
                 and value["failure_code"] == first_failure)
    return qualified


def canonical_result(value):
    validate_result(value)
    raw = _canonical(value) + b"\n"
    _require(len(raw) <= MAX_RESULT_BYTES)
    return raw


def load_result(raw):
    """Load canonical ASCII report data; never construct or grant a receipt."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RESULT_BYTES and raw.endswith(b"\n"))
    try:
        def unique(rows):
            value = {}
            for key, item in rows:
                _require(type(key) is str and key not in value)
                value[key] = item
            return value
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except LocalResultError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise LocalResultError() from error
    _require(canonical_result(value) == raw)
    return value


def main():
    """Zero-argument stub; no serialized input can open production."""
    if len(sys.argv) != 1:
        raise LocalResultBlocked()
    raise LocalResultBlocked()


if __name__ == "__main__":
    try:
        main()
    except LocalResultBlocked:
        raise SystemExit(3)
    except LocalResultError:
        raise SystemExit(2)
