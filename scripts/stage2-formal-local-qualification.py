#!/usr/bin/env python3
"""Publish and aggregate seven independent non-cloud hosted-KVM cycles."""
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
FORMAL_MODULE = ROOT / "deploy/aws-feasibility/remote/completion_formal_cycle_authority.py"
MAX_RECEIPT_BYTES = 96 * 1024
MAX_STATUS_BYTES = 8 * 1024
MAX_CUSTODY_BYTES = 16 * 1024
MAX_API_BYTES = 1024 * 1024
AUTHORITY = "non-cloud-formal-qualification-cycle-only"
CYCLE_AUTHORITY = "non-aws-formal-qualification-owner-evidence-only"
STATUS_AUTHORITY = "non-aws-formal-qualification-cycle-status-only"
PACKAGE_AUTHORITY = "non-aws-prerequisite-evidence-only"
CUSTODY_AUTHORITY = "authenticated-github-actions-api-cycle-artifact-custody-only"
CUSTODY_VERSION = "cogs.stage2-formal-local-artifact-custody/v1"
REPOSITORY = "nenb/cogs"
CYCLE_MODES = ("full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness")
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
ARCHIVE_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
FULL_PROGRAM = "0e62df128ab166344e4a8e20aa9c92b376fbf96ba8454f73cec66ca1b5678406"
FULL_MARKER = "35f125d7914d134854e532a08398153ffcd699426fbeeabcb7c35d7f4ec474f5"
READINESS_PROGRAM = "386f9398688cad05dfc0921ad0e5aa442cf146fd7ff16ddd82a7683244da6bab"
READINESS_MARKER = "b5b71497621037e6b7eada7c581962775625d532cdc06729dfd095e6a6f7c010"
PROGRAMS = {"full": (FULL_PROGRAM, FULL_MARKER), "readiness": (READINESS_PROGRAM, READINESS_MARKER)}
PARSERS = {
    "full": hashlib.sha256((ROOT / "deploy/aws-feasibility/remote/completion_guest_workloads_v3.py").read_bytes()).hexdigest(),
    "readiness": hashlib.sha256((ROOT / "deploy/aws-feasibility/remote/completion_guest_readiness_v1.py").read_bytes()).hexdigest(),
}
NETWORK_MARKERS = ["route-baseline-no-default", "direct-tcp-denied", "direct-udp-denied",
    "default-route-added", "route-tcp-denied", "route-udp-denied",
    "default-route-removed", "route-restored-no-default"]
WORKLOAD_DIGESTS = {"GIT": "73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c",
    "BUILD": "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf",
    "INSTALL": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2"}
SOURCE_KEYS = {"source_head", "source_manifest_sha256", "host_attestation_sha256",
    "runtime_attestation_sha256", "rootfs_sha256", "rootfs_descriptor_sha256",
    "rootfs_package_manifest_sha256", "rootfs_provenance_sha256",
    "rootfs_publication_receipt_sha256", "artifact_sha256", "candidate_sha256",
    "final_pin_sha256", "guest_program_sha256", "owner_implementation_sha256"}
COMMON_RECEIPT_KEYS = {"version", "authority", "route", "cycle_capability_sha256",
    "cycle_grant", "production_publication_authorized", "provider_execution_observed",
    "aws_authority", "formal_qualification_authority", "source_bindings",
    "operation_token", "rootfs_token", "lifecycle_objects", "journal_sha256",
    "program_sha256", "parser_source_sha256", "marker_sha256", "launch_attempts",
    "ssh_attempts", "timing",
    "key_freshness", "runtime_network_sha256", "qmp_lineage", "teardown_projection",
    "private_teardown_records", "final_baselines_sha256", "independent_residue_absent"}
FULL_KEYS = {"network_markers", "route_before_sha256", "route_after_sha256", "workloads",
             "network_causal_proof_sha256"}
READINESS_KEYS = {"runtime_readiness_lineage"}
GRANT_KEYS = {"authority", "batch_commitment", "cycle_ordinal", "mode", "implementation_revision",
    "control_revision", "source_manifest_sha256", "static_control_sha256", "workflow_sha256",
    "result_schema_sha256", "rootfs_descriptor_sha256", "workflow_run_id",
    "workflow_run_attempt", "grant_commitment"}
TEARDOWN = ["READINESS_REVOKED", "TASK_STOPPED", "TASK_ABSENT",
    "RUNTIME_PROCESSES_ABSENT", "NETWORK_ABSENT", "CONTAINER_ABSENT",
    "SHARE_AND_MOUNTS_ABSENT", "FIREWALL_ABSENT", "CONTAINERD_ABSENT",
    "INPUTS_ABSENT", "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRED"]
PRIVATE_TEARDOWN = ["READINESS_REVOKED", "RUNTIME_ROLE_IDENTITIES_V1",
    "RUNTIME_SHARE_IDENTITY_V1", "TASK_STOPPED", "TASK_ABSENT",
    "RUNTIME_ROLE_ABSENCE_V1", "RUNTIME_ABSENT", "RUNTIME_NETWORK_RELEASED_V1",
    "NETWORK_ABSENT", "CONTAINER_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT",
    "CONTAINERD_ABSENT", "INPUT_REMOVED", "ROOTFS_RELEASE_READY",
    "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"]
RESIDUE = ["tasks", "containers", "shim_processes", "qemu_processes", "virtiofsd_processes",
    "containerd_processes", "child_processes", "cgroups", "namespaces", "veth_devices",
    "tap_devices", "traffic_control", "firewall", "shares", "mounts", "inputs",
    "operation_state", "runtime_state", "runtime_cache", "rootfs_lease", "rootfs_build",
    "rootfs_publication", "unexpected_descriptors", "network_state", "network_routes",
    "network_addresses", "firewall_baseline", "mount_baseline", "source_identity",
    "input_control", "share_paths", "runtime_staging", "report_staging", "descriptor_baseline",
    "process_baseline", "cgroup_baseline", "namespace_baseline"]


class FormalQualificationError(ValueError): pass


def require(value, message="formal qualification condition failed"):
    if not value: raise FormalQualificationError(message)


def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value, "duplicate JSON member"); value[key] = item
    return value


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise FormalQualificationError("non-canonical value") from error


def read_regular(path, maximum):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum, "bounded regular file required")
        raw = os.read(descriptor, maximum + 1); after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                 item.st_gid, item.st_nlink, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(after),
                "file changed while reading")
        return raw
    finally: os.close(descriptor)


def decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise FormalQualificationError("invalid JSON") from error
    require(type(value) is dict and canonical(value) == raw, "non-canonical JSON")
    return value


def digest(value):
    require(type(value) is str and SHA256.fullmatch(value) is not None, "SHA-256 required")
    return value


def positive(value):
    require(type(value) is int and value > 0, "positive integer required")
    return value


def archive_digest(value):
    require(type(value) is str and ARCHIVE_SHA256.fullmatch(value) is not None,
            "sha256-prefixed Actions artifact archive digest required")
    return value


def exact_keys(value, names):
    require(type(value) is dict and set(value) == set(names), "exact object members required")


def load_authority(path=FORMAL_MODULE):
    spec = importlib.util.spec_from_file_location("stage2_formal_cycle_authority_workflow", path)
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expected_environment(environ=os.environ):
    names = ("EXPECTED_IMPLEMENTATION_HEAD", "EXPECTED_CONTROL_HEAD",
             "EXPECTED_SOURCE_MANIFEST_SHA256", "EXPECTED_CONTROL_SHA256",
             "EXPECTED_WORKFLOW_SHA256", "EXPECTED_RESULT_SCHEMA_SHA256",
             "EXPECTED_ROOTFS_DESCRIPTOR_SHA256", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    values = {name: environ.get(name, "") for name in names}
    require(SHA1.fullmatch(values["EXPECTED_IMPLEMENTATION_HEAD"]) is not None
            and SHA1.fullmatch(values["EXPECTED_CONTROL_HEAD"]) is not None)
    for name in names[2:7]: digest(values[name])
    require(re.fullmatch(r"[1-9][0-9]*", values["GITHUB_RUN_ID"]) is not None
            and values["GITHUB_RUN_ATTEMPT"] == "1")
    return values


def issue_grant(ordinal, expected, authority=None):
    authority = authority or load_authority()
    require(type(ordinal) is int and 1 <= ordinal <= 7)
    return authority.issue({
        "ordinal": ordinal, "mode": CYCLE_MODES[ordinal - 1],
        "implementation_revision": expected["EXPECTED_IMPLEMENTATION_HEAD"],
        "control_revision": expected["EXPECTED_CONTROL_HEAD"],
        "source_manifest_sha256": expected["EXPECTED_SOURCE_MANIFEST_SHA256"],
        "static_control_sha256": expected["EXPECTED_CONTROL_SHA256"],
        "workflow_sha256": expected["EXPECTED_WORKFLOW_SHA256"],
        "result_schema_sha256": expected["EXPECTED_RESULT_SCHEMA_SHA256"],
        "rootfs_descriptor_sha256": expected["EXPECTED_ROOTFS_DESCRIPTOR_SHA256"],
        "workflow_run_id": int(expected["GITHUB_RUN_ID"]),
        "workflow_run_attempt": 1,
    })


def validate_grant(value, expected=None, ordinal=None, authority=None):
    exact_keys(value, GRANT_KEYS)
    authority = authority or load_authority()
    mapped = dict(value); mapped["ordinal"] = mapped.pop("cycle_ordinal")
    grant = authority.FormalCycleGrant(**mapped)
    if ordinal is not None: require(grant.ordinal == ordinal and grant.mode == CYCLE_MODES[ordinal - 1])
    if expected is not None:
        wanted = issue_grant(grant.ordinal, expected, authority)
        require(grant == wanted, "grant does not bind exact batch, ordinal, H, and G")
    return grant


def validate_receipt(raw, expected=None, ordinal=None):
    value = decode(raw, MAX_RECEIPT_BYTES)
    mode = value.get("route")
    require(mode in {"full", "readiness"})
    exact_keys(value, COMMON_RECEIPT_KEYS | (FULL_KEYS if mode == "full" else READINESS_KEYS))
    require(value["version"] == "cogs.stage2-formal-local-cycle-receipt/v1"
            and value["authority"] == CYCLE_AUTHORITY
            and value["production_publication_authorized"] is False
            and value["provider_execution_observed"] is False
            and value["aws_authority"] is None
            and value["launch_attempts"] == value["ssh_attempts"] == 1)
    grant = validate_grant(value["cycle_grant"], expected, ordinal)
    require(mode == grant.mode and value["formal_qualification_authority"] == grant.grant_commitment)
    program, marker = PROGRAMS[mode]
    capability = hashlib.sha256(b"cogs.stage2-cycle-route/v1\0formal-non-cloud-qualification\0" +
                                mode.encode("ascii") + bytes.fromhex(program) + bytes.fromhex(marker)).hexdigest()
    require(value["program_sha256"] == program
            and value["parser_source_sha256"] == PARSERS[mode]
            and value["marker_sha256"] == marker
            and value["cycle_capability_sha256"] == capability)
    for name in ("cycle_capability_sha256", "operation_token", "rootfs_token", "journal_sha256",
                 "program_sha256", "marker_sha256", "runtime_network_sha256",
                 "final_baselines_sha256"):
        digest(value[name])
    require(value["operation_token"] != value["rootfs_token"])
    exact_keys(value["lifecycle_objects"], {"rootfs_leases", "runtime_stages", "task_launches"})
    require(value["lifecycle_objects"] == {"rootfs_leases": 1, "runtime_stages": 1, "task_launches": 1})
    bindings = value["source_bindings"]; exact_keys(bindings, SOURCE_KEYS)
    require(bindings["source_head"] == grant.implementation_revision
            and bindings["source_manifest_sha256"] == grant.source_manifest_sha256
            and bindings["rootfs_descriptor_sha256"] == grant.rootfs_descriptor_sha256
            and bindings["guest_program_sha256"] == FULL_PROGRAM)
    for name, item in bindings.items():
        if name != "source_head": digest(item)
    timing = value["timing"]
    exact_keys(timing, {"host_boot_id", "launch_record_sha256", "marker_record_sha256",
        "settlement_record_sha256", "kata_launch_started_boottime_ns",
        "ssh_marker_observed_boottime_ns", "ssh_command_settled_boottime_ns", "ssh_ready_ns"})
    require(type(timing["host_boot_id"]) is str and BOOT_ID.fullmatch(timing["host_boot_id"]) is not None)
    for name in ("launch_record_sha256", "marker_record_sha256", "settlement_record_sha256"): digest(timing[name])
    start = positive(timing["kata_launch_started_boottime_ns"])
    ready = positive(timing["ssh_marker_observed_boottime_ns"])
    settled = positive(timing["ssh_command_settled_boottime_ns"])
    require(start < ready <= settled and timing["ssh_ready_ns"] == ready - start)
    keys = value["key_freshness"]; exact_keys(keys, {"client_key_commitment", "host_key_commitment"})
    digest(keys["client_key_commitment"]); digest(keys["host_key_commitment"])
    require(keys["client_key_commitment"] != keys["host_key_commitment"])
    qmp = value["qmp_lineage"]
    exact_keys(qmp, {"live_mapping_sha256", "runtime_identity_sha256", "qemu_process_sha256", "qemu_argv_sha256", "qemu_pid", "qemu_starttime",
        "qemu_executable_device", "qemu_executable_inode", "observer_qmp_device",
        "observer_qmp_inode", "kvm_device", "kvm_inode", "kvm_rdev",
        "kvm_api", "qmp_present", "qmp_enabled"})
    digest(qmp["live_mapping_sha256"]); digest(qmp["runtime_identity_sha256"])
    digest(qmp["qemu_process_sha256"]); digest(qmp["qemu_argv_sha256"])
    identity_value = {name: item for name, item in qmp.items()
                      if name not in {"live_mapping_sha256", "runtime_identity_sha256",
                                      "qemu_process_sha256"}}
    require(qmp["runtime_identity_sha256"] == hashlib.sha256(
        b"cogs.stage2-qemu-runtime-identity/v1\0" + canonical(identity_value)).hexdigest())
    require(positive(qmp["qemu_pid"]) > 1 and positive(qmp["qemu_starttime"]) > 0
            and type(qmp["qemu_executable_device"]) is int
            and qmp["qemu_executable_device"] >= 0
            and positive(qmp["qemu_executable_inode"]) > 0
            and type(qmp["observer_qmp_device"]) is int and qmp["observer_qmp_device"] >= 0
            and positive(qmp["observer_qmp_inode"]) > 0
            and type(qmp["kvm_device"]) is int and qmp["kvm_device"] >= 0
            and positive(qmp["kvm_inode"]) > 0 and positive(qmp["kvm_rdev"]) > 0
            and qmp["kvm_api"] == 12 and qmp["qmp_present"] is True and qmp["qmp_enabled"] is True)
    require(value["teardown_projection"] == TEARDOWN
            and value["private_teardown_records"] == PRIVATE_TEARDOWN
            and value["independent_residue_absent"] == RESIDUE)
    measurements = 0
    if mode == "full":
        rows = value["workloads"]
        require(type(rows) is list and len(rows) == 21)
        for index, row in enumerate(rows, 1):
            exact_keys(row, {"ordinal", "category", "duration_ns", "result_sha256", "deleted"})
            category, sample = ("GIT", "BUILD", "INSTALL")[(index - 1) // 7], (index - 1) % 7 + 1
            require(row["ordinal"] == index and row["category"] == f"{category}_{sample:02d}"
                    and positive(row["duration_ns"]) <= 1_200_000_000_000
                    and row["deleted"] is True)
            digest(row["result_sha256"]); require(row["result_sha256"] == WORKLOAD_DIGESTS[category])
        for name in ("route_before_sha256", "route_after_sha256", "network_causal_proof_sha256"): digest(value[name])
        require(value["route_before_sha256"] == value["route_after_sha256"]
                and value["network_markers"] == NETWORK_MARKERS)
        measurements = 21
    else:
        lineage = value["runtime_readiness_lineage"]
        exact_keys(lineage, {"operation_token", "runtime_mount_record_sha256",
            "runtime_network_sha256", "live_mapping_sha256", "runtime_identity_sha256",
            "qemu_process_sha256", "qmp_identity"})
        for name in ("operation_token", "runtime_mount_record_sha256", "runtime_network_sha256",
                     "live_mapping_sha256", "runtime_identity_sha256", "qemu_process_sha256"): digest(lineage[name])
        identity = lineage["qmp_identity"]
        require(lineage["operation_token"] == value["operation_token"]
                and lineage["runtime_network_sha256"] == value["runtime_network_sha256"]
                and lineage["runtime_identity_sha256"] == qmp["runtime_identity_sha256"]
                and lineage["qemu_process_sha256"] != qmp["qemu_process_sha256"]
                and type(identity) is list and len(identity) == 10
                and all(type(item) is int and item >= 0 for item in identity)
                and identity[0] == qmp["qemu_pid"] and identity[1] == qmp["qemu_starttime"]
                and identity[2] == qmp["qemu_executable_device"]
                and identity[3] == qmp["qemu_executable_inode"]
                and identity[4] == qmp["observer_qmp_device"]
                and identity[5] == qmp["observer_qmp_inode"]
                and identity[6] == qmp["kvm_device"] and identity[7] == qmp["kvm_inode"]
                and identity[8] == qmp["kvm_rdev"] and identity[9] == 12)
    return value, grant, measurements


def status_value(receipt_raw, expected, ordinal, artifact_name):
    receipt, grant, measurements = validate_receipt(receipt_raw, expected, ordinal)
    return {"version": "cogs.stage2-formal-local-cycle-status/v1", "authority": STATUS_AUTHORITY,
        "batch_commitment": grant.batch_commitment, "ordinal": ordinal, "mode": grant.mode,
        "grant_commitment": grant.grant_commitment,
        "workflow_run": {"id": grant.workflow_run_id, "attempt": 1},
        "artifact_name": artifact_name,
        "receipt": {"sha256": hashlib.sha256(receipt_raw).hexdigest(), "bytes": len(receipt_raw)},
        "identities": {"host_boot_id": receipt["timing"]["host_boot_id"],
            "operation": receipt["operation_token"], "rootfs": receipt["rootfs_token"],
            "runtime": receipt["qmp_lineage"]["runtime_identity_sha256"],
            "client_key": receipt["key_freshness"]["client_key_commitment"],
            "host_key": receipt["key_freshness"]["host_key_commitment"]},
        "lifecycle_objects": receipt["lifecycle_objects"], "workload_measurements": measurements,
        "outcomes": {"entry": "success", "recovery": "success", "fixed_cleanup": "success",
            "independent_residue": "success", "publication": "success"},
        "claims": {"formal_non_aws_cycle_passed": True, "aws_authorized": False,
            "provider_executed": False, "promotion_authorized": False}}


def validate_status(raw, receipt_raw, expected, ordinal):
    value = decode(raw, MAX_STATUS_BYTES)
    artifact = f"stage2-formal-cycle-{ordinal}-{expected['EXPECTED_IMPLEMENTATION_HEAD']}-{expected['EXPECTED_CONTROL_HEAD']}-{expected['GITHUB_RUN_ID']}-1"
    require(value == status_value(receipt_raw, expected, ordinal, artifact), "cycle status differs")
    return value


def expected_artifact_name(expected, ordinal):
    return (f"stage2-formal-cycle-{ordinal}-{expected['EXPECTED_IMPLEMENTATION_HEAD']}-"
            f"{expected['EXPECTED_CONTROL_HEAD']}-{expected['GITHUB_RUN_ID']}-1")


def custody_from_api(raw, expected):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_API_BYTES, "bounded API response required")
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise FormalQualificationError("invalid artifact API response") from error
    require(type(value) is dict and type(value.get("total_count")) is int
            and type(value.get("artifacts")) is list
            and value["total_count"] == len(value["artifacts"]) == 7,
            "API artifact inventory must be exactly seven")
    by_name = {}
    for item in value["artifacts"]:
        require(type(item) is dict and type(item.get("name")) is str
                and item["name"] not in by_name and item.get("expired") is False,
                "live unique API artifact required")
        workflow_run = item.get("workflow_run")
        require(type(workflow_run) is dict
                and workflow_run.get("id") == int(expected["GITHUB_RUN_ID"]),
                "artifact API workflow run differs")
        artifact_id = positive(item.get("id"))
        digest_value = archive_digest(item.get("digest"))
        by_name[item["name"]] = (artifact_id, digest_value)
    rows = []
    for ordinal in range(1, 8):
        name = expected_artifact_name(expected, ordinal)
        require(name in by_name, "expected cycle artifact absent from API inventory")
        artifact_id, digest_value = by_name[name]
        rows.append({"ordinal": ordinal, "name": name, "artifact_id": artifact_id,
                     "archive_digest": digest_value})
    require(len({row["artifact_id"] for row in rows}) == 7
            and len({row["archive_digest"] for row in rows}) == 7,
            "cycle artifact identities must be unique")
    return {"version": CUSTODY_VERSION, "authority": CUSTODY_AUTHORITY,
            "repository": REPOSITORY,
            "workflow_run": {"id": int(expected["GITHUB_RUN_ID"]), "attempt": 1},
            "artifacts": rows}


def validate_custody(raw, expected):
    value = decode(raw, MAX_CUSTODY_BYTES)
    exact_keys(value, {"version", "authority", "repository", "workflow_run", "artifacts"})
    require(value["version"] == CUSTODY_VERSION and value["authority"] == CUSTODY_AUTHORITY
            and value["repository"] == REPOSITORY)
    exact_keys(value["workflow_run"], {"id", "attempt"})
    require(value["workflow_run"] == {"id": int(expected["GITHUB_RUN_ID"]), "attempt": 1}
            and type(value["artifacts"]) is list and len(value["artifacts"]) == 7)
    for ordinal, row in enumerate(value["artifacts"], 1):
        exact_keys(row, {"ordinal", "name", "artifact_id", "archive_digest"})
        require(row["ordinal"] == ordinal and row["name"] == expected_artifact_name(expected, ordinal))
        positive(row["artifact_id"]); archive_digest(row["archive_digest"])
    require(len({row["artifact_id"] for row in value["artifacts"]}) == 7
            and len({row["archive_digest"] for row in value["artifacts"]}) == 7,
            "cycle artifact custody identities differ")
    return value


def write_all(descriptor, raw):
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view); require(written > 0); view = view[written:]


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def materialize_grant(environ=os.environ, authority_path=FORMAL_MODULE, authority=None):
    expected = expected_environment(environ); ordinal = int(environ.get("FORMAL_CYCLE_ORDINAL", "0"))
    authority = authority or load_authority(authority_path); grant = issue_grant(ordinal, expected, authority)
    root = authority.ROOT
    require(os.geteuid() == 0 and not root.exists())
    root.mkdir(mode=0o700); os.chown(root, 0, 0)
    descriptor = os.open(root / "grant.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        raw = authority.encode(grant); write_all(descriptor, raw); os.fchmod(descriptor, 0o400); os.fsync(descriptor)
    finally: os.close(descriptor)
    fsync_directory(root)
    return grant


def publish(staging, expected, ordinal, runner_uid):
    staging = Path(staging); source = staging / "receipt.partial"
    require(os.geteuid() == 0 and staging.is_dir() and set(os.listdir(staging)) == {"receipt.partial"})
    seen = source.lstat(); require(stat.S_ISREG(seen.st_mode) and seen.st_uid == runner_uid and seen.st_nlink == 1)
    receipt_raw = read_regular(source, MAX_RECEIPT_BYTES); validate_receipt(receipt_raw, expected, ordinal)
    artifact = f"stage2-formal-cycle-{ordinal}-{expected['EXPECTED_IMPLEMENTATION_HEAD']}-{expected['EXPECTED_CONTROL_HEAD']}-{expected['GITHUB_RUN_ID']}-1"
    status_raw = canonical(status_value(receipt_raw, expected, ordinal, artifact))
    os.chown(staging, 0, 0); os.chmod(staging, 0o700)
    for name, raw in (("receipt.json", receipt_raw), ("status.json", status_raw)):
        descriptor = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try: write_all(descriptor, raw); os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o444); os.fsync(descriptor)
        finally: os.close(descriptor)
    source.unlink(); os.chmod(staging, 0o555)
    validate_status(read_regular(staging / "status.json", MAX_STATUS_BYTES),
                    read_regular(staging / "receipt.json", MAX_RECEIPT_BYTES), expected, ordinal)


def validate_cycle_directory(path, expected, ordinal):
    path = Path(path)
    seen = path.lstat()
    require(stat.S_ISDIR(seen.st_mode) and not stat.S_ISLNK(seen.st_mode)
            and set(os.listdir(path)) == {"receipt.json", "status.json"})
    receipt_raw = read_regular(path / "receipt.json", MAX_RECEIPT_BYTES)
    status_raw = read_regular(path / "status.json", MAX_STATUS_BYTES)
    validate_receipt(receipt_raw, expected, ordinal)
    return receipt_raw, status_raw, validate_status(status_raw, receipt_raw, expected, ordinal)


def aggregate(root, custody_raw, expected, cycle_job_result="success"):
    require(cycle_job_result == "success" and expected["GITHUB_RUN_ATTEMPT"] == "1",
            "failed, retried, canceled, or uncertain cycle batch")
    custody = validate_custody(custody_raw, expected)
    custody_by_ordinal = {row["ordinal"]: row for row in custody["artifacts"]}
    root = Path(root); seen = root.lstat()
    expected_members = {f"cycle-{ordinal}" for ordinal in range(1, 8)}
    require(stat.S_ISDIR(seen.st_mode) and not stat.S_ISLNK(seen.st_mode)
            and set(os.listdir(root)) == expected_members,
            "artifact batch inventory differs")
    rows = []; batches = set(); identity_sets = {name: set() for name in
        ("host_boot_id", "operation", "rootfs", "runtime", "client_key", "host_key")}
    total = 0; shared_bindings = None
    for ordinal in range(1, 8):
        receipt_raw, status_raw, status = validate_cycle_directory(root / f"cycle-{ordinal}", expected, ordinal)
        receipt, _grant, _measurements = validate_receipt(receipt_raw, expected, ordinal)
        if shared_bindings is None:
            shared_bindings = receipt["source_bindings"]
        else:
            require(receipt["source_bindings"] == shared_bindings,
                    "every immutable source binding must be byte-for-byte common")
        artifact = custody_by_ordinal[ordinal]
        require(status["artifact_name"] == artifact["name"], "status and API artifact names differ")
        batches.add(status["batch_commitment"]); total += status["workload_measurements"]
        for name, seen in identity_sets.items():
            identity = status["identities"][name]; require(identity not in seen, f"reused {name}"); seen.add(identity)
        rows.append({"ordinal": ordinal, "mode": CYCLE_MODES[ordinal - 1],
            "grant_commitment": status["grant_commitment"],
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "status_sha256": hashlib.sha256(status_raw).hexdigest(),
            "artifact_name": status["artifact_name"],
            "artifact_id": artifact["artifact_id"],
            "artifact_archive_digest": artifact["archive_digest"],
            "identities": status["identities"]})
    require(len(batches) == 1 and total == 21
            and [row["mode"] for row in rows] == list(CYCLE_MODES)
            and len(identity_sets["operation"] | identity_sets["rootfs"]) == 14
            and len(identity_sets["client_key"] | identity_sets["host_key"]) == 14,
            "batch cardinality, mode, measurement, or cross-role identity differs")
    require(shared_bindings is not None)
    return canonical({"version": "cogs.stage2-pre-aws-qualification-package/v3",
        "authority": PACKAGE_AUTHORITY,
        "implementation_revision": expected["EXPECTED_IMPLEMENTATION_HEAD"],
        "control_revision": expected["EXPECTED_CONTROL_HEAD"],
        "source_manifest_sha256": expected["EXPECTED_SOURCE_MANIFEST_SHA256"],
        "static_control_sha256": expected["EXPECTED_CONTROL_SHA256"],
        "workflow_sha256": expected["EXPECTED_WORKFLOW_SHA256"],
        "result_schema_sha256": expected["EXPECTED_RESULT_SCHEMA_SHA256"],
        "rootfs_descriptor_sha256": expected["EXPECTED_ROOTFS_DESCRIPTOR_SHA256"],
        "runtime_commitment": shared_bindings["runtime_attestation_sha256"],
        "fixture_commitment": shared_bindings["final_pin_sha256"],
        "source_bindings": shared_bindings,
        "cycle_artifact_custody": custody,
        "cycle_artifact_custody_sha256": hashlib.sha256(custody_raw).hexdigest(),
        "batch_commitment": next(iter(batches)), "cycle_count": 7,
        "workload_measurements": total, "cycles": rows,
        "predecessor_versions": ["cogs.stage2-pre-aws-qualification-package/v1",
                                 "cogs.stage2-pre-aws-qualification-package/v2"],
        "claims": {"formal_non_aws_qualification_passed": True, "aws_authorized": False,
                   "aws_executed": False, "provider_executed": False,
                   "promotion_authorized": False}})


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in {"grant", "publish", "readback", "custody", "aggregate"})
    command = sys.argv[1]; expected = expected_environment(); ordinal = int(os.environ.get("FORMAL_CYCLE_ORDINAL", "0"))
    if command == "grant":
        grant = materialize_grant(); print(f"batch_commitment={grant.batch_commitment}"); print(f"grant_commitment={grant.grant_commitment}")
    elif command == "publish":
        uid = int(os.environ.get("TRUSTED_RUNNER_UID", "-1")); require(uid > 0)
        publish(os.environ["CYCLE_STAGING"], expected, ordinal, uid)
    elif command == "readback":
        local = Path(os.environ["CYCLE_STAGING"]); remote = Path(os.environ["CYCLE_READBACK_STAGING"])
        left = validate_cycle_directory(local, expected, ordinal); right = validate_cycle_directory(remote, expected, ordinal)
        require(left[:2] == right[:2], "exact cycle artifact readback differs")
        positive(int(os.environ["CYCLE_ARTIFACT_ID"]))
        archive_digest(os.environ["CYCLE_ARTIFACT_DIGEST"])
    elif command == "custody":
        api_raw = read_regular(os.environ["CYCLE_CUSTODY_API_RESPONSE"], MAX_API_BYTES)
        custody_raw = canonical(custody_from_api(api_raw, expected))
        destination = Path(os.environ["CYCLE_CUSTODY_MAP"])
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try: write_all(descriptor, custody_raw); os.fsync(descriptor)
        finally: os.close(descriptor)
        fsync_directory(destination.parent)
        custody = validate_custody(read_regular(destination, MAX_CUSTODY_BYTES), expected)
        print("artifact_ids=" + ",".join(str(row["artifact_id"]) for row in custody["artifacts"]))
    else:
        custody_raw = read_regular(os.environ["CYCLE_CUSTODY_MAP"], MAX_CUSTODY_BYTES)
        raw = aggregate(os.environ["CYCLE_AGGREGATE_ROOT"], custody_raw, expected,
                        os.environ.get("CYCLE_JOB_RESULT", ""))
        require(sys.stdout.buffer.write(raw) == len(raw))


if __name__ == "__main__":
    try: main()
    except (FormalQualificationError, KeyError, OSError, ValueError): raise SystemExit(2)
