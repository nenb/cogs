#!/usr/bin/env python3
"""Production-shaped hostile aggregation tests for seven local formal cycles."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module


formal = load("stage2_formal_workflow_test", "scripts/stage2-formal-local-qualification.py")
authority = load("stage2_formal_authority_test", "deploy/aws-feasibility/remote/completion_formal_cycle_authority.py")

def d(value): return hashlib.sha256(value.encode()).hexdigest()

expected = {
    "EXPECTED_IMPLEMENTATION_HEAD": "1" * 40,
    "EXPECTED_CONTROL_HEAD": "2" * 40,
    "EXPECTED_SOURCE_MANIFEST_SHA256": d("source"),
    "EXPECTED_CONTROL_SHA256": d("control"),
    "EXPECTED_WORKFLOW_SHA256": d("workflow"),
    "EXPECTED_RESULT_SCHEMA_SHA256": d("schema"),
    "EXPECTED_ROOTFS_DESCRIPTOR_SHA256": d("descriptor"),
    "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "1",
}


def rejected(action):
    try: action()
    except (formal.FormalQualificationError, authority.FormalCycleAuthorityError, OSError, ValueError): return
    raise AssertionError("hostile formal qualification input was accepted")


def receipt(ordinal):
    grant = formal.issue_grant(ordinal, expected, authority)
    grant_value = authority.asdict(grant); grant_value["cycle_ordinal"] = grant_value.pop("ordinal")
    qmp = {"qemu_process_sha256": d(f"runtime-{ordinal}"), "qemu_argv_sha256": d(f"argv-{ordinal}"),
        "qemu_pid": 100 + ordinal, "qemu_starttime": 200 + ordinal,
        "qemu_executable_device": 250, "qemu_executable_inode": 260 + ordinal,
        "observer_qmp_device": 300, "observer_qmp_inode": 400 + ordinal,
        "kvm_device": 500, "kvm_inode": 600 + ordinal, "kvm_rdev": 700,
        "kvm_api": 12, "qmp_present": True, "qmp_enabled": True}
    operation, rootfs = d(f"operation-{ordinal}"), d(f"rootfs-{ordinal}")
    mode = formal.CYCLE_MODES[ordinal - 1]; program, marker = formal.PROGRAMS[mode]
    capability = hashlib.sha256(b"cogs.stage2-cycle-route/v1\0formal-non-cloud-qualification\0" +
        mode.encode() + bytes.fromhex(program) + bytes.fromhex(marker)).hexdigest()
    value = {
        "version": "cogs.stage2-formal-local-cycle-receipt/v1",
        "authority": formal.CYCLE_AUTHORITY, "route": mode,
        "cycle_capability_sha256": capability, "cycle_grant": grant_value,
        "production_publication_authorized": False, "provider_execution_observed": False,
        "aws_authority": None, "formal_qualification_authority": grant.grant_commitment,
        "source_bindings": {name: (expected["EXPECTED_IMPLEMENTATION_HEAD"] if name == "source_head"
            else expected["EXPECTED_SOURCE_MANIFEST_SHA256"] if name == "source_manifest_sha256"
            else expected["EXPECTED_ROOTFS_DESCRIPTOR_SHA256"] if name == "rootfs_descriptor_sha256"
            else formal.FULL_PROGRAM if name == "guest_program_sha256"
            else d(f"binding-{name}")) for name in formal.SOURCE_KEYS},
        "operation_token": operation, "rootfs_token": rootfs,
        "lifecycle_objects": {"rootfs_leases": 1, "runtime_stages": 1, "task_launches": 1},
        "journal_sha256": d(f"journal-{ordinal}"), "program_sha256": program,
        "parser_source_sha256": formal.PARSERS[mode], "marker_sha256": marker,
        "launch_attempts": 1, "ssh_attempts": 1,
        "timing": {"host_boot_id": f"0000000{ordinal}-0000-4000-8000-00000000000{ordinal}",
            "launch_record_sha256": d(f"launch-{ordinal}"), "marker_record_sha256": d(f"marker-record-{ordinal}"),
            "settlement_record_sha256": d(f"settled-{ordinal}"),
            "kata_launch_started_boottime_ns": 100, "ssh_marker_observed_boottime_ns": 200,
            "ssh_command_settled_boottime_ns": 300, "ssh_ready_ns": 100},
        "key_freshness": {"client_key_commitment": d(f"client-{ordinal}"),
                          "host_key_commitment": d(f"host-{ordinal}")},
        "runtime_network_sha256": d(f"network-{ordinal}"), "qmp_lineage": qmp,
        "teardown_projection": formal.TEARDOWN,
        "private_teardown_records": formal.PRIVATE_TEARDOWN,
        "final_baselines_sha256": d(f"baseline-{ordinal}"),
        "independent_residue_absent": formal.RESIDUE,
    }
    if ordinal == 1:
        value.update({"network_markers": formal.NETWORK_MARKERS, "route_before_sha256": d("route"),
            "route_after_sha256": d("route"), "network_causal_proof_sha256": d("causal"),
            "workloads": [{"ordinal": index, "category": f"{category}_{sample:02d}",
                "duration_ns": 1000 + index, "result_sha256": formal.WORKLOAD_DIGESTS[category], "deleted": True}
                for index, (category, sample) in enumerate(
                    ((category, sample) for category in ("GIT", "BUILD", "INSTALL") for sample in range(1, 8)), 1)]})
    else:
        value["runtime_readiness_lineage"] = {"operation_token": operation,
            "runtime_mount_record_sha256": d(f"mount-{ordinal}"),
            "runtime_network_sha256": value["runtime_network_sha256"],
            "live_mapping_sha256": d(f"mapping-{ordinal}"),
            "qemu_process_sha256": qmp["qemu_process_sha256"],
            "qmp_identity": [qmp["qemu_pid"], qmp["qemu_starttime"],
                             qmp["qemu_executable_device"], qmp["qemu_executable_inode"],
                             qmp["observer_qmp_device"], qmp["observer_qmp_inode"],
                             qmp["kvm_device"], qmp["kvm_inode"], qmp["kvm_rdev"], 12]}
    return value


def write_cycle(root, ordinal, value=None):
    value = value or receipt(ordinal); raw = formal.canonical(value)
    status = formal.status_value(raw, expected, ordinal,
        f"stage2-formal-cycle-{ordinal}-{expected['EXPECTED_IMPLEMENTATION_HEAD']}-{expected['EXPECTED_CONTROL_HEAD']}-71-1")
    path = Path(root) / f"cycle-{ordinal}"; path.mkdir()
    (path / "receipt.json").write_bytes(raw); (path / "status.json").write_bytes(formal.canonical(status))


# Grant domains are non-cloud, batch shared, ordinal/mode unique, canonical and one-attempt.
grants = [formal.issue_grant(index, expected, authority) for index in range(1, 8)]
assert len({item.batch_commitment for item in grants}) == 1
assert len({item.grant_commitment for item in grants}) == 7
assert [item.mode for item in grants] == list(formal.CYCLE_MODES)
encoded = authority.encode(grants[0]); assert authority.decode(encoded) == grants[0]
assert b"aws" not in encoded.lower() and b"provider" not in encoded.lower()
for hostile in (encoded[:-1], encoded + b" ", encoded.replace(b'"ordinal":1', b'"ordinal":2')):
    rejected(lambda hostile=hostile: authority.decode(hostile))

# The owner route and durable journal accept only the separate formal grant type.
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_cycle_evidence as cycle_evidence
import completion_formal_cycle_authority as canonical_authority
import completion_kata_operation as operation
canonical_grant = formal.issue_grant(1, expected, canonical_authority)
route = cycle_evidence._formal_full_route()
assert cycle_evidence._cycle_launch_authorized(route, canonical_grant)
assert not cycle_evidence._cycle_launch_authorized(route, None)
route_name, capability, program, marker = cycle_evidence._describe_route(route)
journal_grant = canonical_authority.asdict(canonical_grant)
journal_grant["cycle_ordinal"] = journal_grant.pop("ordinal"); journal_grant.pop("mode")
body = {"operation_token": d("operation"), "route": route_name,
    "cycle_capability_sha256": capability, "program_sha256": program,
    "parser_source_sha256": operation.SSH_PARSER_SHA256, "marker_sha256": marker,
    "grant_authority": canonical_authority.AUTHORITY, **journal_grant}
operation._validate_body("CYCLE_ROUTE_V1", body)
hostile_body = {**body, "grant_authority": "production"}
try: operation._validate_body("CYCLE_ROUTE_V1", hostile_body)
except operation.OperationError: pass
else: raise AssertionError("cloud authority relabeling was accepted")

with tempfile.TemporaryDirectory() as temporary:
    for ordinal in range(1, 8): write_cycle(temporary, ordinal)
    package_raw = formal.aggregate(temporary, expected, "success")
    package = formal.decode(package_raw, 96 * 1024)
    assert package["cycle_count"] == 7 and package["workload_measurements"] == 21
    assert [row["mode"] for row in package["cycles"]] == list(formal.CYCLE_MODES)
    assert package["claims"] == {"formal_non_aws_qualification_passed": True,
        "aws_authorized": False, "aws_executed": False, "provider_executed": False,
        "promotion_authorized": False}
    for outcome in ("failure", "cancelled", "skipped", ""):
        rejected(lambda outcome=outcome: formal.aggregate(temporary, expected, outcome))
    rejected(lambda: formal.aggregate(temporary, {**expected, "GITHUB_RUN_ATTEMPT": "2"}, "success"))

    # Every identity class, ordinal, artifact, status and canonical byte sequence is fail-closed.
    for identity in ("host_boot_id", "operation_token", "rootfs_token", "runtime",
                     "client_key_commitment", "host_key_commitment"):
        hostile = receipt(2); prior = receipt(1)
        if identity == "host_boot_id": hostile["timing"][identity] = prior["timing"][identity]
        elif identity == "runtime":
            hostile["qmp_lineage"]["qemu_process_sha256"] = prior["qmp_lineage"]["qemu_process_sha256"]
            hostile["runtime_readiness_lineage"]["qemu_process_sha256"] = prior["qmp_lineage"]["qemu_process_sha256"]
        elif identity.endswith("key_commitment"):
            hostile["key_freshness"][identity] = prior["key_freshness"][identity]
        else:
            hostile[identity] = prior[identity]
            if identity == "operation_token":
                hostile["runtime_readiness_lineage"]["operation_token"] = prior[identity]
        other = tempfile.TemporaryDirectory()
        try:
            for ordinal in range(1, 8): write_cycle(other.name, ordinal, hostile if ordinal == 2 else receipt(ordinal))
            rejected(lambda: formal.aggregate(other.name, expected, "success"))
        finally: other.cleanup()

    for left, right in (("operation_token", "rootfs_token"),):
        hostile = receipt(2); hostile[left] = receipt(1)[right]
        hostile["runtime_readiness_lineage"]["operation_token"] = hostile[left]
        other = tempfile.TemporaryDirectory()
        try:
            for ordinal in range(1, 8): write_cycle(other.name, ordinal, hostile if ordinal == 2 else receipt(ordinal))
            rejected(lambda: formal.aggregate(other.name, expected, "success"))
        finally: other.cleanup()
    hostile = receipt(2); hostile["key_freshness"]["client_key_commitment"] = receipt(1)["key_freshness"]["host_key_commitment"]
    other = tempfile.TemporaryDirectory()
    try:
        for ordinal in range(1, 8): write_cycle(other.name, ordinal, hostile if ordinal == 2 else receipt(ordinal))
        rejected(lambda: formal.aggregate(other.name, expected, "success"))
    finally: other.cleanup()

    mutations = []
    wrong = receipt(2); wrong["aws_authority"] = wrong["cycle_grant"]["grant_commitment"]; mutations.append(wrong)
    wrong = receipt(2); wrong["lifecycle_objects"]["task_launches"] = 2; mutations.append(wrong)
    wrong = receipt(2); wrong["cycle_grant"]["cycle_ordinal"] = 3; mutations.append(wrong)
    wrong = receipt(2); wrong["parser_source_sha256"] = d("substituted-parser"); mutations.append(wrong)
    wrong = receipt(2); wrong["workloads"] = []; mutations.append(wrong)
    wrong = receipt(1); wrong["workloads"] = wrong["workloads"][:-1]; mutations.append(wrong)
    wrong = receipt(2); wrong["unexpected"] = True; mutations.append(wrong)
    for hostile in mutations:
        rejected(lambda hostile=hostile: formal.validate_receipt(formal.canonical(hostile), expected,
                                                                  hostile["cycle_grant"]["cycle_ordinal"]))
    qmp_fields = ("qemu_pid", "qemu_starttime", "qemu_executable_device",
                  "qemu_executable_inode", "observer_qmp_device", "observer_qmp_inode",
                  "kvm_device", "kvm_inode", "kvm_rdev", "kvm_api")
    for index, name in enumerate(qmp_fields):
        hostile = receipt(2)
        hostile["runtime_readiness_lineage"]["qmp_identity"][index] += 1
        rejected(lambda hostile=hostile: formal.validate_receipt(
            formal.canonical(hostile), expected, 2))

    sample_raw = (Path(temporary) / "cycle-1/receipt.json").read_bytes()
    rejected(lambda: formal.validate_receipt(sample_raw[:-1], expected, 1))
    rejected(lambda: formal.validate_receipt(sample_raw + b" ", expected, 1))
    rejected(lambda: formal.validate_receipt(sample_raw.replace(b'{"authority":', b'{"authority":"x","authority":', 1), expected, 1))
    extra = Path(temporary) / "cycle-8"; extra.mkdir()
    rejected(lambda: formal.aggregate(temporary, expected, "success")); extra.rmdir()
    missing = Path(temporary) / "cycle-7/status.json"; saved = missing.read_bytes(); missing.unlink()
    rejected(lambda: formal.aggregate(temporary, expected, "success")); missing.write_bytes(saved)
    status_path = Path(temporary) / "cycle-7/status.json"; status = json.loads(status_path.read_bytes())
    status["outcomes"]["recovery"] = "uncertain"; status_path.write_bytes(formal.canonical(status))
    rejected(lambda: formal.aggregate(temporary, expected, "success"))

print("stage2 formal seven-cycle qualification hostile checks passed")
