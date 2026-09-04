#!/usr/bin/env python3
"""Provider-free exact SSM receipt schema and commitment mutation matrix."""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_campaign_production as production
import completion_campaign_remote_adapter as adapter
import completion_cycle_authority as authority


def d(value): return hashlib.sha256(value.encode()).hexdigest()
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def qemu_identity(qmp):
    value = {name: item for name, item in qmp.items()
             if name not in {"live_mapping_sha256", "runtime_identity_sha256",
                             "qemu_process_sha256"}}
    return hashlib.sha256(
        b"cogs.stage2-qemu-runtime-identity/v1\0" + canonical(value)).hexdigest()


SOURCE_BINDINGS = {
    "source_head": "1" * 40,
    "source_manifest_sha256": d("source-manifest"),
    "host_attestation_sha256": d("host-attestation"),
    "runtime_attestation_sha256": d("runtime-attestation"),
    "rootfs_sha256": d("rootfs-content"),
    "rootfs_descriptor_sha256": d("rootfs"),
    "rootfs_package_manifest_sha256": d("rootfs-package-manifest"),
    "rootfs_provenance_sha256": d("rootfs-provenance"),
    "rootfs_publication_receipt_sha256": d("rootfs-publication"),
    "artifact_sha256": d("artifact"), "candidate_sha256": d("candidate"),
    "final_pin_sha256": d("final-pin"),
    "guest_program_sha256": adapter.FULL_PROGRAM_SHA256,
    "owner_implementation_sha256": d("owner-implementation"),
}


def approval():
    value = {
        "version": "cogs.stage2-completion-production-approval/v4",
        "phrase": production.APPROVAL_PHRASE,
        "implementation_revision": SOURCE_BINDINGS["source_head"],
        "control_revision": "2" * 40, "qualification_revision": "3" * 40,
        "source_manifest_sha256": SOURCE_BINDINGS["source_manifest_sha256"],
        "source_bindings_sha256": production._commit(
            b"cogs.stage2-source-bindings/v1", SOURCE_BINDINGS),
        "static_control_sha256": d("control"), "pre_aws_package_sha256": d("preaws"),
        "rootfs_descriptor_sha256": SOURCE_BINDINGS["rootfs_descriptor_sha256"],
        "rootfs_package_manifest_sha256": SOURCE_BINDINGS["rootfs_package_manifest_sha256"],
        "rootfs_provenance_sha256": SOURCE_BINDINGS["rootfs_provenance_sha256"],
        "rootfs_qualification_receipt_sha256": d("rootfs-qualification"),
        "rootfs_publication_receipt_sha256": SOURCE_BINDINGS["rootfs_publication_receipt_sha256"],
        "runtime_commitment": SOURCE_BINDINGS["runtime_attestation_sha256"],
        "fixture_commitment": SOURCE_BINDINGS["final_pin_sha256"],
        "provider_binary_sha256": d("provider"), "aws_cli_sha256": d("aws"),
        "account_commitment": d("account"), "partition": "aws", "region": "us-east-1",
        "ami_id": "ami-" + "a" * 17, "ami_owner_id": "099720109477",
        "ami_architecture": "x86_64", "ami_virtualization_type": "hvm",
        "ami_root_device_type": "ebs", "ami_state": "available",
        "plan_sha256s": tuple(d(f"plan-{index}") for index in range(1, 8)),
        "not_before_unix_ns": 1, "effect_deadline_ns": 90 * 60 * 10**9,
        "cleanup_reserve_ns": 10 * 60 * 10**9, "expires_unix_ns": 101 * 60 * 10**9,
        "maximum_cycle_duration_ns": 10 * 60 * 10**9,
        "maximum_cost_micro_usd": 499_999,
        "rate_source_commitment": production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": d("issuer"), "executor_principal_commitment": d("executor"),
        "inventory_observer_principal_commitment": d("observer"), "one_attempt": True,
    }
    value["ami_commitment"] = production.resolved_ami_commitment(value)
    value["batch_commitment"] = production.approval_batch_commitment(value)
    return production.ProductionApproval(**value)


APPROVAL = approval()


def grant(mode, ordinal):
    current = production._grant(APPROVAL, ordinal)
    assert current.mode == mode
    return current


def effect(kind, current, start, end, identity):
    resources = (tuple(sorted((
        ("instance", d(f"instance-resource-{current.ordinal}")),
        ("root_volume", d(f"root-volume-{current.ordinal}")),
        ("launch_template_generation", d(f"launch-template-{current.ordinal}")),
    ))) if kind == "running" else ())
    state = production._commit(b"cogs.stage2-provider-state-slot/v1", {
        "batch_commitment": current.batch_commitment, "ordinal": current.ordinal})
    lineage = production._commit(b"cogs.stage2-provider-state-lineage/v1", {
        "batch_commitment": current.batch_commitment, "ordinal": current.ordinal,
        "state_slot": f"cycle-{current.ordinal}",
    })
    fields = {
        "kind": kind, "grant_commitment": current.grant_commitment,
        "batch_commitment": current.batch_commitment, "ordinal": current.ordinal,
        "mode": current.mode, "state_commitment": state,
        "state_bytes_sha256": d(f"state-bytes-{kind}-{current.ordinal}"),
        "state_lineage_commitment": lineage, "identity_commitment": identity,
        "intent_commitment": d(f"intent-{kind}"), "ami_commitment": current.ami_commitment,
        "resource_commitments": resources, "observed_started_unix_ns": start,
        "observed_ended_unix_ns": end, "invocation_count": 1, "certain": True,
    }
    settlement = production._commit(
        b"cogs.stage2-provider-effect-settlement/v1", fields)
    return production.EffectReceipt(**fields, settlement_commitment=settlement)


def owner(current):
    program, marker = adapter.PROGRAMS[current.mode]
    operation_token = d(f"operation-{current.ordinal}")
    qmp = {
        "live_mapping_sha256": d("live-mapping"),
        "qemu_process_sha256": d("qemu-pre-ssh-fact"), "qemu_argv_sha256": d("qemu-argv"),
        "qemu_pid": 100, "qemu_starttime": 200,
        "qemu_executable_device": 250, "qemu_executable_inode": 260,
        "observer_qmp_device": 300,
        "observer_qmp_inode": 400, "kvm_device": 500, "kvm_inode": 600,
        "kvm_rdev": 700, "kvm_api": 12, "qmp_present": True, "qmp_enabled": True,
    }
    qmp["runtime_identity_sha256"] = qemu_identity(qmp)
    value = {
        "version": adapter.PRIVATE_VERSION,
        "route": current.mode,
        "cycle_capability_sha256": adapter._cycle_capability(current.mode, program, marker),
        "cycle_grant": {
            "batch_commitment": current.batch_commitment,
            "cycle_ordinal": current.ordinal,
            "implementation_revision": current.implementation_revision,
            "control_revision": current.control_revision,
            "static_control_sha256": current.static_control_sha256,
            "rootfs_descriptor_sha256": current.rootfs_descriptor_sha256,
            "ami_commitment": current.ami_commitment,
            "plan_sha256": current.plan_sha256,
            "grant_commitment": current.grant_commitment,
        },
        "production_publication_authorized": False,
        "provider_execution_observed": False,
        "aws_authority": current.grant_commitment,
        "source_bindings": dict(SOURCE_BINDINGS),
        "operation_token": operation_token,
        "journal_sha256": d("journal"),
        "program_sha256": program,
        "parser_source_sha256": adapter.PARSERS[current.mode],
        "marker_sha256": marker,
        "launch_attempts": 1, "ssh_attempts": 1,
        "timing": {
            "host_boot_id": f"boot-{current.ordinal}",
            "launch_record_sha256": d("launch-record"),
            "marker_record_sha256": d("marker-record"),
            "settlement_record_sha256": d("settlement-record"),
            "kata_launch_started_boottime_ns": 100,
            "ssh_marker_observed_boottime_ns": 200,
            "ssh_command_settled_boottime_ns": 300,
            "ssh_ready_ns": 100,
        },
        "key_freshness": {
            "client_key_commitment": d(f"client-key-{current.ordinal}"),
            "host_key_commitment": d(f"host-key-{current.ordinal}"),
        },
        "runtime_network_sha256": d("runtime-network"),
        "qmp_lineage": qmp,
        "teardown_projection": list(adapter.TEARDOWN_PROJECTION),
        "private_teardown_records": list(adapter.PRIVATE_TEARDOWN_RECORDS),
        "final_baselines_sha256": d("final-baselines"),
        "independent_residue_absent": list(adapter.RESIDUE_FACTS),
    }
    if current.mode == "full":
        value.update({
            "network_markers": list(adapter.NETWORK_MARKERS),
            "route_before_sha256": d("route"), "route_after_sha256": d("route"),
            "workloads": [
                {"ordinal": global_ordinal, "category": f"{category}_{sample:02d}",
                 "duration_ns": global_ordinal + 1,
                 "result_sha256": adapter.WORKLOAD_DIGESTS[category], "deleted": True}
                for global_ordinal, (category, sample) in enumerate(
                    ((category, sample) for category in ("GIT", "BUILD", "INSTALL")
                     for sample in range(1, 8)), 1)
            ],
            "network_causal_proof_sha256": d("network-causal-proof"),
        })
    else:
        value["runtime_readiness_lineage"] = {
            "operation_token": value["operation_token"],
            "runtime_mount_record_sha256": d("runtime-mount-record"),
            "runtime_network_sha256": value["runtime_network_sha256"],
            "live_mapping_sha256": qmp["live_mapping_sha256"],
            "runtime_identity_sha256": qmp["runtime_identity_sha256"],
            "qemu_process_sha256": d("qemu-post-ssh-fact"),
            "qmp_identity": [100, 200, 250, 260, 300, 400, 500, 600, 700, 12],
        }
    return value


def rejected(action, message):
    try: action()
    except (adapter.RemoteAdapterError, production.ProductionCampaignError): return
    raise AssertionError(message)


def containers(value, path=()):
    yield path, value
    if type(value) is dict:
        for key, item in value.items(): yield from containers(item, path + (key,))
    elif type(value) is list:
        for index, item in enumerate(value): yield from containers(item, path + (index,))


def locate(value, path):
    for item in path: value = value[item]
    return value


def exhaustive_schema_mutations(current, apply, running, exact):
    def reject_value(mutated, label):
        rejected(lambda: adapter.remote_receipt(
            APPROVAL, current, apply, running, canonical(mutated)), label)

    # Every object is closed to missing and additional members.
    for path, item in list(containers(exact)):
        if type(item) is dict:
            for key in tuple(item):
                mutated = copy.deepcopy(exact); locate(mutated, path).pop(key)
                reject_value(mutated, f"missing key accepted at {path + (key,)}")
            mutated = copy.deepcopy(exact); locate(mutated, path)["unexpected"] = None
            reject_value(mutated, f"additional key accepted at {path}")
        elif type(item) is list:
            mutated = copy.deepcopy(exact); locate(mutated, path).append(None)
            reject_value(mutated, f"additional list member accepted at {path}")
            for index in range(len(item)):
                mutated = copy.deepcopy(exact); locate(mutated, path).pop(index)
                reject_value(mutated, f"missing list member accepted at {path + (index,)}")

    # Every scalar position rejects a wrong exact JSON type.
    for path, item in list(containers(exact)):
        if type(item) not in {dict, list}:
            mutated = copy.deepcopy(exact)
            parent = locate(mutated, path[:-1])
            parent[path[-1]] = ({str: None, int: False, bool: 1}[type(item)])
            reject_value(mutated, f"wrong scalar type accepted at {path}")


for mode, ordinal, command in (("full", 1, adapter.FULL_COMMAND),
                               ("readiness", 2, adapter.READINESS_COMMAND)):
    current = grant(mode, ordinal)
    invocation = adapter.invocation(current)
    assert invocation.command == command and authority.decode(invocation.grant_bytes) == current
    apply = effect("apply", current, 1000, 1010, d(f"apply-{ordinal}"))
    running = effect("running", current, 1020, 1030, d(f"instance-{ordinal}"))
    exact = owner(current)
    receipt = adapter.remote_receipt(APPROVAL, current, apply, running, canonical(exact))
    assert receipt.mode == mode and receipt.ami_commitment == current.ami_commitment
    assert receipt.provider_launch_started_unix_ns == 1000
    assert receipt.provider_running_observed_unix_ns == 1030
    assert receipt.ssh_ready_observed_boottime_ns - receipt.kata_launch_started_boottime_ns == 100
    assert len(receipt.workloads) == (21 if mode == "full" else 0)
    assert receipt.bindings.source == production.RemoteSourceBindings(**SOURCE_BINDINGS)
    assert receipt.bindings.parser_source_sha256 == adapter.PARSERS[mode]
    assert receipt.bindings.qemu.runtime_identity_sha256 == exact["qmp_lineage"]["runtime_identity_sha256"]
    if mode == "readiness":
        assert receipt.bindings.qemu.pre_ssh_runtime_fact_sha256 != receipt.bindings.qemu.post_ssh_runtime_fact_sha256
    exhaustive_schema_mutations(current, apply, running, exact)

    # Valid-looking substitutions at every external/cross-owner seam are denied.
    for path in (("aws_authority",), ("cycle_capability_sha256",),
                 ("parser_source_sha256",), ("cycle_grant", "grant_commitment"),
                 *(("source_bindings", name) for name in adapter.SOURCE_BINDING_KEYS)):
        mutated = copy.deepcopy(exact)
        locate(mutated, path[:-1])[path[-1]] = (
            "f" * 40 if path == ("source_bindings", "source_head") else d("substitute"))
        rejected(lambda mutated=mutated: adapter.remote_receipt(
            APPROVAL, current, apply, running, canonical(mutated)),
            f"cross commitment accepted at {path}")
    if mode == "full":
        for path in (("route_after_sha256",), ("workloads", 0, "result_sha256")):
            mutated = copy.deepcopy(exact); locate(mutated, path[:-1])[path[-1]] = d("substitute")
            rejected(lambda mutated=mutated: adapter.remote_receipt(
                APPROVAL, current, apply, running, canonical(mutated)),
                f"full cross commitment accepted at {path}")
    else:
        for path in (("runtime_readiness_lineage", "operation_token"),
                     ("runtime_readiness_lineage", "runtime_identity_sha256"),
                     ("runtime_readiness_lineage", "qemu_process_sha256")):
            mutated = copy.deepcopy(exact)
            locate(mutated, path[:-1])[path[-1]] = (
                mutated["qmp_lineage"]["qemu_process_sha256"]
                if path[-1] == "qemu_process_sha256" else d("substitute"))
            rejected(lambda mutated=mutated: adapter.remote_receipt(
                APPROVAL, current, apply, running, canonical(mutated)),
                f"readiness cross accepted at {path}")
        qmp_fields = ("qemu_pid", "qemu_starttime", "qemu_executable_device",
                      "qemu_executable_inode", "observer_qmp_device",
                      "observer_qmp_inode", "kvm_device", "kvm_inode", "kvm_rdev",
                      "kvm_api")
        for index, name in enumerate(qmp_fields):
            mutated = copy.deepcopy(exact)
            mutated["runtime_readiness_lineage"]["qmp_identity"][index] += 1
            rejected(lambda mutated=mutated: adapter.remote_receipt(
                APPROVAL, current, apply, running, canonical(mutated)),
                f"QMP identity substitution accepted at {name}")

    for field in ("grant_commitment", "batch_commitment", "state_commitment",
                  "state_lineage_commitment", "ami_commitment", "settlement_commitment"):
        hostile = replace(apply, **{field: d("substitute-provider-lineage")})
        rejected(lambda hostile=hostile: adapter.remote_receipt(
            APPROVAL, current, hostile, running, canonical(exact)),
            f"provider {field} substitution accepted")

# Framing and parser ambiguity remain closed before semantic projection.
current = grant("full", 1); exact = owner(current)
apply = effect("apply", current, 1, 2, d("apply")); running = effect("running", current, 3, 4, d("running"))
for raw in (canonical(exact)[:-1], canonical(exact) + b"\n",
            b'{"version":"x","version":"y"}\n', b'{"x":NaN}\n'):
    rejected(lambda raw=raw: adapter.remote_receipt(
        APPROVAL, current, apply, running, raw),
             "noncanonical or ambiguous receipt accepted")

print("stage2 provider-free remote adapter checks passed")
