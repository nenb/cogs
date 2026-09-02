"""Closed adapter from controller grants to exact private cycle receipts.

This module crosses the SSM byte boundary without performing an effect.  It
accepts only the complete canonical full/readiness receipt shapes emitted by
``completion_cycle_evidence`` and projects those owner facts into controller
receipts.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import completion_campaign_production as production

GRANT_PATH = "/var/lib/cogs/stage2-completion-v1/cycle-authority-v1/grant.json"
SOURCE = "/var/lib/cogs/stage2-completion-v1/source"
FULL_COMMAND = SOURCE + "/deploy/aws-feasibility/remote/run-stage2-completion-full.sh"
READINESS_COMMAND = SOURCE + "/deploy/aws-feasibility/remote/run-stage2-completion-readiness.sh"
MAX_RECEIPT_BYTES = 256 * 1024
PRIVATE_VERSION = "cogs.stage2-cycle-private-owner-receipt/v1"
FULL_PROGRAM_SHA256 = "0e62df128ab166344e4a8e20aa9c92b376fbf96ba8454f73cec66ca1b5678406"
FULL_MARKER_SHA256 = "35f125d7914d134854e532a08398153ffcd699426fbeeabcb7c35d7f4ec474f5"
READINESS_PROGRAM_SHA256 = "386f9398688cad05dfc0921ad0e5aa442cf146fd7ff16ddd82a7683244da6bab"
READINESS_MARKER_SHA256 = "b5b71497621037e6b7eada7c581962775625d532cdc06729dfd095e6a6f7c010"
_REMOTE_SOURCE = Path(__file__).resolve().parent / "remote"
FULL_PARSER_SHA256 = hashlib.sha256(
    (_REMOTE_SOURCE / "completion_guest_workloads_v3.py").read_bytes()).hexdigest()
READINESS_PARSER_SHA256 = hashlib.sha256(
    (_REMOTE_SOURCE / "completion_guest_readiness_v1.py").read_bytes()).hexdigest()
PARSERS = {"full": FULL_PARSER_SHA256, "readiness": READINESS_PARSER_SHA256}
PROGRAMS = {
    "full": (FULL_PROGRAM_SHA256, FULL_MARKER_SHA256),
    "readiness": (READINESS_PROGRAM_SHA256, READINESS_MARKER_SHA256),
}
NETWORK_MARKERS = (
    "route-baseline-no-default", "direct-tcp-denied", "direct-udp-denied",
    "default-route-added", "route-tcp-denied", "route-udp-denied",
    "default-route-removed", "route-restored-no-default",
)
WORKLOAD_DIGESTS = {
    "GIT": "73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c",
    "BUILD": "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf",
    "INSTALL": "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
}
TEARDOWN_PROJECTION = (
    "READINESS_REVOKED", "TASK_STOPPED", "TASK_ABSENT", "RUNTIME_PROCESSES_ABSENT",
    "NETWORK_ABSENT", "CONTAINER_ABSENT", "SHARE_AND_MOUNTS_ABSENT",
    "FIREWALL_ABSENT", "CONTAINERD_ABSENT", "INPUTS_ABSENT", "ROOTFS_ABSENT",
    "FINAL_BASELINES", "RETIRED",
)
PRIVATE_TEARDOWN_RECORDS = (
    "READINESS_REVOKED", "RUNTIME_ROLE_IDENTITIES_V1", "RUNTIME_SHARE_IDENTITY_V1",
    "TASK_STOPPED", "TASK_ABSENT", "RUNTIME_ROLE_ABSENCE_V1", "RUNTIME_ABSENT",
    "RUNTIME_NETWORK_RELEASED_V1", "NETWORK_ABSENT", "CONTAINER_ABSENT",
    "SHARE_ABSENT", "FIREWALL_ABSENT", "CONTAINERD_ABSENT", "INPUT_REMOVED",
    "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED", "ROOTFS_ABSENT",
    "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED",
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
SOURCE_BINDING_KEYS = {
    "source_head", "source_manifest_sha256", "host_attestation_sha256",
    "runtime_attestation_sha256", "rootfs_sha256", "rootfs_descriptor_sha256",
    "rootfs_package_manifest_sha256", "rootfs_provenance_sha256",
    "rootfs_publication_receipt_sha256", "artifact_sha256", "candidate_sha256",
    "final_pin_sha256", "guest_program_sha256", "owner_implementation_sha256",
}
COMMON_KEYS = {
    "version", "route", "cycle_capability_sha256", "cycle_grant",
    "production_publication_authorized", "provider_execution_observed", "aws_authority",
    "source_bindings", "operation_token", "journal_sha256", "program_sha256",
    "parser_source_sha256", "marker_sha256", "launch_attempts", "ssh_attempts",
    "timing", "key_freshness",
    "runtime_network_sha256", "qmp_lineage", "teardown_projection",
    "private_teardown_records", "final_baselines_sha256", "independent_residue_absent",
}


class RemoteAdapterError(Exception):
    pass


def _require(value):
    if not value:
        raise RemoteAdapterError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value)
        value[key] = item
    return value


def _keys(value, expected):
    _require(type(value) is dict and set(value) == set(expected))


def _digest(value):
    production._digest(value)
    return value


def _integer(value, minimum=0):
    _require(type(value) is int and value >= minimum)
    return value


def _cycle_capability(mode, program, marker):
    return hashlib.sha256(
        b"cogs.stage2-cycle-route/v1\0production\0" + mode.encode("ascii")
        + bytes.fromhex(program) + bytes.fromhex(marker)).hexdigest()


@dataclass(frozen=True)
class RemoteInvocation:
    grant_path: str
    grant_bytes: bytes
    command: str
    batch_commitment: str
    ordinal: int
    mode: str
    grant_commitment: str

    def __post_init__(self):
        _require(self.grant_path == GRANT_PATH
                 and self.command in {FULL_COMMAND, READINESS_COMMAND}
                 and type(self.grant_bytes) is bytes
                 and self.grant_bytes.endswith(b"\n"))


def invocation(grant):
    _require(type(grant) is production.CycleLaunchGrant)
    value = {"version": "cogs.stage2-cycle-launch-grant/v1", **grant.__dict__}
    command = FULL_COMMAND if grant.mode == "full" else READINESS_COMMAND
    return RemoteInvocation(GRANT_PATH, _canonical(value), command,
                            grant.batch_commitment, grant.ordinal, grant.mode,
                            grant.grant_commitment)


def _receipt(raw, mode):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RECEIPT_BYTES
             and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise RemoteAdapterError() from error
    route_keys = ({"network_markers", "route_before_sha256", "route_after_sha256",
                   "workloads", "network_causal_proof_sha256"}
                  if mode == "full" else {"runtime_readiness_lineage"})
    _keys(value, COMMON_KEYS | route_keys)
    _require(_canonical(value) == raw and value["version"] == PRIVATE_VERSION
             and value["route"] == mode
             and value["production_publication_authorized"] is False
             and value["provider_execution_observed"] is False
             and value["launch_attempts"] == value["ssh_attempts"] == 1)
    return value


def _validate_provider_lineage(grant, apply, running):
    _require(type(grant) is production.CycleLaunchGrant
             and type(apply) is production.EffectReceipt
             and type(running) is production.EffectReceipt)
    expected_state = production._commit(b"cogs.stage2-provider-state-slot/v1", {
        "batch_commitment": grant.batch_commitment, "ordinal": grant.ordinal})
    expected_lineage = production._commit(b"cogs.stage2-provider-state-lineage/v1", {
        "batch_commitment": grant.batch_commitment, "ordinal": grant.ordinal,
        "state_slot": f"cycle-{grant.ordinal}",
    })
    for receipt, kind in ((apply, "apply"), (running, "running")):
        settlement_fields = dict(receipt.__dict__)
        settlement_fields.pop("settlement_commitment")
        expected_settlement = production._commit(
            b"cogs.stage2-provider-effect-settlement/v1", settlement_fields)
        _require(receipt.kind == kind
                 and receipt.grant_commitment == grant.grant_commitment
                 and receipt.batch_commitment == grant.batch_commitment
                 and receipt.ordinal == grant.ordinal and receipt.mode == grant.mode
                 and receipt.ami_commitment == grant.ami_commitment
                 and receipt.state_commitment == expected_state
                 and receipt.state_lineage_commitment == expected_lineage
                 and receipt.settlement_commitment == expected_settlement)
    _require(apply.state_commitment == running.state_commitment
             and apply.state_lineage_commitment == running.state_lineage_commitment
             and apply.observed_started_unix_ns < running.observed_ended_unix_ns)


def _validate_common(value, grant, approval):
    expected_grant = {
        "batch_commitment": grant.batch_commitment,
        "cycle_ordinal": grant.ordinal,
        "implementation_revision": grant.implementation_revision,
        "control_revision": grant.control_revision,
        "static_control_sha256": grant.static_control_sha256,
        "rootfs_descriptor_sha256": grant.rootfs_descriptor_sha256,
        "ami_commitment": grant.ami_commitment,
        "plan_sha256": grant.plan_sha256,
        "grant_commitment": grant.grant_commitment,
    }
    _require(type(approval) is production.ProductionApproval
             and grant == production._grant(approval, grant.ordinal)
             and value["cycle_grant"] == expected_grant
             and value["aws_authority"] == grant.grant_commitment)
    program, marker = PROGRAMS[grant.mode]
    _require(value["program_sha256"] == program
             and value["parser_source_sha256"] == PARSERS[grant.mode]
             and value["marker_sha256"] == marker
             and value["cycle_capability_sha256"] ==
                 _cycle_capability(grant.mode, program, marker))

    bindings = value["source_bindings"]
    _keys(bindings, SOURCE_BINDING_KEYS)
    _require(bindings["source_head"] == grant.implementation_revision
             and bindings["source_manifest_sha256"] == approval.source_manifest_sha256
             and bindings["runtime_attestation_sha256"] == approval.runtime_commitment
             and bindings["rootfs_descriptor_sha256"] == grant.rootfs_descriptor_sha256
             and bindings["rootfs_package_manifest_sha256"] ==
                 approval.rootfs_package_manifest_sha256
             and bindings["rootfs_provenance_sha256"] ==
                 approval.rootfs_provenance_sha256
             and bindings["rootfs_publication_receipt_sha256"] ==
                 approval.rootfs_publication_receipt_sha256
             and bindings["final_pin_sha256"] == approval.fixture_commitment
             and bindings["guest_program_sha256"] == FULL_PROGRAM_SHA256
             and production._commit(b"cogs.stage2-source-bindings/v1", bindings) ==
                 approval.source_bindings_sha256)
    for name, item in bindings.items():
        if name != "source_head":
            _digest(item)

    for name in ("operation_token", "journal_sha256", "runtime_network_sha256",
                 "final_baselines_sha256"):
        _digest(value[name])
    timing = value["timing"]
    _keys(timing, {"host_boot_id", "launch_record_sha256", "marker_record_sha256",
                   "settlement_record_sha256", "kata_launch_started_boottime_ns",
                   "ssh_marker_observed_boottime_ns", "ssh_command_settled_boottime_ns",
                   "ssh_ready_ns"})
    _require(type(timing["host_boot_id"]) is str
             and 1 <= len(timing["host_boot_id"]) <= 128)
    for name in ("launch_record_sha256", "marker_record_sha256",
                 "settlement_record_sha256"):
        _digest(timing[name])
    launch = _integer(timing["kata_launch_started_boottime_ns"], 1)
    marker_time = _integer(timing["ssh_marker_observed_boottime_ns"], 1)
    settled = _integer(timing["ssh_command_settled_boottime_ns"], 1)
    _require(launch < marker_time <= settled
             and timing["ssh_ready_ns"] == marker_time - launch)

    freshness = value["key_freshness"]
    _keys(freshness, {"client_key_commitment", "host_key_commitment"})
    for item in freshness.values():
        _digest(item)
    _require(freshness["client_key_commitment"] != freshness["host_key_commitment"])

    qmp = value["qmp_lineage"]
    _keys(qmp, {"qemu_process_sha256", "qemu_argv_sha256", "qemu_pid",
                "qemu_starttime", "qemu_executable_device", "qemu_executable_inode",
                "observer_qmp_device", "observer_qmp_inode",
                "kvm_device", "kvm_inode", "kvm_rdev", "kvm_api", "qmp_present",
                "qmp_enabled"})
    _digest(qmp["qemu_process_sha256"]); _digest(qmp["qemu_argv_sha256"])
    _require(_integer(qmp["qemu_pid"]) > 1 and _integer(qmp["qemu_starttime"]) > 0
             and _integer(qmp["qemu_executable_device"]) >= 0
             and _integer(qmp["qemu_executable_inode"]) > 0
             and _integer(qmp["observer_qmp_device"]) >= 0
             and _integer(qmp["observer_qmp_inode"]) > 0
             and _integer(qmp["kvm_device"]) >= 0 and _integer(qmp["kvm_inode"]) > 0
             and _integer(qmp["kvm_rdev"]) > 0 and qmp["kvm_api"] == 12
             and qmp["qmp_present"] is True and qmp["qmp_enabled"] is True)
    _require(value["teardown_projection"] == list(TEARDOWN_PROJECTION)
             and value["private_teardown_records"] == list(PRIVATE_TEARDOWN_RECORDS)
             and value["independent_residue_absent"] == list(RESIDUE_FACTS))
    return timing, freshness, qmp


def _validate_full(value):
    _require(value["network_markers"] == list(NETWORK_MARKERS)
             and value["route_before_sha256"] == value["route_after_sha256"])
    _digest(value["route_before_sha256"])
    _digest(value["network_causal_proof_sha256"])
    rows = value["workloads"]
    _require(type(rows) is list and len(rows) == 21)
    workloads = []
    for global_ordinal, row in enumerate(rows, 1):
        _keys(row, {"ordinal", "category", "duration_ns", "result_sha256", "deleted"})
        category_index, sample = divmod(global_ordinal - 1, 7)
        category = ("GIT", "BUILD", "INSTALL")[category_index]
        expected_label = f"{category}_{sample + 1:02d}"
        _require(row["ordinal"] == global_ordinal and row["category"] == expected_label
                 and type(row["duration_ns"]) is int
                 and 1 <= row["duration_ns"] <= 1_200_000_000_000
                 and row["result_sha256"] == WORKLOAD_DIGESTS[category]
                 and row["deleted"] is True)
        workloads.append(production.WorkloadMeasurement(
            category.lower(), sample + 1, row["duration_ns"], row["result_sha256"]))
    return workloads


def _validate_readiness(value, operation, runtime_network, qmp):
    lineage = value["runtime_readiness_lineage"]
    _keys(lineage, {"operation_token", "runtime_mount_record_sha256",
                    "runtime_network_sha256", "live_mapping_sha256",
                    "qemu_process_sha256", "qmp_identity"})
    for name in ("operation_token", "runtime_mount_record_sha256",
                 "runtime_network_sha256", "live_mapping_sha256", "qemu_process_sha256"):
        _digest(lineage[name])
    identity = lineage["qmp_identity"]
    _require(type(identity) is list and len(identity) == 10
             and all(type(item) is int and item >= 0 for item in identity)
             and identity[0] > 1 and identity[1] > 0 and identity[3] > 0
             and identity[5] > 0 and identity[7] > 0 and identity[9] == 12
             and lineage["operation_token"] == operation
             and lineage["runtime_network_sha256"] == runtime_network
             and lineage["qemu_process_sha256"] == qmp["qemu_process_sha256"]
             and identity[0] == qmp["qemu_pid"] and identity[1] == qmp["qemu_starttime"]
             and identity[2] == qmp["qemu_executable_device"]
             and identity[3] == qmp["qemu_executable_inode"]
             and identity[4] == qmp["observer_qmp_device"]
             and identity[5] == qmp["observer_qmp_inode"]
             and identity[6] == qmp["kvm_device"] and identity[7] == qmp["kvm_inode"]
             and identity[8] == qmp["kvm_rdev"] and identity[9] == qmp["kvm_api"])


def remote_receipt(approval, grant, apply, running, raw):
    _validate_provider_lineage(grant, apply, running)
    value = _receipt(raw, grant.mode)
    timing, freshness, qmp = _validate_common(value, grant, approval)
    operation = value["operation_token"]
    workloads = (_validate_full(value) if grant.mode == "full" else [])
    if grant.mode == "readiness":
        _validate_readiness(value, operation, value["runtime_network_sha256"], qmp)

    host_receipt = hashlib.sha256(
        b"cogs.stage2-cycle-private-owner-receipt/v1\0" + raw).hexdigest()
    host_boot_commitment = production._commit(
        b"cogs.stage2-host-boot/v1", {"host_boot_id": timing["host_boot_id"]})
    return production.RemoteReceipt(
        grant.grant_commitment, grant.batch_commitment, grant.ordinal, grant.mode,
        apply.state_commitment, apply.state_lineage_commitment,
        running.identity_commitment, host_receipt, operation,
        host_boot_commitment, freshness["client_key_commitment"],
        freshness["host_key_commitment"], grant.rootfs_descriptor_sha256,
        grant.ami_commitment, apply.observed_started_unix_ns,
        running.observed_ended_unix_ns,
        timing["kata_launch_started_boottime_ns"],
        timing["ssh_marker_observed_boottime_ns"], tuple(workloads), True)
