"""Closed adapter from controller grants to grant-bound private owner receipts.

The adapter does not invent wall-clock timestamps.  Provider launch/running times
come only from typed apply/running receipts; host SSH readiness remains a separate
boot-clock measurement bound by the private owner receipt.
"""

from dataclasses import dataclass
import hashlib
import json

import completion_campaign_production as production

GRANT_PATH = "/var/lib/cogs/stage2-completion-v1/cycle-authority-v1/grant.json"
SOURCE = "/var/lib/cogs/stage2-completion-v1/source"
FULL_COMMAND = SOURCE + "/deploy/aws-feasibility/remote/run-stage2-completion-full.sh"
READINESS_COMMAND = SOURCE + "/deploy/aws-feasibility/remote/run-stage2-completion-readiness.sh"
MAX_RECEIPT_BYTES = 256 * 1024


class RemoteAdapterError(Exception): pass


def _require(value):
    if not value: raise RemoteAdapterError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(type(key) is str and key not in value); value[key] = item
    return value


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


def _receipt(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RECEIPT_BYTES
             and raw.endswith(b"\n"))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise RemoteAdapterError() from error
    _require(type(value) is dict and _canonical(value) == raw
             and value.get("version") == "cogs.stage2-cycle-private-owner-receipt/v1"
             and value.get("production_publication_authorized") is False
             and value.get("provider_execution_observed") is False
             and value.get("launch_attempts") == value.get("ssh_attempts") == 1)
    return value


def remote_receipt(grant, apply, running, raw):
    _require(type(grant) is production.CycleLaunchGrant
             and type(apply) is production.EffectReceipt
             and type(running) is production.EffectReceipt)
    _require(apply.kind == "apply" and running.kind == "running"
             and apply.grant_commitment == running.grant_commitment ==
                 grant.grant_commitment
             and apply.state_commitment == running.state_commitment
             and apply.state_lineage_commitment == running.state_lineage_commitment)
    value = _receipt(raw)
    _require(value.get("route") == grant.mode
             and value.get("aws_authority") == grant.grant_commitment)
    cycle_grant = value.get("cycle_grant")
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
    _require(cycle_grant == expected_grant)
    bindings = value.get("source_bindings")
    _require(type(bindings) is dict
             and bindings.get("source_head") == grant.implementation_revision
             and bindings.get("rootfs_descriptor_sha256") ==
                 grant.rootfs_descriptor_sha256)
    timing = value.get("timing")
    _require(type(timing) is dict
             and type(timing.get("kata_launch_started_boottime_ns")) is int
             and type(timing.get("ssh_marker_observed_boottime_ns")) is int
             and timing["kata_launch_started_boottime_ns"] <
                 timing["ssh_marker_observed_boottime_ns"])
    workloads = []
    if grant.mode == "full":
        rows = value.get("workloads"); _require(type(rows) is list and len(rows) == 21)
        by_key = {}
        for row in rows:
            _require(type(row) is dict
                     and set(row) == {"ordinal", "category", "duration_ns",
                                     "result_sha256", "deleted"}
                     and row.get("deleted") is True)
            item = production.WorkloadMeasurement(
                row["category"], row["ordinal"], row["duration_ns"],
                row["result_sha256"])
            _require((item.category, item.ordinal) not in by_key)
            by_key[(item.category, item.ordinal)] = item
        workloads = [by_key[(category, ordinal)]
                     for category in ("git", "build", "install")
                     for ordinal in range(1, 8)]
    else:
        _require("workloads" not in value)
    host_receipt = hashlib.sha256(
        b"cogs.stage2-cycle-private-owner-receipt/v1\0" + raw).hexdigest()
    operation = value.get("operation_token"); production._digest(operation)
    host_boot = timing.get("host_boot_id")
    _require(type(host_boot) is str and 1 <= len(host_boot) <= 128)
    host_boot_commitment = production._commit(
        b"cogs.stage2-host-boot/v1", {"host_boot_id": host_boot})
    key_freshness = value.get("key_freshness")
    _require(type(key_freshness) is dict
             and set(key_freshness) == {"client_key_commitment",
                                        "host_key_commitment"})
    for item in key_freshness.values(): production._digest(item)
    _require(len(set(key_freshness.values())) == 2)
    return production.RemoteReceipt(
        grant.grant_commitment, grant.batch_commitment, grant.ordinal, grant.mode,
        apply.state_commitment, apply.state_lineage_commitment,
        running.identity_commitment, host_receipt, operation,
        host_boot_commitment, key_freshness["client_key_commitment"],
        key_freshness["host_key_commitment"], grant.rootfs_descriptor_sha256,
        grant.ami_commitment, apply.observed_started_unix_ns,
        running.observed_ended_unix_ns,
        timing["kata_launch_started_boottime_ns"],
        timing["ssh_marker_observed_boottime_ns"], tuple(workloads), True)
