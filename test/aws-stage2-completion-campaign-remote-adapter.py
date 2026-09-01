#!/usr/bin/env python3
"""Provider-free exact remote invocation and host receipt adapter checks."""
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


def grant(mode, ordinal):
    value = {"batch_commitment": d("batch"), "ordinal": ordinal, "mode": mode,
             "implementation_revision": "1" * 40, "control_revision": "2" * 40,
             "static_control_sha256": d("control"),
             "rootfs_descriptor_sha256": d("rootfs"), "ami_commitment": d("ami"),
             "plan_sha256": d(f"plan-{ordinal}")}
    return production.CycleLaunchGrant(**value, grant_commitment=production._commit(
        b"cogs.stage2-cycle-launch-grant/v1", value))


def effect(kind, grant, start, end, identity):
    resources = (tuple(sorted((
        ("instance", d(f"instance-resource-{grant.ordinal}")),
        ("root_volume", d(f"root-volume-{grant.ordinal}")),
        ("launch_template_generation", d(f"launch-template-{grant.ordinal}")),
    ))) if kind == "running" else ())
    return production.EffectReceipt(
        kind, grant.grant_commitment, grant.batch_commitment, grant.ordinal,
        grant.mode, d(f"state-{grant.ordinal}"), d(f"state-bytes-{grant.ordinal}"),
        d(f"lineage-{grant.ordinal}"),
        identity, d(f"intent-{kind}"), d(f"settlement-{kind}"),
        grant.ami_commitment, resources, start, end, 1, True)


def owner(grant):
    value = {
        "version": "cogs.stage2-cycle-private-owner-receipt/v1",
        "route": grant.mode, "production_publication_authorized": False,
        "provider_execution_observed": False,
        "aws_authority": grant.grant_commitment,
        "cycle_grant": {
            "batch_commitment": grant.batch_commitment,
            "cycle_ordinal": grant.ordinal,
            "implementation_revision": grant.implementation_revision,
            "control_revision": grant.control_revision,
            "static_control_sha256": grant.static_control_sha256,
            "rootfs_descriptor_sha256": grant.rootfs_descriptor_sha256,
            "ami_commitment": grant.ami_commitment,
            "plan_sha256": grant.plan_sha256,
            "grant_commitment": grant.grant_commitment,
        },
        "launch_attempts": 1, "ssh_attempts": 1,
        "operation_token": d(f"operation-{grant.ordinal}"),
        "key_freshness": {
            "client_key_commitment": d(f"client-key-{grant.ordinal}"),
            "host_key_commitment": d(f"host-key-{grant.ordinal}"),
        },
        "source_bindings": {
            "source_head": grant.implementation_revision,
            "rootfs_descriptor_sha256": grant.rootfs_descriptor_sha256,
        },
        "timing": {"host_boot_id": f"boot-{grant.ordinal}",
                   "kata_launch_started_boottime_ns": 100,
                   "ssh_marker_observed_boottime_ns": 200},
        "other_fixed_owner_facts": d("owner"),
    }
    if grant.mode == "full":
        value["workloads"] = [
            {"ordinal": ordinal, "category": category, "duration_ns": ordinal + 1,
             "result_sha256": d(f"{category}-{ordinal}"), "deleted": True}
            for ordinal in range(1, 8) for category in ("git", "build", "install")]
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


for mode, ordinal, command in (("full", 1, adapter.FULL_COMMAND),
                               ("readiness", 2, adapter.READINESS_COMMAND)):
    current = grant(mode, ordinal); invocation = adapter.invocation(current)
    assert invocation.command == command and authority.decode(invocation.grant_bytes) == current
    apply = effect("apply", current, 1000, 1010, d(f"apply-{ordinal}"))
    running = effect("running", current, 1020, 1030, d(f"instance-{ordinal}"))
    receipt = adapter.remote_receipt(current, apply, running, owner(current))
    assert receipt.mode == mode and receipt.ami_commitment == current.ami_commitment
    assert receipt.provider_launch_started_unix_ns == 1000
    assert receipt.provider_running_observed_unix_ns == 1030
    assert receipt.ssh_ready_observed_boottime_ns - receipt.kata_launch_started_boottime_ns == 100
    assert len(receipt.workloads) == (21 if mode == "full" else 0)

try:
    current = grant("full", 1); bad = json.loads(owner(current))
    bad["cycle_grant"]["cycle_ordinal"] = 2
    apply = effect("apply", current, 1000, 1010, d("apply"))
    running = effect("running", current, 1020, 1030, d("instance"))
    adapter.remote_receipt(current, apply, running,
                           json.dumps(bad, sort_keys=True, separators=(",", ":")).encode() + b"\n")
except (adapter.RemoteAdapterError, production.ProductionCampaignError): pass
else: raise AssertionError("cycle grant replay accepted")

print("stage2 provider-free remote adapter checks passed")
