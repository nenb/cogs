#!/usr/bin/env python3
"""Provider-free canonical production approval issuer checks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production

stager_spec = importlib.util.spec_from_file_location(
    "stage2_stage_production_approval_test", ROOT / "scripts/stage2-stage-production-approval.py")
stager = importlib.util.module_from_spec(stager_spec); stager_spec.loader.exec_module(stager)


def d(value): return hashlib.sha256(value.encode()).hexdigest()


value = {
    "version": "cogs.stage2-production-approval-draft/v2",
    "implementation_revision": "1" * 40, "control_revision": "2" * 40,
    "qualification_revision": "3" * 40,
    "source_manifest_sha256": d("source"),
    "source_bindings_sha256": d("source-bindings"),
    "static_control_sha256": d("control"),
    "pre_aws_package_sha256": d("preaws"), "rootfs_descriptor_sha256": d("rootfs"),
    "rootfs_package_manifest_sha256": d("package"),
    "rootfs_provenance_sha256": d("provenance"),
    "rootfs_qualification_receipt_sha256": d("qualification"),
    "rootfs_publication_receipt_sha256": d("publication"),
    "runtime_commitment": d("runtime"), "fixture_commitment": d("fixture"),
    "provider_binary_sha256": d("provider"), "aws_cli_sha256": d("aws"),
    "account_commitment": d("account"), "partition": "aws", "region": "us-east-1",
    "ami_id": "ami-" + "a" * 17, "ami_owner_id": "099720109477",
    "ami_architecture": "x86_64", "ami_virtualization_type": "hvm",
    "ami_root_device_type": "ebs", "ami_state": "available",
    "plan_sha256s": [d(f"plan-{index}") for index in range(7)],
    "not_before_unix_ns": 1, "effect_deadline_ns": 90 * 60 * 10**9,
    "cleanup_reserve_ns": 10 * 60 * 10**9,
    "expires_unix_ns": 101 * 60 * 10**9,
    "maximum_cycle_duration_ns": 10 * 60 * 10**9,
    "maximum_cost_micro_usd": 499_999,
    "executor_principal_commitment": d("executor"),
    "inventory_observer_principal_commitment": d("observer"),
}
value["ami_commitment"] = production.resolved_ami_commitment(value)
with tempfile.TemporaryDirectory() as temporary:
    draft = Path(temporary) / "draft.json"
    draft.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "GITHUB_SHA": "4" * 40, "COGS_STAGE2_CONTROL_REVISION": "2" * 40,
                   "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTOR": "nenb"}
    result = subprocess.run(["python3", "-I", "-B", "scripts/stage2-production-approval.py",
                             "issue", str(draft)], cwd=ROOT, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert result.returncode == 0, result.stderr
    issued = json.loads(result.stdout); issued["plan_sha256s"] = tuple(issued["plan_sha256s"])
    approval = production.ProductionApproval(**issued)
    assert approval.control_revision == "2" * 40
    assert approval.rate_source_commitment == production.RATE_SOURCE_COMMITMENT

    for field in ("implementation_revision", "control_revision", "qualification_revision"):
        retired = dict(value)
        retired[field] = "0296252721fad0502dd4f41dacb1674e71b42bd6"
        draft.write_text(json.dumps(retired, sort_keys=True, separators=(",", ":")) + "\n")
        for operation in ("eligibility", "issue", "authenticate"):
            rejected = subprocess.run(["python3", "-I", "-B", "scripts/stage2-production-approval.py",
                                       operation, str(draft)], cwd=ROOT, env=environment,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            assert rejected.returncode == 2 and not rejected.stdout and not rejected.stderr

    source = Path(temporary) / "staging"; source.mkdir()
    original_uid, original_gid = stager.os.geteuid, stager.os.getegid
    stager.os.geteuid = lambda: 0; stager.os.getegid = lambda: 0
    try:
        for field in ("implementation_revision", "control_revision", "qualification_revision"):
            retired_approval = dict(json.loads(result.stdout))
            retired_approval[field] = "0296252721fad0502dd4f41dacb1674e71b42bd6"
            (source / "approval.json").write_text(
                json.dumps(retired_approval, sort_keys=True, separators=(",", ":")) + "\n")
            try:
                stager.stage(source, Path(temporary) / "unread-budget",
                             Path(temporary) / "unread-config", Path(temporary) / "unread-credentials")
            except stager.StagingError:
                pass
            else:
                raise AssertionError(field + " retired approval reached credential reads")
    finally:
        stager.os.geteuid, stager.os.getegid = original_uid, original_gid

print("stage2 production approval issuer checks passed")
