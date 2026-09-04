#!/usr/bin/env python3
"""Provider-free end-to-end test of the dormant production planner."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stage2_production_planner_test", ROOT / "scripts/stage2-production-planner.py")
planner = importlib.util.module_from_spec(spec); spec.loader.exec_module(planner)


def d(value): return hashlib.sha256(value.encode()).hexdigest()


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); tofu = root / "tofu"; tofu.write_bytes(b"fixed-tofu")
    planner.TOFU_SHA256 = hashlib.sha256(tofu.read_bytes()).hexdigest()
    planner.ROOT = root
    planner.AWS = root / "aws"; planner.AWS.write_bytes(b"fixed-aws")
    h, g, q = "1" * 40, "2" * 40, "3" * 40
    descriptor = {"version": "cogs.stage2-prebuilt-rootfs-descriptor/v1",
        "producer": {"revision": h, "source_manifest_sha256": d("source"),
            "package_manifest_sha256": d("rootfs-package"), "provenance_sha256": d("provenance"),
            "qualification_receipt_sha256": d("qualification"),
            "publication_receipt_sha256": d("publication")}}
    descriptor_raw = planner.canonical(descriptor)
    bindings = {"source_head": h, "source_manifest_sha256": d("source"),
        "rootfs_descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
        "rootfs_package_manifest_sha256": d("rootfs-package"),
        "rootfs_provenance_sha256": d("provenance"),
        "rootfs_publication_receipt_sha256": d("publication"),
        "runtime_attestation_sha256": d("runtime"), "final_pin_sha256": d("fixture")}
    control = {"version": "cogs.stage2-local-static-control-package/v2",
               "producer": {"control_revision": g}}
    control_raw = planner.canonical(control)
    package = {"version": "cogs.stage2-pre-aws-qualification-package/v4",
        "authority": "non-aws-prerequisite-evidence-only", "implementation_revision": h,
        "control_revision": g, "qualification_revision": q,
        "source_manifest_sha256": bindings["source_manifest_sha256"],
        "static_control_sha256": hashlib.sha256(control_raw).hexdigest(),
        "rootfs_descriptor_sha256": bindings["rootfs_descriptor_sha256"],
        "source_bindings": bindings, "cycle_count": 7, "workload_measurements": 21,
        "cycle_artifact_custody": {"workflow_run": {"id": 71, "attempt": 1, "head_sha": q}},
        "mixed_preflight_run_id": 63,
        "static_control_observation": {"run_id": 61, "artifact_id": 62,
            "artifact_archive_digest": "sha256:" + d("static-archive")},
        "claims": {"formal_non_aws_qualification_passed": True, "aws_authorized": False,
                   "aws_executed": False, "provider_executed": False,
                   "promotion_authorized": False}}
    package_path, control_path, descriptor_path = (
        root / "pre-aws-package-v4.json", root / "control.json", root / "descriptor.json")
    package_path.write_bytes(planner.canonical(package)); control_path.write_bytes(control_raw)
    descriptor_path.write_bytes(descriptor_raw)

    def fake_run(arguments, timeout, environment, parse=False):
        assert timeout > 0 and environment["AWS_REGION"] == "us-east-1"
        if "get-caller-identity" in arguments:
            return {"Account": "000000000000",
                    "Arn": "arn:aws:sts::000000000000:assumed-role/planning/session"}
        if "describe-images" in arguments:
            return {"Images": [{"CreationDate": "2026-01-01T00:00:00Z",
                "ImageId": "ami-" + "a" * 17, "OwnerId": "099720109477",
                "Architecture": "x86_64", "VirtualizationType": "hvm",
                "RootDeviceType": "ebs", "State": "available"}]}
        if "init" in arguments:
            provider_root = root / "deploy/aws-feasibility/.terraform/providers/registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"
            provider_root.mkdir(parents=True)
            (provider_root / "tofu-provider-aws_v6.54.0_x5").write_bytes(b"provider")
            return b"initialized\n"
        output_path = next((item[5:] for item in arguments if item.startswith("-out=")), None)
        if output_path is not None:
            Path(output_path).write_bytes(("plan-" + Path(output_path).name).encode()); return b"planned\n"
        if "show" in arguments: return {"variables": {}, "resource_changes": []}
        return {} if parse else b"ok\n"

    planner.run = fake_run
    os.environ.update({"COGS_STAGE2_AWS_PLAN_AUTHORIZATION":
        "authorize-read-only-stage2-production-planning",
        "COGS_STAGE2_BUDGET_ALERT_EMAIL": "owner@example.invalid",
        "COGS_STAGE2_EXECUTOR_ROLE_NAME": "executor",
        "COGS_STAGE2_INVENTORY_OBSERVER_ROLE_NAME": "observer",
        "AWS_ACCESS_KEY_ID": "ASIA" + "A" * 16,
        "AWS_SECRET_ACCESS_KEY": "a" * 40, "AWS_SESSION_TOKEN": "b" * 80})
    output = root / "output"
    planner.main(tuple(str(path) for path in (package_path, control_path, descriptor_path, tofu, output)))
    draft = json.loads((output / "approval-draft.json").read_bytes())
    assert draft["version"] == "cogs.stage2-production-approval-draft/v2"
    assert (draft["implementation_revision"], draft["control_revision"],
            draft["qualification_revision"]) == (h, g, q)
    assert len(draft["plan_sha256s"]) == len(set(draft["plan_sha256s"])) == 7
    assert draft["executor_principal_commitment"] == planner.production.executor_principal_commitment(
        "aws", "000000000000", "executor")
    assert draft["inventory_observer_principal_commitment"] == \
        planner.production.executor_principal_commitment("aws", "000000000000", "observer")
    planned_batch = planner.production.approval_batch_commitment(draft)
    issued_shape = {**draft, "version": "cogs.stage2-completion-production-approval/v4",
        "phrase": planner.production.APPROVAL_PHRASE,
        "rate_source_commitment": planner.production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": d("issuer"), "one_attempt": True}
    assert planner.production.approval_batch_commitment(issued_shape) == planned_batch
    assert not (output / ".aws-credentials").exists()
    assert not (output / ".aws-config").exists()

print("stage2 production planner provider-free checks passed")
