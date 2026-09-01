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
package_spec = importlib.util.spec_from_file_location(
    "stage2_pre_aws_package_test", ROOT / "scripts/stage2-pre-aws-package-v2.py")
packager = importlib.util.module_from_spec(package_spec); package_spec.loader.exec_module(packager)


def d(value): return hashlib.sha256(value.encode()).hexdigest()
def write(path, value): path.write_bytes(planner.canonical(value))


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); tofu = root / "tofu"; tofu.write_bytes(b"fixed-tofu")
    planner.TOFU_SHA256 = hashlib.sha256(tofu.read_bytes()).hexdigest()
    planner.ROOT = root
    planner.AWS = root / "aws"; planner.AWS.write_bytes(b"fixed-aws")
    descriptor = {"version": "cogs.stage2-prebuilt-rootfs-descriptor/v1",
        "producer": {"revision": "1" * 40, "source_manifest_sha256": d("source"),
            "package_manifest_sha256": d("package"), "provenance_sha256": d("provenance"),
            "qualification_receipt_sha256": d("qualification"),
            "publication_receipt_sha256": d("publication")}}
    descriptor_raw = planner.canonical(descriptor)
    bindings = {"source_head": "1" * 40, "source_manifest_sha256": d("source"),
        "rootfs_descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
        "rootfs_package_manifest_sha256": d("package"),
        "rootfs_provenance_sha256": d("provenance"),
        "rootfs_publication_receipt_sha256": d("publication"),
        "runtime_attestation_sha256": d("runtime"), "final_pin_sha256": d("fixture")}
    report = {"version": "cogs.stage2-workload-local-qualification/v4", "result": "pass",
        "qualified": True, "rootfs_input": {"build_attempts": 0, "import_attempts": 1},
        "bindings": bindings}
    report_raw = planner.canonical(report)
    control = {"version": "cogs.stage2-local-static-control-package/v2"}
    control_raw = planner.canonical(control)
    receipt = {"report": {"sha256": hashlib.sha256(report_raw).hexdigest()},
        "control": {"head": "2" * 40, "sha256": hashlib.sha256(control_raw).hexdigest()}}
    receipt_raw = planner.canonical(receipt)
    envelope = {"version": "cogs.stage2-local-execution-envelope/v3",
        "control_revision": "2" * 40, "rootfs": {"prebuilt_descriptor": descriptor}}
    source_rows = (("report.json", report_raw), ("receipt.json", receipt_raw),
                   ("control.json", control_raw), ("descriptor.json", descriptor_raw),
                   ("envelope.json", planner.canonical(envelope)))
    source_paths = {}
    for name, raw in source_rows:
        path = root / name; path.write_bytes(raw); source_paths[name] = path
    os.environ.update({"REPORT_ARTIFACT_ID": "11", "REPORT_ARTIFACT_DIGEST": d("ra"),
                       "RECEIPT_ARTIFACT_ID": "12", "RECEIPT_ARTIFACT_DIGEST": d("rb")})
    package_raw = packager.build(source_paths["report.json"], source_paths["receipt.json"],
                                 source_paths["control.json"], source_paths["envelope.json"])
    package_path = root / "pre-aws-package.json"; package_path.write_bytes(package_raw)
    paths = [source_paths[name] for name in ("report.json", "receipt.json", "control.json",
                                             "descriptor.json")] + [package_path]

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
        output = next((item[5:] for item in arguments if item.startswith("-out=")), None)
        if output is not None:
            Path(output).write_bytes(("plan-" + Path(output).name).encode()); return b"planned\n"
        if "show" in arguments:
            return {"variables": {}, "resource_changes": []}
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
    planner.main(tuple(str(path) for path in (*paths, tofu, output)))
    draft = json.loads((output / "approval-draft.json").read_bytes())
    assert draft["version"] == "cogs.stage2-production-approval-draft/v1"
    assert len(draft["plan_sha256s"]) == len(set(draft["plan_sha256s"])) == 7
    assert draft["executor_principal_commitment"] == planner.production.executor_principal_commitment(
        "aws", "000000000000", "executor")
    assert draft["inventory_observer_principal_commitment"] == \
        planner.production.executor_principal_commitment("aws", "000000000000", "observer")
    planned_batch = planner.production.approval_batch_commitment(draft)
    issued_shape = {**draft, "version": "cogs.stage2-completion-production-approval/v3",
        "phrase": planner.production.APPROVAL_PHRASE,
        "rate_source_commitment": planner.production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": d("issuer"), "one_attempt": True}
    assert planner.production.approval_batch_commitment(issued_shape) == planned_batch
    assert not (output / ".aws-credentials").exists()
    assert not (output / ".aws-config").exists()

print("stage2 production planner provider-free checks passed")
