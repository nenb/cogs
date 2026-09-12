#!/usr/bin/env python3
"""Provider-free end-to-end test of the dormant production planner."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys


def forbidden_audit(event, _args):
    if event.startswith(("subprocess.", "socket.")) or event in {
            "os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty"}:
        raise AssertionError("process/network seam forbidden")


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "stage2_production_planner_test", ROOT / "scripts/stage2-production-planner.py")
planner = importlib.util.module_from_spec(spec); spec.loader.exec_module(planner)

# Exercise post-spawn cancellation and selector-construction cuts only with a
# local sleeping Python child, before the rest of this test forbids subprocesses.
child = (sys.executable, "-I", "-c", "import time;time.sleep(10)")
environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
original_popen = planner.subprocess.Popen
spawned = []

def pending_spawn(*args, **kwargs):
    process = original_popen(*args, **kwargs); spawned.append(process)
    os.kill(os.getpid(), planner.signal.SIGTERM)
    return process

def settled(process):
    assert process.poll() is not None
    try: os.killpg(process.pid, 0)
    except ProcessLookupError: return
    raise AssertionError("child process group survived settlement")

planner.subprocess.Popen = pending_spawn
try:
    try: planner._bounded_process(child, 5, environment)
    except planner.PlanningError: pass
    else: raise AssertionError("pending cancellation crossed spawn adoption")
finally: planner.subprocess.Popen = original_popen
settled(spawned.pop())
original_selector = planner.selectors.DefaultSelector
planner.subprocess.Popen = lambda *args, **kwargs: spawned.append(
    original_popen(*args, **kwargs)) or spawned[-1]
planner.selectors.DefaultSelector = lambda: (_ for _ in ()).throw(OSError("selector cut"))
try:
    try: planner._bounded_process(child, 5, environment)
    except OSError: pass
    else: raise AssertionError("selector failure abandoned child")
finally:
    planner.selectors.DefaultSelector = original_selector
    planner.subprocess.Popen = original_popen
settled(spawned.pop())

sys.addaudithook(forbidden_audit)


def d(value): return hashlib.sha256(value.encode()).hexdigest()


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); tofu = root / "tofu"; tofu.write_bytes(b"fixed-tofu")
    planner.TOFU_SHA256 = hashlib.sha256(tofu.read_bytes()).hexdigest()
    planner.ROOT = root
    planner.AWS = root / "aws"; planner.AWS.write_bytes(b"fixed-aws")
    h, g, q = "1" * 40, "2" * 40, "3" * 40
    try:
        planner.eligible(("0296252721fad0502dd4f41dacb1674e71b42bd6", g, q))
    except planner.PlanningError:
        pass
    else:
        raise AssertionError("retired H reached planner effects")
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
        "runtime_manifest_sha256": d("runtime-manifest"), "final_pin_sha256": d("fixture"),
        "host_attestation_sha256": d("host"), "rootfs_sha256": d("rootfs"),
        "artifact_sha256": d("artifact"), "candidate_sha256": d("candidate"),
        "guest_program_sha256": planner.production.FULL_PROGRAM_SHA256,
        "owner_implementation_sha256": d("owner")}
    control = {"version": "cogs.stage2-local-static-control-package/v2",
               "producer": {"control_revision": g},
               "members": [{"kind": "runtime-manifest",
                   "name": "stage2-local-runtime-manifest-v3.json",
                   "sha256": bindings["runtime_manifest_sha256"]}]}
    control_raw = planner.canonical(control)
    fixture_spec = importlib.util.spec_from_file_location(
        "stage2_approval_fixture", ROOT / "test/stage2-production-approval.py")
    fixture = importlib.util.module_from_spec(fixture_spec); fixture_spec.loader.exec_module(fixture)
    package = fixture.qualification_package(bindings, hashlib.sha256(control_raw).hexdigest())
    package_path, control_path, descriptor_path = (
        root / "pre-aws-package-v5.json", root / "control.json", root / "descriptor.json")
    package_path.write_bytes(planner.canonical(package)); control_path.write_bytes(control_raw)
    descriptor_path.write_bytes(descriptor_raw)
    planner.eligibility(package_path, (h, g, q))
    try:
        planner.eligibility(package_path, ("4" * 40, g, q))
    except planner.PlanningError:
        pass
    else:
        raise AssertionError("dispatch/package mismatch reached planner effects")
    for field in ("implementation_revision", "control_revision", "qualification_revision"):
        retired = {**package, field: "0296252721fad0502dd4f41dacb1674e71b42bd6"}
        retired_path = root / f"retired-{field}.json"
        retired_path.write_bytes(planner.canonical(retired))
        try:
            planner.eligibility(retired_path)
        except planner.PlanningError:
            pass
        else:
            raise AssertionError(field + " retired selection reached planner effects")
    nested_retired = (
        ("mixed_preflight_run_id", "33995592875"),
        ("static_run", "33987659305"),
        ("static_artifact", "9975667979"),
        ("qualification_run", "33995910136"),
        ("qualification_head", "06188f67a9a699924d645ce8aa0e91950b6341c7"),
        ("cycle_artifact", "9975524471"),
    )
    nested_retired_paths = []
    for kind, value in nested_retired:
        candidate = json.loads(planner.canonical(package))
        if kind == "mixed_preflight_run_id": candidate[kind] = int(value)
        elif kind == "static_run": candidate["static_control_observation"]["run_id"] = int(value)
        elif kind == "static_artifact": candidate["static_control_observation"]["artifact_id"] = int(value)
        elif kind == "qualification_run": candidate["cycle_artifact_custody"]["workflow_run"]["id"] = int(value)
        elif kind == "qualification_head": candidate["cycle_artifact_custody"]["workflow_run"]["head_sha"] = value
        else: candidate["cycle_artifact_custody"]["artifacts"][0]["artifact_id"] = int(value)
        retired_path = root / f"retired-{kind}.json"
        retired_path.write_bytes(planner.canonical(candidate)); nested_retired_paths.append(retired_path)
        try:
            planner.eligibility(retired_path)
        except planner.PlanningError:
            pass
        else:
            raise AssertionError(kind + " retired selection reached planner effects")
    for label, head in (("missing", None), ("malformed", 7), ("mismatch", "4" * 40)):
        candidate = json.loads(planner.canonical(package))
        candidate["cycle_artifact_custody"]["workflow_run"]["head_sha"] = head
        path = root / f"invalid-qualification-head-{label}.json"
        path.write_bytes(planner.canonical(candidate))
        try:
            planner.eligibility(path)
        except planner.PlanningError:
            pass
        else:
            raise AssertionError(label + " nested qualification head reached credential boundary")

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
            data = Path(environment["TF_DATA_DIR"])
            assert data.is_dir() and data.parent == root / "output" / "plans"
            provider_root = data / "providers/registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"
            provider_root.mkdir(parents=True, exist_ok=True)
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
    effect_calls = []
    def forbidden_effect(*_arguments, **_keywords):
        effect_calls.append(True); raise AssertionError("retired package reached provider seam")
    planner.run = forbidden_effect
    # Reject old, missing, mixed, and coherently substituted live bindings before
    # even the first fake command seam (not merely after acquiring credentials).
    for kind in ("old-version", "old-field", "mixed-fields", "missing-manifest", "top-drift",
                 "control-drift", "unqualified"):
        hostile = json.loads(planner.canonical(package))
        if kind == "old-version": hostile["version"] = "cogs.stage2-pre-aws-qualification-package/v4"
        elif kind == "old-field":
            hostile["source_bindings"]["runtime_attestation_sha256"] = \
                hostile["source_bindings"].pop("runtime_manifest_sha256")
        elif kind == "mixed-fields": hostile["source_bindings"]["runtime_attestation_sha256"] = d("live")
        elif kind == "missing-manifest": hostile.pop("runtime_manifest_sha256")
        elif kind == "top-drift": hostile["runtime_manifest_sha256"] = d("live")
        elif kind == "control-drift":
            hostile["source_bindings"]["runtime_manifest_sha256"] = d("live")
            hostile["runtime_manifest_sha256"] = d("live")
        else: hostile["claims"]["formal_non_aws_qualification_passed"] = False
        path = root / f"hostile-{kind}.json"; path.write_bytes(planner.canonical(hostile))
        nested_retired_paths.append(path)
    for index, (_label, hostile) in enumerate(fixture.hostile_packages(package)):
        path = root / f"hostile-complete-contract-{index}.json"
        path.write_bytes(planner.canonical(hostile)); nested_retired_paths.append(path)
    for index, retired_path in enumerate(nested_retired_paths):
        try:
            planner.main(tuple(str(path) for path in
                (retired_path, control_path, descriptor_path, tofu, root / f"retired-output-{index}")))
        except planner.PlanningError:
            pass
        else:
            raise AssertionError("retired nested identity reached planner effects")
    assert not effect_calls
    planner.run = fake_run
    output = root / "output"
    planner.main(tuple(str(path) for path in (package_path, control_path, descriptor_path, tofu, output)))
    draft = json.loads((output / "approval-draft.json").read_bytes())
    assert draft["version"] == "cogs.stage2-production-approval-draft/v3"
    assert (draft["implementation_revision"], draft["control_revision"],
            draft["qualification_revision"]) == (h, g, q)
    assert draft["runtime_manifest_sha256"] == bindings["runtime_manifest_sha256"]
    assert "runtime_commitment" not in draft
    assert (output / planner.production.QUALIFICATION_PACKAGE_NAME).read_bytes() == package_path.read_bytes()
    assert (output / planner.production.QUALIFICATION_PACKAGE_NAME).stat().st_mode & 0o777 == 0o600
    assert len(draft["plan_sha256s"]) == len(set(draft["plan_sha256s"])) == 7
    for ordinal in range(1, 8):
        staged = json.loads((output / "plans" / f"{ordinal:02d}.staged-plan.json").read_bytes())
        assert staged["ordinal"] == ordinal and staged["tf_data_dir"] == f"{ordinal:02d}.tf-data"
        assert staged["state_path"] == f"{ordinal:02d}.terraform.tfstate"
        assert staged["plan_path"] == f"{ordinal:02d}.tfplan"
        assert staged["plan_sha256"] == hashlib.sha256(
            (output / "plans" / f"{ordinal:02d}.tfplan").read_bytes()).hexdigest()
    try: planner.cycle_paths(output / "plans", 1)
    except planner.PlanningError: pass
    else: raise AssertionError("stale cycle paths were adopted")
    assert draft["executor_principal_commitment"] == planner.production.executor_principal_commitment(
        "aws", "000000000000", "executor")
    assert draft["inventory_observer_principal_commitment"] == \
        planner.production.executor_principal_commitment("aws", "000000000000", "observer")
    planned_batch = planner.production.approval_batch_commitment(draft)
    issued_shape = {**draft, "version": "cogs.stage2-completion-production-approval/v5",
        "phrase": planner.production.APPROVAL_PHRASE,
        "rate_source_commitment": planner.production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": d("issuer"), "one_attempt": True}
    assert planner.production.approval_batch_commitment(issued_shape) == planned_batch
    assert not (output / ".aws-credentials").exists()
    assert not (output / ".aws-config").exists()

print("stage2 production planner provider-free checks passed")
