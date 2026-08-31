#!/usr/bin/env python3
"""Central ADR 0039/0099 retained-line inventory with no deletion credit."""
import json
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE_REVISION = "746568773798d72f5a79ad639d96cb227597f3b7"
GROSS_CHECKPOINT_REVISION = BASE_REVISION
CORRECTION_BASE_REVISION = "6f7d5c4dfdbf9f5ee4b4be0dc7d54839eac07f57"
INHERITED_POST_BASE_GROSS_ADDITIONS = 0
PHYSICAL_BASELINE_DEPLOYMENT_LINES = 28_599
PHYSICAL_BASELINE_RETAINED_LINES = 7_019
PHYSICAL_BASELINE_LINES = PHYSICAL_BASELINE_DEPLOYMENT_LINES + PHYSICAL_BASELINE_RETAINED_LINES
INHERITED_PREDECESSOR_MINIMUM = 33_912
PRE_BASE_GROSS_ADDITIONS = 2_949
CONSERVATIVE_BASELINE_LINES = INHERITED_PREDECESSOR_MINIMUM + PRE_BASE_GROSS_ADDITIONS
CORRECTION_BASE_CURRENT_LINES = 53_352
CORRECTION_BASE_CONSERVATIVE_LINES = 55_354
PREFERRED_LIMIT = 90_000
HARD_LIMIT = 94_000
DEPLOY_CORRECTION_HIGH = 19_500
RETAINED_CORRECTION_HIGH = 9_500
WORKFLOW_CORRECTION_HIGH = 3_000
GLOBAL_CORRECTION_HIGH = 32_000
MUTABLE_OWNER_LINE_LIMIT = 2_000
DEPLOY_ROOT = "deploy/aws-feasibility"
WORKFLOW_ROOT = ".github/workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")
DEPLOY_SUFFIXES = (".py", ".sh", ".tf")
CONTROL_DATA_ROOT = "deploy/aws-feasibility/remote/stage2-completion-local-control-v2"
CONTROL_DATA_MEMBERS = (
    *(f"{CONTROL_DATA_ROOT}/contracts/{index:02d}-{role}.json" for index, role in enumerate((
        "ip", "tc", "nft", "ssh", "ssh-keygen", "containerd", "ctr", "shim", "qemu", "virtiofsd"))),
    f"{CONTROL_DATA_ROOT}/stage2-local-execution-envelope-v2.json",
    f"{CONTROL_DATA_ROOT}/stage2-local-runtime-manifest-v2.json",
    f"{CONTROL_DATA_ROOT}/stage2-local-static-control-v1.json",
)
MUTABLE_OWNER_FILES = (
    "deploy/aws-feasibility/remote/completion_kata_operation_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_execution_bridge.py",
)
RETAINED_DEPLOY_FILES = (
    *MUTABLE_OWNER_FILES,
    "deploy/aws-feasibility/remote/completion_local_full.py",
    "deploy/aws-feasibility/remote/completion_local_receipt.py",
    "deploy/aws-feasibility/remote/completion_local_evidence.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation_bridge.py",
)
RETAINED_FILES = (
    "deploy/aws-feasibility/remote/stage2-completion-rootfs-v1.json",
    "deploy/aws-feasibility/remote/stage2-completion-rootfs-v2.json",
    "schemas/aws-stage2-completion-private-evidence-v1.json",
    "schemas/aws-stage2-completion-evidence-v1.json",
    "schemas/aws-stage2-completion-evidence-v2.json",
    "schemas/aws-stage2-completion-production-approval-v1.json",
    "schemas/stage2-cycle-launch-grant-v1.json",
    "scripts/validate-aws-stage2-completion-evidence.ts",
    "scripts/validate-aws-stage2-completion-evidence-v2.ts",
    "scripts/render-aws-stage2-completion-report.ts",
    "scripts/render-aws-stage2-completion-report-v2.ts",
    "schemas/aws-stage2-measurement-evidence-v1alpha1.json",
    "scripts/validate-aws-stage2-measurement-report.ts",
    "scripts/render-aws-stage2-measurement-report.ts",
    "schemas/aws-feasibility-report-v1alpha1.json",
    "scripts/validate-aws-feasibility-report.ts",
    "scripts/prepare-stage2-fixed-source.py",
    "scripts/run-stage2-phase-a-candidate.py",
    "scripts/run-stage2-package-native-candidate.py",
    "scripts/stage2-phase-a-budget.py",
    "scripts/stage2-native-settlement.py",
    "scripts/stage2-native-publication.py",
    "scripts/stage2-native-upload-receipt.py",
    "scripts/stage2-static-control-dispatch-guard.py",
    "scripts/stage2-local-qualification-guard.py",
    "scripts/stage2-local-settlement.py",
    "scripts/stage2-local-publication.py",
    "scripts/stage2-local-upload-receipt.py",
    "scripts/stage2-prebuilt-rootfs-producer.py",
    "scripts/stage2-prebuilt-rootfs-publisher.py",
    "scripts/stage2-stage-reviewed-control.py",
    "schemas/stage2-phase-a-candidate-v1.json",
    "schemas/stage2-phase-a-candidate-v2.json",
    "schemas/stage2-workload-candidate-v1.json",
    "schemas/stage2-workload-candidate-v2.json",
    "schemas/stage2-workload-final-pin-v1.json",
    "schemas/stage2-local-executable-closure-v1.json",
    "schemas/stage2-local-execution-envelope-v1.json",
    "schemas/stage2-local-runtime-manifest-v1.json",
    "schemas/stage2-local-static-control-package-v1.json",
    "schemas/stage2-local-execution-envelope-v2.json",
    "schemas/stage2-local-runtime-manifest-v2.json",
    "schemas/stage2-local-execution-envelope-v3.json",
    "schemas/stage2-local-runtime-manifest-v3.json",
    "schemas/stage2-local-static-control-package-v2.json",
    "schemas/stage2-prebuilt-rootfs-descriptor-v1.json",
    "deploy/aws-feasibility/remote/stage2-completion-runtime-v1.json",
    "schemas/stage2-workload-post-pin-v1.json",
    "schemas/stage2-workload-local-qualification-v2.json",
    "schemas/stage2-workload-local-qualification-v3.json",
    "schemas/stage2-workload-local-qualification-v4.json",
    "config/stage2-completion-ssh-workload-v2.json",
    "config/stage2-completion-ssh-workload-v3.json",
    "config/stage2-completion-ssh-readiness-v1.json",
    "scripts/check-stage2-retained-lines.py",
)


class LineBudgetError(Exception):
    pass


def _require(condition):
    if not condition:
        raise LineBudgetError()


def _lines(path):
    observed = path.lstat()
    _require(stat.S_ISREG(observed.st_mode))
    raw = path.read_bytes()
    return raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)


def _deploy_paths():
    root = ROOT / DEPLOY_ROOT
    return tuple(sorted(path for path in root.rglob("*") if path.suffix in DEPLOY_SUFFIXES))


def _workflow_paths():
    root = ROOT / WORKFLOW_ROOT
    return tuple(sorted(path for path in root.rglob("*")
                        if path.suffix in WORKFLOW_SUFFIXES))


def _git(args):
    result = subprocess.run(["git", *args], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    _require(result.returncode == 0)
    return result.stdout


def _counted(path):
    return ((path.startswith(DEPLOY_ROOT + "/") and path.endswith(DEPLOY_SUFFIXES))
            or path in RETAINED_FILES)


def _gross_slice(paths, allowed):
    output = _git(["diff", "--numstat", CORRECTION_BASE_REVISION, "--", *paths])
    added = 0
    for line in output.splitlines():
        columns = line.split("\t")
        _require(len(columns) == 3 and columns[0].isdigit() and columns[1].isdigit())
        _require(allowed(columns[2]))
        added += int(columns[0])
    ordinary = _git(["ls-files", "--others", "--exclude-standard", "--", *paths])
    ignored = _git(["ls-files", "--others", "--ignored", "--exclude-standard", "--", *paths])
    for name in set(ordinary.splitlines() + ignored.splitlines()):
        if allowed(name):
            added += _lines(ROOT / name)
    return added


def measure():
    retained_names = set(RETAINED_FILES)
    retained_deploy_names = set(RETAINED_DEPLOY_FILES)
    _require(len(RETAINED_FILES) == len(retained_names))
    _require(len(RETAINED_DEPLOY_FILES) == len(retained_deploy_names))
    tracked_names = set(_git(["ls-files", "--", *RETAINED_FILES]).splitlines())
    tracked_deploy_names = set(_git(["ls-files", "--", *RETAINED_DEPLOY_FILES]).splitlines())
    control_data_names = set(CONTROL_DATA_MEMBERS)
    tracked_control_data_names = set(_git(["ls-files", "--", CONTROL_DATA_ROOT]).splitlines())
    _require(tracked_names == retained_names)
    _require(tracked_deploy_names == retained_deploy_names)
    _require(len(CONTROL_DATA_MEMBERS) == len(control_data_names)
             and tracked_control_data_names == control_data_names)
    deploy_paths = _deploy_paths()
    _require(retained_deploy_names <= {str(path.relative_to(ROOT)) for path in deploy_paths})
    workflow_paths = _workflow_paths()
    workflow_names = {str(path.relative_to(ROOT)) for path in workflow_paths}
    tracked_workflow_names = set(_git(["ls-files", "--", WORKFLOW_ROOT]).splitlines())
    _require(workflow_names == tracked_workflow_names
             and all(name.endswith(WORKFLOW_SUFFIXES) for name in workflow_names))
    deploy = sum(_lines(path) for path in deploy_paths)
    workflows = sum(_lines(path) for path in workflow_paths)
    mutable_owner_lines = sum(_lines(ROOT / name) for name in MUTABLE_OWNER_FILES)
    _require(mutable_owner_lines < MUTABLE_OWNER_LINE_LIMIT)
    retained = sum(_lines(ROOT / name) for name in RETAINED_FILES)
    current = deploy + retained + workflows
    deploy_gross = _gross_slice((DEPLOY_ROOT,), lambda name: (
        (name.startswith(DEPLOY_ROOT + "/") and name.endswith(DEPLOY_SUFFIXES))
        or name in control_data_names or name in retained_names))
    retained_gross = _gross_slice(RETAINED_FILES, lambda name: name in retained_names)
    workflow_gross = _gross_slice((WORKFLOW_ROOT,), lambda name: (
        name.startswith(WORKFLOW_ROOT + "/") and name.endswith(WORKFLOW_SUFFIXES)))
    correction_gross = deploy_gross + retained_gross + workflow_gross
    conservative = CORRECTION_BASE_CONSERVATIVE_LINES + correction_gross
    slices_satisfied = (
        deploy_gross <= DEPLOY_CORRECTION_HIGH
        and retained_gross <= RETAINED_CORRECTION_HIGH
        and workflow_gross <= WORKFLOW_CORRECTION_HIGH
        and correction_gross <= GLOBAL_CORRECTION_HIGH
    )
    report = {
        "version": "cogs.stage2-retained-line-budget/v1",
        "base_revision": BASE_REVISION,
        "gross_checkpoint_revision": GROSS_CHECKPOINT_REVISION,
        "correction_base_revision": CORRECTION_BASE_REVISION,
        "correction_base_current_lines": CORRECTION_BASE_CURRENT_LINES,
        "correction_base_conservative_lines": CORRECTION_BASE_CONSERVATIVE_LINES,
        "inherited_post_base_gross_additions": INHERITED_POST_BASE_GROSS_ADDITIONS,
        "physical_baseline_lines": PHYSICAL_BASELINE_LINES,
        "physical_baseline_deployment_lines": PHYSICAL_BASELINE_DEPLOYMENT_LINES,
        "physical_baseline_retained_schema_script_lines": PHYSICAL_BASELINE_RETAINED_LINES,
        "inherited_predecessor_minimum": INHERITED_PREDECESSOR_MINIMUM,
        "pre_base_gross_additions": PRE_BASE_GROSS_ADDITIONS,
        "conservative_baseline_lines": CONSERVATIVE_BASELINE_LINES,
        "deployment_lines": deploy,
        "retained_schema_script_lines": retained,
        "workflow_files": len(workflow_paths),
        "workflow_lines": workflows,
        "current_lines": current,
        "gross_added_lines_no_deletion_credit": correction_gross,
        "correction_deploy_gross_added_lines": deploy_gross,
        "correction_retained_gross_added_lines": retained_gross,
        "correction_workflow_gross_added_lines": workflow_gross,
        "correction_global_gross_added_lines": correction_gross,
        "correction_deploy_high": DEPLOY_CORRECTION_HIGH,
        "correction_retained_high": RETAINED_CORRECTION_HIGH,
        "correction_workflow_high": WORKFLOW_CORRECTION_HIGH,
        "correction_global_high": GLOBAL_CORRECTION_HIGH,
        "correction_slice_limits_satisfied": slices_satisfied,
        "conservative_lines_no_deletion_credit": conservative,
        "preferred_limit": PREFERRED_LIMIT,
        "hard_limit": HARD_LIMIT,
        "mutable_owner_files": MUTABLE_OWNER_FILES,
        "mutable_owner_lines": mutable_owner_lines,
        "mutable_owner_line_limit": MUTABLE_OWNER_LINE_LIMIT,
        "mutable_owner_line_limit_satisfied": mutable_owner_lines < MUTABLE_OWNER_LINE_LIMIT,
        "preferred_satisfied": current < PREFERRED_LIMIT and conservative < PREFERRED_LIMIT,
        "hard_satisfied": current < HARD_LIMIT and conservative < HARD_LIMIT,
    }
    # Keep the preferred target advisory, but enforce every non-transferable
    # correction slice, the global correction high, and the mandatory hard stop.
    _require(report["correction_slice_limits_satisfied"])
    _require(report["hard_satisfied"])
    return report


def main():
    _require(len(sys.argv) == 1)
    raw = json.dumps(measure(), sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    _require(sys.stdout.buffer.write(raw) == len(raw))


if __name__ == "__main__":
    try:
        main()
    except LineBudgetError:
        raise SystemExit(2)
