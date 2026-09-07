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
HARD_LIMIT = 95_900
DEPLOY_CORRECTION_HIGH = 22_300
RETAINED_CORRECTION_HIGH = 13_100
WORKFLOW_CORRECTION_HIGH = 5_500
GLOBAL_CORRECTION_HIGH = 40_500
REMEDIATION_BASE_REVISION = "242bbefeae5444118d9e97b46597130b509ca253"
REMEDIATION_BUDGET_PATH = ROOT / "config/external-review-remediation-budget-v1.json"
FINAL_H_REVISION = "8907eba3191d07573cd84573cb0b2adddff17bd6"
FINAL_H_DEPLOY_GROSS, FINAL_H_RETAINED_GROSS, FINAL_H_WORKFLOW_GROSS = 21_948, 11_844, 4_836
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
CONTROL_DATA_ROOTS = (CONTROL_DATA_ROOT, *(f"deploy/aws-feasibility/remote/stage2-completion-local-control-v{n}" for n in (3, 4)))
CONTROL_DATA_MEMBERS += tuple(member for root in CONTROL_DATA_ROOTS[1:] for member in (
    *(f"{root}/contracts/{index:02d}-{role}.json" for index, role in enumerate((
        "ip", "tc", "nft", "ssh", "ssh-keygen", "containerd", "ctr", "shim", "qemu", "virtiofsd"))),
    *(f"{root}/stage2-local-{name}-v3.json" for name in ("execution-envelope", "runtime-manifest")),
    f"{root}/stage2-local-static-control-v2.json",
))
FINAL_CONTROL_DATA_ROOT = "deploy/aws-feasibility/remote/stage2-completion-local-control-v5"
FINAL_CONTROL_DATA_MEMBERS = (
    *(f"{FINAL_CONTROL_DATA_ROOT}/contracts/{index:02d}-{role}.json" for index, role in enumerate((
        "ip", "tc", "nft", "ssh", "ssh-keygen", "containerd", "ctr", "shim", "qemu", "virtiofsd"))),
    *(f"{FINAL_CONTROL_DATA_ROOT}/stage2-local-{name}-v3.json" for name in (
        "execution-envelope", "runtime-manifest")),
    f"{FINAL_CONTROL_DATA_ROOT}/stage2-local-static-control-v2.json",
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
    "config/stage2-retired-revisions-v1.json",
    "scripts/stage2-revision-retirement.py",
    "deploy/aws-feasibility/remote/stage2-completion-rootfs-v1.json",
    "deploy/aws-feasibility/remote/stage2-completion-rootfs-v2.json",
    "schemas/aws-stage2-completion-private-evidence-v1.json",
    "schemas/aws-stage2-completion-evidence-v1.json",
    "schemas/aws-stage2-completion-evidence-v2.json",
    "schemas/aws-stage2-completion-production-approval-v1.json",
    "schemas/aws-stage2-completion-production-approval-v2.json",
    "schemas/aws-stage2-completion-production-approval-v3.json",
    "schemas/aws-stage2-completion-production-approval-v4.json",
    "schemas/aws-stage2-production-evidence-upload-receipt-v1.json",
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
    "scripts/stage2-prebuilt-local-qualification-guard.py",
    "scripts/stage2-formal-local-qualification.py",
    "scripts/stage2-prebuilt-mixed-hg-preflight.sh",
    "scripts/stage2-prebuilt-static-control-runtime-boundary.py",
    "scripts/stage2-prebuilt-rehearsal-grant.py",
    "scripts/stage2-prebuilt-kvm-diagnostic-lock.py",
    "config/stage2-prebuilt-kvm-diagnostic-lock-v1.json",
    "config/stage2-prebuilt-kvm-diagnostic-custody-v1/cosign-verification.json",
    "config/stage2-prebuilt-kvm-diagnostic-custody-v1/descriptor.json",
    "config/stage2-prebuilt-kvm-diagnostic-custody-v1/producer-receipt.json",
    "config/stage2-prebuilt-kvm-diagnostic-custody-v1/publication-receipt.json",
    "config/stage2-prebuilt-kvm-diagnostic-custody-v1/rootfs.package.json",
    "config/stage2-prebuilt-kvm-diagnostic-custody-v1/rootfs.provenance.json",
    "scripts/stage2-pre-aws-package-v2.py",
    "scripts/stage2-production-approval.py",
    "scripts/stage2-production-planner.py",
    "scripts/stage2-stage-production-approval.py",
    "config/stage2-sigstore-trusted-root-v1.json",
    "scripts/stage2-stage-reviewed-control.py",
    "scripts/stage2-stage-prebuilt-control.py",
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
    "schemas/stage2-pre-aws-qualification-package-v1.json",
    "schemas/stage2-pre-aws-qualification-package-v2.json",
    "schemas/stage2-pre-aws-qualification-package-v3.json",
    "schemas/stage2-pre-aws-qualification-package-v4.json",
    "schemas/stage2-formal-local-artifact-custody-v1.json",
    "schemas/stage2-formal-local-artifact-custody-v2.json",
    "schemas/stage2-formal-local-cycle-grant-v1.json",
    "schemas/stage2-formal-local-cycle-status-v1.json",
    "schemas/stage2-formal-local-cycle-status-v2.json",
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
    try:
        relative = path.relative_to(ROOT)
        parent = ROOT
        for part in relative.parts[:-1]:
            parent /= part
            observed_parent = parent.lstat()
            _require(stat.S_ISDIR(observed_parent.st_mode) and not stat.S_ISLNK(observed_parent.st_mode))
        observed = path.lstat()
        _require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1)
        raw = path.read_bytes()
        _require(b"\0" not in raw)
        raw.decode("utf-8")
        return raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
    except (OSError, UnicodeError, ValueError):
        raise LineBudgetError() from None


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


def _gross_slice(paths, allowed, revision=CORRECTION_BASE_REVISION):
    output = _git(["-c", "diff.renames=false", "diff", "--no-renames", "--no-ext-diff",
                   "--no-textconv", "--numstat", revision, "--", *paths])
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


def _reject_json_constant(_value):
    raise LineBudgetError()


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        _require(isinstance(key, str) and key not in result)
        result[key] = value
    return result


def _remediation_budget():
    _require(_lines(REMEDIATION_BUDGET_PATH) <= 1_000
             and REMEDIATION_BUDGET_PATH.stat().st_size <= 64 * 1024)
    try:
        data = json.loads(REMEDIATION_BUDGET_PATH.read_text("utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, ValueError):
        raise LineBudgetError() from None
    _require(set(data) == {"version", "base_revision", "global_gross_line_high", "baseline",
                           "source_limits", "owners"})
    _require(data["version"] == "cogs.external-review-remediation-budget/v1"
             and data["base_revision"] == REMEDIATION_BASE_REVISION
             and data["global_gross_line_high"] == 16_000)
    _require(data["baseline"] == {"tracked_files": 1420, "source_inventory_entries": 1417,
                                   "source_inventory_bytes": 18_763_891})
    _require(data["source_limits"] == {"tracked_files": 1460,
                                        "source_inventory_bytes": 22_020_096,
                                        "serialized_source_inventory_bytes": 262_144})
    expected = {"route": 1_500, "revocation": 3_500, "relay": 1_400,
                "lifecycle": 4_100, "completion": 1_900, "integration": 3_600}
    owners = {}
    paths = {}
    new_file_highs = {}
    forecasts = {}
    _require(isinstance(data["owners"], list) and len(data["owners"]) == len(expected))
    for entry in data["owners"]:
        _require(isinstance(entry, dict) and set(entry) == {"name", "gross_line_high",
                                                            "gross_byte_forecast", "new_file_high", "paths"})
        name = entry["name"]
        _require(name in expected and name not in owners and entry["gross_line_high"] == expected[name])
        forecast = entry["gross_byte_forecast"]
        _require(isinstance(forecast, dict)
                 and set(forecast) == {"source", "tests_fixtures", "docs_contracts", "total"}
                 and all(isinstance(value, int) and value >= 0 for value in forecast.values())
                 and forecast["total"] == forecast["source"] + forecast["tests_fixtures"]
                 + forecast["docs_contracts"])
        _require(isinstance(entry["new_file_high"], int) and entry["new_file_high"] >= 0)
        _require(isinstance(entry["paths"], list) and entry["paths"] == sorted(entry["paths"]))
        for path in entry["paths"]:
            _require(isinstance(path, str) and path and path not in paths and "\x00" not in path)
            candidate = Path(path)
            _require(not candidate.is_absolute() and ".." not in candidate.parts)
            paths[path] = name
        owners[name] = expected[name]
        new_file_highs[name] = entry["new_file_high"]
        forecasts[name] = forecast
    _require(sum(new_file_highs.values()) == 40
             and sum(forecast["total"] for forecast in forecasts.values()) == 2_570_000)
    _require(data["baseline"]["tracked_files"] + sum(new_file_highs.values())
             <= data["source_limits"]["tracked_files"])
    _require(data["baseline"]["source_inventory_bytes"]
             + sum(forecast["total"] for forecast in forecasts.values())
             <= data["source_limits"]["source_inventory_bytes"])
    baseline_names = set(_nul_records(_git(["ls-tree", "-r", "--name-only", "-z",
                                            REMEDIATION_BASE_REVISION])))
    for owner in owners:
        planned_new = sum(1 for path, allocated in paths.items()
                          if allocated == owner and path not in baseline_names)
        _require(planned_new <= new_file_highs[owner])
    _require(paths.get(str(REMEDIATION_BUDGET_PATH.relative_to(ROOT))) == "integration")
    return data, owners, paths, new_file_highs, forecasts


def _nul_records(raw):
    records = raw.split("\0")
    _require(records[-1] == "")
    return records[:-1]


def _remediation_gross():
    budget, highs, allocations, new_file_highs, forecasts = _remediation_budget()
    gross = {owner: 0 for owner in highs}
    new_files = {owner: 0 for owner in highs}
    base_names = set(_nul_records(_git(["ls-tree", "-r", "--name-only", "-z", REMEDIATION_BASE_REVISION])))
    output = _git(["-c", "diff.renames=false", "diff", "--no-renames", "--no-ext-diff",
                   "--no-textconv", "--numstat", "-z", REMEDIATION_BASE_REVISION, "--", "."])
    changed = {}
    for record in _nul_records(output):
        columns = record.split("\t", 2)
        _require(len(columns) == 3 and columns[0].isdigit() and columns[1].isdigit())
        name = columns[2]
        _require(name in allocations and name not in changed)
        changed[name] = int(columns[0])
    ordinary = set(_nul_records(_git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."])))
    ignored = set(_nul_records(_git(["ls-files", "--others", "--ignored", "--exclude-standard",
                                     "-z", "--", *allocations])))
    _require(not ignored)
    for name in ordinary:
        _require(name in allocations and name not in changed)
        changed[name] = _lines(ROOT / name)
    for name, added in changed.items():
        owner = allocations[name]
        gross[owner] += added
        if name not in base_names:
            new_files[owner] += 1
    _require(all(gross[owner] <= highs[owner] for owner in highs))
    _require(all(new_files[owner] <= new_file_highs[owner] for owner in highs))
    return gross, new_files, budget, forecasts


def _final_control_data_state():
    final_names = set(FINAL_CONTROL_DATA_MEMBERS)
    tracked = set(_git(["ls-files", "--", FINAL_CONTROL_DATA_ROOT]).splitlines())
    ordinary = set(_git(["ls-files", "--others", "--exclude-standard", "--",
                         FINAL_CONTROL_DATA_ROOT]).splitlines())
    ignored = set(_git(["ls-files", "--others", "--ignored", "--exclude-standard", "--",
                        FINAL_CONTROL_DATA_ROOT]).splitlines())
    observed = tracked | ordinary
    _require(len(FINAL_CONTROL_DATA_MEMBERS) == len(final_names) and not ignored)
    if not observed:
        return "absent", final_names
    _require(observed == final_names)
    try:
        for name in final_names:
            path = ROOT / name
            _require(_lines(path) == 1)
            value = json.loads(path.read_text("utf-8"), object_pairs_hook=_strict_object,
                               parse_constant=_reject_json_constant)
            _require(isinstance(value, dict))
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True, allow_nan=False) + "\n"
            _require(path.read_text("utf-8") == canonical)
    except (OSError, UnicodeError, ValueError):
        raise LineBudgetError() from None
    return "member-set-complete", final_names


def measure():
    retained_names = set(RETAINED_FILES)
    retained_deploy_names = set(RETAINED_DEPLOY_FILES)
    _require(len(RETAINED_FILES) == len(retained_names))
    _require(len(RETAINED_DEPLOY_FILES) == len(retained_deploy_names))
    tracked_names = set(_git(["ls-files", "--", *RETAINED_FILES]).splitlines())
    tracked_deploy_names = set(_git(["ls-files", "--", *RETAINED_DEPLOY_FILES]).splitlines())
    control_data_names = set(CONTROL_DATA_MEMBERS)
    final_control_data_state, final_control_data_names = _final_control_data_state()
    tracked_control_data_names = set(_git(["ls-files", "--", *CONTROL_DATA_ROOTS]).splitlines())
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
    deploy_gross = FINAL_H_DEPLOY_GROSS + _gross_slice((DEPLOY_ROOT,), lambda name: (
        (name.startswith(DEPLOY_ROOT + "/") and name.endswith(DEPLOY_SUFFIXES))
        or name in control_data_names or name in final_control_data_names or name in retained_names), FINAL_H_REVISION)
    retained_gross = FINAL_H_RETAINED_GROSS + _gross_slice(
        RETAINED_FILES, lambda name: name in retained_names, FINAL_H_REVISION)
    workflow_gross = FINAL_H_WORKFLOW_GROSS + _gross_slice((WORKFLOW_ROOT,), lambda name: (
        name.startswith(WORKFLOW_ROOT + "/") and name.endswith(WORKFLOW_SUFFIXES)), FINAL_H_REVISION)
    correction_gross = deploy_gross + retained_gross + workflow_gross
    conservative = CORRECTION_BASE_CONSERVATIVE_LINES + correction_gross
    remediation, remediation_new_files, remediation_budget, remediation_byte_forecasts = _remediation_gross()
    remediation_gross = sum(remediation.values())
    remediation_highs = {entry["name"]: entry["gross_line_high"] for entry in remediation_budget["owners"]}
    remediation_new_file_highs = {entry["name"]: entry["new_file_high"] for entry in remediation_budget["owners"]}
    remediation_slices_satisfied = (
        remediation_gross <= remediation_budget["global_gross_line_high"]
        and all(remediation[owner] <= remediation_highs[owner] for owner in remediation_highs)
        and all(remediation_new_files[owner] <= remediation_new_file_highs[owner]
                for owner in remediation_new_file_highs)
    )
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
        "remediation_base_revision": REMEDIATION_BASE_REVISION,
        "remediation_workstream_gross_added_lines": remediation,
        "remediation_workstream_highs": remediation_highs,
        "remediation_workstream_new_files": remediation_new_files,
        "remediation_workstream_new_file_highs": remediation_new_file_highs,
        "remediation_workstream_gross_byte_forecasts": remediation_byte_forecasts,
        "remediation_gross_added_lines_no_deletion_credit": remediation_gross,
        "remediation_global_high": remediation_budget["global_gross_line_high"],
        "remediation_limits_satisfied": remediation_slices_satisfied,
        "final_control_data_state": final_control_data_state,
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
    _require(report["remediation_limits_satisfied"])
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
