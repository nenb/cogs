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
INHERITED_POST_BASE_GROSS_ADDITIONS = 0
PHYSICAL_BASELINE_DEPLOYMENT_LINES = 28_599
PHYSICAL_BASELINE_RETAINED_LINES = 7_019
PHYSICAL_BASELINE_LINES = PHYSICAL_BASELINE_DEPLOYMENT_LINES + PHYSICAL_BASELINE_RETAINED_LINES
INHERITED_PREDECESSOR_MINIMUM = 33_912
PRE_BASE_GROSS_ADDITIONS = 2_949
CONSERVATIVE_BASELINE_LINES = INHERITED_PREDECESSOR_MINIMUM + PRE_BASE_GROSS_ADDITIONS
PREFERRED_LIMIT = 60_000
HARD_LIMIT = 62_000
DEPLOY_ROOT = "deploy/aws-feasibility"
DEPLOY_SUFFIXES = (".py", ".sh", ".tf")
RETAINED_FILES = (
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
    "schemas/stage2-phase-a-candidate-v1.json",
    "schemas/stage2-phase-a-candidate-v2.json",
    "schemas/stage2-workload-candidate-v1.json",
    "schemas/stage2-workload-candidate-v2.json",
    "schemas/stage2-workload-final-pin-v1.json",
    "schemas/stage2-local-executable-closure-v1.json",
    "schemas/stage2-local-execution-envelope-v1.json",
    "schemas/stage2-local-runtime-manifest-v1.json",
    "deploy/aws-feasibility/remote/stage2-completion-runtime-v1.json",
    "schemas/stage2-workload-post-pin-v1.json",
    "schemas/stage2-workload-local-qualification-v2.json",
    "config/stage2-completion-ssh-workload-v2.json",
    "config/stage2-completion-ssh-workload-v3.json",
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


def _git(args):
    result = subprocess.run(["git", *args], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    _require(result.returncode == 0)
    return result.stdout


def _counted(path):
    return ((path.startswith(DEPLOY_ROOT + "/") and path.endswith(DEPLOY_SUFFIXES))
            or path in RETAINED_FILES)


def _gross_additions():
    output = _git(["diff", "--numstat", GROSS_CHECKPOINT_REVISION, "--",
                   DEPLOY_ROOT, *RETAINED_FILES])
    added = 0
    for line in output.splitlines():
        columns = line.split("\t")
        _require(len(columns) == 3 and columns[0].isdigit() and columns[1].isdigit())
        _require(_counted(columns[2]))
        added += int(columns[0])
    ordinary = _git(["ls-files", "--others", "--exclude-standard", "--", DEPLOY_ROOT, *RETAINED_FILES])
    ignored = _git(["ls-files", "--others", "--ignored", "--exclude-standard", "--",
                    DEPLOY_ROOT, *RETAINED_FILES])
    for name in set(ordinary.splitlines() + ignored.splitlines()):
        if _counted(name):
            added += _lines(ROOT / name)
    return added


def measure():
    retained_names = set(RETAINED_FILES)
    _require(len(RETAINED_FILES) == len(retained_names))
    tracked_names = set(_git(["ls-files", "--", *RETAINED_FILES]).splitlines())
    _require(tracked_names == retained_names)
    deploy = sum(_lines(path) for path in _deploy_paths())
    retained = sum(_lines(ROOT / name) for name in RETAINED_FILES)
    current = deploy + retained
    gross_added = INHERITED_POST_BASE_GROSS_ADDITIONS + _gross_additions()
    conservative = CONSERVATIVE_BASELINE_LINES + gross_added
    report = {
        "version": "cogs.stage2-retained-line-budget/v1",
        "base_revision": BASE_REVISION,
        "gross_checkpoint_revision": GROSS_CHECKPOINT_REVISION,
        "inherited_post_base_gross_additions": INHERITED_POST_BASE_GROSS_ADDITIONS,
        "physical_baseline_lines": PHYSICAL_BASELINE_LINES,
        "physical_baseline_deployment_lines": PHYSICAL_BASELINE_DEPLOYMENT_LINES,
        "physical_baseline_retained_schema_script_lines": PHYSICAL_BASELINE_RETAINED_LINES,
        "inherited_predecessor_minimum": INHERITED_PREDECESSOR_MINIMUM,
        "pre_base_gross_additions": PRE_BASE_GROSS_ADDITIONS,
        "conservative_baseline_lines": CONSERVATIVE_BASELINE_LINES,
        "deployment_lines": deploy,
        "retained_schema_script_lines": retained,
        "current_lines": current,
        "gross_added_lines_no_deletion_credit": gross_added,
        "conservative_lines_no_deletion_credit": conservative,
        "preferred_limit": PREFERRED_LIMIT,
        "hard_limit": HARD_LIMIT,
        "preferred_satisfied": current < PREFERRED_LIMIT and conservative < PREFERRED_LIMIT,
        "hard_satisfied": current < HARD_LIMIT and conservative < HARD_LIMIT,
    }
    # Keep the preferred target advisory, but retain the mandatory hard stop.
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
