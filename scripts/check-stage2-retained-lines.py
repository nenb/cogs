#!/usr/bin/env python3
"""Central ADR 0039/0099 retained-line inventory with no deletion credit."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

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
HARD_LIMIT = 115_000
DEPLOY_CORRECTION_HIGH = 24_500
RETAINED_CORRECTION_HIGH = 31_000
WORKFLOW_CORRECTION_HIGH = 6_500
GLOBAL_CORRECTION_HIGH = 60_000
REMEDIATION_BASE_REVISION = "242bbefeae5444118d9e97b46597130b509ca253"
REMEDIATION_BUDGET_PATH = ROOT / "config/external-review-remediation-budget-v1.json"
FINAL_H_REVISION = "8907eba3191d07573cd84573cb0b2adddff17bd6"
FINAL_H_DEPLOY_GROSS, FINAL_H_RETAINED_GROSS, FINAL_H_WORKFLOW_GROSS = 21_948, 11_844, 4_836
# ADR0309 reserves are an independent gross diff, not subtraction of two gross
# endpoints (which would credit deletion of additions between the anchors).
POST_H_REVISION = "6bd12dcd25d877ffac03752fa0f71beeeb86a99e"
POST_H_HIGHS = {"deploy": 1_500, "retained": 19_000, "workflow": 1_200, "global": 21_000}
PRODUCT_TEST_Q = "8ca95b1e97447466587bbfae63318d9fce620e68"
PRODUCT_TEST_Q_TREE = "dff53b023e8e4ee4bac4897f200124b3daed9de7"
PRODUCT_TEST_RETAINED_LINES, PRODUCT_TEST_RETAINED_BYTES = 15_537, 5_120_000
PRODUCT_TEST_REMAINING_LINES, PRODUCT_TEST_REMAINING_BYTES = 2_000, 2_000_000
PRODUCT_TEST_FORECASTS = dict(route=0, revocation=0, relay=2_675, lifecycle=4_550, completion=2_580, integration=7_732)
PRODUCT_TEST_REMAINING_FORECASTS = dict(route=0, revocation=0, relay=300, lifecycle=100, completion=0, integration=1_600)
PRODUCT_TEST_BYTE_FORECASTS = {"route": 0, "revocation": 0, "relay": 700_000,
                               "lifecycle": 550_000, "completion": 300_000, "integration": 5_570_000}
REMEDIATION_BYTE_HIGHS = {"route": 350_000, "revocation": 220_000, "relay": 1_000_000,
                         "lifecycle": 1_200_000, "completion": 800_000, "integration": 5_630_000}
PRODUCT_TEST_GLOBAL_BYTE_FORECAST, REMEDIATION_GLOBAL_BYTE_HIGH = 8_000_000, 11_000_000
PRODUCT_TEST_PATH_OWNER_SHA256 = "f110c552c20a3c380b52acb2fb9284ee12461bc2fe2c22fb977fd8f85b32399c"
PRODUCT_TEST_TASK_PATH_SHA256 = "18553a685d9b37c770dc6fd9b49207acd8f89db0a35346fc9a7d566a61500013"
PRODUCT_TEST_NEW_FILES = {
    "docs/adr/0336-converge-remaining-product-governance.md": "integration",
}
PRODUCT_TEST_EXCLUDED_PATHS = {"scripts/check-image-pins.ts"}
PRODUCT_TEST_WORKFLOW_PATH = ".github/workflows/insecure-container.yml"
PRODUCT_TEST_WORKFLOW_LINE_HIGH = 300
SERIALIZED_SOURCE_INVENTORY_LIMIT = 262_144
SOURCE_INVENTORY_PRODUCER = ROOT / "scripts/stage4-offline-source-inventory.ts"
PRODUCT_TEST_HELPER_INTEGRATION_PATHS = frozenset((
    "dev/product-test/host-custody.py", "dev/product-test/snapshot-owner.ts",
    "test/ci-infrastructure-boundary.test.ts"))
PRODUCT_TEST_DOCKER_PATHS = frozenset((
    PRODUCT_TEST_WORKFLOW_PATH, "dev/product-test/runner.ts", "scripts/run-launcher-smoke-evidence.ts",
    "test/launcher-smoke-evidence.test.ts"))
PRODUCT_TEST_GOVERNANCE_PATHS = frozenset((
    "config/external-review-remediation-budget-v1.json",
    "docs/adr/0336-converge-remaining-product-governance.md",
    "docs/adr/README.md",
    "scripts/check-stage2-retained-lines.py",
    "test/aws-stage2-completion-local-result.test.ts",
    "test/stage2-remediation-budget.test.ts"))
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
CONTROL_DATA_ROOTS = (CONTROL_DATA_ROOT, *(f"deploy/aws-feasibility/remote/stage2-completion-local-control-v{n}" for n in (3, 4, 5, 6)))
CONTROL_DATA_MEMBERS += tuple(member for root in CONTROL_DATA_ROOTS[1:] for member in (
    *(f"{root}/contracts/{index:02d}-{role}.json" for index, role in enumerate((
        "ip", "tc", "nft", "ssh", "ssh-keygen", "containerd", "ctr", "shim", "qemu", "virtiofsd"))),
    *(f"{root}/stage2-local-{name}-v3.json" for name in ("execution-envelope", "runtime-manifest")),
    f"{root}/stage2-local-static-control-v2.json",
))
FINAL_CONTROL_DATA_ROOT = "deploy/aws-feasibility/remote/stage2-completion-local-control-v7"
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
# Exact ADR0327 additions may be ordinary untracked files during review, but
# remain mandatory, charged bytes. Historical retained files must stay tracked.
ADR0327_RETAINED_FILES = (
    "schemas/aws-stage2-completion-evidence-v3.json",
    "schemas/aws-stage2-completion-production-approval-v5.json",
    "schemas/aws-stage2-production-evidence-upload-receipt-v2.json",
    "schemas/stage2-formal-local-cycle-receipt-v2.json",
    "schemas/stage2-pre-aws-qualification-package-v5.json",
    "scripts/render-aws-stage2-completion-report-v3.ts",
    "scripts/validate-aws-stage2-completion-evidence-v3.ts",
)
ADR0330_RETAINED_FILES = ("scripts/stage2-hosted-opt-mode.py",)
RETAINED_FILES = (
    *ADR0327_RETAINED_FILES,
    *ADR0330_RETAINED_FILES,
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


def _git_raw(args):
    # After read-only repository discovery, isolate all accounting from config,
    # info/global/system attributes and injected GIT_* settings. Only the real
    # object store/index are inputs; neither is modified.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_ATTR_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    def run(command, *, input=None):
        result = subprocess.run(["git", "-c", "core.attributesFile=" + os.devnull, *command],
                                cwd=ROOT, env=env, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        _require(result.returncode == 0)
        return result.stdout
    locations = run(["rev-parse", "--path-format=absolute", "--git-path", "objects",
                     "--git-path", "index"]).decode("utf-8").splitlines()
    head_result = subprocess.run(["git", "-c", "core.attributesFile=" + os.devnull,
                                  "rev-parse", "--verify", "HEAD"], cwd=ROOT, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    head = head_result.stdout.decode("ascii").strip() if head_result.returncode == 0 else None
    _require(len(locations) == 2 and (head is None or re.fullmatch(r"[0-9a-f]{40}", head) is not None))
    with tempfile.TemporaryDirectory(prefix="cogs-line-budget-") as directory:
        isolated = Path(directory)
        (isolated / "objects").mkdir()
        (isolated / "refs").mkdir()
        (isolated / "HEAD").write_text("ref: refs/heads/accounting\n")
        if head is not None:
            (isolated / "refs" / "heads").mkdir(parents=True)
            (isolated / "refs" / "heads" / "accounting").write_text(head + "\n")
        env.update(GIT_DIR=directory, GIT_WORK_TREE=str(ROOT),
                   GIT_OBJECT_DIRECTORY=locations[0], GIT_INDEX_FILE=locations[1])
        if "diff" in args:
            # Discard stat caches and assume-unchanged/skip-worktree flags: even
            # an already staged clean-filter result must be compared to raw disk.
            index = run(["ls-files", "--stage", "-z"])
            env["GIT_INDEX_FILE"] = str(isolated / "index")
            run(["update-index", "-z", "--index-info"], input=index)
            # Reject every explicit transforming attribute before Git can apply
            # it, including macros and index fallback for deleted attributes.
            paths = args[args.index("--") + 1:]
            names = run(["ls-files", "-z", "--", *paths])
            attributes = run(["check-attr", "-z", "--stdin", "filter", "diff", "text",
                              "eol", "crlf", "ident", "working-tree-encoding"], input=names)
            records = _nul_records(attributes.decode("utf-8"))
            _require(len(records) % 3 == 0 and all(value == "unspecified" for value in records[2::3]))
            at = args.index("diff") + 1
            revisions = [arg for arg in args[at:args.index("--")]
                         if re.fullmatch(r"[0-9a-f]{40}", arg)]
            _require(1 <= len(revisions) <= 2)
            changed = run(["diff", "--no-renames", "--no-ext-diff", "--no-textconv",
                           "--name-only", "-z", *revisions, "--", *paths])
            for name in _nul_records(changed.decode("utf-8")):
                path = ROOT / name
                if path.exists() or path.is_symlink():
                    _lines(path)  # changed tracked files retain ordinary-file/UTF-8/NUL gates too
            # Pin historical defaults for BOTH numstat and patch selection.
            args = [*args[:at], "--diff-algorithm=myers", "--indent-heuristic", *args[at:]]
        return run(args)


def _git(args):
    return _git_raw(args).decode("utf-8")


def _counted(path):
    return ((path.startswith(DEPLOY_ROOT + "/") and path.endswith(DEPLOY_SUFFIXES))
            or path in RETAINED_FILES)


def _gross_slice(paths, allowed, revision=CORRECTION_BASE_REVISION, target=None):
    if not paths:
        return 0
    revisions = (revision,) if target is None else (revision, target)
    output = _git(["-c", "diff.renames=false", "diff", "--no-renames", "--no-ext-diff",
                   "--no-textconv", "--numstat", *revisions, "--", *paths])
    added = 0
    for line in output.splitlines():
        columns = line.split("\t")
        _require(len(columns) == 3 and columns[0].isdigit() and columns[1].isdigit())
        _require(allowed(columns[2]))
        added += int(columns[0])
    if target is None:
        ordinary = _git(["ls-files", "--others", "--exclude-standard", "--", *paths])
        ignored = _git(["ls-files", "--others", "--ignored", "--exclude-standard", "--", *paths])
        for name in set(ordinary.splitlines() + ignored.splitlines()):
            if allowed(name):
                added += _lines(ROOT / name)
    return added


def _gross_added_line_bytes(paths, revision, target=None):
    if not paths:
        return 0
    # U0 can change the edit script (including added-line count). Use Git's
    # historical U3/default Myers+indent selection, with a numstat cross-check.
    revisions = (revision,) if target is None else (revision, target)
    output = _git_raw([
        "-c", "diff.renames=false", "diff", "--no-renames", "--no-ext-diff",
        "--no-textconv", "--no-color", "--unified=3", "--numstat", "-z", "--patch", *revisions, "--", *paths,
    ])
    if output:
        _require(b"\0\0" in output)
        summary, output = output.split(b"\0\0", 1)
        expected_lines = 0
        for record in summary.split(b"\0"):
            columns = record.split(b"\t", 2)
            _require(len(columns) == 3 and columns[0].isdigit() and columns[1].isdigit())
            expected_lines += int(columns[0])
    else:
        expected_lines = 0
    added, added_lines, old_left, new_left, last_added = 0, 0, 0, 0, False
    records = output.split(b"\n")
    _require(records.pop() == b"")
    for line in records:
        if line == b"\\ No newline at end of file":
            if last_added:
                added -= 1
            last_added = False
            continue
        if old_left or new_left:
            prefix = line[:1]
            _require(prefix in (b"+", b"-", b" "))
            old_left -= prefix in (b"-", b" ")
            new_left -= prefix in (b"+", b" ")
            _require(old_left >= 0 and new_left >= 0)
            last_added = prefix == b"+"
            if last_added:
                added_lines += 1
                added += len(line)  # strip '+' and include the patch LF
            continue
        last_added = False
        if line.startswith(b"@@ "):
            hunk = re.match(rb"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", line)
            _require(hunk is not None)
            old_left, new_left = (int(n) if n is not None else 1 for n in hunk.groups())
        else:
            _require(not line.startswith((b"Binary files ", b"GIT binary patch")))
    _require(old_left == new_left == 0 and added_lines == expected_lines)
    if target is None:
        ignored = _git(["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", *paths])
        _require(not ignored)
        for name in _nul_records(_git(["ls-files", "--others", "--exclude-standard", "-z", "--", *paths])):
            _require(name in paths)
            _lines(ROOT / name)  # retain ordinary-file/UTF-8/binary rejection
            added += (ROOT / name).stat().st_size
    return added


def _gross_bytes(budget, product_test=False):
    if product_test:
        return _product_test_consumption(budget)[1]
    entries = budget["owners"]
    revision = REMEDIATION_BASE_REVISION
    highs = PRODUCT_TEST_BYTE_FORECASTS if product_test else REMEDIATION_BYTE_HIGHS
    gross = {entry["name"]: _gross_added_line_bytes(
        (*entry["existing_paths"], *entry["new_files"]) if product_test else tuple(entry["paths"]), revision)
        for entry in entries}
    _require(set(gross) == set(highs) and all(gross[owner] <= highs[owner] for owner in highs))
    _require(sum(gross.values()) <= (
        PRODUCT_TEST_GLOBAL_BYTE_FORECAST if product_test else REMEDIATION_GLOBAL_BYTE_HIGH))
    return gross


def _serialized_inventory_within_limit(raw):
    _require(isinstance(raw, bytes) and len(raw) <= SERIALIZED_SOURCE_INVENTORY_LIMIT); return raw

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
    _require(set(data) == {"version", "base_revision", "global_gross_line_high", "global_gross_byte_high", "baseline",
                           "source_limits", "product_test_correction", "owners"})
    _require(data["version"] == "cogs.external-review-remediation-budget/v1"
             and data["base_revision"] == REMEDIATION_BASE_REVISION
             and data["global_gross_line_high"] == 48_000 and type(data["global_gross_byte_high"]) is int and data["global_gross_byte_high"] == REMEDIATION_GLOBAL_BYTE_HIGH)
    _require(data["baseline"] == {"tracked_files": 1420, "source_inventory_entries": 1417,
                                   "source_inventory_bytes": 18_763_891})
    _require(data["source_limits"] == {"tracked_files": 1530,
                                        "source_inventory_bytes": 30_000_000,
                                        "serialized_source_inventory_bytes": SERIALIZED_SOURCE_INVENTORY_LIMIT})
    try:
        producer = SOURCE_INVENTORY_PRODUCER.read_text("utf-8")
    except (OSError, UnicodeError):
        raise LineBudgetError() from None
    _require("STAGE4_MAXIMUM_SERIALIZED_SOURCE_INVENTORY_BYTES = 262_144" in producer
             and "assertStage4SerializedSourceInventory" in producer)
    expected = dict(route=2_200, revocation=3_000, relay=4_628, lifecycle=11_800, completion=6_080, integration=20_157)
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
        _require(isinstance(forecast, dict) and set(forecast) == {"total"}
                 and type(forecast["total"]) is int
                 and forecast["total"] == REMEDIATION_BYTE_HIGHS[name])
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
    _require(new_file_highs == {"route": 1, "revocation": 0, "relay": 1,
                                "lifecycle": 5, "completion": 3, "integration": 88})
    _require(sum(new_file_highs.values()) == 98)
    _require(data["baseline"]["tracked_files"] + sum(new_file_highs.values())
             <= data["source_limits"]["tracked_files"])
    _require(data["baseline"]["source_inventory_bytes"]
             + data["global_gross_byte_high"]
             <= data["source_limits"]["source_inventory_bytes"])
    baseline_names = set(_nul_records(_git(["ls-tree", "-r", "--name-only", "-z",
                                            REMEDIATION_BASE_REVISION])))
    for owner in owners:
        planned_new = sum(1 for path, allocated in paths.items()
                          if allocated == owner and path not in baseline_names)
        _require(planned_new <= new_file_highs[owner])
    _require(paths.get(str(REMEDIATION_BUDGET_PATH.relative_to(ROOT))) == "integration")
    _product_test_budget(data, paths)
    return data, owners, paths, new_file_highs, forecasts


def _product_path_denied(path):
    return (path.startswith("deploy/aws-feasibility/") or path.startswith("images/") or path.startswith(".github/workflows/release-")
            or path.startswith("docs/operations/release-") or path.startswith("scripts/") and ("provider" in path or "release" in path))

def _product_test_budget(data, allocations):
    plan = data["product_test_correction"]
    _require(isinstance(plan, dict) and set(plan) == {
        "base_revision", "base_tree", "checkpoint_revision", "checkpoint_tree", "retained_allocation",
        "remediation_retained_allocation", "remaining_tranche", "global_gross_line_forecast",
        "global_gross_byte_forecast", "owners"})
    _require(plan["base_revision"] == PRODUCT_TEST_Q and plan["base_tree"] == PRODUCT_TEST_Q_TREE
             and plan["checkpoint_revision"] == PRODUCT_TEST_Q and plan["checkpoint_tree"] == PRODUCT_TEST_Q_TREE
             and plan["retained_allocation"] == {"gross_lines": PRODUCT_TEST_RETAINED_LINES,
                                                   "gross_bytes": PRODUCT_TEST_RETAINED_BYTES}
             and plan["remediation_retained_allocation"] == {"gross_lines": 45_200,
                                                               "gross_bytes": 7_200_000}
             and plan["global_gross_line_forecast"] == 18_000
             and plan["global_gross_byte_forecast"] == PRODUCT_TEST_GLOBAL_BYTE_FORECAST)
    tranche = plan["remaining_tranche"]
    _require(isinstance(tranche, dict) and set(tranche) == {"gross_lines", "gross_bytes", "allocations"}
             and tranche["gross_lines"] == PRODUCT_TEST_REMAINING_LINES
             and tranche["gross_bytes"] == PRODUCT_TEST_REMAINING_BYTES
             and isinstance(tranche["allocations"], list))
    _require(_git(["rev-parse", PRODUCT_TEST_Q + "^{tree}"]).strip() == PRODUCT_TEST_Q_TREE)
    q_names = set(_nul_records(_git(["ls-tree", "-r", "--name-only", "-z", PRODUCT_TEST_Q])))
    q_budget = json.loads(_git(["show", PRODUCT_TEST_Q + ":config/external-review-remediation-budget-v1.json"]))
    q_allocations = {path: owner["name"] for owner in q_budget["owners"] for path in owner["paths"]}
    _require(PRODUCT_TEST_EXCLUDED_PATHS <= set(q_allocations)
             and all(allocations.get(path) == "integration" for path in PRODUCT_TEST_EXCLUDED_PATHS))
    q_product_allocations = {path: owner for path, owner in q_allocations.items()
                             if path not in PRODUCT_TEST_EXCLUDED_PATHS}
    _require(all(allocations.get(path) == owner for path, owner in q_product_allocations.items()))
    planned, new, forecasts = {}, {}, {}
    _require(isinstance(plan["owners"], list) and len(plan["owners"]) == len(PRODUCT_TEST_FORECASTS))
    for entry in plan["owners"]:
        _require(isinstance(entry, dict) and set(entry) == {
            "name", "gross_line_forecast", "gross_byte_forecast", "existing_paths", "new_files"})
        owner = entry["name"]
        _require(owner in PRODUCT_TEST_FORECASTS and owner not in forecasts
                 and type(entry["gross_line_forecast"]) is int
                 and entry["gross_line_forecast"] == PRODUCT_TEST_FORECASTS[owner]
                 and type(entry["gross_byte_forecast"]) is int
                 and entry["gross_byte_forecast"] == PRODUCT_TEST_BYTE_FORECASTS[owner])
        forecasts[owner] = entry["gross_line_forecast"]
        for kind in ("existing_paths", "new_files"):
            names = entry[kind]
            _require(isinstance(names, list) and all(isinstance(path, str) for path in names)
                     and names == sorted(set(names)))
            for path in names:
                _require(path not in planned and allocations.get(path) == owner
                         and (path in q_names) == (kind == "existing_paths"))
                planned[path] = owner
                if kind == "new_files":
                    new[path] = owner
    _require(new == PRODUCT_TEST_NEW_FILES and not (set(planned) & PRODUCT_TEST_EXCLUDED_PATHS)
             and not any(_product_path_denied(path) for path in planned))
    _require(sum(forecasts.values()) == PRODUCT_TEST_RETAINED_LINES + PRODUCT_TEST_REMAINING_LINES
             and sum(entry["gross_byte_forecast"] for entry in plan["owners"])
             == PRODUCT_TEST_RETAINED_BYTES + PRODUCT_TEST_REMAINING_BYTES)
    _require(sum(forecasts.values()) < plan["global_gross_line_forecast"]
             and sum(entry["gross_byte_forecast"] for entry in plan["owners"])
             < plan["global_gross_byte_forecast"])
    _require(set(allocations) == set(q_allocations) | set(planned))
    _require(set(allocations) - q_names == set(PRODUCT_TEST_NEW_FILES))
    canonical = json.dumps(planned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _require(hashlib.sha256(canonical).hexdigest() == PRODUCT_TEST_PATH_OWNER_SHA256)
    tasks = tranche["allocations"]
    task_owner_lines, task_owner_bytes = {}, {}
    required_tasks = (("helper", 452, 350_000, {"integration": (352, 250_000), "lifecycle": (100, 100_000)}),
                      ("docker_workflow_and_tests", 550, 650_000, {"integration": (550, 650_000)}),
                      ("kvm_gate_and_tests", 300, 300_000, {"relay": (300, 300_000)}),
                      ("final_controls_and_evidence", 165, 550_000, {"integration": (165, 550_000)}),
                      ("governance", 533, 150_000, {"integration": (533, 150_000)}))
    _require(len(tasks) == len(required_tasks))
    for task, expected_task in zip(tasks, required_tasks):
        name, lines, raw_bytes, expected_owners = expected_task
        _require(isinstance(task, dict) and set(task) == {"name", "gross_lines", "gross_bytes", "owner_allocations", "path_gross_line_highs"}
                 and task["name"] == name and task["gross_lines"] == lines and task["gross_bytes"] == raw_bytes
                 and isinstance(task["path_gross_line_highs"], list))
        owners = {entry["name"]: (entry["gross_lines"], entry["gross_bytes"])
                  for entry in task["owner_allocations"]
                  if isinstance(entry, dict) and set(entry) == {"name", "gross_lines", "gross_bytes"}}
        _require(len(owners) == len(task["owner_allocations"]) and owners == expected_owners
                 and sum(value[0] for value in owners.values()) == lines
                 and sum(value[1] for value in owners.values()) == raw_bytes)
        for owner, (owner_lines, owner_bytes) in owners.items():
            task_owner_lines[owner] = task_owner_lines.get(owner, 0) + owner_lines
            task_owner_bytes[owner] = task_owner_bytes.get(owner, 0) + owner_bytes
        highs = {entry["path"]: entry["gross_lines"] for entry in task["path_gross_line_highs"]
                 if isinstance(entry, dict) and set(entry) == {"path", "gross_lines"}}
        _require(len(highs) == len(task["path_gross_line_highs"]))
        if name == "docker_workflow_and_tests":
            _require(highs == {PRODUCT_TEST_WORKFLOW_PATH: PRODUCT_TEST_WORKFLOW_LINE_HIGH})
        else:
            _require(not highs)
    _require(task_owner_lines == {"integration": 1_600, "lifecycle": 100, "relay": 300}
             and task_owner_bytes == {"integration": 1_600_000, "lifecycle": 100_000, "relay": 300_000})
    task_canonical = json.dumps(tasks, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _require(hashlib.sha256(task_canonical).hexdigest() == PRODUCT_TEST_TASK_PATH_SHA256)
    _require(sum(forecasts.values()) < data["global_gross_line_high"]
             and PRODUCT_TEST_RETAINED_LINES + PRODUCT_TEST_REMAINING_LINES < data["global_gross_line_high"]
             and 45_200 + PRODUCT_TEST_REMAINING_LINES < data["global_gross_line_high"]
             and 7_200_000 + PRODUCT_TEST_REMAINING_BYTES < data["global_gross_byte_high"])
    return planned

def _product_test_task_paths(task, planned):
    all_paths = set(planned)
    lifecycle = {path for path, owner in planned.items() if owner == "lifecycle"}
    relay = {path for path, owner in planned.items() if owner == "relay"}
    if task == "helper":
        names = lifecycle | PRODUCT_TEST_HELPER_INTEGRATION_PATHS
    elif task == "docker_workflow_and_tests":
        names = set(PRODUCT_TEST_DOCKER_PATHS)
    elif task == "kvm_gate_and_tests":
        names = relay
    elif task == "governance":
        names = set(PRODUCT_TEST_GOVERNANCE_PATHS)
    elif task == "final_controls_and_evidence":
        names = all_paths - lifecycle - relay - PRODUCT_TEST_HELPER_INTEGRATION_PATHS - PRODUCT_TEST_DOCKER_PATHS - PRODUCT_TEST_GOVERNANCE_PATHS
    else:
        raise LineBudgetError()
    _require(names <= all_paths)
    return tuple(sorted(names))

def _product_test_changes(revision, target=None):
    revisions = (revision,) if target is None else (revision, target)
    return set(_nul_records(_git(["diff", "--no-renames", "--no-ext-diff", "--no-textconv",
                                  "--name-only", "-z", *revisions, "--", "."])))

def _product_test_linear_commits(head):
    merges = _git(["rev-list", "--min-parents=2", PRODUCT_TEST_Q + ".." + head]).splitlines()
    _require(not merges)
    commits = _git(["rev-list", "--reverse", PRODUCT_TEST_Q + ".." + head]).splitlines()
    parent = PRODUCT_TEST_Q
    for commit in commits:
        _require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None)
        _require(_git(["rev-list", "--parents", "-n", "1", commit]).split() == [commit, parent])
        yield parent, commit
        parent = commit

def _product_test_consumption(budget):
    plan = budget["product_test_correction"]
    planned = {path: entry["name"] for entry in plan["owners"]
               for path in (*entry["existing_paths"], *entry["new_files"])}
    tasks = plan["remaining_tranche"]["allocations"]
    task_paths = {task["name"]: _product_test_task_paths(task["name"], planned) for task in tasks}
    _require(set().union(*(set(names) for names in task_paths.values())) == set(planned)
             and sum(len(names) for names in task_paths.values()) == len(planned))
    head = _git(["rev-parse", "HEAD"]).strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", head) is not None
             and _git(["merge-base", "--is-ancestor", PRODUCT_TEST_Q, head]) == "")
    slices = list(_product_test_linear_commits(head))
    slices.append((head, None))
    owner_lines = {entry["name"]: 0 for entry in plan["owners"]}
    owner_bytes = dict(owner_lines)
    task_lines = {task["name"]: 0 for task in tasks}
    task_bytes = dict(task_lines)
    task_owner_lines = {task["name"]: {} for task in tasks}
    task_owner_bytes = {task["name"]: {} for task in tasks}
    workflow_lines = 0
    for revision, target in slices:
        changed = _product_test_changes(revision, target)
        if target is None:
            changed.update(_nul_records(_git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."])))
        _require(changed <= set(planned))
        for owner in owner_lines:
            owner_names = tuple(path for path, allocated in planned.items() if allocated == owner)
            owner_lines[owner] += _gross_slice(owner_names, lambda path: path in owner_names, revision, target)
            owner_bytes[owner] += _gross_added_line_bytes(owner_names, revision, target)
        for task in tasks:
            names = task_paths[task["name"]]
            line_charge = _gross_slice(names, lambda path: path in names, revision, target)
            byte_charge = _gross_added_line_bytes(names, revision, target)
            task_lines[task["name"]] += line_charge
            task_bytes[task["name"]] += byte_charge
            for owner in {entry["name"] for entry in task["owner_allocations"]}:
                owner_names = tuple(path for path in names if planned[path] == owner)
                owner_line_charge = _gross_slice(owner_names, lambda path: path in owner_names, revision, target)
                owner_byte_charge = _gross_added_line_bytes(owner_names, revision, target)
                task_owner_lines[task["name"]][owner] = task_owner_lines[task["name"]].get(owner, 0) + owner_line_charge
                task_owner_bytes[task["name"]][owner] = task_owner_bytes[task["name"]].get(owner, 0) + owner_byte_charge
            if task["name"] == "docker_workflow_and_tests":
                workflow_lines += _gross_slice((PRODUCT_TEST_WORKFLOW_PATH,),
                                               lambda path: path == PRODUCT_TEST_WORKFLOW_PATH,
                                               revision, target)
    for task in tasks:
        owner_highs = {entry["name"]: (entry["gross_lines"], entry["gross_bytes"])
                       for entry in task["owner_allocations"]}
        _require(task_lines[task["name"]] <= task["gross_lines"]
                 and task_bytes[task["name"]] <= task["gross_bytes"]
                 and all(task_owner_lines[task["name"]].get(owner, 0) <= high[0]
                         and task_owner_bytes[task["name"]].get(owner, 0) <= high[1]
                         for owner, high in owner_highs.items()))
    consumed_lines, consumed_bytes = sum(owner_lines.values()), sum(owner_bytes.values())
    _require(workflow_lines <= PRODUCT_TEST_WORKFLOW_LINE_HIGH
             and all(owner_lines[owner] <= high for owner, high in PRODUCT_TEST_REMAINING_FORECASTS.items())
             and consumed_lines <= PRODUCT_TEST_REMAINING_LINES
             and consumed_bytes <= PRODUCT_TEST_REMAINING_BYTES
             and PRODUCT_TEST_RETAINED_LINES + consumed_lines < plan["global_gross_line_forecast"]
             and PRODUCT_TEST_RETAINED_BYTES + consumed_bytes < plan["global_gross_byte_forecast"])
    return owner_lines, owner_bytes, task_lines, task_bytes, workflow_lines

def _product_test_gross(budget):
    return _product_test_consumption(budget)[0]


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
    _validate_control_data_members(final_names)
    return "member-set-complete", final_names


def _validate_control_data_members(names):
    try:
        for name in names:
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


def measure():
    retained_names = set(RETAINED_FILES)
    retained_deploy_names = set(RETAINED_DEPLOY_FILES)
    _require(len(RETAINED_FILES) == len(retained_names))
    _require(len(RETAINED_DEPLOY_FILES) == len(retained_deploy_names))
    tracked_names = set(_git(["ls-files", "--", *RETAINED_FILES]).splitlines())
    ordinary_names = set(_git(["ls-files", "--others", "--exclude-standard", "--",
                               *RETAINED_FILES]).splitlines())
    tracked_deploy_names = set(_git(["ls-files", "--", *RETAINED_DEPLOY_FILES]).splitlines())
    control_data_names = set(CONTROL_DATA_MEMBERS)
    final_control_data_state, final_control_data_names = _final_control_data_state()
    tracked_control_data_names = set(_git(["ls-files", "--", *CONTROL_DATA_ROOTS]).splitlines())
    _require(tracked_names | ordinary_names == retained_names
             and ordinary_names <= set((*ADR0327_RETAINED_FILES, *ADR0330_RETAINED_FILES)))
    _require(tracked_deploy_names == retained_deploy_names)
    _require(len(CONTROL_DATA_MEMBERS) == len(control_data_names)
             and tracked_control_data_names == control_data_names)
    # Moving v5 into history must not discard its ordinary/canonical-file gate.
    _validate_control_data_members(control_data_names)
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
    post_h = {
        "deploy": _gross_slice((DEPLOY_ROOT,), lambda name: (
            (name.startswith(DEPLOY_ROOT + "/") and name.endswith(DEPLOY_SUFFIXES))
            or name in control_data_names or name in final_control_data_names
            or name in retained_names), POST_H_REVISION),
        "retained": _gross_slice(RETAINED_FILES, lambda name: name in retained_names, POST_H_REVISION),
        "workflow": _gross_slice((WORKFLOW_ROOT,), lambda name: (
            name.startswith(WORKFLOW_ROOT + "/") and name.endswith(WORKFLOW_SUFFIXES)), POST_H_REVISION),
    }
    post_h["global"] = sum(post_h.values())
    post_h_satisfied = all(post_h[name] <= high for name, high in POST_H_HIGHS.items())
    correction_gross = deploy_gross + retained_gross + workflow_gross
    conservative = CORRECTION_BASE_CONSERVATIVE_LINES + correction_gross
    remediation, remediation_new_files, remediation_budget, remediation_byte_forecasts = _remediation_gross()
    product_test_gross = _product_test_gross(remediation_budget)
    remediation_bytes = _gross_bytes(remediation_budget)
    product_test_bytes = _gross_bytes(remediation_budget, product_test=True)
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
        "post_h_base_revision": POST_H_REVISION,
        "post_h_gross_added_lines": post_h,
        "post_h_reserve_highs": POST_H_HIGHS,
        "post_h_reserve_limits_satisfied": post_h_satisfied,
        "product_test_base_revision": PRODUCT_TEST_Q,
        "product_test_workstream_gross_added_lines": product_test_gross,
        "product_test_workstream_gross_line_forecasts": PRODUCT_TEST_FORECASTS,
        "product_test_gross_added_lines_no_deletion_credit": sum(product_test_gross.values()),
        "product_test_retained_and_consumed_gross_lines": PRODUCT_TEST_RETAINED_LINES + sum(product_test_gross.values()),
        "product_test_global_gross_line_forecast": 18_000,
        "product_test_workstream_gross_added_line_bytes": product_test_bytes,
        "product_test_workstream_gross_byte_forecasts": PRODUCT_TEST_BYTE_FORECASTS,
        "product_test_gross_added_line_bytes_no_deletion_credit": sum(product_test_bytes.values()),
        "product_test_retained_and_consumed_gross_line_bytes": PRODUCT_TEST_RETAINED_BYTES + sum(product_test_bytes.values()),
        "product_test_global_gross_byte_forecast": PRODUCT_TEST_GLOBAL_BYTE_FORECAST,
        "remediation_base_revision": REMEDIATION_BASE_REVISION,
        "remediation_workstream_gross_added_lines": remediation,
        "remediation_workstream_highs": remediation_highs,
        "remediation_workstream_new_files": remediation_new_files,
        "remediation_workstream_new_file_highs": remediation_new_file_highs,
        "remediation_workstream_gross_byte_forecasts": remediation_byte_forecasts,
        "remediation_workstream_gross_added_line_bytes": remediation_bytes,
        "remediation_gross_added_line_bytes_no_deletion_credit": sum(remediation_bytes.values()),
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
    _require(report["post_h_reserve_limits_satisfied"])
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
