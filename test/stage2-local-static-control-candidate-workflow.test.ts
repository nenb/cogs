import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = ".github/workflows/stage2-local-static-control-prebuilt-candidate.yml";
const workflow = readFileSync(path, "utf8");
const dispatchGuard = readFileSync("scripts/stage2-static-control-dispatch-guard.py", "utf8");
const runtimeBoundary = readFileSync("scripts/stage2-prebuilt-static-control-runtime-boundary.py", "utf8");
const preparation = readFileSync("deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py", "utf8");
const settlement = readFileSync("scripts/stage2-local-settlement.py", "utf8");

test("control candidate workflow is manual reviewed-H one-shot and expressly non-authoritative", () => {
  assert.match(workflow, /^name: Stage 2 prebuilt no-KVM static control candidate$/mu);
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(?:push|pull_request|schedule|workflow_run):/u);
  assert.match(workflow, /permissions:\n {2}actions: read\n\n/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,80}(?:contents:|write|id-token:)/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_IMPLEMENTATION_HEAD" = "\$\(\/usr\/bin\/git rev-parse HEAD\)"/u);
  assert.doesNotMatch(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(workflow, /non-authoritative-stage2-static-control/u);
  assert.match(workflow, /^ {4}timeout-minutes: 55$/mu);
  assert.match(workflow, /Step bounds total 49 minutes with a six-minute cleanup\/runner reserve/u);
  assert.doesNotMatch(workflow, /aws-actions|amazon|terraform|opentofu/u);
  assert.match(workflow, /Authenticate exact trusted rootfs control input/u);
  assert.match(workflow, /artifact-ids: \$\{\{ inputs\.rootfs_control_artifact_id \}\}/u);
  assert.doesNotMatch(workflow, /packages:\s*write|id-token:\s*write/u);
  assert.match(workflow, /test ! -e \/run\/netns\/cogs-stage2-ssh/u);
  assert.doesNotMatch(workflow, /completion_local_full|ctr run|systemctl|containerd --/u);
});

test("prebuilt guard is first-created and precedes every source effect", () => {
  const guard = workflow.indexOf("Admit sole first-created prebuilt static-control generation");
  const checkout = workflow.indexOf("Check out exact reviewed implementation head without credentials");
  assert.ok(guard >= 0 && checkout > guard);
  assert.match(workflow, /stage2-local-static-control-prebuilt-candidate\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /test "\$GITHUB_RUN_ATTEMPT" = 1/u);
  assert.match(workflow, /test "\$GITHUB_REF_PROTECTED" = true/u);
});

test("static dispatch guard hostile suite covers event parsing, predecessors, redaction, and API failure", () => {
  const result = spawnSync("python3", ["-B", "test/stage2-static-control-dispatch-guard.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /authenticated static-control dispatch guard hostile tests passed/u);
});

test("reviewed H itself binds corrected immutable and producer sources in the runtime boundary", () => {
  const reviewed = /REVIEWED_IMPLEMENTATION_HEAD = "([0-9a-f]{40})"/u.exec(dispatchGuard)?.[1];
  assert.ok(reviewed);
  const boundaryAtH = spawnSync("git", ["show", `${reviewed}:scripts/stage2-static-control-runtime-boundary.py`], {
    encoding: "utf8",
  });
  assert.equal(boundaryAtH.status, 0, boundaryAtH.stderr);
  const policySources = [
    "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation.py",
  ];
  for (const sourcePath of policySources) {
    const sourceAtH: Uint8Array = execFileSync("git", ["show", `${reviewed}:${sourcePath}`]);
    const digest: string = createHash("sha256").update(sourceAtH).digest("hex");
    assert.match(boundaryAtH.stdout, new RegExp(`"sha256": "${digest}"`, "u"));
  }
});

test("static-only cleanup uses reviewed source policy and owned process-fd censuses", () => {
  assert.match(workflow, /stage2-prebuilt-static-control-runtime-boundary\.py" pre/u);
  assert.match(workflow, /stage2-prebuilt-static-control-runtime-boundary\.py" post/u);
  assert.match(workflow, /Remove owned fixtures and verify the static-only runtime boundary/u);
  assert.match(workflow, /chmod 0711 "\$root" "\$stage" "\$observation"/u);
  assert.match(workflow, /test -r "\$candidate\/stage2-local-static-control-v2\.json"/u);
  assert.match(workflow, /stat -c '%U:%G:%a'.*root:root:711/u);
  assert.match(workflow, /stat -c '%U:%G:%a'.*"\$stage\/source".*root:root:700/su);
  assert.doesNotMatch(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(runtimeBoundary, /MAX_PROCESSES = 32_768/u);
  assert.match(runtimeBoundary, /MAX_FDS_PER_PROCESS = 4_096/u);
  assert.match(
    runtimeBoundary,
    /REVIEWED_WORKFLOW_SHA256 = "da423b595330633b30da3ba5c3ad603cc23ca5dd31e5a64ebee82f1ea85fa1c7"/u,
  );
  assert.doesNotMatch(runtimeBoundary, /replacements == 1/u);
  assert.match(runtimeBoundary, /normalized == "\/dev\/kvm"/u);
  assert.match(runtimeBoundary, /owned-qmp-or-runtime-socket/u);
  assert.match(runtimeBoundary, /owned-network-namespace/u);
  assert.match(runtimeBoundary, /"containerd"[\s\S]+"qemu-system-x86_64"/u);
  for (const path of [
    "scripts/prepare-stage2-fixed-source.py",
    "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation.py",
  ]) {
    assert.match(runtimeBoundary, new RegExp(path.replaceAll("/", "\\/"), "u"));
  }
  const result = spawnSync("python3", ["-B", "test/stage2-prebuilt-static-control-runtime-boundary.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /stage2 prebuilt static boundary checks passed/u);
});

test("final G preparation acquires one prebuilt rootfs plus two runtimes and cleans Kata", () => {
  assert.match(preparation, /def prepare\(\):/u);
  assert.match(preparation, /prebuilt_acquisition\.acquire_fixed\(descriptor_raw\)[\s\S]+_download_runtime/u);
  assert.match(preparation, /_archive_values\(expected_runtime, archives, extracted\)/u);
  assert.match(preparation, /_publish_runtime\(extracted\)[\s\S]+_verify_installed\(expected_runtime\)/u);
  assert.match(preparation, /"rootfs_artifact_count": 1/u);
  assert.doesNotMatch(preparation, /_acquire_rootfs_assets\(contract\)/u);
  assert.match(preparation, /runtime_archive_count": 2/u);
  assert.match(preparation, /CONTROL_ROOT = Path\("\/var\/lib\/cogs\/stage2-completion-v1\/control"\)/u);
  assert.doesNotMatch(preparation, /argparse|sys\.argv\[1\]|os\.getenv\(/u);
  assert.match(settlement, /"\/opt\/kata"/u);
});
