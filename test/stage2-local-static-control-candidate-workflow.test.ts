import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = ".github/workflows/stage2-local-static-control-candidate.yml";
const workflow = readFileSync(path, "utf8");
const dispatchGuard = readFileSync("scripts/stage2-static-control-dispatch-guard.py", "utf8");
const preparation = readFileSync("deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py", "utf8");
const settlement = readFileSync("scripts/stage2-local-settlement.py", "utf8");

test("control candidate workflow is manual reviewed-H one-shot and expressly non-authoritative", () => {
  assert.match(workflow, /^name: Stage 2 no-KVM static control candidate$/mu);
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(?:push|pull_request|schedule|workflow_run):/u);
  assert.match(workflow, /permissions:\n {2}actions: read\n\n/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,80}(?:contents:|write|id-token:)/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_IMPLEMENTATION_HEAD" = "\$\(\/usr\/bin\/git rev-parse HEAD\)"/u);
  assert.match(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(workflow, /non-authoritative-stage2-static-control/u);
  assert.match(workflow, /^ {4}timeout-minutes: 45$/mu);
  assert.match(workflow, /Step bounds total 42 minutes with a three-minute cleanup\/runner reserve/u);
  assert.doesNotMatch(workflow, /secrets\.|github\.token|aws-actions|amazon|terraform|opentofu/u);
  assert.doesNotMatch(workflow, /(?:GITHUB_TOKEN|GH_TOKEN)\s*[:=]|Authorization/u);
  assert.match(workflow, /test ! -e \/run\/netns\/cogs-stage2-ssh/u);
  assert.doesNotMatch(workflow, /completion_local_full|ctr run|systemctl|containerd --/u);
});

test("bounded first-created guard is exact source and precedes every source effect", () => {
  const guardAt = workflow.indexOf("Consume only the globally first-created reviewed-H dispatch");
  const checkoutAt = workflow.indexOf("Check out exact reviewed implementation head");
  const materializeAt = workflow.indexOf("Materialize exact H source");
  const acquireAt = workflow.indexOf("Acquire verify and install immutable fixtures");
  assert.ok(0 <= guardAt && guardAt < checkoutAt && checkoutAt < materializeAt && materializeAt < acquireAt);
  const match = workflow.match(/\/usr\/bin\/python3 -I -B - <<'PY'\n([\s\S]*?)^ {10}PY$/mu);
  assert.ok(match?.[1]);
  const embedded = match[1].replace(/^ {10}/gmu, "");
  assert.equal(embedded, dispatchGuard);
  assert.match(dispatchGuard, /MAX_RUNS = 100/u);
  assert.match(dispatchGuard, /len\(runs\) == total/u);
  assert.match(dispatchGuard, /_require\(not link, "Actions history is paginated"\)/u);
  assert.match(dispatchGuard, /return min\(identities\)/u);
  assert.match(dispatchGuard, /this is not the exact earliest created run ID/u);
  assert.match(dispatchGuard, /REVIEWED_IMPLEMENTATION_HEAD = "26af976022d559ebc2dc5434dd0df45fe976be77"/u);
  assert.match(dispatchGuard, /run\.get\("head_sha"\) == workflow_head/u);
  assert.match(dispatchGuard, /head_repository\.get\("full_name"\) == REPOSITORY/u);
  assert.doesNotMatch(dispatchGuard, /Authorization|GITHUB_TOKEN[^",]|secrets\./u);
  assert.doesNotMatch(
    workflow.slice(0, checkoutAt),
    /actions\/checkout|prepare-stage2-fixed-source|immutable_preparation/u,
  );
});

test("static dispatch guard hostile suite rejects retries, foreign history, and incompleteness", () => {
  const result = spawnSync("python3", ["-B", "test/stage2-static-control-dispatch-guard.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /static-control dispatch guard hostile tests passed/u);
});

test("final G preparation is fixed, verifies 16+2, installs before custody, and cleans Kata", () => {
  assert.match(preparation, /def prepare\(\):/u);
  assert.match(preparation, /_acquire_rootfs_assets\(contract\)[\s\S]+_download_runtime/u);
  assert.match(preparation, /_archive_values\(expected_runtime, archives, extracted\)/u);
  assert.match(preparation, /_publish_runtime\(extracted\)[\s\S]+_verify_installed\(expected_runtime\)/u);
  assert.match(preparation, /rootfs_artifact_count": 16/u);
  assert.match(preparation, /runtime_archive_count": 2/u);
  assert.match(preparation, /CONTROL_ROOT = Path\("\/var\/lib\/cogs\/stage2-completion-v1\/control"\)/u);
  assert.doesNotMatch(preparation, /argparse|sys\.argv\[1\]|os\.getenv\(/u);
  assert.match(settlement, /"\/opt\/kata"/u);
});
