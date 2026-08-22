import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = ".github/workflows/stage2-local-static-control-candidate.yml";
const workflow = readFileSync(path, "utf8");
const preparation = readFileSync("deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py", "utf8");
const settlement = readFileSync("scripts/stage2-local-settlement.py", "utf8");

test("control candidate workflow is manual exact-head attempt-one and expressly non-authoritative", () => {
  assert.match(workflow, /^name: Stage 2 no-KVM static control candidate$/mu);
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(?:push|pull_request|schedule|workflow_run):/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_IMPLEMENTATION_HEAD" = "\$GITHUB_SHA"/u);
  assert.match(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(workflow, /non-authoritative-stage2-static-control/u);
  assert.match(workflow, /^ {4}timeout-minutes: 45$/mu);
  assert.match(workflow, /Step bounds total 41 minutes with a four-minute cleanup\/runner reserve/u);
  assert.doesNotMatch(workflow, /secrets\.|GITHUB_TOKEN|AWS_|aws-actions|amazon|terraform|opentofu/u);
  assert.match(workflow, /test ! -e \/run\/netns\/cogs-stage2-ssh/u);
  assert.doesNotMatch(workflow, /completion_local_full|ctr run|systemctl|containerd --/u);
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
