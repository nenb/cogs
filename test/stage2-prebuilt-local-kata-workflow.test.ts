import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(".github/workflows/stage2-prebuilt-local-kata-qualification.yml", "utf8");
const guard = readFileSync("scripts/stage2-prebuilt-local-qualification-guard.py", "utf8");
const preflight = readFileSync("scripts/stage2-prebuilt-mixed-hg-preflight.sh", "utf8");
const staging = readFileSync("scripts/stage2-stage-prebuilt-control.py", "utf8");

test("corrected qualification is additive, exact H-then-G, and first-created", () => {
  assert.match(workflow, /\n {2}local-kata:\n {4}needs: admission\n/u);
  assert.match(workflow, /REPORT_STAGING: \/var\/tmp\/cogs-stage2-prebuilt-result-/u);
  assert.match(workflow, /timeout-minutes: 201/u);
  assert.match(workflow, /^name: Stage 2 prebuilt local Kata qualification$/mu);
  assert.match(workflow, /reviewed_implementation_head:/u);
  assert.match(workflow, /reviewed_control_head:/u);
  assert.match(workflow, /stage2-prebuilt-local-kata-qualification\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /test "\$EXACT_CONTROL_HEAD" = "\$GITHUB_SHA"/u);
  assert.match(workflow, /stage2-prebuilt-local-qualification-guard\.py/u);
  assert.match(workflow, /stage2-stage-prebuilt-control\.py/u);
  assert.match(staging, /stage2-completion-local-control-v3/u);
  assert.match(staging, /stage2-local-static-control-v2\.json/u);
  assert.match(guard, /Reviewed directional binding/u);
  assert.match(guard, /WORKFLOW_NAME = "stage2-prebuilt-local-kata-qualification\.yml"/u);
});

test("corrected qualification prepares one prebuilt rootfs and preserves cleanup/publication custody", () => {
  const preparation = workflow.indexOf("Complete exact immutable preparation before KVM eligibility and role custody");
  const entry = workflow.indexOf("Execute the sole zero-argument local qualification entry");
  assert.ok(preparation > 0 && entry > preparation);
  const beforeEntry = workflow.slice(preparation, entry);
  assert.match(beforeEntry, /"rootfs_artifact_count":1/u);
  assert.match(beforeEntry, /"runtime_archive_count":2/u);
  assert.match(beforeEntry, /completion_kata_immutable_preparation\.py/u);
  assert.doesNotMatch(beforeEntry, /download-16|_acquire_rootfs_assets/u);
  assert.match(workflow, /Invoke cleanup-only recovery after every local entry outcome/u);
  assert.match(workflow, /Independently prove zero lifecycle residue after cleanup/u);
  assert.match(workflow, /artifact-id/u);
  assert.doesNotMatch(workflow, /aws-actions|opentofu|terraform|\bsts\b|\bssm\b/u);
});

test("corrected mixed preflight remains no-KVM and versioned", () => {
  assert.match(preflight, /stage2-local-immutable-preparation\/v2/u);
  assert.match(preflight, /rootfs_artifact_count/u);
  assert.doesNotMatch(preflight, /\/dev\/kvm|completion_local_full/u);
});
