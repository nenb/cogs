import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(".github/workflows/stage2-prebuilt-local-kata-qualification.yml", "utf8");
const guard = readFileSync("scripts/stage2-prebuilt-local-qualification-guard.py", "utf8");
const preflight = readFileSync("scripts/stage2-prebuilt-mixed-hg-preflight.sh", "utf8");
const staging = readFileSync("scripts/stage2-stage-prebuilt-control.py", "utf8");

test("formal qualification is additive, exact H/G, first-created, and seven fresh jobs", () => {
  assert.match(workflow, /\n {2}local-kata:\n {4}needs: admission\n {4}strategy:/u);
  assert.match(workflow, /ordinal: \[1, 2, 3, 4, 5, 6, 7\]/u);
  assert.match(workflow, /max-parallel: 7/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /FORMAL_CYCLE_ORDINAL: \$\{\{ matrix\.ordinal \}\}/u);
  assert.match(workflow, /timeout-minutes: 201/u);
  assert.match(workflow, /^name: Stage 2 prebuilt local Kata qualification$/mu);
  assert.match(workflow, /stage2-prebuilt-local-kata-qualification\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /Independently authenticate exact final H and G for this ordinal/u);
  assert.match(workflow, /stage2-prebuilt-local-qualification-guard\.py/u);
  assert.match(workflow, /stage2-stage-prebuilt-control\.py/u);
  assert.match(staging, /stage2-completion-local-control-v3/u);
  assert.match(guard, /Reviewed directional binding/u);
  assert.match(guard, /REVIEWED_ROOTFS_DESCRIPTOR_SHA256 = None/u);
});

test("each job prepares one rootfs, executes one mode-bound lifecycle, and closes custody", () => {
  const preparation = workflow.indexOf("Complete exact immutable preparation before KVM eligibility and role custody");
  const entry = workflow.indexOf("Execute exactly one ordinal-bound formal cycle");
  assert.ok(preparation > 0 && entry > preparation);
  const beforeEntry = workflow.slice(preparation, entry);
  assert.match(beforeEntry, /"rootfs_artifact_count":1/u);
  assert.match(beforeEntry, /"runtime_archive_count":2/u);
  assert.match(beforeEntry, /completion_kata_immutable_preparation\.py/u);
  assert.match(beforeEntry, /non-cloud formal grant/u);
  assert.match(workflow, /1\) entry=completion_formal_cycle_full\.py/u);
  assert.match(workflow, /2\|3\|4\|5\|6\|7\) entry=completion_formal_cycle_readiness\.py/u);
  assert.match(workflow, /Invoke cleanup-only recovery after every cycle outcome/u);
  assert.match(workflow, /Independently prove zero lifecycle residue after cleanup/u);
  assert.match(workflow, /supervise-final/u);
  assert.doesNotMatch(workflow, /aws-actions|opentofu|terraform|\bsts\b|\bssm\b/u);
});

test("aggregation is exact, artifact-complete, attempt-one, and non-AWS only", () => {
  assert.match(workflow, /needs: \[admission, local-kata\]/u);
  assert.match(workflow, /Materialize authenticated exact custody for all seven cycle uploads/u);
  assert.match(workflow, /actions\/runs\/\$GITHUB_RUN_ID\/artifacts\?per_page=100/u);
  assert.match(workflow, /Download all seven cycle artifacts by exact numeric IDs/u);
  assert.match(workflow, /artifact-ids: \$\{\{ steps\.cycle_custody\.outputs\.artifact_ids \}\}/u);
  assert.doesNotMatch(workflow, /pattern: stage2-formal-cycle/u);
  assert.match(workflow, /merge-multiple: true/u);
  assert.match(workflow, /CYCLE_ARTIFACT_DIGEST: \$\{\{ steps\.cycle_upload\.outputs\.artifact-digest \}\}/u);
  assert.match(workflow, /CYCLE_JOB_RESULT: \$\{\{ needs\.local-kata\.result \}\}/u);
  assert.match(workflow, /test "\$CYCLE_JOB_RESULT" = success/u);
  assert.match(workflow, /pre-aws-package-v3\.json/u);
  assert.match(workflow, /Byte-compare package and fail closed/u);
  assert.match(workflow, /cycle-artifact-custody-v1\.json/u);
  assert.match(workflow, /PACKAGE_ARTIFACT_DIGEST.*artifact-digest/u);
  assert.ok(Buffer.byteLength(workflow) < 94_000);
});

test("corrected mixed preflight remains no-KVM and versioned", () => {
  assert.match(preflight, /stage2-local-immutable-preparation\/v2/u);
  assert.match(preflight, /rootfs_artifact_count/u);
  assert.doesNotMatch(preflight, /\/dev\/kvm|completion_local_full/u);
});
