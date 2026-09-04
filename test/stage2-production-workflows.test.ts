import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const planning = readFileSync(".github/workflows/stage2-production-plan.yml", "utf8");
const approval = readFileSync(".github/workflows/stage2-production-approval.yml", "utf8");
const campaign = readFileSync(".github/workflows/stage2-production-campaign.yml", "utf8");
const planner = readFileSync("scripts/stage2-production-planner.py", "utf8");
const stager = readFileSync("scripts/stage2-stage-production-approval.py", "utf8");

test("future planning authority is first-created, exact H/G/Q, and separately authorized", () => {
  assert.match(planning, /authorize-read-only-stage2-production-planning/u);
  assert.match(planning, /stage2-production-plan\.yml\/runs/u);
  assert.match(planning, /\.\[\]\.workflow_runs\[\]/u);
  assert.match(planning, /map\(\.id\) == \[\$current\]/u);
  assert.match(planning, /stage2-prebuilt-local-kata-qualification\.yml/u);
  assert.match(planning, /pre-aws-package-v4\.json/u);
  assert.match(planning, /qualification_head/u);
  assert.doesNotMatch(planning, /report_artifact_id|receipt_artifact_id/u);
  assert.match(planning, /run_attempt == 1/u);
  assert.match(planning, /configure-aws-credentials@[0-9a-f]{40}/u);
  assert.match(planning, /stage2-production-planner\.py/u);
  assert.doesNotMatch(planning, /\bapply\b|\bdestroy\b|send-command/u);
  assert.match(planner, /"plan"/u);
  assert.match(planner, /"show", "-json"/u);
  assert.match(planner, /approval_batch_commitment/u);
  assert.match(planner, /qualification_revision/u);
  assert.match(planner, /stage2-pre-aws-qualification-package\/v4/u);
  assert.doesNotMatch(planner, /\bapply\b|\bdestroy\b|send-command/u);
});

test("approval authenticates only the exact planning workflow artifact", () => {
  assert.match(approval, /stage2-production-plan\.yml/u);
  assert.match(approval, /COGS_STAGE2_CONTROL_REVISION/u);
  assert.match(approval, /approval-authentication\.bundle\.json/u);
  assert.match(approval, /--network none/u);
  assert.match(approval, /5db1043ec70bf92296da977941b19b3d86869af3018d4f4a0f457bf54d76bb68/u);
});

test("future campaign has one sealed caller, explicit credential files, recovery, and no retry", () => {
  assert.match(campaign, /authorize-seven-stage2-production-cycles/u);
  assert.match(campaign, /stage2-production-campaign\.yml\/runs/u);
  assert.match(campaign, /stage2-production-approval\.yml/u);
  assert.match(campaign, /CONTROL_HEAD: \$\{\{ inputs\.control_head \}\}/u);
  assert.match(campaign, /\.control_revision == \$g/u);
  assert.match(campaign, /approval-authentication\.bundle\.json/u);
  assert.match(campaign, /prepare-stage2-fixed-source\.py/u);
  assert.ok(
    campaign.indexOf("prepare-stage2-fixed-source.py") <
      campaign.indexOf("Acquire short-lived fixed executor credentials"),
  );
  assert.match(campaign, /stage2-stage-production-approval\.py/u);
  assert.match(campaign, /run-production-campaign\.sh/u);
  assert.match(campaign, /recover-production-campaign-entry\.sh/u);
  assert.match(campaign, /evidence_upload\.outputs\.artifact-id/u);
  assert.match(campaign, /diff -r --no-dereference/u);
  assert.match(campaign, /production-evidence-upload-receipt\/v1/u);
  assert.doesNotMatch(campaign, /continue-on-error:\s*true/u);
  assert.doesNotMatch(`${planning}\n${approval}\n${campaign}`, /\.\[\]\[\]/u);
  assert.match(stager, /aws-credentials/u);
  assert.match(stager, /ASIA\[A-Z0-9\]/u);
  assert.match(stager, /"\/usr\/bin\/unshare", "--net"/u);
  assert.match(stager, /terraform-provider-aws_v6\.54\.0_x5/u);
  assert.match(campaign, /role_duration_seconds/u);
  assert.match(campaign, /expires_unix_ns/u);
});
