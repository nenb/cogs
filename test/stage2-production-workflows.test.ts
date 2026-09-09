import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const planning = readFileSync(".github/workflows/stage2-production-plan.yml", "utf8");
const approval = readFileSync(".github/workflows/stage2-production-approval.yml", "utf8");
const campaign = readFileSync(".github/workflows/stage2-production-campaign.yml", "utf8");
const planner = readFileSync("scripts/stage2-production-planner.py", "utf8");
const issuer = readFileSync("scripts/stage2-production-approval.py", "utf8");
const stager = readFileSync("scripts/stage2-stage-production-approval.py", "utf8");
const campaignEntry = readFileSync("deploy/aws-feasibility/completion_campaign_aws_entry.py", "utf8");
const recoveryEntry = readFileSync("deploy/aws-feasibility/completion_campaign_aws_recovery_entry.py", "utf8");
const providerEntry = readFileSync("deploy/aws-feasibility/completion_campaign_aws_provider.py", "utf8");
const fullEntry = readFileSync("deploy/aws-feasibility/remote/completion_cycle_full.py", "utf8");
const readinessEntry = readFileSync("deploy/aws-feasibility/remote/completion_cycle_readiness.py", "utf8");
const retiredH = "0296252721fad0502dd4f41dacb1674e71b42bd6";

test("future planning authority is first-created, exact H/G/Q, and separately authorized", () => {
  assert.match(planning, /authorize-read-only-stage2-production-planning/u);
  assert.match(planning, /stage2-production-plan\.yml\/runs/u);
  assert.match(planning, /\.\[\]\.workflow_runs\[\]/u);
  assert.match(planning, /map\(\.id\) == \[\$current\]/u);
  assert.match(planning, /stage2-prebuilt-local-kata-qualification\.yml/u);
  assert.match(planning, /pre-aws-package-v5\.json/u);
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
  assert.match(planner, /stage2-pre-aws-qualification-package\/v5/u);
  assert.match(planner, /O_NOFOLLOW \| os\.O_NONBLOCK/u);
  assert.match(issuer, /O_NOFOLLOW \| os\.O_NONBLOCK/u);
  for (const source of [planner, providerEntry]) {
    assert.match(source, /selectors\.DefaultSelector\(\)/u);
    assert.match(source, /os\.killpg\(process\.pid, signal\.SIGKILL\)/u);
    assert.match(source, /def interrupted[\s\S]*interrupted_state\[0\] = True[\s\S]*os\.killpg/u);
    assert.match(source, /signal\.signal\(number, interrupted\)[\s\S]*signal\.signal\(number, signal\.SIG_IGN\)/u);
    assert.doesNotMatch(source, /RLIMIT_FSIZE|subprocess\.run\(/u);
  }
  assert.match(planner, /subprocess\.Popen[\s\S]*selectors\.DefaultSelector/u);
  assert.doesNotMatch(planner, /subprocess\.run/u);
  // Workflow migration is separately blocked: a v4 filename is not v5 authority.
  assert.match(issuer, /QUALIFICATION_PACKAGE_NAME/u);
  assert.match(stager, /validate_approval_package/u);
  assert.doesNotMatch(planner, /\bapply\b|\bdestroy\b|send-command/u);
  assert.ok(planning.indexOf(retiredH) < planning.indexOf("gh api --paginate"));
  assert.ok(
    planning.indexOf("stage2-production-planner.py eligibility") <
      planning.indexOf("Prepare exact control and prebuilt descriptor"),
  );
  assert.ok(
    planning.indexOf("stage2-production-planner.py eligibility") <
      planning.indexOf("Acquire short-lived planning identity"),
  );
  const plannerMain = planner.indexOf("def main(arguments):");
  const plannerEligibility = planner.indexOf("    package_eligible(package)\n", plannerMain);
  const plannerCredentialRead = planner.indexOf("os.environ[key]", plannerMain);
  assert.ok(plannerMain >= 0 && plannerEligibility >= 0 && plannerCredentialRead >= 0);
  assert.ok(plannerEligibility < plannerCredentialRead);
});

test("approval authenticates only the exact planning workflow artifact", () => {
  assert.match(approval, /stage2-production-plan\.yml/u);
  assert.match(approval, /COGS_STAGE2_CONTROL_REVISION/u);
  assert.match(approval, /approval-authentication\.bundle\.json/u);
  assert.match(approval, /--network none/u);
  assert.match(approval, /5db1043ec70bf92296da977941b19b3d86869af3018d4f4a0f457bf54d76bb68/u);
  assert.ok(approval.indexOf(retiredH) < approval.indexOf("gh api --paginate"));
  assert.match(issuer, /stage2-revision-retirement\.py/u);
  const issueStart = issuer.indexOf("def issue(path):");
  const eligibility = issuer.indexOf("eligible((draft.get", issueStart);
  const construction = issuer.indexOf("production.ProductionApproval(**value)", issueStart);
  const packageCheck = issuer.indexOf("validate_package(path, approval)", construction);
  const publication = issuer.indexOf("emit(canonical(output))", packageCheck);
  assert.ok(issueStart >= 0 && eligibility > issueStart && construction > eligibility);
  assert.ok(packageCheck > construction && publication > packageCheck);
});

test("production entry initialization failures emit only fixed diagnostics", () => {
  const directory = mkdtempSync(join(tmpdir(), "cogs-stage2-entry-"));
  try {
    for (const [name, source, diagnostic] of [
      ["approval.py", issuer, "stage2-production-approval: owner.failed\n"],
      ["planner.py", planner, "stage2-production-planner: owner.failed\n"],
      ["campaign.py", campaignEntry, "stage2-production-campaign: owner.failed\n"],
      ["recovery.py", recoveryEntry, "stage2-production-recovery: owner.failed\n"],
      ["provider.py", providerEntry, "stage2-production-provider: owner.failed\n"],
      ["full.py", fullEntry, "stage2-production-cycle-full: owner.failed\n"],
      ["readiness.py", readinessEntry, "stage2-production-cycle-readiness: owner.failed\n"],
    ] as const) {
      const path = join(directory, name);
      writeFileSync(path, source, { mode: 0o600 });
      const result = spawnSync("python3", ["-I", "-B", path], { encoding: "utf8", timeout: 5000 });
      assert.equal(result.status, 2, name);
      assert.equal(result.stdout, "", name);
      assert.equal(result.stderr, diagnostic, name);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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
  assert.match(campaign, /production-evidence-upload-receipt\/v2/u);
  assert.doesNotMatch(campaign, /continue-on-error:\s*true/u);
  assert.doesNotMatch(`${planning}\n${approval}\n${campaign}`, /\.\[\]\[\]/u);
  assert.match(stager, /aws-credentials/u);
  assert.match(stager, /ASIA\[A-Z0-9\]/u);
  assert.match(stager, /"\/usr\/bin\/unshare", "--net"/u);
  assert.match(stager, /terraform-provider-aws_v6\.54\.0_x5/u);
  assert.match(campaign, /role_duration_seconds/u);
  assert.match(campaign, /expires_unix_ns/u);
  for (const source of [planning, approval, campaign]) {
    assert.match(source, /&head_sha=\$GITHUB_SHA/u);
    assert.match(source, /\(\[\.\[\]\.total_count\] \| unique\) == \[1\]/u);
  }
  assert.match(providerEntry, /subprocess\.Popen[\s\S]*selectors\.DefaultSelector/u);
  assert.doesNotMatch(providerEntry, /subprocess\.run/u);
  for (const source of [campaignEntry, recoveryEntry, providerEntry, fullEntry, readinessEntry]) {
    assert.match(source, /owner\.failed/u);
    assert.match(source, /except BaseException/u);
    assert.match(source, /raise SystemExit\(2\) from None/u);
  }
  assert.ok(campaign.indexOf(retiredH) < campaign.indexOf("gh api --paginate"));
  assert.ok(
    campaign.indexOf("approval_sha256") < campaign.indexOf("Acquire exact separately approved implementation H"),
  );
  assert.ok(
    campaign.indexOf("stage2-production-approval.py eligibility") <
      campaign.indexOf("Acquire exact separately approved implementation H"),
  );
  assert.match(stager, /stage2-revision-retirement\.py/u);
  assert.ok(
    stager.indexOf('eligible((value.get("implementation_revision")') < stager.indexOf("aws_credentials = read"),
  );
});
