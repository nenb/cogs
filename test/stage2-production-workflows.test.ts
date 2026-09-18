import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const planning = readFileSync(".github/workflows/stage2-production-plan.yml", "utf8");
const approval = readFileSync(".github/workflows/stage2-production-approval.yml", "utf8");
const approvalDiagnostic = readFileSync(".github/workflows/stage2-production-approval-signing-diagnostic.yml", "utf8");
const campaign = readFileSync(".github/workflows/stage2-production-campaign.yml", "utf8");
const diagnosticPreparation = readFileSync(".github/workflows/stage2-r-diagnostic-preparation.yml", "utf8");
const diagnosticCampaign = readFileSync(".github/workflows/stage2-r-diagnostic-campaign.yml", "utf8");
const signer = readFileSync("scripts/stage2-cosign-keyless-sign.sh", "utf8");
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
  assert.match(signer, /approval-authentication\.bundle\.json/u);
  assert.match(approval, /provider-package\.tar\.sha256/u);
  assert.match(approval, /install -m 0600 "\$RUNNER_TEMP\/planning\/provider-package\.tar"/u);
  assert.doesNotMatch(approval, /tar -xf "\$RUNNER_TEMP\/planning\/provider-package\.tar"/u);
  assert.match(approval, /scripts\/stage2-cosign-keyless-sign\.sh "\$out" "\$identity"/u);
  assert.match(approval, /chmod 0600 "\$RUNNER_TEMP\/approval\/approval-authentication\.json"/u);
  assert.match(approval, /ACTIONS_ID_TOKEN_REQUEST_TOKEN=\\nACTIONS_ID_TOKEN_REQUEST_URL=\\n/u);
  assert.doesNotMatch(approval, /docker run/u);
  assert.match(signer, /runner_uid="\$\(id -u\)"/u);
  assert.match(signer, /--network host/u);
  assert.match(signer, /--network none/u);
  assert.match(signer, /-e HOME=\/cosign-home/u);
  assert.match(signer, /cogs-cosign-sign-home\.XXXXXX/u);
  assert.match(signer, /cogs-cosign-verify-home\.XXXXXX/u);
  assert.match(signer, /--oidc-provider github-actions/u);
  assert.match(signer, /--trusted-root sigstore-trusted-root\.json/u);
  assert.match(signer, /5db1043ec70bf92296da977941b19b3d86869af3018d4f4a0f457bf54d76bb68/u);
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

test("shared signer closes pinned Cosign identity, filesystem, TUF, network, and binary custody", () => {
  assert.match(signer, /set -Eeuo pipefail/u);
  assert.match(signer, /umask 077/u);
  assert.match(signer, /cosign\/cosign@sha256:be924970ba7438c22e18067dec5637946d6566eac711f5bedd1584e7137008fb/u);
  assert.match(signer, /case "\$identity" in/u);
  assert.match(signer, /stage2-production-approval\.yml@refs\/heads\/main/u);
  assert.match(signer, /stage2-production-approval-signing-diagnostic\.yml@refs\/heads\/main/u);
  assert.match(signer, /stage2-r-diagnostic-preparation\.yml@refs\/heads\/main/u);
  assert.match(signer, /directory:\$runner_uid:\$runner_gid:700/u);
  assert.match(signer, /regular file:\$runner_uid:\$runner_gid:1/u);
  assert.match(signer, /--user "\$runner_uid:\$runner_gid"/u);
  assert.match(signer, /--cap-drop ALL/u);
  assert.match(signer, /--security-opt no-new-privileges/u);
  assert.match(signer, /--read-only/u);
  assert.match(signer, /-e HOME=\/cosign-home/u);
  assert.match(signer, /-v "\$sign_home:\/cosign-home"/u);
  assert.match(signer, /-v "\$verify_home:\/cosign-home"/u);
  assert.match(signer, /sign-blob --yes --timeout 180s --oidc-provider github-actions/u);
  assert.match(signer, /\[ -d "\$sign_home\/\.sigstore\/root" \]/u);
  assert.match(signer, /--network none/u);
  assert.match(signer, /-v "\$out:\/work:ro"/u);
  assert.match(signer, /--certificate-identity "\$identity"/u);
  assert.match(signer, /--certificate-oidc-issuer "\$issuer"/u);
  assert.match(signer, /docker cp "\$container:\/ko-app\/cosign" "\$binary"/u);
  assert.doesNotMatch(signer, /AWS_|authorize-seven|authorize-read-only|opentofu|terraform|\bssm\b/iu);
});

test("protected signing diagnostic is singleton, exact-main, non-authorizing, and uses the production signer", () => {
  assert.match(approvalDiagnostic, /^on:\n {2}workflow_dispatch:/mu);
  assert.match(approvalDiagnostic, /id-token: write/u);
  assert.match(approvalDiagnostic, /test "\$GITHUB_REF" = refs\/heads\/main/u);
  assert.match(approvalDiagnostic, /test "\$GITHUB_REF_PROTECTED" = true/u);
  assert.match(approvalDiagnostic, /test "\$GITHUB_RUN_ATTEMPT" = 1/u);
  assert.match(approvalDiagnostic, /stage2-production-approval-signing-diagnostic\.yml\/runs/u);
  assert.match(approvalDiagnostic, /map\(\.id\) == \[\$current\]/u);
  assert.match(approvalDiagnostic, /authority":"non-authorizing-cosign-diagnostic-only/u);
  assert.match(approvalDiagnostic, /scripts\/stage2-cosign-keyless-sign\.sh "\$out" "\$identity"/u);
  assert.match(approvalDiagnostic, /--network|TUF home|offline verification/u);
  assert.match(approvalDiagnostic, /ACTIONS_ID_TOKEN_REQUEST_TOKEN=\\nACTIONS_ID_TOKEN_REQUEST_URL=\\n/u);
  assert.doesNotMatch(approvalDiagnostic, /configure-aws-credentials|AWS_ACCESS_KEY_ID=|opentofu|terraform|\bssm\b/iu);
});

test("R diagnostic lane exercises production bytes without creating evidence authority", () => {
  assert.match(diagnosticPreparation, /start-stage2-r-diagnostic-window/u);
  assert.match(diagnosticPreparation, /stage2-r-diagnostic-preparation\.yml\/runs/u);
  assert.match(diagnosticPreparation, /NON-AUTHORITATIVE-stage2-r-diagnostic-planning/u);
  assert.match(diagnosticPreparation, /NON-AUTHORITATIVE-stage2-r-diagnostic-approval/u);
  assert.match(diagnosticPreparation, /stage2-production-planner\.py/u);
  assert.match(diagnosticPreparation, /plans\/\.provider-tf-data/u);
  assert.match(diagnosticPreparation, /rm -rf --one-file-system -- "\$bootstrap"/u);
  assert.match(diagnosticPreparation, /find "\$RUNNER_TEMP\/planning" -mindepth 1 -name '\.\*'/u);
  assert.ok(
    diagnosticPreparation.indexOf('bootstrap="$RUNNER_TEMP/planning/plans/.provider-tf-data"') <
      diagnosticPreparation.indexOf("Upload diagnostic planning bytes"),
  );
  assert.match(diagnosticPreparation, /COGS_STAGE2_CONTROL_REVISION: \$\{\{ inputs\.control_head \}\}/u);
  assert.match(diagnosticPreparation, /stage2-production-approval\.py issue/u);
  assert.match(diagnosticPreparation, /stage2-cosign-keyless-sign\.sh/u);
  assert.ok(
    diagnosticPreparation.indexOf("COGS_STAGE2_CONTROL_REVISION:") <
      diagnosticPreparation.indexOf("stage2-production-approval.py issue") &&
      diagnosticPreparation.indexOf("stage2-production-approval.py issue") <
        diagnosticPreparation.indexOf("stage2-production-approval.py authenticate") &&
      diagnosticPreparation.indexOf("stage2-production-approval.py authenticate") <
        diagnosticPreparation.indexOf("stage2-cosign-keyless-sign.sh"),
  );
  assert.match(diagnosticPreparation, /diff -r --no-dereference/u);
  assert.ok(diagnosticPreparation.includes('"production_evidence_eligible":False'));
  assert.ok(diagnosticPreparation.includes('"issue42_closure_eligible":False'));
  assert.doesNotMatch(diagnosticPreparation, /gh variable set/u);

  assert.match(diagnosticCampaign, /authorize-seven-stage2-non-authoritative-diagnostic-cycles/u);
  assert.match(diagnosticCampaign, /stage2-r-diagnostic-campaign\.yml\/runs/u);
  assert.match(diagnosticCampaign, /stage2-r-diagnostic-preparation\.yml/u);
  assert.match(diagnosticCampaign, /NON-AUTHORITATIVE-stage2-r-diagnostic-approval/u);
  assert.match(diagnosticCampaign, /Verify executor budget tag-read closure before resource effects/u);
  assert.match(diagnosticCampaign, /stage2-stage-production-approval\.py/u);
  assert.match(diagnosticCampaign, /Overlay only the exact diagnostic adapter and provider/u);
  assert.match(diagnosticCampaign, /COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1/u);
  assert.match(stager, /identity = adapter\.approval_identity\(\)/u);
  assert.doesNotMatch(campaign, /COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC/u);
  assert.ok(
    diagnosticCampaign.indexOf("stage2-stage-production-approval.py") <
      diagnosticCampaign.indexOf("root=/var/lib/cogs/stage2-completion-v1/source"),
  );
  assert.ok(
    diagnosticCampaign.indexOf('target="$root/$name"') < diagnosticCampaign.indexOf("completion_campaign_aws_entry.py"),
  );
  assert.match(diagnosticCampaign, /completion_campaign_aws_recovery_entry\.py/u);
  assert.match(diagnosticCampaign, /validate-aws-stage2-completion-evidence-v3\.ts/u);
  assert.match(diagnosticCampaign, /NON-AUTHORITATIVE-stage2-r-diagnostic-result/u);
  assert.ok(diagnosticCampaign.includes('rm -rf "$private"'));
  assert.ok(diagnosticCampaign.includes('"production_evidence_eligible":False'));
  assert.ok(diagnosticCampaign.includes('"issue42_closure_eligible":False'));
  assert.doesNotMatch(diagnosticCampaign, /gh variable set/u);
  assert.doesNotMatch(diagnosticCampaign, /name: stage2-production-evidence-/u);

  const cleanImmutable =
    /\/usr\/bin\/env -i HOME=\/nonexistent LANG=C LC_ALL=C PATH=\/usr\/bin:\/bin TZ=UTC "\s*\n\s*"\/usr\/bin\/python3 -I -B \/var\/lib\/cogs\/stage2-completion-v1\/source\//u;
  assert.match(providerEntry, cleanImmutable);
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
  assert.match(campaign, /Verify executor budget tag-read closure before any resource effect/u);
  assert.match(campaign, /budgets list-tags-for-resource/u);
  assert.match(campaign, /cogs-s2-permission-probe-\$GITHUB_RUN_ID/u);
  assert.match(campaign, /NotFoundException/u);
  assert.match(campaign, /AccessDenied/u);
  assert.ok(
    campaign.indexOf("Acquire short-lived fixed executor credentials") <
      campaign.indexOf("Verify executor budget tag-read closure") &&
      campaign.indexOf("Verify executor budget tag-read closure") <
        campaign.indexOf("Seal executor credential bytes") &&
      campaign.indexOf("Seal executor credential bytes") < campaign.indexOf("run-production-campaign.sh"),
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
  assert.match(stager, /cogs\.stage2-opentofu-provider-package\/v1/u);
  assert.match(stager, /PACKAGE_MAX_FILES = 64/u);
  assert.match(stager, /st_nlink == 1/u);
  assert.match(stager, /filesystem_mirror/u);
  assert.match(stager, /provider-mirror/u);
  assert.match(stager, /registry\.opentofu\.org\/hashicorp\/aws/u);
  assert.match(stager, /provider_package\(mirror_root, provider_manifest\)/u);
  assert.match(stager, /provider_package_archive\(source, provider_manifest\)/u);
  assert.match(campaign, /verify-provider-package "\$out"/u);
  assert.match(campaign, /provider-package\.tar\.sha256/u);
  assert.doesNotMatch(stager, /dev_overrides/u);
  assert.match(campaign, /role_duration_seconds/u);
  assert.match(campaign, /expires_unix_ns/u);
  assert.match(campaign, /test "\$duration" -ge 16500/u);
  assert.doesNotMatch(campaign, /test "\$duration" -ge 20000/u);
  for (const source of [planning, approval, campaign]) {
    assert.match(source, /&head_sha=\$GITHUB_SHA/u);
    assert.match(source, /\(\[\.\[\]\.total_count\] \| unique\) == \[1\]/u);
  }
  assert.match(providerEntry, /subprocess\.Popen[\s\S]*selectors\.DefaultSelector/u);
  assert.match(providerEntry, /AWS_MAX_ATTEMPTS": "1"/u);
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
