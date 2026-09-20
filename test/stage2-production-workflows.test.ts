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
  assert.match(diagnosticCampaign, /completion_campaign_production\.py completion_campaign_aws_adapter\.py/u);
  assert.match(diagnosticCampaign, /completion_campaign_aws_provider\.py completion_campaign_aws_entry\.py/u);
  assert.match(diagnosticCampaign, /COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1/u);
  assert.match(stager, /identity = adapter\.approval_identity\(\)/u);
  assert.doesNotMatch(campaign, /COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC/u);
  assert.ok(
    diagnosticCampaign.indexOf("stage2-stage-production-approval.py") <
      diagnosticCampaign.indexOf("root=/var/lib/cogs/stage2-completion-v1/source"),
  );
  assert.ok(diagnosticCampaign.indexOf('target="$root/$name"') < diagnosticCampaign.indexOf("Execute seven cycles"));
  assert.match(diagnosticCampaign, /completion_campaign_aws_recovery_entry\.py/u);
  assert.doesNotMatch(diagnosticCampaign, /validate-aws-stage2-completion-evidence/u);
  assert.doesNotMatch(diagnosticCampaign, /aws-stage2-completion-evidence-v[0-9]/u);
  assert.equal((diagnosticCampaign.match(/aws-actions\/configure-aws-credentials@[0-9a-f]{40}/gu) ?? []).length, 2);
  assert.equal((diagnosticCampaign.match(/expiry_s - \$\(date \+%s\) - 900/gu) ?? []).length, 2);
  assert.equal(
    (diagnosticCampaign.match(/timeout-minutes: 10\n {8}uses: aws-actions\/configure-aws-credentials/gu) ?? []).length,
    2,
  );
  assert.match(
    diagnosticCampaign,
    /id: diagnostic_executor_duration[\s\S]*role-duration-seconds: \$\{\{ steps\.diagnostic_executor_duration\.outputs\.role_duration_seconds \}\}/u,
  );
  assert.match(
    diagnosticCampaign,
    /id: diagnostic_observer_duration[\s\S]*role-duration-seconds: \$\{\{ steps\.diagnostic_observer_duration\.outputs\.role_duration_seconds \}\}/u,
  );
  assert.match(diagnosticCampaign, /cogs\.stage2-r-diagnostic-result\/v2/u);
  assert.match(diagnosticCampaign, /NON-AUTHORITATIVE-stage2-r-diagnostic-result/u);
  assert.match(diagnosticCampaign, /test ! -e \/var\/lib\/cogs\/stage2-aws-production-v2\/evidence-publication/u);
  assert.match(diagnosticCampaign, /\.production_evidence_eligible == false/u);
  assert.match(diagnosticCampaign, /\.issue42_closure_eligible == false/u);
  assert.doesNotMatch(diagnosticCampaign, /gh variable set/u);
  assert.doesNotMatch(diagnosticCampaign, /name: stage2-production-evidence-/u);

  const cleanImmutable =
    /\/usr\/bin\/env -i HOME=\/nonexistent LANG=C LC_ALL=C PATH=\/usr\/bin:\/bin TZ=UTC "\s*\n\s*"\/usr\/bin\/python3 -I -B \/var\/lib\/cogs\/stage2-completion-v1\/source\//u;
  assert.match(providerEntry, cleanImmutable);
});

test("budget alert values cross workflow expression boundaries only through step environments", () => {
  for (const [source, expected] of [
    [campaign, 2],
    [diagnosticCampaign, 1],
  ] as const) {
    assert.equal(
      (source.match(/^ {10}BUDGET_ALERT_EMAIL: \$\{\{ vars\.STAGE2_AWS_BUDGET_ALERT_EMAIL \}\}$/gmu) ?? []).length,
      expected,
    );
    assert.equal((source.match(/printf '%s\\n' "\$BUDGET_ALERT_EMAIL"/gu) ?? []).length, expected);
    assert.doesNotMatch(source, /printf[^\n]*\$\{\{ vars\.STAGE2_AWS_BUDGET_ALERT_EMAIL \}\}/u);
  }

  const directory = mkdtempSync(join(tmpdir(), "cogs-stage2-budget-env-"));
  try {
    const output = join(directory, "email");
    const marker = join(directory, "injected");
    const hostile = `owner'; printf injected >"${marker}"; : '@example.invalid`;
    const result = spawnSync("/bin/bash", ["-c", `printf '%s\\n' "$BUDGET_ALERT_EMAIL" >"$OUTPUT"`], {
      encoding: "utf8",
      env: { BUDGET_ALERT_EMAIL: hostile, OUTPUT: output },
    });
    assert.equal(result.status, 0);
    assert.equal(readFileSync(output, "utf8"), `${hostile}\n`);
    assert.throws(() => readFileSync(marker));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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

test("future campaign is exactly two sequential run-bound jobs with fresh credentials", () => {
  assert.match(campaign, /authorize-seven-stage2-production-cycles/u);
  assert.equal((campaign.match(/authorize-seven-stage2-production-cycles/gu) ?? []).length, 1);
  assert.match(campaign, /stage2-production-campaign\.yml\/runs/u);
  assert.match(campaign, /stage2-production-approval\.yml/u);
  assert.match(campaign, /CONTROL_HEAD: \$\{\{ inputs\.control_head \}\}/u);
  assert.match(campaign, /\.control_revision == \$g/u);
  assert.match(campaign, /jobs:\n {2}cycles_1_3:/u);
  assert.match(campaign, /\n {2}cycles_4_7:\n {4}needs: cycles_1_3/u);
  assert.equal((campaign.match(/^ {2}[a-z0-9_]+:\n {4}(?:needs:|runs-on:)/gmu) ?? []).length, 2);
  assert.match(campaign, /timeout-minutes: 300/u);
  assert.match(campaign, /timeout-minutes: 330/u);
  assert.match(campaign, /github\.run_attempt == 1 && needs\.cycles_1_3\.result == 'success'/u);
  assert.doesNotMatch(campaign, /COGS_STAGE2_CAMPAIGN_SEGMENT/u);
  assert.doesNotMatch(campaign, /COGS_STAGE2_CONTINUATION_SHA256=/u);
  assert.match(campaign, /COGS_STAGE2_WORKFLOW_REVISION/u);
  assert.match(campaign, /aws-stage2-production-continuation-admission-v1\.json/u);
  assert.equal((campaign.match(/aws-actions\/configure-aws-credentials@[0-9a-f]{40}/gu) ?? []).length, 4);
  for (const session of ["campaign-s1", "observer-s1", "campaign-s2", "observer-s2"])
    assert.match(campaign, new RegExp(`cogs-stage2-${session}-\\$\\{\\{ github.run_id \\}\\}`, "u"));
  assert.equal((campaign.match(/prepare-stage2-fixed-source\.py/gu) ?? []).length, 2);
  assert.equal((campaign.match(/budgets list-tags-for-resource/gu) ?? []).length, 2);
  assert.match(campaign, /NotFoundException/u);
  assert.match(campaign, /AccessDenied/u);

  assert.match(campaign, /stage2-production-continuation-\$\{\{ github\.sha \}\}-\$\{\{ github\.run_id \}\}-1/u);
  assert.match(campaign, /continuation_upload\.outputs\.artifact-id/u);
  assert.match(campaign, /continuation_upload\.outputs\.artifact-digest/u);
  assert.match(campaign, /\.workflow_run\.id == \$run and \.name == \$name/u);
  assert.match(
    campaign,
    /aws-stage2-production-continuation-v1\.bundle\.json aws-stage2-production-continuation-v1\.json/u,
  );
  assert.match(campaign, /aws-stage2-production-continuation-v1\.bundle\.json/u);
  assert.match(campaign, /CONTINUATION_SHA256/u);
  assert.match(campaign, /AKIA\|ASIA/u);
  assert.match(campaign, /stage2-production-campaign\.yml@refs\/heads\/main/u);
  assert.match(campaign, /stage2-cosign-keyless-sign\.sh[\s\S]*"\$name"/u);
  assert.match(campaign, /stage-continuation \\\n\s+"\$RUNNER_TEMP\/continuation" "\$GITHUB_SHA" "\$GITHUB_RUN_ID"/u);
  assert.match(stager, /def stage_continuation/u);
  assert.match(stager, /adapter\._verify_blob\(\s*verified_continuation, verified_bundle/u);
  assert.match(stager, /mkdtemp\(\s*prefix="\.continuation-verification-", dir=DESTINATION/u);
  assert.doesNotMatch(stager, /adapter\._verify_blob\(continuation_path, bundle_path/u);
  assert.match(stager, /continuation_from_bytes/u);
  assert.match(stager, /os\.environ\.get\("SUDO_UID"\)/u);
  assert.match(stager, /\(item\.lstat\(\)\.st_uid, item\.lstat\(\)\.st_gid\) == caller/u);
  assert.match(stager, /stat\.S_IMODE\(item\.lstat\(\)\.st_mode\) == 0o400/u);
  assert.match(signer, /stage2-production-campaign\.yml@refs\/heads\/main/u);
  assert.match(signer, /aws-stage2-production-continuation-v1/u);

  assert.match(campaign, /effect_deadline_ns == 28800000000000/u);
  assert.match(campaign, /cleanup_reserve_ns == 1800000000000/u);
  assert.match(campaign, /maximum_cycle_duration_ns == 9000000000000/u);
  assert.match(campaign, /maximum_cost_micro_usd == 1100000/u);
  assert.match(campaign, /expires_unix_ns - \.not_before_unix_ns\) == 36000000000000/u);
  assert.match(campaign, /test "\$remaining" -ge 31500/u);
  assert.match(campaign, /test "\$handoff_remaining" -ge 19800/u);
  assert.doesNotMatch(campaign, /steps\.approval_verification\.outputs\.role_duration_seconds/u);

  const roleAssumptions = [
    ["Acquire fresh segment-one executor credentials", "segment_one_executor_duration", 18000, 16200],
    ["Acquire fresh segment-one inventory-observer credentials", "segment_one_observer_duration", 18000, 16200],
    ["Acquire fresh segment-two executor credentials", "segment_two_executor_duration", 19800, 18000],
    ["Acquire fresh segment-two inventory-observer credentials", "segment_two_observer_duration", 19800, 18000],
  ] as const;
  assert.equal((campaign.match(/^ {8}id: segment_(?:one|two)_(?:executor|observer)_duration$/gmu) ?? []).length, 4);
  for (const [name, id, cap, segmentMinimum] of roleAssumptions) {
    const actionMarker = `      - name: ${name}\n        timeout-minutes: 10\n        uses: aws-actions/configure-aws-credentials@`;
    const actionAt = campaign.indexOf(actionMarker);
    assert.ok(actionAt >= 0, name);
    const priorStepAt = campaign.lastIndexOf("\n      - name: ", actionAt - 2);
    const derivation = campaign.slice(priorStepAt, actionAt);
    assert.match(derivation, new RegExp(`id: ${id}`, "u"), name);
    assert.match(derivation, /expires_unix_ns/u, name);
    assert.match(derivation, /now_s=\$\(date \+%s\)/u, name);
    assert.match(derivation, / - now_s - 900 \)\)/u, name);
    assert.match(derivation, new RegExp(`cap=${cap}`, "u"), name);
    assert.match(derivation, new RegExp(`segment_min=${segmentMinimum}`, "u"), name);
    assert.match(derivation, /if \(\( duration > cap \)\); then duration="\$cap"; fi/u, name);
    assert.match(derivation, /test "\$duration" -ge "\$segment_min"/u, name);
    assert.match(derivation, /test "\$duration" -le "\$remaining"/u, name);
    const actionEnd = campaign.indexOf("\n      - name: ", actionAt + actionMarker.length);
    const action = campaign.slice(actionAt, actionEnd);
    assert.match(
      action,
      new RegExp(`role-duration-seconds: \\$\\{\\{ steps\\.${id}\\.outputs\\.role_duration_seconds \\}\\}`, "u"),
      name,
    );
    assert.match(action, /timeout-minutes: 10/u, name);
  }

  const firstJob = campaign.slice(campaign.indexOf("  cycles_1_3:"), campaign.indexOf("  cycles_4_7:"));
  const secondJob = campaign.slice(campaign.indexOf("  cycles_4_7:"));
  assert.equal((campaign.match(/os\.O_EXCL/gu) ?? []).length, 2);
  assert.ok(firstJob.indexOf("os.O_EXCL") < firstJob.indexOf("authorize-seven-stage2-production-cycles"));
  assert.ok(secondJob.indexOf("os.O_EXCL") < secondJob.indexOf('test "$GITHUB_REPOSITORY"'));
  for (const [job, jobMinutes, campaignMinutes] of [
    [firstJob, 300, 240],
    [secondJob, 330, 270],
  ] as const) {
    assert.match(job, new RegExp(`timeout-minutes: ${campaignMinutes}`, "u"));
    assert.match(job, new RegExp(`job_deadline=\\$\\(\\( job_start \\+ \\(${jobMinutes} - 31\\) \\* 60 \\)\\)`, "u"));
    assert.match(job, /remaining=\$\(\( job_deadline - now_s \)\)/u);
    assert.match(job, /test "\$remaining" -gt 0/u);
    assert.match(job, /\/usr\/bin\/timeout --signal=TERM --kill-after=10s "\$remaining"s sudo -n/u);
    assert.match(job, /\|\| campaign_status=\$\?[\s\S]*exit "\$campaign_status"/u);
    assert.ok((jobMinutes - 31) * 60 + 10 + 30 * 60 < jobMinutes * 60);
  }

  const signerAt = firstJob.indexOf("scripts/stage2-cosign-keyless-sign.sh");
  const readbackAt = firstJob.indexOf("Byte-compare continuation readback");
  const oidcRetirementAt = firstJob.indexOf("Retire job-one OIDC request environment after continuation custody");
  assert.ok(signerAt >= 0 && readbackAt > signerAt && oidcRetirementAt > readbackAt);
  assert.doesNotMatch(firstJob.slice(0, signerAt), /ACTIONS_ID_TOKEN_REQUEST_TOKEN=\\n/u);
  assert.match(firstJob.slice(oidcRetirementAt), /ACTIONS_ID_TOKEN_REQUEST_TOKEN=\\nACTIONS_ID_TOKEN_REQUEST_URL=\\n/u);

  assert.match(campaign, /stage2-stage-production-approval\.py/u);
  assert.match(campaign, /run-production-campaign\.sh/u);
  assert.match(campaign, /recover-production-campaign-entry\.sh/u);
  assert.match(campaign, /evidence_upload\.outputs\.artifact-id/u);
  assert.match(campaign, /diff -r --no-dereference/u);
  assert.match(campaign, /production-evidence-upload-receipt\/v3/u);
  assert.equal((campaign.match(/validate-aws-stage2-completion-evidence-v4\.ts --package/gu) ?? []).length, 2);
  assert.equal(
    (campaign.match(/\/usr\/bin\/unshare --net -- "\$RUNNER_TEMP\/approval\/cosign" verify-blob/gu) ?? []).length,
    2,
  );
  assert.ok(
    campaign.indexOf('validate-aws-stage2-completion-evidence-v4.ts --package "$destination"') <
      campaign.indexOf("Upload pass-only canonical evidence after credential retirement"),
  );
  assert.match(campaign, /aws-stage2-completion-evidence-v4\.json/u);
  assert.match(campaign, /aws-stage2-completion-publication-v2\.json/u);
  assert.match(
    campaign,
    /Stage pass-only canonical evidence[\s\S]*test ! -e \/var\/lib\/cogs\/stage2-aws-production-v2\/aws-credentials/u,
  );
  assert.doesNotMatch(campaign, /continue-on-error:\s*true/u);
  assert.doesNotMatch(`${planning}\n${approval}\n${campaign}`, /\.\[\]\[\]/u);

  assert.match(stager, /aws-credentials/u);
  assert.match(stager, /ASIA\[A-Z0-9\]/u);
  assert.match(stager, /"\/usr\/bin\/unshare", "--net"/u);
  assert.match(stager, /cogs\.stage2-opentofu-provider-package\/v1/u);
  assert.match(stager, /PACKAGE_MAX_FILES = 64/u);
  assert.match(stager, /st_nlink == 1/u);
  assert.match(stager, /filesystem_mirror/u);
  assert.match(stager, /provider_package_archive\(source, provider_manifest\)/u);
  assert.equal(campaign.match(/verify-provider-package "\$out"/gu)?.length, 2);
  assert.doesNotMatch(stager, /dev_overrides/u);
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
  assert.match(stager, /stage2-revision-retirement\.py/u);
  assert.ok(
    stager.indexOf('eligible((value.get("implementation_revision")') < stager.indexOf("aws_credentials = read"),
  );
});
