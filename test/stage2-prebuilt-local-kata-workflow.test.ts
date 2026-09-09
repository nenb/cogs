import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(".github/workflows/stage2-prebuilt-local-kata-qualification.yml", "utf8");
const guard = readFileSync("scripts/stage2-prebuilt-local-qualification-guard.py", "utf8");
const qualifier = readFileSync("scripts/stage2-formal-local-qualification.py", "utf8");
const preflightWorkflow = readFileSync(".github/workflows/stage2-prebuilt-mixed-hg-preflight.yml", "utf8");
const preflight = readFileSync("scripts/stage2-prebuilt-mixed-hg-preflight.sh", "utf8");
const staging = readFileSync("scripts/stage2-stage-prebuilt-control.py", "utf8");

test("formal qualification is additive, exact H/G/Q, first-created, and seven fresh jobs", () => {
  assert.match(workflow, /\n {2}local-kata:\n {4}needs: admission\n {4}strategy:/u);
  assert.match(workflow, /ordinal: \[1, 2, 3, 4, 5, 6, 7\]/u);
  assert.match(workflow, /max-parallel: 7/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /FORMAL_CYCLE_ORDINAL: \$\{\{ matrix\.ordinal \}\}/u);
  assert.match(workflow, /timeout-minutes: 210/u);
  assert.match(workflow, /id: preparation\n {8}timeout-minutes: 35/u);
  const local = workflow.slice(workflow.indexOf("  local-kata:"), workflow.indexOf("  aggregate:"));
  const localStepMinutes = [...local.matchAll(/^ {8}timeout-minutes: (\d+)$/gmu)].reduce(
    (total, match) => total + Number(match[1]),
    0,
  );
  assert.ok(localStepMinutes <= 198, `local step bounds ${localStepMinutes}`);
  assert.ok(75 + 5 + 75 + 5 + 1770 + 10 <= 35 * 60);
  assert.ok(7800 + 10 <= 132 * 60);
  assert.match(workflow, /^name: Stage 2 prebuilt local Kata qualification$/mu);
  assert.match(workflow, /stage2-prebuilt-local-kata-qualification\.yml\/runs/u);
  assert.match(workflow, /mixed_preflight_run_id/u);
  assert.match(workflow, /stage2-prebuilt-mixed-hg-preflight\.yml/u);
  assert.match(workflow, /\.conclusion == "success"/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(
    workflow,
    /select\(\.head_sha == \$q and\s*\.path == "\.github\/workflows\/stage2-prebuilt-local-kata-qualification\.yml"\)/u,
  );
  assert.doesNotMatch(workflow, /stage2-prebuilt-local-kata-qualification\.yml\/runs\?[^'\n]*branch=/u);
  assert.doesNotMatch(workflow, /\.head_sha == \$q and \.display_title/u);
  assert.match(
    preflightWorkflow,
    /select\(\.head_sha == \$q and\s*\.path == "\.github\/workflows\/stage2-prebuilt-mixed-hg-preflight\.yml"\)/u,
  );
  assert.doesNotMatch(preflightWorkflow, /stage2-prebuilt-mixed-hg-preflight\.yml\/runs\?[^'\n]*branch=/u);
  assert.doesNotMatch(preflightWorkflow, /\.head_sha == \$q and \.display_title/u);
  assert.match(workflow, /reviewed_qualification_head/u);
  assert.match(workflow, /CONFIGURED_QUALIFICATION_HEAD: \$\{\{ vars\.STAGE2_LOCAL_QUALIFICATION_HEAD \}\}/u);
  assert.match(workflow, /qualification-commit\.json/u);
  assert.match(workflow, /\(\.parents \| map\(\.sha\)\) == \[\$g\]/u);
  assert.match(workflow, /fetch --quiet --no-tags --depth=2 origin "\$EXACT_QUALIFICATION_HEAD"/u);
  assert.match(workflow, /rev-parse HEAD\^\)" = "\$EXACT_CONTROL_HEAD"/u);
  assert.match(workflow, /Independently authenticate exact final H, G, and Q for this ordinal/u);
  assert.match(workflow, /stage2-prebuilt-local-qualification-guard\.py/u);
  assert.match(workflow, /stage2-stage-prebuilt-control\.py/u);
  for (const source of [staging, guard, qualifier]) {
    assert.match(source, /stage2-completion-local-control-v6/u);
    assert.doesNotMatch(source, /stage2-completion-local-control-v5/u);
  }
  assert.match(staging, /def verify_staged\(expected_descriptor, diagnostic=False\)/u);
  assert.match(staging, /except Exception:\n {8}raise SystemExit\(2\) from None/u);
  assert.match(guard, /Reviewed directional binding/u);
  assert.match(guard, /REVIEWED_IMPLEMENTATION_HEAD = "c30e0d69ec374cd812ff361e670e974d51b661c4"/u);
  assert.match(guard, /REVIEWED_CONTROL_HEAD = "15d99b55f4910df94decdd7edcc80bf95aee492d"/u);
  assert.match(
    guard,
    /REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "a5ebebaf515805f65bb2ff7c4ffa79ff1506ee8859e5257763c98dd00114503f"/u,
  );
  assert.match(guard, /REVIEWED_CONTROL_SHA256 = "83a9c5d15705406961b357963312fdea132757dd19d51c15c0ae6a082173bb7e"/u);
  assert.match(guard, /REVIEWED_WORKFLOW_SHA256 = "2ba561203f87f4bb2caa7c3924d463cb7368702bb5514cb4a277c360908fdaa8"/u);
  assert.equal(
    /REVIEWED_RESULT_SCHEMA_SHA256 = "([0-9a-f]{64})"/u.exec(guard)?.[1],
    createHash("sha256").update(readFileSync("schemas/stage2-formal-local-cycle-receipt-v2.json")).digest("hex"),
  );
  assert.match(
    guard,
    /REVIEWED_ROOTFS_DESCRIPTOR_SHA256 = "3ab1238a7424a400f6ad306611218f4434190d7ae040c6bd5acb31b91b1d81a1"/u,
  );
  assert.match(guard, /REVIEWED_STATIC_CONTROL_RUN_ID = 34403562378/u);
  assert.match(guard, /REVIEWED_STATIC_CONTROL_ARTIFACT_ID = 10124443866/u);
  assert.match(
    guard,
    /REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST = "sha256:06c3067a3c0a48672c5832404c66e61773a947abdae30e038d113cfc6e08d6c2"/u,
  );
  assert.match(preflight, /H=c30e0d69ec374cd812ff361e670e974d51b661c4/u);
  assert.match(preflight, /G=15d99b55f4910df94decdd7edcc80bf95aee492d/u);
  assert.match(preflight, /MANIFEST=a5ebebaf515805f65bb2ff7c4ffa79ff1506ee8859e5257763c98dd00114503f/u);
  assert.match(preflight, /CONTROL=83a9c5d15705406961b357963312fdea132757dd19d51c15c0ae6a082173bb7e/u);
  assert.match(preflight, /DESCRIPTOR=3ab1238a7424a400f6ad306611218f4434190d7ae040c6bd5acb31b91b1d81a1/u);
  assert.match(guard, /control\["producer"\]\["control_revision"\] == REVIEWED_CONTROL_HEAD/u);
  assert.match(guard, /_authenticate_control\(\)/u);
  assert.ok(
    workflow.indexOf("scripts/stage2-prebuilt-local-qualification-guard.py") <
      workflow.indexOf("Acquire exact reviewed implementation revision H separately"),
  );
  assert.match(guard, /"qualification_head": qualification/u);
});

test("each job prepares one rootfs, executes one mode-bound lifecycle, and closes custody", () => {
  const preparation = workflow.indexOf("Complete exact immutable preparation before KVM eligibility and role custody");
  const entry = workflow.indexOf("Execute exactly one ordinal-bound formal cycle");
  assert.ok(preparation > 0 && entry > preparation);
  const beforeEntry = workflow.slice(preparation, entry);
  assert.match(beforeEntry, /"rootfs_artifact_count":1/u);
  assert.match(beforeEntry, /"runtime_archive_count":2/u);
  assert.match(beforeEntry, /completion_kata_immutable_preparation\.py/u);
  assert.match(
    beforeEntry,
    /sudo -n env -i PATH=\/usr\/bin:\/bin \/usr\/bin\/python3 -I -B[\s\S]*stage2-stage-prebuilt-control\.py verify/u,
  );
  assert.equal(beforeEntry.split("scripts/stage2-stage-prebuilt-control.py verify").length - 1, 1);
  assert.doesNotMatch(beforeEntry, /descriptor=\$\(\/usr\/bin\/python3/u);
  assert.match(beforeEntry, /non-cloud formal grant/u);
  assert.match(workflow, /1\) entry=completion_formal_cycle_full\.py/u);
  assert.match(workflow, /2\|3\|4\|5\|6\|7\) entry=completion_formal_cycle_readiness\.py/u);
  assert.match(workflow, /Invoke cleanup-only recovery after every cycle outcome/u);
  assert.match(workflow, /Independently prove zero lifecycle residue after cleanup/u);
  assert.match(workflow, /supervise-final/u);
  for (const id of ["fixed_cleanup", "independent_residue", "final_observation"]) {
    assert.ok(workflow.includes(`id: ${id}\n        if: always() && steps.gate.outcome == 'success'`));
  }
  assert.doesNotMatch(workflow, /aws-actions|opentofu|terraform|\bsts\b|\bssm\b/u);
});

test("aggregation is exact, artifact-complete, attempt-one, and non-AWS only", () => {
  assert.match(
    workflow,
    /needs: \[admission, local-kata\]\n {4}if: always\(\) && needs\.admission\.result == 'success'/u,
  );
  assert.match(workflow, /Materialize authenticated exact custody for all seven cycle uploads/u);
  assert.match(workflow, /actions\/runs\/\$GITHUB_RUN_ID\/artifacts\?per_page=100/u);
  assert.match(workflow, /Download all seven cycle artifacts by exact numeric IDs/u);
  assert.match(workflow, /artifact-ids: \$\{\{ steps\.cycle_custody\.outputs\.artifact_ids \}\}/u);
  assert.doesNotMatch(workflow, /pattern: stage2-formal-cycle/u);
  assert.match(workflow, /merge-multiple: true/u);
  assert.match(workflow, /CYCLE_ARTIFACT_DIGEST: \$\{\{ steps\.cycle_upload\.outputs\.artifact-digest \}\}/u);
  assert.match(workflow, /CYCLE_JOB_RESULT: \$\{\{ needs\.local-kata\.result \}\}/u);
  assert.match(workflow, /test "\$CYCLE_JOB_RESULT" = success/u);
  assert.match(qualifier, /pre-aws-package-v5\.json/u);
  assert.doesNotMatch(workflow, /pre-aws-package-v4\.json|\.py aggregate\s*>/u);
  assert.match(workflow, /stage2-formal-local-qualification\.py publish-package\n/u);
  assert.match(workflow, /stage2-formal-local-qualification\.py package-readback\n/u);
  const publication = workflow.slice(workflow.indexOf("id: package_create"), workflow.indexOf("id: package_upload"));
  assert.match(
    publication,
    /sudo -n env -i PATH=\/usr\/bin:\/bin[\s\S]*stage2-formal-local-qualification\.py publish-package/u,
  );
  assert.doesNotMatch(publication, /install |mkdir |\s>\s*"?\$PACKAGE_STAGING/u);
  assert.match(workflow, /id: package_upload\n {8}if: always\(\) && steps\.package_create\.outcome == 'success'/u);
  const aggregateCleanup = workflow.slice(
    workflow.indexOf("id: aggregate_cleanup"),
    workflow.indexOf("Enforce complete aggregate custody and cleanup"),
  );
  assert.match(aggregateCleanup, /sudo -n chmod 0700 "\$PACKAGE_STAGING"/u);
  assert.match(aggregateCleanup, /sudo -n rm -rf -- "\$CYCLE_AGGREGATE_ROOT"/u);
  assert.match(workflow, /mixed_preflight_run_id/u);
  assert.match(workflow, /EXPECTED_STATIC_CONTROL_ARTIFACT_DIGEST/u);
  assert.equal(workflow.match(/retention-days: 90/gu)?.length, 2);
  assert.match(workflow, /printf 'netns_intent=true\\n' >>"\$GITHUB_OUTPUT"[\s\S]*mkdir -m 0755 \/run\/netns/u);
  assert.match(workflow, /printf 'netns_acquired=true\\n' >>"\$GITHUB_OUTPUT"/u);
  assert.match(workflow, /printf 'opt_original_mode=777\\n' >>"\$GITHUB_OUTPUT"/u);
  const scaffoldRestore = workflow.slice(
    workflow.indexOf("Restore only hosted scaffolding acquired by this run"),
    workflow.indexOf("Run one final supervised cycle residue observation"),
  );
  assert.match(scaffoldRestore, /NETNS_INTENT: \$\{\{ steps\.preparation\.outputs\.netns_intent \}\}/u);
  assert.match(scaffoldRestore, /NETNS_ACQUIRED: \$\{\{ steps\.preparation\.outputs\.netns_acquired \}\}/u);
  assert.match(scaffoldRestore, /if test "\$NETNS_ACQUIRED" = true; then[\s\S]*rmdir \/run\/netns/u);
  assert.doesNotMatch(workflow, /\.cogs-stage2-owner-/u);
  assert.match(scaffoldRestore, /test ! -e \/run\/netns && sudo -n \/usr\/bin\/test ! -L \/run\/netns/u);
  assert.match(scaffoldRestore, /if test "\$OPT_ORIGINAL_MODE" = 777; then[\s\S]*chmod 0777 \/opt/u);
  assert.match(workflow, /Byte-compare package and fail closed/u);
  assert.match(qualifier, /cycle-artifact-custody-v2\.json/u);
  assert.match(workflow, /PACKAGE_ARTIFACT_DIGEST.*artifact-digest/u);
  assert.match(workflow, /\[\[ "\$PACKAGE_ARTIFACT_DIGEST" =~ \^\[0-9a-f\]\{64\}\$ \]\]/u);
  assert.match(
    workflow,
    /id: package_readback[\s\S]*?id: aggregate_cleanup[\s\S]*?Enforce complete aggregate custody and cleanup/u,
  );
  assert.match(workflow, /id: aggregate_cleanup\n {8}if: always\(\)/u);
  assert.match(workflow, /timeout-minutes: 25/u);
  const aggregate = workflow.slice(workflow.indexOf("  aggregate:"));
  const aggregateStepMinutes = [...aggregate.matchAll(/^ {8}timeout-minutes: (\d+)$/gmu)].reduce(
    (total, match) => total + Number(match[1]),
    0,
  );
  assert.ok(aggregateStepMinutes <= 20, `aggregate step bounds ${aggregateStepMinutes}`);
  assert.match(workflow, /FINAL_OBSERVATION: \$\{\{ steps\.final_observation\.outcome \}\}/u);
  assert.match(workflow, /"\$FINAL_OBSERVATION"/u);
  assert.match(workflow, /"\$PACKAGE_DOWNLOAD" "\$READBACK" "\$CLEANUP"/u);
  assert.ok(Buffer.byteLength(workflow) < 94_000);
});

test("retired preflight admission preserves the independent cleanup-only dispatch", () => {
  const admission = preflight
    .slice(preflight.indexOf("admit() {"), preflight.indexOf("acquire_h() {"))
    .replace(`\${BASH_SOURCE[0]%/*}`, `${process.cwd()}/scripts`);
  const cleanup = preflight.slice(preflight.indexOf("settle() {"), preflight.indexOf('test "$#" -eq 1'));
  assert.doesNotMatch(cleanup, /retirement/u);
  const tail = preflight.slice(preflight.indexOf('test "$#" -eq 1'));
  const result = spawnSync(
    "bash",
    [
      "-c",
      `${admission}\nH=8907eba3191d07573cd84573cb0b2adddff17bd6\nG=${"b".repeat(40)}\nphase() { :; }\nsettle() { printf cleanup; }\nacquire_h() { printf EFFECT; }\nprepare() { printf EFFECT; }\n${tail}`,
      "scripts/test-entry",
      "run",
    ],
    {
      encoding: "utf8",
      timeout: 5000,
    },
  );
  assert.equal(result.status, 2);
  assert.equal(result.stderr, "");
  assert.equal(result.stdout, "cleanup");
  const settle = spawnSync(
    "bash",
    ["-c", `admit() { printf EFFECT; return 2; }\nsettle() { printf cleanup; }\n${tail}`, "test-entry", "settle"],
    { encoding: "utf8" },
  );
  assert.equal(settle.status, 0);
  assert.equal(settle.stdout, "cleanup");
});

test("corrected mixed preflight remains no-KVM, H/G/Q-bound, and versioned", () => {
  assert.match(preflightWorkflow, /^name: Stage 2 exact mixed H-G-Q no-KVM preflight$/mu);
  assert.match(preflightWorkflow, /qualification_head/u);
  assert.match(preflightWorkflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(
    preflightWorkflow,
    /rev-list --parents -n1 "\$EXACT_CONTROL_HEAD"\)" = "\$EXACT_CONTROL_HEAD \$EXACT_IMPLEMENTATION_HEAD"/u,
  );
  const normalization = preflightWorkflow.indexOf(
    "Normalize the exact hosted opt scaffold before immutable preparation",
  );
  const execution = preflightWorkflow.indexOf(
    "Execute exact mixed H-G preparation and mandatory settlement without KVM",
  );
  const settlement = preflightWorkflow.indexOf("Independently repeat mandatory settlement after every outcome");
  const restoration = preflightWorkflow.indexOf("Restore the exact acquired hosted opt scaffold only after settlement");
  assert.ok(normalization > 0 && execution > normalization && settlement > execution && restoration > settlement);
  const normalized = preflightWorkflow.slice(normalization, execution);
  assert.match(normalized, /test ! -e \/opt\/kata && test ! -L \/opt\/kata/u);
  assert.match(normalized, /stat -c '%U:%G:%a' \/opt\)" = root:root:777/u);
  assert.match(normalized, /sudo -n \/bin\/chmod 0755 \/opt/u);
  assert.match(normalized, /stat -c '%U:%G:%a' \/opt\)" = root:root:755/u);
  assert.match(preflightWorkflow.slice(settlement, restoration), /if: always\(\)/u);
  const restored = preflightWorkflow.slice(restoration);
  assert.match(restored, /if: always\(\)/u);
  assert.match(restored, /OPT_ORIGINAL_MODE: \$\{\{ steps\.opt_scaffold\.outputs\.opt_original_mode \}\}/u);
  assert.match(restored, /if test "\$OPT_ORIGINAL_MODE" = 777; then/u);
  assert.match(restored, /test ! -e \/opt\/kata && test ! -L \/opt\/kata/u);
  assert.match(restored, /root:root:755\) sudo -n \/bin\/chmod 0777 \/opt/u);
  assert.match(restored, /\*\) exit 1/u);
  assert.match(restored, /stat -c '%U:%G:%a' \/opt\)" = root:root:777/u);
  assert.match(
    preflightWorkflow,
    /rev-list --parents -n1 "\$EXACT_QUALIFICATION_HEAD"\)" = "\$EXACT_QUALIFICATION_HEAD \$EXACT_CONTROL_HEAD"/u,
  );
  assert.match(preflight, /stage2-local-immutable-preparation\/v2/u);
  assert.match(preflight, /EXACT_QUALIFICATION_HEAD/u);
  assert.match(preflight, /rootfs_artifact_count/u);
  assert.match(preflight, /stage2-stage-prebuilt-control\.py" verify "\$DESCRIPTOR"/u);
  assert.equal(preflight.split('stage2-stage-prebuilt-control.py" verify "$DESCRIPTOR"').length - 1, 1);
  assert.doesNotMatch(preflight, /\/dev\/kvm|completion_local_full/u);
});
