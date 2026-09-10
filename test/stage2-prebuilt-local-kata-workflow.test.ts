import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const workflow = readFileSync(".github/workflows/stage2-prebuilt-local-kata-qualification.yml", "utf8");
const guard = readFileSync("scripts/stage2-prebuilt-local-qualification-guard.py", "utf8");
const qualifier = readFileSync("scripts/stage2-formal-local-qualification.py", "utf8");
const preflightWorkflow = readFileSync(".github/workflows/stage2-prebuilt-mixed-hg-preflight.yml", "utf8");
const preflight = readFileSync("scripts/stage2-prebuilt-mixed-hg-preflight.sh", "utf8");
const staging = readFileSync("scripts/stage2-stage-prebuilt-control.py", "utf8");
const imageGate = `if test "\${ImageOS-}" != ubuntu24 || test "\${ImageVersion-}" != 20260907.300.1; then
            /usr/bin/printf '%s\\n' 'stage2.runner-image.rejected' >&2
            exit 2
          fi`;

test("runner image admission is exact on preflight and all nine formal runners", () => {
  assert.equal(preflightWorkflow.split(imageGate).length - 1, 1);
  assert.equal(workflow.split(imageGate).length - 1, 3);
  const admission = workflow.slice(workflow.indexOf("  admission:"), workflow.indexOf("  local-kata:"));
  const local = workflow.slice(workflow.indexOf("  local-kata:"), workflow.indexOf("  aggregate:"));
  const aggregate = workflow.slice(workflow.indexOf("  aggregate:"));
  for (const block of [admission, local, aggregate]) assert.ok(block.includes(imageGate));
  assert.ok(preflightWorkflow.indexOf(imageGate) < preflightWorkflow.indexOf("gh api --paginate"));
  assert.ok(local.indexOf(imageGate) < local.indexOf("git init --quiet"));
  assert.ok(aggregate.indexOf(imageGate) < aggregate.indexOf("git init --quiet"));
  for (const [os, version, status] of [
    ["ubuntu24", "20260907.300.1", 0],
    ["ubuntu24", "20260831.293.1", 2],
    ["ubuntu-24.04", "20260907.300.1", 2],
    ["ubuntu24", "20260907.300", 2],
    ["", "20260907.300.1", 2],
    ["ubuntu24", "$(printf injected)", 2],
  ] as const) {
    const result = spawnSync(
      "bash",
      ["--noprofile", "--norc", "-c", `set -euo pipefail\n${imageGate}\nprintf ADMITTED`],
      {
        encoding: "utf8",
        env: { ImageOS: os, ImageVersion: version },
      },
    );
    assert.equal(result.status, status);
    assert.equal(result.stdout, status === 0 ? "ADMITTED" : "");
    assert.equal(result.stderr, status === 0 ? "" : "stage2.runner-image.rejected\n");
  }
  for (const env of [{ ImageOS: "ubuntu24" }, { ImageVersion: "20260907.300.1" }, {}]) {
    const result = spawnSync("bash", ["--noprofile", "--norc", "-c", `${imageGate}\nprintf ADMITTED`], {
      encoding: "utf8",
      env,
    });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
  }
  assert.match(local, /stage2-stage-prebuilt-control\.py[\s\S]{0,120}verify-host/u);
  assert.match(preflightWorkflow, /Compare every ambient host closure before mutation/u);
  assert.match(preflightWorkflow, /steps\.opt_scaffold\.outcome == 'success'/u);
});

test("mixed host-check wrapper preserves exact status and output in its sanitized environment", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-host-check-"));
  const scripts = join(temporary, "qualification", "scripts");
  mkdirSync(scripts, { recursive: true });
  const helper = join(scripts, "stage2-stage-prebuilt-control.py");
  const run = (body: string) => {
    writeFileSync(helper, body, { mode: 0o600 });
    return spawnSync("/bin/bash", ["scripts/stage2-prebuilt-mixed-hg-preflight.sh", "host-check"], {
      encoding: "utf8",
      env: { GITHUB_WORKSPACE: temporary, GITHUB_RUN_ID: "7", GITHUB_RUN_ATTEMPT: "1" },
    });
  };
  try {
    const pass = run('print("host_closure_verified=true")\n');
    assert.equal(pass.status, 0);
    assert.equal(pass.stdout, "host_closure_verified=true\n");
    assert.equal(pass.stderr, "");
    for (const body of ["raise SystemExit(2)\n", 'print("host_closure_verified=true")\nraise SystemExit(2)\n']) {
      const rejected = run(body);
      assert.equal(rejected.status, 2);
      assert.equal(rejected.stdout, "");
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

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
  assert.ok(localStepMinutes <= 201, `local step bounds ${localStepMinutes}`);
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
    assert.match(source, /stage2-completion-local-control-v7/u);
    assert.doesNotMatch(source, /stage2-completion-local-control-v6/u);
  }
  assert.match(staging, /def verify_staged\(expected_descriptor, diagnostic=False\)/u);
  assert.match(staging, /except Exception:\n {8}raise SystemExit\(2\) from None/u);
  assert.match(guard, /Reviewed directional binding/u);
  assert.match(guard, /REVIEWED_IMPLEMENTATION_HEAD = "11c03441468d4c3130667321018e1cb6f626a303"/u);
  assert.match(guard, /REVIEWED_CONTROL_HEAD = "a9b54c1a823601c3e938e2a616abd0222c0a2846"/u);
  assert.match(
    guard,
    /REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "e2e092bd14161425aacaead2abbe1eb41de50c2f78fdea3d6fffdcaf6711115f"/u,
  );
  assert.match(guard, /REVIEWED_CONTROL_SHA256 = "b568b71d04002303edd77f5925e81ffb6c29f2259274ef544de1a4a478a8132d"/u);
  assert.equal(
    /REVIEWED_WORKFLOW_SHA256 = "([0-9a-f]{64})"/u.exec(guard)?.[1],
    createHash("sha256").update(workflow).digest("hex"),
  );
  assert.equal(
    /REVIEWED_RESULT_SCHEMA_SHA256 = "([0-9a-f]{64})"/u.exec(guard)?.[1],
    createHash("sha256").update(readFileSync("schemas/stage2-formal-local-cycle-receipt-v2.json")).digest("hex"),
  );
  assert.match(
    guard,
    /REVIEWED_ROOTFS_DESCRIPTOR_SHA256 = "7e060278933ff79d0b9b40138afbf8bb9e799e6a2951b9c0c021f63069ebf71b"/u,
  );
  assert.match(guard, /REVIEWED_STATIC_CONTROL_RUN_ID = 34486733842/u);
  assert.match(guard, /REVIEWED_STATIC_CONTROL_ARTIFACT_ID = 10155984475/u);
  assert.match(
    guard,
    /REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST = "sha256:4229c9a8acd3f54992edb39a7ccdcda0c5c23a53691e93e16cbe956fc253a068"/u,
  );
  assert.match(preflight, /H=11c03441468d4c3130667321018e1cb6f626a303/u);
  assert.match(preflight, /G=a9b54c1a823601c3e938e2a616abd0222c0a2846/u);
  assert.match(preflight, /MANIFEST=e2e092bd14161425aacaead2abbe1eb41de50c2f78fdea3d6fffdcaf6711115f/u);
  assert.match(preflight, /CONTROL=b568b71d04002303edd77f5925e81ffb6c29f2259274ef544de1a4a478a8132d/u);
  assert.match(preflight, /DESCRIPTOR=7e060278933ff79d0b9b40138afbf8bb9e799e6a2951b9c0c021f63069ebf71b/u);
  assert.match(guard, /control\["producer"\]\["control_revision"\] == REVIEWED_CONTROL_HEAD/u);
  assert.match(guard, /_authenticate_control\(\)/u);
  assert.ok(
    workflow.indexOf("scripts/stage2-prebuilt-local-qualification-guard.py") <
      workflow.indexOf("Acquire exact reviewed implementation revision H separately"),
  );
  assert.match(guard, /"qualification_head": qualification/u);
});

test("checked-in v7 authenticates with the unmocked Q guard and H control codec", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import runpy,sys
from pathlib import Path
root=Path.cwd()
package=root/'deploy/aws-feasibility/remote/stage2-completion-local-control-v7'
sys.path.insert(0,str(root/'deploy/aws-feasibility/remote'))
import completion_kata_preparation as codec
guard=runpy.run_path('scripts/stage2-prebuilt-local-qualification-guard.py')
guard['_reviewed_constants']()
guard['_authenticate_control']()
control_raw=(package/'stage2-local-static-control-v2.json').read_bytes()
control=codec.load_control(control_raw)
members={row['name']:(package/row['name']).read_bytes() for row in control.value['members']}
envelope,runtime,contracts=codec.validate_control_members(control,members)
assert envelope.value['implementation']['revision']==guard['REVIEWED_IMPLEMENTATION_HEAD']
assert envelope.value['control_revision']==guard['REVIEWED_CONTROL_HEAD']
assert envelope.value['rootfs']['prebuilt_descriptor_sha256']==guard['REVIEWED_ROOTFS_DESCRIPTOR_SHA256']
assert len(contracts)==10 and len(runtime.value['executables'])==10
`,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(result.status, 0, result.stderr);
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
  assert.equal(beforeEntry.split('scripts/stage2-stage-prebuilt-control.py verify "').length - 1, 1);
  assert.doesNotMatch(beforeEntry, /descriptor=\$\(\/usr\/bin\/python3/u);
  assert.match(beforeEntry, /non-cloud formal grant/u);
  assert.match(workflow, /1\) entry=completion_formal_cycle_full\.py/u);
  assert.match(workflow, /2\|3\|4\|5\|6\|7\) entry=completion_formal_cycle_readiness\.py/u);
  assert.match(workflow, /Invoke cleanup-only recovery after every cycle outcome/u);
  assert.match(workflow, /id: recovery\n {8}if: always\(\) && steps\.preparation\.outputs\.source_acquired == 'true'/u);
  assert.match(workflow, /Independently prove zero lifecycle residue after cleanup/u);
  assert.match(workflow, /supervise-final/u);
  for (const id of ["fixed_cleanup", "independent_residue", "final_observation"]) {
    assert.ok(workflow.includes(`id: ${id}\n        if: always() && steps.recovery.outcome != 'skipped'`));
  }
  assert.match(
    workflow,
    /id: output_cleanup\n {8}if: always\(\) && steps\.local_entry\.outputs\.output_intent == 'true'/u,
  );
  assert.match(workflow, /id: host_scaffold_restore\n {8}if: always\(\) && steps\.opt_scaffold\.outcome != 'skipped'/u);
  assert.doesNotMatch(workflow, /aws-actions|opentofu|terraform|\bsts\b|\bssm\b/u);
});

test("aggregation is exact, artifact-complete, attempt-one, and non-AWS only", () => {
  assert.match(
    workflow,
    /needs: \[admission, local-kata\]\n {4}if: always\(\) && needs\.admission\.result == 'success'/u,
  );
  assert.ok(
    workflow.indexOf("Admit absent aggregate paths before custody work") <
      workflow.indexOf("Materialize authenticated exact custody for all seven cycle uploads"),
  );
  assert.match(workflow, /id: cycle_custody\n {8}if: always\(\)[^\n]*steps\.aggregate_baseline\.outcome == 'success'/u);
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
  assert.match(workflow, /stage2-hosted-opt-mode\.py normalize "\$GITHUB_RUN_ID" "\$GITHUB_RUN_ATTEMPT"/u);
  const scaffoldRestore = workflow.slice(
    workflow.indexOf("Restore only hosted scaffolding acquired by this run"),
    workflow.indexOf("Run one final supervised cycle residue observation"),
  );
  assert.match(scaffoldRestore, /NETNS_INTENT: \$\{\{ steps\.preparation\.outputs\.netns_intent \}\}/u);
  assert.match(scaffoldRestore, /NETNS_ACQUIRED: \$\{\{ steps\.preparation\.outputs\.netns_acquired \}\}/u);
  assert.match(scaffoldRestore, /if test "\$NETNS_ACQUIRED" = true; then[\s\S]*rmdir \/run\/netns/u);
  assert.doesNotMatch(workflow, /\.cogs-stage2-owner-/u);
  assert.match(
    scaffoldRestore,
    /if sudo -n \/usr\/bin\/test -e \/run\/netns \|\| sudo -n \/usr\/bin\/test -L \/run\/netns; then status=1; fi/u,
  );
  assert.match(scaffoldRestore, /stage2-hosted-opt-mode\.py restore "\$GITHUB_RUN_ID" "\$GITHUB_RUN_ATTEMPT"/u);
  assert.match(workflow, /Byte-compare package and fail closed/u);
  assert.match(qualifier, /cycle-artifact-custody-v2\.json/u);
  assert.match(workflow, /PACKAGE_ARTIFACT_DIGEST.*artifact-digest/u);
  assert.match(workflow, /\[\[ "\$PACKAGE_ARTIFACT_DIGEST" =~ \^\[0-9a-f\]\{64\}\$ \]\]/u);
  assert.match(
    workflow,
    /id: package_readback[\s\S]*?id: aggregate_cleanup[\s\S]*?Enforce complete aggregate custody and cleanup/u,
  );
  assert.match(
    workflow,
    /id: aggregate_cleanup\n {8}if: always\(\) && steps\.aggregate_baseline\.outcome == 'success'/u,
  );
  assert.match(workflow, /timeout-minutes: 25/u);
  const aggregate = workflow.slice(workflow.indexOf("  aggregate:"));
  const aggregateStepMinutes = [...aggregate.matchAll(/^ {8}timeout-minutes: (\d+)$/gmu)].reduce(
    (total, match) => total + Number(match[1]),
    0,
  );
  assert.ok(aggregateStepMinutes <= 21, `aggregate step bounds ${aggregateStepMinutes}`);
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
  const partial = spawnSync(
    "bash",
    [
      "-c",
      `${cleanup}\nOWNER=owner\nSOURCE=source\nOWNER_VALUE=o\nSOURCE_VALUE=s\nphase() { :; }\nmarker_matches() { test "$2" = "$OWNER"; }\nabsent() { test "$1" != /var/lib/cogs; }\nsudo() { printf EFFECT; }\nsettle`,
    ],
    { encoding: "utf8" },
  );
  assert.equal(partial.status, 1);
  assert.equal(partial.stdout, "");
});

test("corrected mixed preflight remains no-KVM, H/G/Q-bound, and versioned", () => {
  assert.match(preflightWorkflow, /^name: Stage 2 exact mixed H-G-Q no-KVM preflight$/mu);
  assert.match(preflightWorkflow, /qualification_head/u);
  assert.match(preflightWorkflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(
    preflightWorkflow,
    /rev-list --parents -n1 "\$EXACT_CONTROL_HEAD"\)" = "\$EXACT_CONTROL_HEAD \$EXACT_IMPLEMENTATION_HEAD"/u,
  );
  const hostCheck = preflightWorkflow.indexOf("Compare every ambient host closure before mutation");
  const normalization = preflightWorkflow.indexOf(
    "Normalize the exact hosted opt scaffold before immutable preparation",
  );
  const execution = preflightWorkflow.indexOf(
    "Execute exact mixed H-G preparation and mandatory settlement without KVM",
  );
  const settlement = preflightWorkflow.indexOf("Independently repeat mandatory settlement after every outcome");
  const restoration = preflightWorkflow.indexOf("Restore the exact acquired hosted opt scaffold only after settlement");
  assert.ok(
    hostCheck > 0 &&
      normalization > hostCheck &&
      execution > normalization &&
      settlement > execution &&
      restoration > settlement,
  );
  const normalized = preflightWorkflow.slice(normalization, execution);
  assert.match(normalized, /stage2-hosted-opt-mode\.py"[\s\S]*normalize "\$GITHUB_RUN_ID" "\$GITHUB_RUN_ATTEMPT"/u);
  assert.match(
    preflightWorkflow.slice(settlement, restoration),
    /if: always\(\) && steps\.opt_scaffold\.outcome == 'success'/u,
  );
  const restored = preflightWorkflow.slice(restoration);
  assert.match(restored, /if: always\(\) && steps\.opt_scaffold\.outcome != 'skipped'/u);
  assert.doesNotMatch(restored, /OPT_ORIGINAL_MODE/u);
  assert.match(restored, /stage2-hosted-opt-mode\.py"[\s\S]*restore "\$GITHUB_RUN_ID" "\$GITHUB_RUN_ATTEMPT"/u);
  assert.doesNotMatch(restored, /chmod 0777 \/opt|test ! -e \/opt\/kata &&/u);
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
