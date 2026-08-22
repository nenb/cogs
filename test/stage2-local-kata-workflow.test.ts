import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflowPath = ".github/workflows/stage2-local-kata-qualification.yml";
const guardPath = "scripts/stage2-local-qualification-guard.py";
const settlementPath = "scripts/stage2-local-settlement.py";
const publicationPath = "scripts/stage2-local-publication.py";
const receiptPath = "scripts/stage2-local-upload-receipt.py";
const recoveryPath = "deploy/aws-feasibility/remote/recover-stage2-completion-remote.sh";
const controlStagingPath = "scripts/stage2-stage-reviewed-control.py";
const workflow = readFileSync(workflowPath, "utf8");
const guard = readFileSync(guardPath, "utf8");
const settlement = readFileSync(settlementPath, "utf8");
const publication = readFileSync(publicationPath, "utf8");
const receipt = readFileSync(receiptPath, "utf8");
const recoverySource = readFileSync(recoveryPath, "utf8");
const controlStaging = readFileSync(controlStagingPath, "utf8");

function stepTimeout(name: string): number {
  const start = workflow.indexOf(`      - name: ${name}`);
  assert.ok(start >= 0, `missing step ${name}`);
  const next = workflow.indexOf("\n      - name:", start + 1);
  const source = workflow.slice(start, next < 0 ? undefined : next);
  const match = source.match(/\n {8}timeout-minutes: ([0-9]+)\n/u);
  assert.ok(match?.[1], `missing timeout for ${name}`);
  return Number(match[1]);
}

const steps = [
  "Admit the stable first-created dispatch before every source effect",
  "Acquire exact control revision G without credentials",
  "Gate reviewed H and G after unauthenticated exact-G acquisition",
  "Acquire exact reviewed implementation revision H separately without credentials",
  "Complete exact immutable preparation before KVM eligibility and role custody",
  "Execute the sole zero-argument local qualification entry",
  "Invoke cleanup-only recovery after every local entry outcome",
  "Settle and remove fixed source and control roots only after recovery",
  "Independently prove zero lifecycle residue after cleanup",
  "Validate semantics and reviewed schema then freeze the private-receipt report",
  "Upload the sole canonical local report member",
  "Download report by exact numeric artifact ID with fatal digest mismatch",
  "Byte-compare sole exact-ID report readback",
  "Create separate canonical upload-binding receipt after exact report readback",
  "Upload separate non-authoritative upload-binding receipt",
  "Download receipt by its exact numeric artifact ID",
  "Byte-compare sole exact-ID receipt readback",
  "Remove all local report and readback staging",
  "Enforce attempt 1 complete custody chain and final zero residue",
];

test("dedicated workflow is manual, same-repository, and exact reviewed H/G", () => {
  assert.match(workflow, /^name: Stage 2 local Kata qualification$/mu);
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(push|pull_request|schedule|workflow_run):/u);
  assert.match(workflow, /reviewed_implementation_head:/u);
  assert.match(workflow, /reviewed_control_head:/u);
  assert.match(workflow, /get\("GITHUB_REPOSITORY"\) == "nenb\/cogs"/u);
  assert.match(guard, /GITHUB_REF_PROTECTED/u);
  assert.match(workflow, /STAGE2_LOCAL_IMPLEMENTATION_HEAD/u);
  assert.match(workflow, /STAGE2_LOCAL_CONTROL_HEAD/u);
  assert.match(workflow, /STAGE2_LOCAL_AUTHORIZED_ACTOR/u);
  assert.match(guard, /REPOSITORY = "nenb\/cogs"/u);
  assert.match(guard, /REVIEWED_IMPLEMENTATION_HEAD = "59d992b305cfd243f2d7b9c770fe24b0a36cc053"/u);
  assert.match(
    guard,
    /REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "09b566a522a3d97983227b679b15f80ead189271617dbcbc70e5e1639250294d"/u,
  );
  assert.match(guard, /REVIEWED_CONTROL_SHA256 = "388618877fab7343e687db88dde5b47326a424810fb1493927381951c7c8c45e"/u);
  assert.match(guard, /REVIEWED_WORKFLOW_SHA256 = "d767a499f829b358f81b9ee06262d36149cf6dda4c56125309b3bbeea5085b49"/u);
  assert.match(
    guard,
    /REVIEWED_RESULT_SCHEMA_SHA256 = "27d60133f202d9c32381d2b3dc8fe281334dc67d59dc8d72b402e6b7ca825375"/u,
  );
  assert.match(guard, /review constants remain blocked/u);
  assert.doesNotMatch(guard, /REVIEWED_[A-Z_]+\s*=\s*(?:""|os\.environ|getenv)/u);
});

test("permissions and actions expose only bounded actions-read authority", () => {
  assert.match(workflow, /permissions:\n {2}actions: read\n {2}contents: read/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,100}(?:write|id-token)/u);
  assert.equal(workflow.match(/secrets\.GITHUB_TOKEN/gu)?.length, 1);
  assert.doesNotMatch(workflow, /github\.token|persist-credentials: true/u);
  assert.match(workflow, /ACTIONS_READ_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}/u);
  assert.doesNotMatch(workflow, /aws-actions|amazon|opentofu|terraform|\bsts\b|\bssm\b/u);
  assert.doesNotMatch(workflow, /strategy:|matrix:|--retry|cancelled\(\)/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.doesNotMatch(workflow, /actions\/checkout/u);
  assert.equal(workflow.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/gu)?.length, 2);
  assert.match(guard, /DENIED_ENVIRONMENT/u);
  assert.match(guard, /ACTIONS_ID_TOKEN_REQUEST_TOKEN/u);
  assert.doesNotMatch(
    `${guard}\n${settlement}\n${publication}\n${receipt}`,
    /\bimport (?:boto|opentofu|terraform)|subprocess[^\n]+(?:aws|sts|ssm)/u,
  );
});

test("attempt-one stable admission is the first step and precedes unauthenticated H/G acquisition", () => {
  const admission = workflow.indexOf("Admit the stable first-created dispatch before every source effect");
  const control = workflow.indexOf("Acquire exact control revision G without credentials");
  const gate = workflow.indexOf("Gate reviewed H and G after unauthenticated exact-G acquisition");
  const implementation = workflow.indexOf(
    "Acquire exact reviewed implementation revision H separately without credentials",
  );
  const preparation = workflow.indexOf("Complete exact immutable preparation before KVM eligibility and role custody");
  const entry = workflow.indexOf("Execute the sole zero-argument local qualification entry");
  assert.ok(
    0 <= admission &&
      admission < control &&
      control < gate &&
      gate < implementation &&
      implementation < preparation &&
      preparation < entry,
  );
  assert.match(workflow.slice(admission, control), /\n {2}local-kata:\n {4}needs: admission/u);
  assert.doesNotMatch(workflow.slice(admission, control), /\n {8}uses:/u);
  assert.match(workflow.slice(admission, control), /item\.get\("run_attempt"\) == 1/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32584575939/u);
  assert.match(
    workflow.slice(admission, control),
    /"completed", "failure", "a9e02f1269684db98a42bfdaed6e2f193ba1c631"/u,
  );
  assert.match(workflow.slice(admission, control), /len\(runs\) == 2/u);
  assert.match(workflow.slice(admission, control), /rows == previous/u);
  assert.match(workflow.slice(admission, control), /ProxyHandler\(\{\}\)/u);
  assert.match(workflow.slice(admission, control), /"Authorization":f"Bearer \{token\}"/u);
  assert.match(workflow.slice(control, implementation), /PRE_EFFECT_ADMITTED_RUN_ID/u);
  assert.match(guard, /pre-effect admission identity differs/u);
  assert.match(guard, /"ACTIONS_READ_TOKEN"/u);
  assert.equal(workflow.match(/clean=\(env -i HOME=\/nonexistent LANG=C LC_ALL=C PATH=\/usr\/bin:\/bin/gu)?.length, 2);
  assert.doesNotMatch(workflow.slice(control, implementation), /GITHUB_TOKEN|GH_TOKEN/u);
  assert.match(workflow.slice(preparation, entry), /prepare-stage2-fixed-source\.py/u);
  assert.match(workflow.slice(preparation, entry), /stage2-stage-reviewed-control\.py/u);
  assert.match(workflow.slice(preparation, entry), /observed=\$\(sudo -n \/usr\/bin\/sha256sum/u);
  assert.match(workflow.slice(preparation, entry), /completion_kata_immutable_preparation\.py/u);
  assert.match(workflow.slice(preparation, entry), /"rootfs_artifact_count":16/u);
  assert.match(workflow.slice(preparation, entry), /"runtime_archive_count":2/u);
  assert.match(workflow.slice(preparation, entry), /"control_verified":True/u);
  assert.match(
    workflow.slice(preparation, entry),
    /stage2-completion-v1\/control\/stage2-local-static-control-v1\.json/u,
  );
  assert.doesNotMatch(workflow.slice(preparation, entry), /\/run\/cogs-stage2-local-control-v2/u);
  assert.doesNotMatch(
    workflow.slice(0, entry),
    /\/dev\/kvm|qmp|systemctl|containerd-start|ctr (?:run|task)|completion_local_full\.py/u,
  );
  assert.equal(workflow.match(/completion_local_full\.py/gu)?.length, 1);
});

test("fixed phase bounds preserve recovery, independent residue, and publication reserve", () => {
  const total = steps.reduce((sum, name) => sum + stepTimeout(name), 0);
  const localJob = workflow.slice(workflow.indexOf("\n  local-kata:"));
  const job = Number(localJob.match(/^ {4}timeout-minutes: ([0-9]+)$/mu)?.[1]);
  assert.equal(job, 120);
  assert.equal(total, 116);
  assert.equal(total - stepTimeout("Admit the stable first-created dispatch before every source effect"), 115);
  assert.equal(stepTimeout("Execute the sole zero-argument local qualification entry"), 59);
  const postEntry = steps.slice(6).reduce((sum, name) => sum + stepTimeout(name), 0);
  assert.equal(postEntry, 21);
  assert.ok(postEntry * 60 >= 600);
  assert.match(workflow, /timeout --foreground --signal=TERM --kill-after=10s 3470s/u);
  assert.ok(3470 + 10 <= 59 * 60);
  assert.match(workflow, /one 7,200-second envelope/u);
});

test("recovery and independent settlement always run without turning cancellation into success", () => {
  const recovery = workflow.indexOf("Invoke cleanup-only recovery after every local entry outcome");
  const cleanup = workflow.indexOf("Settle and remove fixed source and control roots only after recovery");
  const residue = workflow.indexOf("Independently prove zero lifecycle residue after cleanup");
  const publicationAt = workflow.indexOf("Validate semantics and reviewed schema");
  assert.ok(0 < recovery && recovery < cleanup && cleanup < residue && residue < publicationAt);
  for (const name of steps.slice(6, 9)) {
    const start = workflow.indexOf(`      - name: ${name}`);
    const next = workflow.indexOf("\n      - name:", start + 1);
    assert.match(workflow.slice(start, next), /if: always\(\)/u);
  }
  assert.match(workflow, /recover-stage2-completion-remote\.sh/u);
  assert.match(recoverySource, /_recover_fixed_local_qualification/u);
  assert.match(recoverySource, /result is None/u);
  assert.doesNotMatch(recoverySource, /_run_fixed_local_qualification|_consume_local_receipt|completion_local_full/u);
  assert.match(controlStaging, /stage2-local-static-control-v1\.json/u);
  assert.match(controlStaging, /validate_control_members/u);
  assert.match(controlStaging, /os\.O_EXCL/u);
  assert.match(settlement, /native\.scan\("after-unmount"/u);
  assert.match(settlement, /\/sys\/class\/net/u);
  assert.match(settlement, /\/sys\/fs\/cgroup/u);
  assert.match(settlement, /\("\/usr\/sbin\/nft", "-j", "list", "ruleset"\)/u);
  assert.match(settlement, /\("\/usr\/sbin\/ip", "-j", "netns", "list"\)/u);
  assert.match(settlement, /\("\/usr\/sbin\/tc", "-j", "qdisc", "show"\)/u);
  assert.match(settlement, /c42\[hnqt\]/u);
  assert.match(settlement, /cogs_stage2_ssh_v1/u);
  assert.match(settlement, /MAX_JSON_NODES/u);
  assert.match(settlement, /RECOVERY_OUTCOME/u);
  assert.doesNotMatch(settlement, /umount|--lazy|SIGKILL/u);
  assert.match(workflow, /pass:success\|failure:failure/u);
  assert.doesNotMatch(workflow, /for outcome in "\$ENTRY"/u);
  assert.match(workflow, /test "\$REPORT_RESULT" = pass/u);
});

test("publication has semantic/schema binding, exact-ID readback, separate receipt, and final cleanup", () => {
  assert.match(publication, /module\.load_result\(raw\)/u);
  assert.match(publication, /module\.SCHEMA_REGISTRY/u);
  assert.match(publication, /reviewed schema differs/u);
  assert.match(publication, /native\.prove_no_writable_aliases/u);
  assert.match(publication, /os\.fchmod\(fresh, 0o444\)/u);
  assert.match(publication, /os\.fsync\(fresh\)[\s\S]+os\.rename\(/u);
  assert.equal(
    workflow.match(/artifact-ids: \$\{\{ steps\.(?:report|receipt)_upload\.outputs\.artifact-id \}\}/gu)?.length,
    2,
  );
  assert.equal(workflow.match(/digest-mismatch: error/gu)?.length, 2);
  assert.match(receipt, /exact-ID report readback differs from frozen report/u);
  assert.match(receipt, /exact-ID receipt readback differs/u);
  assert.match(receipt, /private_receipt_consumed/u);
  assert.match(receipt, /promotion_authorized": False/u);
  assert.match(receipt, /first-created-dispatch-consumed-no-retry-rerun-or-replacement/u);
  assert.match(workflow, /stage2-local-upload-receipt\.py" create/u);
  assert.match(workflow, /stage2-local-upload-receipt\.py" receipt-readback/u);
  assert.match(workflow, /\/bin\/rm -rf -- "\$REPORT_STAGING"/u);
  assert.match(workflow, /stage2-local-settlement\.py" final/u);
  assert.equal(
    workflow.match(
      /sudo -n env -i[^\n]*[\s\S]{0,500}?\/usr\/bin\/timeout[^\n]*[\s\S]{0,300}?stage2-local-settlement\.py/gu,
    )?.length,
    3,
  );
  assert.doesNotMatch(
    workflow,
    /\/usr\/bin\/timeout[^\n]*[\s\S]{0,200}?env -i[^\n]*[\s\S]{0,300}?stage2-local-settlement\.py/u,
  );
});

test("focused workflow script hostile suite passes", () => {
  const result = spawnSync("python3", ["-B", "test/stage2-local-workflow-scripts.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /stage2 local workflow script tests passed/u);
});
