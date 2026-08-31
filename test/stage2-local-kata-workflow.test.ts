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
const preflightWorkflowPath = ".github/workflows/stage2-mixed-hg-preflight.yml";
const preflightPath = "scripts/stage2-mixed-hg-preflight.sh";
const diagnosticPath = ".github/workflows/stage2-local-static-admission-diagnostic.yml";
const workflow = readFileSync(workflowPath, "utf8");
const guard = readFileSync(guardPath, "utf8");
const settlement = readFileSync(settlementPath, "utf8");
const publication = readFileSync(publicationPath, "utf8");
const receipt = readFileSync(receiptPath, "utf8");
const recoverySource = readFileSync(recoveryPath, "utf8");
const controlStaging = readFileSync(controlStagingPath, "utf8");
const preflightWorkflow = readFileSync(preflightWorkflowPath, "utf8");
const preflight = readFileSync(preflightPath, "utf8");
const diagnostic = readFileSync(diagnosticPath, "utf8");

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
  "Provision the fresh-host NFT writer owner",
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

test("terminal receipt diagnostic is exact, consumed in memory, and never published", () => {
  assert.match(diagnostic, /9a525719bed23e3a948f760862722e8e4864a575/u);
  assert.match(diagnostic, /1fc2dea2dcefea2aaf71a80356e0f5ed946e9991/u);
  assert.match(diagnostic, /_consume_local_receipt\(receipt\)/u);
  assert.match(diagnostic, /traceback\.extract_tb\(error\.__traceback__\)/u);
  assert.match(diagnostic, /frames\[-8:\]/u);
  assert.doesNotMatch(diagnostic, /inspect|getargvalues|f_locals|actions\/upload-artifact|actions\/download-artifact/u);
});

test("mixed H-G preflight runs exact preparation and settlement but never KVM", () => {
  assert.match(preflightWorkflow, /^name: Stage 2 exact mixed H-G no-KVM preflight$/mu);
  assert.match(preflightWorkflow, /workflow_dispatch:/u);
  assert.match(preflightWorkflow, /permissions: \{\}/u);
  assert.doesNotMatch(preflightWorkflow, /actions\/checkout|upload-artifact|id-token|write/u);
  assert.match(preflightWorkflow, /if: always\(\)/u);
  assert.match(preflight, /H=1eaec52dd4e2f1222548362e92adc780a2169025/u);
  assert.match(preflight, /G=e8775fe2fb07170b1b5c9d17b356aaa8c1b93ce4/u);
  assert.match(preflight, /MANIFEST=ec4c46f2247df2fad872dd3f1f7e147d775dfb568fcb7e520ceb7d3653108768/u);
  assert.match(preflight, /CONTROL=d32dad750fdae5118ba164d394145a3c3e7e45894524c2a17cbd502ecb80e26d/u);
  assert.match(preflight, /prepare-stage2-fixed-source\.py/u);
  assert.match(preflight, /stage2-stage-reviewed-control\.py/u);
  assert.match(preflight, /completion_kata_immutable_preparation\.py/u);
  assert.match(preflight, /recover-stage2-completion-remote\.sh/u);
  assert.match(preflight, /cogs-stage2-mixed-hg-owner-v1/u);
  assert.match(preflight, /cogs-stage2-mixed-hg-source-v1/u);
  assert.match(preflight, /TF_TOKEN_app_terraform_io[\s\S]*GOOGLE_APPLICATION_CREDENTIALS[\s\S]*PYTHONOPTIMIZE/u);
  assert.match(preflightWorkflow, /env -i BASH_ENV=\/dev\/null ENV=\/dev\/null/u);
  assert.match(preflightWorkflow, /exact_git "\$GITHUB_WORKSPACE\/control" "\$EXACT_CONTROL_HEAD"/u);
  assert.match(preflightWorkflow, /exact_git "\$GITHUB_WORKSPACE\/driver" "\$GITHUB_SHA"/u);
  assert.equal(preflight.match(/stage2-local-settlement\.py" supervise-(?:cleanup|residue)/gu)?.length, 2);
  assert.doesNotMatch(preflight, /completion_local_full|\/dev\/kvm|containerd-shim-kata-v2[^\n]*--/u);
  const syntax = spawnSync("bash", ["-n", preflightPath], { encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr);
});

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
  assert.match(guard, /REVIEWED_IMPLEMENTATION_HEAD = "1fc2dea2dcefea2aaf71a80356e0f5ed946e9991"/u);
  assert.match(
    guard,
    /REVIEWED_IMPLEMENTATION_MANIFEST_SHA256 = "509dacc4a83b45a2da1ca7892210de8434a2b9de5b2a478ce4d8197f85967f3a"/u,
  );
  assert.match(guard, /REVIEWED_CONTROL_SHA256 = "d94af3687d21c432946f3bb1bc40b76fc8dad786fea2cc51366d1651a8a33926"/u);
  assert.match(guard, /REVIEWED_WORKFLOW_SHA256 = "2c48eb15be3eef4c60ba36171614d499333624fc2bf889f41f749aa382d47ea7"/u);
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
  const provision = workflow.indexOf("Provision the fresh-host NFT writer owner");
  const entry = workflow.indexOf("Execute the sole zero-argument local qualification entry");
  assert.ok(
    0 <= admission &&
      admission < control &&
      control < gate &&
      gate < implementation &&
      implementation < preparation &&
      preparation < provision &&
      provision < entry,
  );
  assert.match(workflow.slice(admission, control), /\n {2}local-kata:\n {4}needs: admission/u);
  assert.doesNotMatch(workflow.slice(admission, control), /\n {8}uses:/u);
  assert.match(workflow.slice(admission, control), /item\.get\("run_attempt"\) == 1/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32584575939/u);
  assert.match(
    workflow.slice(admission, control),
    /"completed", "failure", "a9e02f1269684db98a42bfdaed6e2f193ba1c631"/u,
  );
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32586393441/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32596053811/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32602439014/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32613383776/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32614828572/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32622048772/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32628930290/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 32635519776/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 33292919137/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 33299709836/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 33306125902/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 33321865244/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 33323414697/u);
  assert.match(workflow.slice(admission, control), /item\["id"\] == 33350122895/u);
  assert.match(workflow.slice(admission, control), /len\(runs\) == 16/u);
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
  assert.match(workflow.slice(provision, entry), /source\/scripts\/provision-stage2-nft-owner\.py/u);
  assert.match(workflow.slice(provision, entry), /test -d \/var\/lib\/cogs-stage2-nft-owner-v1/u);
  assert.equal(workflow.slice(preparation, entry).match(/sudo -n \/usr\/bin\/test -x/gu)?.length, 3);
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
  assert.doesNotMatch(workflow, /^\s*cd \/var\/lib\/cogs/mu);
});

test("fixed phase bounds preserve recovery, independent residue, and publication reserve", () => {
  const total = steps.reduce((sum, name) => sum + stepTimeout(name), 0);
  const localJob = workflow.slice(workflow.indexOf("\n  local-kata:"));
  const job = Number(localJob.match(/^ {4}timeout-minutes: ([0-9]+)$/mu)?.[1]);
  assert.equal(job, 201);
  assert.equal(total, 197);
  assert.equal(total - stepTimeout("Admit the stable first-created dispatch before every source effect"), 196);
  assert.equal(stepTimeout("Execute the sole zero-argument local qualification entry"), 132);
  const postEntry = steps.slice(7).reduce((sum, name) => sum + stepTimeout(name), 0);
  assert.equal(postEntry, 28);
  assert.ok(postEntry * 60 >= 600);
  assert.match(workflow, /timeout --foreground --signal=TERM --kill-after=10s 7800s/u);
  assert.ok(7800 + 10 <= 132 * 60);
  assert.match(workflow, /one 12,060-second envelope/u);
});

test("recovery and independent settlement always run without turning cancellation into success", () => {
  const recovery = workflow.indexOf("Invoke cleanup-only recovery after every local entry outcome");
  const cleanup = workflow.indexOf("Settle and remove fixed source and control roots only after recovery");
  const residue = workflow.indexOf("Independently prove zero lifecycle residue after cleanup");
  const publicationAt = workflow.indexOf("Validate semantics and reviewed schema");
  assert.ok(0 < recovery && recovery < cleanup && cleanup < residue && residue < publicationAt);
  for (const name of steps.slice(7, 10)) {
    const start = workflow.indexOf(`      - name: ${name}`);
    const next = workflow.indexOf("\n      - name:", start + 1);
    assert.match(workflow.slice(start, next), /if: always\(\)/u);
  }
  assert.match(workflow, /recover-stage2-completion-remote\.sh/u);
  assert.match(workflow.slice(recovery, cleanup), /kill-after=10s 720s/u);
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
  assert.doesNotMatch(settlement, /\("\/usr\/sbin\/ip", "-j", "netns", "list"\)/u);
  assert.match(settlement, /_bounded_names\("\/run\/netns"\)/u);
  assert.match(settlement, /\("\/usr\/sbin\/tc", "-j", "qdisc", "show"\)/u);
  assert.match(settlement, /c42\[hnqt\]/u);
  assert.match(settlement, /cogs_stage2_ssh_v1/u);
  assert.match(settlement, /MAX_JSON_NODES/u);
  assert.match(settlement, /RECOVERY_OUTCOME/u);
  assert.doesNotMatch(settlement, /umount|--lazy|SIGKILL/u);
  assert.match(workflow, /pass:success\|failure:failure/u);
  assert.doesNotMatch(workflow, /for outcome in "\$ENTRY"/u);
  assert.match(workflow, /root:root:777[\s\S]*chmod 0755 \/opt/u);
  assert.match(workflow, /test ! -e \/run\/netns[\s\S]*mkdir -m 0755 \/run\/netns/u);
  assert.match(workflow, /Restore exact hosted scaffolding[\s\S]*rmdir \/run\/netns[\s\S]*chmod 0777 \/opt/u);
  assert.match(workflow, /HOST_SCAFFOLD_RESTORE/u);
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
  assert.equal(workflow.match(/stage2-local-settlement\.py" supervise-(?:cleanup|residue|final)/gu)?.length, 3);
  assert.match(settlement, /def supervise\(mode\):/u);
  assert.match(settlement, /os\.execve\(command\[0\], command, environment\)/u);
  assert.doesNotMatch(workflow, /\/usr\/bin\/timeout[^\n]*[\s\S]{0,300}?stage2-local-settlement\.py/u);
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
