import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = ".github/workflows/stage2-local-static-control-candidate.yml";
const workflow = readFileSync(path, "utf8");
const dispatchGuard = readFileSync("scripts/stage2-static-control-dispatch-guard.py", "utf8");
const runtimeBoundary = readFileSync("scripts/stage2-static-control-runtime-boundary.py", "utf8");
const preparation = readFileSync("deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py", "utf8");
const settlement = readFileSync("scripts/stage2-local-settlement.py", "utf8");

test("control candidate workflow is manual reviewed-H one-shot and expressly non-authoritative", () => {
  assert.match(workflow, /^name: Stage 2 no-KVM static control candidate$/mu);
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(?:push|pull_request|schedule|workflow_run):/u);
  assert.match(workflow, /permissions:\n {2}actions: read\n\n/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,80}(?:contents:|write|id-token:)/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_IMPLEMENTATION_HEAD" = "\$\(\/usr\/bin\/git rev-parse HEAD\)"/u);
  assert.doesNotMatch(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(workflow, /non-authoritative-stage2-static-control/u);
  assert.match(workflow, /^ {4}timeout-minutes: 45$/mu);
  assert.match(workflow, /Step bounds total 42 minutes with a three-minute cleanup\/runner reserve/u);
  assert.doesNotMatch(workflow, /aws-actions|amazon|terraform|opentofu/u);
  assert.doesNotMatch(workflow, /(?:GITHUB_TOKEN|GH_TOKEN)\s*[:=]/u);
  assert.match(workflow, /test ! -e \/run\/netns\/cogs-stage2-ssh/u);
  assert.doesNotMatch(workflow, /completion_local_full|ctr run|systemctl|containerd --/u);
});

test("event-contract replacement guard is exact source and precedes every source effect", () => {
  const guardAt = workflow.indexOf("Admit only the authorized event-contract replacement generation");
  const checkoutAt = workflow.indexOf("Check out exact reviewed implementation head");
  const materializeAt = workflow.indexOf("Materialize exact H source");
  const acquireAt = workflow.indexOf("Acquire verify and install immutable fixtures");
  assert.ok(0 <= guardAt && guardAt < checkoutAt && checkoutAt < materializeAt && materializeAt < acquireAt);
  const match = workflow.match(/\/usr\/bin\/python3 -I -B - <<'PY'\n([\s\S]*?)^ {10}PY$/mu);
  assert.ok(match?.[1]);
  const embedded = match[1].replace(/^ {10}/gmu, "");
  assert.equal(embedded, dispatchGuard);

  const guardStep = workflow.slice(guardAt, checkoutAt);
  const outsideGuard = workflow.slice(0, guardAt) + workflow.slice(checkoutAt);
  assert.match(guardStep, /ACTIONS_READ_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}/u);
  assert.equal(workflow.match(/\$\{\{ secrets\.GITHUB_TOKEN \}\}/gu)?.length, 1);
  assert.doesNotMatch(workflow, /github\.token/u);
  assert.doesNotMatch(outsideGuard, /ACTIONS_READ_TOKEN|secrets\.GITHUB_TOKEN|Authorization/u);
  assert.doesNotMatch(
    workflow.slice(0, checkoutAt),
    /actions\/checkout|prepare-stage2-fixed-source|immutable_preparation/u,
  );

  assert.match(dispatchGuard, /GUARD_VERSION = "cogs\.stage2-static-control-dispatch-guard\/v6"/u);
  assert.match(dispatchGuard, /MAX_RUNS = 100/u);
  assert.match(dispatchGuard, /MAX_TOKEN_BYTES = 1024/u);
  assert.match(dispatchGuard, /"Authorization": f"Bearer \{token\}"/u);
  assert.match(dispatchGuard, /ProxyHandler\(\{\}\)/u);
  assert.match(dispatchGuard, /class _RejectRedirect/u);
  assert.match(dispatchGuard, /len\(runs\) == total/u);
  assert.match(dispatchGuard, /_require\(not link, "HISTORY_INCOMPLETE"\)/u);
  assert.match(dispatchGuard, /PREDECESSOR_RUN_ID = 32558263561/u);
  assert.match(dispatchGuard, /PREDECESSOR_WORKFLOW_HEAD = "a201d5688013377069b6fb4a36159360dc307cae"/u);
  assert.match(dispatchGuard, /PREDECESSOR_REVIEWED_HEAD = "62bcfbcd58f90d0e329683e3297693c32bb71877"/u);
  assert.match(dispatchGuard, /SECOND_PREDECESSOR_RUN_ID = 32560385792/u);
  assert.match(dispatchGuard, /SECOND_PREDECESSOR_WORKFLOW_HEAD = "7ccb35d14d749a0ef14602889ce2b52934c03d4d"/u);
  assert.match(dispatchGuard, /SECOND_PREDECESSOR_REVIEWED_HEAD = "67b1ca45f101f98c56b2717549e9252a38a9f2a1"/u);
  assert.match(dispatchGuard, /THIRD_PREDECESSOR_RUN_ID = 32561859288/u);
  assert.match(dispatchGuard, /THIRD_PREDECESSOR_WORKFLOW_HEAD = "549126bd7ba72d571d53113722e766967aaa0d23"/u);
  assert.match(dispatchGuard, /THIRD_PREDECESSOR_REVIEWED_HEAD = "5f8c04899422ccf546c0f500b3647a5816b2675c"/u);
  assert.match(dispatchGuard, /FOURTH_PREDECESSOR_RUN_ID = 32563007701/u);
  assert.match(dispatchGuard, /FOURTH_PREDECESSOR_WORKFLOW_HEAD = "7f43d9acc5897b11b5d9794eb2e184767446aa48"/u);
  assert.match(dispatchGuard, /FOURTH_PREDECESSOR_REVIEWED_HEAD = "d05bbc5928bda9b6bd27da1c290b0238219fd185"/u);
  assert.match(dispatchGuard, /FIFTH_PREDECESSOR_RUN_ID = 32564546902/u);
  assert.match(dispatchGuard, /FIFTH_PREDECESSOR_WORKFLOW_HEAD = "dd0e604afabe32f184ede5ec5c3ae2bbecdf464c"/u);
  assert.match(dispatchGuard, /FIFTH_PREDECESSOR_REVIEWED_HEAD = "a263b7eb38b1b0aa4a3732cf3d7a2d72db243109"/u);
  assert.match(dispatchGuard, /token\.encode\("ascii"\)/u);
  assert.match(dispatchGuard, /all\(0x21 <= byte <= 0x7e for byte in raw\)/u);
  assert.match(dispatchGuard, /"TOKEN_BOUND", "TOKEN_CHAR", "TOKEN_MISSING"/u);
  assert.match(dispatchGuard, /status in \(401, 403\)[\s\S]+"API_AUTH_REJECTED"/u);
  assert.match(dispatchGuard, /predecessor_ids == set\(PREDECESSORS\)/u);
  assert.match(dispatchGuard, /run\.get\("status"\) == "completed"[\s\S]+"failure"/u);
  assert.match(dispatchGuard, /current_run_id == min\(current_ids\)/u);
  assert.match(dispatchGuard, /len\(current_ids\) == 1/u);
  assert.match(dispatchGuard, /raise GuardError\("UNKNOWN_HISTORY_REJECTED"\)/u);
  assert.match(dispatchGuard, /REVIEWED_IMPLEMENTATION_HEAD = "a263b7eb38b1b0aa4a3732cf3d7a2d72db243109"/u);
  assert.match(dispatchGuard, /head_repository\.get\("full_name"\) == REPOSITORY/u);
  assert.match(dispatchGuard, /_read_event\(_required\(environ, "GITHUB_EVENT_PATH", "EVENT_PATH_REJECTED"\)\)/u);
  assert.match(dispatchGuard, /"EVENT_BOUND_REJECTED", "EVENT_IO_REJECTED", "EVENT_JSON_REJECTED"/u);
  assert.doesNotMatch(dispatchGuard, /event\.get\("(?:ref|repository|inputs)"\)/u);
  assert.doesNotMatch(dispatchGuard, /def guard\(environ=os\.environ, event=/u);
  assert.match(dispatchGuard, /message = f"\{GUARD_VERSION\}: \{code\}\\n"/u);
  assert.doesNotMatch(dispatchGuard, /print\(|logging|response\.read\([^M]/u);
});

test("static dispatch guard hostile suite covers event parsing, predecessors, redaction, and API failure", () => {
  const result = spawnSync("python3", ["-B", "test/stage2-static-control-dispatch-guard.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /authenticated static-control dispatch guard hostile tests passed/u);
});

test("static-only cleanup uses reviewed source policy and owned process-fd censuses", () => {
  assert.match(workflow, /stage2-static-control-runtime-boundary\.py" pre/u);
  assert.match(workflow, /stage2-static-control-runtime-boundary\.py" post/u);
  assert.match(workflow, /Remove owned fixtures and verify the static-only runtime boundary/u);
  assert.doesNotMatch(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(runtimeBoundary, /MAX_PROCESSES = 32_768/u);
  assert.match(runtimeBoundary, /MAX_FDS_PER_PROCESS = 4_096/u);
  assert.match(
    runtimeBoundary,
    /NORMALIZED_WORKFLOW_SHA256 = "b1310a0eabcad1c05cfb7f0a667fa70ee824e21a6d5a03977c33df04d341a2f1"/u,
  );
  assert.match(runtimeBoundary, /replacements == 1/u);
  assert.match(runtimeBoundary, /normalized == "\/dev\/kvm"/u);
  assert.match(runtimeBoundary, /owned-qmp-or-runtime-socket/u);
  assert.match(runtimeBoundary, /owned-network-namespace/u);
  assert.match(runtimeBoundary, /"containerd"[\s\S]+"qemu-system-x86_64"/u);
  for (const path of [
    "scripts/prepare-stage2-fixed-source.py",
    "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation.py",
  ]) {
    assert.match(runtimeBoundary, new RegExp(path.replaceAll("/", "\\/"), "u"));
  }
  const result = spawnSync("python3", ["-B", "test/stage2-static-control-runtime-boundary.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /static-control runtime boundary hostile tests passed/u);
});

test("final G preparation is fixed, verifies 16+2, installs before custody, and cleans Kata", () => {
  assert.match(preparation, /def prepare\(\):/u);
  assert.match(preparation, /_acquire_rootfs_assets\(contract\)[\s\S]+_download_runtime/u);
  assert.match(preparation, /_archive_values\(expected_runtime, archives, extracted\)/u);
  assert.match(preparation, /_publish_runtime\(extracted\)[\s\S]+_verify_installed\(expected_runtime\)/u);
  assert.match(preparation, /rootfs_artifact_count": 16/u);
  assert.match(preparation, /runtime_archive_count": 2/u);
  assert.match(preparation, /CONTROL_ROOT = Path\("\/var\/lib\/cogs\/stage2-completion-v1\/control"\)/u);
  assert.doesNotMatch(preparation, /argparse|sys\.argv\[1\]|os\.getenv\(/u);
  assert.match(settlement, /"\/opt\/kata"/u);
});
