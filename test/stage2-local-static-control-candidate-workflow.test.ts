import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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

  assert.match(dispatchGuard, /GUARD_VERSION = "cogs\.stage2-static-control-dispatch-guard\/v16"/u);
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
  assert.match(dispatchGuard, /SIXTH_PREDECESSOR_RUN_ID = 32565389560/u);
  assert.match(dispatchGuard, /SIXTH_PREDECESSOR_WORKFLOW_HEAD = "b5fc2996695d8b9fb0621df556cf4c3e66b5c526"/u);
  assert.match(dispatchGuard, /SIXTH_PREDECESSOR_REVIEWED_HEAD = "fdd4b82d07a218d10c7bce11c8146689e4cafdc1"/u);
  assert.match(dispatchGuard, /SEVENTH_PREDECESSOR_RUN_ID = 32566515932/u);
  assert.match(dispatchGuard, /SEVENTH_PREDECESSOR_WORKFLOW_HEAD = "0bbb7047e451d1957302b705242d0fa6e8058006"/u);
  assert.match(dispatchGuard, /SEVENTH_PREDECESSOR_REVIEWED_HEAD = "130832252da16efa1772e76b07051d50f20973ca"/u);
  assert.match(dispatchGuard, /EIGHTH_PREDECESSOR_RUN_ID = 32568536415/u);
  assert.match(dispatchGuard, /EIGHTH_PREDECESSOR_WORKFLOW_HEAD = "9642dcd247aedc0a29068be3aa4e8873db89de3a"/u);
  assert.match(dispatchGuard, /EIGHTH_PREDECESSOR_REVIEWED_HEAD = "94ad8206c696f950fdcdbba2a6ea2bb0136e76d9"/u);
  assert.match(dispatchGuard, /NINTH_PREDECESSOR_RUN_ID = 32569177840/u);
  assert.match(dispatchGuard, /NINTH_PREDECESSOR_WORKFLOW_HEAD = "0da45c37b0a0cf73e288eb9c3f8b23c436f25ac6"/u);
  assert.match(dispatchGuard, /NINTH_PREDECESSOR_REVIEWED_HEAD = "25bfbb4277c9051da352e9c699d4ca98dcb248e2"/u);
  assert.match(dispatchGuard, /TENTH_PREDECESSOR_RUN_ID = 32569932861/u);
  assert.match(dispatchGuard, /TENTH_PREDECESSOR_WORKFLOW_HEAD = "ee789aecc77319909186b4a7d769227896fb3c66"/u);
  assert.match(dispatchGuard, /TENTH_PREDECESSOR_REVIEWED_HEAD = "dd676027801370f7bf025539b8c2c14991689afa"/u);
  assert.match(dispatchGuard, /ELEVENTH_PREDECESSOR_RUN_ID = 32574273244/u);
  assert.match(dispatchGuard, /ELEVENTH_PREDECESSOR_WORKFLOW_HEAD = "c727b167cea2f470807588df913d815148fbb858"/u);
  assert.match(dispatchGuard, /ELEVENTH_PREDECESSOR_REVIEWED_HEAD = "7b1dcc045182616cf657bcf941ba8aee7108eb76"/u);
  assert.match(dispatchGuard, /TWELFTH_PREDECESSOR_RUN_ID = 32576106736/u);
  assert.match(dispatchGuard, /TWELFTH_PREDECESSOR_WORKFLOW_HEAD = "8dd6d58f4f9e24a2f1bcccbd4719fbf03e72bbb2"/u);
  assert.match(dispatchGuard, /TWELFTH_PREDECESSOR_REVIEWED_HEAD = "4a3beae8683309f3fef30cecce3187262efc4b23"/u);
  assert.match(dispatchGuard, /SUCCESSFUL_PREDECESSOR_RUN_ID = 32577727971/u);
  assert.match(dispatchGuard, /SUCCESSFUL_PREDECESSOR_WORKFLOW_HEAD = "c2540af5cb85e2845de1eebfad3475d28c0483e5"/u);
  assert.match(dispatchGuard, /SUCCESSFUL_PREDECESSOR_REVIEWED_HEAD = "59d992b305cfd243f2d7b9c770fe24b0a36cc053"/u);
  assert.match(dispatchGuard, /SECOND_SUCCESSFUL_PREDECESSOR_RUN_ID = 32590966571/u);
  assert.match(
    dispatchGuard,
    /SECOND_SUCCESSFUL_PREDECESSOR_WORKFLOW_HEAD = "acb99d5d6ba4cbd94ad40c9bbe4520d2f8905368"/u,
  );
  assert.match(
    dispatchGuard,
    /SECOND_SUCCESSFUL_PREDECESSOR_REVIEWED_HEAD = "33314a9999cbe1e0eb927ba4a1e6f1ee10fcd5df"/u,
  );
  assert.match(dispatchGuard, /THIRD_SUCCESSFUL_PREDECESSOR_RUN_ID = 32594176203/u);
  assert.match(
    dispatchGuard,
    /THIRD_SUCCESSFUL_PREDECESSOR_WORKFLOW_HEAD = "7759346c281b45a3d98476abdfaa820109601547"/u,
  );
  assert.match(
    dispatchGuard,
    /THIRD_SUCCESSFUL_PREDECESSOR_REVIEWED_HEAD = "a2c25f34c35d778965ab7b125fd3b8b4460b0617"/u,
  );
  assert.match(dispatchGuard, /token\.encode\("ascii"\)/u);
  assert.match(dispatchGuard, /all\(0x21 <= byte <= 0x7e for byte in raw\)/u);
  assert.match(dispatchGuard, /"TOKEN_BOUND", "TOKEN_CHAR", "TOKEN_MISSING"/u);
  assert.match(dispatchGuard, /status in \(401, 403\)[\s\S]+"API_AUTH_REJECTED"/u);
  assert.match(dispatchGuard, /predecessor_ids == set\(PREDECESSORS\)/u);
  assert.match(dispatchGuard, /run\.get\("status"\) == "completed"[\s\S]+run\.get\("conclusion"\) == conclusion/u);
  assert.match(dispatchGuard, /current_run_id == min\(current_ids\)/u);
  assert.match(dispatchGuard, /len\(current_ids\) == 1/u);
  assert.match(dispatchGuard, /raise GuardError\("UNKNOWN_HISTORY_REJECTED"\)/u);
  assert.match(dispatchGuard, /REVIEWED_IMPLEMENTATION_HEAD = "6d142a4499a71cbb0394c9308cad63d186010790"/u);
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

test("reviewed H itself binds corrected immutable and producer sources in the runtime boundary", () => {
  const reviewed = /REVIEWED_IMPLEMENTATION_HEAD = "([0-9a-f]{40})"/u.exec(dispatchGuard)?.[1];
  assert.ok(reviewed);
  const boundaryAtH = spawnSync("git", ["show", `${reviewed}:scripts/stage2-static-control-runtime-boundary.py`], {
    encoding: "utf8",
  });
  assert.equal(boundaryAtH.status, 0, boundaryAtH.stderr);
  const policySources = [
    "deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py",
    "deploy/aws-feasibility/remote/completion_kata_preparation.py",
  ];
  for (const sourcePath of policySources) {
    const sourceAtH: Uint8Array = execFileSync("git", ["show", `${reviewed}:${sourcePath}`]);
    const digest: string = createHash("sha256").update(sourceAtH).digest("hex");
    assert.match(boundaryAtH.stdout, new RegExp(`"sha256": "${digest}"`, "u"));
  }
});

test("static-only cleanup uses reviewed source policy and owned process-fd censuses", () => {
  assert.match(workflow, /stage2-static-control-runtime-boundary\.py" pre/u);
  assert.match(workflow, /stage2-static-control-runtime-boundary\.py" post/u);
  assert.match(workflow, /Remove owned fixtures and verify the static-only runtime boundary/u);
  assert.match(workflow, /chmod 0711 "\$root" "\$stage" "\$observation"/u);
  assert.match(workflow, /test -r "\$candidate\/stage2-local-static-control-v1\.json"/u);
  assert.match(workflow, /stat -c '%U:%G:%a'.*root:root:711/u);
  assert.match(workflow, /stat -c '%U:%G:%a'.*"\$stage\/source".*root:root:700/su);
  assert.doesNotMatch(workflow, /test ! -e \/dev\/kvm/u);
  assert.match(runtimeBoundary, /MAX_PROCESSES = 32_768/u);
  assert.match(runtimeBoundary, /MAX_FDS_PER_PROCESS = 4_096/u);
  assert.match(
    runtimeBoundary,
    /NORMALIZED_WORKFLOW_SHA256 = "64e193d4691209ead5fda3234e8eb13160f568a21f8741c31955e5a689a4b416"/u,
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
