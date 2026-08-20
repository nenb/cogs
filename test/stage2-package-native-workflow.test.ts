import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflowPath = ".github/workflows/stage2-package-native-candidate.yml";
const driverPath = "scripts/run-stage2-package-native-candidate.py";
const settlementPath = "scripts/stage2-native-settlement.py";
const receiptPath = "scripts/stage2-native-upload-receipt.py";
const workflow = readFileSync(workflowPath, "utf8");
const driver = readFileSync(driverPath, "utf8");
const settlement = readFileSync(settlementPath, "utf8");
const receipt = readFileSync(receiptPath, "utf8");

function stepTimeout(name: string): number {
  const start = workflow.indexOf(`      - name: ${name}`);
  assert.ok(start >= 0, `missing step ${name}`);
  const next = workflow.indexOf("\n      - name:", start + 1);
  const step = workflow.slice(start, next < 0 ? undefined : next);
  const match = step.match(/\n {8}timeout-minutes: ([0-9]+)\n/u);
  assert.ok(match, `missing timeout for ${name}`);
  return Number(match[1]);
}

test("native package workflow is manual, same-head, first-run, and read-only", () => {
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(push|pull_request|schedule):/u);
  assert.match(workflow, /actions: read\n {2}contents: read/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,100}(write|id-token)/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.match(workflow, /STAGE2_PACKAGE_REVIEWED_HEAD/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_REVIEWED_HEAD" = "\$DISPATCH_HEAD"/u);
  assert.match(workflow, /each dispatch is a distinct observation/u);
  assert.match(workflow, /single native package candidate attempt in this workflow run/u);
  assert.doesNotMatch(workflow, /\bsole\b/u);
  assert.doesNotMatch(workflow, /--retry|strategy:|matrix:/u);
  assert.doesNotMatch(workflow, /amazon|aws-actions|opentofu|terraform|kvm|docker/u);
});

test("job and step timeout arithmetic preserves a cleanup/publication reserve", () => {
  const names = [
    "Check out the dispatched repository head only",
    "Gate exact reviewed head and first execution of this dispatch",
    "Run the required bounded privileged double-fork integration",
    "Materialize and bind the exact fixed source manifest",
    "Execute the single native package candidate attempt in this workflow run",
    "Remove native candidate source and runtime residue after proven settlement",
    "Validate and atomically publish the single non-authoritative output from this workflow run",
    "Upload this run's candidate JSON for manual final-pin review only",
    "Check post-upload local identity and write a non-authoritative binding receipt",
    "Upload the separate non-authoritative receipt for this run",
    "Remove this run's local staging bytes",
    "Enforce this run's attempt, cleanup, validation, uploads, and zero residue",
  ];
  const jobMinutes = Number(workflow.match(/^ {4}timeout-minutes: ([0-9]+)$/mu)?.[1]);
  const boundedMinutes = names.reduce((total, name) => total + stepTimeout(name), 0);
  assert.equal(jobMinutes, 90);
  assert.equal(boundedMinutes, 84);
  assert.equal(jobMinutes * 60 - boundedMinutes * 60, 360);
  assert.ok(300 + 10 <= stepTimeout(names[2]) * 60);
  assert.ok(300 + 5 <= stepTimeout(names[3]) * 60);
  assert.ok(3000 + 10 <= stepTimeout(names[4]) * 60);
  assert.ok(2 * (60 + 5) + (130 + 5) + (300 + 5) <= stepTimeout(names[5]) * 60);
  assert.ok(2 * (30 + 5) <= stepTimeout(names[8]) * 60);
});

test("native driver performs one exact retained-rootfs package transaction", () => {
  for (const required of [
    "verifier.acquire_completion_artifacts(",
    "verifier.verify_package_archives(",
    "load_candidate_contract()",
    "exact_runtime_closure()",
    "build._build_once_retained(",
    "build._require_pinned(",
    "package.run_candidate_transaction()",
    "CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET",
    "helper = os.fork()",
    "pid = os.fork()",
    "PID1_FD",
    "MS_REC | MS_PRIVATE",
    "os.chroot(root)",
    "materializer._reload_and_cleanup(",
    "_cleanup_cache(verifier, cache_authority)",
  ])
    assert.ok(driver.includes(required), `missing ${required}`);
  assert.equal(driver.match(/build\._build_once_retained\(/gu)?.length, 1);
  assert.equal(driver.match(/package\.run_candidate_transaction\(\)/gu)?.length, 1);
  assert.doesNotMatch(driver, /retry|for attempt|while attempt/u);
  assert.match(driver, /MAX_RESULT_BYTES = 4096/u);
  assert.match(driver, /CHILD_SECONDS = 1_300/u);
  assert.match(driver, /_open_detached_tree[\s\S]*_run_candidate_child/u);
  assert.match(driver, /MOUNT_ATTR_RDONLY[\s\S]*recursive=True/u);
  assert.match(driver, /signal\.pidfd_send_signal\(pidfd, signal\.SIGKILL\)/u);
  assert.match(driver, /os\.waitid\(os\.P_PIDFD, pidfd, os\.WEXITED\)/u);
  assert.match(driver, /set\(os\.listdir\(f"\{root\}\/dev"\)\) == \{"null", "urandom"\}/u);
  assert.doesNotMatch(
    driver,
    /clone3|PyOS_|ctypes\.pythonapi|os\.kill\(|waitpid\([^,]+,\s*0\)|\/proc", f"\{root\}\/proc"[\s\S]{0,30}MS_BIND/u,
  );
});

test("double-fork protocol keeps cleanup uncertainty sticky and has an outer bound", () => {
  const result = spawnSync("python3", ["test/stage2-package-native-doublefork.py"], {
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /stage2 package double-fork tests passed; native=not-requested/u);
  assert.match(workflow, /COGS_REQUIRE_DOUBLEFORK_NATIVE_TEST=1/u);
  assert.match(workflow, /COGS_DOUBLEFORK_NATIVE_TEST=1/u);
  assert.match(
    workflow,
    /timeout --foreground --signal=TERM --kill-after=10s 300s[\s\S]{0,300}stage2-package-native-doublefork\.py/u,
  );
});

test("fixed settlement owner is invoked around ordinary bounded unmount and deletion", () => {
  const cleanupStart = workflow.indexOf("Remove native candidate source and runtime residue after proven settlement");
  const validateStart = workflow.indexOf("Validate and atomically publish");
  const cleanup = workflow.slice(cleanupStart, validateStart);
  const outcome = cleanup.indexOf('test "$CANDIDATE_ATTEMPT_OUTCOME" = success');
  const before = cleanup.indexOf('stage2-native-settlement.py" scan before-unmount');
  const unmount = cleanup.indexOf('stage2-native-settlement.py" unmount');
  const after = cleanup.indexOf('stage2-native-settlement.py" scan after-unmount');
  const deletion = cleanup.indexOf("/var/lib/cogs /run/cogs-stage2-native-preflight-source-v1");
  assert.ok(0 < outcome && outcome < before && before < unmount && unmount < after && after < deletion);
  assert.match(settlement, /unsettled candidate process/u);
  assert.match(settlement, /unsettled target mount namespace/u);
  assert.match(settlement, /unsettled process path/u);
  assert.match(settlement, /unsettled process descriptor/u);
  assert.match(settlement, /"\/bin\/umount", "--", target/u);
  assert.doesNotMatch(`${workflow}\n${settlement}`, /umount\s+-l|--lazy/u);
});

test("fixed workflow scripts execute hostile process, race, mount, fd, unmount, and receipt cases", () => {
  const result = spawnSync("python3", ["-B", "test/stage2-package-native-workflow-scripts.py"], {
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /stage2 native workflow script tests passed/u);
});

test("partial validation and fsync precede atomic candidate publication", () => {
  const attempt = workflow.indexOf("Execute the single native package candidate attempt in this workflow run");
  const cleanup = workflow.indexOf("Remove native candidate source and runtime residue after proven settlement");
  const validate = workflow.indexOf("Validate and atomically publish");
  const upload = workflow.indexOf("Upload this run's candidate JSON");
  assert.ok(0 < attempt && attempt < cleanup && cleanup < validate && validate < upload);
  const validation = workflow.slice(validate, upload);
  assert.match(validation, /candidate\.partial/u);
  assert.match(validation, /EXPECTED_SOURCE_REVISION: \$\{\{ steps\.fixed_source\.outputs\.revision \}\}/u);
  assert.match(
    validation,
    /EXPECTED_SOURCE_MANIFEST_SHA256: \$\{\{ steps\.fixed_source\.outputs\.manifest_sha256 \}\}/u,
  );
  assert.match(
    validation,
    /validate_native_candidate_result\([\s\S]*EXPECTED_SOURCE_REVISION[\s\S]*EXPECTED_SOURCE_MANIFEST_SHA256/u,
  );
  assert.match(validation, /raw != canonical_json\(value\)/u);
  assert.match(validation, /os\.fsync\(source\.fileno\(\)\)[\s\S]*os\.replace\(partial, final\)/u);
  assert.match(validation, /os\.replace\(partial, final\)[\s\S]*os\.fsync\(directory\)/u);
  assert.doesNotMatch(workflow.slice(attempt, validate), /os\.replace\(partial, final\)/u);
});

test("run-unique uploads use the bounded canonical receipt codec with exact source outputs", () => {
  assert.match(
    workflow,
    /CANDIDATE_STAGING: \/var\/tmp\/cogs-stage2-native-package-candidate-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u,
  );
  assert.match(
    workflow,
    /CANDIDATE_ARTIFACT_NAME: stage2-native-package-candidate-\$\{\{ inputs\.reviewed_head \}\}-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u,
  );
  assert.match(workflow, /RECEIPT_ARTIFACT_NAME: stage2-native-package-candidate-receipt-[^\n]+github\.run_id/u);
  assert.match(workflow, /EXPECTED_SOURCE_REVISION: \$\{\{ steps\.fixed_source\.outputs\.revision \}\}/u);
  assert.match(workflow, /EXPECTED_SOURCE_MANIFEST_SHA256: \$\{\{ steps\.fixed_source\.outputs\.manifest_sha256 \}\}/u);
  assert.match(workflow, /CANDIDATE_ARTIFACT_ID: \$\{\{ steps\.upload\.outputs\.artifact-id \}\}/u);
  assert.match(workflow, /CANDIDATE_ARTIFACT_DIGEST: \$\{\{ steps\.upload\.outputs\.artifact-digest \}\}/u);
  assert.match(workflow, /stage2-native-upload-receipt\.py" create[\s\S]*stage2-native-upload-receipt\.py" validate/u);
  assert.match(receipt, /MAX_RECEIPT_BYTES = 4096/u);
  assert.match(receipt, /validate_native_candidate_result\(value, expected\.revision, expected\.manifest\)/u);
  assert.match(receipt, /duplicate JSON key/u);
  assert.match(receipt, /receipt is not canonical/u);
  assert.match(receipt, /each-dispatch-is-a-distinct-observation-and-must-not-be-merged/u);
  assert.doesNotMatch(workflow, /git (commit|push)|stage2-completion-runtime-v1\.json/u);
});
