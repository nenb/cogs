import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflowPath = ".github/workflows/stage2-package-native-candidate.yml";
const driverPath = "scripts/run-stage2-package-native-candidate.py";
const workflow = readFileSync(workflowPath, "utf8");
const driver = readFileSync(driverPath, "utf8");

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
  ]) {
    assert.ok(driver.includes(required), `missing ${required}`);
  }
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

test("cleanup refuses retained-name deletion until producer and namespace settlement are certain", () => {
  const cleanupStart = workflow.indexOf("Remove native candidate source and runtime residue after proven settlement");
  const validateStart = workflow.indexOf("Validate and atomically publish");
  assert.ok(0 < cleanupStart && cleanupStart < validateStart);
  const cleanup = workflow.slice(cleanupStart, validateStart);
  const outcomeGate = cleanup.indexOf('test "$CANDIDATE_ATTEMPT_OUTCOME" = success');
  const preUnmount = cleanup.indexOf("check_settlement before-unmount");
  const ordinaryUnmount = cleanup.indexOf('/bin/umount -- "$path"');
  const postUnmount = cleanup.indexOf("check_settlement after-unmount");
  const retainedDelete = cleanup.indexOf("/var/lib/cogs /run/cogs-stage2-native-preflight-source-v1");
  assert.ok(
    0 < outcomeGate &&
      outcomeGate < preUnmount &&
      preUnmount < ordinaryUnmount &&
      ordinaryUnmount < postUnmount &&
      postUnmount < retainedDelete,
  );
  assert.match(cleanup, /unsettled candidate process/u);
  assert.match(cleanup, /unsettled target mount namespace/u);
  assert.match(cleanup, /unsettled process (path|descriptor)/u);
  assert.doesNotMatch(cleanup, /umount\s+-l|--lazy/u);
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
    /validate_native_candidate_result\(\s*value, os\.environ\["EXPECTED_SOURCE_REVISION"\],\s*os\.environ\["EXPECTED_SOURCE_MANIFEST_SHA256"\]\)/u,
  );
  assert.match(validation, /raw != canonical_json\(value\)/u);
  assert.match(validation, /os\.fsync\(source\.fileno\(\)\)[\s\S]*os\.replace\(partial, final\)/u);
  assert.match(validation, /os\.replace\(partial, final\)[\s\S]*os\.fsync\(directory\)/u);
  assert.doesNotMatch(workflow.slice(attempt, validate), /os\.replace\(partial, final\)/u);
});

test("run-unique uploads are bound by a separate non-authoritative receipt", () => {
  assert.match(
    workflow,
    /CANDIDATE_STAGING: \/var\/tmp\/cogs-stage2-native-package-candidate-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u,
  );
  assert.match(
    workflow,
    /CANDIDATE_ARTIFACT_NAME: stage2-native-package-candidate-\$\{\{ inputs\.reviewed_head \}\}-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u,
  );
  assert.match(workflow, /printf 'revision=%s\\nmanifest_sha256=%s\\n'/u);
  assert.match(workflow, /SOURCE_REVISION: \$\{\{ steps\.fixed_source\.outputs\.revision \}\}/u);
  assert.match(workflow, /CANDIDATE_ARTIFACT_ID: \$\{\{ steps\.upload\.outputs\.artifact-id \}\}/u);
  assert.match(workflow, /CANDIDATE_ARTIFACT_DIGEST: \$\{\{ steps\.upload\.outputs\.artifact-digest \}\}/u);
  assert.match(workflow, /candidate_sha256 != os\.environ\["CANDIDATE_SHA256"\]/u);
  assert.match(workflow, /value = json\.loads\(raw\)/u);
  assert.match(workflow, /validate_native_candidate_result\(value, expected_revision, expected_manifest\)/u);
  assert.match(workflow, /candidate_source = value\["execution_binding"\]/u);
  assert.match(workflow, /"manifest_sha256": candidate_source\["source_manifest_sha256"\]/u);
  assert.match(workflow, /"revision": candidate_source\["source_revision"\]/u);
  assert.match(workflow, /"reviewed_head": os\.environ\["EXACT_REVIEWED_HEAD"\]/u);
  assert.match(workflow, /"run": \{"attempt": int\(run_attempt\), "id": int\(run_id\)\}/u);
  assert.match(workflow, /"digest": artifact_digest/u);
  assert.match(workflow, /"id": int\(artifact_id\)/u);
  assert.match(workflow, /"candidate": \{"bytes": candidate_bytes, "sha256": candidate_sha256\}/u);
  assert.match(workflow, /"authority": "non-authoritative-upload-binding-only"/u);
  assert.match(workflow, /"promotion_authorized": False/u);
  assert.match(workflow, /each-dispatch-is-a-distinct-observation-and-must-not-be-merged/u);
  assert.match(workflow, /Upload the separate non-authoritative receipt for this run/u);
  assert.doesNotMatch(workflow, /git (commit|push)|stage2-completion-runtime-v1\.json/u);
});
