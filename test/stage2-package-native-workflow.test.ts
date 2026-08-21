import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflowPath = ".github/workflows/stage2-package-native-candidate.yml";
const driverPath = "scripts/run-stage2-package-native-candidate.py";
const settlementPath = "scripts/stage2-native-settlement.py";
const publicationPath = "scripts/stage2-native-publication.py";
const receiptPath = "scripts/stage2-native-upload-receipt.py";
const buildPath = "deploy/aws-feasibility/remote/completion_rootfs_build.py";
const materializerPath = "deploy/aws-feasibility/remote/completion_rootfs_materializer.py";
const workflow = readFileSync(workflowPath, "utf8");
const driver = readFileSync(driverPath, "utf8");
const settlement = readFileSync(settlementPath, "utf8");
const publication = readFileSync(publicationPath, "utf8");
const receipt = readFileSync(receiptPath, "utf8");
const build = readFileSync(buildPath, "utf8");
const materializer = readFileSync(materializerPath, "utf8");

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
    "Download the exact uploaded candidate artifact into this run's readback staging",
    "Validate the sole uploaded candidate member against frozen source-bound bytes",
    "Check post-upload readback identity and write a non-authoritative binding receipt",
    "Upload the separate non-authoritative receipt for this run",
    "Download the exact uploaded receipt artifact into run-unique readback staging",
    "Validate the sole receipt readback against candidate source and artifact identity",
    "Remove this run's local staging bytes",
    "Enforce this run's attempt, cleanup, validation, uploads, and zero residue",
  ];
  const jobMinutes = Number(workflow.match(/^ {4}timeout-minutes: ([0-9]+)$/mu)?.[1]);
  const boundedMinutes = names.reduce((total, name) => total + stepTimeout(name), 0);
  const timeoutAt = (index: number): number => {
    const name = names[index];
    assert.ok(name);
    return stepTimeout(name);
  };
  assert.equal(jobMinutes, 90);
  assert.equal(boundedMinutes, 87);
  assert.equal(jobMinutes * 60 - boundedMinutes * 60, 180);
  assert.ok(300 + 10 <= timeoutAt(2) * 60);
  assert.ok(300 + 5 <= timeoutAt(3) * 60);
  assert.ok(3000 + 10 <= timeoutAt(4) * 60);
  assert.ok(2 * (60 + 5) + (130 + 5) + (300 + 5) <= timeoutAt(5) * 60);
  assert.ok(45 + 5 <= timeoutAt(9) * 60);
  assert.ok(45 + 5 <= timeoutAt(10) * 60);
  assert.ok(45 + 5 <= timeoutAt(13) * 60);
});

test("native driver performs one exact retained-rootfs package transaction", () => {
  for (const required of [
    "verifier.acquire_completion_artifacts(",
    "verifier.verify_package_archives(",
    "load_candidate_contract()",
    "exact_runtime_closure()",
    "build._native_package_build_once_retained(",
    "build._require_pinned(",
    "package.run_candidate_transaction()",
    "CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET",
    "helper = os.fork()",
    "pid = os.fork()",
    "PID1_FD",
    "MS_REC | MS_PRIVATE",
    "os.chroot(root)",
    "materializer._reload_and_cleanup(",
    "_cleanup_cache(verifier, cache_authority, lifecycle_deadline_ns)",
  ])
    assert.ok(driver.includes(required), `missing ${required}`);
  assert.equal(driver.match(/build\._native_package_build_once_retained\(/gu)?.length, 1);
  assert.equal(driver.match(/package\.run_candidate_transaction\(\)/gu)?.length, 1);
  assert.match(driver, /rootfs_deadline_ns = lifecycle_deadline_ns - CLEANUP_RESERVE_SECONDS \* NS/u);
  assert.match(build, /BUILD_SECONDS = 900/u);
  assert.match(build, /NATIVE_PACKAGE_BUILD_SECONDS = 1_200/u);
  assert.match(build, /NATIVE_PACKAGE_CLEANUP_RESERVE_SECONDS = 600/u);
  assert.match(build, /work_boundary = outer\.deadline_ns - NATIVE_PACKAGE_CLEANUP_RESERVE_SECONDS/u);
  assert.match(materializer, /MATERIALIZE_SECONDS = 900/u);
  assert.match(materializer, /NATIVE_PACKAGE_MATERIALIZE_SECONDS = 1_200/u);
  assert.doesNotMatch(driver, /BUILD_SECONDS\s*=|MATERIALIZE_SECONDS\s*=/u);
  assert.doesNotMatch(driver, /retry|for attempt|while attempt/u);
  const constant = (name: string): number => {
    const match = driver.match(new RegExp(`^${name} = ([0-9_]+)$`, "mu"));
    assert.ok(match?.[1]);
    return Number(match[1].replaceAll("_", ""));
  };
  assert.match(driver, /MAX_RESULT_BYTES = 4096/u);
  assert.equal(constant("OUTER_SECONDS"), 2_700);
  assert.equal(constant("CHILD_SECONDS"), 1_300);
  const launcherReserve = constant("CLEANUP_RESERVE_SECONDS");
  const buildReserve = Number(
    build.match(/^NATIVE_PACKAGE_CLEANUP_RESERVE_SECONDS = ([0-9_]+)$/mu)?.[1]?.replaceAll("_", ""),
  );
  const commandGuard = workflow.match(
    /timeout --foreground --signal=TERM --kill-after=([0-9]+)s ([0-9]+)s[\s\S]{0,500}run-stage2-package-native-candidate\.py/u,
  );
  assert.ok(commandGuard?.[1] && commandGuard[2]);
  const killGrace = Number(commandGuard[1]);
  const commandSeconds = Number(commandGuard[2]);
  assert.equal(launcherReserve, 600);
  assert.equal(buildReserve, launcherReserve);
  assert.equal(constant("REAP_SECONDS"), 15);
  assert.equal(constant("POST_KILL_REAP_SECONDS"), 5);
  assert.equal(2_700 - launcherReserve, 2_100);
  assert.ok(2_100 + 15 < 2_700);
  assert.equal(commandSeconds, 3_000);
  assert.equal(killGrace, 10);
  assert.ok(
    2_700 < commandSeconds &&
      commandSeconds + killGrace <=
        stepTimeout("Execute the single native package candidate attempt in this workflow run") * 60,
  );
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
  const beforeTag = cleanup.indexOf("native cleanup stage:scan-before-unmount");
  const before = cleanup.indexOf('stage2-native-settlement.py" scan before-unmount');
  const unmountTag = cleanup.indexOf("native cleanup stage:ordinary-unmount");
  const unmount = cleanup.indexOf('stage2-native-settlement.py" unmount');
  const afterTag = cleanup.indexOf("native cleanup stage:scan-after-unmount");
  const after = cleanup.indexOf('stage2-native-settlement.py" scan after-unmount');
  const removeTag = cleanup.indexOf("native cleanup stage:remove-fixed-roots");
  const remove = cleanup.indexOf("/bin/rm -rf --one-file-system");
  const deletion = cleanup.indexOf("/var/lib/cogs /run/cogs-stage2-native-preflight-source-v1");
  const verifyTag = cleanup.indexOf("native cleanup stage:verify-zero-residue");
  const verify = cleanup.indexOf("test ! -e /var/lib/cogs");
  assert.ok(
    0 < outcome &&
      outcome < beforeTag &&
      beforeTag < before &&
      before < unmountTag &&
      unmountTag < unmount &&
      unmount < afterTag &&
      afterTag < after &&
      after < removeTag &&
      removeTag < remove &&
      remove < deletion &&
      deletion < verifyTag &&
      verifyTag < verify,
  );
  assert.match(settlement, /unsettled candidate process/u);
  assert.match(settlement, /unsettled target mount namespace/u);
  assert.match(settlement, /unsettled process path/u);
  assert.match(settlement, /unsettled process descriptor/u);
  assert.match(settlement, /MAX_SCAN_PASSES = 120/u);
  assert.match(settlement, /REQUIRED_STABLE_PASSES = 3/u);
  assert.match(settlement, /native settlement failed:/u);
  assert.match(cleanup, /native cleanup stage:scan-before-unmount/u);
  assert.match(cleanup, /native cleanup stage:ordinary-unmount/u);
  assert.match(cleanup, /native cleanup stage:scan-after-unmount/u);
  assert.match(cleanup, /native cleanup stage:remove-fixed-roots/u);
  assert.match(cleanup, /native cleanup stage:verify-zero-residue/u);
  assert.match(settlement, /_starttime/u);
  assert.match(settlement, /FIXED_TARGETS \+ \(_candidate_target\(environ\),\)/u);
  assert.match(workflow, /CANDIDATE_STAGING="\$CANDIDATE_STAGING"[\s\S]{0,300}stage2-native-settlement\.py" scan/u);
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
  assert.match(validation, /stage2-native-publication\.py" publish/u);
  assert.match(publication, /"candidate\.partial"/u);
  assert.match(validation, /EXPECTED_SOURCE_REVISION: \$\{\{ steps\.fixed_source\.outputs\.revision \}\}/u);
  assert.match(
    validation,
    /EXPECTED_SOURCE_MANIFEST_SHA256: \$\{\{ steps\.fixed_source\.outputs\.manifest_sha256 \}\}/u,
  );
  assert.match(publication, /os\.O_NOFOLLOW/u);
  assert.match(workflow.slice(validate, upload), /sudo -n[\s\S]*stage2-native-publication\.py" publish/u);
  assert.match(publication, /"candidate\.fresh", os\.O_WRONLY \| os\.O_CREAT \| os\.O_EXCL/u);
  assert.match(publication, /os\.fchown\(fresh, frozen_uid, frozen_gid\)/u);
  assert.match(publication, /os\.fchmod\(fresh, 0o444\)/u);
  assert.match(publication, /os\.unlink\("candidate\.partial", dir_fd=directory\)/u);
  assert.doesNotMatch(publication, /os\.fchown\((source|descriptor),/u);
  assert.match(publication, /os\.fchmod\(directory, 0o555\)/u);
  assert.match(publication, /writable shared mapping/u);
  assert.match(publication, /_generation\(after\) != _generation\(before\)/u);
  assert.match(publication, /prove_no_writable_aliases/u);
  assert.match(publication, /MAX_ALIAS_PASSES = 120/u);
  assert.match(publication, /MAX_LARGE_PROC_BYTES = 8 \* 1024 \* 1024/u);
  assert.match(publication, /os\.scandir/u);
  assert.match(publication, /generation in inspected/u);
  assert.match(publication, /coverage\.get\(generation, 0\) \+ 1/u);
  assert.match(publication, /native publication failed:/u);
  assert.match(publication, /validate_native_candidate_result\(value, revision, manifest\)/u);
  assert.match(publication, /raw != canonical_json\(value\)/u);
  assert.match(publication, /os\.fsync\(fresh\)[\s\S]*os\.rename\(/u);
  assert.match(publication, /os\.rename\([\s\S]*os\.fsync\(directory\)[\s\S]*readback_raw/u);
  assert.doesNotMatch(workflow.slice(attempt, validate), /os\.rename\(/u);
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
  assert.match(workflow, /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/u);
  assert.match(workflow, /artifact-ids: \$\{\{ steps\.upload\.outputs\.artifact-id \}\}/u);
  assert.match(workflow, /digest-mismatch: error/u);
  assert.match(workflow, /stage2-native-upload-receipt\.py" readback/u);
  assert.match(workflow, /UPLOAD_READBACK_OUTCOME: \$\{\{ steps\.validate_upload_readback\.outcome \}\}/u);
  assert.match(workflow, /sudo -n[\s\S]*stage2-native-upload-receipt\.py" create/u);
  assert.match(workflow, /artifact-ids: \$\{\{ steps\.receipt_upload\.outputs\.artifact-id \}\}/u);
  assert.match(workflow, /RECEIPT_ARTIFACT_DIGEST: \$\{\{ steps\.receipt_upload\.outputs\.artifact-digest \}\}/u);
  assert.match(workflow, /stage2-native-upload-receipt\.py" receipt-readback/u);
  assert.match(receipt, /MAX_RECEIPT_BYTES = 4096/u);
  assert.match(receipt, /os\.O_NOFOLLOW/u);
  assert.match(receipt, /uploaded candidate member differs from published candidate/u);
  assert.match(receipt, /candidate_upload_readback/u);
  assert.match(receipt, /upload readback success is required/u);
  assert.match(receipt, /validate_native_candidate_result\(value, expected\.revision, expected\.manifest\)/u);
  assert.match(receipt, /duplicate JSON key/u);
  assert.match(receipt, /receipt is not canonical/u);
  assert.match(receipt, /uploaded receipt member differs from frozen receipt/u);
  assert.match(receipt, /staging is not root-owned and non-writable/u);
  assert.match(workflow, /sudo -n[\s\S]*\/bin\/rm -rf -- "\$CANDIDATE_STAGING"/u);
  assert.match(receipt, /each-dispatch-is-a-distinct-observation-and-must-not-be-merged/u);
  assert.doesNotMatch(workflow, /git (commit|push)|stage2-completion-runtime-v1\.json/u);
});
