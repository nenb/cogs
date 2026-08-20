import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflowPath = ".github/workflows/stage2-package-native-candidate.yml";
const driverPath = "scripts/run-stage2-package-native-candidate.py";
const workflow = readFileSync(workflowPath, "utf8");
const driver = readFileSync(driverPath, "utf8");

test("native package workflow is manual, same-head, non-rerun, and read-only", () => {
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(push|pull_request|schedule):/u);
  assert.match(workflow, /actions: read\n {2}contents: read/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,100}(write|id-token)/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.match(workflow, /STAGE2_PACKAGE_REVIEWED_HEAD/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_REVIEWED_HEAD" = "\$DISPATCH_HEAD"/u);
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

test("double-fork protocol keeps cleanup uncertainty sticky", () => {
  const result = spawnSync("python3", ["test/stage2-package-native-doublefork.py"], {
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /stage2 package double-fork tests passed; native=not-requested/u);
  assert.match(workflow, /COGS_REQUIRE_DOUBLEFORK_NATIVE_TEST=1/u);
  assert.match(workflow, /COGS_DOUBLEFORK_NATIVE_TEST=1/u);
});

test("cleanup and canonical validation gate the only uploaded file", () => {
  const attempt = workflow.indexOf("Execute the sole native package candidate attempt");
  const cleanup = workflow.indexOf("Remove all native candidate source and runtime residue");
  const validate = workflow.indexOf("Validate the sole canonical non-authoritative output");
  const upload = workflow.indexOf("Upload candidate JSON for manual final-pin review only");
  assert.ok(0 < attempt && attempt < cleanup && cleanup < validate && validate < upload);
  assert.match(workflow, /raw != canonical_json\(value\)/u);
  assert.match(workflow, /candidate\.partial/u);
  assert.match(workflow, /os\.replace\(partial, final\)/u);
  assert.match(workflow, /validate_native_candidate_result\(value\)/u);
  assert.match(workflow, /path: \/var\/tmp\/cogs-stage2-native-package-candidate-v1\/candidate\.json/u);
  assert.doesNotMatch(workflow, /git (commit|push)|stage2-completion-runtime-v1\.json/u);
  assert.match(workflow, /test ! -e \/var\/lib\/cogs/u);
  assert.match(workflow, /test ! -e \/var\/tmp\/cogs-stage2-native-package-candidate-v1/u);
});
