import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflowPath = ".github/workflows/stage2-package-native-candidate.yml";
const driverPath = "scripts/run-stage2-package-native-candidate.py";
const workflow = readFileSync(workflowPath, "utf8");
const driver = readFileSync(driverPath, "utf8");

test("native package workflow is manual, same-head, one-attempt, and read-only", () => {
  assert.match(workflow, /on:\n {2}workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /\n {2}(push|pull_request|schedule):/u);
  assert.match(workflow, /actions: read\n {2}contents: read/u);
  assert.doesNotMatch(workflow, /permissions:[\s\S]{0,100}(write|id-token)/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.match(workflow, /STAGE2_PACKAGE_REVIEWED_HEAD/u);
  assert.match(workflow, /test "\$\{GITHUB_RUN_ATTEMPT\}" = 1/u);
  assert.match(workflow, /test "\$EXACT_REVIEWED_HEAD" = "\$DISPATCH_HEAD"/u);
  assert.match(workflow, /any\(run_id < current for run_id in ids\)/u);
  assert.doesNotMatch(workflow, /--retry|strategy:|matrix:/u);
  assert.doesNotMatch(workflow, /amazon|aws-actions|open(tofu)?|terraform|kvm|docker/u);
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
    '_libc_call("unshare"',
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
});

test("cleanup and canonical validation gate the only uploaded file", () => {
  const attempt = workflow.indexOf("Execute the sole native package candidate attempt");
  const cleanup = workflow.indexOf("Remove all native candidate source and runtime residue");
  const validate = workflow.indexOf("Validate the sole canonical non-authoritative output");
  const upload = workflow.indexOf("Upload candidate JSON for manual final-pin review only");
  assert.ok(0 < attempt && attempt < cleanup && cleanup < validate && validate < upload);
  assert.match(workflow, /raw != canonical_json\(value\)/u);
  assert.match(workflow, /path: \/var\/tmp\/cogs-stage2-native-package-candidate-v1\/candidate\.json/u);
  assert.doesNotMatch(workflow, /git (commit|push)|stage2-completion-runtime-v1\.json/u);
  assert.match(workflow, /test ! -e \/var\/lib\/cogs/u);
  assert.match(workflow, /test ! -e \/var\/tmp\/cogs-stage2-native-package-candidate-v1/u);
});
