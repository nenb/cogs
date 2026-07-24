import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_lease.py");
const testPath = join(root, "test/aws-stage2-completion-rootfs-lease.py");

test("Stage A retained rootfs lease is private, fixed, and preservation-only", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 600_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs lease portable behavioral matrix: \d+ finite cases/u);
  assert.match(result.stdout, /completion rootfs lease portable tests passed/u);

  const source = await readFile(modulePath, "utf8");
  const harness = await readFile(testPath, "utf8");
  assert.match(harness, /if argv == \["--real"\]/u);
  assert.match(harness, /elif not argv:/u);
  // Harness-only correction: reject assignment without treating equality as assignment.
  assert.doesNotMatch(harness, /build_module\.BUILD_SECONDS\s*=(?!=)/u);
  assert.ok(
    harness.indexOf("lease_module._close_preserving(held.retained)") <
      harness.indexOf('builder_module.main(["recover-owned"])'),
  );
  assert.match(source, /def _stable_lease_pass/u);
  assert.match(source, /LOCK_EX \| fcntl\.LOCK_NB/u);
  assert.doesNotMatch(source, /release-authorized|subprocess|\/proc\/self\/fd|resolve\(\)/u);
});
