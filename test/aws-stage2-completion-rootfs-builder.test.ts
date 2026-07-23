import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_builder.py");
const testPath = join(root, "test/aws-stage2-completion-rootfs-builder.py");

test("D-R2.2c exposes only fixed recover-owned and keeps bootstrap private", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs builder portable tests passed/u);

  const source = await readFile(modulePath, "utf8");
  assert.match(source, /argv != \["recover-owned"\]/u);
  assert.match(source, /RECOVER_SECONDS = 120/u);
  assert.match(source, /LOCK_EX \| fcntl\.LOCK_NB/u);
  assert.doesNotMatch(source, /rmtree|os\.walk|glob|subprocess|socket|os\.environ|os\.getenv|argparse/u);
  assert.doesNotMatch(source, /boto3?|terraform|requests|urllib/u);
});
