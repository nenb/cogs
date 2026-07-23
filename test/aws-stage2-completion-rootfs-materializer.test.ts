import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_materializer.py");
const testPath = join(root, "test/aws-stage2-completion-rootfs-materializer.py");

test("D-R2.3 has one fixed direct writer and complete postwalk without CLI", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs materializer portable tests passed/u);
  const source = await readFile(modulePath, "utf8");
  assert.match(source, /revalidate_build_inputs/u);
  assert.match(source, /def _postwalk/u);
  assert.doesNotMatch(source, /if __name__|sys\.argv|argparse|rmtree|os\.walk|glob|subprocess|socket|tarfile/u);
});
