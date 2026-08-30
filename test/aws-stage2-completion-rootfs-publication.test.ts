import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const testPath = join(root, "test/aws-stage2-completion-rootfs-publication.py");

test("rootfs pins and accepted publication are strict and fixed", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs publication tests passed/u);
  const pins = await readFile(join(root, "deploy/aws-feasibility/remote/stage2-completion-rootfs-v2.json"), "utf8");
  assert.match(pins, /59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1/u);
  assert.match(pins, /41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397/u);
});
