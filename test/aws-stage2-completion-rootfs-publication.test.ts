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
  const pins = await readFile(join(root, "deploy/aws-feasibility/remote/stage2-completion-rootfs-v1.json"), "utf8");
  assert.match(pins, /8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691/u);
  assert.match(pins, /47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3/u);
});
