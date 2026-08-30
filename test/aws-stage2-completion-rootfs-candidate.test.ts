import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const testPath = join(root, "test/aws-stage2-completion-rootfs-candidate.py");

test("ADR 0057 candidate qualification is portable and fixed", async () => {
  const portable = spawnSync("python3", ["-I", testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 45_000,
  });
  assert.equal(portable.status, 0, portable.stderr);
  assert.match(portable.stdout, /candidate portable\/static tests passed/u);
  const source = await readFile(testPath, "utf8");
  assert.match(source, /\("F1",[\s\S]*\("F6",/u);
  assert.match(source, /--linux-synthetic/u);
  assert.match(source, /--hosted-exact/u);
  assert.doesNotMatch(source, /(?:import|from) (?:urllib|requests|boto3?|subprocess|socket)/u);
  const hosted = spawnSync("python3", ["-I", testPath, "--hosted-exact"], {
    cwd: root,
    encoding: "utf8",
    timeout: 45_000,
  });
  assert.notEqual(hosted.status, 0);
});
