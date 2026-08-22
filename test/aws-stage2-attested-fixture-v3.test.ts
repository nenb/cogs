import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const probe = join(root, "test/aws-stage2-attested-fixture-v3.py");

for (const optimized of [false, true]) {
  test(`additive V3 attested static fixture${optimized ? " under Python -O" : ""}`, () => {
    const result = spawnSync("python3", [...(optimized ? ["-O"] : []), "-B", probe], {
      cwd: root,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 120_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "additive V3 attested static fixture tests passed\n");
  });
}
