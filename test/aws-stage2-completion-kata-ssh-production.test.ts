import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";

const root = resolve(process.cwd());
const probe = resolve(root, "test/aws-stage2-completion-kata-ssh-production.py");

for (const optimized of [false, true]) {
  test(`S2 production SSH/input B3 hostile matrix${optimized ? " under -O" : ""}`, () => {
    const result = spawnSync("python3", [...(optimized ? ["-O"] : []), probe], {
      cwd: root,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /production SSH\/input B3 hostile matrix passed/u);
  });
}
