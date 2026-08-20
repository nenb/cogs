import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const script = "test/aws-stage2-completion-kata-network-production.py";

for (const optimized of [false, true]) {
  test(`ADR0099 fixed production network lifecycle${optimized ? " under python -O" : ""}`, () => {
    const args = optimized ? ["-O", script] : [script];
    const result = spawnSync("python3", args, {
      cwd: process.cwd(),
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /fixed production network lifecycle matrix passed/u);
  });
}
