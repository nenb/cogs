import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("dormant production planner emits seven distinct provider-free plans", () => {
  const result = spawnSync("python3", ["-I", "-B", "test/stage2-production-planner.py"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "stage2 production planner provider-free checks passed\n");
});
