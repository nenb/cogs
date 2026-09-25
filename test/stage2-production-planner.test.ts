import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
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

test("production feasibility validators admit the exact ten-hour planner contract", () => {
  const planner = readFileSync("scripts/stage2-production-planner.py", "utf8");
  const checker = readFileSync("deploy/aws-feasibility/check-plan.py", "utf8");
  const terraform = readFileSync("deploy/aws-feasibility/main.tf", "utf8");
  assert.match(planner, /"expires_unix_ns": now \+ 10 \* 60 \* 60 \* 10\*\*9/u);
  assert.match(checker, /30 \* 60 < remaining < 10 \* 60 \* 60/u);
  assert.doesNotMatch(checker, /remaining < 8 \* 60 \* 60/u);
  assert.match(terraform, /timeadd\(timestamp\(\), "10h"\)/u);
  assert.doesNotMatch(terraform, /timeadd\(timestamp\(\), "8h"\)/u);
});
