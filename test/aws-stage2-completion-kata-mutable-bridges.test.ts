import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("mutable Kata owner bridges are narrow and fault-cut", () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const result = spawnSync("python3", ["-B", "test/aws-stage2-completion-kata-mutable-bridges.py"], {
    cwd: process.cwd(),
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /mutable owner bridges and no-KVM fault cuts passed/u);
  const budget = spawnSync("python3", ["scripts/check-stage2-retained-lines.py"], {
    cwd: process.cwd(),
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(budget.status, 0, budget.stderr);
  const report = JSON.parse(budget.stdout) as {
    mutable_owner_files: string[];
    mutable_owner_lines: number;
    mutable_owner_line_limit: number;
    mutable_owner_line_limit_satisfied: boolean;
  };
  assert.deepEqual(report.mutable_owner_files, [
    "deploy/aws-feasibility/remote/completion_kata_operation_bridge.py",
    "deploy/aws-feasibility/remote/completion_kata_execution_bridge.py",
  ]);
  assert.equal(report.mutable_owner_line_limit, 2000);
  assert.equal(report.mutable_owner_line_limit_satisfied, true);
  assert.ok(report.mutable_owner_lines < report.mutable_owner_line_limit);
});
