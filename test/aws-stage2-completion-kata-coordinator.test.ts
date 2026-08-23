import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("local coordinator exhaustively orders composition and cleanup-only recovery", () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  for (const optimization of [[], ["-O"]]) {
    const result = spawnSync("python3", [...optimization, "-B", "test/aws-stage2-completion-kata-coordinator.py"], {
      cwd: process.cwd(),
      env,
      encoding: "utf8",
      timeout: 15_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /exhaustive composition\/cut\/recovery matrix passed/u);
  }
});
