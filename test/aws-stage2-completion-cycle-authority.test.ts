import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
test("fixed production cycle authority is one-shot and mode-bound", () => {
  for (const optimize of ["", "1", "2"]) {
    const result = spawnSync("python3", ["-I", join(root, "test/aws-stage2-completion-cycle-authority.py")], {
      cwd: root,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONOPTIMIZE: optimize },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "stage2 fixed cycle authority checks passed\n");
  }
});
test("fixed wrappers claim controller grants before production route effects", () => {
  const coordinator = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_kata_coordinator.py"), "utf8");
  const routes = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_cycle_evidence.py"), "utf8");
  assert.match(coordinator, /cycle_authority\.claim_full\(\)/u);
  assert.match(coordinator, /cycle_authority\.claim_readiness\(\)/u);
  assert.match(coordinator, /_owners\.validate_cycle_grant\(lifecycle\)/u);
  assert.match(routes, /type\(grant\) is cycle_authority\.campaign\.CycleLaunchGrant/u);
  assert.match(routes, /authorized = \{synthetic_full, synthetic_readiness\}/u);
  assert.doesNotMatch(routes, /authorized = \{full, readiness\}/u);
});
