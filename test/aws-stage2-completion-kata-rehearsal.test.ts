import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const coordinator = readFileSync("deploy/aws-feasibility/remote/completion_kata_coordinator.py", "utf8");
const full = readFileSync("deploy/aws-feasibility/remote/completion_cycle_full_rehearsal.py", "utf8");
const readiness = readFileSync("deploy/aws-feasibility/remote/completion_cycle_readiness_rehearsal.py", "utf8");
const fullWrapper = readFileSync("deploy/aws-feasibility/remote/run-stage2-completion-full-rehearsal.sh", "utf8");
const readinessWrapper = readFileSync(
  "deploy/aws-feasibility/remote/run-stage2-completion-readiness-rehearsal.sh",
  "utf8",
);

test("authentic full and readiness rehearsals enter production routes but cannot mint", () => {
  assert.match(
    coordinator,
    /def _run_fixed_full_rehearsal\(\):[\s\S]*?_run_cycle\(cycle_evidence\._fixed_full_route\(\),[\s\S]*?False\)/u,
  );
  assert.match(
    coordinator,
    /def _run_fixed_readiness_rehearsal\(\):[\s\S]*?_run_cycle\(cycle_evidence\._fixed_readiness_route\(\),[\s\S]*?False\)/u,
  );
  const finish = coordinator.slice(coordinator.indexOf("def _finish("), coordinator.indexOf("def _run_cycle("));
  assert.match(finish, /if not mint:[\s\S]*?_owners\.abort_custody/u);
  assert.match(finish, /return cycle_evidence\._issue_cycle_receipt/u);
  for (const source of [full, readiness]) {
    assert.doesNotMatch(source, /_issue_cycle_receipt|_consume_cycle_receipt|completion_cycle_evidence/u);
    assert.match(source, /is not None/u);
  }
});

test("rehearsal wrappers are zero-argument, isolated, and credential-denying", () => {
  for (const source of [fullWrapper, readinessWrapper]) {
    assert.match(source, /\[ "\$#" -eq 0 \] \|\| exit 64/u);
    assert.match(source, /AWS_ACCESS_KEY_ID/u);
    assert.match(source, /env -i/u);
    assert.doesNotMatch(source, /completion_cycle_(?:full|readiness)\.py/u);
  }
  assert.match(fullWrapper, /completion_cycle_full_rehearsal\.py/u);
  assert.match(readinessWrapper, /completion_cycle_readiness_rehearsal\.py/u);
});
