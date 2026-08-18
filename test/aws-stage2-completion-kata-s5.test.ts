import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const remote = join(root, "deploy/aws-feasibility/remote");
const py = join(root, "test/aws-stage2-completion-kata-s5.py");

test("ADR0099 Slice A entry remains fail-closed", async () => {
  const env = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  for (const args of [[py], ["-O", py]]) {
    const result = spawnSync("python3", args, { cwd: root, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Slice A fail-closed foundation matrix passed/u);
  }
  const [qualification, shell, fdmap] = await Promise.all([
    readFile(join(remote, "completion_kata_qualification.py"), "utf8"),
    readFile(join(remote, "run-stage2-completion-remote.sh"), "utf8"),
    readFile(join(remote, "completion_kata_fdmap.py"), "utf8"),
  ]);
  assert.doesNotMatch(qualification, /CommittedGate|_claim_committed_gate|seal = object\(\)/u);
  assert.match(shell, /\/usr\/bin\/env -i/u);
  assert.match(shell, /\/usr\/bin\/python3 -I -B/u);
  assert.match(fdmap, /content_sha256/u);
  assert.doesNotMatch(fdmap, /make_input_owner_for_tests|seal = object\(\)/u);
});
