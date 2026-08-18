import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const py = join(root, "test/aws-stage2-completion-kata-operation.py");
const production = join(root, "deploy/aws-feasibility/remote/completion_kata_operation.py");

test("ADR0099 Slice A durable command journal is optimization-safe", async () => {
  const env = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  for (const args of [[py], ["-O", py]]) {
    const result = spawnSync("python3", args, { cwd: root, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /durable command journal matrix passed/u);
  }
  const source = await readFile(production, "utf8");
  assert.match(source, /COMMAND_INTENT_V2/u);
  assert.match(source, /COMMAND_PREEXEC_V2/u);
  assert.match(source, /COMMAND_OUTCOME_V2/u);
  assert.match(source, /def durable_command_outcome/u);
  assert.doesNotMatch(source, /_make_fake_lifecycle_for_tests|create_fixed_operation_test_local|seal = object\(\)/u);
});
