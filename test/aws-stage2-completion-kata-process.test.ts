import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const py = join(root, "test/aws-stage2-completion-kata-process.py");
const production = join(root, "deploy/aws-feasibility/remote/completion_kata_process.py");

test("ADR0099 Slice A fixed process boundary is optimization-safe", async () => {
  const env = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  for (const args of [[py], ["-O", py]]) {
    const result = spawnSync("python3", args, { cwd: root, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /fixed process transaction matrix passed/u);
  }
  const source = await readFile(production, "utf8");
  assert.match(source, /CLOCK_BOOTTIME/u);
  assert.match(source, /pidfd_send_signal/u);
  assert.match(source, /cgroup\.procs/u);
  assert.match(source, /absolute_deadline_ns/u);
  assert.doesNotMatch(source, /COGS_KATA_PROCESS_TESTING_V1|def _supervise\(|def _make_test_issuer\(/u);
  assert.doesNotMatch(source, /^def (?:execute|run|spawn|issue_command|spec)\(/mu);
});
