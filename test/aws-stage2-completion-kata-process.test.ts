import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const productionPath = join(root, "deploy/aws-feasibility/remote/completion_kata_process.py");
const pythonTestPath = join(root, "test/aws-stage2-completion-kata-process.py");

test("S1 closed process owner and fixed local supervisor fail closed", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [pythonTestPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(result.status, 0, result.stderr);
  if (process.platform === "linux" && process.arch === "x64") {
    assert.match(result.stdout, /completion Kata process LINUX AMD64 QUALIFIED matrix passed/u);
  } else {
    assert.match(result.stdout, /(?:LINUX AMD64 QUALIFIED matrix passed|supervisor matrix SKIPPED)/u);
  }

  const optimized = spawnSync("python3", ["-O", pythonTestPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.notEqual(optimized.status, 0);

  const source = await readFile(productionPath, "utf8");
  const productionLines = source.split("\n").length - 1;
  assert.ok(productionLines <= 1_000, `S1 production exceeds retained hard 1000: ${productionLines}`);
  assert.match(source, /CommandId = actions\.CommandId/u);
  assert.match(source, /def _parse_contract\(raw, expected_sha256\):/u);
  assert.match(source, /F_SEAL_WRITE \| fcntl\.F_SEAL_GROW \| fcntl\.F_SEAL_SHRINK \| fcntl\.F_SEAL_SEAL/u);
  assert.match(source, /os\.setsid\(\)/u);
  assert.match(source, /if spec\.inherited_fds:\n {12}_install_inherited_fds\(spec\.inherited_fds\)/u);
  assert.match(source, /os\.fork\(\)/u);
  assert.match(source, /os\.pidfd_open\(pid, 0\)/u);
  assert.match(source, /libc\.syscall\(322, descriptor, b"", arguments, environment, 0x1000\)/u);
  assert.match(source, /os\.killpg\(identity\.pgid, signal\.SIGTERM\)/u);
  assert.match(source, /os\.killpg\(identity\.pgid, signal\.SIGKILL\)/u);
  assert.match(source, /os\.waitpid\(pid, os\.WNOHANG\)/u);
  assert.match(source, /libc\.syscall\(436,/u);
  assert.doesNotMatch(source, /RLIMIT_NOFILE|os\.closerange/u);
  assert.match(source, /MAX_STREAM = 65_536/u);
  assert.match(source, /Deliberately no production execute\/run function/u);
  assert.match(source, /class FixedProcessOwner/u);
  assert.match(source, /operation-derived process outcome required/u);
  assert.doesNotMatch(source, /^def (?:run|execute|spawn|issue_command)\(/mu);
  assert.doesNotMatch(source, /subprocess|shell=True|os\.system|pkill|killall|timeout\(1\)/u);
  assert.doesNotMatch(source, /completion_kata_operation/u);
});
