import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const python = "python3";
const suites = [
  "outcome-two-runtime-closure-portable.py",
  "outcome-two-mapped-closure-portable.py",
  "outcome-two-sealing-portable.py",
  "outcome-two-lifecycle-portable.py",
  "outcome-two-recovery-portable.py",
  "outcome-two-runtime-report-portable.py",
  "outcome-two-trusted-launcher-portable.py",
] as const;
const env = {
  PATH: process.env.PATH,
  PYTHONDONTWRITEBYTECODE: "1",
  PYTHONHASHSEED: "0",
};

function run(arguments_: string[], timeout: number) {
  return spawnSync(python, arguments_, {
    cwd: root,
    env,
    encoding: "utf8",
    timeout,
    maxBuffer: 1_048_576,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

test("Outcome 2 portable hostile suites are bounded and optimization-safe", () => {
  for (const suite of suites) {
    const path = join(root, "test", suite);
    const result = run(["-I", "-B", path], 30_000);
    assert.equal(
      result.status,
      0,
      `${suite} failed or exceeded its bound\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    assert.match(result.stdout, /Outcome 2 .* portable tests passed/u, suite);

    const optimized = run(["-O", "-I", "-B", path], 5_000);
    assert.notEqual(optimized.status, 0, `${suite} accepted optimized Python`);
  }
});
