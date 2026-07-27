import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = process.cwd();
const python = "/usr/bin/python3";
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
  PYTHONDONTWRITEBYTECODE: "1",
  PYTHONHASHSEED: "0",
};

function run(arguments_: string[], timeout: number) {
  return spawnSync(python, arguments_, {
    cwd: root,
    env,
    encoding: "utf8",
    timeout,
    maxBuffer: 2_097_152,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function requireSuccess(result: ReturnType<typeof run>, label: string) {
  assert.equal(
    result.status,
    0,
    `${label} failed or exceeded its bound\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.error, undefined, `${label} spawn failed`);
}

test("Outcome 2 portable hostile suites are bounded and optimization-safe", () => {
  for (const suite of suites) {
    const path = join(root, "test", suite);
    const result = run(["-I", "-B", path], 30_000);
    requireSuccess(result, suite);
    assert.match(result.stdout, /Outcome 2 .* portable tests passed/u, suite);

    const optimized = run(["-O", "-I", "-B", path], 5_000);
    assert.notEqual(optimized.status, 0, `${suite} accepted optimized Python`);
  }
});

test("Outcome 2 tracked schema independently validates the exact mutation corpus", () => {
  const reportSuite = join(root, "test", "outcome-two-runtime-report-portable.py");
  const result = run(["-I", "-B", reportSuite, "--schema-corpus"], 5_000);
  requireSuccess(result, "report schema corpus producer");
  const rows = result.stdout
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as { id: string; schema: boolean; value: unknown });
  assert.ok(rows.length > 1);
  assert.equal(new Set(rows.map((row) => row.id)).size, rows.length, "duplicate schema case");

  const schema = JSON.parse(readFileSync(join(root, "schemas", "trusted-runtime-closure-v1.json"), "utf8")) as object;
  const validate = new Ajv2020({
    allErrors: true,
    strict: true,
    strictRequired: false,
  }).compile(schema);
  for (const row of rows) {
    assert.equal(
      validate(row.value),
      row.schema,
      `${row.id}: tracked schema expectation diverged: ${JSON.stringify(validate.errors)}`,
    );
  }
});
