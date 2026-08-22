import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();

test("corrected custody and private receipt remain fail-closed", () => {
  const result = spawnSync("python3", ["-B", "test/aws-stage2-completion-kata-admission.py"], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /corrected custody\/private receipt hostile matrix passed/u);

  const coordinator = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_kata_coordinator.py"), "utf8");
  const admission = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_kata_admission.py"), "utf8");
  const receipt = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_local_receipt.py"), "utf8");
  assert.match(coordinator, /preparation_bridge\._claim_fixed_static_preparation\(\)/u);
  assert.doesNotMatch(coordinator, /load_final_pin|_claim_committed_gate/u);
  assert.doesNotMatch(admission, /def _claim_committed_execution_custody/u);
  assert.doesNotMatch(receipt, /def _issue_local_receipt|operation_raw|journal_raw/u);
  assert.match(receipt, /sealed owner execution evidence/u);
});

test("envelope, complete runtime mapping, and ELF closure schemas reject hostile structure", () => {
  const samples = spawnSync("python3", ["-B", "test/aws-stage2-completion-kata-admission.py", "--samples"], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(samples.status, 0, samples.stderr);
  const values = JSON.parse(samples.stdout) as Record<string, Record<string, unknown>>;
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const ajv = new Ajv2020({ strict: true, allErrors: true, ownProperties: true });
  for (const [key, file] of [
    ["envelope", "stage2-local-execution-envelope-v1.json"],
    ["runtime", "stage2-local-runtime-manifest-v1.json"],
    ["contract", "stage2-local-executable-closure-v1.json"],
  ] as const) {
    const validate = ajv.compile(JSON.parse(readFileSync(join(root, "schemas", file), "utf8")) as object);
    const value = values[key];
    assert.ok(value);
    assert.equal(validate(value), true, `${key}: ${JSON.stringify(validate.errors)}`);
    const extra = structuredClone(value);
    extra.untrusted = true;
    assert.equal(validate(extra), false, `${key} accepted an unknown field`);
  }
  const runtime = structuredClone(values.runtime) as {
    static_closure: { objects: unknown[] };
    execution_mapping: { objects: Array<{ execution_path: string }> };
  };
  runtime.static_closure.objects.pop();
  const validateRuntime = ajv.getSchema("https://cogs.invalid/schemas/stage2-local-runtime-manifest-v1.json");
  assert.ok(validateRuntime);
  assert.equal(validateRuntime(runtime), false, "runtime accepted fewer than 35 static objects");
});
