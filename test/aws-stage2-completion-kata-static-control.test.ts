import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();
const python = (samples = false) =>
  spawnSync("python3", ["-B", "test/aws-stage2-completion-kata-static-control.py", ...(samples ? ["--samples"] : [])], {
    cwd: root,
    encoding: "utf8",
    timeout: 60_000,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });

test("V2 static control is deterministic, no-KVM, and hostile-input closed", () => {
  const result = python();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /static V2 control\/no-KVM admission hostile matrix passed/u);
});

test("V1 and V2 static schemas compile independently without changing V1", () => {
  const result = python(true);
  assert.equal(result.status, 0, result.stderr);
  const samples = JSON.parse(result.stdout) as Record<string, Record<string, unknown>>;
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
  const ajv = new Ajv2020({ strict: true, allErrors: true, ownProperties: true });
  addFormats(ajv);
  for (const file of [
    "stage2-local-executable-closure-v1.json",
    "stage2-local-execution-envelope-v1.json",
    "stage2-local-runtime-manifest-v1.json",
    "stage2-local-static-control-package-v1.json",
    "stage2-local-execution-envelope-v2.json",
    "stage2-local-runtime-manifest-v2.json",
  ]) {
    ajv.addSchema(JSON.parse(readFileSync(join(root, "schemas", file), "utf8")) as object);
  }
  for (const [name, file] of [
    ["control", "stage2-local-static-control-package-v1.json"],
    ["envelope", "stage2-local-execution-envelope-v2.json"],
    ["runtime", "stage2-local-runtime-manifest-v2.json"],
  ] as const) {
    const validate = ajv.getSchema(`https://cogs.invalid/schemas/${file}`);
    assert.ok(validate);
    const sample = samples[name];
    assert.ok(sample);
    assert.equal(validate(sample), true, `${name}: ${JSON.stringify(validate.errors)}`);
    const hostile = structuredClone(sample);
    hostile.unreviewed = true;
    assert.equal(validate(hostile), false, `${name} schema accepted an extra field`);
  }
});
