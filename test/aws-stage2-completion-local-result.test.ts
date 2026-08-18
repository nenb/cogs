import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();
const portable = join(root, "test/aws-stage2-completion-local-result.py");
const producer = join(root, "deploy/aws-feasibility/remote/completion_local_full.py");
const schemaName = "stage2-workload-local-qualification-v2.json";
const schemaPath = join(root, "schemas", schemaName);
const LOCAL_RESULT_SCHEMA_REGISTRY = [
  {
    version: "cogs.stage2-workload-local-qualification/v2",
    file: schemaName,
  },
] as const;

for (const optimized of [false, true]) {
  test(`local qualification result codec is strict${optimized ? " under python -O" : ""}`, () => {
    const result = spawnSync("python3", [...(optimized ? ["-O"] : []), "-B", portable], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /completion local result codec tests passed/u);
  });
}

test("local result schema registry compiles only the new v2 contract", () => {
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  assert.deepEqual(
    LOCAL_RESULT_SCHEMA_REGISTRY.map(({ file }) => file),
    [schemaName],
  );
  for (const entry of LOCAL_RESULT_SCHEMA_REGISTRY) {
    const schema = JSON.parse(readFileSync(join(root, "schemas", entry.file), "utf8")) as {
      $id: string;
      properties: { version: { const: string } };
    };
    assert.equal(schema.properties.version.const, entry.version);
    assert.doesNotThrow(() => ajv.compile(schema));
  }
});

test("zero-argument production stub cannot consume report authority", () => {
  const source = readFileSync(producer, "utf8");
  const schema = readFileSync(schemaPath, "utf8");
  for (const args of [[], ["report.json"], ["--qualified"]]) {
    const result = spawnSync("python3", ["-B", producer, ...args], {
      cwd: root,
      input: '{"qualified":true}\n',
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
    });
    assert.equal(result.status, 3);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
  }
  assert.match(source, /^def main\(\):$/mu);
  assert.doesNotMatch(source, /argparse|sys\.stdin|input\(|open_fixed_coordinator|run_fixed_local_qualification/u);
  assert.doesNotMatch(source, /boto|AWS_|requests|urllib|socket|subprocess|terraform|tofu/iu);
  const gross = source.split("\n").length - 1 + schema.split("\n").length - 1;
  assert.ok(gross <= 700, `local result production additions exceed 700 lines: ${gross}`);
});
