import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { Ajv, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => Ajv;

test("formal CLI bounds pre-main retirement initialization failure", () => {
  const directory = mkdtempSync(join(tmpdir(), "cogs-formal-init-"));
  try {
    for (const [source, name, diagnostic, args] of [
      [
        "scripts/stage2-formal-local-qualification.py",
        "stage2-formal-local-qualification.py",
        "stage2-formal-local-qualification: initialization.failed\n",
        ["grant"],
      ],
      [
        "deploy/aws-feasibility/remote/completion_formal_cycle_full.py",
        "completion_formal_cycle_full.py",
        "stage2-formal-cycle-full: owner.failed\n",
        [],
      ],
      [
        "deploy/aws-feasibility/remote/completion_formal_cycle_readiness.py",
        "completion_formal_cycle_readiness.py",
        "stage2-formal-cycle-readiness: owner.failed\n",
        [],
      ],
    ] as const) {
      const script = join(directory, name);
      copyFileSync(source, script);
      const result = spawnSync("python3", ["-I", "-B", script, ...args], { encoding: "utf8" });
      assert.equal(result.status, 2);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, diagnostic);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("typed formal producers compose with publication, seven-cycle aggregation, and versioned schemas", () => {
  const result = spawnSync("python3", ["-I", "-B", "test/stage2-formal-local-qualification.py", "--schema-samples"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(result.stderr, "");
  const samples = JSON.parse(result.stdout) as {
    receipts: Array<Record<string, unknown> & { source_bindings: Record<string, unknown> }>;
    package: Record<string, unknown>;
  };
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  // Same auto-discovered schema registry as scripts/validate-schemas.ts.
  for (const name of readdirSync("schemas").filter((name) => name.endsWith(".json"))) {
    ajv.addSchema(JSON.parse(readFileSync(`schemas/${name}`, "utf8")));
  }
  const receipt = ajv.getSchema("https://cogs.dev/schemas/stage2-formal-local-cycle-receipt-v2.json");
  const qualified = ajv.getSchema("https://cogs.dev/schemas/stage2-pre-aws-qualification-package-v5.json");
  const historical = ajv.getSchema("https://cogs.dev/schemas/stage2-pre-aws-qualification-package-v4.json");
  assert.ok(receipt && qualified && historical);
  assert.equal(samples.receipts.length, 7);
  for (const value of samples.receipts) {
    assert.equal(receipt(value), true, ajv.errorsText(receipt.errors));
    assert.equal(receipt({ ...value, version: "cogs.stage2-formal-local-cycle-receipt/v1" }), false);
    assert.equal(receipt({ ...value, unexpected: true }), false);
    const bindings = { ...value.source_bindings };
    bindings.runtime_attestation_sha256 = bindings.runtime_manifest_sha256;
    delete bindings.runtime_manifest_sha256;
    assert.equal(receipt({ ...value, source_bindings: bindings }), false);
    assert.equal(receipt({ ...value, source_bindings: { ...value.source_bindings, unexpected: true } }), false);
    if (value.route === "readiness") assert.equal(receipt({ ...value, workloads: [] }), false);
  }
  assert.equal(qualified(samples.package), true, ajv.errorsText(qualified.errors));
  assert.equal(historical(samples.package), false, "historical packages are not silently reinterpreted");
  const renamed: Record<string, unknown> = {
    ...samples.package,
    runtime_commitment: samples.package.runtime_manifest_sha256,
  };
  delete renamed.runtime_manifest_sha256;
  assert.equal(qualified(renamed), false);
  assert.equal(qualified({ ...samples.package, unexpected: true }), false);
});
