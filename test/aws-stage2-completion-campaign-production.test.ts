import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

const root = join(import.meta.dirname, "..");
const probe = join(root, "test/aws-stage2-completion-campaign-production.py");
const source = readFileSync(join(root, "deploy/aws-feasibility/completion_campaign_production.py"), "utf8");

test("provider-free production controller enforces seven independent ordered cycles", () => {
  for (const optimize of [[], ["-O"], ["-OO"]]) {
    const result = spawnSync("python3", ["-I", "-B", ...optimize, probe], {
      cwd: root,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        PYTHONDONTWRITEBYTECODE: "1",
        TMPDIR: tmpdir(),
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "stage2 provider-free production campaign controller checks passed\n");
  }
});

test("actual canonical continuation and admission conform to their registered schemas", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-continuation-schema-"));
  const output = join(temporary, "output");
  try {
    const result = spawnSync("python3", ["-I", "-B", probe], {
      cwd: root,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        PYTHONDONTWRITEBYTECODE: "1",
        TMPDIR: tmpdir(),
        COGS_STAGE2_SCHEMA_OUTPUT: output,
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    for (const [artifact, schema] of [
      ["continuation.json", "aws-stage2-production-continuation-v1.json"],
      ["admission.json", "aws-stage2-production-continuation-admission-v1.json"],
    ] as const) {
      const validate = ajv.compile(JSON.parse(readFileSync(join(root, "schemas", schema), "utf8")));
      assert.equal(
        validate(JSON.parse(readFileSync(join(output, artifact), "utf8"))),
        true,
        JSON.stringify(validate.errors),
      );
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("production controller is pure while issuing only adapter-sealed, receipt-bound effects", () => {
  assert.doesNotMatch(source, /\b(?:boto|botocore|subprocess|socket|urllib|requests|terraform|opentofu)\b/iu);
  // Only prerequisite validation may read fixed local policy/contract files;
  // the controller and its receipt types remain free of filesystem effects.
  const prerequisites = source.slice(
    source.indexOf("QUALIFICATION_PACKAGE_VERSION ="),
    source.indexOf("class RemoteQemuBindings:"),
  );
  const controller = source.replace(prerequisites, "");
  assert.doesNotMatch(controller, /\bos\.|Path\(|\bopen\(|getenv|environ|FakeCampaignPorts/u);
  assert.doesNotMatch(prerequisites, /\bos\.|\bopen\(|getenv|environ|write_bytes|write_text/u);
  assert.equal((prerequisites.match(/\.read_bytes\(\)/gu) ?? []).length, 2);
  assert.equal((prerequisites.match(/runpy\.run_path\(/gu) ?? []).length, 1);
  assert.match(prerequisites, /schemas\/stage2-formal-local-cycle-receipt-v2\.json/u);
  assert.match(prerequisites, /workflows\/stage2-prebuilt-local-kata-qualification\.yml/u);
  assert.match(prerequisites, /scripts\/stage2-revision-retirement\.py/u);
  assert.match(
    source,
    /CYCLE_MODES = \("full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness"\)/u,
  );
  assert.match(source, /INVENTORY_CATEGORIES =/u);
  for (const category of [
    "ec2_instances",
    "ebs_volumes",
    "network_interfaces",
    "eni_public_associations",
    "elastic_ips",
    "vpcs",
    "routes",
  ])
    assert.match(source, new RegExp(`"${category}"`, "u"));
  assert.match(source, /class CampaignContinuation/u);
  assert.match(source, /class ContinuationAdmission/u);
  assert.match(source, /class AuthenticatedPhaseOne/u);
  assert.match(source, /def run_phase_one\(self\):/u);
  assert.match(source, /def run_phase_two\(self, authenticated\):/u);
  assert.doesNotMatch(source, /def run_(?:first|second)_segment/u);
  assert.doesNotMatch(source, /\n {4}def run\(self\):/u);
  assert.match(source, /github_run_attempt == 1/u);
  assert.match(source, /_journal_checkpoint/u);
  assert.match(source, /class CleanupReceipt/u);
  assert.match(source, /self\.ports\.recover\(/u);
  assert.doesNotMatch(
    source.slice(source.indexOf("except BaseException as primary")),
    /self\.ports\.effect\("destroy"/u,
  );
  assert.match(source, /self\.final_zero_unix_ns - self\.first_apply_unix_ns/u);
  assert.match(source, /all\(len\(set\(values\)\) == 7/u);
});
