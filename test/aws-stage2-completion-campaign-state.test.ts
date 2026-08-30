import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const root = resolve(process.cwd());
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const schema = JSON.parse(
  readFileSync(resolve(root, "schemas/aws-stage2-completion-private-evidence-v1.json"), "utf8"),
) as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validate = ajv.compile(schema) as ValidateFunction;
const digest = (label: string): string => createHash("sha256").update(`fake-only:${label}`).digest("hex");

const event = {
  version: "cogs.aws-stage2-completion/controller-event/v1",
  batch_commitment: digest("batch"),
  sequence: 1,
  event: "CYCLE_OPENED",
  cycle_ordinal: 1,
  cycle_mode: "full",
  prior_record_sha256: "0".repeat(64),
  payload_sha256: digest("payload"),
  monotonic_observation_ns: 1,
  wall_observation_unix_ns: 2,
  outcome: "accepted",
  uncertainty: "clear",
};

test("fake-only completion campaign Slice A exhaustive Python matrix", () => {
  const result = spawnSync("python3", [resolve(root, "test/aws-stage2-completion-campaign-state.py")], {
    cwd: root,
    env: { PATH: process.env.PATH ?? "", PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /fake-only completion campaign Slice A exhaustive matrix passed/u);
});

test("private controller-event schema is closed and fixes ordinal one to full", () => {
  assert.equal(validate(event), true, JSON.stringify(validate.errors));
  for (const mutation of [
    { ...event, extra: true },
    { ...event, version: "cogs.aws-stage2-completion/fake-receipt/v1" },
    { ...event, cycle_mode: "readiness" },
    { ...event, cycle_ordinal: 0 },
    { ...event, sequence: 1.5 },
    { ...event, event: "RETRY" },
    { ...event, outcome: "uncertain" },
  ]) {
    assert.equal(validate(mutation), false, JSON.stringify(mutation));
  }
  assert.equal(validate({ ...event, event: "FAILURE_RECORDED", outcome: "failed" }), true);
  assert.equal(validate({ ...event, event: "FAILURE_RECORDED", outcome: "uncertain" }), false);
  assert.equal(
    validate({
      ...event,
      event: "TERMINAL_UNCERTAIN_SEALED",
      cycle_ordinal: null,
      cycle_mode: null,
      outcome: "sealed",
      uncertainty: "sticky",
    }),
    true,
  );
  assert.equal(
    validate({ ...event, event: "FINAL_ZERO_ACCEPTED", cycle_ordinal: null, cycle_mode: null, outcome: "zero" }),
    true,
  );
  assert.equal(
    validate({ ...event, event: "FINAL_ZERO_ACCEPTED", cycle_ordinal: 1, cycle_mode: "full", outcome: "zero" }),
    false,
  );
});

test("Slice A sources expose no command, network, provider, credential, or mode selector", () => {
  for (const name of [
    "completion_campaign_codec.py",
    "completion_campaign_contracts.py",
    "completion_campaign_state.py",
  ]) {
    const source = readFileSync(resolve(root, "deploy/aws-feasibility", name), "utf8");
    assert.doesNotMatch(source, /\b(?:subprocess|socket|boto3|requests|urllib|paramiko)\b/u, name);
    assert.doesNotMatch(source, /def\s+\w+\([^)]*(?:mode_selector|cycle_count|retry_count|command|callback)/u, name);
  }
});
