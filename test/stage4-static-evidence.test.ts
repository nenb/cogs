import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import {
  canonicalStage4StaticEvidenceBytes,
  FUTURE_EKS_CHECK_IDS,
  STAGE4_STATIC_BYTE_LIMITS,
  STATIC_CHECK_IDS,
  type Stage4StaticValidationBindings,
  type StaticCheckOutcome,
  stage4StaticSha256,
  validateStage4StaticEvidence,
} from "../scripts/stage4-static-evidence.ts";

const encode = (value: string): Uint8Array => new TextEncoder().encode(value);
const source = encode('["source-entry",1,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]\n');
const chart = encode("synthetic-chart-archive\n");
const values = encode('{"mode":"synthetic-static-only"}\n');
const render = encode("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: synthetic-static-only\n");

type CheckRow = {
  id: string;
  applicability: string;
  execution: string;
  outcome: string;
};

type Evidence = {
  version: string;
  authority: string;
  qualified: boolean;
  campaign_authorized: boolean;
  cloud_execution_observed: boolean;
  stage4_exit_satisfied: boolean;
  release_eligible: boolean;
  static_outcome: string;
  artifacts: {
    source_sha256: string;
    chart_sha256: string;
    values_sha256: string;
    render_sha256: string;
    repeated_render_sha256: string;
    deterministic: boolean;
  };
  static_checks: CheckRow[];
  future_eks_checks: CheckRow[];
};

function bindings(outcomes: readonly StaticCheckOutcome[] = STATIC_CHECK_IDS.map(() => "satisfied")) {
  return {
    source,
    chart,
    values,
    render,
    repeatedRender: render,
    expectedStaticOutcomes: outcomes,
  } satisfies Stage4StaticValidationBindings;
}

function evidence(outcomes: readonly StaticCheckOutcome[] = STATIC_CHECK_IDS.map(() => "satisfied")): Evidence {
  return {
    version: "cogs.stage4-static-preparation-evidence/v1",
    authority: "static-only-stage4-preparation",
    qualified: false,
    campaign_authorized: false,
    cloud_execution_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    static_outcome: outcomes.every((outcome) => outcome === "satisfied") ? "conforming" : "nonconforming",
    artifacts: {
      source_sha256: stage4StaticSha256(source),
      chart_sha256: stage4StaticSha256(chart),
      values_sha256: stage4StaticSha256(values),
      render_sha256: stage4StaticSha256(render),
      repeated_render_sha256: stage4StaticSha256(render),
      deterministic: true,
    },
    static_checks: STATIC_CHECK_IDS.map((id, index) => ({
      id,
      applicability: "static-shape-only",
      execution: "executed-local-static",
      outcome: outcomes[index] ?? "violated",
    })),
    future_eks_checks: FUTURE_EKS_CHECK_IDS.map((id) => ({
      id,
      applicability: "required-for-future-exact-run-eks",
      execution: "unexecuted",
      outcome: "not-observed",
    })),
  };
}

function validate(report: Evidence, expected = bindings()) {
  return validateStage4StaticEvidence(canonicalStage4StaticEvidenceBytes(report), expected);
}

function expectInvalid(report: Evidence, expected = bindings()): void {
  assert.equal(validate(report, expected).valid, false);
}

test("accepts canonical conforming and accurately nonconforming static evidence", () => {
  const conforming = evidence();
  assert.deepEqual(validate(conforming), { valid: true, errors: [] });

  const outcomes = STATIC_CHECK_IDS.map<StaticCheckOutcome>((_, index) => (index === 8 ? "violated" : "satisfied"));
  const nonconforming = evidence(outcomes);
  assert.equal(nonconforming.static_outcome, "nonconforming");
  assert.deepEqual(validate(nonconforming, bindings(outcomes)), { valid: true, errors: [] });
});

test("fixes every non-authority claim to false and keeps authority domains disjoint", () => {
  for (const property of [
    "qualified",
    "campaign_authorized",
    "cloud_execution_observed",
    "stage4_exit_satisfied",
    "release_eligible",
  ] as const) {
    const mutation = evidence();
    mutation[property] = true;
    assert.ok(validate(mutation).errors.includes("evidence-schema-invalid"), property);
  }

  for (const authority of [
    "functional-only",
    "authoritative-local",
    "authoritative-production-profile",
    "aws-feasibility",
    "exact-run-native-qualification",
  ]) {
    const mutation = evidence();
    mutation.authority = authority;
    assert.ok(validate(mutation).errors.includes("evidence-schema-invalid"), authority);
  }

  const versionMutation = evidence();
  versionMutation.version = "cogs.security-report/v1alpha1";
  expectInvalid(versionMutation);

  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
  const securitySchema = require("../schemas/security-report-v1alpha1.json") as object;
  const securityAjv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(securityAjv);
  const validateSecurity = securityAjv.compile(securitySchema);
  const securityReport = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../docs/security-evidence/example-report.json"), "utf8"),
  ) as Record<string, unknown>;
  securityReport.authority = "static-only-stage4-preparation";
  assert.equal(validateSecurity(securityReport), false, "security-report authority must reject the static domain");
  assert.equal(validateSecurity(evidence()), false, "a static report is never a security report");
});

test("requires every static and future EKS row exactly once in fixed order", () => {
  for (const inventory of ["static_checks", "future_eks_checks"] as const) {
    const length = evidence()[inventory].length;
    for (let index = 0; index < length; index += 1) {
      const omitted = evidence();
      omitted[inventory].splice(index, 1);
      expectInvalid(omitted);

      const renamed = evidence();
      const row = renamed[inventory][index];
      assert.ok(row);
      row.id = `${row.id}.forged`;
      expectInvalid(renamed);
    }
    for (let index = 0; index < length - 1; index += 1) {
      const reordered = evidence();
      const first = reordered[inventory][index];
      const second = reordered[inventory][index + 1];
      assert.ok(first);
      assert.ok(second);
      reordered[inventory][index] = second;
      reordered[inventory][index + 1] = first;
      expectInvalid(reordered);
    }
  }
});

test("rejects forged static outcomes and contradictory aggregate outcomes", () => {
  const outcomes = STATIC_CHECK_IDS.map<StaticCheckOutcome>((_, index) => (index === 4 ? "violated" : "satisfied"));
  const forged = evidence(outcomes);
  const forgedRow = forged.static_checks[4];
  assert.ok(forgedRow);
  forgedRow.outcome = "satisfied";
  forged.static_outcome = "conforming";
  const result = validate(forged, bindings(outcomes));
  assert.equal(result.valid, false);
  assert.ok(result.errors.includes("static-check-outcome-mismatch"));

  const contradictory = evidence(outcomes);
  contradictory.static_outcome = "conforming";
  assert.ok(validate(contradictory, bindings(outcomes)).errors.includes("static-outcome-mismatch"));

  const invalidBindings = bindings(["satisfied"]);
  assert.ok(validate(evidence(), invalidBindings).errors.includes("static-outcome-bindings-invalid"));
});

test("future EKS checks are always required, unexecuted, and not observed", () => {
  const mutations: Array<[keyof CheckRow, string]> = [
    ["applicability", "not-applicable"],
    ["execution", "executed"],
    ["execution", "skipped"],
    ["execution", "stubbed"],
    ["outcome", "pass"],
    ["outcome", "satisfied"],
  ];
  for (const [property, replacement] of mutations) {
    const mutation = evidence();
    const row = mutation.future_eks_checks[0];
    assert.ok(row);
    row[property] = replacement;
    expectInvalid(mutation);
  }

  const staticRelabel = evidence();
  const staticRow = staticRelabel.static_checks[0];
  assert.ok(staticRow);
  staticRow.execution = "unexecuted";
  staticRow.outcome = "not-observed";
  expectInvalid(staticRelabel);
});

test("binds every exact artifact digest and requires byte-identical renders", () => {
  for (const property of [
    "source_sha256",
    "chart_sha256",
    "values_sha256",
    "render_sha256",
    "repeated_render_sha256",
  ] as const) {
    const mutation = evidence();
    mutation.artifacts[property] = "f".repeat(64);
    expectInvalid(mutation);
  }

  const changedBindings: Array<[string, Stage4StaticValidationBindings]> = [
    ["source", { ...bindings(), source: encode("changed-source") }],
    ["chart", { ...bindings(), chart: encode("changed-chart") }],
    ["values", { ...bindings(), values: encode("changed-values") }],
    ["render", { ...bindings(), render: encode("changed-render") }],
    ["repeated render", { ...bindings(), repeatedRender: encode("changed-render") }],
  ];
  for (const [name, changed] of changedBindings) {
    assert.equal(validate(evidence(), changed).valid, false, name);
  }

  const unequalRenders = { ...bindings(), repeatedRender: encode("different-repeat") };
  assert.ok(validate(evidence(), unequalRenders).errors.includes("render-not-deterministic"));

  const malformed = evidence();
  malformed.artifacts.source_sha256 = "A".repeat(64);
  expectInvalid(malformed);
  const short = evidence();
  short.artifacts.source_sha256 = "a".repeat(63);
  expectInvalid(short);
});

test("requires exact canonical JSON bytes", () => {
  const report = evidence();
  const canonical = canonicalStage4StaticEvidenceBytes(report);
  const text = new TextDecoder().decode(canonical);
  const mutations = [
    encode(`${JSON.stringify(report)}\n`),
    encode(`${JSON.stringify(report, null, 2)}\n`),
    encode(text.replace(/\n$/u, "\r\n")),
    encode(`\uFEFF${text}`),
    canonical.slice(0, -1),
    encode(`${text}\n`),
    encode(`${text}trailing`),
    encode(text.replace(/^\{/u, '{"authority":"static-only-stage4-preparation",')),
  ];
  for (const mutation of mutations) {
    assert.equal(validateStage4StaticEvidence(mutation, bindings()).valid, false);
  }
  assert.equal(validateStage4StaticEvidence(canonical, bindings()).valid, true);
});

test("rejects unknown fields and enforces byte bounds", () => {
  const top = evidence() as Evidence & { metadata?: object };
  top.metadata = {};
  expectInvalid(top);

  const nested = evidence() as Evidence & { artifacts: Evidence["artifacts"] & { diagnostics?: object } };
  nested.artifacts.diagnostics = {};
  expectInvalid(nested);

  const row = evidence();
  (row.static_checks[0] as CheckRow & { message?: string }).message = "not permitted";
  expectInvalid(row);

  const oversizedEvidence = new Uint8Array(STAGE4_STATIC_BYTE_LIMITS.evidence + 1);
  assert.ok(validateStage4StaticEvidence(oversizedEvidence, bindings()).errors.includes("evidence-too-large"));
  assert.ok(validate(evidence(), { ...bindings(), values: new Uint8Array() }).errors.includes("values-out-of-bounds"));
  assert.ok(
    validate(evidence(), {
      ...bindings(),
      render: new Uint8Array(STAGE4_STATIC_BYTE_LIMITS.render + 1),
    }).errors.includes("render-out-of-bounds"),
  );
});

test("validator source remains pure and contains no producer or cloud/provider path", () => {
  const validatorSource = readFileSync(resolve(import.meta.dirname, "../scripts/stage4-static-evidence.ts"), "utf8");
  assert.doesNotMatch(
    validatorSource,
    /from\s+["']node:(?:child_process|fs|http|https|net|dns|tls|os|worker_threads)["']|\bprocess\.(?:env|argv)|@aws-sdk|\b(?:helm|kubectl|opentofu|terraform)\b/iu,
  );
  assert.doesNotMatch(validatorSource, /security-report-v1alpha1|authoritative-production-profile/iu);
});
