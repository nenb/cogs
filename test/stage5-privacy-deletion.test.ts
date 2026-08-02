import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import {
  canonicalStage5PrivacyDeletionReport,
  evaluateStage5PrivacyDeletion,
  STAGE5_DELETION_TRANSITIONS,
  STAGE5_PRIVACY_LIMITS,
  STAGE5_PRIVACY_SURFACES,
  STAGE5_PROHIBITED_CATEGORIES,
  type Stage5PrivacyDeletionReport,
  type Stage5SyntheticCanary,
} from "../scripts/stage5-privacy-deletion.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const suiteSchema = require("../schemas/stage5-privacy-deletion-suite-v1.json") as object;
const reportSchema = require("../schemas/stage5-privacy-deletion-report-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validateSuite = ajv.compile(suiteSchema) as ValidateFunction;
const validateReport = ajv.compile(reportSchema) as ValidateFunction;
const root = resolve(import.meta.dirname, "..");
const fixtureFile = resolve(root, "test/fixtures/stage5-privacy/valid-suite-v1.json");
const checkedReportFile = resolve(root, "docs/security-evidence/stage5-privacy-deletion.local-static.json");

type Suite = Record<string, unknown> & {
  surfaces: Array<Record<string, unknown> & { boundary: Record<string, unknown> | null }>;
  retention: Record<string, unknown>;
  legal_hold: Record<string, unknown>;
  deletion: Record<string, unknown> & { transitions: string[]; version_inventory: Record<string, unknown> };
  external_execution: Record<string, unknown>;
};

function suite(): Suite {
  return JSON.parse(readFileSync(fixtureFile, "utf8")) as Suite;
}

function report(value: unknown, canaries?: readonly Stage5SyntheticCanary[]): Stage5PrivacyDeletionReport {
  const result = evaluateStage5PrivacyDeletion(value, canaries);
  assert.equal(validateReport(result), true, JSON.stringify(validateReport.errors));
  assert.equal(result.qualified, false);
  assert.equal(result.campaign_authorized, false);
  assert.equal(result.cloud_execution_observed, false);
  assert.equal(result.kubernetes_execution_observed, false);
  assert.equal(result.provider_execution_observed, false);
  assert.equal(result.external_model_invoked, false);
  assert.equal(result.release_eligible, false);
  assert.equal(result.deletion.actual_eks_deletion, "unexecuted");
  assert.equal(result.deletion.actual_object_store_deletion, "unexecuted");
  return result;
}

function exportBoundary(value: Suite): Record<string, unknown> {
  const row = value.surfaces.find((surface) => surface.surface === "export");
  assert.ok(row?.boundary);
  return row.boundary;
}

function runtimeCanary(category: Stage5SyntheticCanary["category"], index: number): Stage5SyntheticCanary {
  return Object.freeze({
    category,
    value: ["generated", "only", "at", "runtime", String(index).padStart(2, "0")].join("~"),
  });
}

test("bounded fixture covers every surface and emits the canonical non-authoritative report", () => {
  const value = suite();
  assert.equal(validateSuite(value), true, JSON.stringify(validateSuite.errors));
  assert.deepEqual(
    value.surfaces.map((surface) => surface.surface),
    STAGE5_PRIVACY_SURFACES,
  );
  const first = report(value);
  const second = report(value);
  assert.deepEqual(first, second);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.privacy.categories), true);
  assert.equal(first.status, "local-contract-pass");
  assert.deepEqual(first.privacy, {
    result: "clear",
    reason_code: "STAGE5_PRIVACY_CLEAR",
    surfaces_scanned: 6,
    affected_surfaces: [],
    categories: [],
    finding_count: 0,
    finding_root_sha256: null,
    attachments_excluded: true,
    raw_export_boundary: "explicit-sensitive-authenticated-non-model-no-payload",
    sensitive_marking: "present",
  });
  assert.equal(first.deletion.result, "synthetic-sequence-complete");
  assert.equal(first.deletion.terminal_state, "deleted-verified");
  assert.equal(first.deletion.accepted_transition_count, STAGE5_DELETION_TRANSITIONS.length);
  assert.equal(first.deletion.retention_seconds, 30 * 24 * 60 * 60);
  assert.equal(first.deletion.version_deletion, "all-versions-and-delete-markers");
  assert.equal(first.deletion.legal_hold, "none-separate");
  assert.match(first.suite_sha256 ?? "", /^[a-f0-9]{64}$/u);
  assert.equal(canonicalStage5PrivacyDeletionReport(first), readFileSync(checkedReportFile, "utf8"));
});

test("runtime-only synthetic canaries detect every prohibited category without returning canary bytes", () => {
  STAGE5_PROHIBITED_CATEGORIES.forEach((category, index) => {
    const value = suite();
    const canary = runtimeCanary(category, index);
    const surface = value.surfaces[index % value.surfaces.length];
    assert.ok(surface);
    surface.synthetic_sample = canary.value;
    const result = report(value, [canary]);
    assert.equal(result.status, "blocked-prohibited-content");
    assert.equal(result.privacy.result, "prohibited-content");
    assert.deepEqual(result.privacy.categories, [category]);
    assert.deepEqual(result.privacy.affected_surfaces, [surface.surface]);
    assert.equal(result.privacy.finding_count, 1);
    assert.match(result.privacy.finding_root_sha256 ?? "", /^[a-f0-9]{64}$/u);
    assert.equal(JSON.stringify(result).includes(canary.value), false);
    assert.equal(result.deletion.result, "not-evaluated");
  });
});

test("strict key and scalar heuristics reject prohibited central content and return categories only", () => {
  const cases: Array<[string, string, Stage5SyntheticCanary["category"]]> = [
    [["prompt", "text"].join("_"), "generated-runtime-value", "prompt-or-model-content"],
    [["tool", "output"].join("_"), "generated-runtime-value", "source-command-or-tool-content"],
    [["api", "key"].join("_"), "generated-runtime-value", "credential-or-placeholder"],
    [["private", "id"].join("_"), "generated-runtime-value", "private-identifier"],
    [["file", "path"].join("_"), "generated-runtime-value", "arbitrary-path"],
    [["request", "body"].join("_"), "generated-runtime-value", "network-query-or-body"],
    [["export", "bytes"].join("_"), "generated-runtime-value", "raw-export-content"],
    [["attachment", "content"].join("_"), "generated-runtime-value", "attachment-content"],
  ];
  for (const [key, valueText, category] of cases) {
    const value = suite();
    const row = value.surfaces[0];
    assert.ok(row);
    row[key] = valueText;
    const result = report(value);
    assert.deepEqual(result.privacy.categories, [category]);
    assert.deepEqual(result.privacy.affected_surfaces, ["otlp"]);
    assert.equal(JSON.stringify(result).includes(valueText), false);
  }

  for (const [valueText, category] of [
    [["/", "generated", "runtime", "location"].join(""), "arbitrary-path"],
    [["Bearer", "generated-runtime-material"].join(" "), "credential-or-placeholder"],
    [["https:", "", "invalid.example", "?a=generated"].join("/"), "network-query-or-body"],
  ] as const) {
    const value = suite();
    const row = value.surfaces[1];
    assert.ok(row);
    row.synthetic_sample = valueText;
    const result = report(value);
    assert.deepEqual(result.privacy.categories, [category]);
    assert.equal(JSON.stringify(result).includes(valueText), false);
  }
});

test("raw export requires explicit authenticated non-model boundary, attachment exclusion, and sensitive marking", () => {
  const valid = exportBoundary(suite());
  assert.deepEqual(valid, {
    explicit_user_action: true,
    authenticated_api: true,
    model_callable: false,
    mode: "raw",
    sensitive: true,
    sanitized: false,
    anonymized: false,
    attachments_included: false,
    raw_payload_present: false,
  });

  const attachment = suite();
  exportBoundary(attachment).attachments_included = true;
  const attachmentResult = report(attachment);
  assert.equal(attachmentResult.status, "invalid-contract");
  assert.equal(attachmentResult.privacy.reason_code, "STAGE5_PRIVACY_ATTACHMENT_BOUNDARY_INVALID");

  const unmarked = suite();
  exportBoundary(unmarked).sensitive = false;
  const unmarkedResult = report(unmarked);
  assert.equal(unmarkedResult.privacy.reason_code, "STAGE5_PRIVACY_SENSITIVE_MARKING_MISSING");
  assert.equal(unmarkedResult.privacy.sensitive_marking, "missing");

  for (const mutate of [
    (value: Suite) => (exportBoundary(value).model_callable = true),
    (value: Suite) => (exportBoundary(value).authenticated_api = false),
    (value: Suite) => (exportBoundary(value).explicit_user_action = false),
    (value: Suite) => (exportBoundary(value).raw_payload_present = true),
    (value: Suite) => {
      const row = value.surfaces[5];
      if (row !== undefined) row.content_present = true;
    },
  ]) {
    const value = suite();
    mutate(value);
    const result = report(value);
    assert.equal(result.status, "invalid-contract");
    assert.equal(result.privacy.reason_code, "STAGE5_PRIVACY_RAW_EXPORT_BOUNDARY_INVALID");
    assert.equal(result.deletion.result, "not-evaluated");
  }
});

test("proxy, accessor, cyclic, non-JSON, and oversized inputs fail closed without reading hostile values", () => {
  let proxyTraps = 0;
  const proxied = new Proxy(suite(), {
    get() {
      proxyTraps += 1;
      throw new Error("trap");
    },
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error("trap");
    },
    ownKeys() {
      proxyTraps += 1;
      throw new Error("trap");
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error("trap");
    },
  });
  assert.equal(report(proxied).privacy.reason_code, "STAGE5_PRIVACY_INVALID_SHAPE");
  assert.equal(proxyTraps, 0);

  const nestedProxyValue = suite();
  nestedProxyValue.surfaces[0] = new Proxy(nestedProxyValue.surfaces[0] as Record<string, unknown>, {
    get() {
      proxyTraps += 1;
      throw new Error("trap");
    },
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error("trap");
    },
    ownKeys() {
      proxyTraps += 1;
      throw new Error("trap");
    },
  }) as Suite["surfaces"][number];
  assert.equal(report(nestedProxyValue).privacy.result, "uncertain");
  assert.equal(proxyTraps, 0);

  let getterReads = 0;
  const accessor = suite();
  Object.defineProperty(accessor.surfaces[0], "synthetic_sample", {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error("getter");
    },
  });
  assert.equal(report(accessor).privacy.result, "uncertain");
  assert.equal(getterReads, 0);

  const cyclic = suite();
  cyclic.loop = cyclic;
  assert.equal(report(cyclic).privacy.reason_code, "STAGE5_PRIVACY_INVALID_SHAPE");
  assert.equal(report({ ...suite(), bad: new Uint8Array(1) }).privacy.result, "uncertain");

  const oversizedString = suite();
  oversizedString.synthetic_sample = "x".repeat(STAGE5_PRIVACY_LIMITS.maxStringBytes + 1);
  assert.equal(report(oversizedString).privacy.reason_code, "STAGE5_PRIVACY_BOUNDED_INPUT");
  const oversizedArray = suite();
  oversizedArray.synthetic_sample = Array(STAGE5_PRIVACY_LIMITS.maxArrayLength + 1).fill(false);
  assert.equal(report(oversizedArray).privacy.reason_code, "STAGE5_PRIVACY_BOUNDED_INPUT");
  const oversizedProperties = suite();
  oversizedProperties.synthetic_sample = Object.fromEntries(
    Array.from({ length: STAGE5_PRIVACY_LIMITS.maxProperties + 1 }, (_, index) => [`k${index}`, false]),
  );
  assert.equal(report(oversizedProperties).privacy.reason_code, "STAGE5_PRIVACY_BOUNDED_INPUT");
  const oversizedKey = suite();
  oversizedKey["k".repeat(STAGE5_PRIVACY_LIMITS.maxKeyBytes + 1)] = false;
  assert.equal(report(oversizedKey).privacy.reason_code, "STAGE5_PRIVACY_BOUNDED_INPUT");
  const oversizedDepth = suite();
  let cursor: Record<string, unknown> = oversizedDepth;
  for (let index = 0; index <= STAGE5_PRIVACY_LIMITS.maxDepth; index += 1) {
    const nested: Record<string, unknown> = {};
    cursor.nested = nested;
    cursor = nested;
  }
  assert.equal(report(oversizedDepth).privacy.reason_code, "STAGE5_PRIVACY_BOUNDED_INPUT");
  const oversizedAggregate = suite();
  for (let index = 0; index < 20; index += 1) {
    oversizedAggregate[`sample_${index}`] = Array(20).fill("x".repeat(200));
  }
  assert.equal(report(oversizedAggregate).privacy.reason_code, "STAGE5_PRIVACY_BOUNDED_INPUT");
  const oversizedCanary = runtimeCanary("prompt-or-model-content", 0);
  const badCanary = { ...oversizedCanary, value: "x".repeat(STAGE5_PRIVACY_LIMITS.maxCanaryBytes + 1) };
  assert.equal(report(suite(), [badCanary]).privacy.result, "uncertain");
});

test("deletion state machine is canonical, ordered, sticky on failure or uncertainty, and never retries", () => {
  assert.deepEqual(suite().deletion.transitions, STAGE5_DELETION_TRANSITIONS);

  const outOfOrder = suite();
  outOfOrder.deletion.transitions.reverse();
  const outOfOrderResult = report(outOfOrder);
  assert.equal(outOfOrderResult.status, "preserve-uncertain");
  assert.equal(outOfOrderResult.deletion.reason_code, "STAGE5_DELETION_INVALID_SEQUENCE");
  assert.equal(outOfOrderResult.deletion.accepted_transition_count, 0);

  const failure = suite();
  failure.deletion.transitions = ["request-accepted", "operation-failed", "active-state-absence-asserted"];
  const failureResult = report(failure);
  assert.equal(failureResult.status, "failed-stop");
  assert.equal(failureResult.deletion.result, "failed-stop");
  assert.equal(failureResult.deletion.accepted_transition_count, 1);
  assert.equal(failureResult.deletion.legal_hold, "none-separate");
  assert.notEqual(failureResult.deletion.terminal_state, "deleted-verified");

  const uncertain = suite();
  uncertain.deletion.transitions = [
    "request-accepted",
    "active-state-absence-asserted",
    "observation-uncertain",
    "current-object-absence-asserted",
  ];
  const uncertainResult = report(uncertain);
  assert.equal(uncertainResult.status, "preserve-uncertain");
  assert.equal(uncertainResult.deletion.reason_code, "STAGE5_DELETION_OBSERVATION_UNCERTAIN");
  assert.equal(uncertainResult.deletion.accepted_transition_count, 2);
  assert.equal(uncertainResult.deletion.uncertainty_contract, "sticky-preserve-unconfirmed-no-unknown-to-absent");
  assert.notEqual(uncertainResult.deletion.terminal_state, "deleted-verified");
});

test("retention, version deletion, and legal hold are explicit and independent", () => {
  const value = suite();
  assert.deepEqual(value.retention, {
    trusted_session_state_seconds: 2592000,
    object_copy_seconds: 2592000,
    workspace: "until-explicit-workspace-deletion",
    user_deletion_overrides_expiry: true,
    expiry_requires_deletion_sequence: true,
  });
  assert.equal(value.deletion.version_policy, "all-versions-and-delete-markers");
  assert.deepEqual(value.legal_hold, {
    mode: "none",
    authority: "separate-administrator-only",
    disclosed: true,
    retention_policy_independent: true,
    failure_state_is_hold: false,
    uncertainty_state_is_hold: false,
  });

  const held = suite();
  held.legal_hold.mode = "active";
  held.deletion.transitions = [];
  const heldResult = report(held);
  assert.equal(validateSuite(held), true, JSON.stringify(validateSuite.errors));
  assert.equal(heldResult.status, "blocked-legal-hold");
  assert.equal(heldResult.deletion.result, "held-separate");
  assert.equal(heldResult.deletion.legal_hold, "active-separate");
  assert.equal(heldResult.deletion.accepted_transition_count, 0);

  for (const mutate of [
    (candidate: Suite) => (candidate.retention.trusted_session_state_seconds = 0),
    (candidate: Suite) => (candidate.retention.object_copy_seconds = 1),
    (candidate: Suite) => (candidate.deletion.version_policy = "current-only"),
    (candidate: Suite) => (candidate.deletion.version_inventory.versions_expected = 1025),
    (candidate: Suite) => (candidate.legal_hold.failure_state_is_hold = true),
    (candidate: Suite) => (candidate.legal_hold.authority = "deletion-worker"),
  ]) {
    const candidate = suite();
    mutate(candidate);
    const result = report(candidate);
    assert.equal(result.status, "invalid-contract");
    assert.equal(result.deletion.reason_code, "STAGE5_DELETION_INVALID_CONTRACT");
    assert.notEqual(result.deletion.result, "synthetic-sequence-complete");
  }
});

test("report schema rejects authority promotion, execution claims, and contradictory terminal states", () => {
  const base = report(suite()) as unknown as Record<string, unknown>;
  const mutations: Array<(value: Record<string, unknown>) => void> = [
    (value) => {
      value.qualified = true;
    },
    (value) => {
      value.release_eligible = true;
    },
    (value) => {
      (value.deletion as Record<string, unknown>).actual_eks_deletion = "executed";
    },
    (value) => {
      (value.deletion as Record<string, unknown>).actual_object_store_deletion = "executed";
    },
    (value) => {
      (value.deletion as Record<string, unknown>).terminal_state = "held-separate";
    },
    (value) => {
      (value.privacy as Record<string, unknown>).finding_count = 1;
    },
    (value) => {
      value.unbounded_diagnostic = "generated-runtime-value";
    },
  ];
  for (const mutate of mutations) {
    const hostile = structuredClone(base);
    mutate(hostile);
    assert.equal(validateReport(hostile), false);
  }
});

test("fixture and report contain metadata only and keep every external operation fixed unexecuted", () => {
  const value = suite();
  assert.deepEqual(value.external_execution, {
    profile: "local-static-model",
    eks_deletion: "unexecuted",
    object_store_deletion: "unexecuted",
    provider_api_invoked: false,
    cluster_api_invoked: false,
    deployment_invoked: false,
    external_model_invoked: false,
  });
  const fixtureText = readFileSync(fixtureFile, "utf8");
  assert.doesNotMatch(fixtureText, /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+|\bsk-[A-Za-z0-9_-]{8,}/u);
  assert.doesNotMatch(
    fixtureText,
    /"(?:prompt_text|source_text|tool_output|api_key|private_id|file_path|export_bytes)"/u,
  );
  assert.doesNotMatch(fixtureText, /"(?:user_id|session_id|workspace_id|account_id|request_id|correlation_id)"/u);
  assert.doesNotMatch(fixtureText, /"(?:raw_export|session_jsonl|attachment_bytes)"/u);
  assert.doesNotMatch(fixtureText, /(?:^|[":])\/(?:Users|home|workspace|run|tmp)\//mu);
  const scannerSource = readFileSync(resolve(root, "scripts/stage5-privacy-deletion.ts"), "utf8");
  assert.doesNotMatch(scannerSource, /from "node:(?:fs|child_process|http|https|net|tls|dns|cluster)"/u);
  assert.doesNotMatch(scannerSource, /\b(?:fetch|spawn|execFile|kubectl|terraform|tofu)\s*\(/u);
  const checked = JSON.parse(readFileSync(checkedReportFile, "utf8"));
  assert.equal(validateReport(checked), true, JSON.stringify(validateReport.errors));
  assert.equal(checked.release_eligible, false);
  assert.equal(checked.deletion.actual_eks_deletion, "unexecuted");
  assert.equal(checked.deletion.actual_object_store_deletion, "unexecuted");
});
