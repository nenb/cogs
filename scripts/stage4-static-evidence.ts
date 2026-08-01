import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const schema = require("../schemas/stage4-static-preparation-evidence-v1.json") as object;

export const STATIC_CHECK_IDS = Object.freeze([
  "static.source.exact-clean-revision",
  "static.source.complete-bounded-inventory",
  "static.config.strict-synthetic-values",
  "static.render.pinned-local-renderer",
  "static.render.deterministic-bounded-parse",
  "static.sandbox.explicit-kata-runtimeclass-no-fallback",
  "static.sandbox.no-trusted-sidecar-shape",
  "static.identity.sandbox-token-automount-disabled",
  "static.network.declarative-default-deny-shape",
  "static.network.no-public-ingress-or-provider-resource",
  "static.scheduling.trusted-sandbox-separation-shape",
  "static.storage.workspace-session-role-separation-shape",
  "static.limits.resource-and-lifecycle-bounds-present",
  "static.material.no-inline-sensitive-content",
] as const);

export const FUTURE_EKS_CHECK_IDS = Object.freeze([
  "eks.launch-template.nested-virtualization-applied",
  "eks.node.kvm-modules-device-and-active-acceleration",
  "eks.runtime.actual-kata-root-distinct-kernel-no-trusted-sidecar",
  "eks.network.guest-root-cni-bypass-resistance",
  "eks.identity.no-kubernetes-cloud-openbao-or-ca-credentials",
  "eks.isolation.api-admin-cross-session-and-storage-denial",
  "eks.conformance.real-authz-wal-openbao-proxy-otlp-dependencies",
  "eks.storage.ebs-attach-reattach-and-exclusive-writer",
  "eks.functional.real-pi-end-to-end",
  "eks.performance.scheduled-to-ssh-ready-and-first-tool-percentiles",
  "eks.recovery.stage4-failure-campaign",
  "eks.lifecycle.repeatable-install-destroy-and-no-runtime-fallback",
  "eks.teardown.independent-zero-resource-inventory-and-cost",
] as const);

export const STAGE4_STATIC_BYTE_LIMITS = Object.freeze({
  evidence: 128 * 1024,
  source: 4 * 1024 * 1024,
  chart: 4 * 1024 * 1024,
  values: 64 * 1024,
  render: 1024 * 1024,
});

export type StaticCheckOutcome = "satisfied" | "violated";

export interface Stage4StaticValidationBindings {
  /** Exact bytes of the independently selected, bounded source manifest or source bundle. */
  readonly source: Uint8Array;
  /** Exact bytes of the independently selected, bounded chart artifact. */
  readonly chart: Uint8Array;
  /** Exact bytes of the synthetic values artifact. */
  readonly values: Uint8Array;
  /** Exact bytes from the first local static render. */
  readonly render: Uint8Array;
  /** Exact bytes from an independent repeat of the same local static render. */
  readonly repeatedRender: Uint8Array;
  /** Independently derived outcomes in STATIC_CHECK_IDS order. */
  readonly expectedStaticOutcomes: readonly StaticCheckOutcome[];
}

export type Stage4StaticValidationError =
  | "evidence-too-large"
  | "evidence-invalid-utf8-or-json"
  | "evidence-not-canonical"
  | "evidence-schema-invalid"
  | "source-out-of-bounds"
  | "chart-out-of-bounds"
  | "values-out-of-bounds"
  | "render-out-of-bounds"
  | "repeated-render-out-of-bounds"
  | "render-not-deterministic"
  | "source-digest-mismatch"
  | "chart-digest-mismatch"
  | "values-digest-mismatch"
  | "render-digest-mismatch"
  | "repeated-render-digest-mismatch"
  | "static-outcome-bindings-invalid"
  | "static-check-outcome-mismatch"
  | "static-outcome-mismatch";

export interface Stage4StaticValidationResult {
  readonly valid: boolean;
  readonly errors: readonly Stage4StaticValidationError[];
}

type Stage4StaticEvidence = {
  static_outcome: "conforming" | "nonconforming";
  artifacts: {
    source_sha256: string;
    chart_sha256: string;
    values_sha256: string;
    render_sha256: string;
    repeated_render_sha256: string;
  };
  static_checks: Array<{ outcome: StaticCheckOutcome }>;
};

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateSchema = ajv.compile(schema) as ValidateFunction<Stage4StaticEvidence>;

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const properties = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`);
    return `{${properties.join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("value is not representable as canonical JSON");
  return encoded;
}

/** Encodes a JSON value with code-point-sorted keys, no insignificant whitespace, and one trailing LF. */
export function canonicalStage4StaticEvidenceBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

export function stage4StaticSha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function artifactInBounds(value: Uint8Array, maximum: number): boolean {
  return value.byteLength > 0 && value.byteLength <= maximum;
}

/**
 * Validates only the bounded static evidence contract against caller-supplied exact bytes and independently derived rows.
 * It performs no I/O, process execution, environment lookup, provider access, or authority promotion.
 */
export function validateStage4StaticEvidence(
  evidenceBytes: Uint8Array,
  bindings: Stage4StaticValidationBindings,
): Stage4StaticValidationResult {
  const errors: Stage4StaticValidationError[] = [];
  const add = (error: Stage4StaticValidationError): void => {
    if (!errors.includes(error)) errors.push(error);
  };

  const sourceInBounds = artifactInBounds(bindings.source, STAGE4_STATIC_BYTE_LIMITS.source);
  const chartInBounds = artifactInBounds(bindings.chart, STAGE4_STATIC_BYTE_LIMITS.chart);
  const valuesInBounds = artifactInBounds(bindings.values, STAGE4_STATIC_BYTE_LIMITS.values);
  const renderInBounds = artifactInBounds(bindings.render, STAGE4_STATIC_BYTE_LIMITS.render);
  const repeatedRenderInBounds = artifactInBounds(bindings.repeatedRender, STAGE4_STATIC_BYTE_LIMITS.render);
  if (!sourceInBounds) add("source-out-of-bounds");
  if (!chartInBounds) add("chart-out-of-bounds");
  if (!valuesInBounds) add("values-out-of-bounds");
  if (!renderInBounds) add("render-out-of-bounds");
  if (!repeatedRenderInBounds) add("repeated-render-out-of-bounds");
  if (renderInBounds && repeatedRenderInBounds && !bytesEqual(bindings.render, bindings.repeatedRender)) {
    add("render-not-deterministic");
  }

  const bindingsValid =
    bindings.expectedStaticOutcomes.length === STATIC_CHECK_IDS.length &&
    bindings.expectedStaticOutcomes.every((outcome) => outcome === "satisfied" || outcome === "violated");
  if (!bindingsValid) add("static-outcome-bindings-invalid");
  if (evidenceBytes.byteLength > STAGE4_STATIC_BYTE_LIMITS.evidence) add("evidence-too-large");
  if (
    !sourceInBounds ||
    !chartInBounds ||
    !valuesInBounds ||
    !renderInBounds ||
    !repeatedRenderInBounds ||
    evidenceBytes.byteLength > STAGE4_STATIC_BYTE_LIMITS.evidence
  ) {
    return { valid: false, errors };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(evidenceBytes));
  } catch {
    add("evidence-invalid-utf8-or-json");
    return { valid: false, errors };
  }

  let canonical: Uint8Array;
  try {
    canonical = canonicalStage4StaticEvidenceBytes(parsed);
  } catch {
    add("evidence-invalid-utf8-or-json");
    return { valid: false, errors };
  }
  if (!bytesEqual(evidenceBytes, canonical)) add("evidence-not-canonical");
  if (!validateSchema(parsed)) {
    add("evidence-schema-invalid");
    return { valid: false, errors };
  }

  if (parsed.artifacts.source_sha256 !== stage4StaticSha256(bindings.source)) add("source-digest-mismatch");
  if (parsed.artifacts.chart_sha256 !== stage4StaticSha256(bindings.chart)) add("chart-digest-mismatch");
  if (parsed.artifacts.values_sha256 !== stage4StaticSha256(bindings.values)) add("values-digest-mismatch");
  if (parsed.artifacts.render_sha256 !== stage4StaticSha256(bindings.render)) add("render-digest-mismatch");
  if (parsed.artifacts.repeated_render_sha256 !== stage4StaticSha256(bindings.repeatedRender)) {
    add("repeated-render-digest-mismatch");
  }
  if (parsed.artifacts.render_sha256 !== parsed.artifacts.repeated_render_sha256) add("render-not-deterministic");

  if (bindingsValid) {
    const outcomesMatch = parsed.static_checks.every(
      (row, index) => row.outcome === bindings.expectedStaticOutcomes[index],
    );
    if (!outcomesMatch) add("static-check-outcome-mismatch");
  }
  const derivedOutcome = parsed.static_checks.every((row) => row.outcome === "satisfied")
    ? "conforming"
    : "nonconforming";
  if (parsed.static_outcome !== derivedOutcome) add("static-outcome-mismatch");

  return { valid: errors.length === 0, errors };
}
