import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes } from "./private-bytes.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const receiptSchema = require("../schemas/release-image-receipt-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validateReceipt = ajv.compile(receiptSchema) as ValidateFunction;

const MAX_RECEIPT_BYTES = 1024 * 1024;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;

type JsonPrimitive = string | number | boolean | null;
export type ReleaseReceiptJson = JsonPrimitive | ReleaseReceiptJson[] | { [key: string]: ReleaseReceiptJson };
type JsonObject = { [key: string]: ReleaseReceiptJson };

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

function canonicalJson(value: ReleaseReceiptJson): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("non-JSON receipt value");
  return encoded;
}

export function canonicalReleaseImageReceiptBytes(value: ReleaseReceiptJson): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}: object required`);
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label}: plain object required`);
  return value as Record<string, unknown>;
}

function asCount(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(`${label}: invalid count`);
  return value as number;
}

function assertReceiptSemantics(value: unknown): asserts value is JsonObject {
  if (!validateReceipt(value)) throw new Error(`receipt schema drift: ${ajv.errorsText(validateReceipt.errors)}`);
  const receipt = asObject(value, "receipt");
  const source = asObject(receipt.source, "source");
  const workflow = asObject(receipt.workflow, "workflow");
  if (
    source.reviewed_sha !== source.observed_head_sha ||
    source.reviewed_sha !== workflow.sha ||
    workflow.run_attempt !== 1
  ) {
    throw new Error("source, protected-main HEAD, and workflow SHA must be identical on attempt one");
  }

  const images = receipt.images;
  if (!Array.isArray(images) || images.length !== 2) throw new Error("exact worker and sandbox image pair required");
  const roles = ["worker", "sandbox"] as const;
  const digests = new Set<string>();
  for (const [index, role] of roles.entries()) {
    const image = asObject(images[index], `${role} image`);
    const repository = `ghcr.io/nenb/cogs/${role}`;
    const digest = image.registry_digest;
    const childDigest = image.linux_amd64_manifest_digest;
    if (
      image.role !== role ||
      image.registry_repository !== repository ||
      typeof digest !== "string" ||
      !DIGEST.test(digest) ||
      typeof childDigest !== "string" ||
      !DIGEST.test(childDigest) ||
      digest === childDigest ||
      image.exact_reference !== `${repository}@${digest}` ||
      image.release_tag !== `sha-${source.reviewed_sha}` ||
      image.candidate_tag !== `candidate-${source.reviewed_sha}-${workflow.run_id}-${workflow.run_attempt}`
    ) {
      throw new Error(`${role}: digest namespace, exact reference, platform manifest, or tag identity mismatch`);
    }
    if (digests.has(digest)) throw new Error("worker and sandbox registry digests must differ");
    digests.add(digest);

    const vulnerabilities = asObject(image.vulnerabilities, `${role} vulnerabilities`);
    if (vulnerabilities.scanned_reference !== image.exact_reference) {
      throw new Error(`${role}: vulnerability scan does not bind the exact published digest`);
    }
    const counts = asObject(vulnerabilities.counts, `${role} vulnerability counts`);
    const total = asCount(counts.total, "total");
    const unknown = asCount(counts.unknown, "unknown");
    const low = asCount(counts.low, "low");
    const medium = asCount(counts.medium, "medium");
    const high = asCount(counts.high, "high");
    const critical = asCount(counts.critical, "critical");
    const fixed = asCount(counts.fixed_available, "fixed_available");
    const unfixed = asCount(counts.unfixed, "unfixed");
    if (total !== unknown + low + medium + high + critical || total !== fixed + unfixed) {
      throw new Error(`${role}: vulnerability count partitions do not cover every finding`);
    }
    const gate = asObject(vulnerabilities.gate, `${role} gate`);
    if (high !== 0 || critical !== 0 || gate.finding_count !== high + critical || gate.outcome !== "pass") {
      throw new Error(`${role}: HIGH/CRITICAL gate must pass with no fixed or unfixed gating finding`);
    }
    const disposition = asObject(vulnerabilities.disposition, `${role} disposition`);
    const unknownDisposition = asObject(disposition.unknown, `${role} unknown disposition`);
    const lowMediumDisposition = asObject(disposition.low_medium, `${role} low/medium disposition`);
    const highCriticalDisposition = asObject(disposition.high_critical, `${role} high/critical disposition`);
    if (
      unknownDisposition.count !== unknown ||
      lowMediumDisposition.count !== low + medium ||
      highCriticalDisposition.count !== high + critical
    ) {
      throw new Error(`${role}: explicit dispositions do not partition severity findings`);
    }

    const sbom = asObject(image.sbom, `${role} SBOM`);
    const signature = asObject(image.signature, `${role} signature`);
    if (
      sbom.certificate_identity !== workflow.certificate_identity ||
      sbom.certificate_oidc_issuer !== workflow.certificate_oidc_issuer ||
      signature.certificate_identity !== workflow.certificate_identity ||
      signature.certificate_oidc_issuer !== workflow.certificate_oidc_issuer
    ) {
      throw new Error(`${role}: verified image or SBOM authority does not equal the workflow authority`);
    }
  }
}

export type ReleaseReceiptClassification = Readonly<{
  authority: "static-release-image-assertion-record-parser";
  record_valid: boolean;
  record_sha256: string | null;
  workflow_recorded_publication_complete: boolean;
  workflow_recorded_vulnerability_gate_passed: boolean;
  workflow_recorded_signatures_verified: boolean;
  cryptographic_verification_performed: false;
  publication_truth_established: false;
  vulnerability_truth_established: false;
  signature_truth_established: false;
  readiness_promoted: false;
  production_ready: false;
  release_eligible: false;
  reason_code:
    | "VALID_WORKFLOW_ASSERTION_RECORD"
    | "BOUNDED_INPUT_VIOLATION"
    | "NON_CANONICAL_JSON"
    | "SCHEMA_OR_SEMANTIC_DRIFT";
}>;

function classification(
  reasonCode: ReleaseReceiptClassification["reason_code"],
  digest: string | null,
): ReleaseReceiptClassification {
  const recordValid = reasonCode === "VALID_WORKFLOW_ASSERTION_RECORD";
  return Object.freeze({
    authority: "static-release-image-assertion-record-parser",
    record_valid: recordValid,
    record_sha256: digest,
    workflow_recorded_publication_complete: recordValid,
    workflow_recorded_vulnerability_gate_passed: recordValid,
    workflow_recorded_signatures_verified: recordValid,
    cryptographic_verification_performed: false,
    publication_truth_established: false,
    vulnerability_truth_established: false,
    signature_truth_established: false,
    readiness_promoted: false,
    production_ready: false,
    release_eligible: false,
    reason_code: reasonCode,
  });
}

export function finalizeReleaseImageReceipt(value: unknown): Uint8Array {
  assertReceiptSemantics(value);
  return canonicalReleaseImageReceiptBytes(value);
}

export function classifyReleaseImageReceipt(input: unknown): ReleaseReceiptClassification {
  const captured = capturePrivateBytes(input, MAX_RECEIPT_BYTES);
  if (captured.bytes === null) return classification("BOUNDED_INPUT_VIOLATION", null);
  const digest = createHash("sha256").update(captured.bytes).digest("hex");
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
    const canonical = canonicalReleaseImageReceiptBytes(parsed as ReleaseReceiptJson);
    if (!Buffer.from(captured.bytes).equals(Buffer.from(canonical))) {
      return classification("NON_CANONICAL_JSON", digest);
    }
  } catch {
    return classification("NON_CANONICAL_JSON", digest);
  }
  try {
    assertReceiptSemantics(parsed);
  } catch {
    return classification("SCHEMA_OR_SEMANTIC_DRIFT", digest);
  }
  return classification("VALID_WORKFLOW_ASSERTION_RECORD", digest);
}

export const RELEASE_IMAGE_RECEIPT_LIMITS = Object.freeze({ max_receipt_bytes: MAX_RECEIPT_BYTES });
