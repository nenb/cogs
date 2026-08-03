import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes } from "./private-bytes.ts";
import { classifyReleaseImageSetAssertion } from "./release-image-set-assertion.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const reviewSchema = require("../schemas/release-image-set-review-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
require("ajv-formats")(ajv);
const validateReview = ajv.compile(reviewSchema) as ValidateFunction;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export const RELEASE_IMAGE_SET_ASSERTION_SHA256 = "ad45d6b0a114c481eb869daff38f4ddc669801e8a5b5d808c404b506ae33c450";
export const RELEASE_IMAGE_SET_REVIEW_SHA256 = "f6a607349062f5ca9211978600012b4cd16651af984c083a0329646a74da6a3a";
export const RELEASE_IMAGE_SOURCE_SHA = "d3ddb987ceeec0bae0fa2d89fdc134187a0d1de3";
export const RELEASE_IMAGE_SOURCE_TREE_SHA = "6fb6dbe512280e906555b02d6367d6a43c1421a9";
export const RELEASE_IMAGE_SOURCE_INVENTORY_SHA256 = "e2f4a4ad970c6e1e68e995db96b26e35f85d752b41670acee2c9090c5e663b94";
export const RELEASE_IMAGE_WORKFLOW_RUN_ID = 30852317459;
export const RELEASE_IMAGE_ASSERTION_ARTIFACT_ID = 8871223316;
export const RELEASE_IMAGE_REFERENCES = Object.freeze({
  worker: "ghcr.io/nenb/cogs/worker@sha256:c2f240fa191fb22970f6b1ff0142448841401885c87f403efca152d9201004bc",
  sandbox: "ghcr.io/nenb/cogs/sandbox@sha256:b8827b17c73fac0ce869681fad4a01c625f068566a55f1aa7e3a9efc0e1bdc60",
});

export type ReleaseImageSetReviewReasonCode =
  | "VALID_REVIEWED_RELEASE_IMAGE_SET_RECORD"
  | "REVIEW_INPUT_BOUNDEDNESS_INVALID"
  | "ASSERTION_RECORD_INVALID"
  | "REVIEW_RECORD_NONCANONICAL"
  | "REVIEW_RECORD_SCHEMA_INVALID"
  | "REVIEW_RECORD_IDENTITY_MISMATCH";

export type ReleaseImageSetReviewVerdict = Readonly<{
  version: "cogs.release-image-set-review-verdict/v1";
  authority: "static-release-image-set-review-record-classifier";
  record_valid: boolean;
  reason_code: ReleaseImageSetReviewReasonCode;
  assertion_sha256: string | null;
  review_sha256: string | null;
  release_image_set_present: boolean;
  exact_image_identity_closure_satisfied: boolean;
  independent_review_recorded: boolean;
  cryptographic_verification_performed: false;
  registry_observation_performed: false;
  runtime_qualification_observed: false;
  cloud_execution_observed: false;
  provider_execution_observed: false;
  kubernetes_execution_observed: false;
  readiness_promoted: false;
  production_ready: false;
  release_eligible: false;
}>;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

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

function canonicalJson(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("non-JSON value");
  return encoded;
}

function canonicalBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

function record(value: Json | undefined): JsonObject | null {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function invalid(
  reasonCode: ReleaseImageSetReviewReasonCode,
  assertionSha256: string | null = null,
  reviewSha256: string | null = null,
): ReleaseImageSetReviewVerdict {
  return Object.freeze({
    version: "cogs.release-image-set-review-verdict/v1",
    authority: "static-release-image-set-review-record-classifier",
    record_valid: false,
    reason_code: reasonCode,
    assertion_sha256: assertionSha256,
    review_sha256: reviewSha256,
    release_image_set_present: false,
    exact_image_identity_closure_satisfied: false,
    independent_review_recorded: false,
    cryptographic_verification_performed: false,
    registry_observation_performed: false,
    runtime_qualification_observed: false,
    cloud_execution_observed: false,
    provider_execution_observed: false,
    kubernetes_execution_observed: false,
    readiness_promoted: false,
    production_ready: false,
    release_eligible: false,
  });
}

function reviewMatchesAssertion(review: JsonObject, assertion: JsonObject): boolean {
  const reviewAssertion = record(review.assertion);
  const reviewSource = record(review.source);
  const assertionSource = record(assertion.source);
  const workflow = record(assertion.workflow);
  if (
    reviewAssertion?.artifact_id !== RELEASE_IMAGE_ASSERTION_ARTIFACT_ID ||
    reviewAssertion.workflow_run_id !== RELEASE_IMAGE_WORKFLOW_RUN_ID ||
    reviewAssertion.workflow_run_attempt !== 1 ||
    reviewAssertion.canonical_size !== 9092 ||
    reviewAssertion.sha256 !== RELEASE_IMAGE_SET_ASSERTION_SHA256 ||
    reviewSource?.image_source_sha !== RELEASE_IMAGE_SOURCE_SHA ||
    reviewSource.image_source_tree_sha !== RELEASE_IMAGE_SOURCE_TREE_SHA ||
    reviewSource.image_source_inventory_sha256 !== RELEASE_IMAGE_SOURCE_INVENTORY_SHA256 ||
    assertionSource?.reviewed_sha !== RELEASE_IMAGE_SOURCE_SHA ||
    assertionSource.tree_sha !== RELEASE_IMAGE_SOURCE_TREE_SHA ||
    assertionSource.inventory_sha256 !== RELEASE_IMAGE_SOURCE_INVENTORY_SHA256 ||
    workflow?.run_id !== RELEASE_IMAGE_WORKFLOW_RUN_ID ||
    workflow.run_attempt !== 1 ||
    workflow.sha !== RELEASE_IMAGE_SOURCE_SHA
  )
    return false;
  if (!Array.isArray(review.images) || !Array.isArray(assertion.images) || review.images.length !== 2) return false;
  for (const role of ["worker", "sandbox"] as const) {
    const reviewed = review.images.find((item) => record(item)?.role === role);
    const asserted = assertion.images.find((item) => record(item)?.role === role);
    const reviewedImage = record(reviewed);
    const assertedImage = record(asserted);
    const provenance = record(assertedImage?.buildkit_provenance);
    const sbom = record(assertedImage?.sbom);
    const vulnerabilities = record(assertedImage?.vulnerabilities);
    const counts = record(vulnerabilities?.counts);
    if (
      reviewedImage === null ||
      assertedImage === null ||
      reviewedImage.exact_reference !== RELEASE_IMAGE_REFERENCES[role] ||
      reviewedImage.exact_reference !== assertedImage.exact_reference ||
      reviewedImage.linux_amd64_manifest_digest !== assertedImage.linux_amd64_manifest_digest ||
      reviewedImage.buildkit_provenance_sha256 !== provenance?.readback_sha256 ||
      reviewedImage.sbom_sha256 !== sbom?.spdx_json_sha256 ||
      canonicalJson(reviewedImage.vulnerabilities as Json) !==
        canonicalJson({
          critical: counts?.critical as Json,
          high: counts?.high as Json,
          low: counts?.low as Json,
          medium: counts?.medium as Json,
          total: counts?.total as Json,
          unknown: counts?.unknown as Json,
        })
    )
      return false;
  }
  return true;
}

/** Pure parser: it records but does not repeat registry, cryptographic, scanner, cloud, or runtime observations. */
export function classifyReleaseImageSetReview(
  assertionInput: unknown,
  reviewInput: unknown,
): ReleaseImageSetReviewVerdict {
  const assertionCapture = capturePrivateBytes(assertionInput, 64 * 1024);
  const reviewCapture = capturePrivateBytes(reviewInput, 16 * 1024);
  if (assertionCapture.bytes === null || reviewCapture.bytes === null)
    return invalid("REVIEW_INPUT_BOUNDEDNESS_INVALID");
  const assertionSha = sha256(assertionCapture.bytes);
  const reviewSha = sha256(reviewCapture.bytes);
  const assertionVerdict = classifyReleaseImageSetAssertion(assertionCapture.bytes);
  if (!assertionVerdict.record_valid || assertionSha !== RELEASE_IMAGE_SET_ASSERTION_SHA256) {
    return invalid("ASSERTION_RECORD_INVALID", assertionSha, reviewSha);
  }
  let review: JsonObject;
  let assertion: JsonObject;
  try {
    review = JSON.parse(decoder.decode(reviewCapture.bytes)) as JsonObject;
    assertion = JSON.parse(decoder.decode(assertionCapture.bytes)) as JsonObject;
  } catch {
    return invalid("REVIEW_RECORD_NONCANONICAL", assertionSha, reviewSha);
  }
  if (!bytesEqual(reviewCapture.bytes, canonicalBytes(review))) {
    return invalid("REVIEW_RECORD_NONCANONICAL", assertionSha, reviewSha);
  }
  if (!validateReview(review)) return invalid("REVIEW_RECORD_SCHEMA_INVALID", assertionSha, reviewSha);
  if (reviewSha !== RELEASE_IMAGE_SET_REVIEW_SHA256 || !reviewMatchesAssertion(review, assertion)) {
    return invalid("REVIEW_RECORD_IDENTITY_MISMATCH", assertionSha, reviewSha);
  }
  return Object.freeze({
    ...invalid("VALID_REVIEWED_RELEASE_IMAGE_SET_RECORD", assertionSha, reviewSha),
    record_valid: true,
    reason_code: "VALID_REVIEWED_RELEASE_IMAGE_SET_RECORD" as const,
    release_image_set_present: true,
    exact_image_identity_closure_satisfied: true,
    independent_review_recorded: true,
  });
}
