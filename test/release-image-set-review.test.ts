/* biome-ignore-all lint/suspicious/noExplicitAny: hostile review mutations intentionally cross strict JSON types */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import {
  classifyReleaseImageSetReview,
  RELEASE_IMAGE_REFERENCES,
  RELEASE_IMAGE_SET_ASSERTION_SHA256,
  RELEASE_IMAGE_SET_REVIEW_SHA256,
  RELEASE_IMAGE_SOURCE_SHA,
} from "../scripts/release-image-set-review.ts";

const root = resolve(import.meta.dirname, "..");
const assertion = new Uint8Array(
  readFileSync(resolve(root, "docs/security-evidence/release-image-set-assertion-30852317459.canonical.json")),
);
const review = new Uint8Array(
  readFileSync(resolve(root, "docs/security-evidence/release-image-set-review-30852317459.canonical.json")),
);

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function canonical(value: Json): Uint8Array {
  const encode = (item: Json): string => {
    if (Array.isArray(item)) return `[${item.map(encode).join(",")}]`;
    if (item !== null && typeof item === "object") {
      return `{${Object.entries(item)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => `${JSON.stringify(key)}:${encode(child)}`)
        .join(",")}}`;
    }
    return JSON.stringify(item);
  };
  return new TextEncoder().encode(`${encode(value)}\n`);
}

function mutateReview(change: (value: Record<string, any>) => void): Uint8Array {
  const value = JSON.parse(new TextDecoder().decode(review)) as Record<string, any>;
  change(value);
  return canonical(value);
}

test("review binds the exact independently reviewed assertion without promoting runtime or release authority", () => {
  const verdict = classifyReleaseImageSetReview(assertion, review);
  assert.deepEqual(verdict, {
    version: "cogs.release-image-set-review-verdict/v1",
    authority: "static-release-image-set-review-record-classifier",
    record_valid: true,
    reason_code: "VALID_REVIEWED_RELEASE_IMAGE_SET_RECORD",
    assertion_sha256: RELEASE_IMAGE_SET_ASSERTION_SHA256,
    review_sha256: RELEASE_IMAGE_SET_REVIEW_SHA256,
    release_image_set_present: true,
    exact_image_identity_closure_satisfied: true,
    independent_review_recorded: true,
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
  const record = JSON.parse(new TextDecoder().decode(review)) as Record<string, any>;
  assert.equal(record.source.image_source_sha, RELEASE_IMAGE_SOURCE_SHA);
  assert.deepEqual(
    record.images.map((image: { exact_reference: string }) => image.exact_reference),
    [RELEASE_IMAGE_REFERENCES.worker, RELEASE_IMAGE_REFERENCES.sandbox],
  );
});

test("review classifier rejects boundedness and canonical encoding violations", () => {
  assert.equal(
    classifyReleaseImageSetReview(new Uint8Array(0), review).reason_code,
    "REVIEW_INPUT_BOUNDEDNESS_INVALID",
  );
  assert.equal(
    classifyReleaseImageSetReview(assertion, new Uint8Array(0)).reason_code,
    "REVIEW_INPUT_BOUNDEDNESS_INVALID",
  );
  assert.equal(
    classifyReleaseImageSetReview(
      assertion,
      new TextEncoder().encode(JSON.stringify(JSON.parse(new TextDecoder().decode(review)))),
    ).reason_code,
    "REVIEW_RECORD_NONCANONICAL",
  );
  assert.equal(
    classifyReleaseImageSetReview(assertion, new Uint8Array(16 * 1024 + 1)).reason_code,
    "REVIEW_INPUT_BOUNDEDNESS_INVALID",
  );
});

test("review classifier rejects assertion substitution and every authority or identity mutation", () => {
  const changedAssertion = Uint8Array.from(assertion);
  changedAssertion[100] = (changedAssertion[100] ?? 0) ^ 1;
  assert.equal(classifyReleaseImageSetReview(changedAssertion, review).reason_code, "ASSERTION_RECORD_INVALID");

  for (const [name, change, expected] of [
    [
      "release promotion",
      (value: Record<string, any>) => (value.claims.release_eligible = true),
      "REVIEW_RECORD_SCHEMA_INVALID",
    ],
    [
      "runtime promotion",
      (value: Record<string, any>) => (value.claims.runtime_qualification_observed = true),
      "REVIEW_RECORD_SCHEMA_INVALID",
    ],
    [
      "wrong assertion",
      (value: Record<string, any>) => (value.assertion.sha256 = "0".repeat(64)),
      "REVIEW_RECORD_IDENTITY_MISMATCH",
    ],
    [
      "wrong source",
      (value: Record<string, any>) => (value.source.image_source_sha = "0".repeat(40)),
      "REVIEW_RECORD_IDENTITY_MISMATCH",
    ],
    [
      "wrong worker",
      (value: Record<string, any>) => (value.images[0].exact_reference = RELEASE_IMAGE_REFERENCES.sandbox),
      "REVIEW_RECORD_IDENTITY_MISMATCH",
    ],
    ["reordered images", (value: Record<string, any>) => value.images.reverse(), "REVIEW_RECORD_SCHEMA_INVALID"],
    [
      "extra image",
      (value: Record<string, any>) => value.images.push(structuredClone(value.images[0])),
      "REVIEW_RECORD_SCHEMA_INVALID",
    ],
  ] as const) {
    assert.equal(classifyReleaseImageSetReview(assertion, mutateReview(change)).reason_code, expected, name);
  }
});
