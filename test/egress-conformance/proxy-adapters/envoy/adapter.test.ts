import assert from "node:assert/strict";
import test from "node:test";
import { parseExternalCaseResult } from "./adapter.ts";
import { ENVOY_IMAGE, ENVOY_IMAGE_DIGEST, ENVOY_VERSION } from "./image.ts";

test("Envoy candidate identity is an exact version and multi-platform digest pin", () => {
  assert.match(ENVOY_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(ENVOY_IMAGE_DIGEST, /^sha256:[a-f0-9]{64}$/);
  assert.equal(ENVOY_IMAGE, `envoyproxy/envoy:v${ENVOY_VERSION}@${ENVOY_IMAGE_DIGEST}`);
});

test("external case results accept only the bounded adapter contract", () => {
  assert.deepEqual(parseExternalCaseResult('{"passed":true,"diagnosticsRedacted":"bounded"}'), {
    passed: true,
    diagnosticsRedacted: "bounded",
  });
  for (const malformed of [
    "not-json",
    "null",
    "[]",
    '{"passed":"yes"}',
    '{"passed":true,"extra":true}',
    '{"passed":false,"diagnosticsRedacted":7}',
  ]) {
    assert.throws(() => parseExternalCaseResult(malformed), /malformed/);
  }
  assert.throws(() => parseExternalCaseResult(`"${"x".repeat(70 * 1024)}"`), /exceeded/);
});
