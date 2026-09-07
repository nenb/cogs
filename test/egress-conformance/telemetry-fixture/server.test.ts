import assert from "node:assert/strict";
import test from "node:test";
import { decodeEnvelope, emitOtlpMetadata, envelope, startOtlpFixture } from "./server.ts";

test("OTLP no-response metadata accepts only canonical decimal strings", () => {
  const valid = JSON.stringify(envelope({ test_id: "audit.case", outcome: "failed", status_class: 0, duration_ms: 0 }));
  const replace = (key: string, invalid: string) =>
    JSON.parse(
      valid.replace(
        `"key":"cogs.${key}","value":{"stringValue":"0"}`,
        `"key":"cogs.${key}","value":{"stringValue":${JSON.stringify(invalid)}}`,
      ),
    );
  assert.deepEqual(decodeEnvelope(JSON.parse(valid)), {
    test_id: "audit.case",
    outcome: "failed",
    status_class: 0,
    duration_ms: 0,
  });
  for (const invalid of ["", " ", "00", "0x0", "0e0", "0.0"]) {
    assert.equal(decodeEnvelope(replace("status_class", invalid)), undefined);
    assert.equal(decodeEnvelope(replace("duration_ms", invalid)), undefined);
  }
});

test("OTLP fixture accepts only bounded central metadata and retains no forbidden value", async () => {
  const secret = "cogs-secret-value-not-for-telemetry";
  const fixture = await startOtlpFixture([secret]);
  try {
    await emitOtlpMetadata(fixture.origin, {
      test_id: "audit.case",
      outcome: "success",
      status_class: 2,
      duration_ms: 12,
    });
    await emitOtlpMetadata(fixture.origin, {
      test_id: "audit.no-response",
      outcome: "failed",
      status_class: 0,
      duration_ms: 7,
    });
    await assert.rejects(() =>
      emitOtlpMetadata(fixture.origin, {
        test_id: "audit.no-response",
        outcome: "success",
        status_class: 0,
        duration_ms: 7,
      }),
    );
    await assert.rejects(() =>
      emitOtlpMetadata(fixture.origin, {
        test_id: `prefix-${secret}-suffix`,
        outcome: "success",
        status_class: 2,
        duration_ms: 12,
      }),
    );
    const extra = await fetch(`${fixture.origin}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        test_id: "audit.case",
        outcome: "success",
        status_class: 2,
        duration_ms: 12,
        query: "forbidden",
      }),
    });
    assert.equal(extra.status, 400);
    assert.deepEqual(fixture.records(), [
      { test_id: "audit.case", outcome: "success", status_class: 2, duration_ms: 12 },
      { test_id: "audit.no-response", outcome: "failed", status_class: 0, duration_ms: 7 },
    ]);
    assert.equal(JSON.stringify(fixture.records()).includes(secret), false);
  } finally {
    await fixture.stop();
  }
});
