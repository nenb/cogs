import assert from "node:assert/strict";
import test from "node:test";
import { emitOtlpMetadata, startOtlpFixture } from "./server.ts";

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
    ]);
    assert.equal(JSON.stringify(fixture.records()).includes(secret), false);
  } finally {
    await fixture.stop();
  }
});
