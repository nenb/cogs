import assert from "node:assert/strict";
import { test } from "node:test";
import type { EgressAuditWal, EgressAuditWalRecord } from "../src/egress/audit-wal.ts";
import { CogsEgressCompletionError, createCogsEgressCompletionQueue } from "../src/egress/completion-queue.ts";

const raw = "host.example/path?token=secret credential handle workspace";
const generic = (error: unknown) => {
  assert.ok(error instanceof CogsEgressCompletionError);
  assert.equal(error.code, "COGS_EGRESS_COMPLETION_FAILED");
  assert.equal(error.message, "egress completion unavailable");
  assert.equal(String(error.stack ?? "").includes(raw), false);
  assert.equal(String(error).includes("secret"), false);
  return true;
};

test("completes only post-baseline WAL intents, ignores denied logs, and drains frozen metadata in arrival order", async () => {
  const wal = fakeWal([record(1, "old", "r1")]);
  const queue = createCogsEgressCompletionQueue(wal, { capacity: 4, nowMs: () => 1234 });
  wal.records = [...wal.records, record(3, "second", "r2"), record(2, "first", "r1")];
  await queue.onCompletionLine(line({ intent_id: "-", route_id: "-", response_code: "403", duration_ms: "0" }));
  await queue.onCompletionLine(line({ intent_id: "second", route_id: "r2", response_code: "201", duration_ms: "9" }));
  await queue.onCompletionLine(line({ intent_id: "first", route_id: "r1", response_code: "200", duration_ms: "7" }));
  const drained = queue.drain(4);
  assert.deepEqual(drained, [
    { intentId: "second", sequence: 3, routeId: "r2", responseCode: 201, durationMs: 9, completedAtMs: 1234 },
    { intentId: "first", sequence: 2, routeId: "r1", responseCode: 200, durationMs: 7, completedAtMs: 1234 },
  ]);
  assert.throws(() => (drained as unknown[]).push({}), TypeError);
  assert.throws(() => ((drained[0] as { intentId: string }).intentId = raw), TypeError);
  assert.deepEqual(queue.drain(1), []);
});

test("schema, key, JSON type, byte bound, event, number, and clock failures are generic", async () => {
  for (const bad of [
    "",
    "[]",
    "null",
    JSON.stringify({ ...base(), extra: raw }),
    '{"event":"request-complete","event":"request-complete","intent_id":"i","route_id":"r","response_code":"200","duration_ms":"1"}',
    '{"\\u0065vent":"request-complete","intent_id":"i","route_id":"r","response_code":"200","duration_ms":"1"}',
    '{"event":"wrong","\\u0065vent":"request-complete","intent_id":"i","route_id":"r","response_code":"200","duration_ms":"1"}',
    ` ${line()}`,
    `${line()} `,
    JSON.stringify({ event: "request-complete", intent_id: "i", route_id: "r", response_code: 200, duration_ms: "1" }),
    line({ event: "wrong" }),
    line({ response_code: "099" }),
    line({ response_code: "600" }),
    line({ duration_ms: "01" }),
    line({ duration_ms: "86400001" }),
    `${"é".repeat(2049)}`,
    line({ intent_id: "\uD800" }),
  ]) {
    const wal = fakeWal([record(1, "i", "r")]);
    const queue = createCogsEgressCompletionQueue(wal, { capacity: 1, nowMs: () => 1 });
    await assert.rejects(queue.onCompletionLine(bad), generic);
    assert.equal(queue.ready, false);
    assert.throws(() => queue.drain(1), generic);
  }

  const poisoned = createCogsEgressCompletionQueue(fakeWal([record(1, "i", "r")]), {
    capacity: 1,
    nowMs: () => Number.NaN,
  });
  await assert.rejects(poisoned.onCompletionLine(line()), generic);
});

test("unknown, duplicate, old, route mismatch, WAL readiness loss, full queue, and malformed denied logs poison", async () => {
  const cases: Array<(wal: FakeWal, queue: ReturnType<typeof createCogsEgressCompletionQueue>) => Promise<void>> = [
    async (_wal, queue) => queue.onCompletionLine(line({ intent_id: "unknown" })),
    async (wal, queue) => {
      wal.records = [record(2, "i", "r")];
      await queue.onCompletionLine(line());
      await queue.onCompletionLine(line());
    },
    async (wal, queue) => {
      wal.records = [record(2, "i", "r")];
      await queue.onCompletionLine(line({ route_id: "other" }));
    },
    async (wal, queue) => {
      wal.records = [record(Number.NaN, "i", "r")];
      await queue.onCompletionLine(line());
    },
    async (wal, queue) => {
      wal.ready = false;
      await queue.onCompletionLine(line());
    },
    async (wal, queue) => {
      wal.records = [record(2, "i", "r"), record(3, "j", "r")];
      await queue.onCompletionLine(line());
      await queue.onCompletionLine(line({ intent_id: "j" }));
    },
    async (_wal, queue) => queue.onCompletionLine(line({ intent_id: "-", route_id: raw })),
  ];
  const oldWal = fakeWal([record(1, "i", "r")]);
  const oldQueue = createCogsEgressCompletionQueue(oldWal, { capacity: 1, nowMs: () => 1 });
  await assert.rejects(oldQueue.onCompletionLine(line()), generic);

  for (const run of cases) {
    const wal = fakeWal([]);
    const queue = createCogsEgressCompletionQueue(wal, { capacity: 1, nowMs: () => 1 });
    await assert.rejects(run(wal, queue), generic);
    assert.equal(queue.ready, false);
    assert.throws(() => queue.drain(1), generic);
  }
});

test("field-name values are valid without confusing duplicate-key detection", async () => {
  const wal = fakeWal([]);
  const queue = createCogsEgressCompletionQueue(wal, { capacity: 1, nowMs: () => 1 });
  wal.records = [record(1, "duration_ms", "event")];
  await queue.onCompletionLine(line({ intent_id: "duration_ms", route_id: "event" }));
  assert.deepEqual(queue.drain(1), [
    { intentId: "duration_ms", sequence: 1, routeId: "event", responseCode: 200, durationMs: 1, completedAtMs: 1 },
  ]);
});

test("constructor, drain bounds, close idempotence, and accept-after-close are generic and bounded", async () => {
  assert.throws(() => createCogsEgressCompletionQueue(fakeWal([], false), { capacity: 1, nowMs: () => 1 }), generic);
  assert.throws(() => createCogsEgressCompletionQueue(fakeWal([]), { capacity: 0, nowMs: () => 1 }), generic);
  const queue = createCogsEgressCompletionQueue(fakeWal([record(1, "i", "r")]), { capacity: 2, nowMs: () => 1 });
  assert.throws(() => queue.drain(0), generic);
  assert.throws(() => queue.drain(3), generic);
  await Promise.all([queue.close(), queue.close()]);
  assert.equal(queue.ready, false);
  assert.throws(() => queue.drain(1), generic);
  await assert.rejects(queue.onCompletionLine(line()), generic);

  const wal = fakeWal([]);
  const loss = createCogsEgressCompletionQueue(wal, { capacity: 2, nowMs: () => 1 });
  wal.records = [record(1, "i", "r")];
  await loss.onCompletionLine(line());
  wal.ready = false;
  assert.equal(loss.ready, false);
  wal.ready = true;
  assert.equal(loss.ready, false);
  assert.throws(() => loss.drain(1), generic);
});

function base(
  overrides: Partial<Record<"event" | "intent_id" | "route_id" | "response_code" | "duration_ms", string>> = {},
) {
  return {
    event: "request-complete",
    intent_id: "i",
    route_id: "r",
    response_code: "200",
    duration_ms: "1",
    ...overrides,
  };
}

function line(overrides: Partial<ReturnType<typeof base>> = {}): string {
  return JSON.stringify(base(overrides));
}

function record(sequence: number, intentId: string, routeId: string): EgressAuditWalRecord {
  return Object.freeze({
    version: "cogs.egress-intent/v1alpha1",
    sequence,
    intent_id: intentId,
    timestamp_ms: 1,
    session_id: "s",
    integration_id: "g",
    route_id: routeId,
    method: "GET",
    credential_required: false,
  });
}

type FakeWal = EgressAuditWal & { ready: boolean; records: readonly EgressAuditWalRecord[] };
function fakeWal(records: readonly EgressAuditWalRecord[], ready = true): FakeWal {
  return {
    ready,
    records,
    append: async () => record(99, "unused", "unused"),
    close: async () => {},
  };
}
