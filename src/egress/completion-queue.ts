import {
  type CogsTelemetry,
  captureTelemetry,
  emitMetric,
  emitSpan,
  emitTelemetryHealth,
  TelemetryHealthCursor,
} from "../telemetry/instrumentation.ts";
import type { EgressAuditWal, EgressAuditWalRecord } from "./audit-wal.ts";
import { type CogsEgressTelemetrySink, validateCogsEgressTelemetrySink } from "./otlp-telemetry.ts";

const expectedKeys = ["event", "intent_id", "route_id", "response_code", "duration_ms"] as const;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type CogsEgressCompletion = Readonly<{
  intentId: string;
  sequence: number;
  routeId: string;
  responseCode: number;
  durationMs: number;
  completedAtMs: number;
}>;

export type CogsEgressCompletionQueue = Readonly<{
  ready: boolean;
  onCompletionLine(line: string): Promise<void>;
  drain(limit: number): readonly CogsEgressCompletion[];
  close(): Promise<void>;
}>;

export type CogsEgressCompletionQueueOptions = Readonly<{
  capacity: number;
  nowMs: () => number;
  telemetry?: CogsEgressTelemetrySink;
  workerTelemetry?: CogsTelemetry;
}>;

export class CogsEgressCompletionError extends Error {
  public readonly code = "COGS_EGRESS_COMPLETION_FAILED";
  public constructor() {
    super("egress completion unavailable");
    this.name = "CogsEgressCompletionError";
  }
}

export function createCogsEgressCompletionQueue(
  wal: EgressAuditWal,
  options: CogsEgressCompletionQueueOptions,
): CogsEgressCompletionQueue {
  try {
    const captured = Object.freeze({
      capacity: options.capacity,
      nowMs: options.nowMs,
      telemetry: options.telemetry,
      workerTelemetry: options.workerTelemetry,
    });
    const capacity = bound(captured.capacity, 1, 1024);
    validateCogsEgressTelemetrySink(captured.telemetry);
    captureTelemetry(captured.workerTelemetry);
    if (typeof captured.nowMs !== "function" || !wal.ready || wal.records.length > 10_000) throw new Error("bad queue");
    const baseline = Math.max(-1, ...wal.records.map((record) => safeSequence(record.sequence)));
    const queue = new CompletionQueue(
      wal,
      capacity,
      captured.nowMs,
      baseline,
      captured.telemetry,
      captured.workerTelemetry,
    );
    return queue.handle();
  } catch {
    throw new CogsEgressCompletionError();
  }
}

class CompletionQueue {
  private closed = false;
  private poisoned = false;
  private readonly retained: CogsEgressCompletion[] = [];
  private readonly completed = new Set<string>();
  private readonly telemetryHealth = new TelemetryHealthCursor();

  public constructor(
    private readonly wal: EgressAuditWal,
    private readonly capacity: number,
    private readonly nowMs: () => number,
    private readonly baseline: number,
    private readonly telemetry: CogsEgressTelemetrySink | undefined,
    private readonly workerTelemetry: CogsTelemetry,
  ) {}

  public handle(): CogsEgressCompletionQueue {
    const queue = this;
    return Object.freeze({
      get ready() {
        if (!queue.wal.ready) queue.poison();
        return !queue.closed && !queue.poisoned && queue.wal.ready;
      },
      onCompletionLine: (line) => queue.accept(line),
      drain: (limit) => queue.drain(limit),
      close: () => queue.close(),
    });
  }

  private async accept(line: string): Promise<void> {
    try {
      if (this.closed || this.poisoned || !this.wal.ready) throw new Error("not ready");
      const parsed = parseLine(line);
      if (parsed.intent_id === "-") {
        if (parsed.route_id === "-" || opaque.test(parsed.route_id)) return;
        throw new Error("bad denied route");
      }
      const match = this.matchRecord(parsed.intent_id, parsed.route_id);
      if (this.completed.has(parsed.intent_id) || this.retained.length >= this.capacity)
        throw new Error("duplicate/full");
      const completion = Object.freeze({
        intentId: parsed.intent_id,
        sequence: match.sequence,
        routeId: match.route_id,
        responseCode: parseDecimal(parsed.response_code, 100, 599),
        durationMs: parseDecimal(parsed.duration_ms, 0, 86_400_000),
        completedAtMs: safeNow(this.nowMs()),
      });
      this.completed.add(parsed.intent_id);
      this.retained.push(completion);
      try {
        // Telemetry is best-effort; sink exceptions must not poison durable completion correlation.
        this.telemetry?.enqueue(Object.freeze({ intent: safeIntent(match), completion }));
      } catch {}
      emitSpan(this.workerTelemetry, "egress.complete", {
        operation: "complete",
        outcome: "ok",
        status_bucket: statusBucket(completion.responseCode),
        duration_ms: completion.durationMs,
      });
      emitMetric(this.workerTelemetry, "egress.requests", 1, { status_bucket: statusBucket(completion.responseCode) });
      emitTelemetryHealth(this.workerTelemetry, this.telemetryHealth);
    } catch {
      this.poison();
      throw new CogsEgressCompletionError();
    }
  }

  private matchRecord(intentId: string, routeId: string): EgressAuditWalRecord {
    if (!opaque.test(intentId) || !opaque.test(routeId)) throw new Error("bad opaque");
    if (this.wal.records.length > 10_000) throw new Error("bad wal");
    const matches = this.wal.records.filter((record) => record.intent_id === intentId);
    if (matches.length !== 1) throw new Error("unknown intent");
    const record = matches[0];
    if (record === undefined || safeSequence(record.sequence) <= this.baseline || record.route_id !== routeId)
      throw new Error("stale or mismatch");
    return record;
  }

  private drain(limit: number): readonly CogsEgressCompletion[] {
    try {
      if (this.closed || this.poisoned || !this.wal.ready) {
        this.poison();
        throw new Error("not ready");
      }
      const count = bound(limit, 1, this.capacity);
      return Object.freeze(this.retained.splice(0, count));
    } catch {
      throw new CogsEgressCompletionError();
    }
  }

  private async close(): Promise<void> {
    this.closed = true;
    this.retained.length = 0;
    this.completed.clear();
  }

  private poison(): void {
    this.poisoned = true;
    this.retained.length = 0;
    this.completed.clear();
  }
}

function safeIntent(record: EgressAuditWalRecord) {
  return Object.freeze({
    sequence: record.sequence,
    intent_id: record.intent_id,
    timestamp_ms: record.timestamp_ms,
    session_id: record.session_id,
    integration_id: record.integration_id,
    route_id: record.route_id,
    method: record.method,
    credential_required: record.credential_required,
  });
}

function parseLine(line: string): {
  readonly event: string;
  readonly intent_id: string;
  readonly route_id: string;
  readonly response_code: number;
  readonly duration_ms: number;
} {
  if (typeof line !== "string" || line.length < 1 || line.length > 4096 || line.trim() !== line || line.includes("\\"))
    throw new Error("bad line");
  const data = new TextEncoder().encode(line);
  if (new TextDecoder("utf-8", { fatal: true }).decode(data) !== line) throw new Error("bad utf8");
  if (data.byteLength < 1 || data.byteLength > 4096) throw new Error("bad line size");
  const value: unknown = JSON.parse(line);
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("bad json");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join("\0") !== [...expectedKeys].sort().join("\0")) throw new Error("bad keys");
  for (const key of expectedKeys) {
    if ((line.match(new RegExp(`"${key}"\\s*:`, "g")) ?? []).length !== 1) throw new Error("bad key token");
  }
  const parsed = Object.freeze({
    event: ownString(record, "event"),
    intent_id: ownString(record, "intent_id"),
    route_id: ownString(record, "route_id"),
    response_code: ownDecimalField(record, "response_code"),
    duration_ms: ownDecimalField(record, "duration_ms"),
  });
  if (parsed.event !== "request-complete") throw new Error("bad event");
  parseDecimal(parsed.response_code, 100, 599);
  parseDecimal(parsed.duration_ms, 0, 86_400_000);
  return Object.freeze(parsed);
}

function ownString(record: Record<string, unknown>, key: string): string {
  if (!Object.hasOwn(record, key) || typeof record[key] !== "string") throw new Error("bad string");
  return record[key];
}

function ownDecimalField(record: Record<string, unknown>, key: "response_code" | "duration_ms"): number {
  if (!Object.hasOwn(record, key) || typeof record[key] !== "number") throw new Error("bad decimal");
  return record[key];
}

function parseDecimal(value: number, minimum: number, maximum: number): number {
  return bound(value, minimum, maximum);
}

function bound(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("bad bound");
  return value;
}

function safeSequence(value: number): number {
  return bound(value, 0, Number.MAX_SAFE_INTEGER);
}

function safeNow(value: number): number {
  return bound(value, 0, Number.MAX_SAFE_INTEGER);
}

function statusBucket(code: number): "1xx" | "2xx" | "3xx" | "4xx" | "5xx" {
  if (code < 200) return "1xx";
  if (code < 300) return "2xx";
  if (code < 400) return "3xx";
  if (code < 500) return "4xx";
  return "5xx";
}
