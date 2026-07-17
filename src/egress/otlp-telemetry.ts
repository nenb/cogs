import { exactPlainObject, otlpEndpoint, postOtlpJson, safeInteger } from "../telemetry/otlp-http.ts";
import type { EgressAuditWalRecord } from "./audit-wal.ts";
import type { CogsEgressCompletion } from "./completion-queue.ts";

const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const attrKeys = [
  "cogs.event",
  "cogs.intent_id",
  "cogs.intent_sequence",
  "cogs.session_id",
  "cogs.integration_id",
  "cogs.route_id",
  "cogs.method",
  "cogs.credential_required",
  "cogs.status_class",
  "cogs.duration_ms",
  "cogs.completed_lag_ms",
] as const;
type SafeRecord = Readonly<{
  timeUnixNano: string;
  attributes: Readonly<Record<(typeof attrKeys)[number], string | number | boolean>>;
}>;
export type CogsEgressTelemetryMode =
  | Readonly<{ mode: "injected-stub-evidence" }>
  | Readonly<{
      mode: "otlp";
      endpoint: string;
      allowLoopbackHttpDevelopment?: boolean;
      capacity?: number;
      timeoutMs?: number;
      maxResponseBytes?: number;
    }>;
export type CogsEgressTelemetryEvent = Readonly<{
  intent: Pick<
    EgressAuditWalRecord,
    | "sequence"
    | "intent_id"
    | "timestamp_ms"
    | "session_id"
    | "integration_id"
    | "route_id"
    | "method"
    | "credential_required"
  >;
  completion: CogsEgressCompletion;
}>;
export type CogsEgressTelemetrySnapshot = Readonly<{
  queued: number;
  exported: number;
  dropped: number;
  failed: number;
  depth: number;
}>;
export type CogsEgressTelemetrySink = Readonly<{
  ready: boolean;
  enqueue(event: CogsEgressTelemetryEvent): void;
  close(signal?: AbortSignal): Promise<void>;
  snapshot(): CogsEgressTelemetrySnapshot;
}>;

export class CogsEgressTelemetryError extends Error {
  public readonly code = "COGS_EGRESS_TELEMETRY_FAILED";
  public constructor() {
    super("egress telemetry unavailable");
    this.name = "CogsEgressTelemetryError";
  }
}

export function createCogsEgressTelemetrySink(config: CogsEgressTelemetryMode): CogsEgressTelemetrySink {
  try {
    exactPlainObject(
      config,
      ["mode"],
      ["allowLoopbackHttpDevelopment", "capacity", "endpoint", "maxResponseBytes", "timeoutMs"],
    );
    const mode = config.mode;
    if (mode === "injected-stub-evidence") {
      exactPlainObject(config, ["mode"], []);
      return stubSink();
    }
    if (mode !== "otlp") throw new Error("bad telemetry");
    exactPlainObject(
      config,
      ["endpoint", "mode"],
      ["allowLoopbackHttpDevelopment", "capacity", "maxResponseBytes", "timeoutMs"],
    );
    const allow = Boolean(optional(config, "allowLoopbackHttpDevelopment", "boolean") ?? false);
    const capacity = optional(config, "capacity", "number") ?? 64;
    const timeoutMs = optional(config, "timeoutMs", "number") ?? 1000;
    const maxResponseBytes = optional(config, "maxResponseBytes", "number") ?? 8192;
    return new OtlpSink(
      otlpEndpoint(config.endpoint, "logs", allow),
      safeInteger(capacity, 1, 64),
      safeInteger(timeoutMs, 50, 5000),
      safeInteger(maxResponseBytes, 0, 65536),
    ).handle();
  } catch {
    throw new CogsEgressTelemetryError();
  }
}

export function validateCogsEgressTelemetrySink(value: CogsEgressTelemetrySink | undefined): void {
  if (value === undefined) return;
  if (!value || typeof value !== "object" || !Object.isFrozen(value)) throw new CogsEgressTelemetryError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key === "symbol") ||
    (keys as string[]).sort().join("\0") !== "close\0enqueue\0ready\0snapshot"
  )
    throw new CogsEgressTelemetryError();
  const sink = value as Record<string, unknown>;
  if (typeof sink.enqueue !== "function" || typeof sink.close !== "function" || typeof sink.snapshot !== "function")
    throw new CogsEgressTelemetryError();
  if (sink.ready !== true) throw new CogsEgressTelemetryError();
}

class OtlpSink {
  private queue: SafeRecord[] = [];
  private pumping: Promise<void> | undefined;
  private controller: AbortController | undefined;
  private scheduled = false;
  private closing = false;
  private closed = false;
  private exported = 0;
  private dropped = 0;
  private failed = 0;
  private retryRequested = false;
  private closePromise: Promise<void> | undefined;
  public constructor(
    private readonly url: string,
    private readonly capacity: number,
    private readonly timeoutMs: number,
    private readonly maxResponseBytes: number,
  ) {}
  public handle(): CogsEgressTelemetrySink {
    const sink = this;
    return Object.freeze({
      get ready() {
        return !sink.closing && !sink.closed;
      },
      enqueue: (event) => sink.enqueue(event),
      close: (signal) => (sink.closePromise ??= sink.close(signal)),
      snapshot: () => sink.snapshot(),
    });
  }
  private enqueue(event: CogsEgressTelemetryEvent): void {
    try {
      const accepted = safeRecord(event);
      if (this.closing || this.closed || this.queue.length >= this.capacity) {
        this.dropped++;
        this.kick();
        return;
      }
      this.queue.push(accepted);
      this.kick();
    } catch {
      this.dropped++;
    }
  }
  private async close(signal?: AbortSignal): Promise<void> {
    if (this.closed) return;
    this.closing = true;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timer = setTimeout(abort, this.timeoutMs);
    try {
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      this.controller?.abort();
      await this.pumping?.catch(() => undefined);
      await this.pump(true, controller.signal).catch(() => undefined);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      this.dropped += this.queue.length;
      this.queue = [];
      this.closed = true;
    }
  }
  private snapshot(): CogsEgressTelemetrySnapshot {
    return Object.freeze({
      queued: this.queue.length,
      exported: this.exported,
      dropped: this.dropped,
      failed: this.failed,
      depth: this.queue.length,
    });
  }
  private kick(): void {
    if (this.pumping !== undefined) {
      this.retryRequested = true;
      return;
    }
    if (!this.scheduled) {
      this.scheduled = true;
      queueMicrotask(() => {
        this.scheduled = false;
        if (!this.closing && this.queue.length > 0) this.startPump(false);
      });
    }
  }
  private startPump(final: boolean): void {
    this.pumping = this.pump(final).then((blocked) => {
      this.pumping = undefined;
      const retry = this.retryRequested;
      this.retryRequested = false;
      if ((!blocked || retry) && !this.closing && this.queue.length > 0) this.startPump(false);
    });
  }
  private async pump(final: boolean, parent?: AbortSignal): Promise<boolean> {
    let sent = 0;
    while (this.queue.length > 0 && sent < (final ? this.capacity : 16)) {
      const batch = this.queue.slice(0, Math.min(16, this.queue.length));
      try {
        await this.post(batch, parent);
        this.queue.splice(0, batch.length);
        this.exported += batch.length;
        sent += batch.length;
      } catch {
        this.failed++;
        return true;
      }
    }
    return false;
  }
  private async post(batch: readonly SafeRecord[], parent?: AbortSignal): Promise<void> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    this.controller = controller;
    try {
      parent?.addEventListener("abort", abort, { once: true });
      if (parent?.aborted) abort();
      await postOtlpJson({
        url: this.url,
        kind: "logs",
        body: envelope(batch),
        timeoutMs: this.timeoutMs,
        maxRequestBytes: 65_536,
        maxResponseBytes: this.maxResponseBytes,
        parent: controller.signal,
      });
    } finally {
      parent?.removeEventListener("abort", abort);
      controller.abort();
      if (this.controller === controller) this.controller = undefined;
    }
  }
}

function safeRecord(event: CogsEgressTelemetryEvent): SafeRecord {
  exactPlainObject(event, ["completion", "intent"], []);
  exactPlainObject(
    event.intent,
    [
      "credential_required",
      "integration_id",
      "intent_id",
      "method",
      "route_id",
      "sequence",
      "session_id",
      "timestamp_ms",
    ],
    [],
  );
  exactPlainObject(
    event.completion,
    ["completedAtMs", "durationMs", "intentId", "responseCode", "routeId", "sequence"],
    [],
  );
  const intent = Object.freeze({ ...event.intent });
  const completion = Object.freeze({ ...event.completion });
  if (
    completion.intentId !== intent.intent_id ||
    completion.sequence !== intent.sequence ||
    completion.routeId !== intent.route_id
  )
    throw new Error("bad correlation");
  const lag = safeInteger(
    completion.completedAtMs - safeInteger(intent.timestamp_ms, 0, Number.MAX_SAFE_INTEGER),
    0,
    86_400_000,
  );
  return Object.freeze({
    timeUnixNano: (BigInt(safeInteger(completion.completedAtMs, 0, Number.MAX_SAFE_INTEGER)) * 1_000_000n).toString(),
    attributes: Object.freeze({
      "cogs.event": "egress.complete",
      "cogs.intent_id": validOpaque(intent.intent_id),
      "cogs.intent_sequence": safeInteger(intent.sequence, 0, Number.MAX_SAFE_INTEGER),
      "cogs.session_id": validOpaque(intent.session_id),
      "cogs.integration_id": validOpaque(intent.integration_id),
      "cogs.route_id": validOpaque(intent.route_id),
      "cogs.method": intent.method === "GET" || intent.method === "POST" ? intent.method : fail(),
      "cogs.credential_required": typeof intent.credential_required === "boolean" ? intent.credential_required : fail(),
      "cogs.status_class": Math.floor(safeInteger(completion.responseCode, 100, 599) / 100),
      "cogs.duration_ms": safeInteger(completion.durationMs, 0, 86_400_000),
      "cogs.completed_lag_ms": lag,
    }),
  });
}

function envelope(records: readonly SafeRecord[]): unknown {
  return {
    resourceLogs: [
      {
        resource: { attributes: [{ key: "service.name", value: { stringValue: "cogs-egress" } }] },
        scopeLogs: [
          {
            scope: { name: "cogs.egress.telemetry", version: "v1alpha1" },
            logRecords: records.map((record) => ({
              timeUnixNano: record.timeUnixNano,
              severityText: "INFO",
              body: { stringValue: "cogs.egress.complete" },
              attributes: attrKeys.map((key) => attr(key, record.attributes[key])),
            })),
          },
        ],
      },
    ],
  };
}
function attr(key: string, value: string | number | boolean): unknown {
  if (typeof value === "string") return { key, value: { stringValue: value } };
  if (typeof value === "number") return { key, value: { intValue: String(value) } };
  return { key, value: { boolValue: value } };
}
function optional(
  value: Record<string, unknown>,
  key: string,
  type: "boolean" | "number",
): boolean | number | undefined {
  if (!Object.hasOwn(value, key)) return undefined;
  if (typeof value[key] !== type) throw new Error("bad option");
  return value[key] as boolean | number;
}
function validOpaque(value: unknown): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
  return value;
}
function fail(): never {
  throw new Error("bad event");
}
function stubSink(): CogsEgressTelemetrySink {
  let closed = false;
  let dropped = 0;
  return Object.freeze({
    get ready() {
      return !closed;
    },
    enqueue: () => {
      dropped++;
    },
    close: async () => {
      closed = true;
    },
    snapshot: () => Object.freeze({ queued: 0, exported: 0, dropped, failed: 0, depth: 0 }),
  });
}
