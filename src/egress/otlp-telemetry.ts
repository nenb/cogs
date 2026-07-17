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
    exactPlain(
      config,
      ["mode"],
      ["allowLoopbackHttpDevelopment", "capacity", "endpoint", "maxResponseBytes", "timeoutMs"],
    );
    const mode = config.mode;
    if (mode === "injected-stub-evidence") {
      exactPlain(config, ["mode"], []);
      return stubSink();
    }
    if (mode !== "otlp") throw new Error("bad telemetry");
    exactPlain(
      config,
      ["endpoint", "mode"],
      ["allowLoopbackHttpDevelopment", "capacity", "maxResponseBytes", "timeoutMs"],
    );
    const allow = Boolean(optional(config, "allowLoopbackHttpDevelopment", "boolean") ?? false);
    const capacity = optional(config, "capacity", "number") ?? 64;
    const timeoutMs = optional(config, "timeoutMs", "number") ?? 1000;
    const maxResponseBytes = optional(config, "maxResponseBytes", "number") ?? 8192;
    return new OtlpSink(
      endpoint(config.endpoint, allow),
      integer(capacity, 1, 64),
      integer(timeoutMs, 50, 5000),
      integer(maxResponseBytes, 0, 65536),
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
    if (parent?.aborted) throw new Error("aborted");
    const controller = new AbortController();
    this.controller = controller;
    const abort = () => controller.abort();
    const timer = parent === undefined ? setTimeout(abort, this.timeoutMs) : undefined;
    try {
      parent?.addEventListener("abort", abort, { once: true });
      const body = JSON.stringify(envelope(batch));
      if (Buffer.byteLength(body) > 65_536) throw new Error("too large");
      const response = await fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        redirect: "error",
        signal: controller.signal,
      });
      const length = response.headers.get("content-length");
      const badLength = length !== null && (!/^[0-9]+$/.test(length) || Number(length) > this.maxResponseBytes);
      if (response.status !== 200 || !jsonType(response.headers.get("content-type")) || badLength) {
        await response.body?.cancel().catch(() => undefined);
        throw new Error("bad response");
      }
      validateResponse(await boundedText(response, this.maxResponseBytes));
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      parent?.removeEventListener("abort", abort);
      if (this.controller === controller) this.controller = undefined;
    }
  }
}

function safeRecord(event: CogsEgressTelemetryEvent): SafeRecord {
  exactPlain(event, ["completion", "intent"], []);
  exactPlain(
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
  exactPlain(event.completion, ["completedAtMs", "durationMs", "intentId", "responseCode", "routeId", "sequence"], []);
  const intent = Object.freeze({ ...event.intent });
  const completion = Object.freeze({ ...event.completion });
  if (
    completion.intentId !== intent.intent_id ||
    completion.sequence !== intent.sequence ||
    completion.routeId !== intent.route_id
  )
    throw new Error("bad correlation");
  const lag = integer(
    completion.completedAtMs - integer(intent.timestamp_ms, 0, Number.MAX_SAFE_INTEGER),
    0,
    86_400_000,
  );
  return Object.freeze({
    timeUnixNano: (BigInt(integer(completion.completedAtMs, 0, Number.MAX_SAFE_INTEGER)) * 1_000_000n).toString(),
    attributes: Object.freeze({
      "cogs.event": "egress.complete",
      "cogs.intent_id": validOpaque(intent.intent_id),
      "cogs.intent_sequence": integer(intent.sequence, 0, Number.MAX_SAFE_INTEGER),
      "cogs.session_id": validOpaque(intent.session_id),
      "cogs.integration_id": validOpaque(intent.integration_id),
      "cogs.route_id": validOpaque(intent.route_id),
      "cogs.method": intent.method === "GET" || intent.method === "POST" ? intent.method : fail(),
      "cogs.credential_required": typeof intent.credential_required === "boolean" ? intent.credential_required : fail(),
      "cogs.status_class": Math.floor(integer(completion.responseCode, 100, 599) / 100),
      "cogs.duration_ms": integer(completion.durationMs, 0, 86_400_000),
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
async function boundedText(response: Response, max: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  let total = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > max) throw new Error("too large");
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}
function validateResponse(text: string): void {
  const value = text === "" ? {} : JSON.parse(text);
  exactPlain(value, [], ["partialSuccess"]);
  if (!Object.hasOwn(value, "partialSuccess")) return;
  const partial = value.partialSuccess;
  exactPlain(partial, [], ["rejectedLogRecords", "errorMessage"]);
  if (Object.hasOwn(partial, "rejectedLogRecords") && partial.rejectedLogRecords !== "0") throw new Error("rejected");
  if (Object.hasOwn(partial, "errorMessage") && partial.errorMessage !== "") throw new Error("rejected");
}
function endpoint(value: unknown, allowLoopbackHttp: boolean): string {
  if (typeof value !== "string") throw new Error("bad url");
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/v1/logs" || url.port === "0")
    throw new Error("bad url");
  if (url.protocol === "https:") return url.href;
  if (url.protocol === "http:" && allowLoopbackHttp && (url.hostname === "127.0.0.1" || url.hostname === "[::1]"))
    return url.href;
  throw new Error("bad url");
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
function jsonType(value: string | null): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}
function validOpaque(value: unknown): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
  return value;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max)
    throw new Error("bad int");
  return value;
}
function exactPlain(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
): asserts value is Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("bad object");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key === "symbol")) throw new Error("bad keys");
  const names = keys as string[];
  for (const key of names) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error("bad keys");
    if (!required.includes(key) && !optional.includes(key)) throw new Error("bad keys");
  }
  for (const key of required) if (!Object.hasOwn(descriptors, key)) throw new Error("bad keys");
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
