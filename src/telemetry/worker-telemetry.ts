import { exactPlainObject, frozenFetch, otlpEndpoint, postOtlpJson, raceTimeout, safeInteger } from "./otlp-http.ts";

export type CogsWorkerTelemetryMode =
  | Readonly<{ mode: "disabled" }>
  | Readonly<{
      mode: "otlp";
      tracesEndpoint: string;
      metricsEndpoint: string;
      allowLoopbackHttpDevelopment?: boolean;
      capacity?: number;
      batchSize?: number;
      timeoutMs?: number;
      maxResponseBytes?: number;
      fetch?: FetchLike;
      clock?: ClockLike;
      random?: RandomLike;
    }>;

type FetchLike = (url: string, init: RequestInit) => Promise<Response>;
type ClockLike = Readonly<{ nowMs: () => number }>;
type RandomLike = Readonly<{ bytes: (length: number) => Uint8Array }>;

export type CogsWorkerTelemetrySnapshot = Readonly<{
  ready: boolean;
  queued: number;
  exported: number;
  dropped: number;
  failed: number;
  lag_ms: number;
}>;

export type CogsWorkerTelemetrySink = Readonly<{
  ready: boolean;
  span(input: unknown): boolean;
  metric(input: unknown): boolean;
  snapshot(): CogsWorkerTelemetrySnapshot;
  close(signal?: AbortSignal): Promise<void>;
}>;

const spanNames = new Set([
  "lifecycle.start",
  "lifecycle.ready",
  "dependency.start",
  "dependency.ready",
  "dependency.lost",
  "api.request",
  "pi.run",
  "pi.turn",
  "pi.model_call",
  "pi.event",
  "pi.history.flush",
  "tool.enable",
  "tool.dispatch",
  "ssh.connect",
  "ssh.channel",
  "sftp.operation",
  "bash.operation",
  "egress.authorize",
  "egress.complete",
  "wal.append",
  "wal.complete",
  "git.observe",
  "otlp.export",
  "export.create",
  "export.failure",
  "shutdown.prepare",
  "shutdown.ready",
  "checkpoint.create",
  "checkpoint.failure",
]);
const gaugeMetricNames = new Set(["cost.bucket", "session.active", "wal.depth", "otlp.queue.depth", "otlp.export.lag"]);
const metricNames = new Set([
  "token.input",
  "token.output",
  "token.cache",
  "cost.microunits",
  "cost.bucket",
  "session.active",
  "tool.count",
  "tool.errors",
  "tool.timeouts",
  "tool.truncated",
  "egress.requests",
  "egress.bytes",
  "egress.denials",
  "wal.depth",
  "wal.bytes",
  "wal.failures",
  "otlp.queue.depth",
  "otlp.dropped",
  "otlp.failed",
  "otlp.export.lag",
  "checkpoint.count",
  "checkpoint.failures",
  "export.bytes",
  "export.failures",
]);
const outcomes = new Set(["ok", "error", "denied", "dropped", "cancelled", "timeout"]);
const states = new Set(["starting", "ready", "running", "idle", "settled", "shutdown", "failed"]);
const dependencies = new Set([
  "pi",
  "ssh",
  "sftp",
  "egress",
  "wal",
  "otlp",
  "export",
  "git",
  "policy",
  "storage",
  "proxy",
  "auth",
]);
const tools = new Set(["read", "write", "edit", "bash"]);
const pathClasses = new Set(["workspace", "shared_skill", "user_skill"]);
const operations = new Set([
  "start",
  "stop",
  "flush",
  "append",
  "authorize",
  "dispatch",
  "export",
  "checkpoint",
  "read",
  "write",
  "edit",
  "connect",
  "channel",
  "complete",
  "create",
  "prepare",
  "run",
  "observe",
  "settle",
  "close",
]);
const methods = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"]);
const buckets = new Set(["0", "1", "2_4", "5_16", "17_64", "65_256", "257_1024", "gt_1024"]);
const statusBuckets = new Set(["1xx", "2xx", "3xx", "4xx", "5xx"]);
const attrKeys = [
  "outcome",
  "state",
  "dependency",
  "tool",
  "path_class",
  "operation",
  "method",
  "credential_required",
  "truncated",
  "timed_out",
  "cancelled",
  "duration_ms",
  "count",
  "value",
  "bytes_bucket",
  "status_bucket",
] as const;
type AttrKey = (typeof attrKeys)[number];
type AttrValue = string | number | boolean;
type Item = Readonly<{
  kind: "span" | "metric";
  name: string;
  timestamp: number;
  traceId: string;
  spanId: string;
  attributes: Readonly<Record<string, AttrValue>>;
}>;

export function createCogsWorkerTelemetrySink(config: CogsWorkerTelemetryMode = Object.freeze({ mode: "disabled" })) {
  try {
    const snap = snapshotConfig(config);
    if (snap.mode === "disabled") return disabledSink();
    return new OtlpWorkerSink(snap).handle();
  } catch {
    throw new Error("invalid worker telemetry");
  }
}

export function validateCogsWorkerTelemetrySink(value: CogsWorkerTelemetrySink | undefined): void {
  try {
    if (value === undefined) return;
    if (value === null || typeof value !== "object" || !Object.isFrozen(value)) throw new Error("bad sink");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors).sort();
    if (keys.join("\0") !== ["close", "metric", "ready", "snapshot", "span"].join("\0")) throw new Error("bad sink");
    for (const key of ["span", "metric", "snapshot", "close"] as const) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "function")
        throw new Error("bad sink");
    }
    const ready = descriptors.ready;
    if (ready === undefined || typeof ready.get !== "function" || typeof value.ready !== "boolean")
      throw new Error("bad sink");
  } catch {
    throw new Error("invalid worker telemetry sink");
  }
}

function snapshotConfig(config: CogsWorkerTelemetryMode):
  | Readonly<{ mode: "disabled" }>
  | Readonly<{
      mode: "otlp";
      tracesEndpoint: string;
      metricsEndpoint: string;
      capacity: number;
      batchSize: number;
      timeoutMs: number;
      maxResponseBytes: number;
      fetch: FetchLike;
      clock: ClockLike;
      random: RandomLike;
    }> {
  exactPlainObject(
    config,
    ["mode"],
    [
      "allowLoopbackHttpDevelopment",
      "batchSize",
      "capacity",
      "clock",
      "fetch",
      "maxResponseBytes",
      "metricsEndpoint",
      "random",
      "timeoutMs",
      "tracesEndpoint",
    ],
  );
  if (config.mode === "disabled") {
    exactPlainObject(config, ["mode"], []);
    return Object.freeze({ mode: "disabled" });
  }
  if (config.mode !== "otlp") throw new Error("bad mode");
  exactPlainObject(
    config,
    ["metricsEndpoint", "mode", "tracesEndpoint"],
    [
      "allowLoopbackHttpDevelopment",
      "batchSize",
      "capacity",
      "clock",
      "fetch",
      "maxResponseBytes",
      "random",
      "timeoutMs",
    ],
  );
  const allow = boolOpt(config, "allowLoopbackHttpDevelopment") ?? false;
  const fetchFn = (Object.hasOwn(config, "fetch") ? frozenFetch(config.fetch) : fetch) as FetchLike;
  const clock = clockOpt(config, "clock") ?? Object.freeze({ nowMs: () => Date.now() });
  const random =
    randomOpt(config, "random") ??
    Object.freeze({ bytes: (length: number) => crypto.getRandomValues(new Uint8Array(length)) });
  return Object.freeze({
    mode: "otlp",
    tracesEndpoint: otlpEndpoint(config.tracesEndpoint, "traces", allow),
    metricsEndpoint: otlpEndpoint(config.metricsEndpoint, "metrics", allow),
    capacity: intOpt(config, "capacity", 1, 1024) ?? 128,
    batchSize: intOpt(config, "batchSize", 1, 128) ?? 32,
    timeoutMs: intOpt(config, "timeoutMs", 50, 10_000) ?? 1000,
    maxResponseBytes: intOpt(config, "maxResponseBytes", 0, 65_536) ?? 8192,
    fetch: fetchFn,
    clock,
    random,
  });
}

class OtlpWorkerSink {
  private queue: Item[] = [];
  private nextBatchId = 0;
  private pumping: Promise<void> | undefined;
  private controller: AbortController | undefined;
  private closePromise: Promise<void> | undefined;
  private scheduled = false;
  private closing = false;
  private closed = false;
  private exported = 0;
  private dropped = 0;
  private failed = 0;
  private firstQueuedAt = 0;
  private inFlight = 0;
  private inFlightOldestAt = 0;
  private inFlightUnaccounted = 0;
  private inFlightId = 0;
  private cooldownUntil = 0;
  public constructor(private readonly config: Extract<ReturnType<typeof snapshotConfig>, { mode: "otlp" }>) {}
  public handle(): CogsWorkerTelemetrySink {
    const sink = this;
    return Object.freeze({
      get ready() {
        return !sink.closing && !sink.closed;
      },
      span: (input) => sink.enqueue("span", input),
      metric: (input) => sink.enqueue("metric", input),
      snapshot: () => sink.snapshot(),
      close: (signal) => (sink.closePromise ??= sink.close(signal)),
    });
  }
  private enqueue(kind: "span" | "metric", input: unknown): boolean {
    try {
      if (
        this.closing ||
        this.closed ||
        this.inCooldown() ||
        this.queue.length + this.inFlight >= this.config.capacity
      ) {
        this.dropped = saturatingAdd(this.dropped, 1);
        return false;
      }
      const item = itemFrom(kind, input, this.config.clock, this.config.random);
      if (this.queue.length === 0) this.firstQueuedAt = item.timestamp;
      this.queue.push(item);
      this.kick();
      return true;
    } catch {
      this.dropped = saturatingAdd(this.dropped, 1);
      return false;
    }
  }
  private snapshot(): CogsWorkerTelemetrySnapshot {
    let lag = 0;
    try {
      const oldest = oldestTimestamp(this.firstQueuedAt, this.inFlightOldestAt);
      if (oldest > 0 && this.queue.length + this.inFlight > 0) lag = Math.max(0, this.nowMs() - oldest);
    } catch {
      lag = 0;
    }
    return Object.freeze({
      ready: !this.closing && !this.closed,
      queued: this.queue.length + this.inFlight,
      exported: this.exported,
      dropped: this.dropped,
      failed: this.failed,
      lag_ms: lag,
    });
  }
  private kick(): void {
    if (this.pumping !== undefined || this.scheduled) return;
    this.scheduled = true;
    queueMicrotask(() => {
      this.scheduled = false;
      if (!this.closing && !this.closed && this.queue.length > 0) this.startPump();
    });
  }
  private startPump(): void {
    this.pumping = this.pump()
      .catch(() => {
        this.accountFailed(this.inFlightId, this.inFlightUnaccounted);
      })
      .finally(() => {
        this.pumping = undefined;
      });
  }
  private async pump(): Promise<void> {
    while (!this.closing && !this.closed && this.queue.length > 0) {
      const batch = this.takeBatch();
      try {
        await this.postBatch(batch);
      } finally {
        if (!this.closed) this.clearInFlight(batch.id);
      }
    }
  }
  private async close(signal?: AbortSignal): Promise<void> {
    this.closing = true;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timer = setTimeout(abort, this.config.timeoutMs);
    try {
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      this.controller?.abort();
      if (this.pumping !== undefined)
        await raceTimeout(
          this.pumping.catch(() => undefined),
          this.config.timeoutMs,
          () => this.controller?.abort(),
          controller.signal,
        ).catch(() => undefined);
      while (!controller.signal.aborted && this.queue.length > 0) {
        const batch = this.takeBatch();
        try {
          await this.postBatch(batch, controller.signal);
        } finally {
          if (!this.closed) this.clearInFlight(batch.id);
        }
      }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      this.dropped = saturatingAdd(this.dropped, this.queue.length);
      this.queue = [];
      this.firstQueuedAt = 0;
      this.accountFailed(this.inFlightId, this.inFlightUnaccounted);
      this.inFlightUnaccounted = 0;
      this.inFlight = 0;
      this.inFlightOldestAt = 0;
      this.inFlightId = 0;
      this.closed = true;
    }
  }
  private takeBatch(): Readonly<{ id: number; items: readonly Item[] }> {
    const items = this.queue.splice(0, Math.min(this.config.batchSize, this.queue.length));
    const id = ++this.nextBatchId;
    this.firstQueuedAt = this.queue[0]?.timestamp ?? 0;
    this.inFlight = items.length;
    this.inFlightUnaccounted = items.length;
    this.inFlightOldestAt = items[0]?.timestamp ?? 0;
    this.inFlightId = id;
    return Object.freeze({ id, items });
  }
  private clearInFlight(id: number): void {
    if (this.inFlightId !== id) return;
    this.inFlight = 0;
    this.inFlightUnaccounted = 0;
    this.inFlightOldestAt = 0;
    this.inFlightId = 0;
  }
  private async postBatch(
    batch: Readonly<{ id: number; items: readonly Item[] }>,
    parent?: AbortSignal,
  ): Promise<void> {
    const traces = batch.items.filter((item) => item.kind === "span");
    const metrics = batch.items.filter((item) => item.kind === "metric");
    if (!this.canPost(parent)) {
      this.accountFailed(batch.id, traces.length + metrics.length);
      return;
    }
    const tracesOk = await this.postGroup(batch.id, this.config.tracesEndpoint, traces, tracesEnvelope, parent);
    if (!tracesOk || !this.canPost(parent) || this.inCooldown()) {
      this.accountFailed(batch.id, metrics.length);
      return;
    }
    await this.postGroup(batch.id, this.config.metricsEndpoint, metrics, metricsEnvelope, parent);
  }
  private nowMs(): number {
    return safeInteger(this.config.clock.nowMs(), 0, Number.MAX_SAFE_INTEGER);
  }
  private safeNowMs(): number {
    try {
      return this.nowMs();
    } catch {
      return 0;
    }
  }
  private inCooldown(): boolean {
    return this.cooldownUntil > this.safeNowMs();
  }
  private startCooldown(): void {
    try {
      this.cooldownUntil = saturatingAdd(this.nowMs(), this.config.timeoutMs);
    } catch {
      this.cooldownUntil = Number.MAX_SAFE_INTEGER;
    }
  }
  private canPost(parent?: AbortSignal): boolean {
    if (this.closed || this.inCooldown()) return false;
    if (parent?.aborted) return false;
    return !(this.closing && parent === undefined);
  }
  private retire(id: number, count: number): void {
    if (this.inFlightId !== id) return;
    this.inFlightUnaccounted = Math.max(0, this.inFlightUnaccounted - Math.max(0, count));
  }
  private accountFailed(id: number, count: number): void {
    if (this.inFlightId !== id || count <= 0) return;
    if (!this.closed) {
      this.failed = saturatingAdd(this.failed, count);
      this.dropped = saturatingAdd(this.dropped, count);
    }
    this.retire(id, count);
  }
  private async postGroup(
    id: number,
    url: string,
    records: readonly Item[],
    envelope: (records: readonly Item[]) => unknown,
    parent?: AbortSignal,
  ): Promise<boolean> {
    if (records.length === 0) return true;
    if (!this.canPost(parent)) {
      this.accountFailed(id, records.length);
      return false;
    }
    try {
      await this.post(url, envelope(records), parent);
      if (!this.closed) this.exported = saturatingAdd(this.exported, records.length);
      this.retire(id, records.length);
      return true;
    } catch {
      this.accountFailed(id, records.length);
      if (!this.closed) this.startCooldown();
      return false;
    }
  }
  private async post(url: string, bodyObject: unknown, parent?: AbortSignal): Promise<void> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    this.controller = controller;
    try {
      parent?.addEventListener("abort", abort, { once: true });
      if (parent?.aborted) abort();
      await postOtlpJson({
        url,
        kind: url.endsWith("/v1/traces") ? "traces" : "metrics",
        body: bodyObject,
        timeoutMs: this.config.timeoutMs,
        maxRequestBytes: 262_144,
        maxResponseBytes: this.config.maxResponseBytes,
        fetch: this.config.fetch,
        parent: controller.signal,
      });
    } finally {
      parent?.removeEventListener("abort", abort);
      controller.abort();
      if (this.controller === controller) this.controller = undefined;
    }
  }
}

function itemFrom(kind: "span" | "metric", input: unknown, clock: ClockLike, random: RandomLike): Item {
  exactPlainObject(input, ["attributes", "name"], ["span_id", "trace_id"]);
  const name = str(input.name);
  if (kind === "span" ? !spanNames.has(name) : !metricNames.has(name)) throw new Error("bad name");
  const traceId = Object.hasOwn(input, "trace_id") ? nonzeroHex(input.trace_id, 32) : randomHex(random, 16);
  const spanId = Object.hasOwn(input, "span_id") ? nonzeroHex(input.span_id, 16) : randomHex(random, 8);
  return Object.freeze({
    kind,
    name,
    timestamp: safeInteger(clock.nowMs(), 0, Number.MAX_SAFE_INTEGER),
    traceId,
    spanId,
    attributes: attrs(input.attributes),
  });
}

function attrs(value: unknown): Readonly<Record<string, AttrValue>> {
  exactPlainObject(value, [], attrKeys);
  const out: Record<string, AttrValue> = {};
  for (const key of attrKeys) {
    if (!Object.hasOwn(value, key)) continue;
    const raw = (value as Record<string, unknown>)[key];
    out[key] = attrValue(key, raw);
  }
  return Object.freeze(out);
}
function attrValue(key: AttrKey, value: unknown): AttrValue {
  if (key === "outcome") return enumString(value, outcomes);
  if (key === "state") return enumString(value, states);
  if (key === "dependency") return enumString(value, dependencies);
  if (key === "tool") return enumString(value, tools);
  if (key === "path_class") return enumString(value, pathClasses);
  if (key === "operation") return enumString(value, operations);
  if (key === "method") return enumString(value, methods);
  if (key === "bytes_bucket") return enumString(value, buckets);
  if (key === "status_bucket") return enumString(value, statusBuckets);
  if (key === "credential_required" || key === "truncated" || key === "timed_out" || key === "cancelled") {
    if (typeof value !== "boolean") throw new Error("bad bool");
    return value;
  }
  const max = key === "count" || key === "value" ? Number.MAX_SAFE_INTEGER : 86_400_000;
  return safeInteger(value, 0, max);
}

function tracesEnvelope(records: readonly Item[]): unknown {
  return {
    resourceSpans: [
      {
        resource: { attributes: [otAttr("service.name", "cogs-worker")] },
        scopeSpans: [
          {
            scope: { name: "cogs.worker.telemetry", version: "v1alpha1" },
            spans: records.map((item) => ({
              traceId: item.traceId,
              spanId: item.spanId,
              name: item.name,
              kind: 1,
              startTimeUnixNano: ns(Math.max(0, item.timestamp - durationMs(item.attributes))),
              endTimeUnixNano: ns(item.timestamp),
              attributes: otAttrs(item.attributes),
            })),
          },
        ],
      },
    ],
  };
}
function metricsEnvelope(records: readonly Item[]): unknown {
  const grouped = new Map<string, Item[]>();
  for (const item of records) {
    const existing = grouped.get(item.name);
    if (existing === undefined) grouped.set(item.name, [item]);
    else existing.push(item);
  }
  return {
    resourceMetrics: [
      {
        resource: { attributes: [otAttr("service.name", "cogs-worker")] },
        scopeMetrics: [
          {
            scope: { name: "cogs.worker.telemetry", version: "v1alpha1" },
            metrics: Array.from(grouped, ([name, items]) => {
              const dataPoints = items.map((item) => ({
                timeUnixNano: ns(item.timestamp),
                asInt: String(metricValue(item.attributes)),
                attributes: otAttrs(metricAttrs(item.attributes)),
              }));
              return gaugeMetricNames.has(name)
                ? { name, gauge: { dataPoints } }
                : { name, sum: { aggregationTemporality: 1, isMonotonic: true, dataPoints } };
            }),
          },
        ],
      },
    ],
  };
}
function metricValue(attrs: Readonly<Record<string, AttrValue>>): number {
  if (typeof attrs.value === "number") return attrs.value;
  if (typeof attrs.count === "number") return attrs.count;
  return 1;
}
function durationMs(attrs: Readonly<Record<string, AttrValue>>): number {
  return typeof attrs.duration_ms === "number" ? attrs.duration_ms : 0;
}
function metricAttrs(attrs: Readonly<Record<string, AttrValue>>): Readonly<Record<string, AttrValue>> {
  const filtered: Record<string, AttrValue> = {};
  for (const key of Object.keys(attrs).sort()) {
    if (key !== "count" && key !== "value") filtered[key] = attrs[key] as AttrValue;
  }
  return Object.freeze(filtered);
}
function otAttrs(attrs: Readonly<Record<string, AttrValue>>): unknown[] {
  return Object.keys(attrs)
    .sort()
    .map((key) => otAttr(`cogs.${key}`, attrs[key] as AttrValue));
}
function otAttr(key: string, value: AttrValue): unknown {
  if (typeof value === "string") return { key, value: { stringValue: value } };
  if (typeof value === "boolean") return { key, value: { boolValue: value } };
  return { key, value: { intValue: String(value) } };
}
function ns(ms: number): string {
  return (BigInt(ms) * 1_000_000n).toString();
}

function saturatingAdd(value: number, delta: number): number {
  return Math.min(Number.MAX_SAFE_INTEGER, value + Math.max(0, delta));
}

function oldestTimestamp(a: number, b: number): number {
  if (a <= 0) return b;
  if (b <= 0) return a;
  return Math.min(a, b);
}

function intOpt(value: Record<string, unknown>, key: string, min: number, max: number): number | undefined {
  return Object.hasOwn(value, key) ? safeInteger(value[key], min, max) : undefined;
}
function boolOpt(value: Record<string, unknown>, key: string): boolean | undefined {
  if (!Object.hasOwn(value, key)) return undefined;
  if (typeof value[key] !== "boolean") throw new Error("bad bool");
  return value[key];
}
function clockOpt(value: Record<string, unknown>, key: string): ClockLike | undefined {
  if (!Object.hasOwn(value, key)) return undefined;
  exactPlainObject(value[key], ["nowMs"], []);
  if (typeof (value[key] as ClockLike).nowMs !== "function" || !Object.isFrozen((value[key] as ClockLike).nowMs))
    throw new Error("bad clock");
  return Object.freeze({ nowMs: (value[key] as ClockLike).nowMs });
}
function randomOpt(value: Record<string, unknown>, key: string): RandomLike | undefined {
  if (!Object.hasOwn(value, key)) return undefined;
  exactPlainObject(value[key], ["bytes"], []);
  if (typeof (value[key] as RandomLike).bytes !== "function" || !Object.isFrozen((value[key] as RandomLike).bytes))
    throw new Error("bad random");
  return Object.freeze({ bytes: (value[key] as RandomLike).bytes });
}
function str(value: unknown): string {
  if (typeof value !== "string") throw new Error("bad string");
  return value;
}
function enumString(value: unknown, allowed: Set<string>): string {
  const text = str(value);
  if (!allowed.has(text)) throw new Error("bad enum");
  return text;
}
function nonzeroHex(value: unknown, length: number): string {
  const text = str(value);
  if (!new RegExp(`^[0-9a-f]{${length}}$`).test(text) || /^0+$/.test(text)) throw new Error("bad hex");
  return text;
}
function randomHex(random: RandomLike, length: number): string {
  const bytes = random.bytes(length);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) throw new Error("bad random");
  return nonzeroHex(Buffer.from(bytes).toString("hex"), length * 2);
}
function disabledSink(): CogsWorkerTelemetrySink {
  let closed = false;
  const snapshot = () => Object.freeze({ ready: !closed, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 });
  return Object.freeze({
    get ready() {
      return !closed;
    },
    span: () => false,
    metric: () => false,
    snapshot,
    close: async () => {
      closed = true;
    },
  });
}
