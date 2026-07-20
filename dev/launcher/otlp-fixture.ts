import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Socket } from "node:net";
import { hasDuplicateJsonKeys } from "./contract.ts";

const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const EVENT_ADD = EventTarget.prototype.addEventListener;
const EVENT_REMOVE = EventTarget.prototype.removeEventListener;

export type OtlpSignal = "logs" | "traces" | "metrics";
export type OtlpFixtureSnapshot = Readonly<{
  ready: boolean;
  port: number;
  generation: number;
  inflight: number;
  logs: number;
  traces: number;
  metrics: number;
  names: readonly string[];
}>;
export type OtlpCooperativeOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;
export type OtlpFixture = Readonly<{
  endpoint(signal: OtlpSignal): string;
  snapshot(): OtlpFixtureSnapshot;
  reset(): void;
  close(options?: OtlpCooperativeOptions): Promise<void>;
}>;

const paths: Record<string, OtlpSignal> = Object.freeze({
  "/v1/logs": "logs",
  "/v1/traces": "traces",
  "/v1/metrics": "metrics",
});
const forbidden =
  /(?:prompt|output|secret|token|credential|authorization|api[-_]?key|private|password|path|account|provider|(?:^|[_.-])source(?:$|[_.-]))/iu;
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
const workerAttr = new Set([
  "cogs.outcome",
  "cogs.state",
  "cogs.dependency",
  "cogs.tool",
  "cogs.path_class",
  "cogs.operation",
  "cogs.method",
  "cogs.credential_required",
  "cogs.truncated",
  "cogs.timed_out",
  "cogs.cancelled",
  "cogs.duration_ms",
  "cogs.count",
  "cogs.value",
  "cogs.bytes_bucket",
  "cogs.status_bucket",
]);
const egressAttr = new Set([
  "cogs.completed_lag_ms",
  "cogs.credential_required",
  "cogs.duration_ms",
  "cogs.event",
  "cogs.integration_id",
  "cogs.intent_id",
  "cogs.intent_sequence",
  "cogs.method",
  "cogs.route_id",
  "cogs.session_id",
  "cogs.status_class",
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

export async function startOtlpFixture(
  options: {
    deadlineMs?: number;
    maxBytes?: number;
    maxInflight?: number;
    maxRecords?: number;
    signal?: AbortSignal;
    deadlineAt?: number;
  } = {},
): Promise<OtlpFixture> {
  let o: {
    deadlineMs?: number;
    maxBytes?: number;
    maxInflight?: number;
    maxRecords?: number;
    signal?: AbortSignal;
    deadlineAt?: number;
  };
  let cooperative: OtlpCooperativeOptions;
  let deadlineMs: number;
  let maxBytes: number;
  let maxInflight: number;
  let maxRecords: number;
  try {
    o = snapshotOptions(options);
    cooperative = cooperativeOptions(o, true);
    deadlineMs = integer(o.deadlineMs ?? 1000, 50, 10_000);
    maxBytes = integer(o.maxBytes ?? 1024 * 1024, 128, 1024 * 1024);
    maxInflight = integer(o.maxInflight ?? 8, 1, 64);
    maxRecords = integer(o.maxRecords ?? 4096, 1, 4096);
  } catch {
    throw new Error("launcher otlp fixture failed");
  }
  let acceptedTotal = 0;
  let closed = false;
  let generation = 0;
  let inflight = 0;
  const counts: Record<OtlpSignal, number> = { logs: 0, traces: 0, metrics: 0 };
  const names = new Set<string>();
  const sockets = new Set<Socket>();
  let closePromise: Promise<void> | undefined;
  const server = createServer((request, response) => {
    void handle(request, response).catch(() => rejectRequest(request, response, 400));
  });
  server.maxConnections = maxInflight;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.setTimeout(deadlineMs, () => socket.destroy());
    socket.once("close", () => sockets.delete(socket));
  });
  let port: number;
  try {
    await listenServer(server, cooperative, () => destroyOwnedConnections());
    if (aborted(cooperative)) throw new Error("launcher otlp fixture failed");
    const address = server.address();
    port = typeof address === "object" && address ? address.port : 0;
    if (!Number.isInteger(port) || port < 1) throw new Error("bad port");
  } catch {
    await closeServer(server, () => destroyOwnedConnections());
    throw new Error("launcher otlp fixture failed");
  }

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (closed || inflight >= maxInflight) return rejectRequest(request, response, 503);
    const signal = paths[String(request.url ?? "")];
    if (!signal || request.method !== "POST" || hasBadHeaders(request, maxBytes))
      return rejectRequest(request, response, 400);
    inflight++;
    const timer = setTimeout(() => request.destroy(), deadlineMs);
    try {
      const body = await readBody(request, maxBytes, deadlineMs);
      if (hasDuplicateJsonKeys(body)) throw new Error("bad json");
      const value = JSON.parse(body) as unknown;
      const accepted = audit(value, signal);
      if (acceptedTotal + accepted.count > maxRecords) throw new Error("bad count");
      acceptedTotal += accepted.count;
      counts[signal] += accepted.count;
      for (const name of accepted.names) names.add(name);
      response.setHeader("content-type", "application/json");
      response.setHeader("cache-control", "no-store");
      response.end("{}");
    } catch {
      rejectRequest(request, response, 400);
    } finally {
      clearTimeout(timer);
      inflight--;
    }
  }

  return Object.freeze({
    endpoint: (signal) => {
      if (signal !== "logs" && signal !== "traces" && signal !== "metrics")
        throw new Error("launcher otlp fixture failed");
      return `http://127.0.0.1:${port}/v1/${signal}`;
    },
    snapshot: () =>
      Object.freeze({ ready: !closed, port, generation, inflight, ...counts, names: Object.freeze([...names].sort()) }),
    reset: () => {
      if (closed || inflight !== 0) throw new Error("launcher otlp fixture failed");
      counts.logs = 0;
      counts.traces = 0;
      counts.metrics = 0;
      names.clear();
      acceptedTotal = 0;
      generation++;
    },
    close: (options) => {
      const closeOptions = cooperativeOptions(options ?? {}, false);
      if (closePromise === undefined) {
        closePromise = (async () => {
          closed = true;
          const cleanupAbort = watchAbort(closeOptions, destroyOwnedConnections);
          const deadlineTimer = armDeadline(closeOptions, destroyOwnedConnections);
          try {
            await closeServer(server, destroyOwnedConnections);
            destroyOwnedConnections();
            await new Promise((resolve) => setTimeout(resolve, 0));
            if (server.listening || inflight !== 0) throw new Error("launcher otlp fixture failed");
            await assertClosed(port);
          } finally {
            cleanupAbort();
            deadlineTimer();
            counts.logs = 0;
            counts.traces = 0;
            counts.metrics = 0;
            names.clear();
            acceptedTotal = 0;
          }
        })();
      }
      return closePromise;
    },
  });

  function destroyOwnedConnections(): void {
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections?.();
  }

  function audit(value: unknown, signal: OtlpSignal): { count: number; names: readonly string[] } {
    const seen: string[] = [];
    const count =
      signal === "traces" ? traces(value, seen) : signal === "metrics" ? metrics(value, seen) : logs(value, seen);
    if (count < 1 || count > maxRecords) throw new Error("bad count");
    return Object.freeze({ count, names: Object.freeze(seen) });
  }
}

function traces(value: unknown, seen: string[]): number {
  const root = obj(value, ["resourceSpans"]);
  const rs = arr(root.resourceSpans, 1, 1).map((r) => obj(r, ["resource", "scopeSpans"]));
  const res = obj(rs[0]?.resource, ["attributes"]);
  service(res.attributes, "cogs-worker");
  const scopeSpans = arr(rs[0]?.scopeSpans, 1, 1).map((s) => obj(s, ["scope", "spans"]));
  scope(scopeSpans[0]?.scope, "cogs.worker.telemetry");
  const spans = arr(scopeSpans[0]?.spans, 1, 4096).map((s) =>
    obj(s, ["attributes", "endTimeUnixNano", "kind", "name", "spanId", "startTimeUnixNano", "traceId"]),
  );
  for (const span of spans) {
    hex(span.traceId, 32);
    hex(span.spanId, 16);
    if (span.kind !== 1 || typeof span.name !== "string" || !spanNames.has(span.name)) throw new Error("bad span");
    const start = nano(span.startTimeUnixNano);
    const end = nano(span.endTimeUnixNano);
    if (end < start) throw new Error("bad span time");
    attrs(span.attributes, false);
    seen.push(span.name);
  }
  seen.push("cogs.worker.telemetry");
  return spans.length;
}
function metrics(value: unknown, seen: string[]): number {
  const root = obj(value, ["resourceMetrics"]);
  const rm = arr(root.resourceMetrics, 1, 1).map((r) => obj(r, ["resource", "scopeMetrics"]));
  service(obj(rm[0]?.resource, ["attributes"]).attributes, "cogs-worker");
  const sm = arr(rm[0]?.scopeMetrics, 1, 1).map((s) => obj(s, ["metrics", "scope"]));
  scope(sm[0]?.scope, "cogs.worker.telemetry");
  const metrics = arr(sm[0]?.metrics, 1, 4096).map((m) => obj(m, ["name"], ["gauge", "sum"]));
  const namesSeen = new Set<string>();
  let points = 0;
  for (const metric of metrics) {
    if (typeof metric.name !== "string" || !metricNames.has(metric.name) || namesSeen.has(metric.name))
      throw new Error("bad metric");
    namesSeen.add(metric.name);
    const gauge = Object.hasOwn(metric, "gauge");
    if (Object.hasOwn(metric, "gauge") === Object.hasOwn(metric, "sum")) throw new Error("bad metric kind");
    if (gauge !== gaugeMetricNames.has(metric.name)) throw new Error("bad metric kind");
    const holder = obj(
      gauge ? metric.gauge : metric.sum,
      gauge ? ["dataPoints"] : ["aggregationTemporality", "dataPoints", "isMonotonic"],
    );
    if (!gauge && (holder.aggregationTemporality !== 1 || holder.isMonotonic !== true)) throw new Error("bad sum");
    const dps = arr(holder.dataPoints, 1, 4096).map((p) => obj(p, ["asInt", "attributes", "timeUnixNano"]));
    points += dps.length;
    if (points > 4096) throw new Error("bad points");
    for (const point of dps) {
      nano(point.timeUnixNano);
      asInt(point.asInt, "value");
      attrs(point.attributes, false);
    }
    seen.push(metric.name);
  }
  seen.push("cogs.worker.telemetry");
  return points;
}
function logs(value: unknown, seen: string[]): number {
  const root = obj(value, ["resourceLogs"]);
  const rl = arr(root.resourceLogs, 1, 1).map((r) => obj(r, ["resource", "scopeLogs"]));
  service(obj(rl[0]?.resource, ["attributes"]).attributes, "cogs-egress");
  const sl = arr(rl[0]?.scopeLogs, 1, 1).map((s) => obj(s, ["logRecords", "scope"]));
  scope(sl[0]?.scope, "cogs.egress.telemetry");
  const records = arr(sl[0]?.logRecords, 1, 4096).map((r) =>
    obj(r, ["attributes", "body", "severityText", "timeUnixNano"]),
  );
  for (const record of records) {
    if (record.severityText !== "INFO" || obj(record.body, ["stringValue"]).stringValue !== "cogs.egress.complete")
      throw new Error("bad log");
    nano(record.timeUnixNano);
    attrs(record.attributes, true);
    seen.push("cogs.egress.complete");
  }
  seen.push("cogs.egress.telemetry");
  return records.length;
}
function service(value: unknown, expected: string): void {
  const a = arr(value, 1, 1).map((x) => obj(x, ["key", "value"]));
  if (a[0]?.key !== "service.name" || obj(a[0].value, ["stringValue"]).stringValue !== expected)
    throw new Error("bad service");
}
function scope(value: unknown, expected: string): void {
  const s = obj(value, ["name", "version"]);
  if (s.name !== expected || s.version !== "v1alpha1") throw new Error("bad scope");
}
function attrs(value: unknown, egress: boolean): void {
  const list = arr(value, egress ? 11 : 0, egress ? 11 : 32).map((x) => obj(x, ["key", "value"]));
  const values = new Map<string, string | number | boolean>();
  for (const item of list) {
    const allowed = egress ? egressAttr : workerAttr;
    if (typeof item.key !== "string" || values.has(item.key) || !allowed.has(item.key)) throw new Error("bad attr");
    values.set(item.key, attrValue(item.key, item.value));
  }
  if (!egress) return;
  const expected = [
    "cogs.completed_lag_ms",
    "cogs.credential_required",
    "cogs.duration_ms",
    "cogs.event",
    "cogs.integration_id",
    "cogs.intent_id",
    "cogs.intent_sequence",
    "cogs.method",
    "cogs.route_id",
    "cogs.session_id",
    "cogs.status_class",
  ];
  if ([...values.keys()].sort().join(",") !== expected.join(",")) throw new Error("bad egress attrs");
  if (values.get("cogs.event") !== "egress.complete") throw new Error("bad egress event");
  if (!["GET", "POST"].includes(String(values.get("cogs.method")))) throw new Error("bad egress method");
  const status = values.get("cogs.status_class");
  if (typeof status !== "number" || status < 1 || status > 5) throw new Error("bad egress status");
  if (typeof values.get("cogs.credential_required") !== "boolean") throw new Error("bad egress bool");
}
function obj(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("bad object");
  const d = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(d);
  if (keys.some((k) => typeof k !== "string" || ![...required, ...optional].includes(k))) throw new Error("bad keys");
  for (const key of required) if (!Object.hasOwn(d, key)) throw new Error("missing key");
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys as string[]) {
    const item = d[key];
    if (!item || !("value" in item) || item.enumerable !== true) throw new Error("bad descriptor");
    out[key] = item.value;
  }
  return out;
}
function arr(value: unknown, min: number, max: number): unknown[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < min ||
    value.length > max
  )
    throw new Error("bad array");
  return value;
}
function hex(value: unknown, length: number): void {
  if (typeof value !== "string" || !new RegExp(`^[a-f0-9]{${length}}$`, "u").test(value) || /^0+$/u.test(value))
    throw new Error("bad hex");
}
function attrValue(key: string, value: unknown): string | number | boolean {
  const v = obj(value, [], ["boolValue", "intValue", "stringValue"]);
  if (Object.keys(v).length !== 1) throw new Error("bad attr value");
  const name = key.replace(/^cogs\./u, "");
  if (["credential_required", "truncated", "timed_out", "cancelled"].includes(name)) {
    if (typeof v.boolValue !== "boolean") throw new Error("bad bool");
    return v.boolValue;
  }
  if (["duration_ms", "count", "value", "intent_sequence", "status_class", "completed_lag_ms"].includes(name)) {
    return asInt(v.intValue, name);
  }
  if (typeof v.stringValue !== "string" || forbidden.test(v.stringValue)) throw new Error("bad string");
  if (name === "outcome" && !outcomes.has(v.stringValue)) throw new Error("bad enum");
  if (name === "state" && !states.has(v.stringValue)) throw new Error("bad enum");
  if (name === "dependency" && !dependencies.has(v.stringValue)) throw new Error("bad enum");
  if (name === "tool" && !tools.has(v.stringValue)) throw new Error("bad enum");
  if (name === "path_class" && !pathClasses.has(v.stringValue)) throw new Error("bad enum");
  if (name === "operation" && !operations.has(v.stringValue)) throw new Error("bad enum");
  if (name === "method" && !methods.has(v.stringValue)) throw new Error("bad enum");
  if (name === "bytes_bucket" && !buckets.has(v.stringValue)) throw new Error("bad enum");
  if (name === "status_bucket" && !statusBuckets.has(v.stringValue)) throw new Error("bad enum");
  if (["event", "intent_id", "session_id", "integration_id", "route_id"].includes(name)) {
    if (!/^[A-Za-z0-9_.:-]{1,128}$/u.test(v.stringValue)) throw new Error("bad opaque");
  }
  return v.stringValue;
}
function asInt(value: unknown, key: string): number {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,15})$/u.test(value)) throw new Error("bad int");
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("bad int");
  if ((key === "duration_ms" || key === "completed_lag_ms") && n > 86_400_000) throw new Error("bad duration");
  if (key === "status_class" && (n < 1 || n > 5)) throw new Error("bad status");
  return n;
}
function nano(value: unknown): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,19})$/u.test(value)) throw new Error("bad time");
  return BigInt(value);
}

function hasBadHeaders(request: IncomingMessage, maxBytes: number): boolean {
  const url = request.url ?? "";
  const len = request.headers["content-length"];
  const rawNames = request.rawHeaders.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase());
  const dup = new Set<string>();
  for (const name of rawNames) {
    if (["content-type", "content-length", "content-encoding"].includes(name)) {
      if (dup.has(name)) return true;
      dup.add(name);
    }
  }
  return (
    url.includes("?") ||
    request.headers["content-encoding"] !== undefined ||
    contentType(request.headers["content-type"]) !== "application/json" ||
    Array.isArray(len) ||
    (len !== undefined && (!/^\d+$/u.test(len) || Number(len) > maxBytes))
  );
}
function contentType(value: string | string[] | undefined): string {
  return typeof value === "string" ? (value.split(";", 1)[0]?.trim().toLowerCase() ?? "") : "";
}
async function readBody(request: IncomingMessage, max: number, deadlineMs: number): Promise<string> {
  let total = 0;
  const chunks: Buffer[] = [];
  const start = Date.now();
  let chunkCount = 0;
  for await (const chunk of request) {
    if (Date.now() - start > deadlineMs) throw new Error("timeout");
    if (++chunkCount > 1024) throw new Error("too many chunks");
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += b.length;
    if (total > max) throw new Error("too large");
    chunks.push(b);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
}
function rejectRequest(request: IncomingMessage, response: ServerResponse, status: number): void {
  response.statusCode = status;
  response.setHeader("cache-control", "no-store");
  response.end("");
  request.resume();
  setTimeout(() => request.destroy(), 25).unref();
}
function integer(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error("launcher otlp fixture failed");
  return value;
}
function snapshotOptions(value: {
  deadlineMs?: number;
  maxBytes?: number;
  maxInflight?: number;
  maxRecords?: number;
  signal?: AbortSignal;
  deadlineAt?: number;
}): {
  deadlineMs?: number;
  maxBytes?: number;
  maxInflight?: number;
  maxRecords?: number;
  signal?: AbortSignal;
  deadlineAt?: number;
} {
  try {
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    )
      throw new Error("bad options");
    const d = Object.getOwnPropertyDescriptors(value);
    const out: {
      deadlineMs?: number;
      maxBytes?: number;
      maxInflight?: number;
      maxRecords?: number;
      signal?: AbortSignal;
      deadlineAt?: number;
    } = {};
    for (const key of Reflect.ownKeys(d)) {
      if (
        typeof key !== "string" ||
        !["deadlineMs", "maxBytes", "maxInflight", "maxRecords", "signal", "deadlineAt"].includes(key)
      )
        throw new Error("bad options");
      const item = d[key];
      if (!item || !("value" in item) || item.enumerable !== true) throw new Error("bad options");
      out[key as keyof typeof out] = item.value as never;
    }
    return Object.freeze(out);
  } catch {
    throw new Error("launcher otlp fixture failed");
  }
}
function cooperativeOptions(value: unknown, startOptions: boolean): OtlpCooperativeOptions {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("launcher otlp fixture failed");
  const d = Object.getOwnPropertyDescriptors(value);
  const out: { signal?: AbortSignal; deadlineAt?: number } = {};
  const allowed = startOptions
    ? ["deadlineMs", "maxBytes", "maxInflight", "maxRecords", "signal", "deadlineAt"]
    : ["signal", "deadlineAt"];
  for (const key of Reflect.ownKeys(d)) {
    if (typeof key !== "string" || !allowed.includes(key)) throw new Error("launcher otlp fixture failed");
    const item = d[key];
    if (!item || !("value" in item) || item.enumerable !== true) throw new Error("launcher otlp fixture failed");
    if (key === "signal") {
      if (!(item.value instanceof AbortSignal)) throw new Error("launcher otlp fixture failed");
      out.signal = item.value;
    } else if (key === "deadlineAt") {
      if (!Number.isSafeInteger(item.value) || item.value > Date.now() + 30_000)
        throw new Error("launcher otlp fixture failed");
      out.deadlineAt = item.value;
    }
  }
  return Object.freeze(out);
}
function aborted(options: OtlpCooperativeOptions): boolean {
  const signalAborted =
    options.signal !== undefined &&
    (ABORTED_GETTER === undefined ? false : ABORTED_GETTER.call(options.signal) === true);
  return signalAborted || (options.deadlineAt !== undefined && Date.now() >= options.deadlineAt);
}
function watchAbort(options: OtlpCooperativeOptions, callback: () => void): () => void {
  if (options.signal === undefined) return () => undefined;
  EVENT_ADD.call(options.signal, "abort", callback, { once: true });
  return () => EVENT_REMOVE.call(options.signal as AbortSignal, "abort", callback);
}
function armDeadline(options: OtlpCooperativeOptions, callback: () => void): () => void {
  if (options.deadlineAt === undefined) return () => undefined;
  const timer = setTimeout(callback, Math.max(0, options.deadlineAt - Date.now()));
  timer.unref?.();
  return () => clearTimeout(timer);
}
async function listenServer(server: Server, options: OtlpCooperativeOptions, destroyOwned: () => void): Promise<void> {
  if (aborted(options)) throw new Error("launcher otlp fixture failed");
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const done = (error?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    };
    let cancelRequested = false;
    const closeBeforeReject = () => {
      destroyOwned();
      server.close((error) => {
        if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") done(error);
        else done(new Error("launcher otlp fixture failed"));
      });
    };
    const onAbort = () => {
      cancelRequested = true;
      destroyOwned();
      if (server.listening) closeBeforeReject();
    };
    const onError = (error: Error) => done(error);
    const timer =
      options.deadlineAt === undefined ? undefined : setTimeout(onAbort, Math.max(0, options.deadlineAt - Date.now()));
    timer?.unref?.();
    const cleanup = () => {
      server.off("error", onError);
      if (options.signal !== undefined) EVENT_REMOVE.call(options.signal, "abort", onAbort);
      if (timer) clearTimeout(timer);
    };
    if (options.signal !== undefined) EVENT_ADD.call(options.signal, "abort", onAbort, { once: true });
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      if (cancelRequested || aborted(options)) closeBeforeReject();
      else done();
    });
  });
}
async function closeServer(server: Server, destroyOwned: () => void): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
      else resolve();
    });
    destroyOwned();
  }).catch(() => {
    throw new Error("launcher otlp fixture failed");
  });
}
async function assertClosed(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = new Socket();
    socket.setTimeout(250, () => {
      socket.destroy();
      reject(new Error("launcher otlp fixture failed"));
    });
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error("launcher otlp fixture failed"));
    });
    socket.once("error", () => resolve());
    socket.connect(port, "127.0.0.1");
  });
}
