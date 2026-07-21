import { randomBytes } from "node:crypto";

export type ApiOperation = "run" | "abort" | "state" | "status" | "entries" | "export" | "shutdown";
export type ApiEvent = Readonly<{ id: number; data: Readonly<Record<string, unknown>> }>;
export type ApiSeams = Readonly<{ fetch: typeof fetch; randomBytes: typeof randomBytes }>;
export type ApiClient = Readonly<{
  request(op: ApiOperation, input?: Readonly<Record<string, unknown>>, signal?: AbortSignal): Promise<unknown>;
  events(after: number | undefined, limit: number, signal?: AbortSignal): AsyncGenerator<ApiEvent>;
}>;

type Ctx = { ac: AbortController; deadline: number; done: () => void; wait: () => Promise<never> };
const routes: Record<ApiOperation, readonly [string, string, number]> = Object.freeze({
  run: ["POST", "/v1/input", 202],
  abort: ["POST", "/v1/abort", 202],
  state: ["GET", "/v1/state", 200],
  status: ["GET", "/v1/state", 200],
  entries: ["GET", "/v1/entries", 200],
  export: ["POST", "/v1/export", 200],
  shutdown: ["POST", "/v1/shutdown", 202],
});
const cursorRe = /^[A-Za-z0-9_-]{1,768}\.[A-Za-z0-9_-]{32,256}$/u;
const idRe = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const isoRe = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const runStates = new Set(["idle", "running", "settled", "aborting", "shutdown"]);
const lifecycles = new Set(["created", "starting", "ready", "draining", "stopped", "failed"]);
const replayGapCode = "COGS_LAUNCHER_API_REPLAY_GAP";
const eventKinds = new Set([
  "pi_event",
  "tool_start",
  "tool_update",
  "tool_end",
  "usage",
  "git_mapping",
  "checkpoint",
  "approval_required",
  "warning",
  "error",
  "run_settled",
  "run_aborted",
  "shutdown_ready",
]);

export function isReplayGapError(error: unknown): boolean {
  return error instanceof Error && (error as { code?: unknown }).code === replayGapCode;
}

export function createApiClient(options: {
  port: number;
  token: string;
  timeoutMs?: number;
  maxBytes?: number;
  seams?: ApiSeams;
}): ApiClient {
  try {
    return createApiClientChecked(options);
  } catch {
    throw new Error("launcher api failed");
  }
}
function createApiClientChecked(options: {
  port: number;
  token: string;
  timeoutMs?: number;
  maxBytes?: number;
  seams?: ApiSeams;
}): ApiClient {
  const o = opts(options);
  const base = `http://127.0.0.1:${o.port}`;
  const seams = o.seams ?? Object.freeze({ fetch: globalThis.fetch, randomBytes });
  const request = Object.freeze(
    async (op: ApiOperation, input: Readonly<Record<string, unknown>> = {}, signal?: AbortSignal) => {
      const ctx = context(o.timeoutMs, signal);
      try {
        const [method, path, status] = route(op);
        const payload = bodyFor(op, input, seams);
        const url = new URL(path, base);
        if (op === "entries") {
          url.searchParams.set("limit", String(payload.limit));
          if (payload.after) url.searchParams.set("after", String(payload.after));
        }
        const body = method === "GET" ? undefined : JSON.stringify(payload);
        if (body && Buffer.byteLength(body) > 16 * 1024) fail();
        const res = await fetchChecked(seams, url, method, status, o.token, body, o.maxBytes, ctx, "application/json");
        return validate(op, await jsonBody(res, o.maxBytes, ctx), payload);
      } catch {
        throw new Error("launcher api failed");
      } finally {
        ctx.done();
      }
    },
  );
  const events = Object.freeze(async function* (after = 0, limit: number, signal?: AbortSignal) {
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) fail();
    const ctx = context(o.timeoutMs, signal);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      const url = new URL("/v1/events", base);
      url.searchParams.set("after", String(after));
      const res = await fetchChecked(seams, url, "GET", 200, o.token, undefined, o.maxBytes, ctx, "text/event-stream");
      reader = res.body?.getReader();
      if (!reader) fail();
      let count = 0;
      for await (const event of sse(reader, o.maxBytes, ctx)) {
        yield event;
        count += 1;
        if (count >= limit) return;
      }
    } catch (error) {
      if (isReplayGapError(error)) throw error;
      throw new Error("launcher api failed");
    } finally {
      if (reader) await cancelReader(reader);
      try {
        reader?.releaseLock();
      } catch {
        // generic cleanup only
      }
      ctx.done();
    }
  });
  return Object.freeze({ request, events });
}

function replayGapError(): Error {
  const error = new Error("launcher api replay gap");
  Object.defineProperty(error, "code", { value: replayGapCode, enumerable: false });
  return error;
}

function context(timeoutMs: number, parent?: AbortSignal): Ctx {
  const ac = new AbortController();
  let settled = false;
  let timer!: NodeJS.Timeout;
  const wait = new Promise<never>((_, reject) => {
    const failNow = () => {
      if (settled) return;
      ac.abort();
      reject(new Error("launcher api failed"));
    };
    const abort = () => failNow();
    timer = setTimeout(failNow, timeoutMs);
    try {
      parent?.addEventListener("abort", abort, { once: true });
      if (parent?.aborted) failNow();
    } catch {
      failNow();
    }
    ac.signal.addEventListener("abort", () => {
      try {
        parent?.removeEventListener("abort", abort);
      } catch {
        // generic cleanup only
      }
    });
  });
  wait.catch(() => undefined);
  return {
    ac,
    deadline: Date.now() + timeoutMs,
    wait: () => wait,
    done: () => {
      settled = true;
      ac.abort();
      clearTimeout(timer);
    },
  };
}
async function fetchChecked(
  seams: ApiSeams,
  url: URL,
  method: string,
  status: number,
  token: string,
  body: string | undefined,
  maxBytes: number,
  ctx: Ctx,
  accept: string,
): Promise<Response> {
  let res: Response | undefined;
  try {
    const init: RequestInit = {
      method,
      redirect: "error",
      signal: ctx.ac.signal,
      headers: {
        authorization: `Bearer ${token}`,
        accept,
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    };
    if (body !== undefined) init.body = body;
    const fetchPromise = seams.fetch(url, init);
    fetchPromise.catch(() => undefined);
    res = await Promise.race([fetchPromise, ctx.wait()]);
    const d = Object.getOwnPropertyDescriptors(res);
    if (d.url?.get || d.redirected?.get || d.status?.get || d.headers?.get || d.body?.get) fail();
    const ct = res.headers.get("content-type")?.split(";")[0]?.trim();
    const len = res.headers.get("content-length");
    if (accept === "text/event-stream" && res.status === 409) throw replayGapError();
    if (
      res.url !== String(url) ||
      res.redirected ||
      res.status !== status ||
      ct !== accept ||
      res.headers.get("content-encoding") ||
      res.headers.get("cache-control") !== "no-store" ||
      (len !== null && (!/^\d+$/u.test(len) || Number(len) > maxBytes))
    )
      fail();
    return res;
  } catch (error) {
    if (res) await cancelBody(res);
    if (isReplayGapError(error)) throw error;
    throw new Error("launcher api failed");
  }
}
async function jsonBody(res: Response, max: number, ctx: Ctx): Promise<unknown> {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await bytes(res, max, ctx)));
  } catch {
    await cancelBody(res);
    throw new Error("launcher api failed");
  }
}
async function bytes(res: Response, max: number, ctx: Ctx): Promise<Buffer> {
  const reader = res.body?.getReader();
  if (!reader) fail();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (let count = 0; ; count += 1) {
      if (count > 1024) fail();
      const r = await read(reader, ctx);
      if (r.done) break;
      if (!(r.value instanceof Uint8Array)) fail();
      total += r.value.byteLength;
      if (total > max) fail();
      chunks.push(r.value);
    }
    return Buffer.concat(chunks, total);
  } catch {
    await cancelReader(reader);
    throw new Error("launcher api failed");
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // generic cleanup only
    }
  }
}
async function* sse(reader: ReadableStreamDefaultReader<Uint8Array>, max: number, ctx: Ctx): AsyncGenerator<ApiEvent> {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buf = "";
  let total = 0;
  for (let count = 0; ; count += 1) {
    if (count > 1024) fail();
    const r = await read(reader, ctx);
    if (r.done) break;
    if (!(r.value instanceof Uint8Array)) fail();
    total += r.value.byteLength;
    if (total > max) fail();
    buf += decoder.decode(r.value, { stream: true });
    for (;;) {
      const idx = buf.indexOf("\n\n");
      if (idx < 0) break;
      const event = oneEvent(buf.slice(0, idx));
      buf = buf.slice(idx + 2);
      yield event;
    }
  }
  decoder.decode();
  if (buf.length !== 0) fail();
}
async function read(reader: ReadableStreamDefaultReader<Uint8Array>, ctx: Ctx) {
  if (Date.now() >= ctx.deadline || ctx.ac.signal.aborted) fail();
  const readPromise = reader.read();
  readPromise.catch(() => undefined);
  return await Promise.race([readPromise, ctx.wait()]);
}
async function cancelBody(res: Response): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const body = res.body;
    const cancel = body?.cancel();
    if (cancel) cancel.catch(() => undefined);
    await Promise.race([
      cancel,
      new Promise((r) => {
        timer = setTimeout(r, 50);
      }),
    ]);
  } catch {
    // generic cleanup only
  } finally {
    if (timer) clearTimeout(timer);
  }
}
async function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const cancel = reader.cancel();
    cancel.catch(() => undefined);
    await Promise.race([
      cancel,
      new Promise((r) => {
        timer = setTimeout(r, 50);
      }),
    ]);
  } catch {
    // generic cleanup only
  } finally {
    if (timer) clearTimeout(timer);
  }
}
function oneEvent(raw: string): ApiEvent {
  try {
    return oneEventChecked(raw);
  } catch {
    throw new Error("launcher api failed");
  }
}
function oneEventChecked(raw: string): ApiEvent {
  const lines = raw.split("\n");
  if (
    lines.length !== 3 ||
    !/^id: [1-9]\d*$/u.test(lines[0] ?? "") ||
    lines[1] !== "event: cogs" ||
    !lines[2]?.startsWith("data: ")
  )
    fail();
  const idLine = lines[0] ?? "";
  const dataLine = lines[2] ?? "";
  const id = Number(idLine.slice(4));
  const data = exact(JSON.parse(dataLine.slice(6)));
  const keys = Object.keys(data).sort().join(",");
  if (
    keys !== "correlation_id,kind,payload,seq,session_id,timestamp,version" &&
    keys !== "correlation_id,kind,payload,request_id,seq,session_id,timestamp,version"
  )
    fail();
  if (data.version !== "cogs.event/v1alpha1" || data.seq !== id || !eventKinds.has(String(data.kind))) fail();
  if (!Number.isSafeInteger(id) || id < 1 || typeof data.timestamp !== "string" || !isoRe.test(data.timestamp)) fail();
  if (
    typeof data.session_id !== "string" ||
    !idRe.test(data.session_id) ||
    typeof data.correlation_id !== "string" ||
    !idRe.test(data.correlation_id)
  )
    fail();
  if (data.request_id !== undefined && (typeof data.request_id !== "string" || !idRe.test(data.request_id))) fail();
  const clean = { ...data, payload: jsonValue(data.payload) };
  return Object.freeze({ id, data: deepFreeze(clean) as Readonly<Record<string, unknown>> });
}
function bodyFor(op: ApiOperation, input: Readonly<Record<string, unknown>>, seams: ApiSeams): Record<string, unknown> {
  const v = exact(input);
  const keys = Object.keys(v).sort().join(",");
  if (op === "run")
    return keys === "content" &&
      typeof v.content === "string" &&
      v.content.length > 0 &&
      v.content.length <= 8192 &&
      Buffer.byteLength(v.content) <= 16 * 1024
      ? { request_id: rid(seams), type: "prompt", content: v.content }
      : fail();
  if (op === "abort" || op === "export") return keys === "" ? { request_id: rid(seams) } : fail();
  if (op === "shutdown") return keys === "" ? {} : fail();
  if (op === "entries") {
    if (keys !== "after,limit" && keys !== "limit") fail();
    if (!Number.isSafeInteger(v.limit) || (v.limit as number) < 1 || (v.limit as number) > 100) fail();
    if (v.after !== undefined && (typeof v.after !== "string" || v.after.length > 1024 || !cursorRe.test(v.after)))
      fail();
    return v;
  }
  return keys === "" ? v : fail();
}
function validate(op: ApiOperation, value: unknown, payload: Record<string, unknown>): unknown {
  const v = exact(value);
  const keys = Object.keys(v).sort().join(",");
  if (
    op === "run" &&
    keys === "accepted,correlation_id,duplicate,request_id,run_state,version" &&
    v.version === "cogs.input-acceptance/v1alpha1" &&
    v.accepted === true &&
    v.duplicate === false &&
    v.request_id === payload.request_id &&
    id(v.correlation_id) &&
    runStates.has(String(v.run_state))
  )
    return Object.freeze(v);
  if (
    op === "abort" &&
    keys === "aborted,request_id,run_state,version" &&
    v.version === "cogs.abort/v1alpha1" &&
    typeof v.aborted === "boolean" &&
    v.request_id === payload.request_id &&
    runStates.has(String(v.run_state))
  )
    return Object.freeze(v);
  if (
    (op === "state" || op === "status") &&
    keys === "closed,lifecycle,ready,run_state,usage,version" &&
    v.version === "cogs.state/v1alpha1" &&
    typeof v.ready === "boolean" &&
    typeof v.closed === "boolean" &&
    lifecycles.has(String(v.lifecycle)) &&
    runStates.has(String(v.run_state))
  )
    return deepFreeze({ ...v, usage: jsonValue(v.usage) });
  if (
    op === "entries" &&
    (keys === "entries,version" || keys === "entries,next,version") &&
    v.version === "cogs.entries/v1alpha1" &&
    Array.isArray(v.entries) &&
    v.entries.length <= 100 &&
    (v.next === undefined || (typeof v.next === "string" && v.next.length <= 1024 && cursorRe.test(v.next)))
  )
    return deepFreeze({ ...v, entries: jsonValue(v.entries) });
  if (
    op === "export" &&
    keys === "bundle,sensitive,version" &&
    v.version === "cogs.export-response/v1alpha1" &&
    v.sensitive === true
  )
    return deepFreeze({ ...v, bundle: jsonValue(v.bundle) });
  if (op === "shutdown" && keys === "accepted,version" && v.version === "cogs.shutdown/v1alpha1" && v.accepted === true)
    return Object.freeze(v);
  fail();
}
function route(op: ApiOperation): readonly [string, string, number] {
  return routes[op] ?? fail();
}
function opts(input: { port: number; token: string; timeoutMs?: number; maxBytes?: number; seams?: ApiSeams }) {
  const v = exact(input);
  if (Object.keys(v).some((k) => !["port", "token", "timeoutMs", "maxBytes", "seams"].includes(k))) fail();
  const port = v.port,
    token = v.token,
    timeoutMs = v.timeoutMs ?? 30_000,
    maxBytes = v.maxBytes ?? 128 * 1024;
  if (
    typeof port !== "number" ||
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65535 ||
    typeof token !== "string" ||
    Buffer.byteLength(token) < 32 ||
    Buffer.byteLength(token) > 4096 ||
    hasControl(token)
  )
    fail();
  if (typeof timeoutMs !== "number" || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 900_000) fail();
  if (typeof maxBytes !== "number" || !Number.isSafeInteger(maxBytes) || maxBytes < 128 || maxBytes > 1024 * 1024)
    fail();
  const seams = v.seams as ApiSeams | undefined;
  if (seams !== undefined) {
    const s = exact(seams);
    if (
      !Object.isFrozen(seams) ||
      Object.keys(s).sort().join(",") !== "fetch,randomBytes" ||
      typeof s.fetch !== "function" ||
      typeof s.randomBytes !== "function" ||
      !Object.isFrozen(s.fetch) ||
      !Object.isFrozen(s.randomBytes)
    )
      fail();
  }
  return { port, token, timeoutMs, maxBytes, seams };
}
function rid(seams: ApiSeams): string {
  const raw = seams.randomBytes(16);
  if (!Buffer.isBuffer(raw) || raw.length !== 16 || raw.every((x) => x === 0)) fail();
  const b = Buffer.from(raw);
  return `req-${b.toString("base64url")}`;
}
function id(value: unknown): boolean {
  return typeof value === "string" && idRe.test(value);
}
function exact(value: unknown): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    fail();
  const out: Record<string, unknown> = {};
  for (const [key, d] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (
      key === "__proto__" ||
      key === "prototype" ||
      key === "constructor" ||
      !d ||
      !("value" in d) ||
      d.enumerable !== true
    )
      fail();
    out[key] = d.value;
  }
  return out;
}
function jsonValue(value: unknown, seen = new WeakSet<object>(), depth = 0, count = { n: 0 }): unknown {
  count.n += 1;
  if (depth > 32 || count.n > 4096) fail();
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : fail();
  if (!value || typeof value !== "object" || seen.has(value)) fail();
  seen.add(value);
  try {
    if (Array.isArray(value)) return jsonArray(value, seen, depth, count);
    const out = Object.create(null) as Record<string, unknown>;
    const source = exact(value);
    for (const key of Object.keys(source)) {
      if (key === "prototype" || key === "constructor") fail();
      out[key] = jsonValue(source[key], seen, depth + 1, count);
    }
    return Object.freeze(out);
  } finally {
    seen.delete(value);
  }
}
function jsonArray(value: unknown[], seen: WeakSet<object>, depth: number, count: { n: number }): readonly unknown[] {
  if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0) fail();
  const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > 1000) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter((key) => key !== "length");
  if (keys.length !== length || keys.some((key) => !/^\d+$/u.test(key) || Number(key) >= length)) fail();
  const out: unknown[] = [];
  for (let i = 0; i < length; i += 1) {
    const d = descriptors[String(i)];
    if (!d || !("value" in d) || d.enumerable !== true) fail();
    out.push(jsonValue(d.value, seen, depth + 1, count));
  }
  return Object.freeze(out);
}
function deepFreeze(value: unknown): unknown {
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return Object.freeze(value);
  }
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}
function hasControl(value: string): boolean {
  for (const c of value) if ((c.codePointAt(0) ?? 0) < 0x20 || c === "\u007f") return true;
  return false;
}
function fail(): never {
  throw new Error("launcher api failed");
}
