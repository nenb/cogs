import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Socket } from "node:net";

const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const EVENT_ADD = EventTarget.prototype.addEventListener;
const EVENT_REMOVE = EventTarget.prototype.removeEventListener;

export type LocalFixtureSnapshot = Readonly<{
  ready: boolean;
  port: number;
  generation: number;
  inflight: number;
  total: number;
  counts: Readonly<Record<string, number>>;
}>;
export type FixtureCooperativeOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;
export type LocalFixture = Readonly<{
  endpoint(): string;
  snapshot(): LocalFixtureSnapshot;
  reset(): void;
  close(options?: FixtureCooperativeOptions): Promise<void>;
}>;

export async function startLocalFixtures(options: {
  credential: string;
  deadlineMs?: number;
  maxBytes?: number;
  maxInflight?: number;
  maxRecords?: number;
  signal?: AbortSignal;
  deadlineAt?: number;
}): Promise<LocalFixture> {
  const o = snap(options),
    cooperative = cooperativeOptions(o, true),
    deadlineMs = int(o.deadlineMs ?? 1000, 50, 10000),
    maxBytes = int(o.maxBytes ?? 16384, 0, 65536),
    maxInflight = int(o.maxInflight ?? 8, 1, 64),
    maxRecords = int(o.maxRecords ?? 4096, 1, 4096);
  let credential = text(o.credential, 256),
    closed = false,
    generation = 0,
    inflight = 0,
    total = 0;
  const counts: Record<string, number> = {};
  const sockets = new Set<Socket>();
  let closePromise: Promise<void> | undefined;
  const server = createServer((req, res) => void handle(req, res).catch(() => reject(req, res, 400)));
  server.maxConnections = maxInflight;
  server.on("connection", (s) => {
    sockets.add(s);
    s.setTimeout(deadlineMs, () => s.destroy());
    s.once("close", () => sockets.delete(s));
  });
  let port: number;
  try {
    await listenServer(server, cooperative, () => destroyOwnedConnections());
    if (aborted(cooperative)) fail();
    const a = server.address();
    port = typeof a === "object" && a ? a.port : 0;
    if (!Number.isSafeInteger(port) || port < 1) fail();
  } catch {
    await closeServer(server, () => destroyOwnedConnections());
    throw fail();
  }
  async function handle(req: IncomingMessage, res: ServerResponse) {
    if (closed || inflight >= maxInflight) return reject(req, res, 503);
    const path = String(req.url ?? ""),
      method = String(req.method ?? "");
    if (
      badHeaders(req, maxBytes) ||
      path.includes("?") ||
      !["GET", "POST"].includes(method) ||
      !["/health", "/allowed", "/credential"].includes(path) ||
      (path === "/health" && method !== "GET") ||
      (method === "GET" &&
        (req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined))
    )
      return reject(req, res, 400);
    inflight++;
    const timer = setTimeout(() => req.destroy(), deadlineMs);
    try {
      if (method === "POST") await drainBody(req, maxBytes, deadlineMs);
      const auth = req.headers.authorization;
      const status =
        path === "/credential" && (typeof auth !== "string" || !safeEq(auth, `Bearer ${credential}`)) ? 401 : 200;
      if (total + 1 > maxRecords) return reject(req, res, 429);
      total++;
      counts[`${method} ${path} ${status}`] = (counts[`${method} ${path} ${status}`] ?? 0) + 1;
      return ok(res, status, status === 200 ? { ok: true } : undefined);
    } catch {
      reject(req, res, 400);
    } finally {
      clearTimeout(timer);
      inflight--;
    }
  }
  return Object.freeze({
    endpoint: () => `http://127.0.0.1:${port}`,
    snapshot: () =>
      Object.freeze({ ready: !closed, port, generation, inflight, total, counts: Object.freeze({ ...counts }) }),
    reset: () => {
      if (closed || inflight !== 0) fail();
      for (const k of Object.keys(counts)) delete counts[k];
      total = 0;
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
            await new Promise((r) => setTimeout(r, 0));
            if (server.listening || inflight !== 0 || sockets.size !== 0) fail();
            await closedPort(port);
          } finally {
            cleanupAbort();
            deadlineTimer();
            credential = "";
            for (const k of Object.keys(counts)) delete counts[k];
            total = 0;
          }
        })();
      }
      return closePromise;
    },
  });
  function destroyOwnedConnections(): void {
    for (const s of sockets) s.destroy();
    server.closeAllConnections?.();
  }
}
async function drainBody(req: IncomingMessage, max: number, deadline: number) {
  let total = 0,
    chunks = 0;
  const start = Date.now();
  for await (const c of req) {
    if (Date.now() - start > deadline || ++chunks > 1024) fail();
    const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
    total += b.length;
    if (total > max) fail();
  }
}
function badHeaders(req: IncomingMessage, max: number) {
  const len = req.headers["content-length"];
  const names = req.rawHeaders.filter((_, i) => i % 2 === 0).map((x) => x.toLowerCase());
  const seen = new Set<string>();
  for (const n of names)
    if (
      ["authorization", "content-encoding", "content-length", "content-type", "expect", "transfer-encoding"].includes(n)
    ) {
      if (seen.has(n)) return true;
      seen.add(n);
    }
  return (
    req.headers["content-encoding"] !== undefined ||
    req.headers.expect !== undefined ||
    (req.method === "POST" &&
      (req.headers["content-type"] ?? "").toString().split(";", 1)[0]?.trim().toLowerCase() !== "application/json") ||
    (req.method === "GET" && req.headers["transfer-encoding"] !== undefined) ||
    Array.isArray(len) ||
    (len !== undefined && (!/^\d+$/u.test(len) || Number(len) > max))
  );
}
function ok(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader("cache-control", "no-store");
  if (body) {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(body));
  } else res.end("");
}
function reject(req: IncomingMessage, res: ServerResponse, status: number) {
  res.statusCode = status;
  res.setHeader("cache-control", "no-store");
  res.end("");
  req.resume();
  setTimeout(() => req.destroy(), 25).unref();
}
function safeEq(a: string, b: string) {
  const ab = Buffer.from(a),
    bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
function snap(v: {
  credential: string;
  deadlineMs?: number;
  maxBytes?: number;
  maxInflight?: number;
  maxRecords?: number;
  signal?: AbortSignal;
  deadlineAt?: number;
}) {
  if (!v || typeof v !== "object" || Array.isArray(v) || Object.getPrototypeOf(v) !== Object.prototype) fail();
  const d = Object.getOwnPropertyDescriptors(v);
  for (const k of Reflect.ownKeys(d)) {
    if (
      typeof k !== "string" ||
      !["credential", "deadlineMs", "maxBytes", "maxInflight", "maxRecords", "signal", "deadlineAt"].includes(k)
    )
      fail();
    const x = d[k];
    if (!x || !("value" in x) || x.enumerable !== true) fail();
  }
  return v;
}
function text(v: unknown, max: number) {
  if (typeof v !== "string" || v.length < 8 || v.length > max) fail();
  return v;
}
function int(v: number, min: number, max: number) {
  if (!Number.isSafeInteger(v) || v < min || v > max) fail();
  return v;
}
function cooperativeOptions(value: unknown, startOptions: boolean): FixtureCooperativeOptions {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  const d = Object.getOwnPropertyDescriptors(value);
  const out: { signal?: AbortSignal; deadlineAt?: number } = {};
  const allowed = startOptions
    ? ["credential", "deadlineMs", "maxBytes", "maxInflight", "maxRecords", "signal", "deadlineAt"]
    : ["signal", "deadlineAt"];
  for (const key of Reflect.ownKeys(d)) {
    if (typeof key !== "string" || !allowed.includes(key)) fail();
    const item = d[key];
    if (!item || !("value" in item) || item.enumerable !== true) fail();
    if (key === "signal") {
      if (!(item.value instanceof AbortSignal)) fail();
      out.signal = item.value;
    } else if (key === "deadlineAt") {
      if (!Number.isSafeInteger(item.value) || item.value > Date.now() + 10_000) fail();
      out.deadlineAt = item.value;
    }
  }
  return Object.freeze(out);
}
function aborted(options: FixtureCooperativeOptions): boolean {
  const signalAborted =
    options.signal !== undefined &&
    (ABORTED_GETTER === undefined ? false : ABORTED_GETTER.call(options.signal) === true);
  return signalAborted || (options.deadlineAt !== undefined && Date.now() >= options.deadlineAt);
}
function watchAbort(options: FixtureCooperativeOptions, callback: () => void): () => void {
  if (options.signal === undefined) return () => undefined;
  EVENT_ADD.call(options.signal, "abort", callback, { once: true });
  return () => EVENT_REMOVE.call(options.signal as AbortSignal, "abort", callback);
}
function armDeadline(options: FixtureCooperativeOptions, callback: () => void): () => void {
  if (options.deadlineAt === undefined) return () => undefined;
  const timer = setTimeout(callback, Math.max(0, options.deadlineAt - Date.now()));
  timer.unref?.();
  return () => clearTimeout(timer);
}
async function listenServer(
  server: Server,
  options: FixtureCooperativeOptions,
  destroyOwned: () => void,
): Promise<void> {
  if (aborted(options)) fail();
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
        else done(new Error("launcher fixture failed"));
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
  }).catch(() => fail());
}
async function closedPort(port: number) {
  await new Promise<void>((res, rej) => {
    const s = new Socket();
    const t = setTimeout(() => {
      s.destroy();
      rej(fail());
    }, 250);
    s.once("connect", () => {
      clearTimeout(t);
      s.destroy();
      rej(fail());
    });
    s.once("error", () => {
      clearTimeout(t);
      res();
    });
    s.connect(port, "127.0.0.1");
  });
}
function fail(): never {
  throw new Error("launcher fixture failed");
}
