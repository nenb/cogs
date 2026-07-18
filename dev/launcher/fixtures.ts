import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Socket } from "node:net";

export type LocalFixtureSnapshot = Readonly<{
  ready: boolean;
  port: number;
  generation: number;
  inflight: number;
  total: number;
  counts: Readonly<Record<string, number>>;
}>;
export type LocalFixture = Readonly<{
  endpoint(): string;
  snapshot(): LocalFixtureSnapshot;
  reset(): void;
  close(): Promise<void>;
}>;

export async function startLocalFixtures(options: {
  credential: string;
  deadlineMs?: number;
  maxBytes?: number;
  maxInflight?: number;
  maxRecords?: number;
}): Promise<LocalFixture> {
  const o = snap(options),
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
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  }).catch(() => {
    throw fail();
  });
  const a = server.address();
  const port = typeof a === "object" && a ? a.port : 0;
  if (!Number.isSafeInteger(port) || port < 1) fail();
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
    close: () =>
      (closePromise ??= (async () => {
        closed = true;
        let t: NodeJS.Timeout | undefined;
        try {
          const closing = new Promise<void>((r) => server.close(() => r()));
          await new Promise((r) => setTimeout(r, 25));
          for (const s of sockets) s.destroy();
          await Promise.race([
            closing,
            new Promise((_, rej) => {
              t = setTimeout(() => rej(fail()), 500);
            }),
          ]);
          await new Promise((r) => setTimeout(r, 10));
          if (inflight !== 0 || sockets.size !== 0) fail();
          await closedPort(port);
        } finally {
          if (t) clearTimeout(t);
          credential = "";
          for (const k of Object.keys(counts)) delete counts[k];
          total = 0;
        }
      })()),
  });
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
}) {
  if (!v || typeof v !== "object" || Array.isArray(v) || Object.getPrototypeOf(v) !== Object.prototype) fail();
  const d = Object.getOwnPropertyDescriptors(v);
  for (const k of Reflect.ownKeys(d)) {
    if (typeof k !== "string" || !["credential", "deadlineMs", "maxBytes", "maxInflight", "maxRecords"].includes(k))
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
