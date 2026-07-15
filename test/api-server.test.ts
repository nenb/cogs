import assert from "node:assert/strict";
import { request as httpRequest, ServerResponse } from "node:http";
import test from "node:test";
import {
  type ApiServer,
  createApiServer,
  type ExportPort,
  type HistoryPort,
  type RunState,
  type SessionPort,
} from "../src/api/server.ts";

type Lifecycle = {
  ready: boolean;
  state: string;
  shutdowns: number;
  requestShutdown: (reason?: string) => Promise<void>;
};

function lifecycle(): Lifecycle {
  return {
    ready: true,
    state: "ready",
    shutdowns: 0,
    requestShutdown: async function () {
      this.ready = false;
      this.state = "stopped";
      this.shutdowns += 1;
    },
  };
}

function ports(
  overrides: Partial<{
    session: Partial<SessionPort>;
    history: Partial<HistoryPort>;
    exporter: Partial<ExportPort>;
  }> = {},
) {
  let runState: RunState = "idle";
  const inputs: string[] = [];
  const session: SessionPort = {
    input: async (input) => {
      inputs.push(`${input.kind}:${input.content}:${input.correlationId}`);
      runState = "running";
      return runState;
    },
    abort: async () => {
      runState = "aborting";
      return { aborted: true, runState };
    },
    state: async () => ({ runState }),
    ...overrides.session,
  };
  const history: HistoryPort = {
    entries: async ({ after, limit }) => ({ entries: [{ after: after ?? "start", limit }], nextAfter: "entry-2" }),
    ...overrides.history,
  };
  const exporter: ExportPort = {
    createExport: async ({ requestId }) => ({ requestId, files: [] }),
    ...overrides.exporter,
  };
  return {
    session,
    history,
    exporter,
    inputs,
    setRunState: (state: RunState) => {
      runState = state;
    },
  };
}

async function withServer<T>(
  fn: (ctx: { base: string; api: ApiServer; life: Lifecycle; p: ReturnType<typeof ports> }) => Promise<T>,
  opts: {
    maxRequestBytes?: number;
    maxResponseBytes?: number;
    eventReplayCapacity?: number;
    requestTimeoutMs?: number;
    portTimeoutMs?: number;
    maxEventBytes?: number;
    duplicateCapacity?: number;
  } = {},
): Promise<T> {
  const life = lifecycle();
  const p = ports();
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
    ...opts,
  });
  const { port } = await api.listen();
  try {
    return await fn({ base: `http://127.0.0.1:${port}`, api, life, p });
  } finally {
    await api.close();
  }
}

async function json(base: string, path: string, init: RequestInit = {}) {
  return fetch(`${base}${path}`, {
    ...init,
    headers: {
      authorization: "Bearer worker-secret-0123456789abcdefghi",
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

async function body(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

test("auth, route, method, and content-type handling are strict and redacted", async () => {
  await withServer(async ({ base }) => {
    assert.equal((await fetch(`${base}/health/live`)).status, 200);
    assert.equal((await fetch(`${base}/v1/state`)).status, 401);
    assert.equal((await fetch(`${base}/v1/state`, { headers: { authorization: "Bearer wrong" } })).status, 401);
    assert.equal((await json(base, "/v1/input", { method: "GET" })).status, 405);
    assert.equal((await json(base, "/v1/input/", { method: "POST", body: "{}" })).status, 404);
    const badType = await fetch(`${base}/v1/input`, {
      method: "POST",
      headers: { authorization: "Bearer worker-secret-0123456789abcdefghi", "content-type": "text/plain" },
      body: "{}",
    });
    assert.equal(badType.status, 415);
    assert.doesNotMatch(await badType.text(), /worker-secret-0123456789abcdefghi|prompt|users\//);
  });
});

test("input accepts legal transitions, rejects malformed and illegal combinations, and preserves correlation", async () => {
  await withServer(async ({ base, p }) => {
    const malformed = await json(base, "/v1/input", {
      method: "POST",
      headers: { "x-cogs-correlation-id": "corr-1" },
      body: JSON.stringify({ request_id: "r1", type: "prompt", content: "hi", extra: true }),
    });
    assert.equal(malformed.status, 400);
    p.setRunState("idle");
    const steer = await json(base, "/v1/input", {
      method: "POST",
      body: JSON.stringify({ request_id: "r2", type: "steer", content: "go" }),
    });
    assert.equal(steer.status, 409);
    const accepted = await json(base, "/v1/input", {
      method: "POST",
      headers: { "x-cogs-correlation-id": "corr-ok" },
      body: JSON.stringify({ request_id: "r3", type: "prompt", content: "hello" }),
    });
    assert.equal(accepted.status, 202);
    assert.equal(accepted.headers.get("x-cogs-correlation-id"), "corr-ok");
    assert.equal((await body(accepted)).correlation_id, "corr-ok");
    assert.deepEqual(p.inputs, ["prompt:hello:corr-ok"]);
  });
});

test("bounded duplicate suppression coalesces concurrent duplicate input", async () => {
  let release: (() => void) | undefined;
  let calls = 0;
  const life = lifecycle();
  const p = ports({
    session: {
      input: async () => {
        calls += 1;
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return "running";
      },
    },
  });
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  const { port } = await api.listen();
  const base = `http://127.0.0.1:${port}`;
  try {
    const payload = JSON.stringify({ request_id: "dup", type: "prompt", content: "same" });
    const first = json(base, "/v1/input", { method: "POST", body: payload });
    for (let i = 0; i < 20 && release === undefined; i += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    const second = json(base, "/v1/input", { method: "POST", body: payload });
    assert.ok(release);
    release();
    const [a, b] = await Promise.all([first, second]);
    assert.equal(a.status, 202);
    assert.equal(b.status, 202);
    assert.equal(calls, 1);
    assert.equal((await body(a)).duplicate, false);
    assert.equal((await body(b)).duplicate, true);
  } finally {
    await api.close();
  }
});

test("abort and shutdown are idempotent and fail closed", async () => {
  await withServer(async ({ base, p, life }) => {
    p.setRunState("idle");
    const idleAbort = await json(base, "/v1/abort", { method: "POST", body: JSON.stringify({ request_id: "a1" }) });
    assert.equal((await body(idleAbort)).aborted, false);
    p.setRunState("running");
    const activeAbort = await json(base, "/v1/abort", { method: "POST", body: JSON.stringify({ request_id: "a2" }) });
    assert.equal((await body(activeAbort)).aborted, true);
    const shutdown1 = await json(base, "/v1/shutdown", { method: "POST", body: "{}" });
    const shutdown2 = await json(base, "/v1/shutdown", { method: "POST", body: "{}" });
    assert.equal(shutdown1.status, 202);
    assert.equal(shutdown2.status, 202);
    assert.equal(life.ready, false);
  });
});

test("SSE sequence supports replay and rejects replay gaps while slow consumers are cleaned up", async () => {
  await withServer(
    async ({ base, api }) => {
      api.publish({ type: "one" });
      api.publish({ type: "two", payload: { ok: true } });
      const replay = await fetch(`${base}/v1/events?after=0`, {
        headers: { authorization: "Bearer worker-secret-0123456789abcdefghi" },
      });
      assert.equal(replay.status, 200);
      const reader = replay.body?.getReader();
      assert.ok(reader);
      const chunks: string[] = [];
      for (;;) {
        const read = await reader.read();
        if (read.done) break;
        chunks.push(Buffer.from(read.value).toString("utf8"));
        if (chunks.join("").includes("id: 2")) break;
      }
      await reader.cancel();
      const text = chunks.join("");
      assert.match(text, /id: 1/);
      assert.match(text, /id: 2/);
    },
    { eventReplayCapacity: 2 },
  );
  await withServer(
    async ({ base, api }) => {
      api.publish({ type: "one" });
      api.publish({ type: "two" });
      api.publish({ type: "three" });
      const gap = await fetch(`${base}/v1/events?after=0`, {
        headers: { authorization: "Bearer worker-secret-0123456789abcdefghi" },
      });
      assert.equal(gap.status, 409);
    },
    { eventReplayCapacity: 1 },
  );
});

test("entries use authenticated opaque cursors and reject tampering", async () => {
  await withServer(async ({ base }) => {
    const first = await json(base, "/v1/entries?limit=2", {
      method: "GET",
      headers: { "content-type": "application/json" },
    });
    assert.equal(first.status, 200);
    const page = await body(first);
    assert.equal(Array.isArray(page.entries), true);
    const next = String(page.next);
    assert.match(next, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const second = await json(base, `/v1/entries?after=${encodeURIComponent(next)}&limit=2`, { method: "GET" });
    assert.equal(second.status, 200);
    const bad = await json(base, `/v1/entries?after=${encodeURIComponent(`${next}x`)}&limit=2`, { method: "GET" });
    assert.equal(bad.status, 400);
  });
});

test("export is authenticated API only and response overflow is bounded", async () => {
  await withServer(async ({ base }) => {
    const exported = await json(base, "/v1/export", { method: "POST", body: JSON.stringify({ request_id: "x1" }) });
    assert.equal(exported.status, 200);
    assert.equal((await body(exported)).sensitive, true);
  });
  const life = lifecycle();
  const p = ports({ exporter: { createExport: async () => ({ huge: "x".repeat(1024) }) } });
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
    maxResponseBytes: 128,
  });
  const { port } = await api.listen();
  try {
    const overflow = await json(`http://127.0.0.1:${port}`, "/v1/export", {
      method: "POST",
      body: JSON.stringify({ request_id: "x2" }),
    });
    assert.equal(overflow.status, 500);
    assert.equal((await body(overflow)).error, "response_too_large");
  } finally {
    await api.close();
  }
});

test("malformed, oversized, and slow request bodies are rejected", async () => {
  await withServer(
    async ({ base }) => {
      assert.equal((await json(base, "/v1/input", { method: "POST", body: "{" })).status, 400);
      assert.equal(
        (
          await json(base, "/v1/input", {
            method: "POST",
            body: JSON.stringify({ request_id: "r", type: "prompt", content: "x".repeat(20_000) }),
          })
        ).status,
        413,
      );
    },
    { maxRequestBytes: 256 },
  );

  const life = lifecycle();
  const p = ports();
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
    requestTimeoutMs: 20,
  });
  const { port } = await api.listen();
  try {
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/v1/input",
          method: "POST",
          headers: { authorization: "Bearer worker-secret-0123456789abcdefghi", "content-type": "application/json" },
        },
        (res) => {
          resolve(res.statusCode ?? 0);
          res.resume();
        },
      );
      req.on("error", reject);
      req.write("{");
    });
    assert.equal(status, 408);
  } finally {
    await api.close();
  }
});

test("readiness loss gates dependency-requiring operations", async () => {
  await withServer(async ({ base, life }) => {
    life.ready = false;
    assert.equal(
      (
        await json(base, "/v1/input", {
          method: "POST",
          body: JSON.stringify({ request_id: "nr1", type: "prompt", content: "x" }),
        })
      ).status,
      503,
    );
    assert.equal(
      (await json(base, "/v1/export", { method: "POST", body: JSON.stringify({ request_id: "nr2" }) })).status,
      503,
    );
    assert.equal((await json(base, "/v1/entries", { method: "GET" })).status, 503);
    assert.equal((await json(base, "/v1/state", { method: "GET" })).status, 503);
    assert.equal((await json(base, "/v1/shutdown", { method: "POST", body: "{}" })).status, 202);
  });
});

test("duplicate id mismatch and pending duplicate flood fail boundedly", async () => {
  let release: (() => void) | undefined;
  const life = lifecycle();
  const p = ports({
    session: {
      input: async () => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return "running";
      },
    },
  });
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
    duplicateCapacity: 1,
  });
  const { port } = await api.listen();
  const base = `http://127.0.0.1:${port}`;
  try {
    const first = json(base, "/v1/input", {
      method: "POST",
      body: JSON.stringify({ request_id: "same", type: "prompt", content: "one" }),
    });
    for (let i = 0; i < 20 && release === undefined; i += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(
      (
        await json(base, "/v1/input", {
          method: "POST",
          body: JSON.stringify({ request_id: "same", type: "prompt", content: "two" }),
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await json(base, "/v1/input", {
          method: "POST",
          body: JSON.stringify({ request_id: "other", type: "prompt", content: "x" }),
        })
      ).status,
      429,
    );
    assert.ok(release);
    release();
    assert.equal((await first).status, 202);
  } finally {
    await api.close();
  }
});

test("concurrent distinct prompts are serialized and abort/shutdown ports are idempotent", async () => {
  const order: string[] = [];
  let abortCalls = 0;
  const life = lifecycle();
  const p = ports({
    session: {
      input: async ({ content }) => {
        order.push(`start:${content}`);
        await new Promise((resolve) => setTimeout(resolve, content === "one" ? 25 : 0));
        order.push(`end:${content}`);
        return "running";
      },
      abort: async () => {
        abortCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return { aborted: true, runState: "aborting" };
      },
      state: async () => ({ runState: "running" }),
    },
  });
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  const { port } = await api.listen();
  const base = `http://127.0.0.1:${port}`;
  try {
    const a = json(base, "/v1/input", {
      method: "POST",
      body: JSON.stringify({ request_id: "d1", type: "steer", content: "one" }),
    });
    const b = json(base, "/v1/input", {
      method: "POST",
      body: JSON.stringify({ request_id: "d2", type: "steer", content: "two" }),
    });
    assert.equal((await a).status, 202);
    assert.equal((await b).status, 202);
    assert.deepEqual(order, ["start:one", "end:one", "start:two", "end:two"]);
    const aborts = await Promise.all([
      json(base, "/v1/abort", { method: "POST", body: JSON.stringify({ request_id: "a1" }) }),
      json(base, "/v1/abort", { method: "POST", body: JSON.stringify({ request_id: "a2" }) }),
    ]);
    assert.deepEqual(
      aborts.map((r) => r.status),
      [202, 202],
    );
    assert.equal(abortCalls, 1);
    const shutdowns = await Promise.all([
      json(base, "/v1/shutdown", { method: "POST", body: "{}" }),
      json(base, "/v1/shutdown", { method: "POST", body: "{}" }),
    ]);
    assert.deepEqual(
      shutdowns.map((r) => r.status),
      [202, 202],
    );
    assert.equal(life.shutdowns, 1);
  } finally {
    await api.close();
  }
});

test("query/body smuggling, malformed cursors, and hanging ports fail closed", async () => {
  await withServer(async ({ base }) => {
    assert.equal((await json(base, "/v1/entries?limit=1&limit=2", { method: "GET" })).status, 400);
    assert.equal((await json(base, "/v1/state?x=1", { method: "GET" })).status, 400);
    const getBodyStatus = await new Promise<number>((resolve, reject) => {
      const url = new URL(base);
      const req = httpRequest(
        {
          host: url.hostname,
          port: Number(url.port),
          path: "/v1/state",
          method: "GET",
          headers: { authorization: "Bearer worker-secret-0123456789abcdefghi", "content-length": "2" },
        },
        (res) => {
          resolve(res.statusCode ?? 0);
          res.resume();
        },
      );
      req.on("error", reject);
      req.write("{}");
      req.end();
    });
    assert.equal(getBodyStatus, 400);
    assert.equal(
      (await json(base, "/v1/shutdown", { method: "POST", body: JSON.stringify({ extra: true }) })).status,
      400,
    );
    assert.equal((await json(base, "/v1/entries?after=not-a-cursor", { method: "GET" })).status, 400);
  });
  const life = lifecycle();
  const p = ports({ session: { state: async () => new Promise(() => undefined) } });
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
    portTimeoutMs: 20,
  });
  const { port } = await api.listen();
  try {
    assert.equal((await json(`http://127.0.0.1:${port}`, "/v1/state", { method: "GET" })).status, 504);
  } finally {
    await api.close();
  }
});

test("SSE rejects malformed or oversized events and handles disconnect cleanup", async () => {
  await withServer(
    async ({ base, api }) => {
      assert.equal(api.publish({ type: "ok", payload: { seq: 99, version: "evil" } }), true);
      assert.equal(api.publish({ type: "bad", seq: 1 } as never), false);
      const stream = await fetch(`${base}/v1/events?after=0`, {
        headers: { authorization: "Bearer worker-secret-0123456789abcdefghi" },
      });
      assert.equal(stream.status, 200);
      await stream.body?.cancel();
      assert.equal(api.publish({ type: "after-disconnect" }), true);
    },
    { maxEventBytes: 256 },
  );
  await withServer(
    async ({ api }) => {
      assert.equal(api.publish({ type: "too-big", payload: { data: "x".repeat(512) } }), false);
    },
    { maxEventBytes: 128 },
  );
});

test("duplicate cache is LRU for settled entries and refreshes exact duplicate hits", async () => {
  await withServer(
    async ({ base, p }) => {
      const submit = async (request_id: string, content: string) => {
        p.setRunState("idle");
        return body(
          await json(base, "/v1/input", {
            method: "POST",
            body: JSON.stringify({ request_id, type: "prompt", content }),
          }),
        );
      };
      assert.equal((await submit("lru-a", "a")).duplicate, false);
      assert.equal((await submit("lru-b", "b")).duplicate, false);
      assert.equal((await submit("lru-a", "a")).duplicate, true);
      assert.equal((await submit("lru-c", "c")).duplicate, false);
      assert.equal((await submit("lru-a", "a")).duplicate, true);
      assert.equal((await submit("lru-b", "b")).duplicate, false);
    },
    { duplicateCapacity: 2 },
  );
});

test("configuration rejects unsafe bearer, session, capacity, and size options", async () => {
  const life = lifecycle();
  const p = ports();
  const base = {
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "x".repeat(32),
    sessionId: "session-1",
  };
  assert.throws(() => createApiServer({ ...base, bearerToken: "short" }), /bearer/);
  assert.throws(() => createApiServer({ ...base, bearerToken: `${"x".repeat(31)}\n` }), /bearer/);
  assert.throws(() => createApiServer({ ...base, bearerToken: "x".repeat(4097) }), /bearer/);
  assert.throws(() => createApiServer({ ...base, sessionId: "../other" }), /session/);
  assert.throws(() => createApiServer({ ...base, duplicateCapacity: 0 }), /duplicateCapacity/);
  assert.throws(() => createApiServer({ ...base, eventReplayCapacity: 0 }), /eventReplayCapacity/);
  assert.throws(() => createApiServer({ ...base, maxResponseBytes: 1 }), /maxResponseBytes/);
  assert.throws(() => createApiServer({ ...base, requestTimeoutMs: Number.POSITIVE_INFINITY }), /requestTimeoutMs/);
});

test("not-ready admission drains slow bodies without dangling sockets", async () => {
  const life = lifecycle();
  life.ready = false;
  const p = ports();
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  const { port } = await api.listen();
  try {
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/v1/input",
          method: "POST",
          headers: {
            authorization: "Bearer worker-secret-0123456789abcdefghi",
            "content-type": "application/json",
            "content-length": "100000",
          },
        },
        (res) => {
          resolve(res.statusCode ?? 0);
          res.resume();
        },
      );
      req.on("error", reject);
      req.write('{"request_id":"slow"');
    });
    assert.equal(status, 503);
    assert.equal((await json(`http://127.0.0.1:${port}`, "/health/live", { method: "GET" })).status, 200);
  } finally {
    await api.close();
  }
});

test("port timeout poisons readiness, shuts down once, and ignores late noncooperative completion", async () => {
  let inputCalls = 0;
  let lateMutation = "before";
  const life = lifecycle();
  const p = ports({
    session: {
      input: async () => {
        inputCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        lateMutation = "after";
        return "running";
      },
    },
  });
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
    portTimeoutMs: 10,
  });
  const { port } = await api.listen();
  const base = `http://127.0.0.1:${port}`;
  try {
    const timedOut = await json(base, "/v1/input", {
      method: "POST",
      body: JSON.stringify({ request_id: "t1", type: "prompt", content: "timeout" }),
    });
    assert.equal(timedOut.status, 504);
    assert.equal(life.shutdowns, 1);
    assert.equal((await json(base, "/health/ready", { method: "GET" })).status, 503);
    assert.equal(
      (await json(base, "/v1/export", { method: "POST", body: JSON.stringify({ request_id: "x" }) })).status,
      503,
    );
    await new Promise((resolve) => setTimeout(resolve, 70));
    assert.equal(lateMutation, "after");
    assert.equal(inputCalls, 1);
    assert.equal(life.shutdowns, 1);
    assert.equal((await json(base, "/v1/entries", { method: "GET" })).status, 503);
  } finally {
    await api.close();
  }
});

test("publish validates payload graph and disconnects actual backpressure consumers", async () => {
  await withServer(async ({ api }) => {
    assert.equal(api.publish({ type: "nan", payload: Number.NaN }), false);
    assert.equal(api.publish({ type: "bigint", payload: 1n as never }), false);
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    assert.equal(api.publish({ type: "cycle", payload: cycle as never }), false);
    const accessor = Object.create(null, { value: { get: () => "secret", enumerable: true } });
    assert.equal(api.publish({ type: "accessor", payload: accessor }), false);
    assert.equal(api.publish({ type: "ok", payload: { nested: [1, true, null] } }), true);
  });

  const originalWrite = ServerResponse.prototype.write;
  let sawBackpressureWrite = false;
  try {
    ServerResponse.prototype.write = function patchedWrite(
      this: ServerResponse,
      chunk: unknown,
      ...args: unknown[]
    ): boolean {
      if (typeof chunk === "string" && chunk.includes("backpressure")) {
        sawBackpressureWrite = true;
        return false;
      }
      return Reflect.apply(originalWrite, this, [chunk, ...args]) as boolean;
    };
    await withServer(async ({ base, api }) => {
      void fetch(`${base}/v1/events`, {
        headers: { authorization: "Bearer worker-secret-0123456789abcdefghi" },
      }).catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, 20));
      assert.equal(api.publish({ type: "backpressure" }), true);
      assert.equal(sawBackpressureWrite, true);
      assert.equal(api.publish({ type: "after-backpressure" }), true);
    });
  } finally {
    ServerResponse.prototype.write = originalWrite;
  }
});

test("startup and request-target routing are loopback and origin-form only", async () => {
  const life = lifecycle();
  const p = ports();
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  await assert.rejects(api.listen(0, "0.0.0.0"), /loopback/);
  const first = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  const second = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  const { port } = await first.listen();
  await assert.rejects(second.listen(port), /EADDRINUSE/);
  await first.close();

  const routed = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret-0123456789abcdefghi",
    sessionId: "session-1",
  });
  const listened = await routed.listen();
  try {
    const rawStatus = (
      path: string,
      headers: string[] = ["authorization", "Bearer worker-secret-0123456789abcdefghi"],
    ) =>
      new Promise<number>((resolve, reject) => {
        const req = httpRequest({ host: "127.0.0.1", port: listened.port, path, method: "GET", headers }, (res) => {
          resolve(res.statusCode ?? 0);
          res.resume();
        });
        req.on("error", reject);
        req.end();
      });
    assert.equal(await rawStatus("http://evil.example/v1/state"), 400);
    assert.equal(await rawStatus("//evil.example/v1/state"), 400);
    assert.equal(
      await rawStatus("/v1/state", [
        "authorization",
        "Bearer worker-secret-0123456789abcdefghi",
        "Authorization",
        "Bearer worker-secret-0123456789abcdefghi",
      ]),
      400,
    );
    assert.equal(
      await rawStatus("/v1/state", [
        "authorization",
        "Bearer worker-secret-0123456789abcdefghi",
        "x-cogs-correlation-id",
        "a",
        "X-Cogs-Correlation-Id",
        "b",
      ]),
      400,
    );
  } finally {
    await routed.close();
  }
});

test("state and readiness follow lifecycle without cross-session data", async () => {
  await withServer(async ({ base, life }) => {
    let ready = await json(base, "/health/ready", { method: "GET" });
    assert.equal(ready.status, 200);
    life.ready = false;
    ready = await json(base, "/health/ready", { method: "GET" });
    assert.equal(ready.status, 503);
    const state = await json(base, "/v1/state", { method: "GET" });
    const stateBody = JSON.stringify(await body(state));
    assert.doesNotMatch(stateBody, /worker-secret-0123456789abcdefghi|other-session|raw_export/);
  });
});
