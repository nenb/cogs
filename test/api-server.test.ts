import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
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
  } = {},
): Promise<T> {
  const life = lifecycle();
  const p = ports();
  const api = createApiServer({
    lifecycle: life as never,
    session: p.session,
    history: p.history,
    exporter: p.exporter,
    bearerToken: "worker-secret",
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
    headers: { authorization: "Bearer worker-secret", "content-type": "application/json", ...(init.headers ?? {}) },
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
      headers: { authorization: "Bearer worker-secret", "content-type": "text/plain" },
      body: "{}",
    });
    assert.equal(badType.status, 415);
    assert.doesNotMatch(await badType.text(), /worker-secret|prompt|users\//);
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
    bearerToken: "worker-secret",
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
      const replay = await fetch(`${base}/v1/events?after=0`, { headers: { authorization: "Bearer worker-secret" } });
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
      const gap = await fetch(`${base}/v1/events?after=0`, { headers: { authorization: "Bearer worker-secret" } });
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
    bearerToken: "worker-secret",
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
    bearerToken: "worker-secret",
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
          headers: { authorization: "Bearer worker-secret", "content-type": "application/json" },
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

test("state and readiness follow lifecycle without cross-session data", async () => {
  await withServer(async ({ base, life }) => {
    let ready = await json(base, "/health/ready", { method: "GET" });
    assert.equal(ready.status, 200);
    life.ready = false;
    ready = await json(base, "/health/ready", { method: "GET" });
    assert.equal(ready.status, 503);
    const state = await json(base, "/v1/state", { method: "GET" });
    const stateBody = JSON.stringify(await body(state));
    assert.doesNotMatch(stateBody, /worker-secret|other-session|raw_export/);
  });
});
