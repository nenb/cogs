import assert from "node:assert/strict";
import type { randomBytes } from "node:crypto";
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { type ApiSeams, createApiClient } from "../dev/launcher/api-client.ts";
import { parseLauncherArgs, readPromptFile, writeSensitiveExport } from "../dev/launcher/cli.ts";
import { type ApiEvent, createApiServer, type JsonValue } from "../src/api/server.ts";

const token = "t".repeat(32);
function seams(fetchImpl: typeof fetch): ApiSeams {
  return Object.freeze({
    fetch: Object.freeze(fetchImpl),
    randomBytes: Object.freeze((() => Buffer.alloc(16, 1)) as typeof randomBytes),
  });
}
function jsonResponse(url: URL, body: unknown, status = 200): Response {
  const response = new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
  Object.defineProperty(response, "url", { value: String(url) });
  Object.defineProperty(response, "redirected", { value: false });
  return response;
}
function fakeClient(body: unknown, status = 200) {
  return createApiClient({
    port: 9,
    token,
    seams: seams(Object.freeze((async (url: URL) => jsonResponse(url, body, status)) as unknown as typeof fetch)),
  });
}

async function server() {
  const calls: string[] = [];
  let runState: "idle" | "running" | "settled" | "aborting" | "shutdown" = "idle";
  const api = createApiServer({
    bearerToken: token,
    sessionId: "session-1",
    lifecycle: {
      ready: true,
      state: "ready",
      requestShutdown: async () => {
        runState = "shutdown";
      },
    } as never,
    session: {
      state: async () => ({ runState, usage: { tokens: 1 } }),
      input: async (input) => {
        calls.push(`input:${input.content}`);
        runState = "running";
        return runState;
      },
      abort: async (input) => {
        calls.push(`abort:${input.requestId}`);
        runState = "aborting";
        return { aborted: true, runState };
      },
    },
    history: { entries: async ({ limit }) => ({ entries: [{ n: limit }], nextAfter: "n1" }) },
    exporter: { createExport: async ({ requestId }) => ({ requestId, secret: "local-only" }) as JsonValue },
  });
  const { port } = await api.listen(0, "127.0.0.1");
  return { api, port, calls };
}

test("launcher cli parser uses profile state operation order and exact flags", () => {
  assert.deepEqual(parseLauncherArgs(["--profile", "linux-kvm", "--state", "s1", "run", "--prompt-file", "p.txt"]), {
    op: "run",
    profile: "linux-kvm",
    state: "s1",
    promptFile: "p.txt",
  });
  assert.equal(parseLauncherArgs(["--profile", "insecure-container", "--state", "s", "status", "--json"]).json, true);
  assert.equal(parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "history", "--limit", "100"]).limit, 100);
  assert.deepEqual(parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "s3-09"]), {
    op: "s3-09",
    profile: "linux-kvm",
    state: "s",
  });
  for (const bad of [
    ["run", "--profile", "linux-kvm", "--state", "s"],
    ["--profile=linux-kvm", "--state", "s", "status"],
    ["--profile", "linux-kvm", "--state", "s", "run", "--prompt", "p.txt"],
    ["--profile", "linux-kvm", "--state", "s", "run", "--prompt-file", "../x"],
    ["--profile", "linux-kvm", "--state", "s", "export", "--export-root", "x"],
    ["--profile", "bad", "--state", "s", "status"],
  ])
    assert.throws(() => parseLauncherArgs(bad));
});

test("launcher cli snapshots hostile argv without invoking getters", () => {
  let invoked = false;
  const argv = ["--profile", "linux-kvm", "--state", "s", "status"];
  Object.defineProperty(argv, "1", {
    get() {
      invoked = true;
      throw new Error("SECRET");
    },
    enumerable: true,
  });
  assert.throws(() => parseLauncherArgs(argv));
  assert.equal(invoked, false);
});

test("prompt reader rejects traversal links hardlinks modes and controls", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-cli-"));
  try {
    await chmod(dir, 0o700);
    const root = await realpath(dir);
    await writeFile(join(root, "ok.txt"), "hello");
    assert.equal(await readPromptFile(root, "ok.txt", 32), "hello");
    await writeFile(join(root, "bad.txt"), "bad\u0001");
    await assert.rejects(() => readPromptFile(root, "bad.txt"));
    await symlink(join(root, "ok.txt"), join(root, "sym.txt"));
    await assert.rejects(() => readPromptFile(root, "sym.txt"));
    await link(join(root, "ok.txt"), join(root, "hard.txt"));
    await assert.rejects(() => readPromptFile(root, "ok.txt"));
    await writeFile(join(root, "mode.txt"), "x");
    await chmod(join(root, "mode.txt"), 0o622);
    await assert.rejects(() => readPromptFile(root, "mode.txt"));
    const outside = await mkdtemp(join(tmpdir(), "cogs-outside-"));
    await chmod(outside, 0o700);
    await writeFile(join(outside, "escape.txt"), "escape");
    await symlink(outside, join(root, "linked"));
    await assert.rejects(() => readPromptFile(root, "linked/escape.txt"));
    await rm(outside, { recursive: true, force: true });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("export writer preserves sensitive response and refuses overwrite/private-root violations", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-export-"));
  try {
    await chmod(dir, 0o700);
    const root = await realpath(dir);
    const nested = Object.freeze(Object.assign(Object.create(null) as Record<string, unknown>, { ok: true }));
    const bundle = Object.freeze(
      Object.assign(Object.create(null) as Record<string, unknown>, {
        token: "kept-local",
        nested: Object.freeze([1, nested]),
      }),
    );
    const response = Object.freeze(
      Object.assign(Object.create(null) as Record<string, unknown>, {
        version: "cogs.export-response/v1alpha1",
        sensitive: true,
        bundle,
      }),
    );
    const out = await writeSensitiveExport(root, "out.json", response);
    assert.match(await readFile(out, "utf8"), /kept-local/);
    await assert.rejects(() =>
      writeSensitiveExport(root, "out.json", { version: "cogs.export-response/v1alpha1", sensitive: true, bundle: {} }),
    );
    await assert.rejects(() => writeSensitiveExport(root, "bad.json", { sensitive: false }));
    const hostile = { version: "cogs.export-response/v1alpha1", sensitive: true };
    Object.defineProperty(hostile, "bundle", {
      get() {
        throw new Error("SECRET");
      },
      enumerable: true,
    });
    await assert.rejects(() => writeSensitiveExport(root, "getter.json", hostile));
    const custom = Object.create({ inherited: true }) as Record<string, unknown>;
    custom.version = "cogs.export-response/v1alpha1";
    custom.sensitive = true;
    custom.bundle = {};
    await assert.rejects(() => writeSensitiveExport(root, "custom.json", custom));
    await assert.rejects(() =>
      writeSensitiveExport(root, "date.json", {
        version: "cogs.export-response/v1alpha1",
        sensitive: true,
        bundle: new Date(),
      }),
    );
    await assert.rejects(() =>
      writeSensitiveExport(root, "map.json", {
        version: "cogs.export-response/v1alpha1",
        sensitive: true,
        bundle: new Map(),
      }),
    );
    await chmod(dir, 0o755);
    await assert.rejects(() => writeSensitiveExport(root, "x.json", { sensitive: true }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("api client interoperates with authoritative server routes and schemas", async () => {
  const s = await server();
  try {
    const client = createApiClient({ port: s.port, token });
    assert.equal(((await client.request("state")) as { version: string }).version, "cogs.state/v1alpha1");
    assert.equal(((await client.request("status")) as { version: string }).version, "cogs.state/v1alpha1");
    assert.equal(
      ((await client.request("run", { content: "prompt text" })) as { version: string }).version,
      "cogs.input-acceptance/v1alpha1",
    );
    assert.equal(((await client.request("abort")) as { version: string }).version, "cogs.abort/v1alpha1");
    assert.equal(
      ((await client.request("entries", { limit: 2 })) as { version: string }).version,
      "cogs.entries/v1alpha1",
    );
    const exp = (await client.request("export")) as { sensitive: boolean; bundle: { secret: string } };
    assert.equal(exp.sensitive, true);
    assert.equal(exp.bundle.secret, "local-only");
    assert.equal(((await client.request("shutdown")) as { version: string }).version, "cogs.shutdown/v1alpha1");
    assert(s.calls.some((x) => x === "input:prompt text"));
  } finally {
    await s.api.close();
  }
});

test("api SSE client parses real server events and rejects replay mismatch", async () => {
  const s = await server();
  try {
    const event: ApiEvent = { kind: "warning", correlation_id: "corr-1", payload: { code: "x" } };
    assert.equal(s.api.publish(event), true);
    const client = createApiClient({ port: s.port, token });
    const events = [];
    for await (const item of client.events(0, 1)) events.push(item);
    assert.equal(events[0]?.id, 1);
    assert.equal(events[0]?.data.version, "cogs.event/v1alpha1");
    await assert.rejects(async () => {
      for await (const _ of client.events(99, 1)) break;
    }, /launcher api replay gap/);
  } finally {
    await s.api.close();
  }
});

test("api SSE client keeps one live connection through more than replay capacity", async () => {
  const s = await server();
  let fetches = 0;
  try {
    assert.equal(s.api.publish({ kind: "warning", correlation_id: "corr-live", payload: { code: "seed" } }), true);
    const client = createApiClient({
      port: s.port,
      token,
      maxBytes: 1024 * 1024,
      seams: seams(
        Object.freeze(((url: URL, init?: RequestInit) => {
          fetches += 1;
          return globalThis.fetch(url, init);
        }) as typeof fetch),
      ),
    });
    const iterator = client.events(0, 1000);
    const first = await iterator.next();
    assert.equal(first.done, false);
    assert.equal(first.value?.id, 1);
    for (let i = 0; i < 260; i += 1) {
      assert.equal(
        s.api.publish({ kind: "tool_update", correlation_id: "corr-live", payload: { chunk: "metadata" } }),
        true,
      );
    }
    assert.equal(s.api.publish({ kind: "run_settled", correlation_id: "corr-live", payload: { ok: true } }), true);
    let terminal = 0;
    let count = 1;
    for await (const event of iterator) {
      count += 1;
      if (event.data.kind === "run_settled") {
        terminal = event.id;
        break;
      }
    }
    await iterator.return?.(undefined);
    assert.equal(fetches, 1);
    assert.equal(count, 262);
    assert.equal(terminal, 262);
    assert.equal(s.api.publish({ kind: "warning", correlation_id: "corr-live", payload: { code: "post" } }), true);
    await assert.rejects(async () => {
      for await (const _ of client.events(0, 1)) break;
    }, /launcher api replay gap/);
    await assert.rejects(async () => {
      for await (const _ of client.events(0, 1001)) break;
    }, /launcher api failed/);
  } finally {
    await s.api.close();
  }
});

test("api SSE replay gap is specific to HTTP 409, not forged network messages", async () => {
  const forged = createApiClient({
    port: 9,
    token,
    seams: seams(
      Object.freeze((async () => {
        throw new Error("launcher api replay gap");
      }) as unknown as typeof fetch),
    ),
  });
  await assert.rejects(async () => {
    for await (const _ of forged.events(0, 1)) break;
  }, /launcher api failed/);
  const http409 = createApiClient({
    port: 9,
    token,
    seams: seams(
      Object.freeze((async (url: URL) =>
        jsonResponse(url, { version: "cogs.error/v1alpha1", error: "replay_gap" }, 409)) as unknown as typeof fetch),
    ),
  });
  await assert.rejects(async () => {
    for await (const _ of http409.events(0, 1)) break;
  }, /launcher api replay gap/);
});

test("api client rejects redirect oversize malformed extras hanging body and parent abort", async () => {
  const mk = (response: Response, timeoutMs = 50) =>
    createApiClient({
      port: 9,
      token,
      timeoutMs,
      seams: seams(
        Object.freeze((async (url: URL) => {
          Object.defineProperty(response, "url", { value: String(url) });
          Object.defineProperty(response, "redirected", { value: false });
          return response;
        }) as unknown as typeof fetch),
      ),
    });
  await assert.rejects(() =>
    mk(
      new Response("{}", { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } }),
    ).request("state"),
  );
  await assert.rejects(() =>
    mk(
      new Response(
        '{"version":"cogs.state/v1alpha1","ready":true,"closed":false,"lifecycle":"ready","run_state":"idle","usage":null,"extra":1}',
        { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } },
      ),
    ).request("state"),
  );
  await assert.rejects(() =>
    mk(
      new Response("x".repeat(200_000), {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
      }),
    ).request("state"),
  );
  assert.throws(() => createApiClient({ port: 9, token: "bad" }));
  const hanging = new Response(new ReadableStream({ start() {} }), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
  await assert.rejects(() => mk(hanging, 5).request("state"));
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(() =>
    mk(
      new Response("{}", { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } }),
    ).request("state", {}, ac.signal),
  );
  const ignoredAbort = createApiClient({
    port: 9,
    token,
    timeoutMs: 5,
    seams: seams(Object.freeze((async () => new Promise<Response>(() => undefined)) as typeof fetch)),
  });
  await assert.rejects(() => ignoredAbort.request("state"));
  const delayedAbort = new AbortController();
  const duringRead = createApiClient({
    port: 9,
    token,
    timeoutMs: 500,
    seams: seams(
      Object.freeze((async (url: URL) => {
        const response = new Response(new ReadableStream({ start() {} }), {
          status: 200,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        });
        Object.defineProperty(response, "url", { value: String(url) });
        Object.defineProperty(response, "redirected", { value: false });
        return response;
      }) as unknown as typeof fetch),
    ),
  });
  const pending = duringRead.request("state", {}, delayedAbort.signal);
  delayedAbort.abort();
  await assert.rejects(() => pending);
});

test("api client snapshots hostile seams and responses without secret leakage", async () => {
  let invoked = false;
  const response = new Response("{}", {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
  Object.defineProperty(response, "url", {
    get() {
      invoked = true;
      throw new Error("SECRET");
    },
  });
  const client = createApiClient({
    port: 9,
    token,
    seams: seams(Object.freeze((async () => response) as typeof fetch)),
  });
  await assert.rejects(
    () => client.request("state"),
    (e: unknown) => e instanceof Error && !String(e.message).includes("SECRET"),
  );
  assert.equal(invoked, false);
  assert.throws(() =>
    createApiClient({
      port: 9,
      token,
      seams: { fetch: globalThis.fetch, randomBytes: (() => Buffer.alloc(16)) as typeof randomBytes } as ApiSeams,
    }),
  );
});

test("api client rejects malformed state lifecycle booleans and ids", async () => {
  await assert.rejects(() =>
    fakeClient({
      version: "cogs.state/v1alpha1",
      lifecycle: "closed",
      ready: true,
      closed: false,
      run_state: "idle",
      usage: null,
    }).request("state"),
  );
  await assert.rejects(() =>
    fakeClient({
      version: "cogs.state/v1alpha1",
      lifecycle: "ready",
      ready: "yes",
      closed: false,
      run_state: "idle",
      usage: null,
    }).request("state"),
  );
  await assert.rejects(() =>
    fakeClient(
      { version: "cogs.abort/v1alpha1", request_id: "bad space", aborted: true, run_state: "idle" },
      202,
    ).request("abort"),
  );
});

test("api client already-aborted ignored fetch resolves generically", async () => {
  const ac = new AbortController();
  ac.abort();
  const client = createApiClient({
    port: 9,
    token,
    timeoutMs: 100,
    seams: seams(Object.freeze((async () => new Promise<Response>(() => undefined)) as typeof fetch)),
  });
  await assert.rejects(() => client.request("state", {}, ac.signal));
});

test("api client rejects malformed response families", async () => {
  await assert.rejects(() =>
    fakeClient(
      {
        version: "cogs.input-acceptance/v1alpha1",
        request_id: "r",
        correlation_id: "c",
        accepted: false,
        duplicate: false,
        run_state: "running",
      },
      202,
    ).request("run", { content: "x" }),
  );
  await assert.rejects(() =>
    fakeClient({ version: "cogs.entries/v1alpha1", entries: Array.from({ length: 101 }, () => null) }).request(
      "entries",
      { limit: 1 },
    ),
  );
  await assert.rejects(() =>
    fakeClient({ version: "cogs.shutdown/v1alpha1", accepted: false }, 202).request("shutdown"),
  );
  await assert.rejects(() =>
    fakeClient({ version: "cogs.export-response/v1alpha1", sensitive: true, bundle: { constructor: 1 } }).request(
      "export",
    ),
  );
});

test("api client rejects hostile JSON arrays and random ids", async () => {
  const array = [1];
  Object.defineProperty(array, "1", {
    get() {
      throw new Error("SECRET");
    },
    enumerable: true,
  });
  await assert.rejects(() =>
    fakeClient({ version: "cogs.entries/v1alpha1", entries: array }).request("entries", { limit: 1 }),
  );
  await assert.rejects(() =>
    createApiClient({
      port: 9,
      token,
      seams: Object.freeze({
        fetch: Object.freeze(globalThis.fetch),
        randomBytes: Object.freeze((() => Buffer.alloc(17)) as typeof randomBytes),
      }),
    }).request("run", { content: "x" }),
  );
  await assert.rejects(() =>
    createApiClient({
      port: 9,
      token,
      seams: Object.freeze({
        fetch: Object.freeze(globalThis.fetch),
        randomBytes: Object.freeze((() => Buffer.alloc(16)) as typeof randomBytes),
      }),
    }).request("run", { content: "x" }),
  );
});

test("api client cancels on bad headers without leaking cancel errors", async () => {
  const response = new Response("{}", {
    status: 500,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
  Object.defineProperty(response, "url", { value: "http://127.0.0.1:9/v1/state" });
  Object.defineProperty(response, "redirected", { value: false });
  Object.defineProperty(response, "body", {
    value: {
      cancel() {
        throw new Error("SECRET cancel");
      },
    },
  });
  const client = createApiClient({
    port: 9,
    token,
    seams: seams(Object.freeze((async () => response) as typeof fetch)),
  });
  await assert.rejects(
    () => client.request("state"),
    (e: unknown) => e instanceof Error && !String(e.message).includes("SECRET"),
  );
});

test("api client rejects malformed SSE duplicate and id mismatch", async () => {
  const sse =
    'id: 2\nevent: cogs\ndata: {"version":"cogs.event/v1alpha1","seq":3,"timestamp":"2026-01-01T00:00:00.000Z","session_id":"s","kind":"warning","correlation_id":"c","payload":{}}\n\n';
  const client = createApiClient({
    port: 9,
    token,
    seams: seams(
      Object.freeze((async (url: URL) => {
        const r = new Response(sse, {
          status: 200,
          headers: { "content-type": "text/event-stream", "cache-control": "no-store" },
        });
        Object.defineProperty(r, "url", { value: String(url) });
        Object.defineProperty(r, "redirected", { value: false });
        return r;
      }) as unknown as typeof fetch),
    ),
  });
  await assert.rejects(async () => {
    for await (const _ of client.events(0, 1)) break;
  });
});

test("prompt reader rejects invalid max and allows tab newline carriage return", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-prompt-extra-"));
  try {
    await chmod(dir, 0o700);
    const root = await realpath(dir);
    await writeFile(join(root, "ok.txt"), "a\t\n\rb");
    assert.equal(await readPromptFile(root, "ok.txt"), "a\t\n\rb");
    await assert.rejects(() => readPromptFile(root, "ok.txt", Number.NaN));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("export writer rejects hostile arrays symbols cycles depth and preserves preexisting", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-export-extra-"));
  try {
    await chmod(dir, 0o700);
    const root = await realpath(dir);
    const base = { version: "cogs.export-response/v1alpha1", sensitive: true } as Record<string, unknown>;
    base.bundle = [[{ ok: true }]];
    await writeSensitiveExport(root, "nested.json", base);
    const hole = [1, 2, 3];
    delete hole[1];
    await assert.rejects(() =>
      writeSensitiveExport(root, "hole.json", {
        version: "cogs.export-response/v1alpha1",
        sensitive: true,
        bundle: hole,
      }),
    );
    const sym = { version: "cogs.export-response/v1alpha1", sensitive: true, bundle: {} };
    Object.defineProperty(sym.bundle, Symbol("x"), { value: 1 });
    await assert.rejects(() => writeSensitiveExport(root, "sym.json", sym));
    const cyc: Record<string, unknown> = { version: "cogs.export-response/v1alpha1", sensitive: true };
    cyc.bundle = cyc;
    await assert.rejects(() => writeSensitiveExport(root, "cyc.json", cyc));
    await writeFile(join(root, "exists.json"), "old", { mode: 0o600 });
    await assert.rejects(() => writeSensitiveExport(root, "exists.json", base));
    assert.equal(await readFile(join(root, "exists.json"), "utf8"), "old");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("parser rejects duplicate operation flags and inline tricks", () => {
  assert.throws(() => parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "status", "--json", "--json"]));
  assert.throws(() => parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "status", "--timeout-ms=1"]));
  assert.throws(() => parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "status", "--", "--json"]));
});

test("api client rejects body trickle past absolute deadline", async () => {
  const client = createApiClient({
    port: 9,
    token,
    timeoutMs: 20,
    seams: seams(
      Object.freeze((async (url: URL) => {
        const response = new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("{"));
              setTimeout(() => {
                try {
                  controller.enqueue(new TextEncoder().encode("}"));
                } catch {
                  // cancelled by bounded client
                }
              }, 60);
            },
          }),
          { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } },
        );
        Object.defineProperty(response, "url", { value: String(url) });
        Object.defineProperty(response, "redirected", { value: false });
        return response;
      }) as unknown as typeof fetch),
    ),
  });
  await assert.rejects(() => client.request("state"));
});

test("api client normalizes already-aborted malformed input without unhandled rejection", async () => {
  const ac = new AbortController();
  ac.abort();
  const unhandled: unknown[] = [];
  const onUnhandled = (error: unknown) => unhandled.push(error);
  process.on("unhandledRejection", onUnhandled);
  try {
    await assert.rejects(() => fakeClient({}).request("run", {}, ac.signal), /launcher api failed/u);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

test("api client enforces request id response match duplicate false and simple 8192 prompt", async () => {
  let captured = "";
  const client = createApiClient({
    port: 9,
    token,
    seams: seams(
      Object.freeze((async (url: URL, init?: RequestInit) => {
        captured = String(init?.body ?? "");
        const req = JSON.parse(captured) as { request_id: string };
        return jsonResponse(
          url,
          {
            version: "cogs.input-acceptance/v1alpha1",
            accepted: true,
            duplicate: false,
            request_id: req.request_id,
            correlation_id: "corr-1",
            run_state: "running",
          },
          202,
        );
      }) as unknown as typeof fetch),
    ),
  });
  await client.request("run", { content: "a".repeat(8192) });
  assert.equal((JSON.parse(captured) as { content: string }).content.length, 8192);
  await assert.rejects(() =>
    fakeClient({
      version: "cogs.input-acceptance/v1alpha1",
      accepted: true,
      duplicate: true,
      request_id: "req-AQEBAQEBAQEBAQEBAQEBAQ",
      correlation_id: "corr-1",
      run_state: "running",
    }).request("run", { content: "x" }),
  );
  await assert.rejects(() =>
    fakeClient({
      version: "cogs.abort/v1alpha1",
      aborted: true,
      request_id: "req-mismatch",
      run_state: "aborting",
    }).request("abort"),
  );
});

test("api client cancellation remains bounded and SSE JSON errors are generic", async () => {
  const client = createApiClient({
    port: 9,
    token,
    timeoutMs: 1_000,
    seams: seams(
      Object.freeze((async (url: URL) => {
        const response = new Response(
          new ReadableStream({
            cancel() {
              return new Promise(() => undefined);
            },
          }),
          { status: 500, headers: { "content-type": "application/json", "cache-control": "no-store" } },
        );
        Object.defineProperty(response, "url", { value: String(url) });
        Object.defineProperty(response, "redirected", { value: false });
        return response;
      }) as unknown as typeof fetch),
    ),
  });
  const start = Date.now();
  await assert.rejects(() => client.request("state"), /launcher api failed/u);
  assert.ok(Date.now() - start < 500);

  const sseClient = createApiClient({
    port: 9,
    token,
    seams: seams(
      Object.freeze((async (url: URL) => {
        const response = new Response("id: 1\nevent: cogs\ndata: {SECRET\n\n", {
          status: 200,
          headers: { "content-type": "text/event-stream", "cache-control": "no-store" },
        });
        Object.defineProperty(response, "url", { value: String(url) });
        Object.defineProperty(response, "redirected", { value: false });
        return response;
      }) as unknown as typeof fetch),
    ),
  });
  await assert.rejects(async () => {
    for await (const _ of sseClient.events(undefined, 1));
  }, /^Error: launcher api failed$/u);
});

test("prompt rejects nested parent symlink escape", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-prompt-link-"));
  const root = await realpath(dir);
  try {
    const outside = join(dir, "outside");
    await mkdir(outside, { mode: 0o700 });
    await writeFile(join(outside, "p.txt"), "hello", { mode: 0o600 });
    await symlink(outside, join(root, "linkdir"));
    await assert.rejects(() => readPromptFile(root, "linkdir/p.txt"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("export rejects aggregate oversize and nonenumerable without invoking getter", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-export-budget-"));
  const root = await realpath(dir);
  await chmod(root, 0o700);
  try {
    await assert.rejects(() =>
      writeSensitiveExport(
        root,
        "too-big.json",
        { version: "cogs.export-response/v1alpha1", sensitive: true, bundle: { a: "x".repeat(900) } },
        256,
      ),
    );
    await assert.rejects(() =>
      writeSensitiveExport(
        root,
        "huge-key.json",
        { version: "cogs.export-response/v1alpha1", sensitive: true, bundle: { ["k".repeat(4096)]: 1 } },
        256,
      ),
    );
    const hostile = { version: "cogs.export-response/v1alpha1", sensitive: true, bundle: {} } as Record<
      string,
      unknown
    >;
    Object.defineProperty(hostile, "hidden", {
      get() {
        throw new Error("SECRET");
      },
    });
    await assert.rejects(() => writeSensitiveExport(root, "hidden.json", hostile));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("api client create normalizes hostile option proxy", () => {
  assert.doesNotThrow(() =>
    createApiClient({ port: 9, token, timeoutMs: 900_000, seams: seams(Object.freeze(globalThis.fetch)) }),
  );
  assert.throws(() =>
    createApiClient({ port: 9, token, timeoutMs: 900_001, seams: seams(Object.freeze(globalThis.fetch)) }),
  );
  assert.throws(
    () =>
      createApiClient(
        new Proxy(Object.create(null), {
          getPrototypeOf() {
            throw new Error("SECRET");
          },
        }) as { port: number; token: string },
      ),
    /^Error: launcher api failed$/u,
  );
});
