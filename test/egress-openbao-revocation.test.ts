import assert from "node:assert/strict";
import { test } from "node:test";
import type { OpenBaoIdentityPort } from "../src/auth/model-auth.ts";
import {
  CogsEgressOpenBaoRevocationError,
  createOpenBaoEgressRevocationBinding,
  OpenBaoEgressRevocationSource,
} from "../src/egress/openbao-revocation.ts";
import { createCogsEgressRevocationWatcher } from "../src/egress/revocation-watcher.ts";

const raw = "tokensecret users/user-a/provider path metadata";
const base = {
  origin: "http://127.0.0.1:8200/",
  mount: "model",
  userId: "user-a",
  credentialHandle: "users/user-a/provider",
  presetRevision: "preset1",
  pkiExpiresAtMs: 99_999,
  allowLoopbackHttpDevelopment: true,
  timeoutMs: 50,
  maxResponseBytes: 4096,
};

const generic = (error: unknown) => {
  assert.ok(error instanceof CogsEgressOpenBaoRevocationError);
  assert.equal(error.message, "egress revocation metadata unavailable");
  assert.equal(String(error).includes(raw), false);
  assert.equal(String((error as Error).stack ?? "").includes("tokensecret"), false);
  return true;
};

test("reads strict KV-v2 metadata into a frozen source-only revocation snapshot", async () => {
  const seen: string[] = [];
  const source = src({
    fetchImpl: async (url, init) => {
      seen.push(String(url));
      assert.equal(init?.method, "GET");
      assert.equal(init?.redirect, "error");
      const headers = init?.headers as Record<string, string> | undefined;
      assert.equal(headers?.["x-vault-token"], "tokensecret");
      return json(meta(7));
    },
  });
  const snapshot = await source.read(new AbortController().signal);
  assert.deepEqual(snapshot, {
    presetRevision: "preset1",
    credentialVersion: "7",
    revoked: false,
    pkiExpiresAtMs: 99_999,
  });
  assert.equal(Object.isFrozen(snapshot), true);
  assert.deepEqual(seen, ["http://127.0.0.1:8200/v1/model/metadata/users/user-a/provider"]);
});

test("version changes, deleted current versions, and 404 are observable without silent malformed revocation", async () => {
  const responses = [json(meta(1)), json(meta(2)), json(meta(2, { deletion_time: "2026-01-01T00:00:00Z" }))];
  const source = src({ fetchImpl: async () => responses.shift() ?? json(meta(3, { destroyed: true })) });
  assert.equal((await source.read(new AbortController().signal)).credentialVersion, "1");
  assert.equal((await source.read(new AbortController().signal)).credentialVersion, "2");
  assert.equal((await source.read(new AbortController().signal)).revoked, true);
  assert.equal((await source.read(new AbortController().signal)).revoked, true);

  let cancelled = false;
  const missing = src({
    fetchImpl: async () =>
      response("missing", 404, "text/plain", () => {
        cancelled = true;
      }),
  });
  assert.deepEqual(await missing.read(new AbortController().signal), {
    presetRevision: "preset1",
    credentialVersion: "missing",
    revoked: true,
    pkiExpiresAtMs: 99_999,
  });
  assert.equal(cancelled, true);
  await assert.rejects(
    src({ fetchImpl: async () => response("missing", 404, "text/plain", () => Promise.reject(new Error(raw))) }).read(
      new AbortController().signal,
    ),
    generic,
  );

  const malformed = src({ fetchImpl: async () => json(meta(9, {}, { versions: {} })) });
  await assert.rejects(malformed.read(new AbortController().signal), generic);
});

test("constructor validates origin, user-bound handles, and session handle exclusion", () => {
  for (const patch of [
    { origin: "http://example.com/" },
    { credentialHandle: "users/other/provider" },
    { credentialHandle: "sessions/user-a/provider" },
    { credentialHandle: "users/user-a/../provider" },
    { credentialHandle: "organizations/./provider" },
    { credentialHandle: "users/user-a/pro%vider" },
    { userId: "bad user" },
    { presetRevision: "bad preset" },
  ]) {
    assert.throws(() => src(patch), generic);
  }
});

test("hostile envelopes, current entries, custom metadata, content type, size, and auth fields fail generically", async () => {
  const hostile = [
    meta(1, {}, { request_id: 1 }),
    meta(1, {}, { auth: { client_token: raw } }),
    meta(1, {}, { wrap_info: { token: raw } }),
    meta(1, {}, { data: { ...meta(1).data, extra: true } }),
    meta(1, {}, { data: { ...meta(1).data, custom_metadata: { token: raw } } }),
    meta(1, {}, { data: { ...meta(1).data, current_version: 0 } }),
    meta(1, {}, { data: { ...meta(1).data, delete_version_after: "" } }),
    meta(1, {}, { data: { ...meta(1).data, delete_version_after: "1 day" } }),
    meta(1, {}, { data: { ...meta(1).data, delete_version_after: "1\n" } }),
    meta(1, {}, { data: { ...meta(1).data, versions: { "01": version() } } }),
    meta(1, {}, { data: { ...meta(1).data, versions: manyVersions(1025) } }),
    meta(1, {}, { data: { ...meta(1).data, versions: { "1": { ...version(), created_by: raw } } } }),
    meta(2, {}, { data: { ...meta(2).data, versions: { "1": { ...version(), created_by: raw }, "2": version() } } }),
    meta(2, {}, { data: { ...meta(2).data, versions: { "1": version() } } }),
    meta(1, {}, { data: { ...meta(1).data, created_time: "" } }),
    meta(1, { created_time: "" }),
  ];
  for (const [index, body] of hostile.entries())
    await assert.rejects(
      src({ fetchImpl: async () => json(body) }).read(new AbortController().signal),
      generic,
      `hostile ${index}`,
    );
  await assert.rejects(
    src({ fetchImpl: async () => response("{}", 200, "text/plain") }).read(new AbortController().signal),
    generic,
  );
  await assert.rejects(src({ fetchImpl: async () => response("{}", 204) }).read(new AbortController().signal), generic);
  for (const status of [301, 302, 401, 403, 500, 503])
    await assert.rejects(
      src({ fetchImpl: async () => response("{}", status) }).read(new AbortController().signal),
      generic,
    );
  await assert.rejects(
    src({ maxResponseBytes: 512, fetchImpl: async () => response("x".repeat(513), 200) }).read(
      new AbortController().signal,
    ),
    generic,
  );
  await assert.rejects(
    src({ fetchImpl: async () => badLengthResponse("{}") }).read(new AbortController().signal),
    generic,
  );
  await assert.rejects(
    src({ fetchImpl: async () => readerFailureResponse() }).read(new AbortController().signal),
    generic,
  );
  let cancelOnDecode = false;
  await assert.rejects(
    src({
      fetchImpl: async () =>
        streamingResponse(new Uint8Array([0xff]), () => {
          cancelOnDecode = true;
        }),
    }).read(new AbortController().signal),
    generic,
  );
  assert.equal(cancelOnDecode, true);
  for (const validDuration of ["1h30m", "1.5s", "2h45m10s"]) {
    const snapshot = await src({
      fetchImpl: async () => json(meta(1, {}, { data: { ...meta(1).data, delete_version_after: validDuration } })),
    }).read(new AbortController().signal);
    assert.equal(snapshot.credentialVersion, "1");
  }
});

test("callback-scoped token is exactly once, aborts propagate, redirects are disabled, and bad token callbacks fail", async () => {
  let calls = 0;
  let late: ((token: string) => Promise<void>) | undefined;
  const source = src({
    identity: {
      async withToken(_signal, operation) {
        calls++;
        late = operation;
        await operation("tokensecret");
        await assert.rejects(operation("tokensecret"));
      },
    },
    fetchImpl: async (_url, init) => {
      assert.equal(init?.redirect, "error");
      return json(meta(1));
    },
  });
  await source.read(new AbortController().signal);
  assert.equal(calls, 1);
  await assert.rejects(late?.("tokensecret") ?? Promise.resolve());

  await assert.rejects(
    src({ identity: { withToken: async () => undefined } }).read(new AbortController().signal),
    generic,
  );
  await assert.rejects(
    src({ identity: { withToken: async (_s, op) => void (await op(raw)) } }).read(new AbortController().signal),
    generic,
  );
  let fetchAborted = false;
  await assert.rejects(
    src({
      identity: {
        async withToken(_signal, operation) {
          void operation("tokensecret");
          throw new Error(raw);
        },
      },
      fetchImpl: async (_url, init) =>
        new Promise<Response>(() => {
          const requestSignal = init?.signal as AbortSignal | undefined;
          requestSignal?.addEventListener("abort", () => {
            fetchAborted = true;
          });
        }),
    }).read(new AbortController().signal),
    generic,
  );
  await flush();
  assert.equal(fetchAborted, true);
  await assert.rejects(
    src({
      timeoutMs: 1,
      fetchImpl: async (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          const requestSignal = init?.signal as AbortSignal | undefined;
          requestSignal?.addEventListener("abort", () => reject(new Error(raw)), { once: true });
        }),
    }).read(new AbortController().signal),
    generic,
  );
  const aborted = new AbortController();
  aborted.abort(raw);
  await assert.rejects(src().read(aborted.signal), generic);
});

test("aggregate binding derives credential-required handles, deduplicates, and supports zero-handle no-use", async () => {
  const seen: string[] = [];
  const binding = await createOpenBaoEgressRevocationBinding({
    ...aggregateBase(),
    routePlan: plan(["users/user-a/a", "organizations/org/b", "users/user-a/a"]),
    fetchImpl: async (url) => {
      seen.push(String(url));
      return json(meta(seen.length));
    },
  });
  assert.match(binding.credentialVersion, /^sha256:[a-f0-9]{64}$/);
  assert.equal(binding.credentialVersion.includes("users/user-a"), false);
  assert.deepEqual(seen, [
    "http://127.0.0.1:8200/v1/model/metadata/organizations/org/b",
    "http://127.0.0.1:8200/v1/model/metadata/users/user-a/a",
  ]);
  const second = await binding.source.read(new AbortController().signal);
  assert.notEqual(second.credentialVersion, binding.credentialVersion);

  let tokens = 0;
  let fetches = 0;
  const zero = await createOpenBaoEgressRevocationBinding({
    ...aggregateBase({ identity: { withToken: async () => void tokens++ } }),
    routePlan: plan([], false),
    fetchImpl: async () => {
      fetches++;
      return json(meta(1));
    },
  });
  assert.match(zero.credentialVersion, /^sha256:[a-f0-9]{64}$/);
  assert.equal((await zero.source.read(new AbortController().signal)).credentialVersion, zero.credentialVersion);
  assert.equal(tokens, 0);
  assert.equal(fetches, 0);
});

test("aggregate post-binding revoked member preserves full aggregate and watcher reason revoked", async () => {
  let revokedA = false;
  let malformedB = false;
  const seen: string[] = [];
  const binding = await createOpenBaoEgressRevocationBinding({
    ...aggregateBase(),
    routePlan: plan(["users/user-a/b", "users/user-a/a"]),
    fetchImpl: async (url) => {
      seen.push(String(url));
      if (String(url).endsWith("/a")) return json(meta(1, revokedA ? { deletion_time: "2026-01-01T00:00:00Z" } : {}));
      if (malformedB) return json(meta(1, {}, { data: { ...meta(1).data, versions: {} } }));
      return json(meta(1));
    },
  });
  assert.deepEqual(seen, [
    "http://127.0.0.1:8200/v1/model/metadata/users/user-a/a",
    "http://127.0.0.1:8200/v1/model/metadata/users/user-a/b",
  ]);
  revokedA = true;
  const revoked = await binding.source.read(new AbortController().signal);
  assert.equal(Object.isFrozen(revoked), true);
  assert.equal(revoked.presetRevision, base.presetRevision);
  assert.equal(revoked.credentialVersion, binding.credentialVersion);
  assert.equal(revoked.revoked, true);
  assert.equal(revoked.pkiExpiresAtMs, base.pkiExpiresAtMs);

  revokedA = false;
  const timers = new ManualTimers();
  const calls: string[] = [];
  const watcher = await createCogsEgressRevocationWatcher(
    binding.source,
    {
      denyNew: async (reason) => void calls.push(`denyNew:${reason}`),
      drain: async (reason) => void calls.push(`drain:${reason}`),
      replace: async (reason) => void calls.push(`replace:${reason}`),
    },
    {
      baseline: {
        presetRevision: base.presetRevision,
        credentialVersion: binding.credentialVersion,
        revoked: false,
        pkiExpiresAtMs: base.pkiExpiresAtMs,
      },
      pollIntervalMs: 50,
      minPkiRemainingMs: 1000,
      operationTimeoutMs: 50,
      nowMs: () => 1,
      timers,
    },
  );
  revokedA = true;
  timers.tick(50);
  await flush();
  await flush();
  assert.equal(watcher.ready, false);
  assert.deepEqual(calls, ["denyNew:revoked", "drain:revoked", "replace:revoked"]);

  malformedB = true;
  await assert.rejects(binding.source.read(new AbortController().signal), generic);
});

test("aggregate binding returns credential source coupled to same OpenBao authority and identity", async () => {
  const urls: string[] = [];
  let tokenCalls = 0;
  const binding = await createOpenBaoEgressRevocationBinding({
    ...aggregateBase({
      identity: {
        async withToken(signal, operation) {
          tokenCalls++;
          if (!signal.aborted) await operation("tokensecret");
        },
      },
    }),
    routePlan: plan(["users/user-a/a"]),
    fetchImpl: async (url) => {
      urls.push(String(url));
      return String(url).includes("/data/") ? json(dataSecret("K".repeat(16))) : json(meta(1));
    },
  });
  await binding.credentialSource.withCredential(
    Object.freeze({ integrationId: "provider", secretHandle: "users/user-a/a", authType: "bearer_header" as const }),
    async (credential) => {
      assert.deepEqual(credential, { type: "bearer", token: "K".repeat(16) });
    },
  );
  assert.deepEqual(urls, [
    "http://127.0.0.1:8200/v1/model/metadata/users/user-a/a",
    "http://127.0.0.1:8200/v1/model/data/users/user-a/a",
  ]);
  assert.equal(tokenCalls, 2);
});

test("bound credential source observes lifecycle abort during OpenBao data rendering", async () => {
  const controller = new AbortController();
  let liveCallbacks = 0;
  let dataFetchAborted = false;
  const binding = await createOpenBaoEgressRevocationBinding({
    ...aggregateBase({
      signal: controller.signal,
      identity: {
        async withToken(signal, operation) {
          liveCallbacks++;
          try {
            if (!signal.aborted) await operation("tokensecret");
          } finally {
            liveCallbacks--;
          }
        },
      },
    }),
    routePlan: plan(["users/user-a/a"]),
    fetchImpl: async (url, init) => {
      if (String(url).includes("/metadata/")) return json(meta(1));
      return new Promise<Response>((_resolve, reject) => {
        (init?.signal as AbortSignal | undefined)?.addEventListener(
          "abort",
          () => {
            dataFetchAborted = true;
            reject(new Error(raw));
          },
          { once: true },
        );
      });
    },
  });
  const read = binding.credentialSource.withCredential(
    Object.freeze({ integrationId: "provider", secretHandle: "users/user-a/a", authType: "bearer_header" as const }),
    async () => undefined,
  );
  await flush();
  controller.abort();
  await assert.rejects(read);
  await flush();
  assert.equal(dataFetchAborted, true);
  assert.equal(liveCallbacks, 0);
});

test("aggregate zero-handle binding still validates config and rejects aborted signals", async () => {
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase({ origin: "http://example.com/" }),
      routePlan: plan([], false),
    }),
    generic,
  );
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase({ identity: {} as never }),
      routePlan: plan([], false),
    }),
    generic,
  );
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase({ userId: 123 as never }),
      routePlan: plan([], false),
    }),
    generic,
  );
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase({ presetRevision: 123 as never }),
      routePlan: plan([], false),
    }),
    generic,
  );
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase({ signal: aborted.signal }),
      routePlan: plan([], false),
    }),
    generic,
  );
});

test("aggregate binding fails malformed and unavailable handles generically and leaves no identity callback alive", async () => {
  let live = 0;
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase({
        identity: {
          async withToken(_signal, operation) {
            live++;
            try {
              await operation("tokensecret");
            } finally {
              live--;
            }
          },
        },
      }),
      routePlan: plan(["users/user-a/a", "users/user-a/b"]),
      fetchImpl: async (url) =>
        String(url).endsWith("/b") ? json(meta(1, {}, { data: { ...meta(1).data, versions: {} } })) : json(meta(1)),
    }),
    generic,
  );
  assert.equal(live, 0);
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase(),
      routePlan: plan(["users/user-a/a"]),
      fetchImpl: async () => json(meta(1, {}, { data: { ...meta(1).data, versions: {} } })),
    }),
    generic,
  );
  await assert.rejects(
    createOpenBaoEgressRevocationBinding({
      ...aggregateBase(),
      routePlan: plan(["users/user-a/a"]),
      fetchImpl: async () => response("missing", 404, "text/plain"),
    }),
    generic,
  );
});

test("existing watcher maps OpenBao version, deletion, and source failures to fail-closed transitions", async () => {
  for (const [second, expected] of [
    [json(meta(2)), "credential_changed"],
    [json(meta(1, { destroyed: true })), "revoked"],
    [response("{}", 500), "source_unavailable"],
  ] as const) {
    const timers = new ManualTimers();
    const calls: string[] = [];
    const responses = [json(meta(1)), second];
    const watcher = await createCogsEgressRevocationWatcher(
      src({ fetchImpl: async () => responses.shift() ?? json(meta(1)) }),
      {
        denyNew: async (reason) => void calls.push(`denyNew:${reason}`),
        drain: async (reason) => void calls.push(`drain:${reason}`),
        replace: async (reason) => void calls.push(`replace:${reason}`),
      },
      {
        baseline: { presetRevision: "preset1", credentialVersion: "1", revoked: false, pkiExpiresAtMs: 99_999 },
        pollIntervalMs: 50,
        minPkiRemainingMs: 1000,
        operationTimeoutMs: 50,
        nowMs: () => 1,
        timers,
      },
    );
    timers.tick(50);
    await flush();
    await flush();
    assert.equal(watcher.ready, false);
    assert.deepEqual(calls, [`denyNew:${expected}`, `drain:${expected}`, `replace:${expected}`]);
  }
});

function aggregateBase(patch: Partial<Parameters<typeof createOpenBaoEgressRevocationBinding>[0]> = {}) {
  return {
    origin: base.origin,
    mount: base.mount,
    identity: id(),
    userId: base.userId,
    presetRevision: base.presetRevision,
    pkiExpiresAtMs: base.pkiExpiresAtMs,
    allowLoopbackHttpDevelopment: true,
    timeoutMs: 50,
    maxResponseBytes: 4096,
    ...patch,
  };
}

function plan(handles: readonly string[], credentialRequired = true) {
  return Object.freeze({
    routeCount: Math.max(1, handles.length),
    integrations: Object.freeze(
      handles.map((handle, index) =>
        Object.freeze({
          id: `i${index}`,
          presetRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          auth: Object.freeze({
            type: "bearer_header" as const,
            header: "Authorization",
            prefix: "Bearer ",
            placeholder: "COGS_PLACEHOLDER_TOKEN",
            secretHandle: handle,
          }),
          routes: Object.freeze([
            Object.freeze({
              integrationId: `i${index}`,
              ruleName: "r",
              routeId: `r${index}`,
              host: "example.com",
              port: 443,
              method: "GET",
              pathPattern: "/",
              pathStrategy: "exact" as const,
              queryPolicy: Object.freeze({ mode: "deny" as const }),
              pathMatch: Object.freeze({ kind: "safe_regex" as const, value: "^/$" }),
              injectAuth: credentialRequired,
              credentialRequired,
            }),
          ]),
        }),
      ),
    ),
  });
}

function src(patch: Partial<ConstructorParameters<typeof OpenBaoEgressRevocationSource>[0]> = {}) {
  return new OpenBaoEgressRevocationSource({
    ...base,
    identity: patch.identity ?? id(),
    fetchImpl: patch.fetchImpl ?? (async () => json(meta(1))),
    ...patch,
  });
}
function id(): OpenBaoIdentityPort {
  return {
    withToken: async (signal, operation) => (signal.aborted ? undefined : void (await operation("tokensecret"))),
  };
}
function meta(current: number, entry: Partial<ReturnType<typeof version>> = {}, patch: Record<string, unknown> = {}) {
  const data = {
    cas_required: false,
    created_time: "2026-01-01T00:00:00Z",
    current_metadata_version: 0,
    current_version: current,
    custom_metadata: null,
    delete_version_after: "0s",
    max_versions: 0,
    metadata_cas_required: false,
    oldest_version: 0,
    updated_time: "2026-01-01T00:00:00Z",
    versions: { [String(current)]: { ...version(), ...entry } },
  };
  return {
    request_id: "req",
    lease_id: "",
    renewable: false,
    lease_duration: 0,
    data,
    wrap_info: null,
    warnings: null,
    auth: null,
    mount_type: "kv",
    ...patch,
  };
}
function version() {
  return { created_time: "2026-01-01T00:00:00Z", deletion_time: "", destroyed: false };
}
function manyVersions(count: number) {
  return Object.fromEntries(Array.from({ length: count }, (_, index) => [String(index + 1), version()]));
}
function json(value: unknown) {
  return response(JSON.stringify(value), 200);
}
function dataSecret(apiKey: string) {
  return {
    request_id: "req",
    lease_id: "",
    renewable: false,
    lease_duration: 0,
    data: {
      data: { api_key: apiKey },
      metadata: {
        created_time: "2026-01-01T00:00:00Z",
        deletion_time: "",
        destroyed: false,
        version: 1,
        custom_metadata: null,
      },
    },
    wrap_info: null,
    warnings: null,
    auth: null,
    mount_type: "kv",
  };
}
function response(text: string, status = 200, type = "application/json", cancel?: () => void | Promise<void>) {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(text));
      controller.close();
    },
    ...(cancel === undefined ? {} : { cancel }),
  });
  return new Response(stream, {
    status,
    headers: { "content-type": type, "content-length": String(Buffer.byteLength(text)) },
  });
}
function badLengthResponse(text: string) {
  return new Response(text, { status: 200, headers: { "content-type": "application/json", "content-length": "nan" } });
}
function readerFailureResponse() {
  return new Response(
    new ReadableStream<Uint8Array>({
      pull() {
        throw new Error(raw);
      },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}
function streamingResponse(chunk: Uint8Array, cancel: () => void) {
  let sent = false;
  return new Response(
    new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!sent) {
          sent = true;
          controller.enqueue(chunk);
        }
      },
      cancel,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}
async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
}
class ManualTimers {
  private queue: Array<() => void> = [];
  setTimeout(callback: () => void) {
    this.queue.push(callback);
    return callback;
  }
  clearTimeout(timer: unknown) {
    this.queue = this.queue.filter((item) => item !== timer);
  }
  tick(_ms: number) {
    this.queue.shift()?.();
  }
}
