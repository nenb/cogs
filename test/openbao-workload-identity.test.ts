import assert from "node:assert/strict";
import { chmod, link, mkdtemp, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  OpenBaoKubernetesWorkloadIdentity,
  type OpenBaoKubernetesWorkloadIdentityOptions,
  OpenBaoWorkloadIdentityError,
} from "../src/auth/openbao-workload-identity.ts";
import type { TrustedFileCaptureOptions } from "../src/runtime/trusted-files.ts";

const uid = process.getuid?.() ?? -1;
const gid = process.getgid?.() ?? -1;
const jwtOne = `${"a".repeat(24)}.${"b".repeat(24)}.${"c".repeat(24)}`;
const jwtTwo = `${"d".repeat(24)}.${"e".repeat(24)}.${"f".repeat(24)}`;
const clientToken = "hvs.production-token-value";

async function jwtFixture(value = jwtOne) {
  const created = await mkdtemp(join(tmpdir(), "cogs-openbao-jwt-"));
  const root = await realpath(created);
  const path = join(root, "jwt");
  await writeFile(path, value, { mode: 0o600 });
  await chmod(path, 0o600);
  const options = (): TrustedFileCaptureOptions => ({
    path,
    minimumBytes: 26,
    maximumBytes: 16 * 1024,
    allowedModes: [0o600],
    allowedUids: [uid],
    allowedGids: [gid],
  });
  return { root, path, options, close: () => rm(root, { recursive: true, force: true }) };
}

function loginBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    request_id: "request-id",
    lease_id: "",
    renewable: false,
    lease_duration: 0,
    data: null,
    wrap_info: null,
    warnings: null,
    auth: {
      client_token: clientToken,
      accessor: "accessor-value",
      policies: ["default", "cogs-worker"],
      token_policies: ["default", "cogs-worker"],
      identity_policies: [],
      metadata: { service_account_name: "cogs-worker", service_account_namespace: "cogs" },
      lease_duration: 600,
      renewable: false,
      entity_id: "entity-id",
      token_type: "service",
      orphan: true,
      mfa_requirement: null,
      num_uses: 0,
      ...overrides,
    },
    mount_type: "kubernetes",
  });
}

function options(
  jwtFile: TrustedFileCaptureOptions,
  fetchImpl: typeof fetch,
  extra: Partial<OpenBaoKubernetesWorkloadIdentityOptions> = {},
): OpenBaoKubernetesWorkloadIdentityOptions {
  return {
    origin: "https://openbao.internal:8200/",
    authMount: "kubernetes-cogs",
    role: "cogs-worker",
    jwtFile,
    fetchImpl,
    ...extra,
  };
}

async function rejects(operation: Promise<unknown>, forbidden: readonly string[] = []): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof OpenBaoWorkloadIdentityError);
    assert.equal(error.message, "OpenBao workload identity unavailable");
    const text = String(error.stack ?? error);
    for (const value of forbidden) assert.equal(text.includes(value), false, `leaked ${value}`);
    return true;
  });
}

test("workload identity performs one exact HTTPS Kubernetes login and scopes the returned token", async () => {
  const item = await jwtFixture();
  let callbackCalls = 0;
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  try {
    const identity = new OpenBaoKubernetesWorkloadIdentity(
      options(item.options(), async (url, init) => {
        requestUrl = String(url);
        requestInit = init;
        return new Response(loginBody(), { status: 200, headers: { "content-type": "application/json" } });
      }),
    );
    await identity.withToken(new AbortController().signal, async (token) => {
      callbackCalls += 1;
      assert.equal(token, clientToken);
    });
    assert.equal(callbackCalls, 1);
    assert.equal(requestUrl, "https://openbao.internal:8200/v1/auth/kubernetes-cogs/login");
    assert.ok(requestInit);
    assert.equal(requestInit.method, "POST");
    assert.equal(requestInit.redirect, "error");
    assert.ok(requestInit.signal instanceof AbortSignal);
    assert.deepEqual(JSON.parse(String(requestInit.body)), { role: "cogs-worker", jwt: jwtOne });
    const headers = requestInit.headers as Record<string, string>;
    assert.equal(headers["content-type"], "application/json");
    assert.equal(headers["content-length"], String(Buffer.byteLength(String(requestInit.body))));
  } finally {
    await item.close();
  }
});

test("workload identity rereads the trusted JWT on every login so projected-token rotation is honored", async () => {
  const item = await jwtFixture();
  const observed: string[] = [];
  try {
    const identity = new OpenBaoKubernetesWorkloadIdentity(
      options(item.options(), async (_url, init) => {
        observed.push((JSON.parse(String(init?.body)) as { jwt: string }).jwt);
        return new Response(loginBody(), { status: 200, headers: { "content-type": "application/json" } });
      }),
    );
    await identity.withToken(new AbortController().signal, async () => undefined);
    await writeFile(item.path, jwtTwo);
    await chmod(item.path, 0o600);
    await identity.withToken(new AbortController().signal, async () => undefined);
    assert.deepEqual(observed, [jwtOne, jwtTwo]);
  } finally {
    await item.close();
  }
});

test("workload identity rejects non-HTTPS, noncanonical origins and malformed mount or role configuration", async () => {
  const item = await jwtFixture();
  const fetchImpl = async () =>
    new Response(loginBody(), { status: 200, headers: { "content-type": "application/json" } });
  try {
    for (const origin of [
      "http://openbao.internal/",
      "https://user@openbao.internal/",
      "https://openbao.internal/base",
      "https://openbao.internal/?x=1",
      "https://openbao.internal/#x",
      "https://OPENBAO.internal/",
      "https://openbao.internal",
    ])
      assert.throws(
        () => new OpenBaoKubernetesWorkloadIdentity(options(item.options(), fetchImpl, { origin })),
        OpenBaoWorkloadIdentityError,
      );
    for (const authMount of ["", "bad/mount", "_mount", "a".repeat(65)])
      assert.throws(
        () => new OpenBaoKubernetesWorkloadIdentity(options(item.options(), fetchImpl, { authMount })),
        OpenBaoWorkloadIdentityError,
      );
    for (const role of ["", "_role", "bad/role", "a".repeat(129)])
      assert.throws(
        () => new OpenBaoKubernetesWorkloadIdentity(options(item.options(), fetchImpl, { role })),
        OpenBaoWorkloadIdentityError,
      );

    let trapCalls = 0;
    const hostileOptions = new Proxy(options(item.options(), fetchImpl), {
      getPrototypeOf() {
        trapCalls += 1;
        return Object.prototype;
      },
    });
    assert.throws(() => new OpenBaoKubernetesWorkloadIdentity(hostileOptions), OpenBaoWorkloadIdentityError);
    const hostileJwtFile = new Proxy(item.options(), {
      ownKeys() {
        trapCalls += 1;
        return [];
      },
    });
    assert.throws(
      () => new OpenBaoKubernetesWorkloadIdentity(options(hostileJwtFile, fetchImpl)),
      OpenBaoWorkloadIdentityError,
    );
    const hostileFetch = new Proxy(fetchImpl, {
      apply() {
        trapCalls += 1;
        return Promise.reject(new Error("unexpected fetch"));
      },
    });
    assert.throws(
      () => new OpenBaoKubernetesWorkloadIdentity(options(item.options(), hostileFetch)),
      OpenBaoWorkloadIdentityError,
    );
    assert.equal(trapCalls, 0);
  } finally {
    await item.close();
  }
});

test("pre-abort, caller abort, and login timeout fail closed without callback or fallback", async () => {
  const item = await jwtFixture();
  let fetchCalls = 0;
  let callbackCalls = 0;
  const hangingFetch: typeof fetch = async (_url, init) => {
    fetchCalls += 1;
    return await new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal;
      const abort = () => reject(new Error(`${jwtOne} ${clientToken}`));
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
    });
  };
  try {
    const preAborted = new AbortController();
    preAborted.abort();
    const identity = new OpenBaoKubernetesWorkloadIdentity(options(item.options(), hangingFetch, { timeoutMs: 20 }));
    await rejects(
      identity.withToken(preAborted.signal, async () => {
        callbackCalls += 1;
      }),
      [jwtOne, clientToken, item.path],
    );
    assert.equal(fetchCalls, 0);

    const caller = new AbortController();
    const pending = identity.withToken(caller.signal, async () => {
      callbackCalls += 1;
    });
    setTimeout(() => caller.abort(), 5);
    await rejects(pending, [jwtOne, clientToken, item.path]);

    await rejects(
      identity.withToken(new AbortController().signal, async () => {
        callbackCalls += 1;
      }),
      [jwtOne, clientToken, item.path],
    );
    assert.equal(fetchCalls, 2);

    const held = Promise.withResolvers<Response>();
    const entered = Promise.withResolvers<void>();
    const ignoringFetch: typeof fetch = async () => {
      entered.resolve();
      return held.promise;
    };
    const ignoringIdentity = new OpenBaoKubernetesWorkloadIdentity(
      options(item.options(), ignoringFetch, { timeoutMs: 5 }),
    );
    const actual = ignoringIdentity.withToken(new AbortController().signal, async () => {
      callbackCalls += 1;
    });
    let retired = false;
    const rejected = rejects(actual, [jwtOne, clientToken, item.path]).then(() => {
      retired = true;
    });
    await entered.promise;
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(retired, false);
    held.resolve(new Response(loginBody(), { headers: { "content-type": "application/json" } }));
    await rejected;

    const hangingBody = new ReadableStream<Uint8Array>({
      async pull() {
        await new Promise<void>(() => undefined);
      },
    });
    const hangingBodyIdentity = new OpenBaoKubernetesWorkloadIdentity(
      options(
        item.options(),
        async () => new Response(hangingBody, { status: 200, headers: { "content-type": "application/json" } }),
        { timeoutMs: 5 },
      ),
    );
    await rejects(
      hangingBodyIdentity.withToken(new AbortController().signal, async () => {
        callbackCalls += 1;
      }),
      [jwtOne, clientToken, item.path],
    );
    assert.equal(callbackCalls, 0);
  } finally {
    await item.close();
  }
});

test("hostile login status, headers, bounds, JSON, token, TTL, and envelope fields fail generically", async () => {
  const item = await jwtFixture();
  const hostile: Array<() => Response> = [
    () => new Response(loginBody(), { status: 403, headers: { "content-type": "application/json" } }),
    () => new Response(loginBody(), { status: 200, headers: { "content-type": "text/plain" } }),
    () => new Response(loginBody(), { status: 200, headers: { "content-type": "application/json;invalid" } }),
    () =>
      new Response(loginBody(), {
        status: 200,
        headers: { "content-type": "application/json", "content-length": "99999" },
      }),
    () => new Response("not-json", { status: 200, headers: { "content-type": "application/json" } }),
    () =>
      new Response(loginBody().replace('"auth":{', '"auth":null,"auth":{'), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(loginBody().replace('"client_token":', '"client_token":"shadowed","client_token":'), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(JSON.stringify({ auth: null }), { status: 200, headers: { "content-type": "application/json" } }),
    () =>
      new Response(loginBody({ client_token: "bad token" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(loginBody({ lease_duration: 601 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(loginBody({ token_type: "default-service" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(loginBody({ unexpected: true }), { status: 200, headers: { "content-type": "application/json" } }),
    () =>
      new Response(loginBody({ mfa_requirement: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(JSON.stringify({ ...JSON.parse(loginBody()), unexpected: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () => new Response("x".repeat(513), { status: 200, headers: { "content-type": "application/json" } }),
  ];
  try {
    for (const response of hostile) {
      let called = false;
      const identity = new OpenBaoKubernetesWorkloadIdentity(
        options(item.options(), async () => response(), { maxResponseBytes: 512 }),
      );
      await rejects(
        identity.withToken(new AbortController().signal, async () => {
          called = true;
        }),
        [jwtOne, clientToken, item.path, "openbao.internal"],
      );
      assert.equal(called, false);
    }
  } finally {
    await item.close();
  }
});

test("workload login joins original cancellation on abort, malformed and late response exits", async () => {
  const item = await jwtFixture();
  try {
    for (const mode of ["body", "invalid", "late", "headers", "read", "cancel-reject"] as const) {
      const held = Promise.withResolvers<void>();
      const reading = Promise.withResolvers<{ done: true; value: undefined }>();
      const fetched = Promise.withResolvers<Response>();
      const entered = Promise.withResolvers<void>();
      const cancelling = Promise.withResolvers<void>();
      const controller = new AbortController();
      let cancellations = 0;
      let retired = false;
      let consumed = false;
      const response = new Response(
        new ReadableStream({
          start(stream) {
            stream.enqueue(new TextEncoder().encode("{"));
          },
          cancel() {
            cancellations++;
            cancelling.resolve();
            controller.abort();
            return held.promise;
          },
        }),
        { status: mode === "invalid" ? 503 : 200, headers: { "content-type": "application/json" } },
      );
      if (mode === "headers")
        Object.defineProperty(response, "headers", {
          get() {
            throw new Error(clientToken);
          },
        });
      if (mode === "read")
        Object.defineProperty(response, "body", {
          value: {
            getReader: () => ({
              read: () => reading.promise,
              cancel: () => {
                cancellations++;
                cancelling.resolve();
                return held.promise;
              },
              releaseLock: () => undefined,
            }),
          },
        });
      const identity = new OpenBaoKubernetesWorkloadIdentity(
        options(item.options(), async () => {
          entered.resolve();
          return mode === "late" ? fetched.promise : response;
        }),
      );
      const actual = rejects(
        identity.withToken(controller.signal, async () => {
          consumed = true;
        }),
        [jwtOne, clientToken],
      );
      void actual.then(() => {
        retired = true;
      });
      await entered.promise;
      await new Promise((resolve) => setImmediate(resolve));
      controller.abort();
      fetched.resolve(response);
      await cancelling.promise;
      await new Promise((resolve) => setImmediate(resolve));
      try {
        assert.equal(retired, false);
        assert.equal(consumed, false);
        assert.equal(cancellations, 1);
      } finally {
        if (mode === "cancel-reject") held.reject(new Error(clientToken));
        else held.resolve();
      }
      if (mode === "read") {
        await new Promise((resolve) => setImmediate(resolve));
        assert.equal(retired, false, "cancellation is not original read settlement");
        reading.resolve({ done: true, value: undefined });
      }
      await actual;
      assert.equal(cancellations, 1);
    }
  } finally {
    await item.close();
  }
});

test("trusted JWT capture rejects malformed bytes, symlinks, hard links, and wrong modes before login", async () => {
  const cases: Array<(item: Awaited<ReturnType<typeof jwtFixture>>) => Promise<TrustedFileCaptureOptions>> = [
    async (item) => {
      await writeFile(item.path, "not-a-jwt");
      return item.options();
    },
    async (item) => {
      await chmod(item.path, 0o644);
      return item.options();
    },
    async (item) => {
      await link(item.path, join(item.root, "jwt-link"));
      return item.options();
    },
    async (item) => {
      const target = join(item.root, "target");
      await writeFile(target, jwtOne, { mode: 0o600 });
      await unlink(item.path);
      await symlink(target, item.path);
      return item.options();
    },
  ];
  for (const mutate of cases) {
    const item = await jwtFixture();
    let fetchCalls = 0;
    try {
      const jwtFile = await mutate(item);
      const identity = new OpenBaoKubernetesWorkloadIdentity(
        options(jwtFile, async () => {
          fetchCalls += 1;
          return new Response(loginBody(), { status: 200, headers: { "content-type": "application/json" } });
        }),
      );
      await rejects(
        identity.withToken(new AbortController().signal, async () => undefined),
        [item.path, jwtOne],
      );
      assert.equal(fetchCalls, 0);
    } finally {
      await item.close();
    }
  }
});

test("fetch and callback failures cannot leak JWT, client token, role, origin, or file path", async () => {
  const item = await jwtFixture();
  try {
    const fetchFailure = new OpenBaoKubernetesWorkloadIdentity(
      options(item.options(), async () => {
        throw new Error(`${jwtOne} ${clientToken} cogs-worker https://openbao.internal:8200/ ${item.path}`);
      }),
    );
    await rejects(
      fetchFailure.withToken(new AbortController().signal, async () => undefined),
      [jwtOne, clientToken, "cogs-worker", "openbao.internal", item.path],
    );

    const callbackFailure = new OpenBaoKubernetesWorkloadIdentity(
      options(
        item.options(),
        async () => new Response(loginBody(), { status: 200, headers: { "content-type": "application/json" } }),
      ),
    );
    await rejects(
      callbackFailure.withToken(new AbortController().signal, async (token) => {
        throw new Error(`${jwtOne} ${token} ${item.path}`);
      }),
      [jwtOne, clientToken, item.path],
    );
  } finally {
    await item.close();
  }
});
