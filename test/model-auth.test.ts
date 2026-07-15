import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import {
  DevelopmentModelApiKeySource,
  DisabledOAuthBrokerClient,
  type ModelApiKeySource,
  ModelAuthError,
  ModelCredentialResolver,
  type OAuthAccessMaterial,
  type OAuthBrokerClient,
  type OpenBaoIdentityPort,
  OpenBaoModelApiKeyStore,
} from "../src/auth/model-auth.ts";

const key = "aaaaaaaa";
const token = "bbbbbbbb";
const request = {
  userId: "alice",
  provider: "anthropic",
  model: "claude/sonnet",
  credentialHandle: "users/alice/anthropic",
};

async function withActualCi<T>(value: string | undefined, operation: () => T | Promise<T>): Promise<T> {
  const original = process.env.CI;
  try {
    if (value === undefined) delete process.env.CI;
    else process.env.CI = value;
    return await operation();
  } finally {
    if (original === undefined) delete process.env.CI;
    else process.env.CI = original;
  }
}

class StaticIdentity implements OpenBaoIdentityPort {
  public calls = 0;
  public constructor(private readonly value = token) {}
  public async withToken(_signal: AbortSignal, operation: (token: string) => Promise<void>): Promise<void> {
    this.calls += 1;
    let held = this.value;
    try {
      await operation(held);
    } finally {
      held = "";
    }
  }
}

async function fixture(handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>) {
  const server = createServer((request, response) => void handler(request, response));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function body(api_key = key): string {
  return JSON.stringify({
    request_id: "req",
    lease_id: "",
    renewable: false,
    lease_duration: 0,
    data: {
      data: { api_key },
      metadata: {
        created_time: "2026-07-15T00:00:00Z",
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
  });
}

function store(
  origin: string,
  identity: OpenBaoIdentityPort = new StaticIdentity(),
  extra: Partial<ConstructorParameters<typeof OpenBaoModelApiKeyStore>[0]> = {},
) {
  return new OpenBaoModelApiKeyStore({
    origin: `${origin}/`,
    mount: "kv",
    identity,
    allowLoopbackHttpDevelopment: true,
    ...extra,
  });
}

async function resolve(
  source: { withApiKey: (typeofRequest: typeof request, op: (apiKey: string) => Promise<void>) => Promise<void> },
  input = request,
): Promise<string> {
  let result = "";
  await source.withApiKey(input, async (apiKey) => {
    result = apiKey;
  });
  return result;
}

async function assertAuthRejects(operation: Promise<unknown>, forbidden: string[] = []): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof ModelAuthError);
    const text = String(error.stack ?? error);
    for (const value of forbidden) assert.equal(text.includes(value), false, `leaked ${value}`);
    assert.equal(text, text.replace(/127\.0\.0\.1|bbbbbbbb|aaaaaaaa|users\/alice|dddddddd|anthropic/g, ""));
    return true;
  });
}

test("OpenBao uses callback-scoped identity/key and exact encoded KV-v2 path", async () => {
  let seenPath = "";
  let seenToken = "";
  const app = await fixture((req, res) => {
    seenPath = req.url ?? "";
    seenToken = String(req.headers["x-vault-token"] ?? "");
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    const identity = new StaticIdentity();
    const source = store(app.origin, identity);
    const resolver = new ModelCredentialResolver(source);
    assert.equal(await resolver.withApiKey(request, async (apiKey) => `seen:${apiKey.slice(0, 2)}`), "seen:aa");
    assert.equal(seenPath, "/v1/kv/data/users/alice/anthropic");
    assert.equal(seenToken, token);
    assert.equal(identity.calls, 1);
    await assertAuthRejects(
      resolver.withApiKey(request, async () => {
        throw new Error(`${key} ${token} ${app.origin}`);
      }),
      [key, token, app.origin],
    );
  } finally {
    await app.close();
  }
});

test("pre-aborted requests fail before identity and callbacks", async () => {
  const identity = new StaticIdentity();
  const controller = new AbortController();
  controller.abort();
  const app = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    let called = false;
    await assertAuthRejects(
      store(app.origin, identity).withApiKey({ ...request, signal: controller.signal }, async () => {
        called = true;
      }),
      [key, token, app.origin],
    );
    assert.equal(identity.calls, 0);
    assert.equal(called, false);
  } finally {
    await app.close();
  }
});

test("OpenBao handle, user, origin, mount, provider, and model validation fail closed", async () => {
  for (const origin of [
    "http://example.com/",
    "https://user@example.com/",
    "https://example.com/base",
    "https://example.com/?x=1",
    "https://example.com/#x",
  ]) {
    assert.throws(
      () =>
        new OpenBaoModelApiKeyStore({
          origin,
          mount: "kv",
          identity: new StaticIdentity(),
          allowLoopbackHttpDevelopment: true,
        }),
      ModelAuthError,
    );
  }
  assert.throws(
    () =>
      new OpenBaoModelApiKeyStore({
        origin: "http://127.0.0.1:1/",
        mount: "bad/mount",
        identity: new StaticIdentity(),
        allowLoopbackHttpDevelopment: true,
      }),
    ModelAuthError,
  );
  const app = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    const source = store(app.origin);
    for (const bad of [
      { credentialHandle: "sessions/a/a" },
      { credentialHandle: "users/bob/anthropic" },
      { credentialHandle: "users/alice/../anthropic" },
      { credentialHandle: "users/alice/%2e%2e/anthropic" },
      { credentialHandle: "users//alice" },
      { credentialHandle: `users/alice/${"a/".repeat(9)}x` },
      { credentialHandle: `users/alice/${"a".repeat(513)}` },
      { credentialHandle: "organizations" },
      { credentialHandle: "bad/a/a" },
      { userId: "_alice" },
      { provider: "_anthropic" },
      { provider: "anthropic/evil" },
      { model: "\nmodel" },
    ])
      await assertAuthRejects(resolve(source, { ...request, ...bad }), [app.origin, key, token]);
    assert.equal(await resolve(source, { ...request, credentialHandle: "organizations/a/a" }), key);
  } finally {
    await app.close();
  }
});

test("OpenBao hostile HTTP status, headers, bodies, chunks, redirect, abort, and malicious errors are generic", async () => {
  const cases: Array<{ name: string; handler: (req: IncomingMessage, res: ServerResponse) => void }> = [
    {
      name: "403",
      handler: (_req, res) => {
        res.writeHead(403, { "content-type": "application/json" }).end("dddddddd");
      },
    },
    {
      name: "429",
      handler: (_req, res) => {
        res.writeHead(429).end("dddddddd");
      },
    },
    {
      name: "500",
      handler: (_req, res) => {
        res.writeHead(500).end("dddddddd");
      },
    },
    {
      name: "type",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" }).end(body());
      },
    },
    {
      name: "length",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json", "content-length": "9999" }).end(body());
      },
    },
    {
      name: "shape",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            data: {
              api_key: key,
              metadata: {
                created_time: "2026-07-15T00:00:00Z",
                deletion_time: "",
                destroyed: false,
                version: 1,
                custom_metadata: null,
              },
            },
          }),
        );
      },
    },
    {
      name: "extra",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            data: {
              data: { api_key: key, refresh_token: "dddddddd" },
              metadata: {
                created_time: "2026-07-15T00:00:00Z",
                deletion_time: "",
                destroyed: false,
                version: 1,
                custom_metadata: null,
              },
            },
          }),
        );
      },
    },
    {
      name: "array",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            data: {
              data: [{ api_key: key }],
              metadata: {
                created_time: "2026-07-15T00:00:00Z",
                deletion_time: "",
                destroyed: false,
                version: 1,
                custom_metadata: null,
              },
            },
          }),
        );
      },
    },
    {
      name: "badjson",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" }).end("{");
      },
    },
    {
      name: "oversize",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.write("x".repeat(300));
        res.end("x".repeat(300));
      },
    },
    {
      name: "invalid-utf8",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(Buffer.from([0xff, 0xfe]));
      },
    },
    {
      name: "redirect",
      handler: (_req, res) => {
        res.writeHead(302, { location: "https://example.com/" }).end();
      },
    },
  ];
  for (const item of cases) {
    const app = await fixture(item.handler);
    try {
      await assertAuthRejects(resolve(store(app.origin, new StaticIdentity(), { maxResponseBytes: 512 })), [
        key,
        token,
        "dddddddd",
        app.origin,
      ]);
    } finally {
      await app.close();
    }
  }
  const split = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const bytes = Buffer.from(body("boundary-key-1234"));
    res.write(bytes.subarray(0, 7));
    res.end(bytes.subarray(7));
  });
  try {
    assert.equal(await resolve(store(split.origin)), "boundary-key-1234");
  } finally {
    await split.close();
  }
  const slow = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    setTimeout(() => res.end(body()), 100);
  });
  try {
    await assertAuthRejects(resolve(store(slow.origin, new StaticIdentity(), { timeoutMs: 10 })), [
      slow.origin,
      key,
      token,
    ]);
  } finally {
    await slow.close();
  }
  const app = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    const badIdentity: OpenBaoIdentityPort = {
      withToken: async () => {
        throw new Error(`${token} ${key} ${app.origin}`);
      },
    };
    await assertAuthRejects(resolve(store(app.origin, badIdentity)), [token, key, app.origin]);
    const badFetch: typeof fetch = async () => {
      throw new Error(`${token} ${key} ${app.origin}`);
    };
    await assertAuthRejects(resolve(store(app.origin, new StaticIdentity(), { fetchImpl: badFetch })), [
      token,
      key,
      app.origin,
    ]);
  } finally {
    await app.close();
  }
});

test("API key limits, controls, unicode, and resolver validation for custom sources", async () => {
  for (const api_key of ["short", "a".repeat(8193), "valid\ncontrol", "🔑".repeat(3000)]) {
    const app = await fixture((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" }).end(body(api_key));
    });
    try {
      await assertAuthRejects(resolve(store(app.origin, new StaticIdentity(), { maxResponseBytes: 64 * 1024 })), [
        api_key.slice(0, 16),
        app.origin,
        token,
      ]);
    } finally {
      await app.close();
    }
  }
  const unicode = "é".repeat(4);
  const app = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body(unicode));
  });
  try {
    assert.equal(await resolve(store(app.origin)), unicode);
  } finally {
    await app.close();
  }
  const custom = {
    withApiKey: async <T>(_request: typeof request, operation: (apiKey: string) => Promise<T>) => operation("bad\nkey"),
  };
  await assertAuthRejects(new ModelCredentialResolver(custom).withApiKey(request, async () => "bad"));
});

test("development source is explicit, request-bound, CI-closed, and not an OpenBao fallback", async () => {
  assert.throws(
    () =>
      new DevelopmentModelApiKeySource({
        developmentMode: false,
        envName: "MODEL_KEY",
        userId: "alice",
        provider: "anthropic",
        model: "claude/sonnet",
        credentialHandle: "users/alice/anthropic",
        env: { MODEL_KEY: key },
      }),
    ModelAuthError,
  );
  assert.throws(
    () =>
      new DevelopmentModelApiKeySource({
        developmentMode: true,
        envName: "MODEL_KEY",
        userId: "alice",
        provider: "anthropic",
        model: "claude/sonnet",
        credentialHandle: "users/alice/anthropic",
        env: { CI: "true", MODEL_KEY: key },
      }),
    ModelAuthError,
  );
  await withActualCi("true", async () => {
    assert.throws(
      () =>
        new DevelopmentModelApiKeySource({
          developmentMode: true,
          envName: "MODEL_KEY",
          userId: "alice",
          provider: "anthropic",
          model: "claude/sonnet",
          credentialHandle: "users/alice/anthropic",
          env: { MODEL_KEY: key },
        }),
      ModelAuthError,
    );
  });
  await withActualCi(undefined, async () => {
    assert.throws(() => {
      const hostileEnv = Object.create(null, {
        CI: {
          enumerable: true,
          get: () => {
            throw new Error(`${key} hostile ci`);
          },
        },
        MODEL_KEY: { enumerable: true, value: key },
      }) as Record<string, string | undefined>;
      return new DevelopmentModelApiKeySource({
        developmentMode: true,
        envName: "MODEL_KEY",
        userId: "alice",
        provider: "anthropic",
        model: "claude/sonnet",
        credentialHandle: "users/alice/anthropic",
        env: hostileEnv,
      });
    }, ModelAuthError);
    assert.throws(
      () =>
        new DevelopmentModelApiKeySource({
          developmentMode: true,
          envName: "bad-name",
          userId: "alice",
          provider: "anthropic",
          model: "claude/sonnet",
          credentialHandle: "users/alice/anthropic",
          env: { "bad-name": key },
        }),
      ModelAuthError,
    );
    const source = new DevelopmentModelApiKeySource({
      developmentMode: true,
      envName: "MODEL_KEY",
      userId: "alice",
      provider: "anthropic",
      model: "claude/sonnet",
      credentialHandle: "users/alice/anthropic",
      env: { MODEL_KEY: key, OTHER_KEY: "cccccccc" },
    });
    assert.equal(await resolve(source), key);
    for (const bad of [
      { provider: "openai" },
      { model: "other/model" },
      { userId: "bob" },
      { credentialHandle: "users/alice/other" },
    ])
      await assertAuthRejects(resolve(source, { ...request, ...bad }), [key, "OTHER_KEY"]);
    const missing = new DevelopmentModelApiKeySource({
      developmentMode: true,
      envName: "MODEL_KEY",
      userId: "alice",
      provider: "anthropic",
      model: "claude/sonnet",
      credentialHandle: "users/alice/anthropic",
      env: { OTHER_KEY: "cccccccc" },
    });
    await assertAuthRejects(resolve(missing), ["OTHER_KEY", "cccccccc"]);
    await assertAuthRejects(
      resolve(
        new OpenBaoModelApiKeyStore({
          origin: "http://127.0.0.1:9/",
          mount: "kv",
          identity: new StaticIdentity(),
          allowLoopbackHttpDevelopment: true,
          timeoutMs: 10,
        }),
      ),
      [key, "MODEL_KEY"],
    );
  });
});

test("OAuth production gate is disabled and exposes no refresh token field", async () => {
  const client = new DisabledOAuthBrokerClient();
  await assertAuthRejects(client.getAccessMaterial({ userId: "alice", provider: "anthropic", model: "claude" }));
  await assertAuthRejects(client.invalidateAccessMaterial("ref"));
  await assertAuthRejects(client.getExpiry("ref"));
  assert.equal(
    (
      ["reference", "provider", "model", "accessToken", "expiresAt"] satisfies Array<
        keyof OAuthAccessMaterial
      > as string[]
    ).includes("refreshToken"),
    false,
  );
});

class FakeBroker implements OAuthBrokerClient {
  public outage = false;
  public now = 0;
  public refreshes = 0;
  readonly #entries = new Map<string, OAuthAccessMaterial>();
  readonly #revoked = new Set<string>();
  readonly #pending = new Map<string, Promise<OAuthAccessMaterial>>();
  public async getAccessMaterial(input: {
    userId: string;
    provider: string;
    model: string;
  }): Promise<OAuthAccessMaterial> {
    const key = `${input.userId}|${input.provider}|${input.model}`;
    if (this.outage || this.#revoked.has(key)) throw new ModelAuthError();
    const current = this.#entries.get(key);
    if (current && Date.parse(current.expiresAt) > this.now) return current;
    let pending = this.#pending.get(key);
    if (!pending) {
      pending = (async () => {
        this.refreshes += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        const material = {
          reference: `ref:${key}:${this.refreshes}`,
          provider: input.provider,
          model: input.model,
          accessToken: `access:${key}:${this.refreshes}`,
          expiresAt: new Date(this.now + 1000).toISOString(),
        };
        this.#entries.set(key, material);
        this.#pending.delete(key);
        return material;
      })();
      this.#pending.set(key, pending);
    }
    return pending;
  }
  public async invalidateAccessMaterial(reference: string): Promise<void> {
    const found = [...this.#entries].find(([, value]) => value.reference === reference);
    if (!found) throw new ModelAuthError();
    this.#revoked.add(found[0]);
    this.#entries.delete(found[0]);
  }
  public async getExpiry(reference: string): Promise<string> {
    if (this.outage) throw new ModelAuthError();
    const found = [...this.#entries.values()].find((entry) => entry.reference === reference);
    if (!found) throw new ModelAuthError();
    return found.expiresAt;
  }
}

test("test fake broker serializes per identity, refreshes on expiry, isolates identities, revokes, and has no refresh material", async () => {
  const broker = new FakeBroker();
  const concurrent = await Promise.all(
    Array.from({ length: 4 }, () =>
      broker.getAccessMaterial({ userId: "alice", provider: "anthropic", model: "claude" }),
    ),
  );
  assert.equal(new Set(concurrent.map((item) => item.reference)).size, 1);
  assert.equal(broker.refreshes, 1);
  const bob = await broker.getAccessMaterial({ userId: "bob", provider: "anthropic", model: "claude" });
  assert.notEqual(bob.reference, concurrent[0]?.reference);
  assert.equal(broker.refreshes, 2);
  broker.now = 2000;
  const refreshed = await broker.getAccessMaterial({ userId: "alice", provider: "anthropic", model: "claude" });
  assert.notEqual(refreshed.reference, concurrent[0]?.reference);
  assert.equal(broker.refreshes, 3);
  assert.equal(await broker.getExpiry(refreshed.reference), refreshed.expiresAt);
  assert.equal(
    Object.keys(refreshed).some((name) => /refresh/i.test(name)),
    false,
  );
  broker.outage = true;
  await assertAuthRejects(broker.getAccessMaterial({ userId: "alice", provider: "anthropic", model: "claude" }));
  broker.outage = false;
  await broker.invalidateAccessMaterial(refreshed.reference);
  await assertAuthRejects(broker.getAccessMaterial({ userId: "alice", provider: "anthropic", model: "claude" }));
  assert.ok(await broker.getAccessMaterial({ userId: "bob", provider: "anthropic", model: "claude" }));
});

test("hostile source and identity callbacks are exactly-once and late callbacks do not reach consumers", async () => {
  let consumerCalls = 0;
  const missingSource = { withApiKey: async () => undefined } as unknown as ModelApiKeySource;
  await assertAuthRejects(
    new ModelCredentialResolver(missingSource).withApiKey(request, async () => {
      consumerCalls += 1;
      return "bad";
    }),
  );
  assert.equal(consumerCalls, 0);

  const duplicateSource = {
    withApiKey: async (_request: typeof request, operation: (apiKey: string) => Promise<void>) => {
      await operation(key);
      await operation(key);
    },
  };
  await assertAuthRejects(
    new ModelCredentialResolver(duplicateSource).withApiKey(request, async () => {
      consumerCalls += 1;
      return "bad";
    }),
    [key],
  );
  assert.equal(consumerCalls, 0);

  const earlySource = {
    withApiKey: async (_request: typeof request, operation: (apiKey: string) => Promise<void>) => {
      operation(key).catch(() => undefined);
      return undefined;
    },
  };
  assert.equal(
    await new ModelCredentialResolver(earlySource).withApiKey(request, async (apiKey) => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return apiKey;
    }),
    key,
  );

  let lateConsumerCalls = 0;
  let late: ((apiKey: string) => Promise<unknown>) | undefined;
  const lateSource = {
    withApiKey: async (_request: typeof request, operation: (apiKey: string) => Promise<void>) => {
      late = operation;
      return undefined;
    },
  };
  await assertAuthRejects(
    new ModelCredentialResolver(lateSource).withApiKey(request, async () => {
      lateConsumerCalls += 1;
      return "bad";
    }),
  );
  await assert.rejects(late?.(key) ?? Promise.reject(new Error("missing late")));
  assert.equal(lateConsumerCalls, 0);

  const app = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    const earlyIdentity: OpenBaoIdentityPort = {
      withToken: async (_signal: AbortSignal, operation: (token: string) => Promise<void>) => {
        operation(token).catch(() => undefined);
        return undefined;
      },
    };
    assert.equal(await resolve(store(app.origin, earlyIdentity)), key);
    const missingIdentity = { withToken: async () => undefined } as unknown as OpenBaoIdentityPort;
    await assertAuthRejects(resolve(store(app.origin, missingIdentity)), [app.origin, token, key]);
    const duplicateIdentity: OpenBaoIdentityPort = {
      withToken: async (_signal: AbortSignal, operation: (token: string) => Promise<void>) => {
        await operation(token);
        await operation(token);
      },
    };
    await assertAuthRejects(resolve(store(app.origin, duplicateIdentity)), [app.origin, token, key]);
  } finally {
    await app.close();
  }
});

test("OpenBao cancellation cleanup is non-blocking for hostile bodies", async () => {
  let cancelCalled = false;
  const hangingBody = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("dddddddd"));
    },
    cancel() {
      cancelCalled = true;
      return new Promise(() => undefined);
    },
  });
  const fetchImpl: typeof fetch = async () =>
    new Response(hangingBody, { status: 500, headers: { "content-type": "application/json" } });
  await assertAuthRejects(resolve(store("http://127.0.0.1:1", new StaticIdentity(), { fetchImpl, timeoutMs: 50 })), [
    "dddddddd",
    token,
    key,
  ]);
  assert.equal(cancelCalled, true);
});

test("OpenBao real envelope accepts metadata and rejects outer secret-like extras", async () => {
  const ok = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    assert.equal(await resolve(store(ok.origin)), key);
  } finally {
    await ok.close();
  }
  const badOuter = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(
      JSON.stringify({
        request_id: "req",
        data: {
          data: { api_key: key },
          metadata: {
            created_time: "2026-07-15T00:00:00Z",
            deletion_time: "",
            destroyed: false,
            version: 1,
            custom_metadata: null,
          },
        },
        token: "dddddddd",
      }),
    );
  });
  try {
    await assertAuthRejects(resolve(store(badOuter.origin)), ["dddddddd", key, token, badOuter.origin]);
  } finally {
    await badOuter.close();
  }
});

test("OpenBao decodes split multibyte UTF-8 and rejects split invalid UTF-8", async () => {
  const multibyteKey = "éééékey";
  const valid = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const bytes = Buffer.from(body(multibyteKey));
    const split = bytes.indexOf(Buffer.from("é")) + 1;
    res.write(bytes.subarray(0, split));
    res.end(bytes.subarray(split));
  });
  try {
    assert.equal(await resolve(store(valid.origin)), multibyteKey);
  } finally {
    await valid.close();
  }
  const invalid = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.write(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3]));
    res.end(Buffer.from([0x28, 0x22, 0x7d]));
  });
  try {
    await assertAuthRejects(resolve(store(invalid.origin)), [invalid.origin, token, key]);
  } finally {
    await invalid.close();
  }
});

test("provider ports cannot observe consumer return values and abort race blocks consumer", async () => {
  let observed: unknown = "unset";
  const observingSource: ModelApiKeySource = {
    withApiKey: async (_request, operation) => {
      observed = await operation(key);
    },
  };
  assert.equal(
    await new ModelCredentialResolver(observingSource).withApiKey(request, async () => "consumer-secret-result"),
    "consumer-secret-result",
  );
  assert.equal(observed, undefined);

  const controller = new AbortController();
  const abortingIdentity: OpenBaoIdentityPort = {
    withToken: async (_signal, operation) => {
      observed = await operation(token);
      controller.abort();
    },
  };
  const app = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }).end(body());
  });
  try {
    let consumerCalled = false;
    await assertAuthRejects(
      store(app.origin, abortingIdentity).withApiKey({ ...request, signal: controller.signal }, async () => {
        consumerCalled = true;
      }),
      [key, token, app.origin],
    );
    assert.equal(observed, undefined);
    assert.equal(consumerCalled, false);
  } finally {
    await app.close();
  }
});

test("OpenBao rejects token-bearing auth/wrap and nonstandard metadata generically", async () => {
  const variants = [
    { ...JSON.parse(body()), auth: { client_token: "dddddddd" } },
    { ...JSON.parse(body()), wrap_info: { token: "dddddddd" } },
    (() => {
      const value = JSON.parse(body());
      value.data.metadata.custom_metadata = { token: "dddddddd" };
      return value;
    })(),
    (() => {
      const value = JSON.parse(body());
      value.data.metadata.token = "dddddddd";
      return value;
    })(),
  ];
  for (const variant of variants) {
    const app = await fixture((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(variant));
    });
    try {
      await assertAuthRejects(resolve(store(app.origin)), ["dddddddd", key, token, app.origin]);
    } finally {
      await app.close();
    }
  }
});
