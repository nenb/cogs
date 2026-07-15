import assert from "node:assert/strict";
import { chmod, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import * as grpc from "@grpc/grpc-js";
import {
  type EgressAuditWal,
  type EgressAuditWalAppendInput,
  type EgressAuditWalRecord,
  openEgressAuditWal,
} from "../src/egress/audit-wal.ts";
import { loadExtAuthzDescriptor } from "../src/egress/ext-authz-descriptor.ts";
import {
  type CogsExtAuthzServer,
  CogsExtAuthzServerError,
  startCogsExtAuthzServer,
} from "../src/egress/ext-authz-server.ts";
import type { CogsEgressRoutePlan } from "../src/egress/route-policy.ts";

const token = "internal-token-1";
const capability = "Basic capability-token";
const session = "session-1";
const routeId = "route-https";

function plan(): CogsEgressRoutePlan {
  return deepFreeze({
    routeCount: 1,
    integrations: [
      {
        id: "github",
        presetRevision: `sha256:${"a".repeat(64)}`,
        auth: {
          type: "bearer_header",
          header: "Authorization",
          prefix: "Bearer ",
          placeholder: "COGS_PLACEHOLDER_TOKEN",
          secretHandle: "users/session/secret",
        },
        routes: [
          {
            integrationId: "github",
            ruleName: "fetch",
            routeId,
            host: "github.com",
            port: 443,
            method: "GET",
            pathPattern: "/owner/repo.git/info/refs",
            pathStrategy: "exact",
            queryPolicy: { mode: "exact", values: ["service=git-upload-pack"], canonical: "service=git-upload-pack" },
            pathMatch: { kind: "safe_regex", value: "^/owner/repo\\.git/info/refs\\?service=git-upload-pack$" },
            injectAuth: true,
            credentialRequired: true,
          },
        ],
      },
    ],
  });
}

async function withTempWal<T>(run: (wal: EgressAuditWal) => Promise<T>): Promise<T> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "cogs-authz-server-")));
  await chmod(dir, 0o700);
  const wal = await openEgressAuditWal({
    path: join(dir, "audit.wal"),
    maxBytes: 4096,
    maxRecords: 32,
    maxRecordBytes: 1024,
    nowMs: () => 1000,
    newIntentId: (() => {
      let next = 1;
      return () => `intent-${next++}`;
    })(),
  });
  try {
    return await run(wal);
  } finally {
    await wal.close().catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  }
}

async function withServer<T>(wal: EgressAuditWal, run: (server: CogsExtAuthzServer) => Promise<T>): Promise<T> {
  const server = await startCogsExtAuthzServer({
    sessionId: session,
    internalAuthzToken: token,
    proxyCapability: capability,
    routePlan: plan(),
    wal,
  });
  try {
    assert.deepEqual(Object.keys(server).sort(), ["close", "ready", "target"]);
    assert.equal(Object.isFrozen(server), true);
    assert.equal(JSON.stringify(server).includes(token), false);
    assert.equal(JSON.stringify(server).includes("server"), false);
    assert.equal(server.ready, true);
    return await run(server);
  } finally {
    await server.close().catch(() => undefined);
  }
}

async function call(
  target: string,
  req: unknown,
  extra?: { token?: string | string[]; deadlineMs?: number; cancel?: boolean },
) {
  const { authorizationService } = await loadExtAuthzDescriptor();
  const client = new grpc.Client(target, grpc.credentials.createInsecure());
  const metadata = new grpc.Metadata();
  const values = extra?.token === undefined ? [token] : Array.isArray(extra.token) ? extra.token : [extra.token];
  for (const value of values) metadata.add("x-cogs-authz-token", value);
  const options = { deadline: new Date(Date.now() + (extra?.deadlineMs ?? 1000)) };
  return await new Promise<unknown>((resolve, reject) => {
    const c = client.makeUnaryRequest(
      authorizationService.Check.path,
      authorizationService.Check.requestSerialize,
      authorizationService.Check.responseDeserialize,
      req,
      metadata,
      options,
      (error, response) => {
        client.close();
        if (error) reject(error);
        else resolve(response);
      },
    );
    if (extra?.cancel) c.cancel();
  });
}

function capabilityRequest(auth = capability): unknown {
  return request({ mode: "capability", requireCapability: true, credentialRequired: false, proxyAuthorization: auth });
}
function authorizeRequest(
  overrides: Partial<{
    sessionId: string;
    routeId: string;
    method: string;
    host: string;
    path: string;
    scheme: string;
    requireCapability: boolean;
    credentialRequired: boolean;
    proxyAuthorization: string;
  }> = {},
): unknown {
  return request({
    mode: "authorize",
    routeId,
    requireCapability: false,
    credentialRequired: true,
    method: "GET",
    host: "github.com",
    path: "/owner/repo.git/info/refs?service=git-upload-pack",
    scheme: "https",
    ...overrides,
  });
}
function request(input: {
  mode: "capability" | "authorize";
  routeId?: string;
  sessionId?: string;
  requireCapability: boolean;
  credentialRequired: boolean;
  proxyAuthorization?: string;
  method?: string;
  host?: string;
  path?: string;
  scheme?: string;
}): unknown {
  return {
    attributes: {
      context_extensions: [
        { key: "cogs.mode", value: input.mode },
        { key: "cogs.case_id", value: "case-1" },
        { key: "cogs.session_id", value: input.sessionId ?? session },
        ...(input.routeId === undefined ? [] : [{ key: "cogs.route_id", value: input.routeId }]),
        { key: "cogs.require_capability", value: String(input.requireCapability) },
        { key: "cogs.credential_required", value: String(input.credentialRequired) },
      ],
      request: {
        http: {
          headers:
            input.proxyAuthorization === undefined
              ? []
              : [{ key: "proxy-authorization", value: input.proxyAuthorization }],
          ...(input.method === undefined ? {} : { method: input.method }),
          ...(input.host === undefined ? {} : { host: input.host }),
          ...(input.path === undefined ? {} : { path: input.path }),
          ...(input.scheme === undefined ? {} : { scheme: input.scheme }),
        },
      },
    },
  };
}

function deniedCode(response: unknown): string | number | undefined {
  return (response as { denied_response?: { status?: { code?: string | number } } }).denied_response?.status?.code;
}
function intentId(response: unknown): string | undefined {
  return (
    response as { dynamic_metadata?: { fields?: { key: string; value: { string_value?: string } }[] } }
  ).dynamic_metadata?.fields?.find((f) => f.key === "x-cogs-intent-id")?.value.string_value;
}

test("loopback server authorizes capability without WAL or intent metadata", async () => {
  await withTempWal(async (wal) => {
    await withServer(wal, async (server) => {
      const ok = await call(server.target, capabilityRequest());
      assert.equal(intentId(ok), undefined);
      assert.equal(wal.records.length, 0);
      assert.equal(deniedCode(await call(server.target, capabilityRequest("wrong"))), "ProxyAuthenticationRequired");
      assert.equal(
        deniedCode(
          await call(
            server.target,
            request({ mode: "capability", requireCapability: true, credentialRequired: false }),
          ),
        ),
        "ProxyAuthenticationRequired",
      );
    });
  });
});

test("loopback server appends WAL before authorize allow and denies route mismatches", async () => {
  await withTempWal(async (wal) => {
    await withServer(wal, async (server) => {
      const ok = await call(server.target, authorizeRequest());
      assert.equal(intentId(ok), "intent-1");
      assert.equal(wal.records.length, 1);
      assert.equal(wal.records[0]?.route_id, routeId);
      assert.equal(intentId(await call(server.target, authorizeRequest({ host: "github.com:443" }))), "intent-2");
      for (const bad of [
        { sessionId: "session-2" },
        { routeId: "route-missing" },
        { method: "POST" },
        { scheme: "http" },
        { host: "github.com:444" },
        { path: "/owner/repo.git/info/refs?service=bad" },
        { path: "/owner/repo.git/info/refs?service=git-upload-pack#frag" },
        { requireCapability: true },
        { credentialRequired: false },
        { proxyAuthorization: capability },
      ]) {
        assert.equal(deniedCode(await call(server.target, authorizeRequest(bad))), "Forbidden");
      }
      assert.equal(wal.records.length, 2);
    });
  });
});

test("loopback server rejects internal auth, malformed requests, bad deadlines, and cancellation generically", async () => {
  await withTempWal(async (wal) => {
    await withServer(wal, async (server) => {
      await assert.rejects(() => call(server.target, authorizeRequest(), { token: [] }), {
        code: grpc.status.UNAUTHENTICATED,
      });
      await assert.rejects(() => call(server.target, authorizeRequest(), { token: [token, token] }), {
        code: grpc.status.UNAUTHENTICATED,
      });
      await assert.rejects(() => call(server.target, authorizeRequest(), { token: "wrong" }), {
        code: grpc.status.UNAUTHENTICATED,
      });
      assert.equal(
        deniedCode(
          await call(server.target, { attributes: { context_extensions: [{ key: "cogs.mode", value: "authorize" }] } }),
        ),
        "Forbidden",
      );
      await assert.rejects(() => call(server.target, authorizeRequest(), { deadlineMs: 3000 }), {
        code: grpc.status.DEADLINE_EXCEEDED,
      });
      await assert.rejects(() => call(server.target, authorizeRequest(), { cancel: true }), {
        code: grpc.status.CANCELLED,
      });
      assert.equal(wal.records.length, 0);
    });
  });
});

test("server enforces concurrency, WAL poison, close races, and start failures", async () => {
  const slowWal = fakeWal(async () => new Promise(() => undefined));
  const server = await startCogsExtAuthzServer({
    sessionId: session,
    internalAuthzToken: token,
    proxyCapability: capability,
    routePlan: plan(),
    wal: slowWal,
  });
  try {
    const results: unknown[] = [];
    const calls = Array.from({ length: 33 }, () =>
      call(server.target, authorizeRequest())
        .then(() => grpc.status.OK)
        .catch((error: grpc.ServiceError) => error.code)
        .then((result) => {
          results.push(result);
          return result;
        }),
    );
    await boundedUntil(() => results.includes(grpc.status.RESOURCE_EXHAUSTED));
    await server.close();
    await Promise.allSettled(calls);
    await server.close();
    assert.equal(server.ready, false);
  } finally {
    await server.close().catch(() => undefined);
  }

  const mutableReady = fakeWal();
  const unreadyServer = await startCogsExtAuthzServer({
    sessionId: session,
    internalAuthzToken: token,
    proxyCapability: capability,
    routePlan: plan(),
    wal: mutableReady,
  });
  try {
    mutableReady.setReady(false);
    await assert.rejects(() => call(unreadyServer.target, authorizeRequest()), { code: grpc.status.UNAVAILABLE });
    assert.equal(mutableReady.records.length, 0);
  } finally {
    await unreadyServer.close().catch(() => undefined);
  }

  const poisoned = fakeWal(async () => {
    throw new Error("poison");
  });
  const poisonServer = await startCogsExtAuthzServer({
    sessionId: session,
    internalAuthzToken: token,
    proxyCapability: capability,
    routePlan: plan(),
    wal: poisoned,
  });
  try {
    await assert.rejects(() => call(poisonServer.target, authorizeRequest()), { code: grpc.status.UNAVAILABLE });
    assert.equal(poisonServer.ready, false);
  } finally {
    await poisonServer.close().catch(() => undefined);
  }

  await assert.rejects(
    () =>
      startCogsExtAuthzServer({
        sessionId: "bad/session",
        internalAuthzToken: token,
        proxyCapability: capability,
        routePlan: plan(),
        wal: fakeWal(),
      }),
    CogsExtAuthzServerError,
  );
  const original = plan();
  const mismatched = {
    ...original,
    integrations: original.integrations.map((integration) => ({
      ...integration,
      routes: integration.routes.map((route) => ({
        ...route,
        pathMatch: { ...route.pathMatch },
        integrationId: "other",
      })),
    })),
  };
  deepFreeze(mismatched);
  await assert.rejects(
    () =>
      startCogsExtAuthzServer({
        sessionId: session,
        internalAuthzToken: token,
        proxyCapability: capability,
        routePlan: mismatched as CogsEgressRoutePlan,
        wal: fakeWal(),
      }),
    CogsExtAuthzServerError,
  );
  await assert.rejects(
    () =>
      startCogsExtAuthzServer({
        sessionId: session,
        internalAuthzToken: token,
        proxyCapability: token,
        routePlan: plan(),
        wal: fakeWal(),
      }),
    CogsExtAuthzServerError,
  );
  const inconsistentOriginal = plan();
  const inconsistent = {
    ...inconsistentOriginal,
    integrations: inconsistentOriginal.integrations.map((integration) => ({
      ...integration,
      routes: integration.routes.map((route) => ({ ...route, pathMatch: { ...route.pathMatch }, injectAuth: false })),
    })),
  };
  deepFreeze(inconsistent);
  await assert.rejects(
    () =>
      startCogsExtAuthzServer({
        sessionId: session,
        internalAuthzToken: token,
        proxyCapability: capability,
        routePlan: inconsistent as CogsEgressRoutePlan,
        wal: fakeWal(),
      }),
    CogsExtAuthzServerError,
  );
});

function fakeWal(
  append: (input: EgressAuditWalAppendInput) => Promise<EgressAuditWalRecord> = async (input) => ({
    version: "cogs.egress-intent/v1alpha1",
    sequence: 0,
    intent_id: "intent-fake",
    timestamp_ms: 1,
    ...input,
  }),
): EgressAuditWal & { setReady(value: boolean): void } {
  const records: EgressAuditWalRecord[] = [];
  let ready = true;
  return {
    get ready() {
      return ready;
    },
    setReady(value: boolean) {
      ready = value;
    },
    get records() {
      return records;
    },
    append: async (input) => {
      const record = await append(input);
      records.push(record);
      return record;
    },
    close: async () => undefined,
  };
}

async function boundedUntil(done: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000;
  while (!done()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for bounded condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
