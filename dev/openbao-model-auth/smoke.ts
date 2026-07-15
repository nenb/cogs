import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { arch, platform } from "node:os";
import { resolve } from "node:path";
import { TextDecoder } from "node:util";
import {
  ModelAuthError,
  ModelCredentialResolver,
  type OpenBaoIdentityPort,
  OpenBaoModelApiKeyStore,
} from "../../src/auth/model-auth.ts";
import { OPENBAO_IMAGE } from "./image.ts";

const rawAddr = process.env.COGS_OPENBAO_ADDR;
const outDir = process.env.COGS_OPENBAO_REPORT_DIR;
const runtimeVersion = process.env.COGS_OPENBAO_RUNTIME_VERSION;
const sourceRevision = process.env.COGS_SOURCE_REVISION;
if (!rawAddr || !outDir || !runtimeVersion || !sourceRevision) throw new Error("missing smoke configuration");
const addr = validateLoopbackOrigin(rawAddr);
assert.match(sourceRevision, /^[a-f0-9]{40}$/);
const imageMatch = OPENBAO_IMAGE.match(/^quay\.io\/openbao\/openbao:(\d+\.\d+\.\d+)@(sha256:[a-f0-9]{64})$/);
assert.ok(imageMatch);
const [, openBaoVersion, openBaoDigest] = imageMatch;
assert.ok(openBaoVersion);
assert.ok(openBaoDigest);
assert.match(runtimeVersion, /^OpenBao\s+v2\.6\.0(?:[\s,]|$)/);

const request = {
  userId: "alice",
  provider: "anthropic",
  model: "claude-sonnet-4-5",
  credentialHandle: "users/alice/anthropic",
};
const deniedRequest = { ...request, userId: "bob", credentialHandle: "users/bob/anthropic" };
const startedAtMs = Date.now();
const startedAt = new Date(startedAtMs).toISOString();
let apiKey = `cogs-openbao-key-${crypto.randomUUID()}`;
let rootToken = "";
let unsealKey = "";
let readToken = "";

class StaticIdentity implements OpenBaoIdentityPort {
  public calls = 0;
  public lastToken = "";
  public constructor(private readonly tokenProvider: () => string) {}
  public async withToken(_signal: AbortSignal | undefined, operation: (token: string) => Promise<void>): Promise<void> {
    this.calls += 1;
    this.lastToken = this.tokenProvider();
    await operation(this.lastToken);
  }
}

function validateLoopbackOrigin(input: string): string {
  const url = new URL(input);
  assert.equal(url.protocol, "http:");
  assert.ok(url.hostname === "127.0.0.1" || url.hostname === "localhost");
  assert.equal(url.username, "");
  assert.equal(url.password, "");
  assert.equal(url.pathname, "/");
  assert.equal(url.search, "");
  assert.equal(url.hash, "");
  return url.origin;
}

async function bao(path: string, init: RequestInit & { token?: string } = {}): Promise<unknown> {
  const { token, ...requestInit } = init;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  let response: Response | undefined;
  try {
    const headers = new Headers(requestInit.headers);
    if (token) headers.set("X-Vault-Token", token);
    if (requestInit.body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
    response = await fetch(`${addr}${path}`, { ...requestInit, headers, redirect: "error", signal: controller.signal });
    if (!response.ok) throw new Error("OpenBao request failed");
    return await readJson(response, 64 * 1024);
  } catch {
    throw new Error("OpenBao request failed");
  } finally {
    clearTimeout(timeout);
    response?.body?.cancel().catch(() => undefined);
  }
}

async function readJson(response: Response, maxBytes: number): Promise<unknown> {
  const reader = response.body?.getReader();
  if (reader === undefined) return undefined;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) throw new Error("bad body");
      total += value.byteLength;
      if (total > maxBytes) throw new Error("body too large");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) return undefined;
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

function object(value: unknown): Record<string, unknown> {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as Record<string, unknown>;
}

function stringField(value: unknown, key: string): string {
  const result = object(value)[key];
  assert.equal(typeof result, "string");
  assert.notEqual(result, "");
  return result;
}

function initFields(value: unknown): { root: string; unseal: string } {
  const root = stringField(value, "root_token");
  const keys = object(value).keys_base64;
  assert.ok(Array.isArray(keys));
  assert.equal(keys.length, 1);
  assert.equal(typeof keys[0], "string");
  assert.notEqual(keys[0], "");
  return { root, unseal: keys[0] };
}

function tokenField(value: unknown): string {
  const auth = object(value).auth;
  return stringField(auth, "client_token");
}

async function assertGenericFailure(promise: Promise<unknown>, forbidden: readonly string[]): Promise<void> {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof ModelAuthError);
    const text = `${String(error)}\n${error instanceof Error ? (error.stack ?? "") : ""}`;
    for (const secret of forbidden) assert.equal(secret === "" || text.includes(secret), false);
    return true;
  });
}

const init = initFields(
  await bao("/v1/sys/init", { method: "POST", body: JSON.stringify({ secret_shares: 1, secret_threshold: 1 }) }),
);
rootToken = init.root;
unsealKey = init.unseal;
await bao("/v1/sys/unseal", { method: "POST", body: JSON.stringify({ key: unsealKey }) });
unsealKey = "";

await bao("/v1/sys/mounts/model", {
  method: "POST",
  token: rootToken,
  body: JSON.stringify({ type: "kv", options: { version: "2" } }),
});
await bao("/v1/model/data/users/alice/anthropic", {
  method: "POST",
  token: rootToken,
  body: JSON.stringify({ data: { api_key: apiKey } }),
});
const policy = 'path "model/data/users/alice/anthropic" { capabilities = ["read"] }';
await bao("/v1/sys/policies/acl/cogs-model-auth-read", {
  method: "PUT",
  token: rootToken,
  body: JSON.stringify({ policy }),
});
readToken = tokenField(
  await bao("/v1/auth/token/create-orphan", {
    method: "POST",
    token: rootToken,
    body: JSON.stringify({ policies: ["cogs-model-auth-read"], ttl: "2m", explicit_max_ttl: "2m", renewable: false }),
  }),
);

const identity = new StaticIdentity(() => readToken);
const store = new OpenBaoModelApiKeyStore({
  origin: `${addr}/`,
  mount: "model",
  identity,
  allowLoopbackHttpDevelopment: true,
  timeoutMs: 5_000,
});
const resolver = new ModelCredentialResolver(store);
let observed = "";
await resolver.withApiKey(request, async (key) => {
  observed = key;
});
assert.equal(observed, apiKey);
observed = "";
await assertGenericFailure(
  new ModelCredentialResolver(store).withApiKey(deniedRequest, async () => undefined),
  [apiKey, readToken, rootToken],
);

await bao("/v1/auth/token/revoke-self", { method: "POST", token: readToken, body: JSON.stringify({}) });
let revokedReadToken = readToken;
const callsBeforeRevokedRead = identity.calls;
await assertGenericFailure(
  resolver.withApiKey(request, async () => undefined),
  [apiKey, revokedReadToken, rootToken],
);
assert.equal(identity.calls, callsBeforeRevokedRead + 1);
assert.equal(identity.lastToken, revokedReadToken);
identity.lastToken = "";
readToken = "";
revokedReadToken = "";
await bao("/v1/auth/token/revoke-self", { method: "POST", token: rootToken, body: JSON.stringify({}) });
rootToken = "";
const completedAtMs = Date.now();
apiKey = "";

await mkdir(outDir, { recursive: true });
await writeFile(
  resolve(outDir, "report.json"),
  `${JSON.stringify(
    {
      version: "cogs.security-report/v1alpha1",
      report_id: `openbao-model-auth-${sourceRevision.slice(0, 12)}`,
      source_revision: sourceRevision,
      profile: "insecure-container",
      authority: "functional-only",
      started_at: startedAt,
      completed_at: new Date(completedAtMs).toISOString(),
      duration_ms: completedAtMs - startedAtMs,
      environment: {
        os: platform(),
        architecture: arch(),
        runner: process.env.GITHUB_ACTIONS === "true" ? "github-actions" : "local-docker",
        runtime_versions: { node: process.version },
        metadata: { loopback_only: true, persistent_volume: false, openbao_runtime_version: runtimeVersion },
      },
      components: [
        { name: "cogs", version: "0.0.0" },
        { name: "openbao", version: openBaoVersion, image_digest: openBaoDigest },
      ],
      dependencies: {
        authorization: {
          mode: "real",
          implementation: "OpenBao ACL policy scoped to model/data/users/alice/anthropic",
          version: openBaoVersion,
        },
        audit: { mode: "not-applicable", implementation: "no audit sink in local OpenBao API-key fixture" },
        revocation: { mode: "real", implementation: "OpenBao token revoke-self", version: openBaoVersion },
        identity: {
          mode: "real",
          implementation: "short-lived orphan OpenBao token scoped to exact KV-v2 path",
          version: openBaoVersion,
        },
        network_enforcement: { mode: "not-applicable", implementation: "insecure-container functional profile" },
      },
      tests: [
        {
          id: "openbao.kv2-exact-path-read",
          group: "model-auth-openbao",
          result: "pass",
          release_eligible: false,
          duration_ms: completedAtMs - startedAtMs,
          dependency_modes: {
            authorization: "real",
            identity: "real",
            revocation: "real",
            network_enforcement: "not-applicable",
          },
          diagnostics_redacted: "production resolver retrieved the expected in-memory API key without printing it",
        },
        {
          id: "openbao.other-user-denied",
          group: "model-auth-openbao",
          result: "pass",
          release_eligible: false,
          dependency_modes: {
            authorization: "real",
            identity: "real",
            revocation: "real",
            network_enforcement: "not-applicable",
          },
          diagnostics_redacted: "different user/path failed generically",
        },
        {
          id: "openbao.revoked-token-denied",
          group: "model-auth-openbao",
          result: "pass",
          release_eligible: false,
          dependency_modes: {
            authorization: "real",
            identity: "real",
            revocation: "real",
            network_enforcement: "not-applicable",
          },
          diagnostics_redacted: "post-revocation retrieval failed generically",
        },
      ],
      known_limitations: [
        "functional-only local OpenBao integration evidence; no isolation, release, Kubernetes-auth, AWS, or production claim",
        "report is written before shell EXIT-trap independent container/volume/temp cleanup verification",
        "bootstrap root token exists only inside the trusted smoke process and is revoked before report completion",
      ],
    },
    null,
    2,
  )}\n`,
  { mode: 0o600 },
);
