import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import type { OpenBaoIdentityPort } from "../src/auth/model-auth.ts";
import { CogsEgressPkiError, OpenBaoEgressPkiSource } from "../src/egress/openbao-pki.ts";

const exec = promisify(execFile);

class Identity implements OpenBaoIdentityPort {
  public calls = 0;
  public token = "vault-token-test";
  public mode: "normal" | "missing" | "duplicate" | "reject" = "normal";
  public async withToken(signal: AbortSignal, operation: (token: string) => Promise<void>): Promise<void> {
    this.calls += 1;
    assert.equal(signal.aborted, false);
    if (this.mode === "reject") throw new Error("leaky-token-error");
    if (this.mode === "missing") return;
    await operation(this.token);
    if (this.mode === "duplicate") await operation(this.token);
  }
}

test("issues deterministic PKI request and returns frozen chain material", async () => {
  const certs = await fixture(["b.example.com", "a.example.com"]);
  const identity = new Identity();
  const calls: { url: string; init: RequestInit }[] = [];
  const source = new OpenBaoEgressPkiSource({
    origin: "https://bao.example/",
    mount: "pki",
    role: "egress",
    identity,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init: init as RequestInit });
      return jsonResponse(certs);
    },
  });
  const expires = Date.now() + 60_000;
  const material = await source.withPkiMaterial(
    { sessionId: "session-1", hosts: ["b.example.com", "a.example.com"], maxSessionExpiresAtMs: expires },
    async (value) => value,
  );
  assert.equal(identity.calls, 1);
  const call = calls[0];
  assert.ok(call);
  assert.equal(call.url, "https://bao.example/v1/pki/issue/egress");
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.redirect, "error");
  assert.equal((call.init.headers as Record<string, string>)["x-vault-token"], "vault-token-test");
  const body = JSON.parse(String(call.init.body));
  assert.deepEqual(body, { common_name: "a.example.com", alt_names: "b.example.com", ttl: body.ttl });
  assert.match(body.ttl, /^[0-9]+s$/);
  assert.equal(Object.isFrozen(material), true);
  assert.equal(material.certificateChainPem, certs.leaf);
  assert.equal(material.caCertificatePem, certs.ca);
  assert.equal(material.privateKeyPem, certs.key);
  assert.ok(material.expiresAtMs >= expires + 30_000);
});

test("omits alt_names for a single sorted host and allows explicit loopback http", async () => {
  const certs = await fixture(["solo.example.com"]);
  let body = "";
  const source = new OpenBaoEgressPkiSource({
    origin: "http://127.0.0.1:8200/",
    mount: "pki",
    role: "egress",
    identity: new Identity(),
    allowLoopbackHttpDevelopment: true,
    fetchImpl: async (_url, init) => {
      body = String(init?.body);
      return jsonResponse(certs);
    },
  });
  await source.withPkiMaterial(
    { sessionId: "session-1", hosts: ["solo.example.com"], maxSessionExpiresAtMs: Date.now() + 60_000 },
    async () => {},
  );
  assert.deepEqual(Object.keys(JSON.parse(body)).sort(), ["common_name", "ttl"]);
  assert.throws(
    () =>
      new OpenBaoEgressPkiSource({
        origin: "http://example.com/",
        mount: "pki",
        role: "egress",
        identity: new Identity(),
        allowLoopbackHttpDevelopment: true,
      }),
    CogsEgressPkiError,
  );
});

test("rejects duplicate, malformed, uppercase, and excessive-session hosts before fetch", async () => {
  for (const input of [["a.example.com", "a.example.com"], ["A.example.com"], ["127.0.0.1"], []] as string[][]) {
    const identity = new Identity();
    await assert.rejects(
      new OpenBaoEgressPkiSource({
        origin: "https://bao.example/",
        mount: "pki",
        role: "egress",
        identity,
      }).withPkiMaterial(
        { sessionId: "session-1", hosts: input, maxSessionExpiresAtMs: Date.now() + 60_000 },
        async () => {},
      ),
      generic,
    );
    assert.equal(identity.calls, 0);
  }
  const missingSession = new Identity();
  await assert.rejects(
    new OpenBaoEgressPkiSource({
      origin: "https://bao.example/",
      mount: "pki",
      role: "egress",
      identity: missingSession,
    }).withPkiMaterial(
      { hosts: ["a.example.com"], maxSessionExpiresAtMs: Date.now() + 60_000 } as never,
      async () => {},
    ),
    generic,
  );
  assert.equal(missingSession.calls, 0);
  await assert.rejects(
    new OpenBaoEgressPkiSource({
      origin: "https://bao.example/",
      mount: "pki",
      role: "egress",
      identity: new Identity(),
    }).withPkiMaterial(
      { sessionId: "session-1", hosts: ["a.example.com"], maxSessionExpiresAtMs: Date.now() + 9 * 60 * 60 * 1000 },
      async () => {},
    ),
    generic,
  );
});

test("validates direct-root and intermediate chains with separate trust anchor", async () => {
  const direct = await fixture(["a.example.com"]);
  const directMaterial = await new OpenBaoEgressPkiSource({
    origin: "https://bao.example/",
    mount: "pki",
    role: "egress",
    identity: new Identity(),
    fetchImpl: async () => jsonResponse({ ...direct, caChain: [] }),
  }).withPkiMaterial(
    { sessionId: "session-1", hosts: ["a.example.com"], maxSessionExpiresAtMs: Date.now() + 60_000 },
    async (value) => value,
  );
  assert.equal(directMaterial.certificateChainPem, direct.leaf);
  assert.equal(directMaterial.caCertificatePem, direct.ca);

  const chained = await intermediateFixture(["a.example.com"]);
  const chainedMaterial = await new OpenBaoEgressPkiSource({
    origin: "https://bao.example/",
    mount: "pki",
    role: "egress",
    identity: new Identity(),
    fetchImpl: async () => jsonResponse({ ...chained, caChain: [chained.intermediate, chained.ca] }),
  }).withPkiMaterial(
    { sessionId: "session-1", hosts: ["a.example.com"], maxSessionExpiresAtMs: Date.now() + 60_000 },
    async (value) => value,
  );
  assert.equal(chainedMaterial.certificateChainPem, `${chained.leaf}${chained.intermediate}`);
  assert.equal(chainedMaterial.caCertificatePem, chained.ca);
});

test("rejects SAN mismatch, extra SAN, key mismatch, duplicate chain, bad key type, and short lifetime", async () => {
  const good = await fixture(["a.example.com"]);
  const extraSan = await fixture(["a.example.com", "b.example.com"]);
  const other = await fixture(["a.example.com"]);
  const badCa = await fixture(["ca.example.com"]);
  for (const bad of [
    { ...good, hosts: ["b.example.com"] },
    extraSan,
    { ...good, key: other.key },
    { ...good, caChain: [good.ca, good.ca] },
    { ...good, privateKeyType: "ec" },
    { ...good, maxSessionExpiresAtMs: Date.now() + 2 * 24 * 60 * 60 * 1000 },
    { ...good, ca: badCa.ca },
  ]) {
    await assert.rejects(callWith(bad), generic);
  }
});

test("rejects bad HTTP responses, JSON shape, identity callbacks, aborts, getters, and consumer leakage", async () => {
  const certs = await fixture(["a.example.com"]);
  const cancelled = { value: false };
  for (const response of [
    new Response("{}", { status: 500, headers: { "content-type": "application/json" } }),
    new Response("{}", { status: 200, headers: { "content-type": "text/plain" } }),
    new Response("{}", { status: 200, headers: { "content-type": "application/json", "content-length": "9999999" } }),
    new Response(new Uint8Array([0xff]), { status: 200, headers: { "content-type": "application/json" } }),
    new Response(JSON.stringify({ mount_type: "kv", data: payload(certs) }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
    new Response(JSON.stringify({ request_id: 7, data: payload(certs) }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
    new Response(JSON.stringify({ data: { ...payload(certs), extra: true } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
    streamingJsonResponse("x".repeat(70 * 1024), cancelled),
    jsonResponse({ ...certs, leaf: certs.leaf + certs.ca }),
    jsonResponse({ ...certs, key: certs.key + certs.key }),
  ])
    await assert.rejects(
      callWith(certs, async () => response),
      generic,
    );
  assert.equal(cancelled.value, true);

  for (const mode of ["missing", "duplicate", "reject"] as const) {
    const identity = new Identity();
    identity.mode = mode;
    await assert.rejects(callWith(certs, undefined, identity), generic);
  }
  const whitespaceToken = new Identity();
  whitespaceToken.token = "vault-token\n";
  await assert.rejects(callWith(certs, undefined, whitespaceToken), generic);

  const controller = new AbortController();
  controller.abort();
  await assert.rejects(callWith({ ...certs, signal: controller.signal }), generic);

  const request = {} as { sessionId: string; hosts: string[]; maxSessionExpiresAtMs: number };
  Object.defineProperty(request, "hosts", {
    get: () => {
      throw new Error("leaky-host");
    },
  });
  await assert.rejects(
    new OpenBaoEgressPkiSource({
      origin: "https://bao.example/",
      mount: "pki",
      role: "egress",
      identity: new Identity(),
    }).withPkiMaterial(request, async () => {}),
    generic,
  );

  await assert.rejects(
    callWith(certs, undefined, undefined, async () => {
      throw new Error(`${certs.key} leaky-token-error a.example.com`);
    }),
    generic,
  );
});

async function callWith(
  certs: Awaited<ReturnType<typeof fixture>> & {
    hosts?: string[];
    maxSessionExpiresAtMs?: number;
    signal?: AbortSignal;
    privateKeyType?: string;
    caChain?: string[];
    intermediate?: string;
  },
  fetchImpl: typeof fetch = async () => jsonResponse(certs),
  identity = new Identity(),
  consume: (material: unknown) => Promise<void> = async () => {},
) {
  return new OpenBaoEgressPkiSource({
    origin: "https://bao.example/",
    mount: "pki",
    role: "egress",
    identity,
    fetchImpl,
  }).withPkiMaterial(
    {
      sessionId: "session-1",
      hosts: certs.hosts ?? ["a.example.com"],
      maxSessionExpiresAtMs: certs.maxSessionExpiresAtMs ?? Date.now() + 60_000,
      ...(certs.signal ? { signal: certs.signal } : {}),
    },
    consume,
  );
}

function jsonResponse(
  certs: Awaited<ReturnType<typeof fixture>> & { privateKeyType?: string; caChain?: string[]; intermediate?: string },
): Response {
  const text = JSON.stringify({
    request_id: "r",
    lease_id: "",
    renewable: false,
    lease_duration: 3600,
    data: payload(certs),
    warnings: null,
    auth: null,
    wrap_info: null,
  });
  return new Response(text, {
    status: 200,
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(text)) },
  });
}

function payload(
  certs: Awaited<ReturnType<typeof fixture>> & { privateKeyType?: string; caChain?: string[]; intermediate?: string },
) {
  return {
    certificate: certs.leaf,
    private_key: certs.key,
    issuing_ca: certs.intermediate ?? certs.ca,
    ca_chain: certs.caChain ?? [certs.ca],
    serial_number: "01",
    expiration: Math.floor(new X509Certificate(certs.leaf).validToDate.getTime() / 1000),
    private_key_type: certs.privateKeyType ?? "rsa",
  };
}

function streamingJsonResponse(text: string, cancelled: { value: boolean }): Response {
  const bytes = new TextEncoder().encode(text);
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
      },
      cancel() {
        cancelled.value = true;
      },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

async function fixture(hosts: string[], caDays = 2) {
  const dir = await mkdtemp(join(tmpdir(), "cogs-pki-"));
  try {
    await exec("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      String(caDays),
      "-subj",
      "/CN=Cogs Test CA",
      "-keyout",
      join(dir, "ca.key"),
      "-out",
      join(dir, "ca.crt"),
    ]);
    await exec("openssl", [
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      `/CN=${hosts[0]}`,
      "-keyout",
      join(dir, "leaf.key"),
      "-out",
      join(dir, "leaf.csr"),
    ]);
    await writeFile(join(dir, "ext.cnf"), `subjectAltName=${hosts.map((host) => `DNS:${host}`).join(",")}\n`);
    await exec("openssl", [
      "x509",
      "-req",
      "-in",
      join(dir, "leaf.csr"),
      "-CA",
      join(dir, "ca.crt"),
      "-CAkey",
      join(dir, "ca.key"),
      "-CAcreateserial",
      "-days",
      "1",
      "-extfile",
      join(dir, "ext.cnf"),
      "-out",
      join(dir, "leaf.crt"),
    ]);
    return {
      leaf: await readFile(join(dir, "leaf.crt"), "utf8"),
      key: await readFile(join(dir, "leaf.key"), "utf8"),
      ca: await readFile(join(dir, "ca.crt"), "utf8"),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function intermediateFixture(hosts: string[]) {
  const dir = await mkdtemp(join(tmpdir(), "cogs-pki-chain-"));
  try {
    await exec("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "2",
      "-subj",
      "/CN=Cogs Root CA",
      "-keyout",
      join(dir, "root.key"),
      "-out",
      join(dir, "root.crt"),
    ]);
    await exec("openssl", [
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=Cogs Intermediate CA",
      "-keyout",
      join(dir, "intermediate.key"),
      "-out",
      join(dir, "intermediate.csr"),
    ]);
    await writeFile(
      join(dir, "ca-ext.cnf"),
      "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
    );
    await exec("openssl", [
      "x509",
      "-req",
      "-in",
      join(dir, "intermediate.csr"),
      "-CA",
      join(dir, "root.crt"),
      "-CAkey",
      join(dir, "root.key"),
      "-CAcreateserial",
      "-days",
      "1",
      "-extfile",
      join(dir, "ca-ext.cnf"),
      "-out",
      join(dir, "intermediate.crt"),
    ]);
    await exec("openssl", [
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      `/CN=${hosts[0]}`,
      "-keyout",
      join(dir, "leaf.key"),
      "-out",
      join(dir, "leaf.csr"),
    ]);
    await writeFile(join(dir, "leaf-ext.cnf"), `subjectAltName=${hosts.map((host) => `DNS:${host}`).join(",")}\n`);
    await exec("openssl", [
      "x509",
      "-req",
      "-in",
      join(dir, "leaf.csr"),
      "-CA",
      join(dir, "intermediate.crt"),
      "-CAkey",
      join(dir, "intermediate.key"),
      "-CAcreateserial",
      "-days",
      "1",
      "-extfile",
      join(dir, "leaf-ext.cnf"),
      "-out",
      join(dir, "leaf.crt"),
    ]);
    return {
      leaf: await readFile(join(dir, "leaf.crt"), "utf8"),
      key: await readFile(join(dir, "leaf.key"), "utf8"),
      ca: await readFile(join(dir, "root.crt"), "utf8"),
      intermediate: await readFile(join(dir, "intermediate.crt"), "utf8"),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function generic(error: unknown): boolean {
  assert.ok(error instanceof CogsEgressPkiError);
  assert.equal(error.code, "COGS_EGRESS_PKI_FAILED");
  assert.equal(error.message, "egress PKI material unavailable");
  assert.doesNotMatch(String(error.stack), /BEGIN|PRIVATE|leaky|a\.example|vault-token/);
  return true;
}
