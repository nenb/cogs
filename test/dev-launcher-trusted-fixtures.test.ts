import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { startLocalFixtures } from "../dev/launcher/fixtures.ts";
import {
  OPENBAO_IMAGE,
  type OpenBaoSeams,
  startTrustedOpenBao,
  startTrustedOpenBaoCooperative,
} from "../dev/launcher/openbao.ts";
import { createState, readManifest, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";

const sourceRevision = "a".repeat(40);
function testCaPem() {
  const dir = mkdtempSync(join(tmpdir(), "cogs-launcher-ca-"));
  try {
    const key = join(dir, "ca.key"),
      cert = join(dir, "ca.crt");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        key,
        "-out",
        cert,
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-days",
        "1",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
      ],
      { stdio: "ignore" },
    );
    return readFileSync(cert, "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
async function state() {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-fixtures-"));
  const root = join(await realpath(dir), "launcher");
  await mkdir(root, { mode: 0o700 });
  const s = await resolveLauncherState({ root, name: "s1", sourceRevision });
  const m = await createState(s, "linux-kvm");
  await writePhase(s, m, "sandbox-ready");
  return { dir, state: s };
}
function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}
function openBaoSeams(events: string[] = [], badInspect = false, badClose = false): OpenBaoSeams {
  let container = "",
    inspectCount = 0,
    keyCount = 0,
    tokenCount = 0,
    healthy = false;
  const id = "a".repeat(64);
  const docker = Object.freeze(async (raw: readonly string[]) => {
    events.push(`docker ${raw.join(" ")}`);
    assert.equal(raw[0], "/usr/bin/docker");
    const args = raw.slice(1);
    assert.equal(args.includes("--pull"), false);
    if (args[0] === "image")
      return { status: 0, stdout: `${JSON.stringify([OPENBAO_IMAGE.replace(":2.6.0@", "@")])}\n` };
    if (args[0] === "run") {
      assert.deepEqual(args.slice(0, 2), ["run", "--detach"]);
      assert.ok(args.includes("--cap-drop") && args.includes("ALL"));
      assert.ok(args.includes("no-new-privileges"));
      assert.ok(args.includes("--rm"));
      assert.ok(args.includes("100:1000"));
      assert.ok(args.includes("127.0.0.1::8200"));
      assert.ok(args.includes(OPENBAO_IMAGE));
      container = String(args[args.indexOf("--name") + 1]);
      return { status: 0, stdout: `${id}\n` };
    }
    if (args[0] === "inspect") {
      inspectCount++;
      return {
        status: 0,
        stdout: `${JSON.stringify({ Id: badInspect || (badClose && inspectCount > 1) ? "c".repeat(64) : id, Name: `/${container}`, Config: { Image: OPENBAO_IMAGE, Labels: { "cogs.dev.launcher.state": container.replace("cogs-openbao-", "") } }, State: { Running: true }, NetworkSettings: { Ports: { "8200/tcp": [{ HostIp: "127.0.0.1", HostPort: "9" }] } } })}\n`,
      };
    }
    if (args[0] === "exec") return { status: 0, stdout: "OpenBao v2.6.0\n" };
    if (args[0] === "rm") return { status: 0, stdout: "" };
    if (args[0] === "ps") return { status: 0, stdout: events.includes("inventory-busy") ? `${id}\n` : "" };
    return { status: 1, stdout: "" };
  });
  const fetchImpl = Object.freeze(async (url: string | URL | Request, init?: RequestInit) => {
    const u = new URL(String(url));
    events.push(`${init?.method ?? "GET"} ${u.pathname}`);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    assert.equal(u.hostname, "127.0.0.1");
    assert.equal(init?.redirect, "error");
    if (u.pathname === "/v1/sys/health") return json({ initialized: healthy, sealed: !healthy }, healthy ? 200 : 501);
    if (u.pathname === "/v1/sys/init") {
      assert.deepEqual(body, { secret_shares: 1, secret_threshold: 1 });
      return json({ root_token: "rootToken123", keys_base64: ["unsealKey123"] });
    }
    if (u.pathname === "/v1/sys/unseal") {
      healthy = true;
      return json({ sealed: false });
    }
    if (u.pathname === "/v1/pki/root/generate/internal") return json({ data: { certificate: testCaPem() } });
    if (u.pathname === "/v1/pki/roles/cogs-egress") {
      assert.deepEqual(body, {
        allowed_domains: ["localhost"],
        allow_bare_domains: true,
        allow_subdomains: false,
        allow_localhost: false,
        max_ttl: "8h",
        ttl: "2h",
        key_type: "rsa",
        key_bits: 2048,
      });
      return json({});
    }
    if (u.pathname === "/v1/sys/policies/acl/cogs-stage3-runtime") {
      assert.equal(body.policy.includes('path "model/data/users/alice/integrations/stage3-localhost"'), true);
      assert.equal(body.policy.includes('path "model/metadata/users/alice/integrations/stage3-localhost"'), true);
      assert.equal(body.policy.includes('path "pki/issue/cogs-egress"'), true);
      return json({});
    }
    if (u.pathname === "/v1/auth/token/create-orphan") {
      tokenCount++;
      assert.equal(body.ttl, "8h");
      assert.equal(body.explicit_max_ttl, "8h");
      assert.equal(body.renewable, false);
      assert.deepEqual(body.policies, [tokenCount === 1 ? "cogs-model-auth-read" : "cogs-stage3-runtime"]);
      return json({ auth: { client_token: tokenCount === 1 ? "modelToken123" : "egressToken123" } });
    }
    if (u.pathname === "/v1/auth/token/revoke-self") return json({});
    return json({ ok: true });
  }) as typeof fetch;
  return Object.freeze({
    docker,
    fetch: fetchImpl,
    randomBytes: Object.freeze(() => Buffer.alloc(32, ++keyCount)) as never,
  });
}

test("openbao lifecycle uses exact image, health sequence, model seed, and disposes holders", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    const bao = await startTrustedOpenBao(s, openBaoSeams(events));
    const snap = bao.snapshot();
    assert.equal(snap.ready, true);
    assert.equal(snap.image, OPENBAO_IMAGE);
    assert.equal(snap.seeded, "model-kv-egress-pki");
    assert.equal(snap.egress.credentialHandle, "users/alice/integrations/stage3-localhost");
    assert.equal(JSON.stringify(snap).includes("Token123"), false);
    let model = "",
      key = "";
    let egress = "",
      integration = "";
    bao.modelToken.withSecret((v) => (model = v));
    bao.modelApiKey.withSecret((v) => (key = v));
    bao.egressToken.withSecret((v) => (egress = v));
    bao.integrationCredential.withSecret((v) => (integration = v));
    assert.equal(model, "modelToken123");
    assert.equal(egress, "egressToken123");
    assert.match(key, /^[A-Za-z0-9_-]{43}$/u);
    assert.match(integration, /^[A-Za-z0-9_-]{43}$/u);
    assert.notEqual(key, integration);
    assert.ok(events.includes("GET /v1/sys/health"));
    assert.ok(events.includes("POST /v1/sys/unseal"));
    await bao.close();
    assert.ok(events.some((e) => e.includes("docker rm -f")));
    assert.throws(() => bao.modelToken.withSecret(() => undefined));
    assert.throws(() => bao.modelApiKey.withSecret(() => undefined));
    assert.throws(() => bao.egressToken.withSecret(() => undefined));
    assert.throws(() => bao.integrationCredential.withSecret(() => undefined));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao startup identity mismatch preserves replacement container", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    await assert.rejects(() => startTrustedOpenBao(s, openBaoSeams(events, true)), /launcher openbao failed/);
    assert.equal(
      events.some((e) => e.includes(" rm -f ")),
      false,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao close refuses identity mismatch and preserves owned container", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    const bao = await startTrustedOpenBao(s, openBaoSeams(events, false, true));
    events.length = 0;
    await assert.rejects(() => bao.close(), /launcher openbao failed/);
    assert.equal(
      events.some((e) => e.includes(" rm -f ")),
      false,
    );
    assert.equal(events.includes("POST /v1/auth/token/revoke-self"), false);
    assert.throws(() => bao.modelToken.withSecret(() => undefined));
    assert.throws(() => bao.egressToken.withSecret(() => undefined));
    assert.throws(() => bao.integrationCredential.withSecret(() => undefined));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao rejects forged control directory before docker", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    await rm(s.controlDir, { recursive: true, force: true });
    await symlink("/tmp", s.controlDir);
    await assert.rejects(() => startTrustedOpenBao(s, openBaoSeams(events)), /launcher openbao failed/);
    assert.equal(events.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao rejects non-sandbox-ready phase and occupied label inventory before docker run", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-fixtures-"));
  const root = join(await realpath(dir), "launcher");
  const events: string[] = [];
  try {
    await mkdir(root, { mode: 0o700 });
    const s = await resolveLauncherState({ root, name: "s1", sourceRevision });
    await createState(s, "linux-kvm");
    await assert.rejects(() => startTrustedOpenBao(s, openBaoSeams(events)), /launcher openbao failed/);
    assert.equal(events.length, 0);
    await writePhase(s, await readManifest(s), "sandbox-ready");
    const newer = await resolveLauncherState({ root, name: "s1", sourceRevision: "b".repeat(40) });
    await assert.rejects(() => startTrustedOpenBao(newer, openBaoSeams(events)), /launcher openbao failed/);
    assert.equal(events.length, 0);
    events.push("inventory-busy");
    await assert.rejects(() => startTrustedOpenBao(s, openBaoSeams(events)), /launcher openbao failed/);
    assert.equal(
      events.some((e) => e.includes(" run ")),
      false,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao rejects non-frozen seams and redacts secrets from errors", async () => {
  const { dir, state: s } = await state();
  try {
    await assert.rejects(
      () => startTrustedOpenBao(s, { ...openBaoSeams() } as OpenBaoSeams),
      (e) => {
        assert.match(String(e), /launcher openbao failed/);
        assert.equal(String(e).includes("rootToken"), false);
        return true;
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao cooperative preabort avoids docker and option bags are strict", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      () => startTrustedOpenBaoCooperative(s, { signal: controller.signal }, openBaoSeams(events)),
      /launcher openbao failed/,
    );
    assert.equal(events.length, 0);
    await assert.rejects(() => startTrustedOpenBaoCooperative(s, { deadlineAt: Date.now() }, openBaoSeams(events)));
    let invoked = false;
    await assert.rejects(() =>
      startTrustedOpenBaoCooperative(
        s,
        Object.defineProperty({}, "signal", {
          get: () => {
            invoked = true;
            return controller.signal;
          },
          enumerable: true,
        }) as never,
        openBaoSeams(events),
      ),
    );
    assert.equal(invoked, false);
    await assert.rejects(() => startTrustedOpenBaoCooperative(s, Object.assign(Object.create(null), {}) as never));
    await assert.rejects(() => startTrustedOpenBaoCooperative(s, { [Symbol()]: true } as never));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao abort after run removes exact owned container before rejecting", async () => {
  const { dir, state: s } = await state();
  const controller = new AbortController();
  const events: string[] = [];
  const base = openBaoSeams(events);
  const seams = Object.freeze({
    ...base,
    docker: Object.freeze(async (args: readonly string[], options?: { signal?: AbortSignal }) => {
      const result = await base.docker?.(args, options);
      if (args[1] === "run") queueMicrotask(() => controller.abort());
      return result ?? { status: 1, stdout: "" };
    }),
  }) as OpenBaoSeams;
  try {
    await assert.rejects(
      () => startTrustedOpenBaoCooperative(s, { signal: controller.signal }, seams),
      /launcher openbao failed/,
    );
    assert.ok(events.some((e) => e.includes("docker rm -f")));
    assert.equal(JSON.stringify(events).includes("Token123"), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao cooperative close is same promise, wipes secrets, and rejects hostile close options", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    const bao = await startTrustedOpenBaoCooperative(s, {}, openBaoSeams(events));
    assert.throws(() => bao.close({ signal: {} as AbortSignal }));
    assert.throws(() =>
      bao.close(Object.defineProperty({}, "deadlineAt", { get: () => Date.now(), enumerable: true }) as never),
    );
    const close = bao.close({ deadlineAt: Date.now() + 5000 });
    assert.equal(bao.close(), close);
    await close;
    assert.throws(() => bao.modelToken.withSecret(() => undefined));
    assert.throws(() => bao.egressToken.withSecret(() => undefined));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao expired deadline after run rolls back exactly once with fresh cleanup", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  const base = openBaoSeams(events);
  const seams = Object.freeze({
    ...base,
    docker: Object.freeze(async (args: readonly string[], options?: { signal?: AbortSignal; deadlineAt?: number }) => {
      const result = await base.docker?.(args, options);
      if (args[1] === "run") await new Promise((resolve) => setTimeout(resolve, 120));
      return result ?? { status: 1, stdout: "" };
    }),
  }) as OpenBaoSeams;
  try {
    await assert.rejects(
      () => startTrustedOpenBaoCooperative(s, { deadlineAt: Date.now() + 100 }, seams),
      /launcher openbao failed/,
    );
    assert.equal(events.filter((e) => e.includes("docker rm -f")).length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao rollback cleanup failures dominate generically", async () => {
  for (const mode of ["inspect", "rm", "inventory"] as const) {
    const { dir, state: s } = await state();
    const events: string[] = [];
    const base = openBaoSeams(events);
    const seams = Object.freeze({
      ...base,
      docker: Object.freeze(
        async (args: readonly string[], options?: { signal?: AbortSignal; deadlineAt?: number }) => {
          if (mode === "inspect" && args[1] === "inspect") return { status: 1, stdout: "" };
          if (mode === "rm" && args[1] === "rm") return { status: 1, stdout: "" };
          if (mode === "inventory" && args[1] === "ps" && events.some((e) => e.includes("docker rm -f")))
            return { status: 0, stdout: `${"a".repeat(64)}\n` };
          const result = await base.docker?.(args, options);
          if (args[1] === "run") queueMicrotask(() => controller.abort());
          return result ?? { status: 1, stdout: "" };
        },
      ),
    }) as OpenBaoSeams;
    const controller = new AbortController();
    try {
      await assert.rejects(
        () => startTrustedOpenBaoCooperative(s, { signal: controller.signal }, seams),
        /launcher openbao failed/,
      );
      assert.equal(String(events).includes("Token123"), false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("openbao revoke failures are redacted while exact removal and secret wiping complete", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  const base = openBaoSeams(events);
  const seams = Object.freeze({
    ...base,
    fetch: Object.freeze(async (url: string | URL | Request, init?: RequestInit) => {
      const u = new URL(String(url));
      if (u.pathname === "/v1/auth/token/revoke-self") return json({ failed: true }, 500);
      return (base.fetch as typeof fetch)(url, init);
    }) as typeof fetch,
  }) as OpenBaoSeams;
  try {
    const bao = await startTrustedOpenBaoCooperative(s, {}, seams);
    await bao.close();
    assert.ok(events.some((e) => e.includes("docker rm -f")));
    assert.throws(() => bao.modelToken.withSecret(() => undefined));
    assert.throws(() => bao.egressToken.withSecret(() => undefined));
    assert.equal(JSON.stringify(events).includes("Token123"), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openbao cooperative docker and fetch receive cancellation authority", async () => {
  const first = await state();
  try {
    const controller = new AbortController();
    let observedDockerAbort = false;
    const seams = Object.freeze({
      docker: Object.freeze(
        (_args: readonly string[], options?: { signal?: AbortSignal }) =>
          new Promise<{ status: number; stdout: string }>((_resolve, reject) => {
            options?.signal?.addEventListener("abort", () => {
              observedDockerAbort = true;
              reject(new Error("aborted"));
            });
            queueMicrotask(() => controller.abort());
          }),
      ),
      fetch: openBaoSeams().fetch,
      randomBytes: openBaoSeams().randomBytes,
    }) as OpenBaoSeams;
    const started = startTrustedOpenBaoCooperative(first.state, { signal: controller.signal }, seams);
    await assert.rejects(started, /launcher openbao failed/);
    assert.equal(observedDockerAbort, true);
  } finally {
    await rm(first.dir, { recursive: true, force: true });
  }

  const second = await state();
  try {
    const controller = new AbortController();
    const events: string[] = [];
    const base = openBaoSeams(events);
    let observedFetchAbort = false;
    const seams = Object.freeze({
      ...base,
      fetch: Object.freeze((url: string | URL | Request, init?: RequestInit) => {
        const u = new URL(String(url));
        if (u.pathname === "/v1/sys/health") {
          queueMicrotask(() => controller.abort());
          return new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => {
              observedFetchAbort = true;
              reject(new Error("aborted"));
            });
          });
        }
        return (base.fetch as typeof fetch)(url, init);
      }) as typeof fetch,
    }) as OpenBaoSeams;
    await assert.rejects(
      () => startTrustedOpenBaoCooperative(second.state, { signal: controller.signal }, seams),
      /launcher openbao failed/,
    );
    assert.equal(observedFetchAbort, true);
    assert.ok(events.some((e) => e.includes("docker rm -f")));
  } finally {
    await rm(second.dir, { recursive: true, force: true });
  }
});

test("openbao docker seams receive cooperative signal and deadline", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  const base = openBaoSeams(events);
  const controller = new AbortController();
  let sawSignal = false,
    sawDeadline = false;
  const seams = Object.freeze({
    ...base,
    docker: Object.freeze(async (args: readonly string[], options?: { signal?: AbortSignal; deadlineAt?: number }) => {
      sawSignal ||= options?.signal === controller.signal;
      sawDeadline ||= typeof options?.deadlineAt === "number";
      return (await base.docker?.(args, options)) ?? { status: 1, stdout: "" };
    }),
  }) as OpenBaoSeams;
  try {
    await assert.rejects(
      () => startTrustedOpenBaoCooperative(s, { deadlineAt: Date.now() + 31_000 }, seams),
      /launcher openbao failed/,
    );
    const bao = await startTrustedOpenBaoCooperative(
      s,
      { signal: controller.signal, deadlineAt: Date.now() + 29_000 },
      seams,
    );
    await bao.close();
    assert.equal(sawSignal, true);
    assert.equal(sawDeadline, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

async function post(url: string, body = "", headers: Record<string, string> = {}) {
  return fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
}

test("local fixtures serve real loopback upstream routes with metadata-only snapshots", async () => {
  const f = await startLocalFixtures({ credential: "cogs-dev-egress-key" });
  try {
    const health = await fetch(`${f.endpoint()}/health`);
    const allowed = await fetch(`${f.endpoint()}/allowed`);
    const allowedPost = await post(`${f.endpoint()}/allowed`, "ignored body");
    const credential = await post(`${f.endpoint()}/credential`, "ignored", {
      authorization: "Bearer cogs-dev-egress-key",
    });
    assert.equal(health.status, 200);
    assert.equal(allowed.status, 200);
    assert.equal(allowedPost.status, 200);
    assert.equal(credential.status, 200);
    assert.equal(credential.headers.get("x-cogs-fixture-proof"), "launcher-v1");
    for (const response of [health, allowed, allowedPost])
      assert.equal(response.headers.get("x-cogs-fixture-proof"), null);
    const snap = f.snapshot();
    assert.equal(snap.total, 4);
    assert.equal(snap.counts["GET /health 200"], 1);
    assert.equal(JSON.stringify(snap).includes("ignored"), false);
    f.reset();
    assert.equal(f.snapshot().total, 0);
  } finally {
    await f.close();
  }
});

test("local fixtures reject credential malformed oversize duplicate headers and close raw sockets", async () => {
  const f = await startLocalFixtures({
    credential: "cogs-dev-egress-key",
    maxBytes: 256,
    deadlineMs: 60,
    maxRecords: 3,
  });
  try {
    const unauthorized = await post(`${f.endpoint()}/credential`, "", { authorization: "Bearer wrong" });
    assert.equal(unauthorized.status, 401);
    assert.equal(unauthorized.headers.get("x-cogs-fixture-proof"), null);
    assert.notEqual((await post(`${f.endpoint()}/nope`, "{}")).status, 200);
    assert.notEqual((await post(`${f.endpoint()}/allowed`, "x".repeat(300))).status, 200);
    assert.equal((await fetch(`${f.endpoint()}/allowed`)).status, 200);
    assert.equal((await fetch(`${f.endpoint()}/allowed`)).status, 200);
    assert.equal((await fetch(`${f.endpoint()}/allowed`)).status, 429);
    const getSock = new Socket();
    const getChunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) =>
      getSock.connect(f.snapshot().port, "127.0.0.1", resolve).once("error", reject),
    );
    getSock.on("data", (c) => getChunks.push(Buffer.from(c)));
    const getSockClosed = new Promise((resolve) => getSock.once("close", resolve));
    getSock.end("GET /allowed HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    await getSockClosed;
    assert.match(Buffer.concat(getChunks).toString("utf8"), / 400 /u);
    const sock = new Socket();
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) =>
      sock.connect(f.snapshot().port, "127.0.0.1", resolve).once("error", reject),
    );
    sock.on("data", (c) => chunks.push(Buffer.from(c)));
    const sockClosed = new Promise((resolve) => sock.once("close", resolve));
    const body = "{}";
    sock.end(
      `POST /allowed HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
    await sockClosed;
    assert.match(Buffer.concat(chunks).toString("utf8"), / 400 /u);
  } finally {
    await f.close();
  }
  await assert.rejects(() => fetch(`${f.endpoint()}/allowed`, { method: "POST", body: "{}" }));
});

test("local fixtures reject reset while inflight and close idempotently under raw socket", async () => {
  const f = await startLocalFixtures({ credential: "cogs-dev-egress-key", deadlineMs: 80 });
  const sock = new Socket();
  try {
    await new Promise<void>((resolve, reject) =>
      sock.connect(f.snapshot().port, "127.0.0.1", resolve).once("error", reject),
    );
    sock.write(
      "POST /allowed HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.throws(() => f.reset());
    const closedRaw = new Promise((resolve) => sock.once("close", resolve));
    const started = Date.now();
    const close = f.close({ deadlineAt: Date.now() });
    assert.equal(f.close(), close);
    await close;
    await closedRaw;
    assert.ok(Date.now() - started < 1000);
  } finally {
    sock.destroy();
    await f.close().catch(() => undefined);
  }
});

test("local fixtures cooperative start and option bags are strict", async () => {
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(() => startLocalFixtures({ credential: "cogs-dev-egress-key", signal: aborted.signal }));
  await assert.rejects(() => startLocalFixtures({ credential: "cogs-dev-egress-key", deadlineAt: Date.now() }));
  await assert.rejects(() =>
    startLocalFixtures({ credential: "cogs-dev-egress-key", deadlineAt: Date.now() + 31_000 }),
  );
  const composed = await startLocalFixtures({ credential: "cogs-dev-egress-key", deadlineAt: Date.now() + 29_000 });
  await composed.close();
  let invoked = false;
  await assert.rejects(() =>
    startLocalFixtures(
      Object.defineProperty({ credential: "cogs-dev-egress-key" }, "signal", {
        get: () => {
          invoked = true;
          return aborted.signal;
        },
        enumerable: true,
      }) as never,
    ),
  );
  assert.equal(invoked, false);
  await assert.rejects(() =>
    startLocalFixtures(Object.assign(Object.create(null), { credential: "cogs-dev-egress-key" }) as never),
  );
  await assert.rejects(() => startLocalFixtures({ credential: "cogs-dev-egress-key", [Symbol()]: true } as never));
  const hostileSignal = new AbortController().signal;
  let signalAccessorInvoked = false;
  Object.defineProperties(hostileSignal, {
    aborted: {
      get: () => {
        signalAccessorInvoked = true;
        return true;
      },
    },
    addEventListener: {
      value: () => {
        signalAccessorInvoked = true;
        throw new Error("hostile add");
      },
    },
    removeEventListener: {
      value: () => {
        signalAccessorInvoked = true;
        throw new Error("hostile remove");
      },
    },
  });
  const f = await startLocalFixtures({ credential: "cogs-dev-egress-key", signal: hostileSignal });
  try {
    assert.equal(signalAccessorInvoked, false);
    assert.throws(() => f.close({ signal: {} as AbortSignal }));
    assert.throws(() => f.close({ deadlineMs: 100 } as never));
    assert.throws(() => f.close(Object.defineProperty({}, "deadlineAt", { get: () => Date.now(), enumerable: true })));
    await f.close({ signal: hostileSignal });
    assert.equal(signalAccessorInvoked, false);
  } finally {
    await f.close();
  }
});

test("local fixtures cooperative cancellation before ownership leaves no live server", async () => {
  for (let i = 0; i < 20; i++) {
    const controller = new AbortController();
    const started = startLocalFixtures({ credential: "cogs-dev-egress-key", signal: controller.signal });
    queueMicrotask(() => controller.abort());
    await assert.rejects(started, /launcher fixture failed/);
  }
});
