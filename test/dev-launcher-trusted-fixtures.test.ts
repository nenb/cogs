import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { startLocalFixtures } from "../dev/launcher/fixtures.ts";
import { OPENBAO_IMAGE, type OpenBaoSeams, startTrustedOpenBao } from "../dev/launcher/openbao.ts";
import { createState, readManifest, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";

const sourceRevision = "a".repeat(40);
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
    if (u.pathname === "/v1/auth/token/create-orphan") return json({ auth: { client_token: "modelToken123" } });
    if (u.pathname === "/v1/auth/token/revoke-self") return json({});
    return json({ ok: true });
  }) as typeof fetch;
  return Object.freeze({ docker, fetch: fetchImpl, randomBytes: Object.freeze(() => Buffer.alloc(32, 7)) as never });
}

test("openbao lifecycle uses exact image, health sequence, model seed, and disposes holders", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    const bao = await startTrustedOpenBao(s, openBaoSeams(events));
    const snap = bao.snapshot();
    assert.equal(snap.ready, true);
    assert.equal(snap.image, OPENBAO_IMAGE);
    assert.equal(snap.seeded, "model-kv");
    assert.equal(JSON.stringify(snap).includes("Token123"), false);
    let model = "",
      key = "";
    bao.modelToken.withSecret((v) => (model = v));
    bao.modelApiKey.withSecret((v) => (key = v));
    assert.equal(model, "modelToken123");
    assert.match(key, /^[A-Za-z0-9_-]{43}$/u);
    assert.ok(events.includes("GET /v1/sys/health"));
    assert.ok(events.includes("POST /v1/sys/unseal"));
    await bao.close();
    assert.ok(events.some((e) => e.includes("docker rm -f")));
    assert.throws(() => bao.modelToken.withSecret(() => undefined));
    assert.throws(() => bao.modelApiKey.withSecret(() => undefined));
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

async function post(url: string, body = "", headers: Record<string, string> = {}) {
  return fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
}

test("local fixtures serve real loopback upstream routes with metadata-only snapshots", async () => {
  const f = await startLocalFixtures({ credential: "cogs-dev-egress-key" });
  try {
    assert.equal((await fetch(`${f.endpoint()}/health`)).status, 200);
    assert.equal((await fetch(`${f.endpoint()}/allowed`)).status, 200);
    assert.equal((await post(`${f.endpoint()}/allowed`, "ignored body")).status, 200);
    assert.equal(
      (await post(`${f.endpoint()}/credential`, "ignored", { authorization: "Bearer cogs-dev-egress-key" })).status,
      200,
    );
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
    assert.equal((await post(`${f.endpoint()}/credential`, "", { authorization: "Bearer wrong" })).status, 401);
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
    getSock.end("GET /allowed HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    await new Promise((resolve) => getSock.once("close", resolve));
    assert.match(Buffer.concat(getChunks).toString("utf8"), / 400 /u);
    const sock = new Socket();
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) =>
      sock.connect(f.snapshot().port, "127.0.0.1", resolve).once("error", reject),
    );
    sock.on("data", (c) => chunks.push(Buffer.from(c)));
    const body = "{}";
    sock.end(
      `POST /allowed HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
    await new Promise((resolve) => sock.once("close", resolve));
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
    const started = Date.now();
    await Promise.all([f.close(), f.close()]);
    assert.ok(Date.now() - started < 1000);
  } finally {
    sock.destroy();
    await f.close().catch(() => undefined);
  }
});
