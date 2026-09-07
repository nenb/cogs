import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink } from "node:fs/promises";
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
let certificates: { certificate: string; private_key: string; issuing_ca: string } | undefined;
function testCaPem() {
  if (certificates) return certificates;
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
    const leafKey = join(dir, "leaf.key"),
      csr = join(dir, "leaf.csr"),
      leaf = join(dir, "leaf.crt");
    execFileSync(
      "openssl",
      [
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-keyout",
        leafKey,
        "-out",
        csr,
      ],
      { stdio: "ignore" },
    );
    execFileSync(
      "openssl",
      [
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        cert,
        "-CAkey",
        key,
        "-CAcreateserial",
        "-days",
        "1",
        "-copy_extensions",
        "copy",
        "-out",
        leaf,
      ],
      { stdio: "ignore" },
    );
    certificates = {
      certificate: readFileSync(leaf, "utf8"),
      private_key: readFileSync(leafKey, "utf8"),
      issuing_ca: readFileSync(cert, "utf8"),
    };
    return certificates;
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
    healthy = false,
    running = false,
    rootLive = true;
  let nonce = "",
    config = "";
  const keys = new Map<string, string>();
  const tokens = new Map<string, string>();
  const id = "a".repeat(64);
  const docker = Object.freeze(async (raw: readonly string[]) => {
    events.push(`docker ${raw.join(" ")}`);
    assert.equal(raw[0], "/usr/bin/docker");
    const args = raw.slice(1);
    if (args[0] === "image")
      return {
        status: 0,
        stdout: `${JSON.stringify({ Id: `sha256:${"b".repeat(64)}`, RepoDigests: [OPENBAO_IMAGE.replace(":2.6.1@", "@")], Os: "linux", Architecture: "amd64", Config: { Volumes: { "/openbao/file": {} } } })}\n`,
      };
    if (args[0] === "create") {
      assert.equal(args[args.indexOf("--pull") + 1], "never");
      assert.ok(args.includes("--read-only"));
      assert.ok(args.includes("/openbao/file:rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid=100,gid=1000"));
      nonce = String(args[args.indexOf("--label") + 1]).split("=")[1] ?? "";
      config = String(args[args.indexOf("--volume") + 1]).split(":")[0] ?? "";
      assert.ok(args.includes("--cap-drop") && args.includes("ALL"));
      assert.ok(args.includes("no-new-privileges"));
      assert.equal(args.includes("--rm"), false);
      assert.ok(args.includes("100:1000"));
      assert.ok(args.includes("127.0.0.1::8200"));
      assert.ok(args.includes(OPENBAO_IMAGE));
      container = String(args[args.indexOf("--name") + 1]);
      return { status: 0, stdout: `${id}\n` };
    }
    if (args[0] === "start") {
      running = true;
      return { status: 0, stdout: `${id}\n` };
    }
    if (args[0] === "inspect") {
      inspectCount++;
      return {
        status: 0,
        stdout: `${JSON.stringify({
          Id: badInspect || (badClose && inspectCount > 3) ? "c".repeat(64) : id,
          Image: `sha256:${"b".repeat(64)}`,
          Name: `/${container}`,
          Config: {
            User: "100:1000",
            Image: OPENBAO_IMAGE,
            Labels: {
              "cogs.dev.launcher.state": container.replace("cogs-openbao-", ""),
              "cogs.dev.launcher.acquisition": nonce,
            },
          },
          HostConfig: {
            ReadonlyRootfs: true,
            Tmpfs: { "/openbao/file": "rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid=100,gid=1000" },
            CapDrop: ["ALL"],
            SecurityOpt: ["no-new-privileges"],
            VolumesFrom: null,
            NetworkMode: "default",
            RestartPolicy: { Name: "no" },
          },
          Mounts: [
            { Type: "tmpfs", Destination: "/openbao/file", RW: true },
            {
              Type: "bind",
              Source: config,
              Destination: "/openbao/cogs-config.hcl",
              RW: false,
              Propagation: "rprivate",
            },
          ],
          State: { Running: running },
          NetworkSettings: { Ports: { "8200/tcp": [{ HostIp: "127.0.0.1", HostPort: "9" }] } },
        })}\n`,
      };
    }
    if (args[0] === "exec") return { status: 0, stdout: "OpenBao v2.6.1\n" };
    if (args[0] === "rm") return { status: 0, stdout: "" };
    if (args[0] === "ps") return { status: 0, stdout: events.includes("inventory-busy") ? `${id}\n` : "" };
    return { status: 1, stdout: "" };
  });
  const fetchImpl = Object.freeze(async (url: string | URL | Request, init?: RequestInit) => {
    const u = new URL(String(url));
    events.push(`${init?.method ?? "GET"} ${u.pathname}`);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const tok = new Headers(init?.headers).get("x-vault-token") ?? "";
    const policy = tokens.get(tok);
    const denial = () => json({ errors: ["permission denied"] }, 403);
    if (tok === "rootToken123" && !rootLive) return denial();
    if (policy) {
      const ownPath =
        policy === "cogs-model-auth-read" ? "users/alice/anthropic" : "users/alice/integrations/stage3-localhost";
      if (u.pathname === "/v1/auth/token/lookup-self")
        return json({
          data: {
            id: tok,
            policies: [policy],
            orphan: true,
            renewable: false,
            type: "service",
            explicit_max_ttl: 29151,
            ttl: 29151,
            num_uses: 0,
          },
        });
      if (u.pathname === "/v1/auth/token/revoke-self") {
        tokens.delete(tok);
        return new Response(null, { status: 204 });
      }
      if (init?.method === "GET" && u.pathname === `/v1/model/data/${ownPath}`)
        return json({
          data: {
            data: { api_key: keys.get(ownPath) },
            metadata: { version: 1, created_time: "2026-09-07T00:00:00Z" },
          },
        });
      if (policy === "cogs-stage3-runtime" && init?.method === "GET" && u.pathname === `/v1/model/metadata/${ownPath}`)
        return json({ data: { current_version: 1, versions: { "1": { created_time: "2026-09-07T00:00:00Z" } } } });
      if (policy === "cogs-stage3-runtime" && u.pathname === "/v1/pki/issue/cogs-egress")
        return body.common_name === "localhost" ? json({ data: testCaPem() }) : json({ errors: ["invalid name"] }, 400);
      return denial();
    }
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
    if (u.pathname === "/v1/pki/root/generate/internal") return json({ data: { certificate: testCaPem().issuing_ca } });
    if (u.pathname.startsWith("/v1/model/data/") && tok === "rootToken123") {
      keys.set(u.pathname.slice("/v1/model/data/".length), body.data.api_key);
      return json({});
    }
    if (u.pathname === "/v1/pki/roles/cogs-egress") {
      assert.deepEqual(body, {
        allowed_domains: ["localhost"],
        allow_bare_domains: true,
        allow_subdomains: false,
        allow_localhost: false,
        allow_any_name: false,
        allow_glob_domains: false,
        allow_wildcard_certificates: false,
        allow_ip_sans: false,
        max_ttl: "9h",
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
      assert.equal(body.ttl, "29151s");
      assert.equal(body.explicit_max_ttl, "29151s");
      assert.equal(body.no_default_policy, true);
      assert.equal(body.type, "service");
      assert.equal(body.num_uses, 0);
      assert.equal(body.renewable, false);
      assert.deepEqual(body.policies, [tokenCount === 1 ? "cogs-model-auth-read" : "cogs-stage3-runtime"]);
      const token = tokenCount === 1 ? "modelToken123" : "egressToken123";
      tokens.set(token, body.policies[0]);
      return json({
        auth: {
          client_token: token,
          policies: body.policies,
          token_type: "service",
          renewable: false,
          lease_duration: 29151,
        },
      });
    }
    if (u.pathname === "/v1/auth/token/revoke-self" && tok === "rootToken123") {
      rootLive = false;
      events.push("root-retired");
      return new Response(null, { status: 204 });
    }
    if (
      tok === "rootToken123" &&
      (u.pathname === "/v1/sys/mounts/model" ||
        u.pathname === "/v1/sys/mounts/pki" ||
        u.pathname === "/v1/sys/policies/acl/cogs-model-auth-read")
    )
      return json({});
    return denial();
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
      if (args[1] === "create") queueMicrotask(() => controller.abort());
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

test("openbao cooperative close has fresh observers, wipes secrets, and rejects hostile close options", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [];
  try {
    const bao = await startTrustedOpenBaoCooperative(s, {}, openBaoSeams(events));
    assert.throws(() => bao.close({ signal: {} as AbortSignal }));
    assert.throws(() =>
      bao.close(Object.defineProperty({}, "deadlineAt", { get: () => Date.now(), enumerable: true }) as never),
    );
    const close = bao.close({ deadlineAt: Date.now() + 5000 });
    assert.notEqual(bao.close(), close);
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
      if (args[1] === "create") await new Promise((resolve) => setTimeout(resolve, 120));
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
          if (args[1] === "create") queueMicrotask(() => controller.abort());
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
      if (
        u.pathname === "/v1/auth/token/revoke-self" &&
        new Headers(init?.headers).get("x-vault-token") !== "rootToken123"
      )
        return json({ failed: true }, 500);
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

test("synthetic-only launcher blocks the retired default artifact before effects", async () => {
  const { dir, state: s } = await state();
  try {
    await assert.rejects(startTrustedOpenBao(s), /launcher openbao failed/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("intent precedes create; failed, malformed, late and uncertain acquisition retains exact custody", async () => {
  for (const mode of ["malformed", "nonzero", "throw", "late", "uncertain"] as const) {
    const { dir, state: s } = await state();
    const events: string[] = [],
      base = openBaoSeams(events);
    let producerSettled = false;
    const intentPath = join(s.controlDir, "openbao-acquisition.json");
    const seams = Object.freeze({
      ...base,
      docker: Object.freeze(async (args: readonly string[]) => {
        if (args[1] === "create") {
          const intent = JSON.parse(await readFile(intentPath, "utf8"));
          assert.equal((await lstat(intentPath)).mode & 0o777, 0o600);
          assert.equal(intent.name, args[args.indexOf("--name") + 1]);
          assert.equal(args.includes(`cogs.dev.launcher.acquisition=${intent.nonce}`), true);
          assert.doesNotMatch(JSON.stringify(intent), /Token123|PRIVATE|api_key/);
          if (mode === "late") await new Promise((resolve) => setTimeout(resolve, 80));
          await base.docker?.(args);
          producerSettled = true;
          if (mode === "throw") throw new Error("rootToken123");
          return {
            status: mode === "nonzero" ? 1 : 0,
            stdout: mode === "uncertain" ? `${"a".repeat(64)}\n` : "truncated",
            cleanupUncertain: mode === "uncertain",
          };
        }
        if (args[1] === "rm") {
          assert.equal(producerSettled, true);
          assert.equal(args[3], "a".repeat(64));
        }
        return (await base.docker?.(args)) ?? { status: 1, stdout: "" };
      }),
    });
    try {
      await assert.rejects(
        startTrustedOpenBaoCooperative(s, mode === "late" ? { deadlineAt: Date.now() + 40 } : {}, seams),
        /launcher openbao failed/,
      );
      assert.equal(events.filter((e) => e.includes("docker rm -f")).length, 1);
      assert.equal(events.includes("POST /v1/sys/init"), false);
      if (mode === "uncertain") {
        await lstat(intentPath);
        const creates = events.filter((e) => e.includes("docker create")).length;
        await assert.rejects(startTrustedOpenBao(s, seams));
        assert.equal(events.filter((e) => e.includes("docker create")).length, creates);
      } else await assert.rejects(lstat(intentPath), { code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("root ack, denial and exact orphan capabilities are mandatory, never rescued by cleanup", async () => {
  for (const mode of [
    "root403",
    "root500",
    "root200",
    "still-root",
    "wrong-denial",
    "bad-denial",
    "model-root",
    "default-policy",
    "identity-policy",
    "renewable",
    "clipped",
    "warning",
    "not-orphan",
    "overprivileged",
    "post-root-failure",
  ] as const) {
    const { dir, state: s } = await state();
    const events: string[] = [],
      base = openBaoSeams(events);
    const seams = Object.freeze({
      ...base,
      fetch: Object.freeze(async (url: string | URL | Request, init?: RequestInit) => {
        const path = new URL(String(url)).pathname,
          tok = new Headers(init?.headers).get("x-vault-token");
        if (tok === "rootToken123" && path.endsWith("revoke-self") && mode.startsWith("root"))
          return json({}, Number(mode.slice(4)));
        if (tok === "rootToken123" && path.endsWith("lookup-self")) {
          if (mode === "still-root") return json({ data: {} });
          if (mode === "wrong-denial") return json({ errors: ["no"] }, 404);
          if (mode === "bad-denial") return json({ errors: "rootToken123" }, 403);
        }
        if (mode === "overprivileged" && path.endsWith("users/bob/anthropic")) return json({});
        if (mode === "post-root-failure" && events.includes("root-retired") && tok === "modelToken123")
          return json({}, 500);
        const r = await (base.fetch as typeof fetch)(url, init);
        if (path.endsWith("create-orphan") && tok === "rootToken123") {
          const value = (await r.json()) as {
            auth: {
              client_token: string;
              policies: string[];
              identity_policies?: string[];
              renewable: boolean;
              lease_duration: number;
            };
            warnings?: string[];
          };
          if (mode === "model-root") value.auth.client_token = "rootToken123";
          if (mode === "default-policy") value.auth.policies.push("default");
          if (mode === "identity-policy") value.auth.identity_policies = ["extra"];
          if (mode === "renewable") value.auth.renewable = true;
          if (mode === "clipped") value.auth.lease_duration = 28800;
          if (mode === "warning") value.warnings = ["TTL clipped"];
          return json(value);
        }
        if (mode === "not-orphan" && path.endsWith("lookup-self") && tok !== "rootToken123") {
          const value = (await r.json()) as { data: { orphan: boolean } };
          value.data.orphan = false;
          return json(value);
        }
        return r;
      }) as typeof fetch,
    });
    try {
      await assert.rejects(startTrustedOpenBao(s, seams), (error) => {
        assert.equal(String(error), "Error: launcher openbao failed");
        return true;
      });
      assert.equal(events.filter((e) => e.includes("docker rm -f")).length, 1);
      await assert.rejects(lstat(join(s.controlDir, "openbao-acquisition.json")), { code: "ENOENT" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("storage and publication mutations never reach initialization", async () => {
  for (const mode of [
    "image-volume",
    "image-id",
    "volume",
    "writable",
    "uid",
    "tmpfs",
    "extra-port",
    "public-port",
  ] as const) {
    const { dir, state: s } = await state();
    const events: string[] = [],
      base = openBaoSeams(events);
    const seams = Object.freeze({
      ...base,
      docker: Object.freeze(async (args: readonly string[]) => {
        const result = await (base.docker as NonNullable<OpenBaoSeams["docker"]>)(args);
        if (mode === "image-volume" && args[1] === "image") {
          const image = JSON.parse(result.stdout);
          image.Config.Volumes["/openbao/logs"] = {};
          return { status: 0, stdout: JSON.stringify(image) };
        }
        if (args[1] !== "inspect") return result;
        const j = JSON.parse(result.stdout);
        if (mode === "image-id") j.Image = `sha256:${"c".repeat(64)}`;
        if (mode === "volume") j.Mounts.push({ Type: "volume", Name: "unowned-volume", Destination: "/openbao/logs" });
        if (mode === "writable") j.HostConfig.ReadonlyRootfs = false;
        if (mode === "uid") j.Config.User = "0:0";
        if (mode === "tmpfs") j.HostConfig.Tmpfs["/openbao/file"] = "rw";
        if (mode === "extra-port") j.NetworkSettings.Ports["8200/tcp"].push({ HostIp: "127.0.0.1", HostPort: "10" });
        if (mode === "public-port") j.NetworkSettings.Ports["8200/tcp"][0].HostIp = "0.0.0.0";
        return { status: 0, stdout: JSON.stringify(j) };
      }),
    });
    try {
      await assert.rejects(startTrustedOpenBao(s, seams));
      assert.equal(events.includes("POST /v1/sys/init"), false);
      assert.equal(
        events.some((e) => e.includes("volume rm")),
        false,
      );
      if (mode === "image-volume")
        assert.equal(
          events.some((e) => e.includes("docker create")),
          false,
        );
      if (!["image-volume", "extra-port", "public-port"].includes(mode))
        await lstat(join(s.controlDir, "openbao-acquisition.json"));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("post-header abort cancels body; backend removal does not retire pending cancellation", async () => {
  for (const target of ["/v1/sys/init", "/v1/auth/token/revoke-self", "/v1/auth/token/lookup-self"]) {
    const { dir, state: s } = await state();
    const events: string[] = [],
      base = openBaoSeams(events),
      controller = new AbortController();
    let finishCancel = () => {},
      cancelled = false;
    const seams = Object.freeze({
      ...base,
      fetch: Object.freeze(async (url: string | URL | Request, init?: RequestInit) => {
        if (
          new URL(String(url)).pathname === target &&
          (target === "/v1/sys/init" || new Headers(init?.headers).get("x-vault-token") === "rootToken123")
        ) {
          setTimeout(() => controller.abort(), 5);
          const body = new ReadableStream({
            start(c) {
              c.enqueue(new TextEncoder().encode('{"root_token":'));
            },
            cancel() {
              cancelled = true;
              return new Promise<void>((resolve) => {
                finishCancel = resolve;
              });
            },
          });
          const response = new Response(body, { headers: { "content-type": "application/json" } });
          if (target.endsWith("lookup-self"))
            Object.defineProperty(body, "getReader", {
              value: () => {
                throw new Error("reader unavailable");
              },
            });
          return response;
        }
        return (base.fetch as typeof fetch)(url, init);
      }) as typeof fetch,
    });
    try {
      let settled = false;
      const started = startTrustedOpenBaoCooperative(
        s,
        { signal: controller.signal, deadlineAt: Date.now() + 5_000 },
        seams,
      ).finally(() => {
        settled = true;
      });
      const rejected = assert.rejects(started, /launcher openbao failed/);
      for (let n = 0; n < 100 && !(cancelled && events.some((e) => e.includes("docker rm -f"))); n++)
        await new Promise((r) => setTimeout(r, 5));
      assert.equal(cancelled, true);
      assert.ok(events.some((e) => e.includes("docker rm -f")));
      assert.equal(settled, false);
      await lstat(join(s.controlDir, "openbao-acquisition.json"));
      finishCancel();
      await rejected;
      await assert.rejects(lstat(join(s.controlDir, "openbao-acquisition.json")), { code: "ENOENT" });
    } finally {
      finishCancel();
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("close seals holders immediately and gives fresh observers around one root-free retirement", async () => {
  const { dir, state: s } = await state();
  const events: string[] = [],
    base = openBaoSeams(events);
  let release = () => {},
    closeStarted = false;
  const seams = Object.freeze({
    ...base,
    docker: Object.freeze(async (args: readonly string[]) => {
      if (args[1] === "rm")
        await new Promise<void>((resolve) => {
          release = resolve;
        });
      return (await base.docker?.(args)) ?? { status: 1, stdout: "" };
    }),
    fetch: Object.freeze(async (url: string | URL | Request, init?: RequestInit) => {
      if (closeStarted) assert.notEqual(new Headers(init?.headers).get("x-vault-token"), "rootToken123");
      return (base.fetch as typeof fetch)(url, init);
    }) as typeof fetch,
  });
  try {
    const bao = await startTrustedOpenBao(s, seams);
    assert.ok(events.includes("root-retired"));
    closeStarted = true;
    const short = bao.close({ deadlineAt: Date.now() + 10 });
    assert.throws(() => bao.modelToken.withSecret(() => {}));
    const long = bao.close({ deadlineAt: Date.now() + 5000 });
    await assert.rejects(short);
    await lstat(join(s.controlDir, "openbao-acquisition.json"));
    release();
    await long;
    await assert.rejects(bao.close({ deadlineAt: Date.now() }));
    await bao.close();
    assert.equal(events.filter((e) => e.includes("docker rm -f")).length, 1);
    assert.equal(bao.snapshot().ready, false);
  } finally {
    release();
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
    const credential = await fetch(`${f.endpoint()}/credential`, {
      headers: { authorization: "Bearer cogs-dev-egress-key" },
    });
    const credentialPost = await post(`${f.endpoint()}/credential`, "ignored", {
      authorization: "Bearer cogs-dev-egress-key",
    });
    assert.equal(health.status, 200);
    assert.equal(allowed.status, 200);
    assert.equal(allowedPost.status, 200);
    assert.equal(credential.status, 200);
    assert.equal(credentialPost.status, 200);
    assert.equal(credential.headers.get("x-cogs-fixture-proof"), `launcher-v1-${f.snapshot().port}`);
    for (const response of [health, allowed, allowedPost, credentialPost])
      assert.equal(response.headers.get("x-cogs-fixture-proof"), null);
    const snap = f.snapshot();
    assert.equal(snap.total, 5);
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
    const unauthorized = await fetch(`${f.endpoint()}/credential`, { headers: { authorization: "Bearer wrong" } });
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
    const later = f.close();
    assert.notEqual(later, close);
    await assert.rejects(close, /launcher fixture failed/);
    await later;
    await assert.rejects(f.close({ signal: AbortSignal.abort() }));
    await f.close();
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
