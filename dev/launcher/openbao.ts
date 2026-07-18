import { randomBytes, X509Certificate } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { Socket } from "node:net";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OPENBAO_IMAGE } from "../openbao-model-auth/image.ts";
import { hasDuplicateJsonKeys } from "./contract.ts";
import { commandDescriptor, runCommand } from "./runner.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";

export { OPENBAO_IMAGE };
export type SecretHolder = Readonly<{ withSecret<T>(op: (secret: string) => T): T; dispose(): void }>;
export type OpenBaoSnapshot = Readonly<{
  ready: boolean;
  name: string;
  containerId: string;
  port: number;
  image: string;
  seeded: "model-kv-egress-pki";
  egress: {
    mount: "model";
    pkiMount: "pki";
    pkiRole: "cogs-egress";
    credentialHandle: "users/alice/integrations/stage3-localhost";
  };
}>;
export type OpenBaoHandle = Readonly<{
  snapshot(): OpenBaoSnapshot;
  modelToken: SecretHolder;
  modelApiKey: SecretHolder;
  egressToken: SecretHolder;
  integrationCredential: SecretHolder;
  close(): Promise<void>;
}>;
export type OpenBaoSeams = Readonly<{
  docker?: (args: readonly string[]) => Promise<{ status: number; stdout: string }>;
  fetch?: typeof fetch;
  randomBytes?: typeof randomBytes;
}>;

const version = /^OpenBao\s+v2\.6\.0(?:[\s,]|$)/u;
const imageRe = /^quay\.io\/openbao\/openbao:2\.6\.0@sha256:([a-f0-9]{64})$/u;
const idRe = /^[a-f0-9]{64}$/u;
const secretRe = /^[A-Za-z0-9._~+/=-]{8,4096}$/u;
const pemCert = /^-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----\n?$/u;
const egressHandle = "users/alice/integrations/stage3-localhost";
const configPath = fileURLToPath(new URL("../openbao-model-auth/config.hcl", import.meta.url));
const expectedConfig =
  'disable_mlock = true\napi_addr = "http://127.0.0.1:8200"\n\nstorage "file" {\n  path = "/openbao/file"\n}\n\nlistener "tcp" {\n  address = "0.0.0.0:8200"\n  tls_disable = 1\n}\n';

type Exec = (args: readonly string[]) => Promise<{ status: number; stdout: string }>;
type Meta = { id: string; name: string; image: string; label: string; running: boolean; port: number };

export async function startTrustedOpenBao(state: LauncherState, seams?: OpenBaoSeams): Promise<OpenBaoHandle> {
  let root = "",
    unseal = "",
    model = "",
    egress = "",
    apiKey = "",
    integrationCredential = "";
  try {
    const digest = imageDigest();
    await validateState(state);
    await validateConfig();
    const s = snapSeams(seams, state.dir);
    apiKey = key(s.randomBytes);
    integrationCredential = key(s.randomBytes);
    if (integrationCredential === apiKey) fail();
    const exec = (a: readonly string[]) => dock(s.docker, a);
    const name = `cogs-openbao-${state.stateId}`,
      label = `cogs.dev.launcher.state=${state.stateId}`;
    const existing = await exec(["ps", "-a", "--filter", `label=${label}`, "--format", "{{.ID}}"]);
    if (existing.status !== 0 || existing.stdout.trim() !== "") fail();
    const img = await ok(exec(["image", "inspect", OPENBAO_IMAGE, "--format", "{{json .RepoDigests}}"]));
    if (!repoDigest(img.stdout, digest)) fail();
    const run = await ok(
      exec([
        "run",
        "--detach",
        "--rm",
        "--name",
        name,
        "--label",
        label,
        "--publish",
        "127.0.0.1::8200",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "100:1000",
        "--volume",
        `${configPath}:/openbao/cogs-config.hcl:ro`,
        OPENBAO_IMAGE,
        "server",
        "-config=/openbao/cogs-config.hcl",
      ]),
    );
    const id = oneLine(run.stdout);
    if (!idRe.test(id)) fail();
    let ready = false;
    try {
      const meta = await inspect(exec, name);
      if (!owned(meta, id, name, state.stateId) || !meta.running || meta.port < 1) fail();
      if (!version.test(oneLine((await ok(exec(["exec", name, "bao", "version"]))).stdout))) fail();
      const origin = `http://127.0.0.1:${meta.port}`;
      await waitReachable(s.fetch, origin);
      const init = await bao(
        s.fetch,
        origin,
        "/v1/sys/init",
        "POST",
        undefined,
        { secret_shares: 1, secret_threshold: 1 },
        [200],
      );
      root = str(init, "root_token");
      unseal = arrStr(init, "keys_base64");
      await bao(s.fetch, origin, "/v1/sys/unseal", "POST", undefined, { key: unseal }, [200]);
      unseal = "";
      await healthReady(s.fetch, origin);
      await bao(
        s.fetch,
        origin,
        "/v1/sys/mounts/model",
        "POST",
        root,
        { type: "kv", options: { version: "2" } },
        [200, 204],
      );
      await bao(
        s.fetch,
        origin,
        "/v1/model/data/users/alice/anthropic",
        "POST",
        root,
        { data: { api_key: apiKey } },
        [200, 204],
      );
      await bao(
        s.fetch,
        origin,
        "/v1/sys/policies/acl/cogs-model-auth-read",
        "PUT",
        root,
        { policy: 'path "model/data/users/alice/anthropic" { capabilities = ["read"] }' },
        [200, 204],
      );
      await bao(
        s.fetch,
        origin,
        `/v1/model/data/${egressHandle}`,
        "POST",
        root,
        { data: { api_key: integrationCredential } },
        [200, 204],
      );
      await bao(
        s.fetch,
        origin,
        "/v1/sys/mounts/pki",
        "POST",
        root,
        { type: "pki", config: { max_lease_ttl: "24h" } },
        [200, 204],
      );
      const ca = await bao(
        s.fetch,
        origin,
        "/v1/pki/root/generate/internal",
        "POST",
        root,
        { common_name: "localhost", ttl: "24h" },
        [200],
      );
      certOnly(ca);
      await bao(
        s.fetch,
        origin,
        "/v1/pki/roles/cogs-egress",
        "POST",
        root,
        {
          allowed_domains: ["localhost"],
          allow_bare_domains: true,
          allow_subdomains: false,
          allow_localhost: false,
          max_ttl: "8h",
          ttl: "2h",
          key_type: "rsa",
          key_bits: 2048,
        },
        [200, 204],
      );
      await bao(
        s.fetch,
        origin,
        "/v1/sys/policies/acl/cogs-stage3-runtime",
        "PUT",
        root,
        {
          policy: [
            `path "model/data/${egressHandle}" { capabilities = ["read"] }`,
            `path "model/metadata/${egressHandle}" { capabilities = ["read"] }`,
            'path "pki/issue/cogs-egress" { capabilities = ["update"] }',
          ].join("\n"),
        },
        [200, 204],
      );
      model = token(
        await bao(
          s.fetch,
          origin,
          "/v1/auth/token/create-orphan",
          "POST",
          root,
          { policies: ["cogs-model-auth-read"], ttl: "8h", explicit_max_ttl: "8h", renewable: false },
          [200],
        ),
      );
      egress = token(
        await bao(
          s.fetch,
          origin,
          "/v1/auth/token/create-orphan",
          "POST",
          root,
          { policies: ["cogs-stage3-runtime"], ttl: "8h", explicit_max_ttl: "8h", renewable: false },
          [200],
        ),
      );
      if (egress === model || egress === root) fail();
      ready = true;
      const clear = () => {
        ready = false;
        root = "";
        unseal = "";
        model = "";
        egress = "";
        apiKey = "";
        integrationCredential = "";
      };
      return Object.freeze({
        snapshot: () =>
          Object.freeze({
            ready,
            name,
            containerId: id,
            port: meta.port,
            image: OPENBAO_IMAGE,
            seeded: "model-kv-egress-pki" as const,
            egress: {
              mount: "model",
              pkiMount: "pki",
              pkiRole: "cogs-egress",
              credentialHandle: egressHandle,
            } as const,
          }),
        modelToken: holder(
          () => model,
          (v) => (model = v),
        ),
        modelApiKey: holder(
          () => apiKey,
          (v) => (apiKey = v),
        ),
        egressToken: holder(
          () => egress,
          (v) => (egress = v),
        ),
        integrationCredential: holder(
          () => integrationCredential,
          (v) => (integrationCredential = v),
        ),
        close: once(async () => {
          try {
            const before = await inspect(exec, name);
            if (!ownedLive(before, id, name, state.stateId, meta.port)) fail();
            await revoke(s.fetch, origin, model);
            model = "";
            await revoke(s.fetch, origin, egress);
            egress = "";
            await revoke(s.fetch, origin, root);
            root = "";
            const latest = await inspect(exec, name);
            if (!ownedLive(latest, id, name, state.stateId, meta.port)) fail();
            await ok(exec(["rm", "-f", id]));
            const left = await exec(["ps", "-a", "--filter", `label=${label}`, "--format", "{{.ID}}"]);
            if (left.status !== 0 || left.stdout.trim() !== "") fail();
            await closedPort(meta.port);
          } finally {
            clear();
          }
        }),
      });
    } catch (e) {
      const meta = await inspect(exec, name).catch(() => undefined);
      if (meta && owned(meta, id, name, state.stateId)) await ok(exec(["rm", "-f", id])).catch(() => undefined);
      throw e;
    }
  } catch {
    root = "";
    unseal = "";
    model = "";
    egress = "";
    apiKey = "";
    integrationCredential = "";
    throw fail();
  }
}

async function validateState(state: LauncherState) {
  const manifest = await readManifest(state);
  if (manifest.phase !== "sandbox-ready" || manifest.sourceRevision !== state.sourceRevision) fail();
  const st = await lstat(state.controlDir);
  if (
    !st.isDirectory() ||
    st.isSymbolicLink() ||
    (st.mode & 0o777) !== 0o700 ||
    (await realpath(state.controlDir)) !== state.controlDir
  )
    fail();
  if (typeof process.geteuid === "function" && st.uid !== process.geteuid()) fail();
}
async function validateConfig() {
  const st = await lstat(configPath);
  if (
    !st.isFile() ||
    st.isSymbolicLink() ||
    (await realpath(configPath)) !== configPath ||
    dirname(configPath).endsWith("openbao-model-auth") === false
  )
    fail();
  if ((await readFile(configPath, "utf8")) !== expectedConfig) fail();
}
function snapSeams(v: OpenBaoSeams | undefined, cwd: string): Required<OpenBaoSeams> {
  if (v === undefined) return Object.freeze({ docker: defaultDocker(cwd), fetch, randomBytes });
  if (!v || typeof v !== "object" || !Object.isFrozen(v) || Object.getPrototypeOf(v) !== Object.prototype) fail();
  const d = Object.getOwnPropertyDescriptors(v);
  for (const k of Reflect.ownKeys(d)) {
    if (typeof k !== "string" || !["docker", "fetch", "randomBytes"].includes(k)) fail();
    const x = d[k];
    if (!x || !("value" in x) || x.enumerable !== true || typeof x.value !== "function" || !Object.isFrozen(x.value))
      fail();
  }
  return Object.freeze({
    docker: (d.docker?.value ?? defaultDocker(cwd)) as Exec,
    fetch: (d.fetch?.value ?? fetch) as typeof fetch,
    randomBytes: (d.randomBytes?.value ?? randomBytes) as typeof randomBytes,
  });
}
function defaultDocker(cwd: string): Exec {
  return async (args: readonly string[]) => {
    const r = await runCommand(
      commandDescriptor({
        executable: "/usr/bin/docker",
        args: [...args].slice(1),
        cwd,
        env: { PATH: "/usr/bin:/bin" },
        timeoutMs: 15000,
        maxOutputBytes: 8192,
        killGraceMs: 1000,
      }),
    );
    return { status: r.status === "ok" && !r.cleanupUncertain ? 0 : 1, stdout: r.stdout };
  };
}
async function dock(exec: Exec, args: readonly string[]) {
  return exec(Object.freeze(["/usr/bin/docker", ...args]));
}
async function ok(p: Promise<{ status: number; stdout: string }>) {
  const r = await p;
  if (r.status !== 0 || r.stdout.length > 8192) fail();
  return r;
}
function oneLine(s: string) {
  if (!/^[^\n\r]{1,8192}\n?$/u.test(s)) fail();
  return s.trim();
}
function imageDigest() {
  const m = OPENBAO_IMAGE.match(imageRe);
  if (!m?.[1]) fail();
  return `sha256:${m[1]}`;
}
function repoDigest(s: string, digest: string) {
  const v = JSON.parse(oneLine(s));
  return Array.isArray(v) && v.some((x) => typeof x === "string" && x === `quay.io/openbao/openbao@${digest}`);
}
async function inspect(exec: Exec, name: string): Promise<Meta> {
  const j = JSON.parse(oneLine((await ok(exec(["inspect", name, "--format", "{{json .}}"]))).stdout)) as {
    Id?: string;
    Name?: string;
    Config?: { Image?: string; Labels?: Record<string, string> };
    State?: { Running?: boolean };
    NetworkSettings?: { Ports?: Record<string, Array<{ HostIp?: string; HostPort?: string }> | null> };
  };
  const b = j.NetworkSettings?.Ports?.["8200/tcp"]?.[0],
    port = Number(b?.HostPort ?? 0);
  return {
    id: j.Id ?? "",
    name: j.Name ?? "",
    image: j.Config?.Image ?? "",
    label: j.Config?.Labels?.["cogs.dev.launcher.state"] ?? "",
    running: j.State?.Running === true,
    port: b?.HostIp === "127.0.0.1" && Number.isSafeInteger(port) ? port : 0,
  };
}
function owned(m: Meta, id: string, name: string, stateId: string) {
  return m.id === id && m.name === `/${name}` && m.image === OPENBAO_IMAGE && m.label === stateId;
}
function ownedLive(m: Meta, id: string, name: string, stateId: string, port: number) {
  return owned(m, id, name, stateId) && m.running && m.port === port;
}
async function bao(
  fetcher: typeof fetch,
  origin: string,
  path: string,
  method: "GET" | "POST" | "PUT",
  tok: string | undefined,
  body: unknown,
  statuses: readonly number[],
) {
  if (!path.startsWith("/v1/")) fail();
  const ac = new AbortController(),
    t = setTimeout(() => ac.abort(), 5000);
  try {
    const h: Record<string, string> = { accept: "application/json" };
    if (tok) h["x-vault-token"] = tok;
    let b: string | undefined;
    if (body !== undefined) {
      b = JSON.stringify(body);
      h["content-type"] = "application/json";
    }
    const init: RequestInit = { method, headers: h, redirect: "error", signal: ac.signal };
    if (b !== undefined) init.body = b;
    const r = await fetcher(`${origin}${path}`, init);
    try {
      if (!statuses.includes(r.status)) fail();
      if (r.status === 204) return undefined;
      if (!/^application\/json(?:\s*;|$)/iu.test(r.headers.get("content-type") ?? "")) fail();
      const text = await bounded(r, 65536);
      if (hasDuplicateJsonKeys(text)) fail();
      const parsed = JSON.parse(text) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail();
      return parsed;
    } finally {
      await cancel(r);
    }
  } finally {
    clearTimeout(t);
  }
}
async function bounded(r: Response, max: number) {
  const rd = r.body?.getReader();
  if (!rd) return "";
  let n = 0,
    c = 0;
  const xs: Buffer[] = [];
  try {
    for (;;) {
      const x = await rd.read();
      if (x.done) break;
      if (!x.value || ++c > 1024) fail();
      n += x.value.byteLength;
      if (n > max) fail();
      xs.push(Buffer.from(x.value));
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(xs, n));
  } finally {
    rd.releaseLock();
    await cancel(r);
  }
}
async function cancel(r: Response) {
  await r.body?.cancel().catch(() => undefined);
}
async function waitReachable(fetcher: typeof fetch, origin: string) {
  for (let i = 0; i < 20; i++) {
    try {
      await health(fetcher, origin, [200, 429, 472, 473, 501, 503]);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  fail();
}
async function healthReady(fetcher: typeof fetch, origin: string) {
  const state = await health(fetcher, origin, [200]);
  if (state.initialized !== true || state.sealed !== false) fail();
}
async function health(fetcher: typeof fetch, origin: string, statuses: readonly number[]) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 5000);
  try {
    const r = await fetcher(`${origin}/v1/sys/health`, { method: "GET", redirect: "error", signal: ac.signal });
    try {
      if (!statuses.includes(r.status)) fail();
      if (!/^application\/json(?:\s*;|$)/iu.test(r.headers.get("content-type") ?? "")) fail();
      const text = await bounded(r, 4096);
      if (hasDuplicateJsonKeys(text)) fail();
      const parsed = JSON.parse(text) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail();
      const state = parsed as { initialized?: unknown; sealed?: unknown };
      if (typeof state.initialized !== "boolean" || typeof state.sealed !== "boolean") fail();
      return { initialized: state.initialized, sealed: state.sealed };
    } finally {
      await cancel(r);
    }
  } finally {
    clearTimeout(t);
  }
}
function key(rb: typeof randomBytes) {
  const b = rb(32);
  try {
    if (!Buffer.isBuffer(b) || b.length !== 32 || b.every((x) => x === 0)) fail();
    return b.toString("base64url");
  } finally {
    if (Buffer.isBuffer(b)) b.fill(0);
  }
}
function str(v: unknown, k: string) {
  const x = (v as Record<string, unknown>)[k];
  if (typeof x !== "string" || !secretRe.test(x)) fail();
  return x;
}
function arrStr(v: unknown, k: string) {
  const x = (v as Record<string, unknown>)[k];
  if (!Array.isArray(x) || x.length !== 1 || typeof x[0] !== "string" || !secretRe.test(x[0])) fail();
  return x[0];
}
function token(v: unknown) {
  return str((v as { auth?: unknown }).auth, "client_token");
}
function certOnly(v: unknown) {
  const d = (v as { data?: unknown }).data as Record<string, unknown>;
  if (!d || typeof d !== "object" || Array.isArray(d) || Object.hasOwn(d, "private_key")) fail();
  if (typeof d.certificate !== "string" || !pemCert.test(d.certificate)) fail();
  try {
    if (new X509Certificate(d.certificate).ca !== true) fail();
  } catch {
    fail();
  }
}
function holder(get: () => string, set: (v: string) => void): SecretHolder {
  return Object.freeze({
    withSecret: Object.freeze(<T>(op: (s: string) => T) => {
      const s = get();
      if (!s) fail();
      return op(s);
    }),
    dispose: Object.freeze(() => set("")),
  });
}
async function revoke(fetcher: typeof fetch, origin: string, tok: string) {
  if (tok) await bao(fetcher, origin, "/v1/auth/token/revoke-self", "POST", tok, {}, [200, 204]).catch(() => undefined);
}
function once(fn: () => Promise<void>) {
  let p: Promise<void> | undefined;
  return () =>
    (p ??= fn().catch(() => {
      throw fail();
    }));
}
async function closedPort(port: number) {
  await new Promise<void>((res, rej) => {
    const s = new Socket();
    const t = setTimeout(() => {
      s.destroy();
      rej(fail());
    }, 250);
    s.once("connect", () => {
      clearTimeout(t);
      s.destroy();
      rej(fail());
    });
    s.once("error", () => {
      clearTimeout(t);
      res();
    });
    s.connect(port, "127.0.0.1");
  });
}
function fail(): never {
  throw new Error("launcher openbao failed");
}
