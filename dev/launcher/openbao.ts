import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, realpath, unlink } from "node:fs/promises";
import { Socket } from "node:net";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { OPENBAO_PKI_BUDGET, OpenBaoEgressPkiSource } from "../../src/egress/openbao-pki.ts";
import { OPENBAO_IMAGE } from "../openbao-model-auth/image.ts";
import { hasDuplicateJsonKeys } from "./contract.ts";
import { commandDescriptor, type RunnerResult, runCommand } from "./runner.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";

export { OPENBAO_IMAGE };
export type OpenBaoCooperativeOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;
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
  close(options?: OpenBaoCooperativeOptions): Promise<void>;
}>;
export type OpenBaoSeams = Readonly<{
  docker?: (args: readonly string[], options?: OpenBaoCooperativeOptions) => Promise<DockerResult>;
  fetch?: typeof fetch;
  randomBytes?: typeof randomBytes;
}>;

const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const EVENT_ADD = EventTarget.prototype.addEventListener;
const EVENT_REMOVE = EventTarget.prototype.removeEventListener;
const MAX_COOPERATIVE_DEADLINE_MS = 30_000;
const deadlines = new WeakMap<OpenBaoCooperativeOptions, number>();
// 8h session + 30s bootstrap + maximum 300s margin + 15s drain + 5s clock + 1s rounding.
const tokenSeconds = OPENBAO_PKI_BUDGET.maxSessionMs / 1000 + 30 + OPENBAO_PKI_BUDGET.maxMarginMs / 1000 + 15 + 5 + 1;
const selfPolicy =
  'path "auth/token/lookup-self" { capabilities = ["read"] }\npath "auth/token/revoke-self" { capabilities = ["update"] }';
const tmpfs = "/openbao/file:rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid=100,gid=1000";
// Strong custody survives failed-start observation. Only actual settlement removes work.
const custody = new Set<Promise<unknown>>();
const uncertainRequests = new WeakSet<Set<Promise<unknown>>>();
function retain<T>(work: Promise<T>, local?: Set<Promise<unknown>>): Promise<T> {
  custody.add(work);
  local?.add(work);
  work.then(
    () => {
      custody.delete(work);
      local?.delete(work);
    },
    () => {
      custody.delete(work);
      local?.delete(work);
    },
  );
  return work;
}

const version = /^OpenBao\s+v2\.6\.1(?:[\s,]|$)/u;
const imageRe = /^quay\.io\/openbao\/openbao:2\.6\.1@sha256:([a-f0-9]{64})$/u;
const idRe = /^[a-f0-9]{64}$/u;
const secretRe = /^[A-Za-z0-9._~+/=-]{8,4096}$/u;
const pemCert = /^-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----\n?$/u;
const egressHandle = "users/alice/integrations/stage3-localhost";
const configPath = fileURLToPath(new URL("../openbao-model-auth/config.hcl", import.meta.url));
const expectedConfig =
  'disable_mlock = true\napi_addr = "http://127.0.0.1:8200"\n\nstorage "file" {\n  path = "/openbao/file"\n}\n\nlistener "tcp" {\n  address = "0.0.0.0:8200"\n  tls_disable = 1\n}\n';

type DockerResult = {
  status: number;
  stdout: string;
  cleanupUncertain?: boolean;
  outcome?: RunnerResult["status"];
  stdoutTruncated?: boolean;
};
type Exec = (args: readonly string[], options?: OpenBaoCooperativeOptions) => Promise<DockerResult>;
type Meta = {
  id: string;
  name: string;
  image: string;
  imageId: string;
  label: string;
  nonce: string;
  running: boolean;
  port: number;
  safe: boolean;
};

export async function startTrustedOpenBao(state: LauncherState, seams?: OpenBaoSeams): Promise<OpenBaoHandle> {
  return startTrustedOpenBaoCooperative(state, {}, seams);
}

export async function startTrustedOpenBaoCooperative(
  state: LauncherState,
  options: OpenBaoCooperativeOptions = {},
  seams?: OpenBaoSeams,
): Promise<OpenBaoHandle> {
  const supplied = cooperativeOptions(options);
  const cooperative = within(supplied, 30_000);
  const startedAt = Date.now(),
    startedMono = performance.now();
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
    // Retired artifact: only fully injected synthetic-contract fixtures may execute this path.
    if (!seams || !Object.hasOwn(seams, "docker") || !Object.hasOwn(seams, "fetch")) fail();
    apiKey = key(s.randomBytes);
    integrationCredential = key(s.randomBytes);
    if (integrationCredential === apiKey) fail();
    const dockerWork = new Set<Promise<unknown>>();
    let uncertainProducer = false;
    const exec = (a: readonly string[], callOptions: OpenBaoCooperativeOptions = cooperative) => {
      const work = retain(
        dock(s.docker, a, callOptions).then((result) => {
          uncertainProducer ||=
            result.cleanupUncertain === true ||
            result.stdoutTruncated === true ||
            result.outcome === "timeout" ||
            result.outcome === "aborted";
          return result;
        }),
        dockerWork,
      );
      return observe(work, callOptions);
    };
    const name = `cogs-openbao-${state.stateId}`,
      label = `cogs.dev.launcher.state=${state.stateId}`;
    const requests = new Set<Promise<unknown>>();
    const fetcher = client(s.fetch, cooperative, requests);
    checkCooperative(cooperative);
    const existing = await exec(["ps", "-a", "--filter", `label=${label}`, "--format", "{{.ID}}"]);
    if (existing.status !== 0 || existing.stdout.trim() !== "") fail();
    const img = JSON.parse(
      oneLine((await ok(exec(["image", "inspect", OPENBAO_IMAGE, "--format", "{{json .}}"]))).stdout),
    ) as {
      Id: string;
      RepoDigests: unknown;
      Os: string;
      Architecture: string;
      Config: { Volumes?: Record<string, unknown> | null };
    };
    if (
      !repoDigest(JSON.stringify(img.RepoDigests), digest) ||
      !/^sha256:[a-f0-9]{64}$/u.test(img.Id) ||
      img.Os !== "linux" ||
      !["amd64", "arm64"].includes(img.Architecture) ||
      !img.Config ||
      Object.keys(img.Config.Volumes ?? {}).some((path) => path !== "/openbao/file")
    )
      fail();
    const imageId = img.Id;
    const nonce = randomBytes(16).toString("hex");
    const intent = await acquisitionIntent(state, name, nonce, imageId, img.Architecture);
    let id = "";
    let producer: Promise<DockerResult> | undefined;
    let ready = false;
    try {
      producer = retain(
        exec([
          "create",
          "--pull",
          "never",
          "--read-only",
          "--tmpfs",
          tmpfs,
          "--label",
          `cogs.dev.launcher.acquisition=${nonce}`,
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
      const run = await observe(producer, cooperative);
      id = oneLine((await ok(Promise.resolve(run))).stdout);
      if (!idRe.test(id)) fail();
      const created = await inspect(exec, id, cooperative);
      if (!owned(created, id, name, state.stateId, nonce, imageId) || !created.safe) fail();
      await ok(exec(["start", id]));
      const meta = await inspect(exec, id, cooperative);
      if (!owned(meta, id, name, state.stateId, nonce, imageId) || !meta.safe || !meta.running || meta.port < 1) fail();
      if (!version.test(oneLine((await ok(exec(["exec", id, "bao", "version"]))).stdout))) fail();
      const origin = `http://127.0.0.1:${meta.port}`;
      await waitReachable(fetcher, origin);
      let init = await bao(
        fetcher,
        origin,
        "/v1/sys/init",
        "POST",
        undefined,
        { secret_shares: 1, secret_threshold: 1 },
        [200],
      );
      root = str(init, "root_token");
      unseal = arrStr(init, "keys_base64");
      init = undefined;
      await bao(fetcher, origin, "/v1/sys/unseal", "POST", undefined, { key: unseal }, [200]);
      unseal = "";
      await healthReady(fetcher, origin);
      await bao(
        fetcher,
        origin,
        "/v1/sys/mounts/model",
        "POST",
        root,
        { type: "kv", options: { version: "2" } },
        [200, 204],
      );
      await bao(
        fetcher,
        origin,
        "/v1/model/data/users/alice/anthropic",
        "POST",
        root,
        { data: { api_key: apiKey } },
        [200, 204],
      );
      await bao(
        fetcher,
        origin,
        "/v1/sys/policies/acl/cogs-model-auth-read",
        "PUT",
        root,
        { policy: `${selfPolicy}\npath "model/data/users/alice/anthropic" { capabilities = ["read"] }` },
        [200, 204],
      );
      await bao(
        fetcher,
        origin,
        `/v1/model/data/${egressHandle}`,
        "POST",
        root,
        { data: { api_key: integrationCredential } },
        [200, 204],
      );
      await bao(
        fetcher,
        origin,
        "/v1/sys/mounts/pki",
        "POST",
        root,
        { type: "pki", config: { max_lease_ttl: "24h" } },
        [200, 204],
      );
      const ca = await bao(
        fetcher,
        origin,
        "/v1/pki/root/generate/internal",
        "POST",
        root,
        { common_name: "localhost", ttl: "24h" },
        [200],
      );
      certOnly(ca);
      await bao(
        fetcher,
        origin,
        "/v1/pki/roles/cogs-egress",
        "POST",
        root,
        {
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
        },
        [200, 204],
      );
      await bao(
        fetcher,
        origin,
        "/v1/sys/policies/acl/cogs-stage3-runtime",
        "PUT",
        root,
        {
          policy: [
            selfPolicy,
            `path "model/data/${egressHandle}" { capabilities = ["read"] }`,
            `path "model/metadata/${egressHandle}" { capabilities = ["read"] }`,
            'path "pki/issue/cogs-egress" { capabilities = ["update"] }',
          ].join("\n"),
        },
        [200, 204],
      );
      model = token(
        await bao(
          fetcher,
          origin,
          "/v1/auth/token/create-orphan",
          "POST",
          root,
          tokenRequest("cogs-model-auth-read"),
          [200],
        ),
        "cogs-model-auth-read",
      );
      egress = token(
        await bao(
          fetcher,
          origin,
          "/v1/auth/token/create-orphan",
          "POST",
          root,
          tokenRequest("cogs-stage3-runtime"),
          [200],
        ),
        "cogs-stage3-runtime",
      );
      if (egress === model || egress === root || model === root) fail();
      const validateChildren = async () => {
        await validateChild(fetcher, origin, model, "cogs-model-auth-read", apiKey, startedAt);
        await validateChild(fetcher, origin, egress, "cogs-stage3-runtime", integrationCredential, startedAt);
      };
      await validateChildren();
      await bao(fetcher, origin, "/v1/auth/token/revoke-self", "POST", root, {}, [204]);
      await denied(fetcher, origin, root, "/v1/auth/token/lookup-self", "GET");
      root = "";
      await validateChildren();
      await healthReady(fetcher, origin);
      const final = await inspect(exec, id, cooperative);
      if (
        !owned(final, id, name, state.stateId, nonce, imageId) ||
        !final.safe ||
        !final.running ||
        final.port !== meta.port
      )
        fail();
      checkCooperative(cooperative);
      if (Math.abs(Date.now() - startedAt - (performance.now() - startedMono)) > 1000) fail();
      ready = true;
      const clear = () => {
        ready = false;
        model = "";
        egress = "";
        apiKey = "";
        integrationCredential = "";
      };
      if (aborted(cooperative)) {
        clear();
        fail();
      }
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
          () => (ready ? model : ""),
          (v) => (model = v),
        ),
        modelApiKey: holder(
          () => (ready ? apiKey : ""),
          (v) => (apiKey = v),
        ),
        egressToken: holder(
          () => (ready ? egress : ""),
          (v) => (egress = v),
        ),
        integrationCredential: holder(
          () => (ready ? integrationCredential : ""),
          (v) => (integrationCredential = v),
        ),
        close: once(
          () => {
            ready = false;
          },
          async () => {
            const cleanupCooperative = cleanupOptions();
            const closeFetch = client(s.fetch, cleanupCooperative, requests);
            try {
              const before = await inspect(exec, id, cleanupCooperative);
              if (!owned(before, id, name, state.stateId, nonce, imageId) || !before.safe) fail();
              if (before.running) {
                if (before.port !== meta.port) fail();
                await Promise.all([revoke(closeFetch, origin, model), revoke(closeFetch, origin, egress)]);
              }
              model = "";
              egress = "";
              apiKey = "";
              integrationCredential = "";
              const latest = await inspect(exec, id, cleanupCooperative);
              if (!owned(latest, id, name, state.stateId, nonce, imageId) || !latest.safe) fail();
              await ok(exec(["rm", "-f", id], cleanupCooperative));
              const left = await exec(
                ["ps", "-a", "--filter", `label=${label}`, "--format", "{{.ID}}"],
                cleanupCooperative,
              );
              if (left.status !== 0 || left.stdout.trim() !== "") fail();
              await closedPort(meta.port, cleanupCooperative);
              await Promise.allSettled([...requests, ...dockerWork]);
              if (uncertainProducer || uncertainRequests.has(requests)) fail();
              await intent.remove();
            } finally {
              clear();
            }
          },
        ),
      });
    } catch (e) {
      root = "";
      unseal = "";
      const retirement = retain(
        (async () => {
          // Never reconcile absence while a create producer can still acquire the backend.
          await producer?.catch(() => undefined);
          await Promise.allSettled([...dockerWork]);
          await rollbackOwned(exec, name, id, state.stateId, label, nonce, imageId);
          await Promise.allSettled([...requests, ...dockerWork]);
          if (uncertainProducer || uncertainRequests.has(requests)) fail();
          await intent.remove();
        })(),
      );
      await observe(retirement, cleanupOptions());
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
  return async (args: readonly string[], options: OpenBaoCooperativeOptions = {}) => {
    const r = await runCommand(
      commandDescriptor({
        executable: "/usr/bin/docker",
        args: [...args].slice(1),
        cwd,
        env: { PATH: "/usr/bin:/bin" },
        timeoutMs: remainingMs(options, 15_000),
        maxOutputBytes: 8192,
        killGraceMs: 1000,
      }),
      options.signal === undefined ? {} : { signal: options.signal },
    );
    return {
      status: r.status === "ok" && !r.cleanupUncertain ? 0 : 1,
      stdout: r.stdout,
      cleanupUncertain: r.cleanupUncertain,
      outcome: r.status,
      stdoutTruncated: r.stdoutTruncated,
    };
  };
}
async function dock(exec: Exec, args: readonly string[], options: OpenBaoCooperativeOptions = {}) {
  checkCooperative(options);
  return exec(Object.freeze(["/usr/bin/docker", ...args]), options);
}
async function ok(p: Promise<DockerResult>) {
  const r = await p;
  if (
    r.status !== 0 ||
    r.cleanupUncertain ||
    r.stdoutTruncated ||
    (r.outcome !== undefined && r.outcome !== "ok") ||
    r.stdout.length > 8192
  )
    fail();
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
async function inspect(exec: Exec, name: string, options: OpenBaoCooperativeOptions): Promise<Meta> {
  const j = JSON.parse(oneLine((await ok(exec(["inspect", name, "--format", "{{json .}}"], options))).stdout)) as {
    Id?: string;
    Image?: string;
    Name?: string;
    Config?: { Image?: string; User?: string; Labels?: Record<string, string> };
    HostConfig?: {
      ReadonlyRootfs?: boolean;
      Tmpfs?: Record<string, string>;
      CapDrop?: string[];
      SecurityOpt?: string[];
      VolumesFrom?: unknown[] | null;
      NetworkMode?: string;
      RestartPolicy?: { Name?: string };
    };
    Mounts?: Array<{ Type?: string; Source?: string; Destination?: string; RW?: boolean; Propagation?: string }>;
    State?: { Running?: boolean };
    NetworkSettings?: { Ports?: Record<string, Array<{ HostIp?: string; HostPort?: string }> | null> };
  };
  const b = j.NetworkSettings?.Ports?.["8200/tcp"]?.[0],
    port = Number(b?.HostPort ?? 0);
  return {
    id: j.Id ?? "",
    name: j.Name ?? "",
    image: j.Config?.Image ?? "",
    imageId: j.Image ?? "",
    label: j.Config?.Labels?.["cogs.dev.launcher.state"] ?? "",
    nonce: j.Config?.Labels?.["cogs.dev.launcher.acquisition"] ?? "",
    running: j.State?.Running === true,
    port:
      b?.HostIp === "127.0.0.1" &&
      Number.isSafeInteger(port) &&
      port > 0 &&
      port <= 65535 &&
      j.NetworkSettings?.Ports?.["8200/tcp"]?.length === 1 &&
      Object.keys(j.NetworkSettings.Ports).length === 1
        ? port
        : 0,
    safe:
      j.Config?.User === "100:1000" &&
      j.HostConfig?.ReadonlyRootfs === true &&
      JSON.stringify(j.HostConfig.Tmpfs) === JSON.stringify({ "/openbao/file": tmpfs.split(":")[1] }) &&
      JSON.stringify(j.HostConfig.CapDrop) === '["ALL"]' &&
      JSON.stringify(j.HostConfig.SecurityOpt) === '["no-new-privileges"]' &&
      (j.HostConfig.VolumesFrom == null || j.HostConfig.VolumesFrom.length === 0) &&
      j.HostConfig.NetworkMode === "default" &&
      j.HostConfig.RestartPolicy?.Name === "no" &&
      Array.isArray(j.Mounts) &&
      j.Mounts.length === 2 &&
      j.Mounts.filter((m) => m.Type === "tmpfs" && m.Destination === "/openbao/file" && m.RW === true).length === 1 &&
      j.Mounts.filter(
        (m) =>
          m.Type === "bind" &&
          m.Source === configPath &&
          m.Destination === "/openbao/cogs-config.hcl" &&
          m.RW === false &&
          m.Propagation === "rprivate",
      ).length === 1,
  };
}
function owned(m: Meta, id: string, name: string, stateId: string, nonce: string, imageId: string) {
  return (
    idRe.test(m.id) &&
    m.id === id &&
    m.name === `/${name}` &&
    m.image === OPENBAO_IMAGE &&
    m.imageId === imageId &&
    m.label === stateId &&
    m.nonce === nonce
  );
}
function cooperativeOptions(value: unknown): OpenBaoCooperativeOptions {
  if (value === undefined) return Object.freeze({});
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  const d = Object.getOwnPropertyDescriptors(value);
  const out: { signal?: AbortSignal; deadlineAt?: number } = {};
  for (const key of Reflect.ownKeys(d)) {
    if (typeof key !== "string" || (key !== "signal" && key !== "deadlineAt")) fail();
    const item = d[key];
    if (!item || !("value" in item) || item.enumerable !== true) fail();
    if (key === "signal") {
      if (!(item.value instanceof AbortSignal)) fail();
      out.signal = item.value;
    } else {
      if (!Number.isSafeInteger(item.value) || item.value > Date.now() + MAX_COOPERATIVE_DEADLINE_MS) fail();
      out.deadlineAt = item.value;
    }
  }
  const checked = Object.freeze(out);
  if (out.deadlineAt !== undefined) deadlines.set(checked, performance.now() + out.deadlineAt - Date.now());
  return checked;
}
function aborted(options: OpenBaoCooperativeOptions): boolean {
  const signalAborted =
    options.signal !== undefined &&
    (ABORTED_GETTER === undefined ? false : ABORTED_GETTER.call(options.signal) === true);
  return signalAborted || deadlineRemaining(options) <= 0;
}
function checkCooperative(options: OpenBaoCooperativeOptions): void {
  if (aborted(options)) fail();
}
function cleanupOptions(): OpenBaoCooperativeOptions {
  // Independent owner escalation budget, not a renewed caller observation.
  return within({}, 15_000);
}
function deadlineRemaining(options: OpenBaoCooperativeOptions): number {
  const end = deadlines.get(options);
  return end !== undefined
    ? end - performance.now()
    : options.deadlineAt === undefined
      ? Infinity
      : options.deadlineAt - Date.now();
}
function within(options: OpenBaoCooperativeOptions, boundMs: number): OpenBaoCooperativeOptions {
  const remaining = Math.min(boundMs, deadlineRemaining(options));
  const checked = Object.freeze({ ...options, deadlineAt: Math.ceil(Date.now() + remaining) });
  deadlines.set(checked, performance.now() + remaining);
  return checked;
}
function remainingMs(options: OpenBaoCooperativeOptions, boundMs: number): number {
  return Math.max(1, Math.ceil(Math.min(boundMs, deadlineRemaining(options))));
}
type BaoClient = ReturnType<typeof client>;
function client(fetcher: typeof fetch, options: OpenBaoCooperativeOptions, work: Set<Promise<unknown>>) {
  return { fetcher, options, work };
}
async function rollbackOwned(
  exec: Exec,
  name: string,
  id: string,
  stateId: string,
  label: string,
  nonce: string,
  imageId: string,
): Promise<void> {
  const cleanup = cleanupOptions();
  const meta = await inspect(exec, idRe.test(id) ? id : name, cleanup);
  if (!owned(meta, idRe.test(id) ? id : meta.id, name, stateId, nonce, imageId) || !meta.safe) fail();
  await ok(exec(["rm", "-f", meta.id], cleanup));
  const left = await exec(["ps", "-a", "--filter", `label=${label}`, "--format", "{{.ID}}"], cleanup);
  if (left.status !== 0 || left.stdout.trim() !== "") fail();
  if (meta.port > 0) await closedPort(meta.port, cleanup);
  // Unknown storage stays attached to its preserved container and retained intent.
}
async function bao(
  client: BaoClient,
  origin: string,
  path: string,
  method: "GET" | "POST" | "PUT",
  tok: string | undefined,
  body: unknown,
  statuses: readonly number[],
) {
  if (!path.startsWith("/v1/")) fail();
  checkCooperative(client.options);
  const ac = new AbortController();
  const options = within(client.options, 5000);
  const abort = () => ac.abort();
  const t = setTimeout(abort, remainingMs(options, 5000));
  if (options.signal) EVENT_ADD.call(options.signal, "abort", abort, { once: true });
  if (aborted(options)) abort();
  const actual = retain(
    (async () => {
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
        const r = await client.fetcher(`${origin}${path}`, init);
        const text = await bounded(r, 65536, ac.signal, client.work);
        checkCooperative(options);
        if (ac.signal.aborted) fail();
        if (!statuses.includes(r.status)) fail();
        if (r.status === 204) {
          if (text !== "") fail();
          return undefined;
        }
        if (!/^application\/json(?:\s*;|$)/iu.test(r.headers.get("content-type") ?? "")) fail();
        if (hasDuplicateJsonKeys(text)) fail();
        const parsed = JSON.parse(text) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail();
        return parsed;
      } finally {
        clearTimeout(t);
        if (options.signal) EVENT_REMOVE.call(options.signal, "abort", abort);
      }
    })(),
    client.work,
  );
  return observe(actual, options);
}
async function bounded(r: Response, max: number, signal: AbortSignal, work: Set<Promise<unknown>>) {
  const rd = r.body?.getReader();
  if (!rd) return "";
  let n = 0,
    c = 0;
  const xs: Buffer[] = [];
  let cancellation: Promise<void> | undefined;
  const cancel = () => {
    cancellation ??= rd.cancel().catch(() => {
      uncertainRequests.add(work);
    });
  };
  EVENT_ADD.call(signal, "abort", cancel, { once: true });
  if (signal.aborted) cancel();
  try {
    const length = r.headers.get("content-length");
    if (length !== null && (!/^[0-9]+$/u.test(length) || Number(length) > max)) fail();
    for (;;) {
      if (signal.aborted) fail();
      const x = await rd.read();
      if (signal.aborted) fail();
      if (x.done) break;
      if (!x.value || ++c > 1024) fail();
      n += x.value.byteLength;
      if (n > max) fail();
      xs.push(Buffer.from(x.value));
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(xs, n));
  } finally {
    cancel();
    await cancellation;
    EVENT_REMOVE.call(signal, "abort", cancel);
    rd.releaseLock();
    for (const bytes of xs) bytes.fill(0);
  }
}
async function waitReachable(fetcher: BaoClient, origin: string) {
  for (let i = 0; i < 20; i++) {
    try {
      await health(fetcher, origin, [200, 429, 472, 473, 501, 503]);
      return;
    } catch {
      checkCooperative(fetcher.options);
      if (fetcher.work.size > 0) fail();
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  fail();
}
async function healthReady(fetcher: BaoClient, origin: string) {
  const state = await health(fetcher, origin, [200]);
  if (state.initialized !== true || state.sealed !== false) fail();
}
async function health(fetcher: BaoClient, origin: string, statuses: readonly number[]) {
  const state = (await bao(fetcher, origin, "/v1/sys/health", "GET", undefined, undefined, statuses)) as {
    initialized?: unknown;
    sealed?: unknown;
  };
  if (typeof state.initialized !== "boolean" || typeof state.sealed !== "boolean") fail();
  return { initialized: state.initialized, sealed: state.sealed };
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
function exactPolicy(value: unknown, policy: string) {
  return Array.isArray(value) && value.length === 1 && value[0] === policy;
}
function tokenRequest(policy: string) {
  return {
    policies: [policy],
    no_default_policy: true,
    type: "service",
    ttl: `${tokenSeconds}s`,
    explicit_max_ttl: `${tokenSeconds}s`,
    renewable: false,
    num_uses: 0,
  };
}
function token(v: unknown, policy: string) {
  const envelope = v as { auth?: Record<string, unknown>; warnings?: unknown; wrap_info?: unknown };
  const a = envelope.auth;
  if (
    !a ||
    (envelope.warnings != null && (!Array.isArray(envelope.warnings) || envelope.warnings.length !== 0)) ||
    envelope.wrap_info != null ||
    !exactPolicy(a.policies, policy) ||
    (a.token_policies !== undefined && !exactPolicy(a.token_policies, policy)) ||
    (a.identity_policies !== undefined && (!Array.isArray(a.identity_policies) || a.identity_policies.length !== 0)) ||
    a.token_type !== "service" ||
    a.renewable !== false ||
    a.lease_duration !== tokenSeconds ||
    (a.entity_id != null && a.entity_id !== "")
  )
    fail();
  return str(a, "client_token");
}
async function denied(
  c: BaoClient,
  origin: string,
  tok: string,
  path: string,
  method: "GET" | "POST" = "POST",
  body: unknown = {},
) {
  const response = (await bao(c, origin, path, method, tok, method === "GET" ? undefined : body, [403])) as {
    errors?: unknown;
  };
  if (
    !Array.isArray(response.errors) ||
    response.errors.length < 1 ||
    response.errors.length > 4 ||
    response.errors.some((x) => x !== "permission denied" && x !== "invalid token")
  )
    fail();
}
async function validateChild(
  c: BaoClient,
  origin: string,
  tok: string,
  policy: string,
  key: string,
  startedAt: number,
) {
  const response = (await bao(c, origin, "/v1/auth/token/lookup-self", "GET", tok, undefined, [200])) as {
    data?: Record<string, unknown>;
  };
  const d = response.data;
  const elapsed = Math.ceil((Date.now() - startedAt) / 1000);
  if (
    !d ||
    d.id !== tok ||
    !exactPolicy(d.policies, policy) ||
    d.orphan !== true ||
    d.renewable !== false ||
    d.type !== "service" ||
    d.explicit_max_ttl !== tokenSeconds ||
    !Number.isSafeInteger(d.ttl) ||
    Number(d.ttl) < tokenSeconds - elapsed - 5 ||
    Number(d.ttl) > tokenSeconds ||
    d.num_uses !== 0 ||
    (d.period !== undefined && d.period !== 0) ||
    (d.entity_id != null && d.entity_id !== "") ||
    (d.role != null && d.role !== "") ||
    (d.identity_policies !== undefined && (!Array.isArray(d.identity_policies) || d.identity_policies.length !== 0))
  )
    fail();
  if (elapsed > 30 || elapsed < 0) fail();
  const model = policy === "cogs-model-auth-read";
  const path = model ? "users/alice/anthropic" : egressHandle;
  const data = (await bao(c, origin, `/v1/model/data/${path}`, "GET", tok, undefined, [200])) as {
    data?: { data?: { api_key?: unknown }; metadata?: { version?: unknown; created_time?: unknown } };
  };
  if (
    data.data?.data?.api_key !== key ||
    data.data.metadata?.version !== 1 ||
    typeof data.data.metadata.created_time !== "string"
  )
    fail();
  if (!model) {
    const metadata = (await bao(c, origin, `/v1/model/metadata/${egressHandle}`, "GET", tok, undefined, [200])) as {
      data?: { current_version?: unknown; versions?: Record<string, { created_time?: unknown }> };
    };
    if (
      metadata.data?.current_version !== 1 ||
      metadata.data.versions?.["1"]?.created_time !== data.data.metadata.created_time
    )
      fail();
    const pki = new OpenBaoEgressPkiSource({
      origin,
      mount: "pki",
      role: "cogs-egress",
      allowLoopbackHttpDevelopment: true,
      minValidityMarginMs: OPENBAO_PKI_BUDGET.maxMarginMs,
      identity: { withToken: (_signal, op) => op(tok) },
      fetchImpl: c.fetcher,
      timeoutMs: remainingMs(c.options, 5000),
    });
    await observe(
      retain(
        pki.withPkiMaterial(
          {
            sessionId: "bootstrap-proof",
            hosts: ["localhost"],
            maxSessionExpiresAtMs: Date.now() + OPENBAO_PKI_BUDGET.maxSessionMs,
            ...(c.options.signal ? { signal: c.options.signal } : {}),
          },
          async () => {},
        ),
        c.work,
      ),
      c.options,
    );
  }
  if (!model)
    await bao(c, origin, "/v1/pki/issue/cogs-egress", "POST", tok, { common_name: "other.example", ttl: "60s" }, [400]);
  const other = model ? egressHandle : "users/alice/anthropic";
  for (const deniedPath of [
    `/v1/model/data/${other}`,
    `/v1/model/metadata/${other}`,
    "/v1/model/metadata/users/alice?list=true",
    "/v1/model/data/users/bob/anthropic",
    "/v1/model/metadata/users/bob/integrations/stage3-localhost",
    "/v1/sys/policies/acl/cogs-model-auth-read",
    "/v1/pki/roles/cogs-egress",
  ])
    await denied(c, origin, tok, deniedPath, "GET");
  for (const [deniedPath, body] of [
    ["/v1/auth/token/create-orphan", tokenRequest(policy)],
    ["/v1/auth/token/renew-self", {}],
    ["/v1/auth/token/revoke", { token: "unowned-probe-token" }],
    [`/v1/model/data/${path}`, { data: { api_key: "denied-probe" } }],
    ["/v1/sys/mounts/denied-probe", { type: "kv" }],
    ["/v1/pki/roles/cogs-egress", { allowed_domains: ["example.com"] }],
    ["/v1/sys/policies/acl/cogs-model-auth-read", { policy: 'path "*" { capabilities = ["sudo"] }' }],
    ["/v1/pki/root/generate/internal", { common_name: "denied-probe" }],
    [model ? "/v1/pki/issue/cogs-egress" : "/v1/pki/issue/other-role", { common_name: "localhost", ttl: "60s" }],
  ] as const)
    await denied(c, origin, tok, deniedPath, "POST", body);
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
async function revoke(fetcher: BaoClient, origin: string, tok: string) {
  if (tok) await bao(fetcher, origin, "/v1/auth/token/revoke-self", "POST", tok, {}, [200, 204]).catch(() => undefined);
}
function once(seal: () => void, fn: () => Promise<void>) {
  let p: Promise<void> | undefined;
  return (options?: OpenBaoCooperativeOptions) => {
    const checked = cooperativeOptions(options);
    if (p === undefined) {
      seal();
      // Install the owner before callbacks (including reentrant close).
      p = retain(
        Promise.resolve()
          .then(fn)
          .catch(() => fail()),
      );
    }
    return observe(p, within(checked, 15_000));
  };
}
async function closedPort(port: number, options: OpenBaoCooperativeOptions = {}) {
  await new Promise<void>((res, rej) => {
    const s = new Socket();
    let settled = false;
    const t = setTimeout(() => done(false), remainingMs(options, 250));
    const abort = () => done(false);
    const cleanup = () => {
      clearTimeout(t);
      if (options.signal !== undefined) EVENT_REMOVE.call(options.signal, "abort", abort);
      s.off("connect", onConnect);
      s.off("error", onError);
    };
    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      cleanup();
      s.destroy();
      if (ok) res();
      else rej(fail());
    };
    const onConnect = () => done(false);
    const onError = (error: NodeJS.ErrnoException) => done(error.code === "ECONNREFUSED");
    if (options.signal !== undefined) EVENT_ADD.call(options.signal, "abort", abort, { once: true });
    s.once("connect", onConnect);
    s.once("error", onError);
    s.connect(port, "127.0.0.1");
  });
}
async function acquisitionIntent(
  state: LauncherState,
  name: string,
  nonce: string,
  imageId: string,
  architecture: string,
) {
  const path = join(state.controlDir, "openbao-acquisition.json");
  const file = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  const identity = await file.stat();
  try {
    await file.writeFile(
      JSON.stringify({
        schema: "openbao-acquisition-v1",
        stateId: state.stateId,
        sourceRevision: state.sourceRevision,
        name,
        nonce,
        image: OPENBAO_IMAGE,
        imageId,
        architecture,
        configPath,
        configSha256: createHash("sha256").update(expectedConfig).digest("hex"),
        portBinding: "127.0.0.1::8200/tcp",
        capDrop: ["ALL"],
        securityOpt: ["no-new-privileges"],
        volumes: [],
        tmpfs,
        user: "100:1000",
        readonlyRootfs: true,
        cleanupRequired: true,
      }),
    );
    await file.sync();
  } finally {
    await file.close();
  }
  const syncDir = async () => {
    const dir = await open(state.controlDir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
  };
  await syncDir();
  return {
    remove: async () => {
      const current = await lstat(path);
      if (current.dev !== identity.dev || current.ino !== identity.ino || !current.isFile() || current.isSymbolicLink())
        fail();
      await unlink(path);
      await syncDir();
    },
  };
}
// A deadline bounds observation, never the lifetime of the promise being observed.
function observe<T>(work: Promise<T>, options: OpenBaoCooperativeOptions): Promise<T> {
  const end = performance.now() + remainingMs(options, 30_000);
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (ok: boolean, value?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (options.signal) EVENT_REMOVE.call(options.signal, "abort", abort);
      if (ok) resolve(value as T);
      else reject(new Error("launcher openbao failed"));
    };
    const abort = () => done(false);
    const timer = setTimeout(abort, Math.max(1, end - performance.now()));
    if (options.signal) EVENT_ADD.call(options.signal, "abort", abort, { once: true });
    if (aborted(options)) abort();
    work.then((value) => done(!aborted(options) && performance.now() < end, value), abort);
  });
}
function fail(): never {
  throw new Error("launcher openbao failed");
}
