import { randomBytes, X509Certificate } from "node:crypto";
import { constants, readSync, writeSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer as httpsServer } from "node:https";
import { pathToFileURL } from "node:url";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { AssistantMessage } from "@earendil-works/pi-ai/compat";
import { type ApiServer, createApiServer } from "../../src/api/server.ts";
import type { ModelApiKeySource, OpenBaoIdentityPort } from "../../src/auth/model-auth.ts";
import type { CogsEgressPkiSource } from "../../src/egress/egress-material.ts";
import { canonicalPresetPolicyRevision } from "../../src/egress/preset-revision.ts";
import { lowerLaunchEgressRoutePlan } from "../../src/egress/route-policy.ts";
import {
  aggregateCogsEgressRoutePlanRevision,
  type CogsEgressRuntimeManager,
  observeCogsEgressRuntime,
  startCogsEgressRuntimeManager,
} from "../../src/egress/runtime-manager.ts";
import { beginRegisteredClose, registerCloseOwner } from "../../src/launch/close.ts";
import { deepFreeze, type LaunchConfig, validateLaunchConfig } from "../../src/launch/config.ts";
import { type CogsPiSessionPorts, createAuthenticatedCogsPiSession } from "../../src/pi/session.ts";
import { admitProductionLaunch, startProductionWorker } from "../../src/runtime/compose.ts";
import {
  canonicalRuntimeConfig,
  parseRuntimeConfigBytes,
  type RuntimeConfig,
  validateRuntimeConfig,
} from "../../src/runtime/config.ts";
import { withTrustedFileBytes } from "../../src/runtime/trusted-files.ts";
import { type CogsWorkerTelemetrySink, createCogsWorkerTelemetrySink } from "../../src/telemetry/worker-telemetry.ts";
import { createApiClient } from "../launcher/api-client.ts";
import {
  type ContainerReceipt,
  type ContainerSpec,
  type CustodyPort,
  canonical,
  check,
  containerArguments,
  dir,
  HostCustody,
  hash,
  LocalSkillSnapshotOwner,
  type Mount,
  pinnedTrust,
  put,
  SANDBOX_CAPABILITIES,
  SANDBOX_CAPABILITY_MASK,
  sandboxCapabilities,
} from "./snapshot-owner.ts";

export const BASELINE = "8ddd4c3164bae32dbe02c67d2ee9b82eb8315a38";
export const PROFILE = "functional-only-protected-linux-docker/v1";
export const FINDINGS = Object.freeze([4, 5, 6, 8, 9, 10, 14]);
export const PROBE_GENERATIONS = 8;
export const PROBE_GENERATION_SECONDS = 600;
export const PROBE_CLEANUP_SECONDS = 60;
export const PROBE_SUITE_SECONDS = PROBE_GENERATIONS * (PROBE_GENERATION_SECONDS + PROBE_CLEANUP_SECONDS);
const admittedRestrictions = new WeakSet<object>();
// In-memory build input only. No build, pull, registry, workflow, or image-definition mutation here.
export const WORKER_DOCKERFILE = `ARG PINNED_WORKER
FROM \${PINNED_WORKER}
USER 0:0
COPY --chown=0:0 src /opt/cogs/src
COPY --chown=0:0 schemas /opt/cogs/schemas
COPY --chown=0:0 dev/product-test /opt/cogs/dev/product-test
COPY --chown=0:0 dev/launcher/api-client.ts /opt/cogs/dev/launcher/api-client.ts
COPY --chown=0:0 third_party /opt/cogs/third_party
USER 65532:65532
ENTRYPOINT ["/nodejs/bin/node"]
`;
export type Restrictions = Readonly<{
  version: "cogs.product-restrictions/v1";
  baseline: string;
  candidate: string;
  owner: string;
  expires: number;
  run_id: string;
  run_attempt: string;
  tree: string;
  source_inventory: string;
  dockerignore: string;
  package_lock: string;
  npm_closure: string;
  image_os: string;
  image_version: string;
  profile: typeof PROFILE;
  breach: "fail-and-settle-exact";
  findings: readonly number[];
  seconds: number;
  skills: "empty" | "nonempty";
  sandbox_image: string;
  worker_image: string;
  stock_worker_image: string;
  fresh_protected_runner: true;
}>;
export function admitRestrictions(bytes: Buffer, candidate: string, now: number): Restrictions {
  check(bytes.length > 0 && bytes.length <= 8192);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const value = JSON.parse(text) as Restrictions;
  check(canonical(value) === text);
  check(
    Object.keys(value).sort().join() ===
      "version baseline candidate owner expires run_id run_attempt tree source_inventory dockerignore package_lock npm_closure image_os image_version profile breach findings seconds skills sandbox_image worker_image stock_worker_image fresh_protected_runner"
        .split(" ")
        .sort()
        .join(),
  );
  check(value.version === "cogs.product-restrictions/v1" && value.baseline === BASELINE);
  check(/^[a-f0-9]{40}$/.test(candidate) && value.candidate === candidate && value.owner === "repository-owner");
  check(/^[1-9][0-9]{0,19}$/.test(value.run_id) && /^[1-9][0-9]{0,9}$/.test(value.run_attempt));
  check(/^[a-f0-9]{40}$/.test(value.tree) && /^sha256:[a-f0-9]{64}$/.test(value.source_inventory));
  check(/^sha256:[a-f0-9]{64}$/.test(value.dockerignore) && /^sha256:[a-f0-9]{64}$/.test(value.package_lock));
  check(/^sha256:[a-f0-9]{64}$/.test(value.npm_closure));
  check(/^[A-Za-z0-9._-]{1,128}$/.test(value.image_os) && /^[A-Za-z0-9._-]{1,128}$/.test(value.image_version));
  check(value.profile === PROFILE && value.breach === "fail-and-settle-exact" && value.fresh_protected_runner === true);
  check(
    Number.isSafeInteger(value.expires) &&
      value.expires > now + value.seconds * 1000 &&
      value.expires <= now + 86400000,
  );
  check(Number.isInteger(value.seconds) && value.seconds >= 60 && value.seconds <= 600);
  check(value.skills === "empty" || value.skills === "nonempty");
  check(canonical(value.findings) === canonical(FINDINGS));
  for (const image of [value.sandbox_image, value.worker_image, value.stock_worker_image])
    check(/^sha256:[a-f0-9]{64}$/.test(image));
  check(new Set([value.sandbox_image, value.worker_image, value.stock_worker_image]).size === 3);
  const admitted = deepFreeze(value);
  admittedRestrictions.add(admitted);
  return admitted;
}
export function requireProbeSuiteWindow(restrictions: Restrictions, now: number, generation: number): void {
  check(Number.isSafeInteger(now) && Number.isInteger(generation) && generation >= 0 && generation < PROBE_GENERATIONS);
  // Every generation remains independently limited to 600 seconds. The fresh
  // suite grant also reserves sequential cleanup for all eight generations.
  check(restrictions.seconds === PROBE_GENERATION_SECONDS);
  check(restrictions.expires > now + restrictions.seconds * 1000);
  if (generation === 0) check(restrictions.expires > now + PROBE_SUITE_SECONDS * 1000);
}

export function runtimeDocument(): RuntimeConfig {
  return validateRuntimeConfig({
    version: "cogs.runtime/v1alpha1",
    profile: "api-key-only",
    paths: {
      launch_document: "/etc/cogs/launch.json",
      api_bearer: "/run/cogs/api/bearer",
      openbao_jwt: "/run/cogs/openbao/jwt",
      proxy_capability: "/run/cogs/proxy/capability",
      envoy_executable: "/usr/local/bin/envoy",
      egress_tmpfs: "/run/cogs/egress",
      audit_wal: "/var/lib/cogs/session/egress-audit.wal",
      agent_directory: "/var/lib/cogs/session/agent",
      session_root: "/var/lib/cogs/session/sessions",
      shared_skill_oci: "/var/lib/cogs/skills/shared-oci",
      private_skill_source: "/var/lib/cogs/skills/private-source",
      private_skill_store: "/var/lib/cogs/skills/private-store",
      skill_snapshot_receipt: "/run/cogs/skills/snapshot-receipt.json",
      skill_snapshot_control_socket: "/run/cogs/skills/control.sock",
    },
    api: { listen_host: "127.0.0.1", port: 18081 },
    openbao: {
      origin: "https://127.0.0.1:18444/",
      kubernetes_auth_mount: "synthetic",
      kubernetes_auth_role: "synthetic",
      model_kv_mount: "synthetic",
      egress_kv_mount: "synthetic",
      pki_mount: "synthetic",
      pki_role: "synthetic",
      projected_jwt_ttl_seconds: 600,
      max_client_token_ttl_seconds: 600,
    },
    otlp: {
      protocol: "http/json",
      traces_endpoint: "https://127.0.0.1:18444/v1/traces",
      metrics_endpoint: "https://127.0.0.1:18444/v1/metrics",
      logs_endpoint: "https://127.0.0.1:18444/v1/logs",
    },
    egress: { listener_port: 18080, revocation_poll_seconds: 1, completion_capacity: 8 },
    lifecycle: { maximum_session_seconds: 28800, shutdown_timeout_seconds: 10 },
  });
}
export function launchDocument(shared: string, user: string, pin = `SHA256:${"A".repeat(43)}`): LaunchConfig {
  const integration = {
    version: "cogs.integration/v1alpha1",
    id: "synthetic-local",
    dns: { mode: "proxy-connect-authority", guest_resolution: false },
    auth: {
      type: "bearer_header",
      header: "Authorization",
      prefix: "Bearer ",
      placeholder: "COGS_PLACEHOLDER_TOKEN",
      secret_handle: "users/synthetic/integrations/local",
    },
    rules: [
      {
        name: "fixture",
        host: "fixture.cogs.test",
        port: 18443,
        methods: ["GET"],
        path_patterns: ["/credential"],
        path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
        query_policy: { mode: "deny" },
        redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
        inject_auth: true,
      },
    ],
  };
  return validateLaunchConfig({
    version: "cogs.dev/v1alpha1",
    user_id: "synthetic",
    session_id: "product-session",
    workspace_id: "product-workspace",
    sandbox: {
      ssh_endpoint: "127.0.0.1:22",
      ssh_host_key: pin,
      client_key_path: "/run/cogs/ssh/client",
      proxy_auth_handle: "sessions/product-session/proxy",
    },
    model: { provider: "anthropic", id: "claude-sonnet-4-5", credential_handle: "users/synthetic/model" },
    skills: { shared_revision: shared, user_revision: user, shared_path: "/shared/skills", user_path: "/user/skills" },
    integrations: [{ ...integration, preset_revision: canonicalPresetPolicyRevision(integration) }],
    limits: {
      cpu: 2,
      memory_bytes: 4294967296,
      tool_timeout_seconds: 5,
      turn_timeout_seconds: 65,
      max_tool_output_bytes: 16384,
    },
  });
}
export function admitProfile(runtime: RuntimeConfig, launch: LaunchConfig): void {
  admitProductionLaunch(launch); // first semantic operation after the two validated reads
  check(canonical(runtime) === canonical(runtimeDocument()));
  check(
    canonical(launch) ===
      canonical(
        launchDocument(launch.skills.shared_revision, launch.skills.user_revision, launch.sandbox.ssh_host_key),
      ),
  );
  check(launch.integrations.length === 1 && launch.limits.max_tool_output_bytes === 16384);
}

/** No arbitrary input language: this one program bounds input, time, output and every destination. */
export const PROXY_CLIENT = `import os,ssl,urllib.request,urllib.error
proxy=os.environ.get('HTTPS_PROXY')
if not proxy: raise SystemExit(20)
if not proxy.startswith('http://cogs:') or not proxy.endswith('@127.0.0.1:18080'): raise SystemExit(21)
context=ssl.create_default_context(cafile=os.environ['SSL_CERT_FILE'])
url='https://fixture.cogs.test:18443/credential'
def attempt(value):
    handler=urllib.request.ProxyHandler({'https':value})
    client=urllib.request.build_opener(handler,urllib.request.HTTPSHandler(context=context))
    try:
        with client.open(urllib.request.Request(url,headers={'Authorization':'Bearer COGS_PLACEHOLDER_TOKEN'}),timeout=2) as r:
            return r.status,r.read(33)
    except urllib.error.URLError: return 0,b''
wrong='http://cogs:'+'x'*48+'@127.0.0.1:18080'
if attempt(wrong)[0] != 0: raise SystemExit(22)
if attempt(proxy) != (200,b'cogs-local-upstream'): raise SystemExit(23)
print('proxy-controls-passed')
`;
export class RestrictionCounters {
  events = 0;
  turns = 0;
  failed = false;
  headers = false;
  shutdown = false;
  admit(kind: "event" | "turn" | "history", entries = 0, nodes = 0): void {
    try {
      check(!this.failed);
      if (kind === "event") check(++this.events <= 48);
      if (kind === "turn") check(this.headers && !this.shutdown && ++this.turns <= 16);
      if (kind === "history") check(entries <= 25 && nodes <= 2048 && entries >= 0 && nodes >= 0);
    } catch {
      this.failed = true;
      throw new Error("restriction breach");
    }
  }
  disconnect(): void {
    if (!this.shutdown) {
      this.failed = true;
      throw new Error("unexpected SSE disconnect");
    }
  }
}

// Runs as image PID 1, using built-ins ONLY until the authenticated host reply.
export const WORKER_GATE = `
const fs=await import('node:fs'); const net=await import('node:net'); const crypto=await import('node:crypto');
const until=performance.now()+10000; let receipt,raw;
while(!receipt){
 try{const fd=fs.openSync('/run/cogs/skills/snapshot-receipt.json',fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==0||s.nlink!==1||s.size>8192)throw Error();
 raw=fs.readFileSync(fd);fs.closeSync(fd);receipt=JSON.parse(raw);}
 catch{if(performance.now()>=until)process.exit(70);await new Promise(r=>setTimeout(r,20));}
}
const encode=v=>typeof v==='object'&&v!==null?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+encode(v[k])).join(',')+'}':JSON.stringify(v);
const q={version:'cogs.skill-snapshot-control/v1',op:'acquire',nonce:crypto.randomBytes(16).toString('hex'),sequence:1,receipt_digest:'sha256:'+crypto.createHash('sha256').update(raw).digest('hex'),consumer_id:receipt.consumer_id,pid:process.pid};
const socket=net.createConnection('/run/cogs/skills/gate.sock');const timer=setTimeout(()=>process.exit(71),5000);
socket.on('error',()=>process.exit(72));socket.on('end',()=>process.exit(73));
await new Promise((resolve,reject)=>{let data='';socket.on('data',function onData(b){data+=b;if(data.length>1024)reject(Error());if(!data.includes('\\n'))return;
 if(data!==encode({...q,op:'leased'})+'\\n')reject(Error());else{socket.off('data',onData);resolve();}});socket.on('connect',()=>socket.write(encode(q)+'\\n'));});
clearTimeout(timer);socket.pause();globalThis.__cogsGate={fd:socket._handle.fd,q};
await (await import('/opt/cogs/dev/product-test/runner.ts')).workerMain();
socket.destroy();
`;
type GateState = { fd: number; q: Record<string, unknown> & { sequence: number } };
function gate(op: string, counts: Record<string, unknown> = {}): void {
  const state = (globalThis as typeof globalThis & { __cogsGate?: GateState }).__cogsGate;
  check(state);
  const q = { ...state.q, ...counts, sequence: ++state.q.sequence, op };
  const request = Buffer.from(canonical(q));
  check(writeSync(state.fd, request) === request.length);
  const bytes = Buffer.alloc(131073);
  let length = 0;
  const deadline = performance.now() + 2000;
  while (!bytes.subarray(0, length).includes(10)) {
    check(performance.now() < deadline && length < 131072);
    try {
      const n = readSync(state.fd, bytes, length, bytes.length - length, null);
      check(n > 0);
      length += n;
    } catch (e) {
      check((e as NodeJS.ErrnoException).code === "EAGAIN");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  const reply = op === "ping" ? "alive" : op === "release" ? "released" : "granted";
  check(bytes.subarray(0, length).equals(Buffer.from(canonical({ ...q, op: reply }))));
}

export function syntheticPkiArgv(root: string, name: "envoy" | "telemetry"): readonly (readonly string[])[] {
  const leafSubject = name === "envoy" ? "/CN=fixture.cogs.test" : "/CN=127.0.0.1";
  return [
    ["genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", `${root}/${name}-ca.key`],
    [
      "req",
      "-x509",
      "-key",
      `${root}/${name}-ca.key`,
      "-sha256",
      "-days",
      "1",
      "-subj",
      `/CN=synthetic-${name}-CA`,
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-out",
      `${root}/${name}-ca.crt`,
    ],
    ["genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", `${root}/${name}.key`],
    ["req", "-new", "-key", `${root}/${name}.key`, "-subj", leafSubject, "-out", `${root}/${name}.csr`],
    [
      "x509",
      "-req",
      "-in",
      `${root}/${name}.csr`,
      "-CA",
      `${root}/${name}-ca.crt`,
      "-CAkey",
      `${root}/${name}-ca.key`,
      "-set_serial",
      "1",
      "-days",
      "1",
      "-extfile",
      `${root}/${name}.ext`,
      "-out",
      `${root}/${name}.crt`,
    ],
  ];
}

class SyntheticAuthorityOwner {
  constructor(readonly host: CustodyPort) {}
  async create(): Promise<string> {
    await dir(this.host, "authority");
    const run = async (program: string, args: string[]) => this.host.request<string>("exec", { program, args });
    const root = `${this.host.root}/authority`;
    for (const name of ["host", "client"])
      await run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "synthetic-product", "-f", `${root}/${name}`]);
    // Fixed argv and paths only; custody retains nonzero and stderr-cap checks.
    for (const name of ["envoy", "telemetry"] as const) {
      await put(
        this.host,
        `authority/${name}.ext`,
        `subjectAltName=${name === "envoy" ? "DNS:fixture.cogs.test" : "IP:127.0.0.1"}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n`,
      );
      for (const args of syntheticPkiArgv(root, name)) await run("openssl", [...args]);
    }
    await dir(this.host, "sandbox-input", 0o500);
    for (const [source, target] of [
      ["host", "ssh_host_ed25519_key"],
      ["host.pub", "ssh_host_ed25519_key.pub"],
      ["client.pub", "client_ed25519_key.pub"],
      ["envoy-ca.crt", "egress-ca.crt"],
    ])
      await put(
        this.host,
        `sandbox-input/${target}`,
        await readFile(`${root}/${source}`),
        source === "host" ? 0o400 : 0o444,
      );
    const proxy = randomBytes(32).toString("base64url");
    await put(this.host, "sandbox-input/proxy-capability", proxy, 0o400);
    for (const name of ["api", "proxy", "ssh", "pki"]) await dir(this.host, `inputs/${name}`, 0o755);
    await put(this.host, "inputs/api/bearer", randomBytes(32).toString("base64url"), 0o400, 65532);
    await put(this.host, "inputs/proxy/capability", proxy, 0o400, 65532);
    await put(this.host, "inputs/ssh/client", await readFile(`${root}/client`), 0o400, 65532);
    for (const name of ["envoy-ca.crt", "envoy.crt", "envoy.key", "telemetry-ca.crt", "telemetry.crt", "telemetry.key"])
      await put(this.host, `inputs/pki/${name}`, await readFile(`${root}/${name}`), 0o400, 65532);
    const publicKey = (await readFile(`${root}/host.pub`, "utf8")).split(" ");
    await put(this.host, "authority/known_hosts", `127.0.0.1 ${publicKey.slice(0, 2).join(" ")}\n`);
    await put(this.host, "authority/sftp-batch", "ls /shared/skills\nls /user/skills\n");
    const key = publicKey[1];
    check(key);
    return `SHA256:${Buffer.from(hash(Buffer.from(key, "base64")).slice(7), "hex")
      .toString("base64")
      .replace(/=+$/, "")}`;
  }
}

export async function withProductCustody(host: CustodyPort, operation: () => Promise<boolean>): Promise<void> {
  let passed = false;
  const failures: unknown[] = [];
  try {
    passed = await operation();
  } catch (error) {
    failures.push(error);
  }
  try {
    const result = await host.request<{ retired: boolean; failed: boolean }>("settle", { passed });
    check(
      result.retired && (host.purpose === "capability-probe" ? result.failed && !passed : !result.failed && passed),
    );
  } catch (error) {
    failures.push(error);
  }
  try {
    await host.closed;
  } catch (error) {
    failures.push(error);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "product custody failed");
}
export async function capabilityRemovalScenario(host: CustodyPort, full: ContainerSpec, removed: string) {
  check(
    host.purpose === "capability-probe" &&
      canonical(full.caps) === canonical(SANDBOX_CAPABILITIES) &&
      full.mask === SANDBOX_CAPABILITY_MASK,
  );
  const spec = { ...full, ...sandboxCapabilities(removed) };
  await createSandbox(host, spec);
  return host.request("capability-probe");
}
async function createSandbox(host: CustodyPort, spec: ContainerSpec) {
  return host.request<string>("create", {
    role: "sandbox",
    spec,
    argv: containerArguments(host, spec, ["--env", "COGS_PROXY_ENDPOINT=http://127.0.0.1:18080"], "0:0"),
  });
}
export type ProductPassReceipt = Readonly<{
  version: "cogs.product-pass-receipt/v1";
  generation: string;
  candidate: string;
  tree: string;
  source_inventory: string;
  run_id: string;
  run_attempt: string;
  skills: "empty" | "nonempty";
}>;
export async function productMain(
  restrictions: Restrictions,
  removed?: string,
): Promise<ProductPassReceipt | undefined> {
  if (removed !== undefined) sandboxCapabilities(removed);
  check(admittedRestrictions.has(restrictions) && restrictions.expires > Date.now() + restrictions.seconds * 1000);
  const generation = randomBytes(16).toString("hex");
  // Pure construction and admission before the first root, secret, snapshot, daemon or process acquisition.
  const placeholder: CustodyPort = {
    root: "",
    generation,
    request: async () => {
      throw new Error("not admitted");
    },
  };
  const prospective = new LocalSkillSnapshotOwner(placeholder, restrictions.skills === "nonempty");
  const runtime = parseRuntimeConfigBytes(Buffer.from(canonicalRuntimeConfig(runtimeDocument())));
  admitProfile(runtime, launchDocument(prospective.sharedRevision, prospective.user.digest));
  check(restrictions.seconds + 120 < runtime.lifecycle.maximum_session_seconds);
  check(process.platform === "linux" && process.arch === "x64" && process.geteuid?.() === 0);
  for (const key of Object.keys(process.env))
    check(
      !/^(AWS_|AZURE_|GOOGLE_|ANTHROPIC_|OPENAI_|VAULT_|BAO_|OPENBAO_|SSH_|GIT_|DOCKER_|KUBECONFIG|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_|CURL_|LD_|PYTHON)/.test(
        key,
      ),
    );
  const host = new HostCustody(generation, restrictions.seconds, removed === undefined ? "run" : "capability-probe");
  let measurement: unknown;
  await withProductCustody(host, async () => {
    for (const id of [restrictions.sandbox_image, restrictions.worker_image, restrictions.stock_worker_image])
      await host.request("image", { id });
    const provenance = await host.request("provenance", { ...restrictions, recipe: hash(WORKER_DOCKERFILE) });
    const stockTrust = await pinnedTrust(host, restrictions.stock_worker_image);
    await host.request("storage", { name: "state" });
    await host.request("storage", { name: "workspace" });
    for (const name of ["host-private", "session", "private-store"])
      await dir(host, `state/${name}`, 0o700, name === "host-private" ? 0 : 65532);
    for (const name of ["agent", "sessions"]) await dir(host, `state/session/${name}`, 0o700, 65532);
    const skills = new LocalSkillSnapshotOwner(host, restrictions.skills === "nonempty");
    await skills.publish(launchDocument(skills.sharedRevision, skills.user.digest));
    const pin = await new SyntheticAuthorityOwner(host).create();
    const launch = launchDocument(skills.sharedRevision, skills.user.digest, pin);
    admitProfile(runtime, launch);
    await dir(host, "documents", 0o755);
    await dir(host, "lease", 0o750);
    await host.request("lease-directory");
    for (const [name, text] of [
      ["runtime.json", canonical(runtime)],
      ["launch.json", canonical(launch)],
    ] as const)
      await put(host, `documents/${name}`, text, 0o400, 65532);
    await put(
      host,
      "documents/envoy-trust.crt",
      Buffer.concat([stockTrust, Buffer.from("\n"), await readFile(`${host.root}/authority/envoy-ca.crt`)]),
      0o444,
    );
    await put(host, "documents/hosts", "127.0.0.1 localhost fixture.cogs.test\n::1 localhost\n", 0o444);
    await put(host, "documents/resolv.conf", "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", 0o444);
    await put(host, "documents/hostname", "cogs-product\n", 0o444);
    await put(host, "documents/provenance.json", canonical(provenance), 0o444);
    const mount = (source: string, target: string, ro = true): Mount => ({
      source: `${host.root}/${source}`,
      target,
      ro,
    });
    const networkFiles = [
      mount("documents/hosts", "/etc/hosts"),
      mount("documents/resolv.conf", "/etc/resolv.conf"),
      mount("documents/hostname", "/etc/hostname"),
    ];
    const sandboxSpec: ContainerSpec = {
      image: restrictions.sandbox_image,
      network: "none",
      caps: SANDBOX_CAPABILITIES,
      mask: SANDBOX_CAPABILITY_MASK,
      mounts: [
        ...networkFiles,
        ...skills.mounts(),
        mount("sandbox-input", "/run/cogs-input"),
        mount("workspace", "/workspace", false),
      ],
      tmpfs: {
        "/run/cogs-runtime": "rw,nosuid,nodev,noexec,size=4m,mode=0700",
        "/run/sshd": "rw,nosuid,nodev,noexec,size=1m,mode=0755",
        "/tmp": "rw,nosuid,nodev,noexec,size=16m,mode=1777",
      },
    };
    await host.request("seal");
    if (removed !== undefined) {
      measurement = await capabilityRemovalScenario(host, sandboxSpec, removed);
      return false; // no worker, lease, evidence admission or pass authority
    }
    const sandboxId = await createSandbox(host, sandboxSpec);
    const workerSpec: ContainerSpec = {
      image: restrictions.worker_image,
      network: `container:${sandboxId}`,
      caps: [],
      mask: 0,
      mounts: [
        ...networkFiles,
        mount("documents/runtime.json", "/etc/cogs/runtime.json"),
        mount("documents/launch.json", "/etc/cogs/launch.json"),
        mount("documents/provenance.json", "/etc/cogs/provenance.json"),
        ...["api", "proxy", "ssh", "pki"].map((n) => mount(`inputs/${n}`, `/run/cogs/${n}`)),
        mount("lease", "/run/cogs/skills"),
        mount("inputs/shared-oci", runtime.paths.shared_skill_oci),
        mount("inputs/private-source", runtime.paths.private_skill_source),
        mount("state/private-store", runtime.paths.private_skill_store, false),
        mount("state/session", "/var/lib/cogs/session", false),
        mount("workspace", "/workspace"),
        mount("documents/envoy-trust.crt", "/etc/ssl/certs/ca-certificates.crt"),
      ],
      tmpfs: {
        "/tmp": "rw,nosuid,nodev,noexec,size=32m,mode=1777",
        "/run/cogs/egress": "rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=65532,gid=65532",
      },
    };
    const argv = containerArguments(
      host,
      workerSpec,
      ["--env", "NODE_EXTRA_CA_CERTS=/run/cogs/pki/telemetry-ca.crt", "--entrypoint", "/nodejs/bin/node"],
      "65532:65532",
    );
    argv.push("--experimental-transform-types", "--input-type=module", "--eval", WORKER_GATE);
    await host.request("create", { role: "worker", spec: workerSpec, argv });
    const sandbox = await host.request<ContainerReceipt>("authenticate", { role: "sandbox" });
    const worker = await host.request<ContainerReceipt>("authenticate", { role: "worker" });
    await skills.lease(launch, worker, sandbox);
    for (;;) {
      const status = await host.request<{ running: boolean; code: number }>("status");
      if (!status.running) {
        check(status.code === 0);
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    const evidence = JSON.parse(await host.request<string>("evidence"));
    check(evidence.outcome === "pass" && evidence.generation === generation && evidence.upstream === 1);
    check(canonical(evidence.provenance) === canonical(provenance));
    check(evidence.traces > 0 && evidence.metrics > 0 && evidence.audit > 0 && evidence.omitted === true);
    return true;
  });
  if (measurement) {
    process.stdout.write(canonical(measurement)); // only after receipt-bound settlement
    return undefined;
  }
  // This is emitted only after withProductCustody observed the root settlement
  // receipt and host.closed; it contains no control contents or credentials.
  return Object.freeze({
    version: "cogs.product-pass-receipt/v1",
    generation,
    candidate: restrictions.candidate,
    tree: restrictions.tree,
    source_inventory: restrictions.source_inventory,
    run_id: restrictions.run_id,
    run_attempt: restrictions.run_attempt,
    skills: restrictions.skills,
  });
}

async function material(name: string): Promise<string> {
  return withTrustedFileBytes(
    {
      path: `/run/cogs/pki/${name}`,
      minimumBytes: 64,
      maximumBytes: 65536,
      allowedUids: [65532],
      allowedGids: [65532],
      allowedModes: [0o400],
    },
    async (b) => b.toString(),
  );
}
export async function syntheticPorts(launch: LaunchConfig) {
  const certificate = await material("envoy.crt"),
    privateKey = await material("envoy.key"),
    ca = await material("envoy-ca.crt");
  const cert = new X509Certificate(certificate);
  check(cert.subjectAltName === "DNS:fixture.cogs.test" && cert.checkHost("fixture.cogs.test") === "fixture.cogs.test");
  const expiresAtMs = Date.parse(cert.validTo);
  const identity = Object.freeze<OpenBaoIdentityPort>({
    withToken: async (signal, consume) => {
      check(!signal.aborted);
      await consume("synthetic-disposable-token");
    },
  });
  const model = Object.freeze<ModelApiKeySource>({
    withApiKey: async (request, consume) => {
      check(
        !request.signal?.aborted &&
          request.userId === launch.user_id &&
          request.provider === launch.model.provider &&
          request.model === launch.model.id &&
          request.credentialHandle === launch.model.credential_handle,
      );
      await consume("synthetic-model-key-not-a-provider-credential");
    },
  });
  const pki = Object.freeze<CogsEgressPkiSource>({
    withPkiMaterial: async (request, consume) => {
      check(
        !request.signal?.aborted &&
          request.sessionId === launch.session_id &&
          canonical(request.hosts) === canonical(["fixture.cogs.test"]) &&
          request.maxSessionExpiresAtMs < expiresAtMs,
      );
      return consume(
        Object.freeze({
          certificateChainPem: certificate,
          privateKeyPem: privateKey,
          caCertificatePem: ca,
          expiresAtMs,
        }),
      );
    },
  });
  const revision = aggregateCogsEgressRoutePlanRevision(lowerLaunchEgressRoutePlan(launch));
  const revocation = Object.freeze({
    mode: "injected" as const,
    credentialVersion: "synthetic-1",
    credentialSource: Object.freeze({
      withCredential: async (
        request: { integrationId: string; secretHandle: string; authType: string },
        consume: (value: { type: "bearer"; token: string }) => Promise<void>,
      ) => {
        check(
          request.integrationId === "synthetic-local" &&
            request.secretHandle === "users/synthetic/integrations/local" &&
            request.authType === "bearer_header",
        );
        await consume(Object.freeze({ type: "bearer", token: "synthetic-upstream-credential" }));
      },
    }),
    revocationSource: Object.freeze({
      read: async () =>
        Object.freeze({
          presetRevision: revision,
          credentialVersion: "synthetic-1",
          revoked: false,
          pkiExpiresAtMs: expiresAtMs,
        }),
    }),
  });
  return Object.freeze({ identity, model, pki, revocation, certificate, privateKey });
}

/** A settled turn is not proof that its tool succeeded. Failure remains latched after effects. */
export class ProductToolResults {
  readonly results: string[] = [];
  failed = false;
  admit(entry: unknown): unknown {
    try {
      check(!this.failed);
      admitScenarioValue(entry);
      // Match the gate and native JSONL projection, including Pi's own usage: undefined.
      const projected = JSON.parse(JSON.stringify(entry));
      const message = projected.message;
      if (message?.role !== "toolResult") return projected;
      check(message.isError === false && message.toolCallId === "product-proxy" && message.toolName === "bash");
      check(canonical(message.details) === canonical({ cogsTool: "bash" }));
      check(Array.isArray(message.content) && message.content.length === 1);
      const block = message.content[0];
      check(Object.keys(block).sort().join() === "text,type" && block.type === "text");
      check(typeof block.text === "string" && Buffer.byteLength(block.text) <= 16384);
      const result = JSON.parse(block.text);
      check(
        JSON.stringify(result) === block.text && result.ok === true && result.exitCode === 0 && result.signal === null,
      );
      const flags =
        "timedOut idleTimedOut cancelled stdoutTruncated stderrTruncated stdoutLossyUtf8 stderrLossyUtf8".split(" ");
      const zeros =
        "stdoutDroppedBytes stderrDroppedBytes stdoutResultOmittedUtf8Bytes stderrResultOmittedUtf8Bytes updateDropped".split(
          " ",
        );
      check(
        Object.keys(result).sort().join() ===
          [
            ...flags,
            ...zeros,
            "ok",
            "exitCode",
            "signal",
            "elapsedMs",
            "stdout",
            "stderr",
            "stdoutBytes",
            "stderrBytes",
          ]
            .sort()
            .join(),
      );
      check(flags.every((key) => result[key] === false) && zeros.every((key) => result[key] === 0));
      check(Number.isSafeInteger(result.elapsedMs) && result.elapsedMs >= 0 && result.elapsedMs <= 10000);
      for (const key of ["stdout", "stderr"]) {
        check(typeof result[key] === "string" && Buffer.byteLength(result[key]) <= 4096);
        check(result[`${key}Bytes`] === Buffer.byteLength(result[key]));
      }
      check(this.results.length === 0);
      this.results.push(hash(canonical(message)));
      return projected;
    } catch {
      this.failed = true;
      throw new Error("product tool failed; settle exact custody");
    }
  }
  evidence(): readonly string[] {
    check(!this.failed && this.results.length === 1);
    return Object.freeze([...this.results]);
  }
}
export function deterministicStream(): StreamFn {
  let index = 0;
  return Object.freeze((model, _context, options) => {
    check(!options?.signal?.aborted && options?.apiKey === "synthetic-model-key-not-a-provider-credential");
    check(model.provider === "anthropic" && model.id === "claude-sonnet-4-5" && index < 4);
    const stage = index++;
    const stream = createAssistantMessageEventStream();
    const command = `set -eu\ncd /workspace\nprintf 'alpha\\n' > proof.txt\ngit init -q --template= --initial-branch=master\ngit config user.email synthetic@example.invalid\ngit config user.name Synthetic\ngit add proof.txt\ngit commit -q -m synthetic-baseline\npython3 -I - <<'COGS_FIXED_PROGRAM'\n${PROXY_CLIENT}COGS_FIXED_PROGRAM\n`;
    const result: AssistantMessage = {
      role: "assistant",
      api: "anthropic-messages",
      provider: model.provider,
      model: model.id,
      content:
        stage === 0
          ? [{ type: "toolCall", id: "product-proxy", name: "bash", arguments: { command } }]
          : [{ type: "text", text: stage === 2 ? "synthetic-detail ".repeat(4096) : "product settled" }],
      stopReason: stage === 0 ? "toolUse" : "stop",
      timestamp: Date.now(),
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
    };
    admitScenarioValue(result);
    stream.push({ type: "start", partial: result });
    stream.push({ type: "done", reason: result.stopReason as "stop" | "toolUse", message: result });
    stream.end();
    return stream;
  });
}

export function admitScenarioValue(value: unknown): void {
  let nodes = 0;
  const visit = (v: unknown, depth: number): void => {
    check(++nodes <= 2048 && depth <= 16);
    if (v && typeof v === "object") {
      check([Object.prototype, Array.prototype, null].includes(Object.getPrototypeOf(v)));
      for (const key of Reflect.ownKeys(v)) {
        check(typeof key === "string" && key !== "__proto__");
        const d = Object.getOwnPropertyDescriptor(v, key);
        check(d && "value" in d);
        visit(d.value, depth + 1);
      }
    }
  };
  visit(value, 0);
}

async function verifyFragments(pi: CogsPiSessionPorts, bearer: string): Promise<void> {
  check(pi.projectedEntry);
  let cursor: string | undefined, after: string | undefined;
  let held: { entryId: string; bytes: Buffer } | undefined;
  let offset = 0,
    total = 0;
  for (let pages = 0; pages < 128; pages++) {
    const path = `/v1/entry-fragments${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`;
    const response = await fetch(`http://127.0.0.1:18081${path}`, {
      headers: { authorization: `Bearer ${bearer}` },
      redirect: "error",
      signal: AbortSignal.timeout(2000),
    });
    check(response.status === 200 && response.body);
    const reader = response.body.getReader(),
      chunks: Buffer[] = [];
    let size = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.length;
        check(size <= 131072);
        chunks.push(Buffer.from(part.value));
      }
    } finally {
      await reader.cancel();
      reader.releaseLock();
    }
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    check(
      value.version === "cogs.entry-fragments/v1" &&
        value.projection === "cogs.permitted-json/v1" &&
        value.fragments.length <= 1,
    );
    for (const fragment of value.fragments) {
      held ??= await pi.projectedEntry({ after });
      const data = Buffer.from(fragment.data, "base64");
      total += data.length;
      check(total <= 2 * 1024 * 1024 && data.length > 0);
      check(
        fragment.encoding === "base64" &&
          data.toString("base64") === fragment.data &&
          fragment.entryId === held.entryId &&
          fragment.offset === offset &&
          fragment.totalBytes === held.bytes.length,
      );
      check(data.equals(held.bytes.subarray(offset, offset + data.length)));
      offset += data.length;
      if (fragment.final) {
        check(offset === held.bytes.length);
        after = held.entryId;
        held = undefined;
        offset = 0;
      }
    }
    if (value.snapshotFinal) {
      check(!held && after !== undefined);
      return;
    }
    check(typeof value.next === "string" && value.next.length <= 2048 && value.next !== cursor);
    cursor = value.next;
  }
  throw new Error("fragment bound crossed");
}

/** Candidate entry is callable only after the inert built-in gate authenticates this PID. */
export async function workerMain(): Promise<void> {
  gate("ping");
  const heartbeat = setInterval(() => {
    try {
      gate("ping");
    } catch {
      process.exit(74);
    }
  }, 1000);
  const runtime = parseRuntimeConfigBytes(await readFile("/etc/cogs/runtime.json"));
  const launch = validateLaunchConfig(JSON.parse(await readFile("/etc/cogs/launch.json", "utf8")));
  admitProfile(runtime, launch);
  const synthetic = await syntheticPorts(launch);
  let upstream = 0,
    traces = 0,
    metrics = 0,
    audit = 0;
  const exports: Array<{ path: string; body: unknown }> = [];
  const upstreamRequests: Array<{ method: string; path: string; credential: boolean }> = [];
  const upstreamServer = httpsServer({ cert: synthetic.certificate, key: synthetic.privateKey }, (req, res) => {
    upstream++;
    upstreamRequests.push({
      method: req.method ?? "",
      path: req.url ?? "",
      credential: req.headers.authorization === "Bearer synthetic-upstream-credential",
    });
    if (
      req.method !== "GET" ||
      req.url !== "/credential" ||
      req.headers.authorization !== "Bearer synthetic-upstream-credential" ||
      upstream > 1
    ) {
      res.writeHead(403).end();
      return;
    }
    res.writeHead(200, { "content-type": "text/plain" }).end("cogs-local-upstream");
  });
  const collector = httpsServer(
    { cert: await material("telemetry.crt"), key: await material("telemetry.key") },
    (req, res) => {
      if (req.method !== "POST" || !["/v1/traces", "/v1/metrics", "/v1/logs"].includes(req.url ?? "")) {
        res.writeHead(404).end();
        return;
      }
      let bytes = 0;
      const chunks: Buffer[] = [];
      req.on("data", (b: Buffer) => {
        bytes += b.length;
        if (bytes <= 1024 * 1024) chunks.push(b);
        if (bytes > 1024 * 1024) req.destroy();
      });
      req.on("end", () => {
        try {
          check(bytes > 0 && bytes <= 1024 * 1024 && exports.length < 128);
          exports.push({ path: req.url ?? "", body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch {
          res.writeHead(400).end();
          return;
        }
        if (req.url === "/v1/traces") traces++;
        if (req.url === "/v1/metrics") metrics++;
        res.writeHead(200, { "content-type": "application/json" }).end("{}");
      });
    },
  );
  for (const [server, port] of [
    [upstreamServer, 18443],
    [collector, 18444],
  ] as const) {
    server.requestTimeout = 2000;
    server.headersTimeout = 2000;
    server.maxConnections = 8;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
  }
  let pi: CogsPiSessionPorts | undefined, api: ApiServer | undefined;
  let omitted = false,
    settled = 0,
    shutdown = false,
    streamFailed = false;
  const counters = new RestrictionCounters();
  const toolResults = new ProductToolResults();
  const observedEvents: Array<{ kind: unknown; correlation_id: unknown; request_id: unknown }> = [];
  let exported: unknown;
  let auditTimer: ReturnType<typeof setInterval> | undefined;
  let egressHandle: CogsEgressRuntimeManager | undefined;
  let telemetry: CogsWorkerTelemetrySink | undefined;
  const worker = await startProductionWorker({
    seams: {
      createIdentity: () => synthetic.identity,
      createTelemetry: (config) =>
        (telemetry = createCogsWorkerTelemetrySink({
          mode: "otlp",
          tracesEndpoint: config.otlp.traces_endpoint,
          metricsEndpoint: config.otlp.metrics_endpoint,
        })),
      createModelStore: () => synthetic.model,
      createEgress: async (options) => {
        const egress = await startCogsEgressRuntimeManager({
          ...options,
          pkiSource: synthetic.pki,
          revocation: synthetic.revocation,
        });
        const handle = egress;
        egressHandle = handle;
        auditTimer = setInterval(() => {
          audit = Math.max(audit, handle.auditRecords?.(128).length ?? 0);
        }, 50);
        return egress;
      },
      createPi: async (options) => {
        pi = await createAuthenticatedCogsPiSession({
          ...options,
          streamFn: deterministicStream(),
          historyAdmission: (entry) => {
            gate("persist", { entry: toolResults.admit(entry) });
          },
        });
        return pi;
      },
      createApi: (options) => {
        const created = createApiServer(options);
        api = registerCloseOwner(
          Object.freeze({
            ...created,
            publish: (event: Parameters<ApiServer["publish"]>[0]) => {
              try {
                counters.admit("event");
                gate("event", {
                  event: {
                    kind: event.kind,
                    correlation_id: event.correlation_id,
                    request_id: event.request_id ?? null,
                  },
                });
                return created.publish(event);
              } catch {
                streamFailed = true;
                return false;
              }
            },
          }),
          () => beginRegisteredClose(created),
        );
        return api;
      },
    },
  });
  const bearer = await readFile(runtime.paths.api_bearer, "utf8");
  const headers = Promise.withResolvers<void>();
  const streamAbort = new AbortController();
  const client = createApiClient({
    port: 18081,
    token: bearer,
    timeoutMs: 30000,
    maxBytes: 1024 * 1024,
    seams: Object.freeze({
      randomBytes: Object.freeze(randomBytes.bind(undefined)),
      fetch: Object.freeze<typeof fetch>(async (input, init) => {
        check(String(input).startsWith("http://127.0.0.1:18081/"));
        const response = await fetch(input, init);
        if (new URL(String(input)).pathname === "/v1/events") {
          check(response.status === 200);
          counters.headers = true;
          gate("headers");
          headers.resolve();
        }
        return response;
      }),
    }),
  });
  const stream = (async () => {
    try {
      for await (const { data: event } of client.events(0, 48, streamAbort.signal)) {
        observedEvents.push({
          kind: event.kind,
          correlation_id: event.correlation_id,
          request_id: event.request_id ?? null,
        });
        if (event.kind === "run_settled") settled++;
        if (event.kind === "shutdown_ready") {
          shutdown = true;
          const payload = event.payload as Record<string, unknown>;
          exported = {
            sensitive: true,
            bundle: Object.fromEntries(
              ["bundle", "manifest_sha256", "mode", "file_count", "total_bytes"].map((key) => [key, payload[key]]),
            ),
          };
        }
        const payload = event.payload as { cogs_transport?: { status?: string } };
        if (payload?.cogs_transport?.status === "omitted") omitted = true;
      }
    } catch {
      if (!shutdown) streamFailed = true;
    } finally {
      if (!shutdown) {
        streamFailed = true;
        headers.reject(new Error("SSE failed"));
      }
    }
  })();
  await headers.promise;
  try {
    for (let turn = 0; turn < 3; turn++) {
      counters.admit("turn");
      gate("turn");
      await client.request("run", { content: "synthetic" });
      const deadline = performance.now() + 10000;
      while (settled <= turn) {
        check(!streamFailed && !toolResults.failed && performance.now() < deadline);
        await new Promise((r) => setTimeout(r, 20));
      }
    }
    const successfulTools = toolResults.evidence();
    gate("history"); // host reads durable JSONL and reconciles its own pre-write admissions
    await client.request("entries", { limit: 25 });
    check(pi && upstream === 1 && omitted && !streamFailed);
    await verifyFragments(pi, bearer);
    await client.request("shutdown");
    await worker.closed;
    check(shutdown && !streamFailed);
    counters.shutdown = true;
    streamAbort.abort();
    await stream;
    await Promise.all(
      [upstreamServer, collector].map(
        (server) =>
          new Promise<void>((resolve, reject) => {
            server.closeAllConnections();
            server.close((e) => (e ? reject(e) : resolve()));
          }),
      ),
    );
    check(traces > 0 && metrics > 0 && audit > 0);
    const state = (globalThis as typeof globalThis & { __cogsGate: GateState }).__cogsGate;
    const receipt = JSON.parse(await readFile(runtime.paths.skill_snapshot_receipt, "utf8"));
    const { open } = await import("node:fs/promises");
    const evidence = await open(
      "/var/lib/cogs/session/product-evidence.json",
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    await evidence.writeFile(
      canonical({
        outcome: "pass",
        toolResults: successfulTools,
        provenance: JSON.parse(await readFile("/etc/cogs/provenance.json", "utf8")),
        egress: egressHandle && observeCogsEgressRuntime(egressHandle),
        telemetry: telemetry?.snapshot(),
        exports,
        upstreamRequests,
        exported,
        observedEvents,
        generation: receipt.generation,
        upstream,
        traces,
        metrics,
        audit,
        omitted,
        events: counters.events,
        turns: counters.turns,
        consumer: state.q.consumer_id,
      }),
    );
    await evidence.sync();
    await evidence.close();
    gate("shutdown");
    gate("release");
  } finally {
    clearInterval(heartbeat);
    clearInterval(auditTimer);
    await worker.close().catch(() => {
      process.exitCode = 1;
    });
    streamAbort.abort();
    upstreamServer.closeAllConnections();
    collector.closeAllConnections();
    upstreamServer.close();
    collector.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length === 3 && process.argv[2] === "--dockerfile") process.stdout.write(WORKER_DOCKERFILE);
  else {
    check(process.argv.length === 5 && ["--protected-linux", "--capability-probes"].includes(process.argv[2] ?? ""));
    const [path, candidate] = process.argv.slice(3);
    check(path && candidate);
    const restrictions = await withTrustedFileBytes(
      { path, minimumBytes: 2, maximumBytes: 8192, allowedUids: [0], allowedGids: [0], allowedModes: [0o400] },
      async (b) => admitRestrictions(b, candidate, Date.now()),
    );
    if (process.argv[2] === "--capability-probes") {
      check(SANDBOX_CAPABILITIES.length === PROBE_GENERATIONS);
      for (const [generation, removed] of SANDBOX_CAPABILITIES.entries()) {
        requireProbeSuiteWindow(restrictions, Date.now(), generation);
        await productMain(restrictions, removed);
      }
    } else {
      const receipt = await productMain(restrictions);
      check(receipt);
      process.stdout.write(canonical(receipt));
    }
  }
}
