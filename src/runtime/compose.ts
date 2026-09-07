import { randomBytes } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { ApiServer, ApiServerOptions } from "../api/server.ts";
import { createApiServer } from "../api/server.ts";
import { type ModelApiKeySource, type OpenBaoIdentityPort, OpenBaoModelApiKeyStore } from "../auth/model-auth.ts";
import { OpenBaoKubernetesWorkloadIdentity } from "../auth/openbao-workload-identity.ts";
import { createNodeCogsEnvoyProcessPort } from "../egress/envoy-process.ts";
import { OpenBaoEgressPkiSource } from "../egress/openbao-pki.ts";
import { requireProxyCapability } from "../egress/proxy-capability.ts";
import {
  type CogsEgressRuntimeManager,
  type CogsEgressRuntimeManagerOptions,
  startCogsEgressRuntimeManager,
} from "../egress/runtime-manager.ts";
import {
  beginRegisteredClose,
  type CloseContext,
  type CloseWork,
  closeContext,
  createCloseOwner,
  joinCloseWork,
  observeClose,
  registerCloseOwner,
} from "../launch/close.ts";
import { type LaunchConfig, validateLaunchConfig } from "../launch/config.ts";
import {
  createCogsEgressRuntimeLaunchDependency,
  type LaunchDependency,
  LaunchLifecycle,
  type LaunchLifecycleOptions,
} from "../launch/lifecycle.ts";
import {
  type AuthenticatedCogsPiSessionOptions,
  type CogsPiSessionPorts,
  createAuthenticatedCogsPiSession,
  failedCogsPiSessionRetirement,
} from "../pi/session.ts";
import { authorizeCogsPolicyAction } from "../policy/static-policy.ts";
import { type CogsPrivateSkillStore, createCogsPrivateSkillStore } from "../skills/local-private-store.ts";
import { type CogsSharedSkillOciResolver, createCogsSharedSkillOciLayoutResolver } from "../skills/oci-layout.ts";
import { createCogsSkillSessionPreparer } from "../skills/session-preparer.ts";
import { createSshBashToolPort } from "../ssh/bash-tool.ts";
import { SshConnectionManager, type SshConnectionManagerOptions } from "../ssh/connection.ts";
import { createSftpFileToolPorts } from "../ssh/file-tools.ts";
import type { CogsTelemetry } from "../telemetry/instrumentation.ts";
import { type CogsWorkerTelemetrySink, createCogsWorkerTelemetrySink } from "../telemetry/worker-telemetry.ts";
import { parseRuntimeConfigBytes, type RuntimeConfig } from "./config.ts";
import { type TrustedFileCaptureOptions, withTrustedFileBytes } from "./trusted-files.ts";

export const PRODUCTION_RUNTIME_DOCUMENT = "/etc/cogs/runtime.json";
const GENERIC = "production worker unavailable";
const POLICY = Object.freeze(authorizeCogsPolicyAction);

type SecretKind = "api-bearer" | "proxy-capability";
type Storage = Readonly<{ shared: CogsSharedSkillOciResolver; private: CogsPrivateSkillStore }>;
type CloseReason = "requested" | "signal" | "dependency-lost" | "pi-fatal" | "startup-failed";

export interface ProductionWorkerRuntime {
  readonly ready: boolean;
  readonly apiPort: number;
  readonly closed: Promise<void>;
  readonly close: (reason?: CloseReason, context?: CloseContext) => Promise<void>;
}

export type ProductionWorkerSeams = Readonly<{
  readRuntime(): Promise<RuntimeConfig>;
  readLaunch(runtime: RuntimeConfig): Promise<LaunchConfig>;
  readSecret(kind: SecretKind, path: string): Promise<string>;
  createIdentity(runtime: RuntimeConfig): OpenBaoIdentityPort;
  createTelemetry(runtime: RuntimeConfig): CogsWorkerTelemetrySink;
  prepareStorage(runtime: RuntimeConfig): Promise<Storage>;
  verifyAuditWal(path: string): Promise<void>;
  createModelStore(runtime: RuntimeConfig, identity: OpenBaoIdentityPort): ModelApiKeySource;
  createSsh(options: SshConnectionManagerOptions): SshConnectionManager;
  createEgress(options: CogsEgressRuntimeManagerOptions): Promise<CogsEgressRuntimeManager>;
  createLifecycle(options: LaunchLifecycleOptions): LaunchLifecycle;
  createPi(options: AuthenticatedCogsPiSessionOptions): Promise<CogsPiSessionPorts>;
  createApi(options: ApiServerOptions): ApiServer;
  now(): number;
  randomSecret(bytes: number): string;
}>;

export class ProductionWorkerError extends Error {
  public readonly code = "COGS_PRODUCTION_WORKER_FAILED";
  public constructor() {
    super(GENERIC);
    this.name = "ProductionWorkerError";
    this.stack = `${this.name}: ${this.message}`;
  }
}

const DEFAULT_SEAMS: ProductionWorkerSeams = Object.freeze({
  readRuntime: () => readRuntimeDocument(),
  readLaunch: (runtime) => readLaunchDocument(runtime),
  readSecret: (kind, path) => readSecretFile(kind, path),
  createIdentity: (runtime) =>
    new OpenBaoKubernetesWorkloadIdentity({
      origin: runtime.openbao.origin,
      authMount: runtime.openbao.kubernetes_auth_mount,
      role: runtime.openbao.kubernetes_auth_role,
      jwtFile: trustedOptions(runtime.paths.openbao_jwt, 26, 16 * 1024, [0o400, 0o440]),
      maxTokenTtlSeconds: runtime.openbao.max_client_token_ttl_seconds,
    }),
  createTelemetry: (runtime) =>
    createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: runtime.otlp.traces_endpoint,
      metricsEndpoint: runtime.otlp.metrics_endpoint,
    }),
  prepareStorage: async (runtime) => {
    await verifyPersistentStorage(runtime);
    const shared = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: runtime.paths.shared_skill_oci });
    const privateStore = await createCogsPrivateSkillStore({
      sourceRoot: runtime.paths.private_skill_source,
      storeRoot: runtime.paths.private_skill_store,
    });
    return Object.freeze({ shared, private: privateStore });
  },
  verifyAuditWal: (path) => verifyWalParent(path),
  createModelStore: (runtime, identity) =>
    new OpenBaoModelApiKeyStore({
      origin: runtime.openbao.origin,
      mount: runtime.openbao.model_kv_mount,
      identity,
    }),
  createSsh: (options) => new SshConnectionManager(options),
  createEgress: (options) => startCogsEgressRuntimeManager(options),
  createLifecycle: (options) => new LaunchLifecycle(options),
  createPi: (options) => createAuthenticatedCogsPiSession(options),
  createApi: (options) => createApiServer(options),
  now: Date.now,
  randomSecret: (bytes) => randomBytes(bytes).toString("base64url"),
});

export async function startProductionWorker(
  input: Readonly<{ signal?: AbortSignal; seams?: Partial<ProductionWorkerSeams> }> = Object.freeze({}),
): Promise<ProductionWorkerRuntime> {
  const seams = mergeSeams(input.seams);
  const startup = linkedAbort(input.signal);
  let telemetry: CogsWorkerTelemetrySink | undefined;
  let lifecycle: LaunchLifecycle | undefined;
  let pi: CogsPiSessionPorts | undefined;
  let piStartupWork: Promise<CogsPiSessionPorts> | undefined;
  let api: ApiServer | undefined;
  let closeStarted = false;
  let resolveClosed!: () => void;
  let rejectClosed!: (error: Error) => void;
  const closed = new Promise<void>((resolvePromise, rejectPromise) => {
    resolveClosed = resolvePromise;
    rejectClosed = rejectPromise;
  });
  closed.catch(() => undefined);
  let published = false;
  let cleanupUncertain = false;
  let spontaneousFailure = false;
  const startedDependencies = new Set<LaunchDependency["name"]>();
  const closedDependencies = new Set<LaunchDependency["name"]>();
  let runtime!: RuntimeConfig;
  const onCallerAbort = () => {
    if (published) void close("signal").catch(() => undefined);
  };
  input.signal?.addEventListener("abort", onCallerAbort, { once: true });

  const beginCompositeClose = createCloseOwner(
    async () => {
      // API admission and Pi work stop before dependency release. Neither a
      // timeout nor one rejection authorizes lifecycle/SSH/material destruction.
      const independent = await Promise.allSettled([
        api ? Promise.resolve().then(() => joinCloseWork(beginRegisteredClose(api as ApiServer))) : Promise.resolve(),
        closePiStartupOwner(),
      ]);
      if (independent.some((result) => result.status === "rejected")) {
        cleanupUncertain = true;
        throw new ProductionWorkerError();
      }
      const dependencyWork = lifecycle?.closeDependencies(closeContext(10_000));
      if (dependencyWork !== undefined) await Promise.all([dependencyWork.done, dependencyWork.retired]);
      await (telemetry?.close() ?? Promise.resolve());
      for (const name of startedDependencies) if (!closedDependencies.has(name)) cleanupUncertain = true;
      startup.dispose();
      input.signal?.removeEventListener("abort", onCallerAbort);
      if (cleanupUncertain) throw new ProductionWorkerError();
    },
    () => {
      closeStarted = true;
      startup.abort();
    },
  );

  const closePiStartupOwner = async (): Promise<void> => {
    const startupWork = piStartupWork;
    if (startupWork === undefined) return closePi(pi);
    let acquired: CogsPiSessionPorts;
    try {
      acquired = await startupWork;
    } catch (error) {
      await failedCogsPiSessionRetirement(error);
      return;
    }
    if (pi === undefined) pi = acquired;
    await closePi(acquired);
  };

  const close = (reason: CloseReason = "requested", context = closeContext(10_000)): Promise<void> => {
    if (reason === "dependency-lost" || reason === "pi-fatal" || reason === "startup-failed") spontaneousFailure = true;
    closeStarted = true;
    const observed = lifecycle
      ? lifecycle.requestShutdown(`production:${reason}`, context)
      : observeClose(beginCompositeClose(), context);
    const result = observed
      .then(() => {
        if (cleanupUncertain || spontaneousFailure || lifecycle?.state === "failed") throw new ProductionWorkerError();
      })
      .catch(() => {
        if (lifecycle?.state !== "stopped") cleanupUncertain = true;
        throw new ProductionWorkerError();
      });
    result.then(resolveClosed, () => rejectClosed(new ProductionWorkerError()));
    return result;
  };

  try {
    runtime = await seams.readRuntime();
    throwIfAborted(startup.signal);
    const launch = await seams.readLaunch(runtime);
    requireUserScopedHandles(launch);
    const bearer = await seams.readSecret("api-bearer", runtime.paths.api_bearer);
    const proxyCapability = await seams.readSecret("proxy-capability", runtime.paths.proxy_capability);
    throwIfAborted(startup.signal);
    const identity = seams.createIdentity(runtime);
    telemetry = seams.createTelemetry(runtime);
    if (telemetry.ready !== true) throw new Error("telemetry unavailable");
    const modelStore = seams.createModelStore(runtime, identity);
    let storage: Storage | undefined;
    let ssh: SshConnectionManager | undefined;

    const dependency = (
      name: LaunchDependency["name"],
      start: (signal: AbortSignal) => Promise<void>,
      shutdown: (signal: AbortSignal) => Promise<void>,
      ready: () => boolean,
      beginClose?: (context: CloseContext) => CloseWork,
    ): LaunchDependency =>
      Object.freeze({
        name,
        start: async (signal: AbortSignal) => {
          // Custody begins before acquisition code can create a partial owner.
          startedDependencies.add(name);
          await start(signal);
        },
        ready,
        ...(beginClose === undefined
          ? {}
          : {
              beginClose: (context: CloseContext) => {
                const work = beginClose(context);
                const actual = joinCloseWork(work).then(
                  () => {
                    closedDependencies.add(name);
                  },
                  () => {
                    cleanupUncertain = true;
                    throw new ProductionWorkerError();
                  },
                );
                void actual.catch(() => undefined);
                return { done: actual, retired: work.retired };
              },
            }),
        shutdown: async (signal: AbortSignal) => {
          const uncertain = () => {
            cleanupUncertain = true;
          };
          signal.addEventListener("abort", uncertain, { once: true });
          try {
            await shutdown(signal);
            closedDependencies.add(name);
          } catch {
            cleanupUncertain = true;
            throw new Error("cleanup failed");
          } finally {
            signal.removeEventListener("abort", uncertain);
          }
        },
      });

    const egressDependency = createCogsEgressRuntimeLaunchDependency(async (signal) => {
      if (ssh === undefined) throw new Error("ssh unavailable");
      return seams.createEgress({
        launch,
        walPath: runtime.paths.audit_wal,
        listenerPort: runtime.egress.listener_port,
        maxSessionExpiresAtMs: seams.now() + runtime.lifecycle.maximum_session_seconds * 1000,
        completionCapacity: runtime.egress.completion_capacity,
        revocation: {
          mode: "openbao",
          openbao: {
            origin: runtime.openbao.origin,
            mount: runtime.openbao.egress_kv_mount,
            identity,
          },
        },
        telemetry: { mode: "otlp", endpoint: runtime.otlp.logs_endpoint },
        workerTelemetry: telemetry as CogsTelemetry,
        proxyCapability,
        pkiSource: new OpenBaoEgressPkiSource({
          origin: runtime.openbao.origin,
          mount: runtime.openbao.pki_mount,
          role: runtime.openbao.pki_role,
          identity,
        }),
        envoyProcess: createNodeCogsEnvoyProcessPort({
          executablePath: runtime.paths.envoy_executable,
          startupTimeoutMs: 5000,
          closeTimeoutMs: runtime.lifecycle.shutdown_timeout_seconds * 1000,
        }),
        randomSecret: seams.randomSecret,
        onReplacementRequired: async () => lifecycle?.dependencyLost("egressRuntime"),
        nowMs: seams.now,
        timers: Object.freeze({ setTimeout, clearTimeout }),
        signal,
        policyAuthorizer: POLICY,
        revocationPollIntervalMs: runtime.egress.revocation_poll_seconds * 1000,
      });
    });

    lifecycle = seams.createLifecycle({
      launchDocument: launch,
      telemetry,
      shutdownTimeoutMs: runtime.lifecycle.shutdown_timeout_seconds * 1000,
      recycleAfterMs: runtime.lifecycle.maximum_session_seconds * 1000,
      dependencies: Object.freeze([
        dependency(
          "sessionStorage",
          async () => {
            storage = await seams.prepareStorage(runtime);
          },
          async () => undefined,
          () => storage !== undefined,
        ),
        dependency(
          "ssh",
          async (signal) => {
            ssh = seams.createSsh({
              config: {
                endpoint: launch.sandbox.ssh_endpoint,
                username: "root",
                hostKeySha256: launch.sandbox.ssh_host_key,
                clientKeyPath: launch.sandbox.client_key_path,
                shutdownTimeoutMs: runtime.lifecycle.shutdown_timeout_seconds * 1000,
              },
              telemetry,
              onLost: () => lifecycle?.dependencyLost("ssh"),
            });
            await ssh.start(signal);
          },
          async () => ssh?.shutdown(),
          () => ssh?.ready === true,
        ),
        dependency(
          "proxy",
          async () => validateProxyCapability(proxyCapability),
          async () => undefined,
          () => true,
        ),
        dependency(
          "auth",
          (signal) => probeModelAuthentication(modelStore, launch, signal),
          async () => undefined,
          () => true,
        ),
        dependency(
          "auditWal",
          async () => seams.verifyAuditWal(runtime.paths.audit_wal),
          async () => undefined,
          () => true,
        ),
        dependency(
          "egressRuntime",
          (signal) => egressDependency.start(signal),
          (signal) => egressDependency.shutdown(signal),
          () => egressDependency.ready?.() === true,
          egressDependency.beginClose,
        ),
      ]),
      shutdownOwner: beginCompositeClose,
      onEvent: (event) => {
        if (published && (event.state === "failed" || event.state === "stopped"))
          void close(event.state === "failed" ? "dependency-lost" : "requested").catch(() => undefined);
      },
    });
    await lifecycle.start();
    if (!lifecycle.ready || storage === undefined || ssh === undefined) throw new Error("dependencies unavailable");
    throwIfAborted(startup.signal);
    const activeSsh = ssh;
    const activeStorage = storage;

    const filePorts = createSftpFileToolPorts({
      manager: activeSsh,
      maxReadBytes: launch.limits.max_tool_output_bytes,
      maxWriteBytes: launch.limits.max_tool_output_bytes,
      operationTimeoutMs: launch.limits.tool_timeout_seconds * 1000,
    });
    const bashPort = createSshBashToolPort({
      manager: activeSsh,
      timeoutMs: launch.limits.tool_timeout_seconds * 1000,
      maxResultBytes: Math.min(launch.limits.max_tool_output_bytes, 16 * 1024),
    });
    // Register the actual factory promise before invoking arbitrary startup code;
    // shutdown must retain a late Pi owner before dependency/material release.
    piStartupWork = Promise.resolve().then(() =>
      seams.createPi({
        cwd: "/workspace",
        agentDir: runtime.paths.agent_directory,
        sessionRoot: runtime.paths.session_root,
        launchDocument: launch,
        modelApiKeys: modelStore,
        skillPreparer: createCogsSkillSessionPreparer({
          ssh: activeSsh,
          sharedResolver: activeStorage.shared,
          privateStore: activeStorage.private,
        }),
        signal: startup.signal,
        toolPorts: Object.freeze({ ...filePorts, ...bashPort }),
        emit: (event) => api?.publish(event) ?? true,
        onFatal: () => void close("pi-fatal").catch(() => undefined),
        policyAuthorizer: POLICY,
        telemetry,
        git: Object.freeze({ repositoryId: launch.workspace_id, manager: activeSsh, enableNotes: true }),
      }),
    );
    pi = await piStartupWork;
    throwIfAborted(startup.signal);
    api = seams.createApi({
      lifecycle,
      session: pi,
      history: pi,
      exporter: pi,
      bearerToken: bearer,
      sessionId: launch.session_id,
    });
    const listened = await api.listen(runtime.api.port, runtime.api.listen_host, { signal: startup.signal });
    if (!lifecycle.ready || telemetry.ready !== true) throw new Error("readiness lost");
    published = true;
    return registerCloseOwner(
      Object.freeze({
        get ready() {
          return published && !closeStarted && lifecycle?.ready === true && telemetry?.ready === true;
        },
        apiPort: listened.port,
        closed,
        close,
      }),
      createCloseOwner(async () => {
        void close().catch(() => undefined);
        await joinCloseWork(lifecycle?.closeWork ?? beginCompositeClose());
        if (cleanupUncertain || spontaneousFailure || lifecycle?.state === "failed") throw new ProductionWorkerError();
      }),
    );
  } catch {
    await close("startup-failed").catch(() => undefined);
    throw new ProductionWorkerError();
  }
}

async function closePi(pi: CogsPiSessionPorts | undefined): Promise<void> {
  if (pi === undefined) return;
  let failed = false;
  try {
    const state = await pi.state();
    if (state.runState === "idle" || state.runState === "settled") {
      await pi.prepareShutdown({ requestId: "production-shutdown", correlationId: "production-shutdown" });
    }
  } catch {
    failed = true;
  }
  try {
    // This starts only after state/preparation settled; no timeout authorizes an
    // overlapping dispose. Persistence poison still permits cleanup.
    await pi.dispose();
  } catch {
    failed = true;
  }
  if (failed) throw new ProductionWorkerError();
}

async function probeModelAuthentication(
  store: ModelApiKeySource,
  launch: LaunchConfig,
  signal: AbortSignal,
): Promise<void> {
  let called = false;
  await store.withApiKey(
    {
      userId: launch.user_id,
      provider: launch.model.provider,
      model: launch.model.id,
      credentialHandle: launch.model.credential_handle,
      signal,
    },
    async () => {
      if (called) throw new Error("duplicate key");
      called = true;
    },
  );
  if (!called) throw new Error("missing key");
}

function requireUserScopedHandles(launch: LaunchConfig): void {
  const prefix = `users/${launch.user_id}/`;
  if (!launch.model.credential_handle.startsWith(prefix)) throw new Error("model handle must be user scoped");
  if (launch.sandbox.proxy_auth_handle !== `sessions/${launch.session_id}/proxy`) throw new Error("bad proxy handle");
  for (const integration of launch.integrations) {
    if (integration === null || typeof integration !== "object" || Array.isArray(integration))
      throw new Error("bad integration");
    const auth = (integration as Record<string, unknown>).auth;
    if (auth === null || typeof auth !== "object" || Array.isArray(auth)) throw new Error("bad integration auth");
    const handle = (auth as Record<string, unknown>).secret_handle;
    if (typeof handle !== "string" || !handle.startsWith(prefix))
      throw new Error("integration handle must be user scoped");
  }
}

async function readRuntimeDocument(): Promise<RuntimeConfig> {
  return withTrustedFileBytes(
    trustedOptions(PRODUCTION_RUNTIME_DOCUMENT, 2, 32 * 1024, [0o400, 0o440]),
    async (bytes) => parseRuntimeConfigBytes(bytes),
  );
}

async function readLaunchDocument(runtime: RuntimeConfig): Promise<LaunchConfig> {
  return withTrustedFileBytes(
    trustedOptions(runtime.paths.launch_document, 2, 1024 * 1024, [0o400, 0o440]),
    async (bytes) => {
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      if (text.codePointAt(0) === 0xfeff || !text.endsWith("\n")) throw new Error("bad launch bytes");
      return validateLaunchConfig(JSON.parse(text.slice(0, -1)));
    },
  );
}

async function readSecretFile(kind: SecretKind, path: string): Promise<string> {
  const minimum = kind === "api-bearer" ? 32 : 16;
  const maximum = kind === "api-bearer" ? 4096 : 256;
  return withTrustedFileBytes(trustedOptions(path, minimum, maximum, [0o400]), async (bytes) => {
    const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (Buffer.byteLength(value, "utf8") !== bytes.length || !/^[\x21-\x7e]+$/.test(value))
      throw new Error("bad secret");
    if (kind === "proxy-capability") validateProxyCapability(value);
    return value;
  });
}

function trustedOptions(
  path: string,
  minimumBytes: number,
  maximumBytes: number,
  modes: number[],
): TrustedFileCaptureOptions {
  const uid = effectiveId("uid");
  const gid = effectiveId("gid");
  return Object.freeze({
    path,
    minimumBytes,
    maximumBytes,
    allowedModes: Object.freeze(modes),
    allowedUids: Object.freeze([uid]),
    allowedGids: Object.freeze([gid]),
  });
}

async function verifyPersistentStorage(runtime: RuntimeConfig): Promise<void> {
  for (const path of [dirname(runtime.paths.audit_wal), runtime.paths.agent_directory, runtime.paths.session_root])
    await strictOwnedDirectory(path);
}

async function verifyWalParent(path: string): Promise<void> {
  await strictOwnedDirectory(dirname(path));
}

async function strictOwnedDirectory(path: string): Promise<void> {
  const canonical = resolve(path);
  if (canonical !== path || (await realpath(path)) !== path) throw new Error("bad directory");
  const stat = await lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== effectiveId("uid") ||
    stat.gid !== effectiveId("gid") ||
    (stat.mode & 0o777) !== 0o700
  )
    throw new Error("bad directory");
}

function validateProxyCapability(value: string): void {
  requireProxyCapability(value);
}

function effectiveId(kind: "uid" | "gid"): number {
  const value = kind === "uid" ? process.geteuid?.() : process.getegid?.();
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error("identity unavailable");
  return value as number;
}

function mergeSeams(overrides: Partial<ProductionWorkerSeams> | undefined): ProductionWorkerSeams {
  const merged = { ...DEFAULT_SEAMS, ...(overrides ?? {}) };
  for (const value of Object.values(merged)) if (typeof value !== "function") throw new ProductionWorkerError();
  return Object.freeze(merged);
}

function linkedAbort(parent: AbortSignal | undefined): AbortController & { dispose(): void } {
  const controller = new AbortController() as AbortController & { dispose(): void };
  const abort = () => controller.abort();
  if (parent?.aborted) abort();
  else parent?.addEventListener("abort", abort, { once: true });
  controller.dispose = () => parent?.removeEventListener("abort", abort);
  return controller;
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new Error("aborted");
}
