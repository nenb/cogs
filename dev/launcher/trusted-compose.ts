import { timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { type FileHandle, lstat, mkdir, open, readdir, realpath, rmdir, unlink } from "node:fs/promises";
import { createServer, Socket } from "node:net";
import { dirname, join, relative } from "node:path";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { type ApiEvent, type ApiServer, createApiServer, type ExportPort } from "../../src/api/server.ts";
import { OpenBaoModelApiKeyStore } from "../../src/auth/model-auth.ts";
import { canonicalPresetPolicyRevision } from "../../src/egress/preset-revision.ts";
import { type LaunchConfig, validateLaunchConfig } from "../../src/launch/config.ts";
import { type LaunchDependency, type LaunchDependencyName, LaunchLifecycle } from "../../src/launch/lifecycle.ts";
import { type CogsPiSessionPorts, createAuthenticatedCogsPiSession } from "../../src/pi/session.ts";
import { authorizeCogsPolicyAction } from "../../src/policy/static-policy.ts";
import { createSshBashToolPort } from "../../src/ssh/bash-tool.ts";
import { SshConnectionManager } from "../../src/ssh/connection.ts";
import { createSftpFileToolPorts } from "../../src/ssh/file-tools.ts";
import { createCogsWorkerTelemetrySink } from "../../src/telemetry/worker-telemetry.ts";
import type { LauncherProfile } from "./contract.ts";
import { type ApiTokenHolder, readApiToken, readWorkerDescriptor } from "./control.ts";
import { createDeterministicLauncherStream } from "./deterministic-stream.ts";
import {
  cleanupEnvoyBinary,
  type EnvoyBinaryDescriptor,
  type EnvoyEgressHandle,
  prepareEnvoyBinary,
  startEnvoyEgress,
} from "./envoy-egress.ts";
import { type LocalFixture, startLocalFixtures } from "./fixtures.ts";
import { type OpenBaoHandle, startTrustedOpenBaoCooperative } from "./openbao.ts";
import { type OtlpFixture, startOtlpFixture } from "./otlp-fixture.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";
import {
  materializeTrustedSshControls,
  preflightTrustedEgressRoot,
  type TrustedSshControls,
} from "./trusted-controls.ts";
import { createTrustedSkillInputs, type TrustedSkillInputs } from "./trusted-skills.ts";
import type { WorkerProvisionalRuntime } from "./worker-process.ts";

type DeadlineOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;
type Reservation = Readonly<{ port: number; close(options?: DeadlineOptions): Promise<void> }>;

export type TrustedCompositionSeams = Readonly<{
  readManifest: typeof readManifest;
  readWorkerDescriptor: typeof readWorkerDescriptor;
  preflightEgressRoot: typeof preflightTrustedEgressRoot;
  materializeSshControls: typeof materializeTrustedSshControls;
  createSkillInputs: typeof createTrustedSkillInputs;
  readApiToken: typeof readApiToken;
  startOpenBao: typeof startTrustedOpenBaoCooperative;
  startLocalFixtures: typeof startLocalFixtures;
  startOtlpFixture: typeof startOtlpFixture;
  createTelemetry: typeof createCogsWorkerTelemetrySink;
  prepareEnvoyBinary: typeof prepareEnvoyBinary;
  cleanupEnvoyBinary: typeof cleanupEnvoyBinary;
  startEnvoyEgress: typeof startEnvoyEgress;
  createSshManager: (options: ConstructorParameters<typeof SshConnectionManager>[0]) => SshConnectionManager;
  createLifecycle: (options: ConstructorParameters<typeof LaunchLifecycle>[0]) => LaunchLifecycle;
  createPi: typeof createAuthenticatedCogsPiSession;
  createApi: typeof createApiServer;
  fetch: typeof fetch;
  createNetServer: typeof createServer;
  reserveLoopbackPort: (signal: AbortSignal, deadlineAt: number) => Promise<Reservation>;
  mkdir: typeof mkdir;
  beforeRemoveRuntimePath: (path: string) => Promise<void> | void;
}>;

type Cleanup = Readonly<{ name: CleanupName; close: (options: DeadlineOptions) => Promise<void> | void }>;
type RuntimeRoots = Readonly<{
  agentDir: string;
  sessionRoot: string;
  close(afterPiOwnedCleanup: boolean): Promise<void>;
}>;
type PathMarker = Readonly<{
  path: string;
  handle: FileHandle;
  dev: number;
  ino: number;
  uid: number;
  mode: number;
  nlink: number;
  size: number;
  kind: "dir" | "file";
}>;
type Admitted = Readonly<{
  key: string;
  profile: "insecure-container" | "linux-kvm";
  authority: "functional-only" | "authoritative-local";
}>;

const GENERIC = "launcher trusted composition failed";
const USER = "alice";
const MODEL_PROVIDER = "anthropic";
const MODEL_ID = "claude-sonnet-4-5";
const MODEL_HANDLE = "users/alice/anthropic";
const INTEGRATION_ID = "stage3-localhost";
const INTEGRATION_HANDLE = "users/alice/integrations/stage3-localhost";
const LINUX_KVM_PROXY_PORT = 18080;
const SHARED_PATH = "/shared/skills";
const USER_PATH = "/user/skills";
const EMPTY_BUNDLE_DIGEST = "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c";
const EMPTY_MANIFEST_DIGEST = "sha256:726176e9bdb7524fbe935a0235fcbe5d509bf44592b9571421fc9fd8551ff1c1";
const STARTUP_DEADLINE_MS = 30_000;
const CLEANUP_DEADLINE_MS = 15_000;
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const EVENT_ADD = EventTarget.prototype.addEventListener;
const EVENT_REMOVE = EventTarget.prototype.removeEventListener;
const CLEANUP_ORDER = Object.freeze([
  "api",
  "pi",
  "lifecycle",
  "egress",
  "ssh",
  "envoy-binary",
  "listener-reservation",
  "telemetry",
  "local-fixture",
  "otlp",
  "openbao",
  "api-token",
  "runtime-roots",
  "host-skills",
  "ssh-key",
] as const);
type CleanupName = (typeof CLEANUP_ORDER)[number];
const CLEANUP_NAMES = new Set<string>(CLEANUP_ORDER);
const RAW_EXPORT_TOTAL_BYTES_MAX = 72 * 1024 * 1024;
const RAW_EXPORT_SESSION_JSONL_MAX = 2 * 1024 * 1024;
const EXPORT_DIGEST = /^[a-f0-9]{64}$/u;
const EXPORT_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

const DEFAULT_SEAMS: TrustedCompositionSeams = Object.freeze({
  readManifest,
  readWorkerDescriptor,
  preflightEgressRoot: preflightTrustedEgressRoot,
  materializeSshControls: materializeTrustedSshControls,
  createSkillInputs: createTrustedSkillInputs,
  readApiToken,
  startOpenBao: startTrustedOpenBaoCooperative,
  startLocalFixtures,
  startOtlpFixture,
  createTelemetry: createCogsWorkerTelemetrySink,
  prepareEnvoyBinary,
  cleanupEnvoyBinary,
  startEnvoyEgress,
  createSshManager: (options) => new SshConnectionManager(options),
  createLifecycle: (options) => new LaunchLifecycle(options),
  createPi: createAuthenticatedCogsPiSession,
  createApi: createApiServer,
  fetch,
  createNetServer: createServer,
  reserveLoopbackPort,
  mkdir,
  beforeRemoveRuntimePath: () => undefined,
});

export async function createTrustedWorkerRuntime(
  state: LauncherState,
  callerSignal: AbortSignal,
  seams?: Partial<TrustedCompositionSeams>,
): Promise<WorkerProvisionalRuntime> {
  const s = captureSeams(seams);
  const startup = new AbortController();
  const deadlineAt = Date.now() + STARTUP_DEADLINE_MS;
  let startupTimer: NodeJS.Timeout | undefined;
  let outerCleanup: Promise<void> | undefined;
  let stoppedClose: NodeJS.Immediate | undefined;
  let admitted: Admitted | undefined;
  let pi: CogsPiSessionPorts | undefined;
  let piOwnedCleaned = false;
  let lifecycleStopped = false;
  let cleanupEntered = false;
  let cleanupRequested = false;
  let quiesced = false;
  let releaseQuiesced: (() => void) | undefined;
  const startupQuiesced = new Promise<void>((resolve) => {
    releaseQuiesced = resolve;
  });
  let sessionStorageReady = false;
  let authReady = false;
  let auditWalReady = false;

  const cleanups: Cleanup[] = [];
  const onAbort = () => startup.abort();
  EVENT_ADD.call(callerSignal, "abort", onAbort, { once: true });
  if (aborted(callerSignal)) startup.abort();
  startupTimer = setTimeout(() => startup.abort(), STARTUP_DEADLINE_MS);

  const cleanup = () => {
    cleanupRequested = true;
    startup.abort();
    if (stoppedClose !== undefined) {
      clearImmediate(stoppedClose);
      stoppedClose = undefined;
    }
    outerCleanup ??= (async () => {
      await startupQuiesced;
      await cleanupAll(cleanups, startup);
    })();
    return outerCleanup;
  };

  const markQuiesced = () => {
    if (!quiesced) {
      quiesced = true;
      releaseQuiesced?.();
      releaseQuiesced = undefined;
    }
  };

  const checkAdmission = async (): Promise<Admitted> => {
    checkCooperative(startup.signal, deadlineAt);
    const manifest = await s.readManifest(state);
    checkCooperative(startup.signal, deadlineAt);
    const descriptor = await s.readWorkerDescriptor(state);
    const current = captureAdmission(state, manifest, descriptor);
    if (admitted !== undefined && current.key !== admitted.key) fail();
    checkCooperative(startup.signal, deadlineAt);
    return current;
  };

  try {
    admitted = await checkAdmission();
    await s.preflightEgressRoot(startup.signal);
    await checkAdmission();

    const sshControls = await s.materializeSshControls(state, admitted.profile, admitted.authority, startup.signal);
    registerCleanup(cleanups, { name: "ssh-key", close: () => sshControls.close() });
    requireSshControls(sshControls);
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const skills = await s.createSkillInputs(state, startup.signal);
    registerCleanup(cleanups, { name: "host-skills", close: () => skills.close() });
    requireSkills(skills);
    checkCooperative(startup.signal, deadlineAt);

    const roots = await createRuntimeRoots(state, s);
    registerCleanup(cleanups, { name: "runtime-roots", close: () => roots.close(piOwnedCleaned) });
    sessionStorageReady = true;
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const apiToken = await s.readApiToken(state);
    registerCleanup(cleanups, { name: "api-token", close: () => apiToken.dispose() });
    requireToken(apiToken);
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const openbao = await s.startOpenBao(state, { signal: startup.signal, deadlineAt });
    registerCleanup(cleanups, { name: "openbao", close: (options) => openbao.close(options) });
    requireOpenBao(openbao);
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const fixture = await openbao.integrationCredential.withSecret((credential) =>
      s.startLocalFixtures({
        credential,
        deadlineMs: 1000,
        maxBytes: 16384,
        maxInflight: 8,
        maxRecords: 4096,
        signal: startup.signal,
        deadlineAt,
      }),
    );
    registerCleanup(cleanups, { name: "local-fixture", close: (options) => fixture.close(options) });
    requireFixture(fixture);
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const otlp = await s.startOtlpFixture({ signal: startup.signal, deadlineAt });
    registerCleanup(cleanups, {
      name: "otlp",
      close: async (options) => {
        otlp.reset();
        await otlp.close(options);
      },
    });
    requireOtlp(otlp);
    checkCooperative(startup.signal, deadlineAt);

    const telemetry = s.createTelemetry(
      Object.freeze({
        mode: "otlp" as const,
        tracesEndpoint: otlp.endpoint("traces"),
        metricsEndpoint: otlp.endpoint("metrics"),
        allowLoopbackHttpDevelopment: true,
      }),
    );
    registerCleanup(cleanups, { name: "telemetry", close: () => telemetry.close() });
    requireTelemetry(telemetry);
    checkCooperative(startup.signal, deadlineAt);

    const launch = buildLaunch(state.stateId, sshControls, skills, fixture.snapshot().port);
    const openbaoSnapshot = requireOpenBaoSnapshot(openbao.snapshot());
    const modelStore = new OpenBaoModelApiKeyStore({
      origin: `http://127.0.0.1:${openbaoSnapshot.port}`,
      mount: "model",
      allowLoopbackHttpDevelopment: true,
      identity: Object.freeze({
        withToken: (_requestSignal: AbortSignal, operation: (token: string) => Promise<void>) =>
          openbao.modelToken.withSecret((token) => operation(token)),
      }),
    });

    const ssh = s.createSshManager({
      config: {
        endpoint: sshControls.endpoint,
        username: sshControls.username,
        hostKeySha256: sshControls.hostKeySha256,
        clientKeyPath: sshControls.clientKeyPath,
      },
      onLost: () => void cleanup().catch(() => undefined),
      telemetry,
    });
    registerCleanup(cleanups, { name: "ssh", close: () => ssh.shutdown() });
    await ssh.start(startup.signal);
    requireSshReady(ssh);
    checkCooperative(startup.signal, deadlineAt);

    let binary: EnvoyBinaryDescriptor | undefined;
    let binaryOwned = false;
    binary = await s.prepareEnvoyBinary(state, { signal: startup.signal, deadlineAt });
    binaryOwned = true;
    registerCleanup(cleanups, {
      name: "envoy-binary",
      close: async () => {
        if (binaryOwned && binary !== undefined) {
          await s.cleanupEnvoyBinary(state, binary);
          binaryOwned = false;
        }
      },
    });
    checkCooperative(startup.signal, deadlineAt);

    await modelStore.withApiKey(
      {
        userId: USER,
        provider: MODEL_PROVIDER,
        model: MODEL_ID,
        credentialHandle: MODEL_HANDLE,
        signal: startup.signal,
      },
      (actual) => openbao.modelApiKey.withSecret((expected) => compareSecret(actual, expected)),
    );
    authReady = true;
    checkCooperative(startup.signal, deadlineAt);

    await proveAuditWalAbsent(state);
    await proveSessionRootsEmpty(roots);
    auditWalReady = true;

    const reservation = await (s.reserveLoopbackPort === DEFAULT_SEAMS.reserveLoopbackPort
      ? reserveLoopbackPort(startup.signal, deadlineAt, s.createNetServer)
      : s.reserveLoopbackPort(startup.signal, deadlineAt));
    let reservationOwned = true;
    registerCleanup(cleanups, {
      name: "listener-reservation",
      close: async (options) => {
        if (reservationOwned) {
          await reservation.close(options);
          reservationOwned = false;
        }
      },
    });
    const listenerPort = port(reservation.port);
    await reservation.close({ signal: startup.signal, deadlineAt });
    reservationOwned = false;
    await proveLoopbackPortBindable(listenerPort);
    checkCooperative(startup.signal, deadlineAt);

    const egress = await s.startEnvoyEgress({
      state,
      profile: admitted.profile,
      openbao,
      fixturePort: fixture.snapshot().port,
      launchDocument: launch,
      listenerPort,
      otlpLogsEndpoint: otlp.endpoint("logs"),
      binary,
      signal: startup.signal,
      deadlineAt,
    });
    registerCleanup(cleanups, { name: "egress", close: (options) => egress.close(options) });
    requireEgress(egress, admitted.profile, listenerPort);
    const proxyCapability = ownData(egress, "proxyCapability");
    requireSecretHolder(proxyCapability);
    const withProxySecret = ownFunction(proxyCapability, "withSecret") as (op: (secret: string) => unknown) => unknown;
    withProxySecret((secret) => {
      if (typeof secret !== "string" || secret.length < 16 || secret.length > 256) fail();
    });
    binaryOwned = false;
    checkCooperative(startup.signal, deadlineAt);

    let lifecycle: LaunchLifecycle | undefined;
    const dependencies = nonProducingDependencies(
      ssh,
      egress,
      () => sessionStorageReady,
      () => authReady,
      () => auditWalReady,
    );
    lifecycle = s.createLifecycle({
      launchDocument: launch,
      dependencies,
      telemetry,
      shutdownTimeoutMs: 10_000,
      emergencyHardDeadlineMs: 30_000,
      dependencyHealthIntervalMs: 100,
      onEvent: (event) => {
        if (event.state === "stopped") lifecycleStopped = true;
        if (event.state === "failed" || event.state === "stopped") cleanupRequested = true;
        if ((event.state === "failed" || event.state === "stopped") && stoppedClose === undefined && !cleanupEntered) {
          stoppedClose = setImmediate(() => {
            stoppedClose = undefined;
            void cleanup().catch(() => undefined);
          });
        }
      },
    });
    registerCleanup(cleanups, {
      name: "lifecycle",
      close: () => (lifecycleStopped ? undefined : lifecycle?.requestShutdown("trusted-compose-close")),
    });
    await lifecycle.start();
    if (!lifecycle.ready) fail();
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const disposePi = async () => {
      if (pi === undefined) return;
      const current = pi;
      pi = undefined;
      const result = await current.disposeOwnedRuntime();
      if (result.version !== "cogs.pi-owned-runtime-cleanup/v1alpha1" || result.cleaned !== true) fail();
      piOwnedCleaned = true;
    };
    registerCleanup(cleanups, { name: "pi", close: disposePi });

    const filePorts = createSftpFileToolPorts({ manager: ssh });
    const bashPort = createSshBashToolPort({ manager: ssh });
    const s309Emit = createS309ProofEmitter(fixture, admitted.profile);
    pi = await s.createPi({
      cwd: "/workspace",
      agentDir: roots.agentDir,
      sessionRoot: roots.sessionRoot,
      launchDocument: launch,
      modelApiKeys: modelStore,
      skillPreparer: skills.createPreparer(ssh),
      signal: startup.signal,
      toolPorts: Object.freeze({ ...filePorts, ...bashPort }),
      streamFn: createDeterministicLauncherStream(Object.freeze({ s309FixturePort: fixture.snapshot().port })),
      emit: (event) => api?.publish(s309Emit(event)) ?? true,
      onFatal: () => void cleanup().catch(() => undefined),
      policyAuthorizer: Object.freeze(authorizeCogsPolicyAction),
      telemetry,
      ownedRuntime: Object.freeze({ enabled: true, requireEmptyRoots: true, cleanupDeadlineMs: 10_000 }),
      git: Object.freeze({
        repositoryId: "launcher",
        manager: ssh,
        enableNotes: true,
        checkpoint: Object.freeze({ enabled: false }),
      }),
    });
    await verifyPi(pi, roots.sessionRoot, skills);
    checkCooperative(startup.signal, deadlineAt);
    await checkAdmission();

    const admittedProfile = admitted.profile;
    let api: ApiServer | undefined;
    api = apiToken.withToken((token) =>
      s.createApi({
        lifecycle,
        session: pi as CogsPiSessionPorts,
        history: pi as CogsPiSessionPorts,
        exporter:
          admittedProfile === "linux-kvm"
            ? createRawExportOpeningVerifier(pi as CogsPiSessionPorts, roots.sessionRoot, launch.session_id)
            : (pi as CogsPiSessionPorts),
        bearerToken: token,
        sessionId: `launcher-${state.stateId}`,
      }),
    );
    registerCleanup(cleanups, { name: "api", close: (options) => api?.close(options) });
    requireApi(api);
    const listened = await api.listen(0, "127.0.0.1", { signal: startup.signal, deadlineAt });
    const apiPort = port(listened.port);
    await readyProof(s.fetch, apiPort, apiToken, startup.signal);
    if (!lifecycle.ready) fail();
    await verifyPi(pi, roots.sessionRoot, skills);
    await checkAdmission();
    if (cleanupRequested || outerCleanup !== undefined || aborted(startup.signal) || !lifecycle.ready) fail();

    cleanupStartupTimer(startupTimer, callerSignal, onAbort);
    startupTimer = undefined;
    markQuiesced();
    const closeRuntime = Object.freeze(() => cleanup());
    return Object.freeze({
      apiPort,
      close: closeRuntime,
    });
  } catch {
    cleanupStartupTimer(startupTimer, callerSignal, onAbort);
    startupTimer = undefined;
    markQuiesced();
    await cleanup().catch(() => undefined);
    throw new Error(GENERIC);
  }

  function cleanupStartupTimer(timer: NodeJS.Timeout | undefined, signal: AbortSignal, listener: () => void): void {
    if (timer !== undefined) clearTimeout(timer);
    EVENT_REMOVE.call(signal, "abort", listener);
  }

  async function cleanupAll(items: Cleanup[], controller: AbortController): Promise<void> {
    cleanupEntered = true;
    controller.abort();
    let failed = false;
    const byName = cleanupMap(items);
    for (const name of CLEANUP_ORDER) {
      const item = byName.get(name);
      if (item === undefined) continue;
      try {
        await item.close(Object.freeze({ deadlineAt: Date.now() + CLEANUP_DEADLINE_MS }));
      } catch {
        failed = true;
      }
    }
    if (failed) throw new Error(GENERIC);
  }
}

function registerCleanup(items: Cleanup[], item: Cleanup): void {
  if (!CLEANUP_NAMES.has(item.name) || items.some((existing) => existing.name === item.name)) fail();
  items.push(item);
}

function cleanupMap(items: readonly Cleanup[]): Map<CleanupName, Cleanup> {
  const byName = new Map<CleanupName, Cleanup>();
  for (const item of items) {
    if (!CLEANUP_NAMES.has(item.name) || byName.has(item.name)) fail();
    byName.set(item.name, item);
  }
  return byName;
}

function nonProducingDependencies(
  ssh: SshConnectionManager,
  egress: EnvoyEgressHandle,
  sessionStorageReady: () => boolean,
  authReady: () => boolean,
  auditWalReady: () => boolean,
): readonly LaunchDependency[] {
  const dep = (name: LaunchDependencyName, ready: () => boolean) =>
    Object.freeze({ name, start: async () => undefined, shutdown: async () => undefined, ready });
  return Object.freeze([
    dep("sessionStorage", sessionStorageReady),
    dep("ssh", () => ssh.ready === true),
    dep("proxy", () => egress.snapshot().ready === true),
    dep("auth", authReady),
    dep("auditWal", auditWalReady),
    dep("egressRuntime", () => egress.snapshot().ready === true),
  ]);
}

export function createS309ProofEmitter(fixture: LocalFixture, profile: LauncherProfile): (event: ApiEvent) => ApiEvent {
  let setupSettled = false;
  let scenarioToolEnds = 0;
  let scenarioCorrelation = "";
  return (event) => {
    if (profile !== "linux-kvm") return event;
    if (event.kind === "tool_end" && setupSettled) {
      if (scenarioCorrelation === "") scenarioCorrelation = event.correlation_id;
      if (event.correlation_id === scenarioCorrelation) scenarioToolEnds += 1;
    }
    if (event.kind !== "run_settled") return event;
    if (!setupSettled) {
      setupSettled = true;
      return event;
    }
    if (event.correlation_id !== scenarioCorrelation || scenarioToolEnds !== 3) return event;
    const snap = fixture.snapshot();
    const counts = snap.counts;
    const credential = counts["GET /credential 200"] ?? 0;
    const deniedForwarded = counts["GET /allowed 200"] ?? 0;
    if (
      snap.ready !== true ||
      snap.generation !== 0 ||
      snap.inflight !== 0 ||
      credential !== 1 ||
      deniedForwarded !== 0
    )
      return event;
    const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
    if (total !== 1 || snap.total !== 1) return event;
    return Object.freeze({
      ...event,
      payload: Object.freeze({
        ...event.payload,
        s3_09_proof: Object.freeze({
          version: "cogs.launcher.s3-09-proof/v1alpha1",
          scenario: "s3-09",
          profile: "linux-kvm",
          credential_route_200: true,
          denied_route_absent: true,
          total_exact_expected: true,
          fixture_ready: true,
          fixture_generation_zero: true,
        }),
      }),
    });
  };
}

export function createRawExportOpeningVerifier(
  pi: CogsPiSessionPorts,
  sessionRoot: string,
  sessionId: string,
): ExportPort {
  return Object.freeze({
    createExport: async (input: Parameters<ExportPort["createExport"]>[0]) => {
      try {
        const descriptor = plainRecord(await pi.createExport(input));
        await verifyRawExportOpening(sessionRoot, sessionId, descriptor);
        return Object.freeze({
          ...descriptor,
          raw_export_opening: Object.freeze({
            version: "cogs.launcher.raw-export-opening/v1alpha1",
            opened_with: "pinned-pi-session-manager",
            session_jsonl_openable: true,
            current_session: true,
            content_redacted: true,
          }),
        });
      } catch {
        throw new Error(GENERIC);
      }
    },
  });
}

async function verifyRawExportOpening(sessionRoot: string, sessionId: string, descriptor: Record<string, unknown>) {
  validateRawExportDescriptor(descriptor, sessionId);
  const sessionDir = join(sessionRoot, sessionId);
  const exportsDir = join(sessionDir, "exports");
  const bundle = join(exportsDir, descriptor.bundle as string);
  const file = join(bundle, "session.jsonl");
  await verifyDir(sessionRoot, 0o700);
  await verifyDir(sessionDir, 0o700);
  await verifyDir(exportsDir, 0o700);
  await verifyDir(bundle, 0o700);
  if ((await realpath(sessionRoot)) !== sessionRoot || (await realpath(sessionDir)) !== sessionDir) fail();
  if (
    (await realpath(exportsDir)) !== exportsDir ||
    (await realpath(bundle)) !== bundle ||
    (await realpath(file)) !== file
  )
    fail();
  const before = await lstat(file);
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      before.dev !== opened.dev ||
      before.ino !== opened.ino ||
      !opened.isFile() ||
      opened.isSymbolicLink() ||
      opened.nlink !== 1 ||
      (opened.mode & 0o777) !== 0o600 ||
      opened.size < 1 ||
      opened.size > RAW_EXPORT_SESSION_JSONL_MAX ||
      (typeof process.geteuid === "function" && opened.uid !== process.geteuid())
    )
      fail();
    const manager = SessionManager.open(file, bundle, "/workspace");
    if (
      manager.getSessionId() !== sessionId ||
      manager.getHeader()?.id !== sessionId ||
      manager.getSessionFile() !== file ||
      manager.getEntries().length < 1
    )
      fail();
    const afterPath = await lstat(file);
    const after = await handle.stat();
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      afterPath.dev !== opened.dev ||
      afterPath.ino !== opened.ino ||
      (await realpath(file)) !== file
    )
      fail();
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function validateRawExportDescriptor(descriptor: Record<string, unknown>, sessionId: string): void {
  if (
    Object.keys(descriptor).sort().join("\0") !==
    [
      "anonymized",
      "attachments_included",
      "bundle",
      "created_at",
      "file_count",
      "manifest_sha256",
      "mode",
      "sanitized",
      "sensitive",
      "total_bytes",
      "version",
    ].join("\0")
  )
    fail();
  if (
    descriptor.version !== "cogs.export-descriptor/v1alpha1" ||
    descriptor.bundle !== `cogs-session-${sessionId}` ||
    typeof descriptor.manifest_sha256 !== "string" ||
    !EXPORT_DIGEST.test(descriptor.manifest_sha256) ||
    typeof descriptor.created_at !== "string" ||
    !EXPORT_ISO.test(descriptor.created_at) ||
    descriptor.mode !== "raw" ||
    descriptor.attachments_included !== false ||
    descriptor.file_count !== 6 ||
    !Number.isSafeInteger(descriptor.total_bytes) ||
    (descriptor.total_bytes as number) < 1 ||
    (descriptor.total_bytes as number) > RAW_EXPORT_TOTAL_BYTES_MAX ||
    descriptor.sensitive !== true ||
    descriptor.sanitized !== false ||
    descriptor.anonymized !== false
  )
    fail();
}

async function verifyDir(path: string, mode: number): Promise<void> {
  const stat = await lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== mode ||
    (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
  )
    fail();
}

function buildLaunch(
  stateId: string,
  ssh: TrustedSshControls,
  skills: TrustedSkillInputs,
  fixturePort: number,
): LaunchConfig {
  const integration: Record<string, unknown> = {
    version: "cogs.integration/v1alpha1",
    id: INTEGRATION_ID,
    dns: { mode: "proxy-connect-authority", guest_resolution: false },
    auth: {
      type: "bearer_header",
      header: "Authorization",
      prefix: "Bearer ",
      placeholder: "COGS_PLACEHOLDER_TOKEN",
      secret_handle: INTEGRATION_HANDLE,
    },
    rules: [
      {
        name: "credential",
        host: "localhost",
        port: fixturePort,
        methods: ["GET", "POST"],
        path_patterns: ["/credential"],
        path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
        query_policy: { mode: "deny" },
        redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
        inject_auth: true,
      },
    ],
  };
  integration.preset_revision = canonicalPresetPolicyRevision(integration);
  return validateLaunchConfig({
    version: "cogs.dev/v1alpha1",
    user_id: USER,
    session_id: `launcher-${stateId}`,
    workspace_id: "launcher",
    sandbox: {
      ssh_endpoint: ssh.endpoint,
      ssh_host_key: ssh.hostKeySha256,
      client_key_path: ssh.clientKeyPath,
      proxy_auth_handle: "sessions/launcher/proxy",
    },
    model: { provider: MODEL_PROVIDER, id: MODEL_ID, credential_handle: MODEL_HANDLE },
    skills: {
      shared_revision: skills.sharedRevision,
      shared_path: SHARED_PATH,
      user_revision: skills.userRevision,
      user_path: USER_PATH,
    },
    integrations: [integration],
    limits: { cpu: 1, memory_bytes: 536870912, tool_timeout_seconds: 60, max_tool_output_bytes: 65536 },
  });
}

function effectiveUid(): number {
  if (typeof process.geteuid !== "function") fail();
  const uid = process.geteuid();
  if (!Number.isSafeInteger(uid) || uid < 0) fail();
  return uid;
}

async function createRuntimeRoots(state: LauncherState, seams: TrustedCompositionSeams): Promise<RuntimeRoots> {
  const uid = effectiveUid();
  const root = join(state.sandboxDir, `trusted-compose-${state.stateId}`);
  const sentinel = join(root, ".cogs-trusted-compose-owner");
  const agentDir = join(root, "agent");
  const sessionRoot = join(root, "sessions");
  const made: string[] = [];
  const handles: FileHandle[] = [];
  let ledger: { root: PathMarker; agent: PathMarker; session: PathMarker; sentinel: PathMarker } | undefined;
  try {
    await strictDirectory(state.sandboxDir, uid);
    for (const dir of [root, agentDir, sessionRoot]) {
      await seams.mkdir(dir, { mode: 0o700 });
      made.push(dir);
      await strictDirectory(dir, uid);
      await fsyncDir(dirname(dir));
    }
    const rootHandle = await open(root, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
    const agentHandle = await open(agentDir, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
    const sessionHandle = await open(sessionRoot, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
    handles.push(rootHandle, agentHandle, sessionHandle);
    const sentinelHandle = await open(sentinel, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR, 0o600);
    handles.push(sentinelHandle);
    await sentinelHandle.writeFile(`${state.stateId}\n`);
    await sentinelHandle.sync();
    ledger = {
      root: await markerFrom(root, rootHandle, uid, "dir"),
      agent: await markerFrom(agentDir, agentHandle, uid, "dir"),
      session: await markerFrom(sessionRoot, sessionHandle, uid, "dir"),
      sentinel: await markerFrom(sentinel, sentinelHandle, uid, "file"),
    };
    await requireRuntimeInventory(root, state.stateId, uid, false);
    await fsyncDir(root);
    return Object.freeze({
      agentDir,
      sessionRoot,
      close: async (afterPiOwnedCleanup: boolean) => {
        try {
          await removeRuntimeRoot(root, state.stateId, uid, afterPiOwnedCleanup, ledger, seams);
          await fsyncDir(state.sandboxDir);
        } finally {
          await closeHandles(handles);
        }
      },
    });
  } catch (error) {
    try {
      if (ledger !== undefined) {
        await removeRuntimeRoot(root, state.stateId, uid, false, ledger, seams);
      } else {
        for (const dir of made.reverse()) {
          await strictDirectory(dir, uid);
          if ((await readdir(dir)).length !== 0) fail();
          await rmdir(dir);
          await fsyncDir(dirname(dir));
        }
      }
    } finally {
      await closeHandles(handles);
    }
    throw error;
  }
}

async function proveAuditWalAbsent(state: LauncherState): Promise<void> {
  await strictDirectory(state.dir, effectiveUid());
  await lstat(join(state.dir, "egress-audit.wal")).then(
    () => fail(),
    (error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    },
  );
}

async function proveSessionRootsEmpty(roots: RuntimeRoots): Promise<void> {
  if ((await readdir(roots.agentDir)).length !== 0 || (await readdir(roots.sessionRoot)).length !== 0) fail();
}

async function readyProof(
  fetchImpl: typeof fetch,
  portValue: number,
  token: ApiTokenHolder,
  signal: AbortSignal,
): Promise<void> {
  const response = await token.withToken((bearer) =>
    fetchImpl(`http://127.0.0.1:${portValue}/health/ready`, {
      method: "GET",
      headers: { authorization: `Bearer ${bearer}` },
      redirect: "error",
      signal,
    }),
  );
  try {
    if (
      response.status !== 200 ||
      response.redirected ||
      !/^application\/json(?:\s*;|$)/iu.test(response.headers.get("content-type") ?? "")
    )
      fail();
    const text = await boundedResponseText(response, signal, 128);
    const parsed = JSON.parse(text) as unknown;
    const record = plainRecord(parsed);
    const keys = Object.keys(record).sort();
    if (keys.join(",") !== "closed,ready" || record.ready !== true || record.closed !== false) fail();
  } finally {
    await response.body?.cancel().catch(() => undefined);
  }
}

async function verifyPi(pi: CogsPiSessionPorts, sessionRoot: string, skills: TrustedSkillInputs): Promise<void> {
  const state = plainRecord(await pi.state());
  if (state.runState !== "idle") fail();
  if (pi.activeToolNames().join(",") !== "read,write,edit,bash") fail();
  const file = pi.sessionFile();
  if (typeof file !== "string") fail();
  const rel = relative(sessionRoot, file);
  if (rel.startsWith("..") || rel === "" || rel.startsWith("/")) fail();
  const metadata = plainRecord(pi.skillMetadata());
  const shared = plainRecord(metadata.shared);
  const user = plainRecord(metadata.user);
  if (
    metadata.skillCount !== 0 ||
    !["loaded", "missing", "permission_denied", "oversize", "invalid", "read_error"].includes(
      metadata.agentsStatus as string,
    ) ||
    shared.scope !== "shared" ||
    user.scope !== "user" ||
    shared.revision !== skills.sharedRevision ||
    user.revision !== skills.userRevision ||
    shared.revision !== EMPTY_MANIFEST_DIGEST ||
    user.revision !== EMPTY_BUNDLE_DIGEST ||
    shared.bundleDigest !== EMPTY_BUNDLE_DIGEST ||
    user.bundleDigest !== EMPTY_BUNDLE_DIGEST ||
    shared.guestRoot !== SHARED_PATH ||
    user.guestRoot !== USER_PATH ||
    typeof shared.guestSubtree !== "string" ||
    typeof user.guestSubtree !== "string" ||
    shared.byteCount !== 0 ||
    user.byteCount !== 0 ||
    shared.readOnlyEnforced !== false ||
    user.readOnlyEnforced !== false ||
    shared.fileCount !== 0 ||
    user.fileCount !== 0
  )
    fail();
}

async function reserveLoopbackPort(
  signal: AbortSignal,
  deadlineAt: number,
  createNetServer: typeof createServer = createServer,
): Promise<Reservation> {
  checkCooperative(signal, deadlineAt);
  const server = createNetServer();
  let selected = 0;
  let state: "binding" | "listening" | "closing" | "closed" | "failed" = "binding";
  let cancelled = false;
  let closePromise: Promise<void> | undefined;
  const close = async () => {
    closePromise ??= (async () => {
      if (state === "binding") return;
      if (state === "listening") {
        state = "closing";
        await new Promise<void>((resolve, reject) =>
          server.close((error?: Error & { code?: string }) => {
            if (error !== undefined && error.code !== "ERR_SERVER_NOT_RUNNING") reject(error);
            else resolve();
          }),
        );
      }
      if (selected !== 0) await proveClosed("127.0.0.1", selected);
      state = "closed";
    })();
    await closePromise;
  };
  const onAbort = () => {
    cancelled = true;
    if (state === "listening") void close().catch(() => undefined);
  };
  EVENT_ADD.call(signal, "abort", onAbort, { once: true });
  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        state = "failed";
        reject(error);
      };
      server.once("error", onError);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", onError);
        const address = server.address();
        selected = typeof address === "object" && address !== null ? port(address.port) : 0;
        state = "listening";
        if (cancelled || aborted(signal) || Date.now() >= deadlineAt) void close().catch(() => undefined);
        resolve();
      });
    });
    if (cancelled || aborted(signal) || Date.now() >= deadlineAt) {
      await close();
      fail();
    }
    return Object.freeze({
      port: selected,
      close: async (options = Object.freeze({})) => {
        validateDeadlineOptions(options);
        await close();
      },
    });
  } catch (error) {
    await close();
    throw error;
  } finally {
    EVENT_REMOVE.call(signal, "abort", onAbort);
  }
}

async function proveLoopbackPortBindable(portValue: number): Promise<void> {
  const server = createServer();
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(portValue, "127.0.0.1", () => resolve());
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve())).catch(() => undefined);
  }
}

async function proveClosed(host: string, portValue: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = new Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(GENERIC));
    }, 500);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error(GENERIC));
    });
    socket.once("error", () => {
      clearTimeout(timer);
      resolve();
    });
    socket.connect(portValue, host);
  });
}

async function boundedResponseText(response: Response, signal: AbortSignal, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) fail();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let cancelPromise: Promise<void> | undefined;
  const cancel = () => {
    cancelPromise ??= reader.cancel().then(
      () => undefined,
      () => undefined,
    );
  };
  EVENT_ADD.call(signal, "abort", cancel, { once: true });
  try {
    for (;;) {
      throwIfAborted(signal);
      const item = await reader.read();
      throwIfAborted(signal);
      if (item.done) break;
      total += item.value.byteLength;
      if (total > maxBytes) fail();
      chunks.push(item.value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
  } finally {
    EVENT_REMOVE.call(signal, "abort", cancel);
    if (aborted(signal)) cancel();
    if (cancelPromise !== undefined) await cancelPromise;
    reader.releaseLock();
  }
}

async function removeRuntimeRoot(
  root: string,
  stateId: string,
  uid: number,
  afterPiOwnedCleanup: boolean,
  ledger: { root: PathMarker; agent: PathMarker; session: PathMarker; sentinel: PathMarker } | undefined,
  seams: TrustedCompositionSeams,
): Promise<void> {
  await requireRuntimeInventory(root, stateId, uid, afterPiOwnedCleanup);
  if (ledger !== undefined) await assertMarker(ledger.root);
  const entries = (await readdir(root)).sort();
  if (!afterPiOwnedCleanup) {
    for (const [child, marker] of [
      ["agent", ledger?.agent],
      ["sessions", ledger?.session],
    ] as const) {
      if (!entries.includes(child)) continue;
      const dir = join(root, child);
      await strictDirectory(dir, uid);
      if ((await readdir(dir)).length !== 0) fail();
      if (marker !== undefined) await assertMarker(marker);
      await seams.beforeRemoveRuntimePath(dir);
      if (marker !== undefined) await assertMarker(marker);
      await rmdir(dir);
      await fsyncDir(root);
    }
  }
  const sentinel = join(root, ".cogs-trusted-compose-owner");
  if (ledger !== undefined) await assertSentinel(ledger.sentinel, stateId);
  await seams.beforeRemoveRuntimePath(sentinel);
  if (ledger !== undefined) await assertSentinel(ledger.sentinel, stateId);
  await unlink(sentinel);
  await fsyncDir(root);
  if (ledger !== undefined) await assertMarker(ledger.root);
  await seams.beforeRemoveRuntimePath(root);
  if (ledger !== undefined) await assertMarker(ledger.root);
  await rmdir(root);
}

async function markerFrom(path: string, handle: FileHandle, uid: number, kind: "dir" | "file"): Promise<PathMarker> {
  const stat = await handle.stat();
  const pathStat = await lstat(path);
  if (stat.dev !== pathStat.dev || stat.ino !== pathStat.ino) fail();
  const mode = kind === "dir" ? 0o700 : 0o600;
  if (stat.uid !== uid || (stat.mode & 0o777) !== mode || (kind === "file" && stat.nlink !== 1)) fail();
  if (kind === "dir" ? !stat.isDirectory() : !stat.isFile()) fail();
  return Object.freeze({
    path,
    handle,
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    mode: stat.mode & 0o777,
    nlink: stat.nlink,
    size: stat.size,
    kind,
  });
}

async function assertMarker(marker: PathMarker): Promise<void> {
  const handleStat = await marker.handle.stat();
  const pathStat = await lstat(marker.path);
  for (const stat of [handleStat, pathStat]) {
    if (
      stat.dev !== marker.dev ||
      stat.ino !== marker.ino ||
      stat.uid !== marker.uid ||
      (stat.mode & 0o777) !== marker.mode ||
      (marker.kind === "file" && (stat.nlink !== marker.nlink || stat.size !== marker.size)) ||
      (marker.kind === "dir" ? !stat.isDirectory() : !stat.isFile())
    )
      fail();
  }
}

async function assertSentinel(marker: PathMarker, stateId: string): Promise<void> {
  await assertMarker(marker);
  const expected = Buffer.from(`${stateId}\n`);
  if (marker.size !== expected.length) fail();
  const buffer = Buffer.alloc(expected.length);
  const read = await marker.handle.read(buffer, 0, buffer.length, 0);
  if (read.bytesRead !== buffer.length || !buffer.equals(expected)) fail();
}

async function closeHandles(handles: FileHandle[]): Promise<void> {
  let failed = false;
  for (const handle of handles.reverse()) {
    try {
      await handle.close();
    } catch {
      failed = true;
    }
  }
  if (failed) fail();
}

async function requireRuntimeInventory(
  root: string,
  stateId: string,
  uid: number,
  allowMissingPiDirs: boolean,
): Promise<void> {
  await strictDirectory(root, uid);
  const entries = (await readdir(root)).sort();
  const expected = allowMissingPiDirs
    ? [".cogs-trusted-compose-owner"]
    : [".cogs-trusted-compose-owner", "agent", "sessions"];
  if (entries.join(",") !== expected.join(",")) fail();
  for (const child of ["agent", "sessions"]) {
    if (entries.includes(child)) {
      await strictDirectory(join(root, child), uid);
      if ((await readdir(join(root, child))).length !== 0) fail();
    }
  }
  const sentinel = join(root, ".cogs-trusted-compose-owner");
  await strictFile(sentinel, uid, 0o600);
  const handle = await open(sentinel, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (stat.size !== Buffer.byteLength(`${stateId}\n`)) fail();
    const buffer = Buffer.alloc(stat.size);
    const read = await handle.read(buffer, 0, buffer.length, 0);
    if (read.bytesRead !== buffer.length || buffer.toString("utf8") !== `${stateId}\n`) fail();
  } finally {
    await handle.close();
  }
}

async function strictDirectory(path: string, uid: number): Promise<void> {
  const real = await realpath(path);
  if (real !== path) fail();
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o777) !== 0o700) fail();
}

async function strictFile(path: string, uid: number, mode: number): Promise<void> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== uid || stat.nlink !== 1 || (stat.mode & 0o777) !== mode)
    fail();
}

async function fsyncDir(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function compareSecret(actual: string, expected: string): Promise<void> {
  let a: Buffer | undefined;
  let b: Buffer | undefined;
  try {
    a = Buffer.from(actual, "utf8");
    b = Buffer.from(expected, "utf8");
    if (a.length < 1 || a.length > 4096 || b.length < 1 || b.length > 4096 || a.length !== b.length) fail();
    if (!timingSafeEqual(a, b)) fail();
  } finally {
    a?.fill(0);
    b?.fill(0);
  }
}

function captureAdmission(state: LauncherState, manifest: unknown, descriptor: unknown): Admitted {
  const m = plainRecord(manifest);
  const d = plainRecord(descriptor);
  const owned = plainRecord(m.owned);
  const profile = m.profile;
  const authority = d.authority;
  if (profile !== "insecure-container" && profile !== "linux-kvm") fail();
  if (authority !== authorityFor(profile)) fail();
  if (
    m.phase !== "sandbox-ready" ||
    m.stateId !== state.stateId ||
    m.stateName !== state.name ||
    m.sourceRevision !== state.sourceRevision ||
    d.readiness !== "starting" ||
    d.stage !== "child-bound" ||
    d.stateId !== state.stateId ||
    d.sourceRevision !== state.sourceRevision ||
    d.profile !== profile ||
    typeof d.startupDigest !== "string" ||
    typeof d.parentPidIdentity !== "string" ||
    typeof d.childPidIdentity !== "string"
  )
    fail();
  const fields = [
    m.stateId,
    m.stateName,
    m.sourceRevision,
    profile,
    m.phase,
    owned.sandboxState,
    owned.controlDir,
    owned.lockName,
    Array.isArray(m.ports) ? m.ports.length : -1,
    d.startupDigest,
    d.parentPid,
    d.parentPidIdentity,
    d.childPid,
    d.childPidIdentity,
    authority,
  ];
  if (fields.some((value) => typeof value !== "string" && typeof value !== "number")) fail();
  return Object.freeze({
    key: fields.join("\0"),
    profile,
    authority: authority as "functional-only" | "authoritative-local",
  });
}

function captureSeams(seams?: Partial<TrustedCompositionSeams>): TrustedCompositionSeams {
  try {
    if (seams === undefined) return DEFAULT_SEAMS;
    if (seams === null || typeof seams !== "object" || Array.isArray(seams) || !Object.isFrozen(seams)) fail();
    const out: Record<string, unknown> = { ...DEFAULT_SEAMS };
    const descriptors = Object.getOwnPropertyDescriptors(seams);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string" || !(key in DEFAULT_SEAMS)) fail();
      const descriptor = descriptors[key];
      if (
        !descriptor ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true ||
        typeof descriptor.value !== "function"
      )
        fail();
      out[key] = descriptor.value;
    }
    return Object.freeze(out) as TrustedCompositionSeams;
  } catch {
    throw new Error(GENERIC);
  }
}

function requireApi(value: ApiServer): void {
  requireFrozenPlain(value);
  ownFunction(value, "listen");
  ownFunction(value, "close");
  ownFunction(value, "publish");
}
function requireSshControls(value: TrustedSshControls): void {
  requireFrozenPlain(value);
  if (Object.getOwnPropertyNames(value).sort().join(",") !== "clientKeyPath,close,endpoint,hostKeySha256,username")
    fail();
  const endpoint = ownHiddenData(value, "endpoint");
  const username = ownHiddenData(value, "username");
  const hostKeySha256 = ownHiddenData(value, "hostKeySha256");
  const clientKeyPath = ownHiddenData(value, "clientKeyPath");
  if (typeof ownHiddenData(value, "close") !== "function") fail();
  if (
    typeof endpoint !== "string" ||
    !/^.+:[0-9]+$/u.test(endpoint) ||
    username !== "root" ||
    typeof hostKeySha256 !== "string" ||
    !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(hostKeySha256) ||
    typeof clientKeyPath !== "string" ||
    !clientKeyPath.startsWith("/run/cogs/ssh/launcher-")
  )
    fail();
}
function requireSkills(value: TrustedSkillInputs): void {
  requireFrozenPlain(value);
  const sharedRevision = ownData(value, "sharedRevision");
  const userRevision = ownData(value, "userRevision");
  if (
    typeof sharedRevision !== "string" ||
    typeof userRevision !== "string" ||
    !/^sha256:[a-f0-9]{64}$/u.test(sharedRevision) ||
    !/^sha256:[a-f0-9]{64}$/u.test(userRevision)
  )
    fail();
  ownFunction(value, "createPreparer");
  ownFunction(value, "close");
}
function requireToken(value: ApiTokenHolder): void {
  requireFrozenPlain(value);
  ownFunction(value, "withToken");
  ownFunction(value, "dispose");
}
function requireOpenBao(value: OpenBaoHandle): void {
  requireFrozenPlain(value);
  ownFunction(value, "snapshot");
  ownFunction(value, "close");
  requireSecretHolder(ownData(value, "modelToken"));
  requireSecretHolder(ownData(value, "modelApiKey"));
  requireSecretHolder(ownData(value, "egressToken"));
  requireSecretHolder(ownData(value, "integrationCredential"));
  requireOpenBaoSnapshot(value.snapshot());
}
function requireOpenBaoSnapshot(value: unknown): { port: number } {
  const snap = plainRecord(value);
  const egress = plainRecord(snap.egress);
  const portValue = port(snap.port);
  if (snap.ready !== true || snap.seeded !== "model-kv-egress-pki" || egress.credentialHandle !== INTEGRATION_HANDLE)
    fail();
  return { port: portValue };
}
function requireFixture(value: LocalFixture): void {
  requireFrozenPlain(value);
  ownFunction(value, "snapshot");
  ownFunction(value, "close");
  const snap = plainRecord(value.snapshot());
  if (snap.ready !== true) fail();
  port(snap.port);
}
function requireOtlp(value: OtlpFixture): void {
  requireFrozenPlain(value);
  ownFunction(value, "snapshot");
  ownFunction(value, "endpoint");
  ownFunction(value, "reset");
  ownFunction(value, "close");
  const snap = plainRecord(value.snapshot());
  if (snap.ready !== true) fail();
  port(snap.port);
}
function requireTelemetry(value: ReturnType<typeof createCogsWorkerTelemetrySink>): void {
  requireFrozenPlain(value);
  ownFunction(value, "close");
  ownFunction(value, "snapshot");
  ownFunction(value, "span");
  ownFunction(value, "metric");
}
function requireSecretHolder(value: unknown): asserts value is Record<string, unknown> {
  requireFrozenPlain(value);
  ownFunction(value, "withSecret");
  ownFunction(value, "dispose");
}
function requireSshReady(value: SshConnectionManager): void {
  if (value.ready !== true) fail();
}
function requireEgress(
  value: EnvoyEgressHandle,
  profile: "insecure-container" | "linux-kvm",
  listenerPort: number,
): void {
  requireFrozenPlain(value);
  ownFunction(value, "snapshot");
  ownFunction(value, "close");
  const snap = plainRecord(value.snapshot());
  const authority = plainRecord(snap.authority);
  if (
    snap.ready !== true ||
    snap.profile !== profile ||
    snap.listenerPort !== (profile === "linux-kvm" ? LINUX_KVM_PROXY_PORT : listenerPort) ||
    snap.replacementRequired !== false ||
    authority.user !== USER ||
    authority.modelHandle !== MODEL_HANDLE ||
    authority.egressHandle !== INTEGRATION_HANDLE
  )
    fail();
}
function requireFrozenPlain(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  if (!Object.isFrozen(value)) fail();
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) fail();
}
function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")) fail();
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!("value" in descriptor) || descriptor.enumerable !== true) fail();
    out[key] = descriptor.value;
  }
  return out;
}
function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) fail();
  return descriptor.value;
}
function ownHiddenData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (
    !descriptor ||
    !("value" in descriptor) ||
    descriptor.enumerable !== false ||
    descriptor.writable !== false ||
    descriptor.configurable !== false
  )
    fail();
  return descriptor.value;
}
function ownFunction(value: object, key: string): (...args: never[]) => unknown {
  const item = ownData(value, key);
  if (typeof item !== "function") fail();
  return item as (...args: never[]) => unknown;
}
function authorityFor(profile: string): "functional-only" | "authoritative-local" {
  if (profile === "insecure-container") return "functional-only";
  if (profile === "linux-kvm") return "authoritative-local";
  fail();
}
function port(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 65535) fail();
  return value;
}
function validateDeadlineOptions(options: unknown): asserts options is DeadlineOptions {
  if (
    !options ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.getPrototypeOf(options) !== Object.prototype
  )
    fail();
  const descriptors = Object.getOwnPropertyDescriptors(options);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string" || !["deadlineAt", "signal"].includes(key)))
    fail();
  for (const descriptor of Object.values(descriptors)) {
    if (!("value" in descriptor) || descriptor.enumerable !== true) fail();
  }
  if (descriptors.signal?.value !== undefined && !(descriptors.signal.value instanceof AbortSignal)) fail();
  const deadlineAt = descriptors.deadlineAt?.value;
  if (deadlineAt !== undefined && (!Number.isSafeInteger(deadlineAt) || deadlineAt > Date.now() + 60_000)) fail();
}
function checkCooperative(signal: AbortSignal, deadlineAt: number): void {
  if (aborted(signal) || Date.now() >= deadlineAt) fail();
}
function throwIfAborted(signal: AbortSignal): void {
  if (aborted(signal)) fail();
}
function aborted(signal: AbortSignal | undefined): boolean {
  if (signal === undefined) return false;
  try {
    return (ABORTED_GETTER === undefined ? signal.aborted : ABORTED_GETTER.call(signal)) === true;
  } catch {
    return true;
  }
}
function fail(): never {
  throw new Error(GENERIC);
}
