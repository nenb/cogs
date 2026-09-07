import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { modelAuthFailureCause } from "../auth/model-auth.ts";
import {
  type CloseOwner,
  closeClock,
  closeObservationContext,
  createCloseOwner,
  joinCloseWork,
  observeClose,
  registerCloseOwner,
} from "../launch/close.ts";
import type { LaunchConfig } from "../launch/config.ts";
import { type CogsPolicyAuthorizer, requireCogsPolicyAllow } from "../policy/require-policy.ts";
import { type CogsTelemetry, captureTelemetry } from "../telemetry/instrumentation.ts";
import { type EgressAuditWal, type EgressAuditWalRecord, openEgressAuditWal } from "./audit-wal.ts";
import {
  type CogsEgressCompletion,
  type CogsEgressCompletionQueue,
  createCogsEgressCompletionQueue,
} from "./completion-queue.ts";
import { type CogsEgressPkiMaterial, type CogsEgressPkiSource, egressMaterialFailureCause } from "./egress-material.ts";
import {
  type CogsEnvoyProcessHandle,
  type CogsEnvoyProcessPort,
  failedCogsEnvoyProcessRetirement,
} from "./envoy-process.ts";
import {
  type CogsEnvoyCredentialSource,
  type CogsEnvoyRuntimeConfig,
  envoyRuntimeConfigFailureCause,
  withCogsEnvoyRuntimeConfig,
} from "./envoy-runtime-config.ts";
import { type CogsExtAuthzServer, startCogsExtAuthzServer } from "./ext-authz-server.ts";
import { egressPkiFailureCause } from "./openbao-pki.ts";
import {
  createOpenBaoEgressRevocationBinding,
  getOpenBaoHydratedMaterial,
  normalizeOpenBaoEgressRevocationAuthorityOptions,
  type OpenBaoEgressRevocationBinding,
  type OpenBaoEgressRevocationBindingOptions,
  type OpenBaoEgressRevocationBindingRequest,
} from "./openbao-revocation.ts";
import {
  type CogsEgressTelemetryMode,
  type CogsEgressTelemetrySink,
  createCogsEgressTelemetrySink,
} from "./otlp-telemetry.ts";
import { requireProxyCapability } from "./proxy-capability.ts";
import {
  type CogsEgressRevocationReason,
  type CogsEgressRevocationSource,
  type CogsEgressRevocationTimers,
  type CogsEgressRevocationWatcher,
  createCogsEgressRevocationWatcher,
  failedCogsEgressRevocationRetirement,
} from "./revocation-watcher.ts";
import { type CogsEgressRoutePlan, lowerLaunchEgressRoutePlan } from "./route-policy.ts";
import { failedCogsEgressTmpfsRetirement, withCogsEgressTmpfsMaterial } from "./tmpfs-material-writer.ts";

const walLimits = Object.freeze({ maxBytes: 1024 * 1024, maxRecords: 10_000, maxRecordBytes: 4096 });
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const secret = /^[\x21-\x7e]{16,256}$/;
const digest = /^sha256:[a-f0-9]{64}$/;

export type CogsEgressRuntimeManagerCloseOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;

const abortSignalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get as
  | ((this: AbortSignal) => boolean)
  | undefined;
const eventAdd = EventTarget.prototype.addEventListener;
const eventRemove = EventTarget.prototype.removeEventListener;

export type CogsEgressRuntimeManager = Readonly<{
  ready: boolean;
  listenerPort: number;
  replacementRequired: boolean;
  auditRecords?(limit: number): readonly EgressAuditWalRecord[];
  drainCompletions(limit: number): readonly CogsEgressCompletion[];
  close(options?: CogsEgressRuntimeManagerCloseOptions): Promise<void>;
}>;

type RuntimeMaterialPaths = Readonly<{
  bootstrap: string;
  proxyCertificate: string;
  proxyPrivateKey: string;
  proxyCaCertificate: string;
}>;

type RuntimeManagerPorts = Readonly<{
  openWal(options: {
    path: string;
    maxBytes: number;
    maxRecords: number;
    maxRecordBytes: number;
    nowMs: () => number;
  }): Promise<EgressAuditWal>;
  startAuthz(options: Parameters<typeof startCogsExtAuthzServer>[0]): Promise<CogsExtAuthzServer>;
  withConfig<T>(
    options: Parameters<typeof withCogsEnvoyRuntimeConfig>[0],
    source: CogsEnvoyCredentialSource,
    operation: (config: CogsEnvoyRuntimeConfig) => Promise<T>,
  ): Promise<T>;
  withTmpfs<T>(
    config: CogsEnvoyRuntimeConfig,
    pki: CogsEgressPkiMaterial,
    operation: (paths: RuntimeMaterialPaths) => Promise<T>,
  ): Promise<T>;
  bindOpenBaoRevocation(request: OpenBaoEgressRevocationBindingRequest): Promise<OpenBaoEgressRevocationBinding>;
  getOpenBaoHydratedMaterial: typeof getOpenBaoHydratedMaterial;
}>;

export type CogsEgressRuntimeRevocationConfig =
  | Readonly<{ mode: "openbao"; openbao: OpenBaoEgressRevocationBindingOptions }>
  | Readonly<{
      mode: "injected";
      credentialVersion: string;
      credentialSource: CogsEnvoyCredentialSource;
      revocationSource: CogsEgressRevocationSource;
    }>;

export type CogsEgressRuntimeManagerOptions = Readonly<{
  launch: LaunchConfig;
  walPath: string;
  listenerPort: number;
  maxSessionExpiresAtMs: number;
  completionCapacity: number;
  revocation: CogsEgressRuntimeRevocationConfig;
  telemetry: CogsEgressTelemetryMode;
  workerTelemetry?: CogsTelemetry;
  proxyCapability: string;
  pkiSource: CogsEgressPkiSource;
  envoyProcess: CogsEnvoyProcessPort;
  randomSecret(bytes: number): string;
  onReplacementRequired(reason: CogsEgressRevocationReason, signal: AbortSignal): Promise<void>;
  nowMs(): number;
  timers: CogsEgressRevocationTimers;
  signal?: AbortSignal;
  policyAuthorizer?: CogsPolicyAuthorizer;
  revocationPollIntervalMs?: number;
  revocationMinPkiRemainingMs?: number;
  operationTimeoutMs?: number;
  ports?: Partial<RuntimeManagerPorts>;
}>;

export class CogsEgressRuntimeManagerError extends Error {
  public readonly code = "COGS_EGRESS_RUNTIME_MANAGER_FAILED";
  public constructor() {
    super("egress runtime manager unavailable");
    this.name = "CogsEgressRuntimeManagerError";
  }
}

const failedManagerRetirements = new WeakMap<CogsEgressRuntimeManagerError, Promise<void>>();

/** Trusted startup-owner seam; undefined means no manager work was acquired. */
export function failedCogsEgressRuntimeManagerRetirement(error: unknown): Promise<void> | undefined {
  return error instanceof CogsEgressRuntimeManagerError ? failedManagerRetirements.get(error) : undefined;
}

export function aggregateCogsEgressRoutePlanRevision(routePlan: CogsEgressRoutePlan): string {
  try {
    if (!routePlan || typeof routePlan !== "object" || Array.isArray(routePlan) || !Object.isFrozen(routePlan))
      throw new Error("bad plan");
    const integrations = routePlan.integrations;
    if (
      !Object.isFrozen(integrations) ||
      !Array.isArray(integrations) ||
      integrations.length < 1 ||
      integrations.length > 16
    )
      throw new Error("bad plan");
    if (!Number.isSafeInteger(routePlan.routeCount) || routePlan.routeCount < 1) throw new Error("bad plan");
    const ids = new Set<string>();
    const pairs = integrations
      .map((integration) => {
        if (!Object.isFrozen(integration) || !opaque.test(integration.id)) throw new Error("bad revision");
        if (ids.has(integration.id) || !digest.test(integration.presetRevision)) throw new Error("bad revision");
        ids.add(integration.id);
        return Object.freeze([integration.id, integration.presetRevision] as const);
      })
      .sort(([left], [right]) => left.localeCompare(right));
    return `sha256:${createHash("sha256").update(JSON.stringify(pairs)).digest("hex")}`;
  } catch {
    throw new CogsEgressRuntimeManagerError();
  }
}

export async function startCogsEgressRuntimeManager(
  options: CogsEgressRuntimeManagerOptions,
): Promise<CogsEgressRuntimeManager> {
  const manager = new RuntimeManager(capture(options));
  try {
    await manager.start();
    return manager.handle();
  } catch {
    const observation = manager.close();
    const failure = new CogsEgressRuntimeManagerError();
    failedManagerRetirements.set(failure, manager.failedStartupRetirement());
    await observation.catch(() => undefined);
    throw failure;
  }
}

type Captured = Readonly<
  Required<Omit<CogsEgressRuntimeManagerOptions, "signal" | "ports" | "policyAuthorizer">> & {
    signal?: AbortSignal;
    policyAuthorizer?: CogsPolicyAuthorizer;
    ports: RuntimeManagerPorts;
  }
>;

class RuntimeManager {
  private routePlan!: CogsEgressRoutePlan;
  private wal: EgressAuditWal | undefined;
  private queue: CogsEgressCompletionQueue | undefined;
  private telemetry: CogsEgressTelemetrySink | undefined;
  private authz: CogsExtAuthzServer | undefined;
  private authzClose: CloseOwner | undefined;
  private processClose: CloseOwner | undefined;
  private process: CogsEnvoyProcessHandle | undefined;
  private watcher: CogsEgressRevocationWatcher | undefined;
  private internalAuthzToken = "";
  private proxyCapability = "";
  private readyState = false;
  private closing = false;
  private replacement = false;
  private release: (() => void) | undefined;
  private openBaoRelease: (() => void) | undefined;
  private scopePromise: Promise<void> | undefined;
  private readonly beginClose = createCloseOwner(
    () => this.closeOnce(),
    () => {
      this.closing = true;
      this.readyState = false;
    },
  );
  private readonly finalCompletions: CogsEgressCompletion[] = [];
  private readyResolve!: () => void;
  private readyReject!: (error: unknown) => void;
  private readonly startupRetirement: Promise<void>;
  private resolveStartupRetirement!: () => void;
  private published = false;
  private scopeEnded = false;

  public constructor(private readonly options: Captured) {
    this.startupRetirement = new Promise<void>((resolve) => {
      this.resolveStartupRetirement = resolve;
    });
  }

  public async start(): Promise<void> {
    const ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.routePlan = lowerLaunchEgressRoutePlan(this.options.launch);
    const presetRevision = aggregateCogsEgressRoutePlanRevision(this.routePlan);
    this.telemetry = createCogsEgressTelemetrySink(this.options.telemetry);
    this.wal = await this.options.ports.openWal({
      path: this.options.walPath,
      ...walLimits,
      nowMs: this.options.nowMs,
    });
    this.queue = createCogsEgressCompletionQueue(this.wal, {
      capacity: this.options.completionCapacity,
      nowMs: this.options.nowMs,
      telemetry: this.telemetry,
      ...(this.options.workerTelemetry === undefined ? {} : { workerTelemetry: this.options.workerTelemetry }),
    });
    this.internalAuthzToken = validSecret(this.options.randomSecret(32));
    this.proxyCapability = requireProxyCapability(this.options.proxyCapability);
    requireSecretPolicy(
      this.options.launch.user_id,
      this.options.launch.session_id,
      "proxy_capability",
      this.options.policyAuthorizer,
    );
    requireSecretPolicy(
      this.options.launch.user_id,
      this.options.launch.session_id,
      "proxy_leaf_key",
      this.options.policyAuthorizer,
    );
    this.authz = await this.options.ports.startAuthz({
      userId: validOpaque(this.options.launch.user_id),
      sessionId: validOpaque(this.options.launch.session_id),
      internalAuthzToken: this.internalAuthzToken,
      proxyCapability: this.proxyCapability,
      routePlan: this.routePlan,
      wal: this.wal,
      ...(this.options.workerTelemetry === undefined ? {} : { workerTelemetry: this.options.workerTelemetry }),
      nowMs: this.options.nowMs,
      ...(this.options.policyAuthorizer === undefined ? {} : { policyAuthorizer: this.options.policyAuthorizer }),
    });
    this.scopePromise = this.runScoped(presetRevision);
    void this.scopePromise.then(
      () => {
        this.scopeEnded = true;
        this.readyState = false;
        if (this.published && !this.closing) void this.failClosed();
        else if (!this.published) this.readyReject(new Error("scope ended"));
      },
      (error) => {
        this.scopeEnded = true;
        this.readyState = false;
        if (this.published) void this.failClosed();
        else this.readyReject(error);
      },
    );
    let readinessTimer: unknown;
    try {
      readinessTimer = this.options.timers.setTimeout(
        () => this.readyReject(new Error("startup observation deadline")),
        Math.min(60_000, this.options.operationTimeoutMs * 4),
      );
      await ready;
    } finally {
      if (readinessTimer !== undefined) this.options.timers.clearTimeout(readinessTimer);
    }
    this.published = true;
    if (this.scopeEnded && !this.closing) {
      this.readyState = false;
      void this.failClosed();
      throw new Error("scope ended before publication");
    }
  }

  public handle(): CogsEgressRuntimeManager {
    const manager = this;
    return registerCloseOwner(
      Object.freeze({
        get ready() {
          return manager.isReady();
        },
        get listenerPort() {
          return manager.options.listenerPort;
        },
        get replacementRequired() {
          return manager.replacement;
        },
        auditRecords: (limit) => manager.auditRecords(limit),
        drainCompletions: (limit) => manager.drainCompletions(limit),
        close: (options?: CogsEgressRuntimeManagerCloseOptions) => manager.close(options),
      }),
      this.beginClose,
    );
  }

  private async runScoped(presetRevision: string): Promise<void> {
    const hosts = Object.freeze(
      [...new Set(this.routePlan.integrations.flatMap((i) => i.routes.map((r) => r.host)))].sort(),
    );
    await this.options.pkiSource.withPkiMaterial(
      {
        sessionId: this.options.launch.session_id,
        hosts,
        maxSessionExpiresAtMs: this.options.maxSessionExpiresAtMs,
        ...(this.options.signal === undefined ? {} : { signal: this.options.signal }),
      },
      async (pki) => {
        if (this.closing) throw new Error("startup closed");
        const binding = await this.resolveRevocationBinding(presetRevision, pki);
        if (this.closing) throw new Error("startup closed");
        return this.options.ports.withConfig(
          {
            userId: this.options.launch.user_id,
            sessionId: this.options.launch.session_id,
            listenerPort: this.options.listenerPort,
            routePlan: this.routePlan,
            authzTarget: this.authz?.target ?? "",
            internalAuthzToken: this.internalAuthzToken,
            ...(this.options.policyAuthorizer === undefined ? {} : { policyAuthorizer: this.options.policyAuthorizer }),
          },
          binding.credentialSource,
          async (config) => {
            if (this.closing) throw new Error("startup closed");
            return this.withMaterial(config, pki, presetRevision, binding);
          },
        );
      },
    );
  }

  private async resolveRevocationBinding(
    presetRevision: string,
    pki: CogsEgressPkiMaterial,
  ): Promise<OpenBaoEgressRevocationBinding> {
    const revocation = this.options.revocation;
    if (revocation.mode === "injected") {
      return validBinding({
        source: revocation.revocationSource,
        credentialSource: revocation.credentialSource,
        credentialVersion: revocation.credentialVersion,
      });
    }
    const binding = validBinding(
      await this.options.ports.bindOpenBaoRevocation({
        ...revocation.openbao,
        routePlan: this.routePlan,
        userId: this.options.launch.user_id,
        presetRevision,
        pkiExpiresAtMs: pki.expiresAtMs,
        ...(this.options.signal === undefined ? {} : { signal: this.options.signal }),
      }),
      true,
    );
    const hydrated = this.options.ports.getOpenBaoHydratedMaterial(binding);
    this.openBaoRelease = hydrated.release;
    if (
      hydrated.manifest.baseline.presetRevision !== presetRevision ||
      hydrated.manifest.baseline.credentialVersion !== binding.credentialVersion ||
      hydrated.manifest.baseline.revoked ||
      hydrated.manifest.baseline.pkiExpiresAtMs !== pki.expiresAtMs
    )
      throw new Error("hydrated baseline mismatch");
    return binding;
  }

  private async withMaterial(
    config: CogsEnvoyRuntimeConfig,
    pki: CogsEgressPkiMaterial,
    presetRevision: string,
    binding: OpenBaoEgressRevocationBinding,
  ): Promise<void> {
    await this.options.ports.withTmpfs(config, pki, async (paths) => {
      try {
        if (this.closing) throw new Error("startup closed");
        try {
          this.watcher = await createCogsEgressRevocationWatcher(binding.source, this.actions(), {
            baseline: Object.freeze({
              presetRevision,
              credentialVersion: validOpaque(binding.credentialVersion),
              revoked: false,
              pkiExpiresAtMs: pki.expiresAtMs,
            }),
            pollIntervalMs: this.options.revocationPollIntervalMs,
            minPkiRemainingMs: this.options.revocationMinPkiRemainingMs,
            operationTimeoutMs: this.options.operationTimeoutMs,
            nowMs: this.options.nowMs,
            timers: this.options.timers,
            ...(this.options.signal === undefined ? {} : { signal: this.options.signal }),
          });
        } catch (error) {
          this.readyReject(error);
          await failedCogsEgressRevocationRetirement(error);
          throw error;
        }
        if (this.closing) throw new Error("startup closed");
        try {
          this.process = await this.options.envoyProcess.start({
            bootstrapPath: paths.bootstrap,
            listenerPort: this.options.listenerPort,
            ...(this.options.signal === undefined ? {} : { signal: this.options.signal }),
            onCompletionLine: (line) => this.queue?.onCompletionLine(line) ?? Promise.reject(new Error("closed")),
          });
        } catch (error) {
          this.readyReject(error);
          await failedCogsEnvoyProcessRetirement(error);
          throw error;
        }
        if (this.closing || !this.dependenciesReady()) throw new Error("dependency unavailable");
        this.readyState = true;
        this.readyResolve();
        await new Promise<void>((resolve) => {
          this.release = resolve;
        });
      } catch (error) {
        this.readyState = false;
        this.closing = true;
        // Do not return through tmpfs/config/PKI lexical finalizers until every
        // post-acquisition consumer has actually retired. Unknown process/authz
        // retirement intentionally keeps this callback and material owned.
        const [watcherRetired, authzRetired, processRetired] = await Promise.all([
          this.closeWatcher(),
          settle(this.closeAuthz()),
          settle(this.closeProcess()),
        ]);
        void watcherRetired;
        if (!authzRetired || !processRetired) await new Promise<never>(() => undefined);
        throw error;
      }
    });
  }

  private actions() {
    return Object.freeze({
      denyNew: async (_reason: CogsEgressRevocationReason, signal: AbortSignal) => {
        this.readyState = false;
        void signal;
        await this.closeAuthz();
      },
      drain: async (_reason: CogsEgressRevocationReason, signal: AbortSignal) => {
        void signal;
        await this.closeProcess();
        this.captureFinalCompletions();
      },
      replace: async (reason: CogsEgressRevocationReason, signal: AbortSignal) => {
        // This is a sticky request to the generation owner, never permission to
        // release material or start a replacement. Actual manager retirement
        // controls the lexical material scope.
        this.replacement = true;
        await this.withTimeout((inner) => this.options.onReplacementRequired(reason, inner), signal);
      },
    });
  }

  private isReady(): boolean {
    if (!this.readyState || this.closing || this.replacement) return false;
    if (this.dependenciesReady()) return true;
    this.readyState = false;
    void this.failClosed();
    return false;
  }

  private dependenciesReady(): boolean {
    try {
      return Boolean(
        this.wal?.ready && this.queue?.ready && this.authz?.ready && this.process?.ready && this.watcher?.ready,
      );
    } catch {
      return false;
    }
  }

  private auditRecords(limit: number): readonly EgressAuditWalRecord[] {
    try {
      const count = integer(limit, 1, 64);
      if (!this.isReady() || !this.wal?.ready) throw new Error("not ready");
      return Object.freeze(this.wal.records.slice(0, count));
    } catch {
      throw new CogsEgressRuntimeManagerError();
    }
  }

  private drainCompletions(limit: number): readonly CogsEgressCompletion[] {
    try {
      const count = integer(limit, 1, this.options.completionCapacity);
      if (this.queue && this.isReady()) return this.queue.drain(count);
      return Object.freeze(this.finalCompletions.splice(0, count));
    } catch {
      throw new CogsEgressRuntimeManagerError();
    }
  }

  public close(options?: CogsEgressRuntimeManagerCloseOptions): Promise<void> {
    const context = validCloseOptions(options);
    const clock = {
      now: closeClock.now,
      setTimer: (ms: number, callback: () => void) => {
        const timer = this.options.timers.setTimeout(callback, ms);
        return { cancel: () => this.options.timers.clearTimeout(timer) };
      },
    };
    const observation = closeObservationContext(context, this.options.operationTimeoutMs, clock);
    return observeClose(this.beginClose(), observation, clock).catch(() => {
      throw new CogsEgressRuntimeManagerError();
    });
  }

  public failedStartupRetirement(): Promise<void> {
    this.beginClose();
    return this.startupRetirement;
  }

  private async failClosed(): Promise<void> {
    await this.close().catch(() => undefined);
  }

  private async closeOnce(): Promise<void> {
    // Independent denial/termination starts together: a hung watcher must not
    // prevent authz shutdown or Envoy TERM/KILL. These are actual promises, not
    // timeout wrappers.
    const [watcherOutcome, authzOutcome, processOutcome] = await Promise.all([
      this.closeWatcher(),
      settle(this.closeAuthz()),
      settle(this.closeProcess()),
    ]);
    if (!authzOutcome || !processOutcome) throw new CogsEgressRuntimeManagerError();

    let failed = !watcherOutcome;
    let retirementCertain = true;
    let queueRetired = false;
    try {
      await this.closeQueue();
      queueRetired = true;
    } catch {
      failed = true;
      retirementCertain = false;
    }
    try {
      await this.closeTelemetry();
    } catch {
      failed = true;
      retirementCertain = false;
    }
    try {
      if (!(await this.releaseScope())) failed = true;
    } catch {
      failed = true;
      retirementCertain = false;
    }
    // WAL release requires both authz and completion producers to be retired.
    if (queueRetired) {
      try {
        await this.closeWal();
      } catch {
        failed = true;
        retirementCertain = false;
      }
    } else {
      failed = true;
      retirementCertain = false;
    }
    this.internalAuthzToken = "";
    this.proxyCapability = "";
    if (retirementCertain) this.resolveStartupRetirement();
    if (failed) throw new CogsEgressRuntimeManagerError();
  }

  private async closeWatcher(): Promise<boolean> {
    const watcher = this.watcher;
    if (!watcher) return true;
    let observed = true;
    const observation = watcher.close().catch(() => {
      observed = false;
    });
    // A bounded close rejection is not retirement. Keep manager custody until
    // every registered source/action actually settles.
    await Promise.all([observation, watcher.retirement()]);
    if (this.watcher === watcher) this.watcher = undefined;
    return observed;
  }

  private async closeAuthz(): Promise<void> {
    const authz = this.authz;
    if (authz) {
      this.authzClose ??= createCloseOwner(() => authz.close());
      await joinCloseWork(this.authzClose());
    }
    if (this.authz === authz) this.authz = undefined;
  }

  private async closeProcess(): Promise<void> {
    const process = this.process;
    if (process) {
      this.processClose ??= createCloseOwner(() => process.close());
      await joinCloseWork(this.processClose());
    }
    if (this.process === process) this.process = undefined;
  }

  private async closeQueue(): Promise<void> {
    this.captureFinalCompletions();
    const queue = this.queue;
    if (queue) await queue.close();
    if (this.queue === queue) this.queue = undefined;
  }

  private async closeTelemetry(): Promise<void> {
    const telemetry = this.telemetry;
    if (telemetry) await telemetry.close(new AbortController().signal);
    if (this.telemetry === telemetry) this.telemetry = undefined;
  }

  private async releaseScope(): Promise<boolean> {
    const release = this.release;
    release?.();
    if (this.release === release) this.release = undefined;
    let failure: unknown;
    try {
      if (this.scopePromise) await this.scopePromise;
    } catch (error) {
      failure = error;
      const tmpfsRetirement = nestedTmpfsRetirement(error);
      if (tmpfsRetirement !== undefined) await tmpfsRetirement;
    }
    const materialRelease = this.openBaoRelease;
    materialRelease?.();
    if (this.openBaoRelease === materialRelease) this.openBaoRelease = undefined;
    return failure === undefined;
  }

  private async closeWal(): Promise<void> {
    const wal = this.wal;
    if (wal) await wal.close();
    if (this.wal === wal) this.wal = undefined;
  }

  private captureFinalCompletions(): void {
    if (!this.queue || this.finalCompletions.length >= this.options.completionCapacity) return;
    const room = this.options.completionCapacity - this.finalCompletions.length;
    if (room > 0) this.finalCompletions.push(...this.queue.drain(room));
  }

  private async withTimeout<T>(
    work: (signal: AbortSignal) => Promise<T>,
    parent?: AbortSignal,
    deadlineAt?: number,
  ): Promise<T> {
    const controller = new AbortController();
    const relay = () => controller.abort();
    let timer: unknown;
    let cancelled = false;
    let workPromise: Promise<T> | undefined;
    const remaining =
      deadlineAt === undefined
        ? this.options.operationTimeoutMs
        : Math.min(this.options.operationTimeoutMs, deadlineAt - Date.now());
    if (!Number.isSafeInteger(remaining) || remaining < 1) throw new Error("timeout");
    try {
      if (parent) eventAdd.call(parent, "abort", relay, { once: true });
      if (aborted(parent)) controller.abort();
      timer = this.options.timers.setTimeout(() => {
        cancelled = true;
        controller.abort();
      }, remaining);
      if (aborted(controller.signal)) throw new Error("aborted");
      workPromise = work(controller.signal);
      const value = await workPromise;
      if (cancelled || aborted(parent) || aborted(controller.signal)) throw new Error("timeout");
      return value;
    } finally {
      if (workPromise && (cancelled || aborted(controller.signal))) await workPromise.catch(() => undefined);
      if (parent) eventRemove.call(parent, "abort", relay);
      if (timer !== undefined) this.options.timers.clearTimeout(timer);
    }
  }
}

function nestedTmpfsRetirement(error: unknown): Promise<void> | undefined {
  const seen = new Set<object>();
  let current = error;
  // At most sixteen credentialed integrations add two wrappers each; leave
  // bounded headroom for PKI/config and future fixed wrappers.
  for (let depth = 0; depth < 64 && typeof current === "object" && current !== null; depth += 1) {
    if (seen.has(current)) return undefined;
    seen.add(current);
    const retirement = failedCogsEgressTmpfsRetirement(current);
    if (retirement !== undefined) return retirement;
    current =
      egressPkiFailureCause(current) ??
      envoyRuntimeConfigFailureCause(current) ??
      egressMaterialFailureCause(current) ??
      modelAuthFailureCause(current);
  }
  return undefined;
}

async function settle(work: Promise<void>): Promise<boolean> {
  try {
    await work;
    return true;
  } catch {
    return false;
  }
}

function validCloseOptions(options?: CogsEgressRuntimeManagerCloseOptions): CogsEgressRuntimeManagerCloseOptions {
  if (options === undefined) return Object.freeze({});
  if (!plain(options as Record<string, unknown>)) throw new CogsEgressRuntimeManagerError();
  const descriptors = Object.getOwnPropertyDescriptors(options);
  try {
    exactShape(options as Record<string, unknown>, [], ["deadlineAt", "signal"]);
  } catch {
    throw new CogsEgressRuntimeManagerError();
  }
  const signal = descriptors.signal?.value;
  const deadlineAt = descriptors.deadlineAt?.value;
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new CogsEgressRuntimeManagerError();
  if (deadlineAt !== undefined && (!Number.isSafeInteger(deadlineAt) || deadlineAt > Date.now() + 60_000))
    throw new CogsEgressRuntimeManagerError();
  return Object.freeze({
    ...(signal === undefined ? {} : { signal }),
    ...(deadlineAt === undefined ? {} : { deadlineAt }),
  });
}

function aborted(signal: AbortSignal | undefined): boolean {
  if (!signal) return false;
  try {
    return abortSignalAborted?.call(signal) === true;
  } catch {
    return true;
  }
}

function capture(options: CogsEgressRuntimeManagerOptions): Captured {
  try {
    validateRequiredPorts(options);
    if (aborted(options.signal)) throw new Error("aborted");
    return Object.freeze({
      ...options,
      walPath: validPath(options.walPath),
      listenerPort: integer(options.listenerPort, 1, 65_535),
      maxSessionExpiresAtMs: integer(options.maxSessionExpiresAtMs, 1, Number.MAX_SAFE_INTEGER),
      completionCapacity: integer(options.completionCapacity, 1, 1024),
      revocation: validRevocation(options.revocation),
      proxyCapability: requireProxyCapability(options.proxyCapability),
      workerTelemetry: captureTelemetry(options.workerTelemetry),
      revocationPollIntervalMs: integer(options.revocationPollIntervalMs ?? 1000, 50, 60_000),
      revocationMinPkiRemainingMs: integer(options.revocationMinPkiRemainingMs ?? 60_000, 1000, 3_600_000),
      operationTimeoutMs: integer(options.operationTimeoutMs ?? 1000, 50, 5000),
      ...(options.policyAuthorizer === undefined
        ? {}
        : { policyAuthorizer: validPolicyAuthorizer(options.policyAuthorizer) }),
      ports: ports(options.ports),
    });
  } catch {
    throw new CogsEgressRuntimeManagerError();
  }
}

function requireSecretPolicy(
  userId: string,
  sessionId: string,
  secretClass: "proxy_capability" | "proxy_leaf_key",
  authorizer: CogsPolicyAuthorizer | undefined,
): void {
  requireCogsPolicyAllow(
    {
      version: "cogs.policy/v1alpha1",
      action: "secret.use",
      user: userId,
      session: sessionId,
      resource: secretClass,
      attributes: { secret_class: secretClass },
    },
    authorizer,
  );
}

function validPolicyAuthorizer(value: unknown): CogsPolicyAuthorizer {
  try {
    if (typeof value !== "function" || !Object.isFrozen(value)) throw new Error("bad policy authorizer");
    return value as CogsPolicyAuthorizer;
  } catch {
    throw new Error("bad policy authorizer");
  }
}

function validOpaque(value: string): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
  return value;
}
function validSecret(value: string): string {
  if (typeof value !== "string" || !secret.test(value)) throw new Error("bad secret");
  return value;
}
function validPath(value: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || value.includes("\0"))
    throw new Error("bad path");
  return value;
}
function integer(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error("bad integer");
  return value;
}

function validRevocation(value: CogsEgressRuntimeRevocationConfig): CogsEgressRuntimeRevocationConfig {
  if (!plain(value)) throw new Error("bad revocation");
  if (value.mode === "injected") {
    exactShape(value, ["credentialSource", "credentialVersion", "mode", "revocationSource"], []);
    const binding = validBinding({
      credentialVersion: value.credentialVersion,
      credentialSource: value.credentialSource,
      source: value.revocationSource,
    });
    return Object.freeze({
      mode: "injected",
      credentialVersion: binding.credentialVersion,
      credentialSource: binding.credentialSource,
      revocationSource: binding.source,
    });
  }
  if (value.mode === "openbao") {
    exactShape(value, ["mode", "openbao"], []);
    return Object.freeze({ mode: "openbao", openbao: normalizeOpenBaoEgressRevocationAuthorityOptions(value.openbao) });
  }
  throw new Error("bad revocation");
}

function validBinding(value: unknown, preserveIdentity = false): OpenBaoEgressRevocationBinding {
  if (!plain(value)) throw new Error("bad binding");
  exactShape(value, ["credentialSource", "credentialVersion", "source"], []);
  const source = value.source as { read?: unknown };
  const credentialSource = value.credentialSource as { withCredential?: unknown };
  if (!source || typeof source !== "object" || typeof source.read !== "function") throw new Error("bad binding");
  if (
    !credentialSource ||
    typeof credentialSource !== "object" ||
    typeof credentialSource.withCredential !== "function"
  )
    throw new Error("bad binding");
  validOpaque(value.credentialVersion as string);
  if (preserveIdentity) {
    if (!Object.isFrozen(value)) throw new Error("mutable binding");
    return value as unknown as OpenBaoEgressRevocationBinding;
  }
  return Object.freeze({
    source: value.source as CogsEgressRevocationSource,
    credentialSource: value.credentialSource as CogsEnvoyCredentialSource,
    credentialVersion: value.credentialVersion as string,
  });
}

function plain(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactShape(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): void {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key === "symbol")) throw new Error("bad keys");
  const names = keys as string[];
  if (required.some((key) => !names.includes(key))) throw new Error("bad keys");
  if (names.some((key) => !required.includes(key) && !optional.includes(key))) throw new Error("bad keys");
  for (const key of names) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error("bad keys");
  }
}

function validateRequiredPorts(options: CogsEgressRuntimeManagerOptions): void {
  if (Object.hasOwn(options, "credentialSource") || Object.hasOwn(options, "revocationSource"))
    throw new Error("bad ports");
  if (!options.pkiSource || typeof options.pkiSource.withPkiMaterial !== "function") throw new Error("bad ports");
  if (!options.envoyProcess || typeof options.envoyProcess.start !== "function") throw new Error("bad ports");
  if (typeof options.randomSecret !== "function" || typeof options.onReplacementRequired !== "function")
    throw new Error("bad ports");
  if (typeof options.nowMs !== "function" || !options.timers || typeof options.timers.setTimeout !== "function")
    throw new Error("bad ports");
  if (typeof options.timers.clearTimeout !== "function") throw new Error("bad ports");
}

function ports(input: Partial<RuntimeManagerPorts> | undefined): RuntimeManagerPorts {
  const own = (key: keyof RuntimeManagerPorts) => input !== undefined && Object.hasOwn(input, key);
  const value = Object.freeze({
    openWal: own("openWal") ? input?.openWal : openEgressAuditWal,
    startAuthz: own("startAuthz") ? input?.startAuthz : startCogsExtAuthzServer,
    withConfig: own("withConfig") ? input?.withConfig : withCogsEnvoyRuntimeConfig,
    withTmpfs: own("withTmpfs") ? input?.withTmpfs : withCogsEgressTmpfsMaterial,
    bindOpenBaoRevocation: own("bindOpenBaoRevocation")
      ? input?.bindOpenBaoRevocation
      : createOpenBaoEgressRevocationBinding,
    getOpenBaoHydratedMaterial: own("getOpenBaoHydratedMaterial")
      ? input?.getOpenBaoHydratedMaterial
      : getOpenBaoHydratedMaterial,
  });
  if (typeof value.openWal !== "function" || typeof value.startAuthz !== "function") throw new Error("bad ports");
  if (typeof value.withConfig !== "function" || typeof value.withTmpfs !== "function") throw new Error("bad ports");
  if (typeof value.bindOpenBaoRevocation !== "function" || typeof value.getOpenBaoHydratedMaterial !== "function")
    throw new Error("bad ports");
  return value as RuntimeManagerPorts;
}
