import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import type { LaunchConfig } from "../launch/config.ts";
import { type EgressAuditWal, openEgressAuditWal } from "./audit-wal.ts";
import {
  type CogsEgressCompletion,
  type CogsEgressCompletionQueue,
  createCogsEgressCompletionQueue,
} from "./completion-queue.ts";
import type { CogsEgressPkiMaterial, CogsEgressPkiSource } from "./egress-material.ts";
import type { CogsEnvoyProcessHandle, CogsEnvoyProcessPort } from "./envoy-process.ts";
import {
  type CogsEnvoyCredentialSource,
  type CogsEnvoyRuntimeConfig,
  withCogsEnvoyRuntimeConfig,
} from "./envoy-runtime-config.ts";
import { type CogsExtAuthzServer, startCogsExtAuthzServer } from "./ext-authz-server.ts";
import {
  createOpenBaoEgressRevocationBinding,
  normalizeOpenBaoEgressRevocationAuthorityOptions,
  type OpenBaoEgressRevocationBinding,
  type OpenBaoEgressRevocationBindingOptions,
  type OpenBaoEgressRevocationBindingRequest,
} from "./openbao-revocation.ts";
import {
  type CogsEgressRevocationReason,
  type CogsEgressRevocationSource,
  type CogsEgressRevocationTimers,
  type CogsEgressRevocationWatcher,
  createCogsEgressRevocationWatcher,
} from "./revocation-watcher.ts";
import { type CogsEgressRoutePlan, lowerLaunchEgressRoutePlan } from "./route-policy.ts";
import { withCogsEgressTmpfsMaterial } from "./tmpfs-material-writer.ts";

const walLimits = Object.freeze({ maxBytes: 1024 * 1024, maxRecords: 10_000, maxRecordBytes: 4096 });
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const secret = /^[\x21-\x7e]{16,256}$/;
const digest = /^sha256:[a-f0-9]{64}$/;

export type CogsEgressRuntimeManager = Readonly<{
  ready: boolean;
  listenerPort: number;
  replacementRequired: boolean;
  drainCompletions(limit: number): readonly CogsEgressCompletion[];
  close(): Promise<void>;
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
  proxyCapability: string;
  pkiSource: CogsEgressPkiSource;
  envoyProcess: CogsEnvoyProcessPort;
  randomSecret(bytes: number): string;
  onReplacementRequired(reason: CogsEgressRevocationReason, signal: AbortSignal): Promise<void>;
  nowMs(): number;
  timers: CogsEgressRevocationTimers;
  signal?: AbortSignal;
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
    await manager.close().catch(() => undefined);
    throw new CogsEgressRuntimeManagerError();
  }
}

type Captured = Readonly<
  Required<Omit<CogsEgressRuntimeManagerOptions, "signal" | "ports">> & {
    signal?: AbortSignal;
    ports: RuntimeManagerPorts;
  }
>;

class RuntimeManager {
  private routePlan!: CogsEgressRoutePlan;
  private wal: EgressAuditWal | undefined;
  private queue: CogsEgressCompletionQueue | undefined;
  private authz: CogsExtAuthzServer | undefined;
  private process: CogsEnvoyProcessHandle | undefined;
  private watcher: CogsEgressRevocationWatcher | undefined;
  private internalAuthzToken = "";
  private proxyCapability = "";
  private readyState = false;
  private closing = false;
  private replacement = false;
  private release: (() => void) | undefined;
  private scopePromise: Promise<void> | undefined;
  private closePromise: Promise<void> | undefined;
  private readonly finalCompletions: CogsEgressCompletion[] = [];
  private readyResolve!: () => void;
  private readyReject!: (error: unknown) => void;
  private published = false;
  private scopeEnded = false;

  public constructor(private readonly options: Captured) {}

  public async start(): Promise<void> {
    const ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.routePlan = lowerLaunchEgressRoutePlan(this.options.launch);
    const presetRevision = aggregateCogsEgressRoutePlanRevision(this.routePlan);
    this.wal = await this.options.ports.openWal({
      path: this.options.walPath,
      ...walLimits,
      nowMs: this.options.nowMs,
    });
    this.queue = createCogsEgressCompletionQueue(this.wal, {
      capacity: this.options.completionCapacity,
      nowMs: this.options.nowMs,
    });
    this.internalAuthzToken = validSecret(this.options.randomSecret(32));
    this.proxyCapability = validSecret(this.options.proxyCapability);
    this.authz = await this.options.ports.startAuthz({
      sessionId: validOpaque(this.options.launch.session_id),
      internalAuthzToken: this.internalAuthzToken,
      proxyCapability: this.proxyCapability,
      routePlan: this.routePlan,
      wal: this.wal,
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
    await ready;
    this.published = true;
    if (this.scopeEnded && !this.closing) {
      this.readyState = false;
      void this.failClosed();
    }
  }

  public handle(): CogsEgressRuntimeManager {
    const manager = this;
    return Object.freeze({
      get ready() {
        return manager.isReady();
      },
      get listenerPort() {
        return manager.options.listenerPort;
      },
      get replacementRequired() {
        return manager.replacement;
      },
      drainCompletions: (limit) => manager.drainCompletions(limit),
      close: () => manager.close(),
    });
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
        const binding = await this.resolveRevocationBinding(presetRevision, pki);
        return this.options.ports.withConfig(
          {
            sessionId: this.options.launch.session_id,
            listenerPort: this.options.listenerPort,
            routePlan: this.routePlan,
            authzTarget: this.authz?.target ?? "",
            internalAuthzToken: this.internalAuthzToken,
          },
          binding.credentialSource,
          async (config) => this.withMaterial(config, pki, presetRevision, binding),
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
    return validBinding(
      await this.options.ports.bindOpenBaoRevocation({
        ...revocation.openbao,
        routePlan: this.routePlan,
        userId: this.options.launch.user_id,
        presetRevision,
        pkiExpiresAtMs: pki.expiresAtMs,
        ...(this.options.signal === undefined ? {} : { signal: this.options.signal }),
      }),
    );
  }

  private async withMaterial(
    config: CogsEnvoyRuntimeConfig,
    pki: CogsEgressPkiMaterial,
    presetRevision: string,
    binding: OpenBaoEgressRevocationBinding,
  ): Promise<void> {
    await this.options.ports.withTmpfs(config, pki, async (paths) => {
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
      this.process = await this.options.envoyProcess.start({
        bootstrapPath: paths.bootstrap,
        listenerPort: this.options.listenerPort,
        ...(this.options.signal === undefined ? {} : { signal: this.options.signal }),
        onCompletionLine: (line) => this.queue?.onCompletionLine(line) ?? Promise.reject(new Error("closed")),
      });
      if (!this.dependenciesReady()) throw new Error("dependency unavailable");
      this.readyState = true;
      this.readyResolve();
      await new Promise<void>((resolve) => {
        this.release = resolve;
      });
    });
  }

  private actions() {
    return Object.freeze({
      denyNew: async (_reason: CogsEgressRevocationReason, signal: AbortSignal) => {
        this.readyState = false;
        await this.closeAuthz(signal);
      },
      drain: async (_reason: CogsEgressRevocationReason, signal: AbortSignal) => {
        await this.closeProcess(signal);
        this.captureFinalCompletions();
      },
      replace: async (reason: CogsEgressRevocationReason, signal: AbortSignal) => {
        this.replacement = true;
        try {
          await this.withTimeout((inner) => this.options.onReplacementRequired(reason, inner), signal);
        } finally {
          this.release?.();
        }
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

  private drainCompletions(limit: number): readonly CogsEgressCompletion[] {
    try {
      const count = integer(limit, 1, this.options.completionCapacity);
      if (this.queue && this.isReady()) return this.queue.drain(count);
      return Object.freeze(this.finalCompletions.splice(0, count));
    } catch {
      throw new CogsEgressRuntimeManagerError();
    }
  }

  public close(): Promise<void> {
    this.closePromise ??= this.closeOnce();
    return this.closePromise;
  }

  private async failClosed(): Promise<void> {
    await this.close().catch(() => undefined);
  }

  private async closeOnce(): Promise<void> {
    let failed = false;
    this.closing = true;
    this.readyState = false;
    for (const step of [
      () => this.closeWatcher(),
      () => this.closeAuthz(),
      () => this.closeProcess(),
      () => this.closeQueue(),
      () => this.releaseScope(),
      () => this.closeWal(),
    ]) {
      try {
        await step();
      } catch {
        failed = true;
      }
    }
    this.internalAuthzToken = "";
    this.proxyCapability = "";
    if (failed) throw new CogsEgressRuntimeManagerError();
  }

  private async closeWatcher(): Promise<void> {
    const watcher = this.watcher;
    if (watcher) await this.withTimeout(() => watcher.close());
    this.watcher = undefined;
  }

  private async closeAuthz(signal?: AbortSignal): Promise<void> {
    const authz = this.authz;
    if (authz) await this.withTimeout(() => authz.close(), signal);
    this.authz = undefined;
  }

  private async closeProcess(signal?: AbortSignal): Promise<void> {
    const process = this.process;
    if (process) await this.withTimeout(() => process.close(), signal);
    this.process = undefined;
  }

  private async closeQueue(): Promise<void> {
    let failed = false;
    try {
      this.captureFinalCompletions();
    } catch {
      failed = true;
    }
    const queue = this.queue;
    try {
      if (queue) await this.withTimeout(() => queue.close());
      this.queue = undefined;
    } catch {
      failed = true;
    }
    if (failed) throw new Error("queue cleanup failed");
  }

  private async releaseScope(): Promise<void> {
    this.release?.();
    this.release = undefined;
    if (this.scopePromise) await this.withTimeout(() => this.scopePromise ?? Promise.resolve());
  }

  private async closeWal(): Promise<void> {
    const wal = this.wal;
    if (wal) await this.withTimeout(() => wal.close());
    this.wal = undefined;
  }

  private captureFinalCompletions(): void {
    if (!this.queue || this.finalCompletions.length >= this.options.completionCapacity) return;
    const room = this.options.completionCapacity - this.finalCompletions.length;
    if (room > 0) this.finalCompletions.push(...this.queue.drain(room));
  }

  private async withTimeout<T>(work: (signal: AbortSignal) => Promise<T>, parent?: AbortSignal): Promise<T> {
    if (parent?.aborted) throw new Error("aborted");
    const controller = new AbortController();
    const relay = () => controller.abort();
    let timer: unknown;
    try {
      parent?.addEventListener("abort", relay, { once: true });
      if (parent?.aborted) controller.abort();
      return await new Promise<T>((resolve, reject) => {
        timer = this.options.timers.setTimeout(() => {
          controller.abort();
          reject(new Error("timeout"));
        }, this.options.operationTimeoutMs);
        if (controller.signal.aborted) {
          reject(new Error("aborted"));
          return;
        }
        work(controller.signal).then(resolve, reject);
      });
    } finally {
      parent?.removeEventListener("abort", relay);
      if (timer !== undefined) this.options.timers.clearTimeout(timer);
    }
  }
}

function capture(options: CogsEgressRuntimeManagerOptions): Captured {
  try {
    validateRequiredPorts(options);
    if (options.signal?.aborted) throw new Error("aborted");
    return Object.freeze({
      ...options,
      walPath: validPath(options.walPath),
      listenerPort: integer(options.listenerPort, 1, 65_535),
      maxSessionExpiresAtMs: integer(options.maxSessionExpiresAtMs, 1, Number.MAX_SAFE_INTEGER),
      completionCapacity: integer(options.completionCapacity, 1, 1024),
      revocation: validRevocation(options.revocation),
      proxyCapability: validSecret(options.proxyCapability),
      revocationPollIntervalMs: integer(options.revocationPollIntervalMs ?? 1000, 50, 60_000),
      revocationMinPkiRemainingMs: integer(options.revocationMinPkiRemainingMs ?? 60_000, 1000, 3_600_000),
      operationTimeoutMs: integer(options.operationTimeoutMs ?? 1000, 50, 5000),
      ports: ports(options.ports),
    });
  } catch {
    throw new CogsEgressRuntimeManagerError();
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

function validBinding(value: unknown): OpenBaoEgressRevocationBinding {
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
  return Object.freeze({
    source: value.source as CogsEgressRevocationSource,
    credentialSource: value.credentialSource as CogsEnvoyCredentialSource,
    credentialVersion: validOpaque(value.credentialVersion as string),
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
  });
  if (typeof value.openWal !== "function" || typeof value.startAuthz !== "function") throw new Error("bad ports");
  if (typeof value.withConfig !== "function" || typeof value.withTmpfs !== "function") throw new Error("bad ports");
  if (typeof value.bindOpenBaoRevocation !== "function") throw new Error("bad ports");
  return value as RuntimeManagerPorts;
}
