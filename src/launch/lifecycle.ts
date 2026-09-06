import { type CogsEgressRuntimeManager, failedCogsEgressRuntimeManagerRetirement } from "../egress/runtime-manager.ts";
import {
  type CogsTelemetry,
  captureTelemetry,
  emitMetric,
  emitSpan,
  telemetryDuration,
  telemetryStart,
} from "../telemetry/instrumentation.ts";
import { type CloseContext, type CloseWork, closeClock, closeContext, observeClose } from "./close.ts";
import type { LaunchConfig } from "./config.ts";
import { deepFreeze, validateLaunchConfig } from "./config.ts";

export const launchDependencyNames = ["sessionStorage", "ssh", "proxy", "auth", "auditWal", "egressRuntime"] as const;
export type LaunchDependencyName = (typeof launchDependencyNames)[number];
export type LifecycleState = "created" | "starting" | "ready" | "draining" | "stopped" | "failed";

type DependencyState = "pending" | "ready" | "failed" | "lost";

export interface TimerHandle {
  readonly cancel: () => void;
}

export interface Scheduler {
  readonly now: () => number;
  readonly setTimer: (milliseconds: number, callback: () => void) => TimerHandle;
}

export interface SignalSubscription {
  readonly dispose: () => void;
}

export interface SignalSource {
  readonly onSignal: (handler: (signal: "SIGINT" | "SIGTERM") => void) => SignalSubscription;
}

export interface LaunchDependency {
  readonly name: LaunchDependencyName;
  readonly start: (signal: AbortSignal) => Promise<void>;
  readonly shutdown: (signal: AbortSignal, context?: CloseContext) => Promise<void>;
  /** Safe initiation only; dependent release must await this owner's actual users. */
  readonly beginClose?: (context: CloseContext) => CloseWork;
  readonly ready?: () => boolean;
}

export interface LifecycleEvent {
  readonly state: LifecycleState;
  readonly ready: boolean;
  readonly reason: string;
}

export interface RecycleNotice {
  readonly reason: "normal-recycle-deadline";
  readonly deadlineMs: number;
}

export interface LaunchLifecycleOptions {
  readonly launchDocument: unknown;
  readonly dependencies: readonly LaunchDependency[];
  readonly scheduler?: Scheduler;
  readonly signals?: SignalSource;
  readonly shutdownTimeoutMs?: number;
  readonly recycleAfterMs?: number;
  readonly emergencyHardDeadlineMs?: number;
  readonly dependencyHealthIntervalMs?: number;
  readonly onEvent?: (event: LifecycleEvent) => void;
  readonly onRecycleNotice?: (notice: RecycleNotice) => void;
  readonly telemetry?: CogsTelemetry;
  /** Composite owner replaces dependency destruction; must not call requestShutdown recursively. */
  readonly shutdownOwner?: (context: CloseContext) => CloseWork;
}

export class LaunchLifecycleError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.name = "LaunchLifecycleError";
    this.code = code;
  }
}

const systemScheduler: Scheduler = {
  now: closeClock.now,
  setTimer: (milliseconds, callback) => {
    const timeout = setTimeout(callback, milliseconds);
    timeout.unref();
    return { cancel: () => clearTimeout(timeout) };
  },
};

export class LaunchLifecycle {
  readonly #config: LaunchConfig;
  readonly #dependencies: Map<LaunchDependencyName, LaunchDependency>;
  readonly #dependencyStates = new Map<LaunchDependencyName, DependencyState>();
  readonly #dependencyStartedAt = new Map<LaunchDependencyName, number>();
  readonly #attemptedDependencies: LaunchDependencyName[] = [];
  readonly #scheduler: Scheduler;
  readonly #shutdownTimeoutMs: number;
  readonly #recycleAfterMs: number | undefined;
  readonly #emergencyHardDeadlineMs: number;
  readonly #dependencyHealthIntervalMs: number;
  readonly #onEvent: ((event: LifecycleEvent) => void) | undefined;
  readonly #onRecycleNotice: ((notice: RecycleNotice) => void) | undefined;
  readonly #telemetry: CogsTelemetry;
  readonly #signalSubscription: SignalSubscription | undefined;
  readonly #lifecycleAbort = new AbortController();
  #state: LifecycleState = "created";
  #readyConfig: LaunchConfig | undefined;
  #startPromise: Promise<void> | undefined;
  #shutdownPromise: Promise<void> | undefined;
  #closeWork: CloseWork | undefined;
  readonly #startWork = new Map<LaunchDependencyName, Promise<void>>();
  readonly #shutdownOwner: ((context: CloseContext) => CloseWork) | undefined;
  #recyclePending = false;
  #recycleNoticeSent = false;
  #recycleTimer: TimerHandle | undefined;
  #emergencyTimer: TimerHandle | undefined;
  #healthTimer: TimerHandle | undefined;

  public constructor(options: LaunchLifecycleOptions) {
    this.#config = validateLaunchConfig(options.launchDocument);
    this.#dependencies = this.#validateDependencies(options.dependencies);
    for (const name of launchDependencyNames) this.#dependencyStates.set(name, "pending");
    this.#scheduler = options.scheduler ?? systemScheduler;
    this.#shutdownTimeoutMs = options.shutdownTimeoutMs ?? 10_000;
    this.#recycleAfterMs = options.recycleAfterMs;
    this.#emergencyHardDeadlineMs = options.emergencyHardDeadlineMs ?? 30_000;
    this.#dependencyHealthIntervalMs = integer(options.dependencyHealthIntervalMs ?? 100, 50, 5000);
    this.#onEvent = options.onEvent;
    this.#onRecycleNotice = options.onRecycleNotice;
    this.#telemetry = captureTelemetry(options.telemetry);
    this.#shutdownOwner = options.shutdownOwner;
    if (this.#shutdownTimeoutMs < 1) {
      throw new LaunchLifecycleError("COGS_LAUNCH_INVALID_TIMEOUT", "shutdown timeout must be positive");
    }
    if (this.#recycleAfterMs !== undefined && this.#recycleAfterMs < 1) {
      throw new LaunchLifecycleError("COGS_LAUNCH_INVALID_RECYCLE", "recycle deadline must be positive");
    }
    if (this.#emergencyHardDeadlineMs < 1) {
      throw new LaunchLifecycleError("COGS_LAUNCH_INVALID_DEADLINE", "emergency hard deadline must be positive");
    }
    this.#signalSubscription = options.signals?.onSignal((signal) => {
      void this.requestShutdown(`signal:${signal}`).catch(() => undefined);
    });
  }

  public get state(): LifecycleState {
    return this.#state;
  }

  public get ready(): boolean {
    return this.#state === "ready" && this.#readyConfig !== undefined;
  }

  public get recyclePending(): boolean {
    return this.#recyclePending;
  }

  public get readyConfig(): LaunchConfig | undefined {
    return this.#readyConfig;
  }

  public async start(): Promise<void> {
    this.#requireState("created", "COGS_LAUNCH_START_ORDER", "launch lifecycle can start only once");
    this.#startPromise = this.#start();
    return this.#startPromise;
  }

  public dependencyReady(name: LaunchDependencyName): void {
    this.#knownDependency(name);
    if (this.#state !== "starting") return;
    if (!this.#attemptedDependencies.includes(name)) return;
    if (this.#dependencyStates.get(name) === "ready") return;
    this.#dependencyStates.set(name, "ready");
    emitSpan(this.#telemetry, "dependency.ready", { dependency: telemetryDependency(name), outcome: "ok" });
    if (launchDependencyNames.every((dependency) => this.#dependencyStates.get(dependency) === "ready")) {
      if (this.#lifecycleAbort.signal.aborted || this.#shutdownPromise !== undefined || this.#state !== "starting")
        return;
      this.#readyConfig = deepFreeze(structuredClone(this.#config));
      this.#transition("ready", "dependencies-ready");
      this.#armRecycleTimer();
      this.#armHealthTimer();
    }
  }

  public dependencyStartFailed(name: LaunchDependencyName): void {
    this.#knownDependency(name);
    if (this.#state === "stopped" || this.#state === "failed") return;
    this.#dependencyStates.set(name, "failed");
    const started = this.#dependencyStartedAt.get(name);
    emitSpan(this.#telemetry, "dependency.start", {
      dependency: telemetryDependency(name),
      outcome: "error",
      ...(started === undefined ? {} : { duration_ms: telemetryDuration(this.#scheduler, started) }),
    });
    this.#failClosed("dependency-start-failed");
  }

  public dependencyLost(name: LaunchDependencyName): void {
    this.#knownDependency(name);
    if (this.#state === "stopped" || this.#state === "failed") return;
    this.#dependencyStates.set(name, "lost");
    emitSpan(this.#telemetry, "dependency.lost", { dependency: telemetryDependency(name), outcome: "error" });
    this.#failClosed("dependency-lost");
  }

  public turnSettled(): Promise<void> | undefined {
    if (!this.#recyclePending || this.#shutdownPromise !== undefined) return this.#shutdownPromise;
    return this.requestShutdown("recycle-turn-settled");
  }

  public requestShutdown(reason = "requested", context?: CloseContext): Promise<void> {
    if (this.#shutdownPromise !== undefined) return this.#shutdownPromise;
    let resolve!: () => void;
    let reject!: (error: unknown) => void;
    this.#shutdownPromise = new Promise<void>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    // Cache before abort/event callbacks can reenter; seal admission on this stack.
    this.#readyConfig = undefined;
    this.#lifecycleAbort.abort();
    this.#clearRecycleTimers();
    this.#clearHealthTimer();
    void this.#shutdown(reason, context ?? closeContext(this.#shutdownTimeoutMs, this.#scheduler)).then(
      resolve,
      reject,
    );
    return this.#shutdownPromise;
  }

  /** Actual work is retained after an observation deadline. No replacement permission is implied. */
  public get closeWork(): CloseWork | undefined {
    return this.#closeWork;
  }

  public dispose(): Promise<void> {
    return this.requestShutdown("dispose");
  }

  async #start(): Promise<void> {
    const start = telemetryStart(this.#scheduler);
    this.#transition("starting", "start");
    let currentDependency: LaunchDependencyName = "sessionStorage";
    try {
      for (const dependency of this.#dependencies.values()) {
        this.#throwIfStartInterrupted();
        currentDependency = dependency.name;
        this.#attemptedDependencies.push(dependency.name);
        const dependencyStart = telemetryStart(this.#scheduler);
        this.#dependencyStartedAt.set(dependency.name, dependencyStart);
        const work = Promise.resolve().then(() => dependency.start(this.#lifecycleAbort.signal));
        this.#startWork.set(dependency.name, work);
        await this.#withAbort(work, this.#lifecycleAbort.signal);
        emitSpan(this.#telemetry, "dependency.start", {
          dependency: telemetryDependency(dependency.name),
          outcome: "ok",
          duration_ms: telemetryDuration(this.#scheduler, dependencyStart),
        });
        this.#throwIfStartInterrupted();
        this.dependencyReady(dependency.name);
      }
      emitSpan(this.#telemetry, "lifecycle.start", {
        outcome: "ok",
        duration_ms: telemetryDuration(this.#scheduler, start),
      });
    } catch (error) {
      if (this.#shutdownPromise !== undefined || this.#lifecycleAbort.signal.aborted) {
        await this.#shutdownPromise;
        return;
      }
      this.dependencyStartFailed(currentDependency);
      throw error instanceof LaunchLifecycleError
        ? error
        : new LaunchLifecycleError("COGS_LAUNCH_DEPENDENCY_START_FAILED", "dependency start failed");
    }
  }

  #throwIfStartInterrupted(): void {
    if (this.#shutdownPromise !== undefined || this.#lifecycleAbort.signal.aborted || this.#state !== "starting") {
      throw new LaunchLifecycleError("COGS_LAUNCH_START_INTERRUPTED", "launch startup interrupted");
    }
  }

  #armRecycleTimer(): void {
    if (this.#recycleAfterMs === undefined) return;
    this.#recycleTimer = this.#scheduler.setTimer(this.#recycleAfterMs, () => {
      if (!this.ready || this.#recyclePending) return;
      this.#recyclePending = true;
      if (!this.#recycleNoticeSent) {
        this.#recycleNoticeSent = true;
        const deadlineMs = this.#scheduler.now() + this.#emergencyHardDeadlineMs;
        this.#emergencyTimer = this.#scheduler.setTimer(this.#emergencyHardDeadlineMs, () => {
          void this.requestShutdown("recycle-emergency-deadline").catch(() => undefined);
        });
        this.#emitRecycleNotice({ reason: "normal-recycle-deadline", deadlineMs });
      }
    });
  }

  #armHealthTimer(): void {
    if (!this.ready) return;
    try {
      this.#healthTimer = this.#scheduler.setTimer(this.#dependencyHealthIntervalMs, () =>
        this.#checkDependencyHealth(),
      );
    } catch {
      this.#failClosed("dependency-health-timer-failed");
    }
  }

  #checkDependencyHealth(): void {
    this.#healthTimer = undefined;
    if (!this.ready || this.#shutdownPromise !== undefined) return;
    for (const name of launchDependencyNames) {
      if (!this.#attemptedDependencies.includes(name)) continue;
      try {
        const ready = this.#dependencies.get(name)?.ready;
        if (ready && !ready()) {
          this.dependencyLost(name);
          return;
        }
      } catch {
        this.dependencyLost(name);
        return;
      }
    }
    this.#armHealthTimer();
  }

  #clearHealthTimer(): void {
    this.#healthTimer?.cancel();
    this.#healthTimer = undefined;
  }

  #clearRecycleTimers(): void {
    this.#recycleTimer?.cancel();
    this.#emergencyTimer?.cancel();
    this.#recycleTimer = undefined;
    this.#emergencyTimer = undefined;
  }

  #validateDependencies(dependencies: readonly LaunchDependency[]): Map<LaunchDependencyName, LaunchDependency> {
    const result = new Map<LaunchDependencyName, LaunchDependency>();
    for (const dependency of dependencies) {
      if (!launchDependencyNames.includes(dependency.name)) {
        throw new LaunchLifecycleError("COGS_LAUNCH_UNKNOWN_DEPENDENCY", "unknown launch dependency");
      }
      if (result.has(dependency.name)) {
        throw new LaunchLifecycleError("COGS_LAUNCH_DUPLICATE_DEPENDENCY", "duplicate launch dependency");
      }
      result.set(dependency.name, dependency);
    }
    for (const name of launchDependencyNames) {
      if (!result.has(name))
        throw new LaunchLifecycleError("COGS_LAUNCH_MISSING_DEPENDENCY", "missing launch dependency");
    }
    return new Map(launchDependencyNames.map((name) => [name, result.get(name) as LaunchDependency]));
  }

  #knownDependency(name: LaunchDependencyName): void {
    if (!this.#dependencyStates.has(name))
      throw new LaunchLifecycleError("COGS_LAUNCH_UNKNOWN_DEPENDENCY", "unknown launch dependency");
  }

  #requireState(expected: LifecycleState, code: string, message: string): void {
    if (this.#state !== expected) throw new LaunchLifecycleError(code, message);
  }

  #transition(state: LifecycleState, reason: string): void {
    this.#state = state;
    if (state === "ready") {
      emitSpan(this.#telemetry, "lifecycle.ready", { state: "ready", outcome: "ok" });
      emitMetric(this.#telemetry, "session.active", 1, { state: "ready" });
    } else if (state === "stopped" || state === "failed") {
      emitMetric(this.#telemetry, "session.active", 0, { state: state === "failed" ? "failed" : "shutdown" });
    }
    try {
      this.#onEvent?.({ state, ready: this.ready, reason });
    } catch {
      // Observers are diagnostic only and must not control lifecycle safety.
    }
  }

  #emitRecycleNotice(notice: RecycleNotice): void {
    try {
      this.#onRecycleNotice?.(notice);
    } catch {
      // Observers are diagnostic only and must not suppress emergency shutdown.
    }
  }

  #failClosed(reason: string): void {
    this.#readyConfig = undefined;
    this.#transition("failed", reason);
    void this.requestShutdown(reason).catch(() => undefined);
  }

  async #shutdown(reason: string, context: CloseContext): Promise<void> {
    const start = telemetryStart(this.#scheduler);
    emitSpan(this.#telemetry, "shutdown.prepare", { operation: "prepare", state: "shutdown" });
    if (this.#state !== "failed" && this.#state !== "stopped") this.#transition("draining", reason);
    try {
      this.#closeWork = this.#shutdownOwner?.(context) ?? this.closeDependencies(context);
      await observeClose(this.#closeWork, context, this.#scheduler);
      if (this.#state !== "failed") {
        emitSpan(this.#telemetry, "shutdown.ready", {
          operation: "close",
          outcome: "ok",
          duration_ms: telemetryDuration(this.#scheduler, start),
        });
        this.#transition("stopped", reason);
      }
    } catch {
      this.#transition("failed", "cleanup-uncertain");
      throw new LaunchLifecycleError("COGS_LAUNCH_CLEANUP_FAILED", "cleanup uncertain");
    } finally {
      this.#disposeResources();
    }
  }

  /** Initiate independent migrated owners immediately. Legacy destructors retain reverse-order
   * barriers: a failed/hung callback cannot authorize dependent resource release. */
  public closeDependencies(context: CloseContext): CloseWork {
    const independent: CloseWork[] = [];
    const legacy: LaunchDependency[] = [];
    for (const name of [...this.#attemptedDependencies].reverse()) {
      const dependency = this.#dependencies.get(name);
      if (!dependency) continue;
      if (dependency.beginClose) {
        const acquired = this.#startWork.get(name)?.catch(() => undefined) ?? Promise.resolve();
        const work = acquired.then(() => dependency.beginClose?.(context) as CloseWork);
        independent.push({ done: work.then((value) => value.done), retired: work.then((value) => value.retired) });
      } else legacy.push(dependency);
    }
    const serial = (async () => {
      for (const dependency of legacy) {
        await this.#startWork.get(dependency.name)?.catch(() => undefined);
        await dependency.shutdown(context.signal, context);
      }
    })();
    const done = Promise.all([serial, ...independent.map((work) => work.done)]).then(() => undefined);
    const retired = Promise.all([serial, ...independent.map((work) => work.retired)]).then(() => undefined);
    // Retain both even when one rejection makes the observation terminate early.
    void done.catch(() => undefined);
    void retired.catch(() => undefined);
    return Object.freeze({ done, retired });
  }

  #disposeResources(): void {
    this.#lifecycleAbort.abort();
    this.#clearRecycleTimers();
    this.#clearHealthTimer();
    this.#signalSubscription?.dispose();
  }

  async #withAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
    if (signal.aborted) throw new LaunchLifecycleError("COGS_LAUNCH_OPERATION_ABORTED", "operation aborted");
    let removeAbortListener: (() => void) | undefined;
    const aborted = new Promise<never>((_, reject) => {
      const onAbort = () => reject(new LaunchLifecycleError("COGS_LAUNCH_OPERATION_ABORTED", "operation aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      removeAbortListener = () => signal.removeEventListener("abort", onAbort);
    });
    try {
      return await Promise.race([operation, aborted]);
    } finally {
      removeAbortListener?.();
    }
  }
}

function integer(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new LaunchLifecycleError("COGS_LAUNCH_INVALID_HEALTH_INTERVAL", "dependency health interval invalid");
  return value;
}

function telemetryDependency(name: LaunchDependencyName): "storage" | "ssh" | "proxy" | "auth" | "wal" | "egress" {
  if (name === "sessionStorage") return "storage";
  if (name === "auditWal") return "wal";
  if (name === "egressRuntime") return "egress";
  return name;
}

export function createCogsEgressRuntimeLaunchDependency(
  factory: (signal: AbortSignal) => Promise<CogsEgressRuntimeManager>,
): LaunchDependency {
  if (typeof factory !== "function") throw egressRuntimeError();
  let manager: CogsEgressRuntimeManager | undefined;
  let closePromise: Promise<void> | undefined;
  let startWork: Promise<void> | undefined;
  let shutdownPromise: Promise<void> | undefined;
  let failedStartRetirement: Promise<void> | undefined;
  let shutdownRequested = false;
  let started = false;
  return Object.freeze({
    name: "egressRuntime",
    async start(signal: AbortSignal) {
      if (started) throw egressRuntimeError();
      started = true;
      startWork = (async () => {
        try {
          if (signal.aborted) throw new Error("aborted");
          manager = await factory(signal);
          if (signal.aborted || shutdownRequested || !manager.ready) throw new Error("egress not ready");
        } catch (error) {
          failedStartRetirement ??= failedCogsEgressRuntimeManagerRetirement(error);
          if (manager) {
            try {
              closePromise ??= manager.close();
              await closePromise;
              manager = undefined;
            } catch {
              // Retain the owned handle for lifecycle rollback shutdown.
            }
          }
          throw egressRuntimeError();
        }
      })();
      return startWork;
    },
    ready: () => {
      try {
        return manager?.ready === true;
      } catch {
        return false;
      }
    },
    async shutdown(signal: AbortSignal) {
      shutdownRequested = true;
      shutdownPromise ??= (async () => {
        try {
          await startWork?.catch(() => undefined);
          await failedStartRetirement;
          const current = manager;
          if (!current) return;
          closePromise ??= current.close({ signal });
          await closePromise;
          manager = undefined;
        } catch {
          throw egressRuntimeError();
        }
      })();
      return shutdownPromise;
    },
  });
}

function egressRuntimeError(): LaunchLifecycleError {
  return new LaunchLifecycleError("COGS_LAUNCH_EGRESS_RUNTIME_FAILED", "egress runtime unavailable");
}
