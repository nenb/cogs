import type { LaunchConfig } from "./config.ts";
import { deepFreeze, validateLaunchConfig } from "./config.ts";

export const launchDependencyNames = ["sessionStorage", "ssh", "proxy", "auth", "auditWal"] as const;
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
  readonly shutdown: (signal: AbortSignal) => Promise<void>;
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
  readonly onEvent?: (event: LifecycleEvent) => void;
  readonly onRecycleNotice?: (notice: RecycleNotice) => void;
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
  now: Date.now,
  setTimer: (milliseconds, callback) => {
    const timeout = setTimeout(callback, milliseconds);
    return { cancel: () => clearTimeout(timeout) };
  },
};

export class LaunchLifecycle {
  readonly #config: LaunchConfig;
  readonly #dependencies: Map<LaunchDependencyName, LaunchDependency>;
  readonly #dependencyStates = new Map<LaunchDependencyName, DependencyState>();
  readonly #attemptedDependencies: LaunchDependencyName[] = [];
  readonly #scheduler: Scheduler;
  readonly #shutdownTimeoutMs: number;
  readonly #recycleAfterMs: number | undefined;
  readonly #emergencyHardDeadlineMs: number;
  readonly #onEvent: ((event: LifecycleEvent) => void) | undefined;
  readonly #onRecycleNotice: ((notice: RecycleNotice) => void) | undefined;
  readonly #signalSubscription: SignalSubscription | undefined;
  readonly #lifecycleAbort = new AbortController();
  #state: LifecycleState = "created";
  #readyConfig: LaunchConfig | undefined;
  #startPromise: Promise<void> | undefined;
  #shutdownPromise: Promise<void> | undefined;
  #recyclePending = false;
  #recycleNoticeSent = false;
  #recycleTimer: TimerHandle | undefined;
  #emergencyTimer: TimerHandle | undefined;

  public constructor(options: LaunchLifecycleOptions) {
    this.#config = validateLaunchConfig(options.launchDocument);
    this.#dependencies = this.#validateDependencies(options.dependencies);
    for (const name of launchDependencyNames) this.#dependencyStates.set(name, "pending");
    this.#scheduler = options.scheduler ?? systemScheduler;
    this.#shutdownTimeoutMs = options.shutdownTimeoutMs ?? 10_000;
    this.#recycleAfterMs = options.recycleAfterMs;
    this.#emergencyHardDeadlineMs = options.emergencyHardDeadlineMs ?? 30_000;
    this.#onEvent = options.onEvent;
    this.#onRecycleNotice = options.onRecycleNotice;
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
      void this.requestShutdown(`signal:${signal}`);
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
    if (launchDependencyNames.every((dependency) => this.#dependencyStates.get(dependency) === "ready")) {
      if (this.#lifecycleAbort.signal.aborted || this.#shutdownPromise !== undefined || this.#state !== "starting")
        return;
      this.#readyConfig = deepFreeze(structuredClone(this.#config));
      this.#transition("ready", "dependencies-ready");
      this.#armRecycleTimer();
    }
  }

  public dependencyStartFailed(name: LaunchDependencyName): void {
    this.#knownDependency(name);
    if (this.#state === "stopped" || this.#state === "failed") return;
    this.#dependencyStates.set(name, "failed");
    this.#failClosed("dependency-start-failed");
  }

  public dependencyLost(name: LaunchDependencyName): void {
    this.#knownDependency(name);
    if (this.#state === "stopped" || this.#state === "failed") return;
    this.#dependencyStates.set(name, "lost");
    this.#failClosed("dependency-lost");
  }

  public turnSettled(): Promise<void> | undefined {
    if (!this.#recyclePending || this.#shutdownPromise !== undefined) return this.#shutdownPromise;
    return this.requestShutdown("recycle-turn-settled");
  }

  public requestShutdown(reason = "requested"): Promise<void> {
    if (this.#shutdownPromise !== undefined) return this.#shutdownPromise;
    this.#lifecycleAbort.abort();
    this.#clearRecycleTimers();
    this.#readyConfig = undefined;
    this.#shutdownPromise = this.#shutdown(reason);
    return this.#shutdownPromise;
  }

  public dispose(): Promise<void> {
    return this.requestShutdown("dispose");
  }

  async #start(): Promise<void> {
    this.#transition("starting", "start");
    let currentDependency: LaunchDependencyName = "sessionStorage";
    try {
      for (const dependency of this.#dependencies.values()) {
        this.#throwIfStartInterrupted();
        currentDependency = dependency.name;
        this.#attemptedDependencies.push(dependency.name);
        await this.#withAbort(dependency.start(this.#lifecycleAbort.signal), this.#lifecycleAbort.signal);
        this.#throwIfStartInterrupted();
        this.dependencyReady(dependency.name);
      }
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
          void this.requestShutdown("recycle-emergency-deadline");
        });
        this.#emitRecycleNotice({ reason: "normal-recycle-deadline", deadlineMs });
      }
    });
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
    return result;
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
    void this.requestShutdown(reason);
  }

  async #shutdown(reason: string): Promise<void> {
    if (this.#state !== "failed" && this.#state !== "stopped") this.#transition("draining", reason);
    const shutdownAbort = new AbortController();
    const timeout = this.#scheduler.setTimer(this.#shutdownTimeoutMs, () => {
      shutdownAbort.abort();
    });
    try {
      await this.#shutdownDependencies(shutdownAbort.signal);
    } finally {
      timeout.cancel();
      shutdownAbort.abort();
      this.#readyConfig = undefined;
      this.#transition("stopped", reason);
      this.#disposeResources();
    }
  }

  async #shutdownDependencies(signal: AbortSignal): Promise<void> {
    const attempted = [...this.#attemptedDependencies].reverse();
    for (const name of attempted) {
      if (signal.aborted) break;
      const dependency = this.#dependencies.get(name);
      if (dependency === undefined) continue;
      try {
        await this.#withAbort(dependency.shutdown(signal), signal);
      } catch {
        // Shutdown is best-effort after fail-closed readiness has been revoked; no fallback is attempted.
      }
    }
  }

  #disposeResources(): void {
    this.#lifecycleAbort.abort();
    this.#clearRecycleTimers();
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
