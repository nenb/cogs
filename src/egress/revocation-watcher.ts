const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const reasons = new Set<CogsEgressRevocationReason>([
  "revoked",
  "preset_changed",
  "credential_changed",
  "pki_changed",
  "pki_expiring",
  "cancelled",
  "source_unavailable",
]);

export type CogsEgressRevocationReason =
  | "revoked"
  | "preset_changed"
  | "credential_changed"
  | "pki_changed"
  | "pki_expiring"
  | "cancelled"
  | "source_unavailable";

export type CogsEgressRevocationSnapshot = Readonly<{
  presetRevision: string;
  credentialVersion: string;
  revoked: boolean;
  pkiExpiresAtMs: number;
}>;

export type CogsEgressRevocationSource = Readonly<{
  read(signal: AbortSignal): Promise<CogsEgressRevocationSnapshot>;
}>;

export type CogsEgressRevocationActions = Readonly<{
  denyNew(reason: CogsEgressRevocationReason, signal: AbortSignal): Promise<void>;
  drain(reason: CogsEgressRevocationReason, signal: AbortSignal): Promise<void>;
  replace(reason: CogsEgressRevocationReason, signal: AbortSignal): Promise<void>;
}>;

export type CogsEgressRevocationTimers = Readonly<{
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(timer: unknown): void;
}>;

export type CogsEgressRevocationWatcherOptions = Readonly<{
  baseline: CogsEgressRevocationSnapshot;
  pollIntervalMs: number;
  minPkiRemainingMs: number;
  operationTimeoutMs: number;
  nowMs: () => number;
  timers: CogsEgressRevocationTimers;
  signal?: AbortSignal;
}>;

export type CogsEgressRevocationWatcher = Readonly<{
  ready: boolean;
  close(): Promise<void>;
}>;

export class CogsEgressRevocationError extends Error {
  public readonly code = "COGS_EGRESS_REVOCATION_FAILED";
  public constructor() {
    super("egress revocation unavailable");
    this.name = "CogsEgressRevocationError";
  }
}

export async function createCogsEgressRevocationWatcher(
  source: CogsEgressRevocationSource,
  actions: CogsEgressRevocationActions,
  options: CogsEgressRevocationWatcherOptions,
): Promise<CogsEgressRevocationWatcher> {
  try {
    validatePorts(source, actions);
    const watcher = new RevocationWatcher(source, actions, capture(options));
    await watcher.start();
    return watcher.handle();
  } catch {
    throw new CogsEgressRevocationError();
  }
}

class RevocationWatcher {
  private closed = false;
  private readyState = false;
  private timer: unknown;
  private active: AbortController | undefined;
  private activeWork: Promise<void> | undefined;
  private transition: Promise<void> | undefined;
  private abortListener: (() => void) | undefined;
  private closePromise: Promise<void> | undefined;
  private actionFailed = false;

  public constructor(
    private readonly source: CogsEgressRevocationSource,
    private readonly actions: CogsEgressRevocationActions,
    private readonly options: Required<CogsEgressRevocationWatcherOptions>,
  ) {}

  public async start(): Promise<void> {
    if (this.options.signal.aborted) throw new Error("cancelled");
    try {
      const first = await this.readOnce();
      const reason = this.reason(first);
      if (reason) {
        await this.trigger(reason, true);
        throw new Error("initial revoked");
      }
      this.abortListener = () => void this.trigger("cancelled");
      this.options.signal.addEventListener("abort", this.abortListener, { once: true });
      if (this.options.signal.aborted) {
        await this.trigger("cancelled", true);
        throw new Error("cancelled");
      }
      this.readyState = true;
      this.schedule();
    } catch (error) {
      if (!this.transition && !this.closed)
        await this.trigger(this.options.signal.aborted ? "cancelled" : "source_unavailable", true);
      throw error;
    }
  }

  public handle(): CogsEgressRevocationWatcher {
    const watcher = this;
    return Object.freeze({
      get ready() {
        return watcher.readyState && !watcher.closed;
      },
      close: () => watcher.close(),
    });
  }

  private schedule(): void {
    if (this.closed || !this.readyState || this.transition) return;
    try {
      this.timer = this.options.timers.setTimeout(() => void this.poll(), this.options.pollIntervalMs);
    } catch {
      void this.trigger("source_unavailable");
    }
  }

  private poll(): void {
    if (this.closed || !this.readyState || this.activeWork) return;
    this.timer = undefined;
    this.activeWork = (async () => {
      try {
        const snapshot = await this.readOnce();
        const reason = this.reason(snapshot);
        if (reason) await this.trigger(reason);
      } catch {
        await this.trigger(this.options.signal.aborted ? "cancelled" : "source_unavailable");
      } finally {
        this.activeWork = undefined;
        this.schedule();
      }
    })();
  }

  private async readOnce(): Promise<CogsEgressRevocationSnapshot> {
    const controller = new AbortController();
    const relay = () => controller.abort();
    this.active = controller;
    try {
      if (this.options.signal.aborted) controller.abort();
      else this.options.signal.addEventListener("abort", relay, { once: true });
      const snapshot = await this.withTimeout((signal) => this.source.read(signal), controller);
      return validateSnapshot(snapshot);
    } finally {
      this.options.signal.removeEventListener("abort", relay);
      if (this.active === controller) this.active = undefined;
    }
  }

  private reason(snapshot: CogsEgressRevocationSnapshot): CogsEgressRevocationReason | undefined {
    const now = this.options.nowMs();
    if (!safeClock(now)) return "source_unavailable";
    if (snapshot.revoked) return "revoked";
    if (snapshot.presetRevision !== this.options.baseline.presetRevision) return "preset_changed";
    if (snapshot.credentialVersion !== this.options.baseline.credentialVersion) return "credential_changed";
    if (snapshot.pkiExpiresAtMs !== this.options.baseline.pkiExpiresAtMs) return "pki_changed";
    if (snapshot.pkiExpiresAtMs - now <= this.options.minPkiRemainingMs) return "pki_expiring";
    return undefined;
  }

  private async trigger(reason: CogsEgressRevocationReason, duringStart = false): Promise<void> {
    if (this.closed && !duringStart) return;
    if (!reasons.has(reason)) reason = "source_unavailable";
    this.readyState = false;
    try {
      this.cancelTimer();
    } catch {
      this.actionFailed = true;
    }
    this.active?.abort();
    try {
      this.removeAbortListener();
    } catch {
      this.actionFailed = true;
    }
    if (!this.transition) this.transition = this.runActions(reason);
    await this.transition;
  }

  private async runActions(reason: CogsEgressRevocationReason): Promise<void> {
    const attempts = [
      (signal: AbortSignal) => this.actions.denyNew(reason, signal),
      (signal: AbortSignal) => this.actions.drain(reason, signal),
      (signal: AbortSignal) => this.actions.replace(reason, signal),
    ];
    for (const attempt of attempts) {
      try {
        await this.withTimeout(attempt, new AbortController());
      } catch {
        this.actionFailed = true;
      }
    }
  }

  public close(): Promise<void> {
    this.closePromise ??= this.closeOnce();
    return this.closePromise;
  }

  private async closeOnce(): Promise<void> {
    let failed = false;
    this.closed = true;
    this.readyState = false;
    try {
      this.cancelTimer();
    } catch {
      failed = true;
    }
    try {
      this.removeAbortListener();
    } catch {
      failed = true;
    }
    this.active?.abort();
    try {
      const works = [this.activeWork, this.transition].filter((work): work is Promise<void> => work !== undefined);
      if (works.length > 0)
        await boundedAwait(Promise.allSettled(works), this.options.operationTimeoutMs * 4, this.options.timers);
    } catch {
      failed = true;
    }
    if (failed || this.actionFailed) throw new CogsEgressRevocationError();
  }

  private cancelTimer(): void {
    if (this.timer !== undefined) this.options.timers.clearTimeout(this.timer);
    this.timer = undefined;
  }

  private removeAbortListener(): void {
    if (this.abortListener) this.options.signal.removeEventListener("abort", this.abortListener);
    this.abortListener = undefined;
  }

  private async withTimeout<T>(work: (signal: AbortSignal) => Promise<T>, controller: AbortController): Promise<T> {
    let timer: unknown;
    try {
      return await new Promise<T>((resolve, reject) => {
        timer = this.options.timers.setTimeout(() => {
          controller.abort();
          reject(new Error("timeout"));
        }, this.options.operationTimeoutMs);
        try {
          work(controller.signal).then(resolve, reject);
        } catch (error) {
          reject(error);
        }
      });
    } finally {
      if (timer !== undefined) this.options.timers.clearTimeout(timer);
    }
  }
}

function capture(options: CogsEgressRevocationWatcherOptions): Required<CogsEgressRevocationWatcherOptions> {
  const baseline = validateSnapshot(options.baseline);
  const pollIntervalMs = bound(options.pollIntervalMs, 50, 60_000);
  const minPkiRemainingMs = bound(options.minPkiRemainingMs, 1_000, 3_600_000);
  const operationTimeoutMs = bound(options.operationTimeoutMs, 50, 5_000);
  if (typeof options.nowMs !== "function" || !options.timers || typeof options.timers.setTimeout !== "function")
    throw new Error("bad options");
  if (typeof options.timers.clearTimeout !== "function") throw new Error("bad options");
  if (!safeClock(options.nowMs())) throw new Error("bad clock");
  return Object.freeze({
    ...options,
    baseline,
    pollIntervalMs,
    minPkiRemainingMs,
    operationTimeoutMs,
    signal: options.signal ?? new AbortController().signal,
  });
}

function validateSnapshot(value: CogsEgressRevocationSnapshot): CogsEgressRevocationSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("bad snapshot");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 4 ||
    !["presetRevision", "credentialVersion", "revoked", "pkiExpiresAtMs"].every((key) => keys.includes(key))
  )
    throw new Error("bad keys");
  if (typeof value.presetRevision !== "string" || typeof value.credentialVersion !== "string")
    throw new Error("bad revision");
  if (!opaque.test(value.presetRevision) || !opaque.test(value.credentialVersion)) throw new Error("bad revision");
  if (typeof value.revoked !== "boolean" || !safeClock(value.pkiExpiresAtMs)) throw new Error("bad fields");
  return Object.freeze({
    presetRevision: value.presetRevision,
    credentialVersion: value.credentialVersion,
    revoked: value.revoked,
    pkiExpiresAtMs: value.pkiExpiresAtMs,
  });
}

function bound(value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error("bad bound");
  return value;
}

function safeClock(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function validatePorts(source: CogsEgressRevocationSource, actions: CogsEgressRevocationActions): void {
  if (!source || typeof source.read !== "function") throw new Error("bad source");
  if (!actions || typeof actions.denyNew !== "function") throw new Error("bad actions");
  if (typeof actions.drain !== "function" || typeof actions.replace !== "function") throw new Error("bad actions");
}

async function boundedAwait(work: Promise<unknown>, ms: number, timers: CogsEgressRevocationTimers): Promise<void> {
  let timer: unknown;
  try {
    await Promise.race([
      work,
      new Promise((_, reject) => {
        timer = timers.setTimeout(() => reject(new Error("cleanup timeout")), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) timers.clearTimeout(timer);
  }
}
