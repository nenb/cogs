import { performance } from "node:perf_hooks";

/** Cancellation bounds observation, not custody. Internal deadlines are monotonic. */
export type CloseContext = Readonly<{ signal: AbortSignal; deadlineAt: number }>;
export type CloseWork = Readonly<{ done: Promise<void>; retired: Promise<void> }>;
export type CloseClock = Readonly<{
  now(): number;
  setTimer(ms: number, callback: () => void): { cancel(): void };
}>;
export type CloseOwner = () => CloseWork;
const owners = new WeakMap<object, CloseOwner>();
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const eventAdd = EventTarget.prototype.addEventListener;
const eventRemove = EventTarget.prototype.removeEventListener;

/** Publish both facts before sealing admission or invoking any reentrant code. */
export function createCloseOwner(execute: () => CloseWork | Promise<void>, seal: () => void = () => {}): CloseOwner {
  let work: CloseWork | undefined;
  return () => {
    if (work) return work;
    const done = Promise.withResolvers<void>();
    const retired = Promise.withResolvers<void>();
    work = Object.freeze({ done: done.promise, retired: retired.promise });
    void work.done.catch(() => undefined);
    void work.retired.catch(() => undefined);
    try {
      seal();
      const actual = execute();
      const facts = Object.getOwnPropertyDescriptors(
        actual instanceof Promise ? { done: actual, retired: actual } : actual,
      );
      const result = facts.done?.value;
      const retirement = facts.retired?.value;
      // Consume each acquired fact even if its sibling is malformed. Never invoke
      // accessors or certify an absent retirement fact as resolved undefined.
      if (result instanceof Promise) void result.catch(() => undefined);
      if (retirement instanceof Promise) void retirement.catch(() => undefined);
      if (!(result instanceof Promise) || !(retirement instanceof Promise)) throw new CloseObservationError("error");
      result.then(done.resolve, done.reject);
      retirement.then(retired.resolve, retired.reject);
    } catch (error) {
      done.reject(error);
      retired.reject(error);
    }
    return work;
  };
}

/** Internal composition capability, never a public shape change or a cleanup receipt. */
export function registerCloseOwner<T extends object>(handle: T, owner: CloseOwner): T {
  if (owners.has(handle)) throw new CloseObservationError("error");
  owners.set(handle, owner);
  return handle;
}
export function beginRegisteredClose(handle: object): CloseWork {
  const owner = owners.get(handle);
  if (!owner) throw new CloseObservationError("error");
  return owner();
}
export function joinCloseWork(work: CloseWork): Promise<void> {
  return Promise.all([work.done, work.retired]).then(() => undefined);
}

export const closeClock: CloseClock = {
  now: () => performance.now(),
  setTimer(ms, callback) {
    const timer = setTimeout(callback, ms);
    return { cancel: () => clearTimeout(timer) };
  },
};
export class CloseObservationError extends Error {
  readonly code = "COGS_CLOSE_FAILED";
  constructor(readonly outcome: "error" | "deadline" | "cancelled") {
    super(`cleanup ${outcome}`);
  }
}
export function closeContext(timeoutMs: number, clock: CloseClock = closeClock): CloseContext {
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new CloseObservationError("error");
  return Object.freeze({ signal: new AbortController().signal, deadlineAt: clock.now() + timeoutMs });
}

/** Convert already-validated public epoch options once; never forward them into actual work. */
export function closeObservationContext(
  options: Readonly<{ signal?: AbortSignal; deadlineAt?: number }>,
  timeoutMs: number,
  clock: CloseClock = closeClock,
): CloseContext {
  return Object.freeze({
    signal: options.signal ?? new AbortController().signal,
    deadlineAt: clock.now() + (options.deadlineAt === undefined ? timeoutMs : options.deadlineAt - Date.now()),
  });
}

/** No side effects on actual work, escalation timers, or resource handles. */
export function observeClose(work: CloseWork, context: CloseContext, clock: CloseClock = closeClock): Promise<void> {
  const actual = joinCloseWork(work);
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer: { cancel(): void } | undefined;
    const cancelTimer = () => {
      try {
        timer?.cancel();
      } catch {
        /* Observation cleanup cannot change custody. */
      }
    };
    const finish = (outcome?: "error" | "deadline" | "cancelled") => {
      if (settled) return;
      settled = true;
      cancelTimer();
      try {
        eventRemove.call(context.signal, "abort", abort);
      } catch {
        outcome = "error";
      }
      outcome ? reject(new CloseObservationError(outcome)) : resolve();
    };
    const abort = () => finish("cancelled");
    actual.then(
      () => {
        try {
          finish(clock.now() >= context.deadlineAt ? "deadline" : undefined);
        } catch {
          finish("error");
        }
      },
      () => finish("error"),
    );
    try {
      eventAdd.call(context.signal, "abort", abort, { once: true });
      if (signalAborted?.call(context.signal)) abort();
      else if (!Number.isFinite(context.deadlineAt) || clock.now() >= context.deadlineAt) finish("deadline");
      else {
        timer = clock.setTimer(context.deadlineAt - clock.now(), () => finish("deadline"));
        if (settled) cancelTimer(); // A hostile/synchronous timer fired before returning its handle.
      }
    } catch {
      finish("error");
    }
  });
}
