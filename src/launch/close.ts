import { performance } from "node:perf_hooks";

/** One clock domain for the entire close tree. Cancellation bounds observation, not custody. */
export type CloseContext = Readonly<{ signal: AbortSignal; deadlineAt: number }>;
export type CloseWork = Readonly<{ done: Promise<void>; retired: Promise<void> }>;
export type CloseClock = Readonly<{
  now(): number;
  setTimer(ms: number, callback: () => void): { cancel(): void };
}>;
const ownedControllers = new WeakMap<CloseContext, AbortController>();

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
  const controller = new AbortController();
  const context = Object.freeze({ signal: controller.signal, deadlineAt: clock.now() + timeoutMs });
  ownedControllers.set(context, controller);
  return context;
}

/** No side effects on actual work, timers for escalation, or resource handles. */
export function observeClose(work: CloseWork, context: CloseContext, clock: CloseClock = closeClock): Promise<void> {
  const actual = Promise.all([work.done, work.retired]);
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer: { cancel(): void } | undefined;
    const finish = (outcome?: "error" | "deadline" | "cancelled") => {
      if (settled) return;
      settled = true;
      timer?.cancel();
      context.signal.removeEventListener("abort", abort);
      outcome ? reject(new CloseObservationError(outcome)) : resolve();
    };
    const abort = () => finish("cancelled");
    actual.then(
      () => finish(clock.now() >= context.deadlineAt ? "deadline" : undefined),
      () => finish("error"),
    );
    context.signal.addEventListener("abort", abort, { once: true });
    if (context.signal.aborted) abort();
    else if (!Number.isFinite(context.deadlineAt) || clock.now() >= context.deadlineAt) {
      ownedControllers.get(context)?.abort();
      finish("deadline");
    } else
      timer = clock.setTimer(context.deadlineAt - clock.now(), () => {
        // Cancellation is a request to cooperative work. Actual work and custody
        // remain retained after this bounded observation rejects.
        ownedControllers.get(context)?.abort();
        finish("deadline");
      });
  });
}
