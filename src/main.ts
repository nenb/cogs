import { pathToFileURL } from "node:url";
import { type ProductionWorkerRuntime, startProductionWorker } from "./runtime/compose.ts";

const HARD_SHUTDOWN_MS = 31_000;

export type ProductionMainPort = Readonly<{
  start(signal: AbortSignal): Promise<ProductionWorkerRuntime>;
  on(signal: "SIGINT" | "SIGTERM", listener: () => void): void;
  off(signal: "SIGINT" | "SIGTERM", listener: () => void): void;
  setTimer(callback: () => void, milliseconds: number): unknown;
  clearTimer(timer: unknown): void;
  failClosed(): void;
  hardStop(): never;
}>;

const PROCESS_PORT: ProductionMainPort = Object.freeze({
  start: (signal) => startProductionWorker({ signal }),
  on: (signal, listener) => process.on(signal, listener),
  off: (signal, listener) => process.off(signal, listener),
  setTimer: (callback, milliseconds) => setTimeout(callback, milliseconds),
  clearTimer: (timer) => clearTimeout(timer as NodeJS.Timeout),
  failClosed: () => {
    process.exitCode = 1;
  },
  hardStop: () => process.exit(1),
});

export async function runProductionMain(port: ProductionMainPort = PROCESS_PORT): Promise<void> {
  const controller = new AbortController();
  let runtime: ProductionWorkerRuntime | undefined;
  let closePromise: Promise<void> | undefined;
  let hardTimer: unknown;
  let failed = false;
  let cleanupUncertain = false;
  const armHardDeadline = () => {
    hardTimer ??= port.setTimer(() => port.hardStop(), HARD_SHUTDOWN_MS);
  };
  const markFailure = () => {
    cleanupUncertain = true;
    armHardDeadline();
    if (!failed) {
      failed = true;
      port.failClosed();
    }
  };
  const terminate = () => {
    armHardDeadline();
    controller.abort();
    closePromise ??= runtime?.close("signal") ?? Promise.resolve();
    closePromise.catch(markFailure);
  };
  port.on("SIGINT", terminate);
  port.on("SIGTERM", terminate);
  try {
    runtime = await port.start(controller.signal);
    if (controller.signal.aborted) terminate();
    await Promise.race([
      runtime.closed.catch(() => {
        markFailure();
      }),
      closePromise ?? new Promise<void>(() => undefined),
    ]);
  } catch {
    markFailure();
  } finally {
    controller.abort();
    if (runtime !== undefined) {
      closePromise ??= runtime.close(failed ? "startup-failed" : "requested");
      await closePromise.catch(markFailure);
    }
    if (hardTimer !== undefined && !cleanupUncertain) port.clearTimer(hardTimer);
    port.off("SIGINT", terminate);
    port.off("SIGTERM", terminate);
  }
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  void runProductionMain();
}
