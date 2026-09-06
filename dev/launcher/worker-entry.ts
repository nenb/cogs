import { writeWorkerCleanupReceipt } from "./control.ts";
import { type LauncherState, resolveLauncherState } from "./state.ts";
import { createTrustedWorkerRuntime } from "./trusted-compose.ts";
import { processWorkerChannel, runWorkerChild, type WorkerProvisionalRuntime } from "./worker-process.ts";

const shutdown = new AbortController();
let runtime: WorkerProvisionalRuntime | undefined;
let closing: Promise<void> | undefined;
let deadline: NodeJS.Timeout | undefined;
const onTerminate = () => {
  shutdown.abort();
  deadline ??= setTimeout(() => process.exit(1), 5_000);
  if (runtime) void closeRuntime();
};
process.on("SIGTERM", onTerminate);

const trustedRuntimeFactory = Object.freeze((state: LauncherState, signal: AbortSignal) =>
  createTrustedWorkerRuntime(state, signal),
);

void runWorkerChild(process.argv.slice(2), processWorkerChannel(), trustedRuntimeFactory, {
  signal: shutdown.signal,
}).then(
  (handle) => {
    runtime = handle;
    if (shutdown.signal.aborted) void closeRuntime();
  },
  () => failClosed(),
);

async function closeRuntime(): Promise<void> {
  if (!runtime) return;
  closing ??= runtime.close();
  try {
    await closing;
    const [, root, name, sourceRevision, extra] = process.argv.slice(2);
    if (root === undefined || name === undefined || sourceRevision === undefined || extra !== undefined)
      throw new Error("worker cleanup receipt unavailable");
    const state = await resolveLauncherState({ root, name, sourceRevision });
    await writeWorkerCleanupReceipt(state);
    if (deadline) clearTimeout(deadline);
    process.off("SIGTERM", onTerminate);
    process.exitCode = 0;
  } catch {
    failClosed();
  }
}

function failClosed(): void {
  process.off("SIGTERM", onTerminate);
  try {
    if (process.connected) process.disconnect();
  } catch {
    // The durable descriptor is preserved for recovery.
  }
  process.exitCode = 1;
}
