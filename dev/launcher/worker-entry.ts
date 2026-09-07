import { joinCloseWork } from "../../src/launch/close.ts";
import { writeWorkerCleanupReceipt } from "./control.ts";
import { type LauncherState, resolveLauncherState } from "./state.ts";
import { createTrustedWorkerRuntime } from "./trusted-compose.ts";
import {
  createWorkerTerminationOwner,
  processWorkerChannel,
  runWorkerChild,
  type WorkerProvisionalRuntime,
} from "./worker-process.ts";

const shutdown = new AbortController();
const acquired = Promise.withResolvers<WorkerProvisionalRuntime>();
void acquired.promise.catch(() => undefined);
let deadline: NodeJS.Timeout | undefined;
// One termination AND receipt execution, published before abort listeners or runtime callbacks.
const beginTermination = createWorkerTerminationOwner(
  acquired.promise,
  () => {
    deadline = setTimeout(() => process.exit(1), 5_000);
    shutdown.abort();
  },
  async () => {
    const [, root, name, sourceRevision, extra] = process.argv.slice(2);
    if (root === undefined || name === undefined || sourceRevision === undefined || extra !== undefined)
      throw new Error("worker cleanup receipt unavailable");
    const state = await resolveLauncherState({ root, name, sourceRevision });
    await writeWorkerCleanupReceipt(state);
    if (deadline) clearTimeout(deadline);
    process.off("SIGTERM", onTerminate);
    process.exitCode = 0;
  },
);
const onTerminate = () => {
  void joinCloseWork(beginTermination()).catch(() => failClosed());
};
process.on("SIGTERM", onTerminate);

const trustedRuntimeFactory = Object.freeze((state: LauncherState, signal: AbortSignal) =>
  createTrustedWorkerRuntime(state, signal),
);

void runWorkerChild(process.argv.slice(2), processWorkerChannel(), trustedRuntimeFactory, {
  signal: shutdown.signal,
}).then(acquired.resolve, (error) => {
  acquired.reject(error);
  failClosed();
});

function failClosed(): void {
  process.off("SIGTERM", onTerminate);
  try {
    if (process.connected) process.disconnect();
  } catch {
    // The durable descriptor is preserved for recovery.
  }
  // Do not cancel the fallback on any failed/hung cleanup or missing receipt.
  process.exitCode = 1;
}
