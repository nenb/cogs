import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  bindWorkerChild,
  promoteWorkerReady,
  type ReadyWorkerDescriptor,
  readReadyWorkerDescriptor,
  readWorkerDescriptor,
  type WorkerStartup,
} from "./control.ts";
import { observeProcessIdentity } from "./runner.ts";
import { type LauncherState, readManifest, resolveLauncherState } from "./state.ts";
import {
  createParentChallenge,
  createSupervisorAdmit,
  createSupervisorReadyAck,
  parseChildIdentityHello,
  parseChildReady,
  parseWorkerProtocolMessage,
  workerProtocolVersion,
} from "./worker-protocol.ts";

export type WorkerProvisionalRuntime = Readonly<{
  apiPort: number;
  close(): Promise<void>;
}>;

export type WorkerRuntimeFactory = (state: LauncherState, signal: AbortSignal) => Promise<WorkerProvisionalRuntime>;

export type WorkerChildChannel = Readonly<{
  connected(): boolean;
  send(message: unknown, callback: (error: Error | null) => void): void;
  onMessage(listener: (message: unknown) => void): void;
  offMessage(listener: (message: unknown) => void): void;
  onDisconnect(listener: () => void): void;
  offDisconnect(listener: () => void): void;
}>;

export type WorkerProcessSeams = Readonly<{
  spawn: typeof spawn;
  identity(pid: number): string | null | undefined;
  now(): number;
  setTimer(callback: () => void, ms: number): unknown;
  clearTimer(timer: unknown): void;
}>;

export type WorkerChildSeams = Readonly<{
  identity(pid: number): string | null | undefined;
  pid: number;
  now(): number;
  setTimer(callback: () => void, ms: number): unknown;
  clearTimer(timer: unknown): void;
}>;

const digestPattern = /^sha256:[a-f0-9]{64}$/u;
const sourcePattern = /^[a-f0-9]{40}$/u;
const workerMarker = "--cogs-launcher-worker-v1";
const moduleDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(moduleDir, "../..");
const workerEntry = resolve(moduleDir, "worker-entry.ts");
const tsxLoader = resolve(repoRoot, "node_modules/tsx/dist/loader.mjs");
const defaultTimeoutMs = 30_000;
const maxTimeoutMs = 900_000;
const defaultSpawn = Object.freeze(spawn);
const defaultIdentity = observeProcessIdentity;
const defaultSetTimer = Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms));
const defaultClearTimer = Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout));
const defaultNow = Object.freeze(() => Date.now());
const defaultProcessSeams: WorkerProcessSeams = Object.freeze({
  spawn: defaultSpawn,
  identity: defaultIdentity,
  now: defaultNow,
  setTimer: defaultSetTimer,
  clearTimer: defaultClearTimer,
});
const defaultChildSeams: WorkerChildSeams = Object.freeze({
  identity: defaultIdentity,
  pid: process.pid,
  now: defaultNow,
  setTimer: defaultSetTimer,
  clearTimer: defaultClearTimer,
});

export async function startWorkerProcess(
  state: LauncherState,
  startup: WorkerStartup,
  options: Readonly<{ timeoutMs?: number; signal?: AbortSignal; seams?: WorkerProcessSeams }> = Object.freeze({}),
): Promise<ReadyWorkerDescriptor> {
  const captured = processOptions(options);
  const deadline = deadlineAt(captured.seams.now(), captured.timeoutMs);
  let child: ChildProcess | undefined;
  let endpoint: WorkerEndpoint | undefined;
  let childPid: number | undefined;
  let childIdentity: string | undefined;
  let completed = false;
  let recovery = false;
  try {
    const before = await readWorkerDescriptor(state);
    const manifest = await readManifest(state);
    if (
      before.readiness !== "starting" ||
      before.stage !== "pre-spawn" ||
      before.sourceRevision !== state.sourceRevision ||
      manifest.sourceRevision !== state.sourceRevision ||
      JSON.stringify(before) !== JSON.stringify(startup.descriptor) ||
      startup.startup.digest() !== before.startupDigest
    )
      fail();
    child = captured.seams.spawn(
      workerProcessPaths.executable,
      [
        "--import",
        workerProcessPaths.loader,
        workerProcessPaths.entry,
        workerMarker,
        state.root,
        state.name,
        state.sourceRevision,
      ],
      {
        cwd: workerProcessPaths.cwd,
        env: {},
        shell: false,
        stdio: ["ignore", "ignore", "ignore", "ipc"],
        windowsHide: true,
      },
    );
    endpoint = childEndpoint(child);
    const worker = endpoint;
    childPid = worker.pid;
    childIdentity = exactIdentity(captured.seams.identity(childPid));
    const startupDelayMs = remainingMs(deadline, captured.seams.now());
    const ready = await new Promise<ReadyWorkerDescriptor>((resolveReady, rejectReady) => {
      let settled = false;
      let generation = 0;
      let processing = false;
      let messages = 0;
      let timer: unknown;
      let timerArmed = false;
      let stage: "hello" | "ready" = "hello";
      const active = (turn: number) => !settled && generation === turn;
      const finish = (error?: Error, descriptor?: ReadyWorkerDescriptor) => {
        if (settled) return;
        settled = true;
        generation += 1;
        completed = descriptor !== undefined;
        let cleanupFailed = timerArmed && !safeClear(captured.seams, timer);
        timerArmed = false;
        try {
          captured.signal?.removeEventListener("abort", onAbort);
          worker.off("message", onMessage);
          worker.off("disconnect", onFailure);
          worker.off("error", onFailure);
          worker.off("exit", onFailure);
        } catch {
          cleanupFailed = true;
        }
        if (cleanupFailed) rejectReady(recoveryRequired());
        else if (error) rejectReady(error);
        else if (descriptor) resolveReady(descriptor);
        else rejectReady(generic());
      };
      const onFailure = () => finish(recovery ? recoveryRequired() : generic());
      const onAbort = () => finish(recovery ? recoveryRequired() : generic());
      const send = (message: unknown, delivered?: () => void) => {
        try {
          if (settled || !worker.connected()) return finish(recovery ? recoveryRequired() : generic());
          worker.send(message, (error) => {
            if (settled) return;
            if (error) finish(recovery ? recoveryRequired() : generic());
            else delivered?.();
          });
        } catch {
          finish(recovery ? recoveryRequired() : generic());
        }
      };
      const onMessage = (value: unknown) => {
        if (settled || processing || ++messages > 2) return finish(recoveryRequired());
        processing = true;
        const turn = generation;
        void (async () => {
          if (stage === "hello") {
            const hello = parseChildIdentityHello(value);
            if (
              hello.pid !== childPid ||
              hello.pidIdentity !== childIdentity ||
              exactIdentity(captured.seams.identity(childPid)) !== childIdentity ||
              !active(turn)
            )
              fail();
            recovery = true;
            const bound = await bindWorkerChild(state, hello, { identity: captured.seams.identity });
            if (!active(turn)) return;
            if (
              bound.stage !== "child-bound" ||
              bound.childPid !== childPid ||
              bound.childPidIdentity !== childIdentity ||
              exactIdentity(captured.seams.identity(childPid)) !== childIdentity
            )
              fail();
            stage = "ready";
            if (!active(turn)) return;
            send(createSupervisorAdmit(bound.startupDigest));
            return;
          }
          const readyMessage = parseChildReady(value);
          if (
            readyMessage.pid !== childPid ||
            readyMessage.pidIdentity !== childIdentity ||
            exactIdentity(captured.seams.identity(childPid)) !== childIdentity ||
            !active(turn)
          )
            fail();
          recovery = true;
          const descriptor = await promoteWorkerReady(state, readyMessage, { identity: captured.seams.identity });
          if (!active(turn)) return;
          if (exactIdentity(captured.seams.identity(childPid)) !== childIdentity) fail();
          const jointlyReady = await readReadyWorkerDescriptor(state);
          if (!active(turn)) return;
          const readyManifest = await readManifest(state);
          if (!active(turn)) return;
          if (
            readyManifest.phase !== "worker-ready" ||
            readyManifest.sourceRevision !== state.sourceRevision ||
            descriptor.sourceRevision !== state.sourceRevision ||
            JSON.stringify(jointlyReady) !== JSON.stringify(descriptor) ||
            exactIdentity(captured.seams.identity(childPid)) !== childIdentity
          )
            fail();
          if (!active(turn)) return;
          send(createSupervisorReadyAck(descriptor.startupDigest), () => {
            if (active(turn)) finish(undefined, descriptor);
          });
        })()
          .catch(() => finish(recovery ? recoveryRequired() : generic()))
          .finally(() => {
            processing = false;
          });
      };
      try {
        worker.on("message", onMessage);
        worker.on("disconnect", onFailure);
        worker.on("error", onFailure);
        worker.on("exit", onFailure);
        if (captured.signal) captured.signal.addEventListener("abort", onAbort, { once: true });
      } catch {
        return finish(generic());
      }
      if (captured.signal?.aborted) return onAbort();
      if (
        !armTimer(
          captured.seams,
          startupDelayMs,
          () => onFailure(),
          (value) => {
            timer = value;
            timerArmed = true;
          },
        )
      )
        return finish(generic());
      send(createParentChallenge(startup.startup));
    });
    if (!disconnectEndpoint(worker) || !unrefEndpoint(worker)) {
      recovery = true;
      throw recoveryRequired();
    }
    startup.startup.dispose();
    return ready;
  } catch {
    startup.startup.dispose();
    if (child && childPid && childIdentity && !completed) {
      const observed = safeIdentity(captured.seams, childPid);
      if (observed === childIdentity) {
        recovery = true;
        try {
          if (exactIdentity(captured.seams.identity(childPid)) === childIdentity) endpoint?.kill("SIGTERM");
        } catch {
          // Identity was uncertain at the exact signal boundary; preserve controls.
        }
      } else if (observed !== null) {
        recovery = true;
      }
    } else if (child && !completed) {
      recovery = true;
    }
    const disconnected = endpoint ? disconnectEndpoint(endpoint) : disconnectChild(child);
    if (!disconnected) recovery = true;
    throw recovery ? recoveryRequired() : generic();
  }
}

export async function runWorkerChild(
  argv: readonly string[],
  channel: WorkerChildChannel,
  runtimeFactory: WorkerRuntimeFactory,
  options: Readonly<{ timeoutMs?: number; signal?: AbortSignal; seams?: WorkerChildSeams }> = Object.freeze({}),
): Promise<WorkerProvisionalRuntime> {
  validateFrozenFunction(runtimeFactory);
  validateChannel(channel);
  const captured = childOptions(options);
  const deadline = deadlineAt(captured.seams.now(), captured.timeoutMs);
  const state = await parseWorkerCoordinates(argv);
  const descriptor = await readWorkerDescriptor(state);
  const manifest = await readManifest(state);
  if (
    descriptor.readiness !== "starting" ||
    descriptor.stage !== "pre-spawn" ||
    descriptor.sourceRevision !== state.sourceRevision ||
    manifest.sourceRevision !== state.sourceRevision ||
    exactIdentity(captured.seams.identity(descriptor.parentPid)) !== descriptor.parentPidIdentity ||
    !channel.connected()
  )
    fail();
  const selfIdentity = exactIdentity(captured.seams.identity(captured.seams.pid));
  const startupDelayMs = remainingMs(deadline, captured.seams.now());
  const runtimeAbort = new AbortController();
  let runtime: WorkerProvisionalRuntime | undefined;
  let closePromise: Promise<void> | undefined;
  let recovery = false;
  let acknowledged = false;
  const closeOnce = (): Promise<void> => {
    if (!runtime) return Promise.resolve();
    closePromise ??= runtime.close();
    return closePromise;
  };
  try {
    return await new Promise<WorkerProvisionalRuntime>((resolveRuntime, rejectRuntime) => {
      let settled = false;
      let generation = 0;
      let processing = false;
      let checkingDurableReady = false;
      let messageCount = 0;
      let timer: unknown;
      let timerArmed = false;
      let stage: "challenge" | "admit" | "ack" = "challenge";
      const active = (turn: number) => !settled && generation === turn;
      const cleanupListeners = (keepAbort: boolean): boolean => {
        let failed = timerArmed && !safeClear(captured.seams, timer);
        timerArmed = false;
        try {
          channel.offMessage(onMessage);
          channel.offDisconnect(onDisconnect);
          if (!keepAbort) captured.signal?.removeEventListener("abort", onExternalAbort);
        } catch {
          failed = true;
        }
        return !failed;
      };
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        generation += 1;
        const keepAbort = !error && acknowledged;
        if (!cleanupListeners(keepAbort)) rejectRuntime(recoveryRequired());
        else if (error) rejectRuntime(error);
        else if (runtime) resolveRuntime(runtime);
        else rejectRuntime(generic());
      };
      const abortAndRecover = () => {
        if (settled) return;
        recovery = recovery || stage !== "challenge";
        runtimeAbort.abort();
        generation += 1;
        if (runtime) void closeOnce().catch(() => undefined);
        finish(recovery ? recoveryRequired() : generic());
      };
      const acceptDurableReady = async (turn: number): Promise<boolean> => {
        const ready = await readReadyWorkerDescriptor(state);
        if (!active(turn)) return false;
        const readyManifest = await readManifest(state);
        if (!active(turn)) return false;
        if (
          readyManifest.phase !== "worker-ready" ||
          readyManifest.sourceRevision !== state.sourceRevision ||
          ready.sourceRevision !== state.sourceRevision ||
          ready.startupDigest !== descriptor.startupDigest ||
          ready.childPid !== captured.seams.pid ||
          ready.childPidIdentity !== selfIdentity ||
          exactIdentity(captured.seams.identity(captured.seams.pid)) !== selfIdentity
        )
          fail();
        acknowledged = true;
        finish();
        return true;
      };
      const onDisconnect = () => {
        if (settled || acknowledged) return;
        if (stage !== "ack" || !runtime) return abortAndRecover();
        const turn = generation;
        processing = true;
        checkingDurableReady = true;
        void acceptDurableReady(turn)
          .then((accepted) => {
            if (!accepted && active(turn)) abortAndRecover();
          })
          .catch(() => {
            if (active(turn)) abortAndRecover();
          })
          .finally(() => {
            checkingDurableReady = false;
            processing = false;
          });
      };
      const onExternalAbort = () => abortAndRecover();
      const send = (message: unknown) => {
        if (settled || !channel.connected()) return onDisconnect();
        try {
          channel.send(message, (error) => {
            if (!settled && error) onDisconnect();
          });
        } catch {
          onDisconnect();
        }
      };
      const onMessage = (value: unknown) => {
        if (settled || checkingDurableReady) return;
        if (processing || ++messageCount > 3) return abortAndRecover();
        processing = true;
        const turn = generation;
        void (async () => {
          const message = parseWorkerProtocolMessage(value);
          if (stage === "challenge" && message.type === "parent-challenge") {
            if (digestNonce(message.startupNonce) !== descriptor.startupDigest || !active(turn)) fail();
            stage = "admit";
            if (!active(turn)) return;
            send({
              version: workerProtocolVersion,
              type: "child-identity",
              startupDigest: descriptor.startupDigest,
              pid: captured.seams.pid,
              pidIdentity: selfIdentity,
            });
            return;
          }
          if (stage === "admit" && message.type === "supervisor-admit") {
            if (message.startupDigest !== descriptor.startupDigest || !active(turn)) fail();
            const bound = await readWorkerDescriptor(state);
            if (!active(turn)) return;
            const boundManifest = await readManifest(state);
            if (!active(turn)) return;
            if (
              bound.readiness !== "starting" ||
              bound.stage !== "child-bound" ||
              bound.sourceRevision !== state.sourceRevision ||
              boundManifest.sourceRevision !== state.sourceRevision ||
              bound.childPid !== captured.seams.pid ||
              bound.childPidIdentity !== selfIdentity ||
              exactIdentity(captured.seams.identity(bound.parentPid)) !== bound.parentPidIdentity ||
              exactIdentity(captured.seams.identity(captured.seams.pid)) !== selfIdentity
            )
              fail();
            recovery = true;
            stage = "ack";
            const candidate = await runtimeFactory(state, runtimeAbort.signal);
            let provisional: WorkerProvisionalRuntime;
            try {
              provisional = runtimePort(candidate);
            } catch {
              throw recoveryRequired();
            }
            if (!active(turn) || runtimeAbort.signal.aborted) {
              runtime = provisional;
              void closeOnce().catch(() => undefined);
              return;
            }
            if (exactIdentity(captured.seams.identity(captured.seams.pid)) !== selfIdentity) {
              runtime = provisional;
              abortAndRecover();
              return;
            }
            runtime = provisional;
            if (!active(turn)) {
              void closeOnce().catch(() => undefined);
              return;
            }
            send({
              version: workerProtocolVersion,
              type: "child-ready",
              startupDigest: bound.startupDigest,
              pid: bound.childPid,
              pidIdentity: bound.childPidIdentity,
              apiPort: runtime.apiPort,
            });
            return;
          }
          if (stage === "ack" && message.type === "supervisor-ready-ack") {
            if (message.startupDigest !== descriptor.startupDigest || !runtime || !active(turn)) fail();
            await acceptDurableReady(turn);
            return;
          }
          fail();
        })()
          .catch(() => {
            if (active(turn)) abortAndRecover();
          })
          .finally(() => {
            processing = false;
          });
      };
      try {
        channel.onMessage(onMessage);
        channel.onDisconnect(onDisconnect);
        if (captured.signal) captured.signal.addEventListener("abort", onExternalAbort, { once: true });
      } catch {
        return abortAndRecover();
      }
      if (captured.signal?.aborted) return onExternalAbort();
      if (
        !armTimer(captured.seams, startupDelayMs, abortAndRecover, (value) => {
          timer = value;
          timerArmed = true;
        })
      )
        return abortAndRecover();
    });
  } catch {
    runtimeAbort.abort();
    if (runtime && !closePromise) void closeOnce().catch(() => undefined);
    throw recovery ? recoveryRequired() : generic();
  }
}

export function processWorkerChannel(): WorkerChildChannel {
  const send = process.send;
  if (typeof send !== "function") throw generic();
  return Object.freeze({
    connected: Object.freeze(() => process.connected === true),
    send: Object.freeze((message: unknown, callback: (error: Error | null) => void) => {
      send.call(process, message, callback);
    }),
    onMessage: Object.freeze((listener: (message: unknown) => void) => process.on("message", listener)),
    offMessage: Object.freeze((listener: (message: unknown) => void) => process.off("message", listener)),
    onDisconnect: Object.freeze((listener: () => void) => process.on("disconnect", listener)),
    offDisconnect: Object.freeze((listener: () => void) => process.off("disconnect", listener)),
  });
}

export function unavailableWorkerRuntime(
  _state: LauncherState,
  _signal: AbortSignal,
): Promise<WorkerProvisionalRuntime> {
  return Promise.reject(generic());
}

async function parseWorkerCoordinates(argv: readonly string[]): Promise<LauncherState> {
  if (!Array.isArray(argv) || Object.getPrototypeOf(argv) !== Array.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(argv);
  if (Object.getOwnPropertyDescriptor(argv, "length")?.value !== 4 || Reflect.ownKeys(descriptors).length !== 5) fail();
  const values: string[] = [];
  for (let index = 0; index < 4; index += 1) {
    const item = descriptors[String(index)];
    if (!item || !("value" in item) || !item.enumerable || typeof item.value !== "string") fail();
    values.push(item.value);
  }
  if (values[0] !== workerMarker || !values[1]?.startsWith("/") || !sourcePattern.test(values[3] ?? "")) fail();
  const state = await resolveLauncherState({ root: values[1], name: values[2] ?? "", sourceRevision: values[3] ?? "" });
  if (state.root !== values[1]) fail();
  return state;
}

function processOptions(options: Readonly<{ timeoutMs?: number; signal?: AbortSignal; seams?: WorkerProcessSeams }>) {
  const value = exactOptions(options, ["seams", "signal", "timeoutMs"]);
  const timeoutMs = timeout(value.timeoutMs);
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) fail();
  const seams = (value.seams ?? defaultProcessSeams) as WorkerProcessSeams;
  validateSeams(seams, ["clearTimer", "identity", "now", "setTimer", "spawn"]);
  return { timeoutMs, signal: value.signal as AbortSignal | undefined, seams };
}

function childOptions(options: Readonly<{ timeoutMs?: number; signal?: AbortSignal; seams?: WorkerChildSeams }>) {
  const value = exactOptions(options, ["seams", "signal", "timeoutMs"]);
  const seams = (value.seams ?? defaultChildSeams) as WorkerChildSeams;
  validateSeams(seams, ["clearTimer", "identity", "now", "pid", "setTimer"]);
  if (!Number.isSafeInteger(seams.pid) || seams.pid < 1 || seams.pid > 2 ** 31 - 1) fail();
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) fail();
  return { timeoutMs: timeout(value.timeoutMs), signal: value.signal as AbortSignal | undefined, seams };
}

function exactOptions(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0) fail();
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(descriptors)) {
    const item = descriptors[key];
    if (!allowed.includes(key) || !item || !("value" in item) || !item.enumerable) fail();
    out[key] = item.value;
  }
  return out;
}

function validateSeams(value: unknown, keys: readonly string[]): void {
  if (
    !value ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !Object.isFrozen(value)
  )
    fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).sort().join(",") !== [...keys].sort().join(",")) fail();
  for (const key of keys) {
    const item = descriptors[key];
    if (!item || !("value" in item) || !item.enumerable) fail();
    if (key !== "pid" && (typeof item.value !== "function" || !Object.isFrozen(item.value))) fail();
  }
}

function validateFrozenFunction(value: unknown): asserts value is (...args: never[]) => unknown {
  if (typeof value !== "function" || !Object.isFrozen(value)) fail();
}

type WorkerEndpoint = Readonly<{
  pid: number;
  connected(): boolean;
  send(message: unknown, callback: (error: Error | null) => void): void;
  on(event: string, listener: (...args: never[]) => void): void;
  off(event: string, listener: (...args: never[]) => void): void;
  disconnect(): void;
  unref(): void;
  kill(signal: NodeJS.Signals): boolean;
}>;

function childEndpoint(child: ChildProcess): WorkerEndpoint {
  const pidDescriptor = Object.getOwnPropertyDescriptor(child, "pid");
  const pid = pidDescriptor && "value" in pidDescriptor ? pidDescriptor.value : undefined;
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2 ** 31 - 1) fail();
  const send = bindChildMethod(child, "send");
  const on = bindChildMethod(child, "on");
  const off = bindChildMethod(child, "off");
  const disconnect = bindChildMethod(child, "disconnect");
  const unref = bindChildMethod(child, "unref");
  const kill = bindChildMethod(child, "kill");
  return Object.freeze({
    pid,
    connected: Object.freeze(() => child.connected === true),
    send: Object.freeze((message: unknown, callback: (error: Error | null) => void) => {
      send(message, callback);
    }),
    on: Object.freeze((event: string, listener: (...args: never[]) => void) => {
      on(event, listener);
    }),
    off: Object.freeze((event: string, listener: (...args: never[]) => void) => {
      off(event, listener);
    }),
    disconnect: Object.freeze(() => {
      disconnect();
    }),
    unref: Object.freeze(() => {
      unref();
    }),
    kill: Object.freeze((signal: NodeJS.Signals) => kill(signal) === true),
  });
}

function bindChildMethod(child: ChildProcess, name: string): (...args: unknown[]) => unknown {
  let current: object | null = child;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") fail();
      return descriptor.value.bind(child) as (...args: unknown[]) => unknown;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  fail();
}

function validateChannel(value: WorkerChildChannel): void {
  validateSeams(value, ["connected", "offDisconnect", "offMessage", "onDisconnect", "onMessage", "send"]);
}

function runtimePort(value: unknown): WorkerProvisionalRuntime {
  if (
    !value ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !Object.isFrozen(value)
  )
    fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).sort().join(",") !== "apiPort,close") fail();
  const apiPort = descriptors.apiPort?.value;
  const close = descriptors.close?.value;
  if (
    !Number.isSafeInteger(apiPort) ||
    apiPort < 1 ||
    apiPort > 65535 ||
    typeof close !== "function" ||
    !Object.isFrozen(close)
  )
    fail();
  let closing: Promise<void> | undefined;
  const closeOnce = Object.freeze(async () => {
    closing ??= Promise.resolve().then(() => close.call(value));
    await closing;
  });
  return Object.freeze({ apiPort, close: closeOnce });
}

function digestNonce(nonce: string): string {
  let decoded: Buffer | undefined;
  try {
    decoded = Buffer.from(nonce, "base64url");
    return `sha256:${createHash("sha256").update(decoded).digest("hex")}`;
  } finally {
    decoded?.fill(0);
  }
}

function exactIdentity(value: string | null | undefined): string {
  if (typeof value !== "string" || !digestPattern.test(value)) fail();
  return value;
}

function safeIdentity(seams: WorkerProcessSeams, pid: number): string | null | undefined {
  try {
    const value = seams.identity(pid);
    return value === null || value === undefined || (typeof value === "string" && digestPattern.test(value))
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}

function timeout(value: unknown): number {
  const result = value ?? defaultTimeoutMs;
  if (!Number.isSafeInteger(result) || (result as number) < 1 || (result as number) > maxTimeoutMs) fail();
  return result as number;
}

function deadlineAt(now: number, timeoutMs: number): number {
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - timeoutMs) fail();
  return now + timeoutMs;
}

function remainingMs(deadline: number, now: number): number {
  if (!Number.isSafeInteger(now) || now < 0) fail();
  const remaining = deadline - now;
  if (!Number.isSafeInteger(remaining) || remaining < 1 || remaining > maxTimeoutMs) fail();
  return remaining;
}

function armTimer(
  seams: Pick<WorkerProcessSeams, "setTimer" | "clearTimer">,
  ms: number,
  callback: () => void,
  armed: (timer: unknown) => void,
): boolean {
  let synchronous = true;
  let firedSynchronously = false;
  let timer: unknown;
  try {
    timer = seams.setTimer(() => {
      if (synchronous) firedSynchronously = true;
      else callback();
    }, ms);
    synchronous = false;
    armed(timer);
    if (firedSynchronously) {
      if (!safeClear(seams, timer)) return false;
      callback();
      return false;
    }
    return true;
  } catch {
    synchronous = false;
    if (timer !== undefined) safeClear(seams, timer);
    return false;
  }
}

function safeClear(seams: Pick<WorkerProcessSeams, "clearTimer">, timer: unknown): boolean {
  try {
    seams.clearTimer(timer);
    return true;
  } catch {
    return false;
  }
}

function disconnectEndpoint(endpoint: WorkerEndpoint): boolean {
  try {
    if (!endpoint.connected()) return true;
    endpoint.disconnect();
    return !endpoint.connected();
  } catch {
    return false;
  }
}

function unrefEndpoint(endpoint: WorkerEndpoint): boolean {
  try {
    endpoint.unref();
    return true;
  } catch {
    return false;
  }
}

function disconnectChild(child: ChildProcess | undefined): boolean {
  if (!child) return true;
  try {
    if (!child.connected) return true;
    child.disconnect();
    return (child as unknown as { connected: boolean }).connected === false;
  } catch {
    return false;
  }
}

function fail(): never {
  throw generic();
}

function generic(): Error {
  return new Error("launcher worker process failed");
}

function recoveryRequired(): Error {
  return new Error("launcher worker process recovery required");
}

export const workerProcessPaths = Object.freeze({
  executable: realpathSync(process.execPath),
  loader: realpathSync(tsxLoader),
  entry: realpathSync(workerEntry),
  cwd: realpathSync(repoRoot),
});
