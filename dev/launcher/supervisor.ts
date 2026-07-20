import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { join } from "node:path";
import { deepFreeze, type LauncherAuthority, type LauncherPhase, type LauncherProfile } from "./contract.ts";
import {
  beginWorkerStartup,
  cleanupControlFiles,
  createApiToken,
  type ReadyWorkerDescriptor,
  readReadyWorkerDescriptor,
  readWorkerDescriptor,
  requireSessionControlsAbsent,
  type WorkerDescriptor,
} from "./control.ts";
import { observeProcessIdentity } from "./runner.ts";
import type { LauncherState } from "./state.ts";
import { clearRecovery, markRecovery, readManifest, writePhase } from "./state.ts";
import { startWorkerProcess } from "./worker-process.ts";

export type SupervisorMetadata = Readonly<{
  version: "cogs.dev-launcher-supervisor/v1alpha1";
  stateId: string;
  profile: LauncherProfile;
  authority: LauncherAuthority;
  phase: LauncherPhase;
  apiPort?: number;
}>;

export type LauncherInventory = Readonly<{
  version: "cogs.dev-launcher-inventory/v1alpha1";
  stateId: string;
  profile: LauncherProfile;
  authority: LauncherAuthority;
  phase: LauncherPhase;
  descriptor: "none" | "starting" | "ready" | "malformed";
  workerLive: boolean | "unknown";
  recovery: "present" | "absent" | "unknown";
  cleanupRequired: boolean;
  driverState: "present" | "absent" | "unknown";
}>;

export type SupervisorSeams = Readonly<{
  identity(pid: number): string | null | undefined;
  signal(pid: number, signal: "SIGTERM"): boolean;
  now(): number;
  setTimer(callback: () => void, ms: number): unknown;
  clearTimer(timer: unknown): void;
  startWorkerProcess: typeof startWorkerProcess;
}>;

const defaultIdentity = Object.freeze(observeProcessIdentity);
const defaultSignal = Object.freeze((pid: number, signal: "SIGTERM") => process.kill(pid, signal));
const defaultNow = Object.freeze(() => Date.now());
const defaultSetTimer = Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms));
const defaultClearTimer = Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout));
const defaultStart = Object.freeze(startWorkerProcess);
const defaultSpawn = Object.freeze(((...args: Parameters<typeof spawn>) => spawn(...args)) as typeof spawn);
const abortSignalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const defaultSeams: SupervisorSeams = Object.freeze({
  identity: defaultIdentity,
  signal: defaultSignal,
  now: defaultNow,
  setTimer: defaultSetTimer,
  clearTimer: defaultClearTimer,
  startWorkerProcess: defaultStart,
});
const digestPattern = /^sha256:[a-f0-9]{64}$/u;
const waitMs = 10_000;
const pollMs = 25;

export async function startWorkerForState(
  state: LauncherState,
  signal?: AbortSignal,
  seams?: Partial<SupervisorSeams>,
): Promise<SupervisorMetadata> {
  const captured = captureSeams(seams);
  validateSignal(signal);
  if (isAborted(signal)) throw generic();
  let startup: Awaited<ReturnType<typeof beginWorkerStartup>> | undefined;
  try {
    const manifest = await readManifest(state);
    debugStartupStage("supervisor-manifest");
    if (manifest.phase !== "sandbox-ready" || manifest.sourceRevision !== state.sourceRevision) fail();
    if ((await recoveryState(state.recoveryPath)) !== "absent") fail();
    await requireSessionControlsAbsent(state);
    debugStartupStage("supervisor-controls");
    if (isAborted(signal)) throw generic();
    await createApiToken(state);
    debugStartupStage("supervisor-token");
    startup = await beginWorkerStartup(state, { identity: captured.identity });
    debugStartupStage("supervisor-startup-control");
    const ready = await captured.startWorkerProcess(state, startup, {
      ...(signal === undefined ? {} : { signal }),
      seams: workerSeams(captured),
    });
    debugStartupStage("supervisor-worker-process-return");
    const proof = await readReadyWorkerDescriptor(state);
    const promoted = await readManifest(state);
    if (promoted.phase !== "worker-ready" || promoted.sourceRevision !== state.sourceRevision) fail();
    validateReadyResult(ready, proof);
    return metadata(state, promoted.phase, promoted.profile, promoted.authority, proof.apiPort);
  } catch {
    startup?.startup.dispose();
    try {
      await cleanupControlFiles(state, { identity: captured.identity });
      const afterCleanup = await readManifest(state);
      if (afterCleanup.phase === "worker-ready") await writePhase(state, afterCleanup, "sandbox-ready");
    } catch {
      await markIfRecoveryAbsent(state, "worker-start-uncertain").catch(() => undefined);
    }
    throw generic();
  }
}

export async function stopWorkerForState(
  state: LauncherState,
  signal?: AbortSignal,
  seams?: Partial<SupervisorSeams>,
): Promise<SupervisorMetadata> {
  const captured = captureSeams(seams);
  validateSignal(signal);
  if (isAborted(signal)) throw generic();
  try {
    const manifest = await readManifest(state);
    if (manifest.sourceRevision !== state.sourceRevision) fail();
    if (manifest.phase === "sandbox-ready") {
      await cleanupControlFiles(state, { identity: captured.identity }).catch(async () => {
        await markIfRecoveryAbsent(state, "worker-stop-uncertain").catch(() => undefined);
        fail();
      });
      await clearRecovery(state);
      return metadata(state, manifest.phase, manifest.profile, manifest.authority);
    }
    if (manifest.phase !== "worker-ready") fail();
    const descriptor = await readReadyWorkerDescriptor(state);
    if (isAborted(signal)) throw generic();
    const identity = childIdentity(descriptor);
    const observed = captured.identity(identity.pid);
    if (observed === undefined || (observed !== null && !digestPattern.test(observed))) return await uncertain(state);
    let signaled = false;
    if (observed === identity.pidIdentity) {
      if (isAborted(signal)) throw generic();
      const boundary = captured.identity(identity.pid);
      if (boundary !== identity.pidIdentity) return await uncertain(state);
      if (captured.signal(identity.pid, "SIGTERM") !== true) return await uncertain(state);
      signaled = true;
    }
    if (signaled) await waitAbsentOrReused(captured, identity.pid, identity.pidIdentity);
    await cleanupControlFiles(state, { identity: captured.identity });
    const ready = await readManifest(state);
    const next = await writePhase(state, ready, "sandbox-ready");
    await clearRecovery(state);
    return metadata(state, next.phase, next.profile, next.authority);
  } catch {
    await markIfRecoveryAbsent(state, "worker-stop-uncertain").catch(() => undefined);
    throw generic();
  }
}

export async function launcherInventory(
  state: LauncherState,
  seams?: Partial<SupervisorSeams>,
): Promise<LauncherInventory> {
  const captured = captureSeams(seams);
  try {
    const manifest = await readManifest(state);
    const descriptor = await descriptorInventory(state, captured);
    const recovery = await recoveryState(state.recoveryPath);
    const driverState = await directoryState(state.driverStateDir);
    return deepFreeze({
      version: "cogs.dev-launcher-inventory/v1alpha1",
      stateId: state.stateId,
      profile: manifest.profile,
      authority: manifest.authority,
      phase: manifest.phase,
      descriptor: descriptor.class,
      workerLive: descriptor.live,
      recovery,
      cleanupRequired:
        manifest.phase === "worker-ready" ||
        manifest.phase === "cleanup-required" ||
        descriptor.class !== "none" ||
        descriptor.live === "unknown" ||
        recovery !== "absent" ||
        driverState === "unknown",
      driverState,
    });
  } catch {
    throw generic();
  }
}

async function descriptorInventory(
  state: LauncherState,
  seams: SupervisorSeams,
): Promise<{ class: LauncherInventory["descriptor"]; live: LauncherInventory["workerLive"] }> {
  try {
    await lstat(join(state.controlDir, "worker.json"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { class: "none", live: false };
    return { class: "malformed", live: "unknown" };
  }
  let descriptor: WorkerDescriptor;
  try {
    descriptor = await readWorkerDescriptor(state);
  } catch {
    return { class: "malformed", live: "unknown" };
  }
  const id =
    descriptor.readiness === "ready" || descriptor.stage === "child-bound"
      ? childIdentity(descriptor)
      : parentIdentity(descriptor);
  const observed = safeIdentity(seams, id.pid);
  return {
    class: descriptor.readiness === "ready" ? "ready" : "starting",
    live: observed === undefined ? "unknown" : observed === id.pidIdentity,
  };
}

async function waitAbsentOrReused(seams: SupervisorSeams, pid: number, pidIdentity: string): Promise<void> {
  let now = validNow(seams.now());
  const deadline = deadlineAt(now, waitMs);
  while (true) {
    const observed = safeIdentity(seams, pid);
    if (observed === null || (observed !== undefined && observed !== pidIdentity)) return;
    const nextNow = validNow(seams.now());
    if (nextNow < now) fail();
    now = nextNow;
    if (observed === undefined || now >= deadline) fail();
    await sleep(seams, Math.min(pollMs, deadline - now));
  }
}

function workerSeams(seams: SupervisorSeams) {
  return Object.freeze({
    spawn: defaultSpawn,
    identity: seams.identity,
    now: seams.now,
    setTimer: seams.setTimer,
    clearTimer: seams.clearTimer,
  });
}

function debugStartupStage(stage: string): void {
  if (process.env.COGS_LAUNCHER_DEBUG_STAGE === "1") process.stderr.write(`launcher-debug-stage:${stage}\n`);
}

async function uncertain(state: LauncherState): Promise<never> {
  await markIfRecoveryAbsent(state, "worker-stop-uncertain").catch(() => undefined);
  throw generic();
}

async function markIfRecoveryAbsent(state: LauncherState, reason: string): Promise<void> {
  if ((await recoveryState(state.recoveryPath)) === "absent") await markRecovery(state, reason);
}

function validateReadyResult(value: unknown, proof: ReadyWorkerDescriptor): void {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) fail();
  if (Object.getOwnPropertySymbols(value).length !== 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = [
    "apiPort",
    "authority",
    "childPid",
    "childPidIdentity",
    "parentPid",
    "parentPidIdentity",
    "profile",
    "readiness",
    "sourceRevision",
    "stage",
    "startupDigest",
    "stateId",
    "version",
  ];
  if (Object.keys(descriptors).sort().join(",") !== keys.sort().join(",")) fail();
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const item = descriptors[key];
    if (!item || !Object.hasOwn(item, "value") || !item.enumerable) fail();
    out[key] = item.value;
  }
  for (const key of keys) if (out[key] !== proof[key as keyof ReadyWorkerDescriptor]) fail();
}

function metadata(
  state: LauncherState,
  phase: LauncherPhase,
  profile: LauncherProfile,
  authority: LauncherAuthority,
  apiPort?: number,
): SupervisorMetadata {
  return deepFreeze({
    version: "cogs.dev-launcher-supervisor/v1alpha1",
    stateId: state.stateId,
    profile,
    authority,
    phase,
    ...(apiPort === undefined ? {} : { apiPort }),
  });
}

function childIdentity(descriptor: Extract<WorkerDescriptor, { stage: "child-bound" | "ready" }>): {
  pid: number;
  pidIdentity: string;
} {
  return { pid: descriptor.childPid, pidIdentity: descriptor.childPidIdentity };
}

function parentIdentity(descriptor: Extract<WorkerDescriptor, { stage: "pre-spawn" }>): {
  pid: number;
  pidIdentity: string;
} {
  return { pid: descriptor.parentPid, pidIdentity: descriptor.parentPidIdentity };
}

function captureSeams(input?: Partial<SupervisorSeams>): SupervisorSeams {
  if (input === undefined) return defaultSeams;
  if (
    !input ||
    typeof input !== "object" ||
    Object.getPrototypeOf(input) !== Object.prototype ||
    !Object.isFrozen(input)
  )
    fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Object.getOwnPropertySymbols(input).length !== 0) fail();
  const allowed = ["clearTimer", "identity", "now", "setTimer", "signal", "startWorkerProcess"];
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(descriptors)) {
    const item = descriptors[key];
    if (!allowed.includes(key) || !item || !Object.hasOwn(item, "value") || !item.enumerable) fail();
    out[key] = item.value;
  }
  const merged = { ...defaultSeams, ...out };
  for (const key of allowed) {
    const value = merged[key as keyof SupervisorSeams];
    if (typeof value !== "function" || !Object.isFrozen(value)) fail();
  }
  return Object.freeze(merged) as SupervisorSeams;
}

function validateSignal(signal: AbortSignal | undefined): void {
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail();
  if (typeof abortSignalAborted !== "function") fail();
}

function isAborted(signal: AbortSignal | undefined): boolean {
  if (signal === undefined) return false;
  try {
    return abortSignalAborted?.call(signal) === true;
  } catch {
    fail();
  }
}

function safeIdentity(seams: Pick<SupervisorSeams, "identity">, pid: number): string | null | undefined {
  try {
    const observed = seams.identity(pid);
    return observed === null || observed === undefined || (typeof observed === "string" && digestPattern.test(observed))
      ? observed
      : undefined;
  } catch {
    return undefined;
  }
}

async function recoveryState(path: string): Promise<"present" | "absent" | "unknown"> {
  try {
    const stat = await lstat(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o777) !== 0o600 ||
      (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) ||
      (await realpath(path)) !== path
    )
      return "unknown";
    const second = await lstat(path);
    if (
      second.dev !== stat.dev ||
      second.ino !== stat.ino ||
      !second.isFile() ||
      second.isSymbolicLink() ||
      second.nlink !== 1 ||
      (second.mode & 0o777) !== 0o600 ||
      (typeof process.geteuid === "function" && second.uid !== process.geteuid()) ||
      (await realpath(path)) !== path
    )
      return "unknown";
    return "present";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "absent" : "unknown";
  }
}

async function directoryState(path: string): Promise<"present" | "absent" | "unknown"> {
  try {
    const stat = await lstat(path);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.mode & 0o777) !== 0o700 ||
      (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) ||
      (await realpath(path)) !== path
    )
      return "unknown";
    const second = await lstat(path);
    if (
      second.dev !== stat.dev ||
      second.ino !== stat.ino ||
      !second.isDirectory() ||
      second.isSymbolicLink() ||
      (second.mode & 0o777) !== 0o700 ||
      (typeof process.geteuid === "function" && second.uid !== process.geteuid()) ||
      (await realpath(path)) !== path
    )
      return "unknown";
    return "present";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "absent" : "unknown";
  }
}

function sleep(seams: Pick<SupervisorSeams, "setTimer" | "clearTimer">, ms: number): Promise<void> {
  if (!Number.isSafeInteger(ms) || ms < 1 || ms > waitMs) fail();
  return new Promise((resolve, reject) => {
    let timer: unknown;
    let synchronous = true;
    let fired = false;
    let settled = false;
    const rejectOnce = () => {
      if (settled) return;
      settled = true;
      reject(generic());
    };
    try {
      timer = seams.setTimer(() => {
        if (settled || fired || synchronous) return rejectOnce();
        fired = true;
        try {
          seams.clearTimer(timer);
        } catch {
          rejectOnce();
          return;
        }
        settled = true;
        resolve();
      }, ms);
      synchronous = false;
    } catch {
      synchronous = false;
      rejectOnce();
    }
  });
}

function validNow(now: number): number {
  if (!Number.isSafeInteger(now) || now < 0) fail();
  return now;
}

function deadlineAt(now: number, ms: number): number {
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - ms) fail();
  return now + ms;
}

function fail(): never {
  throw generic();
}

function generic(): Error {
  return new Error("launcher supervisor failed");
}
