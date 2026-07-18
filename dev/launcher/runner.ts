import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Readable } from "node:stream";

export type CommandDescriptor = Readonly<{
  executable: string;
  args: readonly string[];
  cwd: string;
  env: Readonly<Record<string, string>>;
  timeoutMs: number;
  maxOutputBytes: number;
  killGraceMs: number;
}>;

export type RunnerResult = Readonly<{
  status: "ok" | "failed" | "timeout" | "aborted";
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  cleanupUncertain: boolean;
}>;

export type RunnerSeams = Readonly<{
  spawn: typeof spawn;
  setTimer: (ms: number, cb: () => void) => { unref?: () => void; close?: () => void; [Symbol.dispose]?: () => void };
  clearTimer: (timer: unknown) => void;
  kill: (pid: number, signal: NodeJS.Signals) => boolean;
  identity: (pid: number) => string | null | undefined;
}>;

const defaultSpawn = Object.freeze(((command: string, args?: readonly string[], options?: unknown) =>
  args ? spawn(command, args, options as never) : spawn(command)) as unknown as typeof spawn);
const defaultSetTimer = Object.freeze((ms: number, cb: () => void) => {
  const timer = setTimeout(cb, ms);
  timer.unref();
  return timer;
});
const defaultClearTimer = Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout));
const defaultKill = Object.freeze((pid: number, signal: NodeJS.Signals) => {
  try {
    process.kill(pid, signal);
    return true;
  } catch {
    return false;
  }
});
export const observeProcessIdentity = Object.freeze((pid: number) => {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2 ** 31 - 1) return null;
  if (process.platform === "linux") {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const tail = stat
        .slice(stat.lastIndexOf(")") + 2)
        .trim()
        .split(/\s+/u);
      return tail[19] ? identityDigest(pid, `linux:${tail[19]}`) : undefined;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT" ? null : undefined;
    }
  }
  if (process.platform === "darwin") {
    try {
      const out = spawnSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
        encoding: "utf8",
        shell: false,
        timeout: 1000,
        maxBuffer: 256,
      });
      if (out.error || out.signal) return undefined;
      if (out.status === 1) return null;
      if (out.status !== 0) return undefined;
      const start = out.stdout.trim().replace(/\s+/gu, " ");
      return start.length > 0 && start.length < 96 ? identityDigest(pid, `darwin:${start}`) : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
});
function identityDigest(pid: number, observed: string): string {
  return `sha256:${createHash("sha256").update(`${pid}\0${observed}`).digest("hex")}`;
}
const defaultSeams: RunnerSeams = Object.freeze({
  spawn: defaultSpawn,
  setTimer: defaultSetTimer,
  clearTimer: defaultClearTimer,
  kill: defaultKill,
  identity: observeProcessIdentity,
});

export function commandDescriptor(input: CommandDescriptor): CommandDescriptor {
  const inputRecord = snapshotCommand(input);
  if (!inputRecord.executable.startsWith("/")) throw new Error("invalid launcher command");
  if (!inputRecord.cwd.startsWith("/")) throw new Error("invalid launcher command");
  if (!Number.isSafeInteger(inputRecord.timeoutMs) || inputRecord.timeoutMs < 1 || inputRecord.timeoutMs > 900_000)
    throw new Error("invalid launcher command");
  if (
    !Number.isSafeInteger(inputRecord.maxOutputBytes) ||
    inputRecord.maxOutputBytes < 0 ||
    inputRecord.maxOutputBytes > 1024 * 1024
  )
    throw new Error("invalid launcher command");
  if (
    !Number.isSafeInteger(inputRecord.killGraceMs) ||
    inputRecord.killGraceMs < 1 ||
    inputRecord.killGraceMs > 120_000
  )
    throw new Error("invalid launcher command");
  const args = inputRecord.args;
  const env = inputRecord.env;
  return Object.freeze({
    executable: inputRecord.executable,
    args: Object.freeze(args),
    cwd: inputRecord.cwd,
    env: Object.freeze(env),
    timeoutMs: inputRecord.timeoutMs,
    maxOutputBytes: inputRecord.maxOutputBytes,
    killGraceMs: inputRecord.killGraceMs,
  });
}

export async function runCommand(
  descriptor: CommandDescriptor,
  options: { signal?: AbortSignal; seams?: RunnerSeams } = {},
): Promise<RunnerResult> {
  const runOptions = snapshotRunOptions(options);
  const command = commandDescriptor(descriptor);
  const seams = validateSeams(runOptions.seams);
  const stdout = new BoundedText(command.maxOutputBytes);
  const stderr = new BoundedText(command.maxOutputBytes);
  let child: {
    pid: number | undefined;
    stdout: Readable;
    stderr: Readable;
    once: (event: string, cb: (...args: never[]) => void) => unknown;
  };
  try {
    child = seams.spawn(command.executable, [...command.args], {
      cwd: command.cwd,
      env: cloneEnv(command.env),
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    }) as typeof child;
  } catch {
    return result("failed", null, null, stdout, stderr);
  }

  const childSnapshot = snapshotChild(child);
  if (!childSnapshot) return result("failed", null, null, stdout, stderr, true);
  const { pid, stdout: childStdout, stderr: childStderr, once } = childSnapshot;
  const identity = safeIdentity(seams, pid);
  if (!identity)
    return await waitUnidentifiedClose(
      command,
      seams,
      once,
      childStdout,
      childStderr,
      stdout,
      stderr,
      runOptions.signal,
    );
  if (!isReadable(childStdout) || !isReadable(childStderr) || typeof once !== "function") {
    safeKill(seams, process.platform === "win32" ? pid : -pid, "SIGKILL", identity);
    return result("failed", null, null, stdout, stderr, true);
  }

  let terminal: "timeout" | "aborted" | undefined;
  let graceTimer: unknown;
  let closeTimer: unknown;
  let cleanupUncertain = false;
  let forceFinish: ((exitCode: number | null, signal: NodeJS.Signals | null) => void) | undefined;
  const killPid = process.platform === "win32" ? pid : -pid;
  let timeout: unknown;
  const terminate = (kind: "timeout" | "aborted") => {
    if (terminal) return;
    terminal = kind;
    if (timeout && !safeClear(seams, timeout)) cleanupUncertain = true;
    if (!safeKill(seams, killPid, "SIGTERM", identity)) cleanupUncertain = true;
    graceTimer = safeTimer(seams, command.killGraceMs, () => {
      if (!safeKill(seams, killPid, "SIGKILL", identity)) cleanupUncertain = true;
      closeTimer = safeTimer(seams, command.killGraceMs, () => {
        cleanupUncertain = true;
        forceFinish?.(null, "SIGKILL");
      });
      if (!closeTimer) cleanupUncertain = true;
    });
    if (!graceTimer) {
      cleanupUncertain = true;
      queueMicrotask(() => forceFinish?.(null, "SIGKILL"));
    }
  };
  const abort = () => terminate("aborted");

  return await new Promise<RunnerResult>((resolve) => {
    let settled = false;
    const finish = (exitCode: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      if (timeout && !safeClear(seams, timeout)) cleanupUncertain = true;
      if (graceTimer && !safeClear(seams, graceTimer)) cleanupUncertain = true;
      if (closeTimer && !safeClear(seams, closeTimer)) cleanupUncertain = true;
      cleanupUncertain = safeRemoveAbort(runOptions.signal, abort) ? cleanupUncertain : true;
      const status = terminal ?? (exitCode === 0 ? "ok" : "failed");
      resolve(result(status, exitCode, signal, stdout, stderr, cleanupUncertain));
    };
    forceFinish = finish;
    try {
      childStdout.on("data", (chunk: unknown) => stdout.append(chunk));
      childStderr.on("data", (chunk: unknown) => stderr.append(chunk));
      once("error", () => finish(null, null));
      once("close", finish);
      timeout = safeTimer(seams, command.timeoutMs, () => terminate("timeout"));
      if (!timeout) {
        cleanupUncertain = true;
        terminate("timeout");
      }
      if (!safeAddAbort(runOptions.signal, abort)) cleanupUncertain = true;
      if (safeAborted(runOptions.signal)) abort();
    } catch {
      cleanupUncertain = true;
      terminate("aborted");
      queueMicrotask(() => forceFinish?.(null, "SIGKILL"));
    }
  });
}

async function waitUnidentifiedClose(
  command: CommandDescriptor,
  seams: RunnerSeams,
  once: (event: string, cb: (...args: never[]) => void) => unknown,
  childStdout: Readable,
  childStderr: Readable,
  stdout: BoundedText,
  stderr: BoundedText,
  signal: AbortSignal | undefined,
): Promise<RunnerResult> {
  return await new Promise((resolve) => {
    let timer: unknown;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) safeClear(seams, timer);
      safeRemoveAbort(signal, finish);
      resolve(result(safeAborted(signal) ? "aborted" : "failed", null, null, stdout, stderr, true));
    };
    try {
      childStdout.on("data", (chunk: unknown) => stdout.append(chunk));
      childStderr.on("data", (chunk: unknown) => stderr.append(chunk));
      once("close", finish);
      once("error", finish);
      if (!safeAddAbort(signal, finish)) return finish();
      if (safeAborted(signal)) return finish();
      timer = safeTimer(seams, command.killGraceMs, finish);
      if (!timer) queueMicrotask(finish);
    } catch {
      queueMicrotask(finish);
    }
  });
}

function snapshotRunOptions(options: { signal?: AbortSignal; seams?: RunnerSeams }): {
  signal?: AbortSignal;
  seams: RunnerSeams;
} {
  if (!options || typeof options !== "object" || Object.getPrototypeOf(options) !== Object.prototype)
    throw new Error("invalid launcher runner options");
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const allowed = new Set(["signal", "seams"]);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string" || !allowed.has(key))) {
    throw new Error("invalid launcher runner options");
  }
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error("invalid launcher runner options");
    }
  }
  const signal = descriptors.signal ? descriptors.signal.value : undefined;
  const seams = descriptors.seams ? descriptors.seams.value : defaultSeams;
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new Error("invalid launcher runner options");
  return signal ? { signal, seams: seams as RunnerSeams } : { seams: seams as RunnerSeams };
}

function validateSeams(seams: RunnerSeams): RunnerSeams {
  if (!Object.isFrozen(seams) || Object.getPrototypeOf(seams) !== Object.prototype) {
    throw new Error("invalid launcher runner seams");
  }
  if (Object.getOwnPropertySymbols(seams).length !== 0) throw new Error("invalid launcher runner seams");
  const descriptors = Object.getOwnPropertyDescriptors(seams);
  const keys = ["clearTimer", "identity", "kill", "setTimer", "spawn"] as const;
  if (Object.keys(descriptors).sort().join(",") !== keys.join(",")) throw new Error("invalid launcher runner seams");
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      typeof descriptor.value !== "function" ||
      !Object.isFrozen(descriptor.value) ||
      descriptor.enumerable !== true
    ) {
      throw new Error("invalid launcher runner seams");
    }
  }
  return seams;
}

function snapshotCommand(input: CommandDescriptor): CommandDescriptor {
  if (!input || typeof input !== "object" || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new Error("invalid launcher command");
  }
  if (Object.getOwnPropertySymbols(input).length !== 0) throw new Error("invalid launcher command");
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = ["args", "cwd", "env", "executable", "killGraceMs", "maxOutputBytes", "timeoutMs"];
  if (Object.keys(descriptors).sort().join(",") !== keys.join(",")) throw new Error("invalid launcher command");
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher command");
  }
  const args = snapshotStringArray(descriptorValue(descriptors, "args"));
  const env = snapshotEnv(descriptorValue(descriptors, "env"));
  return {
    executable: descriptorValue(descriptors, "executable") as string,
    args,
    cwd: descriptorValue(descriptors, "cwd") as string,
    env,
    timeoutMs: descriptorValue(descriptors, "timeoutMs") as number,
    maxOutputBytes: descriptorValue(descriptors, "maxOutputBytes") as number,
    killGraceMs: descriptorValue(descriptors, "killGraceMs") as number,
  };
}

function descriptorValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (!descriptor || !("value" in descriptor)) throw new Error("invalid launcher command");
  return descriptor.value;
}

function snapshotStringArray(value: unknown): string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
    throw new Error("invalid launcher command");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (!length || !("value" in length) || typeof length.value !== "number" || !Number.isSafeInteger(length.value))
    throw new Error("invalid launcher command");
  const size = length.value;
  const allowed = new Set(["length", ...Array.from({ length: size }, (_, i) => String(i))]);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string" || !allowed.has(key)))
    throw new Error("invalid launcher command");
  const out: string[] = [];
  for (let index = 0; index < size; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher command");
    if (typeof descriptor.value !== "string" || descriptor.value.includes("\0"))
      throw new Error("invalid launcher command");
    out.push(descriptor.value);
  }
  return out;
}

function snapshotEnv(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("invalid launcher command");
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error("invalid launcher command");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const out: Record<string, string> = {};
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher command");
    if (!/^[A-Z0-9_]{1,80}$/u.test(key) || typeof descriptor.value !== "string" || descriptor.value.includes("\0"))
      throw new Error("invalid launcher command");
    out[key] = descriptor.value;
  }
  return out;
}

function cloneEnv(env: Readonly<Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {};
  const descriptors = Object.getOwnPropertyDescriptors(env);
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (descriptor && "value" in descriptor) out[key] = descriptor.value as string;
  }
  return out;
}

function snapshotChild(value: unknown):
  | {
      pid: number;
      stdout: Readable;
      stderr: Readable;
      once: (event: string, cb: (...args: never[]) => void) => unknown;
    }
  | undefined {
  try {
    if (!value || typeof value !== "object") return undefined;
    const d = Object.getOwnPropertyDescriptors(value),
      pid = d.pid,
      stdout = d.stdout,
      stderr = d.stderr;
    if (
      !pid ||
      !("value" in pid) ||
      !Number.isSafeInteger(pid.value) ||
      pid.value <= 0 ||
      !stdout ||
      !("value" in stdout) ||
      !stderr ||
      !("value" in stderr)
    )
      return undefined;
    const once = typeof d.once?.value === "function" ? d.once.value : (value as { once?: unknown }).once;
    return typeof once === "function"
      ? {
          pid: pid.value,
          stdout: stdout.value as Readable,
          stderr: stderr.value as Readable,
          once: once.bind(value) as never,
        }
      : undefined;
  } catch {
    return undefined;
  }
}

function isReadable(value: unknown): value is Readable {
  try {
    return !!value && typeof value === "object" && typeof (value as Readable).on === "function";
  } catch {
    return false;
  }
}

function safeIdentity(seams: RunnerSeams, pid: number): string | undefined {
  try {
    const identity = seams.identity(pid);
    return typeof identity === "string" && identity.length > 0 && identity.length < 128 ? identity : undefined;
  } catch {
    return undefined;
  }
}

function safeAborted(signal: AbortSignal | undefined): boolean {
  try {
    return signal?.aborted === true;
  } catch {
    return true;
  }
}

function safeAddAbort(signal: AbortSignal | undefined, listener: () => void): boolean {
  if (!signal) return true;
  try {
    signal.addEventListener("abort", listener, { once: true });
    return true;
  } catch {
    return false;
  }
}

function safeRemoveAbort(signal: AbortSignal | undefined, listener: () => void): boolean {
  if (!signal) return true;
  try {
    signal.removeEventListener("abort", listener);
    return true;
  } catch {
    return false;
  }
}

function safeKill(seams: RunnerSeams, pid: number, signal: NodeJS.Signals, identity: string): boolean {
  try {
    if (safeIdentity(seams, Math.abs(pid)) !== identity) return false;
    return seams.kill(pid, signal) === true;
  } catch {
    return false;
  }
}

function safeClear(seams: RunnerSeams, timer: unknown): boolean {
  try {
    seams.clearTimer(timer);
    return true;
  } catch {
    return false;
  }
}

function safeTimer(seams: RunnerSeams, ms: number, cb: () => void): unknown {
  try {
    const timer = seams.setTimer(ms, cb);
    try {
      timer?.unref?.();
    } catch {
      // nonfatal: timers are bounded by normal process teardown.
    }
    return timer;
  } catch {
    return undefined;
  }
}

function result(
  status: RunnerResult["status"],
  exitCode: number | null,
  signal: NodeJS.Signals | null,
  stdout: BoundedText,
  stderr: BoundedText,
  cleanupUncertain = false,
): RunnerResult {
  return Object.freeze({
    status,
    exitCode,
    signal,
    stdout: stdout.text(),
    stderr: stderr.text(),
    stdoutTruncated: stdout.truncated,
    stderrTruncated: stderr.truncated,
    cleanupUncertain,
  });
}

const maxTextChunks = 1024;

class BoundedText {
  readonly #chunks: Buffer[] = [];
  #bytes = 0;
  public truncated = false;
  public constructor(private readonly max: number) {}
  public append(chunk: unknown): void {
    if (this.#bytes >= this.max) {
      this.truncated = true;
      return;
    }
    if (this.#chunks.length >= maxTextChunks) {
      this.truncated = true;
      return;
    }
    const remaining = this.max - this.#bytes;
    let buffer: Buffer;
    try {
      if (typeof chunk === "string") {
        if (chunk.length === 0) return;
        const limited = chunk.length > remaining + 1 ? chunk.slice(0, remaining + 1) : chunk;
        if (limited.length < chunk.length) this.truncated = true;
        buffer = Buffer.from(limited);
      } else if (Buffer.isBuffer(chunk)) {
        if (chunk.length === 0) return;
        buffer = chunk.subarray(0, Math.min(chunk.length, remaining + 1));
        if (buffer.length < chunk.length) this.truncated = true;
      } else if (chunk instanceof Uint8Array) {
        if (chunk.byteLength === 0) return;
        const view = chunk.subarray(0, Math.min(chunk.byteLength, remaining + 1));
        if (view.byteLength < chunk.byteLength) this.truncated = true;
        buffer = Buffer.from(view);
      } else {
        this.truncated = true;
        return;
      }
    } catch {
      this.truncated = true;
      return;
    }
    const next = buffer.length > remaining ? buffer.subarray(0, remaining) : buffer;
    if (next.length === 0) {
      this.truncated = true;
      return;
    }
    this.#chunks.push(Buffer.from(next));
    this.#bytes += next.length;
    if (next.length < buffer.length) this.truncated = true;
  }
  public text(): string {
    return Buffer.concat(this.#chunks, this.#bytes).toString("utf8");
  }
}
