import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { spawn } from "node:child_process";
import { Socket } from "node:net";
import { isAbsolute, normalize } from "node:path";
import { TextDecoder } from "node:util";

const bootstrapPath = "/run/cogs/egress/envoy/bootstrap.json";
type StreamPort = Readonly<{ on(event: "data" | "error", callback: (value: unknown) => void): void; resume(): void }>;
type ChildPort = Readonly<{
  pid: number;
  stdout: StreamPort;
  stderr: StreamPort;
  on(event: "error" | "exit" | "close", callback: (...args: unknown[]) => void): void;
  once(event: "error" | "exit" | "close", callback: (...args: unknown[]) => void): void;
  off(event: "error" | "exit" | "close", callback: (...args: unknown[]) => void): void;
}>;

type SpawnRequest = Readonly<{
  executablePath: string;
  argv: readonly string[];
  cwd: "/";
  detached: true;
  env: Readonly<Record<string, never>>;
  stdio: readonly ["ignore", "pipe", "pipe"];
}>;

export type CogsEnvoyProcessStartInput = Readonly<{
  bootstrapPath: string;
  listenerPort: number;
  signal?: AbortSignal;
  onCompletionLine: (line: string) => Promise<void>;
}>;

export type CogsEnvoyProcessHandle = Readonly<{ ready: boolean; close(): Promise<void> }>;

type ProbeResult = "connected" | "refused";
export type CogsEnvoyProcessPorts = Readonly<{
  spawn(request: SpawnRequest): ChildPort;
  connect(port: number, host: string, signal?: AbortSignal): Promise<ProbeResult>;
  kill(processGroupId: number, signal: "SIGTERM" | "SIGKILL"): Promise<void>;
  setTimeout(callback: () => void, ms: number): ReturnType<typeof setTimeout>;
  clearTimeout(timer: ReturnType<typeof setTimeout>): void;
}>;

export type CogsEnvoyProcessPort = Readonly<{
  start(input: CogsEnvoyProcessStartInput): Promise<CogsEnvoyProcessHandle>;
}>;

export class CogsEnvoyProcessError extends Error {
  public readonly code = "COGS_ENVOY_PROCESS_FAILED";
  public override readonly message = "egress Envoy process unavailable";
}

export function createNodeCogsEnvoyProcessPort(
  options: Readonly<{
    executablePath: string;
    startupTimeoutMs: number;
    closeTimeoutMs: number;
    ports?: CogsEnvoyProcessPorts;
  }>,
): CogsEnvoyProcessPort {
  try {
    const executablePath = canonicalAbsolute(options.executablePath);
    const startupTimeoutMs = bounded(options.startupTimeoutMs, 50, 60_000);
    const closeTimeoutMs = bounded(options.closeTimeoutMs, 50, 60_000);
    const ports = options.ports ?? nodeEnvoyProcessPorts;
    return Object.freeze({
      start: (input) => startEnvoy(executablePath, startupTimeoutMs, closeTimeoutMs, ports, input),
    });
  } catch {
    throw new CogsEnvoyProcessError();
  }
}

async function startEnvoy(
  executablePath: string,
  startupTimeoutMs: number,
  closeTimeoutMs: number,
  ports: CogsEnvoyProcessPorts,
  input: CogsEnvoyProcessStartInput,
): Promise<CogsEnvoyProcessHandle> {
  let runtime: Runtime | undefined;
  try {
    const captured = Object.freeze({
      bootstrapPath: canonicalAbsolute(input.bootstrapPath),
      listenerPort: bounded(input.listenerPort, 1, 65_535),
      signal: input.signal,
      onCompletionLine: input.onCompletionLine,
    });
    if (captured.bootstrapPath !== bootstrapPath || typeof captured.onCompletionLine !== "function")
      throw new Error("bad input");
    if (captured.signal?.aborted) throw new Error("aborted");
    await preflightRefused(ports, captured.listenerPort, captured.signal);
    const argv = Object.freeze([
      "--config-path",
      bootstrapPath,
      "--mode",
      "serve",
      "--log-level",
      "warning",
      "--disable-hot-restart",
      "--concurrency",
      "1",
    ]);
    const child = ports.spawn(
      Object.freeze({
        executablePath,
        argv,
        cwd: "/" as const,
        detached: true as const,
        env: Object.freeze({}),
        stdio: Object.freeze(["ignore", "pipe", "pipe"] as const),
      }),
    );
    if (!Number.isSafeInteger(child.pid) || child.pid < 1) throw new Error("bad pid");
    runtime = new Runtime(child, ports, closeTimeoutMs, captured.onCompletionLine);
    runtime.attach();
    await waitStartup(runtime, ports, captured.listenerPort, startupTimeoutMs, captured.signal);
    return runtime.handle();
  } catch {
    if (runtime !== undefined) await runtime.shutdown(false).catch(() => undefined);
    throw new CogsEnvoyProcessError();
  }
}

class Runtime {
  private readyState = false;
  private stopping = false;
  private poisoned = false;
  private unexpected = false;
  private exitSeen = false;
  private closeSeen = false;
  private terminal?: Promise<void>;
  private closing?: Promise<void>;
  private draining: Promise<void> | undefined;
  private queue: string[] = [];
  private pending = "";
  private pendingBytes = 0;
  private stderrBytes = 0;
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });

  public constructor(
    private readonly child: ChildPort,
    private readonly ports: CogsEnvoyProcessPorts,
    private readonly closeTimeoutMs: number,
    private readonly onLine: (line: string) => Promise<void>,
  ) {}

  public attach(): void {
    this.terminal = this.terminalPromise();
    this.child.stdout.on("data", (chunk) => this.acceptStdout(chunk));
    this.child.stdout.on("error", () => this.poison());
    this.child.stderr.on("data", (chunk) => this.acceptStderr(chunk));
    this.child.stderr.on("error", () => this.poison());
    this.child.on("error", () => this.poison());
    this.child.stdout.resume();
    this.child.stderr.resume();
  }

  public handle(): CogsEnvoyProcessHandle {
    this.readyState = true;
    const runtime = this;
    return Object.freeze({
      get ready() {
        return runtime.readyState && !runtime.poisoned && !runtime.exitSeen && !runtime.closeSeen;
      },
      close: () => runtime.shutdown(true),
    });
  }

  public alive(): boolean {
    return !this.exitSeen && !this.closeSeen && !this.poisoned;
  }

  public async shutdown(intentional: boolean): Promise<void> {
    this.readyState = false;
    this.closing ??= this.doShutdown(intentional);
    try {
      await this.closing;
    } catch {
      throw new CogsEnvoyProcessError();
    }
  }

  private async doShutdown(intentional: boolean): Promise<void> {
    this.stopping = true;
    if (!intentional) this.poisoned = true;
    let signalFailed = false;
    if (!this.exitSeen || !this.closeSeen) {
      await this.ports.kill(-this.child.pid, "SIGTERM").catch(() => {
        signalFailed = true;
      });
      if (signalFailed || !(await this.waitTerminal(this.closeTimeoutMs))) {
        await this.ports.kill(-this.child.pid, "SIGKILL").catch(() => {
          signalFailed = true;
        });
        if (!(await this.waitTerminal(this.closeTimeoutMs))) throw new Error("not reaped");
      }
    }
    if (this.draining !== undefined) await withTimeout(this.ports, this.draining, 5000);
    if (signalFailed || !this.exitSeen || !this.closeSeen || this.unexpected || this.poisoned)
      throw new Error("closed unhealthy");
  }

  private terminalPromise(): Promise<void> {
    return new Promise((resolve) => {
      const done = () => {
        if (this.exitSeen && this.closeSeen) {
          this.child.off("exit", onExit);
          this.child.off("close", onClose);
          resolve();
        }
      };
      const onExit = () => {
        this.exitSeen = true;
        this.readyState = false;
        if (!this.stopping) {
          this.unexpected = true;
          this.poison();
        }
        done();
      };
      const onClose = () => {
        this.closeSeen = true;
        this.readyState = false;
        this.finalizeOutput(!this.stopping);
        done();
      };
      this.child.once("exit", onExit);
      this.child.once("close", onClose);
    });
  }

  private waitTerminal(ms: number): Promise<boolean> {
    if (this.exitSeen && this.closeSeen) return Promise.resolve(true);
    return withTimeout(this.ports, this.terminal ?? Promise.resolve(), ms).then(
      () => this.exitSeen && this.closeSeen,
      () => false,
    );
  }

  private acceptStdout(chunk: unknown): void {
    if (this.closeSeen || this.poisoned) return;
    try {
      if (!(chunk instanceof Uint8Array)) throw new Error("bad chunk");
      for (const byte of chunk) {
        this.pendingBytes++;
        if (this.pendingBytes > 4096) throw new Error("line too large");
        if (byte === 10) this.pendingBytes = 0;
      }
      this.pending += this.decoder.decode(chunk, { stream: true });
      const parts = this.pending.split("\n");
      this.pending = parts.pop() ?? "";
      for (const part of parts) this.enqueue(part.endsWith("\r") ? part.slice(0, -1) : part);
    } catch {
      this.poison();
    }
  }

  private enqueue(line: string): void {
    this.queue.push(line);
    if (this.queue.length > 256) {
      this.poison();
      return;
    }
    this.draining ??= this.drain();
  }

  private async drain(): Promise<void> {
    try {
      while (this.queue.length > 0 && !this.poisoned)
        await withTimeout(this.ports, this.onLine(this.queue.shift() ?? ""), 5000);
    } catch {
      this.poison();
    } finally {
      this.draining = undefined;
      if (this.queue.length > 0 && !this.poisoned) this.draining = this.drain();
    }
  }

  private acceptStderr(chunk: unknown): void {
    if (this.closeSeen || this.poisoned) return;
    if (!(chunk instanceof Uint8Array)) {
      this.poison();
      return;
    }
    this.stderrBytes += chunk.byteLength;
    if (this.stderrBytes > 65536) this.poison();
  }

  private finalizeOutput(unexpected: boolean): void {
    if (unexpected) this.unexpected = true;
    try {
      this.decoder.decode(undefined, { stream: false });
      if (this.pending.length > 0 || this.pendingBytes > 0) throw new Error("partial line");
      if (unexpected) this.poison();
    } catch {
      this.poison();
    }
  }

  private poison(): void {
    if (this.poisoned) return;
    this.poisoned = true;
    this.readyState = false;
    void this.shutdown(false).catch(() => undefined);
  }
}

async function preflightRefused(ports: CogsEnvoyProcessPorts, port: number, source?: AbortSignal): Promise<void> {
  if ((await probe(ports, port, 1000, source)) !== "refused") throw new Error("alien listener");
}

async function waitStartup(
  runtime: Runtime,
  ports: CogsEnvoyProcessPorts,
  port: number,
  timeoutMs: number,
  source?: AbortSignal,
): Promise<void> {
  const deadline = new AbortController();
  const abort = () => deadline.abort();
  const timer = ports.setTimeout(abort, timeoutMs);
  source?.addEventListener("abort", abort, { once: true });
  if (source?.aborted) abort();
  try {
    while (runtime.alive() && !deadline.signal.aborted) {
      const result = await probe(ports, port, 1000, deadline.signal);
      if (result === "connected" && runtime.alive()) return;
      if (result !== "refused") throw new Error("bad probe");
      await sleep(ports, 25);
    }
    throw new Error("not ready");
  } finally {
    ports.clearTimeout(timer);
    source?.removeEventListener("abort", abort);
  }
}

function probe(ports: CogsEnvoyProcessPorts, port: number, ms: number, source?: AbortSignal): Promise<ProbeResult> {
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (result?: ProbeResult, error?: unknown) => {
      if (settled) return;
      settled = true;
      ports.clearTimeout(timer);
      source?.removeEventListener("abort", abort);
      controller.abort();
      error === undefined && result !== undefined ? resolve(result) : reject(error);
    };
    const abort = () => finish(undefined, new Error("aborted"));
    const timer = ports.setTimeout(() => finish(undefined, new Error("timeout")), ms);
    source?.addEventListener("abort", abort, { once: true });
    if (source?.aborted) {
      abort();
      return;
    }
    ports.connect(port, "127.0.0.1", controller.signal).then(
      (result) => finish(result),
      (error) => finish(undefined, error),
    );
  });
}

function withTimeout<T>(ports: CogsEnvoyProcessPorts, promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = ports.setTimeout(() => reject(new Error("timeout")), ms);
    promise.then(
      (value) => {
        ports.clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        ports.clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function sleep(ports: CogsEnvoyProcessPorts, ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = ports.setTimeout(() => {
      ports.clearTimeout(timer);
      resolve();
    }, ms);
  });
}

function canonicalAbsolute(path: string): string {
  if (typeof path !== "string" || path.length < 1 || path.length > 4096 || path.includes("\0"))
    throw new Error("bad path");
  if (!isAbsolute(path) || normalize(path) !== path) throw new Error("bad path");
  return path;
}

function bounded(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("bad bound");
  return value;
}

export const nodeEnvoyProcessPorts: CogsEnvoyProcessPorts = Object.freeze({
  spawn(request) {
    const child = spawn(request.executablePath, [...request.argv], {
      cwd: request.cwd,
      detached: request.detached,
      env: request.env,
      stdio: [...request.stdio],
    }) as unknown as ChildProcessWithoutNullStreams;
    if (!Number.isSafeInteger(child.pid) || child.pid === undefined || child.pid < 1) {
      child.once("error", () => undefined);
      child.stdout.resume();
      child.stderr.resume();
      throw new Error("bad pid");
    }
    return child as ChildPort;
  },
  connect(port, host, signal) {
    return new Promise((resolve, reject) => {
      const socket = new Socket();
      let settled = false;
      const abort = () => finish(undefined, new Error("aborted"));
      const finish = (result?: ProbeResult, error?: Error) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", abort);
        socket.removeAllListeners();
        socket.destroy();
        error === undefined && result !== undefined ? resolve(result) : reject(error);
      };
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) {
        abort();
        return;
      }
      socket.once("error", (error: NodeJS.ErrnoException) => {
        error.code === "ECONNREFUSED" ? finish("refused") : finish(undefined, error);
      });
      socket.once("connect", () => finish("connected"));
      socket.setTimeout(1000, () => finish(undefined, new Error("timeout")));
      socket.connect(port, host);
    });
  },
  async kill(processGroupId, signal) {
    process.kill(processGroupId, signal);
  },
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (timer) => clearTimeout(timer),
});
