import { timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import ssh2, { type ConnectConfig } from "ssh2";
import type { LaunchConfig } from "../launch/config.ts";

const { Client, utils } = ssh2;

import type { LaunchDependency } from "../launch/lifecycle.ts";

export type SshPermitKind = "exec" | "sftp";

export interface SshConnectionConfig {
  readonly endpoint: string;
  readonly username: string;
  readonly hostKeySha256: string;
  readonly clientKeyPath: string;
  readonly connectTimeoutMs?: number;
  readonly handshakeTimeoutMs?: number;
  readonly permitAcquireTimeoutMs?: number;
  readonly shutdownTimeoutMs?: number;
  readonly maxPermits?: number;
  readonly maxQueue?: number;
  readonly maxPrivateKeyBytes?: number;
}

export interface SshPermitLease {
  readonly kind: SshPermitKind;
  readonly release: () => Promise<void>;
}

export interface SshTransportConnection {
  readonly on: (event: "close" | "error", listener: (error?: unknown) => void) => void;
  readonly off: (event: "close" | "error", listener: (error?: unknown) => void) => void;
  readonly close: () => Promise<void>;
  readonly destroy: () => void;
}

export interface SshTransport {
  readonly connect: (options: SshTransportConnectOptions, signal: AbortSignal) => Promise<SshTransportConnection>;
}

export interface SshTransportConnectOptions {
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly hostKeySha256: string;
  readonly privateKey: Buffer;
  readonly connectTimeoutMs: number;
  readonly handshakeTimeoutMs: number;
}

export interface SshConnectionManagerOptions {
  readonly config: SshConnectionConfig;
  readonly transport?: SshTransport;
  readonly onLost?: (reason: string) => void;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5000;
const DEFAULT_PERMIT_ACQUIRE_TIMEOUT_MS = 5000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 2000;
const DEFAULT_MAX_PERMITS = 4;
const DEFAULT_MAX_QUEUE = 64;
const DEFAULT_MAX_PRIVATE_KEY_BYTES = 64 * 1024;

export class SshConnectionError extends Error {
  public readonly code = "COGS_SSH_CONNECTION_FAILED";
  public constructor(message: string) {
    super(message);
    this.name = "SshConnectionError";
  }
}

type Phase = "created" | "starting" | "ready" | "closing" | "closed" | "failed";
type Waiter = {
  readonly kind: SshPermitKind;
  readonly signal: AbortSignal | undefined;
  readonly resolve: (lease: SshPermitLease) => void;
  readonly reject: (error: Error) => void;
  readonly abort: () => void;
  readonly timer: NodeJS.Timeout;
};
type ActivePermit = { released: boolean };

export class SshConnectionManager {
  readonly #config: Required<SshConnectionConfig>;
  readonly #transport: SshTransport;
  readonly #onLost: ((reason: string) => void) | undefined;
  #phase: Phase = "created";
  #connection: SshTransportConnection | undefined;
  #privateKey: Buffer | undefined;
  #waiters: Waiter[] = [];
  #active = new Set<ActivePermit>();
  #lost = false;
  #shutdownPromise: Promise<void> | undefined;
  #boundLost: ((error?: unknown) => void) | undefined;

  public constructor(options: SshConnectionManagerOptions) {
    this.#config = validateConfig(options.config);
    this.#transport = options.transport ?? new Ssh2Transport();
    this.#onLost = options.onLost;
  }

  public get ready(): boolean {
    return this.#phase === "ready";
  }

  public async start(signal?: AbortSignal): Promise<void> {
    if (this.#phase !== "created") throw new SshConnectionError("ssh manager can start only once");
    this.#phase = "starting";
    let connection: SshTransportConnection | undefined;
    try {
      throwIfAbortedSync(signal);
      const key = await readPrivateKey(this.#config.clientKeyPath, this.#config.maxPrivateKeyBytes);
      this.#privateKey = key;
      const { host, port } = parseEndpoint(this.#config.endpoint);
      const timeoutMs = this.#config.connectTimeoutMs + this.#config.handshakeTimeoutMs;
      const controller = linkedSignal(signal);
      try {
        connection = await raceBounded(
          this.#transport.connect(
            {
              host,
              port,
              username: this.#config.username,
              hostKeySha256: this.#config.hostKeySha256,
              privateKey: key,
              connectTimeoutMs: this.#config.connectTimeoutMs,
              handshakeTimeoutMs: this.#config.handshakeTimeoutMs,
            },
            controller.signal,
          ),
          timeoutMs,
          "ssh start timed out",
          () => controller.abort(),
          (late) => late.destroy(),
          controller.signal,
        );
      } finally {
        controller.dispose();
      }
      if (this.#phase !== "starting") {
        try {
          connection.destroy();
        } catch {
          // Start is already interrupted; preserve fail-closed result.
        }
        throw new SshConnectionError("ssh start interrupted");
      }
      this.#connection = connection;
      this.#boundLost = () => this.#failClosed("connection-lost");
      connection.on("close", this.#boundLost);
      connection.on("error", this.#boundLost);
      this.#phase = "ready";
    } catch (error) {
      try {
        connection?.destroy();
      } catch {
        // Transport cleanup is best-effort; start must still fail closed and clear key material.
      }
      this.#phase = "failed";
      this.#clearKey();
      await this.shutdown().catch(() => undefined);
      throw redactError(error, "ssh start failed");
    }
  }

  public acquire(kind: SshPermitKind, input: { signal?: AbortSignal } = {}): Promise<SshPermitLease> {
    if (kind !== "exec" && kind !== "sftp") throw new SshConnectionError("invalid ssh permit kind");
    if (this.#phase !== "ready" || this.#connection === undefined)
      throw new SshConnectionError("ssh connection is closed");
    throwIfAbortedSync(input.signal);
    if (this.#active.size < this.#config.maxPermits) return Promise.resolve(this.#createPermit(kind));
    if (this.#waiters.length >= this.#config.maxQueue) throw new SshConnectionError("ssh permit queue full");
    return new Promise<SshPermitLease>((resolve, reject) => {
      const waiter: Waiter = {
        kind,
        signal: input.signal,
        resolve,
        reject,
        abort: () => this.#rejectWaiter(waiter, new SshConnectionError("ssh permit acquisition aborted")),
        timer: setTimeout(
          () => this.#rejectWaiter(waiter, new SshConnectionError("ssh permit acquisition timed out")),
          this.#config.permitAcquireTimeoutMs,
        ),
      };
      input.signal?.addEventListener("abort", waiter.abort, { once: true });
      this.#waiters.push(waiter);
    });
  }

  public shutdown(): Promise<void> {
    if (this.#shutdownPromise !== undefined) return this.#shutdownPromise;
    this.#shutdownPromise = this.#shutdown();
    return this.#shutdownPromise;
  }

  async #shutdown(): Promise<void> {
    if (this.#phase === "closed") return;
    this.#phase = "closing";
    try {
      for (const waiter of this.#waiters.splice(0))
        this.#settleWaiter(waiter, new SshConnectionError("ssh connection is closed"));
      this.#active.clear();
      const connection = this.#connection;
      this.#connection = undefined;
      if (connection !== undefined) {
        if (this.#boundLost !== undefined) {
          try {
            connection.off("close", this.#boundLost);
          } catch {
            // Listener cleanup must not block fail-closed shutdown.
          }
          try {
            connection.off("error", this.#boundLost);
          } catch {
            // Listener cleanup must not block fail-closed shutdown.
          }
        }
        await raceBounded(
          Promise.resolve().then(() => connection.close()),
          this.#config.shutdownTimeoutMs,
          "ssh shutdown timed out",
          () => connection.destroy(),
        ).catch(() => undefined);
      }
    } finally {
      this.#clearKey();
      this.#phase = this.#lost ? "failed" : "closed";
    }
  }

  #createPermit(kind: SshPermitKind): SshPermitLease {
    const permit: ActivePermit = { released: false };
    this.#active.add(permit);
    return { kind, release: async () => this.#releasePermit(permit) };
  }

  #releasePermit(permit: ActivePermit): void {
    if (permit.released) return;
    permit.released = true;
    this.#active.delete(permit);
    this.#drainQueue();
  }

  #drainQueue(): void {
    while (this.#phase === "ready" && this.#active.size < this.#config.maxPermits && this.#waiters.length > 0) {
      const waiter = this.#waiters.shift();
      if (waiter === undefined) return;
      if (waiter.signal?.aborted) {
        this.#settleWaiter(waiter, new SshConnectionError("ssh permit acquisition aborted"));
      } else {
        const lease = this.#createPermit(waiter.kind);
        this.#settleWaiter(waiter, undefined, lease);
      }
    }
  }

  #rejectWaiter(waiter: Waiter, error: SshConnectionError): void {
    this.#waiters = this.#waiters.filter((entry) => entry !== waiter);
    this.#settleWaiter(waiter, error);
  }

  #settleWaiter(waiter: Waiter, error?: Error, lease?: SshPermitLease): void {
    clearTimeout(waiter.timer);
    waiter.signal?.removeEventListener("abort", waiter.abort);
    if (error !== undefined) waiter.reject(error);
    else if (lease !== undefined) waiter.resolve(lease);
  }

  #failClosed(reason: string): void {
    if (this.#lost) return;
    this.#lost = true;
    this.#phase = "failed";
    try {
      this.#onLost?.(reason);
    } catch {
      // Lifecycle callbacks are safety notifications and must not block cleanup.
    }
    void this.shutdown().catch(() => undefined);
  }

  #clearKey(): void {
    this.#privateKey?.fill(0);
    this.#privateKey = undefined;
  }
}

export function createSshLaunchDependency(input: {
  readonly launch: LaunchConfig;
  readonly username: string;
  readonly transport?: SshTransport;
  readonly onLost?: (reason: string) => void;
}): LaunchDependency & { readonly manager: SshConnectionManager } {
  const manager = new SshConnectionManager({
    config: {
      endpoint: input.launch.sandbox.ssh_endpoint,
      hostKeySha256: input.launch.sandbox.ssh_host_key,
      clientKeyPath: input.launch.sandbox.client_key_path,
      username: input.username,
    },
    ...(input.transport === undefined ? {} : { transport: input.transport }),
    ...(input.onLost === undefined ? {} : { onLost: input.onLost }),
  });
  return {
    name: "ssh",
    manager,
    start: async (signal) => manager.start(signal),
    shutdown: async () => manager.shutdown(),
  };
}

export class Ssh2Transport implements SshTransport {
  public connect(options: SshTransportConnectOptions, signal: AbortSignal): Promise<SshTransportConnection> {
    return new Promise((resolveConnect, rejectConnect) => {
      if (signal.aborted) {
        rejectConnect(new SshConnectionError("ssh connection aborted"));
        return;
      }
      const client = new Client();
      const wrapped = new Ssh2Connection(client);
      let settled = false;
      const onPreReadyLost = () => finish(new SshConnectionError("ssh connection failed"));
      const cleanup = () => {
        signal.removeEventListener("abort", onAbort);
        try {
          client.off("ready", onReady);
        } catch {
          // ssh2 listener cleanup is best-effort after terminal failure.
        }
        wrapped.off("close", onPreReadyLost);
        wrapped.off("error", onPreReadyLost);
      };
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error !== undefined) {
          try {
            client.destroy();
          } catch {
            // Connection is already failing; preserve the redacted rejection.
          }
          rejectConnect(error);
        } else resolveConnect(wrapped);
      };
      const onAbort = () => finish(new SshConnectionError("ssh connection aborted"));
      const onReady = () => finish();
      signal.addEventListener("abort", onAbort, { once: true });
      wrapped.on("close", onPreReadyLost);
      wrapped.on("error", onPreReadyLost);
      client.once("ready", onReady);
      const pinHex = decodeOpenSshSha256Pin(options.hostKeySha256).toString("hex");
      const config: ConnectConfig = {
        host: options.host,
        port: options.port,
        username: options.username,
        privateKey: options.privateKey,
        tryKeyboard: false,
        agentForward: false,
        keepaliveInterval: Math.max(1000, Math.min(15_000, options.handshakeTimeoutMs)),
        keepaliveCountMax: 2,
        hostHash: "sha256",
        hostVerifier: (hash: string) => safeEqualHex(hash, pinHex),
        authHandler: [{ type: "publickey", username: options.username, key: options.privateKey } as never],
        readyTimeout: options.handshakeTimeoutMs,
        timeout: options.connectTimeoutMs,
        algorithms: {
          cipher: {
            remove: ["aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "3des-cbc", "arcfour"],
          } as never,
          hmac: { remove: ["hmac-sha1", "hmac-md5"] } as never,
          serverHostKey: { remove: ["ssh-dss", "ssh-rsa"] } as never,
        },
      };
      try {
        client.connect(config);
      } catch {
        finish(new SshConnectionError("ssh connection failed"));
      }
    });
  }
}

export class Ssh2Connection implements SshTransportConnection {
  readonly #listeners = new Map<"close" | "error", Set<(error?: unknown) => void>>([
    ["close", new Set()],
    ["error", new Set()],
  ]);
  readonly #onClientError = (error: unknown) => this.#recordLost("error", error);
  readonly #onClientClose = () => this.#recordLost("close");
  readonly #sinkClientError = () => undefined;
  #lost: { event: "close" | "error"; error?: unknown } | undefined;
  #closed = false;
  public constructor(private readonly client: InstanceType<typeof Client>) {
    client.on("error", this.#onClientError);
    client.on("close", this.#onClientClose);
  }
  public on(event: "close" | "error", listener: (error?: unknown) => void): void {
    this.#listeners.get(event)?.add(listener);
    if (this.#lost?.event === event) {
      const lost = this.#lost;
      queueMicrotask(() => this.#notifyOne(listener, lost.error));
    }
  }
  public off(event: "close" | "error", listener: (error?: unknown) => void): void {
    this.#listeners.get(event)?.delete(listener);
  }
  public close(): Promise<void> {
    if (this.#closed) return Promise.resolve();
    if (this.#lost?.event === "error") {
      this.destroy();
      return Promise.resolve();
    }
    return new Promise((resolveClose) => {
      const resolveOnce = () => resolveClose();
      try {
        this.client.once("close", resolveOnce);
        this.client.end();
      } catch {
        try {
          this.client.off("close", resolveOnce);
        } catch {
          // Already terminal or listener cleanup failed; close remains best-effort.
        }
        this.destroy();
        resolveClose();
      }
    });
  }
  public destroy(): void {
    try {
      this.client.destroy();
    } finally {
      this.#markClosed();
    }
  }
  #recordLost(event: "close" | "error", error?: unknown): void {
    if (this.#lost === undefined) this.#lost = { event, ...(error === undefined ? {} : { error }) };
    if (event === "close") this.#markClosed();
    else this.#markErrored();
    for (const listener of [...(this.#listeners.get(event) ?? [])]) this.#notifyOne(listener, error);
  }
  #notifyOne(listener: (error?: unknown) => void, error?: unknown): void {
    try {
      listener(error);
    } catch {
      // Transport loss notifications must not become uncaught EventEmitter-style errors.
    }
  }
  #markErrored(): void {
    try {
      this.client.off("error", this.#onClientError);
    } catch {
      // Listener cleanup is best-effort after an SSH error.
    }
    try {
      this.client.on("error", this.#sinkClientError);
    } catch {
      // A permanent internal sink is best-effort protection against late ssh2 errors.
    }
  }
  #markClosed(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#markErrored();
    try {
      this.client.off("close", this.#onClientClose);
    } catch {
      // Listener cleanup is best-effort at terminal state.
    }
  }
}

async function readPrivateKey(path: string, maxBytes: number): Promise<Buffer> {
  if (!path.startsWith("/") || path.includes("\0")) throw new SshConnectionError("invalid ssh key path");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => {
    throw new SshConnectionError("invalid ssh key file");
  });
  let key: Buffer | undefined;
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new SshConnectionError("invalid ssh key file");
    if (stat.nlink !== 1) throw new SshConnectionError("invalid ssh key link count");
    const uid = typeof process.geteuid === "function" ? process.geteuid() : undefined;
    if (uid !== undefined && stat.uid !== uid) throw new SshConnectionError("invalid ssh key owner");
    if ((stat.mode & 0o077) !== 0) throw new SshConnectionError("invalid ssh key permissions");
    if (stat.size < 1 || stat.size > maxBytes) throw new SshConnectionError("invalid ssh key size");
    const readBuffer = Buffer.allocUnsafe(maxBytes + 1);
    try {
      const { bytesRead } = await handle.read(readBuffer, 0, maxBytes + 1, 0);
      if (bytesRead < 1 || bytesRead > maxBytes) throw new SshConnectionError("invalid ssh key size");
      const trailing = Buffer.allocUnsafe(1);
      try {
        const extra = await handle.read(trailing, 0, 1, bytesRead);
        if (extra.bytesRead !== 0) throw new SshConnectionError("invalid ssh key size");
      } finally {
        trailing.fill(0);
      }
      key = Buffer.from(readBuffer.subarray(0, bytesRead));
    } finally {
      readBuffer.fill(0);
    }
    const parsed = utils.parseKey(key);
    if (parsed instanceof Error || Array.isArray(parsed) || !parsed.isPrivateKey())
      throw new SshConnectionError("invalid ssh private key");
    return Buffer.from(key);
  } catch (error) {
    throw redactError(error, "invalid ssh private key");
  } finally {
    key?.fill(0);
    await handle.close().catch(() => undefined);
  }
}

function validateConfig(config: SshConnectionConfig): Required<SshConnectionConfig> {
  decodeOpenSshSha256Pin(config.hostKeySha256);
  if (!/^[a-z_][a-z0-9_-]{0,63}$/.test(config.username)) throw new SshConnectionError("invalid ssh username");
  parseEndpoint(config.endpoint);
  return {
    endpoint: config.endpoint,
    username: config.username,
    hostKeySha256: config.hostKeySha256,
    clientKeyPath: config.clientKeyPath,
    connectTimeoutMs: integer(config.connectTimeoutMs, DEFAULT_CONNECT_TIMEOUT_MS, 1, 60_000, "connect timeout"),
    handshakeTimeoutMs: integer(
      config.handshakeTimeoutMs,
      DEFAULT_HANDSHAKE_TIMEOUT_MS,
      1,
      60_000,
      "handshake timeout",
    ),
    permitAcquireTimeoutMs: integer(
      config.permitAcquireTimeoutMs,
      DEFAULT_PERMIT_ACQUIRE_TIMEOUT_MS,
      1,
      60_000,
      "permit acquire timeout",
    ),
    shutdownTimeoutMs: integer(config.shutdownTimeoutMs, DEFAULT_SHUTDOWN_TIMEOUT_MS, 1, 60_000, "shutdown timeout"),
    maxPermits: integer(config.maxPermits, DEFAULT_MAX_PERMITS, 1, 32, "max permits"),
    maxQueue: integer(config.maxQueue, DEFAULT_MAX_QUEUE, 0, 1024, "max queue"),
    maxPrivateKeyBytes: integer(
      config.maxPrivateKeyBytes,
      DEFAULT_MAX_PRIVATE_KEY_BYTES,
      128,
      256 * 1024,
      "max private key bytes",
    ),
  };
}

function parseEndpoint(endpoint: string): { host: string; port: number } {
  const match = endpoint.match(/^([A-Za-z0-9.-]+):([0-9]{1,5})$/);
  if (!match) throw new SshConnectionError("invalid ssh endpoint");
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new SshConnectionError("invalid ssh endpoint");
  return { host: match[1] ?? "", port };
}

function integer(value: number | undefined, fallback: number, min: number, max: number, label: string): number {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < min || result > max) throw new SshConnectionError(`invalid ssh ${label}`);
  return result;
}

function linkedSignal(parent: AbortSignal | undefined): AbortController & { dispose: () => void } {
  const controller = new AbortController() as AbortController & { dispose: () => void };
  const abort = () => controller.abort();
  if (parent?.aborted) abort();
  else parent?.addEventListener("abort", abort, { once: true });
  controller.dispose = () => parent?.removeEventListener("abort", abort);
  return controller;
}

function raceBounded<T>(
  promise: Promise<T>,
  timeoutMs: number,
  timeoutMessage: string,
  onTimeout: () => void,
  onLate?: (value: T) => void,
  signal?: AbortSignal,
): Promise<T> {
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  let abort: (() => void) | undefined;
  const timeout = new Promise<never>((_, reject) => {
    const rejectOnce = (error: SshConnectionError) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    timer = setTimeout(() => {
      if (settled) return;
      rejectOnce(new SshConnectionError(timeoutMessage));
      try {
        onTimeout();
      } catch {
        // Timeout cleanup is best-effort and must not mask the bounded failure.
      }
    }, timeoutMs);
    if (signal !== undefined) {
      abort = () => {
        try {
          onTimeout();
        } catch {
          // Abort cleanup is best-effort and must not mask the bounded failure.
        }
        rejectOnce(new SshConnectionError("ssh operation aborted"));
      };
      if (signal.aborted) abort();
      else signal.addEventListener("abort", abort, { once: true });
    }
  });
  promise.then(
    (value) => {
      if (!settled) return;
      try {
        onLate?.(value);
      } catch {
        // Late cleanup is best-effort; the caller has already observed the bounded failure.
      }
    },
    () => undefined,
  );
  return Promise.race([promise, timeout]).finally(() => {
    settled = true;
    if (timer !== undefined) clearTimeout(timer);
    if (signal !== undefined && abort !== undefined) signal.removeEventListener("abort", abort);
  });
}

function throwIfAbortedSync(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new SshConnectionError("ssh operation aborted");
}

function redactError(error: unknown, fallback: string): SshConnectionError {
  if (error instanceof SshConnectionError) return error;
  return new SshConnectionError(fallback);
}

export function decodeOpenSshSha256Pin(pin: string): Buffer {
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(pin)) throw new SshConnectionError("invalid ssh host key pin");
  const digest = Buffer.from(`${pin.slice("SHA256:".length)}=`, "base64");
  if (digest.length !== 32) throw new SshConnectionError("invalid ssh host key pin");
  return digest;
}

export function safeEqualHex(leftHex: string, rightHex: string): boolean {
  if (!/^[0-9a-f]{64}$/i.test(leftHex) || !/^[0-9a-f]{64}$/i.test(rightHex)) return false;
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  return left.length === right.length && timingSafeEqual(left, right);
}
