import { timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import type { ClientChannel, SFTPWrapper } from "ssh2";
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
  readonly sftpOpenTimeoutMs?: number;
  readonly execOpenTimeoutMs?: number;
  readonly shutdownTimeoutMs?: number;
  readonly maxPermits?: number;
  readonly maxQueue?: number;
  readonly maxPrivateKeyBytes?: number;
}

export interface SshPermitLease {
  readonly kind: SshPermitKind;
  readonly release: () => Promise<void>;
}

export interface CogsSftpStats {
  readonly size: number;
  readonly type: "file" | "directory" | "symlink" | "fifo" | "block" | "character" | "socket" | "unknown";
}

export type CogsSftpStatus = "eof" | "no_such_file" | "permission_denied" | "failure";

export class CogsSftpStatusError extends Error {
  public readonly code = "COGS_SFTP_STATUS";
  public constructor(public readonly status: CogsSftpStatus) {
    super(`sftp status: ${status}`);
    this.name = "CogsSftpStatusError";
  }
}

export interface CogsSftpPort {
  readonly lstat: (path: string, signal: AbortSignal) => Promise<CogsSftpStats>;
  readonly realpath: (path: string, signal: AbortSignal) => Promise<string>;
  readonly open: (path: string, mode: "r" | "wx", signal: AbortSignal) => Promise<Buffer>;
  readonly read: (
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    signal: AbortSignal,
  ) => Promise<{ bytesRead: number; buffer: Buffer; position: number }>;
  readonly write: (
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    signal: AbortSignal,
  ) => Promise<void>;
  readonly fstat: (handle: Buffer, signal: AbortSignal) => Promise<CogsSftpStats>;
  readonly closeHandle: (handle: Buffer, signal: AbortSignal) => Promise<void>;
  readonly unlink: (path: string, signal: AbortSignal) => Promise<void>;
  readonly mkdir?: (path: string, mode: number, signal: AbortSignal) => Promise<void>;
  readonly setMode?: (path: string, mode: number, signal: AbortSignal) => Promise<void>;
  readonly rmdir?: (path: string, signal: AbortSignal) => Promise<void>;
  readonly fsync: (handle: Buffer, signal: AbortSignal) => Promise<void>;
  readonly posixRename: (source: string, target: string, signal: AbortSignal) => Promise<void>;
}

export interface SshSftpChannel {
  readonly port: CogsSftpPort;
  readonly close: () => Promise<void>;
  readonly destroy: () => void;
}

export type CogsExecTerminal =
  | { readonly code: number; readonly signal: null }
  | { readonly code: null; readonly signal: string };

export interface CogsExecPort {
  readonly onStdout: (listener: (chunk: Buffer) => void) => void;
  readonly onStderr: (listener: (chunk: Buffer) => void) => void;
  readonly terminal: () => Promise<CogsExecTerminal>;
  readonly signal: (name: "TERM" | "INT") => Promise<void>;
}

export interface SshExecChannel {
  readonly port: CogsExecPort;
  readonly close: () => Promise<void>;
  readonly destroy: () => void;
}

export interface SshTransportConnection {
  readonly on: (event: "close" | "error", listener: (error?: unknown) => void) => void;
  readonly off: (event: "close" | "error", listener: (error?: unknown) => void) => void;
  readonly openSftp: (signal: AbortSignal) => Promise<SshSftpChannel>;
  readonly openExec: (command: string, signal: AbortSignal) => Promise<SshExecChannel>;
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
const DEFAULT_SFTP_OPEN_TIMEOUT_MS = 5000;
const DEFAULT_EXEC_OPEN_TIMEOUT_MS = 5000;
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

  public async withSftp<T>(
    input:
      | { signal?: AbortSignal; openTimeoutMs?: number; closeTimeoutMs?: number; operationTimeoutMs?: number }
      | undefined,
    operation: (port: CogsSftpPort, signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const lease = await this.acquire("sftp", input?.signal === undefined ? {} : { signal: input.signal });
    const controller = linkedSignal(input?.signal);
    let channel: SshSftpChannel | undefined;
    let opened = false;
    let result: T | undefined;
    let operationError: unknown;
    let operationFailed = false;
    try {
      const connection = this.#connection;
      if (this.#phase !== "ready" || connection === undefined) throw new SshConnectionError("ssh connection is closed");
      channel = await raceBounded(
        connection.openSftp(controller.signal),
        input?.openTimeoutMs ?? this.#config.sftpOpenTimeoutMs,
        "ssh sftp open timed out",
        () => controller.abort(),
        (late) => late.destroy(),
        controller.signal,
      );
      if (this.#phase !== "ready") throw new SshConnectionError("ssh connection is closed");
      opened = true;
      result = await raceBounded(
        operation(channel.port, controller.signal),
        input?.operationTimeoutMs ?? this.#config.shutdownTimeoutMs,
        "ssh sftp operation timed out",
        () => {
          controller.abort();
          channel?.destroy();
        },
        undefined,
        controller.signal,
      );
    } catch (error) {
      operationFailed = true;
      operationError = error;
      try {
        channel?.destroy();
      } catch {
        // SFTP channel cleanup is best-effort after fail-closed operation failure.
      }
    }

    let closeFailed = false;
    try {
      if (channel !== undefined) {
        const closingChannel = channel;
        await raceBounded(
          closingChannel.close(),
          input?.closeTimeoutMs ?? this.#config.shutdownTimeoutMs,
          "ssh sftp close timed out",
          () => closingChannel.destroy(),
        );
      }
    } catch {
      closeFailed = true;
      try {
        channel?.destroy();
      } catch {
        // Best effort; connection loss remains fail-closed at manager level.
      }
    } finally {
      controller.dispose();
      await lease.release();
    }

    if (closeFailed) this.#failClosed("sftp-close-failed");
    if (operationFailed) {
      if (opened && isErrorInstance(operationError) && !isSshConnectionError(operationError)) throw operationError;
      throw redactError(operationError, "ssh sftp operation failed");
    }
    if (closeFailed) throw new SshConnectionError("ssh sftp operation failed");
    return result as T;
  }

  public async withBashExec<T>(
    input: {
      wrappedCommand: string;
      signal?: AbortSignal;
      openTimeoutMs?: number;
      closeTimeoutMs?: number;
      operationTimeoutMs?: number;
    },
    operation: (port: CogsExecPort) => Promise<T>,
  ): Promise<T> {
    const lease = await this.acquire("exec", input.signal === undefined ? {} : { signal: input.signal });
    const openSignal = linkedSignal(input.signal);
    let channel: SshExecChannel | undefined;
    let opened = false;
    let result: T | undefined;
    let operationError: unknown;
    let operationFailed = false;
    let terminalSignal = false;
    try {
      const connection = this.#connection;
      if (this.#phase !== "ready" || connection === undefined) throw new SshConnectionError("ssh connection is closed");
      channel = await raceBounded(
        connection.openExec(input.wrappedCommand, openSignal.signal),
        input.openTimeoutMs ?? this.#config.execOpenTimeoutMs,
        "ssh exec open timed out",
        () => openSignal.abort(),
        (late) => late.destroy(),
        openSignal.signal,
      );
      openSignal.dispose();
      if (this.#phase !== "ready") throw new SshConnectionError("ssh connection is closed");
      opened = true;
      result = await raceBounded(
        (async () => {
          const operationResult = await operation(channel.port);
          const terminal = await channel.port.terminal();
          terminalSignal = terminal.signal !== null;
          return operationResult;
        })(),
        input.operationTimeoutMs ?? this.#config.shutdownTimeoutMs,
        "ssh exec operation timed out",
        () => channel?.destroy(),
      );
    } catch (error) {
      operationFailed = true;
      operationError = error;
      try {
        channel?.destroy();
      } catch {
        // Exec channel cleanup is best-effort after fail-closed operation failure.
      }
    }

    let closeFailed = false;
    try {
      if (channel !== undefined) {
        const closingChannel = channel;
        await raceBounded(
          closingChannel.close(),
          input.closeTimeoutMs ?? this.#config.shutdownTimeoutMs,
          "ssh exec close timed out",
          () => closingChannel.destroy(),
        );
      }
    } catch {
      closeFailed = true;
      try {
        channel?.destroy();
      } catch {
        // Best effort; connection loss remains fail-closed at manager level.
      }
    } finally {
      openSignal.dispose();
      await lease.release();
    }

    if (!operationFailed && terminalSignal) this.#failClosed("exec-ended-by-signal");
    if (closeFailed) this.#failClosed("exec-close-failed");
    if (operationFailed) {
      if (opened) this.#failClosed("exec-operation-failed");
      if (opened && isErrorInstance(operationError) && !isSshConnectionError(operationError)) throw operationError;
      throw redactError(operationError, "ssh exec operation failed");
    }
    if (closeFailed) throw new SshConnectionError("ssh exec operation failed");
    return result as T;
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
  public openSftp(signal: AbortSignal): Promise<SshSftpChannel> {
    return new Promise((resolveOpen, rejectOpen) => {
      if (this.#closed || this.#lost !== undefined) {
        rejectOpen(new SshConnectionError("ssh connection is closed"));
        return;
      }
      if (signal.aborted) {
        rejectOpen(new SshConnectionError("ssh sftp open aborted"));
        return;
      }
      let settled = false;
      let channel: Ssh2SftpChannel | undefined;
      const finish = (error?: Error, sftp?: SFTPWrapper) => {
        if (settled) {
          if (sftp !== undefined) destroySftpWrapper(sftp);
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        if (error !== undefined || sftp === undefined || signal.aborted) {
          if (sftp !== undefined) destroySftpWrapper(sftp);
          channel?.destroy();
          rejectOpen(
            error ?? new SshConnectionError(signal.aborted ? "ssh sftp open aborted" : "ssh sftp open failed"),
          );
          return;
        }
        channel = new Ssh2SftpChannel(sftp);
        resolveOpen(channel);
      };
      const onAbort = () => finish(new SshConnectionError("ssh sftp open aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        this.client.sftp((error, sftp) =>
          finish(error === undefined ? undefined : new SshConnectionError("ssh sftp open failed"), sftp),
        );
      } catch {
        finish(new SshConnectionError("ssh sftp open failed"));
      }
    });
  }
  public openExec(command: string, signal: AbortSignal): Promise<SshExecChannel> {
    return new Promise((resolveOpen, rejectOpen) => {
      if (this.#closed || this.#lost !== undefined)
        return rejectOpen(new SshConnectionError("ssh connection is closed"));
      if (signal.aborted) return rejectOpen(new SshConnectionError("ssh exec open aborted"));
      let settled = false;
      const finish = (error?: Error | null, channel?: ClientChannel) => {
        if (settled) {
          if (channel !== undefined) destroyExecChannel(channel);
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        if ((error !== undefined && error !== null) || channel === undefined || signal.aborted) {
          if (channel !== undefined) destroyExecChannel(channel);
          rejectOpen(new SshConnectionError(signal.aborted ? "ssh exec open aborted" : "ssh exec open failed"));
          return;
        }
        try {
          resolveOpen(new Ssh2ExecChannel(channel));
        } catch {
          destroyExecChannel(channel);
          rejectOpen(new SshConnectionError("ssh exec open failed"));
        }
      };
      const onAbort = () => finish(new SshConnectionError("ssh exec open aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        this.client.exec(command, { pty: false, x11: false, agentForward: false } as never, (error, channel) =>
          finish(error, channel),
        );
      } catch {
        finish(new SshConnectionError("ssh exec open failed"));
      }
    });
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

class Ssh2SftpChannel implements SshSftpChannel {
  public readonly port: CogsSftpPort;
  #closed = false;
  readonly #closeWaiters = new Set<() => void>();
  readonly #onClose = () => {
    if (this.#closed) return;
    this.#closed = true;
    for (const waiter of [...this.#closeWaiters]) waiter();
    this.#closeWaiters.clear();
  };
  public constructor(private readonly sftp: SFTPWrapper) {
    this.port = new Ssh2SftpPort(sftp);
    try {
      this.sftp.once("close", this.#onClose);
    } catch {
      this.#onClose();
    }
  }
  public close(): Promise<void> {
    if (this.#closed) return Promise.resolve();
    return new Promise((resolveClose, rejectClose) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        this.#closeWaiters.delete(done);
        resolveClose();
      };
      this.#closeWaiters.add(done);
      try {
        this.sftp.end();
      } catch {
        this.#closeWaiters.delete(done);
        if (!settled) {
          settled = true;
          rejectClose(new Error("sftp close failed"));
        }
      }
    });
  }
  public destroy(): void {
    destroySftpWrapper(this.sftp);
    this.#onClose();
  }
}

function destroySftpWrapper(sftp: SFTPWrapper): void {
  try {
    const destroy = (sftp as { destroy?: () => void }).destroy;
    if (typeof destroy === "function") destroy.call(sftp);
    else sftp.end();
  } catch {
    // Best-effort channel teardown.
  }
}

class Ssh2ExecChannel implements SshExecChannel, CogsExecPort {
  public readonly port: CogsExecPort = this;
  readonly #stdout = new Set<(chunk: Buffer) => void>();
  readonly #stderr = new Set<(chunk: Buffer) => void>();
  #terminalResolve: ((value: CogsExecTerminal) => void) | undefined;
  #terminalReject: ((error: Error) => void) | undefined;
  readonly #terminal = new Promise<CogsExecTerminal>((resolve, reject) => {
    this.#terminalResolve = resolve;
    this.#terminalReject = reject;
  });
  #exit: CogsExecTerminal | undefined;
  #settled = false;
  #closed = false;
  readonly #onStdout = (chunk: unknown) => this.#data("stdout", chunk);
  readonly #onStderr = (chunk: unknown) => this.#data("stderr", chunk);
  readonly #onExit = (code: unknown, signal: unknown, coreDump: unknown, description: unknown) =>
    this.#exitEvent(code, signal, coreDump, description);
  readonly #onClose = () => this.#closeEvent();
  readonly #onError = () => this.#fail();
  readonly #lateErrorSink = () => undefined;
  readonly #stderrStream;
  public constructor(private readonly channel: ClientChannel) {
    this.#terminal.catch(() => undefined);
    try {
      this.#stderrStream = channel.stderr;
      channel.on("error", this.#lateErrorSink);
      this.#stderrStream.on("error", this.#lateErrorSink);
      channel.on("data", this.#onStdout);
      this.#stderrStream.on("data", this.#onStderr);
      this.#stderrStream.on("error", this.#onError);
      channel.on("exit", this.#onExit);
      channel.on("error", this.#onError);
      channel.on("close", this.#onClose);
    } catch {
      this.#cleanup();
      throw new Error("exec channel failed");
    }
  }
  public onStdout(listener: (chunk: Buffer) => void): void {
    if (this.#settled) throw new Error("exec channel closed");
    this.#stdout.add(listener);
  }
  public onStderr(listener: (chunk: Buffer) => void): void {
    if (this.#settled) throw new Error("exec channel closed");
    this.#stderr.add(listener);
  }
  public terminal(): Promise<CogsExecTerminal> {
    return this.#terminal;
  }
  public signal(name: "TERM" | "INT"): Promise<void> {
    if (this.#settled) return Promise.reject(new Error("exec channel closed"));
    return new Promise((resolve, reject) => {
      try {
        this.channel.signal(name);
        resolve();
      } catch {
        reject(new Error("exec signal failed"));
      }
    });
  }
  public close(): Promise<void> {
    if (this.#closed) return Promise.resolve();
    return new Promise((resolveClose, rejectClose) => {
      const done = () => resolveClose();
      try {
        this.channel.once("close", done);
        this.channel.close();
      } catch {
        try {
          this.channel.off("close", done);
        } catch {
          // Listener cleanup is best-effort.
        }
        rejectClose(new Error("exec close failed"));
      }
    });
  }
  public destroy(): void {
    destroyExecChannel(this.channel);
  }
  #data(kind: "stdout" | "stderr", chunk: unknown): void {
    if (this.#settled) return;
    if (!Buffer.isBuffer(chunk)) {
      this.#fail();
      return;
    }
    const listeners = kind === "stdout" ? this.#stdout : this.#stderr;
    for (const listener of [...listeners]) {
      try {
        listener(chunk);
      } catch {
        this.#fail();
        break;
      }
    }
  }
  #exitEvent(code: unknown, signal: unknown, coreDump: unknown, description: unknown): void {
    if (this.#settled || this.#exit !== undefined) {
      this.#fail();
      return;
    }
    if (coreDump !== undefined && coreDump !== false) {
      this.#fail();
      return;
    }
    if (description !== undefined && (typeof description !== "string" || description.length > 1024)) {
      this.#fail();
      return;
    }
    if (Number.isInteger(code) && (code as number) >= 0 && (code as number) <= 255 && signal == null) {
      this.#exit = { code: code as number, signal: null };
      return;
    }
    if (code == null && typeof signal === "string" && EXEC_SIGNAL_NAMES.has(signal)) {
      this.#exit = { code: null, signal };
      return;
    }
    this.#fail();
  }
  #closeEvent(): void {
    if (this.#settled) return;
    this.#closed = true;
    if (this.#exit === undefined) {
      this.#fail();
      return;
    }
    this.#settled = true;
    this.#cleanup();
    this.#terminalResolve?.(this.#exit);
  }
  #fail(): void {
    if (this.#settled) return;
    this.#settled = true;
    this.#cleanup();
    this.#terminalReject?.(new Error("exec channel failed"));
  }
  #cleanup(): void {
    this.#stdout.clear();
    this.#stderr.clear();
    safeEmitterOff(this.channel, "data", this.#onStdout);
    safeEmitterOff(this.#stderrStream, "data", this.#onStderr);
    safeEmitterOff(this.#stderrStream, "error", this.#onError);
    safeEmitterOff(this.channel, "exit", this.#onExit);
    safeEmitterOff(this.channel, "error", this.#onError);
    safeEmitterOff(this.channel, "close", this.#onClose);
  }
}

function safeEmitterOff(
  emitter: { off?: (event: string | symbol, listener: (...args: unknown[]) => void) => unknown },
  event: string,
  listener: (...args: unknown[]) => void,
): void {
  try {
    emitter.off?.(event, listener);
  } catch {
    // Listener cleanup is best-effort after terminal settlement.
  }
}

const EXEC_SIGNAL_NAMES = new Set([
  "SIGABRT",
  "SIGALRM",
  "SIGHUP",
  "SIGFPE",
  "SIGILL",
  "SIGINT",
  "SIGKILL",
  "SIGPIPE",
  "SIGQUIT",
  "SIGSEGV",
  "SIGTERM",
  "SIGUSR1",
  "SIGUSR2",
]);

function destroyExecChannel(channel: ClientChannel): void {
  try {
    channel.on("error", () => undefined);
  } catch {
    // Best-effort late error sink.
  }
  try {
    channel.stderr.on("error", () => undefined);
  } catch {
    // Best-effort late error sink.
  }
  try {
    channel.destroy();
  } catch {
    // Best-effort channel teardown.
  }
}

class Ssh2SftpPort implements CogsSftpPort {
  public constructor(private readonly sftp: SFTPWrapper) {}
  public lstat(path: string, _signal: AbortSignal): Promise<CogsSftpStats> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.lstat(path, (error, stats) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
            return toCogsStats(stats);
          },
        ),
      );
    });
  }
  public realpath(path: string, _signal: AbortSignal): Promise<string> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.realpath(path, (error, resolved) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
            if (typeof resolved !== "string") throw new Error("invalid realpath");
            return resolved;
          },
        ),
      );
    });
  }
  public open(path: string, mode: "r" | "wx", signal: AbortSignal): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanupLateHandle = (handle: Buffer) => {
        this.closeHandle(handle, new AbortController().signal)
          .then(() => (mode === "wx" ? this.unlink(path, new AbortController().signal) : undefined))
          .catch(() => {
            destroySftpWrapper(this.sftp);
          });
      };
      const finish = (error?: unknown, handle?: Buffer) => {
        if (settled) {
          if (Buffer.isBuffer(handle)) cleanupLateHandle(handle);
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        try {
          if (error !== undefined && error !== null) reject(toCogsSftpError(error));
          else if (signal.aborted) {
            if (Buffer.isBuffer(handle)) cleanupLateHandle(handle);
            reject(new Error("sftp open aborted"));
          } else if (isValidHandle(handle)) resolve(handle);
          else reject(new Error("invalid handle"));
        } catch {
          reject(new Error("sftp operation failed"));
        }
      };
      const onAbort = () => finish(new Error("sftp open aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      if (mode === "r") this.sftp.open(path, mode, finish);
      else this.sftp.open(path, mode, { mode: 0o600 }, finish);
    });
  }
  public read(
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    _signal: AbortSignal,
  ): Promise<{ bytesRead: number; buffer: Buffer; position: number }> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.read(handle, buffer, offset, length, position, (error, bytesRead, returned, returnedPosition) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) {
              const mapped = toCogsSftpError(error);
              if (mapped instanceof CogsSftpStatusError && mapped.status === "eof")
                return { bytesRead: 0, buffer, position };
              throw mapped;
            }
            if (!validReadTuple(buffer, offset, length, position, bytesRead, returned, returnedPosition))
              throw new Error("invalid read result");
            return { bytesRead, buffer, position };
          },
        ),
      );
    });
  }
  public write(
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    _signal: AbortSignal,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.write(handle, buffer, offset, length, position, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public fstat(handle: Buffer, _signal: AbortSignal): Promise<CogsSftpStats> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.fstat(handle, (error, stats) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
            return toCogsStats(stats);
          },
        ),
      );
    });
  }
  public closeHandle(handle: Buffer, _signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.close(handle, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public unlink(path: string, _signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.unlink(path, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public mkdir(path: string, mode: number, _signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.mkdir(path, { mode }, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public setMode(path: string, mode: number, _signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.chmod(path, mode, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public rmdir(path: string, _signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.rmdir(path, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public fsync(handle: Buffer, _signal: AbortSignal): Promise<void> {
    if (typeof this.sftp.ext_openssh_fsync !== "function") return Promise.reject(new Error("fsync unavailable"));
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.ext_openssh_fsync(handle, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
  public posixRename(source: string, target: string, _signal: AbortSignal): Promise<void> {
    if (typeof this.sftp.ext_openssh_rename !== "function") return Promise.reject(new Error("rename unavailable"));
    return new Promise((resolve, reject) => {
      let settled = false;
      this.sftp.ext_openssh_rename(source, target, (error) =>
        settleSftpCallback(
          () => settled,
          () => {
            settled = true;
          },
          resolve,
          reject,
          () => {
            if (error !== undefined && error !== null) throw toCogsSftpError(error);
          },
        ),
      );
    });
  }
}

function settleSftpCallback<T>(
  isSettled: () => boolean,
  markSettled: () => void,
  resolve: (value: T) => void,
  reject: (error: Error) => void,
  convert: () => T,
): void {
  if (isSettled()) return;
  markSettled();
  try {
    resolve(convert());
  } catch (error) {
    reject(sanitizeSftpError(error));
  }
}

function sanitizeSftpError(error: unknown): Error {
  const status = cogsStatusFromOwnedError(error);
  return status === undefined ? new Error("sftp operation failed") : new CogsSftpStatusError(status);
}

function cogsStatusFromOwnedError(error: unknown): CogsSftpStatus | undefined {
  try {
    if (!(error instanceof CogsSftpStatusError)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, "status");
    if (descriptor === undefined || !("value" in descriptor)) return undefined;
    return isCogsSftpStatus(descriptor.value) ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function isCogsSftpStatus(value: unknown): value is CogsSftpStatus {
  return value === "eof" || value === "no_such_file" || value === "permission_denied" || value === "failure";
}

function toCogsSftpError(error: unknown): Error {
  try {
    const status = sftpStatusFromError(error);
    if (status !== undefined) return new CogsSftpStatusError(status);
  } catch {
    // Hostile error objects/proxies are redacted below.
  }
  return new Error("sftp operation failed");
}

function sftpStatusFromError(error: unknown): CogsSftpStatus | undefined {
  if (error === null || typeof error !== "object") return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(error, "code");
  if (descriptor === undefined || !("value" in descriptor) || !Number.isInteger(descriptor.value)) return undefined;
  return descriptor.value === 1
    ? "eof"
    : descriptor.value === 2
      ? "no_such_file"
      : descriptor.value === 3
        ? "permission_denied"
        : descriptor.value === 4
          ? "failure"
          : undefined;
}

function isValidHandle(handle: unknown): handle is Buffer {
  return Buffer.isBuffer(handle) && handle.length > 0 && handle.length <= 256;
}

function validReadTuple(
  destination: Buffer,
  offset: number,
  length: number,
  position: number,
  bytesRead: unknown,
  returned: unknown,
  returnedPosition: unknown,
): returned is Buffer {
  if (!Number.isInteger(bytesRead) || (bytesRead as number) < 0 || (bytesRead as number) > length) return false;
  if (returnedPosition !== position || !Buffer.isBuffer(returned)) return false;
  const read = bytesRead as number;
  if (returned.length !== read && returned.length !== length && returned.length !== destination.length) return false;
  if (read === 0) return true;
  const source = returned.length === read ? returned.subarray(0, read) : returned.subarray(offset, offset + read);
  return source.length === read && source.equals(destination.subarray(offset, offset + read));
}

function toCogsStats(stats: unknown): CogsSftpStats {
  if (stats === null || typeof stats !== "object") throw new Error("invalid stats");
  const sizeDescriptor = Object.getOwnPropertyDescriptor(stats, "size");
  const modeDescriptor = Object.getOwnPropertyDescriptor(stats, "mode");
  if (sizeDescriptor === undefined || !("value" in sizeDescriptor) || !Number.isSafeInteger(sizeDescriptor.value))
    throw new Error("invalid stats");
  if (modeDescriptor === undefined || !("value" in modeDescriptor) || !Number.isSafeInteger(modeDescriptor.value))
    throw new Error("invalid stats");
  const size = sizeDescriptor.value as number;
  const mode = modeDescriptor.value as number;
  if (size < 0 || mode < 0 || mode > 0o177777) throw new Error("invalid stats");
  const kind = mode & 0o170000;
  const type =
    kind === 0o100000
      ? "file"
      : kind === 0o040000
        ? "directory"
        : kind === 0o120000
          ? "symlink"
          : kind === 0o010000
            ? "fifo"
            : kind === 0o060000
              ? "block"
              : kind === 0o020000
                ? "character"
                : kind === 0o140000
                  ? "socket"
                  : "unknown";
  if (type === "unknown") throw new Error("invalid stats");
  return { size, type };
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
    sftpOpenTimeoutMs: integer(config.sftpOpenTimeoutMs, DEFAULT_SFTP_OPEN_TIMEOUT_MS, 1, 60_000, "sftp open timeout"),
    execOpenTimeoutMs: integer(config.execOpenTimeoutMs, DEFAULT_EXEC_OPEN_TIMEOUT_MS, 1, 60_000, "exec open timeout"),
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

function isErrorInstance(error: unknown): error is Error {
  try {
    return error instanceof Error;
  } catch {
    return false;
  }
}

function throwIfAbortedSync(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new SshConnectionError("ssh operation aborted");
}

function isSshConnectionError(error: unknown): error is SshConnectionError {
  try {
    return error instanceof SshConnectionError;
  } catch {
    return false;
  }
}

function redactError(error: unknown, fallback: string): SshConnectionError {
  if (isSshConnectionError(error)) return new SshConnectionError(error.message);
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
