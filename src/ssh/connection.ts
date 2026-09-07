import { timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import type { ClientChannel, SFTPWrapper } from "ssh2";
import ssh2, { type ConnectConfig } from "ssh2";
import type { LaunchConfig } from "../launch/config.ts";
import {
  type CogsTelemetry,
  captureTelemetry,
  emitSpan,
  telemetryDuration,
  telemetryStart,
} from "../telemetry/instrumentation.ts";

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
  readonly mode?: number;
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

export class CogsSftpUncertainError extends Error {
  public constructor() {
    super("sftp operation outcome uncertain");
    this.name = "CogsSftpUncertainError";
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
  readonly setModeHandle?: (handle: Buffer, mode: number, signal: AbortSignal) => Promise<void>;
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
  readonly telemetry?: CogsTelemetry;
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
  readonly #telemetry: CogsTelemetry;
  #phase: Phase = "created";
  #connection: SshTransportConnection | undefined;
  #startupPhaseRetired: Promise<void> = Promise.resolve();
  #resolveStartupPhase: (() => void) | undefined;
  #startupConnectionWork: Promise<SshTransportConnection> | undefined;
  #privateKey: Buffer | undefined;
  #waiters: Waiter[] = [];
  #active = new Set<ActivePermit>();
  #activeRetired: Promise<void> = Promise.resolve();
  #resolveActiveRetired: (() => void) | undefined;
  #lost = false;
  #shutdownPromise: Promise<void> | undefined;
  #shutdownActual: Promise<void> | undefined;
  #boundLost: ((error?: unknown) => void) | undefined;

  public constructor(options: SshConnectionManagerOptions) {
    this.#config = validateConfig(options.config);
    this.#transport = options.transport ?? new Ssh2Transport();
    this.#onLost = options.onLost;
    this.#telemetry = captureTelemetry(options.telemetry);
  }

  public get ready(): boolean {
    return this.#phase === "ready";
  }

  public async start(signal?: AbortSignal): Promise<void> {
    const start = telemetryStart();
    if (this.#phase !== "created") throw new SshConnectionError("ssh manager can start only once");
    this.#phase = "starting";
    this.#startupPhaseRetired = new Promise<void>((resolve) => {
      this.#resolveStartupPhase = resolve;
    });
    let connection: SshTransportConnection | undefined;
    try {
      throwIfAbortedSync(signal);
      const key = await readPrivateKey(this.#config.clientKeyPath, this.#config.maxPrivateKeyBytes);
      this.#privateKey = key;
      if (this.#phase !== "starting") throw new SshConnectionError("ssh start interrupted");
      const { host, port } = parseEndpoint(this.#config.endpoint);
      const timeoutMs = this.#config.connectTimeoutMs + this.#config.handshakeTimeoutMs;
      const controller = linkedSignal(signal);
      try {
        this.#startupConnectionWork = this.#transport.connect(
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
        );
        connection = await raceBounded(
          this.#startupConnectionWork,
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
      this.#retireStartupPhase();
      emitSpan(this.#telemetry, "ssh.connect", {
        operation: "connect",
        outcome: "ok",
        duration_ms: telemetryDuration(undefined, start),
      });
    } catch (error) {
      try {
        connection?.destroy();
      } catch {
        // Transport cleanup is best-effort; start must still fail closed and clear key material.
      }
      this.#phase = "failed";
      this.#retireStartupPhase();
      await this.shutdown().catch(() => undefined);
      emitSpan(this.#telemetry, "ssh.connect", {
        operation: "connect",
        outcome: "error",
        duration_ms: telemetryDuration(undefined, start),
      });
      throw redactError(error, "ssh start failed");
    }
  }

  public async withSftp<T>(
    input:
      | { signal?: AbortSignal; openTimeoutMs?: number; closeTimeoutMs?: number; operationTimeoutMs?: number }
      | undefined,
    operation: (port: CogsSftpPort, signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const start = telemetryStart();
    let lease: SshPermitLease;
    try {
      lease = await this.acquire("sftp", input?.signal === undefined ? {} : { signal: input.signal });
    } catch (error) {
      const outcome = input?.signal?.aborted === true ? "cancelled" : "error";
      emitSpan(this.#telemetry, "ssh.channel", {
        operation: "channel",
        outcome,
        duration_ms: telemetryDuration(undefined, start),
      });
      emitSpan(this.#telemetry, "sftp.operation", {
        operation: "channel",
        outcome,
        duration_ms: telemetryDuration(undefined, start),
      });
      throw error;
    }
    const controller = linkedSignal(input?.signal);
    let channel: SshSftpChannel | undefined;
    let opened = false;
    let result: T | undefined;
    let operationError: unknown;
    let operationFailed = false;
    let timedOut = false;
    let openActual: Promise<SshSftpChannel> | undefined;
    let operationActual: Promise<T> | undefined;
    let closeActual: Promise<void> | undefined;
    let lateCloseActual: Promise<void> | undefined;
    try {
      const connection = this.#connection;
      if (this.#phase !== "ready" || connection === undefined) throw new SshConnectionError("ssh connection is closed");
      openActual = connection.openSftp(controller.signal);
      channel = await raceBounded(
        openActual,
        input?.openTimeoutMs ?? this.#config.sftpOpenTimeoutMs,
        "ssh sftp open timed out",
        () => {
          timedOut = true;
          controller.abort();
        },
        (late) => {
          late.destroy();
          lateCloseActual = Promise.resolve().then(() => late.close());
          void lateCloseActual.catch(() => undefined);
        },
        controller.signal,
      );
      if (this.#phase !== "ready") throw new SshConnectionError("ssh connection is closed");
      opened = true;
      const activeChannel = channel;
      operationActual = Promise.resolve().then(() => operation(activeChannel.port, controller.signal));
      result = await raceBounded(
        operationActual,
        input?.operationTimeoutMs ?? this.#config.shutdownTimeoutMs,
        "ssh sftp operation timed out",
        () => {
          timedOut = true;
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
        closeActual = Promise.resolve().then(() => closingChannel.close());
        await raceBounded(
          closeActual,
          input?.closeTimeoutMs ?? this.#config.shutdownTimeoutMs,
          "ssh sftp close timed out",
          () => {
            timedOut = true;
            closingChannel.destroy();
          },
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
      const retirement = retirePermit(lease, () => [openActual, operationActual, closeActual, lateCloseActual]);
      if (!timedOut) await retirement;
      else void retirement.catch(() => undefined);
    }

    if (closeFailed) this.#failClosed("sftp-close-failed");
    if (operationFailed) {
      if (timedOut || isSftpUncertainError(operationError)) this.#failClosed("sftp-operation-uncertain");
      const outcome = timedOut ? "timeout" : input?.signal?.aborted === true ? "cancelled" : "error";
      emitSpan(this.#telemetry, "ssh.channel", {
        operation: "channel",
        outcome,
        duration_ms: telemetryDuration(undefined, start),
        timed_out: timedOut,
      });
      emitSpan(this.#telemetry, "sftp.operation", {
        operation: "channel",
        outcome,
        duration_ms: telemetryDuration(undefined, start),
        timed_out: timedOut,
      });
      if (opened && !timedOut && isErrorInstance(operationError) && !isSshConnectionError(operationError))
        throw operationError;
      throw redactError(operationError, "ssh sftp operation failed");
    }
    if (closeFailed) {
      emitSpan(this.#telemetry, "ssh.channel", {
        operation: "channel",
        outcome: timedOut ? "timeout" : "error",
        duration_ms: telemetryDuration(undefined, start),
        timed_out: timedOut,
      });
      emitSpan(this.#telemetry, "sftp.operation", {
        operation: "channel",
        outcome: timedOut ? "timeout" : "error",
        duration_ms: telemetryDuration(undefined, start),
        timed_out: timedOut,
      });
      throw new SshConnectionError("ssh sftp operation failed");
    }
    emitSpan(this.#telemetry, "ssh.channel", {
      operation: "channel",
      outcome: "ok",
      duration_ms: telemetryDuration(undefined, start),
    });
    emitSpan(this.#telemetry, "sftp.operation", {
      operation: "channel",
      outcome: "ok",
      duration_ms: telemetryDuration(undefined, start),
    });
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
    const start = telemetryStart();
    let lease: SshPermitLease;
    try {
      lease = await this.acquire("exec", input.signal === undefined ? {} : { signal: input.signal });
    } catch (error) {
      emitSpan(this.#telemetry, "ssh.channel", {
        operation: "channel",
        outcome: input.signal?.aborted === true ? "cancelled" : "error",
        duration_ms: telemetryDuration(undefined, start),
      });
      throw error;
    }
    const openSignal = linkedSignal(input.signal);
    let channel: SshExecChannel | undefined;
    let opened = false;
    let result: T | undefined;
    let operationError: unknown;
    let operationFailed = false;
    let terminalSignal = false;
    let timedOut = false;
    let openActual: Promise<SshExecChannel> | undefined;
    let operationActual: Promise<T> | undefined;
    let closeActual: Promise<void> | undefined;
    let lateCloseActual: Promise<void> | undefined;
    try {
      const connection = this.#connection;
      if (this.#phase !== "ready" || connection === undefined) throw new SshConnectionError("ssh connection is closed");
      openActual = connection.openExec(input.wrappedCommand, openSignal.signal);
      channel = await raceBounded(
        openActual,
        input.openTimeoutMs ?? this.#config.execOpenTimeoutMs,
        "ssh exec open timed out",
        () => {
          timedOut = true;
          openSignal.abort();
        },
        (late) => {
          late.destroy();
          lateCloseActual = Promise.resolve().then(() => late.close());
          void lateCloseActual.catch(() => undefined);
        },
        openSignal.signal,
      );
      openSignal.dispose();
      if (this.#phase !== "ready") throw new SshConnectionError("ssh connection is closed");
      opened = true;
      operationActual = (async () => {
        const operationResult = await operation(channel.port);
        const terminal = await channel.port.terminal();
        terminalSignal = terminal.signal !== null;
        return operationResult;
      })();
      result = await raceBounded(
        operationActual,
        input.operationTimeoutMs ?? this.#config.shutdownTimeoutMs,
        "ssh exec operation timed out",
        () => {
          timedOut = true;
          channel?.destroy();
        },
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
        closeActual = Promise.resolve().then(() => closingChannel.close());
        await raceBounded(
          closeActual,
          input.closeTimeoutMs ?? this.#config.shutdownTimeoutMs,
          "ssh exec close timed out",
          () => {
            timedOut = true;
            closingChannel.destroy();
          },
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
      const retirement = retirePermit(lease, () => [openActual, operationActual, closeActual, lateCloseActual]);
      if (!timedOut) await retirement;
      else void retirement.catch(() => undefined);
    }

    if (!operationFailed && terminalSignal) this.#failClosed("exec-ended-by-signal");
    if (closeFailed) this.#failClosed("exec-close-failed");
    if (operationFailed) {
      emitSpan(this.#telemetry, "ssh.channel", {
        operation: "channel",
        outcome: "error",
        duration_ms: telemetryDuration(undefined, start),
      });
      if (opened || timedOut) this.#failClosed("exec-operation-failed");
      if (opened && isErrorInstance(operationError) && !isSshConnectionError(operationError)) throw operationError;
      throw redactError(operationError, "ssh exec operation failed");
    }
    if (closeFailed) {
      emitSpan(this.#telemetry, "ssh.channel", {
        operation: "channel",
        outcome: "error",
        duration_ms: telemetryDuration(undefined, start),
      });
      throw new SshConnectionError("ssh exec operation failed");
    }
    emitSpan(this.#telemetry, "ssh.channel", {
      operation: "channel",
      outcome: "ok",
      duration_ms: telemetryDuration(undefined, start),
    });
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
    this.#phase = "closing";
    for (const waiter of this.#waiters.splice(0))
      this.#settleWaiter(waiter, new SshConnectionError("ssh connection is closed"));
    const connection = this.#connection;
    // Store actual ownership before timers/destroy callbacks can reenter.
    this.#shutdownActual = this.#shutdownOwned(connection);
    void this.#shutdownActual.catch(() => undefined);
    this.#shutdownPromise = raceBounded(
      this.#shutdownActual,
      this.#config.shutdownTimeoutMs,
      "ssh shutdown timed out",
      () => connection?.destroy(),
    ).catch(() => {
      this.#phase = "failed";
      throw new SshConnectionError("ssh shutdown uncertain");
    });
    return this.#shutdownPromise;
  }

  async #shutdownOwned(connection: SshTransportConnection | undefined): Promise<void> {
    if (this.#phase === "closed") return;
    await this.#startupPhaseRetired;
    let startupConnection: SshTransportConnection | undefined;
    try {
      startupConnection = await this.#startupConnectionWork;
    } catch {
      // Rejection occurs only after the transport's acquisition path retires.
    }
    const ownedConnection = connection ?? startupConnection;
    let connectionRetirement = Promise.resolve();
    if (ownedConnection !== undefined) {
      if (this.#boundLost !== undefined) {
        ownedConnection.off("close", this.#boundLost);
        ownedConnection.off("error", this.#boundLost);
      }
      // Safe transport termination starts independently, while key/material
      // release remains behind both transport and active-operation retirement.
      connectionRetirement = ownedConnection.close();
    }
    await Promise.all([this.#activeRetired, connectionRetirement]);
    if (this.#connection === connection || this.#connection === ownedConnection) this.#connection = undefined;
    this.#startupConnectionWork = undefined;
    this.#clearKey();
    this.#phase = this.#lost ? "failed" : "closed";
  }

  #createPermit(kind: SshPermitKind): SshPermitLease {
    const permit: ActivePermit = { released: false };
    if (this.#active.size === 0) {
      this.#activeRetired = new Promise<void>((resolve) => {
        this.#resolveActiveRetired = resolve;
      });
    }
    this.#active.add(permit);
    return { kind, release: async () => this.#releasePermit(permit) };
  }

  #releasePermit(permit: ActivePermit): void {
    if (permit.released) return;
    permit.released = true;
    this.#active.delete(permit);
    if (this.#active.size === 0) {
      this.#resolveActiveRetired?.();
      this.#resolveActiveRetired = undefined;
    }
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
    emitSpan(this.#telemetry, "dependency.lost", { dependency: "ssh", outcome: "error" });
    try {
      this.#onLost?.(reason);
    } catch {
      // Lifecycle callbacks are safety notifications and must not block cleanup.
    }
    void this.shutdown().catch(() => undefined);
  }

  #retireStartupPhase(): void {
    this.#resolveStartupPhase?.();
    this.#resolveStartupPhase = undefined;
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
  readonly telemetry?: CogsTelemetry;
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
    telemetry: input.telemetry,
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
      let cancelled = false;
      let terminalError: Error | undefined;
      const cleanup = () => {
        signal.removeEventListener("abort", onAbort);
        try {
          client.off("ready", onReady);
        } catch {
          // ssh2 listener cleanup is best-effort after terminal failure.
        }
        wrapped.off("close", onPreReadyClose);
        wrapped.off("error", onPreReadyError);
      };
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        error === undefined ? resolveConnect(wrapped) : rejectConnect(error);
      };
      const destroyPending = (error: Error) => {
        terminalError ??= error;
        try {
          client.destroy();
        } catch {
          // Absence of a close event preserves the pending acquisition owner.
        }
      };
      const onAbort = () => {
        cancelled = true;
        destroyPending(new SshConnectionError("ssh connection aborted"));
      };
      const onReady = () => {
        if (cancelled || terminalError !== undefined)
          destroyPending(terminalError ?? new SshConnectionError("ssh connection aborted"));
        else finish();
      };
      const onPreReadyError = () => destroyPending(new SshConnectionError("ssh connection failed"));
      const onPreReadyClose = () => finish(terminalError ?? new SshConnectionError("ssh connection failed"));
      signal.addEventListener("abort", onAbort, { once: true });
      wrapped.on("close", onPreReadyClose);
      wrapped.on("error", onPreReadyError);
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
        destroyPending(new SshConnectionError("ssh connection failed"));
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
  #closing = false;
  #closed = false;
  #resolveRetirement: (() => void) | undefined;
  readonly #retirement = new Promise<void>((resolve) => {
    this.#resolveRetirement = resolve;
  });
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
      if (this.#closing || this.#closed || this.#lost !== undefined) {
        rejectOpen(new SshConnectionError("ssh connection is closed"));
        return;
      }
      if (signal.aborted) {
        rejectOpen(new SshConnectionError("ssh sftp open aborted"));
        return;
      }
      let settled = false;
      let cancelled = false;
      let channel: Ssh2SftpChannel | undefined;
      const finish = (error?: Error, sftp?: SFTPWrapper) => {
        if (settled) {
          if (sftp !== undefined) destroySftpWrapper(sftp);
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        if (error !== undefined || sftp === undefined || signal.aborted || cancelled) {
          if (sftp !== undefined) {
            const failure =
              error ?? new SshConnectionError(signal.aborted ? "ssh sftp open aborted" : "ssh sftp open failed");
            void retireSftpWrapper(sftp).then(() => rejectOpen(failure));
          }
          // Error/no-channel callbacks after client.sftp issuance cannot prove
          // the peer did not open the subsystem. No wrapper means no local
          // retirement mechanism, so preserve uncertainty.
          channel?.destroy();
          return;
        }
        try {
          channel = new Ssh2SftpChannel(sftp);
          resolveOpen(channel);
        } catch {
          void retireSftpWrapper(sftp).then(() => rejectOpen(new SshConnectionError("ssh sftp open failed")));
        }
      };
      // Abort bounds caller observation only. The actual open remains pending
      // until ssh2 invokes its callback, at which point any late channel is destroyed.
      const onAbort = () => {
        cancelled = true;
      };
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        this.client.sftp((error, sftp) =>
          finish(error === undefined ? undefined : new SshConnectionError("ssh sftp open failed"), sftp),
        );
      } catch {
        if (!settled) {
          settled = true;
          signal.removeEventListener("abort", onAbort);
          rejectOpen(new SshConnectionError("ssh sftp open failed"));
        }
      }
    });
  }
  public openExec(command: string, signal: AbortSignal): Promise<SshExecChannel> {
    return new Promise((resolveOpen, rejectOpen) => {
      if (this.#closing || this.#closed || this.#lost !== undefined)
        return rejectOpen(new SshConnectionError("ssh connection is closed"));
      if (signal.aborted) return rejectOpen(new SshConnectionError("ssh exec open aborted"));
      let settled = false;
      let cancelled = false;
      const finish = (error?: Error | null, channel?: ClientChannel) => {
        if (settled) {
          if (channel !== undefined) destroyExecChannel(channel);
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        if (signal.aborted || cancelled) {
          // Even an error/no-channel callback cannot prove the peer did not
          // accept the exec request before transport loss. Keep the acquisition
          // owner permanently unresolved for the outer VM/process owner.
          if (channel !== undefined) destroyExecChannel(channel);
          return;
        }
        if ((error !== undefined && error !== null) || channel === undefined) {
          // Once client.exec accepted the request, callback failure cannot prove
          // that the peer did not start it. Preserve permanent uncertainty.
          if (channel !== undefined) destroyExecChannel(channel);
          return;
        }
        try {
          resolveOpen(new Ssh2ExecChannel(channel));
        } catch {
          destroyExecChannel(channel);
          // The exec success callback proves remote acceptance; failed local
          // channel wrapping cannot retire that command.
        }
      };
      // Keep the actual callback owner alive after caller cancellation.
      const onAbort = () => {
        cancelled = true;
      };
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        this.client.exec(command, { pty: false, x11: false, agentForward: false } as never, (error, channel) =>
          finish(error, channel),
        );
      } catch {
        if (!settled) {
          settled = true;
          signal.removeEventListener("abort", onAbort);
          rejectOpen(new SshConnectionError("ssh exec open failed"));
        }
      }
    });
  }
  public close(): Promise<void> {
    if (this.#closed) return this.#retirement;
    if (!this.#closing) {
      this.#closing = true;
      try {
        if (this.#lost?.event === "error") this.client.destroy();
        else this.client.end();
      } catch {
        try {
          this.client.destroy();
        } catch {
          // Absence of the client close event preserves retirement uncertainty.
        }
      }
    }
    return this.#retirement;
  }
  public destroy(): void {
    this.#closing = true;
    try {
      this.client.destroy();
    } catch {
      // Absence of the client close event preserves retirement uncertainty.
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
    this.#closing = true;
    this.#closed = true;
    this.#resolveRetirement?.();
    this.#resolveRetirement = undefined;
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
  readonly #concretePort: Ssh2SftpPort;
  #closed = false;
  readonly #closeWaiters = new Set<() => void>();
  readonly #onClose = () => {
    if (this.#closed) return;
    this.#closed = true;
    for (const waiter of [...this.#closeWaiters]) waiter();
    this.#closeWaiters.clear();
  };
  public constructor(private readonly sftp: SFTPWrapper) {
    this.#concretePort = new Ssh2SftpPort(sftp);
    this.port = this.#concretePort;
    try {
      this.sftp.once("close", this.#onClose);
    } catch {
      destroySftpWrapper(this.sftp);
      throw new Error("sftp close observation failed");
    }
  }
  public close(): Promise<void> {
    if (this.#closed) return this.#concretePort.retirement();
    const channelClose = new Promise<void>((resolveClose, rejectClose) => {
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
    return channelClose.then(() => this.#concretePort.retirement());
  }
  public destroy(): void {
    destroySftpWrapper(this.sftp);
  }
}

function retireSftpWrapper(sftp: SFTPWrapper): Promise<void> {
  return new Promise<void>((resolve) => {
    try {
      sftp.once("close", resolve);
    } catch {
      return;
    }
    destroySftpWrapper(sftp);
  });
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
  #retirementResolve: (() => void) | undefined;
  readonly #terminal = new Promise<CogsExecTerminal>((resolve, reject) => {
    this.#terminalResolve = resolve;
    this.#terminalReject = reject;
  });
  readonly #retirement = new Promise<void>((resolve) => {
    this.#retirementResolve = resolve;
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
    if (this.#closed) return this.#retirement;
    try {
      this.channel.close();
    } catch {
      // A failed close request cannot retire an accepted remote command.
    }
    return this.#retirement;
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
    if (this.#exit.code !== null) {
      this.#retirementResolve?.();
      this.#retirementResolve = undefined;
    }
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
  readonly #lateWork = new Set<Promise<unknown>>();
  public constructor(private readonly sftp: SFTPWrapper) {}
  public async retirement(): Promise<void> {
    for (;;) {
      const pending = [...this.#lateWork];
      if (pending.length === 0) return;
      await Promise.allSettled(pending);
      await Promise.resolve();
    }
  }
  private trackLate(work: Promise<unknown>): void {
    this.#lateWork.add(work);
    void work.finally(() => this.#lateWork.delete(work)).catch(() => undefined);
  }
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
    const work = new Promise<Buffer>((resolve, reject) => {
      let settled = false;
      let cancelled = false;
      const cleanupLateHandle = (handle: Buffer): Promise<void> => {
        const cleanup = this.closeHandle(handle, new AbortController().signal)
          .then(() => (mode === "wx" ? this.unlink(path, new AbortController().signal) : undefined))
          .catch(() => {
            destroySftpWrapper(this.sftp);
            throw new Error("sftp late handle cleanup failed");
          });
        this.trackLate(cleanup);
        return cleanup;
      };
      const finish = (error?: unknown, handle?: Buffer) => {
        if (settled) {
          if (Buffer.isBuffer(handle)) void cleanupLateHandle(handle).catch(() => undefined);
          return;
        }
        settled = true;
        signal.removeEventListener("abort", onAbort);
        try {
          if (error !== undefined && error !== null) {
            const mapped = toCogsSftpError(error);
            if (mapped instanceof SftpCallbackUncertainError) return;
            reject(mapped);
          } else if (signal.aborted || cancelled) {
            if (Buffer.isBuffer(handle)) {
              void cleanupLateHandle(handle).then(
                () => reject(new Error("sftp open aborted")),
                () => reject(new Error("sftp operation failed")),
              );
            } else reject(new Error("sftp open aborted"));
          } else if (isValidHandle(handle)) resolve(handle);
          else reject(new Error("invalid handle"));
        } catch {
          reject(new Error("sftp operation failed"));
        }
      };
      const onAbort = () => {
        cancelled = true;
      };
      signal.addEventListener("abort", onAbort, { once: true });
      if (mode === "r") this.sftp.open(path, mode, finish);
      else this.sftp.open(path, mode, { mode: 0o600 }, finish);
    });
    return this.owned(work);
  }
  public read(
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    _signal: AbortSignal,
  ): Promise<{ bytesRead: number; buffer: Buffer; position: number }> {
    const work = new Promise<{ bytesRead: number; buffer: Buffer; position: number }>((resolve, reject) => {
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
    return this.owned(work);
  }
  public write(
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    _signal: AbortSignal,
  ): Promise<void> {
    const work = new Promise<void>((resolve, reject) => {
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
    return this.owned(work);
  }
  public fstat(handle: Buffer, _signal: AbortSignal): Promise<CogsSftpStats> {
    const work = new Promise<CogsSftpStats>((resolve, reject) => {
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
    return this.owned(work);
  }
  public closeHandle(handle: Buffer, _signal: AbortSignal): Promise<void> {
    const work = new Promise<void>((resolve, reject) => {
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
    return this.owned(work);
  }
  public unlink(path: string, _signal: AbortSignal): Promise<void> {
    const work = new Promise<void>((resolve, reject) => {
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
    return this.owned(work);
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
  public setModeHandle(handle: Buffer, mode: number, _signal: AbortSignal): Promise<void> {
    const work = new Promise<void>((resolve, reject) => {
      let settled = false;
      this.sftp.fchmod(handle, mode, (error) =>
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
    return this.owned(work);
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
    const work = new Promise<void>((resolve, reject) => {
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
    return this.owned(work);
  }
  public posixRename(source: string, target: string, _signal: AbortSignal): Promise<void> {
    if (typeof this.sftp.ext_openssh_rename !== "function") return Promise.reject(new Error("rename unavailable"));
    const work = new Promise<void>((resolve, reject) => {
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
    return this.owned(work);
  }
  private owned<T>(work: Promise<T>): Promise<T> {
    this.trackLate(work);
    return work;
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
  try {
    const value = convert();
    markSettled();
    resolve(value);
  } catch (error) {
    if (error instanceof SftpCallbackUncertainError) return;
    markSettled();
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

class SftpCallbackUncertainError extends Error {}

function toCogsSftpError(error: unknown): Error {
  try {
    const status = sftpStatusFromError(error);
    if (status !== undefined) return new CogsSftpStatusError(status);
    if (error !== null && typeof error === "object") {
      const descriptor = Object.getOwnPropertyDescriptor(error, "code");
      if (descriptor !== undefined && "value" in descriptor && Number.isSafeInteger(descriptor.value))
        return new Error("sftp operation failed");
    }
  } catch {
    // Hostile error objects/proxies remain uncertain below.
  }
  return new SftpCallbackUncertainError("sftp callback outcome uncertain");
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
  return { size, mode, type };
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

async function retirePermit(
  lease: SshPermitLease,
  current: () => readonly (Promise<unknown> | undefined)[],
): Promise<void> {
  const joined = new Set<Promise<unknown>>();
  for (;;) {
    const pending = current().filter((work): work is Promise<unknown> => work !== undefined && !joined.has(work));
    if (pending.length === 0) break;
    for (const work of pending) joined.add(work);
    await Promise.allSettled(pending);
    // Allow late-open cleanup callbacks registered on the same promises to add
    // their actual close work before the registration frontier is sealed.
    await Promise.resolve();
  }
  await lease.release();
}

function raceBounded<T>(
  promise: Promise<T>,
  timeoutMs: number,
  timeoutMessage: string,
  onTimeout: () => void,
  onLate?: (value: T) => void,
  signal?: AbortSignal,
): Promise<T> {
  const deadlineAt = performance.now() + timeoutMs;
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  let abort: (() => void) | undefined;
  const invokeTimeout = () => {
    try {
      onTimeout();
    } catch {
      // Timeout cleanup is best-effort and must not mask the bounded failure.
    }
  };
  const timeout = new Promise<never>((_, reject) => {
    const rejectOnce = (error: SshConnectionError) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    timer = setTimeout(() => {
      if (settled) return;
      rejectOnce(new SshConnectionError(timeoutMessage));
      invokeTimeout();
    }, timeoutMs);
    if (signal !== undefined) {
      abort = () => {
        invokeTimeout();
        rejectOnce(new SshConnectionError("ssh operation aborted"));
      };
      if (signal.aborted) abort();
      else signal.addEventListener("abort", abort, { once: true });
    }
  });
  const observed = promise.then((value) => {
    if (!settled && performance.now() >= deadlineAt) {
      settled = true;
      invokeTimeout();
      try {
        onLate?.(value);
      } catch {
        // Late cleanup is best-effort; the deadline result remains failure.
      }
      throw new SshConnectionError(timeoutMessage);
    }
    if (settled) {
      try {
        onLate?.(value);
      } catch {
        // Late cleanup is best-effort; the caller has already observed the bounded failure.
      }
    }
    return value;
  });
  return Promise.race([observed, timeout]).finally(() => {
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

function isSftpUncertainError(error: unknown): error is CogsSftpUncertainError {
  try {
    return error instanceof CogsSftpUncertainError;
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
