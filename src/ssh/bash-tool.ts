import { TextDecoder } from "node:util";
import type { JsonValue } from "../api/server.ts";
import type { CogsToolPorts } from "../pi/session.ts";
import type { CogsExecPort, CogsExecTerminal, SshConnectionManager } from "./connection.ts";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS = 10_000;
const DEFAULT_CANCEL_GRACE_MS = 1500;
const DEFAULT_MAX_COMMAND_BYTES = 100_000;
const DEFAULT_MAX_STREAM_BYTES = 4096;
const DEFAULT_MAX_UPDATES = 256;
const DEFAULT_MAX_UPDATE_BYTES = 8192;
const DEFAULT_UPDATE_TIMEOUT_MS = 1000;
const DEFAULT_MAX_RESULT_BYTES = 12 * 1024;

export interface BashToolOptions {
  readonly manager: SshConnectionManager;
  readonly timeoutMs?: number;
  readonly idleTimeoutMs?: number;
  readonly cancelGraceMs?: number;
  readonly maxCommandBytes?: number;
  readonly maxStreamBytes?: number;
  readonly maxUpdates?: number;
  readonly maxUpdateBytes?: number;
  readonly updateTimeoutMs?: number;
  readonly maxResultBytes?: number;
}

type Config = Required<BashToolOptions>;
type Update = {
  content: [{ type: "text"; text: string }];
  details: { cogsTool: "bash"; stream?: "stdout" | "stderr"; terminal?: true; lossyUtf8?: boolean };
};
type Sink = {
  buffer: Buffer | undefined;
  retained: number;
  bytes: number;
  dropped: number;
  truncated: boolean;
  updateDecoder: TextDecoder;
  updateFatalDecoder: TextDecoder;
  updateLossy: boolean;
  lossy: boolean;
  cut: boolean;
};

type AbortKind = "caller" | "timeout" | "idle" | "publisher";

export function createSshBashToolPort(options: BashToolOptions): Pick<CogsToolPorts, "bash"> {
  const config = normalize(options);
  return { bash: (input) => runBash(config, input) };
}

async function runBash(
  config: Config,
  input: { command: string; signal?: AbortSignal; onUpdate?: (update: Update) => void | Promise<void> },
): Promise<JsonValue> {
  validateCommand(input.command, config.maxCommandBytes);
  const started = Date.now();
  const operation = new AbortController();
  let abortKind: AbortKind | undefined;
  const requestAbort = (kind: AbortKind) => {
    abortKind ??= kind;
    operation.abort();
  };
  const callerAbort = () => requestAbort("caller");
  if (input.signal?.aborted) callerAbort();
  else input.signal?.addEventListener("abort", callerAbort, { once: true });
  const totalTimer = setTimeout(() => requestAbort("timeout"), config.timeoutMs);
  let idleTimer: NodeJS.Timeout | undefined;
  const touch = () => {
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => requestAbort("idle"), config.idleTimeoutMs);
  };
  touch();
  const stdout = sink();
  const stderr = sink();
  const publisher = makePublisher(input.onUpdate, config, () => requestAbort("publisher"));
  try {
    return await config.manager.withBashExec(
      {
        wrappedCommand: remoteCommand(input.command, config.cancelGraceMs),
        signal: operation.signal,
        operationTimeoutMs: config.timeoutMs + config.cancelGraceMs * 4 + 5000,
      },
      async (port) => {
        port.onStdout((chunk) => {
          touch();
          append(stdout, chunk, config.maxStreamBytes);
          publisher.enqueue("stdout", stdout, chunk);
        });
        port.onStderr((chunk) => {
          touch();
          append(stderr, chunk, config.maxStreamBytes);
          publisher.enqueue("stderr", stderr, chunk);
        });
        let terminal: CogsExecTerminal;
        try {
          terminal = await Promise.race([port.terminal(), abortPromise(operation.signal), publisher.failure]);
        } catch (error) {
          if (publisher.failed) {
            await cancelAndConfirm(port, config.cancelGraceMs);
            throw new Error("bash update failed");
          }
          if (!operation.signal.aborted) throw error;
          terminal = await cancelAndConfirm(port, config.cancelGraceMs);
        }
        clearTimeout(totalTimer);
        if (idleTimer !== undefined) clearTimeout(idleTimer);
        const out = finish(stdout);
        const err = finish(stderr);
        publisher.flushStream("stdout", stdout);
        publisher.flushStream("stderr", stderr);
        await publisher.terminal({ exitCode: terminal.code, signal: terminal.signal });
        const result = boundResult(
          {
            ok: abortKind === undefined && terminal.code === 0 && terminal.signal === null,
            stdout: out.text,
            stderr: err.text,
            exitCode: terminal.code,
            signal: terminal.signal,
            elapsedMs: Math.max(0, Date.now() - started),
            timedOut: abortKind === "timeout" || abortKind === "idle",
            idleTimedOut: abortKind === "idle",
            cancelled: abortKind === "caller",
            stdoutBytes: stdout.bytes,
            stderrBytes: stderr.bytes,
            stdoutDroppedBytes: stdout.dropped,
            stderrDroppedBytes: stderr.dropped,
            stdoutResultOmittedUtf8Bytes: 0,
            stderrResultOmittedUtf8Bytes: 0,
            stdoutTruncated: stdout.truncated,
            stderrTruncated: stderr.truncated,
            stdoutLossyUtf8: out.lossy,
            stderrLossyUtf8: err.lossy,
            updateDropped: publisher.dropped,
          },
          config.maxResultBytes,
        );
        return result;
      },
    );
  } finally {
    publisher.close();
    input.signal?.removeEventListener("abort", callerAbort);
    clearTimeout(totalTimer);
    if (idleTimer !== undefined) clearTimeout(idleTimer);
  }
}

async function cancelAndConfirm(port: CogsExecPort, graceMs: number): Promise<CogsExecTerminal> {
  try {
    await port.signal("TERM");
  } catch {
    throw new Error("exec cancellation signal failed");
  }
  try {
    return await boundedTerminal(port, graceMs + 250);
  } catch (error) {
    if (!isDeadline(error)) throw error;
  }
  try {
    await port.signal("INT");
  } catch {
    throw new Error("exec cancellation signal failed");
  }
  return boundedTerminal(port, graceMs * 2 + 250);
}

function boundedTerminal(port: CogsExecPort, ms: number): Promise<CogsExecTerminal> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    port.terminal(),
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("deadline")), ms);
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function isDeadline(error: unknown): boolean {
  return error instanceof Error && error.message === "deadline";
}

function abortPromise(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    if (signal.aborted) return reject(new Error("bash aborted"));
    signal.addEventListener("abort", () => reject(new Error("bash aborted")), { once: true });
  });
}

function sink(): Sink {
  return {
    buffer: undefined,
    retained: 0,
    bytes: 0,
    dropped: 0,
    truncated: false,
    updateDecoder: new TextDecoder(),
    updateFatalDecoder: new TextDecoder("utf-8", { fatal: true }),
    updateLossy: false,
    lossy: false,
    cut: false,
  };
}

function append(target: Sink, chunk: Buffer, maxBytes: number): void {
  target.bytes = safeAdd(target.bytes, chunk.length);
  if (target.retained >= maxBytes) {
    target.dropped = safeAdd(target.dropped, chunk.length);
    target.truncated = true;
    target.cut = true;
    return;
  }
  const keep = Math.min(chunk.length, maxBytes - target.retained);
  target.buffer ??= Buffer.allocUnsafe(maxBytes);
  chunk.copy(target.buffer, target.retained, 0, keep);
  target.retained += keep;
  if (keep < chunk.length) {
    target.dropped = safeAdd(target.dropped, chunk.length - keep);
    target.truncated = true;
    target.cut = true;
  }
}

function finish(target: Sink): { text: string; lossy: boolean } {
  const raw = target.buffer?.subarray(0, target.retained) ?? Buffer.alloc(0);
  const trimmed = target.cut ? trimIncompleteUtf8(raw) : raw;
  if (trimmed.length < raw.length) {
    target.lossy = true;
    target.dropped = safeAdd(target.dropped, raw.length - trimmed.length);
    target.truncated = true;
  }
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(trimmed), lossy: target.lossy };
  } catch {
    target.lossy = true;
    return { text: new TextDecoder().decode(trimmed), lossy: true };
  }
}

function trimIncompleteUtf8(buffer: Buffer): Buffer {
  if (buffer.length === 0) return buffer;
  let continuation = 0;
  for (let i = buffer.length - 1; i >= 0 && ((buffer[i] ?? 0) & 0xc0) === 0x80; i--) continuation += 1;
  const lead = buffer[buffer.length - continuation - 1];
  if (lead === undefined) return buffer.subarray(0, buffer.length - continuation);
  const expected = lead >= 0xf0 ? 3 : lead >= 0xe0 ? 2 : lead >= 0xc0 ? 1 : 0;
  return continuation < expected ? buffer.subarray(0, buffer.length - continuation - 1) : buffer;
}

function makePublisher(
  onUpdate: ((update: Update) => void | Promise<void>) | undefined,
  config: Config,
  onFailure: () => void,
) {
  let chain = Promise.resolve();
  let rejectFailure: (error: Error) => void = () => undefined;
  const failure = new Promise<never>((_, reject) => {
    rejectFailure = reject;
  });
  failure.catch(() => undefined);
  let failed = false;
  let closed = false;
  let count = 0;
  let pendingBytes = 0;
  let dropped = 0;
  const fail = (message: string) => {
    if (failed) return;
    failed = true;
    closed = true;
    onFailure();
    rejectFailure(new Error(message));
  };
  const publish = (update: Update, terminal = false) => {
    if (onUpdate === undefined || closed || failed) return;
    const bytes = Buffer.byteLength(JSON.stringify(update), "utf8");
    if (
      !terminal &&
      (++count > config.maxUpdates || bytes > config.maxUpdateBytes || pendingBytes + bytes > config.maxUpdateBytes * 4)
    ) {
      dropped += 1;
      return;
    }
    pendingBytes += bytes;
    chain = chain
      .then(() => {
        if (closed || failed) return undefined;
        return timeout(
          Promise.resolve().then(() => onUpdate(update)),
          config.updateTimeoutMs,
        );
      })
      .catch(() => fail("bash update failed"))
      .finally(() => {
        pendingBytes = Math.max(0, pendingBytes - bytes);
      });
  };
  return {
    get failure() {
      return failure;
    },
    get failed() {
      return failed;
    },
    get dropped() {
      return dropped;
    },
    enqueue(stream: "stdout" | "stderr", sink: Sink, chunk: Buffer) {
      for (let offset = 0; offset < chunk.length; offset += 1024) {
        const piece = chunk.subarray(offset, Math.min(chunk.length, offset + 1024));
        try {
          sink.updateFatalDecoder.decode(piece, { stream: true });
        } catch {
          sink.updateLossy = true;
        }
        const text = sink.updateDecoder.decode(piece, { stream: true });
        if (text.length === 0) continue;
        publish({
          content: [{ type: "text", text: JSON.stringify({ stream, chunk: text.slice(0, 4096) }) }],
          details: { cogsTool: "bash", stream, lossyUtf8: sink.updateLossy },
        });
      }
    },
    flushStream(stream: "stdout" | "stderr", sink: Sink) {
      try {
        sink.updateFatalDecoder.decode();
      } catch {
        sink.updateLossy = true;
      }
      const text = sink.updateDecoder.decode();
      if (text.length > 0)
        publish({
          content: [{ type: "text", text: JSON.stringify({ stream, chunk: text.slice(0, 4096) }) }],
          details: { cogsTool: "bash", stream, lossyUtf8: sink.updateLossy },
        });
    },
    async terminal(value: { exitCode: number | null; signal: string | null }) {
      publish(
        {
          content: [{ type: "text", text: JSON.stringify({ terminal: true, ...value }) }],
          details: { cogsTool: "bash", terminal: true },
        },
        true,
      );
      await chain;
      if (failed) throw new Error("bash update failed");
    },
    close() {
      closed = true;
    },
  };
}

function timeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("deadline")), ms);
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function boundResult<
  T extends {
    stdout: string;
    stderr: string;
    stdoutTruncated: boolean;
    stderrTruncated: boolean;
    stdoutDroppedBytes: number;
    stderrDroppedBytes: number;
    stdoutResultOmittedUtf8Bytes: number;
    stderrResultOmittedUtf8Bytes: number;
  },
>(result: T, maxBytes: number): T {
  let bounded = result;
  while (Buffer.byteLength(JSON.stringify(bounded), "utf8") > maxBytes) {
    const stdoutNext = scalarPrefix(bounded.stdout, Math.max(0, Math.floor(bounded.stdout.length / 2)));
    const stderrNext = scalarPrefix(bounded.stderr, Math.max(0, Math.floor(bounded.stderr.length / 2)));
    if (stdoutNext.length === bounded.stdout.length && stderrNext.length === bounded.stderr.length) break;
    bounded = {
      ...bounded,
      stdout: stdoutNext,
      stderr: stderrNext,
      stdoutTruncated: true,
      stderrTruncated: true,
      stdoutResultOmittedUtf8Bytes: safeAdd(
        bounded.stdoutResultOmittedUtf8Bytes,
        Buffer.byteLength(bounded.stdout.slice(stdoutNext.length)),
      ),
      stderrResultOmittedUtf8Bytes: safeAdd(
        bounded.stderrResultOmittedUtf8Bytes,
        Buffer.byteLength(bounded.stderr.slice(stderrNext.length)),
      ),
    };
    if (stdoutNext.length === 0 && stderrNext.length === 0) break;
  }
  if (Buffer.byteLength(JSON.stringify(bounded), "utf8") > maxBytes) throw new Error("bash result too large");
  return bounded;
}

function scalarPrefix(value: string, maxCodeUnits: number): string {
  if (maxCodeUnits <= 0) return "";
  let end = Math.min(value.length, maxCodeUnits);
  const last = value.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return value.slice(0, end);
}

function safeAdd(a: number, b: number): number {
  const next = a + b;
  return Number.isSafeInteger(next) ? next : Number.MAX_SAFE_INTEGER;
}

function validateCommand(command: string, maxBytes: number): void {
  if (command.length === 0 || command.includes("\0") || /[\uD800-\uDFFF]/u.test(command))
    throw new Error("invalid command");
  if (Buffer.byteLength(command, "utf8") > maxBytes) throw new Error("command too large");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

export function buildRemoteBashCommandForTest(command: string, graceMs = DEFAULT_CANCEL_GRACE_MS): string {
  return remoteCommand(command, graceMs);
}

function remoteCommand(command: string, graceMs: number): string {
  const wrapper = `child=0
escalate(){ trap '' TERM HUP; trap - INT; if [ "$child" -gt 0 ]; then kill -KILL -"$child" 2>/dev/null; wait "$child" 2>/dev/null; fi; exit "$1"; }
cleanup(){ rc="$1"; trap '' TERM HUP; trap 'escalate "$rc"' INT; if [ "$child" -gt 0 ]; then kill -TERM -"$child" 2>/dev/null; sleep "$2"; kill -KILL -"$child" 2>/dev/null; wait "$child" 2>/dev/null; fi; exit "$rc"; }
trap 'cleanup 143 "$2"' TERM
trap 'escalate 130' INT
trap 'cleanup 129 "$2"' HUP
setsid --wait /bin/bash --noprofile --norc -c "$1" &
child=$!
wait "$child"
status=$?
trap - TERM INT HUP
exit "$status"`;
  return `cd /workspace && exec /bin/bash --noprofile --norc -c ${shellQuote(wrapper)} cogs ${shellQuote(command)} ${shellQuote((graceMs / 1000).toFixed(3))}`;
}

function integer(value: number | undefined, fallback: number, min: number, max: number): number {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < min || result > max) throw new Error("invalid bash option");
  return result;
}

function normalize(options: BashToolOptions): Config {
  return {
    manager: options.manager,
    timeoutMs: integer(options.timeoutMs, DEFAULT_TIMEOUT_MS, 1, 3_600_000),
    idleTimeoutMs: integer(options.idleTimeoutMs, DEFAULT_IDLE_TIMEOUT_MS, 1, 60_000),
    cancelGraceMs: integer(options.cancelGraceMs, DEFAULT_CANCEL_GRACE_MS, 1, 60_000),
    maxCommandBytes: integer(options.maxCommandBytes, DEFAULT_MAX_COMMAND_BYTES, 1, 100_000),
    maxStreamBytes: integer(options.maxStreamBytes, DEFAULT_MAX_STREAM_BYTES, 1, 1024 * 1024),
    maxUpdates: integer(options.maxUpdates, DEFAULT_MAX_UPDATES, 1, 10_000),
    maxUpdateBytes: integer(options.maxUpdateBytes, DEFAULT_MAX_UPDATE_BYTES, 256, 1024 * 1024),
    updateTimeoutMs: integer(options.updateTimeoutMs, DEFAULT_UPDATE_TIMEOUT_MS, 1, 60_000),
    maxResultBytes: integer(options.maxResultBytes, DEFAULT_MAX_RESULT_BYTES, 1024, 16 * 1024),
  };
}
