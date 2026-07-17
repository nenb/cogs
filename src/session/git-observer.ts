import { TextDecoder } from "node:util";
import type { JsonValue } from "../api/server.ts";
import type { CogsExecPort, SshConnectionManager } from "../ssh/connection.ts";
import type { CogsGitMapRecord, CogsNearestGitAncestor } from "./git-map.ts";

export type CogsGitObservation =
  | { readonly kind: "observed"; readonly repo: string; readonly commit: string; readonly observed_at: string }
  | { readonly kind: "unavailable" };

export interface CogsGitObserver {
  readonly observeHead: (input?: { signal?: AbortSignal }) => Promise<CogsGitObservation>;
  readonly nearestAncestor: CogsNearestGitAncestor;
  readonly appendNote: (record: CogsGitMapRecord, input?: { signal?: AbortSignal }) => Promise<boolean>;
  readonly dispose: () => Promise<void>;
}

export interface CogsGitObserverOptions {
  readonly manager: SshConnectionManager;
  readonly repositoryId: string;
  readonly clock?: () => Date;
  readonly totalTimeoutMs?: number;
  readonly openTimeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly maxLineBytes?: number;
  readonly maxAncestorCommits?: number;
  readonly maxCandidates?: number;
  readonly maxNoteBytes?: number;
  readonly maxConcurrentOperations?: number;
}

export interface CogsGitCommandPort {
  readonly run: (input: {
    readonly command: string;
    readonly signal?: AbortSignal;
    readonly timeoutMs: number;
    readonly openTimeoutMs: number;
    readonly maxOutputBytes: number;
  }) => Promise<unknown>;
}

interface CommandResult {
  readonly code: number;
  readonly signal: string | null;
  readonly stdout: Buffer;
  readonly stderrBytes: number;
}

const SHA = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const ENTRY = /^[a-f0-9]{8}$/;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DECODER = new TextDecoder("utf-8", { fatal: true });

export function createSshGitObserver(options: CogsGitObserverOptions): CogsGitObserver {
  return createGitObserver({
    commandPort: sshCommandPort(options.manager),
    repositoryId: options.repositoryId,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.totalTimeoutMs === undefined ? {} : { totalTimeoutMs: options.totalTimeoutMs }),
    ...(options.openTimeoutMs === undefined ? {} : { openTimeoutMs: options.openTimeoutMs }),
    ...(options.maxOutputBytes === undefined ? {} : { maxOutputBytes: options.maxOutputBytes }),
    ...(options.maxLineBytes === undefined ? {} : { maxLineBytes: options.maxLineBytes }),
    ...(options.maxAncestorCommits === undefined ? {} : { maxAncestorCommits: options.maxAncestorCommits }),
    ...(options.maxCandidates === undefined ? {} : { maxCandidates: options.maxCandidates }),
    ...(options.maxNoteBytes === undefined ? {} : { maxNoteBytes: options.maxNoteBytes }),
    ...(options.maxConcurrentOperations === undefined
      ? {}
      : { maxConcurrentOperations: options.maxConcurrentOperations }),
  });
}

export function createGitObserver(options: {
  readonly commandPort: CogsGitCommandPort;
  readonly repositoryId: string;
  readonly clock?: () => Date;
  readonly totalTimeoutMs?: number;
  readonly openTimeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly maxLineBytes?: number;
  readonly maxAncestorCommits?: number;
  readonly maxCandidates?: number;
  readonly maxNoteBytes?: number;
  readonly maxConcurrentOperations?: number;
}): CogsGitObserver {
  validateOpaque(options.repositoryId);
  const config = {
    commandPort: options.commandPort,
    repositoryId: options.repositoryId,
    clock: options.clock ?? (() => new Date()),
    totalTimeoutMs: integer(options.totalTimeoutMs ?? 2500, 1, 60_000),
    openTimeoutMs: integer(options.openTimeoutMs ?? 1000, 1, 60_000),
    maxOutputBytes: integer(options.maxOutputBytes ?? 64 * 1024, 128, 1024 * 1024),
    maxLineBytes: integer(options.maxLineBytes ?? 256, 40, 4096),
    maxAncestorCommits: integer(options.maxAncestorCommits ?? 512, 1, 8192),
    maxCandidates: integer(options.maxCandidates ?? 256, 1, 1024),
    maxNoteBytes: integer(options.maxNoteBytes ?? 512, 64, 4096),
    maxConcurrentOperations: integer(options.maxConcurrentOperations ?? 8, 1, 64),
  };
  const active = new Set<AbortController>();
  const operations = new Set<Promise<unknown>>();
  let disposed = false;
  const live = () => {
    if (disposed) throw new Error("git observer unavailable");
  };
  const run = (command: string, signal?: AbortSignal) => runText(config, active, operations, command, signal);
  return Object.freeze({
    observeHead: async (input: { signal?: AbortSignal } = {}) => {
      try {
        live();
        const out = await run(HEAD_COMMAND, input.signal);
        const lines = parseLines(out.stdout, 1, config.maxLineBytes);
        if (out.stderrBytes !== 0 || lines.length !== 1 || !SHA.test(lines[0] ?? "")) return unavailable();
        const observedAt = config.clock().toISOString();
        if (!ISO.test(observedAt)) return unavailable();
        return Object.freeze({
          kind: "observed" as const,
          repo: config.repositoryId,
          commit: lines[0] as string,
          observed_at: observedAt,
        });
      } catch {
        return unavailable();
      }
    },
    nearestAncestor: async (input: {
      readonly requested: string;
      readonly candidates: readonly string[];
      readonly signal?: AbortSignal;
    }) => {
      live();
      if (
        !SHA.test(input.requested) ||
        !Array.isArray(input.candidates) ||
        input.candidates.length > config.maxCandidates
      )
        throw new Error("git ancestor unavailable");
      const candidates = [...input.candidates];
      if (!candidates.every((candidate) => SHA.test(candidate))) throw new Error("git ancestor unavailable");
      const wanted = new Set(candidates);
      const out = await run(ancestorCommand(input.requested, config.maxAncestorCommits + 1), input.signal);
      if (out.stderrBytes !== 0) throw new Error("git ancestor unavailable");
      const lines = parseLines(out.stdout, config.maxAncestorCommits + 1, config.maxLineBytes);
      if (lines.length > config.maxAncestorCommits) throw new Error("git ancestor unavailable");
      for (const line of lines) {
        if (!SHA.test(line)) throw new Error("git ancestor unavailable");
        // rev-list --topo-order walks from requested toward ancestors; the first candidate encountered is nearest.
        if (wanted.has(line)) return line;
      }
      return null;
    },
    appendNote: async (record: CogsGitMapRecord, input: { signal?: AbortSignal } = {}) => {
      try {
        live();
        if (!validRecord(record, config.repositoryId)) return false;
        const message = noteMessage(record, config.maxNoteBytes);
        const out = await run(noteCommand(record.commit, message), input.signal);
        return out.code === 0 && out.signal === null && out.stdout.length === 0 && out.stderrBytes === 0;
      } catch {
        return false;
      }
    },
    dispose: async () => {
      disposed = true;
      for (const controller of active) controller.abort();
      const deadline = Date.now() + config.totalTimeoutMs;
      while ((active.size > 0 || operations.size > 0) && Date.now() < deadline)
        await Promise.race([Promise.allSettled([...operations]), new Promise((resolve) => setTimeout(resolve, 5))]);
    },
  });
}

const HEAD_COMMAND = "LC_ALL=C /usr/bin/git -C /workspace rev-parse --verify 'HEAD^{commit}'";

function ancestorCommand(requested: string, max: number): string {
  return `LC_ALL=C /usr/bin/git -C /workspace rev-list --topo-order --max-count=${max} ${requested}`;
}

function noteCommand(commit: string, message: string): string {
  return `LC_ALL=C /usr/bin/git -C /workspace notes --ref=refs/notes/cogs append -m ${shellQuote(message)} ${commit}`;
}

function noteMessage(record: CogsGitMapRecord, maxBytes: number): string {
  const text = `cogs git mapping: trusted record of untrusted Git observation; session=${record.session}; entry=${record.entry}; turn=${record.turn}; commit=${record.commit}; observed_at=${record.observed_at}; confidence=${record.confidence}`;
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error("note too large");
  return text;
}

function sshCommandPort(manager: SshConnectionManager): CogsGitCommandPort {
  return Object.freeze({
    run: (input: {
      readonly command: string;
      readonly signal?: AbortSignal;
      readonly timeoutMs: number;
      readonly openTimeoutMs: number;
      readonly maxOutputBytes: number;
    }) =>
      manager.withBashExec(
        {
          wrappedCommand: input.command,
          ...(input.signal === undefined ? {} : { signal: input.signal }),
          openTimeoutMs: input.openTimeoutMs,
          operationTimeoutMs: input.timeoutMs,
          closeTimeoutMs: 1000,
        },
        async (port) => collect(port, input.maxOutputBytes),
      ),
  });
}

async function collect(port: CogsExecPort, maxOutputBytes: number): Promise<CommandResult> {
  const chunks: Buffer[] = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let tooLarge = false;
  port.onStdout((chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes > maxOutputBytes) {
      tooLarge = true;
      return;
    }
    chunks.push(Buffer.from(chunk));
  });
  port.onStderr((chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > maxOutputBytes) tooLarge = true;
  });
  const terminal = await port.terminal();
  if (tooLarge) throw new Error("git observation unavailable");
  return { code: terminal.code ?? -1, signal: terminal.signal, stdout: Buffer.concat(chunks), stderrBytes };
}

async function runText(
  config: {
    readonly commandPort: CogsGitCommandPort;
    readonly totalTimeoutMs: number;
    readonly openTimeoutMs: number;
    readonly maxOutputBytes: number;
    readonly maxConcurrentOperations: number;
  },
  active: Set<AbortController>,
  activeOperations: Set<Promise<unknown>>,
  command: string,
  signal: AbortSignal | undefined,
): Promise<CommandResult> {
  throwIfAborted(signal);
  if (activeOperations.size >= config.maxConcurrentOperations) throw new Error("git observation unavailable");
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  active.add(controller);
  let timer: NodeJS.Timeout | undefined;
  const operation = Promise.resolve()
    .then(() =>
      config.commandPort.run({
        command,
        signal: controller.signal,
        timeoutMs: config.totalTimeoutMs,
        openTimeoutMs: config.openTimeoutMs,
        maxOutputBytes: config.maxOutputBytes,
      }),
    )
    .catch((error) => {
      throw error;
    });
  activeOperations.add(operation);
  operation.catch(() => undefined);
  operation.finally(() => activeOperations.delete(operation)).catch(() => undefined);
  try {
    const result = await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("git observation unavailable"));
        }, config.totalTimeoutMs);
      }),
    ]);
    throwIfAborted(signal);
    if (controller.signal.aborted) throw new Error("git observation unavailable");
    const snapshot = snapshotResult(result, config.maxOutputBytes);
    if (snapshot.signal !== null || snapshot.code !== 0 || snapshot.stderrBytes > config.maxOutputBytes)
      throw new Error("git observation unavailable");
    return snapshot;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
    active.delete(controller);
  }
}

function snapshotResult(value: unknown, maxOutputBytes: number): CommandResult {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("git observation unavailable");
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error("git observation unavailable");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (!keys.every((key) => typeof key === "string")) throw new Error("git observation unavailable");
  if ((keys as string[]).sort().join("\0") !== ["code", "signal", "stderrBytes", "stdout"].join("\0"))
    throw new Error("git observation unavailable");
  const get = (key: string) => {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("git observation unavailable");
    return descriptor.value;
  };
  const code = get("code");
  const termSignal = get("signal");
  const stdout = get("stdout");
  const stderrBytes = get("stderrBytes");
  if (
    !Number.isSafeInteger(code) ||
    code < 0 ||
    !Number.isSafeInteger(stderrBytes) ||
    stderrBytes < 0 ||
    stderrBytes > 1024 * 1024
  )
    throw new Error("git observation unavailable");
  if (termSignal !== null && (typeof termSignal !== "string" || termSignal.length < 1 || termSignal.length > 32))
    throw new Error("git observation unavailable");
  if (!Buffer.isBuffer(stdout) || stdout.length > maxOutputBytes) throw new Error("git observation unavailable");
  return Object.freeze({ code, signal: termSignal, stdout: Buffer.from(stdout), stderrBytes });
}

function parseLines(data: Buffer, maxLines: number, maxLineBytes: number): string[] {
  const text = DECODER.decode(data);
  if (!text.endsWith("\n")) throw new Error("git observation unavailable");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length > maxLines) throw new Error("git observation unavailable");
  for (const line of lines) {
    if (line.length === 0 || Buffer.byteLength(line, "utf8") > maxLineBytes)
      throw new Error("git observation unavailable");
  }
  return lines;
}

function unavailable(): CogsGitObservation {
  return Object.freeze({ kind: "unavailable" as const });
}

function validRecord(record: CogsGitMapRecord, repositoryId: string): boolean {
  return (
    record.version === "cogs.git-mapping/v1alpha1" &&
    record.repo === repositoryId &&
    OPAQUE.test(record.session) &&
    ENTRY.test(record.entry) &&
    SHA.test(record.commit) &&
    Number.isSafeInteger(record.turn) &&
    record.turn >= 0 &&
    (record.confidence === "exact" || record.confidence === "checkpoint")
  );
}

function validateOpaque(value: string): void {
  if (!OPAQUE.test(value)) throw new Error("invalid git observer option");
}

function shellQuote(value: string): string {
  if (!/^[\x20-\x7e]*$/.test(value)) throw new Error("unsafe note");
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function integer(value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error("invalid git observer option");
  return value;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error("git observation aborted");
}

export function gitObservationEvent(record: CogsGitMapRecord, boundary: string): Record<string, JsonValue> {
  return Object.freeze({
    trust: "trusted Cogs record of untrusted Git observation",
    repo: record.repo,
    commit: record.commit,
    session: record.session,
    entry: record.entry,
    turn: record.turn,
    observed_at: record.observed_at,
    confidence: record.confidence,
    boundary,
  });
}
