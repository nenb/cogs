import { randomBytes } from "node:crypto";
import { TextDecoder } from "node:util";
import type { JsonValue } from "../api/server.ts";
import {
  type CogsExecPort,
  type CogsSftpPort,
  CogsSftpStatusError,
  type SshConnectionManager,
} from "../ssh/connection.ts";
import type { CogsGitMapRecord } from "./git-map.ts";

export interface CogsGitCheckpointConfig {
  readonly enabled: boolean;
  readonly exclusions?: readonly string[];
  readonly maxChangedFiles?: number;
  readonly maxFileBytes?: number;
  readonly maxTotalBytes?: number;
  readonly maxOutputBytes?: number;
  readonly timeoutMs?: number;
}

export interface CogsGitCheckpointInput {
  readonly repo: string;
  readonly session: string;
  readonly entry: string;
  readonly turn: number;
  readonly head: string;
  readonly observed_at: string;
  readonly signal?: AbortSignal;
}

export interface CogsGitCheckpointResult {
  readonly repo: string;
  readonly session: string;
  readonly entry: string;
  readonly turn: number;
  readonly commit: string;
  readonly checkpoint_ref: string;
  readonly observed_at: string;
  readonly file_count: number;
  readonly total_bytes: number;
  readonly duration_ms: number;
}

export interface CogsGitCheckpointer {
  readonly checkpoint: (input: CogsGitCheckpointInput) => Promise<CogsGitCheckpointResult | null>;
  readonly dispose: () => Promise<void>;
}

export interface CogsGitCheckpointCommandPort {
  readonly run: (input: {
    readonly command: string;
    readonly signal?: AbortSignal;
    readonly timeoutMs: number;
    readonly openTimeoutMs: number;
    readonly maxOutputBytes: number;
  }) => Promise<unknown>;
}

export interface CogsGitCheckpointSftpPort {
  readonly lstat: (path: string, signal: AbortSignal) => Promise<{ size: number; type: string }>;
  readonly unlink: (path: string, signal: AbortSignal) => Promise<void>;
}

interface CommandResult {
  readonly code: number;
  readonly signal: string | null;
  readonly stdout: Buffer;
  readonly stderrBytes: number;
}

type Changed = { path: string; deleted: boolean; size: number; oid?: string };

const SHA = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ENTRY = /^[a-f0-9]{8}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const DECODER = new TextDecoder("utf-8", { fatal: true });

export function createSshGitCheckpointer(options: {
  readonly manager: SshConnectionManager;
  readonly config: CogsGitCheckpointConfig;
}): CogsGitCheckpointer | undefined {
  if (options.config.enabled !== true) return undefined;
  return createGitCheckpointer({
    commandPort: sshCommandPort(options.manager),
    sftpWith: (operation, input) =>
      options.manager.withSftp(
        { signal: input.signal, openTimeoutMs: 1000, operationTimeoutMs: input.timeoutMs, closeTimeoutMs: 1000 },
        (port, signal) => operation(sftpPort(port), signal),
      ),
    config: options.config,
  });
}

export function createGitCheckpointer(options: {
  readonly commandPort: CogsGitCheckpointCommandPort;
  readonly sftpWith: <T>(
    operation: (port: CogsGitCheckpointSftpPort, signal: AbortSignal) => Promise<T>,
    input: { signal: AbortSignal; timeoutMs: number },
  ) => Promise<T>;
  readonly config: CogsGitCheckpointConfig;
  readonly randomHex?: () => string;
  readonly nowMs?: () => number;
}): CogsGitCheckpointer {
  if (options.config.enabled !== true) throw new Error("invalid git checkpoint config");
  const config = normalizeConfig(options.config);
  const active = new Set<AbortController>();
  const operations = new Set<Promise<unknown>>();
  const randomHex = options.randomHex ?? (() => randomBytes(16).toString("hex"));
  const nowMs = options.nowMs ?? (() => Date.now());
  let disposed = false;
  return Object.freeze({
    checkpoint: async (input: CogsGitCheckpointInput) => {
      if (disposed) return null;
      if (!validInput(input)) return null;
      let started = 0;
      let controller: LinkedAbortController | undefined;
      let timer: NodeJS.Timeout | undefined;
      let temp: string | undefined;
      let result: CogsGitCheckpointResult | null = null;
      let failed = false;
      let cleanupArmed = false;
      try {
        started = safeNow(nowMs());
        const deadline = started + config.timeoutMs;
        const remaining = () => remainingMs(deadline, nowMs);
        const run = (command: string, signal: AbortSignal) =>
          runCommand(
            {
              commandPort: options.commandPort,
              timeoutMs: remaining(),
              openTimeoutMs: Math.min(1000, remaining()),
              maxOutputBytes: config.maxOutputBytes,
            },
            active,
            operations,
            command,
            signal,
          );
        controller = linkedSignal(input.signal);
        timer = setTimeout(() => controller?.abort(), config.timeoutMs);
        active.add(controller.controller);
        const hex = randomHex();
        if (typeof hex !== "string" || !/^[a-f0-9]{32}$/.test(hex)) throw new Error("git checkpoint unavailable");
        temp = `/tmp/cogs-index-${hex}`;
        await options.sftpWith((sftp, signal) => preflightTemp(sftp, temp as string, signal), {
          signal: controller.signal,
          timeoutMs: remaining(),
        });
        cleanupArmed = true;
        const changed = parseStatus(await run(statusCommand(config.exclusions), controller.signal), config);
        if (changed.length === 0) return null;
        const checked = await options.sftpWith(
          (sftp, signal) => validateChangedWithSftp(sftp, changed, config, signal),
          { signal: controller.signal, timeoutMs: remaining() },
        );
        await expectOk(await run(indexCommand(temp, `read-tree ${input.head}`), controller.signal));
        await expectOk(
          await run(indexCommand(temp, `add -A -- .${excludeArgs(config.exclusions)}`), controller.signal),
        );
        const staged = parseRaw(
          await run(
            indexCommand(
              temp,
              `diff --cached --raw -z --no-renames --no-abbrev ${input.head} -- .${excludeArgs(config.exclusions)}`,
            ),
            controller.signal,
          ),
          config,
          input.head.length,
        );
        assertSameChanged(checked, staged);
        const totalBytes = await validateBlobSizes(staged, temp, run, controller.signal, config, input.head.length);
        const tree = parseSingleSha(await run(indexCommand(temp, "write-tree"), controller.signal), input.head.length);
        const commit = parseSingleSha(
          await run(commitCommand(temp, tree, input.head, input.observed_at), controller.signal),
          input.head.length,
        );
        const checkpointRef = `refs/cogs/sessions/${input.session}/${input.turn}`;
        expectEmptyOk(await run(updateRefCommand(checkpointRef, commit), controller.signal));
        result = Object.freeze({
          repo: input.repo,
          session: input.session,
          entry: input.entry,
          turn: input.turn,
          commit,
          checkpoint_ref: checkpointRef,
          observed_at: input.observed_at,
          file_count: checked.length,
          total_bytes: totalBytes,
          duration_ms: safeDuration(safeNow(nowMs()) - started),
        });
      } catch {
        failed = true;
      } finally {
        if (timer !== undefined) clearTimeout(timer);
        const cleanupOk =
          !cleanupArmed || temp === undefined
            ? true
            : await cleanup(options.sftpWith, temp, config.timeoutMs).then(
                () => true,
                () => false,
              );
        if (!cleanupOk) failed = true;
        if (controller !== undefined) {
          active.delete(controller.controller);
          controller.dispose();
        }
      }
      if (failed) throw new Error("git checkpoint unavailable");
      return result;
    },
    dispose: async () => {
      disposed = true;
      for (const controller of active) controller.abort();
      const deadline = Date.now() + config.timeoutMs;
      while ((active.size > 0 || operations.size > 0) && Date.now() < deadline)
        await Promise.race([Promise.allSettled([...operations]), new Promise((resolve) => setTimeout(resolve, 5))]);
    },
  });
}

export function checkpointRecord(result: CogsGitCheckpointResult): CogsGitMapRecord {
  return Object.freeze({
    version: "cogs.git-mapping/v1alpha1" as const,
    repo: result.repo,
    commit: result.commit,
    session: result.session,
    entry: result.entry,
    turn: result.turn,
    observed_at: result.observed_at,
    confidence: "checkpoint" as const,
    checkpoint_ref: result.checkpoint_ref,
  });
}

export function checkpointEvent(result: CogsGitCheckpointResult): Record<string, JsonValue> {
  return Object.freeze({
    repo: result.repo,
    session: result.session,
    entry: result.entry,
    turn: result.turn,
    commit: result.commit,
    checkpoint_ref: result.checkpoint_ref,
    observed_at: result.observed_at,
    confidence: "checkpoint",
    file_count: result.file_count,
    total_bytes: result.total_bytes,
    duration_ms: result.duration_ms,
    trust: "trusted Cogs record of untrusted Git observation",
  });
}

function normalizeConfig(config: CogsGitCheckpointConfig) {
  return Object.freeze({
    exclusions: snapshotExclusions(config.exclusions),
    maxChangedFiles: integer(config.maxChangedFiles ?? 128, 1, 4096),
    maxFileBytes: integer(config.maxFileBytes ?? 256 * 1024, 0, 32 * 1024 * 1024),
    maxTotalBytes: integer(config.maxTotalBytes ?? 1024 * 1024, 0, 128 * 1024 * 1024),
    maxOutputBytes: integer(config.maxOutputBytes ?? 256 * 1024, 1024, 4 * 1024 * 1024),
    timeoutMs: integer(config.timeoutMs ?? 2500, 1, 60_000),
  });
}

function snapshotExclusions(value: readonly string[] | undefined): readonly string[] {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
    throw new Error("invalid git checkpoint config");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const length = lengthDescriptor === undefined || !("value" in lengthDescriptor) ? undefined : lengthDescriptor.value;
  if (!Number.isInteger(length) || length < 0 || length > 64) throw new Error("invalid git checkpoint config");
  const out: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid git checkpoint config");
    out.push(validateExclusion(descriptor.value));
  }
  const allowed = new Set(["length", ...out.map((_, index) => String(index))]);
  if (!Reflect.ownKeys(descriptors).every((key) => typeof key === "string" && allowed.has(key)))
    throw new Error("invalid git checkpoint config");
  return Object.freeze(out);
}

function validateExclusion(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256)
    throw new Error("invalid git checkpoint config");
  if (value.startsWith("/") || value.startsWith("-") || value.includes("\\") || value.includes(".."))
    throw new Error("invalid git checkpoint config");
  if (value.includes(":") || hasControl(value) || value.startsWith("!"))
    throw new Error("invalid git checkpoint config");
  return value;
}

function statusCommand(exclusions: readonly string[]): string {
  return `LC_ALL=C /usr/bin/git -C /workspace status --porcelain=v1 -z --untracked-files=all --no-renames -- .${excludeArgs(exclusions)}`;
}

function excludeArgs(exclusions: readonly string[]): string {
  return exclusions.map((item) => ` ${shellQuote(`:(exclude)${item}`)}`).join("");
}

function indexCommand(index: string, gitArgs: string): string {
  return `LC_ALL=C GIT_INDEX_FILE=${shellQuote(index)} /usr/bin/git -C /workspace ${gitArgs}`;
}

function commitCommand(index: string, tree: string, parent: string, at: string): string {
  const env = `GIT_INDEX_FILE=${shellQuote(index)} GIT_AUTHOR_NAME=${shellQuote("Cogs Checkpoint")} GIT_AUTHOR_EMAIL=${shellQuote("cogs-checkpoint@localhost")} GIT_AUTHOR_DATE=${shellQuote(at)} GIT_COMMITTER_NAME=${shellQuote("Cogs Checkpoint")} GIT_COMMITTER_EMAIL=${shellQuote("cogs-checkpoint@localhost")} GIT_COMMITTER_DATE=${shellQuote(at)}`;
  return `LC_ALL=C ${env} /usr/bin/git -C /workspace commit-tree ${tree} -p ${parent} -m ${shellQuote("Cogs hidden checkpoint: trusted record of untrusted Git observation")}`;
}

function updateRefCommand(ref: string, commit: string): string {
  return `LC_ALL=C /usr/bin/git -C /workspace update-ref ${shellQuote(ref)} ${commit} ${"0".repeat(commit.length)}`;
}

function parseStatus(result: CommandResult, config: ReturnType<typeof normalizeConfig>): Changed[] {
  expectOk(result);
  const text = decode(result.stdout);
  if (text.length === 0) return [];
  const records = text.split("\0");
  if (records.at(-1) !== "") throw new Error("git checkpoint unavailable");
  const out: Changed[] = [];
  for (const record of records.slice(0, -1)) {
    if (record.length < 4 || record[2] !== " ") throw new Error("git checkpoint unavailable");
    const status = record.slice(0, 2);
    const path = record.slice(3);
    validateRelativePath(path);
    if (status === "!!" || !/^[ MAD?][ MAD?]$/.test(status) || status.includes("?D") || status.includes("D?"))
      throw new Error("git checkpoint unavailable");
    const deleted = status.includes("D") && !status.includes("?");
    out.push({ path, deleted, size: 0 });
  }
  if (out.length > config.maxChangedFiles) throw new Error("git checkpoint unavailable");
  return out;
}

async function validateChangedWithSftp(
  sftp: CogsGitCheckpointSftpPort,
  changed: readonly Changed[],
  config: ReturnType<typeof normalizeConfig>,
  signal: AbortSignal,
): Promise<Changed[]> {
  let total = 0;
  const out: Changed[] = [];
  for (const item of changed) {
    let stats: { size: number; type: string };
    try {
      stats = await sftp.lstat(`/workspace/${item.path}`, signal);
    } catch (error) {
      if (item.deleted && error instanceof CogsSftpStatusError && error.status === "no_such_file") {
        out.push(item);
        continue;
      }
      throw new Error("git checkpoint unavailable");
    }
    if (item.deleted || stats.type !== "file") throw new Error("git checkpoint unavailable");
    if (!Number.isInteger(stats.size) || stats.size < 0 || stats.size > config.maxFileBytes)
      throw new Error("git checkpoint unavailable");
    total += stats.size;
    if (total > config.maxTotalBytes) throw new Error("git checkpoint unavailable");
    out.push({ ...item, size: stats.size });
  }
  return out;
}

function parseRaw(
  result: CommandResult,
  config: ReturnType<typeof normalizeConfig>,
  algorithmLength: number,
): Changed[] {
  expectOk(result);
  const text = decode(result.stdout);
  if (text.length === 0) return [];
  const records = text.split("\0");
  if (records.at(-1) !== "" || records.length % 2 !== 1) throw new Error("git checkpoint unavailable");
  const out: Changed[] = [];
  for (let index = 0; index < records.length - 1; index += 2) {
    const meta = (records[index] ?? "").split(" ");
    const path = records[index + 1] ?? "";
    if (meta.length !== 5 || !meta[0]?.startsWith(":")) throw new Error("git checkpoint unavailable");
    const oldMode = meta[0].slice(1);
    const newMode = meta[1] ?? "";
    const oldOid = meta[2] ?? "";
    const oid = meta[3] ?? "";
    const status = meta[4] ?? "";
    if (!/^[AMDT]$/.test(status)) throw new Error("git checkpoint unavailable");
    if (![oldMode, newMode].every((mode) => /^[0-7]{6}$/.test(mode))) throw new Error("git checkpoint unavailable");
    if (oldMode === "120000" || oldMode === "160000" || newMode === "120000" || newMode === "160000")
      throw new Error("git checkpoint unavailable");
    validateRelativePath(path);
    const deleted = status === "D";
    if (oldOid.length !== algorithmLength || oid.length !== algorithmLength)
      throw new Error("git checkpoint unavailable");
    if (!SHA.test(oldOid) || !SHA.test(oid)) throw new Error("git checkpoint unavailable");
    const zeroOid = "0".repeat(algorithmLength);
    const regularOld = oldMode === "100644" || oldMode === "100755";
    const regularNew = newMode === "100644" || newMode === "100755";
    if (status === "A") {
      if (oldMode !== "000000" || oldOid !== zeroOid || !regularNew || oid === zeroOid)
        throw new Error("git checkpoint unavailable");
    } else if (deleted) {
      if (!regularOld || oldOid === zeroOid || newMode !== "000000" || oid !== zeroOid)
        throw new Error("git checkpoint unavailable");
    } else if (
      (status === "M" || status === "T") &&
      (!regularOld || !regularNew || oldOid === zeroOid || oid === zeroOid)
    )
      throw new Error("git checkpoint unavailable");
    out.push({ path, deleted, size: 0, ...(deleted ? {} : { oid }) });
  }
  if (out.length > config.maxChangedFiles) throw new Error("git checkpoint unavailable");
  return out;
}

function assertSameChanged(preflight: readonly Changed[], staged: readonly Changed[]): void {
  const a = new Map(preflight.map((item) => [item.path, item]));
  const b = new Map(staged.map((item) => [item.path, item]));
  if (a.size !== preflight.length || b.size !== staged.length || a.size !== b.size)
    throw new Error("git checkpoint unavailable");
  for (const [path, item] of a) {
    const stagedItem = b.get(path);
    if (stagedItem === undefined || stagedItem.deleted !== item.deleted) throw new Error("git checkpoint unavailable");
  }
}

async function validateBlobSizes(
  staged: readonly Changed[],
  index: string,
  run: (command: string, signal: AbortSignal) => Promise<CommandResult>,
  signal: AbortSignal,
  config: ReturnType<typeof normalizeConfig>,
  algorithmLength: number,
): Promise<number> {
  const oids = staged.filter((item) => !item.deleted).map((item) => item.oid ?? "");
  if (oids.length === 0) return 0;
  if (!oids.every((oid) => SHA.test(oid) && oid.length === algorithmLength))
    throw new Error("git checkpoint unavailable");
  const query = `${oids.join("\n")}\n`;
  const command = indexCommand(
    index,
    `cat-file --batch-check=${shellQuote("%(objectname) %(objecttype) %(objectsize)")} <<'COGS_BLOBS'\n${query}COGS_BLOBS`,
  );
  const lines = parseLines(await run(command, signal));
  if (lines.length !== oids.length) throw new Error("git checkpoint unavailable");
  let total = 0;
  for (let index = 0; index < oids.length; index += 1) {
    const parts = (lines[index] ?? "").split(" ");
    if (parts.length !== 3 || parts[0] !== oids[index] || parts[1] !== "blob" || !/^\d+$/.test(parts[2] ?? ""))
      throw new Error("git checkpoint unavailable");
    const size = Number(parts[2]);
    if (!Number.isSafeInteger(size) || size > config.maxFileBytes) throw new Error("git checkpoint unavailable");
    total += size;
    if (total > config.maxTotalBytes) throw new Error("git checkpoint unavailable");
  }
  return total;
}

async function preflightTemp(sftp: CogsGitCheckpointSftpPort, temp: string, signal: AbortSignal): Promise<void> {
  await expectMissing(sftp, temp, signal);
  await expectMissing(sftp, `${temp}.lock`, signal);
}

async function expectMissing(sftp: CogsGitCheckpointSftpPort, path: string, signal: AbortSignal): Promise<void> {
  try {
    await sftp.lstat(path, signal);
  } catch (error) {
    if (error instanceof CogsSftpStatusError && error.status === "no_such_file") return;
    throw new Error("git checkpoint unavailable");
  }
  throw new Error("git checkpoint unavailable");
}

async function cleanup(
  sftpWith: <T>(
    operation: (port: CogsGitCheckpointSftpPort, signal: AbortSignal) => Promise<T>,
    input: { signal: AbortSignal; timeoutMs: number },
  ) => Promise<T>,
  temp: string,
  timeoutMs: number,
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(1000, timeoutMs));
  try {
    await sftpWith(
      async (sftp, opSignal) => {
        await cleanupOne(sftp, temp, opSignal);
        await cleanupOne(sftp, `${temp}.lock`, opSignal);
      },
      { signal: controller.signal, timeoutMs: Math.min(1000, timeoutMs) },
    );
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

async function cleanupOne(sftp: CogsGitCheckpointSftpPort, path: string, signal: AbortSignal): Promise<void> {
  try {
    await sftp.lstat(path, signal);
  } catch (error) {
    if (error instanceof CogsSftpStatusError && error.status === "no_such_file") return;
    throw new Error("git checkpoint unavailable");
  }
  try {
    await sftp.unlink(path, signal);
  } catch (error) {
    if (error instanceof CogsSftpStatusError && error.status === "no_such_file") return;
    throw new Error("git checkpoint unavailable");
  }
}

function parseSingleSha(result: CommandResult, algorithmLength: number): string {
  const line = parseSingleLine(result);
  if (!SHA.test(line) || line.length !== algorithmLength) throw new Error("git checkpoint unavailable");
  return line;
}

function parseSingleLine(result: CommandResult): string {
  const lines = parseLines(result);
  if (lines.length !== 1) throw new Error("git checkpoint unavailable");
  return lines[0] ?? "";
}

function parseLines(result: CommandResult): string[] {
  expectOk(result);
  const lines = decode(result.stdout).split("\n");
  if (lines.at(-1) !== "") throw new Error("git checkpoint unavailable");
  return lines.slice(0, -1);
}

function expectOk(result: CommandResult): void {
  if (result.code !== 0 || result.signal !== null || result.stderrBytes !== 0)
    throw new Error("git checkpoint unavailable");
}

function expectEmptyOk(result: CommandResult): void {
  expectOk(result);
  if (result.stdout.length !== 0) throw new Error("git checkpoint unavailable");
}

async function runCommand(
  config: {
    readonly commandPort: CogsGitCheckpointCommandPort;
    readonly timeoutMs: number;
    readonly openTimeoutMs: number;
    readonly maxOutputBytes: number;
  },
  active: Set<AbortController>,
  operations: Set<Promise<unknown>>,
  command: string,
  signal: AbortSignal,
): Promise<CommandResult> {
  throwIfAborted(signal);
  const controller = linkedSignal(signal);
  active.add(controller.controller);
  const operation = Promise.resolve().then(() =>
    config.commandPort.run({
      command,
      signal: controller.signal,
      timeoutMs: config.timeoutMs,
      openTimeoutMs: config.openTimeoutMs,
      maxOutputBytes: config.maxOutputBytes,
    }),
  );
  operations.add(operation);
  try {
    const raw = await operation;
    throwIfAborted(signal);
    return snapshotResult(raw, config.maxOutputBytes);
  } catch {
    throw new Error("git checkpoint unavailable");
  } finally {
    active.delete(controller.controller);
    controller.dispose();
    operation.finally(() => operations.delete(operation)).catch(() => operations.delete(operation));
  }
}

function snapshotResult(raw: unknown, maxOutputBytes: number): CommandResult {
  if (raw === null || typeof raw !== "object" || Object.getPrototypeOf(raw) !== Object.prototype)
    throw new Error("git checkpoint unavailable");
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const keys = Reflect.ownKeys(descriptors).sort();
  if (keys.join("\0") !== ["code", "signal", "stderrBytes", "stdout"].join("\0"))
    throw new Error("git checkpoint unavailable");
  const code = ownData(descriptors, "code");
  const signal = ownData(descriptors, "signal");
  const stdout = ownData(descriptors, "stdout");
  const stderrBytes = ownData(descriptors, "stderrBytes");
  if (!Number.isInteger(code) || typeof stderrBytes !== "number" || !Number.isInteger(stderrBytes) || stderrBytes < 0)
    throw new Error("git checkpoint unavailable");
  if (!(signal === null || typeof signal === "string")) throw new Error("git checkpoint unavailable");
  if (!Buffer.isBuffer(stdout) || stdout.length > maxOutputBytes || stderrBytes > maxOutputBytes)
    throw new Error("git checkpoint unavailable");
  return Object.freeze({ code: code as number, signal, stdout: Buffer.from(stdout), stderrBytes });
}

function ownData(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
    throw new Error("git checkpoint unavailable");
  return descriptor.value;
}

function decode(buffer: Buffer): string {
  return DECODER.decode(buffer);
}

function validateRelativePath(path: string): void {
  if (path.length === 0 || path.length > 4096) throw new Error("git checkpoint unavailable");
  if (path.startsWith("/") || path.includes("\\") || path.split("/").includes(".."))
    throw new Error("git checkpoint unavailable");
  if (hasControl(path)) throw new Error("git checkpoint unavailable");
}

function validInput(input: CogsGitCheckpointInput): boolean {
  try {
    return validInputSnapshot(input);
  } catch {
    return false;
  }
}

function validInputSnapshot(input: CogsGitCheckpointInput): boolean {
  if (input === null || typeof input !== "object" || Object.getPrototypeOf(input) !== Object.prototype) return false;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const allowed = new Set(["repo", "session", "entry", "turn", "head", "observed_at", "signal"]);
  if (!Reflect.ownKeys(descriptors).every((key) => typeof key === "string" && allowed.has(key))) return false;
  const repo = ownInput(descriptors, "repo");
  const session = ownInput(descriptors, "session");
  const entry = ownInput(descriptors, "entry");
  const turn = ownInput(descriptors, "turn");
  const head = ownInput(descriptors, "head");
  const observedAt = ownInput(descriptors, "observed_at");
  const signal = descriptors.signal === undefined ? undefined : ownInput(descriptors, "signal");
  return (
    typeof repo === "string" &&
    typeof session === "string" &&
    typeof entry === "string" &&
    typeof head === "string" &&
    typeof observedAt === "string" &&
    (signal === undefined || signal instanceof AbortSignal) &&
    OPAQUE.test(repo) &&
    validRefPart(session) &&
    ENTRY.test(entry) &&
    Number.isInteger(turn) &&
    (turn as number) >= 0 &&
    (turn as number) <= 1_000_000_000 &&
    SHA.test(head) &&
    ISO.test(observedAt)
  );
}

function ownInput(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) return undefined;
  return descriptor.value;
}

function validRefPart(value: string): boolean {
  return (
    OPAQUE.test(value) && !value.includes(":") && !value.includes("@") && !value.includes("..") && !value.endsWith(".")
  );
}

function hasControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function safeNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("git checkpoint unavailable");
  return value;
}

function safeDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("git checkpoint unavailable");
  return value;
}

function remainingMs(deadline: number, nowMs: () => number): number {
  const remaining = deadline - safeNow(nowMs());
  if (!Number.isSafeInteger(remaining) || remaining <= 0) throw new Error("git checkpoint unavailable");
  return remaining;
}

function integer(value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error("invalid git checkpoint config");
  return value;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

interface LinkedAbortController {
  readonly controller: AbortController;
  readonly signal: AbortSignal;
  readonly abort: () => void;
  readonly dispose: () => void;
}

function linkedSignal(parent?: AbortSignal): LinkedAbortController {
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (parent?.aborted) controller.abort();
  else parent?.addEventListener("abort", abort, { once: true });
  return Object.freeze({
    controller,
    signal: controller.signal,
    abort,
    dispose: () => {
      parent?.removeEventListener("abort", abort);
      controller.abort();
    },
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("git checkpoint unavailable");
}

function sshCommandPort(manager: SshConnectionManager): CogsGitCheckpointCommandPort {
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

function sftpPort(port: CogsSftpPort): CogsGitCheckpointSftpPort {
  return Object.freeze({
    lstat: (path: string, signal: AbortSignal) => port.lstat(path, signal),
    unlink: (path: string, signal: AbortSignal) => port.unlink(path, signal),
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
  if (tooLarge) throw new Error("git checkpoint unavailable");
  return { code: terminal.code ?? -1, signal: terminal.signal, stdout: Buffer.concat(chunks), stderrBytes };
}
