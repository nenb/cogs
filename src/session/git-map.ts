import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { TextDecoder } from "node:util";
import type { JsonValue } from "../api/server.ts";

export type CogsGitMapConfidence = "exact" | "checkpoint";
export type CogsGitMapResolveConfidence = CogsGitMapConfidence | "inferred-ancestor";

export interface CogsGitMapRecord {
  readonly version: "cogs.git-mapping/v1alpha1";
  readonly repo: string;
  readonly commit: string;
  readonly session: string;
  readonly entry: string;
  readonly turn: number;
  readonly observed_at: string;
  readonly confidence: CogsGitMapConfidence;
  readonly checkpoint_ref?: string;
}

export interface CogsGitMapResolvedMapping {
  readonly version: "cogs.git-mapping/v1alpha1";
  readonly repo: string;
  readonly commit: string;
  readonly session: string;
  readonly entry: string;
  readonly turn: number;
  readonly observed_at: string;
  readonly confidence: CogsGitMapResolveConfidence;
  readonly checkpoint_ref?: string;
}

export type CogsGitMapResolveResult =
  | {
      readonly kind: "mapped";
      readonly requested_commit: string;
      readonly mapping: CogsGitMapResolvedMapping;
      readonly ancestor_commit?: string;
      readonly source_mapping?: CogsGitMapRecord;
    }
  | { readonly kind: "pre-cogs"; readonly repo: string; readonly session: string; readonly requested_commit: string }
  | {
      readonly kind: "unavailable";
      readonly repo: string;
      readonly session: string;
      readonly requested_commit: string;
    };

export interface CogsGitMapStore {
  readonly append: (input: unknown, options?: { signal?: AbortSignal }) => Promise<CogsGitMapRecord>;
  readonly records: () => readonly CogsGitMapRecord[];
  readonly resolve: (input: {
    readonly repo: string;
    readonly session: string;
    readonly commit: string;
    readonly nearestAncestor: CogsNearestGitAncestor;
    readonly signal?: AbortSignal;
  }) => Promise<CogsGitMapResolveResult>;
}

export type CogsNearestGitAncestor = (input: {
  readonly requested: string;
  readonly candidates: readonly string[];
  readonly signal?: AbortSignal;
}) => Promise<string | null>;

export class CogsGitMapError extends Error {
  public readonly code = "COGS_GIT_MAP_FAILED";
  public constructor() {
    super("invalid git map");
    this.name = "CogsGitMapError";
  }
}

interface DirectoryMarker {
  readonly dev: bigint;
  readonly ino: bigint;
}

interface FileMarker {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly size: number;
}

interface OpenedAppend {
  readonly handle: Awaited<ReturnType<typeof open>>;
  readonly marker: FileMarker;
}

interface BigStats {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly uid: bigint;
  readonly mode: bigint | number;
  readonly nlink: bigint;
  readonly size: bigint;
  readonly isFile: () => boolean;
  readonly isDirectory: () => boolean;
  readonly isSymbolicLink: () => boolean;
}

interface FsPort {
  readonly lstat: typeof lstat;
  readonly realpath: typeof realpath;
  readonly open: typeof open;
}

export interface CogsGitMapTestHooks {
  readonly fs?: Partial<FsPort>;
}

const FILE_NAME = "git-map.jsonl";
const VERSION = "cogs.git-mapping/v1alpha1";
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_LINE_BYTES = 16 * 1024;
const MAX_RECORDS = 16_384;
const MAX_CANDIDATES = 256;
const READ_CHUNK_BYTES = 8192;
const DECODER = new TextDecoder("utf-8", { fatal: true });
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ENTRY = /^[a-f0-9]{8}$/;
const COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CHECKPOINT_REF = /^refs\/cogs\/sessions\/([A-Za-z0-9][A-Za-z0-9._:-]*)\/([0-9]+)$/;

export async function createCogsGitMapStore(
  input: { readonly sessionDir: string },
  hooks: CogsGitMapTestHooks = {},
): Promise<CogsGitMapStore> {
  const fs = freezeFs(hooks.fs);
  const sessionDir = input.sessionDir;
  const sidecar = join(sessionDir, FILE_NAME);
  const pinnedDir = await pinDirectory(fs, sessionDir);
  const state: {
    marker?: FileMarker;
    records: CogsGitMapRecord[];
    canonicals: Set<string>;
    poison: boolean;
    chain: Promise<unknown>;
  } = {
    records: [],
    canonicals: new Set(),
    poison: false,
    chain: Promise.resolve(),
  };
  await initializeExisting(fs, sidecar, sessionDir, pinnedDir, state);
  return Object.freeze({
    append: async (raw: unknown, options: { signal?: AbortSignal } = {}) => {
      let record: CogsGitMapRecord;
      try {
        record = snapshotRecord(raw);
      } catch {
        throw new CogsGitMapError();
      }
      return enqueue(state, async () => {
        if (state.poison) throw new CogsGitMapError();
        throwIfAborted(options.signal);
        const canonical = canonicalRecord(record);
        if (state.canonicals.has(canonical)) throw new CogsGitMapError();
        const bytes = Buffer.from(`${canonical}\n`, "utf8");
        if ((state.marker?.size ?? 0) + bytes.length > MAX_BYTES || state.records.length + 1 > MAX_RECORDS)
          throw new CogsGitMapError();
        let opened: OpenedAppend;
        try {
          opened = await openForAppend(fs, sidecar, sessionDir, pinnedDir, state.marker);
        } catch {
          if (state.marker === undefined) state.poison = true;
          throw new CogsGitMapError();
        }
        let mutationStarted = false;
        try {
          mutationStarted = true;
          const write = await opened.handle.write(bytes, 0, bytes.length, null);
          if (write.bytesWritten !== bytes.length) throw new CogsGitMapError();
          throwIfAborted(options.signal);
          await opened.handle.sync();
          const after = await opened.handle.stat({ bigint: true });
          if (
            !after.isFile() ||
            after.dev !== opened.marker.dev ||
            after.ino !== opened.marker.ino ||
            after.size !== BigInt(opened.marker.size + bytes.length)
          ) {
            mutationStarted = true;
            throw new CogsGitMapError();
          }
          const nextMarker = { ...opened.marker, size: opened.marker.size + bytes.length };
          await syncDirectory(opened.handle, nextMarker, fs, sessionDir, pinnedDir);
          await verifyPathFile(fs, sidecar, nextMarker);
          await closeHandle(opened.handle, true);
          const frozen = freezeRecord(record);
          state.records.push(frozen);
          state.canonicals.add(canonical);
          state.marker = nextMarker;
          return frozen;
        } catch {
          if (mutationStarted) state.poison = true;
          await closeHandle(opened.handle, false).catch(() => undefined);
          throw new CogsGitMapError();
        }
      });
    },
    records: () => {
      if (state.poison) throw new CogsGitMapError();
      return Object.freeze(state.records.map((record) => freezeRecord(record)));
    },
    resolve: async ({
      repo,
      session,
      commit,
      nearestAncestor,
      signal,
    }: {
      readonly repo: string;
      readonly session: string;
      readonly commit: string;
      readonly nearestAncestor: CogsNearestGitAncestor;
      readonly signal?: AbortSignal;
    }) => {
      try {
        validateOpaque(repo);
        validateOpaque(session);
        validateCommit(commit);
        if (typeof nearestAncestor !== "function") throw new CogsGitMapError();
        throwIfAborted(signal);
        if (state.poison) return unavailable(repo, session, commit);
        const scoped = state.records.filter((record) => record.repo === repo && record.session === session);
        const exact = latest(scoped.filter((record) => record.commit === commit));
        if (exact !== undefined) return mapped(commit, { ...exact });
        if (scoped.length === 0) return preCogs(repo, session, commit);
        let candidates: string[];
        try {
          candidates = dedupeLatest(scoped.map((record) => record.commit));
        } catch {
          return unavailable(repo, session, commit);
        }
        if (candidates.length === 0) return unavailable(repo, session, commit);
        let selected: string | null;
        try {
          selected = await nearestAncestor(
            Object.freeze({
              requested: commit,
              candidates: Object.freeze([...candidates]),
              ...(signal === undefined ? {} : { signal }),
            }),
          );
        } catch {
          return unavailable(repo, session, commit);
        }
        throwIfAborted(signal);
        if (selected === null) return preCogs(repo, session, commit);
        if (typeof selected !== "string" || !COMMIT.test(selected) || !candidates.includes(selected))
          return unavailable(repo, session, commit);
        const ancestor = latest(scoped.filter((record) => record.commit === selected));
        if (ancestor === undefined) return unavailable(repo, session, commit);
        const { checkpoint_ref: _checkpointRef, ...base } = ancestor;
        return mapped(
          commit,
          {
            ...base,
            commit,
            confidence: "inferred-ancestor",
          },
          selected,
          ancestor,
        );
      } catch (error) {
        if (error instanceof CogsGitMapError) throw error;
        throw new CogsGitMapError();
      }
    },
  });
}

async function initializeExisting(
  fs: FsPort,
  sidecar: string,
  sessionDir: string,
  dir: DirectoryMarker,
  state: { marker?: FileMarker; records: CogsGitMapRecord[]; canonicals: Set<string>; poison: boolean },
): Promise<void> {
  try {
    await fs.lstat(sidecar);
  } catch (error) {
    if ((error as { code?: unknown }).code === "ENOENT") return;
    throw new CogsGitMapError();
  }
  const opened = await openExisting(fs, sidecar, sessionDir, dir);
  try {
    const records = await scanRecords(opened.handle, opened.marker.size);
    const afterRead = await opened.handle.stat({ bigint: true });
    validateOpenedMarker(afterRead, opened.marker);
    await opened.handle.sync();
    const afterSync = await opened.handle.stat({ bigint: true });
    validateOpenedMarker(afterSync, opened.marker);
    await syncDirectory(opened.handle, opened.marker, fs, sessionDir, dir);
    await verifyPathFile(fs, sidecar, opened.marker);
    await closeHandle(opened.handle, true);
    state.marker = opened.marker;
    state.records = records.map((record) => freezeRecord(record));
    state.canonicals = new Set(records.map(canonicalRecord));
  } catch (error) {
    await closeHandle(opened.handle, false).catch(() => undefined);
    if (error instanceof CogsGitMapError) throw error;
    throw new CogsGitMapError();
  }
}

async function openExisting(
  fs: FsPort,
  sidecar: string,
  sessionDir: string,
  dir: DirectoryMarker,
): Promise<OpenedAppend> {
  await validateSidecarPath(fs, sidecar, sessionDir, dir);
  const before = await checkedFileStat(fs, sidecar);
  const handle = await fs.open(sidecar, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => {
    throw new CogsGitMapError();
  });
  try {
    const stat = await handle.stat({ bigint: true });
    validateSameFile(stat, before, before.size);
    return { handle, marker: { dev: stat.dev, ino: stat.ino, size: Number(stat.size) } };
  } catch (error) {
    await closeHandle(handle, false).catch(() => undefined);
    if (error instanceof CogsGitMapError) throw error;
    throw new CogsGitMapError();
  }
}

async function openForAppend(
  fs: FsPort,
  sidecar: string,
  sessionDir: string,
  dir: DirectoryMarker,
  marker: FileMarker | undefined,
): Promise<OpenedAppend> {
  await validateSidecarPath(fs, sidecar, sessionDir, dir);
  if (marker === undefined) {
    const created = await fs
      .open(
        sidecar,
        constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      )
      .catch(() => {
        throw new CogsGitMapError();
      });
    try {
      const stat = await created.stat({ bigint: true });
      validateFileMode(stat, 0n);
      return { handle: created, marker: { dev: stat.dev, ino: stat.ino, size: 0 } };
    } catch (error) {
      await closeHandle(created, false).catch(() => undefined);
      if (error instanceof CogsGitMapError) throw error;
      throw new CogsGitMapError();
    }
  }
  const opened = await openExistingForAppend(fs, sidecar, sessionDir, dir);
  if (
    marker !== undefined &&
    (opened.marker.dev !== marker.dev || opened.marker.ino !== marker.ino || opened.marker.size !== marker.size)
  ) {
    await closeHandle(opened.handle, false).catch(() => undefined);
    throw new CogsGitMapError();
  }
  return opened;
}

async function openExistingForAppend(
  fs: FsPort,
  sidecar: string,
  sessionDir: string,
  dir: DirectoryMarker,
): Promise<OpenedAppend> {
  await validateSidecarPath(fs, sidecar, sessionDir, dir);
  const before = await checkedFileStat(fs, sidecar);
  const handle = await fs.open(sidecar, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW).catch(() => {
    throw new CogsGitMapError();
  });
  try {
    const stat = await handle.stat({ bigint: true });
    validateSameFile(stat, before, before.size);
    return { handle, marker: { dev: stat.dev, ino: stat.ino, size: Number(stat.size) } };
  } catch (error) {
    await closeHandle(handle, false).catch(() => undefined);
    if (error instanceof CogsGitMapError) throw error;
    throw new CogsGitMapError();
  }
}

async function validateSidecarPath(
  fs: FsPort,
  sidecar: string,
  sessionDir: string,
  dir: DirectoryMarker,
): Promise<void> {
  const realDir = await fs.realpath(sessionDir).catch(() => {
    throw new CogsGitMapError();
  });
  const resolved = resolve(sidecar);
  if (resolved !== resolve(sessionDir, FILE_NAME)) throw new CogsGitMapError();
  if ((await fs.realpath(dirname(resolved)).catch(() => "")) !== realDir) throw new CogsGitMapError();
  const current = await fs.lstat(sessionDir, { bigint: true }).catch(() => {
    throw new CogsGitMapError();
  });
  if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== dir.dev || current.ino !== dir.ino)
    throw new CogsGitMapError();
}

async function pinDirectory(fs: FsPort, sessionDir: string): Promise<DirectoryMarker> {
  const before = await fs.lstat(sessionDir, { bigint: true }).catch(() => {
    throw new CogsGitMapError();
  });
  if (!before.isDirectory() || before.isSymbolicLink()) throw new CogsGitMapError();
  const handle = await fs.open(sessionDir, constants.O_RDONLY | constants.O_DIRECTORY).catch(() => {
    throw new CogsGitMapError();
  });
  try {
    const stat = await handle.stat({ bigint: true });
    if (!stat.isDirectory() || stat.dev !== before.dev || stat.ino !== before.ino) throw new CogsGitMapError();
    await handle.close();
    return { dev: stat.dev, ino: stat.ino };
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (error instanceof CogsGitMapError) throw error;
    throw new CogsGitMapError();
  }
}

async function checkedFileStat(fs: FsPort, sidecar: string): Promise<BigStats> {
  const stat = await fs.lstat(sidecar, { bigint: true }).catch(() => {
    throw new CogsGitMapError();
  });
  validateFileMode(stat, undefined);
  return stat;
}

function validateFileMode(stat: BigStats, expectedSize: bigint | undefined): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) throw new CogsGitMapError();
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) throw new CogsGitMapError();
  if ((Number(stat.mode) & 0o777) !== 0o600) throw new CogsGitMapError();
  if (stat.size < 0n || stat.size > BigInt(MAX_BYTES)) throw new CogsGitMapError();
  if (expectedSize !== undefined && stat.size !== expectedSize) throw new CogsGitMapError();
}

function validateSameFile(stat: BigStats, before: BigStats, size: bigint): void {
  validateFileMode(stat, size);
  if (stat.dev !== before.dev || stat.ino !== before.ino || stat.size !== before.size) throw new CogsGitMapError();
}

function validateOpenedMarker(stat: BigStats, marker: FileMarker): void {
  validateFileMode(stat, BigInt(marker.size));
  if (stat.dev !== marker.dev || stat.ino !== marker.ino) throw new CogsGitMapError();
}

async function verifyPathFile(fs: FsPort, sidecar: string, marker: FileMarker): Promise<void> {
  const stat = await checkedFileStat(fs, sidecar);
  validateOpenedMarker(stat, marker);
}

async function syncDirectory(
  handle: Awaited<ReturnType<typeof open>>,
  marker: FileMarker,
  fs: FsPort,
  sessionDir: string,
  dir: DirectoryMarker,
): Promise<void> {
  const file = await handle.stat({ bigint: true });
  if (!file.isFile() || file.dev !== marker.dev || file.ino !== marker.ino || file.size !== BigInt(marker.size))
    throw new CogsGitMapError();
  const dirHandle = await fs.open(sessionDir, constants.O_RDONLY | constants.O_DIRECTORY).catch(() => {
    throw new CogsGitMapError();
  });
  try {
    const before = await dirHandle.stat({ bigint: true });
    if (!before.isDirectory() || before.dev !== dir.dev || before.ino !== dir.ino) throw new CogsGitMapError();
    await dirHandle.sync();
    const after = await dirHandle.stat({ bigint: true });
    if (!after.isDirectory() || after.dev !== dir.dev || after.ino !== dir.ino) throw new CogsGitMapError();
    await closeHandle(dirHandle, true);
  } catch (error) {
    await closeHandle(dirHandle, false).catch(() => undefined);
    if (error instanceof CogsGitMapError) throw error;
    throw new CogsGitMapError();
  }
}

async function scanRecords(handle: Awaited<ReturnType<typeof open>>, bytes: number): Promise<CogsGitMapRecord[]> {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_BYTES) throw new CogsGitMapError();
  const records: CogsGitMapRecord[] = [];
  const seen = new Set<string>();
  let lineBytes = 0;
  let lineChunks: Buffer[] = [];
  let offset = 0;
  let lastByte: number | undefined = bytes === 0 ? 0x0a : undefined;
  while (offset < bytes) {
    const chunk = Buffer.alloc(Math.min(READ_CHUNK_BYTES, bytes - offset));
    const read = await handle.read(chunk, 0, chunk.length, offset);
    if (read.bytesRead !== chunk.length) throw new CogsGitMapError();
    offset += read.bytesRead;
    let segmentStart = 0;
    for (let index = 0; index < read.bytesRead; index += 1) {
      const byte = chunk[index] ?? -1;
      lastByte = byte;
      if (byte !== 0x0a) continue;
      const segment = chunk.subarray(segmentStart, index);
      lineBytes += segment.length;
      if (lineBytes < 1 || lineBytes > MAX_LINE_BYTES) throw new CogsGitMapError();
      lineChunks.push(segment);
      if (records.length + 1 > MAX_RECORDS) throw new CogsGitMapError();
      const canonical = decodeLine(Buffer.concat(lineChunks, lineBytes));
      if (seen.has(canonical)) throw new CogsGitMapError();
      seen.add(canonical);
      records.push(parseCanonicalRecord(canonical));
      lineBytes = 0;
      lineChunks = [];
      segmentStart = index + 1;
    }
    if (segmentStart < read.bytesRead) {
      const segment = chunk.subarray(segmentStart, read.bytesRead);
      lineBytes += segment.length;
      if (lineBytes > MAX_LINE_BYTES) throw new CogsGitMapError();
      lineChunks.push(segment);
    }
  }
  if (lastByte !== 0x0a || lineBytes !== 0) throw new CogsGitMapError();
  return records;
}

function decodeLine(buffer: Buffer): string {
  try {
    return DECODER.decode(buffer);
  } catch {
    throw new CogsGitMapError();
  }
}

function parseCanonicalRecord(line: string): CogsGitMapRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new CogsGitMapError();
  }
  const record = snapshotRecord(parsed);
  if (canonicalRecord(record) !== line) throw new CogsGitMapError();
  return record;
}

function snapshotRecord(input: unknown): CogsGitMapRecord {
  try {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.getPrototypeOf(input) !== Object.prototype
    )
      throw new CogsGitMapError();
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string")) throw new CogsGitMapError();
    const sorted = (keys as string[]).sort();
    const required = ["commit", "confidence", "entry", "observed_at", "repo", "session", "turn", "version"];
    const checkpointKeys = ["checkpoint_ref", ...required].sort();
    const exact = sorted.join("\0");
    if (exact !== required.join("\0") && exact !== checkpointKeys.join("\0")) throw new CogsGitMapError();
    const values = new Map<string, unknown>();
    for (const key of sorted) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) throw new CogsGitMapError();
      values.set(key, descriptor.value);
    }
    const record = {
      version: expectString(values.get("version")),
      repo: expectString(values.get("repo")),
      commit: expectString(values.get("commit")),
      session: expectString(values.get("session")),
      entry: expectString(values.get("entry")),
      turn: expectNumber(values.get("turn")),
      observed_at: expectString(values.get("observed_at")),
      confidence: expectString(values.get("confidence")),
      ...(values.has("checkpoint_ref") ? { checkpoint_ref: expectString(values.get("checkpoint_ref")) } : {}),
    };
    validateRecord(record);
    return freezeRecord(record);
  } catch {
    throw new CogsGitMapError();
  }
}

function validateRecord(record: {
  readonly version: string;
  readonly repo: string;
  readonly commit: string;
  readonly session: string;
  readonly entry: string;
  readonly turn: number;
  readonly observed_at: string;
  readonly confidence: string;
  readonly checkpoint_ref?: string;
}): asserts record is CogsGitMapRecord {
  if (record.version !== VERSION) throw new CogsGitMapError();
  validateOpaque(record.repo);
  validateOpaque(record.session);
  validateCommit(record.commit);
  if (!ENTRY.test(record.entry)) throw new CogsGitMapError();
  if (!Number.isSafeInteger(record.turn) || record.turn < 0 || record.turn > 2 ** 31 - 1) throw new CogsGitMapError();
  try {
    if (!ISO.test(record.observed_at) || new Date(record.observed_at).toISOString() !== record.observed_at)
      throw new CogsGitMapError();
  } catch {
    throw new CogsGitMapError();
  }
  if (record.confidence !== "exact" && record.confidence !== "checkpoint") throw new CogsGitMapError();
  if (record.confidence === "checkpoint") {
    if (record.checkpoint_ref === undefined) throw new CogsGitMapError();
    const match = CHECKPOINT_REF.exec(record.checkpoint_ref);
    if (match?.[1] !== record.session || match[2] !== String(record.turn)) throw new CogsGitMapError();
  } else if (record.checkpoint_ref !== undefined) {
    throw new CogsGitMapError();
  }
}

function canonicalRecord(record: CogsGitMapRecord): string {
  const ordered: Record<string, JsonValue> = {
    version: record.version,
    repo: record.repo,
    commit: record.commit,
    session: record.session,
    entry: record.entry,
    turn: record.turn,
    observed_at: record.observed_at,
    confidence: record.confidence,
  };
  if (record.confidence === "checkpoint") ordered.checkpoint_ref = record.checkpoint_ref ?? "";
  return JSON.stringify(ordered);
}

function freezeRecord(record: CogsGitMapRecord): CogsGitMapRecord {
  const { checkpoint_ref: _checkpointRef, ...base } = record;
  return Object.freeze(
    record.confidence === "checkpoint" ? { ...base, checkpoint_ref: record.checkpoint_ref ?? "" } : base,
  );
}

function freezeMapping(record: CogsGitMapResolvedMapping): CogsGitMapResolvedMapping {
  return Object.freeze({ ...record });
}

function mapped(
  requestedCommit: string,
  mapping: CogsGitMapResolvedMapping,
  ancestorCommit?: string,
  sourceMapping?: CogsGitMapRecord,
): CogsGitMapResolveResult {
  return Object.freeze({
    kind: "mapped",
    requested_commit: requestedCommit,
    mapping: freezeMapping(mapping),
    ...(ancestorCommit === undefined ? {} : { ancestor_commit: ancestorCommit }),
    ...(sourceMapping === undefined ? {} : { source_mapping: freezeRecord(sourceMapping) }),
  });
}

function preCogs(repo: string, session: string, commit: string): CogsGitMapResolveResult {
  return Object.freeze({ kind: "pre-cogs", repo, session, requested_commit: commit });
}

function unavailable(repo: string, session: string, commit: string): CogsGitMapResolveResult {
  return Object.freeze({ kind: "unavailable", repo, session, requested_commit: commit });
}

function latest<T>(records: readonly T[]): T | undefined {
  return records.at(-1);
}

function dedupeLatest(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const value = values[index];
    if (value === undefined || seen.has(value)) continue;
    seen.add(value);
    if (out.length >= MAX_CANDIDATES) throw new CogsGitMapError();
    out.push(value);
  }
  return out;
}

function validateOpaque(value: string): void {
  if (!OPAQUE.test(value)) throw new CogsGitMapError();
}

function validateCommit(value: string): void {
  if (!COMMIT.test(value)) throw new CogsGitMapError();
}

function expectString(value: unknown): string {
  if (typeof value !== "string") throw new CogsGitMapError();
  return value;
}

function expectNumber(value: unknown): number {
  if (typeof value !== "number") throw new CogsGitMapError();
  return value;
}

async function enqueue<T>(state: { chain: Promise<unknown> }, operation: () => Promise<T>): Promise<T> {
  const previous = state.chain.catch(() => undefined);
  const next = previous.then(operation, operation);
  state.chain = next.catch(() => undefined);
  return next;
}

async function closeHandle(handle: Awaited<ReturnType<typeof open>>, required: boolean): Promise<void> {
  try {
    await handle.close();
  } catch {
    if (required) throw new CogsGitMapError();
  }
}

function freezeFs(input: Partial<FsPort> | undefined): FsPort {
  return Object.freeze({
    lstat: input?.lstat ?? lstat,
    realpath: input?.realpath ?? realpath,
    open: input?.open ?? open,
  });
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CogsGitMapError();
}
