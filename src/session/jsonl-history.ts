import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { TextDecoder } from "node:util";
import type { JsonValue } from "../api/server.ts";

export interface CogsJsonlHistoryPage {
  readonly entries: readonly JsonValue[];
  readonly nextAfter?: string;
}

export class CogsJsonlHistoryError extends Error {
  public readonly code = "COGS_JSONL_HISTORY_FAILED";
  public constructor() {
    super("invalid session history");
    this.name = "CogsJsonlHistoryError";
  }
}

export class CogsJsonlHistoryCursorError extends Error {
  public readonly code = "COGS_JSONL_HISTORY_CURSOR_UNKNOWN";
  public constructor() {
    super("unknown history cursor");
    this.name = "CogsJsonlHistoryCursorError";
  }
}

export interface CogsJsonlHistoryStore {
  readonly initialize: (input?: { signal?: AbortSignal }) => Promise<void>;
  readonly flushSettled: (input?: { signal?: AbortSignal }) => Promise<void>;
  readonly entries: (input: {
    after: string | undefined;
    limit: number;
    signal?: AbortSignal;
  }) => Promise<CogsJsonlHistoryPage>;
  readonly durableBytes: () => number;
}

interface DirectoryMarker {
  readonly dirDev: bigint;
  readonly dirIno: bigint;
}

interface DurableMarker extends DirectoryMarker {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly bytes: number;
}

interface OpenedHistory {
  readonly handle: Awaited<ReturnType<typeof open>>;
  readonly dirHandle: Awaited<ReturnType<typeof open>>;
  readonly marker: DurableMarker;
}

interface ScanRequest {
  readonly after?: string;
  readonly limit?: number;
}

interface ScanResult {
  readonly page: readonly JsonValue[];
  readonly nextAfter?: string;
}

// Native Pi JSONL is streamed, but per-line JSON parsing still needs practical hard caps.
const MAX_HISTORY_BYTES = 64 * 1024 * 1024;
const MAX_LINE_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const READ_CHUNK_BYTES = 4096;
const DECODER = new TextDecoder("utf-8", { fatal: true });
const ENTRY_ID = /^(?:[a-f0-9]{8}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/;
const HEADER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CURSOR = /^[A-Za-z0-9-]{1,128}$/;

export function createCogsJsonlHistoryStore(input: {
  readonly sessionFile: string | undefined;
  readonly sessionDir: string;
}): CogsJsonlHistoryStore {
  const sessionFile = input.sessionFile;
  const sessionDir = input.sessionDir;
  let pinnedDirectory: DirectoryMarker | undefined;
  let durableMarker: DurableMarker | undefined;
  return Object.freeze({
    initialize: async ({ signal }: { signal?: AbortSignal } = {}) => {
      throwIfAborted(signal);
      if (sessionFile === undefined) return;
      const pinned = await pinDirectory(sessionDir);
      pinnedDirectory = pinned.marker;
      await pinned.handle.close().catch(() => {
        throw new CogsJsonlHistoryError();
      });
      try {
        await lstat(sessionFile);
      } catch (error) {
        if ((error as { code?: unknown }).code === "ENOENT") return;
        throw new CogsJsonlHistoryError();
      }
      durableMarker = await validateAndSync(sessionFile, sessionDir, pinnedDirectory, undefined, signal);
      pinnedDirectory = durableMarker;
    },
    flushSettled: async ({ signal }: { signal?: AbortSignal } = {}) => {
      throwIfAborted(signal);
      if (sessionFile === undefined || pinnedDirectory === undefined) throw new CogsJsonlHistoryError();
      durableMarker = await validateAndSync(sessionFile, sessionDir, pinnedDirectory, durableMarker, signal);
      pinnedDirectory = durableMarker;
    },
    entries: async ({ after, limit, signal }: { after: string | undefined; limit: number; signal?: AbortSignal }) => {
      throwIfAborted(signal);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new CogsJsonlHistoryError();
      if (after !== undefined && !CURSOR.test(after)) throw new CogsJsonlHistoryError();
      const marker = durableMarker;
      if (sessionFile === undefined || marker === undefined)
        return Object.freeze({ entries: Object.freeze([]) }) satisfies CogsJsonlHistoryPage;
      const opened = await openForRead(sessionFile, sessionDir, marker, signal);
      let success = false;
      try {
        const scanned = await scanHistory(
          opened.handle,
          marker.bytes,
          signal,
          after === undefined ? { limit } : { after, limit },
        );
        success = true;
        return Object.freeze({
          entries: Object.freeze(scanned.page),
          ...(scanned.nextAfter === undefined ? {} : { nextAfter: scanned.nextAfter }),
        });
      } finally {
        await closeOpened(opened, success);
      }
    },
    durableBytes: () => durableMarker?.bytes ?? 0,
  });
}

async function validateAndSync(
  sessionFile: string,
  sessionDir: string,
  expectedDirectory: DirectoryMarker,
  previousMarker: DurableMarker | undefined,
  signal: AbortSignal | undefined,
): Promise<DurableMarker> {
  const opened = await openForFlush(sessionFile, sessionDir, expectedDirectory, previousMarker, signal);
  let success = false;
  try {
    if (opened.marker.bytes === 0) throw new CogsJsonlHistoryError();
    await scanHistory(opened.handle, opened.marker.bytes, signal, {});
    throwIfAborted(signal);
    const afterRead = await opened.handle.stat({ bigint: true });
    if (
      !afterRead.isFile() ||
      afterRead.dev !== opened.marker.dev ||
      afterRead.ino !== opened.marker.ino ||
      afterRead.size !== BigInt(opened.marker.bytes)
    )
      throw new CogsJsonlHistoryError();
    await opened.handle.sync();
    throwIfAborted(signal);
    const afterSync = await opened.handle.stat({ bigint: true });
    if (
      !afterSync.isFile() ||
      afterSync.dev !== opened.marker.dev ||
      afterSync.ino !== opened.marker.ino ||
      afterSync.size !== BigInt(opened.marker.bytes)
    )
      throw new CogsJsonlHistoryError();
    await syncDirectory(opened.dirHandle, opened.marker);
    success = true;
    return opened.marker;
  } finally {
    await closeOpened(opened, success);
  }
}

async function openForFlush(
  sessionFile: string,
  sessionDir: string,
  expectedDirectory: DirectoryMarker,
  previousMarker: DurableMarker | undefined,
  signal: AbortSignal | undefined,
): Promise<OpenedHistory> {
  throwIfAborted(signal);
  const pinned = await pinDirectory(sessionDir);
  const dir = pinned.handle;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    if (pinned.marker.dirDev !== expectedDirectory.dirDev || pinned.marker.dirIno !== expectedDirectory.dirIno)
      throw new CogsJsonlHistoryError();
    const resolved = await validateSessionPath(sessionFile, sessionDir);
    const before = await lstat(resolved, { bigint: true }).catch(() => {
      throw new CogsJsonlHistoryError();
    });
    if (!before.isFile() || before.isSymbolicLink() || before.size < 0n || before.size > BigInt(MAX_HISTORY_BYTES))
      throw new CogsJsonlHistoryError();
    if (
      previousMarker !== undefined &&
      (before.dev !== previousMarker.dev ||
        before.ino !== previousMarker.ino ||
        before.size < BigInt(previousMarker.bytes))
    )
      throw new CogsJsonlHistoryError();
    handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => {
      throw new CogsJsonlHistoryError();
    });
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile() || stat.size !== before.size || stat.dev !== before.dev || stat.ino !== before.ino)
      throw new CogsJsonlHistoryError();
    await verifyCurrentDirectory(sessionDir, expectedDirectory);
    if (
      previousMarker !== undefined &&
      (stat.dev !== previousMarker.dev || stat.ino !== previousMarker.ino || stat.size < BigInt(previousMarker.bytes))
    )
      throw new CogsJsonlHistoryError();
    return {
      handle,
      dirHandle: dir,
      marker: { dev: stat.dev, ino: stat.ino, bytes: Number(stat.size), ...pinned.marker },
    };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await dir.close().catch(() => undefined);
    if (error instanceof CogsJsonlHistoryError) throw error;
    throw new CogsJsonlHistoryError();
  }
}

async function openForRead(
  sessionFile: string,
  sessionDir: string,
  marker: DurableMarker,
  signal: AbortSignal | undefined,
): Promise<OpenedHistory> {
  throwIfAborted(signal);
  const pinned = await pinDirectory(sessionDir);
  const dir = pinned.handle;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    if (pinned.marker.dirDev !== marker.dirDev || pinned.marker.dirIno !== marker.dirIno)
      throw new CogsJsonlHistoryError();
    const resolved = await validateSessionPath(sessionFile, sessionDir);
    handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => {
      throw new CogsJsonlHistoryError();
    });
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile() || stat.dev !== marker.dev || stat.ino !== marker.ino || stat.size < BigInt(marker.bytes))
      throw new CogsJsonlHistoryError();
    await verifyCurrentDirectory(sessionDir, marker);
    return { handle, dirHandle: dir, marker };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await dir.close().catch(() => undefined);
    if (error instanceof CogsJsonlHistoryError) throw error;
    throw new CogsJsonlHistoryError();
  }
}

async function pinDirectory(
  sessionDir: string,
): Promise<{ readonly handle: Awaited<ReturnType<typeof open>>; readonly marker: DirectoryMarker }> {
  const before = await lstat(sessionDir, { bigint: true }).catch(() => {
    throw new CogsJsonlHistoryError();
  });
  if (!before.isDirectory() || before.isSymbolicLink()) throw new CogsJsonlHistoryError();
  const dir = await open(sessionDir, constants.O_RDONLY | constants.O_DIRECTORY).catch(() => {
    throw new CogsJsonlHistoryError();
  });
  try {
    const stat = await dir.stat({ bigint: true });
    if (!stat.isDirectory() || stat.dev !== before.dev || stat.ino !== before.ino) throw new CogsJsonlHistoryError();
    return { handle: dir, marker: { dirDev: stat.dev, dirIno: stat.ino } };
  } catch (error) {
    await dir.close().catch(() => undefined);
    if (error instanceof CogsJsonlHistoryError) throw error;
    throw new CogsJsonlHistoryError();
  }
}

async function verifyCurrentDirectory(sessionDir: string, marker: DirectoryMarker): Promise<void> {
  const stat = await lstat(sessionDir, { bigint: true }).catch(() => {
    throw new CogsJsonlHistoryError();
  });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== marker.dirDev || stat.ino !== marker.dirIno)
    throw new CogsJsonlHistoryError();
}

async function validateSessionPath(sessionFile: string, sessionDir: string): Promise<string> {
  const realDir = await realpath(sessionDir).catch(() => {
    throw new CogsJsonlHistoryError();
  });
  const resolved = resolve(sessionFile);
  if ((await realpath(dirname(resolved)).catch(() => "")) !== realDir) throw new CogsJsonlHistoryError();
  return resolved;
}

async function syncDirectory(handle: Awaited<ReturnType<typeof open>>, marker: DurableMarker): Promise<void> {
  const before = await handle.stat({ bigint: true });
  if (!before.isDirectory() || before.dev !== marker.dirDev || before.ino !== marker.dirIno)
    throw new CogsJsonlHistoryError();
  await handle.sync();
  const after = await handle.stat({ bigint: true });
  if (!after.isDirectory() || after.dev !== marker.dirDev || after.ino !== marker.dirIno)
    throw new CogsJsonlHistoryError();
}

async function closeOpened(opened: OpenedHistory, success: boolean): Promise<void> {
  if (success) {
    const fileClose = await opened.handle.close().then(
      () => undefined,
      () => new CogsJsonlHistoryError(),
    );
    const dirClose = await opened.dirHandle.close().then(
      () => undefined,
      () => new CogsJsonlHistoryError(),
    );
    if (fileClose !== undefined || dirClose !== undefined) throw new CogsJsonlHistoryError();
    return;
  }
  await opened.handle.close().catch(() => undefined);
  await opened.dirHandle.close().catch(() => undefined);
}

async function scanHistory(
  handle: Awaited<ReturnType<typeof open>>,
  bytes: number,
  signal: AbortSignal | undefined,
  request: ScanRequest,
): Promise<ScanResult> {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_HISTORY_BYTES) throw new CogsJsonlHistoryError();
  const ids = new Set<string>();
  const page: JsonValue[] = [];
  let sawAfter = request.after === undefined;
  let nextAfter: string | undefined;
  let lineCount = 0;
  let lineBytes = 0;
  let lineChunks: Buffer[] = [];
  let offset = 0;
  let lastByte: number | undefined;
  while (offset < bytes) {
    throwIfAborted(signal);
    const chunk = Buffer.alloc(Math.min(READ_CHUNK_BYTES, bytes - offset));
    const read = await handle.read(chunk, 0, chunk.length, offset);
    if (read.bytesRead !== chunk.length) throw new CogsJsonlHistoryError();
    offset += read.bytesRead;
    let segmentStart = 0;
    for (let index = 0; index < read.bytesRead; index += 1) {
      const byte = chunk[index] ?? -1;
      lastByte = byte;
      if (byte !== 0x0a) continue;
      const segment = chunk.subarray(segmentStart, index);
      lineBytes += segment.length;
      if (lineBytes < 1 || lineBytes > MAX_LINE_BYTES) throw new CogsJsonlHistoryError();
      lineChunks.push(segment);
      lineCount += 1;
      if (lineCount > MAX_ENTRIES + 1) throw new CogsJsonlHistoryError();
      processLine(
        Buffer.concat(lineChunks, lineBytes),
        lineCount,
        ids,
        page,
        request,
        () => sawAfter,
        (value) => {
          sawAfter = value;
        },
        (value) => {
          nextAfter = value;
        },
      );
      lineBytes = 0;
      lineChunks = [];
      segmentStart = index + 1;
    }
    if (segmentStart < read.bytesRead) {
      const segment = chunk.subarray(segmentStart, read.bytesRead);
      lineBytes += segment.length;
      if (lineBytes > MAX_LINE_BYTES) throw new CogsJsonlHistoryError();
      lineChunks.push(segment);
    }
  }
  if (lastByte !== 0x0a || lineBytes !== 0 || lineCount < 1) throw new CogsJsonlHistoryError();
  if (request.after !== undefined && !sawAfter) throw new CogsJsonlHistoryCursorError();
  return Object.freeze({ page: Object.freeze(page), ...(nextAfter === undefined ? {} : { nextAfter }) });
}

function processLine(
  buffer: Buffer,
  lineNumber: number,
  ids: Set<string>,
  page: JsonValue[],
  request: ScanRequest,
  getSawAfter: () => boolean,
  setSawAfter: (value: boolean) => void,
  setNextAfter: (value: string) => void,
): void {
  let text: string;
  try {
    text = DECODER.decode(buffer);
  } catch {
    throw new CogsJsonlHistoryError();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CogsJsonlHistoryError();
  }
  if (!isPlainJsonObject(parsed)) throw new CogsJsonlHistoryError();
  if (lineNumber === 1) {
    validateHeader(parsed as JsonValue);
    return;
  }
  const entry = parsed as JsonValue;
  const id = entryId(entry);
  if (ids.has(id)) throw new CogsJsonlHistoryError();
  const parentId = (entry as { readonly parentId?: unknown }).parentId;
  if (parentId !== null && (typeof parentId !== "string" || !ids.has(parentId))) throw new CogsJsonlHistoryError();
  ids.add(id);
  if (request.after !== undefined && !getSawAfter()) {
    if (id === request.after) setSawAfter(true);
    return;
  }
  const limit = request.limit;
  if (limit === undefined) return;
  if (page.length < limit) {
    page.push(entry);
    return;
  }
  if (page.length === limit) {
    const last = page.at(-1);
    if (last !== undefined) setNextAfter(entryId(last));
  }
}

function validateHeader(value: JsonValue | undefined): void {
  if (!isPlainJsonObject(value)) throw new CogsJsonlHistoryError();
  const header = value as { readonly type?: unknown; readonly version?: unknown; readonly id?: unknown };
  if (header.type !== "session" || header.version !== 3 || typeof header.id !== "string" || !HEADER_ID.test(header.id))
    throw new CogsJsonlHistoryError();
}

function entryId(value: JsonValue): string {
  if (!isPlainJsonObject(value)) throw new CogsJsonlHistoryError();
  const entry = value as { readonly type?: unknown; readonly id?: unknown; readonly parentId?: unknown };
  if (typeof entry.type !== "string" || entry.type.length < 1 || entry.type.length > 128)
    throw new CogsJsonlHistoryError();
  if (typeof entry.id !== "string" || !ENTRY_ID.test(entry.id)) throw new CogsJsonlHistoryError();
  if (!("parentId" in entry)) throw new CogsJsonlHistoryError();
  return entry.id;
}

function isPlainJsonObject(value: unknown): value is { readonly [key: string]: JsonValue | undefined } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CogsJsonlHistoryError();
}
