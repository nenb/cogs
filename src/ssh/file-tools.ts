import { randomBytes } from "node:crypto";
import path from "node:path/posix";
import type { JsonValue } from "../api/server.ts";
import type { CogsToolPorts } from "../pi/session.ts";
import {
  type CogsSftpPort,
  type CogsSftpStats,
  CogsSftpStatusError,
  SshConnectionError,
  type SshConnectionManager,
} from "./connection.ts";

const READ_ROOTS = ["/workspace", "/shared/skills", "/user/skills"] as const;
const WRITE_ROOT = "/workspace";
const CHUNK_BYTES = 32 * 1024;

export interface SftpFileToolOptions {
  readonly manager: SshConnectionManager;
  readonly maxReadBytes?: number;
  readonly maxWriteBytes?: number;
  readonly maxPathBytes?: number;
  readonly maxResultBytes?: number;
  readonly operationTimeoutMs?: number;
  readonly idleTimeoutMs?: number;
  readonly openTimeoutMs?: number;
  readonly closeTimeoutMs?: number;
}

type Config = Required<SftpFileToolOptions>;

class SftpFileToolError extends Error {
  public readonly code = "COGS_SFTP_FILE_TOOL_FAILED";
  public constructor(message: string) {
    super(message);
    this.name = "SftpFileToolError";
  }
}

export function createSftpFileToolPorts(options: SftpFileToolOptions): Pick<CogsToolPorts, "read" | "write" | "edit"> {
  const config = normalizeOptions(options);
  return {
    read: async (input) => readTool(config, input),
    write: async (input) => writeTool(config, input),
    edit: async (input) => editTool(config, input),
  };
}

async function readTool(
  config: Config,
  input: { path: string; offset?: number; limit?: number; signal?: AbortSignal },
): Promise<JsonValue> {
  const guestPath = normalizeGuestPath(input.path, "read", config.maxPathBytes);
  const offset = integer(input.offset ?? 0, 0, 1_000_000, "offset");
  const limit = integer(input.limit ?? 2000, 1, 10_000, "limit");
  return config.manager.withSftp(withBounds(config, input.signal), async (sftp, signal) => {
    await validateExistingFile(sftp, guestPath, READ_ROOTS, config, signal);
    const attrs = await call(config, signal, (callSignal) => sftp.lstat(guestPath, callSignal));
    const size = sizeOf(attrs);
    if (size > config.maxReadBytes) return nonTextResult(guestPath, "unknown", "too_large", size);
    const handle = await call(config, signal, (callSignal) => sftp.open(guestPath, "r", callSignal));
    try {
      const stat = await call(config, signal, (callSignal) => sftp.fstat(handle, callSignal));
      const statSize = sizeOf(stat);
      if (stat.type !== "file") throw new SftpFileToolError("unsupported file type");
      if (statSize > config.maxReadBytes || statSize < size) throw new SftpFileToolError("file size changed");
      const data = await readBounded(sftp, handle, statSize, config, signal);
      const text = decodeUtf8(data);
      if (text === undefined) return binaryResult(guestPath, "invalid_utf8", statSize);
      const lines = splitLines(text);
      const selected = lines.slice(offset, offset + limit);
      let content = selected.join("\n");
      if (text.endsWith("\n") && offset + selected.length === lines.length) content += "\n";
      let result = readResult(guestPath, content, offset, limit, selected.length, lines.length, data.length, statSize);
      const bounded = boundReadResult(
        result,
        selected,
        text.endsWith("\n") && offset + selected.length === lines.length,
        config.maxResultBytes,
      );
      result = bounded.result;
      const exhaustedLines = offset + selected.length >= lines.length;
      return { ...result, eof: exhaustedLines && !bounded.truncated, truncated: !exhaustedLines || bounded.truncated };
    } finally {
      await cleanup(config, (cleanupSignal) => sftp.closeHandle(handle, cleanupSignal));
    }
  }) as Promise<JsonValue>;
}

async function writeTool(
  config: Config,
  input: { path: string; content: string; signal?: AbortSignal },
): Promise<JsonValue> {
  const guestPath = normalizeGuestPath(input.path, "write", config.maxPathBytes);
  const data = encodeInput(input.content, config.maxWriteBytes);
  return atomicWrite(config, guestPath, data, input.signal) as Promise<JsonValue>;
}

async function editTool(
  config: Config,
  input: { path: string; oldText: string; newText: string; signal?: AbortSignal },
): Promise<JsonValue> {
  if (input.oldText.length === 0) throw new SftpFileToolError("old text must be nonempty");
  const guestPath = normalizeGuestPath(input.path, "write", config.maxPathBytes);
  const oldText = encodeInput(input.oldText, config.maxWriteBytes).toString("utf8");
  const newText = encodeInput(input.newText, config.maxWriteBytes).toString("utf8");
  return config.manager.withSftp(withBounds(config, input.signal), async (sftp, signal) => {
    await validateExistingFile(sftp, guestPath, [WRITE_ROOT], config, signal);
    const attrs = await call(config, signal, (callSignal) => sftp.lstat(guestPath, callSignal));
    const size = sizeOf(attrs);
    if (size > config.maxReadBytes) throw new SftpFileToolError("file is too large");
    const handle = await call(config, signal, (callSignal) => sftp.open(guestPath, "r", callSignal));
    let text: string;
    try {
      const stat = await call(config, signal, (callSignal) => sftp.fstat(handle, callSignal));
      const statSize = sizeOf(stat);
      if (stat.type !== "file") throw new SftpFileToolError("unsupported file type");
      if (statSize > config.maxReadBytes || statSize < size) throw new SftpFileToolError("file size changed");
      const data = await readBounded(sftp, handle, statSize, config, signal);
      const decoded = decodeUtf8(data);
      if (decoded === undefined) throw new SftpFileToolError("file is not strict utf8");
      text = decoded;
    } finally {
      await cleanup(config, (cleanupSignal) => sftp.closeHandle(handle, cleanupSignal));
    }
    if (countOccurrences(text, oldText) !== 1) throw new SftpFileToolError("edit text is not unique");
    const updated = Buffer.from(text.replace(oldText, newText), "utf8");
    if (updated.length > config.maxWriteBytes) throw new SftpFileToolError("content is too large");
    return { ...(await atomicWriteWithPort(config, sftp, guestPath, updated, signal)), occurrences: 1 };
  }) as Promise<JsonValue>;
}

async function atomicWrite(config: Config, guestPath: string, data: Buffer, signal?: AbortSignal) {
  return config.manager.withSftp(withBounds(config, signal), (sftp, opSignal) =>
    atomicWriteWithPort(config, sftp, guestPath, data, opSignal),
  );
}

async function atomicWriteWithPort(
  config: Config,
  sftp: CogsSftpPort,
  guestPath: string,
  data: Buffer,
  signal: AbortSignal,
) {
  await validateWritableTarget(sftp, guestPath, config, signal);
  const temp = `${path.dirname(guestPath)}/.cogs-${randomBytes(18).toString("hex")}.tmp`;
  let handle: Buffer | undefined;
  let cleanupTemp = false;
  let primaryError: unknown;
  try {
    handle = await call(config, signal, (callSignal) => sftp.open(temp, "wx", callSignal));
    cleanupTemp = true;
    await writeAll(sftp, handle, data, config, signal);
    const stat = await call(config, signal, (callSignal) => sftp.fstat(handle as Buffer, callSignal));
    if (stat.type !== "file" || sizeOf(stat) !== data.length)
      throw new SftpFileToolError("temporary file validation failed");
    await call(config, signal, (callSignal) => sftp.fsync(handle as Buffer, callSignal));
    await call(config, signal, (callSignal) => sftp.closeHandle(handle as Buffer, callSignal));
    handle = undefined;
    await call(config, signal, (callSignal) => sftp.posixRename(temp, guestPath, callSignal));
    cleanupTemp = false;
    return { ok: true, path: guestPath, bytesWritten: data.length, atomic: true, fsync: "openssh" };
  } catch (error) {
    primaryError = error;
  }
  let cleanupFailed = false;
  if (handle !== undefined) {
    try {
      await cleanup(config, (cleanupSignal) => sftp.closeHandle(handle as Buffer, cleanupSignal));
    } catch {
      cleanupFailed = true;
    }
  }
  if (cleanupTemp) {
    try {
      await cleanup(config, (cleanupSignal) => sftp.unlink(temp, cleanupSignal));
    } catch {
      cleanupFailed = true;
    }
  }
  if (cleanupFailed) throw new SftpFileToolError("cleanup failed");
  throw primaryError;
}

async function readBounded(
  sftp: CogsSftpPort,
  handle: Buffer,
  size: number,
  config: Config,
  signal: AbortSignal,
): Promise<Buffer> {
  const output = Buffer.alloc(size);
  let position = 0;
  while (position < size) {
    const length = Math.min(CHUNK_BYTES, size - position);
    const chunk = Buffer.alloc(length);
    const result = await call(config, signal, (callSignal) =>
      sftp.read(handle, chunk, 0, length, position, callSignal),
    );
    if (result.bytesRead === 0) throw new SftpFileToolError("short read");
    chunk.copy(output, position, 0, result.bytesRead);
    chunk.fill(0);
    position += result.bytesRead;
  }
  const trailing = Buffer.alloc(1);
  try {
    const extra = await call(config, signal, (callSignal) => sftp.read(handle, trailing, 0, 1, size, callSignal));
    if (extra.bytesRead !== 0) throw new SftpFileToolError("file grew during read");
  } finally {
    trailing.fill(0);
  }
  return output;
}

async function writeAll(sftp: CogsSftpPort, handle: Buffer, data: Buffer, config: Config, signal: AbortSignal) {
  for (let position = 0; position < data.length; position += CHUNK_BYTES) {
    const length = Math.min(CHUNK_BYTES, data.length - position);
    await call(config, signal, (callSignal) => sftp.write(handle, data, position, length, position, callSignal));
  }
}

async function validateExistingFile(
  sftp: CogsSftpPort,
  guestPath: string,
  roots: readonly string[],
  config: Config,
  signal: AbortSignal,
) {
  await validateComponents(sftp, guestPath, roots, config, signal, true);
  const attrs = await call(config, signal, (callSignal) => sftp.lstat(guestPath, callSignal));
  if (attrs.type !== "file") throw new SftpFileToolError("unsupported file type");
}

async function validateWritableTarget(sftp: CogsSftpPort, guestPath: string, config: Config, signal: AbortSignal) {
  await validateComponents(sftp, guestPath, [WRITE_ROOT], config, signal, false);
  try {
    const attrs = await call(config, signal, (callSignal) => sftp.lstat(guestPath, callSignal));
    if (attrs.type !== "file") throw new SftpFileToolError("unsupported file type");
  } catch (error) {
    if (!(error instanceof SftpFileToolError) || error.message !== "not found") throw error;
  }
}

async function validateComponents(
  sftp: CogsSftpPort,
  guestPath: string,
  roots: readonly string[],
  config: Config,
  signal: AbortSignal,
  includeFinal: boolean,
) {
  assertInsideRoots(guestPath, roots);
  const parts = guestPath.split("/").filter(Boolean);
  const last = includeFinal ? parts.length : parts.length - 1;
  for (let index = 1; index <= last; index += 1) {
    const current = `/${parts.slice(0, index).join("/")}`;
    const attrs = await call(config, signal, (callSignal) => sftp.lstat(current, callSignal));
    if (attrs.type === "symlink") throw new SftpFileToolError("symlink paths are not allowed");
    if (index < parts.length && attrs.type !== "directory") throw new SftpFileToolError("invalid path component");
  }
  const resolved = await call(config, signal, (callSignal) => sftp.realpath(path.dirname(guestPath), callSignal));
  validateCanonicalPath(resolved, config.maxPathBytes);
  assertInsideRoots(resolved, roots);
}

async function call<T>(
  config: Config,
  signal: AbortSignal,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = linkedSignal(signal);
  let idle: NodeJS.Timeout | undefined;
  let total: NodeJS.Timeout | undefined;
  try {
    return await new Promise<T>((resolve, reject) => {
      let settled = false;
      const succeed = (value: T) => {
        if (settled) return;
        settled = true;
        if (idle) clearTimeout(idle);
        if (total) clearTimeout(total);
        controller.dispose();
        resolve(value);
      };
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        if (idle) clearTimeout(idle);
        if (total) clearTimeout(total);
        controller.dispose();
        reject(redactToolError(error));
      };
      idle = setTimeout(() => {
        controller.abort();
        fail(new SftpFileToolError("operation idle timed out"));
      }, config.idleTimeoutMs);
      total = setTimeout(() => {
        controller.abort();
        fail(new SftpFileToolError("operation timed out"));
      }, config.operationTimeoutMs);
      controller.signal.addEventListener("abort", () => fail(new SftpFileToolError("operation aborted")), {
        once: true,
      });
      operation(controller.signal).then(succeed, fail);
    });
  } finally {
    controller.dispose();
  }
}

async function cleanup(config: Config, operation: (signal: AbortSignal) => Promise<void>): Promise<void> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const succeed = () => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        resolve();
      };
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        reject(error);
      };
      timer = setTimeout(() => {
        controller.abort();
        fail(new SftpFileToolError("cleanup failed"));
      }, config.closeTimeoutMs);
      operation(controller.signal).then(succeed, fail);
    });
  } catch {
    throw new SftpFileToolError("cleanup failed");
  }
}

function normalizeGuestPath(input: string, mode: "read" | "write", maxPathBytes: number): string {
  const absolute = input.startsWith("/") ? input : `${WRITE_ROOT}/${input}`;
  const normalized = validateCanonicalPath(absolute, maxPathBytes);
  assertInsideRoots(normalized, mode === "write" ? [WRITE_ROOT] : READ_ROOTS);
  return normalized;
}

function validateCanonicalPath(input: string, maxPathBytes: number): string {
  if (!isSafeString(input) || Buffer.byteLength(input, "utf8") > maxPathBytes || input.includes("\\"))
    throw new SftpFileToolError("invalid path");
  if (!input.startsWith("/")) throw new SftpFileToolError("invalid path");
  const normalized = path.normalize(input);
  if (normalized !== input || normalized.includes("..")) throw new SftpFileToolError("invalid path");
  for (const segment of normalized.split("/").filter(Boolean)) {
    if (!isSafeString(segment) || segment.normalize("NFC") !== segment || segment === "." || segment === "..")
      throw new SftpFileToolError("invalid path");
  }
  return normalized;
}

function isSafeString(value: string): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f || (code >= 0x80 && /\p{C}/u.test(character))) return false;
  }
  return !/[\uD800-\uDFFF]/u.test(value);
}

function encodeInput(content: string, maxBytes: number): Buffer {
  if (!isSafeContent(content)) throw new SftpFileToolError("invalid content");
  const data = Buffer.from(content, "utf8");
  if (data.length > maxBytes) throw new SftpFileToolError("content is too large");
  return data;
}
function isSafeContent(value: string): boolean {
  return typeof value === "string" && !/[\uD800-\uDFFF]/u.test(value);
}
function decodeUtf8(data: Buffer): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    return undefined;
  }
}
function splitLines(text: string): string[] {
  return text.length === 0 ? [] : text.endsWith("\n") ? text.slice(0, -1).split("\n") : text.split("\n");
}
function countOccurrences(text: string, needle: string): number {
  let count = 0;
  let index = text.indexOf(needle, 0);
  while (index !== -1) {
    count += 1;
    index = text.indexOf(needle, index + 1);
  }
  return count;
}
function sizeOf(attrs: CogsSftpStats): number {
  if (!Number.isSafeInteger(attrs.size) || attrs.size < 0) throw new SftpFileToolError("invalid file metadata");
  return attrs.size;
}
function readResult(
  path: string,
  content: string,
  offset: number,
  limit: number,
  linesReturned: number,
  totalLines: number,
  bytesRead: number,
  sizeBytes: number,
): Record<string, JsonValue> {
  return {
    ok: true,
    path,
    content,
    encoding: "utf8",
    offset,
    limit,
    linesReturned,
    totalLines,
    eof: false,
    truncated: false,
    bytesRead,
    sizeBytes,
  };
}

function boundReadResult(
  result: Record<string, JsonValue>,
  selectedLines: readonly string[],
  appendTrailingNewline: boolean,
  maxResultBytes: number,
) {
  if (Buffer.byteLength(JSON.stringify(result), "utf8") <= maxResultBytes) return { result, truncated: false };
  let low = 0;
  let high = selectedLines.length;
  let bestContent = "";
  let bestCount = 0;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const content = renderLines(selectedLines, mid, appendTrailingNewline && mid === selectedLines.length);
    const candidate = { ...result, content, linesReturned: mid };
    if (Buffer.byteLength(JSON.stringify(candidate), "utf8") <= maxResultBytes) {
      bestContent = content;
      bestCount = mid;
      low = mid + 1;
    } else high = mid - 1;
  }
  const bounded = { ...result, content: bestContent, linesReturned: bestCount };
  if (Buffer.byteLength(JSON.stringify(bounded), "utf8") > maxResultBytes)
    throw new SftpFileToolError("result is too large");
  return { result: bounded, truncated: true };
}

function renderLines(lines: readonly string[], count: number, trailingNewline: boolean): string {
  if (count <= 0) return "";
  const content = lines.slice(0, count).join("\n");
  return trailingNewline ? `${content}\n` : content;
}

function nonTextResult(
  path: string,
  encoding: "binary" | "unknown",
  reason: "invalid_utf8" | "too_large",
  sizeBytes: number,
): JsonValue {
  return {
    ok: false,
    path,
    content: "",
    encoding,
    binary: encoding === "binary",
    reason,
    truncated: reason === "too_large",
    eof: false,
    bytesRead: 0,
    sizeBytes,
  };
}
function binaryResult(path: string, reason: "invalid_utf8", sizeBytes: number): JsonValue {
  return nonTextResult(path, "binary", reason, sizeBytes);
}
function assertInsideRoots(guestPath: string, roots: readonly string[]): void {
  if (!roots.some((root) => guestPath === root || guestPath.startsWith(`${root}/`)))
    throw new SftpFileToolError("path is outside allowed roots");
}
function integer(value: number, min: number, max: number, label: string): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new SftpFileToolError(`invalid ${label}`);
  return value;
}
function normalizeOptions(options: SftpFileToolOptions): Config {
  return {
    manager: options.manager,
    maxReadBytes: integer(options.maxReadBytes ?? 1024 * 1024, 1, 16 * 1024 * 1024, "max read bytes"),
    maxWriteBytes: integer(options.maxWriteBytes ?? 1024 * 1024, 0, 16 * 1024 * 1024, "max write bytes"),
    maxPathBytes: integer(options.maxPathBytes ?? 4096, 1, 4096, "max path bytes"),
    maxResultBytes: integer(options.maxResultBytes ?? 16 * 1024, 1, 1024 * 1024, "max result bytes"),
    operationTimeoutMs: integer(options.operationTimeoutMs ?? 5000, 1, 60_000, "operation timeout"),
    idleTimeoutMs: integer(options.idleTimeoutMs ?? 5000, 1, 60_000, "idle timeout"),
    openTimeoutMs: integer(options.openTimeoutMs ?? 5000, 1, 60_000, "open timeout"),
    closeTimeoutMs: integer(options.closeTimeoutMs ?? 2000, 1, 60_000, "close timeout"),
  };
}
function withBounds(
  config: Config,
  signal: AbortSignal | undefined,
): { signal?: AbortSignal; openTimeoutMs: number; closeTimeoutMs: number; operationTimeoutMs: number } {
  return signal === undefined
    ? {
        openTimeoutMs: config.openTimeoutMs,
        closeTimeoutMs: config.closeTimeoutMs,
        operationTimeoutMs: config.operationTimeoutMs,
      }
    : {
        signal,
        openTimeoutMs: config.openTimeoutMs,
        closeTimeoutMs: config.closeTimeoutMs,
        operationTimeoutMs: config.operationTimeoutMs,
      };
}
function redactToolError(error: unknown): SftpFileToolError {
  try {
    if (error instanceof SftpFileToolError) return new SftpFileToolError(error.message);
  } catch {
    return new SftpFileToolError("sftp file operation failed");
  }
  try {
    if (error instanceof SshConnectionError) return new SftpFileToolError("ssh sftp operation failed");
  } catch {
    return new SftpFileToolError("sftp file operation failed");
  }
  const status = cogsSftpStatus(error);
  if (status === "no_such_file") return new SftpFileToolError("not found");
  if (status === "permission_denied") return new SftpFileToolError("permission denied");
  return new SftpFileToolError("sftp file operation failed");
}
function cogsSftpStatus(error: unknown): "eof" | "no_such_file" | "permission_denied" | "failure" | undefined {
  try {
    if (!(error instanceof CogsSftpStatusError)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, "status");
    if (descriptor === undefined || !("value" in descriptor)) return undefined;
    const value = descriptor.value;
    return value === "eof" || value === "no_such_file" || value === "permission_denied" || value === "failure"
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}
function linkedSignal(parent: AbortSignal): AbortController & { dispose: () => void } {
  const controller = new AbortController() as AbortController & { dispose: () => void };
  const abort = () => controller.abort();
  if (parent.aborted) abort();
  else parent.addEventListener("abort", abort, { once: true });
  controller.dispose = () => parent.removeEventListener("abort", abort);
  return controller;
}
