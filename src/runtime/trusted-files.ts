import { constants } from "node:fs";
import { type FileHandle, lstat, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve, sep } from "node:path";
import { types } from "node:util";

export type TrustedFileCaptureOptions = Readonly<{
  path: string;
  minimumBytes: number;
  maximumBytes: number;
  allowedModes: readonly number[];
  allowedUids: readonly number[];
  allowedGids: readonly number[];
}>;

export type TrustedFileIdentity = Readonly<{
  device: bigint;
  inode: bigint;
  uid: number;
  gid: number;
  mode: number;
  size: number;
}>;

export class TrustedFileError extends Error {
  public readonly code = "COGS_TRUSTED_FILE_INVALID";
  public constructor() {
    super("trusted file unavailable");
    this.name = "TrustedFileError";
  }
}

type BigStat = Awaited<ReturnType<FileHandle["stat"]>> & {
  dev: bigint;
  ino: bigint;
  uid: bigint;
  gid: bigint;
  mode: bigint;
  nlink: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
};

type CapturedOptions = Readonly<{
  path: string;
  minimumBytes: number;
  maximumBytes: number;
  allowedModes: ReadonlySet<number>;
  allowedUids: ReadonlySet<number>;
  allowedGids: ReadonlySet<number>;
}>;

type HeldDirectory = Readonly<{ path: string; handle: FileHandle; identity: BigStat }>;

export async function withTrustedFileBytes<T>(
  options: TrustedFileCaptureOptions,
  operation: (bytes: Buffer, identity: TrustedFileIdentity) => Promise<T>,
): Promise<T> {
  const held: HeldDirectory[] = [];
  let file: FileHandle | undefined;
  let bytes: Buffer | undefined;
  try {
    const captured = captureOptions(options);
    if (typeof operation !== "function") throw new Error("invalid operation");
    requireFlags();
    for (const path of parentPaths(captured.path)) held.push(await holdDirectory(path));
    if ((await realpath(captured.path)) !== captured.path) throw new Error("noncanonical file");
    const beforePath = await statPath(captured.path);
    validateFile(beforePath, captured);
    file = await open(captured.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = (await file.stat({ bigint: true })) as BigStat;
    validateFile(opened, captured);
    sameGeneration(beforePath, opened);
    bytes = await readExact(file, opened.size, captured.maximumBytes);
    const afterOpen = (await file.stat({ bigint: true })) as BigStat;
    const afterPath = await statPath(captured.path);
    validateFile(afterOpen, captured);
    validateFile(afterPath, captured);
    sameGeneration(opened, afterOpen);
    sameGeneration(opened, afterPath);
    await verifyHeldDirectories(held);
    if ((await realpath(captured.path)) !== captured.path) throw new Error("file moved");
    const identity = freezeIdentity(opened);
    await closeAll(file, held);
    file = undefined;
    held.length = 0;
    return await operation(bytes, identity);
  } catch {
    throw new TrustedFileError();
  } finally {
    bytes?.fill(0);
    await file?.close().catch(() => undefined);
    for (const directory of held.reverse()) await directory.handle.close().catch(() => undefined);
  }
}

function captureOptions(options: TrustedFileCaptureOptions): CapturedOptions {
  if (types.isProxy(options) || !plain(options)) throw new Error("invalid options");
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const expected = ["allowedGids", "allowedModes", "allowedUids", "maximumBytes", "minimumBytes", "path"];
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") ||
    Object.keys(descriptors).sort().join() !== expected.join()
  )
    throw new Error("invalid options");
  for (const descriptor of Object.values(descriptors)) {
    if (!descriptor.enumerable || !("value" in descriptor)) throw new Error("invalid options");
  }
  const path = data<string>(descriptors, "path");
  if (
    typeof path !== "string" ||
    path.length < 2 ||
    path.length > 4096 ||
    path.includes("\0") ||
    !isAbsolute(path) ||
    resolve(path) !== path ||
    path === sep
  )
    throw new Error("invalid path");
  const minimumBytes = boundedInteger(data(descriptors, "minimumBytes"), 1, 1024 * 1024);
  const maximumBytes = boundedInteger(data(descriptors, "maximumBytes"), minimumBytes, 1024 * 1024);
  return Object.freeze({
    path,
    minimumBytes,
    maximumBytes,
    allowedModes: boundedSet(data(descriptors, "allowedModes"), 0, 0o777),
    allowedUids: boundedSet(data(descriptors, "allowedUids"), 0, 2 ** 32 - 2),
    allowedGids: boundedSet(data(descriptors, "allowedGids"), 0, 2 ** 32 - 2),
  });
}

function requireFlags(): void {
  if (constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined) throw new Error("flags unavailable");
}

function parentPaths(path: string): string[] {
  const result: string[] = [];
  let current = dirname(path);
  while (current !== sep) {
    result.push(current);
    current = dirname(current);
  }
  result.push(sep);
  return result.reverse();
}

async function holdDirectory(path: string): Promise<HeldDirectory> {
  const before = await statPath(path);
  if (!before.isDirectory() || before.isSymbolicLink()) throw new Error("invalid parent");
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const opened = (await handle.stat({ bigint: true })) as BigStat;
    if (!opened.isDirectory() || opened.isSymbolicLink()) throw new Error("invalid parent");
    sameGeneration(before, opened);
    return Object.freeze({ path, handle, identity: opened });
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function verifyHeldDirectories(held: readonly HeldDirectory[]): Promise<void> {
  for (const directory of held) {
    const descriptor = (await directory.handle.stat({ bigint: true })) as BigStat;
    const path = await statPath(directory.path);
    if (!descriptor.isDirectory() || !path.isDirectory() || descriptor.isSymbolicLink() || path.isSymbolicLink())
      throw new Error("invalid parent");
    sameGeneration(directory.identity, descriptor);
    sameGeneration(directory.identity, path);
  }
}

async function statPath(path: string): Promise<BigStat> {
  return (await lstat(path, { bigint: true })) as BigStat;
}

function validateFile(stat: BigStat, options: CapturedOptions): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) throw new Error("invalid file");
  const uid = safeBigInt(stat.uid, 0, 2 ** 32 - 2);
  const gid = safeBigInt(stat.gid, 0, 2 ** 32 - 2);
  const mode = Number(stat.mode & 0o777n);
  const size = safeBigInt(stat.size, options.minimumBytes, options.maximumBytes);
  if (!options.allowedUids.has(uid) || !options.allowedGids.has(gid) || !options.allowedModes.has(mode))
    throw new Error("invalid authority");
  if (size < options.minimumBytes || size > options.maximumBytes) throw new Error("invalid size");
}

async function readExact(file: FileHandle, rawSize: bigint, maximumBytes: number): Promise<Buffer> {
  const size = safeBigInt(rawSize, 1, maximumBytes);
  const result = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const read = await file.read(result, offset, size - offset, offset);
    if (!Number.isSafeInteger(read.bytesRead) || read.bytesRead < 1 || read.bytesRead > size - offset)
      throw new Error("short read");
    offset += read.bytesRead;
  }
  const extra = Buffer.alloc(1);
  try {
    const read = await file.read(extra, 0, 1, size);
    if (read.bytesRead !== 0) throw new Error("file grew");
  } finally {
    extra.fill(0);
  }
  return result;
}

async function closeAll(file: FileHandle, held: readonly HeldDirectory[]): Promise<void> {
  let failed = false;
  try {
    await file.close();
  } catch {
    failed = true;
  }
  for (const directory of [...held].reverse()) {
    try {
      await directory.handle.close();
    } catch {
      failed = true;
    }
  }
  if (failed) throw new Error("descriptor close failed");
}

function sameGeneration(expected: BigStat, actual: BigStat): void {
  if (
    expected.dev !== actual.dev ||
    expected.ino !== actual.ino ||
    expected.uid !== actual.uid ||
    expected.gid !== actual.gid ||
    expected.mode !== actual.mode ||
    expected.nlink !== actual.nlink ||
    expected.size !== actual.size ||
    expected.mtimeNs !== actual.mtimeNs ||
    expected.ctimeNs !== actual.ctimeNs
  )
    throw new Error("generation changed");
}

function freezeIdentity(stat: BigStat): TrustedFileIdentity {
  return Object.freeze({
    device: stat.dev,
    inode: stat.ino,
    uid: safeBigInt(stat.uid, 0, 2 ** 32 - 2),
    gid: safeBigInt(stat.gid, 0, 2 ** 32 - 2),
    mode: Number(stat.mode & 0o777n),
    size: safeBigInt(stat.size, 1, 1024 * 1024),
  });
}

function boundedSet(value: unknown, minimum: number, maximum: number): ReadonlySet<number> {
  if (
    types.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < 1 ||
    value.length > 8
  )
    throw new Error("invalid set");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== value.length + 1) throw new Error("invalid set");
  const result = new Set<number>();
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("invalid set");
    result.add(boundedInteger(descriptor.value, minimum, maximum));
  }
  if (result.size !== value.length) throw new Error("invalid set");
  return result;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error("invalid integer");
  return value;
}

function safeBigInt(value: bigint, minimum: number, maximum: number): number {
  if (value < BigInt(minimum) || value > BigInt(maximum)) throw new Error("invalid integer");
  return Number(value);
}

function data<T>(descriptors: PropertyDescriptorMap, key: string): T {
  const descriptor = descriptors[key];
  if (descriptor === undefined || !("value" in descriptor)) throw new Error("invalid options");
  return descriptor.value as T;
}

function plain(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
