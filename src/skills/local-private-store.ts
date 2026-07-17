import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, opendir, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import posix from "node:path/posix";
import {
  buildCogsSkillBundle,
  COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES,
  COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES,
  COGS_SKILLS_BUNDLE_MAX_FILE_BYTES,
  COGS_SKILLS_BUNDLE_MAX_FILES,
  COGS_SKILLS_BUNDLE_MAX_PATH_BYTES,
  type CogsSkillBundleHandle,
  verifyCogsSkillBundle,
} from "./bundle.ts";

export interface CogsPrivateSkillStoreOptions {
  readonly sourceRoot: string;
  readonly storeRoot: string;
  readonly fs?: Partial<PrivateSkillStoreFs>;
}

export interface CogsPrivateSkillStoreSnapshotInput {
  readonly userId: string;
  readonly expectedDigest: `sha256:${string}`;
  readonly signal?: AbortSignal;
}

export interface CogsPrivateSkillStoreResolveInput {
  readonly userId: string;
  readonly digest: `sha256:${string}`;
  readonly signal?: AbortSignal;
}

export interface CogsPrivateSkillStoreResult {
  readonly scope: "user";
  readonly userNamespace: `sha256:${string}`;
  readonly digest: `sha256:${string}`;
  readonly byteLength: number;
  readonly decodedByteLength: number;
  readonly fileCount: number;
  readonly bundle: CogsSkillBundleHandle;
}

export interface CogsPrivateSkillStore {
  readonly snapshot: (input: CogsPrivateSkillStoreSnapshotInput) => Promise<CogsPrivateSkillStoreResult>;
  readonly resolve: (input: CogsPrivateSkillStoreResolveInput) => Promise<CogsPrivateSkillStoreResult>;
}

interface BigStats {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly size: bigint;
  readonly mode: bigint;
  readonly nlink: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
  readonly isDirectory: () => boolean;
  readonly isFile: () => boolean;
  readonly isSymbolicLink: () => boolean;
}

interface PrivateSkillStoreFileHandle {
  readonly stat: () => Promise<BigStats>;
  readonly read: (buffer: Buffer, offset: number, length: number, position: number) => Promise<{ bytesRead: number }>;
  readonly writeFile?: (bytes: Buffer) => Promise<void>;
  readonly sync: () => Promise<void>;
  readonly close: () => Promise<void>;
}

interface PrivateSkillStoreDir {
  readonly read: () => Promise<{ name: string } | null>;
  readonly close: () => Promise<void>;
}

interface PrivateSkillStoreFs {
  readonly realpath: (target: string) => Promise<string>;
  readonly lstat: (target: string) => Promise<BigStats>;
  readonly mkdir: (target: string, options: { recursive: boolean; mode: number }) => Promise<void>;
  readonly opendir: (target: string) => Promise<PrivateSkillStoreDir>;
  readonly open: (target: string, flags: number | string, mode?: number) => Promise<PrivateSkillStoreFileHandle>;
  readonly link: (existing: string, target: string) => Promise<void>;
  readonly unlink: (target: string) => Promise<void>;
}

export class CogsPrivateSkillStoreError extends Error {
  public readonly code = "COGS_PRIVATE_SKILL_STORE_INVALID";
  public constructor() {
    super("invalid private skill store");
    this.name = "CogsPrivateSkillStoreError";
  }
}

const MAX_DEPTH = 16;
const MAX_DIRS = 128;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const O_DIRECTORY = constants.O_DIRECTORY ?? 0;

const REAL_FS: PrivateSkillStoreFs = {
  realpath,
  lstat: (target) => lstat(target, { bigint: true }) as Promise<BigStats>,
  mkdir: async (target, options) => {
    await mkdir(target, options);
  },
  opendir: (target) => opendir(target) as Promise<PrivateSkillStoreDir>,
  open: async (target, flags, mode) => {
    const handle = await open(target, flags, mode);
    return {
      stat: () => handle.stat({ bigint: true }) as Promise<BigStats>,
      read: (buffer: Buffer, offset: number, length: number, position: number) =>
        handle.read(buffer, offset, length, position),
      writeFile: (bytes: Buffer) => handle.writeFile(bytes),
      sync: () => handle.sync(),
      close: () => handle.close(),
    };
  },
  link,
  unlink,
};

export async function createCogsPrivateSkillStore(
  options: CogsPrivateSkillStoreOptions,
): Promise<CogsPrivateSkillStore> {
  try {
    const snapshot = snapshotOptions(options);
    const fs = mergeFs(snapshot.fs);
    const sourceRoot = await validateRoot(fs, snapshot.sourceRoot);
    const storeRoot = await validateRoot(fs, snapshot.storeRoot);
    rejectOverlappingRoots(sourceRoot, storeRoot);
    const handle: CogsPrivateSkillStore = Object.freeze({
      snapshot: (input: CogsPrivateSkillStoreSnapshotInput) => snapshotUser(fs, sourceRoot, storeRoot, input),
      resolve: (input: CogsPrivateSkillStoreResolveInput) => resolveUser(fs, storeRoot, input),
    });
    return handle;
  } catch (error) {
    if (error instanceof CogsPrivateSkillStoreError) throw error;
    throw new CogsPrivateSkillStoreError();
  }
}

async function snapshotUser(
  fs: PrivateSkillStoreFs,
  sourceRoot: string,
  storeRoot: string,
  input: CogsPrivateSkillStoreSnapshotInput,
): Promise<CogsPrivateSkillStoreResult> {
  try {
    const snapshot = snapshotSnapshotInput(input);
    const userId = validateUserId(snapshot.userId);
    const expectedDigest = validateDigest(snapshot.expectedDigest);
    const signal = validateSignal(snapshot.signal);
    throwIfAborted(signal);
    const userNamespace = namespaceForUser(userId);
    const sourceDirectory = joinTrusted(sourceRoot, userNamespace.slice("sha256:".length));
    await verifyDirectory(fs, sourceDirectory, sourceRoot);
    const entries = await scanSource(fs, sourceDirectory, signal);
    const bundle = buildCogsSkillBundle({ entries });
    if (bundle.digest !== expectedDigest) throw new CogsPrivateSkillStoreError();
    await publishBundle(fs, storeRoot, userNamespace, bundle.copyBytes(), bundle.digest, signal);
    return freezeResult(userNamespace, bundle);
  } catch (error) {
    if (error instanceof CogsPrivateSkillStoreError) throw error;
    throw new CogsPrivateSkillStoreError();
  }
}

async function resolveUser(
  fs: PrivateSkillStoreFs,
  storeRoot: string,
  input: CogsPrivateSkillStoreResolveInput,
): Promise<CogsPrivateSkillStoreResult> {
  try {
    const snapshot = snapshotResolveInput(input);
    const userId = validateUserId(snapshot.userId);
    const digest = validateDigest(snapshot.digest);
    const signal = validateSignal(snapshot.signal);
    throwIfAborted(signal);
    const userNamespace = namespaceForUser(userId);
    const blob = blobPath(storeRoot, userNamespace, digest);
    const bytes = await readResolveBlob(fs, blob, storeRoot, signal);
    const bundle = verifyCogsSkillBundle(bytes);
    if (bundle.digest !== digest) throw new CogsPrivateSkillStoreError();
    return freezeResult(userNamespace, bundle);
  } catch (error) {
    if (error instanceof CogsPrivateSkillStoreError) throw error;
    throw new CogsPrivateSkillStoreError();
  }
}

async function scanSource(fs: PrivateSkillStoreFs, root: string, signal: AbortSignal | undefined) {
  const entries: { path: string; executable: boolean; content: Buffer }[] = [];
  let directoryCount = 0;
  let encounteredCount = 0;
  let totalRegularBytes = 0n;
  const scanDirectory = async (directory: string, relative: string, depth: number): Promise<void> => {
    throwIfAborted(signal);
    if (depth > MAX_DEPTH) throw new CogsPrivateSkillStoreError();
    directoryCount += 1;
    if (directoryCount > MAX_DIRS) throw new CogsPrivateSkillStoreError();
    const before = await stableDirectoryStats(fs, directory);
    const dir = await fs.opendir(directory);
    const names: string[] = [];
    let primaryError: unknown;
    try {
      for (;;) {
        throwIfAborted(signal);
        const dirent = await dir.read();
        if (dirent === null) break;
        encounteredCount += 1;
        if (encounteredCount > MAX_DIRS + COGS_SKILLS_BUNDLE_MAX_FILES) throw new CogsPrivateSkillStoreError();
        names.push(validatePathComponent(dirent.name));
      }
    } catch (error) {
      primaryError = error;
    }
    try {
      await dir.close();
    } catch (error) {
      if (primaryError === undefined && !isCode(error, "ERR_DIR_CLOSED")) throw new CogsPrivateSkillStoreError();
    }
    if (primaryError !== undefined) throw primaryError;
    names.sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
    for (const name of names) {
      throwIfAborted(signal);
      const childRelative = relative === "" ? name : posix.join(relative, name);
      validateBundleRelativePath(childRelative);
      const child = joinTrusted(directory, name);
      const stat = await fs.lstat(child);
      if (stat.isSymbolicLink()) throw new CogsPrivateSkillStoreError();
      if (stat.isDirectory()) await scanDirectory(child, childRelative, depth + 1);
      else if (stat.isFile()) {
        if (stat.nlink !== 1n) throw new CogsPrivateSkillStoreError();
        if (stat.size > BigInt(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES)) throw new CogsPrivateSkillStoreError();
        totalRegularBytes += stat.size;
        if (totalRegularBytes > BigInt(COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES)) throw new CogsPrivateSkillStoreError();
        const content = await readRegularFile(fs, child, directory, stat, signal, COGS_SKILLS_BUNDLE_MAX_FILE_BYTES);
        entries.push({ path: childRelative, executable: (Number(stat.mode) & 0o111) !== 0, content });
        if (entries.length > COGS_SKILLS_BUNDLE_MAX_FILES) throw new CogsPrivateSkillStoreError();
      } else throw new CogsPrivateSkillStoreError();
    }
    const after = await stableDirectoryStats(fs, directory);
    if (!sameStableStats(before, after, true)) throw new CogsPrivateSkillStoreError();
  };
  await scanDirectory(root, "", 0);
  return entries;
}

async function readResolveBlob(
  fs: PrivateSkillStoreFs,
  file: string,
  root: string,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  const stat = await fs.lstat(file);
  if ((Number(stat.mode) & 0o777) !== 0o600) throw new CogsPrivateSkillStoreError();
  return readRegularFile(fs, file, root, stat, signal, COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES);
}

async function readRegularFile(
  fs: PrivateSkillStoreFs,
  file: string,
  root: string,
  expected: BigStats | undefined,
  signal: AbortSignal | undefined,
  maxBytes: number,
): Promise<Buffer> {
  throwIfAborted(signal);
  assertContained(await fs.realpath(path.dirname(file)), root);
  const before = expected ?? (await fs.lstat(file));
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) throw new CogsPrivateSkillStoreError();
  if (before.size < 0n || before.size > BigInt(maxBytes)) throw new CogsPrivateSkillStoreError();
  const handle = await fs.open(file, constants.O_RDONLY | O_NOFOLLOW);
  let primaryError: unknown;
  let output: Buffer | undefined;
  try {
    const opened = await handle.stat();
    if (!sameStableStats(before, opened, false) || !opened.isFile() || opened.nlink !== 1n)
      throw new CogsPrivateSkillStoreError();
    const size = Number(opened.size);
    output = Buffer.alloc(size);
    let position = 0;
    while (position < size) {
      throwIfAborted(signal);
      const { bytesRead } = await handle.read(output, position, size - position, position);
      if (bytesRead <= 0) throw new CogsPrivateSkillStoreError();
      position += bytesRead;
    }
    const after = await handle.stat();
    if (!sameStableStats(opened, after, false)) throw new CogsPrivateSkillStoreError();
  } catch (error) {
    primaryError = error;
  }
  try {
    await handle.close();
  } catch {
    if (primaryError === undefined) throw new CogsPrivateSkillStoreError();
  }
  if (primaryError !== undefined) throw primaryError;
  if (output === undefined) throw new CogsPrivateSkillStoreError();
  return output;
}

async function publishBundle(
  fs: PrivateSkillStoreFs,
  storeRoot: string,
  userNamespace: `sha256:${string}`,
  bytes: Buffer,
  digest: `sha256:${string}`,
  signal: AbortSignal | undefined,
): Promise<void> {
  throwIfAborted(signal);
  const namespaceDirectory = joinTrusted(storeRoot, userNamespace.slice("sha256:".length));
  const blobsDirectory = joinTrusted(namespaceDirectory, "blobs");
  const shaDirectory = joinTrusted(blobsDirectory, "sha256");
  for (const directory of [namespaceDirectory, blobsDirectory, shaDirectory]) {
    try {
      await fs.mkdir(directory, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (!isCode(error, "EEXIST")) throw error;
    }
    await verifyDirectory(fs, directory, storeRoot);
  }
  const finalPath = blobPath(storeRoot, userNamespace, digest);
  const temp = joinTrusted(shaDirectory, `.tmp-${process.pid}-${randomBytes(18).toString("hex")}`);
  let cleanupTemp = true;
  let tempCreated = false;
  let handle: PrivateSkillStoreFileHandle | undefined;
  try {
    handle = await fs.open(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | O_NOFOLLOW, 0o600);
    tempCreated = true;
    if (handle.writeFile === undefined) throw new CogsPrivateSkillStoreError();
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await verifyTempBlob(fs, temp, shaDirectory, bytes, digest, signal);
    try {
      await fs.link(temp, finalPath);
    } catch (error) {
      if (!isCode(error, "EEXIST")) throw error;
      await waitForSingleLink(fs, finalPath);
      await verifyStoredBlob(fs, finalPath, storeRoot, bytes, digest, signal);
      await fs.unlink(temp);
      cleanupTemp = false;
      await syncDirectory(fs, shaDirectory);
      return;
    }
    const stat = await fs.lstat(finalPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== BigInt(bytes.length))
      throw new CogsPrivateSkillStoreError();
    await fs.unlink(temp);
    cleanupTemp = false;
    await waitForSingleLink(fs, finalPath);
    await verifyStoredBlob(fs, finalPath, storeRoot, bytes, digest, signal);
    await syncDirectory(fs, shaDirectory);
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        // Preserve primary failure; close failures before publish are fatal above when primary succeeds.
      }
    }
    if (cleanupTemp && tempCreated) await fs.unlink(temp);
  }
}

async function verifyStoredBlob(
  fs: PrivateSkillStoreFs,
  file: string,
  root: string,
  expectedBytes: Buffer,
  expectedDigest: `sha256:${string}`,
  signal: AbortSignal | undefined,
): Promise<void> {
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size !== BigInt(expectedBytes.length))
    throw new CogsPrivateSkillStoreError();
  if ((Number(stat.mode) & 0o777) !== 0o600) throw new CogsPrivateSkillStoreError();
  const bytes = await readRegularFile(fs, file, root, stat, signal, COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES);
  if (!bytes.equals(expectedBytes)) throw new CogsPrivateSkillStoreError();
  if (verifyCogsSkillBundle(bytes).digest !== expectedDigest) throw new CogsPrivateSkillStoreError();
}

async function verifyTempBlob(
  fs: PrivateSkillStoreFs,
  temp: string,
  root: string,
  expectedBytes: Buffer,
  expectedDigest: `sha256:${string}`,
  signal: AbortSignal | undefined,
): Promise<void> {
  const stat = await fs.lstat(temp);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size !== BigInt(expectedBytes.length))
    throw new CogsPrivateSkillStoreError();
  if ((Number(stat.mode) & 0o777) !== 0o600) throw new CogsPrivateSkillStoreError();
  const bytes = await readRegularFile(fs, temp, root, stat, signal, COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES);
  if (!bytes.equals(expectedBytes)) throw new CogsPrivateSkillStoreError();
  if (verifyCogsSkillBundle(bytes).digest !== expectedDigest) throw new CogsPrivateSkillStoreError();
}

async function waitForSingleLink(fs: PrivateSkillStoreFs, file: string): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new CogsPrivateSkillStoreError();
    if (stat.nlink === 1n) return;
    if (stat.nlink !== 2n) throw new CogsPrivateSkillStoreError();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const stat = await fs.lstat(file);
  if (stat.nlink !== 1n) throw new CogsPrivateSkillStoreError();
}

async function syncDirectory(fs: PrivateSkillStoreFs, directory: string): Promise<void> {
  const handle = await fs.open(directory, constants.O_RDONLY | O_DIRECTORY);
  let primaryError: unknown;
  try {
    await handle.sync();
  } catch (error) {
    primaryError = error;
  }
  try {
    await handle.close();
  } catch {
    if (primaryError === undefined) throw new CogsPrivateSkillStoreError();
  }
  if (primaryError !== undefined) throw primaryError;
}

function freezeResult(userNamespace: `sha256:${string}`, bundle: CogsSkillBundleHandle): CogsPrivateSkillStoreResult {
  return Object.freeze({
    scope: "user" as const,
    userNamespace,
    digest: bundle.digest,
    byteLength: bundle.byteLength,
    decodedByteLength: bundle.decodedByteLength,
    fileCount: bundle.fileCount,
    bundle,
  });
}

function rejectOverlappingRoots(sourceRoot: string, storeRoot: string): void {
  const sourceToStore = path.relative(sourceRoot, storeRoot);
  const storeToSource = path.relative(storeRoot, sourceRoot);
  if (sourceToStore === "" || storeToSource === "") throw new CogsPrivateSkillStoreError();
  if (!sourceToStore.startsWith("..") && !path.isAbsolute(sourceToStore)) throw new CogsPrivateSkillStoreError();
  if (!storeToSource.startsWith("..") && !path.isAbsolute(storeToSource)) throw new CogsPrivateSkillStoreError();
}

async function validateRoot(fs: PrivateSkillStoreFs, value: string): Promise<string> {
  if (!path.isAbsolute(value)) throw new CogsPrivateSkillStoreError();
  const resolved = await fs.realpath(value);
  if (!path.isAbsolute(resolved)) throw new CogsPrivateSkillStoreError();
  await verifyDirectory(fs, resolved, resolved);
  return resolved;
}

async function verifyDirectory(fs: PrivateSkillStoreFs, directory: string, root: string): Promise<void> {
  assertContained(await fs.realpath(directory), root);
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new CogsPrivateSkillStoreError();
}

async function stableDirectoryStats(fs: PrivateSkillStoreFs, directory: string): Promise<BigStats> {
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new CogsPrivateSkillStoreError();
  return stat;
}

function sameStableStats(left: BigStats, right: BigStats, directory: boolean): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    (directory || left.size === right.size) &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function blobPath(storeRoot: string, userNamespace: `sha256:${string}`, digest: `sha256:${string}`): string {
  return joinTrusted(
    storeRoot,
    userNamespace.slice("sha256:".length),
    "blobs",
    "sha256",
    digest.slice("sha256:".length),
  );
}

function namespaceForUser(userId: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(userId, "utf8").digest("hex")}`;
}

function validateUserId(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) throw new CogsPrivateSkillStoreError();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)) throw new CogsPrivateSkillStoreError();
  return value;
}

function validateDigest(value: unknown): `sha256:${string}` {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw new CogsPrivateSkillStoreError();
  return value as `sha256:${string}`;
}

function validateSignal(value: unknown): AbortSignal | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof AbortSignal)) throw new CogsPrivateSkillStoreError();
  return value;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CogsPrivateSkillStoreError();
}

function validatePathComponent(value: string): string {
  if (value.length === 0 || value !== value.normalize("NFC")) throw new CogsPrivateSkillStoreError();
  const bytes = Buffer.from(value, "utf8");
  if (bytes.toString("utf8") !== value || bytes.length === 0 || bytes.length > COGS_SKILLS_BUNDLE_MAX_PATH_BYTES)
    throw new CogsPrivateSkillStoreError();
  if (value === "." || value === ".." || value.includes("/") || value.includes("\\"))
    throw new CogsPrivateSkillStoreError();
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code < 0x20 || code === 0x7f) throw new CogsPrivateSkillStoreError();
  }
  return value;
}

function validateBundleRelativePath(value: string): void {
  if (Buffer.byteLength(value, "utf8") > COGS_SKILLS_BUNDLE_MAX_PATH_BYTES) throw new CogsPrivateSkillStoreError();
}

function joinTrusted(root: string, ...segments: string[]): string {
  return path.join(root, ...segments);
}

function assertContained(target: string, root: string): void {
  const relative = path.relative(root, target);
  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) return;
  throw new CogsPrivateSkillStoreError();
}

function isCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

function snapshotSnapshotInput(value: unknown): { userId: unknown; expectedDigest: unknown; signal: unknown } {
  const snapshot = snapshotOptionalObject(value, ["userId", "expectedDigest"], ["signal"]);
  return { userId: snapshot.userId, expectedDigest: snapshot.expectedDigest, signal: snapshot.signal };
}

function snapshotResolveInput(value: unknown): { userId: unknown; digest: unknown; signal: unknown } {
  const snapshot = snapshotOptionalObject(value, ["userId", "digest"], ["signal"]);
  return { userId: snapshot.userId, digest: snapshot.digest, signal: snapshot.signal };
}

function snapshotOptions(value: unknown): { sourceRoot: string; storeRoot: string; fs?: Partial<PrivateSkillStoreFs> } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsPrivateSkillStoreError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsPrivateSkillStoreError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (!names.every((name) => typeof name === "string")) throw new CogsPrivateSkillStoreError();
  if (!names.every((name) => name === "sourceRoot" || name === "storeRoot" || name === "fs"))
    throw new CogsPrivateSkillStoreError();
  const sourceRoot = dataDescriptorValue(descriptors.sourceRoot);
  const storeRoot = dataDescriptorValue(descriptors.storeRoot);
  const fs = descriptors.fs === undefined ? undefined : dataDescriptorValue(descriptors.fs);
  if (typeof sourceRoot !== "string" || typeof storeRoot !== "string") throw new CogsPrivateSkillStoreError();
  return { sourceRoot, storeRoot, ...(fs === undefined ? {} : { fs: snapshotFs(fs) }) };
}

function dataDescriptorValue(descriptor: PropertyDescriptor | undefined): unknown {
  if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
    throw new CogsPrivateSkillStoreError();
  return descriptor.value;
}

function snapshotFs(value: unknown): Partial<PrivateSkillStoreFs> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsPrivateSkillStoreError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsPrivateSkillStoreError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  const allowed: readonly (keyof PrivateSkillStoreFs)[] = [
    "realpath",
    "lstat",
    "mkdir",
    "opendir",
    "open",
    "link",
    "unlink",
  ];
  if (!names.every((name) => typeof name === "string" && allowed.includes(name as keyof PrivateSkillStoreFs)))
    throw new CogsPrivateSkillStoreError();
  const snapshot: Partial<PrivateSkillStoreFs> = {};
  for (const name of names) {
    if (typeof name !== "string") throw new CogsPrivateSkillStoreError();
    const descriptor = descriptors[name];
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
      throw new CogsPrivateSkillStoreError();
    if (typeof descriptor.value !== "function") throw new CogsPrivateSkillStoreError();
    (snapshot as Record<string, unknown>)[name] = descriptor.value;
  }
  return snapshot;
}

function mergeFs(overrides: Partial<PrivateSkillStoreFs> | undefined): PrivateSkillStoreFs {
  if (overrides === undefined) return REAL_FS;
  const merged = { ...REAL_FS };
  for (const key of Object.keys(overrides) as (keyof PrivateSkillStoreFs)[]) {
    const value = overrides[key];
    if (value !== undefined) (merged as Record<keyof PrivateSkillStoreFs, unknown>)[key] = value;
  }
  return merged;
}

function snapshotOptionalObject(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsPrivateSkillStoreError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsPrivateSkillStoreError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  const allowed = [...requiredKeys, ...optionalKeys];
  if (!names.every((name) => typeof name === "string" && allowed.includes(name)))
    throw new CogsPrivateSkillStoreError();
  const snapshot: Record<string, unknown> = {};
  for (const key of requiredKeys) snapshot[key] = dataDescriptorValue(descriptors[key]);
  for (const key of optionalKeys) {
    const descriptor = descriptors[key];
    if (descriptor !== undefined) snapshot[key] = dataDescriptorValue(descriptor);
  }
  return snapshot;
}
