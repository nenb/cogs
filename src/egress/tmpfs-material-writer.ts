import type { Stats } from "node:fs";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rmdir, statfs, unlink } from "node:fs/promises";
import type { CogsEgressPkiMaterial } from "./egress-material.ts";
import type { CogsEnvoyRuntimeConfig } from "./envoy-runtime-config.ts";

const parentPath = "/run/cogs/egress";
const childPath = "/run/cogs/egress/envoy";
const tmpfsMagic = 0x01021994;
const modeDir = 0o700;
const modeFile = 0o600;
const maxBootstrapBytes = 1024 * 1024;
const maxPemBytes = 128 * 1024;

type MaterialPaths = Readonly<{
  bootstrap: string;
  proxyCertificate: string;
  proxyPrivateKey: string;
  proxyCaCertificate: string;
}>;

type StoredIdentity = Readonly<{ path: string; dev: bigint; ino: bigint }>;

type FilePort = Readonly<{
  write(data: Uint8Array): Promise<number>;
  sync(): Promise<void>;
  stat(): Promise<CogsEgressTmpfsStats>;
  close(): Promise<void>;
}>;

export type CogsEgressTmpfsStats = Readonly<{
  dev: bigint;
  ino: bigint;
  uid: number;
  mode: number;
  nlink: number;
  size: number;
  isDirectory: boolean;
  isFile: boolean;
  isSymbolicLink: boolean;
}>;

export type CogsEgressTmpfsStoragePort = Readonly<{
  realpath(path: string): Promise<string>;
  lstat(path: string): Promise<CogsEgressTmpfsStats>;
  statfs(path: string): Promise<{ type: number | bigint }>;
  mkdir(path: string, mode: number): Promise<void>;
  openFile(path: string, flags: number, mode: number): Promise<FilePort>;
  openDir(path: string, flags: number): Promise<FilePort>;
  unlink(path: string): Promise<void>;
  rmdir(path: string): Promise<void>;
}>;

export type CogsEgressTmpfsWriterOptions = Readonly<{ storage?: CogsEgressTmpfsStoragePort; euid?: number }>;

export class CogsEgressTmpfsError extends Error {
  public readonly code = "COGS_EGRESS_TMPFS_FAILED";
  public constructor() {
    super("egress tmpfs material unavailable");
    this.name = "CogsEgressTmpfsError";
  }
}

export async function withCogsEgressTmpfsMaterial<T>(
  config: CogsEnvoyRuntimeConfig,
  pki: CogsEgressPkiMaterial,
  operation: (paths: MaterialPaths) => Promise<T>,
  options: CogsEgressTmpfsWriterOptions = {},
): Promise<T> {
  const written: StoredIdentity[] = [];
  let childReady = false;
  let childIdentity: StoredIdentity | undefined;
  let cleanupAttempted = false;
  let storage: CogsEgressTmpfsStoragePort | undefined;
  try {
    const captured = Object.freeze({ storage: options.storage, euid: options.euid });
    storage = captured.storage ?? nodeTmpfsStorage;
    const euid = validEuid(captured.euid);
    const paths = validatePaths(config.paths);
    await verifyParent(storage, euid);
    await ensureMissing(storage, childPath);
    await storage.mkdir(childPath, modeDir);
    childReady = true;
    const child = await storage.lstat(childPath);
    verifyDirectory(child, euid, modeDir);
    childIdentity = { path: childPath, dev: child.dev, ino: child.ino };
    const files = [
      [paths.bootstrap, config.bootstrapJson, maxBootstrapBytes],
      [paths.proxyCertificate, pki.certificateChainPem, maxPemBytes],
      [paths.proxyPrivateKey, pki.privateKeyPem, maxPemBytes],
      [paths.proxyCaCertificate, pki.caCertificatePem, maxPemBytes],
    ] as const;
    for (const [path, content, maxBytes] of files) {
      await writeFile(storage, path, content, maxBytes, euid, (identity) => written.push(identity));
    }
    await syncDirectory(storage, childPath);
    let result: T;
    try {
      result = await operation(Object.freeze({ ...paths }));
    } finally {
      cleanupAttempted = true;
      await cleanup(storage, written, childIdentity);
    }
    return result;
  } catch {
    if (!cleanupAttempted && storage !== undefined)
      await cleanup(storage, written, childReady ? childIdentity : undefined).catch(() => undefined);
    throw new CogsEgressTmpfsError();
  }
}

async function verifyParent(storage: CogsEgressTmpfsStoragePort, euid: number): Promise<void> {
  if ((await storage.realpath(parentPath)) !== parentPath) throw new Error("bad parent");
  const stat = await storage.lstat(parentPath);
  verifyDirectory(stat, euid, modeDir);
  const fs = await storage.statfs(parentPath);
  if (BigInt(fs.type) !== BigInt(tmpfsMagic)) throw new Error("bad fs");
}

function verifyDirectory(stat: CogsEgressTmpfsStats, euid: number, mode: number): void {
  if (!stat.isDirectory || stat.isSymbolicLink || stat.uid !== euid || (stat.mode & 0o777) !== mode)
    throw new Error("bad dir");
}

async function writeFile(
  storage: CogsEgressTmpfsStoragePort,
  path: string,
  content: string,
  maxBytes: number,
  euid: number,
  onCreated: (identity: StoredIdentity) => void,
): Promise<void> {
  const data = bytes(content, maxBytes);
  let file: FilePort | undefined;
  let identity: StoredIdentity | undefined;
  try {
    file = await storage.openFile(path, fileFlags(), modeFile);
    const initial = await file.stat();
    verifyFile(initial, euid, 0);
    identity = { path, dev: initial.dev, ino: initial.ino };
    onCreated(identity);
    let offset = 0;
    while (offset < data.byteLength) {
      const wrote = await file.write(data.subarray(offset));
      if (!Number.isSafeInteger(wrote) || wrote < 1 || wrote > data.byteLength - offset) throw new Error("bad write");
      offset += wrote;
    }
    await file.sync();
    const stat = await file.stat();
    verifyFile(stat, euid, data.byteLength);
    if (identity.dev !== stat.dev || identity.ino !== stat.ino) throw new Error("file changed");
  } finally {
    data.fill(0);
    if (file !== undefined) await file.close();
  }
}

function verifyFile(stat: CogsEgressTmpfsStats, euid: number, size: number): void {
  if (
    !stat.isFile ||
    stat.isSymbolicLink ||
    stat.uid !== euid ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== modeFile ||
    stat.size !== size
  )
    throw new Error("bad file");
}

async function cleanup(
  storage: CogsEgressTmpfsStoragePort,
  written: readonly StoredIdentity[],
  child?: StoredIdentity,
): Promise<void> {
  let failed = false;
  for (const item of [...written].reverse()) {
    try {
      const stat = await storage.lstat(item.path);
      if (!stat.isFile || stat.isSymbolicLink || stat.nlink !== 1 || stat.dev !== item.dev || stat.ino !== item.ino)
        throw new Error("mismatch");
      await storage.unlink(item.path);
    } catch {
      failed = true;
    }
  }
  if (child !== undefined) {
    try {
      await syncDirectory(storage, child.path);
      const stat = await storage.lstat(child.path);
      if (!stat.isDirectory || stat.isSymbolicLink || stat.dev !== child.dev || stat.ino !== child.ino)
        throw new Error("mismatch");
      await storage.rmdir(child.path);
      await syncDirectory(storage, parentPath);
    } catch {
      failed = true;
    }
  }
  if (failed) throw new Error("cleanup failed");
}

async function syncDirectory(storage: CogsEgressTmpfsStoragePort, path: string): Promise<void> {
  const dir = await storage.openDir(path, dirFlags());
  try {
    await dir.sync();
  } finally {
    await dir.close();
  }
}

async function ensureMissing(storage: CogsEgressTmpfsStoragePort, path: string): Promise<void> {
  try {
    await storage.lstat(path);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
  throw new Error("exists");
}

function validatePaths(paths: CogsEnvoyRuntimeConfig["paths"]): MaterialPaths {
  if (
    paths.bootstrap !== `${childPath}/bootstrap.json` ||
    paths.proxyCertificate !== `${childPath}/proxy-cert.pem` ||
    paths.proxyPrivateKey !== `${childPath}/proxy-key.pem` ||
    paths.proxyCaCertificate !== `${childPath}/proxy-ca.pem`
  )
    throw new Error("bad paths");
  return Object.freeze({ ...paths });
}

function validEuid(value: number | undefined): number {
  const euid: unknown = value ?? process.geteuid?.();
  if (typeof euid !== "number" || !Number.isSafeInteger(euid) || euid < 0) throw new Error("bad euid");
  return euid;
}

function fileFlags(): number {
  const flags = [constants.O_CREAT, constants.O_EXCL, constants.O_NOFOLLOW, constants.O_WRONLY];
  if (flags.some((flag) => typeof flag !== "number")) throw new Error("bad flags");
  return flags.reduce((mask, flag) => mask | flag, 0);
}

function dirFlags(): number {
  const flags = [constants.O_RDONLY, constants.O_DIRECTORY, constants.O_NOFOLLOW];
  if (flags.some((flag) => typeof flag !== "number")) throw new Error("bad flags");
  return flags.reduce((mask, flag) => mask | flag, 0);
}

function bytes(value: string, maximum: number): Uint8Array {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) throw new Error("bad content");
  const byteLength = Buffer.byteLength(value, "utf8");
  if (byteLength < 1 || byteLength > maximum) throw new Error("bad content");
  const data = new TextEncoder().encode(value);
  if (data.byteLength !== byteLength || data.byteLength > maximum) throw new Error("bad content");
  return data;
}

function isNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function toStats(stat: Stats): CogsEgressTmpfsStats {
  return {
    dev: BigInt(stat.dev),
    ino: BigInt(stat.ino),
    uid: stat.uid,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    isDirectory: stat.isDirectory(),
    isFile: stat.isFile(),
    isSymbolicLink: stat.isSymbolicLink(),
  };
}

export const nodeTmpfsStorage: CogsEgressTmpfsStoragePort = Object.freeze({
  async realpath(path) {
    return realpath(path);
  },
  async lstat(path) {
    return toStats(await lstat(path));
  },
  async statfs(path) {
    const stat = await statfs(path);
    return { type: stat.type };
  },
  async mkdir(path, mode) {
    await mkdir(path, { mode, recursive: false });
  },
  async openFile(path, flags, mode) {
    const handle = await open(path, flags, mode);
    return fileHandle(handle);
  },
  async openDir(path, flags) {
    const handle = await open(path, flags);
    return fileHandle(handle);
  },
  async unlink(path) {
    await unlink(path);
  },
  async rmdir(path) {
    await rmdir(path);
  },
});

function fileHandle(handle: Awaited<ReturnType<typeof open>>): FilePort {
  return Object.freeze({
    async write(data) {
      const result = await handle.write(data, 0, data.byteLength);
      return result.bytesWritten;
    },
    async sync() {
      await handle.sync();
    },
    async stat() {
      return toStats(await handle.stat());
    },
    async close() {
      await handle.close();
    },
  });
}
