import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open, readdir, realpath, statfs, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { LauncherAuthority, LauncherProfile } from "./contract.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";

export const TRUSTED_SSH_RUNTIME_ROOT = "/run/cogs/ssh";
export const TRUSTED_EGRESS_RUNTIME_ROOT = "/run/cogs/egress";

export type TrustedSshControls = Readonly<{
  endpoint: string;
  username: "root";
  hostKeySha256: string;
  clientKeyPath: string;
  close(): Promise<void>;
}>;

type FileStat = Pick<
  Stats,
  | "dev"
  | "ino"
  | "mode"
  | "nlink"
  | "size"
  | "uid"
  | "mtimeMs"
  | "ctimeMs"
  | "isFile"
  | "isDirectory"
  | "isSymbolicLink"
>;

type FilePort = Readonly<{
  stat(): Promise<FileStat>;
  read(buffer: Buffer, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
  writeFile(bytes: Buffer): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}>;

type ControlFs = Readonly<{
  lstat(path: string): Promise<FileStat>;
  realpath(path: string): Promise<string>;
  readdir(path: string): Promise<string[]>;
  statfs(path: string): Promise<{ type: number | bigint }>;
  open(path: string, flags: number, mode?: number): Promise<FilePort>;
  unlink(path: string): Promise<void>;
}>;

export type TrustedControlSeams = Readonly<{
  platform: NodeJS.Platform;
  uid: number;
  fs: ControlFs;
  after?: (stage: string) => void | Promise<void>;
}>;

const TMPFS_MAGIC = 0x0102_1994;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const MAX_CONTROL_BYTES = 64 * 1024;
const DEFAULT_FS: ControlFs = Object.freeze({
  lstat: (path) => lstat(path),
  realpath,
  readdir,
  statfs: (path) => statfs(path),
  open: async (path, flags, mode) => {
    const handle = await open(path, flags, mode);
    return Object.freeze({
      stat: () => handle.stat(),
      read: (buffer, offset, length, position) => handle.read(buffer, offset, length, position),
      writeFile: (bytes: Buffer) => handle.writeFile(bytes),
      sync: () => handle.sync(),
      close: () => handle.close(),
    });
  },
  unlink,
});

export async function preflightTrustedEgressRoot(signal?: AbortSignal, seams?: TrustedControlSeams): Promise<void> {
  try {
    validateOptionalSignal(signal);
    const trusted = captureSeams(seams);
    await validateEmptyTmpfs(TRUSTED_EGRESS_RUNTIME_ROOT, trusted, signal);
  } catch {
    throw failure();
  }
}

export async function materializeTrustedSshControls(
  state: LauncherState,
  profile: LauncherProfile,
  authority: LauncherAuthority,
  signal?: AbortSignal,
  seams?: TrustedControlSeams,
): Promise<TrustedSshControls> {
  validateOptionalSignal(signal);
  const trusted = captureSeams(seams);
  let source: FilePort | undefined;
  let destination: FilePort | undefined;
  let sourceBytes: Buffer | undefined;
  let reread: Buffer | undefined;
  let destinationPath = "";
  let destinationIdentity: Pick<FileStat, "dev" | "ino"> | undefined;
  let destinationCreated = false;
  let closePromise: Promise<void> | undefined;
  try {
    await validateEmptyTmpfs(TRUSTED_SSH_RUNTIME_ROOT, trusted, signal);
    await trusted.after?.("after-preflight");
    throwIfAborted(signal);

    const manifest = await readManifest(state);
    throwIfAborted(signal);
    if (
      manifest.phase !== "sandbox-ready" ||
      manifest.sourceRevision !== state.sourceRevision ||
      manifest.profile !== profile ||
      authority !== authorityFor(profile) ||
      profile === "macos-vm"
    )
      fail();

    await validateSourceDirectories(state, profile, trusted, signal);
    await validateDriverSentinel(state, profile, trusted, signal);
    const sourceValues = await readProfileControls(state, profile, trusted, signal);
    const sourcePath = join(state.driverStateDir, "control", "client_ed25519_key");
    const sourceBefore = await strictFileStat(sourcePath, 0o600, trusted);
    source = await trusted.fs.open(sourcePath, constants.O_RDONLY | O_NOFOLLOW);
    const sourceOpened = await source.stat();
    requireSameFile(sourceBefore, sourceOpened, 0o600, trusted.uid);
    if (sourceOpened.size < 1 || sourceOpened.size > MAX_CONTROL_BYTES) fail();
    sourceBytes = await readSensitiveExact(source, sourceOpened.size);
    await trusted.after?.("after-source-read");
    throwIfAborted(signal);
    requireStable(sourceOpened, await source.stat());

    destinationPath = `${TRUSTED_SSH_RUNTIME_ROOT}/launcher-${state.stateId}`;
    destination = await trusted.fs.open(
      destinationPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | O_NOFOLLOW,
      0o600,
    );
    destinationCreated = true;
    const destinationOpened = await destination.stat();
    requireSameFile(destinationOpened, destinationOpened, 0o600, trusted.uid);
    if (destinationOpened.size !== 0) fail();
    destinationIdentity = { dev: destinationOpened.dev, ino: destinationOpened.ino };
    await trusted.after?.("after-destination-open");
    throwIfAborted(signal);
    await destination.writeFile(sourceBytes);
    await destination.sync();
    await syncDirectory(TRUSTED_SSH_RUNTIME_ROOT, trusted);
    reread = await readSensitiveExact(destination, sourceBytes.length);
    if (!reread.equals(sourceBytes)) fail();
    const destinationAfter = await destination.stat();
    if (destinationAfter.size !== sourceBytes.length) fail();
    requireSameIdentity(destinationOpened, destinationAfter, 0o600, trusted.uid);
    const destinationPathAfter = await strictFileStat(destinationPath, 0o600, trusted);
    if (destinationPathAfter.size !== sourceBytes.length) fail();
    requireSameIdentity(destinationOpened, destinationPathAfter, 0o600, trusted.uid);
    requireStable(sourceOpened, await source.stat());
    requireStable(sourceOpened, await strictFileStat(sourcePath, 0o600, trusted));
    const sourceAgain = await readSensitiveExact(source, sourceOpened.size);
    try {
      if (!sourceAgain.equals(sourceBytes)) fail();
    } finally {
      sourceAgain.fill(0);
    }
    await trusted.after?.("after-materialize");
    throwIfAborted(signal);
    await source.close();
    source = undefined;
    await destination.close();
    destination = undefined;
    const destinationClosed = await strictFileStat(destinationPath, 0o600, trusted);
    if (destinationClosed.size !== sourceBytes.length) fail();
    requireSameIdentity(destinationOpened, destinationClosed, 0o600, trusted.uid);
    sourceBytes.fill(0);
    sourceBytes = undefined;
    reread.fill(0);
    reread = undefined;

    const identity = destinationIdentity;
    if (identity === undefined) fail();
    await requireOnlyRuntimeKey(destinationPath, identity, trusted);
    const close = Object.freeze(() => {
      closePromise ??= cleanupRuntimeKey(destinationPath, identity, trusted);
      return closePromise;
    });
    return Object.freeze(
      defineHidden({
        endpoint: sourceValues.endpoint,
        username: "root" as const,
        hostKeySha256: sourceValues.hostKeySha256,
        clientKeyPath: destinationPath,
        close,
      }),
    );
  } catch {
    sourceBytes?.fill(0);
    reread?.fill(0);
    await source?.close().catch(() => undefined);
    await destination?.close().catch(() => undefined);
    if (destinationCreated && destinationIdentity !== undefined) {
      await cleanupRuntimeKey(destinationPath, destinationIdentity, trusted).catch(() => undefined);
    }
    throw failure();
  }
}

async function readProfileControls(
  state: LauncherState,
  profile: Exclude<LauncherProfile, "macos-vm">,
  seams: TrustedControlSeams,
  signal: AbortSignal | undefined,
): Promise<{ endpoint: string; hostKeySha256: string }> {
  let endpoint: string;
  let hostToken: string;
  if (profile === "insecure-container") {
    const portText = await readStrictText(join(state.driverStateDir, "port"), 0o600, 16, seams, signal);
    if (!/^(?:[1-9][0-9]{0,4})\n$/.test(portText)) fail();
    const port = Number(portText.trim());
    if (!Number.isSafeInteger(port) || port > 65535) fail();
    endpoint = `127.0.0.1:${port}`;
    hostToken = `[127.0.0.1]:${port}`;
  } else {
    endpoint = "192.0.2.2:22";
    hostToken = "192.0.2.2";
  }
  const knownHosts = await readStrictText(join(state.driverStateDir, "known_hosts"), 0o600, 4096, seams, signal);
  const match = knownHosts.match(/^([^\s]+) ssh-ed25519 ([A-Za-z0-9+/]+={0,2})\n$/);
  if (match?.[1] !== hostToken || match[2] === undefined) fail();
  const encoded = match[2];
  const decoded = Buffer.from(encoded, "base64");
  try {
    if (decoded.length !== 51 || decoded.toString("base64") !== encoded) fail();
    if (
      decoded.readUInt32BE(0) !== 11 ||
      decoded.subarray(4, 15).toString("ascii") !== "ssh-ed25519" ||
      decoded.readUInt32BE(15) !== 32 ||
      decoded.subarray(19).every((byte) => byte === 0)
    )
      fail();
    const digest = createHash("sha256").update(decoded).digest("base64").replace(/=+$/u, "");
    if (!/^[A-Za-z0-9+/]{43}$/.test(digest)) fail();
    return { endpoint, hostKeySha256: `SHA256:${digest}` };
  } finally {
    decoded.fill(0);
  }
}

async function validateDriverSentinel(
  state: LauncherState,
  profile: Exclude<LauncherProfile, "macos-vm">,
  seams: TrustedControlSeams,
  signal: AbortSignal | undefined,
): Promise<void> {
  const sentinel =
    profile === "insecure-container"
      ? join(state.driverStateDir, ".cogs-insecure-owner")
      : join(state.driverStateDir, ".cogs-linux-kvm-v1");
  const expected = profile === "insecure-container" ? `${driverStateId(state.driverStateDir)}\n` : "";
  const bytes = await readStrictBytes(sentinel, 0o600, 128, seams, signal, false);
  try {
    if (bytes.toString("utf8") !== expected) fail();
  } finally {
    bytes.fill(0);
  }
}

async function validateSourceDirectories(
  state: LauncherState,
  profile: Exclude<LauncherProfile, "macos-vm">,
  seams: TrustedControlSeams,
  signal: AbortSignal | undefined,
): Promise<void> {
  for (const path of [dirname(state.driverStateDir), state.driverStateDir, join(state.driverStateDir, "control")]) {
    await strictDirectory(path, 0o700, seams);
    throwIfAborted(signal);
  }
  const expected =
    profile === "insecure-container"
      ? ["client_ed25519_key", "client_ed25519_key.pub"]
      : ["client_ed25519_key", "client_ed25519_key.pub", "host_ed25519_key", "host_ed25519_key.pub"];
  const entries = (await seams.fs.readdir(join(state.driverStateDir, "control"))).sort();
  if (entries.join("\0") !== expected.sort().join("\0")) fail();
}

async function validateEmptyTmpfs(
  root: string,
  seams: TrustedControlSeams,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (seams.platform !== "linux") fail();
  await strictDirectory(root, 0o700, seams);
  throwIfAborted(signal);
  const filesystem = await seams.fs.statfs(root);
  const type = typeof filesystem.type === "bigint" ? filesystem.type : BigInt(filesystem.type);
  if (type !== BigInt(TMPFS_MAGIC)) fail();
  if ((await seams.fs.readdir(root)).length !== 0) fail();
  await strictDirectory(root, 0o700, seams);
  throwIfAborted(signal);
}

async function readStrictText(
  path: string,
  mode: number,
  maximum: number,
  seams: TrustedControlSeams,
  signal: AbortSignal | undefined,
): Promise<string> {
  const bytes = await readStrictBytes(path, mode, maximum, seams, signal, false);
  try {
    if (bytes.length < 1) fail();
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function readStrictBytes(
  path: string,
  mode: number,
  maximum: number,
  seams: TrustedControlSeams,
  signal: AbortSignal | undefined,
  sensitive: boolean,
): Promise<Buffer> {
  const before = await strictFileStat(path, mode, seams);
  if (before.size < 0 || before.size > maximum) fail();
  const handle = await seams.fs.open(path, constants.O_RDONLY | O_NOFOLLOW);
  let bytes: Buffer | undefined;
  try {
    const opened = await handle.stat();
    requireSameFile(before, opened, mode, seams.uid);
    bytes = sensitive ? await readSensitiveExact(handle, opened.size) : await readExact(handle, opened.size);
    await seams.after?.("after-control-read");
    throwIfAborted(signal);
    const after = await handle.stat();
    requireStable(opened, after);
    const pathAfter = await strictFileStat(path, mode, seams);
    requireSameFile(opened, pathAfter, mode, seams.uid);
    const output = bytes;
    bytes = undefined;
    return output;
  } finally {
    bytes?.fill(0);
    await handle.close();
  }
}

async function readExact(handle: FilePort, size: number): Promise<Buffer> {
  return readBuffered(handle, size, false);
}

async function readSensitiveExact(handle: FilePort, size: number): Promise<Buffer> {
  return readBuffered(handle, size, true);
}

async function readBuffered(handle: FilePort, size: number, sensitive: boolean): Promise<Buffer> {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_CONTROL_BYTES) fail();
  const output = Buffer.alloc(size);
  try {
    let position = 0;
    while (position < size) {
      const result = await handle.read(output, position, size - position, position);
      if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead <= 0 || result.bytesRead > size - position)
        fail();
      position += result.bytesRead;
    }
    return output;
  } catch (error) {
    if (sensitive) output.fill(0);
    throw error;
  }
}

async function cleanupRuntimeKey(
  path: string,
  identity: Pick<FileStat, "dev" | "ino">,
  seams: TrustedControlSeams,
): Promise<void> {
  try {
    await requireOnlyRuntimeKey(path, identity, seams);
    await seams.fs.unlink(path);
    await syncDirectory(TRUSTED_SSH_RUNTIME_ROOT, seams);
    if ((await seams.fs.readdir(TRUSTED_SSH_RUNTIME_ROOT)).length !== 0) fail();
    await strictDirectory(TRUSTED_SSH_RUNTIME_ROOT, 0o700, seams);
  } catch {
    throw failure();
  }
}

async function requireOnlyRuntimeKey(
  path: string,
  identity: Pick<FileStat, "dev" | "ino">,
  seams: TrustedControlSeams,
): Promise<void> {
  await strictDirectory(TRUSTED_SSH_RUNTIME_ROOT, 0o700, seams);
  const entries = await seams.fs.readdir(TRUSTED_SSH_RUNTIME_ROOT);
  if (entries.length !== 1 || `${TRUSTED_SSH_RUNTIME_ROOT}/${entries[0]}` !== path) fail();
  const current = await strictFileStat(path, 0o600, seams);
  if (current.dev !== identity.dev || current.ino !== identity.ino) fail();
}

async function syncDirectory(path: string, seams: TrustedControlSeams): Promise<void> {
  const before = await strictDirectory(path, 0o700, seams);
  const handle = await seams.fs.open(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    requireSameDirectory(before, opened, 0o700, seams.uid);
    await handle.sync();
    const after = await handle.stat();
    requireSameDirectory(opened, after, 0o700, seams.uid);
    const pathAfter = await strictDirectory(path, 0o700, seams);
    requireSameDirectory(opened, pathAfter, 0o700, seams.uid);
  } finally {
    await handle.close();
  }
}

async function strictDirectory(path: string, mode: number, seams: TrustedControlSeams): Promise<FileStat> {
  const stat = await seams.fs.lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== mode ||
    stat.uid !== seams.uid ||
    (await seams.fs.realpath(path)) !== path
  )
    fail();
  return stat;
}

async function strictFileStat(path: string, mode: number, seams: TrustedControlSeams): Promise<FileStat> {
  const stat = await seams.fs.lstat(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== mode ||
    stat.uid !== seams.uid ||
    (await seams.fs.realpath(path)) !== path
  )
    fail();
  return stat;
}

function requireSameFile(before: FileStat, after: FileStat, mode: number, uid: number): void {
  requireSameIdentity(before, after, mode, uid);
  requireStable(before, after);
}

function requireSameIdentity(before: FileStat, after: FileStat, mode: number, uid: number): void {
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    !after.isFile() ||
    after.isSymbolicLink() ||
    after.nlink !== 1 ||
    (after.mode & 0o777) !== mode ||
    after.uid !== uid
  )
    fail();
}

function requireSameDirectory(before: FileStat, after: FileStat, mode: number, uid: number): void {
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    !after.isDirectory() ||
    after.isSymbolicLink() ||
    (after.mode & 0o777) !== mode ||
    after.uid !== uid
  )
    fail();
}

function requireStable(before: FileStat, after: FileStat): void {
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs ||
    before.ctimeMs !== after.ctimeMs
  )
    fail();
}

function captureSeams(value: TrustedControlSeams | undefined): TrustedControlSeams {
  if (value === undefined) {
    const uid = typeof process.geteuid === "function" ? process.geteuid() : -1;
    return Object.freeze({ platform: process.platform, uid, fs: DEFAULT_FS });
  }
  if (!Object.isFrozen(value) || Object.getPrototypeOf(value) !== Object.prototype) fail();
  if (Object.getOwnPropertySymbols(value).length !== 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (!Object.keys(descriptors).every((key) => ["platform", "uid", "fs", "after"].includes(key))) fail();
  const platform = data(descriptors.platform);
  const uid = data(descriptors.uid);
  const fs = data(descriptors.fs);
  const after = descriptors.after === undefined ? undefined : data(descriptors.after);
  if (platform !== "linux" || !Number.isSafeInteger(uid) || (uid as number) < 0) fail();
  if (!Object.isFrozen(fs) || Object.getPrototypeOf(fs) !== Object.prototype) fail();
  if (Object.getOwnPropertySymbols(fs).length !== 0) fail();
  const fsDescriptors = Object.getOwnPropertyDescriptors(fs);
  const methods = ["lstat", "realpath", "readdir", "statfs", "open", "unlink"];
  if (Object.keys(fsDescriptors).sort().join("\0") !== methods.sort().join("\0")) fail();
  const capturedFs: Record<string, unknown> = {};
  for (const method of methods) {
    const methodValue = data(fsDescriptors[method]);
    if (typeof methodValue !== "function" || !Object.isFrozen(methodValue)) fail();
    capturedFs[method] = methodValue;
  }
  if (after !== undefined && (typeof after !== "function" || !Object.isFrozen(after))) fail();
  return Object.freeze({
    platform,
    uid: uid as number,
    fs: Object.freeze(capturedFs) as ControlFs,
    ...(after === undefined ? {} : { after: after as (stage: string) => void | Promise<void> }),
  });
}

function data(descriptor: PropertyDescriptor | undefined): unknown {
  if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  return descriptor.value;
}

function driverStateId(path: string): string {
  return createHash("sha256").update(path).digest("hex").slice(0, 12);
}

function defineHidden(input: TrustedSshControls): TrustedSshControls {
  const output: Record<PropertyKey, unknown> = {};
  for (const key of ["endpoint", "username", "hostKeySha256", "clientKeyPath", "close"] as const) {
    Object.defineProperty(output, key, { value: input[key], enumerable: false, writable: false, configurable: false });
  }
  return output as TrustedSshControls;
}

function authorityFor(profile: LauncherProfile): LauncherAuthority {
  return profile === "linux-kvm" ? "authoritative-local" : "functional-only";
}

function validateOptionalSignal(signal: AbortSignal | undefined): void {
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail();
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) fail();
}

function fail(): never {
  throw failure();
}

function failure(): Error {
  return new Error("launcher trusted controls failed");
}
