import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rename, rm, rmdir, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  createLauncherManifest,
  type LauncherManifest,
  type LauncherPhase,
  type LauncherProfile,
  launcherRecoveryVersion,
  parseCanonicalManifest,
  stateIdFor,
} from "./contract.ts";

export type LauncherState = Readonly<{
  root: string;
  name: string;
  dir: string;
  controlDir: string;
  sandboxDir: string;
  driverStateName: string;
  driverStateDir: string;
  driverCacheDir: string;
  lockDir: string;
  manifestPath: string;
  sentinelPath: string;
  recoveryPath: string;
  stateId: string;
  sourceRevision: string;
}>;

const nameRe = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const fileMode = 0o600;
const dirMode = 0o700;
const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const repoLauncherRoot = join(repoRoot, ".cogs-dev", "launcher");

export async function resolveLauncherState(input: {
  root: string;
  name: string;
  sourceRevision: string;
}): Promise<LauncherState> {
  const captured = snapshotStateInput(input);
  if (!/^[a-f0-9]{40}$/u.test(captured.sourceRevision)) throw new Error("invalid launcher state");
  if (!nameRe.test(captured.name) || captured.name === "." || captured.name === "..")
    throw new Error("invalid launcher state");
  if (!captured.root.startsWith(sep) || captured.root !== resolve(captured.root))
    throw new Error("invalid launcher state");
  let root = captured.root;
  if (basename(root) === "." || root === sep) throw new Error("invalid launcher state");
  await ensureRoot(root);
  root = await realpath(root);
  const dir = join(root, captured.name);
  if (dirname(dir) !== root) throw new Error("invalid launcher state");
  const stateId = stateIdFor({ root, name: captured.name });
  const driverStateName = `launcher-state-${stateId}`;
  return Object.freeze({
    root,
    name: captured.name,
    dir,
    controlDir: join(dir, "control"),
    sandboxDir: join(dir, "control", "sandbox"),
    driverStateName,
    driverStateDir: join(dirname(root), driverStateName),
    driverCacheDir: join(dirname(root), "cache"),
    lockDir: join(root, `.${stateId}.lock`),
    manifestPath: join(dir, "manifest.json"),
    sentinelPath: join(dir, ".cogs-launcher-owner"),
    recoveryPath: join(dir, ".cogs-launcher-recovery"),
    stateId,
    sourceRevision: captured.sourceRevision,
  });
}

function snapshotStateInput(input: { root: string; name: string; sourceRevision: string }): {
  root: string;
  name: string;
  sourceRevision: string;
} {
  if (!input || typeof input !== "object" || Object.getPrototypeOf(input) !== Object.prototype)
    throw new Error("invalid launcher state");
  if (Object.getOwnPropertySymbols(input).length !== 0) throw new Error("invalid launcher state");
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = ["name", "root", "sourceRevision"];
  if (Object.keys(descriptors).sort().join(",") !== keys.join(",")) throw new Error("invalid launcher state");
  const out: Record<string, string> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true ||
      typeof descriptor.value !== "string"
    )
      throw new Error("invalid launcher state");
    out[key] = descriptor.value;
  }
  const { root, name, sourceRevision } = out;
  if (root === undefined || name === undefined || sourceRevision === undefined)
    throw new Error("invalid launcher state");
  return { root, name, sourceRevision };
}

export async function withStateLock<T>(state: LauncherState, operation: () => Promise<T>): Promise<T> {
  const lease = await acquireLock(state);
  let output: T;
  try {
    output = await operation();
  } catch (operationError) {
    try {
      await releaseLock(state, lease);
    } catch {
      throw new Error("launcher state lock cleanup failed");
    }
    throw operationError;
  }
  await releaseLock(state, lease);
  return output;
}

async function releaseLock(state: LauncherState, lease: { dev: number; ino: number; owner: string }): Promise<void> {
  const stat = await lstat(state.lockDir);
  if (!stat.isDirectory() || stat.dev !== lease.dev || stat.ino !== lease.ino || (stat.mode & 0o777) !== dirMode)
    throw new Error("launcher state lock cleanup failed");
  const entries = await readdir(state.lockDir);
  if (entries.length !== 1 || entries[0] !== "owner") throw new Error("launcher state lock cleanup failed");
  const ownerPath = join(state.lockDir, "owner");
  if ((await readFileNoFollow(ownerPath, 128)) !== lease.owner) throw new Error("launcher state lock cleanup failed");
  await unlink(ownerPath);
  await rmdir(state.lockDir);
  try {
    await lstat(state.lockDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("launcher state lock remained");
}

export async function createState(state: LauncherState, profile: LauncherProfile): Promise<LauncherManifest> {
  let ownsSentinel = false;
  try {
    await mkdir(state.dir, { mode: dirMode });
    await ensureDirectory(state.dir);
    try {
      await writeExclusive(state.sentinelPath, `${state.stateId}\n`);
      ownsSentinel = true;
    } catch (error) {
      await rm(state.dir, { recursive: false, force: true }).catch(() => undefined);
      throw error;
    }
    await mkdir(state.controlDir, { mode: dirMode });
    await mkdir(state.sandboxDir, { mode: dirMode });
    await chmodStrictDirs(state);
    const manifest = manifestFor(state, profile, "creating");
    await writeManifest(state, manifest);
    return manifest;
  } catch (error) {
    if (ownsSentinel) await writeRecovery(state, "create-uncertain").catch(() => undefined);
    throw error;
  }
}

export async function readManifest(state: LauncherState): Promise<LauncherManifest> {
  await validateOwnedState(state);
  const text = await readFileNoFollow(state.manifestPath, 8192);
  const manifest = parseCanonicalManifest(text);
  if (manifest.stateId !== state.stateId || manifest.stateName !== state.name)
    throw new Error("invalid launcher state");
  if (
    manifest.owned.sandboxState !== state.driverStateName ||
    manifest.owned.controlDir !== "control" ||
    manifest.owned.lockName !== `.${state.stateId}.lock`
  )
    throw new Error("invalid launcher state");
  return manifest;
}

export async function writePhase(
  state: LauncherState,
  manifest: LauncherManifest,
  phase: LauncherPhase,
): Promise<LauncherManifest> {
  await validateOwnedState(state);
  const next = createLauncherManifest({ ...manifest, phase, owned: manifest.owned, ports: manifest.ports });
  await writeManifest(state, next);
  return next;
}

export async function markRecovery(state: LauncherState, reason: string): Promise<void> {
  await writeRecovery(state, reason);
}

export async function clearRecovery(
  state: LauncherState,
  seams: Readonly<{ beforeFinalRevalidate?: () => void | Promise<void> }> = Object.freeze({}),
): Promise<void> {
  const captured = snapshotClearRecoverySeams(seams);
  const parent = await validateOwnedState(state);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let closeFailed = false;
  try {
    handle = await open(state.recoveryPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new Error("launcher recovery cleanup failed");
  }
  try {
    const marker = await handle.stat();
    validateRecoveryMarker(marker);
    if ((await realpath(state.recoveryPath)) !== state.recoveryPath)
      throw new Error("launcher recovery cleanup failed");
    const text = await readRecoveryHandle(handle, marker);
    validateRecoveryContent(text, state.stateId);
    const pathStat = await lstat(state.recoveryPath);
    validateRecoveryMarker(pathStat);
    if (!sameFile(pathStat, marker) || (await realpath(state.recoveryPath)) !== state.recoveryPath)
      throw new Error("launcher recovery cleanup failed");
    await captured.beforeFinalRevalidate?.();
    const finalParent = await validateOwnedState(state);
    if (!sameFile(finalParent, parent)) throw new Error("launcher recovery cleanup failed");
    const finalPathStat = await lstat(state.recoveryPath);
    validateRecoveryMarker(finalPathStat);
    if (!sameFile(finalPathStat, marker) || (await realpath(state.recoveryPath)) !== state.recoveryPath)
      throw new Error("launcher recovery cleanup failed");
    const finalHandle = await open(state.recoveryPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const finalOpenStat = await finalHandle.stat();
      validateRecoveryMarker(finalOpenStat);
      if (!sameFile(finalOpenStat, marker)) throw new Error("launcher recovery cleanup failed");
    } finally {
      await finalHandle.close();
    }
    await unlink(state.recoveryPath);
    try {
      await lstat(state.recoveryPath);
      throw new Error("launcher recovery cleanup failed");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await fsyncDir(state.dir);
    const afterParent = await validateOwnedState(state);
    if (!sameFile(afterParent, parent)) throw new Error("launcher recovery cleanup failed");
  } catch {
    throw new Error("launcher recovery cleanup failed");
  } finally {
    try {
      await handle.close();
    } catch {
      closeFailed = true;
    }
  }
  if (closeFailed) throw new Error("launcher recovery cleanup failed");
}

function snapshotClearRecoverySeams(seams: Readonly<{ beforeFinalRevalidate?: () => void | Promise<void> }>): Readonly<{
  beforeFinalRevalidate?: () => void | Promise<void>;
}> {
  if (
    !seams ||
    typeof seams !== "object" ||
    Object.getPrototypeOf(seams) !== Object.prototype ||
    !Object.isFrozen(seams)
  )
    throw new Error("launcher recovery cleanup failed");
  if (Object.getOwnPropertySymbols(seams).length !== 0) throw new Error("launcher recovery cleanup failed");
  const descriptors = Object.getOwnPropertyDescriptors(seams);
  if (Object.keys(descriptors).some((key) => key !== "beforeFinalRevalidate"))
    throw new Error("launcher recovery cleanup failed");
  const hook = descriptors.beforeFinalRevalidate;
  if (hook === undefined) return Object.freeze({});
  if (!hook.enumerable || !Object.hasOwn(hook, "value") || typeof hook.value !== "function")
    throw new Error("launcher recovery cleanup failed");
  return Object.freeze({ beforeFinalRevalidate: hook.value });
}

type RecoveryMarker = {
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  size: number;
  uid: number;
  isFile(): boolean;
  isSymbolicLink(): boolean;
};

function validateRecoveryMarker(stat: RecoveryMarker): void {
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    stat.size < 1 ||
    stat.size > 8192 ||
    (stat.mode & 0o777) !== fileMode ||
    (geteuid() !== undefined && stat.uid !== geteuid())
  )
    throw new Error("launcher recovery cleanup failed");
}

async function readRecoveryHandle(handle: Awaited<ReturnType<typeof open>>, marker: RecoveryMarker) {
  const bytes = await handle.readFile("utf8");
  const after = await handle.stat();
  if (!sameFile(after, marker) || after.size !== Buffer.byteLength(bytes) || after.size > 8192)
    throw new Error("launcher recovery cleanup failed");
  return bytes;
}

function validateRecoveryContent(text: string, stateId: string): void {
  const parsed = JSON.parse(text) as unknown;
  const record = parsed && typeof parsed === "object" ? Object.getOwnPropertyDescriptors(parsed) : undefined;
  if (
    !record ||
    Object.getPrototypeOf(parsed) !== Object.prototype ||
    Object.getOwnPropertySymbols(parsed).length !== 0 ||
    Object.keys(record).sort().join(",") !== "reason,stateId,version"
  )
    throw new Error("launcher recovery cleanup failed");
  const { reason, stateId: parsedStateId, version } = record;
  if (
    !version ||
    !parsedStateId ||
    !reason ||
    !("value" in version) ||
    !("value" in parsedStateId) ||
    !("value" in reason) ||
    version.value !== launcherRecoveryVersion ||
    parsedStateId.value !== stateId ||
    typeof reason.value !== "string" ||
    !/^[a-z0-9._-]{1,64}$/u.test(reason.value) ||
    canonicalJson({ version: launcherRecoveryVersion, stateId, reason: reason.value }) !== text
  )
    throw new Error("launcher recovery cleanup failed");
}

function sameFile(
  a: { dev: number | bigint; ino: number | bigint },
  b: { dev: number | bigint; ino: number | bigint },
): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

export async function removeOwnedState(state: LauncherState): Promise<void> {
  const before = await validateOwnedState(state);
  if (before.nlink < 2) throw new Error("invalid launcher state");
  await atomicWrite(
    state.recoveryPath,
    canonicalJson({ version: launcherRecoveryVersion, stateId: state.stateId, reason: "cleanup-in-progress" }),
  );
  const tombstone = join(state.root, `.remove-${state.stateId}-${randomBytes(8).toString("hex")}`);
  await rename(state.dir, tombstone);
  const moved = await lstat(tombstone);
  if (moved.dev !== before.dev || moved.ino !== before.ino) throw new Error("launcher state cleanup uncertain");
  if ((await readFileNoFollow(join(tombstone, ".cogs-launcher-owner"), 128)) !== `${state.stateId}\n`)
    throw new Error("launcher state cleanup uncertain");
  try {
    await lstat(state.dir);
    throw new Error("launcher state cleanup uncertain");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await rm(tombstone, { recursive: true, force: false });
  try {
    await lstat(tombstone);
    throw new Error("launcher state cleanup uncertain");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await fsyncDir(state.root);
}

export function manifestFor(state: LauncherState, profile: LauncherProfile, phase: LauncherPhase): LauncherManifest {
  return createLauncherManifest({
    sourceRevision: state.sourceRevision,
    stateId: state.stateId,
    stateName: state.name,
    profile,
    phase,
    owned: { sandboxState: state.driverStateName, controlDir: "control", lockName: `.${state.stateId}.lock` },
  });
}

async function acquireLock(state: LauncherState): Promise<{ dev: number; ino: number; owner: string }> {
  await ensureDirectory(state.root);
  let stat: Awaited<ReturnType<typeof lstat>> | undefined;
  try {
    await mkdir(state.lockDir, { mode: dirMode });
    stat = await lstat(state.lockDir);
    if (
      !stat.isDirectory() ||
      (stat.mode & 0o777) !== dirMode ||
      (geteuid() !== undefined && stat.uid !== geteuid()) ||
      (await realpath(state.lockDir)) !== state.lockDir
    )
      throw new Error("launcher state lock is uncertain");
    const owner = `${process.pid}\n${randomBytes(16).toString("hex")}\n`;
    try {
      await writeExclusive(join(state.lockDir, "owner"), owner);
    } catch (error) {
      await removeJustCreatedEmptyLock(state, stat);
      throw error;
    }
    return { dev: stat.dev, ino: stat.ino, owner };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  throw new Error("launcher state is locked");
}

async function removeJustCreatedEmptyLock(state: LauncherState, lease: { dev: number; ino: number }): Promise<void> {
  try {
    const stat = await lstat(state.lockDir);
    if (!stat.isDirectory() || stat.dev !== lease.dev || stat.ino !== lease.ino)
      throw new Error("launcher state lock is uncertain");
    if ((await readdir(state.lockDir)).length !== 0) throw new Error("launcher state lock is uncertain");
    await rmdir(state.lockDir);
  } catch {
    throw new Error("launcher state lock is uncertain");
  }
}

async function validateOwnedState(state: LauncherState): Promise<Awaited<ReturnType<typeof lstat>>> {
  const stat = await lstat(state.dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("invalid launcher state");
  if (geteuid() !== undefined && stat.uid !== geteuid()) throw new Error("invalid launcher state");
  if ((stat.mode & 0o777) !== dirMode) throw new Error("invalid launcher state");
  if ((await realpath(state.dir)) !== state.dir) throw new Error("invalid launcher state");
  if ((await readFileNoFollow(state.sentinelPath, 128)) !== `${state.stateId}\n`)
    throw new Error("invalid launcher state");
  return stat;
}

async function chmodStrictDirs(state: LauncherState): Promise<void> {
  for (const dir of [state.dir, state.controlDir, state.sandboxDir]) await ensureDirectory(dir);
}

async function ensureRoot(path: string): Promise<void> {
  if (path === repoLauncherRoot) {
    await ensureRepoLauncherRoot();
    return;
  }
  try {
    await ensureDirectory(path);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const parent = dirname(path);
  await ensureDirectory(parent);
  await mkdir(path, { mode: dirMode });
  await ensureDirectory(path);
}

async function ensureRepoLauncherRoot(): Promise<void> {
  await ensureRepoRoot(repoRoot);
  const cogsDev = dirname(repoLauncherRoot);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await ensureDirectory(cogsDev);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(cogsDev, { mode: dirMode }).catch((mkdirError: NodeJS.ErrnoException) => {
        if (mkdirError.code !== "EEXIST") throw mkdirError;
      });
      await ensureDirectory(cogsDev);
    }
    try {
      await ensureDirectory(repoLauncherRoot);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(repoLauncherRoot, { mode: dirMode }).catch((mkdirError: NodeJS.ErrnoException) => {
        if (mkdirError.code !== "EEXIST") throw mkdirError;
      });
    }
  }
  await ensureDirectory(repoLauncherRoot);
}

async function ensureRepoRoot(path: string): Promise<void> {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("invalid launcher state");
  if (geteuid() !== undefined && stat.uid !== geteuid()) throw new Error("invalid launcher state");
  if ((stat.mode & 0o022) !== 0) throw new Error("invalid launcher state");
  if ((await realpath(path)) !== path) throw new Error("invalid launcher state");
}

async function ensureDirectory(path: string, allowedMode = dirMode): Promise<void> {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("invalid launcher state");
  if (geteuid() !== undefined && stat.uid !== geteuid()) throw new Error("invalid launcher state");
  if ((stat.mode & 0o777) !== allowedMode) throw new Error("invalid launcher state");
  if ((await realpath(path)) !== path) throw new Error("invalid launcher state");
}

async function checkedFile(path: string) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("invalid launcher state");
  if (geteuid() !== undefined && stat.uid !== geteuid()) throw new Error("invalid launcher state");
  if ((stat.mode & 0o777) !== fileMode) throw new Error("invalid launcher state");
  return stat;
}

async function writeManifest(state: LauncherState, manifest: LauncherManifest): Promise<void> {
  await atomicWrite(state.manifestPath, canonicalJson(manifest));
}

async function writeRecovery(state: LauncherState, reason: string): Promise<void> {
  await validateOwnedState(state);
  await atomicWrite(
    state.recoveryPath,
    canonicalJson({ version: launcherRecoveryVersion, stateId: state.stateId, reason: scrubReason(reason) }),
  );
}

async function writeExclusive(path: string, content: string): Promise<void> {
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    fileMode,
  );
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fsyncDir(dirname(path));
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const dir = dirname(path);
  const tmp = join(dir, `.tmp-${basename(path)}-${process.pid}-${Date.now()}`);
  try {
    await ensureDirectory(dir);
    const handle = await open(
      tmp,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      fileMode,
    );
    try {
      await handle.writeFile(content);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmp, path);
    await checkedFile(path);
    await fsyncDir(dir);
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function fsyncDir(path: string): Promise<void> {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    await fd.sync();
  } finally {
    await fd.close();
  }
}

async function readFileNoFollow(path: string, maxBytes: number): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.size > maxBytes ||
      (geteuid() !== undefined && before.uid !== geteuid()) ||
      (before.mode & 0o777) !== fileMode
    )
      throw new Error("invalid launcher state");
    const text = await handle.readFile("utf8");
    const after = await handle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      !after.isFile() ||
      after.nlink !== 1 ||
      after.size > maxBytes ||
      Buffer.byteLength(text) > maxBytes ||
      (geteuid() !== undefined && after.uid !== geteuid()) ||
      (after.mode & 0o777) !== fileMode
    )
      throw new Error("invalid launcher state");
    return text;
  } finally {
    await handle.close();
  }
}

function geteuid(): number | undefined {
  return typeof process.geteuid === "function" ? process.geteuid() : undefined;
}

function scrubReason(reason: string): string {
  return /^[a-z0-9._-]{1,64}$/u.test(reason) ? reason : "uncertain";
}
