import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath, unlink } from "node:fs/promises";
import { basename, join } from "node:path";
import { canonicalJson, type LauncherAuthority, type LauncherProfile } from "./contract.ts";
import { observeProcessIdentity } from "./runner.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";

export type ApiTokenHolder = Readonly<{
  read(): string;
  withToken<T>(operation: (token: string) => T): T;
  dispose(): void;
}>;
export type WorkerDescriptor = Readonly<{
  version: "cogs.dev-launcher-worker/v1alpha1";
  stateId: string;
  sourceRevision: string;
  profile: LauncherProfile;
  pid: number;
  pidIdentity: string;
  apiPort: number;
  authority: LauncherAuthority;
  readiness: "ready";
}>;
export type ControlSeams = Readonly<{
  randomBytes: typeof randomBytes;
  identity: (pid: number) => string | null | undefined;
  afterExclusiveOpen?: (path: string) => void | Promise<void>;
  afterExclusiveWrite?: (path: string) => void | Promise<void>;
}>;

const workerVersion = "cogs.dev-launcher-worker/v1alpha1" as const;
const tokenFile = "api-token";
const workerFile = "worker.json";
const fileMode = 0o600;
const digestRe = /^sha256:[a-f0-9]{64}$/u;
const defaultRandomBytes = Object.freeze((size: number) => randomBytes(size)) as typeof randomBytes;
const defaultIdentity = observeProcessIdentity;

export async function createApiToken(state: LauncherState, seams?: Partial<ControlSeams>): Promise<void> {
  let raw: Buffer | undefined;
  try {
    const s = captureSeams(seams);
    raw = s.randomBytes(32);
    if (!Buffer.isBuffer(raw) || raw.length !== 32 || raw.every((b) => b === 0)) fail();
    await writeExclusive(state, tokenFile, `${raw.toString("base64url")}\n`, s);
  } catch {
    throw generic();
  } finally {
    if (Buffer.isBuffer(raw)) raw.fill(0);
  }
}

export async function readApiToken(state: LauncherState): Promise<ApiTokenHolder> {
  let token = "";
  try {
    const text = await readOwnedFile(state, tokenFile, 128);
    if (!/^[A-Za-z0-9_-]{43}\n$/u.test(text)) fail();
    const decoded = Buffer.from(text.trim(), "base64url");
    try {
      if (decoded.length !== 32 || decoded.every((b) => b === 0)) fail();
      token = text.trim();
      return Object.freeze({
        read: Object.freeze(() => {
          if (token === "") throw generic();
          return token;
        }),
        withToken: Object.freeze(<T>(operation: (token: string) => T): T => {
          if (token === "") throw generic();
          return operation(token);
        }),
        dispose: Object.freeze(() => {
          token = "";
        }),
      });
    } finally {
      decoded.fill(0);
    }
  } catch {
    token = "";
    throw generic();
  }
}

export async function writeWorkerDescriptor(
  state: LauncherState,
  input: Omit<WorkerDescriptor, "version">,
): Promise<void> {
  try {
    const manifest = await readManifest(state);
    const descriptor = descriptorFor(state, input, manifest.sourceRevision, manifest.profile);
    await writeExclusive(state, workerFile, canonicalJson(descriptor));
  } catch {
    throw generic();
  }
}

export async function readWorkerDescriptor(state: LauncherState): Promise<WorkerDescriptor> {
  try {
    const manifest = await readManifest(state);
    const parsed = parseWorker(
      await readOwnedFile(state, workerFile, 4096),
      state,
      manifest.sourceRevision,
      manifest.profile,
    );
    return parsed;
  } catch {
    throw generic();
  }
}

export async function verifyWorkerIdentity(state: LauncherState, seams?: Partial<ControlSeams>): Promise<boolean> {
  try {
    const s = captureSeams(seams);
    const descriptor = await readWorkerDescriptor(state);
    const observed = s.identity(descriptor.pid);
    if (observed === null) return false;
    if (observed === undefined || !digestRe.test(observed) || observed !== descriptor.pidIdentity) fail();
    return true;
  } catch {
    throw generic();
  }
}

export async function cleanupControlFiles(state: LauncherState, seams?: Partial<ControlSeams>): Promise<void> {
  try {
    await readManifest(state);
    const s = captureSeams(seams);
    const entries = await readdir(state.controlDir);
    if (entries.some((entry) => entry !== "sandbox" && entry !== tokenFile && entry !== workerFile)) fail();
    await validateSandboxDir(state);
    const token = await ownedStat(state, tokenFile, false);
    const worker = await ownedStat(state, workerFile, false);
    if (token) {
      const holder = await readApiToken(state);
      holder.dispose();
    }
    if (worker) {
      const descriptor = await readWorkerDescriptor(state);
      const observed = s.identity(descriptor.pid);
      if (observed === undefined || (observed !== null && !digestRe.test(observed))) fail();
      if (observed === descriptor.pidIdentity) fail();
    }
    if (token) await unlinkExact(controlPath(state, tokenFile), token);
    if (worker) await unlinkExact(controlPath(state, workerFile), worker);
    await fsyncDir(state.controlDir);
    if ((await ownedStat(state, tokenFile, false)) || (await ownedStat(state, workerFile, false))) fail();
  } catch {
    throw generic();
  }
}

function descriptorFor(
  state: Pick<LauncherState, "stateId">,
  input: unknown,
  sourceRevision: string,
  profile: LauncherProfile,
): WorkerDescriptor {
  const v = exact(input, [
    "apiPort",
    "authority",
    "pid",
    "pidIdentity",
    "profile",
    "readiness",
    "sourceRevision",
    "stateId",
  ]);
  if (v.stateId !== state.stateId || v.sourceRevision !== sourceRevision || v.profile !== profile) fail();
  const authority = profile === "linux-kvm" ? "authoritative-local" : "functional-only";
  if (v.authority !== authority || v.readiness !== "ready") fail();
  if (!Number.isSafeInteger(v.pid) || (v.pid as number) < 1 || (v.pid as number) > 2 ** 31 - 1) fail();
  if (typeof v.pidIdentity !== "string" || !digestRe.test(v.pidIdentity)) fail();
  if (!Number.isSafeInteger(v.apiPort) || (v.apiPort as number) < 1 || (v.apiPort as number) > 65535) fail();
  return Object.freeze({
    version: workerVersion,
    stateId: state.stateId,
    sourceRevision,
    profile,
    pid: v.pid as number,
    pidIdentity: v.pidIdentity as string,
    apiPort: v.apiPort as number,
    authority,
    readiness: "ready",
  });
}

function parseWorker(
  text: string,
  state: Pick<LauncherState, "stateId">,
  sourceRevision: string,
  profile: LauncherProfile,
): WorkerDescriptor {
  if (text.length > 4096) fail();
  const parsed = JSON.parse(text);
  const all = exact(parsed, [
    "apiPort",
    "authority",
    "pid",
    "pidIdentity",
    "profile",
    "readiness",
    "sourceRevision",
    "stateId",
    "version",
  ]);
  if (all.version !== workerVersion) fail();
  const input = Object.freeze({
    stateId: all.stateId,
    sourceRevision: all.sourceRevision,
    profile: all.profile,
    pid: all.pid,
    pidIdentity: all.pidIdentity,
    apiPort: all.apiPort,
    authority: all.authority,
    readiness: all.readiness,
  });
  const out = descriptorFor(state, input, sourceRevision, profile);
  if (canonicalJson(out) !== text) fail();
  return out;
}

async function writeExclusive(
  state: LauncherState,
  name: string,
  text: string,
  seams: Pick<ControlSeams, "afterExclusiveOpen" | "afterExclusiveWrite"> = {},
): Promise<void> {
  await validateControlDir(state);
  const path = controlPath(state, name);
  let owned: { dev: number; ino: number } | undefined;
  let closed = false;
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    fileMode,
  );
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || (opened.mode & 0o777) !== fileMode) fail();
    if (typeof process.geteuid === "function" && opened.uid !== process.geteuid()) fail();
    owned = { dev: opened.dev, ino: opened.ino };
    await seams.afterExclusiveOpen?.(path);
    await handle.writeFile(text, "utf8");
    await seams.afterExclusiveWrite?.(path);
    await handle.sync();
    const stat = await handle.stat();
    if (
      !sameFile(opened, stat) ||
      !stat.isFile() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o777) !== fileMode ||
      stat.size !== Buffer.byteLength(text)
    )
      fail();
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) fail();
    await handle.close();
    closed = true;
    await fsyncDir(state.controlDir);
  } catch (error) {
    if (!closed) await handle.close().catch(() => undefined);
    if (owned) await unlinkExact(path, owned).catch(() => undefined);
    throw error;
  }
}

async function readOwnedFile(state: LauncherState, name: string, max: number): Promise<string> {
  await validateControlDir(state);
  const path = controlPath(state, name);
  const before = await lstat(path);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (
      !sameFile(before, stat) ||
      !stat.isFile() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o777) !== fileMode ||
      stat.size < 1 ||
      stat.size > max
    )
      fail();
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) fail();
    const buffer = Buffer.alloc(Math.min(max + 1, Number(stat.size) + 1));
    const read = await handle.read(buffer, 0, buffer.length, 0);
    if (read.bytesRead !== stat.size || read.bytesRead > max) fail();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, read.bytesRead));
    const after = await handle.stat();
    if (
      !sameFile(stat, after) ||
      !after.isFile() ||
      after.nlink !== 1 ||
      (after.mode & 0o777) !== fileMode ||
      after.size !== read.bytesRead ||
      after.size !== Buffer.byteLength(text) ||
      (typeof process.geteuid === "function" && after.uid !== process.geteuid())
    )
      fail();
    return text;
  } finally {
    await handle.close();
  }
}

async function ownedStat(
  state: LauncherState,
  name: string,
  required: boolean,
): Promise<{ dev: number; ino: number } | undefined> {
  try {
    const stat = await lstat(controlPath(state, name));
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== fileMode) fail();
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) fail();
    return { dev: stat.dev, ino: stat.ino };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !required) return undefined;
    throw error;
  }
}

async function unlinkExact(path: string, owned: { dev: number; ino: number }): Promise<void> {
  const stat = await lstat(path);
  if (!sameFile(stat, owned) || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== fileMode) fail();
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) fail();
  await unlink(path);
  try {
    await lstat(path);
    fail();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function validateSandboxDir(state: LauncherState): Promise<void> {
  const path = join(state.controlDir, "sandbox");
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || (await realpath(path)) !== path)
    fail();
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) fail();
}

async function validateControlDir(state: LauncherState): Promise<void> {
  await readManifest(state);
  const stat = await lstat(state.controlDir);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== 0o700 ||
    (await realpath(state.controlDir)) !== state.controlDir
  )
    fail();
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) fail();
}

function controlPath(state: LauncherState, name: string): string {
  if (name !== tokenFile && name !== workerFile) fail();
  const path = join(state.controlDir, name);
  if (basename(path) !== name) fail();
  return path;
}

function sameFile(a: { dev: number; ino: number }, b: { dev: number; ino: number }): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  const d = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(d);
  if (
    actual.some((k) => typeof k !== "string") ||
    (actual as string[]).sort().join("\0") !== [...keys].sort().join("\0")
  )
    fail();
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const item = d[key];
    if (!item || !("value" in item) || item.enumerable !== true) fail();
    out[key] = item.value;
  }
  return out;
}

function captureSeams(seams?: Partial<ControlSeams>): ControlSeams {
  if (seams === undefined) return Object.freeze({ randomBytes: defaultRandomBytes, identity: defaultIdentity });
  try {
    if (!Object.isFrozen(seams) || Object.getPrototypeOf(seams) !== Object.prototype) fail();
    const keys = Reflect.ownKeys(seams).sort();
    if (
      keys.some(
        (key) =>
          typeof key !== "string" ||
          !["afterExclusiveOpen", "afterExclusiveWrite", "identity", "randomBytes"].includes(key),
      )
    )
      fail();
    const d = Object.getOwnPropertyDescriptors(seams);
    for (const key of keys) {
      const item = d[key as string];
      if (!item || !("value" in item) || item.enumerable !== true) fail();
      if (typeof item.value !== "function" || !Object.isFrozen(item.value)) fail();
    }
    const out: {
      randomBytes: typeof randomBytes;
      identity: (pid: number) => string | null | undefined;
      afterExclusiveOpen?: (path: string) => void | Promise<void>;
      afterExclusiveWrite?: (path: string) => void | Promise<void>;
    } = {
      randomBytes: ("randomBytes" in d ? d.randomBytes.value : defaultRandomBytes) as typeof randomBytes,
      identity: ("identity" in d ? d.identity.value : defaultIdentity) as (pid: number) => string | null | undefined,
    };
    if ("afterExclusiveOpen" in d)
      out.afterExclusiveOpen = d.afterExclusiveOpen.value as (path: string) => void | Promise<void>;
    if ("afterExclusiveWrite" in d)
      out.afterExclusiveWrite = d.afterExclusiveWrite.value as (path: string) => void | Promise<void>;
    return Object.freeze(out);
  } catch {
    throw generic();
  }
}

async function fsyncDir(path: string): Promise<void> {
  const dir = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    await dir.sync();
  } finally {
    await dir.close();
  }
}

function generic(): Error {
  return new Error("launcher control failed");
}
function fail(): never {
  throw generic();
}
