import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import { basename, join } from "node:path";
import { canonicalJson, type LauncherAuthority, type LauncherProfile } from "./contract.ts";
import { observeProcessIdentity } from "./runner.ts";
import type { LauncherState } from "./state.ts";
import { readManifest, writePhase } from "./state.ts";
import { parseChildIdentityHello, parseChildReady } from "./worker-protocol.ts";

export type ApiTokenHolder = Readonly<{
  read(): string;
  withToken<T>(operation: (token: string) => T): T;
  dispose(): void;
}>;

export type StartupNonceHolder = Readonly<{
  digest(): `sha256:${string}`;
  withNonce<T>(operation: (nonce: string) => T): T;
  dispose(): void;
}>;

export type PreSpawnWorkerDescriptor = Readonly<{
  version: "cogs.dev-launcher-worker/v1alpha1";
  stateId: string;
  sourceRevision: string;
  profile: LauncherProfile;
  authority: LauncherAuthority;
  readiness: "starting";
  stage: "pre-spawn";
  startupDigest: `sha256:${string}`;
  parentPid: number;
  parentPidIdentity: `sha256:${string}`;
}>;

export type ChildBoundWorkerDescriptor = Readonly<{
  version: "cogs.dev-launcher-worker/v1alpha1";
  stateId: string;
  sourceRevision: string;
  profile: LauncherProfile;
  authority: LauncherAuthority;
  readiness: "starting";
  stage: "child-bound";
  startupDigest: `sha256:${string}`;
  parentPid: number;
  parentPidIdentity: `sha256:${string}`;
  childPid: number;
  childPidIdentity: `sha256:${string}`;
}>;

export type StartingWorkerDescriptor = PreSpawnWorkerDescriptor | ChildBoundWorkerDescriptor;

export type ReadyWorkerDescriptor = Readonly<{
  version: "cogs.dev-launcher-worker/v1alpha1";
  stateId: string;
  sourceRevision: string;
  profile: LauncherProfile;
  authority: LauncherAuthority;
  readiness: "ready";
  stage: "ready";
  startupDigest: `sha256:${string}`;
  parentPid: number;
  parentPidIdentity: `sha256:${string}`;
  childPid: number;
  childPidIdentity: `sha256:${string}`;
  apiPort: number;
}>;

export type WorkerDescriptor = StartingWorkerDescriptor | ReadyWorkerDescriptor;

export type WorkerStartup = Readonly<{
  descriptor: PreSpawnWorkerDescriptor;
  startup: StartupNonceHolder;
}>;

export type ControlSeams = Readonly<{
  randomBytes: typeof randomBytes;
  identity: (pid: number) => string | null | undefined;
  parentPid?: number;
  afterExclusiveOpen?: (path: string) => void | Promise<void>;
  afterExclusiveWrite?: (path: string) => void | Promise<void>;
  tempName?: () => string;
}>;

const workerVersion = "cogs.dev-launcher-worker/v1alpha1" as const;
const tokenFile = "api-token";
const workerFile = "worker.json";
const fileMode = 0o600;
const digestPattern = /^sha256:[a-f0-9]{64}$/u;
const tokenPattern = /^[A-Za-z0-9_-]{43}\n$/u;
const defaultRandomBytes = Object.freeze((size: number) => randomBytes(size)) as typeof randomBytes;
const defaultIdentity = observeProcessIdentity;

export async function createApiToken(state: LauncherState, seams?: Partial<ControlSeams>): Promise<void> {
  let raw: Buffer | undefined;
  try {
    const capturedSeams = captureSeams(seams);
    raw = capturedSeams.randomBytes(32);
    if (!Buffer.isBuffer(raw) || raw.length !== 32 || raw.every((byte) => byte === 0)) fail();
    await writeExclusive(state, tokenFile, `${raw.toString("base64url")}\n`, capturedSeams);
  } catch {
    throw generic();
  } finally {
    raw?.fill(0);
  }
}

export async function readApiToken(state: LauncherState): Promise<ApiTokenHolder> {
  let token = "";
  try {
    const text = await readOwnedFile(state, tokenFile, 128);
    if (!tokenPattern.test(text)) fail();
    const decoded = Buffer.from(text.trim(), "base64url");
    try {
      if (decoded.length !== 32 || decoded.every((byte) => byte === 0)) fail();
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

export async function beginWorkerStartup(state: LauncherState, seams?: Partial<ControlSeams>): Promise<WorkerStartup> {
  let nonce: Buffer | undefined;
  let startup: StartupNonceHolder | undefined;
  try {
    const manifest = await readManifest(state);
    if (manifest.phase !== "sandbox-ready") fail();
    await validateControlDir(state);
    const capturedSeams = captureSeams(seams);
    const parentPid = capturedSeams.parentPid ?? process.pid;
    const parentPidIdentity = observedDigest(capturedSeams.identity(parentPid));
    nonce = capturedSeams.randomBytes(32);
    if (!Buffer.isBuffer(nonce) || nonce.length !== 32 || nonce.every((byte) => byte === 0)) fail();
    startup = startupHolder(nonce);
    const descriptor = descriptorFor(state, {
      stateId: state.stateId,
      sourceRevision: manifest.sourceRevision,
      profile: manifest.profile,
      authority: authorityFor(manifest.profile),
      readiness: "starting",
      stage: "pre-spawn",
      startupDigest: startup.digest(),
      parentPid,
      parentPidIdentity,
    });
    await writeExclusive(state, workerFile, canonicalJson(descriptor), capturedSeams);
    return Object.freeze({
      descriptor: descriptor as PreSpawnWorkerDescriptor,
      startup,
    });
  } catch {
    startup?.dispose();
    nonce?.fill(0);
    throw generic();
  }
}

export async function requireSessionControlsAbsent(state: LauncherState): Promise<void> {
  try {
    const manifest = await readManifest(state);
    if (manifest.phase === "worker-ready") fail();
    await validateControlDir(state);
    await validateSandboxDir(state);
    const firstEntries = await readdir(state.controlDir);
    if (!onlySandboxEntry(firstEntries)) fail();
    if (await ownedStat(state, workerFile, false)) fail();
    if (await ownedStat(state, tokenFile, false)) fail();
    const secondEntries = await readdir(state.controlDir);
    if (!onlySandboxEntry(secondEntries)) fail();
  } catch {
    throw generic();
  }
}

export async function bindWorkerChild(
  state: LauncherState,
  hello: unknown,
  seams?: Partial<ControlSeams>,
): Promise<StartingWorkerDescriptor> {
  try {
    const capturedSeams = captureSeams(seams);
    const parsedHello = parseChildIdentityHello(hello);
    const current = await readWorkerDescriptor(state);
    if (current.readiness !== "starting" || current.stage !== "pre-spawn") fail();
    if (parsedHello.startupDigest !== current.startupDigest) fail();
    if (parsedHello.pid === current.parentPid) fail();
    if (parsedHello.pidIdentity !== observedDigest(capturedSeams.identity(parsedHello.pid))) fail();
    const next = descriptorFor(state, {
      stateId: current.stateId,
      sourceRevision: current.sourceRevision,
      profile: current.profile,
      authority: current.authority,
      readiness: "starting",
      stage: "child-bound",
      startupDigest: current.startupDigest,
      parentPid: current.parentPid,
      parentPidIdentity: current.parentPidIdentity,
      childPid: parsedHello.pid,
      childPidIdentity: parsedHello.pidIdentity,
    });
    await replaceWorkerDescriptor(state, current, next, capturedSeams);
    return next as StartingWorkerDescriptor;
  } catch {
    throw generic();
  }
}

export async function promoteWorkerReady(
  state: LauncherState,
  ready: unknown,
  seams?: Partial<ControlSeams>,
): Promise<ReadyWorkerDescriptor> {
  let manifestPromoted = false;
  try {
    const capturedSeams = captureSeams(seams);
    const parsedReady = parseChildReady(ready);
    const current = await readWorkerDescriptor(state);
    if (current.readiness !== "starting" || current.stage !== "child-bound") fail();
    if (parsedReady.startupDigest !== current.startupDigest) fail();
    if (parsedReady.pid !== current.childPid || parsedReady.pidIdentity !== current.childPidIdentity) fail();
    if (parsedReady.pidIdentity !== observedDigest(capturedSeams.identity(parsedReady.pid))) fail();
    const manifest = await readManifest(state);
    if (manifest.phase !== "sandbox-ready") fail();
    await writePhase(state, manifest, "worker-ready");
    manifestPromoted = true;
    const next = descriptorFor(state, {
      stateId: current.stateId,
      sourceRevision: current.sourceRevision,
      profile: current.profile,
      authority: current.authority,
      readiness: "ready",
      stage: "ready",
      startupDigest: current.startupDigest,
      parentPid: current.parentPid,
      parentPidIdentity: current.parentPidIdentity,
      childPid: current.childPid,
      childPidIdentity: current.childPidIdentity,
      apiPort: parsedReady.apiPort,
    });
    await replaceWorkerDescriptor(state, current, next, capturedSeams);
    return next as ReadyWorkerDescriptor;
  } catch {
    if (manifestPromoted) throw generic();
    throw generic();
  }
}

export async function readWorkerDescriptor(state: LauncherState): Promise<WorkerDescriptor> {
  try {
    const manifest = await readManifest(state);
    return parseWorker(await readOwnedFile(state, workerFile, 4096), state, manifest.sourceRevision, manifest.profile);
  } catch {
    throw generic();
  }
}

export async function readReadyWorkerDescriptor(state: LauncherState): Promise<ReadyWorkerDescriptor> {
  try {
    const manifest = await readManifest(state);
    if (manifest.phase !== "worker-ready") fail();
    const descriptor = await readWorkerDescriptor(state);
    if (descriptor.readiness !== "ready" || descriptor.stage !== "ready") fail();
    return descriptor;
  } catch {
    throw generic();
  }
}

export async function verifyWorkerIdentity(state: LauncherState, seams?: Partial<ControlSeams>): Promise<boolean> {
  try {
    const capturedSeams = captureSeams(seams);
    const descriptor = await readWorkerDescriptor(state);
    const identity = identityForCleanup(descriptor);
    const observed = capturedSeams.identity(identity.pid);
    if (observed === null) return false;
    if (observed === undefined || !digestPattern.test(observed) || observed !== identity.pidIdentity) fail();
    return true;
  } catch {
    throw generic();
  }
}

export async function cleanupControlFiles(state: LauncherState, seams?: Partial<ControlSeams>): Promise<void> {
  try {
    const manifest = await readManifest(state);
    const capturedSeams = captureSeams(seams);
    const entries = await readdir(state.controlDir);
    const allowedTempPrefix = `.worker-${state.stateId}-`;
    if (entries.some((entry) => entry !== "sandbox" && entry !== tokenFile && entry !== workerFile)) fail();
    await validateSandboxDir(state);
    const token = await ownedStat(state, tokenFile, false);
    const worker = await ownedStat(state, workerFile, false);
    if (token) {
      const holder = await readApiToken(state);
      holder.dispose();
    }
    if (worker) {
      let descriptor: WorkerDescriptor;
      try {
        descriptor = await readWorkerDescriptor(state);
      } catch {
        if (manifest.phase === "worker-ready") fail();
        throw generic();
      }
      if (manifest.phase === "worker-ready" && descriptor.readiness !== "ready") fail();
      const identity = identityForCleanup(descriptor);
      const observed = capturedSeams.identity(identity.pid);
      if (observed === undefined || (observed !== null && !digestPattern.test(observed))) fail();
      if (observed === identity.pidIdentity) fail();
    } else if (manifest.phase === "worker-ready") {
      fail();
    }
    if (entries.some((entry) => entry.startsWith(allowedTempPrefix))) fail();
    if (token) await unlinkExact(controlPath(state, tokenFile), token);
    if (worker) await unlinkExact(controlPath(state, workerFile), worker);
    await fsyncDir(state.controlDir);
    if ((await ownedStat(state, tokenFile, false)) || (await ownedStat(state, workerFile, false))) fail();
  } catch {
    throw generic();
  }
}

function startupHolder(nonce: Buffer): StartupNonceHolder {
  let secret = Buffer.from(nonce);
  nonce.fill(0);
  const digestValue = `sha256:${createHash("sha256").update(secret).digest("hex")}` as `sha256:${string}`;
  return Object.freeze({
    digest: Object.freeze(() => {
      if (secret.length === 0) throw generic();
      return digestValue;
    }),
    withNonce: Object.freeze(<T>(operation: (nonce: string) => T): T => {
      if (secret.length === 0) throw generic();
      return operation(secret.toString("base64url"));
    }),
    dispose: Object.freeze(() => {
      secret.fill(0);
      secret = Buffer.alloc(0);
    }),
  });
}

function descriptorFor(state: Pick<LauncherState, "stateId">, input: unknown): WorkerDescriptor {
  const base = exactOpen(input);
  const readiness = base.readiness;
  const stage = base.stage;
  const commonKeys = [
    "authority",
    "parentPid",
    "parentPidIdentity",
    "profile",
    "readiness",
    "sourceRevision",
    "stage",
    "startupDigest",
    "stateId",
  ];
  const keys =
    readiness === "starting" && stage === "pre-spawn"
      ? commonKeys
      : readiness === "starting" && stage === "child-bound"
        ? [...commonKeys, "childPid", "childPidIdentity"]
        : readiness === "ready" && stage === "ready"
          ? [...commonKeys, "apiPort", "childPid", "childPidIdentity"]
          : [];
  if (keys.length === 0 || Object.keys(base).sort().join(",") !== keys.sort().join(",")) fail();
  if (base.stateId !== state.stateId) fail();
  const profile = profileValue(base.profile);
  const authority = authorityFor(profile);
  if (base.authority !== authority) fail();
  const common = {
    version: workerVersion,
    stateId: state.stateId,
    sourceRevision: sourceRevision(base.sourceRevision),
    profile,
    authority,
    startupDigest: digest(base.startupDigest),
    parentPid: pid(base.parentPid),
    parentPidIdentity: digest(base.parentPidIdentity),
  };
  if (readiness === "starting" && stage === "pre-spawn") {
    return Object.freeze({ ...common, readiness: "starting" as const, stage: "pre-spawn" as const });
  }
  const childPid = pid(base.childPid);
  const childPidIdentity = digest(base.childPidIdentity);
  if (readiness === "starting" && stage === "child-bound") {
    return Object.freeze({
      ...common,
      readiness: "starting" as const,
      stage: "child-bound" as const,
      childPid,
      childPidIdentity,
    });
  }
  return Object.freeze({
    ...common,
    readiness: "ready" as const,
    stage: "ready" as const,
    childPid,
    childPidIdentity,
    apiPort: port(base.apiPort),
  });
}

function parseWorker(
  text: string,
  state: Pick<LauncherState, "stateId">,
  source: string,
  profile: LauncherProfile,
): WorkerDescriptor {
  if (text.length > 4096) fail();
  const parsed = JSON.parse(text);
  const all = exactOpen(parsed);
  if (all.version !== workerVersion) fail();
  const { version: _version, ...withoutVersion } = all;
  const descriptor = descriptorFor(state, Object.freeze(withoutVersion));
  if (descriptor.sourceRevision !== source || descriptor.profile !== profile) fail();
  if (canonicalJson(descriptor) !== text) fail();
  return descriptor;
}

async function replaceWorkerDescriptor(
  state: LauncherState,
  oldDescriptor: WorkerDescriptor,
  nextDescriptor: WorkerDescriptor,
  seams: Pick<ControlSeams, "afterExclusiveOpen" | "afterExclusiveWrite" | "tempName"> = {},
): Promise<void> {
  await validateControlDir(state);
  const currentStat = await ownedStat(state, workerFile, true);
  if (!currentStat) fail();
  const currentText = await readOwnedFile(state, workerFile, 4096);
  if (currentText !== canonicalJson(oldDescriptor)) fail();
  const tempName = seams.tempName?.() ?? `.worker-${state.stateId}-${randomBytes(16).toString("hex")}.tmp`;
  if (
    basename(tempName) !== tempName ||
    !tempName.startsWith(`.worker-${state.stateId}-`) ||
    !tempName.endsWith(".tmp")
  )
    fail();
  const tempPath = controlPath(state, tempName);
  await writeExclusiveNamed(state, tempName, canonicalJson(nextDescriptor), seams);
  const beforeRename = await ownedStat(state, workerFile, true);
  if (!beforeRename || !sameFile(currentStat, beforeRename)) fail();
  await rename(tempPath, controlPath(state, workerFile));
  await fsyncDir(state.controlDir);
  const after = await ownedStat(state, workerFile, true);
  if (after?.nlink !== 1 || (await readOwnedFile(state, workerFile, 4096)) !== canonicalJson(nextDescriptor)) fail();
}

async function writeExclusive(
  state: LauncherState,
  name: string,
  text: string,
  seams: Pick<ControlSeams, "afterExclusiveOpen" | "afterExclusiveWrite"> = {},
): Promise<void> {
  await writeExclusiveNamed(state, name, text, seams, true);
}

async function writeExclusiveNamed(
  state: LauncherState,
  name: string,
  text: string,
  seams: Pick<ControlSeams, "afterExclusiveOpen" | "afterExclusiveWrite"> = {},
  removeOnFailure = false,
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
    if (!sameFile(opened, stat) || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== fileMode) fail();
    if (
      stat.size !== Buffer.byteLength(text) ||
      (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
    )
      fail();
    await handle.close();
    closed = true;
    await fsyncDir(state.controlDir);
    const final = await ownedStat(state, name, true);
    if (!final || !sameFile(final, stat)) fail();
  } catch (error) {
    if (!closed) await handle.close().catch(() => undefined);
    if (removeOnFailure && owned) await unlinkIfExact(path, owned).catch(() => undefined);
    throw error;
  }
}

async function readOwnedFile(state: LauncherState, name: string, maxBytes: number): Promise<string> {
  const stat = await ownedStat(state, name, true);
  if (!stat || stat.size < 1 || stat.size > maxBytes) fail();
  const file = await open(controlPath(state, name), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await file.stat();
    if (!sameFile(stat, opened)) fail();
    const bytes = await file.readFile();
    const after = await file.stat();
    if (!sameFile(opened, after) || after.size !== bytes.length) fail();
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally {
    await file.close();
  }
}

async function ownedStat(state: LauncherState, name: string, required: boolean) {
  await validateControlDir(state);
  const path = controlPath(state, name);
  let stat: Awaited<ReturnType<typeof lstat>>;
  try {
    stat = await lstat(path);
  } catch (error) {
    if (!required && (error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== fileMode ||
    (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) ||
    (await realpath(path)) !== path
  ) {
    fail();
  }
  return stat;
}

async function validateControlDir(state: LauncherState): Promise<void> {
  await readManifest(state);
  const stat = await lstat(state.controlDir);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== 0o700 ||
    (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) ||
    (await realpath(state.controlDir)) !== state.controlDir
  ) {
    fail();
  }
}

async function validateSandboxDir(state: LauncherState): Promise<void> {
  const stat = await lstat(state.sandboxDir);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== 0o700 ||
    (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) ||
    (await realpath(state.sandboxDir)) !== state.sandboxDir
  ) {
    fail();
  }
}

async function fsyncDir(path: string): Promise<void> {
  const file = await open(path, constants.O_RDONLY);
  try {
    await file.sync();
  } finally {
    await file.close();
  }
}

async function unlinkExact(path: string, stat: { dev: number; ino: number }): Promise<void> {
  await unlinkIfExact(path, stat);
  try {
    await lstat(path);
    fail();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function unlinkIfExact(path: string, stat: { dev: number; ino: number }): Promise<void> {
  const current = await lstat(path);
  if (current.dev !== stat.dev || current.ino !== stat.ino || !current.isFile() || current.nlink !== 1) fail();
  await unlink(path);
}

function captureSeams(seams?: Partial<ControlSeams>): ControlSeams {
  if (seams === undefined) {
    return Object.freeze({ randomBytes: defaultRandomBytes, identity: defaultIdentity });
  }
  if (!seams || typeof seams !== "object" || Object.getPrototypeOf(seams) !== Object.prototype) fail();
  if (Object.getOwnPropertySymbols(seams).length !== 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(seams);
  const allowed = ["afterExclusiveOpen", "afterExclusiveWrite", "identity", "parentPid", "randomBytes", "tempName"];
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string" || !allowed.includes(key)) fail();
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  const randomValue = descriptors.randomBytes?.value ?? defaultRandomBytes;
  const identityValue = descriptors.identity?.value ?? defaultIdentity;
  if (typeof randomValue !== "function" || typeof identityValue !== "function") fail();
  const parentPid = descriptors.parentPid?.value;
  if (parentPid !== undefined) pid(parentPid);
  return Object.freeze({
    randomBytes: randomValue,
    identity: identityValue,
    ...(parentPid === undefined ? {} : { parentPid: parentPid as number }),
    ...(descriptors.afterExclusiveOpen === undefined
      ? {}
      : { afterExclusiveOpen: descriptors.afterExclusiveOpen.value }),
    ...(descriptors.afterExclusiveWrite === undefined
      ? {}
      : { afterExclusiveWrite: descriptors.afterExclusiveWrite.value }),
    ...(descriptors.tempName === undefined ? {} : { tempName: descriptors.tempName.value }),
  });
}

function onlySandboxEntry(entries: readonly string[]): boolean {
  return entries.length === 1 && entries[0] === "sandbox";
}

function identityForCleanup(descriptor: WorkerDescriptor): { pid: number; pidIdentity: string } {
  if (descriptor.readiness === "starting" && descriptor.stage === "pre-spawn") {
    return { pid: descriptor.parentPid, pidIdentity: descriptor.parentPidIdentity };
  }
  return { pid: descriptor.childPid, pidIdentity: descriptor.childPidIdentity };
}

function exactOpen(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  if (Object.getOwnPropertySymbols(value).length !== 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const output: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail();
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    output[key] = descriptor.value;
  }
  return output;
}

function authorityFor(profile: LauncherProfile): LauncherAuthority {
  return profile === "linux-kvm" ? "authoritative-local" : "functional-only";
}

function profileValue(value: unknown): LauncherProfile {
  if (value !== "insecure-container" && value !== "linux-kvm" && value !== "macos-vm") fail();
  return value;
}

function digest(value: unknown): `sha256:${string}` {
  if (typeof value !== "string" || !digestPattern.test(value)) fail();
  return value as `sha256:${string}`;
}

function observedDigest(value: string | null | undefined): `sha256:${string}` {
  if (value === null || value === undefined) fail();
  return digest(value);
}

function sourceRevision(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/u.test(value)) fail();
  return value;
}

function pid(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 2 ** 31 - 1) fail();
  return value as number;
}

function port(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 65535) fail();
  return value as number;
}

function sameFile(a: { dev: number; ino: number }, b: { dev: number; ino: number }): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function controlPath(state: LauncherState, name: string): string {
  if (basename(name) !== name || name.includes("/")) fail();
  return join(state.controlDir, name);
}

function fail(): never {
  throw generic();
}

function generic(): Error {
  return new Error("launcher control failed");
}
