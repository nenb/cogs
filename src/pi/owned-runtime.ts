import { constants } from "node:fs";
import { lstat, open, readdir, realpath, rmdir, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

export interface CogsPiOwnedRuntimeOptions {
  readonly enabled: true;
  readonly requireEmptyRoots: true;
  readonly cleanupDeadlineMs?: number;
}

export interface CogsPiOwnedRuntimeCleanupResult {
  readonly version: "cogs.pi-owned-runtime-cleanup/v1alpha1";
  readonly cleaned: true;
}

export class CogsPiOwnedRuntimeError extends Error {
  public constructor() {
    super("Pi owned runtime cleanup failed");
    this.name = "CogsPiOwnedRuntimeError";
  }
}

type Kind = "file" | "dir";

type Mark = {
  readonly path: string;
  readonly dev: bigint;
  readonly ino: bigint;
  readonly uid: bigint;
  readonly mode: number;
  readonly nlink: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
  readonly kind: Kind;
};

export interface InternalCogsPiOwnedMarker {
  readonly path: string;
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: number;
  readonly nlink: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
  readonly kind: "file" | "dir";
}

export interface InternalCogsPiOwnedExportLedger {
  readonly root: InternalCogsPiOwnedMarker;
  readonly bundleDir: InternalCogsPiOwnedMarker;
  readonly files: readonly InternalCogsPiOwnedMarker[];
}

export interface CogsPiOwnedRuntimeTracker {
  readonly enabled: true;
  readonly begin: () => Promise<void>;
  readonly adoptSessionDir: (path: string) => Promise<void>;
  readonly recordSessionFile: (marker: InternalCogsPiOwnedMarker | undefined) => Promise<void>;
  readonly recordGitMapFile: (marker: InternalCogsPiOwnedMarker) => Promise<void>;
  readonly verifyExportTransition: (ledger: InternalCogsPiOwnedExportLedger) => Promise<void>;
  readonly recordExportBundle: (ledger: InternalCogsPiOwnedExportLedger) => Promise<void>;
  readonly cleanup: (dispose: (deadlineExpiresAt: number) => Promise<void>) => Promise<CogsPiOwnedRuntimeCleanupResult>;
}

const DEFAULT_DEADLINE_MS = 10_000;
const EXPORT_FILES = new Set([
  "git-map.json",
  "manifest.json",
  "session.jsonl",
  "skills.json",
  "transform-report.json",
  "warnings.json",
]);

export function snapshotCogsPiOwnedRuntimeOptions(value: unknown): CogsPiOwnedRuntimeOptions | undefined {
  if (value === undefined) return undefined;
  try {
    if (value === null || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
      throw new Error("invalid owned runtime");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const allowed = new Set(["enabled", "requireEmptyRoots", "cleanupDeadlineMs"]);
    if (!keys.every((key) => typeof key === "string" && allowed.has(key))) throw new Error("invalid owned runtime");
    const enabled = data(descriptors, "enabled");
    const requireEmptyRoots = data(descriptors, "requireEmptyRoots");
    const cleanupDeadlineMs = data(descriptors, "cleanupDeadlineMs");
    if (enabled !== true) throw new Error("invalid owned runtime");
    if (requireEmptyRoots !== true) throw new Error("invalid owned runtime");
    if (cleanupDeadlineMs !== undefined) {
      if (
        typeof cleanupDeadlineMs !== "number" ||
        !Number.isInteger(cleanupDeadlineMs) ||
        cleanupDeadlineMs < 100 ||
        cleanupDeadlineMs > 60_000
      )
        throw new Error("invalid owned runtime");
    }
    return Object.freeze({
      enabled: true,
      requireEmptyRoots: true as const,
      ...(cleanupDeadlineMs === undefined ? {} : { cleanupDeadlineMs: cleanupDeadlineMs as number }),
    });
  } catch {
    throw new CogsPiOwnedRuntimeError();
  }
}

export function createCogsPiOwnedRuntimeTracker(input: {
  readonly agentDir: string;
  readonly sessionRoot: string;
  readonly sessionId: string;
  readonly options: CogsPiOwnedRuntimeOptions;
  readonly resumeFile?: string;
  readonly testHook?: { readonly after: (stage: string) => void | Promise<void> };
}): CogsPiOwnedRuntimeTracker {
  const agentDir = resolve(input.agentDir);
  const sessionRoot = resolve(input.sessionRoot);
  const sessionDir = resolve(sessionRoot, input.sessionId);
  const resumeFile = input.resumeFile;
  const deadlineMs = input.options.cleanupDeadlineMs ?? DEFAULT_DEADLINE_MS;
  let agentMark: Mark | undefined;
  let rootMark: Mark | undefined;
  let sessionDirMark: Mark | undefined;
  let sessionFileMark: Mark | undefined;
  let gitMapMark: Mark | undefined;
  let exportRootMark: Mark | undefined;
  let exportBundleMark: Mark | undefined;
  const exportFileMarks = new Map<string, Mark>();
  const after = snapshotTestHook(input.testHook);
  let cleanupPromise: Promise<CogsPiOwnedRuntimeCleanupResult> | undefined;

  const tracker = Object.freeze({
    enabled: true as const,
    begin: async () => {
      agentMark = await markExistingDir(agentDir, 0o700);
      rootMark = await markExistingDir(sessionRoot, 0o700);
      await requireNames(agentDir, [], agentMark);
      if (resumeFile === undefined) {
        await requireNames(sessionRoot, [], rootMark);
        return;
      }
      if (resumeFile !== basename(resumeFile) || !resumeFile.endsWith(".jsonl")) throw new CogsPiOwnedRuntimeError();
      await requireNames(sessionRoot, [basename(sessionDir)], rootMark);
      sessionDirMark = await markExistingDir(sessionDir, 0o700);
      await requireNames(sessionDir, [resumeFile], sessionDirMark);
      sessionFileMark = await markExistingFile(join(sessionDir, resumeFile));
      if (sessionFileMark.mode !== 0o644) throw new CogsPiOwnedRuntimeError();
    },
    adoptSessionDir: async (path: string) => {
      const real = await realpath(path).catch(() => {
        throw new CogsPiOwnedRuntimeError();
      });
      if (real !== sessionDir) throw new CogsPiOwnedRuntimeError();
      sessionDirMark = await markExistingDir(real, 0o700);
      rootMark = await markExistingDir(sessionRoot, 0o700);
      await requireNames(sessionRoot, [basename(sessionDir)], rootMark);
    },
    recordSessionFile: async (owner: InternalCogsPiOwnedMarker | undefined) => {
      if (owner === undefined) return;
      const resolved = resolve(owner.path);
      if (resolved !== join(sessionDir, basename(resolved)) || !resolved.endsWith(".jsonl"))
        throw new CogsPiOwnedRuntimeError();
      const mark = await markOwnedFile(owner, 0o644);
      if (sessionFileMark === undefined) sessionFileMark = mark;
      else sessionFileMark = growMark(mark, sessionFileMark);
      sessionDirMark = await markExistingDir(sessionDir, 0o700);
      await requireNames(sessionDir, knownSessionNames(sessionFileMark, gitMapMark, exportRootMark), sessionDirMark);
    },
    recordGitMapFile: async (owner: InternalCogsPiOwnedMarker) => {
      const resolved = resolve(owner.path);
      if (resolved !== join(sessionDir, "git-map.jsonl")) throw new CogsPiOwnedRuntimeError();
      const mark = await markOwnedFile(owner, 0o600);
      if (gitMapMark === undefined) gitMapMark = mark;
      else gitMapMark = growMark(mark, gitMapMark);
      sessionDirMark = await markExistingDir(sessionDir, 0o700);
      await requireNames(sessionDir, knownSessionNames(sessionFileMark, gitMapMark, exportRootMark), sessionDirMark);
    },
    verifyExportTransition: async (ledger: InternalCogsPiOwnedExportLedger) => {
      if (exportRootMark === undefined || exportBundleMark === undefined || exportFileMarks.size !== EXPORT_FILES.size)
        throw new CogsPiOwnedRuntimeError();
      const observedRoot = markOwnedDir(ledger.root, 0o700, await markExistingDir(ledger.root.path, 0o700));
      const observedBundle = markOwnedDir(ledger.bundleDir, 0o700, await markExistingDir(ledger.bundleDir.path, 0o700));
      sameIdentity(observedRoot, exportRootMark);
      sameMark(observedBundle, exportBundleMark);
      for (const file of ledger.files) {
        const expected = exportFileMarks.get(basename(file.path));
        if (expected === undefined) throw new CogsPiOwnedRuntimeError();
        sameMark(await markOwnedFile(file, 0o600), expected);
      }
    },
    recordExportBundle: async (ledger: InternalCogsPiOwnedExportLedger) => {
      const root = resolve(ledger.root.path);
      const bundle = resolve(ledger.bundleDir.path);
      if (root !== join(sessionDir, "exports") || dirname(bundle) !== root) throw new CogsPiOwnedRuntimeError();
      if (!/^cogs-session-[A-Za-z0-9._:-]{1,128}$/.test(basename(bundle))) throw new CogsPiOwnedRuntimeError();
      const names = ledger.files.map((file) => basename(resolve(file.path))).sort();
      if (names.length !== EXPORT_FILES.size || !names.every((name) => EXPORT_FILES.has(name)))
        throw new CogsPiOwnedRuntimeError();
      exportRootMark = markOwnedDir(ledger.root, 0o700, await markExistingDir(root, 0o700));
      exportBundleMark = markOwnedDir(ledger.bundleDir, 0o700, await markExistingDir(bundle, 0o700));
      const next = new Map<string, Mark>();
      for (const file of ledger.files) {
        const resolved = resolve(file.path);
        if (dirname(resolved) !== bundle || !EXPORT_FILES.has(basename(resolved))) throw new CogsPiOwnedRuntimeError();
        next.set(basename(resolved), await markOwnedFile(file, 0o600));
      }
      exportFileMarks.clear();
      for (const [name, mark] of next) exportFileMarks.set(name, mark);
      await requireNames(bundle, [...exportFileMarks.keys()], exportBundleMark);
      await requireNames(root, [basename(bundle)], exportRootMark);
      sessionDirMark = await markExistingDir(sessionDir, 0o700);
    },
    cleanup: (dispose: (deadlineExpiresAt: number) => Promise<void>) => {
      cleanupPromise ??= cleanupWithDeadline(deadlineMs, async (deadline) => {
        try {
          await dispose(deadline.expiresAt);
          await removeOwned(deadline, after, {
            agentDir,
            sessionRoot,
            sessionDir,
            agentMark,
            rootMark,
            sessionDirMark,
            sessionFileMark,
            gitMapMark,
            exportRootMark,
            exportBundleMark,
            exportFileMarks: new Map(exportFileMarks),
          });
          return Object.freeze({ version: "cogs.pi-owned-runtime-cleanup/v1alpha1", cleaned: true as const });
        } catch {
          throw new CogsPiOwnedRuntimeError();
        }
      });
      return cleanupPromise;
    },
  });
  return tracker;
}

async function removeOwned(
  deadline: Deadline,
  after: TestAfter | undefined,
  input: {
    readonly agentDir: string;
    readonly sessionRoot: string;
    readonly sessionDir: string;
    readonly agentMark: Mark | undefined;
    readonly rootMark: Mark | undefined;
    readonly sessionDirMark: Mark | undefined;
    readonly sessionFileMark: Mark | undefined;
    readonly gitMapMark: Mark | undefined;
    readonly exportRootMark: Mark | undefined;
    readonly exportBundleMark: Mark | undefined;
    readonly exportFileMarks: ReadonlyMap<string, Mark>;
  },
): Promise<void> {
  const plan = await preflight(deadline, after, input);
  for (const file of plan.files) await removeFile(deadline, after, file);
  for (const dir of plan.dirs) await removeDir(deadline, after, dir);
}

async function preflight(
  deadline: Deadline,
  after: TestAfter | undefined,
  input: {
    readonly agentDir: string;
    readonly sessionRoot: string;
    readonly sessionDir: string;
    readonly agentMark: Mark | undefined;
    readonly rootMark: Mark | undefined;
    readonly sessionDirMark: Mark | undefined;
    readonly sessionFileMark: Mark | undefined;
    readonly gitMapMark: Mark | undefined;
    readonly exportRootMark: Mark | undefined;
    readonly exportBundleMark: Mark | undefined;
    readonly exportFileMarks: ReadonlyMap<string, Mark>;
  },
): Promise<{ readonly files: Mark[]; readonly dirs: Mark[] }> {
  await stage(deadline, after, "preflight:start");
  if (input.agentMark === undefined || input.rootMark === undefined) throw new CogsPiOwnedRuntimeError();
  sameMark(await markExistingDir(input.agentDir, 0o700, deadline, after), input.agentMark);
  checkDeadline(deadline);
  sameMark(await markExistingDir(input.sessionRoot, 0o700, deadline, after), input.rootMark);
  checkDeadline(deadline);
  const files: Mark[] = [];
  const dirs: Mark[] = [];
  const agentNames: string[] = [];
  const sessionRootNames: string[] = [];
  const sessionDirNames: string[] = [];

  if (input.sessionDirMark !== undefined) {
    sameMark(await markExistingDir(input.sessionDir, 0o700, deadline, after), input.sessionDirMark);
    checkDeadline(deadline);
    sessionRootNames.push(basename(input.sessionDir));
    dirs.push(input.sessionDirMark);
    if (input.sessionFileMark !== undefined) {
      sameMark(await markExistingFile(input.sessionFileMark.path, deadline, after), input.sessionFileMark);
      checkDeadline(deadline);
      sessionDirNames.push(basename(input.sessionFileMark.path));
      files.push(input.sessionFileMark);
    }
    if (input.gitMapMark !== undefined) {
      sameMark(await markExistingFile(input.gitMapMark.path, deadline, after), input.gitMapMark);
      checkDeadline(deadline);
      sessionDirNames.push(basename(input.gitMapMark.path));
      files.push(input.gitMapMark);
    }
    if (input.exportRootMark !== undefined) {
      if (input.exportBundleMark === undefined || input.exportFileMarks.size !== EXPORT_FILES.size)
        throw new CogsPiOwnedRuntimeError();
      sameMark(await markExistingDir(input.exportRootMark.path, 0o700, deadline, after), input.exportRootMark);
      checkDeadline(deadline);
      sameMark(await markExistingDir(input.exportBundleMark.path, 0o700, deadline, after), input.exportBundleMark);
      checkDeadline(deadline);
      sessionDirNames.push(basename(input.exportRootMark.path));
      dirs.push(input.exportBundleMark, input.exportRootMark);
      const bundleNames: string[] = [];
      for (const [name, mark] of input.exportFileMarks) {
        if (
          !EXPORT_FILES.has(name) ||
          basename(mark.path) !== name ||
          dirname(mark.path) !== input.exportBundleMark.path
        )
          throw new CogsPiOwnedRuntimeError();
        sameMark(await markExistingFile(mark.path, deadline, after), mark);
        checkDeadline(deadline);
        bundleNames.push(name);
        files.push(mark);
      }
      await requireNames(input.exportBundleMark.path, bundleNames, input.exportBundleMark, deadline, after);
      await requireNames(
        input.exportRootMark.path,
        [basename(input.exportBundleMark.path)],
        input.exportRootMark,
        deadline,
        after,
      );
    }
    await requireNames(input.sessionDir, sessionDirNames, input.sessionDirMark, deadline, after);
    checkDeadline(deadline);
  }
  dirs.push(input.rootMark, input.agentMark);
  await requireNames(input.sessionRoot, sessionRootNames, input.rootMark, deadline, after);
  checkDeadline(deadline);
  await requireNames(input.agentDir, agentNames, input.agentMark, deadline, after);
  checkDeadline(deadline);
  await stage(deadline, after, "preflight:done");
  return { files: files.reverse(), dirs: dirs.sort((left, right) => right.path.length - left.path.length) };
}

async function removeFile(deadline: Deadline, after: TestAfter | undefined, expected: Mark): Promise<void> {
  checkDeadline(deadline);
  const parent = await markExistingDir(dirname(expected.path), 0o700, deadline, after);
  sameMark(await markExistingFile(expected.path, deadline, after), expected);
  checkDeadline(deadline);
  sameIdentity(await markExistingDir(dirname(expected.path), 0o700, deadline, after), parent);
  sameMark(await markExistingFile(expected.path, deadline, after), expected);
  checkDeadline(deadline);
  await stage(deadline, after, "unlink:before");
  await unlink(expected.path).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  await stage(deadline, after, "unlink:after");
  await syncDir(parent.path, parent, deadline, after);
  await requireAbsent(expected.path);
  sameIdentity(await markExistingDir(parent.path, 0o700, deadline, after), parent);
}

async function removeDir(deadline: Deadline, after: TestAfter | undefined, expected: Mark): Promise<void> {
  checkDeadline(deadline);
  const parent = await markExistingDir(dirname(expected.path), 0o700, deadline, after);
  sameIdentity(await markExistingDir(expected.path, 0o700, deadline, after), expected);
  await requireNames(expected.path, [], undefined, deadline, after);
  sameIdentity(await markExistingDir(expected.path, 0o700, deadline, after), expected);
  checkDeadline(deadline);
  sameIdentity(await markExistingDir(dirname(expected.path), 0o700, deadline, after), parent);
  sameIdentity(await markExistingDir(expected.path, 0o700, deadline, after), expected);
  checkDeadline(deadline);
  await stage(deadline, after, "rmdir:before");
  await rmdir(expected.path).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  await stage(deadline, after, "rmdir:after");
  await syncDir(parent.path, parent, deadline, after);
  await requireAbsent(expected.path);
  sameIdentity(await markExistingDir(parent.path, 0o700, deadline, after), parent);
}

async function markExistingDir(path: string, mode: number, deadline?: Deadline, after?: TestAfter): Promise<Mark> {
  const real = await realpath(path).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  if (real !== resolve(path)) throw new CogsPiOwnedRuntimeError();
  const mark = await markExisting(path, "dir", mode);
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  try {
    sameMark(markFromStat(path, await handle.stat({ bigint: true }), "dir", mode), mark);
  } finally {
    await closeOwnedHandle(handle, deadline, after);
  }
  return mark;
}

async function markExistingFile(path: string, deadline?: Deadline, after?: TestAfter): Promise<Mark> {
  const mark = await markExisting(path, "file", undefined);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  try {
    sameMark(markFromStat(path, await handle.stat({ bigint: true }), "file", undefined), mark);
  } finally {
    await closeOwnedHandle(handle, deadline, after);
  }
  return mark;
}

async function markExisting(path: string, kind: Kind, mode: number | undefined): Promise<Mark> {
  const stat = await lstat(path, { bigint: true }).catch((error) => {
    if ((error as { code?: unknown }).code === "ENOENT") throw error;
    throw new CogsPiOwnedRuntimeError();
  });
  return markFromStat(path, stat, kind, mode);
}

function markFromStat(
  path: string,
  stat: Awaited<ReturnType<typeof lstat>>,
  kind: Kind,
  mode: number | undefined,
): Mark {
  if (stat.isSymbolicLink()) throw new CogsPiOwnedRuntimeError();
  if (kind === "dir" ? !stat.isDirectory() : !stat.isFile()) throw new CogsPiOwnedRuntimeError();
  if (BigInt(stat.uid) !== BigInt(process.getuid?.() ?? -1)) throw new CogsPiOwnedRuntimeError();
  const nlink = BigInt(stat.nlink);
  if (kind === "file" && nlink !== 1n) throw new CogsPiOwnedRuntimeError();
  if (kind === "dir" && nlink < 2n) throw new CogsPiOwnedRuntimeError();
  if (mode !== undefined && (Number(stat.mode) & 0o777) !== mode) throw new CogsPiOwnedRuntimeError();
  return Object.freeze({
    path: resolve(path),
    dev: BigInt(stat.dev),
    ino: BigInt(stat.ino),
    uid: BigInt(stat.uid),
    mode: Number(stat.mode) & 0o777,
    nlink,
    size: BigInt(stat.size),
    mtimeNs: statNs(stat, "mtime"),
    ctimeNs: statNs(stat, "ctime"),
    kind,
  });
}

async function requireNames(
  path: string,
  expected: readonly string[],
  expectedDir: Mark | undefined,
  deadline?: Deadline,
  after?: TestAfter,
): Promise<void> {
  if (expectedDir !== undefined) sameIdentity(await markExistingDir(path, 0o700, deadline, after), expectedDir);
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  try {
    if (expectedDir !== undefined)
      sameIdentity(markFromStat(path, await handle.stat({ bigint: true }), "dir", 0o700), expectedDir);
    const names = (await readdir(path)).sort();
    if (names.join("\0") !== [...expected].sort().join("\0")) throw new CogsPiOwnedRuntimeError();
    if (expectedDir !== undefined)
      sameIdentity(markFromStat(path, await handle.stat({ bigint: true }), "dir", 0o700), expectedDir);
  } catch (error) {
    if (error instanceof CogsPiOwnedRuntimeError) throw error;
    throw new CogsPiOwnedRuntimeError();
  } finally {
    await closeOwnedHandle(handle, deadline, after);
  }
  if (expectedDir !== undefined) sameIdentity(await markExistingDir(path, 0o700, deadline, after), expectedDir);
}

async function markOwnedFile(owner: InternalCogsPiOwnedMarker, expectedMode: 0o600 | 0o644): Promise<Mark> {
  const mark = await markExistingFile(owner.path);
  return markOwned(owner, mark, "file", expectedMode);
}

function markOwnedDir(owner: InternalCogsPiOwnedMarker, expectedMode: 0o700, mark: Mark): Mark {
  return markOwned(owner, mark, "dir", expectedMode);
}

function markOwned(owner: InternalCogsPiOwnedMarker, mark: Mark, kind: Kind, expectedMode: number): Mark {
  if (
    resolve(owner.path) !== mark.path ||
    owner.kind !== kind ||
    owner.dev !== mark.dev ||
    owner.ino !== mark.ino ||
    owner.mode !== mark.mode ||
    owner.nlink !== mark.nlink ||
    BigInt(owner.size) !== mark.size ||
    owner.mtimeNs !== mark.mtimeNs ||
    owner.ctimeNs !== mark.ctimeNs ||
    mark.mode !== expectedMode
  )
    throw new CogsPiOwnedRuntimeError();
  return mark;
}

function knownSessionNames(
  sessionFileMark: Mark | undefined,
  gitMapMark: Mark | undefined,
  exportRootMark: Mark | undefined,
): string[] {
  return [sessionFileMark, gitMapMark, exportRootMark]
    .filter((mark): mark is Mark => mark !== undefined)
    .map((mark) => basename(mark.path));
}

function growMark(actual: Mark, expected: Mark): Mark {
  sameIdentity(actual, expected);
  if (actual.nlink !== expected.nlink || actual.size < expected.size) throw new CogsPiOwnedRuntimeError();
  if (actual.size === expected.size) sameMark(actual, expected);
  return actual;
}

function statNs(stat: Awaited<ReturnType<typeof lstat>>, prefix: "mtime" | "ctime"): bigint {
  const keyed = stat as unknown as Record<string, unknown>;
  const ns = keyed[`${prefix}Ns`];
  if (typeof ns === "bigint") return ns;
  const ms = prefix === "mtime" ? stat.mtimeMs : stat.ctimeMs;
  if (typeof ms === "bigint") return ms * 1_000_000n;
  return BigInt(Math.trunc(Number(ms) * 1_000_000));
}

function sameMark(actual: Mark, expected: Mark): void {
  if (
    actual.path !== expected.path ||
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode ||
    actual.nlink !== expected.nlink ||
    actual.size !== expected.size ||
    actual.mtimeNs !== expected.mtimeNs ||
    actual.ctimeNs !== expected.ctimeNs ||
    actual.kind !== expected.kind
  )
    throw new CogsPiOwnedRuntimeError();
}

async function syncDir(path: string, expected: Mark, deadline: Deadline, after: TestAfter | undefined): Promise<void> {
  sameIdentity(await markExistingDir(path, 0o700, deadline, after), expected);
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW).catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  try {
    sameIdentity(markFromStat(path, await handle.stat({ bigint: true }), "dir", 0o700), expected);
    await stage(deadline, after, "fsync:before");
    await handle.sync();
    await stage(deadline, after, "fsync:after");
  } catch {
    throw new CogsPiOwnedRuntimeError();
  } finally {
    await closeOwnedHandle(handle, deadline, after);
  }
  sameIdentity(await markExistingDir(path, 0o700, deadline, after), expected);
}

function sameIdentity(actual: Mark, expected: Mark): void {
  if (
    actual.path !== expected.path ||
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode ||
    actual.kind !== expected.kind
  )
    throw new CogsPiOwnedRuntimeError();
}

async function closeOwnedHandle(
  handle: Awaited<ReturnType<typeof open>>,
  deadline?: Deadline,
  after?: TestAfter,
): Promise<void> {
  let stageError: unknown;
  if (deadline !== undefined) {
    try {
      await stage(deadline, after, "close:before");
    } catch (error) {
      stageError = error;
    }
  }
  await handle.close().catch(() => {
    throw new CogsPiOwnedRuntimeError();
  });
  if (stageError !== undefined) throw new CogsPiOwnedRuntimeError();
  if (deadline !== undefined) await stage(deadline, after, "close:after");
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as { code?: unknown }).code === "ENOENT") return false;
    throw new CogsPiOwnedRuntimeError();
  }
}

async function requireAbsent(path: string): Promise<void> {
  if (await exists(path)) throw new CogsPiOwnedRuntimeError();
}

function data(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) throw new Error("invalid owned runtime");
  return descriptor.value;
}

type Deadline = { readonly expiresAt: number };
type TestAfter = (stage: string) => void | Promise<void>;

const ASYNC_FUNCTION_PROTOTYPE = Object.getPrototypeOf(async () => undefined);

function snapshotTestHook(hook: { readonly after: TestAfter } | undefined): TestAfter | undefined {
  if (hook === undefined) return undefined;
  try {
    if (hook === null || typeof hook !== "object" || Object.getPrototypeOf(hook) !== Object.prototype)
      throw new CogsPiOwnedRuntimeError();
    if (!Object.isFrozen(hook)) throw new CogsPiOwnedRuntimeError();
    const descriptors = Object.getOwnPropertyDescriptors(hook);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== 1 || keys[0] !== "after") throw new CogsPiOwnedRuntimeError();
    const descriptor = descriptors.after;
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
      throw new CogsPiOwnedRuntimeError();
    const captured = descriptor.value;
    if (typeof captured !== "function" || !Object.isFrozen(captured)) throw new CogsPiOwnedRuntimeError();
    const prototype = Object.getPrototypeOf(captured);
    if (prototype !== Function.prototype && prototype !== ASYNC_FUNCTION_PROTOTYPE) throw new CogsPiOwnedRuntimeError();
    const functionDescriptors = Object.getOwnPropertyDescriptors(captured);
    for (const key of Reflect.ownKeys(functionDescriptors)) {
      if (typeof key !== "string" || !["length", "name"].includes(key)) throw new CogsPiOwnedRuntimeError();
      const functionDescriptor = functionDescriptors[key];
      if (functionDescriptor === undefined || !("value" in functionDescriptor)) throw new CogsPiOwnedRuntimeError();
    }
    if ("then" in captured) throw new CogsPiOwnedRuntimeError();
    return captured as TestAfter;
  } catch {
    throw new CogsPiOwnedRuntimeError();
  }
}

async function stage(deadline: Deadline, after: TestAfter | undefined, name: string): Promise<void> {
  try {
    await after?.(name);
    checkDeadline(deadline);
  } catch {
    throw new CogsPiOwnedRuntimeError();
  }
}

function checkDeadline(deadline: Deadline): void {
  if (Date.now() > deadline.expiresAt) throw new CogsPiOwnedRuntimeError();
}

async function cleanupWithDeadline<T>(ms: number, operation: (deadline: Deadline) => Promise<T>): Promise<T> {
  const deadline = Object.freeze({ expiresAt: Date.now() + ms });
  const result = await operation(deadline);
  checkDeadline(deadline);
  return result;
}
