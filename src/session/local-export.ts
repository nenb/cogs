import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rename, rmdir, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { JsonValue } from "../api/server.ts";
import type { CogsPreparedSkillMetadata } from "../skills/session-preparer.ts";
import type { CogsGitMapRecord, CogsGitMapStore } from "./git-map.ts";
import type { CogsJsonlHistoryStore } from "./jsonl-history.ts";

export class CogsLocalExportError extends Error {
  public readonly code = "COGS_LOCAL_EXPORT_FAILED";
  public constructor() {
    super("local export unavailable");
    this.name = "CogsLocalExportError";
  }
}

export interface CogsLocalExportDescriptor {
  readonly version: "cogs.export-descriptor/v1alpha1";
  readonly bundle: string;
  readonly manifest_sha256: string;
  readonly created_at: string;
  readonly mode: "raw";
  readonly attachments_included: false;
  readonly file_count: number;
  readonly total_bytes: number;
  readonly sensitive: true;
  readonly sanitized: false;
  readonly anonymized: false;
}

export interface CogsLocalExporter {
  readonly createExport: (input?: { readonly signal?: AbortSignal }) => Promise<CogsLocalExportDescriptor>;
  readonly dispose: () => Promise<void>;
}

interface FileEntry {
  readonly path: BundleFile;
  readonly bytes: Buffer;
}

interface BigStats {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly uid: bigint;
  readonly mode: bigint;
  readonly nlink: bigint;
  readonly size: bigint;
  readonly isFile: () => boolean;
  readonly isDirectory: () => boolean;
  readonly isSymbolicLink: () => boolean;
}

interface Marker {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly nlink: bigint;
  readonly size: bigint;
}

interface BundleSnapshot {
  readonly dir: Marker;
  readonly files: ReadonlyMap<BundleFile, Marker>;
}

type BundleFile =
  | "session.jsonl"
  | "git-map.json"
  | "skills.json"
  | "warnings.json"
  | "transform-report.json"
  | "manifest.json";

const EXPORT_ROOT = "exports";
const VERSION = "cogs.export/v1alpha1";
const DESCRIPTOR_VERSION = "cogs.export-descriptor/v1alpha1";
const COGS_VERSION = "0.0.0";
const PI_VERSION = "0.80.6";
const MAX_BUNDLE_BYTES = 72 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const ENTRY = /^[a-f0-9]{8}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const FILES: readonly BundleFile[] = [
  "session.jsonl",
  "git-map.json",
  "skills.json",
  "warnings.json",
  "transform-report.json",
  "manifest.json",
];

export function createCogsLocalExporter(input: {
  readonly sessionDir: string;
  readonly sessionId: string;
  readonly history: CogsJsonlHistoryStore;
  readonly gitMap?: CogsGitMapStore;
  readonly skillMetadata: () => CogsPreparedSkillMetadata | undefined;
  readonly model?: { readonly provider: string; readonly id: string };
}): CogsLocalExporter {
  const config = snapshotConfig(input);
  let chain: Promise<unknown> = Promise.resolve();
  let disposed = false;
  const active = new Set<AbortController>();
  return Object.freeze({
    createExport: (request: { readonly signal?: AbortSignal } = {}) => {
      const signal = snapshotRequest(request);
      const next = chain
        .catch(() => undefined)
        .then(async () => {
          if (disposed) throw new CogsLocalExportError();
          throwIfAborted(signal);
          return withDeadline(signal, active, (deadlineSignal) => writeExport(config, deadlineSignal));
        });
      chain = next.catch(() => undefined);
      return next;
    },
    dispose: async () => {
      disposed = true;
      for (const controller of active) controller.abort();
      const done = Symbol("done");
      const result = await Promise.race([
        chain.then(
          () => done,
          () => done,
        ),
        new Promise((resolve) => setTimeout(resolve, DEFAULT_TIMEOUT_MS)),
      ]);
      if (result !== done) throw new CogsLocalExportError();
    },
  });
}

async function writeExport(
  config: Readonly<ReturnType<typeof snapshotConfig>>,
  signal: AbortSignal | undefined,
): Promise<CogsLocalExportDescriptor> {
  const root = join(config.sessionDir, EXPORT_ROOT);
  const bundle = `cogs-session-${config.sessionId}`;
  const finalDir = join(root, bundle);
  const nonce = randomBytes(16).toString("hex");
  const tempDir = join(root, `.tmp-${bundle}-${nonce}`);
  const backupDir = join(root, `.bak-${bundle}-${nonce}`);
  await prepareRoot(config.sessionDir, root, signal);
  await scanRoot(root, bundle, signal);
  await absent(tempDir);
  await absent(backupDir);
  throwIfAborted(signal);
  await mkdir(tempDir, { mode: 0o700 });
  await syncDir(root, signal);
  let tempOwned: BundleSnapshot | undefined;
  let finalOwned: BundleSnapshot | undefined;
  let backupOwned: BundleSnapshot | undefined;
  try {
    tempOwned = { dir: await verifyDir(tempDir, 0o700), files: new Map() };
    const files = await buildFiles(config, signal);
    let total = 0;
    for (const file of files) {
      total += file.bytes.length;
      if (total > MAX_BUNDLE_BYTES) throw new CogsLocalExportError();
      (tempOwned.files as Map<BundleFile, Marker>).set(
        file.path,
        await writeFileStrict(join(tempDir, file.path), file.bytes, signal),
      );
    }
    await syncDir(tempDir, signal);
    throwIfAborted(signal);
    if (await exists(finalDir)) {
      const old = await verifyExistingBundle(finalDir, config.sessionId);
      throwIfAborted(signal);
      await rename(finalDir, backupDir).catch(() => {
        throw new CogsLocalExportError();
      });
      await syncDir(root, signal);
      backupOwned = old;
    }
    throwIfAborted(signal);
    await rename(tempDir, finalDir).catch(async () => {
      if (backupOwned !== undefined) await rename(backupDir, finalDir).catch(() => undefined);
      throw new CogsLocalExportError();
    });
    finalOwned = tempOwned;
    tempOwned = undefined;
    await syncDir(root, signal);
    await verifyExistingBundle(finalDir, config.sessionId, files);
    if (backupOwned !== undefined) {
      await removeKnownBundle(backupDir, backupOwned, false);
      backupOwned = undefined;
      await syncDir(root, signal);
    }
    finalOwned = undefined;
    const manifest = files.find((file) => file.path === "manifest.json");
    if (manifest === undefined) throw new CogsLocalExportError();
    return Object.freeze({
      version: DESCRIPTOR_VERSION,
      bundle,
      manifest_sha256: sha256(manifest.bytes),
      created_at: JSON.parse(manifest.bytes.toString("utf8")).created_at as string,
      mode: "raw",
      attachments_included: false,
      file_count: FILES.length,
      total_bytes: files.reduce((sum, file) => sum + file.bytes.length, 0),
      sensitive: true,
      sanitized: false,
      anonymized: false,
    });
  } catch (error) {
    if (finalOwned !== undefined) await removeKnownBundle(finalDir, finalOwned, true).catch(() => undefined);
    if (backupOwned !== undefined && !(await exists(finalDir)))
      await rename(backupDir, finalDir).catch(() => undefined);
    if (tempOwned !== undefined) await removeKnownBundle(tempDir, tempOwned, true).catch(() => undefined);
    if (error instanceof CogsLocalExportError) throw error;
    throw new CogsLocalExportError();
  }
}

async function buildFiles(
  config: Readonly<ReturnType<typeof snapshotConfig>>,
  signal: AbortSignal | undefined,
): Promise<readonly FileEntry[]> {
  const history = await config.history.snapshot(signal === undefined ? {} : { signal });
  const entryIds = new Set(history.entryIds);
  const skills = skillsJson(config.skillMetadata());
  const allGit = config.gitMap?.records() ?? Object.freeze([]);
  const git: CogsGitMapRecord[] = [];
  let excludedGitMappings = 0;
  for (const record of allGit) {
    if (record.session !== config.sessionId || !entryIds.has(record.entry)) {
      excludedGitMappings += 1;
      continue;
    }
    git.push(record);
  }
  const nonManifest: FileEntry[] = [
    { path: "session.jsonl", bytes: Buffer.from(history.bytes) },
    {
      path: "git-map.json",
      bytes: jsonBytes({ version: "cogs.git-map-export/v1alpha1", records: git.map(canonicalGit) }),
    },
    { path: "skills.json", bytes: jsonBytes(skills) },
    {
      path: "warnings.json",
      bytes: jsonBytes({
        version: "cogs.export-warnings/v1alpha1",
        warnings:
          excludedGitMappings === 0 ? [] : [{ code: "git_mapping_beyond_durable_prefix", count: excludedGitMappings }],
      }),
    },
    {
      path: "transform-report.json",
      bytes: jsonBytes({
        version: "cogs.transform-report/v1alpha1",
        mode: "raw",
        transform: "identity",
        sanitized: false,
        anonymized: false,
        attachments_included: false,
        transformations: 0,
        claim: "no sanitization or anonymization performed",
      }),
    },
  ];
  const fileEntries = nonManifest
    .map((file) => ({ path: file.path, sha256: sha256(file.bytes), bytes: file.bytes.length }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const manifest = {
    version: VERSION,
    cogs_version: COGS_VERSION,
    pi_version: PI_VERSION,
    session_id: config.sessionId,
    created_at: history.createdAt,
    mode: "raw",
    attachments_included: false,
    ...(config.model === undefined ? {} : { model: config.model }),
    skills: { shared_revision: skills.shared_revision, user_revision: skills.user_revision },
    files: fileEntries,
  };
  return Object.freeze([...nonManifest, { path: "manifest.json", bytes: jsonBytes(manifest) }]);
}

function skillsJson(metadata: CogsPreparedSkillMetadata | undefined): {
  readonly version: "cogs.skills-export/v1alpha1";
  readonly shared_revision: string;
  readonly user_revision: string;
} {
  if (metadata === undefined) throw new CogsLocalExportError();
  const root = exactData(metadata, ["agentsStatus", "shared", "skillCount", "user"]);
  const sharedSet = exactData(root.shared, [
    "bundleDigest",
    "byteCount",
    "fileCount",
    "guestRoot",
    "guestSubtree",
    "readOnlyEnforced",
    "revision",
    "scope",
  ]);
  const userSet = exactData(root.user, [
    "bundleDigest",
    "byteCount",
    "fileCount",
    "guestRoot",
    "guestSubtree",
    "readOnlyEnforced",
    "revision",
    "scope",
  ]);
  if (sharedSet.scope !== "shared" || userSet.scope !== "user") throw new CogsLocalExportError();
  if (typeof sharedSet.revision !== "string" || typeof userSet.revision !== "string") throw new CogsLocalExportError();
  if (!DIGEST.test(sharedSet.revision) || !DIGEST.test(userSet.revision)) throw new CogsLocalExportError();
  return Object.freeze({
    version: "cogs.skills-export/v1alpha1",
    shared_revision: sharedSet.revision,
    user_revision: userSet.revision,
  });
}

function canonicalGit(record: CogsGitMapRecord): JsonValue {
  const raw = exactData(
    record,
    record.confidence === "checkpoint"
      ? ["checkpoint_ref", "commit", "confidence", "entry", "observed_at", "repo", "session", "turn", "version"]
      : ["commit", "confidence", "entry", "observed_at", "repo", "session", "turn", "version"],
  );
  if (
    raw.version !== "cogs.git-mapping/v1alpha1" ||
    typeof raw.repo !== "string" ||
    !OPAQUE.test(raw.repo) ||
    typeof raw.session !== "string" ||
    !OPAQUE.test(raw.session) ||
    typeof raw.commit !== "string" ||
    !COMMIT.test(raw.commit) ||
    typeof raw.entry !== "string" ||
    !ENTRY.test(raw.entry) ||
    typeof raw.turn !== "number" ||
    !Number.isSafeInteger(raw.turn) ||
    raw.turn < 0 ||
    typeof raw.observed_at !== "string" ||
    !ISO.test(raw.observed_at)
  )
    throw new CogsLocalExportError();
  const out: Record<string, JsonValue> = {
    version: raw.version,
    repo: raw.repo,
    commit: raw.commit,
    session: raw.session,
    entry: raw.entry,
    turn: raw.turn,
    observed_at: raw.observed_at,
    confidence: raw.confidence as JsonValue,
  };
  if (raw.confidence === "checkpoint") {
    if (typeof raw.checkpoint_ref !== "string" || raw.checkpoint_ref.length < 1) throw new CogsLocalExportError();
    out.checkpoint_ref = raw.checkpoint_ref;
  } else if (raw.confidence !== "exact") throw new CogsLocalExportError();
  return out;
}

async function prepareRoot(sessionDir: string, root: string, signal: AbortSignal | undefined): Promise<void> {
  throwIfAborted(signal);
  await verifyDir(sessionDir, undefined);
  if (!(await exists(root))) {
    await mkdir(root, { mode: 0o700 });
    await syncDir(sessionDir, signal);
  }
  throwIfAborted(signal);
  await verifyDir(root, 0o700);
  const realSession = await realpath(sessionDir).catch(() => {
    throw new CogsLocalExportError();
  });
  if ((await realpath(resolve(root, "..")).catch(() => "")) !== realSession) throw new CogsLocalExportError();
}

async function scanRoot(root: string, bundle: string, signal: AbortSignal | undefined): Promise<void> {
  throwIfAborted(signal);
  const names = await readdir(root).catch(() => {
    throw new CogsLocalExportError();
  });
  if (!names.every((name) => name === bundle)) throw new CogsLocalExportError();
}

async function writeFileStrict(path: string, bytes: Buffer, signal: AbortSignal | undefined): Promise<Marker> {
  throwIfAborted(signal);
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  ).catch(() => {
    throw new CogsLocalExportError();
  });
  let closed = false;
  let marker: Marker | undefined;
  const created = markerFrom(await handle.stat({ bigint: true }), "file", 0o600, 0n);
  try {
    let offset = 0;
    while (offset < bytes.length) {
      throwIfAborted(signal);
      const write = await handle.write(bytes, offset, bytes.length - offset, offset);
      if (write.bytesWritten < 1) throw new CogsLocalExportError();
      offset += write.bytesWritten;
    }
    marker = markerFrom(await handle.stat({ bigint: true }), "file", 0o600, BigInt(bytes.length));
    await handle.sync();
    throwIfAborted(signal);
    sameMarker(markerFrom(await handle.stat({ bigint: true }), "file", 0o600, BigInt(bytes.length)), marker);
    await handle.close();
    closed = true;
    sameMarker(await verifyFile(path, BigInt(bytes.length)), marker);
    return marker;
  } catch (error) {
    await handle.close().catch(() => undefined);
    closed = true;
    await verifyFile(path)
      .then((actual) => {
        sameNode(actual, created);
        return unlink(path);
      })
      .catch(() => undefined);
    if (error instanceof CogsLocalExportError) throw error;
    throw new CogsLocalExportError();
  } finally {
    if (!closed) await handle.close().catch(() => undefined);
  }
}

async function verifyExistingBundle(
  dir: string,
  sessionId: string,
  expected?: readonly FileEntry[],
): Promise<BundleSnapshot> {
  const dirMarker = await verifyDir(dir, 0o700);
  const names = (
    await readdir(dir).catch(() => {
      throw new CogsLocalExportError();
    })
  ).sort();
  if (names.join("\0") !== [...FILES].sort().join("\0")) throw new CogsLocalExportError();
  const markers = new Map<BundleFile, Marker>();
  let totalSize = 0n;
  for (const name of FILES) {
    const marker = await verifyFile(join(dir, name));
    markers.set(name, marker);
    totalSize += marker.size;
    if (totalSize > BigInt(MAX_BUNDLE_BYTES)) throw new CogsLocalExportError();
  }
  const bytes = new Map<BundleFile, Buffer>();
  for (const name of FILES) bytes.set(name, (await readVerifiedFile(join(dir, name), markers.get(name))).bytes);
  if (expected !== undefined) {
    for (const file of expected) {
      const actual = bytes.get(file.path);
      if (actual === undefined || !file.bytes.equals(actual)) throw new CogsLocalExportError();
    }
  }
  const manifest = parseJson(bytes.get("manifest.json") ?? Buffer.alloc(0));
  const raw = exactData(
    manifest,
    [
      "attachments_included",
      "cogs_version",
      "created_at",
      "files",
      "mode",
      "model",
      "pi_version",
      "session_id",
      "skills",
      "version",
    ],
    true,
  );
  if (
    raw.version !== VERSION ||
    raw.cogs_version !== COGS_VERSION ||
    raw.pi_version !== PI_VERSION ||
    raw.session_id !== sessionId ||
    raw.mode !== "raw" ||
    raw.attachments_included !== false ||
    typeof raw.created_at !== "string" ||
    !ISO.test(raw.created_at)
  )
    throw new CogsLocalExportError();
  const files = snapshotManifestFiles(raw.files);
  const expectedPaths = ["git-map.json", "session.jsonl", "skills.json", "transform-report.json", "warnings.json"];
  if (files.map((file) => file.path).join("\0") !== expectedPaths.join("\0")) throw new CogsLocalExportError();
  for (const file of files) {
    const data = bytes.get(file.path);
    if (data === undefined || sha256(data) !== file.sha256 || data.length !== file.bytes)
      throw new CogsLocalExportError();
  }
  const git = canonicalGitExport(bytes.get("git-map.json"));
  const skills = canonicalSkillsExport(bytes.get("skills.json"));
  const manifestSkills = exactData(raw.skills, ["shared_revision", "user_revision"]);
  if (
    manifestSkills.shared_revision !== skills.shared_revision ||
    manifestSkills.user_revision !== skills.user_revision
  )
    throw new CogsLocalExportError();
  const warnings = canonicalWarningsExport(bytes.get("warnings.json"));
  const transform = canonicalTransformExport(bytes.get("transform-report.json"));
  const model = raw.model === undefined ? undefined : snapshotModel(raw.model as { provider: string; id: string });
  const rebuiltManifest = {
    version: VERSION,
    cogs_version: COGS_VERSION,
    pi_version: PI_VERSION,
    session_id: sessionId,
    created_at: raw.created_at,
    mode: "raw",
    attachments_included: false,
    ...(model === undefined ? {} : { model }),
    skills: { shared_revision: skills.shared_revision, user_revision: skills.user_revision },
    files,
  };
  if (!jsonBytes(rebuiltManifest).equals(bytes.get("manifest.json") ?? Buffer.alloc(0)))
    throw new CogsLocalExportError();
  void git;
  void warnings;
  void transform;
  return Object.freeze({ dir: dirMarker, files: markers });
}

async function verifyDir(path: string, mode: 0o700 | undefined): Promise<Marker> {
  const stat = await lstat(path, { bigint: true }).catch(() => {
    throw new CogsLocalExportError();
  });
  return markerFrom(stat, "dir", mode, undefined);
}

async function verifyFile(path: string, size?: bigint): Promise<Marker> {
  const stat = await lstat(path, { bigint: true }).catch(() => {
    throw new CogsLocalExportError();
  });
  return markerFrom(stat, "file", 0o600, size);
}

async function readVerifiedFile(
  path: string,
  expected?: Marker,
): Promise<{ readonly bytes: Buffer; readonly marker: Marker }> {
  const before = await verifyFile(path);
  if (expected !== undefined) sameMarker(before, expected);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => {
    throw new CogsLocalExportError();
  });
  let closed = false;
  try {
    sameMarker(markerFrom(await handle.stat({ bigint: true }), "file", 0o600, before.size), before);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead < 1) throw new CogsLocalExportError();
      offset += read.bytesRead;
    }
    sameMarker(markerFrom(await handle.stat({ bigint: true }), "file", 0o600, before.size), before);
    await handle.close();
    closed = true;
    sameMarker(await verifyFile(path, before.size), before);
    return { bytes, marker: before };
  } finally {
    if (!closed) await handle.close().catch(() => undefined);
  }
}

function markerFrom(
  stat: BigStats,
  kind: "file" | "dir",
  mode: 0o600 | 0o700 | undefined,
  size: bigint | undefined,
): Marker {
  if (kind === "file" ? !stat.isFile() : !stat.isDirectory()) throw new CogsLocalExportError();
  if (stat.isSymbolicLink() || (kind === "file" ? stat.nlink !== 1n : stat.nlink < 1n))
    throw new CogsLocalExportError();
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) throw new CogsLocalExportError();
  if (mode !== undefined && Number(stat.mode & 0o777n) !== mode) throw new CogsLocalExportError();
  if (size !== undefined && stat.size !== size) throw new CogsLocalExportError();
  if (stat.size < 0n || stat.size > BigInt(MAX_BUNDLE_BYTES)) throw new CogsLocalExportError();
  return Object.freeze({ dev: stat.dev, ino: stat.ino, mode: stat.mode, nlink: stat.nlink, size: stat.size });
}

function sameMarker(actual: Marker, expected: Marker): void {
  if (
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.mode !== expected.mode ||
    actual.nlink !== expected.nlink ||
    actual.size !== expected.size
  )
    throw new CogsLocalExportError();
}

function sameNode(actual: Marker, expected: Marker): void {
  if (actual.dev !== expected.dev || actual.ino !== expected.ino || actual.mode !== expected.mode)
    throw new CogsLocalExportError();
}

function parseJson(bytes: Buffer): unknown {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new CogsLocalExportError();
  }
}

function canonicalGitExport(bytes: Buffer | undefined): JsonValue {
  const value = exactData(parseJson(bytes ?? Buffer.alloc(0)), ["records", "version"]);
  if (value.version !== "cogs.git-map-export/v1alpha1" || !Array.isArray(value.records))
    throw new CogsLocalExportError();
  const out = {
    version: value.version,
    records: value.records.map((record) => canonicalGit(record as CogsGitMapRecord)),
  };
  if (!jsonBytes(out).equals(bytes ?? Buffer.alloc(0))) throw new CogsLocalExportError();
  return out as JsonValue;
}

function canonicalSkillsExport(bytes: Buffer | undefined): { shared_revision: string; user_revision: string } {
  const skills = exactData(parseJson(bytes ?? Buffer.alloc(0)), ["shared_revision", "user_revision", "version"]);
  if (
    skills.version !== "cogs.skills-export/v1alpha1" ||
    typeof skills.shared_revision !== "string" ||
    typeof skills.user_revision !== "string" ||
    !DIGEST.test(skills.shared_revision) ||
    !DIGEST.test(skills.user_revision)
  )
    throw new CogsLocalExportError();
  const out = { version: skills.version, shared_revision: skills.shared_revision, user_revision: skills.user_revision };
  if (!jsonBytes(out).equals(bytes ?? Buffer.alloc(0))) throw new CogsLocalExportError();
  return out;
}

function canonicalWarningsExport(bytes: Buffer | undefined): JsonValue {
  const value = exactData(parseJson(bytes ?? Buffer.alloc(0)), ["version", "warnings"]);
  if (value.version !== "cogs.export-warnings/v1alpha1" || !Array.isArray(value.warnings))
    throw new CogsLocalExportError();
  if (value.warnings.length > 1) throw new CogsLocalExportError();
  if (value.warnings.length === 1) {
    const warning = exactData(value.warnings[0], ["code", "count"]);
    if (
      warning.code !== "git_mapping_beyond_durable_prefix" ||
      typeof warning.count !== "number" ||
      !Number.isSafeInteger(warning.count) ||
      warning.count < 1
    )
      throw new CogsLocalExportError();
  }
  const out = { version: value.version, warnings: value.warnings };
  if (!jsonBytes(out).equals(bytes ?? Buffer.alloc(0))) throw new CogsLocalExportError();
  return out as JsonValue;
}

function canonicalTransformExport(bytes: Buffer | undefined): JsonValue {
  const value = exactData(parseJson(bytes ?? Buffer.alloc(0)), [
    "anonymized",
    "attachments_included",
    "claim",
    "mode",
    "sanitized",
    "transform",
    "transformations",
    "version",
  ]);
  if (
    value.version !== "cogs.transform-report/v1alpha1" ||
    value.mode !== "raw" ||
    value.transform !== "identity" ||
    value.sanitized !== false ||
    value.anonymized !== false ||
    value.attachments_included !== false ||
    value.transformations !== 0 ||
    value.claim !== "no sanitization or anonymization performed"
  )
    throw new CogsLocalExportError();
  const out = {
    version: value.version,
    mode: value.mode,
    transform: value.transform,
    sanitized: value.sanitized,
    anonymized: value.anonymized,
    attachments_included: value.attachments_included,
    transformations: value.transformations,
    claim: value.claim,
  };
  if (!jsonBytes(out).equals(bytes ?? Buffer.alloc(0))) throw new CogsLocalExportError();
  return out as JsonValue;
}

function snapshotManifestFiles(
  value: unknown,
): { readonly path: Exclude<BundleFile, "manifest.json">; readonly sha256: string; readonly bytes: number }[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length !== 5)
    throw new CogsLocalExportError();
  return value.map((item) => {
    const raw = exactData(item, ["bytes", "path", "sha256"]);
    if (
      typeof raw.path !== "string" ||
      raw.path === "manifest.json" ||
      !(FILES as readonly string[]).includes(raw.path)
    )
      throw new CogsLocalExportError();
    if (typeof raw.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(raw.sha256)) throw new CogsLocalExportError();
    if (typeof raw.bytes !== "number" || !Number.isSafeInteger(raw.bytes) || raw.bytes < 0)
      throw new CogsLocalExportError();
    return { path: raw.path as Exclude<BundleFile, "manifest.json">, sha256: raw.sha256, bytes: raw.bytes };
  });
}

async function syncDir(path: string, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY).catch(() => {
    throw new CogsLocalExportError();
  });
  let closed = false;
  try {
    await handle.sync();
    throwIfAborted(signal);
    await handle.close();
    closed = true;
  } finally {
    if (!closed) await handle.close().catch(() => undefined);
  }
}

async function removeKnownBundle(dir: string, snapshot: BundleSnapshot, partial: boolean): Promise<void> {
  if (!(await exists(dir))) return;
  sameNode(await verifyDir(dir, 0o700), snapshot.dir);
  const names = await readdir(dir).catch(() => {
    throw new CogsLocalExportError();
  });
  for (const name of names) if (!(FILES as readonly string[]).includes(name)) throw new CogsLocalExportError();
  if (!partial && names.length !== FILES.length) throw new CogsLocalExportError();
  for (const name of FILES) {
    if (!names.includes(name)) continue;
    const marker = snapshot.files.get(name);
    if (marker === undefined) throw new CogsLocalExportError();
    sameMarker(await verifyFile(join(dir, name), marker.size), marker);
    await unlink(join(dir, name)).catch(() => {
      throw new CogsLocalExportError();
    });
  }
  sameNode(await verifyDir(dir, 0o700), snapshot.dir);
  await rmdir(dir).catch(() => {
    throw new CogsLocalExportError();
  });
}

async function absent(path: string): Promise<void> {
  if (await exists(path)) throw new CogsLocalExportError();
}

async function exists(path: string): Promise<boolean> {
  return lstat(path).then(
    () => true,
    (error: { code?: unknown }) => {
      if (error.code === "ENOENT") return false;
      throw new CogsLocalExportError();
    },
  );
}

function snapshotConfig(input: {
  readonly sessionDir: string;
  readonly sessionId: string;
  readonly history: CogsJsonlHistoryStore;
  readonly gitMap?: CogsGitMapStore;
  readonly skillMetadata: () => CogsPreparedSkillMetadata | undefined;
  readonly model?: { readonly provider: string; readonly id: string };
}) {
  try {
    const raw = exactData(input, ["gitMap", "history", "model", "sessionDir", "sessionId", "skillMetadata"], true);
    if (typeof raw.sessionId !== "string" || !OPAQUE.test(raw.sessionId)) throw new CogsLocalExportError();
    if (typeof raw.sessionDir !== "string" || raw.sessionDir.length < 1) throw new CogsLocalExportError();
    const history = raw.history as CogsJsonlHistoryStore;
    const gitMap = raw.gitMap as CogsGitMapStore | undefined;
    if (typeof history?.snapshot !== "function") throw new CogsLocalExportError();
    if (gitMap !== undefined && typeof gitMap.records !== "function") throw new CogsLocalExportError();
    if (typeof raw.skillMetadata !== "function") throw new CogsLocalExportError();
    const model = raw.model === undefined ? undefined : snapshotModel(raw.model as { provider: string; id: string });
    return Object.freeze({
      sessionDir: raw.sessionDir,
      sessionId: raw.sessionId,
      history,
      gitMap,
      skillMetadata: raw.skillMetadata as () => CogsPreparedSkillMetadata | undefined,
      ...(model === undefined ? {} : { model }),
    });
  } catch {
    throw new CogsLocalExportError();
  }
}

function exactData(value: unknown, keys: readonly string[], optional = false): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new CogsLocalExportError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  const allowed = new Set(keys);
  if (!actual.every((key) => typeof key === "string" && allowed.has(key))) throw new CogsLocalExportError();
  if (!optional && actual.length !== keys.length) throw new CogsLocalExportError();
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined) {
      if (optional) continue;
      throw new CogsLocalExportError();
    }
    if (!descriptor.enumerable || !("value" in descriptor)) throw new CogsLocalExportError();
    out[key] = descriptor.value;
  }
  return out;
}

function snapshotModel(input: { readonly provider: string; readonly id: string }) {
  const raw = exactData(input, ["id", "provider"]);
  if (
    typeof raw.provider !== "string" ||
    !OPAQUE.test(raw.provider) ||
    typeof raw.id !== "string" ||
    raw.id.length < 1 ||
    raw.id.length > 256 ||
    hasControl(raw.id)
  )
    throw new CogsLocalExportError();
  return Object.freeze({ provider: raw.provider, id: raw.id });
}

function hasControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function jsonBytes(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function snapshotRequest(request: unknown): AbortSignal | undefined {
  const raw = exactData(request, ["signal"], true);
  if (raw.signal !== undefined && !(raw.signal instanceof AbortSignal)) throw new CogsLocalExportError();
  return raw.signal;
}

async function withDeadline<T>(
  signal: AbortSignal | undefined,
  active: Set<AbortController>,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  active.add(controller);
  const onAbort = () => controller.abort();
  let timer: NodeJS.Timeout | undefined = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    throwIfAborted(signal);
    return await operation(controller.signal);
  } catch {
    throw new CogsLocalExportError();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    active.delete(controller);
    signal?.removeEventListener("abort", onAbort);
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CogsLocalExportError();
}
