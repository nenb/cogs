import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, writeFileSync } from "node:fs";
import {
  canonicalReleaseLocalBytes,
  inspectTrivyDatabaseMetadata,
  type ReleaseLocalJson,
  type ReleaseTrivyDatabaseMetadata,
  type ReleaseTrivyDatabaseType,
} from "./release-local-preflight.ts";

const MAX_METADATA_BYTES = 64 * 1024;
const MAX_SNAPSHOT_BYTES = 16 * 1024;
const SNAPSHOT_KEYS = new Set([
  "version",
  "schema",
  "type",
  "database_version",
  "updated_at",
  "next_update",
  "downloaded_at",
  "evaluated_at",
  "minimum_valid_until",
  "metadata_sha256",
  "metadata_size_bytes",
]);

type Snapshot = Readonly<{
  version: "cogs.release-trivy-database-metadata-observation/v1";
  schema: "trivy-db-cache-metadata/v1";
  type: ReleaseTrivyDatabaseType;
  database_version: number;
  updated_at: string;
  next_update: string;
  downloaded_at: string;
  evaluated_at: string;
  minimum_valid_until: string;
  metadata_sha256: string;
  metadata_size_bytes: number;
}>;

function usage(): never {
  throw new Error(
    "usage: release-trivy-database-metadata-cli.ts <snapshot|verify> <vulnerability|java> <metadata.json> <minimum-valid-until> <snapshot.json>",
  );
}

function readPrivateRegularFile(path: string, maximum: number, label: string): Uint8Array {
  const before = lstatSync(path);
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.size < 1 ||
    before.size > maximum ||
    uid === undefined ||
    gid === undefined ||
    before.uid !== uid ||
    before.gid !== gid ||
    (before.mode & 0o777) !== 0o600
  ) {
    throw new Error(`${label}: private caller-owned bounded regular file required`);
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.uid !== uid ||
      opened.gid !== gid ||
      opened.size !== before.size ||
      (opened.mode & 0o777) !== 0o600
    ) {
      throw new Error(`${label}: identity changed while opening`);
    }
    const bytes = Uint8Array.from(readFileSync(descriptor));
    const after = fstatSync(descriptor);
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs ||
      bytes.byteLength !== opened.size
    ) {
      throw new Error(`${label}: identity changed while reading`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function writePrivateSnapshot(path: string, bytes: Uint8Array): void {
  const descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    const state = fstatSync(descriptor);
    if (!state.isFile() || state.nlink !== 1 || state.size !== bytes.byteLength || (state.mode & 0o777) !== 0o600) {
      throw new Error("database metadata snapshot: private regular output required");
    }
  } finally {
    closeSync(descriptor);
  }
}

function deadline(source: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(source)) {
    throw new Error("database metadata: strict UTC minimum-valid-until required");
  }
  const parsed = new Date(source);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== source.replace(/Z$/u, ".000Z")) {
    throw new Error("database metadata: invalid minimum-valid-until");
  }
  return parsed;
}

function observation(type: ReleaseTrivyDatabaseType, metadataBytes: Uint8Array, minimumValidUntil: Date): Snapshot {
  const metadata = inspectTrivyDatabaseMetadata(metadataBytes, new Date(), type, minimumValidUntil);
  if (!metadata.current) throw new Error("database metadata: expired at evaluation time");
  return Object.freeze({
    version: "cogs.release-trivy-database-metadata-observation/v1",
    schema: metadata.schema,
    type: metadata.type,
    database_version: metadata.version,
    updated_at: metadata.updated_at,
    next_update: metadata.next_update,
    downloaded_at: metadata.downloaded_at,
    evaluated_at: metadata.evaluated_at,
    minimum_valid_until: minimumValidUntil.toISOString(),
    metadata_sha256: createHash("sha256").update(metadataBytes).digest("hex"),
    metadata_size_bytes: metadataBytes.byteLength,
  });
}

function parseSnapshot(bytes: Uint8Array): Snapshot {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("database metadata snapshot: invalid UTF-8 JSON");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.getPrototypeOf(parsed) !== Object.prototype
  ) {
    throw new Error("database metadata snapshot: object required");
  }
  const value = parsed as Record<string, unknown>;
  const keys = Object.keys(value);
  if (keys.length !== SNAPSHOT_KEYS.size || keys.some((key) => !SNAPSHOT_KEYS.has(key))) {
    throw new Error("database metadata snapshot: exact schema required");
  }
  if (!Buffer.from(canonicalReleaseLocalBytes(value as ReleaseLocalJson)).equals(Buffer.from(bytes))) {
    throw new Error("database metadata snapshot: canonical JSON required");
  }
  if (
    value.version !== "cogs.release-trivy-database-metadata-observation/v1" ||
    value.schema !== "trivy-db-cache-metadata/v1" ||
    (value.type !== "vulnerability" && value.type !== "java") ||
    !Number.isSafeInteger(value.database_version) ||
    typeof value.updated_at !== "string" ||
    typeof value.next_update !== "string" ||
    typeof value.downloaded_at !== "string" ||
    typeof value.evaluated_at !== "string" ||
    typeof value.minimum_valid_until !== "string" ||
    typeof value.metadata_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(value.metadata_sha256) ||
    !Number.isSafeInteger(value.metadata_size_bytes) ||
    (value.metadata_size_bytes as number) < 1 ||
    (value.metadata_size_bytes as number) > MAX_METADATA_BYTES
  ) {
    throw new Error("database metadata snapshot: invalid field");
  }
  return value as Snapshot;
}

function stableMetadata(metadata: ReleaseTrivyDatabaseMetadata | Snapshot): readonly unknown[] {
  return [
    metadata.schema,
    metadata.type,
    "database_version" in metadata ? metadata.database_version : metadata.version,
    metadata.updated_at,
    metadata.next_update,
    metadata.downloaded_at,
  ];
}

const [operation, typeSource, metadataPath, deadlineSource, snapshotPath] = process.argv.slice(2);
if (
  process.argv.length !== 7 ||
  (operation !== "snapshot" && operation !== "verify") ||
  (typeSource !== "vulnerability" && typeSource !== "java") ||
  metadataPath === undefined ||
  deadlineSource === undefined ||
  snapshotPath === undefined
) {
  usage();
}
const type: ReleaseTrivyDatabaseType = typeSource;
const minimumValidUntil = deadline(deadlineSource);
const metadataBytes = readPrivateRegularFile(metadataPath, MAX_METADATA_BYTES, `${type} database metadata`);
const current = observation(type, metadataBytes, minimumValidUntil);

if (operation === "snapshot") {
  writePrivateSnapshot(snapshotPath, canonicalReleaseLocalBytes(current as unknown as ReleaseLocalJson));
} else {
  const expected = parseSnapshot(
    readPrivateRegularFile(snapshotPath, MAX_SNAPSHOT_BYTES, `${type} database metadata snapshot`),
  );
  if (
    expected.type !== type ||
    expected.minimum_valid_until !== minimumValidUntil.toISOString() ||
    expected.metadata_size_bytes !== current.metadata_size_bytes ||
    expected.metadata_sha256 !== current.metadata_sha256 ||
    JSON.stringify(stableMetadata(expected)) !== JSON.stringify(stableMetadata(current))
  ) {
    throw new Error(`${type} database metadata: independently substituted after acquisition`);
  }
}
