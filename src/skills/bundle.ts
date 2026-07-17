import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

export const COGS_SKILLS_BUNDLE_MEDIA_TYPE = "application/vnd.cogs.skills.bundle.v1+json";
export const COGS_SKILLS_BUNDLE_VERSION = "cogs.dev/skills-bundle/v1";
export const COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES = 1024 * 1024;
export const COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES = 768 * 1024;
export const COGS_SKILLS_BUNDLE_MAX_FILES = 128;
export const COGS_SKILLS_BUNDLE_MAX_FILE_BYTES = 256 * 1024;
export const COGS_SKILLS_BUNDLE_MAX_PATH_BYTES = 256;

export interface CogsSkillBundleBuildEntry {
  readonly path: string;
  readonly executable: boolean;
  readonly content: Buffer;
}

export interface CogsSkillBundleFileMetadata {
  readonly path: string;
  readonly executable: boolean;
  readonly size: number;
  readonly sha256: `sha256:${string}`;
}

export interface CogsSkillBundleHandle {
  readonly mediaType: typeof COGS_SKILLS_BUNDLE_MEDIA_TYPE;
  readonly version: typeof COGS_SKILLS_BUNDLE_VERSION;
  readonly digest: `sha256:${string}`;
  readonly byteLength: number;
  readonly decodedByteLength: number;
  readonly fileCount: number;
  readonly files: readonly CogsSkillBundleFileMetadata[];
  readonly copyBytes: () => Buffer;
  readonly copyFile: (path: string) => Buffer;
}

interface CanonicalBundleJson {
  readonly version: typeof COGS_SKILLS_BUNDLE_VERSION;
  readonly mediaType: typeof COGS_SKILLS_BUNDLE_MEDIA_TYPE;
  readonly entries: readonly CanonicalBundleEntryJson[];
}

interface CanonicalBundleEntryJson {
  readonly path: string;
  readonly executable: boolean;
  readonly size: number;
  readonly sha256: `sha256:${string}`;
  readonly contentBase64: string;
}

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class CogsSkillBundleError extends Error {
  public readonly code = "COGS_SKILL_BUNDLE_INVALID";
  public constructor() {
    super("invalid skill bundle");
    this.name = "CogsSkillBundleError";
  }
}

export function buildCogsSkillBundle(input: {
  readonly entries: readonly CogsSkillBundleBuildEntry[];
}): CogsSkillBundleHandle {
  try {
    const inputSnapshot = snapshotPlainExactObject(input, ["entries"]);
    const inputEntries = snapshotExactArray(inputSnapshot.entries, COGS_SKILLS_BUNDLE_MAX_FILES);

    const paths = new Set<string>();
    const entries: CanonicalBundleEntryJson[] = [];
    let decodedByteLength = 0;
    for (const candidate of inputEntries) {
      const entrySnapshot = snapshotPlainExactObject(candidate, ["path", "executable", "content"]);
      const normalizedPath = validatePath(entrySnapshot.path);
      if (paths.has(normalizedPath)) throw new CogsSkillBundleError();
      paths.add(normalizedPath);
      if (typeof entrySnapshot.executable !== "boolean") throw new CogsSkillBundleError();
      if (!Buffer.isBuffer(entrySnapshot.content)) throw new CogsSkillBundleError();
      if (entrySnapshot.content.length > COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) throw new CogsSkillBundleError();
      decodedByteLength += entrySnapshot.content.length;
      if (decodedByteLength > COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES) throw new CogsSkillBundleError();
      const content = Buffer.from(entrySnapshot.content);
      entries.push({
        path: normalizedPath,
        executable: entrySnapshot.executable,
        size: content.length,
        sha256: sha256Digest(content),
        contentBase64: canonicalBase64(content),
      });
    }

    entries.sort((left, right) => Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")));
    return handleFromCanonicalJson({
      version: COGS_SKILLS_BUNDLE_VERSION,
      mediaType: COGS_SKILLS_BUNDLE_MEDIA_TYPE,
      entries,
    });
  } catch (error) {
    if (error instanceof CogsSkillBundleError) throw error;
    throw new CogsSkillBundleError();
  }
}

export function verifyCogsSkillBundle(bytes: Buffer): CogsSkillBundleHandle {
  try {
    if (!Buffer.isBuffer(bytes)) throw new CogsSkillBundleError();
    if (bytes.length > COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES) throw new CogsSkillBundleError();
    const source = Buffer.from(bytes);
    const text = TEXT_DECODER.decode(source);
    const parsed: unknown = JSON.parse(text);
    const bundle = validateParsedBundle(parsed);
    const canonical = serializeCanonicalBundle(bundle);
    if (!source.equals(canonical)) throw new CogsSkillBundleError();
    return createHandle(canonical, bundle);
  } catch (error) {
    if (error instanceof CogsSkillBundleError) throw error;
    throw new CogsSkillBundleError();
  }
}

function validateParsedBundle(value: unknown): CanonicalBundleJson {
  const bundle = snapshotPlainExactObject(value, ["version", "mediaType", "entries"]);
  if (bundle.version !== COGS_SKILLS_BUNDLE_VERSION) throw new CogsSkillBundleError();
  if (bundle.mediaType !== COGS_SKILLS_BUNDLE_MEDIA_TYPE) throw new CogsSkillBundleError();
  const bundleEntries = snapshotExactArray(bundle.entries, COGS_SKILLS_BUNDLE_MAX_FILES);

  const paths = new Set<string>();
  const entries: CanonicalBundleEntryJson[] = [];
  let decodedByteLength = 0;
  let priorPathBytes: Buffer | undefined;
  for (const rawEntry of bundleEntries) {
    const entry = snapshotPlainExactObject(rawEntry, ["path", "executable", "size", "sha256", "contentBase64"]);
    const normalizedPath = validatePath(entry.path);
    if (paths.has(normalizedPath)) throw new CogsSkillBundleError();
    paths.add(normalizedPath);
    const pathBytes = Buffer.from(normalizedPath, "utf8");
    if (priorPathBytes !== undefined && Buffer.compare(priorPathBytes, pathBytes) >= 0)
      throw new CogsSkillBundleError();
    priorPathBytes = pathBytes;
    if (typeof entry.executable !== "boolean") throw new CogsSkillBundleError();
    const size = validateSafeInteger(entry.size, 0, COGS_SKILLS_BUNDLE_MAX_FILE_BYTES);
    if (typeof entry.sha256 !== "string" || !SHA256_PATTERN.test(entry.sha256)) throw new CogsSkillBundleError();
    if (typeof entry.contentBase64 !== "string" || !BASE64_PATTERN.test(entry.contentBase64))
      throw new CogsSkillBundleError();
    const content = Buffer.from(entry.contentBase64, "base64");
    if (content.length !== size) throw new CogsSkillBundleError();
    if (canonicalBase64(content) !== entry.contentBase64) throw new CogsSkillBundleError();
    if (sha256Digest(content) !== entry.sha256) throw new CogsSkillBundleError();
    decodedByteLength += content.length;
    if (decodedByteLength > COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES) throw new CogsSkillBundleError();
    entries.push({
      path: normalizedPath,
      executable: entry.executable,
      size,
      sha256: entry.sha256 as `sha256:${string}`,
      contentBase64: entry.contentBase64,
    });
  }
  return { version: COGS_SKILLS_BUNDLE_VERSION, mediaType: COGS_SKILLS_BUNDLE_MEDIA_TYPE, entries };
}

function handleFromCanonicalJson(bundle: CanonicalBundleJson): CogsSkillBundleHandle {
  const canonical = serializeCanonicalBundle(bundle);
  if (canonical.length > COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES) throw new CogsSkillBundleError();
  return createHandle(canonical, validateParsedBundle(JSON.parse(canonical.toString("utf8"))));
}

function createHandle(canonicalBytes: Buffer, bundle: CanonicalBundleJson): CogsSkillBundleHandle {
  const bytes = Buffer.from(canonicalBytes);
  const contents = new Map<string, Buffer>();
  let decodedByteLength = 0;
  const files = bundle.entries.map((entry) => {
    const content = Buffer.from(entry.contentBase64, "base64");
    contents.set(entry.path, content);
    decodedByteLength += content.length;
    return Object.freeze({ path: entry.path, executable: entry.executable, size: entry.size, sha256: entry.sha256 });
  });
  const frozenFiles = Object.freeze(files.slice());
  return Object.freeze({
    mediaType: COGS_SKILLS_BUNDLE_MEDIA_TYPE,
    version: COGS_SKILLS_BUNDLE_VERSION,
    digest: sha256Digest(bytes),
    byteLength: bytes.length,
    decodedByteLength,
    fileCount: frozenFiles.length,
    files: frozenFiles,
    copyBytes: () => Buffer.from(bytes),
    copyFile: (path: string) => {
      const normalizedPath = validatePath(path);
      const content = contents.get(normalizedPath);
      if (content === undefined) throw new CogsSkillBundleError();
      return Buffer.from(content);
    },
  });
}

function serializeCanonicalBundle(bundle: CanonicalBundleJson): Buffer {
  return Buffer.from(
    JSON.stringify({
      version: bundle.version,
      mediaType: bundle.mediaType,
      entries: bundle.entries.map((entry) => ({
        path: entry.path,
        executable: entry.executable,
        size: entry.size,
        sha256: entry.sha256,
        contentBase64: entry.contentBase64,
      })),
    }),
    "utf8",
  );
}

function snapshotPlainExactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsSkillBundleError();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype) throw new CogsSkillBundleError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (names.length !== keys.length || !names.every((name) => typeof name === "string"))
    throw new CogsSkillBundleError();
  const snapshot: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
      throw new CogsSkillBundleError();
    snapshot[key] = descriptor.value;
  }
  for (const name of names) if (typeof name !== "string" || !keys.includes(name)) throw new CogsSkillBundleError();
  return snapshot;
}

function snapshotExactArray(value: unknown, maximumLength: number): readonly unknown[] {
  if (!Array.isArray(value)) throw new CogsSkillBundleError();
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new CogsSkillBundleError();
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>;
  const keys = Reflect.ownKeys(descriptors);
  if (!keys.every((key) => typeof key === "string")) throw new CogsSkillBundleError();
  const lengthDescriptor = descriptors.length;
  if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) throw new CogsSkillBundleError();
  const length = validateSafeInteger(lengthDescriptor.value, 0, maximumLength);
  if (keys.length !== length + 1) throw new CogsSkillBundleError();
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = `${index}`;
    const descriptor = descriptors[key];
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
      throw new CogsSkillBundleError();
    snapshot.push(descriptor.value);
  }
  for (const key of keys) {
    if (key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key)))
      throw new CogsSkillBundleError();
  }
  return snapshot;
}

function validatePath(value: unknown): string {
  if (typeof value !== "string") throw new CogsSkillBundleError();
  if (value.length === 0 || value !== value.normalize("NFC")) throw new CogsSkillBundleError();
  const bytes = Buffer.from(value, "utf8");
  if (bytes.toString("utf8") !== value) throw new CogsSkillBundleError();
  if (bytes.length === 0 || bytes.length > COGS_SKILLS_BUNDLE_MAX_PATH_BYTES) throw new CogsSkillBundleError();
  if (value.startsWith("/") || /^[A-Za-z]:/.test(value) || value.includes("\\")) throw new CogsSkillBundleError();
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code < 0x20 || code === 0x7f) throw new CogsSkillBundleError();
  }
  for (const segment of value.split("/")) {
    if (segment.length === 0 || segment === "." || segment === "..") throw new CogsSkillBundleError();
  }
  return value;
}

function validateSafeInteger(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new CogsSkillBundleError();
  return value;
}

function sha256Digest(bytes: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalBase64(bytes: Buffer): string {
  return bytes.toString("base64");
}
