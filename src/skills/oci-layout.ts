import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import {
  COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES,
  COGS_SKILLS_BUNDLE_MEDIA_TYPE,
  type CogsSkillBundleHandle,
  verifyCogsSkillBundle,
} from "./bundle.ts";

export const COGS_OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
export const COGS_OCI_EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json";

export interface CogsSharedSkillOciLayoutOptions {
  readonly layoutRoot: string;
  readonly fs?: Partial<CogsSharedSkillOciFs>;
}

export interface CogsSharedSkillOciResolveInput {
  readonly manifestDigest: `sha256:${string}`;
  readonly signal?: AbortSignal;
}

export interface CogsSharedSkillOciResult {
  readonly scope: "shared";
  readonly manifestDigest: `sha256:${string}`;
  readonly bundleDigest: `sha256:${string}`;
  readonly manifestBytes: number;
  readonly bundleBytes: number;
  readonly configBytes: number;
  readonly fileCount: number;
  readonly decodedByteLength: number;
  readonly bundle: CogsSkillBundleHandle;
}

export interface CogsSharedSkillOciResolver {
  readonly resolve: (input: CogsSharedSkillOciResolveInput) => Promise<CogsSharedSkillOciResult>;
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

interface FileHandleLike {
  readonly stat: () => Promise<BigStats>;
  readonly read: (buffer: Buffer, offset: number, length: number, position: number) => Promise<{ bytesRead: number }>;
  readonly close: () => Promise<void>;
}

interface CogsSharedSkillOciFs {
  readonly realpath: (target: string) => Promise<string>;
  readonly lstat: (target: string) => Promise<BigStats>;
  readonly open: (target: string, flags: number) => Promise<FileHandleLike>;
}

const MAX_LAYOUT_JSON_BYTES = 64;
const MAX_INDEX_BYTES = 1024;
const MAX_MANIFEST_BYTES = 2048;
const MAX_CONFIG_BYTES = 2;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const REAL_FS: CogsSharedSkillOciFs = {
  realpath,
  lstat: (target) => lstat(target, { bigint: true }) as Promise<BigStats>,
  open: async (target, flags) => {
    const handle = await open(target, flags);
    return {
      stat: () => handle.stat({ bigint: true }) as Promise<BigStats>,
      read: (buffer, offset, length, position) => handle.read(buffer, offset, length, position),
      close: () => handle.close(),
    };
  },
};

export class CogsSharedSkillOciLayoutError extends Error {
  public readonly code = "COGS_SHARED_SKILL_OCI_LAYOUT_INVALID";
  public constructor() {
    super("invalid shared skill OCI layout");
    this.name = "CogsSharedSkillOciLayoutError";
  }
}

export async function createCogsSharedSkillOciLayoutResolver(
  options: CogsSharedSkillOciLayoutOptions,
): Promise<CogsSharedSkillOciResolver> {
  try {
    const snapshot = snapshotOptions(options);
    const fs = mergeFs(snapshot.fs);
    const layoutRoot = await validateRoot(fs, snapshot.layoutRoot);
    return Object.freeze({
      resolve: (input: CogsSharedSkillOciResolveInput) => resolveLayout(fs, layoutRoot, input),
    });
  } catch (error) {
    if (error instanceof CogsSharedSkillOciLayoutError) throw error;
    throw new CogsSharedSkillOciLayoutError();
  }
}

async function resolveLayout(
  fs: CogsSharedSkillOciFs,
  layoutRoot: string,
  input: CogsSharedSkillOciResolveInput,
): Promise<CogsSharedSkillOciResult> {
  try {
    const request = snapshotResolveInput(input);
    const manifestDigest = validateDigest(request.manifestDigest);
    const signal = validateSignal(request.signal);
    throwIfAborted(signal);
    const layoutBytes = await readRegularFile(
      fs,
      joinTrusted(layoutRoot, "oci-layout"),
      layoutRoot,
      MAX_LAYOUT_JSON_BYTES,
      signal,
    );
    const layout = parseCanonical(layoutBytes, serializeLayout, validateLayout);
    if (layout.imageLayoutVersion !== "1.0.0") throw new CogsSharedSkillOciLayoutError();
    const index = parseCanonical(
      await readRegularFile(fs, joinTrusted(layoutRoot, "index.json"), layoutRoot, MAX_INDEX_BYTES, signal),
      serializeIndex,
      validateIndex,
    );
    const indexDescriptor = index.manifests[0];
    if (indexDescriptor.digest !== manifestDigest) throw new CogsSharedSkillOciLayoutError();
    const manifestBytes = await readBlob(
      fs,
      layoutRoot,
      manifestDigest,
      indexDescriptor.size,
      MAX_MANIFEST_BYTES,
      signal,
    );
    const manifest = parseCanonical(manifestBytes, serializeManifest, validateManifest);
    const configBytes = await readBlob(
      fs,
      layoutRoot,
      manifest.config.digest,
      manifest.config.size,
      MAX_CONFIG_BYTES,
      signal,
    );
    if (!configBytes.equals(Buffer.from("{}", "utf8"))) throw new CogsSharedSkillOciLayoutError();
    const layer = manifest.layers[0];
    const bundleBytes = await readBlob(
      fs,
      layoutRoot,
      layer.digest,
      layer.size,
      COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES,
      signal,
    );
    const bundle = verifyCogsSkillBundle(bundleBytes);
    if (bundle.digest !== layer.digest) throw new CogsSharedSkillOciLayoutError();
    return Object.freeze({
      scope: "shared" as const,
      manifestDigest,
      bundleDigest: bundle.digest,
      manifestBytes: manifestBytes.length,
      bundleBytes: bundle.byteLength,
      configBytes: configBytes.length,
      fileCount: bundle.fileCount,
      decodedByteLength: bundle.decodedByteLength,
      bundle,
    });
  } catch (error) {
    if (error instanceof CogsSharedSkillOciLayoutError) throw error;
    throw new CogsSharedSkillOciLayoutError();
  }
}

async function readBlob(
  fs: CogsSharedSkillOciFs,
  layoutRoot: string,
  digest: `sha256:${string}`,
  expectedSize: number,
  maxBytes: number,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  const bytes = await readRegularFile(fs, blobPath(layoutRoot, digest), layoutRoot, maxBytes, signal);
  if (bytes.length !== expectedSize || sha256(bytes) !== digest) throw new CogsSharedSkillOciLayoutError();
  return bytes;
}

async function readRegularFile(
  fs: CogsSharedSkillOciFs,
  file: string,
  layoutRoot: string,
  maxBytes: number,
  signal: AbortSignal | undefined,
): Promise<Buffer> {
  throwIfAborted(signal);
  assertContained(await fs.realpath(path.dirname(file)), layoutRoot);
  const before = await fs.lstat(file);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.size < 0n ||
    before.size > BigInt(maxBytes)
  )
    throw new CogsSharedSkillOciLayoutError();
  const handle = await fs.open(file, constants.O_RDONLY | O_NOFOLLOW);
  let primary: unknown;
  let output: Buffer | undefined;
  try {
    const opened = await handle.stat();
    if (!sameStats(before, opened) || !opened.isFile() || opened.nlink !== 1n)
      throw new CogsSharedSkillOciLayoutError();
    const size = Number(opened.size);
    output = Buffer.alloc(size);
    let position = 0;
    while (position < size) {
      throwIfAborted(signal);
      const requested = size - position;
      const { bytesRead } = await handle.read(output, position, requested, position);
      if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0 || bytesRead > requested)
        throw new CogsSharedSkillOciLayoutError();
      position += bytesRead;
    }
    const after = await handle.stat();
    if (!sameStats(opened, after)) throw new CogsSharedSkillOciLayoutError();
  } catch (error) {
    primary = error;
  }
  try {
    await handle.close();
  } catch {
    if (primary === undefined) throw new CogsSharedSkillOciLayoutError();
  }
  if (primary !== undefined) throw primary;
  if (output === undefined) throw new CogsSharedSkillOciLayoutError();
  return output;
}

function parseCanonical<T>(bytes: Buffer, serialize: (value: T) => Buffer, validate: (value: unknown) => T): T {
  const text = DECODER.decode(bytes);
  const value = validate(JSON.parse(text));
  if (!serialize(value).equals(bytes)) throw new CogsSharedSkillOciLayoutError();
  return value;
}

type Descriptor = Readonly<{
  mediaType: string;
  digest: `sha256:${string}`;
  size: number;
  artifactType?: string;
}>;

type Layout = Readonly<{ imageLayoutVersion: "1.0.0" }>;
type Index = Readonly<{ schemaVersion: 2; manifests: readonly [Descriptor] }>;
type Manifest = Readonly<{
  schemaVersion: 2;
  mediaType: string;
  artifactType: string;
  config: Descriptor;
  layers: readonly [Descriptor];
}>;

function validateLayout(value: unknown): Layout {
  const snapshot = snapshotExact(value, ["imageLayoutVersion"]);
  if (snapshot.imageLayoutVersion !== "1.0.0") throw new CogsSharedSkillOciLayoutError();
  return { imageLayoutVersion: "1.0.0" };
}

function validateIndex(value: unknown): Index {
  const snapshot = snapshotExact(value, ["schemaVersion", "manifests"]);
  if (snapshot.schemaVersion !== 2) throw new CogsSharedSkillOciLayoutError();
  const manifests = snapshotArray(snapshot.manifests, 1);
  return { schemaVersion: 2, manifests: [validateDescriptor(manifests[0], true, COGS_OCI_MANIFEST_MEDIA_TYPE)] };
}

function validateManifest(value: unknown): Manifest {
  const snapshot = snapshotExact(value, ["schemaVersion", "mediaType", "artifactType", "config", "layers"]);
  if (snapshot.schemaVersion !== 2 || snapshot.mediaType !== COGS_OCI_MANIFEST_MEDIA_TYPE)
    throw new CogsSharedSkillOciLayoutError();
  if (snapshot.artifactType !== COGS_SKILLS_BUNDLE_MEDIA_TYPE) throw new CogsSharedSkillOciLayoutError();
  const layers = snapshotArray(snapshot.layers, 1);
  return {
    schemaVersion: 2,
    mediaType: COGS_OCI_MANIFEST_MEDIA_TYPE,
    artifactType: COGS_SKILLS_BUNDLE_MEDIA_TYPE,
    config: validateDescriptor(snapshot.config, false, COGS_OCI_EMPTY_CONFIG_MEDIA_TYPE),
    layers: [validateDescriptor(layers[0], false, COGS_SKILLS_BUNDLE_MEDIA_TYPE)],
  };
}

function validateDescriptor(value: unknown, requireArtifactType: boolean, mediaType: string): Descriptor {
  const keys = requireArtifactType ? ["mediaType", "digest", "size", "artifactType"] : ["mediaType", "digest", "size"];
  const snapshot = snapshotExact(value, keys);
  if (snapshot.mediaType !== mediaType) throw new CogsSharedSkillOciLayoutError();
  const digest = validateDigest(snapshot.digest);
  const size = validateSafeInteger(snapshot.size, 0, COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES);
  if (requireArtifactType && snapshot.artifactType !== COGS_SKILLS_BUNDLE_MEDIA_TYPE)
    throw new CogsSharedSkillOciLayoutError();
  return { mediaType, digest, size, ...(requireArtifactType ? { artifactType: COGS_SKILLS_BUNDLE_MEDIA_TYPE } : {}) };
}

function serializeLayout(value: Layout): Buffer {
  return Buffer.from(JSON.stringify({ imageLayoutVersion: value.imageLayoutVersion }), "utf8");
}

function serializeIndex(value: Index): Buffer {
  const descriptor = value.manifests[0];
  return Buffer.from(
    JSON.stringify({
      schemaVersion: value.schemaVersion,
      manifests: [
        {
          mediaType: descriptor.mediaType,
          digest: descriptor.digest,
          size: descriptor.size,
          artifactType: descriptor.artifactType,
        },
      ],
    }),
    "utf8",
  );
}

function serializeManifest(value: Manifest): Buffer {
  const config = value.config;
  const layer = value.layers[0];
  return Buffer.from(
    JSON.stringify({
      schemaVersion: value.schemaVersion,
      mediaType: value.mediaType,
      artifactType: value.artifactType,
      config: { mediaType: config.mediaType, digest: config.digest, size: config.size },
      layers: [{ mediaType: layer.mediaType, digest: layer.digest, size: layer.size }],
    }),
    "utf8",
  );
}

function snapshotExact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsSharedSkillOciLayoutError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsSharedSkillOciLayoutError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (names.length !== keys.length || !names.every((name) => typeof name === "string" && keys.includes(name)))
    throw new CogsSharedSkillOciLayoutError();
  const snapshot: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
      throw new CogsSharedSkillOciLayoutError();
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function snapshotArray(value: unknown, expectedLength: number): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
    throw new CogsSharedSkillOciLayoutError();
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>;
  const names = Reflect.ownKeys(descriptors);
  if (!names.every((name) => typeof name === "string") || names.length !== expectedLength + 1)
    throw new CogsSharedSkillOciLayoutError();
  const length = descriptors.length;
  if (length === undefined || !("value" in length) || length.value !== expectedLength)
    throw new CogsSharedSkillOciLayoutError();
  const output: unknown[] = [];
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[`${index}`];
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
      throw new CogsSharedSkillOciLayoutError();
    output.push(descriptor.value);
  }
  for (const name of names) if (name !== "length" && name !== "0") throw new CogsSharedSkillOciLayoutError();
  return output;
}

function snapshotOptions(value: unknown): { layoutRoot: string; fs?: Partial<CogsSharedSkillOciFs> } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsSharedSkillOciLayoutError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsSharedSkillOciLayoutError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (!names.every((name) => typeof name === "string" && (name === "layoutRoot" || name === "fs")))
    throw new CogsSharedSkillOciLayoutError();
  const layoutRoot = dataValue(descriptors.layoutRoot);
  const fs = descriptors.fs === undefined ? undefined : dataValue(descriptors.fs);
  if (typeof layoutRoot !== "string") throw new CogsSharedSkillOciLayoutError();
  return { layoutRoot, ...(fs === undefined ? {} : { fs: snapshotFs(fs) }) };
}

function snapshotResolveInput(value: unknown): { manifestDigest: unknown; signal: unknown } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsSharedSkillOciLayoutError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsSharedSkillOciLayoutError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (!names.every((name) => typeof name === "string" && (name === "manifestDigest" || name === "signal")))
    throw new CogsSharedSkillOciLayoutError();
  return {
    manifestDigest: dataValue(descriptors.manifestDigest),
    signal: descriptors.signal ? dataValue(descriptors.signal) : undefined,
  };
}

function dataValue(descriptor: PropertyDescriptor | undefined): unknown {
  if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
    throw new CogsSharedSkillOciLayoutError();
  return descriptor.value;
}

function snapshotFs(value: unknown): Partial<CogsSharedSkillOciFs> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new CogsSharedSkillOciLayoutError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new CogsSharedSkillOciLayoutError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  const allowed: readonly (keyof CogsSharedSkillOciFs)[] = ["realpath", "lstat", "open"];
  if (!names.every((name) => typeof name === "string" && allowed.includes(name as keyof CogsSharedSkillOciFs)))
    throw new CogsSharedSkillOciLayoutError();
  const snapshot: Partial<CogsSharedSkillOciFs> = {};
  for (const name of names) {
    if (typeof name !== "string") throw new CogsSharedSkillOciLayoutError();
    const value = dataValue(descriptors[name]);
    if (typeof value !== "function") throw new CogsSharedSkillOciLayoutError();
    (snapshot as Record<string, unknown>)[name] = value;
  }
  return snapshot;
}

function mergeFs(overrides: Partial<CogsSharedSkillOciFs> | undefined): CogsSharedSkillOciFs {
  if (overrides === undefined) return REAL_FS;
  return { ...REAL_FS, ...overrides };
}

async function validateRoot(fs: CogsSharedSkillOciFs, value: string): Promise<string> {
  if (!path.isAbsolute(value)) throw new CogsSharedSkillOciLayoutError();
  const supplied = await fs.lstat(value);
  if (!supplied.isDirectory() || supplied.isSymbolicLink()) throw new CogsSharedSkillOciLayoutError();
  const resolved = await fs.realpath(value);
  if (!path.isAbsolute(resolved)) throw new CogsSharedSkillOciLayoutError();
  const stat = await fs.lstat(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new CogsSharedSkillOciLayoutError();
  if (!sameStats(supplied, stat)) throw new CogsSharedSkillOciLayoutError();
  return resolved;
}

function validateDigest(value: unknown): `sha256:${string}` {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw new CogsSharedSkillOciLayoutError();
  return value as `sha256:${string}`;
}

function validateSafeInteger(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new CogsSharedSkillOciLayoutError();
  return value;
}

function blobPath(layoutRoot: string, digest: `sha256:${string}`): string {
  return joinTrusted(layoutRoot, "blobs", "sha256", digest.slice("sha256:".length));
}

function joinTrusted(root: string, ...segments: string[]): string {
  return path.join(root, ...segments);
}

function assertContained(target: string, root: string): void {
  const relative = path.relative(root, target);
  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) return;
  throw new CogsSharedSkillOciLayoutError();
}

function sameStats(left: BigStats, right: BigStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function validateSignal(value: unknown): AbortSignal | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof AbortSignal)) throw new CogsSharedSkillOciLayoutError();
  return value;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CogsSharedSkillOciLayoutError();
}

function sha256(bytes: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
