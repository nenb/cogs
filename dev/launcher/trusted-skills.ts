import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rmdir, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  buildCogsSkillBundle,
  COGS_SKILLS_BUNDLE_MEDIA_TYPE,
  type CogsSkillBundleHandle,
} from "../../src/skills/bundle.ts";
import { createCogsPrivateSkillStore } from "../../src/skills/local-private-store.ts";
import {
  COGS_OCI_EMPTY_CONFIG_MEDIA_TYPE,
  COGS_OCI_MANIFEST_MEDIA_TYPE,
  createCogsSharedSkillOciLayoutResolver,
} from "../../src/skills/oci-layout.ts";
import {
  type CogsPreparedSkills,
  type CogsSkillPreparerPort,
  createCogsSkillSessionPreparer,
} from "../../src/skills/session-preparer.ts";
import { SshConnectionManager } from "../../src/ssh/connection.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";

export type TrustedSkillInputs = Readonly<{
  sharedRevision: `sha256:${string}`;
  userRevision: `sha256:${string}`;
  createPreparer(manager: SshConnectionManager): CogsSkillPreparerPort;
  close(): Promise<void>;
}>;

export type TrustedSkillSeams = Readonly<{
  after?: (stage: string) => void | Promise<void>;
}>;

type StableStat = Pick<
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

type InventoryItem = Readonly<{
  path: string;
  kind: "file" | "directory";
  mode: number;
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}>;

const ROOT_NAME = "trusted-skills";
const SENTINEL_NAME = ".cogs-trusted-skills-owner";
const MAX_STATIC_DEPTH = 8;
const MAX_STATIC_ENTRIES = 64;
const MAX_STATIC_PATH_BYTES = 512;
const EMPTY_BUNDLE_DIGEST = "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c" as const;
const EMPTY_CONFIG_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" as const;
const EMPTY_MANIFEST_DIGEST = "sha256:726176e9bdb7524fbe935a0235fcbe5d509bf44592b9571421fc9fd8551ff1c1" as const;
const EMPTY_INDEX_DIGEST = "sha256:8774a0322b44a711ccfb252d59ab4dc9bcdc09d791f9a72b985765931d305111" as const;
const ALICE_NAMESPACE = "sha256:2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90" as const;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

export async function createTrustedSkillInputs(
  state: LauncherState,
  signal?: AbortSignal,
  seams?: TrustedSkillSeams,
): Promise<TrustedSkillInputs> {
  validateOptionalSignal(signal);
  const trustedSeams = captureSeams(seams);
  const root = join(state.sandboxDir, ROOT_NAME);
  const sharedRoot = join(root, "shared-oci");
  const privateSourceRoot = join(root, "private-source");
  const privateStoreRoot = join(root, "private-store");
  const inventory: InventoryItem[] = [];
  let activePrepared = 0;
  let closing = false;
  let closePromise: Promise<void> | undefined;
  try {
    const manifest = await readManifest(state);
    if (manifest.phase !== "sandbox-ready" || manifest.sourceRevision !== state.sourceRevision) fail();
    await strictDirectory(state.sandboxDir, 0o700);
    throwIfAborted(signal);

    await createDirectory(root, state.sandboxDir, inventory, trustedSeams);
    await createFile(
      join(root, SENTINEL_NAME),
      Buffer.from(`${state.stateId}\n`, "utf8"),
      root,
      inventory,
      trustedSeams,
    );
    await createDirectory(sharedRoot, root, inventory, trustedSeams);
    await createDirectory(join(sharedRoot, "blobs"), sharedRoot, inventory, trustedSeams);
    await createDirectory(join(sharedRoot, "blobs", "sha256"), join(sharedRoot, "blobs"), inventory, trustedSeams);
    await createDirectory(privateSourceRoot, root, inventory, trustedSeams);
    await createDirectory(privateStoreRoot, root, inventory, trustedSeams);
    await createDirectory(
      join(privateSourceRoot, digestHex(ALICE_NAMESPACE)),
      privateSourceRoot,
      inventory,
      trustedSeams,
    );
    await trustedSeams.after?.("after-directories");
    throwIfAborted(signal);

    const bundle = requireEmptyBundle(buildCogsSkillBundle({ entries: [] }));
    const configBytes = Buffer.from("{}", "utf8");
    requireDigest(configBytes, EMPTY_CONFIG_DIGEST, 2);
    const manifestBytes = canonicalManifest(bundle, configBytes);
    requireDigest(manifestBytes, EMPTY_MANIFEST_DIGEST, 451);
    const indexBytes = canonicalIndex(manifestBytes);
    requireDigest(indexBytes, EMPTY_INDEX_DIGEST, 246);
    const layoutBytes = Buffer.from('{"imageLayoutVersion":"1.0.0"}', "utf8");

    const blobRoot = join(sharedRoot, "blobs", "sha256");
    await createFile(join(sharedRoot, "oci-layout"), layoutBytes, sharedRoot, inventory, trustedSeams);
    await createFile(join(sharedRoot, "index.json"), indexBytes, sharedRoot, inventory, trustedSeams);
    await createFile(join(blobRoot, digestHex(EMPTY_CONFIG_DIGEST)), configBytes, blobRoot, inventory, trustedSeams);
    await createFile(
      join(blobRoot, digestHex(EMPTY_BUNDLE_DIGEST)),
      bundle.copyBytes(),
      blobRoot,
      inventory,
      trustedSeams,
    );
    await createFile(
      join(blobRoot, digestHex(EMPTY_MANIFEST_DIGEST)),
      manifestBytes,
      blobRoot,
      inventory,
      trustedSeams,
    );
    await trustedSeams.after?.("after-shared-files");
    throwIfAborted(signal);

    const sharedResolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: sharedRoot });
    const sharedRequest =
      signal === undefined
        ? { manifestDigest: EMPTY_MANIFEST_DIGEST }
        : { manifestDigest: EMPTY_MANIFEST_DIGEST, signal };
    const resolvedShared = await sharedResolver.resolve(sharedRequest);
    if (
      resolvedShared.manifestDigest !== EMPTY_MANIFEST_DIGEST ||
      resolvedShared.bundleDigest !== EMPTY_BUNDLE_DIGEST ||
      resolvedShared.fileCount !== 0
    )
      fail();
    const privateStore = await createCogsPrivateSkillStore({
      sourceRoot: privateSourceRoot,
      storeRoot: privateStoreRoot,
    });
    const userRequest =
      signal === undefined
        ? { userId: "alice", expectedDigest: EMPTY_BUNDLE_DIGEST }
        : { userId: "alice", expectedDigest: EMPTY_BUNDLE_DIGEST, signal };
    const resolvedUser = await privateStore.snapshot(userRequest);
    if (resolvedUser.digest !== EMPTY_BUNDLE_DIGEST || resolvedUser.fileCount !== 0) fail();
    await capturePrivateStore(privateStoreRoot, inventory);
    await trustedSeams.after?.("after-private-store");
    throwIfAborted(signal);
    await verifyInventory(root, inventory, state.stateId, trustedSeams);
    inventory.splice(0, inventory.length, ...(await snapshotInventory(root)));
    await trustedSeams.after?.("after-final-snapshot");
    await verifyInventory(root, inventory, state.stateId, trustedSeams);

    const createPreparer = Object.freeze((manager: SshConnectionManager): CogsSkillPreparerPort => {
      if (closing || !(manager instanceof SshConnectionManager)) fail();
      const real = createCogsSkillSessionPreparer({ ssh: manager, sharedResolver, privateStore });
      return Object.freeze({
        prepare: async (input: Parameters<CogsSkillPreparerPort["prepare"]>[0]) => {
          if (closing) fail();
          activePrepared += 1;
          let prepared: CogsPreparedSkills;
          try {
            prepared = await real.prepare(input);
          } catch {
            activePrepared -= 1;
            throw failure();
          }
          let disposePromise: Promise<void> | undefined;
          const dispose = Object.freeze(() => {
            disposePromise ??= prepared.dispose().then(
              () => {
                activePrepared -= 1;
              },
              () => {
                throw failure();
              },
            );
            return disposePromise;
          });
          return Object.freeze({
            piSkills: prepared.piSkills,
            eagerTrustedSkillPrompt: prepared.eagerTrustedSkillPrompt,
            agentsFiles: prepared.agentsFiles,
            metadata: prepared.metadata,
            dispose,
          });
        },
      });
    });
    const close = Object.freeze(() => {
      closePromise ??= (async () => {
        closing = true;
        if (activePrepared !== 0) fail();
        await verifyInventory(root, inventory, state.stateId, trustedSeams);
        await removeInventory(root, state.sandboxDir, inventory, trustedSeams);
      })().catch(() => {
        throw failure();
      });
      return closePromise;
    });
    return Object.freeze({
      sharedRevision: EMPTY_MANIFEST_DIGEST,
      userRevision: EMPTY_BUNDLE_DIGEST,
      createPreparer,
      close,
    });
  } catch {
    closing = true;
    await rollbackIfExact(root, state.sandboxDir, inventory).catch(() => undefined);
    throw failure();
  }
}

function requireEmptyBundle(bundle: CogsSkillBundleHandle): CogsSkillBundleHandle {
  const bytes = bundle.copyBytes();
  requireDigest(bytes, EMPTY_BUNDLE_DIGEST, 109);
  if (bundle.digest !== EMPTY_BUNDLE_DIGEST || bundle.fileCount !== 0 || bundle.decodedByteLength !== 0) fail();
  if (
    bytes.toString("utf8") !==
    '{"version":"cogs.dev/skills-bundle/v1","mediaType":"application/vnd.cogs.skills.bundle.v1+json","entries":[]}'
  )
    fail();
  return bundle;
}

function canonicalManifest(bundle: CogsSkillBundleHandle, config: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: COGS_OCI_MANIFEST_MEDIA_TYPE,
      artifactType: COGS_SKILLS_BUNDLE_MEDIA_TYPE,
      config: {
        mediaType: COGS_OCI_EMPTY_CONFIG_MEDIA_TYPE,
        digest: digest(config),
        size: config.length,
      },
      layers: [{ mediaType: COGS_SKILLS_BUNDLE_MEDIA_TYPE, digest: bundle.digest, size: bundle.byteLength }],
    }),
    "utf8",
  );
}

function canonicalIndex(manifest: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      manifests: [
        {
          mediaType: COGS_OCI_MANIFEST_MEDIA_TYPE,
          digest: digest(manifest),
          size: manifest.length,
          artifactType: COGS_SKILLS_BUNDLE_MEDIA_TYPE,
        },
      ],
    }),
    "utf8",
  );
}

async function createDirectory(
  path: string,
  parent: string,
  inventory: InventoryItem[],
  seams: TrustedSkillSeams,
): Promise<void> {
  await strictDirectory(parent, 0o700);
  await mkdir(path, { recursive: false, mode: 0o700 });
  const stat = await strictDirectory(path, 0o700);
  inventory.push(item(path, "directory", 0o700, stat));
  await seams.after?.("after-directory-create");
  await syncDirectory(parent);
}

async function createFile(
  path: string,
  bytes: Buffer,
  parent: string,
  inventory: InventoryItem[],
  seams: TrustedSkillSeams,
): Promise<void> {
  await strictDirectory(parent, 0o700);
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | O_NOFOLLOW, 0o600);
  let closed = false;
  try {
    const opened = await handle.stat();
    requireFile(opened, 0o600);
    if (opened.size !== 0) fail();
    await handle.writeFile(bytes);
    await handle.sync();
    const reread = Buffer.alloc(bytes.length);
    let position = 0;
    while (position < reread.length) {
      const result = await handle.read(reread, position, reread.length - position, position);
      if (result.bytesRead <= 0 || result.bytesRead > reread.length - position) fail();
      position += result.bytesRead;
    }
    if (!reread.equals(bytes)) fail();
    const after = await handle.stat();
    requireFile(after, 0o600);
    if (opened.dev !== after.dev || opened.ino !== after.ino || after.size !== bytes.length) fail();
    await handle.close();
    closed = true;
    const final = await lstat(path);
    requireFile(final, 0o600);
    if (final.dev !== after.dev || final.ino !== after.ino || final.size !== bytes.length) fail();
    inventory.push(item(path, "file", 0o600, final));
    await seams.after?.("after-file-create");
    await syncDirectory(parent);
  } finally {
    if (!closed) await handle.close().catch(() => undefined);
  }
}

async function capturePrivateStore(root: string, inventory: InventoryItem[]): Promise<void> {
  const namespace = join(root, digestHex(ALICE_NAMESPACE));
  const blobs = join(namespace, "blobs");
  const sha = join(blobs, "sha256");
  const bundle = join(sha, digestHex(EMPTY_BUNDLE_DIGEST));
  for (const path of [namespace, blobs, sha]) {
    const stat = await strictDirectory(path, 0o700);
    inventory.push(item(path, "directory", 0o700, stat));
  }
  const stat = await strictFile(bundle, 0o600);
  if (stat.size !== 109) fail();
  inventory.push(item(bundle, "file", 0o600, stat));
  await requireExactEntries(root, [digestHex(ALICE_NAMESPACE)]);
  await requireExactEntries(namespace, ["blobs"]);
  await requireExactEntries(blobs, ["sha256"]);
  await requireExactEntries(sha, [digestHex(EMPTY_BUNDLE_DIGEST)]);
}

async function verifyInventory(
  root: string,
  inventory: readonly InventoryItem[],
  stateId: string,
  seams: TrustedSkillSeams,
): Promise<void> {
  const actual = await walk(root);
  const expected = new Map(inventory.map((entry) => [entry.path, entry]));
  if (actual.length !== expected.size) fail();
  for (const path of actual) {
    const entry = expected.get(path);
    if (entry === undefined) fail();
    const stat = await lstat(path);
    if (stat.dev !== entry.dev || stat.ino !== entry.ino || (stat.mode & 0o777) !== entry.mode) fail();
    if (
      entry.kind === "file" &&
      (stat.size !== entry.size || stat.mtimeMs !== entry.mtimeMs || stat.ctimeMs !== entry.ctimeMs)
    )
      fail();
    if (entry.kind === "file") await strictFile(entry.path, entry.mode);
    else await strictDirectory(entry.path, entry.mode);
  }
  if (stateId !== "") await verifySentinel(root, stateId, seams);
}

async function verifySentinel(root: string, stateId: string, seams: TrustedSkillSeams): Promise<void> {
  const bytes = await readFileBytes(join(root, SENTINEL_NAME), 128, seams);
  try {
    if (bytes.toString("utf8") !== `${stateId}\n`) fail();
  } finally {
    bytes.fill(0);
  }
}

async function readFileBytes(path: string, maxBytes: number, seams: TrustedSkillSeams): Promise<Buffer> {
  const before = await strictFile(path, 0o600);
  if (before.size > maxBytes) fail();
  const handle = await open(path, constants.O_RDONLY | O_NOFOLLOW);
  let output: Buffer | undefined;
  try {
    const opened = await handle.stat();
    requireFileIdentity(before, opened, 0o600);
    await seams.after?.("after-sentinel-open");
    output = Buffer.alloc(opened.size);
    let position = 0;
    while (position < output.length) {
      const result = await handle.read(output, position, output.length - position, position);
      if (
        !Number.isSafeInteger(result.bytesRead) ||
        result.bytesRead <= 0 ||
        result.bytesRead > output.length - position
      )
        fail();
      position += result.bytesRead;
    }
    const after = await handle.stat();
    requireFileIdentity(opened, after, 0o600);
    const pathAfter = await strictFile(path, 0o600);
    requireFileIdentity(opened, pathAfter, 0o600);
    const bytes = output;
    output = undefined;
    return bytes;
  } finally {
    output?.fill(0);
    await handle.close();
  }
}

async function snapshotInventory(root: string): Promise<InventoryItem[]> {
  const output: InventoryItem[] = [];
  for (const path of await walk(root)) {
    const stat = await lstat(path);
    const kind = stat.isDirectory() ? "directory" : "file";
    const mode = kind === "directory" ? 0o700 : 0o600;
    if (kind === "directory") await strictDirectory(path, mode);
    else await strictFile(path, mode);
    output.push(item(path, kind, mode, stat));
  }
  return output;
}

async function removeInventory(
  root: string,
  parent: string,
  inventory: readonly InventoryItem[],
  seams: TrustedSkillSeams,
): Promise<void> {
  const files = inventory.filter((entry) => entry.kind === "file").sort(deepestFirst);
  const directories = inventory.filter((entry) => entry.kind === "directory").sort(deepestFirst);
  for (const entry of files) {
    await requireIdentity(entry);
    await unlink(entry.path);
    await seams.after?.("after-file-unlink");
    await requireAbsent(entry.path);
    await syncDirectory(dirname(entry.path));
  }
  for (const entry of directories) {
    await requireIdentity(entry);
    if ((await readdir(entry.path)).length !== 0) fail();
    await rmdir(entry.path);
    await seams.after?.("after-directory-rmdir");
    await requireAbsent(entry.path);
    await syncDirectory(entry.path === root ? parent : dirname(entry.path));
  }
  await strictDirectory(parent, 0o700);
}

async function rollbackIfExact(root: string, parent: string, inventory: readonly InventoryItem[]): Promise<void> {
  try {
    await lstat(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  await verifyInventory(root, inventory, "", Object.freeze({}));
  await removeInventory(root, parent, inventory, Object.freeze({}));
}

async function walk(root: string): Promise<string[]> {
  const output: string[] = [];
  const visit = async (directory: string, depth: number): Promise<void> => {
    if (depth > MAX_STATIC_DEPTH || Buffer.byteLength(directory, "utf8") > MAX_STATIC_PATH_BYTES) fail();
    await strictDirectory(directory, 0o700);
    const entries = await readdir(directory);
    if (entries.length > MAX_STATIC_ENTRIES) fail();
    for (const name of entries) {
      if (!safeName(name)) fail();
      const path = join(directory, name);
      if (Buffer.byteLength(path, "utf8") > MAX_STATIC_PATH_BYTES) fail();
      const stat = await lstat(path);
      output.push(path);
      if (output.length > MAX_STATIC_ENTRIES) fail();
      if (stat.isDirectory()) {
        await strictDirectory(path, 0o700);
        await visit(path, depth + 1);
      } else if (stat.isFile()) {
        await strictFile(path, 0o600);
      } else fail();
    }
  };
  await strictDirectory(root, 0o700);
  output.push(root);
  await visit(root, 0);
  return output;
}

async function requireIdentity(entry: InventoryItem): Promise<void> {
  const stat = await lstat(entry.path);
  if (stat.dev !== entry.dev || stat.ino !== entry.ino || (stat.mode & 0o777) !== entry.mode) fail();
  if (
    entry.kind === "file" &&
    (stat.size !== entry.size || stat.mtimeMs !== entry.mtimeMs || stat.ctimeMs !== entry.ctimeMs)
  )
    fail();
  if (entry.kind === "file") await strictFile(entry.path, entry.mode);
  else await strictDirectory(entry.path, entry.mode);
}

async function strictDirectory(path: string, mode: number): Promise<StableStat> {
  const stat = await lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== mode ||
    stat.uid !== currentUid() ||
    (await realpath(path)) !== path
  )
    fail();
  return stat;
}

async function strictFile(path: string, mode: number): Promise<StableStat> {
  const stat = await lstat(path);
  requireFile(stat, mode);
  if ((await realpath(path)) !== path) fail();
  return stat;
}

function requireFile(stat: StableStat, mode: number): void {
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== mode ||
    stat.uid !== currentUid()
  )
    fail();
}

async function requireExactEntries(path: string, expected: readonly string[]): Promise<void> {
  if ((await readdir(path)).sort().join("\0") !== [...expected].sort().join("\0")) fail();
}

async function syncDirectory(path: string): Promise<void> {
  const before = await strictDirectory(path, 0o700);
  const handle = await open(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    requireDirectoryIdentity(before, opened, 0o700);
    await handle.sync();
    const after = await handle.stat();
    requireDirectoryIdentity(opened, after, 0o700);
    const pathAfter = await strictDirectory(path, 0o700);
    requireDirectoryIdentity(opened, pathAfter, 0o700);
  } finally {
    await handle.close();
  }
}

async function requireAbsent(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  fail();
}

function requireFileIdentity(before: StableStat, after: StableStat, mode: number): void {
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs ||
    before.ctimeMs !== after.ctimeMs ||
    !after.isFile() ||
    after.isSymbolicLink() ||
    after.nlink !== 1 ||
    (after.mode & 0o777) !== mode ||
    after.uid !== currentUid() ||
    before.uid !== after.uid
  )
    fail();
}

function requireDirectoryIdentity(before: StableStat, after: StableStat, mode: number): void {
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    !after.isDirectory() ||
    after.isSymbolicLink() ||
    (after.mode & 0o777) !== mode ||
    after.uid !== currentUid() ||
    before.uid !== after.uid
  )
    fail();
}

function safeName(name: string): boolean {
  return name.length > 0 && name !== "." && name !== ".." && !name.includes("/") && !name.includes("\0");
}

function item(path: string, kind: InventoryItem["kind"], mode: number, stat: StableStat): InventoryItem {
  return Object.freeze({
    path,
    kind,
    mode,
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  });
}

function deepestFirst(left: InventoryItem, right: InventoryItem): number {
  return right.path.split("/").length - left.path.split("/").length;
}

function digest(bytes: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function requireDigest(bytes: Buffer, expected: string, size: number): void {
  if (bytes.length !== size || digest(bytes) !== expected) fail();
}

function digestHex(value: string): string {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) fail();
  return value.slice("sha256:".length);
}

function currentUid(): number {
  if (typeof process.geteuid !== "function") fail();
  return process.geteuid();
}

function captureSeams(value: TrustedSkillSeams | undefined): TrustedSkillSeams {
  if (value === undefined) return Object.freeze({});
  if (!Object.isFrozen(value) || Object.getPrototypeOf(value) !== Object.prototype) fail();
  if (Object.getOwnPropertySymbols(value).length !== 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors);
  if (names.some((key) => key !== "after")) fail();
  const after = descriptors.after;
  if (after === undefined) return Object.freeze({});
  if (
    !after.enumerable ||
    !Object.hasOwn(after, "value") ||
    typeof after.value !== "function" ||
    !Object.isFrozen(after.value)
  )
    fail();
  return Object.freeze({ after: after.value as (stage: string) => void | Promise<void> });
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
  return new Error("launcher trusted skills failed");
}
