import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { canonicalStage4OfflineReadinessBytes, stage4OfflineReadinessSha256 } from "./stage4-offline-readiness.ts";

export const STAGE4_SOURCE_INVENTORY_EXCLUSIONS = Object.freeze([
  "docs/security-evidence/stage4-offline-readiness-package.json",
  "docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json",
  "docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json",
] as const);

export const STAGE4_PINNED_GIT = Object.freeze({
  executable: "/usr/bin/git",
  version: "git version 2.50.1 (Apple Git-155)",
  sha256: "7588ceab299393618d6f8861502ac0588d1594025f301d9a61a898215b5571d3",
} as const);

const MAXIMUM_FILE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_GIT_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAXIMUM_TRACKED_FILES = 1208;
const MAXIMUM_AGGREGATE_BYTES = 18 * 1024 * 1024;
const WORKTREE_MERKLE_DOMAIN = "cogs.stage4/tracked-worktree-mode-path-byte-merkle/v2\0";
const UNTRACKED_VALIDATION_PREFIXES = Object.freeze([
  "deploy/helm/cogs/",
  "deploy/nic/",
  "images/",
  "schemas/",
  "scripts/",
  "spikes/",
  "src/",
  "test/",
  "third_party/",
]);

type GitFileMode = "100644" | "100755";

type TrackedFile = Readonly<{
  mode: GitFileMode;
  path: string;
}>;

type SourceInventoryEntry = Readonly<{
  mode: GitFileMode;
  path: string;
  sha256: string;
}>;

type Identity = Readonly<{
  dev: bigint;
  ino: bigint;
  mode: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
  nlink: bigint;
}>;

function identity(metadata: BigIntStats): Identity {
  return {
    dev: metadata.dev,
    ino: metadata.ino,
    mode: metadata.mode,
    size: metadata.size,
    mtimeNs: metadata.mtimeNs,
    ctimeNs: metadata.ctimeNs,
    nlink: metadata.nlink,
  };
}

function sameIdentity(left: Identity, right: Identity): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs &&
    left.nlink === right.nlink
  );
}

function safeComponents(path: string): string[] {
  const components = path.split("/");
  if (
    components.length === 0 ||
    components.some(
      (component) => component.length === 0 || component === "." || component === ".." || component.includes("\\"),
    )
  ) {
    throw new Error("STAGE4_SOURCE_INVENTORY_PATH_INVALID");
  }
  return components;
}

/**
 * Reads one repository file only through an O_NOFOLLOW descriptor. Every parent is opened and retained,
 * and its lstat/fstat identity is checked before and after the bounded final-descriptor read.
 */
export function readStage4SourceFile(
  root: string,
  path: string,
  maximum = MAXIMUM_FILE_BYTES,
  requireSingleLink = true,
  expectedGitMode?: GitFileMode,
): Uint8Array {
  const physicalRoot = realpathSync(root);
  const components = safeComponents(path);
  const descriptors: Array<{ fd: number; path: string; expected: Identity }> = [];
  try {
    let current = physicalRoot;
    const rootFd = openSync(physicalRoot, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const rootMetadata = fstatSync(rootFd, { bigint: true });
    if (!rootMetadata.isDirectory()) throw new Error("STAGE4_SOURCE_INVENTORY_COMPONENT_INVALID");
    descriptors.push({ fd: rootFd, path: physicalRoot, expected: identity(rootMetadata) });

    for (const [index, component] of components.entries()) {
      current = join(current, component);
      const beforePath = lstatSync(current, { bigint: true });
      const final = index === components.length - 1;
      if (beforePath.isSymbolicLink() || (final ? !beforePath.isFile() : !beforePath.isDirectory())) {
        throw new Error(
          final ? "STAGE4_SOURCE_INVENTORY_FILE_BOUND_INVALID" : "STAGE4_SOURCE_INVENTORY_COMPONENT_INVALID",
        );
      }
      const flags = constants.O_RDONLY | constants.O_NOFOLLOW | (final ? 0 : constants.O_DIRECTORY);
      const fd = openSync(current, flags);
      const opened = fstatSync(fd, { bigint: true });
      const expected = identity(opened);
      const pathIdentity = identity(beforePath);
      if (!sameIdentity(pathIdentity, expected) || (final ? !opened.isFile() : !opened.isDirectory())) {
        closeSync(fd);
        throw new Error("STAGE4_SOURCE_INVENTORY_FILE_RACE");
      }
      descriptors.push({ fd, path: current, expected });
    }

    const final = descriptors.at(-1);
    if (
      final === undefined ||
      final.expected.size <= 0n ||
      final.expected.size > BigInt(maximum) ||
      (requireSingleLink ? final.expected.nlink !== 1n : final.expected.nlink < 1n)
    ) {
      throw new Error("STAGE4_SOURCE_INVENTORY_FILE_BOUND_INVALID");
    }
    if (expectedGitMode !== undefined && ((final.expected.mode & 0o111n) !== 0n) !== (expectedGitMode === "100755")) {
      throw new Error("STAGE4_SOURCE_INVENTORY_FILE_MODE_INVALID");
    }
    const bytes = new Uint8Array(readFileSync(final.fd));
    if (BigInt(bytes.byteLength) !== final.expected.size) throw new Error("STAGE4_SOURCE_INVENTORY_FILE_RACE");

    for (const descriptor of descriptors) {
      const afterFd = identity(fstatSync(descriptor.fd, { bigint: true }));
      const afterPathMetadata = lstatSync(descriptor.path, { bigint: true });
      if (
        afterPathMetadata.isSymbolicLink() ||
        !sameIdentity(descriptor.expected, afterFd) ||
        !sameIdentity(afterFd, identity(afterPathMetadata))
      ) {
        throw new Error("STAGE4_SOURCE_INVENTORY_FILE_RACE");
      }
    }
    const physicalFile = realpathSync(final.path);
    if (!physicalFile.startsWith(`${physicalRoot}${sep}`) || relative(physicalRoot, physicalFile) !== path) {
      throw new Error("STAGE4_SOURCE_INVENTORY_COMPONENT_INVALID");
    }
    return bytes;
  } finally {
    for (const descriptor of descriptors.reverse()) closeSync(descriptor.fd);
  }
}

function pinnedGit(root: string, arguments_: readonly string[]): Uint8Array {
  const executable = readStage4SourceFile(dirname(STAGE4_PINNED_GIT.executable), "git", 64 * 1024 * 1024, false);
  if (stage4OfflineReadinessSha256(executable, 64 * 1024 * 1024) !== STAGE4_PINNED_GIT.sha256) {
    throw new Error("STAGE4_SOURCE_INVENTORY_GIT_IDENTITY_INVALID");
  }
  const result = spawnSync(STAGE4_PINNED_GIT.executable, ["-c", "core.fsmonitor=false", ...arguments_], {
    cwd: root,
    encoding: null,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      HOME: "/tmp",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
    maxBuffer: MAXIMUM_GIT_OUTPUT_BYTES,
    timeout: 10_000,
    shell: false,
  });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null || result.stderr.byteLength !== 0) {
    throw new Error("STAGE4_SOURCE_INVENTORY_GIT_FAILED");
  }
  return new Uint8Array(result.stdout);
}

function text(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function trackedFiles(root: string): TrackedFile[] {
  const version = text(pinnedGit(root, ["--version"])).trim();
  if (version !== STAGE4_PINNED_GIT.version) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_IDENTITY_INVALID");
  const top = realpathSync(text(pinnedGit(root, ["rev-parse", "--show-toplevel"])).trim());
  if (top !== root) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_ROOT_INVALID");
  const files: TrackedFile[] = [];
  for (const record of text(pinnedGit(root, ["ls-files", "--cached", "--stage", "-z"])).split("\0")) {
    if (record === "") continue;
    const match = /^(100644|100755) ([0-9a-f]{40,64}) 0\t(.+)$/u.exec(record);
    if (match === null || match[1] === undefined || match[3] === undefined)
      throw new Error("STAGE4_SOURCE_INVENTORY_GIT_ENTRY_INVALID");
    files.push({ mode: match[1] as GitFileMode, path: match[3] });
  }
  const untracked = text(pinnedGit(root, ["ls-files", "--others", "-z", "--", ...UNTRACKED_VALIDATION_PREFIXES]))
    .split("\0")
    .filter((path) => path !== "");
  if (
    untracked.some((path) =>
      UNTRACKED_VALIDATION_PREFIXES.some((prefix) => path === prefix.slice(0, -1) || path.startsWith(prefix)),
    )
  ) {
    throw new Error("STAGE4_SOURCE_INVENTORY_UNTRACKED_VALIDATION_INPUT_FORBIDDEN");
  }
  if (files.length === 0 || files.length > MAXIMUM_TRACKED_FILES)
    throw new Error("STAGE4_SOURCE_INVENTORY_FILE_COUNT_INVALID");
  return files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
}

export function stage4TrackedWorktreeMerkle(entries: readonly SourceInventoryEntry[]): string {
  return createHash("sha256")
    .update(WORKTREE_MERKLE_DOMAIN, "utf8")
    .update(canonicalStage4OfflineReadinessBytes(entries.map((entry) => ({ ...entry }))))
    .digest("hex");
}

export function stage4SourceClosurePaths(root: string): string[] {
  const physicalRoot = realpathSync(root);
  return trackedFiles(physicalRoot)
    .map((file) => file.path)
    .filter((path) => !STAGE4_SOURCE_INVENTORY_EXCLUSIONS.includes(path as never));
}

export function generateStage4SourceInventory(root: string): Uint8Array {
  const physicalRoot = realpathSync(root);
  const allTrackedFiles = trackedFiles(physicalRoot);
  const files = allTrackedFiles.filter((file) => !STAGE4_SOURCE_INVENTORY_EXCLUSIONS.includes(file.path as never));
  let aggregate = 0;
  const entries = files.map(({ mode, path }) => {
    const bytes = readStage4SourceFile(physicalRoot, path, MAXIMUM_FILE_BYTES, true, mode);
    aggregate += bytes.byteLength;
    if (aggregate > MAXIMUM_AGGREGATE_BYTES) throw new Error("STAGE4_SOURCE_INVENTORY_AGGREGATE_BOUND_INVALID");
    return { mode, path, sha256: stage4OfflineReadinessSha256(bytes) };
  });
  return canonicalStage4OfflineReadinessBytes({
    algorithm: "sha256-domain-separated-canonical-git-mode-path-and-exact-byte-digest-list",
    entries,
    excluded_generated_evidence_outputs: STAGE4_SOURCE_INVENTORY_EXCLUSIONS.map((path) => ({
      path,
      reason: "excluded-generated-evidence-recursion",
    })),
    scope: "complete-tracked-worktree-source-build-qualification-closure",
    version: "cogs.stage4-offline-source-inventory/v5",
    worktree_binding: {
      file_count: entries.length,
      git_executable_sha256: STAGE4_PINNED_GIT.sha256,
      git_version: STAGE4_PINNED_GIT.version,
      tracked_path_set_sha256: createHash("sha256")
        .update(canonicalStage4OfflineReadinessBytes(allTrackedFiles.map((file) => file.path)))
        .digest("hex"),
      worktree_merkle_sha256: stage4TrackedWorktreeMerkle(entries),
      semantics:
        "complete-tracked-git-modes-and-worktree-bytes-excluding-recorded-generated-evidence;no-commit-or-clean-index-claim",
    },
  });
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  if (process.argv.length !== 2) throw new Error("STAGE4_SOURCE_INVENTORY_ARGUMENTS_FORBIDDEN");
  process.stdout.write(generateStage4SourceInventory(resolve(import.meta.dirname, "..")));
}
