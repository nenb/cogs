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

const ROOT_FILES = Object.freeze([
  "COGS.md",
  "DESIGN.md",
  "IMPLEMENTATION.md",
  "README.md",
  "SECRET-INJECTION.md",
  "biome.json",
  "package-lock.json",
  "package.json",
  "tsconfig.json",
]);
const EXACT_FILES = Object.freeze([
  "docs/adr/0012-use-aws-virtual-nested-kvm-for-stage-4-candidate.md",
  "docs/operations/aws-feasibility-campaign.md",
  "docs/operations/ci-schedule.md",
  "docs/operations/ownership.md",
  "docs/security-evidence/README.md",
  "scripts/private-bytes.ts",
  "scripts/check-lock-integrity.ts",
  "scripts/check-npm-audit.ts",
  "scripts/validate-schemas.ts",
]);
const DIRECTORY_PREFIXES = Object.freeze(["deploy/helm/cogs/", "deploy/nic/"]);
const PREFIX_PATTERNS = Object.freeze([
  /^docs\/operations\/stage-4-.*\.md$/u,
  /^docs\/test-reports\/stage-4-.*\.md$/u,
  /^schemas\/stage[45]-.*\.json$/u,
  /^scripts\/stage4-.*\.ts$/u,
  /^test\/stage4-.*\.test\.ts$/u,
  /^test\/helm-stage4-.*\.test\.ts$/u,
  /^test\/fixtures\/helm\/stage4-.*\.yaml$/u,
  /^test\/fixtures\/stage4-[^/]+\//u,
  /^docs\/security-evidence\/stage4-offline-readiness-artifacts\//u,
]);
const MAXIMUM_FILE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_GIT_OUTPUT_BYTES = 1024 * 1024;
const EXPECTED_REGENERATION_BASE_HEAD = "c80b5eb8c6308b605c677e8c2b4154267fc147cf";

type Identity = Readonly<{
  dev: bigint;
  ino: bigint;
  mode: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
  nlink: bigint;
}>;

function selectedSourcePath(path: string): boolean {
  return (
    ROOT_FILES.includes(path as (typeof ROOT_FILES)[number]) ||
    EXACT_FILES.includes(path as (typeof EXACT_FILES)[number]) ||
    DIRECTORY_PREFIXES.some((prefix) => path.startsWith(prefix)) ||
    PREFIX_PATTERNS.some((pattern) => pattern.test(path))
  );
}

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
  if (stage4OfflineReadinessSha256(executable) !== STAGE4_PINNED_GIT.sha256) {
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

function repositorySnapshot(root: string): { baseHead: string; paths: string[] } {
  const version = text(pinnedGit(root, ["--version"])).trim();
  if (version !== STAGE4_PINNED_GIT.version) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_IDENTITY_INVALID");
  const top = realpathSync(text(pinnedGit(root, ["rev-parse", "--show-toplevel"])).trim());
  if (top !== root) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_ROOT_INVALID");
  const head = text(pinnedGit(root, ["rev-parse", "--verify", "HEAD"])).trim();
  if (!/^[0-9a-f]{40}$/u.test(head)) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_REVISION_INVALID");
  const baseHead =
    head === EXPECTED_REGENERATION_BASE_HEAD ? head : text(pinnedGit(root, ["rev-parse", "--verify", "HEAD^"])).trim();
  if (baseHead !== EXPECTED_REGENERATION_BASE_HEAD) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_REVISION_INVALID");
  const index = pinnedGit(root, ["ls-files", "--cached", "--stage", "-z"]);
  const paths: string[] = [];
  for (const record of text(index).split("\0")) {
    if (record === "") continue;
    const match = /^(100644|100755) ([0-9a-f]{40,64}) 0\t(.+)$/u.exec(record);
    if (match === null) {
      const candidate = record.slice(record.indexOf("\t") + 1);
      if (selectedSourcePath(candidate)) throw new Error("STAGE4_SOURCE_INVENTORY_GIT_ENTRY_INVALID");
      continue;
    }
    const path = match[3];
    if (path !== undefined && selectedSourcePath(path)) paths.push(path);
  }
  const untracked = text(pinnedGit(root, ["ls-files", "--others", "--exclude-standard", "-z"]))
    .split("\0")
    .filter((path) => path !== "" && selectedSourcePath(path));
  if (untracked.length !== 0) throw new Error("STAGE4_SOURCE_INVENTORY_UNTRACKED_SOURCE_FORBIDDEN");
  return { baseHead, paths };
}

export function stage4SourceClosurePaths(root: string): string[] {
  const physicalRoot = realpathSync(root);
  const paths = repositorySnapshot(physicalRoot)
    .paths.filter((path) => !STAGE4_SOURCE_INVENTORY_EXCLUSIONS.includes(path as never))
    .sort();
  for (const required of [...ROOT_FILES, ...EXACT_FILES]) {
    if (!paths.includes(required)) throw new Error("STAGE4_SOURCE_INVENTORY_REQUIRED_SOURCE_MISSING");
  }
  return paths;
}

export function generateStage4SourceInventory(root: string): Uint8Array {
  const physicalRoot = realpathSync(root);
  const repository = repositorySnapshot(physicalRoot);
  const paths = repository.paths.filter((path) => !STAGE4_SOURCE_INVENTORY_EXCLUSIONS.includes(path as never)).sort();
  if (paths.length === 0 || paths.length > 256) throw new Error("STAGE4_SOURCE_INVENTORY_FILE_COUNT_INVALID");
  for (const required of [...ROOT_FILES, ...EXACT_FILES]) {
    if (!paths.includes(required)) throw new Error("STAGE4_SOURCE_INVENTORY_REQUIRED_SOURCE_MISSING");
  }
  let aggregate = 0;
  const entries = paths.map((path) => {
    const bytes = readStage4SourceFile(physicalRoot, path);
    aggregate += bytes.byteLength;
    if (aggregate > 16 * 1024 * 1024) throw new Error("STAGE4_SOURCE_INVENTORY_AGGREGATE_BOUND_INVALID");
    return { path, sha256: stage4OfflineReadinessSha256(bytes) };
  });
  return canonicalStage4OfflineReadinessBytes({
    algorithm: "sha256-over-exact-file-bytes",
    entries,
    excluded_self_referential_outputs: STAGE4_SOURCE_INVENTORY_EXCLUSIONS.map((path) => ({
      path,
      reason: "excluded-self-referential-generated-output",
    })),
    repository_binding: {
      git_executable_sha256: STAGE4_PINNED_GIT.sha256,
      git_index_path_set_sha256: createHash("sha256")
        .update(canonicalStage4OfflineReadinessBytes(repository.paths.slice().sort()))
        .digest("hex"),
      git_version: STAGE4_PINNED_GIT.version,
      regeneration_base_head: repository.baseHead,
      semantics: "exact-tracked-worktree-bytes-at-regeneration-dirty-tracked-files-allowed",
    },
    scope: "complete-stage4-source-closure",
    version: "cogs.stage4-offline-source-inventory/v3",
  });
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  if (process.argv.length !== 2) throw new Error("STAGE4_SOURCE_INVENTORY_ARGUMENTS_FORBIDDEN");
  process.stdout.write(generateStage4SourceInventory(resolve(import.meta.dirname, "..")));
}
