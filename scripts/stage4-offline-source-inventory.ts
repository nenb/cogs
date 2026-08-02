import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { relative, resolve } from "node:path";
import { canonicalStage4OfflineReadinessBytes, stage4OfflineReadinessSha256 } from "./stage4-offline-readiness.ts";

export const STAGE4_SOURCE_INVENTORY_EXCLUSIONS = Object.freeze([
  "docs/security-evidence/stage4-offline-readiness-package.json",
  "docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json",
  "docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json",
] as const);

const ROOT_FILES = Object.freeze([
  "COGS.md",
  "DESIGN.md",
  "IMPLEMENTATION.md",
  "README.md",
  "SECRET-INJECTION.md",
  "biome.json",
  "package-lock.json",
  "package.json",
]);
const EXACT_FILES = Object.freeze([
  "docs/adr/0012-use-aws-virtual-nested-kvm-for-stage-4-candidate.md",
  "docs/operations/aws-feasibility-campaign.md",
  "docs/operations/ci-schedule.md",
  "docs/operations/ownership.md",
  "docs/security-evidence/README.md",
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

function selectedSourcePath(path: string): boolean {
  return (
    ROOT_FILES.includes(path as (typeof ROOT_FILES)[number]) ||
    EXACT_FILES.includes(path as (typeof EXACT_FILES)[number]) ||
    DIRECTORY_PREFIXES.some((prefix) => path.startsWith(prefix)) ||
    PREFIX_PATTERNS.some((pattern) => pattern.test(path))
  );
}

function allFiles(directory: string, root: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const absolute = resolve(directory, name);
    const path = relative(root, absolute);
    const metadata = lstatSync(absolute);
    if (metadata.isSymbolicLink()) {
      if (selectedSourcePath(path)) throw new Error("STAGE4_SOURCE_INVENTORY_LINK_FORBIDDEN");
      return [];
    }
    if (metadata.isDirectory()) {
      const [top] = path.split("/");
      if (!["deploy", "docs", "schemas", "scripts", "test"].includes(top ?? "")) return [];
      if (path === "deploy/aws" || path === "deploy/systemd" || path === "deploy/opentofu") return [];
      return allFiles(absolute, root);
    }
    return [path];
  });
}

export function stage4SourceClosurePaths(root: string): string[] {
  const physicalRoot = realpathSync(root);
  return allFiles(physicalRoot, physicalRoot)
    .filter(selectedSourcePath)
    .filter((path) => !STAGE4_SOURCE_INVENTORY_EXCLUSIONS.includes(path as never))
    .sort();
}

export function generateStage4SourceInventory(root: string): Uint8Array {
  const physicalRoot = realpathSync(root);
  const paths = stage4SourceClosurePaths(physicalRoot);
  if (paths.length === 0 || paths.length > 256) throw new Error("STAGE4_SOURCE_INVENTORY_FILE_COUNT_INVALID");
  const entries = paths.map((path) => {
    const absolute = resolve(physicalRoot, path);
    const metadata = lstatSync(absolute);
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > 4 * 1024 * 1024) {
      throw new Error("STAGE4_SOURCE_INVENTORY_FILE_BOUND_INVALID");
    }
    const bytes = new Uint8Array(readFileSync(absolute));
    if (bytes.byteLength !== metadata.size) throw new Error("STAGE4_SOURCE_INVENTORY_FILE_RACE");
    return { path, sha256: stage4OfflineReadinessSha256(bytes) };
  });
  return canonicalStage4OfflineReadinessBytes({
    algorithm: "sha256-over-exact-file-bytes",
    entries,
    excluded_self_referential_outputs: STAGE4_SOURCE_INVENTORY_EXCLUSIONS.map((path) => ({
      path,
      reason: "excluded-self-referential-generated-output",
    })),
    scope: "complete-stage4-source-closure",
    version: "cogs.stage4-offline-source-inventory/v2",
  });
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  if (process.argv.length !== 2) throw new Error("STAGE4_SOURCE_INVENTORY_ARGUMENTS_FORBIDDEN");
  process.stdout.write(generateStage4SourceInventory(resolve(import.meta.dirname, "..")));
}
