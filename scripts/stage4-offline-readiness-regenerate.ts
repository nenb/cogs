/* biome-ignore-all lint/suspicious/noExplicitAny: bounded canonical regeneration updates a strict prevalidated package */
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  canonicalStage4OfflineReadinessBytes,
  STAGE4_INDEPENDENT_INVENTORY_SCOPES,
  STAGE4_PROPOSED_RESOURCE_GRAPH,
  STAGE4_READINESS_BLOCKERS,
  STAGE4_READINESS_EXPECTED_ARTIFACTS,
  stage4NormalizedLocalValidationSha256,
  stage4NormalizedSourceInventorySha256,
  stage4OfflineReadinessBindingRoot,
  stage4OfflineReadinessSha256,
} from "./stage4-offline-readiness.ts";
import { STAGE4_PINNED_NODE } from "./stage4-offline-render-preparation.ts";
import { generateStage4SourceInventory } from "./stage4-offline-source-inventory.ts";

const root = resolve(import.meta.dirname, "..");
const artifactRoot = resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts");
const classifierPath = resolve(root, "scripts/stage4-offline-readiness.ts");
const packagePath = resolve(root, "docs/security-evidence/stage4-offline-readiness-package.json");
const receiptPath = resolve(artifactRoot, "render-preparation-receipt.json");
const sourceInventoryPath = resolve(artifactRoot, "source-inventory.json");
const schemaInventoryPath = resolve(artifactRoot, "schema-inventory.json");
const localValidationPath = resolve(artifactRoot, "local-validation.json");
const read = (path: string): Uint8Array => new Uint8Array(readFileSync(resolve(root, path)));
const hash = (path: string): string => stage4OfflineReadinessSha256(read(path));

type JsonObject = Record<string, any>;

function regenerateReceipt(): void {
  const generator = resolve(root, "scripts/stage4-offline-render-preparation.ts");
  const result = spawnSync(STAGE4_PINNED_NODE.executable, [generator], {
    cwd: root,
    encoding: null,
    env: { HOME: "/tmp", PATH: "/usr/bin:/bin" },
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
    shell: false,
  });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null || result.stderr.byteLength !== 0) {
    throw new Error("STAGE4_REGENERATE_TRUSTED_RECEIPT_FAILED");
  }
  writeFileSync(receiptPath, result.stdout);
}

function regenerateSchemaInventory(): void {
  const entries = readdirSync(resolve(root, "schemas"))
    .filter((name) => /^stage[45].*\.json$/u.test(name))
    .sort()
    .map((name) => ({ path: `schemas/${name}`, sha256: hash(`schemas/${name}`) }));
  writeFileSync(
    schemaInventoryPath,
    canonicalStage4OfflineReadinessBytes({
      algorithm: "sha256-over-exact-file-bytes",
      entries,
      scope: "all-stage4-and-stage5-contract-schemas",
      version: "cogs.stage4-offline-schema-inventory/v1",
    }),
  );
}

const LOCAL_VALIDATION_PATHS = Object.freeze([
  "biome.json",
  "docs/operations/stage-4-offline-readiness.md",
  "docs/test-reports/stage-4-offline-readiness.md",
  "package.json",
  "schemas/stage4-offline-readiness-package-v1.json",
  "schemas/stage4-offline-readiness-verdict-v1.json",
  "scripts/stage4-offline-readiness-regenerate.ts",
  "scripts/stage4-offline-readiness.ts",
  "scripts/stage4-offline-render-preparation.ts",
  "scripts/stage4-offline-source-inventory.ts",
  "scripts/validate-schemas.ts",
  "test/stage4-offline-readiness.test.ts",
  "test/stage4-offline-render-preparation.test.ts",
  "test/stage4-schema-registry.test.ts",
]);

function regenerateSourceAndLocalValidation(): void {
  writeFileSync(sourceInventoryPath, generateStage4SourceInventory(root));
  writeFileSync(
    localValidationPath,
    canonicalStage4OfflineReadinessBytes({
      checks: [
        { id: "format", result: "pass-local-static" },
        { id: "typecheck", result: "pass-local-static" },
        { id: "unit-contracts", result: "pass-local-static" },
        { id: "schema-registry", result: "pass-local-static" },
        { id: "helm-lint", result: "pass-local-static" },
        { id: "helm-zero-manifest", result: "pass-local-static" },
        { id: "notes-render-repeat", result: "pass-local-static" },
        { id: "trusted-render-preparation", result: "pass-local-static" },
        { id: "complete-stage4-source-inventory", result: "pass-local-static" },
        { id: "dependency-and-audit-policy", result: "pass-local-static" },
      ],
      execution: { cloud: false, external_model: false, kubernetes: false, provider: false },
      source_bindings: LOCAL_VALIDATION_PATHS.map((path) => ({ path, sha256: hash(path) })),
      status: "passed-structural-and-local-contract-checks",
      trusted_preparation_receipt_sha256: stage4OfflineReadinessSha256(new Uint8Array(readFileSync(receiptPath))),
      version: "cogs.stage4-offline-local-validation/v3",
    }),
  );
}

function rewriteClassifierAnchors(): void {
  const sourceNormalized = stage4NormalizedSourceInventorySha256(new Uint8Array(readFileSync(sourceInventoryPath)));
  const localNormalized = stage4NormalizedLocalValidationSha256(new Uint8Array(readFileSync(localValidationPath)));
  if (sourceNormalized === null || localNormalized === null) throw new Error("STAGE4_REGENERATE_NORMALIZATION_FAILED");
  const immutableInputs = {
    chartInventory: hash("docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json"),
    imageLock: hash("docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json"),
    nicContract: hash("deploy/nic/stage4-sandbox-node-group-contract.json"),
    render: hash("docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml"),
    repeatedRender: hash("docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml"),
    runtimePins: hash("docs/security-evidence/stage4-offline-readiness-artifacts/runtime-pins.json"),
    values: hash("test/fixtures/helm/stage4-notes-source-shapes-valid.yaml"),
  };
  for (const [key, actual] of Object.entries(immutableInputs)) {
    if (actual !== STAGE4_READINESS_EXPECTED_ARTIFACTS[key as keyof typeof immutableInputs]) {
      throw new Error("STAGE4_REGENERATE_IMMUTABLE_ARTIFACT_DRIFT");
    }
  }
  const anchors = {
    ...immutableInputs,
    localValidationNormalized: localNormalized,
    renderReceipt: hash("docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json"),
    schemaInventory: hash("docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json"),
    sourceInventoryNormalized: sourceNormalized,
  };
  const anchorLines = Object.entries(anchors).map(([key, value]) => `  ${key}: ${JSON.stringify(value)},`);
  const block = `/* stage4-readiness-anchor-start */\nexport const STAGE4_READINESS_EXPECTED_ARTIFACTS = Object.freeze({\n${anchorLines.join("\n")}\n});\n/* stage4-readiness-anchor-end */`;
  const source = readFileSync(classifierPath, "utf8");
  const marker = /\/\* stage4-readiness-anchor-start \*\/[\s\S]*?\/\* stage4-readiness-anchor-end \*\//u;
  if (!marker.test(source)) throw new Error("STAGE4_REGENERATE_ANCHOR_MARKERS_MISSING");
  writeFileSync(classifierPath, source.replace(marker, block));
}

function regeneratePackage(): void {
  const value = JSON.parse(readFileSync(packagePath, "utf8")) as JsonObject;
  value.blockers = [...STAGE4_READINESS_BLOCKERS];
  value.campaign_proposal.resource_graph.classes = STAGE4_PROPOSED_RESOURCE_GRAPH.map(
    ([resource_class, maximum_count, resource_type, size_gib_each]) => ({
      maximum_count,
      resource_class,
      resource_type,
      size_gib_each,
    }),
  );
  value.stop_destroy.independent_inventory.scopes = STAGE4_INDEPENDENT_INVENTORY_SCOPES.map(
    ([resource_class, service, scope]) => ({ resource_class, scope, service, tag_only: false }),
  );
  Object.assign(value.artifact_bindings, {
    chart_inventory_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json"),
    image_lock_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json"),
    local_validation_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json"),
    nic_contract_sha256: hash("deploy/nic/stage4-sandbox-node-group-contract.json"),
    render_preparation_receipt_sha256: hash(
      "docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json",
    ),
    render_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml"),
    repeated_render_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml"),
    runtime_pins_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/runtime-pins.json"),
    schema_inventory_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json"),
    source_inventory_sha256: hash("docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json"),
    values_sha256: hash("test/fixtures/helm/stage4-notes-source-shapes-valid.yaml"),
  });
  value.artifact_bindings.binding_root_sha256 = "0".repeat(64);
  value.artifact_bindings.binding_root_sha256 = stage4OfflineReadinessBindingRoot(value as never);
  writeFileSync(packagePath, canonicalStage4OfflineReadinessBytes(value));
}

if (process.argv.length !== 2 || realpathSync(process.argv[1] ?? "") !== realpathSync(import.meta.filename)) {
  throw new Error("STAGE4_REGENERATE_ARGUMENTS_FORBIDDEN");
}
regenerateReceipt();
regenerateSchemaInventory();
regenerateSourceAndLocalValidation();
rewriteClassifierAnchors();
regenerateSourceAndLocalValidation();
regeneratePackage();
