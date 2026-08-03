/* biome-ignore-all lint/suspicious/noExplicitAny: bounded canonical regeneration updates a strict prevalidated package */
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
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
import {
  generateStage4SourceInventory,
  readStage4SourceFile,
  stage4TrackedWorktreeMerkle,
} from "./stage4-offline-source-inventory.ts";

const root = resolve(import.meta.dirname, "..");
const artifactRoot = resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts");
const classifierPath = resolve(root, "scripts/stage4-offline-readiness.ts");
const packagePath = resolve(root, "docs/security-evidence/stage4-offline-readiness-package.json");
const receiptPath = resolve(artifactRoot, "render-preparation-receipt.json");
const sourceInventoryPath = resolve(artifactRoot, "source-inventory.json");
const schemaInventoryPath = resolve(artifactRoot, "schema-inventory.json");
const localValidationPath = resolve(artifactRoot, "local-validation.json");
const runbookIndexPath = resolve(root, "docs/operations/runbooks/index.json");
const runtimeArtifactClosurePath = resolve(root, "scripts/stage4-runtime-artifact-closure.ts");
const MAXIMUM_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const read = (path: string): Uint8Array => readStage4SourceFile(root, path);
const hash = (path: string): string => stage4OfflineReadinessSha256(read(path));

type JsonObject = Record<string, any>;
type CommandSpec = Readonly<{
  id: string;
  executable: string;
  executableSha256: string;
  tool: string;
  toolVersion: string;
  arguments: readonly string[];
  timeoutMs: number;
  sourcePaths: readonly string[];
  toolComponents?: readonly Readonly<{ path: string; sha256: string }>[];
  normalization: "none" | "stable-test-and-tool-timing" | "normalized-source-inventory-classifier-anchor";
}>;

const BIOME = Object.freeze({
  executable: resolve(root, "node_modules/@biomejs/cli-darwin-arm64/biome"),
  sha256: "610d3e1e770d373368d4ccee5a19c5e1735b0235024fcbed6ae07eb080d3bb09",
  version: "2.5.3",
});
const NODE = Object.freeze({
  executable: STAGE4_PINNED_NODE.executable,
  sha256: STAGE4_PINNED_NODE.sha256,
  version: STAGE4_PINNED_NODE.version,
});
const UNIT_TESTS = Object.freeze([
  "test/stage4-campaign-approval.test.ts",
  "test/stage4-campaign-model.test.ts",
  "test/stage4-exit-review.test.ts",
  "test/stage4-nic-sandbox-node-group.test.ts",
  "test/stage4-policy-contract.test.ts",
  "test/stage4-static-evidence.test.ts",
  "test/stage4-storage-launch-contract.test.ts",
  "test/stage4-teardown-verifier.test.ts",
  "test/stage4-runtime-artifact-closure.test.ts",
]);
const PRODUCTION_CONTRACT_TESTS = Object.freeze([
  "test/api-server.test.ts",
  "test/local-image-artifacts.test.ts",
  "test/openbao-workload-identity.test.ts",
  "test/production-compose.test.ts",
  "test/production-sandbox-image.test.ts",
  "test/production-worker-image.test.ts",
  "test/release-image-set-assertion.test.ts",
  "test/release-local-preflight.test.ts",
  "test/runtime-config.test.ts",
  "test/runtime-trusted-files.test.ts",
  "test/stage4-nic-sandbox-node-group-v2.test.ts",
  "test/stage4-static-manifest-package.test.ts",
]);
const PRODUCTION_SCHEMA_NAMES = Object.freeze([
  "integration-v1alpha1.json",
  "launch-v1alpha1.json",
  "local-image-artifact-package-v1.json",
  "release-image-set-assertion-v1.json",
  "runtime-v1alpha1.json",
]);
const FORMAT_PATHS = Object.freeze([
  "scripts/release-local-preflight-cli.ts",
  "scripts/release-local-preflight.ts",
  "scripts/stage4-offline-readiness-regenerate.ts",
  "scripts/stage4-offline-readiness.ts",
  "scripts/stage4-offline-render-preparation.ts",
  "scripts/stage4-offline-source-inventory.ts",
  "scripts/stage4-runtime-artifact-closure-regenerate.ts",
  "scripts/stage4-runtime-artifact-closure.ts",
  "test/release-local-preflight.test.ts",
  "test/stage4-offline-readiness.test.ts",
  "test/stage4-runtime-artifact-closure.test.ts",
  "test/stage4-offline-render-preparation.test.ts",
  "test/stage4-schema-registry.test.ts",
]);
const LOCAL_VALIDATION_PATHS = Object.freeze([
  "biome.json",
  "config/release-image-set-pins-v1.json",
  "docs/operations/release-local-vulnerability-preflight.md",
  "docs/operations/stage-4-offline-readiness.md",
  "docs/test-reports/stage-4-offline-readiness.md",
  "package-lock.json",
  "package.json",
  "schemas/stage4-offline-readiness-package-v1.json",
  "schemas/stage4-offline-readiness-package-v2.json",
  "schemas/stage4-offline-readiness-verdict-v1.json",
  "schemas/stage4-offline-readiness-verdict-v2.json",
  "schemas/stage4-authenticated-runtime-artifact-evidence-v1.json",
  ...PRODUCTION_SCHEMA_NAMES.map((name) => `schemas/${name}`),
  "scripts/private-bytes.ts",
  "scripts/check-lock-integrity.ts",
  "scripts/check-npm-audit.ts",
  "scripts/release-image-set-pins.ts",
  "scripts/release-local-preflight-cli.ts",
  "scripts/release-local-preflight.ts",
  "scripts/stage4-offline-readiness-regenerate.ts",
  "scripts/stage4-offline-readiness.ts",
  "scripts/stage4-offline-render-preparation.ts",
  "scripts/stage4-offline-source-inventory.ts",
  "scripts/stage4-runtime-artifact-closure-regenerate.ts",
  "scripts/stage4-runtime-artifact-closure.ts",
  "scripts/validate-schemas.ts",
  "test/release-local-preflight.test.ts",
  "test/stage4-offline-readiness.test.ts",
  "test/stage4-offline-render-preparation.test.ts",
  "test/stage4-runtime-artifact-closure.test.ts",
  "test/stage4-schema-registry.test.ts",
  "tsconfig.json",
]);

function executableBytes(path: string): Uint8Array {
  return readStage4SourceFile(dirname(path), basename(path), 128 * 1024 * 1024, false);
}

function verifyExecutable(spec: CommandSpec): void {
  if (stage4OfflineReadinessSha256(executableBytes(spec.executable), 128 * 1024 * 1024) !== spec.executableSha256) {
    throw new Error("STAGE4_REGENERATE_COMMAND_IDENTITY_INVALID");
  }
  for (const component of spec.toolComponents ?? []) {
    if (
      stage4OfflineReadinessSha256(executableBytes(resolve(root, component.path)), 128 * 1024 * 1024) !==
      component.sha256
    ) {
      throw new Error("STAGE4_REGENERATE_COMMAND_IDENTITY_INVALID");
    }
  }
}

function stableOutput(bytes: Uint8Array, normalization: CommandSpec["normalization"]): Uint8Array {
  if (normalization === "none") return bytes;
  if (normalization === "normalized-source-inventory-classifier-anchor") {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as JsonObject;
    const entry = value.entries?.find((row: JsonObject) => row.path === "scripts/stage4-offline-readiness.ts");
    if (entry === undefined) throw new Error("STAGE4_REGENERATE_SOURCE_OUTPUT_INVALID");
    entry.sha256 = "0".repeat(64);
    value.worktree_binding.worktree_merkle_sha256 = stage4TrackedWorktreeMerkle(value.entries);
    return canonicalStage4OfflineReadinessBytes(value);
  }
  const text = new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .replace(/duration_ms: [0-9.]+/gu, "duration_ms: <ELAPSED>")
    .replace(/# duration_ms [0-9.]+/gu, "# duration_ms <ELAPSED>")
    .replace(/Checked ([0-9]+) files in [0-9.]+m?s\./gu, "Checked $1 files in <ELAPSED>.");
  return new TextEncoder().encode(text);
}

function runCommand(spec: CommandSpec): JsonObject {
  verifyExecutable(spec);
  const sourceBindings = spec.sourcePaths.map((path) => ({ path, sha256: hash(path) }));
  const result = spawnSync(spec.executable, spec.arguments, {
    cwd: root,
    encoding: null,
    env: {
      HOME: "/tmp",
      LC_ALL: "C",
      NO_COLOR: "1",
      PATH: "/usr/bin:/bin",
      TMPDIR: "/var/folders/8t/gnwvs5y53j7dtnt672ylyfvr0000gn/T",
      TZ: "UTC",
    },
    maxBuffer: MAXIMUM_COMMAND_OUTPUT_BYTES,
    timeout: spec.timeoutMs,
    shell: false,
  });
  verifyExecutable(spec);
  const sourceBindingsAfter = spec.sourcePaths.map((path) => ({ path, sha256: hash(path) }));
  if (JSON.stringify(sourceBindingsAfter) !== JSON.stringify(sourceBindings)) {
    throw new Error(`STAGE4_REGENERATE_COMMAND_SOURCE_RACE:${spec.id}`);
  }
  if (result.error !== undefined || result.status !== 0 || result.signal !== null) {
    throw new Error(`STAGE4_REGENERATE_LOCAL_COMMAND_FAILED:${spec.id}`);
  }
  const stdout = stableOutput(new Uint8Array(result.stdout), spec.normalization);
  const stderr = stableOutput(
    new Uint8Array(result.stderr),
    spec.normalization === "normalized-source-inventory-classifier-anchor" ? "none" : spec.normalization,
  );
  const outcome = {
    exit_code: result.status,
    signal: result.signal,
    stderr_bytes: stderr.byteLength,
    stderr_sha256: stage4OfflineReadinessSha256(stderr),
    stdout_bytes: stdout.byteLength,
    stdout_sha256: stage4OfflineReadinessSha256(stdout),
  };
  return {
    command: { arguments: [...spec.arguments], executable: spec.executable },
    id: spec.id,
    normalization: spec.normalization,
    outcome: {
      ...outcome,
      digest_sha256: stage4OfflineReadinessSha256(canonicalStage4OfflineReadinessBytes(outcome)),
    },
    result: "pass-exit-zero",
    source_bindings: sourceBindings,
    tool: {
      components: (spec.toolComponents ?? []).map((component) => ({ ...component })),
      executable_sha256: spec.executableSha256,
      name: spec.tool,
      version: spec.toolVersion,
    },
  };
}

function nodeCommand(
  id: string,
  arguments_: readonly string[],
  sourcePaths: readonly string[],
  normalization: CommandSpec["normalization"] = "stable-test-and-tool-timing",
  timeoutMs = 60_000,
  toolComponents?: CommandSpec["toolComponents"],
): CommandSpec {
  return {
    id,
    executable: NODE.executable,
    executableSha256: NODE.sha256,
    tool: "node",
    toolVersion: NODE.version,
    arguments: arguments_,
    timeoutMs,
    sourcePaths,
    ...(toolComponents === undefined ? {} : { toolComponents }),
    normalization,
  };
}

function commandSpecs(): readonly CommandSpec[] {
  return [
    {
      id: "readiness-format",
      executable: BIOME.executable,
      executableSha256: BIOME.sha256,
      tool: "biome",
      toolVersion: BIOME.version,
      arguments: ["check", ...FORMAT_PATHS],
      timeoutMs: 30_000,
      sourcePaths: ["biome.json", ...FORMAT_PATHS],
      normalization: "stable-test-and-tool-timing",
    },
    nodeCommand(
      "repository-typecheck",
      ["node_modules/typescript/bin/tsc", "--noEmit"],
      ["tsconfig.json", "package.json", "package-lock.json"],
      "stable-test-and-tool-timing",
      60_000,
      [
        {
          path: "node_modules/typescript/bin/tsc",
          sha256: "8d5fa5bd883fec0979fc2004f1fe1d99aef40570155d550eadc0b03b55513bf0",
        },
        {
          path: "node_modules/typescript/lib/tsc.js",
          sha256: "2cffde0b8c6760dfb0b5b0382bbb7e00ba6a8b2d981b9205b256a700a481d983",
        },
        {
          path: "node_modules/typescript/lib/_tsc.js",
          sha256: "e8f349eabd48486bdb2bf9dc1a00c89d58297270c54b745838879e2859194419",
        },
      ],
    ),
    nodeCommand(
      "stage4-unit-contracts",
      ["--test", "--test-concurrency=1", ...UNIT_TESTS],
      UNIT_TESTS,
      "stable-test-and-tool-timing",
      90_000,
    ),
    nodeCommand(
      "production-runtime-image-static-route-contracts",
      ["--import", "tsx", "--test", "--test-concurrency=1", ...PRODUCTION_CONTRACT_TESTS],
      PRODUCTION_CONTRACT_TESTS,
      "stable-test-and-tool-timing",
      120_000,
      [
        {
          path: "node_modules/tsx/dist/loader.mjs",
          sha256: "150d1ff8a7770665997a940d4c686f1a3a5660349a5c7c3523b39eb43016ca74",
        },
      ],
    ),
    nodeCommand(
      "stage4-schema-registry",
      ["--test", "--test-concurrency=1", "test/stage4-schema-registry.test.ts"],
      [
        "test/stage4-schema-registry.test.ts",
        "schemas/stage4-offline-readiness-package-v1.json",
        "schemas/stage4-offline-readiness-package-v2.json",
        "schemas/stage4-offline-readiness-verdict-v1.json",
        "schemas/stage4-offline-readiness-verdict-v2.json",
        "schemas/stage4-authenticated-runtime-artifact-evidence-v1.json",
        ...PRODUCTION_SCHEMA_NAMES.map((name) => `schemas/${name}`),
      ],
    ),
    nodeCommand("all-schema-contracts", ["scripts/validate-schemas.ts"], ["scripts/validate-schemas.ts"]),
    nodeCommand(
      "trusted-helm-local-contracts",
      ["scripts/stage4-offline-render-preparation.ts"],
      ["scripts/stage4-offline-render-preparation.ts"],
      "none",
    ),
    nodeCommand(
      "complete-stage4-source-inventory",
      ["scripts/stage4-offline-source-inventory.ts"],
      ["scripts/stage4-offline-source-inventory.ts"],
      "normalized-source-inventory-classifier-anchor",
    ),
    nodeCommand(
      "dependency-lock-integrity",
      ["scripts/check-lock-integrity.ts"],
      ["scripts/check-lock-integrity.ts", "package-lock.json"],
      "none",
    ),
  ];
}

function regenerateReceipt(): void {
  const generator = resolve(root, "scripts/stage4-offline-render-preparation.ts");
  const result = spawnSync(STAGE4_PINNED_NODE.executable, [generator], {
    cwd: root,
    encoding: null,
    env: { HOME: "/tmp", LC_ALL: "C", PATH: "/usr/bin:/bin", TZ: "UTC" },
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
    shell: false,
  });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null || result.stderr.byteLength !== 0) {
    throw new Error("STAGE4_REGENERATE_TRUSTED_RECEIPT_FAILED");
  }
  writeFileSync(receiptPath, result.stdout);
}

function regenerateRunbookIndex(): void {
  const value = JSON.parse(readFileSync(runbookIndexPath, "utf8")) as JsonObject;
  for (const row of [...value.policy_documents, ...value.runbooks] as JsonObject[]) {
    if (typeof row.path !== "string") throw new Error("STAGE4_REGENERATE_RUNBOOK_INDEX_INVALID");
    row.content_sha256 = hash(row.path);
  }
  writeFileSync(runbookIndexPath, `${JSON.stringify(value, null, 2)}\n`);
}

function regenerateSchemaInventory(): void {
  const entries = readdirSync(resolve(root, "schemas"))
    .filter((name) => /^stage[45].*\.json$/u.test(name) || PRODUCTION_SCHEMA_NAMES.includes(name as never))
    .sort()
    .map((name) => ({ path: `schemas/${name}`, sha256: hash(`schemas/${name}`) }));
  writeFileSync(
    schemaInventoryPath,
    canonicalStage4OfflineReadinessBytes({
      algorithm: "sha256-over-exact-file-bytes",
      entries,
      scope: "all-stage4-stage5-and-production-runtime-image-contract-schemas",
      version: "cogs.stage4-offline-schema-inventory/v2",
    }),
  );
}

function rewriteRuntimeSchemaInventoryAnchor(): void {
  const digest = stage4OfflineReadinessSha256(new Uint8Array(readFileSync(schemaInventoryPath)));
  const source = readFileSync(runtimeArtifactClosurePath, "utf8");
  const marker =
    /\/\* stage4-runtime-schema-inventory-anchor-start \*\/[\s\S]*?\/\* stage4-runtime-schema-inventory-anchor-end \*\//u;
  const block = `/* stage4-runtime-schema-inventory-anchor-start */\nconst STAGE4_RUNTIME_SCHEMA_INVENTORY_SHA256 = ${JSON.stringify(digest)};\n/* stage4-runtime-schema-inventory-anchor-end */`;
  if (!marker.test(source)) throw new Error("STAGE4_REGENERATE_RUNTIME_SCHEMA_ANCHOR_MISSING");
  writeFileSync(runtimeArtifactClosurePath, source.replace(marker, block));
}

function regenerateRuntimeArtifactEvidence(): void {
  const generator = resolve(root, "scripts/stage4-runtime-artifact-closure-regenerate.ts");
  const result = spawnSync(STAGE4_PINNED_NODE.executable, [generator], {
    cwd: root,
    encoding: null,
    env: { HOME: "/tmp", LC_ALL: "C", PATH: "/usr/bin:/bin", TZ: "UTC" },
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
    shell: false,
  });
  if (
    result.error !== undefined ||
    result.status !== 0 ||
    result.signal !== null ||
    result.stdout.byteLength !== 0 ||
    result.stderr.byteLength !== 0
  ) {
    throw new Error("STAGE4_REGENERATE_RUNTIME_ARTIFACT_EVIDENCE_FAILED");
  }
}

function regenerateSourceAndLocalValidation(): void {
  writeFileSync(sourceInventoryPath, generateStage4SourceInventory(root));
  const checks = commandSpecs().map(runCommand);
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as JsonObject;
  if (
    receipt.helm_lint_passed !== true ||
    receipt.zero_submitted_manifests !== true ||
    receipt.renders_byte_identical !== true
  ) {
    throw new Error("STAGE4_REGENERATE_HELM_PROCEDURES_UNPROVEN");
  }
  writeFileSync(
    localValidationPath,
    canonicalStage4OfflineReadinessBytes({
      checks,
      execution: {
        cloud: false,
        docker: false,
        external_model: false,
        image_publication: false,
        kubernetes: false,
        provider: false,
      },
      scope:
        "only-the-nine-recorded-bounded-local-commands;no-docker-publication-or-current-registry-advisory-discovery",
      source_bindings: LOCAL_VALIDATION_PATHS.map((path) => ({ path, sha256: hash(path) })),
      status: "passed-recorded-bounded-local-commands",
      trusted_preparation_receipt_sha256: stage4OfflineReadinessSha256(new Uint8Array(readFileSync(receiptPath))),
      unexecuted: [
        {
          id: "current-npm-registry-audit",
          reason: "external-network-operation-outside-local-offline-preparation-scope",
          result: "not-run-not-claimed",
        },
        {
          id: "production-image-docker-builds",
          reason: "docker-build-operation-owned-by-separate-image-workflow",
          result: "not-run-not-claimed",
        },
        {
          id: "release-image-publication",
          reason: "registry-publication-operation-owned-by-separate-protected-main-workflow",
          result: "not-run-not-claimed",
        },
      ],
      version: "cogs.stage4-offline-local-validation/v5",
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
    authenticatedRuntimeArtifacts: hash(
      "docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
    ),
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
  const nic = JSON.parse(readFileSync(resolve(root, "deploy/nic/stage4-sandbox-node-group-contract.json"), "utf8"));
  const runtimePins = JSON.parse(readFileSync(resolve(artifactRoot, "runtime-pins.json"), "utf8"));
  const sourceInventory = JSON.parse(readFileSync(sourceInventoryPath, "utf8"));
  value.blockers = [...STAGE4_READINESS_BLOCKERS];
  value.source = {
    commit_binding_present: false,
    excluded_generated_evidence_outputs: sourceInventory.excluded_generated_evidence_outputs.map(
      (row: JsonObject) => row.path,
    ),
    inventory_algorithm: sourceInventory.algorithm,
    inventory_scope: sourceInventory.scope,
    source_closure_complete: true,
    worktree_merkle_sha256: sourceInventory.worktree_binding.worktree_merkle_sha256,
  };
  value.pins.nic = {
    capability_state: "source-capability-present-operator-attestation-only",
    commit_sha: nic.nic_source.commit_sha,
    module_commit_sha: nic.nic_source.eks_module.commit_sha,
    module_version: nic.nic_source.eks_module.version,
    reason_code: "STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING",
    release: nic.nic_source.release_tag,
  };
  value.pins.runtime = {
    accelerator: runtimePins.runtime.accelerator,
    containerd_artifact_sha256: runtimePins.runtime.containerd.artifact_sha256,
    containerd_artifact_state: runtimePins.runtime.containerd.artifact_state,
    containerd_version: runtimePins.runtime.containerd.version,
    eks_node_ami_id: runtimePins.eks_node_image.ami_id,
    eks_node_image_release: runtimePins.eks_node_image.release,
    eks_node_kernel_release: runtimePins.eks_node_image.kernel_release,
    exact_runtime_artifact_closure_satisfied: true,
    kata_archive_sha256: runtimePins.runtime.kata.archive_sha256,
    kata_version: runtimePins.runtime.kata.version,
    node_image_state: runtimePins.eks_node_image.pin_state,
    qemu_artifact_sha256: runtimePins.runtime.qemu.artifact_sha256,
    qemu_artifact_state: runtimePins.runtime.qemu.artifact_state,
    qemu_version: runtimePins.runtime.qemu.version,
    runc_fallback: runtimePins.runtime.runc_fallback,
    tcg_fallback: runtimePins.runtime.tcg_fallback,
  };
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
    authenticated_runtime_artifacts_sha256: hash(
      "docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
    ),
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
regenerateRunbookIndex();
regenerateSchemaInventory();
rewriteRuntimeSchemaInventoryAnchor();
regenerateRuntimeArtifactEvidence();
// Normalize source-derived package semantics before schema-registry checks, then bind final generated artifacts below.
writeFileSync(sourceInventoryPath, generateStage4SourceInventory(root));
regeneratePackage();
regenerateSourceAndLocalValidation();
rewriteClassifierAnchors();
const expectedLocalNormalized = stage4NormalizedLocalValidationSha256(
  new Uint8Array(readFileSync(localValidationPath)),
);
regenerateSourceAndLocalValidation();
if (
  stage4NormalizedLocalValidationSha256(new Uint8Array(readFileSync(localValidationPath))) !== expectedLocalNormalized
) {
  throw new Error("STAGE4_REGENERATE_NONIDEMPOTENT_VALIDATION");
}
regeneratePackage();
