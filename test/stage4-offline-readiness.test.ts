/* biome-ignore-all lint/suspicious/noExplicitAny: hostile package mutations intentionally cross strict JSON types */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import {
  canonicalStage4OfflineReadinessBytes,
  classifyStage4OfflineReadiness,
  STAGE4_INDEPENDENT_INVENTORY_SCOPES,
  STAGE4_PROPOSED_RESOURCE_GRAPH,
  STAGE4_READINESS_ARTIFACT_KEYS,
  STAGE4_READINESS_BLOCKERS,
  STAGE4_READINESS_BYTE_LIMITS,
  stage4OfflineReadinessBindingRoot,
  stage4OfflineReadinessSha256,
} from "../scripts/stage4-offline-readiness.ts";
import {
  generateStage4SourceInventory,
  readStage4SourceFile,
  STAGE4_PINNED_GIT,
  STAGE4_SOURCE_INVENTORY_EXCLUSIONS,
  stage4TrackedWorktreeMerkle,
} from "../scripts/stage4-offline-source-inventory.ts";

const root = resolve(import.meta.dirname, "..");
const packagePath = resolve(root, "docs/security-evidence/stage4-offline-readiness-package.json");
const bytes = (path: string): Uint8Array => new Uint8Array(readFileSync(resolve(root, path)));
const packageBytes = (): Uint8Array => new Uint8Array(readFileSync(packagePath));
const packageObject = (): Record<string, any> => JSON.parse(readFileSync(packagePath, "utf8")) as Record<string, any>;

function artifacts(): Record<string, Uint8Array> {
  return {
    sourceInventory: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json"),
    chartInventory: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json"),
    values: bytes("test/fixtures/helm/stage4-notes-source-shapes-valid.yaml"),
    render: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml"),
    repeatedRender: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml"),
    renderReceipt: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json"),
    imageLock: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json"),
    releaseImageAssertion: bytes("docs/security-evidence/release-image-set-assertion-31856469035.canonical.json"),
    releaseImageReview: bytes("docs/security-evidence/release-image-set-review-31856469035.canonical.json"),
    nicContract: bytes("deploy/nic/stage4-sandbox-node-group-contract.json"),
    runtimePins: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/runtime-pins.json"),
    authenticatedRuntimeArtifacts: bytes(
      "docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
    ),
    schemaInventory: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json"),
    localValidation: bytes("docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json"),
  };
}

function classify(value = packageBytes(), bindings: unknown = artifacts()) {
  return classifyStage4OfflineReadiness(value, bindings);
}

function canonicalMutation(mutate: (value: Record<string, any>) => void, updateRoot = false): Uint8Array {
  const value = packageObject();
  mutate(value);
  if (updateRoot) value.artifact_bindings.binding_root_sha256 = stage4OfflineReadinessBindingRoot(value as never);
  return canonicalStage4OfflineReadinessBytes(value);
}

test("committed canonical package is locally complete but campaign-blocked and non-authoritative", () => {
  const verdict = classify();
  assert.equal(verdict.status, "local-preparation-complete-blocked");
  assert.equal(verdict.local_preparation_complete, true);
  assert.equal(verdict.local_preparation_scope, "bounded-package-assembly-and-local-validation-only");
  assert.equal(verdict.trusted_render_preparation_complete, true);
  assert.equal(verdict.candidate_artifact_closure_complete, true);
  assert.equal(verdict.selected_runtime_artifacts_authenticated, true);
  assert.equal(verdict.exact_image_runtime_closure_satisfied, false);
  assert.equal(verdict.campaign_request_ready, false);
  assert.equal(verdict.campaign_approved, false);
  assert.equal(verdict.cloud_authorized, false);
  assert.equal(verdict.cloud_execution_observed, false);
  assert.equal(verdict.provider_truth_observed, false);
  assert.equal(verdict.current_resources_observed, false);
  assert.equal(verdict.zero_resources_claimed, false);
  assert.equal(verdict.stage4_exit_satisfied, false);
  assert.equal(verdict.release_eligible, false);
  assert.deepEqual(verdict.blockers, STAGE4_READINESS_BLOCKERS);
  assert.equal(verdict.package_sha256, stage4OfflineReadinessSha256(packageBytes()));
  assert.equal(verdict.binding_root_sha256, packageObject().artifact_bindings.binding_root_sha256);
  assert.ok(Object.isFrozen(verdict));
  assert.ok(Object.isFrozen(verdict.blockers));
});

test("verdict and package compile under strict independent schemas", () => {
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  const packageSchema = JSON.parse(
    readFileSync(resolve(root, "schemas/stage4-offline-readiness-package-v5.json"), "utf8"),
  );
  const verdictSchema = JSON.parse(
    readFileSync(resolve(root, "schemas/stage4-offline-readiness-verdict-v5.json"), "utf8"),
  );
  const validatePackage = ajv.compile(packageSchema);
  const validateVerdict = ajv.compile(verdictSchema);
  assert.equal(validatePackage(packageObject()), true, JSON.stringify(validatePackage.errors));
  assert.equal(validateVerdict(classify()), true, JSON.stringify(validateVerdict.errors));

  const unknown = packageObject();
  unknown.diagnostic = "arbitrary text is forbidden";
  assert.equal(validatePackage(unknown), false);
  const nested = packageObject();
  nested.campaign_proposal.spend.current_price = "unknown prose";
  assert.equal(validatePackage(nested), false);

  const complete = structuredClone(classify()) as any;
  complete.blockers.reverse();
  assert.equal(validateVerdict(complete), false, "complete verdict blocker order is exact");
  const duplicate = structuredClone(classify()) as any;
  duplicate.blockers[1] = duplicate.blockers[0];
  assert.equal(validateVerdict(duplicate), false, "complete verdict blockers are unique");
  const reasonMismatch = structuredClone(classify()) as any;
  reasonMismatch.reason_code = "STAGE4_READINESS_SCHEMA_OR_SEMANTIC_DRIFT";
  assert.equal(validateVerdict(reasonMismatch), false, "complete status/reason coupling is exact");
  const preserveMismatch = structuredClone(classify(new Uint8Array())) as any;
  preserveMismatch.reason_code = "STAGE4_LOCAL_PREPARATION_COMPLETE_CAMPAIGN_BLOCKED";
  assert.equal(validateVerdict(preserveMismatch), false, "preserve status cannot use complete reason");
});

test("committed inventories are canonical, complete for their scopes, and bind exact current files", () => {
  const hashFile = (path: string): string => stage4OfflineReadinessSha256(bytes(path));
  const readManifest = (path: string): Record<string, any> => {
    const input = bytes(path);
    const value = JSON.parse(new TextDecoder().decode(input)) as Record<string, any>;
    assert.deepEqual(input, canonicalStage4OfflineReadinessBytes(value), `${path} must be canonical`);
    return value;
  };
  const assertEntries = (entries: Array<{ path: string; sha256: string }>): void => {
    for (const entry of entries) assert.equal(entry.sha256, hashFile(entry.path), entry.path);
  };

  const sourcePath = "docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json";
  const source = readManifest(sourcePath);
  const pinnedGitAvailable =
    existsSync(STAGE4_PINNED_GIT.executable) &&
    stage4OfflineReadinessSha256(new Uint8Array(readFileSync(STAGE4_PINNED_GIT.executable)), 64 * 1024 * 1024) ===
      STAGE4_PINNED_GIT.sha256;
  if (pinnedGitAvailable) assert.deepEqual(bytes(sourcePath), generateStage4SourceInventory(root));
  assert.deepEqual(
    source.excluded_generated_evidence_outputs.map((row: { path: string }) => row.path),
    STAGE4_SOURCE_INVENTORY_EXCLUSIONS,
  );
  assert.equal(source.scope, "complete-tracked-worktree-source-build-qualification-closure");
  assert.equal(source.version, "cogs.stage4-offline-source-inventory/v5");
  assert.deepEqual(source.worktree_binding, {
    file_count: source.entries.length,
    git_executable_sha256: "7588ceab299393618d6f8861502ac0588d1594025f301d9a61a898215b5571d3",
    git_version: "git version 2.50.1 (Apple Git-155)",
    tracked_path_set_sha256: source.worktree_binding.tracked_path_set_sha256,
    worktree_merkle_sha256: stage4TrackedWorktreeMerkle(source.entries),
    semantics:
      "complete-tracked-git-modes-and-worktree-bytes-excluding-recorded-generated-evidence;no-commit-or-clean-index-claim",
  });
  assert.match(source.worktree_binding.tracked_path_set_sha256, /^[0-9a-f]{64}$/u);
  assert.match(source.worktree_binding.worktree_merkle_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(Object.hasOwn(source.worktree_binding, "regeneration_base_head"), false);
  for (const entry of source.entries as Array<{ mode: string; path: string }>) {
    assert.match(entry.mode, /^100(?:644|755)$/u, entry.path);
    const executable = (statSync(resolve(root, entry.path)).mode & 0o111) !== 0;
    assert.equal(entry.mode, executable ? "100755" : "100644", entry.path);
  }
  const modeChanged = source.entries.map((entry: { mode: string; path: string; sha256: string }, index: number) =>
    index === 0 ? { ...entry, mode: entry.mode === "100755" ? "100644" : "100755" } : entry,
  );
  assert.notEqual(stage4TrackedWorktreeMerkle(modeChanged), source.worktree_binding.worktree_merkle_sha256);
  assert.ok(
    source.entries.some((entry: { path: string }) => entry.path === "scripts/stage4-storage-launch-contract.ts"),
  );
  assert.ok(
    source.entries.some((entry: { path: string }) => entry.path === "test/stage4-storage-launch-contract.test.ts"),
  );
  assert.ok(source.entries.some((entry: { path: string }) => entry.path === "scripts/validate-schemas.ts"));
  assert.ok(
    source.entries.some((entry: { path: string }) => entry.path === "scripts/stage4-offline-readiness-regenerate.ts"),
  );
  const tracked = (prefix: string): string[] =>
    readdirSync(resolve(root, prefix), { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) =>
        `${prefix}/${entry.parentPath.slice(resolve(root, prefix).length + 1)}/${entry.name}`.replace("//", "/"),
      )
      .sort();
  const sourcePaths = source.entries.map((entry: { path: string }) => entry.path);
  for (const prefix of ["src", "images"]) {
    assert.deepEqual(
      sourcePaths.filter((path: string) => path.startsWith(`${prefix}/`)),
      tracked(prefix),
      `${prefix} closure`,
    );
  }
  for (const required of [
    ".github/workflows/ci.yml",
    ".github/workflows/local-image-artifacts.yml",
    ".github/workflows/release-images.yml",
    "docs/operations/local-image-artifacts.md",
    "docs/operations/production-runtime-foundation.md",
    "docs/operations/release-image-publication.md",
    "schemas/local-image-artifact-package-v1.json",
    "schemas/release-image-set-assertion-v1.json",
    "schemas/release-image-set-review-v1.json",
    "schemas/release-image-set-review-v2.json",
    "schemas/runtime-v1alpha1.json",
    "third_party/envoy-ext-authz-v1.38.3/ext_authz.descriptor.pb",
    "third_party/envoy-ext-authz-v1.38.3/manifest.json",
    "scripts/local-image-artifacts.ts",
    "scripts/release-image-set-assertion.ts",
    "scripts/release-image-set-review.ts",
    "scripts/release-image-set-review-v2.ts",
    "docs/security-evidence/release-image-set-assertion-30852317459.canonical.json",
    "docs/security-evidence/release-image-set-review-30852317459.canonical.json",
    "docs/security-evidence/release-image-set-assertion-31856469035.canonical.json",
    "docs/security-evidence/release-image-set-review-31856469035.canonical.json",
    "scripts/validate-trivy-image-report.jq",
    "test/production-compose.test.ts",
    "test/production-sandbox-image.test.ts",
    "test/production-worker-image.test.ts",
  ]) {
    assert.ok(sourcePaths.includes(required), required);
  }
  assert.ok(source.entries.length <= 1250);
  assertEntries(source.entries);

  const walk = (directory: string): string[] =>
    readdirSync(directory).flatMap((name) => {
      const path = join(directory, name);
      return statSync(path).isDirectory() ? walk(path) : [path];
    });
  const chart = readManifest("docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json");
  const chartRoot = resolve(root, "deploy/helm/cogs");
  assert.deepEqual(
    chart.entries.map((entry: { path: string }) => entry.path),
    walk(chartRoot)
      .map((path) => relative(chartRoot, path))
      .sort(),
  );
  assertEntries(
    chart.entries.map((entry: { path: string; sha256: string }) => ({
      ...entry,
      path: `deploy/helm/cogs/${entry.path}`,
    })),
  );

  const schemas = readManifest("docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json");
  assert.deepEqual(
    schemas.entries.map((entry: { path: string }) => entry.path),
    readdirSync(resolve(root, "schemas"))
      .filter(
        (name) =>
          /^stage[45].*\.json$/u.test(name) ||
          [
            "integration-v1alpha1.json",
            "launch-v1alpha1.json",
            "local-image-artifact-package-v1.json",
            "release-image-set-assertion-v1.json",
            "release-image-set-review-v1.json",
            "release-image-set-review-v2.json",
            "runtime-v1alpha1.json",
          ].includes(name),
      )
      .sort()
      .map((name) => `schemas/${name}`),
  );
  assertEntries(schemas.entries);

  const validation = readManifest("docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json");
  assert.deepEqual(
    validation.checks.map((check: { id: string }) => check.id),
    [
      "readiness-format",
      "repository-typecheck",
      "stage4-unit-contracts",
      "production-runtime-image-static-route-contracts",
      "stage4-schema-registry",
      "all-schema-contracts",
      "trusted-helm-local-contracts",
      "complete-stage4-source-inventory",
      "dependency-lock-integrity",
    ],
  );
  for (const check of validation.checks) {
    assert.equal(check.result, "pass-exit-zero", check.id);
    assert.equal(check.outcome.exit_code, 0, check.id);
    assert.equal(check.outcome.signal, null, check.id);
    assert.match(check.tool.executable_sha256, /^[0-9a-f]{64}$/u, check.id);
    assert.ok(check.command.executable.startsWith("/"), check.id);
    const { digest_sha256, ...outcome } = check.outcome;
    assert.equal(digest_sha256, stage4OfflineReadinessSha256(canonicalStage4OfflineReadinessBytes(outcome)), check.id);
  }
  assert.deepEqual(validation.unexecuted, [
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
  ]);
  assert.equal(validation.status, "passed-recorded-bounded-local-commands");
  assert.equal(
    validation.scope,
    "only-the-nine-recorded-bounded-local-commands;no-docker-publication-or-current-registry-advisory-discovery",
  );
  assert.deepEqual(validation.execution, {
    cloud: false,
    docker: false,
    external_model: false,
    image_publication: false,
    kubernetes: false,
    provider: false,
  });
  assert.deepEqual(
    validation.source_bindings.map((entry: { path: string }) => entry.path),
    [
      "biome.json",
      "config/release-image-set-pins-v1.json",
      "docs/operations/release-local-vulnerability-preflight.md",
      "docs/operations/stage-4-offline-readiness.md",
      "docs/test-reports/stage-4-offline-readiness.md",
      "package-lock.json",
      "package.json",
      "schemas/stage4-offline-readiness-package-v1.json",
      "schemas/stage4-offline-readiness-package-v2.json",
      "schemas/stage4-offline-readiness-package-v3.json",
      "schemas/stage4-offline-readiness-package-v4.json",
      "schemas/stage4-offline-readiness-package-v5.json",
      "schemas/stage4-offline-readiness-verdict-v1.json",
      "schemas/stage4-offline-readiness-verdict-v2.json",
      "schemas/stage4-offline-readiness-verdict-v3.json",
      "schemas/stage4-offline-readiness-verdict-v4.json",
      "schemas/stage4-offline-readiness-verdict-v5.json",
      "schemas/stage4-authenticated-runtime-artifact-evidence-v1.json",
      "schemas/stage4-authenticated-runtime-artifact-evidence-v2.json",
      "schemas/stage4-authenticated-runtime-artifact-evidence-v3.json",
      "schemas/stage4-authenticated-runtime-artifact-evidence-v4.json",
      "schemas/integration-v1alpha1.json",
      "schemas/launch-v1alpha1.json",
      "schemas/local-image-artifact-package-v1.json",
      "schemas/release-image-set-assertion-v1.json",
      "schemas/release-image-set-review-v1.json",
      "schemas/release-image-set-review-v2.json",
      "schemas/runtime-v1alpha1.json",
      "scripts/private-bytes.ts",
      "scripts/check-lock-integrity.ts",
      "scripts/check-npm-audit.ts",
      "scripts/release-image-set-pins.ts",
      "scripts/release-image-set-review.ts",
      "scripts/release-image-set-review-v2.ts",
      "scripts/release-local-preflight-cli.ts",
      "scripts/release-local-preflight.ts",
      "scripts/release-trivy-database-metadata-cli.ts",
      "scripts/stage4-offline-readiness-regenerate.ts",
      "scripts/stage4-offline-readiness.ts",
      "scripts/stage4-offline-render-preparation.ts",
      "scripts/stage4-offline-source-inventory.ts",
      "scripts/stage4-runtime-artifact-closure-regenerate.ts",
      "scripts/stage4-runtime-artifact-closure.ts",
      "scripts/validate-schemas.ts",
      "test/release-image-set-review.test.ts",
      "test/release-image-set-review-v2.test.ts",
      "test/release-local-preflight.test.ts",
      "test/stage4-offline-readiness.test.ts",
      "test/stage4-offline-render-preparation.test.ts",
      "test/stage4-runtime-artifact-closure.test.ts",
      "test/stage4-schema-registry.test.ts",
      "tsconfig.json",
    ],
  );
  assertEntries(validation.source_bindings);
  assert.equal(
    validation.trusted_preparation_receipt_sha256,
    stage4OfflineReadinessSha256(
      bytes("docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json"),
    ),
  );

  const committedPackage = packageObject();
  const imageLock = readManifest("docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json");
  assert.deepEqual(
    imageLock.images.map((image: { reference: string }) => image.reference),
    [committedPackage.pins.images.worker, committedPackage.pins.images.proxy, committedPackage.pins.images.sandbox].map(
      (image: { reference: string }) => image.reference,
    ),
  );
  assert.equal(imageLock.release_image_set_present, true);
  assert.equal(imageLock.exact_image_closure_satisfied, true);
  assert.equal(imageLock.images[0].artifact_identity_state, "reviewed-protected-main-image-set-record");
  assert.equal(imageLock.images[2].artifact_identity_state, "reviewed-protected-main-image-set-record");
  assert.equal(
    imageLock.release_image_set.assertion_sha256,
    packageObject().artifact_bindings.release_image_assertion_sha256,
  );
  assert.equal(
    imageLock.release_image_set.review_sha256,
    packageObject().artifact_bindings.release_image_review_sha256,
  );
  const runtime = readManifest("docs/security-evidence/stage4-offline-readiness-artifacts/runtime-pins.json");
  assert.equal(runtime.eks_node_image.kubernetes_minor, "1.35");
  assert.equal(runtime.eks_node_image.public_release_tag, "v20260728");
  assert.equal(runtime.eks_node_image.public_release_commit, "80b4c870f33069dadf27e075f184c06cccfc7999");
  assert.equal(runtime.eks_node_image.release, "1.35.6-20260728");
  assert.equal(runtime.eks_node_image.ami_id, null);
  assert.equal(runtime.eks_node_image.kernel_release, null);
  assert.equal(runtime.eks_node_image.pin_state, "public-candidate-aws-fields-unresolved");
  assert.equal(runtime.runtime.kata.archive_sha256, committedPackage.pins.runtime.kata_archive_sha256);
  assert.equal(runtime.runtime.containerd.version, committedPackage.pins.runtime.containerd_version);
  assert.equal(runtime.runtime.qemu.version, committedPackage.pins.runtime.qemu_version);
  assert.equal(runtime.runtime.containerd.artifact_sha256, committedPackage.pins.runtime.containerd_artifact_sha256);
  assert.equal(runtime.runtime.containerd.artifact_state, "authenticated-public-release-selected-candidate");
  assert.equal(runtime.runtime.qemu.artifact_sha256, committedPackage.pins.runtime.qemu_artifact_sha256);
  assert.equal(runtime.runtime.qemu.provenance, "kata-bundled-release-member");
  assert.equal(runtime.historical_host_observation.qemu.version, "8.2.2");
  assert.equal(runtime.historical_host_observation.qemu.selected_runtime, false);
  assert.equal(committedPackage.pins.runtime.exact_runtime_artifact_closure_satisfied, true);
});

test("source reads reject final and component symlinks, hard links, and oversize files", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-source-hostile-"));
  try {
    const repository = join(temporary, "repository");
    const outside = join(temporary, "outside");
    mkdirSync(join(repository, "safe"), { recursive: true });
    mkdirSync(outside);
    writeFileSync(join(repository, "safe/source.ts"), "trusted\n");
    writeFileSync(join(outside, "source.ts"), "hostile\n");
    assert.equal(new TextDecoder().decode(readStage4SourceFile(repository, "safe/source.ts")), "trusted\n");
    assert.equal(
      new TextDecoder().decode(readStage4SourceFile(repository, "safe/source.ts", 1024, true, "100644")),
      "trusted\n",
    );
    assert.throws(() => readStage4SourceFile(repository, "safe/source.ts", 1024, true, "100755"), /FILE_MODE_INVALID/u);
    chmodSync(join(repository, "safe/source.ts"), 0o755);
    assert.equal(
      new TextDecoder().decode(readStage4SourceFile(repository, "safe/source.ts", 1024, true, "100755")),
      "trusted\n",
    );
    assert.throws(() => readStage4SourceFile(repository, "safe/source.ts", 1024, true, "100644"), /FILE_MODE_INVALID/u);
    chmodSync(join(repository, "safe/source.ts"), 0o644);

    symlinkSync(join(outside, "source.ts"), join(repository, "final-link.ts"));
    assert.throws(() => readStage4SourceFile(repository, "final-link.ts"), /STAGE4_SOURCE_INVENTORY_/u);
    symlinkSync(outside, join(repository, "component-link"));
    assert.throws(() => readStage4SourceFile(repository, "component-link/source.ts"), /STAGE4_SOURCE_INVENTORY_/u);

    linkSync(join(repository, "safe/source.ts"), join(repository, "hard-link.ts"));
    assert.throws(() => readStage4SourceFile(repository, "safe/source.ts"), /FILE_BOUND_INVALID/u);
    writeFileSync(join(repository, "oversize.ts"), "too large");
    assert.throws(() => readStage4SourceFile(repository, "oversize.ts", 2), /FILE_BOUND_INVALID/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("source inventory ignores irrelevant untracked outputs but rejects untracked validation inputs", () => {
  const pinnedGitAvailable =
    existsSync(STAGE4_PINNED_GIT.executable) &&
    stage4OfflineReadinessSha256(new Uint8Array(readFileSync(STAGE4_PINNED_GIT.executable)), 64 * 1024 * 1024) ===
      STAGE4_PINNED_GIT.sha256;
  if (!pinnedGitAvailable) return;

  const repository = mkdtempSync(join(tmpdir(), "cogs-stage4-untracked-scope-"));
  try {
    writeFileSync(join(repository, "README.md"), "tracked\n");
    const initialized = spawnSync(STAGE4_PINNED_GIT.executable, ["init", "--quiet"], { cwd: repository });
    assert.equal(initialized.status, 0);
    const added = spawnSync(STAGE4_PINNED_GIT.executable, ["add", "README.md"], { cwd: repository });
    assert.equal(added.status, 0);

    mkdirSync(join(repository, "generated-output"));
    writeFileSync(join(repository, "generated-output/result.json"), "{}\n");
    assert.doesNotThrow(() => generateStage4SourceInventory(repository));

    writeFileSync(join(repository, ".git/info/exclude"), "src/\n");
    mkdirSync(join(repository, "src"));
    writeFileSync(join(repository, "src/hostile.ts"), "export {};\n");
    assert.throws(
      () => generateStage4SourceInventory(repository),
      /STAGE4_SOURCE_INVENTORY_UNTRACKED_VALIDATION_INPUT_FORBIDDEN/u,
    );
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test("binds every exact artifact and byte-identical repeated render", () => {
  const expected = packageObject().artifact_bindings as Record<string, string>;
  const artifactSet = artifacts();
  const digestFields: Record<string, string> = {
    sourceInventory: "source_inventory_sha256",
    chartInventory: "chart_inventory_sha256",
    values: "values_sha256",
    render: "render_sha256",
    repeatedRender: "repeated_render_sha256",
    renderReceipt: "render_preparation_receipt_sha256",
    imageLock: "image_lock_sha256",
    releaseImageAssertion: "release_image_assertion_sha256",
    releaseImageReview: "release_image_review_sha256",
    nicContract: "nic_contract_sha256",
    runtimePins: "runtime_pins_sha256",
    authenticatedRuntimeArtifacts: "authenticated_runtime_artifacts_sha256",
    schemaInventory: "schema_inventory_sha256",
    localValidation: "local_validation_sha256",
  };
  assert.deepEqual(Object.keys(artifactSet), [...STAGE4_READINESS_ARTIFACT_KEYS]);
  for (const key of STAGE4_READINESS_ARTIFACT_KEYS) {
    const artifact = artifactSet[key];
    assert.ok(artifact);
    assert.equal(expected[digestFields[key] ?? ""], stage4OfflineReadinessSha256(artifact), key);
    const changed = artifacts();
    changed[key] = new TextEncoder().encode(`changed-${key}\n`);
    assert.equal(classify(packageBytes(), changed).reason_code, "STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH", key);
  }

  const changed = artifacts();
  changed.repeatedRender = new TextEncoder().encode("different-render\n");
  const changedPackage = packageObject();
  changedPackage.artifact_bindings.repeated_render_sha256 = stage4OfflineReadinessSha256(changed.repeatedRender);
  changedPackage.artifact_bindings.binding_root_sha256 = stage4OfflineReadinessBindingRoot(changedPackage as never);
  assert.equal(
    classify(canonicalStage4OfflineReadinessBytes(changedPackage), changed).reason_code,
    "STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH",
  );
});

test("opaque or semantically forged records fail even when package digests and root are rewritten", () => {
  const digestFields: Record<string, string> = {
    sourceInventory: "source_inventory_sha256",
    renderReceipt: "render_preparation_receipt_sha256",
    imageLock: "image_lock_sha256",
    releaseImageAssertion: "release_image_assertion_sha256",
    releaseImageReview: "release_image_review_sha256",
    runtimePins: "runtime_pins_sha256",
    authenticatedRuntimeArtifacts: "authenticated_runtime_artifacts_sha256",
    schemaInventory: "schema_inventory_sha256",
    localValidation: "local_validation_sha256",
  };
  for (const key of Object.keys(digestFields)) {
    const changed = artifacts();
    const artifact = changed[key];
    const digestField = digestFields[key];
    assert.ok(artifact);
    assert.ok(digestField);
    const original = JSON.parse(new TextDecoder().decode(artifact)) as Record<string, any>;
    original.forged_but_canonical = true;
    changed[key] = canonicalStage4OfflineReadinessBytes(original);
    const forgedPackage = packageObject();
    forgedPackage.artifact_bindings[digestField] = stage4OfflineReadinessSha256(changed[key]);
    forgedPackage.artifact_bindings.binding_root_sha256 = stage4OfflineReadinessBindingRoot(forgedPackage as never);
    const verdict = classify(canonicalStage4OfflineReadinessBytes(forgedPackage), changed);
    assert.equal(verdict.local_preparation_complete, false, key);
    assert.equal(verdict.reason_code, "STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH", key);
  }

  const changed = artifacts();
  const receipt = JSON.parse(new TextDecoder().decode(changed.renderReceipt)) as Record<string, any>;
  receipt.first_render_sha256 = "f".repeat(64);
  changed.renderReceipt = canonicalStage4OfflineReadinessBytes(receipt);
  const local = JSON.parse(new TextDecoder().decode(changed.localValidation)) as Record<string, any>;
  local.trusted_preparation_receipt_sha256 = stage4OfflineReadinessSha256(changed.renderReceipt);
  changed.localValidation = canonicalStage4OfflineReadinessBytes(local);
  const source = JSON.parse(new TextDecoder().decode(changed.sourceInventory)) as Record<string, any>;
  source.entries.find(
    (entry: { path: string }) =>
      entry.path === "docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json",
  ).sha256 = stage4OfflineReadinessSha256(changed.renderReceipt);
  changed.sourceInventory = canonicalStage4OfflineReadinessBytes(source);
  const forgedPackage = packageObject();
  forgedPackage.artifact_bindings.render_preparation_receipt_sha256 = stage4OfflineReadinessSha256(
    changed.renderReceipt,
  );
  forgedPackage.artifact_bindings.local_validation_sha256 = stage4OfflineReadinessSha256(changed.localValidation);
  forgedPackage.artifact_bindings.source_inventory_sha256 = stage4OfflineReadinessSha256(changed.sourceInventory);
  forgedPackage.artifact_bindings.binding_root_sha256 = stage4OfflineReadinessBindingRoot(forgedPackage as never);
  assert.equal(
    classify(canonicalStage4OfflineReadinessBytes(forgedPackage), changed).reason_code,
    "STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH",
  );
});

test("unsupported local pass labels and audit promotion cannot yield local completion", () => {
  for (const mutate of [
    (local: Record<string, any>) => {
      local.checks[0] = { id: "readiness-format", result: "pass-exit-zero" };
    },
    (local: Record<string, any>) => {
      local.checks[0].outcome.exit_code = 1;
    },
    (local: Record<string, any>) => {
      local.unexecuted[0].result = "pass-exit-zero";
    },
  ]) {
    const changed = artifacts();
    const local = JSON.parse(new TextDecoder().decode(changed.localValidation)) as Record<string, any>;
    mutate(local);
    changed.localValidation = canonicalStage4OfflineReadinessBytes(local);
    const forgedPackage = packageObject();
    forgedPackage.artifact_bindings.local_validation_sha256 = stage4OfflineReadinessSha256(changed.localValidation);
    forgedPackage.artifact_bindings.binding_root_sha256 = stage4OfflineReadinessBindingRoot(forgedPackage as never);
    assert.equal(
      classify(canonicalStage4OfflineReadinessBytes(forgedPackage), changed).local_preparation_complete,
      false,
    );
  }
});

test("resource ceilings and service-specific inventory scopes form one exact closed world", () => {
  const value = packageObject();
  assert.equal(value.campaign_proposal.resource_graph.closed_world, true);
  assert.equal(value.campaign_proposal.resource_graph.undeclared_resource_classes_allowed, false);
  assert.deepEqual(
    value.campaign_proposal.resource_graph.classes,
    STAGE4_PROPOSED_RESOURCE_GRAPH.map(([resourceClass, maximumCount, resourceType, sizeGib]) => ({
      maximum_count: maximumCount,
      resource_class: resourceClass,
      resource_type: resourceType,
      size_gib_each: sizeGib,
    })),
  );
  assert.equal(value.stop_destroy.independent_inventory.tag_only_inventory_allowed, false);
  assert.deepEqual(
    value.stop_destroy.independent_inventory.scopes,
    STAGE4_INDEPENDENT_INVENTORY_SCOPES.map(([resourceClass, service, scope]) => ({
      resource_class: resourceClass,
      scope,
      service,
      tag_only: false,
    })),
  );
  assert.deepEqual(
    value.campaign_proposal.resource_graph.classes.map((row: { resource_class: string }) => row.resource_class),
    value.stop_destroy.independent_inventory.scopes.map((row: { resource_class: string }) => row.resource_class),
  );
  for (const row of value.stop_destroy.independent_inventory.scopes) {
    assert.match(row.scope, /account/u, row.resource_class);
    assert.match(row.scope, /service-wide/u, row.resource_class);
    assert.doesNotMatch(row.scope, /approved|exact-campaign|enumerated-role|node-attachment/u, row.resource_class);
  }
  for (const resourceClass of [
    "nat-gateway",
    "vpc-endpoint",
    "elastic-ip",
    "load-balancer",
    "target-group",
    "ebs-snapshot",
    "eks-managed-addon",
  ]) {
    assert.equal(
      value.campaign_proposal.resource_graph.classes.find(
        (row: { resource_class: string }) => row.resource_class === resourceClass,
      ).maximum_count,
      0,
      resourceClass,
    );
  }

  for (const mutate of [
    (candidate: Record<string, any>) => candidate.campaign_proposal.resource_graph.classes.reverse(),
    (candidate: Record<string, any>) => candidate.campaign_proposal.resource_graph.classes.pop(),
    (candidate: Record<string, any>) => {
      candidate.campaign_proposal.resource_graph.classes[0].maximum_count = 2;
    },
    (candidate: Record<string, any>) => candidate.stop_destroy.independent_inventory.scopes.reverse(),
    (candidate: Record<string, any>) => {
      candidate.stop_destroy.independent_inventory.scopes[0].tag_only = true;
    },
  ]) {
    assert.equal(classify(canonicalMutation(mutate, true)).local_preparation_complete, false);
  }
});

test("expanded revalidation inventory is exact and any omission or reordering fails closed", () => {
  const expected = [
    "issue-42-closure",
    "source-change",
    "pin-change",
    "price-change",
    "quota-change",
    "campaign-shape-change",
    "helm-chart-change",
    "helm-values-change",
    "renderer-change",
    "helm-tool-identity-or-version-change",
    "validation-procedure-change",
    "security-advisory-or-disposition-expiry",
    "account-binding-change",
    "principal-binding-change",
    "separation-state-change",
    "campaign-approval-change",
    "campaign-envelope-change",
    "campaign-attempt-change",
    "stop-destroy-procedure-change",
    "independent-inventory-scope-or-procedure-change",
  ];
  assert.deepEqual(packageObject().revalidation.triggers, expected);
  for (const mutate of [
    (candidate: Record<string, any>) => candidate.revalidation.triggers.pop(),
    (candidate: Record<string, any>) => candidate.revalidation.triggers.reverse(),
    (candidate: Record<string, any>) => candidate.revalidation.triggers.push("source-change"),
  ])
    assert.equal(classify(canonicalMutation(mutate, true)).local_preparation_complete, false);
});

test("canonical bytes reject replay aliases, duplicate keys, BOM, whitespace, and newline drift", () => {
  const canonical = packageBytes();
  const text = new TextDecoder().decode(canonical);
  for (const mutation of [
    new TextEncoder().encode(JSON.stringify(packageObject())),
    new TextEncoder().encode(`${JSON.stringify(packageObject(), null, 2)}\n`),
    new TextEncoder().encode(`\uFEFF${text}`),
    new TextEncoder().encode(text.replace(/\n$/u, "\r\n")),
    canonical.slice(0, -1),
    new TextEncoder().encode(`${text}\n`),
    new TextEncoder().encode(text.replace(/^\{/u, '{"authority":"local-static-stage4-readiness-package",')),
  ]) {
    assert.equal(classify(mutation).reason_code, "STAGE4_READINESS_INVALID_CANONICAL_PACKAGE");
  }
});

test("authority promotion and one-attempt replay or retry authority fail closed", () => {
  const mutations: Array<[string, (value: Record<string, any>) => void]> = [
    [
      "campaign request",
      (value) => {
        value.claims.campaign_request_ready = true;
      },
    ],
    [
      "campaign approval",
      (value) => {
        value.claims.campaign_approved = true;
      },
    ],
    [
      "cloud authority",
      (value) => {
        value.claims.cloud_authorized = true;
      },
    ],
    [
      "provider truth",
      (value) => {
        value.claims.provider_truth_observed = true;
      },
    ],
    [
      "zero resources",
      (value) => {
        value.claims.zero_resources_claimed = true;
      },
    ],
    [
      "Stage 4 exit",
      (value) => {
        value.claims.stage4_exit_satisfied = true;
      },
    ],
    [
      "release",
      (value) => {
        value.claims.release_eligible = true;
      },
    ],
    [
      "approval present",
      (value) => {
        value.attempt_authority.approval_present = true;
      },
    ],
    [
      "attempt present",
      (value) => {
        value.attempt_authority.attempt_id_present = true;
      },
    ],
    [
      "two attempts",
      (value) => {
        value.attempt_authority.maximum_attempts_per_approval = 2;
      },
    ],
    [
      "prior retry",
      (value) => {
        value.attempt_authority.prior_approval_authorizes_retry = true;
      },
    ],
    [
      "provider route",
      (value) => {
        value.attempt_authority.executable_provider_route_present = true;
      },
    ],
  ];
  for (const [name, mutate] of mutations) {
    assert.equal(
      classify(canonicalMutation(mutate, true)).reason_code,
      "STAGE4_READINESS_SCHEMA_OR_SEMANTIC_DRIFT",
      name,
    );
  }

  const replayed = classify();
  assert.equal(replayed.local_preparation_complete, true, "an exact replay may revalidate only the local package");
  assert.equal(replayed.campaign_request_ready, false);
  assert.equal(replayed.cloud_authorized, false);
});

test("NIC v2 remains non-observing while node-image and runtime uncertainty cannot be promoted", () => {
  const mutations: Array<[string, (value: Record<string, any>) => void]> = [
    [
      "NIC capability promoted to observation",
      (value) => {
        value.pins.nic.capability_state = "provider-observed-ready";
      },
    ],
    [
      "NIC release invented",
      (value) => {
        value.pins.nic.release = "v0.12.0";
      },
    ],
    [
      "AMI invented",
      (value) => {
        value.pins.runtime.eks_node_ami_id = "ami-12345678";
      },
    ],
    [
      "kernel invented",
      (value) => {
        value.pins.runtime.eks_node_kernel_release = "6.8.0";
      },
    ],
    [
      "image resolved",
      (value) => {
        value.pins.runtime.node_image_state = "resolved";
      },
    ],
    [
      "reviewed release image set removed",
      (value) => {
        value.pins.images.release_image_set_present = false;
      },
    ],
    [
      "reviewed image identity closure removed",
      (value) => {
        value.pins.images.exact_image_closure_satisfied = false;
      },
    ],
    [
      "reviewed worker digest substituted",
      (value) => {
        value.pins.images.worker.reference = value.pins.images.sandbox.reference;
      },
    ],
    [
      "containerd artifact invented",
      (value) => {
        value.pins.runtime.containerd_artifact_sha256 = "d".repeat(64);
      },
    ],
    [
      "runtime artifact closure downgraded",
      (value) => {
        value.pins.runtime.exact_runtime_artifact_closure_satisfied = false;
      },
    ],
    [
      "account invented",
      (value) => {
        value.campaign_proposal.account_binding.account_sha256 = "a".repeat(64);
      },
    ],
    [
      "identity invented",
      (value) => {
        value.identities.roles[0].principal_binding_sha256 = "b".repeat(64);
      },
    ],
    [
      "remove blocker",
      (value) => {
        value.blockers.splice(1, 1);
      },
    ],
  ];
  for (const [name, mutate] of mutations) {
    assert.equal(classify(canonicalMutation(mutate, true)).local_preparation_complete, false, name);
  }
});

test("binding root makes source, pin, validation, and campaign-shape replay sticky", () => {
  for (const mutate of [
    (value: Record<string, any>) => {
      value.artifact_bindings.source_inventory_sha256 = "f".repeat(64);
    },
    (value: Record<string, any>) => {
      value.artifact_bindings.local_validation_sha256 = "e".repeat(64);
    },
    (value: Record<string, any>) => {
      value.campaign_proposal.time.absolute_ttl_seconds = 7200;
    },
    (value: Record<string, any>) => {
      value.revalidation.price_state = "validated";
    },
  ]) {
    const verdict = classify(canonicalMutation(mutate));
    assert.equal(verdict.local_preparation_complete, false);
    assert.ok(
      [
        "STAGE4_READINESS_SCHEMA_OR_SEMANTIC_DRIFT",
        "STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH",
        "STAGE4_READINESS_BINDING_ROOT_MISMATCH",
      ].includes(verdict.reason_code),
    );
  }
});

test("bounded hostile prototypes, proxies, getters, symbols, and artifact-key drift preserve uncertainty", () => {
  let traps = 0;
  const hostile = new Proxy(new Uint8Array([1]), {
    getPrototypeOf() {
      traps += 1;
      throw new Error("must not run");
    },
    get() {
      traps += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(
    classifyStage4OfflineReadiness(hostile, artifacts()).reason_code,
    "STAGE4_READINESS_BOUNDED_IO_VIOLATION",
  );
  assert.equal(traps, 0);

  const hostileBindings = new Proxy(artifacts(), {
    ownKeys() {
      traps += 1;
      throw new Error("must not run");
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(classify(packageBytes(), hostileBindings).status, "preserve-uncertain");
  assert.equal(traps, 0);

  const getterBindings: Record<string, unknown> = {};
  let getterRuns = 0;
  for (const key of STAGE4_READINESS_ARTIFACT_KEYS) {
    Object.defineProperty(getterBindings, key, {
      enumerable: true,
      get() {
        getterRuns += 1;
        return artifacts()[key];
      },
    });
  }
  assert.equal(classify(packageBytes(), getterBindings).status, "preserve-uncertain");
  assert.equal(getterRuns, 0);

  const inherited = Object.assign(Object.create({ inherited: true }), artifacts());
  assert.equal(classify(packageBytes(), inherited).status, "preserve-uncertain");
  const symbol = artifacts() as Record<PropertyKey, unknown>;
  symbol[Symbol("hostile")] = true;
  assert.equal(classify(packageBytes(), symbol).status, "preserve-uncertain");
  const missing = artifacts();
  delete missing.localValidation;
  assert.equal(classify(packageBytes(), missing).status, "preserve-uncertain");

  const recursive = artifacts();
  const runtimePins = recursive.runtimePins;
  assert.ok(runtimePins);
  recursive.runtimePins = new Proxy(runtimePins, {
    get() {
      traps += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(classify(packageBytes(), recursive).status, "preserve-uncertain");
  assert.equal(traps, 0);
});

test("intrinsic byte capture rejects hostile typed-array storage without getters or oversized processing", () => {
  const canonical = packageBytes();
  const expectedDigest = stage4OfflineReadinessSha256(canonical);
  let getterReads = 0;
  for (const key of ["byteLength", "buffer"] as const) {
    Object.defineProperty(canonical, key, {
      configurable: true,
      get() {
        getterReads += 1;
        throw new Error("must not execute");
      },
    });
  }
  assert.equal(classify(canonical).local_preparation_complete, true);
  assert.equal(stage4OfflineReadinessSha256(canonical), expectedDigest);
  assert.equal(getterReads, 0);

  const oversized = new Uint8Array(STAGE4_READINESS_BYTE_LIMITS.package + 1);
  Object.defineProperty(oversized, "byteLength", {
    get() {
      getterReads += 1;
      return 1;
    },
  });
  assert.equal(classify(oversized).reason_code, "STAGE4_READINESS_BOUNDED_IO_VIOLATION");
  const oversizedHashInput = new Uint8Array(4 * 1024 * 1024 + 1);
  Object.defineProperty(oversizedHashInput, "byteLength", {
    get() {
      getterReads += 1;
      return 1;
    },
  });
  assert.throws(() => stage4OfflineReadinessSha256(oversizedHashInput), /invalid or oversized bytes/u);
  const oversizedArtifacts = artifacts();
  oversizedArtifacts.localValidation = new Uint8Array(STAGE4_READINESS_BYTE_LIMITS.localValidation + 1);
  Object.defineProperty(oversizedArtifacts.localValidation, "byteLength", {
    get() {
      getterReads += 1;
      return 1;
    },
  });
  assert.equal(classify(packageBytes(), oversizedArtifacts).reason_code, "STAGE4_READINESS_BOUNDED_IO_VIOLATION");
  assert.equal(getterReads, 0);

  const impostor = Object.create(Uint8Array.prototype) as Uint8Array;
  Object.defineProperty(impostor, "byteLength", {
    get() {
      getterReads += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(classify(impostor).reason_code, "STAGE4_READINESS_BOUNDED_IO_VIOLATION");
  assert.equal(classify(Buffer.from(Uint8Array.prototype.slice.call(canonical))).local_preparation_complete, false);
  assert.equal(getterReads, 0);

  if (typeof SharedArrayBuffer !== "undefined") {
    const shared = new Uint8Array(new SharedArrayBuffer(Uint8Array.prototype.slice.call(canonical).length));
    shared.set(canonical);
    assert.equal(classify(shared).local_preparation_complete, false);
  }
  const resizableBuffer = new ArrayBuffer(Uint8Array.prototype.slice.call(canonical).length, {
    maxByteLength: Uint8Array.prototype.slice.call(canonical).length + 1,
  });
  if (resizableBuffer.resizable) {
    const resizable = new Uint8Array(resizableBuffer);
    resizable.set(canonical);
    assert.equal(classify(resizable).local_preparation_complete, false);
  }
  const detachedBuffer = new ArrayBuffer(Uint8Array.prototype.slice.call(canonical).length);
  const detached = new Uint8Array(detachedBuffer);
  detached.set(canonical);
  structuredClone(detachedBuffer, { transfer: [detachedBuffer] });
  assert.equal(classify(detached).local_preparation_complete, false);
  assert.throws(() => stage4OfflineReadinessSha256(detached), /invalid or oversized bytes/u);
});

test("byte and aggregate bounds fail before hashing or authority classification", () => {
  const oversizedPackage = new Uint8Array(STAGE4_READINESS_BYTE_LIMITS.package + 1);
  assert.equal(classify(oversizedPackage).reason_code, "STAGE4_READINESS_BOUNDED_IO_VIOLATION");
  const oversized = artifacts();
  oversized.localValidation = new Uint8Array(STAGE4_READINESS_BYTE_LIMITS.localValidation + 1);
  assert.equal(classify(packageBytes(), oversized).reason_code, "STAGE4_READINESS_BOUNDED_IO_VIOLATION");
  const empty = artifacts();
  empty.imageLock = new Uint8Array();
  assert.equal(classify(packageBytes(), empty).reason_code, "STAGE4_READINESS_BOUNDED_IO_VIOLATION");
});

test("committed regeneration procedure is local, bounded, and wired to native Node", () => {
  const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
  assert.equal(packageJson.scripts["readiness:regenerate"], "node scripts/stage4-offline-readiness-regenerate.ts");
  assert.equal(packageJson.scripts["readiness:render:check"], "node scripts/stage4-offline-render-preparation.ts");
  assert.match(packageJson.scripts["readiness:production:check"], /^tsx --test --test-concurrency=1 /u);
  const source = readFileSync(resolve(root, "scripts/stage4-offline-readiness-regenerate.ts"), "utf8");
  for (const procedure of [
    "regenerateReceipt",
    "regenerateRunbookIndex",
    "regenerateSchemaInventory",
    "rewriteRuntimeSchemaInventoryAnchor",
    "regenerateRuntimeArtifactEvidence",
    "regenerateSourceAndLocalValidation",
    "rewriteClassifierAnchors",
    "regeneratePackage",
  ])
    assert.match(source, new RegExp(`function ${procedure}\\(`, "u"));
  assert.match(source, /STAGE4_REGENERATE_IMMUTABLE_ARTIFACT_DRIFT/u);
  assert.doesNotMatch(source, /@aws-sdk|kubectl|opentofu|terraform|external[- ]model/iu);
});

test("classifier source has no executable provider, filesystem, environment, or arbitrary diagnostic route", () => {
  const source = readFileSync(resolve(root, "scripts/stage4-offline-readiness.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /from\s+["']node:(?:child_process|fs|http|https|net|dns|tls|os|worker_threads)["']|\bprocess\.(?:env|argv)|@aws-sdk|\b(?:kubectl|opentofu|terraform)\b|helm\s+(?:install|upgrade)|external[- ]model/iu,
  );
  assert.doesNotMatch(source, /diagnostic|resource[_-]id|account[_-]id|command[_-](?:input|output|route)/iu);
  const verdict = classify();
  assert.deepEqual(
    Object.keys(verdict).sort(),
    [
      "authority",
      "binding_root_sha256",
      "blockers",
      "campaign_approved",
      "campaign_request_ready",
      "candidate_artifact_closure_complete",
      "cloud_authorized",
      "cloud_execution_observed",
      "current_resources_observed",
      "exact_image_runtime_closure_satisfied",
      "local_preparation_complete",
      "local_preparation_scope",
      "package_sha256",
      "provider_truth_observed",
      "reason_code",
      "release_eligible",
      "selected_runtime_artifacts_authenticated",
      "stage4_exit_satisfied",
      "status",
      "trusted_render_preparation_complete",
      "version",
      "zero_resources_claimed",
    ].sort(),
  );
});
