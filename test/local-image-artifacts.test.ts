import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import {
  canonicalLocalImageBytes,
  classifyLocalImageArtifactPackage as classifyPackageBytes,
  compareOciLayouts,
  type ImageRole,
  imageLicenseInventory,
  type JsonValue,
  localProvenanceStatement,
  signatureAbsenceEvidence,
  verifyOciLayout,
} from "../scripts/local-image-artifacts.ts";

const sha = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");
const digest = (bytes: Uint8Array | string) => `sha256:${sha(bytes)}`;
const canonical = (value: JsonValue) => Buffer.from(canonicalLocalImageBytes(value));
const classifyLocalImageArtifactPackage = (bytes: Buffer, root: string) =>
  classifyPackageBytes(Uint8Array.from(bytes), root);

function descriptor(bytes: Buffer, mediaType: string, platform?: { os: string; architecture: string }) {
  return { mediaType, digest: digest(bytes), size: bytes.length, ...(platform === undefined ? {} : { platform }) };
}

function layout(root: string, role: ImageRole, mutation?: "arm64" | "bad-digest" | "extra-blob"): void {
  mkdirSync(resolve(root, "blobs/sha256"), { recursive: true });
  const layer = Buffer.from(`${role}-layer\n`);
  const config = canonical({
    architecture: "amd64",
    os: "linux",
    config: {
      User: role === "worker" ? "nonroot" : "root",
      Cmd: role === "worker" ? ["--version"] : ["/bin/sh"],
      Labels: {
        "dev.cogs.profile": "stage0-scaffold",
        "org.opencontainers.image.licenses": "Apache-2.0",
        "org.opencontainers.image.source": "https://github.com/nenb/cogs",
      },
    },
    rootfs: { type: "layers", diff_ids: [digest(Buffer.from(`${role}-diff`))] },
    history: [{ created_by: "fixture", empty_layer: false }],
  });
  const configDescriptor = descriptor(config, "application/vnd.oci.image.config.v1+json");
  const layerDescriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip");
  const manifest = canonical({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: configDescriptor,
    layers: [layerDescriptor],
  });
  const manifestDescriptor = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json", {
    os: "linux",
    architecture: mutation === "arm64" ? "arm64" : "amd64",
  });
  const index = canonical({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [manifestDescriptor],
  });
  writeFileSync(resolve(root, "oci-layout"), '{"imageLayoutVersion":"1.0.0"}\n');
  writeFileSync(resolve(root, "index.json"), index);
  for (const bytes of [layer, config, manifest]) writeFileSync(resolve(root, "blobs/sha256", sha(bytes)), bytes);
  if (mutation === "bad-digest") writeFileSync(resolve(root, "blobs/sha256", sha(layer)), "changed");
  if (mutation === "extra-blob") writeFileSync(resolve(root, "blobs/sha256", "f".repeat(64)), "extra");
}

function fixture(): { root: string; workerA: string; workerB: string; sandboxA: string; sandboxB: string } {
  const root = mkdtempSync(resolve(tmpdir(), "cogs-local-image-artifacts-"));
  const paths = {
    root,
    workerA: resolve(root, "worker-a"),
    workerB: resolve(root, "worker-b"),
    sandboxA: resolve(root, "sandbox-a"),
    sandboxB: resolve(root, "sandbox-b"),
  };
  layout(paths.workerA, "worker");
  cpSync(paths.workerA, paths.workerB, { recursive: true });
  layout(paths.sandboxA, "sandbox");
  cpSync(paths.sandboxA, paths.sandboxB, { recursive: true });
  return paths;
}

function artifact(root: string, role: ImageRole, kind: string, path: string, value: JsonValue) {
  const bytes = canonical(value);
  const absolute = resolve(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, bytes);
  return { role, kind, path, sha256: sha(bytes), size_bytes: bytes.length };
}

function packageFixture(
  root: string,
  workerGraph: ReturnType<typeof compareOciLayouts>,
  sandboxGraph: ReturnType<typeof compareOciLayouts>,
) {
  const source = {
    commit_sha: "a".repeat(40),
    tree_sha: "b".repeat(40),
    inventory_sha256: "c".repeat(64),
    source_date_epoch: 1_700_000_000,
  };
  const builder = { buildx_version: "buildx fixture", buildkit_version: "v0.fixture" };
  const artifacts: Array<Record<string, unknown>> = [];
  const images = (
    [
      ["worker", workerGraph],
      ["sandbox", sandboxGraph],
    ] as const
  ).map(([role, graph]) => {
    const prefix = role;
    const graphPath = `${prefix}/graph-comparison.json`;
    const sbomPath = `${prefix}/sbom.spdx.json`;
    const vulnerabilityPath = `${prefix}/vulnerabilities.json`;
    const licensePath = `${prefix}/licenses.json`;
    const provenancePath = `${prefix}/local-provenance.json`;
    const signaturePath = `${prefix}/signature-absence.json`;
    const graphBytes = canonical(graph as unknown as JsonValue);
    mkdirSync(resolve(root, prefix), { recursive: true });
    writeFileSync(resolve(root, graphPath), graphBytes);
    artifacts.push({
      role,
      kind: "oci-graph-comparison",
      path: graphPath,
      sha256: sha(graphBytes),
      size_bytes: graphBytes.length,
    });
    const sbom = {
      spdxVersion: "SPDX-2.3",
      packages: [
        { name: `${role}-package`, versionInfo: "1", licenseDeclared: "Apache-2.0", licenseConcluded: "Apache-2.0" },
      ],
    } as JsonValue;
    const sbomBytes = canonical(sbom);
    writeFileSync(resolve(root, sbomPath), sbomBytes);
    artifacts.push({ role, kind: "sbom", path: sbomPath, sha256: sha(sbomBytes), size_bytes: sbomBytes.length });
    artifacts.push(artifact(root, role, "vulnerabilities", vulnerabilityPath, { SchemaVersion: 2, Results: [] }));
    const licenses = imageLicenseInventory(role, sbomBytes);
    artifacts.push(artifact(root, role, "licenses", licensePath, licenses));
    const dockerfilePath = role === "worker" ? "images/worker/Dockerfile" : "images/sandbox/Dockerfile";
    const dockerfile = { path: dockerfilePath, sha256: role === "worker" ? "d".repeat(64) : "e".repeat(64) };
    const indexDigest = role === "worker" ? `sha256:${"1".repeat(64)}` : `sha256:${"2".repeat(64)}`;
    const base = {
      reference: `example.invalid/${role}@${indexDigest}`,
      index_digest: indexDigest,
      linux_amd64_manifest_digest: role === "worker" ? `sha256:${"3".repeat(64)}` : `sha256:${"4".repeat(64)}`,
    };
    const provenance = localProvenanceStatement(
      role,
      graph.attempt_a.oci_subject_manifest_digest,
      source,
      sha(graphBytes),
      builder,
      { dockerfile, base },
    );
    artifacts.push(artifact(root, role, "local-provenance", provenancePath, provenance));
    artifacts.push(artifact(root, role, "signature-absence", signaturePath, signatureAbsenceEvidence(role)));
    return {
      role,
      dockerfile,
      base,
      builder: {
        ...builder,
        platform: "linux/amd64",
        attempts: 2,
        no_cache: true,
        pull_by_digest: true,
        run_network: "none",
      },
      graph: {
        oci_subject_manifest_digest: graph.attempt_a.oci_subject_manifest_digest,
        config_digest: graph.attempt_a.config_digest,
        layer_digests: graph.attempt_a.layer_digests,
        oci_layout_index_sha256: graph.attempt_a.oci_layout_index_sha256,
        docker_image_id: null,
        oci_archive_sha256: null,
        registry_reference: null,
        registry_digest: null,
      },
      reproducibility: { two_builds: true, oci_graph_equal: true, layout_index_equal: true },
      evidence: {
        graph: { kind: "oci-graph-comparison", path: graphPath },
        sbom: { kind: "sbom", path: sbomPath, generator_image: `anchore/syft@sha256:${"5".repeat(64)}` },
        vulnerabilities: {
          kind: "vulnerabilities",
          path: vulnerabilityPath,
          scanner_image: `aquasec/trivy@sha256:${"6".repeat(64)}`,
          database_reference: `ghcr.io/aquasecurity/trivy-db:2@sha256:${"7".repeat(64)}`,
          database_files_sha256: "8".repeat(64),
          severities: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
          ignore_unfixed: false,
          offline_scan: true,
        },
        licenses: { kind: "licenses", path: licensePath },
        provenance: { kind: "local-provenance", path: provenancePath },
        signature: { kind: "signature-absence", path: signaturePath },
      },
    };
  });
  return {
    version: "cogs.local-image-artifact-package/v1",
    authority: "unauthenticated-local-image-artifact-transaction",
    source,
    target: { os: "linux", architecture: "amd64", variant: null },
    content_profile: "stage0-scaffold-local-candidate",
    images,
    artifacts,
    publication: { performed: false, registry_reference: null, registry_digest: null, remote_readback_observed: false },
    claims: {
      local_build_observed: true,
      two_build_oci_graphs_equal: true,
      production_payload_present: false,
      image_signature_verified: false,
      registry_digest_observed: false,
      cloud_execution_observed: false,
      kubernetes_execution_observed: false,
      provider_execution_observed: false,
      external_model_execution_observed: false,
      runtime_isolation_qualified: false,
      rc_frozen: false,
      production_ready: false,
      release_eligible: false,
    },
    blockers: [
      "PRODUCTION_IMAGE_PAYLOAD_ABSENT",
      "REGISTRY_PUBLICATION_NOT_OBSERVED",
      "IMAGE_SIGNATURE_NOT_VERIFIED",
      "RUNTIME_CONFORMANCE_NOT_EXECUTED",
      "STAGE4_IMAGE_RUNTIME_CLOSURE_UNCHANGED_FALSE",
      "STAGE5_RELEASE_FREEZE_UNCHANGED_ABSENT",
    ],
  };
}

test("strict OCI verifier identifies a direct linux/amd64 scaffold graph", () => {
  const value = fixture();
  try {
    const graph = verifyOciLayout(value.workerA, "worker");
    assert.equal(graph.target.architecture, "amd64");
    assert.equal(graph.content_profile, "stage0-scaffold-local-candidate");
    assert.match(graph.oci_subject_manifest_digest, /^sha256:[0-9a-f]{64}$/u);
    assert.notEqual(graph.oci_layout_index_sha256, graph.oci_subject_manifest_digest.slice(7));
    const comparison = compareOciLayouts(value.workerA, value.workerB, "worker");
    assert.equal(comparison.docker_image_id, null);
    assert.equal(comparison.registry_digest, null);
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("OCI verifier rejects platform drift, digest drift, unreachable blobs, symlinks, and hard links", () => {
  for (const mutation of ["arm64", "bad-digest", "extra-blob"] as const) {
    const root = mkdtempSync(resolve(tmpdir(), `cogs-oci-${mutation}-`));
    try {
      layout(root, "worker", mutation);
      assert.throws(() => verifyOciLayout(root, "worker"));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
  const symlinkRoot = mkdtempSync(resolve(tmpdir(), "cogs-oci-symlink-"));
  try {
    layout(symlinkRoot, "worker");
    const original = resolve(symlinkRoot, "oci-layout");
    const target = resolve(symlinkRoot, "layout-target");
    writeFileSync(target, readFileSync(original));
    rmSync(original);
    symlinkSync(target, original);
    assert.throws(() => verifyOciLayout(symlinkRoot, "worker"), /symlink/u);
  } finally {
    rmSync(symlinkRoot, { recursive: true, force: true });
  }
  const hardlinkRoot = mkdtempSync(resolve(tmpdir(), "cogs-oci-hardlink-"));
  try {
    layout(hardlinkRoot, "worker");
    linkSync(resolve(hardlinkRoot, "oci-layout"), resolve(hardlinkRoot, "oci-layout-alias"));
    assert.throws(() => verifyOciLayout(hardlinkRoot, "worker"));
  } finally {
    rmSync(hardlinkRoot, { recursive: true, force: true });
  }
});

test("two-build comparison fails on any reachable graph drift", () => {
  const value = fixture();
  try {
    const configPath = resolve(value.workerB, "index.json");
    const index = JSON.parse(readFileSync(configPath, "utf8")) as { annotations?: Record<string, string> };
    index.annotations = { "org.example.drift": "true" };
    writeFileSync(configPath, canonical(index as JsonValue));
    assert.throws(() => compareOciLayouts(value.workerA, value.workerB, "worker"), /mismatch/u);
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("bound package classifies complete local evidence while retaining every release blocker", () => {
  const value = fixture();
  try {
    const packageRoot = resolve(value.root, "package");
    mkdirSync(packageRoot);
    const packageValue = packageFixture(
      packageRoot,
      compareOciLayouts(value.workerA, value.workerB, "worker"),
      compareOciLayouts(value.sandboxA, value.sandboxB, "sandbox"),
    );
    const result = classifyLocalImageArtifactPackage(canonical(packageValue as unknown as JsonValue), packageRoot);
    assert.deepEqual(result, {
      authority: "local-static-artifact-package-classifier",
      valid: true,
      package_sha256: sha(canonical(packageValue as unknown as JsonValue)),
      local_artifacts_complete: true,
      content_profile: "stage0-scaffold-local-candidate",
      registry_digest_observed: false,
      image_signature_verified: false,
      stage4_image_runtime_closure_satisfied: false,
      stage5_release_freeze_satisfied: false,
      production_ready: false,
      release_eligible: false,
      reason_code: "VALID_BLOCKED_SCAFFOLD_PACKAGE",
    });
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("package classifier rejects noncanonical, schema promotion, evidence drift, and signature fabrication", () => {
  const value = fixture();
  try {
    const packageRoot = resolve(value.root, "package");
    mkdirSync(packageRoot);
    const packageValue = packageFixture(
      packageRoot,
      compareOciLayouts(value.workerA, value.workerB, "worker"),
      compareOciLayouts(value.sandboxA, value.sandboxB, "sandbox"),
    ) as Record<string, unknown>;
    const pretty = Buffer.from(`${JSON.stringify(packageValue, null, 2)}\n`);
    assert.equal(classifyLocalImageArtifactPackage(pretty, packageRoot).reason_code, "NON_CANONICAL_JSON");
    const proxied = new Proxy(Uint8Array.from(canonical(packageValue as unknown as JsonValue)), {});
    assert.equal(classifyPackageBytes(proxied, packageRoot).reason_code, "BOUNDED_INPUT_VIOLATION");

    const promoted = structuredClone(packageValue) as { claims: { release_eligible: boolean } };
    promoted.claims.release_eligible = true;
    assert.equal(
      classifyLocalImageArtifactPackage(canonical(promoted as unknown as JsonValue), packageRoot).reason_code,
      "SCHEMA_DRIFT",
    );

    const sourceDrift = structuredClone(packageValue) as { source: { inventory_sha256: string } };
    sourceDrift.source.inventory_sha256 = "9".repeat(64);
    assert.equal(
      classifyLocalImageArtifactPackage(canonical(sourceDrift as unknown as JsonValue), packageRoot).reason_code,
      "ARTIFACT_BINDING_FAILURE",
    );

    writeFileSync(resolve(packageRoot, "worker/vulnerabilities.json"), canonical({ changed: true }));
    assert.equal(
      classifyLocalImageArtifactPackage(canonical(packageValue as unknown as JsonValue), packageRoot).reason_code,
      "ARTIFACT_BINDING_FAILURE",
    );

    const restored = packageFixture(
      packageRoot,
      compareOciLayouts(value.workerA, value.workerB, "worker"),
      compareOciLayouts(value.sandboxA, value.sandboxB, "sandbox"),
    ) as Record<string, unknown>;
    writeFileSync(resolve(packageRoot, "worker/signature-absence.json"), canonical({ performed: true }));
    const artifacts = restored.artifacts as Array<Record<string, unknown>>;
    const signature = artifacts.find((item) => item.role === "worker" && item.kind === "signature-absence");
    assert.ok(signature);
    const signatureBytes = readFileSync(resolve(packageRoot, "worker/signature-absence.json"));
    signature.sha256 = sha(signatureBytes);
    signature.size_bytes = signatureBytes.length;
    assert.equal(
      classifyLocalImageArtifactPackage(canonical(restored as JsonValue), packageRoot).reason_code,
      "ARTIFACT_BINDING_FAILURE",
    );
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("strict assembler emits a canonical package that classifies only as a blocked scaffold", () => {
  const value = fixture();
  try {
    const packageRoot = resolve(value.root, "package");
    mkdirSync(packageRoot);
    const packageValue = packageFixture(
      packageRoot,
      compareOciLayouts(value.workerA, value.workerB, "worker"),
      compareOciLayouts(value.sandboxA, value.sandboxB, "sandbox"),
    ) as Record<string, unknown>;
    const source = packageValue.source as Record<string, unknown>;
    const packageImages = packageValue.images as Array<Record<string, unknown>>;
    const firstImage = packageImages[0] as Record<string, unknown>;
    const firstBuilder = firstImage.builder as Record<string, unknown>;
    const firstEvidence = firstImage.evidence as Record<string, unknown>;
    const sbomEvidence = firstEvidence.sbom as Record<string, unknown>;
    const vulnerabilityEvidence = firstEvidence.vulnerabilities as Record<string, unknown>;
    const input = {
      version: "cogs.local-image-artifact-transaction-input/v1",
      source,
      builder: {
        buildx_version: firstBuilder.buildx_version,
        buildkit_version: firstBuilder.buildkit_version,
      },
      tools: {
        syft_image: sbomEvidence.generator_image,
        trivy_image: vulnerabilityEvidence.scanner_image,
        trivy_database_reference: vulnerabilityEvidence.database_reference,
        trivy_database_files_sha256: vulnerabilityEvidence.database_files_sha256,
      },
      images: packageImages.map((image) => {
        const evidence = image.evidence as Record<string, Record<string, unknown>>;
        const evidencePath = (kind: string) => {
          const selected = evidence[kind];
          assert.ok(selected);
          return selected.path;
        };
        return {
          role: image.role,
          dockerfile: image.dockerfile,
          base: image.base,
          graph_path: evidencePath("graph"),
          sbom_path: evidencePath("sbom"),
          vulnerabilities_path: evidencePath("vulnerabilities"),
          licenses_path: evidencePath("licenses"),
          provenance_path: evidencePath("provenance"),
          signature_path: evidencePath("signature"),
        };
      }),
    };
    const inputPath = resolve(value.root, "transaction-input.json");
    const outputPath = resolve(value.root, "package.canonical.json");
    writeFileSync(inputPath, canonical(input as unknown as JsonValue));
    const stdout = execFileSync(
      process.execPath,
      [
        "--import",
        "tsx",
        resolve(import.meta.dirname, "../scripts/assemble-local-image-artifact-package.ts"),
        inputPath,
        packageRoot,
        outputPath,
      ],
      { encoding: "utf8", maxBuffer: 1024 * 1024 },
    );
    const classification = JSON.parse(stdout) as { reason_code: string; production_ready: boolean };
    assert.equal(classification.reason_code, "VALID_BLOCKED_SCAFFOLD_PACKAGE");
    assert.equal(classification.production_ready, false);
    const output = readFileSync(outputPath);
    assert.deepEqual(output, canonical(JSON.parse(output.toString("utf8")) as JsonValue));
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("package classifier rejects a symlinked artifact directory", () => {
  const value = fixture();
  try {
    const packageRoot = resolve(value.root, "package");
    mkdirSync(packageRoot);
    const packageValue = packageFixture(
      packageRoot,
      compareOciLayouts(value.workerA, value.workerB, "worker"),
      compareOciLayouts(value.sandboxA, value.sandboxB, "sandbox"),
    );
    renameSync(resolve(packageRoot, "worker"), resolve(packageRoot, "worker-real"));
    symlinkSync(resolve(packageRoot, "worker-real"), resolve(packageRoot, "worker"));
    assert.equal(
      classifyLocalImageArtifactPackage(canonical(packageValue as unknown as JsonValue), packageRoot).reason_code,
      "ARTIFACT_BINDING_FAILURE",
    );
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("historical manual workflow rejects current production payload before Docker and remains non-publishing", () => {
  const workflow = readFileSync(resolve(import.meta.dirname, "../.github/workflows/local-image-artifacts.yml"), "utf8");
  const worker = readFileSync(resolve(import.meta.dirname, "../images/worker/Dockerfile"), "utf8");
  const sandbox = readFileSync(resolve(import.meta.dirname, "../images/sandbox/Dockerfile"), "utf8");
  assert.match(workflow, /^name: Historical prepublication local image artifacts$/mu);
  assert.match(workflow, /^on:\n {2}workflow_dispatch:/mu);
  assert.equal(worker.includes('dev.cogs.profile="stage0-scaffold"'), false);
  assert.equal(sandbox.includes('dev.cogs.profile="stage0-scaffold"'), false);
  const historicalGate = workflow.indexOf("grep -Fq 'dev.cogs.profile=\"stage0-scaffold\"'");
  const firstDocker = workflow.indexOf("docker ");
  assert.ok(historicalGate >= 0 && firstDocker > historicalGate, "historical profile gate must precede Docker");
  assert.match(workflow, /permissions:\n {2}contents: read/u);
  assert.match(workflow, /github\.run_attempt == 1/u);
  assert.match(workflow, /github\.ref_protected == true/u);
  assert.match(workflow, /test "\$REVIEWED_SHA" = "\$ENVELOPE_SHA"/u);
  assert.match(workflow, /--platform linux\/amd64/u);
  assert.match(workflow, /--provenance=false/u);
  assert.match(workflow, /--sbom=false/u);
  assert.match(workflow, /--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL/u);
  assert.match(workflow, /--ignore-unfixed=false/u);
  assert.match(workflow, /--offline-scan/u);
  assert.doesNotMatch(workflow, /(?:packages|id-token):\s*write/u);
  assert.doesNotMatch(workflow, /docker\s+(?:push|login)|docker\/login-action|cosign|secrets\./u);
  assert.doesNotMatch(workflow, /docs\/security-evidence\/stage4-offline-readiness-artifacts\/image-lock\.json/u);
});

test("license inventory preserves unknowns and never grants legal or release approval", () => {
  const sbom = canonical({
    spdxVersion: "SPDX-2.3",
    packages: [{ name: "known", licenseDeclared: "Apache-2.0", licenseConcluded: "Apache-2.0" }, { name: "unknown" }],
  });
  const inventory = imageLicenseInventory("worker", sbom);
  assert.equal(inventory.package_count, 2);
  assert.equal(inventory.unknown_count, 1);
  assert.equal(inventory.legal_review_performed, false);
  assert.equal(inventory.release_approved, false);
});
