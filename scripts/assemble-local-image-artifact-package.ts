import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import {
  canonicalLocalImageBytes,
  classifyLocalImageArtifactPackage,
  type ImageRole,
  type JsonValue,
} from "./local-image-artifacts.ts";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const HEX = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const PINNED = /^\S+@sha256:[0-9a-f]{64}$/u;
const SAFE_PATH = /^[a-z0-9][a-z0-9._/-]*$/u;
const MAX_INPUT = 1024 * 1024;
const MAX_ARTIFACT = 256 * 1024 * 1024;

type InputImage = {
  role: ImageRole;
  dockerfile: { path: string; sha256: string };
  base: { reference: string; index_digest: string; linux_amd64_manifest_digest: string };
  graph_path: string;
  sbom_path: string;
  vulnerabilities_path: string;
  licenses_path: string;
  provenance_path: string;
  signature_path: string;
};

type Input = {
  version: string;
  source: { commit_sha: string; tree_sha: string; inventory_sha256: string; source_date_epoch: number };
  builder: { buildx_version: string; buildkit_version: string };
  tools: {
    syft_image: string;
    trivy_image: string;
    trivy_database_reference: string;
    trivy_database_files_sha256: string;
  };
  images: InputImage[];
};

function fail(message: string): never {
  throw new Error(message);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label}: plain object required`);
  }
  return value as Record<string, unknown>;
}

function keys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  if (actual.length !== sorted.length || actual.some((item, index) => item !== sorted[index]))
    fail(`${label}: exact fields required`);
}

function string(value: unknown, pattern: RegExp, label: string, maximum = 256): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || !pattern.test(value))
    fail(`${label}: invalid string`);
  return value;
}

function path(value: unknown, label: string): string {
  const selected = string(value, SAFE_PATH, label, 192);
  if (selected.includes("//") || selected.split("/").includes("..")) fail(`${label}: unsafe path`);
  return selected;
}

function parseInput(value: unknown): Input {
  const top = object(value, "input");
  keys(top, ["version", "source", "builder", "tools", "images"], "input");
  if (top.version !== "cogs.local-image-artifact-transaction-input/v1") fail("input version");
  const source = object(top.source, "source");
  keys(source, ["commit_sha", "tree_sha", "inventory_sha256", "source_date_epoch"], "source");
  const commit_sha = string(source.commit_sha, GIT, "commit sha", 40);
  const tree_sha = string(source.tree_sha, GIT, "tree sha", 40);
  const inventory_sha256 = string(source.inventory_sha256, HEX, "inventory sha", 64);
  if (
    !Number.isSafeInteger(source.source_date_epoch) ||
    (source.source_date_epoch as number) < 1 ||
    (source.source_date_epoch as number) > 4102444800
  ) {
    fail("source date epoch");
  }
  const builder = object(top.builder, "builder");
  keys(builder, ["buildx_version", "buildkit_version"], "builder");
  const buildx_version = string(builder.buildx_version, /^.{1,128}$/u, "buildx version", 128);
  const buildkit_version = string(builder.buildkit_version, /^.{1,128}$/u, "buildkit version", 128);
  const tools = object(top.tools, "tools");
  keys(tools, ["syft_image", "trivy_image", "trivy_database_reference", "trivy_database_files_sha256"], "tools");
  const parsedTools = {
    syft_image: string(tools.syft_image, PINNED, "syft image"),
    trivy_image: string(tools.trivy_image, PINNED, "trivy image"),
    trivy_database_reference: string(tools.trivy_database_reference, PINNED, "trivy database"),
    trivy_database_files_sha256: string(tools.trivy_database_files_sha256, HEX, "trivy database files", 64),
  };
  if (!Array.isArray(top.images) || top.images.length !== 2) fail("exact image inputs");
  const images = top.images.map((raw, index) => {
    const image = object(raw, `images[${index}]`);
    keys(
      image,
      [
        "role",
        "dockerfile",
        "base",
        "graph_path",
        "sbom_path",
        "vulnerabilities_path",
        "licenses_path",
        "provenance_path",
        "signature_path",
      ],
      `images[${index}]`,
    );
    const role = image.role;
    if (role !== (index === 0 ? "worker" : "sandbox")) fail("ordered image roles required");
    const dockerfile = object(image.dockerfile, "dockerfile");
    keys(dockerfile, ["path", "sha256"], "dockerfile");
    const expectedDockerfile = role === "worker" ? "images/worker/Dockerfile" : "images/sandbox/Dockerfile";
    if (dockerfile.path !== expectedDockerfile) fail("dockerfile role mismatch");
    const base = object(image.base, "base");
    keys(base, ["reference", "index_digest", "linux_amd64_manifest_digest"], "base");
    const reference = string(base.reference, PINNED, "base reference");
    const index_digest = string(base.index_digest, DIGEST, "base index digest", 71);
    if (!reference.endsWith(`@${index_digest}`)) fail("base reference/index mismatch");
    return {
      role,
      dockerfile: { path: expectedDockerfile, sha256: string(dockerfile.sha256, HEX, "dockerfile sha", 64) },
      base: {
        reference,
        index_digest,
        linux_amd64_manifest_digest: string(base.linux_amd64_manifest_digest, DIGEST, "base platform digest", 71),
      },
      graph_path: path(image.graph_path, "graph path"),
      sbom_path: path(image.sbom_path, "sbom path"),
      vulnerabilities_path: path(image.vulnerabilities_path, "vulnerabilities path"),
      licenses_path: path(image.licenses_path, "licenses path"),
      provenance_path: path(image.provenance_path, "provenance path"),
      signature_path: path(image.signature_path, "signature path"),
    } as InputImage;
  });
  return {
    version: top.version,
    source: { commit_sha, tree_sha, inventory_sha256, source_date_epoch: source.source_date_epoch as number },
    builder: { buildx_version, buildkit_version },
    tools: parsedTools,
    images,
  };
}

function assertPathComponents(root: string, absolute: string): void {
  const rootState = lstatSync(root);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) fail("artifact root must be a real directory");
  const selected = relative(root, absolute);
  if (selected === "" || selected.startsWith(`..${sep}`) || isAbsolute(selected)) fail("artifact path escape");
  let current = root;
  for (const part of selected.split(sep).slice(0, -1)) {
    current = resolve(current, part);
    const state = lstatSync(current);
    if (!state.isDirectory() || state.isSymbolicLink()) fail("artifact directory symlink forbidden");
  }
}

function boundArtifact(root: string, role: ImageRole, kind: string, relativePath: string) {
  const absolute = resolve(root, relativePath);
  assertPathComponents(root, absolute);
  const state = lstatSync(absolute);
  if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.size < 1 || state.size > MAX_ARTIFACT) {
    fail("invalid artifact file");
  }
  const bytes = readFileSync(absolute);
  return {
    role,
    kind,
    path: relativePath,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size_bytes: bytes.length,
  };
}

function graph(root: string, image: InputImage): Record<string, unknown> {
  const value = JSON.parse(readFileSync(resolve(root, image.graph_path), "utf8")) as unknown;
  const comparison = object(value, "graph comparison");
  if (
    comparison.version !== "cogs.local-oci-graph-comparison/v1" ||
    comparison.role !== image.role ||
    comparison.oci_graph_equal !== true ||
    comparison.layout_index_equal !== true
  ) {
    fail("graph comparison result");
  }
  const first = object(comparison.attempt_a, "attempt_a");
  const second = object(comparison.attempt_b, "attempt_b");
  if (JSON.stringify(first) !== JSON.stringify(second)) fail("attempt graph mismatch");
  const index = string(first.oci_layout_index_sha256, HEX, "layout index", 64);
  const subject = string(first.oci_subject_manifest_digest, DIGEST, "subject digest", 71);
  const config = string(first.config_digest, DIGEST, "config digest", 71);
  if (!Array.isArray(first.layer_digests) || first.layer_digests.length < 1 || first.layer_digests.length > 256)
    fail("layer digest inventory");
  const layers = first.layer_digests.map((digest) => string(digest, DIGEST, "layer digest", 71));
  return {
    oci_subject_manifest_digest: subject,
    config_digest: config,
    layer_digests: layers,
    oci_layout_index_sha256: index,
    docker_image_id: null,
    oci_archive_sha256: null,
    registry_reference: null,
    registry_digest: null,
  };
}

const [inputPath, artifactRootInput, outputPath] = process.argv.slice(2);
try {
  if (
    inputPath === undefined ||
    artifactRootInput === undefined ||
    outputPath === undefined ||
    process.argv.length !== 5
  ) {
    fail("usage: assemble-local-image-artifact-package.ts <input.json> <artifact-root> <output.json>");
  }
  const inputState = lstatSync(inputPath);
  if (
    !inputState.isFile() ||
    inputState.isSymbolicLink() ||
    inputState.nlink !== 1 ||
    inputState.size < 1 ||
    inputState.size > MAX_INPUT
  ) {
    fail("transaction input bound");
  }
  const inputBytes = readFileSync(inputPath);
  const input = parseInput(JSON.parse(inputBytes.toString("utf8")));
  const root = resolve(artifactRootInput);
  const artifacts = input.images.flatMap((image) => [
    boundArtifact(root, image.role, "oci-graph-comparison", image.graph_path),
    boundArtifact(root, image.role, "sbom", image.sbom_path),
    boundArtifact(root, image.role, "vulnerabilities", image.vulnerabilities_path),
    boundArtifact(root, image.role, "licenses", image.licenses_path),
    boundArtifact(root, image.role, "local-provenance", image.provenance_path),
    boundArtifact(root, image.role, "signature-absence", image.signature_path),
  ]);
  const packageValue = {
    version: "cogs.local-image-artifact-package/v1",
    authority: "unauthenticated-local-image-artifact-transaction",
    source: input.source,
    target: { os: "linux", architecture: "amd64", variant: null },
    content_profile: "stage0-scaffold-local-candidate",
    images: input.images.map((image) => ({
      role: image.role,
      dockerfile: image.dockerfile,
      base: image.base,
      builder: {
        ...input.builder,
        platform: "linux/amd64",
        attempts: 2,
        no_cache: true,
        pull_by_digest: true,
        run_network: "none",
      },
      graph: graph(root, image),
      reproducibility: { two_builds: true, oci_graph_equal: true, layout_index_equal: true },
      evidence: {
        graph: { kind: "oci-graph-comparison", path: image.graph_path },
        sbom: { kind: "sbom", path: image.sbom_path, generator_image: input.tools.syft_image },
        vulnerabilities: {
          kind: "vulnerabilities",
          path: image.vulnerabilities_path,
          scanner_image: input.tools.trivy_image,
          database_reference: input.tools.trivy_database_reference,
          database_files_sha256: input.tools.trivy_database_files_sha256,
          severities: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
          ignore_unfixed: false,
          offline_scan: true,
        },
        licenses: { kind: "licenses", path: image.licenses_path },
        provenance: { kind: "local-provenance", path: image.provenance_path },
        signature: { kind: "signature-absence", path: image.signature_path },
      },
    })),
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
  } as unknown as JsonValue;
  const packageBytes = canonicalLocalImageBytes(packageValue);
  writeFileSync(outputPath, packageBytes, { flag: "wx", mode: 0o600 });
  const result = classifyLocalImageArtifactPackage(packageBytes, root);
  if (!result.valid || result.reason_code !== "VALID_BLOCKED_SCAFFOLD_PACKAGE")
    fail("assembled package did not classify");
  process.stdout.write(Buffer.from(canonicalLocalImageBytes(result as unknown as JsonValue)));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "package assembly failed"}\n`);
  process.exitCode = 1;
}
