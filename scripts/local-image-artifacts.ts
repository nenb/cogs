import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes } from "./private-bytes.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const packageSchema = require("../schemas/local-image-artifact-package-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validatePackage = ajv.compile(packageSchema) as ValidateFunction;

const SHA256 = /^[0-9a-f]{64}$/u;
const DIGEST = /^sha256:([0-9a-f]{64})$/u;
const SAFE_RELATIVE = /^[a-z0-9][a-z0-9._/-]*$/u;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_LAYOUT_FILES = 4096;
const MAX_LAYOUT_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_BLOB_BYTES = 1024 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 256 * 1024 * 1024;
const MAX_EVIDENCE_TOTAL_BYTES = 512 * 1024 * 1024;
const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";
const CONFIG_TYPES = new Set([
  "application/vnd.oci.image.config.v1+json",
  "application/vnd.docker.container.image.v1+json",
]);
const LAYER_TYPES = new Set([
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
  "application/vnd.oci.image.layer.v1.tar+zstd",
  "application/vnd.docker.image.rootfs.diff.tar",
  "application/vnd.docker.image.rootfs.diff.tar.gzip",
]);

export type ImageRole = "worker" | "sandbox";

type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonObject = { [key: string]: JsonValue };

type Descriptor = {
  mediaType: string;
  digest: string;
  size: number;
  annotations?: Record<string, string>;
  platform?: { architecture: string; os: string; variant?: string };
};

export type OciGraph = Readonly<{
  version: "cogs.local-oci-graph/v1";
  role: ImageRole;
  target: Readonly<{ os: "linux"; architecture: "amd64"; variant: null }>;
  content_profile: "stage0-scaffold-local-candidate";
  oci_layout_index_sha256: string;
  oci_subject_manifest_digest: string;
  config_digest: string;
  layer_digests: readonly string[];
  reachable_blob_digests: readonly string[];
  blob_count: number;
  total_blob_bytes: number;
}>;

export type OciGraphComparison = Readonly<{
  version: "cogs.local-oci-graph-comparison/v1";
  role: ImageRole;
  attempt_a: OciGraph;
  attempt_b: OciGraph;
  oci_graph_equal: true;
  layout_index_equal: true;
  docker_image_id: null;
  oci_archive_sha256: null;
  registry_reference: null;
  registry_digest: null;
}>;

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("non-JSON value");
  return encoded;
}

export function canonicalLocalImageBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}: object required`);
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label}: plain object required`);
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
) {
  const keys = Object.keys(value).sort();
  const allowed = new Set([...required, ...optional]);
  if (keys.some((key) => !allowed.has(key))) throw new Error(`${label}: unknown field`);
  if (required.some((key) => !Object.hasOwn(value, key))) throw new Error(`${label}: missing field`);
}

function boundedString(value: unknown, label: string, max = 1024): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) throw new Error(`${label}: invalid string`);
  return value;
}

function boundedInteger(value: unknown, label: string, maximum = MAX_BLOB_BYTES): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) {
    throw new Error(`${label}: invalid integer`);
  }
  return value as number;
}

function assertDigest(value: unknown, label: string): string {
  const digest = boundedString(value, label, 71);
  if (!DIGEST.test(digest)) throw new Error(`${label}: invalid digest`);
  return digest;
}

function safeArtifactPath(value: unknown, label: string): string {
  const path = boundedString(value, label, 192);
  if (!SAFE_RELATIVE.test(path) || path.includes("//") || path.split("/").includes("..")) {
    throw new Error(`${label}: unsafe relative path`);
  }
  return path;
}

function stableFile(path: string, maximum: number): Buffer {
  const beforePath = lstatSync(path);
  if (!beforePath.isFile() || beforePath.isSymbolicLink() || beforePath.nlink !== 1) {
    throw new Error("regular single-linked file required");
  }
  if (beforePath.size < 1 || beforePath.size > maximum) throw new Error("file size outside bound");
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.size !== beforePath.size)
      throw new Error("file identity drift");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const afterPath = lstatSync(path);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.dev !== afterPath.dev ||
      before.ino !== afterPath.ino ||
      afterPath.isSymbolicLink()
    ) {
      throw new Error("file identity drift");
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function parseJson(bytes: Uint8Array, label: string): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${label}: invalid UTF-8 JSON`);
  }
}

function parseAnnotations(value: unknown, label: string): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const annotations = asObject(value, label);
  const entries = Object.entries(annotations);
  if (entries.length > 64) throw new Error(`${label}: too many annotations`);
  for (const [key, item] of entries) {
    if (key.length < 1 || key.length > 256 || typeof item !== "string" || item.length > 4096) {
      throw new Error(`${label}: invalid annotation`);
    }
  }
  return annotations as Record<string, string>;
}

function parseDescriptor(value: unknown, label: string, platformRequired: boolean): Descriptor {
  const descriptor = asObject(value, label);
  exactKeys(descriptor, ["mediaType", "digest", "size"], ["annotations", "platform"], label);
  const mediaType = boundedString(descriptor.mediaType, `${label}.mediaType`, 128);
  const digest = assertDigest(descriptor.digest, `${label}.digest`);
  const size = boundedInteger(descriptor.size, `${label}.size`);
  const annotations = parseAnnotations(descriptor.annotations, `${label}.annotations`);
  let platform: Descriptor["platform"];
  if (descriptor.platform !== undefined) {
    const raw = asObject(descriptor.platform, `${label}.platform`);
    exactKeys(raw, ["architecture", "os"], ["variant", "os.version", "os.features"], `${label}.platform`);
    const architecture = boundedString(raw.architecture, `${label}.platform.architecture`, 32);
    const os = boundedString(raw.os, `${label}.platform.os`, 32);
    const variant = raw.variant === undefined ? undefined : boundedString(raw.variant, `${label}.platform.variant`, 32);
    if (raw["os.version"] !== undefined) boundedString(raw["os.version"], `${label}.platform.os.version`, 128);
    if (raw["os.features"] !== undefined) {
      if (!Array.isArray(raw["os.features"]) || raw["os.features"].length > 32)
        throw new Error(`${label}: os.features`);
      for (const feature of raw["os.features"]) boundedString(feature, `${label}.platform.os.features`, 64);
    }
    platform = variant === undefined ? { architecture, os } : { architecture, os, variant };
  }
  if (platformRequired && platform === undefined) throw new Error(`${label}: platform required`);
  return {
    mediaType,
    digest,
    size,
    ...(annotations === undefined ? {} : { annotations }),
    ...(platform === undefined ? {} : { platform }),
  };
}

function blobPath(root: string, digest: string): string {
  const match = digest.match(DIGEST);
  if (!match?.[1]) throw new Error("invalid blob digest");
  return resolve(root, "blobs", "sha256", match[1]);
}

function verifiedBlob(root: string, descriptor: Descriptor, maximum = MAX_BLOB_BYTES): Buffer {
  if (descriptor.size > maximum) throw new Error("blob exceeds semantic bound");
  const path = blobPath(root, descriptor.digest);
  const bytes = stableFile(path, maximum);
  if (bytes.length !== descriptor.size) throw new Error("descriptor size mismatch");
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (`sha256:${actual}` !== descriptor.digest) throw new Error("descriptor digest mismatch");
  return bytes;
}

function inventoryLayout(root: string): { files: Set<string>; total: number } {
  const rootState = lstatSync(root);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) throw new Error("layout root must be a directory");
  const files = new Set<string>();
  let total = 0;
  const visit = (directory: string) => {
    for (const name of readdirSync(directory).sort(compareCodePoints)) {
      if (name.length < 1 || name === "." || name === ".." || name.includes("/") || name.includes("\\")) {
        throw new Error("invalid layout entry name");
      }
      const path = resolve(directory, name);
      const state = lstatSync(path);
      if (state.isSymbolicLink()) throw new Error("layout symlink forbidden");
      if (state.isDirectory()) {
        visit(path);
        continue;
      }
      if (!state.isFile() || state.nlink !== 1 || state.size < 1 || state.size > MAX_BLOB_BYTES) {
        throw new Error("invalid layout file");
      }
      const rel = relative(root, path).split(sep).join("/");
      if (rel.startsWith("../") || isAbsolute(rel)) throw new Error("layout path escape");
      files.add(rel);
      total += state.size;
      if (files.size > MAX_LAYOUT_FILES || total > MAX_LAYOUT_BYTES) throw new Error("layout inventory bound exceeded");
    }
  };
  visit(root);
  return { files, total };
}

function validateConfig(value: unknown, role: ImageRole): void {
  const config = asObject(value, "config");
  exactKeys(config, ["architecture", "os", "config", "rootfs"], ["created", "author", "history", "variant"], "config");
  if (config.architecture !== "amd64" || config.os !== "linux") throw new Error("config platform mismatch");
  if (config.variant !== undefined) throw new Error("amd64 config variant forbidden");
  if (config.created !== undefined) boundedString(config.created, "config.created", 64);
  if (config.author !== undefined) boundedString(config.author, "config.author", 256);
  const runtime = asObject(config.config, "config.config");
  exactKeys(
    runtime,
    [],
    [
      "User",
      "ExposedPorts",
      "Env",
      "Entrypoint",
      "Cmd",
      "Volumes",
      "WorkingDir",
      "Labels",
      "StopSignal",
      "ArgsEscaped",
      "OnBuild",
      "Shell",
      "Healthcheck",
    ],
    "config.config",
  );
  const labels = asObject(runtime.Labels, "config.config.Labels");
  if (labels["dev.cogs.profile"] !== "stage0-scaffold") throw new Error("scaffold profile label required");
  if (labels["org.opencontainers.image.licenses"] !== "Apache-2.0") throw new Error("license label mismatch");
  boundedString(labels["org.opencontainers.image.source"], "source label", 256);
  const rootfs = asObject(config.rootfs, "config.rootfs");
  exactKeys(rootfs, ["type", "diff_ids"], [], "config.rootfs");
  if (
    rootfs.type !== "layers" ||
    !Array.isArray(rootfs.diff_ids) ||
    rootfs.diff_ids.length < 1 ||
    rootfs.diff_ids.length > 256
  ) {
    throw new Error("invalid rootfs");
  }
  for (const digest of rootfs.diff_ids) assertDigest(digest, "config.rootfs.diff_id");
  if (config.history !== undefined) {
    if (!Array.isArray(config.history) || config.history.length > 1024) throw new Error("invalid history");
    for (const [index, item] of config.history.entries()) {
      const row = asObject(item, `history[${index}]`);
      exactKeys(row, [], ["created", "created_by", "author", "comment", "empty_layer"], `history[${index}]`);
    }
  }
  if (role === "worker" && runtime.User === undefined) throw new Error("worker user must be explicit");
}

export function verifyOciLayout(rootInput: string, role: ImageRole): OciGraph {
  const root = resolve(rootInput);
  const inventory = inventoryLayout(root);
  if (!inventory.files.has("oci-layout") || !inventory.files.has("index.json"))
    throw new Error("layout control files missing");
  const layout = asObject(parseJson(stableFile(resolve(root, "oci-layout"), 1024), "oci-layout"), "oci-layout");
  exactKeys(layout, ["imageLayoutVersion"], [], "oci-layout");
  if (layout.imageLayoutVersion !== "1.0.0") throw new Error("unsupported OCI layout version");

  const indexBytes = stableFile(resolve(root, "index.json"), MAX_JSON_BYTES);
  const indexSha = createHash("sha256").update(indexBytes).digest("hex");
  const index = asObject(parseJson(indexBytes, "index.json"), "index.json");
  exactKeys(index, ["schemaVersion", "manifests"], ["mediaType", "annotations"], "index.json");
  if (index.schemaVersion !== 2 || (index.mediaType !== undefined && index.mediaType !== OCI_INDEX)) {
    throw new Error("invalid OCI index");
  }
  parseAnnotations(index.annotations, "index.annotations");
  if (!Array.isArray(index.manifests) || index.manifests.length !== 1) {
    throw new Error("exactly one image descriptor required; attestations and extra platforms are forbidden");
  }
  const subject = parseDescriptor(index.manifests[0], "index.manifests[0]", true);
  if (subject.mediaType !== OCI_MANIFEST && subject.mediaType !== DOCKER_MANIFEST)
    throw new Error("direct image manifest required");
  if (
    subject.platform?.os !== "linux" ||
    subject.platform.architecture !== "amd64" ||
    subject.platform.variant !== undefined
  ) {
    throw new Error("linux/amd64 subject required");
  }

  const manifest = asObject(parseJson(verifiedBlob(root, subject, MAX_JSON_BYTES), "manifest"), "manifest");
  exactKeys(manifest, ["schemaVersion", "config", "layers"], ["mediaType", "annotations"], "manifest");
  if (manifest.schemaVersion !== 2 || (manifest.mediaType !== undefined && manifest.mediaType !== subject.mediaType)) {
    throw new Error("manifest media type mismatch");
  }
  parseAnnotations(manifest.annotations, "manifest.annotations");
  const configDescriptor = parseDescriptor(manifest.config, "manifest.config", false);
  if (
    !CONFIG_TYPES.has(configDescriptor.mediaType) ||
    configDescriptor.annotations !== undefined ||
    configDescriptor.platform !== undefined
  ) {
    throw new Error("invalid config descriptor");
  }
  validateConfig(parseJson(verifiedBlob(root, configDescriptor, MAX_JSON_BYTES), "config"), role);
  if (!Array.isArray(manifest.layers) || manifest.layers.length < 1 || manifest.layers.length > 256) {
    throw new Error("invalid layer inventory");
  }
  const layers = manifest.layers.map((value, index) => parseDescriptor(value, `manifest.layers[${index}]`, false));
  for (const layer of layers) {
    if (!LAYER_TYPES.has(layer.mediaType) || layer.platform !== undefined) throw new Error("invalid layer descriptor");
    verifiedBlob(root, layer);
  }

  const reachable = [subject.digest, configDescriptor.digest, ...layers.map((layer) => layer.digest)];
  if (new Set(reachable).size !== reachable.length) throw new Error("duplicate reachable blob descriptor");
  const expectedFiles = new Set([
    "oci-layout",
    "index.json",
    ...reachable.map((digest) => `blobs/sha256/${digest.slice(7)}`),
  ]);
  if (inventory.files.size !== expectedFiles.size || [...inventory.files].some((path) => !expectedFiles.has(path))) {
    throw new Error("unreachable or unexpected OCI layout content");
  }
  const totalBlobBytes = reachable.reduce((total, digest) => total + lstatSync(blobPath(root, digest)).size, 0);
  return Object.freeze({
    version: "cogs.local-oci-graph/v1",
    role,
    target: Object.freeze({ os: "linux", architecture: "amd64", variant: null }),
    content_profile: "stage0-scaffold-local-candidate",
    oci_layout_index_sha256: indexSha,
    oci_subject_manifest_digest: subject.digest,
    config_digest: configDescriptor.digest,
    layer_digests: Object.freeze(layers.map((layer) => layer.digest)),
    reachable_blob_digests: Object.freeze(reachable),
    blob_count: reachable.length,
    total_blob_bytes: totalBlobBytes,
  });
}

function graphComparable(graph: OciGraph): JsonValue {
  return {
    version: graph.version,
    role: graph.role,
    target: graph.target,
    content_profile: graph.content_profile,
    oci_layout_index_sha256: graph.oci_layout_index_sha256,
    oci_subject_manifest_digest: graph.oci_subject_manifest_digest,
    config_digest: graph.config_digest,
    layer_digests: [...graph.layer_digests],
    reachable_blob_digests: [...graph.reachable_blob_digests],
    blob_count: graph.blob_count,
    total_blob_bytes: graph.total_blob_bytes,
  } as JsonValue;
}

export function compareOciLayouts(attemptA: string, attemptB: string, role: ImageRole): OciGraphComparison {
  const first = verifyOciLayout(attemptA, role);
  const second = verifyOciLayout(attemptB, role);
  if (canonicalJson(graphComparable(first)) !== canonicalJson(graphComparable(second))) {
    throw new Error(`${role}: two-build OCI graph mismatch`);
  }
  return Object.freeze({
    version: "cogs.local-oci-graph-comparison/v1",
    role,
    attempt_a: first,
    attempt_b: second,
    oci_graph_equal: true,
    layout_index_equal: true,
    docker_image_id: null,
    oci_archive_sha256: null,
    registry_reference: null,
    registry_digest: null,
  });
}

export type PackageClassification = Readonly<{
  authority: "local-static-artifact-package-classifier";
  valid: boolean;
  package_sha256: string | null;
  local_artifacts_complete: boolean;
  content_profile: "stage0-scaffold-local-candidate" | null;
  registry_digest_observed: false;
  image_signature_verified: false;
  stage4_image_runtime_closure_satisfied: false;
  stage5_release_freeze_satisfied: false;
  production_ready: false;
  release_eligible: false;
  reason_code:
    | "VALID_BLOCKED_SCAFFOLD_PACKAGE"
    | "BOUNDED_INPUT_VIOLATION"
    | "NON_CANONICAL_JSON"
    | "SCHEMA_DRIFT"
    | "SEMANTIC_DRIFT"
    | "ARTIFACT_BINDING_FAILURE";
}>;

function failedClassification(
  reason: PackageClassification["reason_code"],
  digest: string | null,
): PackageClassification {
  return Object.freeze({
    authority: "local-static-artifact-package-classifier",
    valid: false,
    package_sha256: digest,
    local_artifacts_complete: false,
    content_profile: null,
    registry_digest_observed: false,
    image_signature_verified: false,
    stage4_image_runtime_closure_satisfied: false,
    stage5_release_freeze_satisfied: false,
    production_ready: false,
    release_eligible: false,
    reason_code: reason,
  });
}

function assertNoSymlinkComponents(root: string, candidate: string): void {
  const rootState = lstatSync(root);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) throw new Error("artifact root must be a real directory");
  const selected = relative(root, candidate);
  if (selected === "" || selected.startsWith(`..${sep}`) || isAbsolute(selected))
    throw new Error("artifact path escape");
  const parts = selected.split(sep);
  let current = root;
  for (const part of parts.slice(0, -1)) {
    current = resolve(current, part);
    const state = lstatSync(current);
    if (!state.isDirectory() || state.isSymbolicLink()) throw new Error("artifact directory symlink forbidden");
  }
}

function parseBoundEvidence(root: string, path: string, expectedSha: string, expectedSize: number): Buffer {
  assertNoSymlinkComponents(root, path);
  const bytes = stableFile(path, MAX_EVIDENCE_BYTES);
  if (bytes.length !== expectedSize || createHash("sha256").update(bytes).digest("hex") !== expectedSha) {
    throw new Error("artifact binding mismatch");
  }
  return bytes;
}

function assertGraphEvidence(bytes: Uint8Array, image: Record<string, unknown>, role: ImageRole) {
  const comparison = asObject(parseJson(bytes, `${role} graph evidence`), `${role} graph evidence`);
  exactKeys(
    comparison,
    [
      "version",
      "role",
      "attempt_a",
      "attempt_b",
      "oci_graph_equal",
      "layout_index_equal",
      "docker_image_id",
      "oci_archive_sha256",
      "registry_reference",
      "registry_digest",
    ],
    [],
    "graph comparison",
  );
  if (
    comparison.version !== "cogs.local-oci-graph-comparison/v1" ||
    comparison.role !== role ||
    comparison.oci_graph_equal !== true ||
    comparison.layout_index_equal !== true
  ) {
    throw new Error("graph comparison semantics mismatch");
  }
  for (const field of ["docker_image_id", "oci_archive_sha256", "registry_reference", "registry_digest"]) {
    if (comparison[field] !== null) throw new Error("digest namespace absence mismatch");
  }
  const first = asObject(comparison.attempt_a, "attempt_a");
  const second = asObject(comparison.attempt_b, "attempt_b");
  for (const [label, attempt] of [
    ["attempt_a", first],
    ["attempt_b", second],
  ] as const) {
    exactKeys(
      attempt,
      [
        "version",
        "role",
        "target",
        "content_profile",
        "oci_layout_index_sha256",
        "oci_subject_manifest_digest",
        "config_digest",
        "layer_digests",
        "reachable_blob_digests",
        "blob_count",
        "total_blob_bytes",
      ],
      [],
      label,
    );
    const target = asObject(attempt.target, `${label}.target`);
    exactKeys(target, ["os", "architecture", "variant"], [], `${label}.target`);
    if (
      attempt.version !== "cogs.local-oci-graph/v1" ||
      attempt.role !== role ||
      attempt.content_profile !== "stage0-scaffold-local-candidate" ||
      target.os !== "linux" ||
      target.architecture !== "amd64" ||
      target.variant !== null ||
      typeof attempt.oci_layout_index_sha256 !== "string" ||
      !SHA256.test(attempt.oci_layout_index_sha256) ||
      typeof attempt.oci_subject_manifest_digest !== "string" ||
      !DIGEST.test(attempt.oci_subject_manifest_digest) ||
      typeof attempt.config_digest !== "string" ||
      !DIGEST.test(attempt.config_digest) ||
      !Array.isArray(attempt.layer_digests) ||
      attempt.layer_digests.length < 1 ||
      attempt.layer_digests.some((digest) => typeof digest !== "string" || !DIGEST.test(digest)) ||
      !Array.isArray(attempt.reachable_blob_digests) ||
      attempt.reachable_blob_digests.some((digest) => typeof digest !== "string" || !DIGEST.test(digest)) ||
      attempt.blob_count !== attempt.reachable_blob_digests.length ||
      !Number.isSafeInteger(attempt.total_blob_bytes) ||
      (attempt.total_blob_bytes as number) < 1
    ) {
      throw new Error("invalid graph attempt semantics");
    }
    const expectedReachable = [attempt.oci_subject_manifest_digest, attempt.config_digest, ...attempt.layer_digests];
    if (canonicalJson(expectedReachable as JsonValue) !== canonicalJson(attempt.reachable_blob_digests as JsonValue)) {
      throw new Error("graph reachability mismatch");
    }
  }
  if (canonicalJson(first as JsonValue) !== canonicalJson(second as JsonValue))
    throw new Error("graph attempts differ");
  const graph = asObject(image.graph, "image.graph");
  if (
    graph.oci_layout_index_sha256 !== first.oci_layout_index_sha256 ||
    graph.oci_subject_manifest_digest !== first.oci_subject_manifest_digest ||
    graph.config_digest !== first.config_digest ||
    canonicalJson(graph.layer_digests as JsonValue) !== canonicalJson(first.layer_digests as JsonValue)
  ) {
    throw new Error("package graph does not bind comparison");
  }
}

function assertSignatureAbsence(bytes: Uint8Array, role: ImageRole) {
  const value = asObject(parseJson(bytes, `${role} signature evidence`), `${role} signature evidence`);
  exactKeys(
    value,
    ["version", "role", "performed", "scope", "reason", "image_signature_claimed", "registry_subject_present"],
    [],
    "signature evidence",
  );
  if (
    value.version !== "cogs.local-image-signature-evidence/v1" ||
    value.role !== role ||
    value.performed !== false ||
    value.scope !== "none" ||
    value.reason !== "authorized-release-key-and-published-registry-subject-unavailable" ||
    value.image_signature_claimed !== false ||
    value.registry_subject_present !== false
  ) {
    throw new Error("invalid signature absence evidence");
  }
}

function assertProvenance(
  bytes: Uint8Array,
  role: ImageRole,
  subjectDigest: unknown,
  expectedSource: Record<string, unknown>,
  expectedBuilder: Record<string, unknown>,
  expectedMaterials: Record<string, unknown>,
  expectedGraphSha256: string,
) {
  const statement = asObject(parseJson(bytes, `${role} provenance`), `${role} provenance`);
  exactKeys(statement, ["_type", "subject", "predicateType", "predicate"], [], "provenance");
  if (
    statement._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== "https://cogs.dev/attestations/local-build-record/v1"
  ) {
    throw new Error("invalid local provenance type");
  }
  if (!Array.isArray(statement.subject) || statement.subject.length !== 1)
    throw new Error("invalid provenance subject");
  const subject = asObject(statement.subject[0], "provenance.subject");
  exactKeys(subject, ["name", "digest"], [], "provenance.subject");
  const digest = asObject(subject.digest, "provenance.subject.digest");
  exactKeys(digest, ["sha256"], [], "provenance.subject.digest");
  if (subject.name !== role || `sha256:${digest.sha256}` !== subjectDigest)
    throw new Error("provenance subject mismatch");
  const predicate = asObject(statement.predicate, "provenance.predicate");
  exactKeys(
    predicate,
    [
      "authority",
      "signed",
      "published",
      "content_profile",
      "source",
      "builder",
      "materials",
      "invocation",
      "graph_comparison_sha256",
    ],
    [],
    "provenance.predicate",
  );
  const invocation = asObject(predicate.invocation, "provenance.invocation");
  exactKeys(
    invocation,
    [
      "platform",
      "attempts",
      "no_cache",
      "pull_by_digest",
      "run_network",
      "buildkit_provenance_embedded",
      "buildkit_sbom_embedded",
    ],
    [],
    "provenance.invocation",
  );
  if (
    predicate.authority !== "unauthenticated-local-build-observation" ||
    predicate.signed !== false ||
    predicate.published !== false ||
    predicate.content_profile !== "stage0-scaffold-local-candidate" ||
    invocation.platform !== "linux/amd64" ||
    invocation.attempts !== 2 ||
    invocation.no_cache !== true ||
    invocation.pull_by_digest !== true ||
    invocation.run_network !== "none" ||
    invocation.buildkit_provenance_embedded !== false ||
    invocation.buildkit_sbom_embedded !== false ||
    typeof predicate.graph_comparison_sha256 !== "string" ||
    !SHA256.test(predicate.graph_comparison_sha256)
  ) {
    throw new Error("provenance authority mismatch");
  }
  if (
    canonicalJson(asObject(predicate.source, "provenance.source") as JsonValue) !==
      canonicalJson(expectedSource as JsonValue) ||
    canonicalJson(asObject(predicate.builder, "provenance.builder") as JsonValue) !==
      canonicalJson(expectedBuilder as JsonValue) ||
    canonicalJson(asObject(predicate.materials, "provenance.materials") as JsonValue) !==
      canonicalJson(expectedMaterials as JsonValue) ||
    predicate.graph_comparison_sha256 !== expectedGraphSha256
  ) {
    throw new Error("provenance source, builder, materials, or graph mismatch");
  }
}

function assertVulnerabilityInventory(bytes: Uint8Array) {
  const report = asObject(parseJson(bytes, "vulnerability report"), "vulnerability report");
  if (!Number.isSafeInteger(report.SchemaVersion) || (report.SchemaVersion as number) < 1) {
    throw new Error("Trivy JSON SchemaVersion required");
  }
  if (!Array.isArray(report.Results)) throw new Error("Trivy JSON Results required");
}

function assertSbom(bytes: Uint8Array) {
  const sbom = asObject(parseJson(bytes, "SBOM"), "SBOM");
  if (sbom.spdxVersion !== "SPDX-2.2" && sbom.spdxVersion !== "SPDX-2.3") throw new Error("SPDX JSON SBOM required");
  if (!Array.isArray(sbom.packages)) throw new Error("SBOM package inventory required");
}

function assertLicenseInventory(bytes: Uint8Array, role: ImageRole) {
  const inventory = asObject(parseJson(bytes, "license inventory"), "license inventory");
  if (
    inventory.version !== "cogs.local-image-license-inventory/v1" ||
    inventory.role !== role ||
    inventory.release_approved !== false
  ) {
    throw new Error("license inventory remains non-approving");
  }
  if (!Array.isArray(inventory.packages)) throw new Error("license packages required");
}

export function classifyLocalImageArtifactPackage(
  packageInput: unknown,
  artifactRootInput: string,
): PackageClassification {
  const captured = capturePrivateBytes(packageInput, MAX_JSON_BYTES);
  if (captured.bytes === null) return failedClassification("BOUNDED_INPUT_VIOLATION", null);
  const packageBytes = captured.bytes;
  const packageDigest = createHash("sha256").update(packageBytes).digest("hex");
  let parsed: unknown;
  try {
    parsed = parseJson(packageBytes, "package");
    if (!Buffer.from(packageBytes).equals(Buffer.from(canonicalLocalImageBytes(parsed as JsonValue)))) {
      return failedClassification("NON_CANONICAL_JSON", packageDigest);
    }
  } catch {
    return failedClassification("NON_CANONICAL_JSON", packageDigest);
  }
  if (!validatePackage(parsed)) return failedClassification("SCHEMA_DRIFT", packageDigest);

  const root = resolve(artifactRootInput);
  try {
    const packageObject = asObject(parsed, "package");
    const artifacts = packageObject.artifacts as Array<Record<string, unknown>>;
    const images = packageObject.images as Array<Record<string, unknown>>;
    const identity = new Set<string>();
    const pathSet = new Set<string>();
    let total = 0;
    const bytesByIdentity = new Map<string, Buffer>();
    for (const artifact of artifacts) {
      const role = artifact.role as ImageRole;
      const kind = boundedString(artifact.kind, "artifact.kind", 64);
      const key = `${role}:${kind}`;
      if (identity.has(key)) throw new Error("duplicate role/kind artifact");
      identity.add(key);
      const relativePath = safeArtifactPath(artifact.path, "artifact.path");
      if (pathSet.has(relativePath)) throw new Error("duplicate artifact path");
      pathSet.add(relativePath);
      const candidate = resolve(root, relativePath);
      if (relative(root, candidate).startsWith(`..${sep}`) || candidate === root)
        throw new Error("artifact root escape");
      const size = boundedInteger(artifact.size_bytes, "artifact.size", MAX_EVIDENCE_BYTES);
      const sha = boundedString(artifact.sha256, "artifact.sha256", 64);
      if (!SHA256.test(sha)) throw new Error("invalid artifact hash");
      const bytes = parseBoundEvidence(root, candidate, sha, size);
      total += bytes.length;
      if (total > MAX_EVIDENCE_TOTAL_BYTES) return failedClassification("BOUNDED_INPUT_VIOLATION", packageDigest);
      bytesByIdentity.set(key, bytes);
    }
    const expectedSource = asObject(packageObject.source, "package.source");
    for (const role of ["worker", "sandbox"] as const) {
      const image = images.find((item) => item.role === role);
      if (image === undefined) throw new Error("missing image role");
      const base = asObject(image.base, "image.base");
      if (
        typeof base.reference !== "string" ||
        typeof base.index_digest !== "string" ||
        !base.reference.endsWith(`@${base.index_digest}`)
      ) {
        throw new Error("base reference/index digest mismatch");
      }
      const evidence = asObject(image.evidence, "image.evidence");
      for (const [field, kind] of [
        ["graph", "oci-graph-comparison"],
        ["sbom", "sbom"],
        ["licenses", "licenses"],
        ["provenance", "local-provenance"],
        ["signature", "signature-absence"],
      ] as const) {
        const reference = asObject(evidence[field], `evidence.${field}`);
        if (reference.kind !== kind) throw new Error("evidence kind mismatch");
        const artifact = artifacts.find((item) => item.role === role && item.kind === kind);
        if (artifact?.path !== reference.path) throw new Error("evidence path mismatch");
      }
      const vulnerability = asObject(evidence.vulnerabilities, "evidence.vulnerabilities");
      const vulnerabilityArtifact = artifacts.find((item) => item.role === role && item.kind === "vulnerabilities");
      if (vulnerabilityArtifact?.path !== vulnerability.path) throw new Error("vulnerability path mismatch");
      assertGraphEvidence(bytesByIdentity.get(`${role}:oci-graph-comparison`) as Buffer, image, role);
      assertSbom(bytesByIdentity.get(`${role}:sbom`) as Buffer);
      assertVulnerabilityInventory(bytesByIdentity.get(`${role}:vulnerabilities`) as Buffer);
      assertLicenseInventory(bytesByIdentity.get(`${role}:licenses`) as Buffer, role);
      const graph = asObject(image.graph, "image.graph");
      const imageBuilder = asObject(image.builder, "image.builder");
      const expectedBuilder = {
        buildx_version: imageBuilder.buildx_version as JsonValue,
        buildkit_version: imageBuilder.buildkit_version as JsonValue,
      };
      const expectedMaterials = {
        dockerfile: image.dockerfile as JsonValue,
        base: image.base as JsonValue,
      };
      const graphArtifact = artifacts.find((item) => item.role === role && item.kind === "oci-graph-comparison");
      if (typeof graphArtifact?.sha256 !== "string") throw new Error("graph artifact digest missing");
      assertProvenance(
        bytesByIdentity.get(`${role}:local-provenance`) as Buffer,
        role,
        graph.oci_subject_manifest_digest,
        expectedSource,
        expectedBuilder,
        expectedMaterials,
        graphArtifact.sha256,
      );
      assertSignatureAbsence(bytesByIdentity.get(`${role}:signature-absence`) as Buffer, role);
    }
  } catch {
    return failedClassification("ARTIFACT_BINDING_FAILURE", packageDigest);
  }

  return Object.freeze({
    authority: "local-static-artifact-package-classifier",
    valid: true,
    package_sha256: packageDigest,
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
}

export function signatureAbsenceEvidence(role: ImageRole): JsonObject {
  return {
    version: "cogs.local-image-signature-evidence/v1",
    role,
    performed: false,
    scope: "none",
    reason: "authorized-release-key-and-published-registry-subject-unavailable",
    image_signature_claimed: false,
    registry_subject_present: false,
  };
}

export function localProvenanceStatement(
  role: ImageRole,
  subjectDigest: string,
  source: { commit_sha: string; tree_sha: string; inventory_sha256: string; source_date_epoch: number },
  graphComparisonSha256: string,
  builder: { buildx_version: string; buildkit_version: string },
  materials: {
    dockerfile: { path: string; sha256: string };
    base: { reference: string; index_digest: string; linux_amd64_manifest_digest: string };
  },
): JsonObject {
  const digest = assertDigest(subjectDigest, "provenance subject").slice(7);
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: role, digest: { sha256: digest } }],
    predicateType: "https://cogs.dev/attestations/local-build-record/v1",
    predicate: {
      authority: "unauthenticated-local-build-observation",
      signed: false,
      published: false,
      content_profile: "stage0-scaffold-local-candidate",
      source,
      builder,
      materials,
      invocation: {
        platform: "linux/amd64",
        attempts: 2,
        no_cache: true,
        pull_by_digest: true,
        run_network: "none",
        buildkit_provenance_embedded: false,
        buildkit_sbom_embedded: false,
      },
      graph_comparison_sha256: graphComparisonSha256,
    },
  };
}

export function imageLicenseInventory(role: ImageRole, sbomInput: Uint8Array): JsonObject {
  if (sbomInput.byteLength < 1 || sbomInput.byteLength > MAX_EVIDENCE_BYTES) throw new Error("SBOM bound exceeded");
  const sbom = asObject(parseJson(sbomInput, "SBOM"), "SBOM");
  if (!Array.isArray(sbom.packages) || sbom.packages.length > 100000) throw new Error("invalid SBOM packages");
  const packages = sbom.packages.map((value, index) => {
    const item = asObject(value, `packages[${index}]`);
    const name = boundedString(item.name, `packages[${index}].name`, 512);
    const version =
      item.versionInfo === undefined ? null : boundedString(item.versionInfo, `packages[${index}].versionInfo`, 512);
    const concluded =
      item.licenseConcluded === undefined
        ? "NOASSERTION"
        : boundedString(item.licenseConcluded, "licenseConcluded", 4096);
    const declared =
      item.licenseDeclared === undefined ? "NOASSERTION" : boundedString(item.licenseDeclared, "licenseDeclared", 4096);
    const state =
      concluded === "NOASSERTION" || declared === "NOASSERTION"
        ? "unknown-review-required"
        : "declared-not-legally-approved";
    return { name, version, license_concluded: concluded, license_declared: declared, state };
  });
  packages.sort((left, right) =>
    compareCodePoints(`${left.name}\0${left.version ?? ""}`, `${right.name}\0${right.version ?? ""}`),
  );
  return {
    version: "cogs.local-image-license-inventory/v1",
    role,
    source: "exact-spdx-json-sbom",
    packages,
    package_count: packages.length,
    unknown_count: packages.filter((item) => item.state === "unknown-review-required").length,
    legal_review_performed: false,
    release_approved: false,
  };
}

export const LOCAL_IMAGE_LIMITS = Object.freeze({
  max_json_bytes: MAX_JSON_BYTES,
  max_layout_files: MAX_LAYOUT_FILES,
  max_layout_bytes: MAX_LAYOUT_BYTES,
  max_blob_bytes: MAX_BLOB_BYTES,
  max_evidence_bytes: MAX_EVIDENCE_BYTES,
  max_evidence_total_bytes: MAX_EVIDENCE_TOTAL_BYTES,
});
