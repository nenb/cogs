import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder, types as utilTypes } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes, intrinsicByteLength } from "./private-bytes.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const contractSchema = require("../schemas/stage4-storage-launch-contract-v1.json") as object;
const validateSchema = new Ajv2020({ allErrors: true, strict: true, strictRequired: false }).compile(
  contractSchema,
) as ValidateFunction<Stage4StorageLaunchGraph>;

export const STAGE4_STORAGE_LAUNCH_LIMITS = Object.freeze({
  maxContractBytes: 131072,
  maxSnapshotNodes: 512,
  maxDepth: 16,
  maxStringBytes: 2048,
  maxPropertyKeyBytes: 256,
  maxPropertiesPerObject: 64,
  maxAggregateCanonicalBytes: 131072,
  maxResourcesPerRole: 1,
});

export const STAGE4_STORAGE_ROLES = deepFreeze({
  workspace: {
    role: "untrusted-project-workspace",
    size_bytes: 20 * 1024 * 1024 * 1024,
    access_mode: "ReadWriteOncePod",
    volume_mode: "Filesystem",
    volume_binding_mode: "WaitForFirstConsumer",
    reclaim_policy: "Retain",
    medium: "csi-block",
    mount_owner: "kata-sandbox-only",
    retention: "retain-until-explicit-workspace-deletion",
    reclaim_on_session_end: false,
  },
  trustedSessionState: {
    role: "trusted-pi-session-state",
    size_bytes: 5 * 1024 * 1024 * 1024,
    access_mode: "ReadWriteOncePod",
    volume_mode: "Filesystem",
    volume_binding_mode: "WaitForFirstConsumer",
    reclaim_policy: "Retain",
    mount_owner: "trusted-worker-only",
    retention: "retain-30-days-after-session-close",
    retention_seconds: 30 * 24 * 60 * 60,
    sandbox_visible: false,
  },
} as const);

export const STAGE4_STORAGE_LAUNCH_REASON_CODES = Object.freeze([
  "STAGE4_STORAGE_LAUNCH_GRAPH_VALID",
  "STAGE4_STORAGE_LAUNCH_CLEANUP_IN_PROGRESS",
  "STAGE4_STORAGE_LAUNCH_CLEANUP_ORDER_COMPLETE",
  "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE",
  "STAGE4_STORAGE_LAUNCH_INVALID_VERSION",
  "STAGE4_STORAGE_ROLE_DRIFT",
  "STAGE4_STORAGE_MODE_INVALID",
  "STAGE4_WORKSPACE_CONCURRENT_WRITER",
  "STAGE4_WORKSPACE_LEASE_INVALID",
  "STAGE4_RUNTIMECLASS_MISSING_OR_WRONG",
  "STAGE4_SSH_HOST_KEY_MISMATCH",
  "STAGE4_LAUNCH_DOCUMENT_STALE",
  "STAGE4_LAUNCH_DOCUMENT_REPLAY",
  "STAGE4_LAUNCH_DOCUMENT_DIGEST_MISMATCH",
  "STAGE4_LAUNCH_BINDING_INVALID",
  "STAGE4_RESOURCE_CARDINALITY_INVALID",
  "STAGE4_EPHEMERAL_IDENTITY_PERSISTENCE_FORBIDDEN",
  "STAGE4_CLEANUP_AMBIGUOUS",
  "STAGE4_BOUNDED_IO_VIOLATION",
] as const);

export type Stage4StorageLaunchReasonCode = (typeof STAGE4_STORAGE_LAUNCH_REASON_CODES)[number];
export type Stage4StorageLaunchStatus =
  | "admissible-static-graph"
  | "cleanup-in-progress"
  | "cleanup-order-complete"
  | "preserve-uncertain"
  | "reject";

export type Stage4StorageLaunchVerdict = Readonly<{
  version: "cogs.stage4-storage-launch-verdict/v1";
  authority: "local-static-storage-launch-classifier";
  qualified: false;
  campaign_authorized: false;
  cloud_execution_observed: false;
  kubernetes_execution_observed: false;
  provider_truth_observed: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  graph_sha256: string | null;
  status: Stage4StorageLaunchStatus;
  reason_code: Stage4StorageLaunchReasonCode;
  preservation: Readonly<{
    state: "preserve";
    resources: "preserve";
    attachments: "preserve";
    workspace_lease: "preserve";
  }> | null;
}>;

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };
type Stage4StorageLaunchGraph = JsonRecord & {
  version: string;
  storage: JsonRecord & { workspace: JsonRecord; trusted_session_state: JsonRecord };
  workspace_lease: JsonRecord;
  launch_document: JsonRecord & { metadata: JsonRecord; ssh_host_key: JsonRecord };
  runtime_class: JsonRecord;
  resources: JsonRecord & { trusted_worker_proxy: JsonRecord[]; kata_sandbox: JsonRecord[] };
  lifecycle: JsonRecord;
  bounded_io: JsonRecord;
};

type Snapshot = Readonly<{ value: JsonRecord | null; bounded: boolean }>;
const PRESERVATION = deepFreeze({
  state: "preserve",
  resources: "preserve",
  attachments: "preserve",
  workspace_lease: "preserve",
} as const);
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const GRAPH_DOMAIN = "cogs.stage4/storage-launch-semantic-graph/v1";
const LAUNCH_DOCUMENT_DOMAIN = "cogs.stage4/immutable-session-launch-document/v1";

function verdict(
  status: Stage4StorageLaunchStatus,
  reasonCode: Stage4StorageLaunchReasonCode,
  digest: string | null,
): Stage4StorageLaunchVerdict {
  return Object.freeze({
    version: "cogs.stage4-storage-launch-verdict/v1",
    authority: "local-static-storage-launch-classifier",
    qualified: false,
    campaign_authorized: false,
    cloud_execution_observed: false,
    kubernetes_execution_observed: false,
    provider_truth_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    graph_sha256: digest,
    status,
    reason_code: reasonCode,
    preservation: status === "preserve-uncertain" ? PRESERVATION : null,
  });
}

function snapshotJson(input: unknown): Snapshot {
  let nodes = 0;
  let aggregateBytes = 1; // Canonical trailing LF.
  let bounded = false;
  const consume = (bytes: number): void => {
    aggregateBytes += bytes;
    if (aggregateBytes > STAGE4_STORAGE_LAUNCH_LIMITS.maxAggregateCanonicalBytes) {
      bounded = true;
      throw new TypeError("aggregate canonical byte bound");
    }
  };
  const visit = (candidate: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > STAGE4_STORAGE_LAUNCH_LIMITS.maxSnapshotNodes || depth > STAGE4_STORAGE_LAUNCH_LIMITS.maxDepth) {
      bounded = true;
      throw new TypeError("object graph bound");
    }
    const candidateType = typeof candidate;
    if (
      ((candidateType === "object" && candidate !== null) || candidateType === "function") &&
      utilTypes.isProxy(candidate)
    ) {
      throw new TypeError("proxy object");
    }
    if (candidate === null) {
      consume(4);
      return candidate;
    }
    if (typeof candidate === "boolean") {
      consume(candidate ? 4 : 5);
      return candidate;
    }
    if (typeof candidate === "string") {
      if (Buffer.byteLength(candidate, "utf8") > STAGE4_STORAGE_LAUNCH_LIMITS.maxStringBytes) {
        bounded = true;
        throw new TypeError("string bound");
      }
      consume(Buffer.byteLength(JSON.stringify(candidate), "utf8"));
      return candidate;
    }
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) throw new TypeError("number shape");
      consume(Buffer.byteLength(JSON.stringify(candidate), "utf8"));
      return candidate;
    }
    if (typeof candidate !== "object" || candidate === null) throw new TypeError("non-JSON value");

    const prototype = Object.getPrototypeOf(candidate);
    if (Array.isArray(candidate)) {
      if (prototype !== Array.prototype) throw new TypeError("array prototype");
      const keys = Reflect.ownKeys(candidate);
      if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
      if (
        (keys as string[]).some(
          (key) => Buffer.byteLength(key, "utf8") > STAGE4_STORAGE_LAUNCH_LIMITS.maxPropertyKeyBytes,
        )
      ) {
        bounded = true;
        throw new TypeError("array property key bound");
      }
      if (keys.length > STAGE4_STORAGE_LAUNCH_LIMITS.maxPropertiesPerObject + 1) {
        bounded = true;
        throw new TypeError("array property bound");
      }
      const descriptors = Object.getOwnPropertyDescriptors(candidate) as Record<string, PropertyDescriptor | undefined>;
      const lengthDescriptor = descriptors.length;
      if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) throw new TypeError("array length");
      const rawLength = lengthDescriptor.value;
      if (
        typeof rawLength !== "number" ||
        !Number.isSafeInteger(rawLength) ||
        rawLength < 0 ||
        rawLength > STAGE4_STORAGE_LAUNCH_LIMITS.maxSnapshotNodes
      ) {
        bounded = true;
        throw new TypeError("array bound");
      }
      const length = rawLength;
      const expected = [...Array.from({ length }, (_, index) => String(index)), "length"];
      if (keys.length !== expected.length || expected.some((key) => !keys.includes(key))) {
        throw new TypeError("sparse or extended array");
      }
      consume(2 + Math.max(0, length - 1));
      return Array.from({ length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
          throw new TypeError("array accessor");
        }
        return visit(descriptor.value, depth + 1);
      });
    }

    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("object prototype");
    const keys = Reflect.ownKeys(candidate);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
    if (keys.length > STAGE4_STORAGE_LAUNCH_LIMITS.maxPropertiesPerObject) {
      bounded = true;
      throw new TypeError("object property bound");
    }
    for (const key of keys as string[]) {
      if (Buffer.byteLength(key, "utf8") > STAGE4_STORAGE_LAUNCH_LIMITS.maxPropertyKeyBytes) {
        bounded = true;
        throw new TypeError("property key bound");
      }
    }
    consume(2 + Math.max(0, keys.length - 1));
    for (const key of keys as string[]) consume(Buffer.byteLength(JSON.stringify(key), "utf8") + 1);

    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const output: JsonRecord = Object.create(null) as JsonRecord;
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
        throw new TypeError("object accessor");
      }
      output[key] = visit(descriptor.value, depth + 1);
    }
    return output;
  };

  try {
    const value = visit(input, 0);
    return { value: isRecord(value) ? value : null, bounded: false };
  } catch {
    return { value: null, bounded };
  }
}

function isRecord(value: JsonValue): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function claimedCleanupUncertainty(root: JsonRecord): boolean {
  const lifecycle = root.lifecycle;
  if (lifecycle === undefined || !isRecord(lifecycle)) return false;
  return (
    lifecycle.state === "uncertain" ||
    lifecycle.trusted_worker_proxy === "uncertain" ||
    lifecycle.kata_sandbox === "uncertain" ||
    lifecycle.workspace_attachment === "uncertain" ||
    lifecycle.session_state_attachment === "uncertain" ||
    lifecycle.lease === "uncertain" ||
    typeof lifecycle.uncertainty_artifact_sha256 === "string"
  );
}

function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const b = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function semanticDigest(domain: string, value: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function graphDigest(value: JsonRecord): string {
  return semanticDigest(GRAPH_DOMAIN, value);
}

function launchDocumentDigest(metadata: JsonRecord): string {
  return semanticDigest(LAUNCH_DOCUMENT_DOMAIN, metadata);
}

function same(left: JsonValue | undefined, right: JsonValue): boolean {
  return left !== undefined && canonicalJson(left) === canonicalJson(right);
}

function resourceBindingValid(graph: Stage4StorageLaunchGraph): boolean {
  const trusted = graph.resources.trusted_worker_proxy[0];
  const sandbox = graph.resources.kata_sandbox[0];
  const metadata = graph.launch_document.metadata;
  const digest = graph.launch_document.document_sha256;
  return (
    trusted !== undefined &&
    sandbox !== undefined &&
    trusted.launch_document_sha256 === digest &&
    sandbox.launch_document_sha256 === digest &&
    trusted.session_id === metadata.session_id &&
    sandbox.session_id === metadata.session_id &&
    trusted.workspace_id === metadata.workspace_id &&
    sandbox.workspace_id === metadata.workspace_id &&
    graph.workspace_lease.workspace_id === metadata.workspace_id &&
    trusted.resource_id === metadata.trusted_worker_proxy_resource_id &&
    sandbox.resource_id === metadata.kata_sandbox_resource_id &&
    graph.runtime_class.required_name === metadata.runtime_class_name
  );
}

function lifecycleShape(graph: Stage4StorageLaunchGraph, digest: string): Stage4StorageLaunchVerdict | null {
  const state = graph.lifecycle.state;
  const uncertaintyFields = [
    graph.lifecycle.trusted_worker_proxy,
    graph.lifecycle.kata_sandbox,
    graph.lifecycle.workspace_attachment,
    graph.lifecycle.session_state_attachment,
    graph.lifecycle.lease,
  ];
  if (state === "uncertain" || uncertaintyFields.includes("uncertain")) {
    return verdict("preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS", digest);
  }
  if (graph.lifecycle.uncertainty_artifact_sha256 !== null) {
    return verdict("preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS", digest);
  }

  const expected =
    state === "active"
      ? ["present", "present", "attached", "attached", "held"]
      : state === "cleanup-requested"
        ? ["removal-requested", "removal-requested", "detach-requested", "detach-requested", "release-requested"]
        : state === "complete"
          ? ["removed", "removed", "detached", "detached", "released"]
          : null;
  if (expected === null || !uncertaintyFields.every((value, index) => value === expected[index])) {
    return verdict("preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS", digest);
  }
  return null;
}

/**
 * Classifies one already-decoded local/static object graph. It performs no I/O,
 * process launch, environment lookup, Kubernetes/provider operation, or truth discovery.
 */
export function evaluateStage4StorageLaunchGraph(input: unknown): Stage4StorageLaunchVerdict {
  const snapshot = snapshotJson(input);
  if (snapshot.value === null) {
    return snapshot.bounded
      ? verdict("preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION", null)
      : verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", null);
  }
  const digest = graphDigest(snapshot.value);
  // A safely snapshotted explicit cleanup-uncertainty marker is sticky even if
  // another admission field later fails strict schema validation.
  if (claimedCleanupUncertainty(snapshot.value)) {
    return verdict("preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS", digest);
  }
  if (snapshot.value.version !== "cogs.stage4-storage-launch-contract/v1") {
    return verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_VERSION", digest);
  }
  if (!validateSchema(snapshot.value)) return verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", digest);
  const graph = snapshot.value;

  // Cleanup uncertainty is sticky and dominates every otherwise validly shaped
  // admission error. No failed admission check may authorize mutation or cleanup.
  const lifecycleFailure = lifecycleShape(graph, digest);
  if (lifecycleFailure !== null) return lifecycleFailure;

  if (launchDocumentDigest(graph.launch_document.metadata) !== graph.launch_document.document_sha256) {
    return verdict("reject", "STAGE4_LAUNCH_DOCUMENT_DIGEST_MISMATCH", digest);
  }

  if (
    !same(graph.storage.workspace, STAGE4_STORAGE_ROLES.workspace as unknown as JsonValue) ||
    !same(graph.storage.trusted_session_state, STAGE4_STORAGE_ROLES.trustedSessionState as unknown as JsonValue)
  ) {
    const workspace = graph.storage.workspace;
    const session = graph.storage.trusted_session_state;
    const wrongMode =
      workspace.access_mode !== "ReadWriteOncePod" ||
      workspace.volume_mode !== "Filesystem" ||
      workspace.volume_binding_mode !== "WaitForFirstConsumer" ||
      workspace.reclaim_policy !== "Retain" ||
      workspace.medium !== "csi-block" ||
      session.access_mode !== "ReadWriteOncePod" ||
      session.volume_mode !== "Filesystem" ||
      session.volume_binding_mode !== "WaitForFirstConsumer" ||
      session.reclaim_policy !== "Retain";
    return verdict("reject", wrongMode ? "STAGE4_STORAGE_MODE_INVALID" : "STAGE4_STORAGE_ROLE_DRIFT", digest);
  }

  const lease = graph.workspace_lease;
  if (typeof lease.writer_count === "number" && lease.writer_count > 1) {
    return verdict("preserve-uncertain", "STAGE4_WORKSPACE_CONCURRENT_WRITER", digest);
  }
  if (graph.launch_document.state === "stale") {
    return verdict("reject", "STAGE4_LAUNCH_DOCUMENT_STALE", digest);
  }
  if (graph.launch_document.state === "replayed" || graph.launch_document.admission_count !== 1) {
    return verdict("reject", "STAGE4_LAUNCH_DOCUMENT_REPLAY", digest);
  }
  if (graph.launch_document.ssh_host_key.verification !== "match") {
    return verdict("reject", "STAGE4_SSH_HOST_KEY_MISMATCH", digest);
  }
  if (
    graph.runtime_class.resolution !== "present-static-assertion" ||
    graph.runtime_class.resolved_name !== "kata-qemu-cogs"
  ) {
    return verdict("reject", "STAGE4_RUNTIMECLASS_MISSING_OR_WRONG", digest);
  }
  if (
    graph.resources.trusted_worker_proxy.length !== STAGE4_STORAGE_LAUNCH_LIMITS.maxResourcesPerRole ||
    graph.resources.kata_sandbox.length !== STAGE4_STORAGE_LAUNCH_LIMITS.maxResourcesPerRole
  ) {
    return verdict("reject", "STAGE4_RESOURCE_CARDINALITY_INVALID", digest);
  }
  if (!resourceBindingValid(graph)) return verdict("reject", "STAGE4_LAUNCH_BINDING_INVALID", digest);

  const trusted = graph.resources.trusted_worker_proxy[0];
  const sandbox = graph.resources.kata_sandbox[0];
  if (trusted === undefined || sandbox === undefined) {
    return verdict("reject", "STAGE4_RESOURCE_CARDINALITY_INVALID", digest);
  }
  if (
    trusted.ephemeral_identity_persistence !== "none" ||
    graph.launch_document.durable_identity_material !== false ||
    graph.launch_document.sandbox_secret_store_handles !== false ||
    sandbox.secret_store_handles !== false
  ) {
    return verdict("reject", "STAGE4_EPHEMERAL_IDENTITY_PERSISTENCE_FORBIDDEN", digest);
  }
  if (
    trusted.workspace_mounted !== false ||
    trusted.session_state_mounted !== true ||
    sandbox.workspace_mounted !== true ||
    sandbox.session_state_mounted !== false ||
    sandbox.trusted_sidecars !== false ||
    sandbox.runtime_class_name !== "kata-qemu-cogs"
  ) {
    return verdict("reject", "STAGE4_LAUNCH_BINDING_INVALID", digest);
  }

  const lifecycleState = graph.lifecycle.state;
  const expectedLease =
    lifecycleState === "active"
      ? { state: "held", writers: 1, holder: graph.launch_document.document_sha256 }
      : lifecycleState === "cleanup-requested"
        ? { state: "release-requested", writers: 1, holder: graph.launch_document.document_sha256 }
        : { state: "released", writers: 0, holder: null };
  if (
    lease.state !== expectedLease.state ||
    lease.writer_count !== expectedLease.writers ||
    lease.holder_launch_document_sha256 !== expectedLease.holder
  ) {
    return verdict("preserve-uncertain", "STAGE4_WORKSPACE_LEASE_INVALID", digest);
  }

  if (lifecycleState === "cleanup-requested") {
    return verdict("cleanup-in-progress", "STAGE4_STORAGE_LAUNCH_CLEANUP_IN_PROGRESS", digest);
  }
  if (lifecycleState === "complete") {
    return verdict("cleanup-order-complete", "STAGE4_STORAGE_LAUNCH_CLEANUP_ORDER_COMPLETE", digest);
  }
  return verdict("admissible-static-graph", "STAGE4_STORAGE_LAUNCH_GRAPH_VALID", digest);
}

/** Validates bounded canonical JSON bytes without reading any path or contacting any dependency. */
export function validateStage4StorageLaunchBytes(input: Uint8Array): Stage4StorageLaunchVerdict {
  const captured = capturePrivateBytes(input, STAGE4_STORAGE_LAUNCH_LIMITS.maxContractBytes);
  if (captured.bytes === null) {
    return captured.bounded
      ? verdict("preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION", null)
      : verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", null);
  }
  const bytes = captured.bytes;
  if (intrinsicByteLength(bytes) >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", null);
  }
  try {
    const text = decoder.decode(bytes);
    const parsed = JSON.parse(text) as unknown;
    const snapshot = snapshotJson(parsed);
    if (snapshot.value === null) {
      return snapshot.bounded
        ? verdict("preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION", null)
        : verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", null);
    }
    const canonical = `${canonicalJson(snapshot.value)}\n`;
    if (text !== canonical)
      return verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", graphDigest(snapshot.value));
    return evaluateStage4StorageLaunchGraph(snapshot.value);
  } catch {
    return verdict("reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE", null);
  }
}

export function canonicalStage4StorageLaunchBytes(input: unknown): Uint8Array {
  const snapshot = snapshotJson(input);
  if (snapshot.value === null) {
    throw new TypeError(
      snapshot.bounded ? "input exceeds an object or byte bound" : "input is not a plain JSON object",
    );
  }
  const encoded = new TextEncoder().encode(`${canonicalJson(snapshot.value)}\n`);
  if (intrinsicByteLength(encoded) > STAGE4_STORAGE_LAUNCH_LIMITS.maxContractBytes) {
    throw new TypeError("canonical contract exceeds the byte bound");
  }
  return encoded;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
