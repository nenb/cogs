import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder, types } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes, intrinsicByteLength } from "./private-bytes.ts";
import {
  classifyReleaseImageSetReview,
  RELEASE_IMAGE_REFERENCES,
  RELEASE_IMAGE_SET_ASSERTION_SHA256,
  RELEASE_IMAGE_SET_REVIEW_SHA256,
  RELEASE_IMAGE_SOURCE_INVENTORY_SHA256,
  RELEASE_IMAGE_SOURCE_SHA,
  RELEASE_IMAGE_SOURCE_TREE_SHA,
  RELEASE_IMAGE_WORKFLOW_RUN_ID,
} from "./release-image-set-review-v2.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const packageSchema = require("../schemas/stage4-offline-readiness-package-v5.json") as object;

export const STAGE4_READINESS_BLOCKERS = Object.freeze([
  "ISSUE_42_OPEN",
  "OPENBAO_FIXED_RELEASE_IMAGE_ABSENT",
  "EKS_AMI_IMAGE_RELEASE_KERNEL_UNRESOLVED",
  "PROPOSED_ACCOUNT_BINDING_ABSENT",
  "CURRENT_PRICE_NOT_REVALIDATED",
  "CURRENT_QUOTA_NOT_REVALIDATED",
  "SEPARATED_CAMPAIGN_IDENTITIES_ABSENT",
  "CAMPAIGN_ENVELOPE_AND_APPROVAL_ABSENT",
  "NO_EXECUTABLE_PROVIDER_ROUTE",
] as const);

export const STAGE4_READINESS_ARTIFACT_KEYS = Object.freeze([
  "sourceInventory",
  "chartInventory",
  "values",
  "render",
  "repeatedRender",
  "renderReceipt",
  "imageLock",
  "releaseImageAssertion",
  "releaseImageReview",
  "nicContract",
  "runtimePins",
  "authenticatedRuntimeArtifacts",
  "schemaInventory",
  "localValidation",
] as const);

export const STAGE4_READINESS_BYTE_LIMITS = Object.freeze({
  package: 256 * 1024,
  sourceInventory: 256 * 1024,
  chartInventory: 64 * 1024,
  values: 64 * 1024,
  render: 256 * 1024,
  repeatedRender: 256 * 1024,
  renderReceipt: 16 * 1024,
  imageLock: 16 * 1024,
  releaseImageAssertion: 64 * 1024,
  releaseImageReview: 16 * 1024,
  nicContract: 128 * 1024,
  runtimePins: 16 * 1024,
  authenticatedRuntimeArtifacts: 64 * 1024,
  schemaInventory: 256 * 1024,
  localValidation: 128 * 1024,
  aggregateArtifacts: 1024 * 1024,
});

export type Stage4ReadinessArtifactKey = (typeof STAGE4_READINESS_ARTIFACT_KEYS)[number];
export type Stage4ReadinessReasonCode =
  | "STAGE4_LOCAL_PREPARATION_COMPLETE_CAMPAIGN_BLOCKED"
  | "STAGE4_READINESS_BOUNDED_IO_VIOLATION"
  | "STAGE4_READINESS_INVALID_CANONICAL_PACKAGE"
  | "STAGE4_READINESS_SCHEMA_OR_SEMANTIC_DRIFT"
  | "STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH"
  | "STAGE4_READINESS_RENDER_NONDETERMINISTIC"
  | "STAGE4_READINESS_BINDING_ROOT_MISMATCH";

export type Stage4OfflineReadinessVerdict = Readonly<{
  version: "cogs.stage4-offline-readiness-verdict/v5";
  authority: "local-static-stage4-readiness-classifier";
  local_preparation_complete: boolean;
  candidate_artifact_closure_complete: boolean;
  selected_runtime_artifacts_authenticated: boolean;
  local_preparation_scope: "bounded-package-assembly-and-local-validation-only";
  trusted_render_preparation_complete: boolean;
  exact_image_runtime_closure_satisfied: false;
  campaign_request_ready: false;
  campaign_approved: false;
  cloud_authorized: false;
  cloud_execution_observed: false;
  provider_truth_observed: false;
  current_resources_observed: false;
  zero_resources_claimed: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  package_sha256: string | null;
  binding_root_sha256: string | null;
  status: "local-preparation-complete-blocked" | "preserve-uncertain";
  reason_code: Stage4ReadinessReasonCode;
  blockers: readonly (typeof STAGE4_READINESS_BLOCKERS)[number][];
}>;

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };
type ReadinessPackage = JsonRecord & {
  artifact_bindings: JsonRecord & {
    binding_root_sha256: string;
    render_sha256: string;
    repeated_render_sha256: string;
  };
  pins: JsonRecord & { images: JsonRecord };
  campaign_proposal: JsonRecord;
  stop_destroy: JsonRecord;
};

type ArtifactCopies = Record<Stage4ReadinessArtifactKey, Uint8Array>;

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validatePackageSchema = ajv.compile(packageSchema) as ValidateFunction<ReadinessPackage>;

const DIGEST_FIELDS: Readonly<Record<Stage4ReadinessArtifactKey, string>> = Object.freeze({
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
});

export const STAGE4_PROPOSED_RESOURCE_GRAPH = Object.freeze([
  ["eks-cluster", 1, "regional-control-plane", null],
  ["eks-managed-addon", 0, "none", null],
  ["vpc", 1, "dedicated-ipv4-only", null],
  ["subnet", 2, "public-no-inbound", null],
  ["route-table", 2, "campaign-dedicated", null],
  ["route", 4, "two-local-two-internet-gateway", null],
  ["internet-gateway", 1, "campaign-dedicated", null],
  ["network-acl", 1, "vpc-default-closed-review", null],
  ["dhcp-options-association", 1, "vpc-default-closed-review", null],
  ["nat-gateway", 0, "prohibited", null],
  ["vpc-endpoint", 0, "prohibited", null],
  ["elastic-ip", 0, "prohibited", null],
  ["load-balancer", 0, "prohibited", null],
  ["target-group", 0, "prohibited", null],
  ["security-group", 5, "default-cluster-shared-trusted-sandbox", null],
  ["iam-role", 4, "cluster-trusted-node-sandbox-node-ttl-function", null],
  ["iam-customer-managed-policy", 4, "one-per-campaign-role", null],
  ["iam-policy-attachment", 8, "bounded-role-attachments", null],
  ["instance-profile", 2, "trusted-node-and-sandbox-node", null],
  ["launch-template", 2, "trusted-and-sandbox-explicit-version", null],
  ["managed-node-group", 2, "trusted-and-sandbox", null],
  ["autoscaling-group", 2, "managed-node-group-owned", null],
  ["trusted-node", 1, "c8i-flex.large-on-demand", 30],
  ["sandbox-node", 1, "c8i-flex.large-on-demand-nested-kvm", 30],
  ["network-interface", 10, "hard-maximum-provider-managed-and-node", null],
  ["ebs-trusted-root-volume", 1, "encrypted-gp3-delete-on-termination", 30],
  ["ebs-sandbox-root-volume", 1, "encrypted-gp3-delete-on-termination", 30],
  ["ebs-workspace-volume", 1, "encrypted-gp3-retain", 20],
  ["ebs-session-state-volume", 1, "encrypted-gp3-retain", 5],
  ["ebs-snapshot", 0, "prohibited", null],
  ["kms-key", 1, "symmetric-campaign-storage", null],
  ["kms-alias", 1, "campaign-key-alias", null],
  ["log-group", 2, "eks-control-and-ttl-function-30-day", null],
  ["budget", 1, "usd-20-proposal", null],
  ["budget-notification", 3, "usd-5-10-20-proposal", null],
  ["ttl-schedule", 1, "absolute-14400-seconds", null],
  ["ttl-function", 1, "terminator-128-mib", null],
  ["ttl-function-permission", 1, "scheduler-invoke-only", null],
] as const);

export const STAGE4_INDEPENDENT_INVENTORY_SCOPES = Object.freeze([
  ["eks-cluster", "eks", "clusters-account-region-service-wide"],
  ["eks-managed-addon", "eks", "addons-for-every-cluster-account-region-service-wide"],
  ["vpc", "ec2", "vpcs-account-region-service-wide"],
  ["subnet", "ec2", "subnets-account-region-service-wide"],
  ["route-table", "ec2", "route-tables-account-region-service-wide"],
  ["route", "ec2", "routes-for-every-route-table-account-region-service-wide"],
  ["internet-gateway", "ec2", "internet-gateways-account-region-service-wide-all-attachment-states"],
  ["network-acl", "ec2", "network-acls-account-region-service-wide"],
  ["dhcp-options-association", "ec2", "dhcp-options-account-region-service-wide"],
  ["nat-gateway", "ec2", "nat-gateways-account-region-service-wide-all-lifecycle-states"],
  ["vpc-endpoint", "ec2", "vpc-endpoints-account-region-service-wide"],
  ["elastic-ip", "ec2", "addresses-account-region-service-wide"],
  ["load-balancer", "elasticloadbalancing", "load-balancers-account-region-service-wide"],
  ["target-group", "elasticloadbalancing", "target-groups-account-region-service-wide"],
  ["security-group", "ec2", "security-groups-account-region-service-wide"],
  ["iam-role", "iam", "roles-account-service-wide"],
  ["iam-customer-managed-policy", "iam", "customer-managed-policies-account-service-wide"],
  ["iam-policy-attachment", "iam", "role-and-policy-attachments-account-service-wide"],
  ["instance-profile", "iam", "instance-profiles-account-service-wide"],
  ["launch-template", "ec2", "launch-templates-and-all-versions-account-region-service-wide"],
  ["managed-node-group", "eks", "nodegroups-for-every-cluster-account-region-service-wide"],
  ["autoscaling-group", "autoscaling", "groups-account-region-service-wide"],
  ["trusted-node", "ec2", "instances-account-region-service-wide-all-states"],
  ["sandbox-node", "ec2", "instances-account-region-service-wide-all-states"],
  ["network-interface", "ec2", "network-interfaces-account-region-service-wide-all-attachment-states"],
  ["ebs-trusted-root-volume", "ec2", "volumes-account-region-service-wide-all-attachment-states"],
  ["ebs-sandbox-root-volume", "ec2", "volumes-account-region-service-wide-all-attachment-states"],
  ["ebs-workspace-volume", "ec2", "volumes-account-region-service-wide-all-attachment-states"],
  ["ebs-session-state-volume", "ec2", "volumes-account-region-service-wide-all-attachment-states"],
  ["ebs-snapshot", "ec2", "snapshots-owned-by-account-region-service-wide"],
  ["kms-key", "kms", "keys-account-region-service-wide-all-key-states"],
  ["kms-alias", "kms", "aliases-account-region-service-wide"],
  ["log-group", "logs", "log-groups-account-region-service-wide"],
  ["budget", "budgets", "budgets-account-service-wide"],
  ["budget-notification", "budgets", "notifications-for-every-budget-account-service-wide"],
  ["ttl-schedule", "scheduler", "schedules-account-region-service-wide"],
  ["ttl-function", "lambda", "functions-account-region-service-wide"],
  ["ttl-function-permission", "lambda", "resource-policies-for-every-function-account-region-service-wide"],
] as const);

const EXPECTED_IMAGE_REFERENCES = Object.freeze({
  worker: RELEASE_IMAGE_REFERENCES.worker,
  proxy: "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb",
  sandbox: RELEASE_IMAGE_REFERENCES.sandbox,
});

/* stage4-readiness-anchor-start */
export const STAGE4_READINESS_EXPECTED_ARTIFACTS = Object.freeze({
  chartInventory: "a3801a32d9f1a59864bd027aebf44554b087911c7d4a4486e7bcda697ff68617",
  imageLock: "daf3272a82879f8df79ba3ca412a330494af94cc7f162be45fdd67333f8215ed",
  releaseImageAssertion: "2368b09be02dc6e21debd8f047e58400173d62ff13edc27398ddbfe1708474d4",
  releaseImageReview: "9e3f9ababef58e8b4cc90e9f007251c05a2065eb2ff2e25f928e7c8b4d61e216",
  nicContract: "9b61b547884b6baa081974242171885f92c7d756224bc181fe6e78c965c1fa9a",
  render: "399d9b86a43777a57542c70c93f6ef595224e455d6969d2bfbd154e6d05d8fa0",
  repeatedRender: "399d9b86a43777a57542c70c93f6ef595224e455d6969d2bfbd154e6d05d8fa0",
  runtimePins: "1e683ef6513f9f86f7eaead0fd64d949f037afd06043882eb1b6514aa5c4a145",
  values: "c689236c57e1eab668f8bf504e148245cc23a652b529d1aaab20ef8d4e0fdc7a",
  authenticatedRuntimeArtifacts: "cd87233d2f3e6be755e78ce63a4b3e85c088fe75997dfe22943bb890317844e3",
  localValidationNormalized: "bd9b6c1b526246c0b7c49309913f55f5a404d70069b28039c93a376e46c34298",
  renderReceipt: "491c7963c00873ee6429cb3917c2ae1316e83b5905257b1abc8c60a4464541cf",
  schemaInventory: "ca8a324816c2ab45f96aafb0c916b3b12d4b1b15eeb51bf63ac69b45b143e683",
  sourceInventoryNormalized: "3f94791b535cf8976fc05f1a05db719d06e627de743d5ce7ef4e406e630ad6d9",
});
/* stage4-readiness-anchor-end */

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

/** Code-point-key-sorted canonical JSON with exactly one terminal LF. */
export function canonicalStage4OfflineReadinessBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

export function stage4OfflineReadinessSha256(bytes: Uint8Array, maximum = 4 * 1024 * 1024): string {
  const captured = capturePrivateBytes(bytes, maximum, true);
  if (captured.bytes === null) throw new TypeError("invalid or oversized bytes");
  return createHash("sha256").update(captured.bytes).digest("hex");
}

function domainHash(domain: string, value: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  const length = intrinsicByteLength(left);
  if (length !== intrinsicByteLength(right)) return false;
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function copyBytes(value: unknown, maximum: number): Uint8Array | null {
  return capturePrivateBytes(value, maximum).bytes;
}

function copyArtifacts(input: unknown): ArtifactCopies | null {
  if ((typeof input === "object" && input !== null) || typeof input === "function") {
    if (types.isProxy(input)) return null;
  }
  if (input === null || typeof input !== "object" || Object.getPrototypeOf(input) !== Object.prototype) return null;
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== STAGE4_READINESS_ARTIFACT_KEYS.length ||
    keys.some(
      (key) => typeof key !== "string" || !STAGE4_READINESS_ARTIFACT_KEYS.includes(key as Stage4ReadinessArtifactKey),
    )
  )
    return null;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const output = Object.create(null) as ArtifactCopies;
  let aggregate = 0;
  for (const key of STAGE4_READINESS_ARTIFACT_KEYS) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) return null;
    const maximum = STAGE4_READINESS_BYTE_LIMITS[key];
    const bytes = copyBytes(descriptor.value, maximum);
    if (bytes === null) return null;
    aggregate += intrinsicByteLength(bytes);
    if (aggregate > STAGE4_READINESS_BYTE_LIMITS.aggregateArtifacts) return null;
    output[key] = bytes;
  }
  return output;
}

function record(value: JsonValue | undefined): JsonRecord | null {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function stringProperty(value: JsonValue | undefined, key: string): string | null {
  const object = record(value);
  const property = object?.[key];
  return typeof property === "string" ? property : null;
}

function parseCanonicalArtifact(bytes: Uint8Array): JsonRecord | null {
  try {
    const value = JSON.parse(decoder.decode(bytes)) as JsonValue;
    const object = record(value);
    return object !== null && bytesEqual(bytes, canonicalStage4OfflineReadinessBytes(value)) ? object : null;
  } catch {
    return null;
  }
}

function trackedWorktreeMerkle(value: JsonValue | undefined): string | null {
  if (!Array.isArray(value)) return null;
  return createHash("sha256")
    .update("cogs.stage4/tracked-worktree-mode-path-byte-merkle/v2\0", "utf8")
    .update(canonicalStage4OfflineReadinessBytes(value))
    .digest("hex");
}

function digestEntries(value: JsonValue | undefined, requireGitMode = false): Map<string, string> | null {
  if (!Array.isArray(value)) return null;
  const output = new Map<string, string>();
  for (const item of value) {
    const row = record(item);
    if (
      row === null ||
      Reflect.ownKeys(row).length !== (requireGitMode ? 3 : 2) ||
      typeof row.path !== "string" ||
      typeof row.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/u.test(row.sha256) ||
      (requireGitMode && row.mode !== "100644" && row.mode !== "100755") ||
      output.has(row.path)
    )
      return null;
    output.set(row.path, row.sha256);
  }
  return output;
}

function normalizedInventoryDigest(bytes: Uint8Array, arrayKey: string, selfPath: string): string | null {
  const value = parseCanonicalArtifact(bytes);
  const entries = value?.[arrayKey];
  if (value === null || !Array.isArray(entries)) return null;
  let replacements = 0;
  const normalized = entries.map((item) => {
    const row = record(item);
    if (row?.path !== selfPath) return item;
    replacements += 1;
    return { ...row, sha256: "0".repeat(64) } as JsonValue;
  });
  if (replacements !== 1) return null;
  const normalizedValue = { ...value, [arrayKey]: normalized };
  if (arrayKey === "entries" && selfPath === "scripts/stage4-offline-readiness.ts") {
    const binding = record(normalizedValue.worktree_binding);
    if (binding === null) return null;
    normalizedValue.worktree_binding = {
      ...binding,
      worktree_merkle_sha256: trackedWorktreeMerkle(normalized),
    };
  }
  return stage4OfflineReadinessSha256(canonicalStage4OfflineReadinessBytes(normalizedValue));
}

export function stage4NormalizedSourceInventorySha256(input: Uint8Array): string | null {
  const captured = capturePrivateBytes(input, STAGE4_READINESS_BYTE_LIMITS.sourceInventory);
  return captured.bytes === null
    ? null
    : normalizedInventoryDigest(captured.bytes, "entries", "scripts/stage4-offline-readiness.ts");
}

export function stage4NormalizedLocalValidationSha256(input: Uint8Array): string | null {
  const captured = capturePrivateBytes(input, STAGE4_READINESS_BYTE_LIMITS.localValidation);
  if (captured.bytes === null) return null;
  const value = parseCanonicalArtifact(captured.bytes);
  if (value === null || !Array.isArray(value.source_bindings) || !Array.isArray(value.checks)) return null;
  let replacements = 0;
  const normalizeBindings = (bindings: JsonValue): JsonValue => {
    if (!Array.isArray(bindings)) return bindings;
    return bindings.map((item) => {
      const row = record(item);
      if (row?.path !== "scripts/stage4-offline-readiness.ts") return item;
      replacements += 1;
      return { ...row, sha256: "0".repeat(64) } as JsonValue;
    });
  };
  const checks = value.checks.map((item) => {
    const check = record(item);
    return check === null
      ? item
      : ({ ...check, source_bindings: normalizeBindings(check.source_bindings ?? null) } as JsonValue);
  });
  const normalized = {
    ...value,
    checks,
    source_bindings: normalizeBindings(value.source_bindings),
  };
  return replacements >= 1 ? stage4OfflineReadinessSha256(canonicalStage4OfflineReadinessBytes(normalized)) : null;
}

function exactArtifactSemantics(value: ReadinessPackage, artifacts: ArtifactCopies): boolean {
  const exactRaw: ReadonlyArray<readonly [Stage4ReadinessArtifactKey, string]> = [
    ["chartInventory", STAGE4_READINESS_EXPECTED_ARTIFACTS.chartInventory],
    ["values", STAGE4_READINESS_EXPECTED_ARTIFACTS.values],
    ["render", STAGE4_READINESS_EXPECTED_ARTIFACTS.render],
    ["repeatedRender", STAGE4_READINESS_EXPECTED_ARTIFACTS.repeatedRender],
    ["renderReceipt", STAGE4_READINESS_EXPECTED_ARTIFACTS.renderReceipt],
    ["imageLock", STAGE4_READINESS_EXPECTED_ARTIFACTS.imageLock],
    ["releaseImageAssertion", STAGE4_READINESS_EXPECTED_ARTIFACTS.releaseImageAssertion],
    ["releaseImageReview", STAGE4_READINESS_EXPECTED_ARTIFACTS.releaseImageReview],
    ["nicContract", STAGE4_READINESS_EXPECTED_ARTIFACTS.nicContract],
    ["runtimePins", STAGE4_READINESS_EXPECTED_ARTIFACTS.runtimePins],
    ["authenticatedRuntimeArtifacts", STAGE4_READINESS_EXPECTED_ARTIFACTS.authenticatedRuntimeArtifacts],
    ["schemaInventory", STAGE4_READINESS_EXPECTED_ARTIFACTS.schemaInventory],
  ];
  if (exactRaw.some(([key, expected]) => stage4OfflineReadinessSha256(artifacts[key]) !== expected)) return false;
  if (
    stage4NormalizedSourceInventorySha256(artifacts.sourceInventory) !==
      STAGE4_READINESS_EXPECTED_ARTIFACTS.sourceInventoryNormalized ||
    stage4NormalizedLocalValidationSha256(artifacts.localValidation) !==
      STAGE4_READINESS_EXPECTED_ARTIFACTS.localValidationNormalized
  )
    return false;

  const source = parseCanonicalArtifact(artifacts.sourceInventory);
  const schemas = parseCanonicalArtifact(artifacts.schemaInventory);
  const local = parseCanonicalArtifact(artifacts.localValidation);
  const receipt = parseCanonicalArtifact(artifacts.renderReceipt);
  const image = parseCanonicalArtifact(artifacts.imageLock);
  const runtime = parseCanonicalArtifact(artifacts.runtimePins);
  if ([source, schemas, local, receipt, image, runtime].some((item) => item === null)) return false;
  const sourceEntries = digestEntries(source?.entries, true);
  const schemaEntries = digestEntries(schemas?.entries);
  const localBindings = digestEntries(local?.source_bindings);
  if (sourceEntries === null || schemaEntries === null || localBindings === null) return false;
  const worktree = record(source?.worktree_binding);
  const packageSource = record(value.source);
  const worktreeMerkle = trackedWorktreeMerkle(source?.entries);
  if (
    source?.version !== "cogs.stage4-offline-source-inventory/v5" ||
    source.algorithm !== "sha256-domain-separated-canonical-git-mode-path-and-exact-byte-digest-list" ||
    source.scope !== "complete-tracked-worktree-source-build-qualification-closure" ||
    worktree === null ||
    packageSource === null ||
    worktree.file_count !== sourceEntries.size ||
    worktree.worktree_merkle_sha256 !== worktreeMerkle ||
    packageSource.worktree_merkle_sha256 !== worktreeMerkle ||
    packageSource.commit_binding_present !== false
  )
    return false;

  const sourceArtifactPaths: ReadonlyArray<readonly [string, Stage4ReadinessArtifactKey]> = [
    ["docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json", "chartInventory"],
    ["docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json", "imageLock"],
    ["docs/security-evidence/release-image-set-assertion-31856469035.canonical.json", "releaseImageAssertion"],
    ["docs/security-evidence/release-image-set-review-31856469035.canonical.json", "releaseImageReview"],
    ["docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml", "repeatedRender"],
    ["docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml", "render"],
    ["docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json", "renderReceipt"],
    ["docs/security-evidence/stage4-offline-readiness-artifacts/runtime-pins.json", "runtimePins"],
    [
      "docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
      "authenticatedRuntimeArtifacts",
    ],
    ["docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json", "schemaInventory"],
    ["deploy/nic/stage4-sandbox-node-group-contract.json", "nicContract"],
    ["test/fixtures/helm/stage4-notes-source-shapes-valid.yaml", "values"],
  ];
  if (
    sourceArtifactPaths.some(
      ([path, key]) => sourceEntries.get(path) !== stage4OfflineReadinessSha256(artifacts[key]),
    ) ||
    [...schemaEntries].some(([path, digest]) => sourceEntries.get(path) !== digest) ||
    [...localBindings].some(([path, digest]) => sourceEntries.get(path) !== digest)
  )
    return false;

  const generatorDigest = sourceEntries.get("scripts/stage4-offline-render-preparation.ts");
  const expectedLocalChecks = [
    "readiness-format",
    "repository-typecheck",
    "stage4-unit-contracts",
    "production-runtime-image-static-route-contracts",
    "stage4-schema-registry",
    "all-schema-contracts",
    "trusted-helm-local-contracts",
    "complete-stage4-source-inventory",
    "dependency-lock-integrity",
  ];
  const localChecks = local?.checks;
  const localChecksPass =
    Array.isArray(localChecks) &&
    localChecks.length === expectedLocalChecks.length &&
    localChecks.every((item, index) => {
      const check = record(item);
      const outcome = record(check?.outcome);
      return (
        check?.id === expectedLocalChecks[index] &&
        check?.result === "pass-exit-zero" &&
        outcome?.exit_code === 0 &&
        outcome.signal === null &&
        typeof outcome.digest_sha256 === "string" &&
        /^[0-9a-f]{64}$/u.test(outcome.digest_sha256)
      );
    });
  const unexecuted = local?.unexecuted;
  const expectedUnexecuted = [
    "current-npm-registry-audit",
    "production-image-docker-builds",
    "release-image-publication",
  ];
  const honestlyUnexecuted =
    Array.isArray(unexecuted) &&
    unexecuted.length === expectedUnexecuted.length &&
    unexecuted.every(
      (item, index) => record(item)?.id === expectedUnexecuted[index] && record(item)?.result === "not-run-not-claimed",
    );
  const execution = record(local?.execution);
  const executionLayer = {
    generator_source_sha256: receipt?.generator_source_sha256 as JsonValue,
    node_arch: receipt?.node_arch as JsonValue,
    node_executable_sha256: receipt?.node_executable_sha256 as JsonValue,
    node_platform: receipt?.node_platform as JsonValue,
    node_version: receipt?.node_version as JsonValue,
    typescript_loader: receipt?.typescript_loader as JsonValue,
  };
  if (
    receipt?.chart_inventory_sha256 !== stage4OfflineReadinessSha256(artifacts.chartInventory) ||
    receipt.values_sha256 !== stage4OfflineReadinessSha256(artifacts.values) ||
    receipt.first_render_sha256 !== stage4OfflineReadinessSha256(artifacts.render) ||
    receipt.repeated_render_sha256 !== stage4OfflineReadinessSha256(artifacts.repeatedRender) ||
    !localChecksPass ||
    !honestlyUnexecuted ||
    execution === null ||
    Reflect.ownKeys(execution).length !== 6 ||
    Object.values(execution).some((observed) => observed !== false) ||
    receipt.generator_source_sha256 !== generatorDigest ||
    receipt.execution_layer_sha256 !==
      stage4OfflineReadinessSha256(canonicalStage4OfflineReadinessBytes(executionLayer)) ||
    receipt.helm_lint_passed !== true ||
    !/^[0-9a-f]{64}$/u.test(String(receipt.helm_lint_output_sha256)) ||
    receipt.zero_submitted_manifests !== true ||
    receipt.zero_manifest_output_sha256 !== stage4OfflineReadinessSha256(new TextEncoder().encode("\n")) ||
    local?.status !== "passed-recorded-bounded-local-commands" ||
    local.scope !==
      "only-the-nine-recorded-bounded-local-commands;no-docker-publication-or-current-registry-advisory-discovery" ||
    local.trusted_preparation_receipt_sha256 !== stage4OfflineReadinessSha256(artifacts.renderReceipt)
  )
    return false;

  const imageRows = image?.images;
  const packageImages = value.pins.images;
  const releaseSet = record(image?.release_image_set);
  const packageImageSource = record(packageSource?.image_source);
  const releaseReviewVerdict = classifyReleaseImageSetReview(
    artifacts.releaseImageAssertion,
    artifacts.releaseImageReview,
  );
  if (
    !releaseReviewVerdict.record_valid ||
    !releaseReviewVerdict.release_image_set_present ||
    !releaseReviewVerdict.exact_image_identity_closure_satisfied ||
    !Array.isArray(imageRows) ||
    imageRows.length !== 3 ||
    image?.version !== "cogs.stage4-offline-image-lock/v5" ||
    image.release_image_set_present !== true ||
    image.exact_image_closure_satisfied !== true ||
    stringProperty(imageRows[0], "reference") !== stringProperty(packageImages.worker, "reference") ||
    stringProperty(imageRows[1], "reference") !== stringProperty(packageImages.proxy, "reference") ||
    stringProperty(imageRows[2], "reference") !== stringProperty(packageImages.sandbox, "reference") ||
    record(imageRows[0])?.state !== "reviewed-current-source-image-set" ||
    record(imageRows[2])?.state !== "reviewed-current-source-image-set" ||
    releaseSet?.state !== "reviewed-current-source-image-set" ||
    releaseSet?.assertion_sha256 !== RELEASE_IMAGE_SET_ASSERTION_SHA256 ||
    releaseSet?.review_sha256 !== RELEASE_IMAGE_SET_REVIEW_SHA256 ||
    releaseSet?.image_source_sha !== RELEASE_IMAGE_SOURCE_SHA ||
    releaseSet?.workflow_run_id !== RELEASE_IMAGE_WORKFLOW_RUN_ID ||
    packageImages.release_image_set_present !== true ||
    packageImages.exact_image_closure_satisfied !== true ||
    packageImageSource?.reviewed_sha !== RELEASE_IMAGE_SOURCE_SHA ||
    packageImageSource?.tree_sha !== RELEASE_IMAGE_SOURCE_TREE_SHA ||
    packageImageSource?.inventory_sha256 !== RELEASE_IMAGE_SOURCE_INVENTORY_SHA256 ||
    packageImageSource?.relation !== "separately-bound-immutable-image-source"
  )
    return false;
  const packageRuntime = record(value.pins.runtime);
  const runtimeRecord = record(runtime?.runtime);
  if (
    packageRuntime === null ||
    runtimeRecord === null ||
    stringProperty(runtimeRecord.containerd, "version") !== packageRuntime.containerd_version ||
    stringProperty(runtimeRecord.containerd, "artifact_sha256") !== packageRuntime.containerd_artifact_sha256 ||
    stringProperty(runtimeRecord.containerd, "artifact_state") !== packageRuntime.containerd_artifact_state ||
    stringProperty(runtimeRecord.qemu, "version") !== packageRuntime.qemu_version ||
    stringProperty(runtimeRecord.qemu, "artifact_sha256") !== packageRuntime.qemu_artifact_sha256 ||
    stringProperty(runtimeRecord.qemu, "artifact_state") !== packageRuntime.qemu_artifact_state ||
    stringProperty(runtimeRecord.kata, "archive_sha256") !== packageRuntime.kata_archive_sha256 ||
    record(runtime?.eks_node_image)?.ami_id !== packageRuntime.eks_node_ami_id ||
    record(runtime?.eks_node_image)?.release !== packageRuntime.eks_node_image_release ||
    record(runtime?.eks_node_image)?.kernel_release !== packageRuntime.eks_node_kernel_release
  )
    return false;
  return true;
}

function makeVerdict(
  reasonCode: Stage4ReadinessReasonCode,
  packageSha256: string | null = null,
  bindingRootSha256: string | null = null,
): Stage4OfflineReadinessVerdict {
  const complete = reasonCode === "STAGE4_LOCAL_PREPARATION_COMPLETE_CAMPAIGN_BLOCKED";
  return Object.freeze({
    version: "cogs.stage4-offline-readiness-verdict/v5",
    authority: "local-static-stage4-readiness-classifier",
    local_preparation_complete: complete,
    candidate_artifact_closure_complete: complete,
    selected_runtime_artifacts_authenticated: complete,
    local_preparation_scope: "bounded-package-assembly-and-local-validation-only",
    trusted_render_preparation_complete: complete,
    exact_image_runtime_closure_satisfied: false,
    campaign_request_ready: false,
    campaign_approved: false,
    cloud_authorized: false,
    cloud_execution_observed: false,
    provider_truth_observed: false,
    current_resources_observed: false,
    zero_resources_claimed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    package_sha256: packageSha256,
    binding_root_sha256: bindingRootSha256,
    status: complete ? "local-preparation-complete-blocked" : "preserve-uncertain",
    reason_code: reasonCode,
    blockers: complete ? STAGE4_READINESS_BLOCKERS : Object.freeze([]),
  });
}

function bindingRootInput(value: ReadinessPackage): JsonValue {
  const artifactBindings = { ...value.artifact_bindings } as JsonRecord;
  delete artifactBindings.binding_root_sha256;
  return {
    artifact_bindings: artifactBindings,
    attempt_authority: value.attempt_authority as JsonValue,
    blockers: value.blockers as JsonValue,
    campaign_proposal: value.campaign_proposal as JsonValue,
    claims: value.claims as JsonValue,
    identities: value.identities as JsonValue,
    local_validation: value.local_validation as JsonValue,
    pins: value.pins,
    revalidation: value.revalidation as JsonValue,
    source: value.source as JsonValue,
    stop_destroy: value.stop_destroy as JsonValue,
    version: value.version as JsonValue,
  };
}

/** Computes the domain-separated semantic root; callers must first validate the package schema. */
export function stage4OfflineReadinessBindingRoot(value: ReadinessPackage): string {
  return domainHash("cogs.stage4/offline-readiness-binding-root/v1", bindingRootInput(value));
}

function exactResourceAndInventoryClosure(value: ReadinessPackage): boolean {
  const resourceGraph = record(value.campaign_proposal.resource_graph);
  const inventory = record(value.stop_destroy.independent_inventory);
  const expectedGraph = STAGE4_PROPOSED_RESOURCE_GRAPH.map(([resourceClass, maximumCount, resourceType, sizeGib]) => ({
    maximum_count: maximumCount,
    resource_class: resourceClass,
    resource_type: resourceType,
    size_gib_each: sizeGib,
  })) as unknown as JsonValue;
  const expectedScopes = STAGE4_INDEPENDENT_INVENTORY_SCOPES.map(([resourceClass, service, scope]) => ({
    resource_class: resourceClass,
    scope,
    service,
    tag_only: false,
  })) as unknown as JsonValue;
  return (
    resourceGraph?.closed_world === true &&
    resourceGraph.undeclared_resource_classes_allowed === false &&
    resourceGraph.count_semantics === "hard-maximum-proposal" &&
    resourceGraph.classes !== undefined &&
    canonicalJson(resourceGraph.classes) === canonicalJson(expectedGraph) &&
    inventory?.tag_only_inventory_allowed === false &&
    inventory.scopes !== undefined &&
    canonicalJson(inventory.scopes) === canonicalJson(expectedScopes)
  );
}

function exactImagePins(value: ReadinessPackage): boolean {
  const images = value.pins.images;
  return (
    stringProperty(images.worker, "reference") === EXPECTED_IMAGE_REFERENCES.worker &&
    stringProperty(images.proxy, "reference") === EXPECTED_IMAGE_REFERENCES.proxy &&
    stringProperty(images.sandbox, "reference") === EXPECTED_IMAGE_REFERENCES.sandbox
  );
}

/**
 * Classifies canonical package bytes and exact caller-supplied artifact bytes. The function is local and pure:
 * it performs no filesystem, process, environment, network, provider, Kubernetes, Helm, or model operation.
 * Validity means only that this bounded package is structurally assembled and locally digest-consistent.
 */
export function classifyStage4OfflineReadiness(
  packageInput: unknown,
  artifactInput: unknown,
): Stage4OfflineReadinessVerdict {
  const packageBytes = copyBytes(packageInput, STAGE4_READINESS_BYTE_LIMITS.package);
  const artifacts = copyArtifacts(artifactInput);
  if (packageBytes === null || artifacts === null) {
    return makeVerdict("STAGE4_READINESS_BOUNDED_IO_VIOLATION");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(packageBytes));
  } catch {
    return makeVerdict("STAGE4_READINESS_INVALID_CANONICAL_PACKAGE");
  }

  let canonical: Uint8Array;
  try {
    canonical = canonicalStage4OfflineReadinessBytes(parsed as JsonValue);
  } catch {
    return makeVerdict("STAGE4_READINESS_INVALID_CANONICAL_PACKAGE");
  }
  if (!bytesEqual(packageBytes, canonical)) {
    return makeVerdict("STAGE4_READINESS_INVALID_CANONICAL_PACKAGE");
  }
  if (!validatePackageSchema(parsed)) {
    return makeVerdict("STAGE4_READINESS_SCHEMA_OR_SEMANTIC_DRIFT");
  }

  const packageSha256 = stage4OfflineReadinessSha256(packageBytes);
  const bindingRoot = parsed.artifact_bindings.binding_root_sha256;
  if (!exactImagePins(parsed) || !exactResourceAndInventoryClosure(parsed)) {
    return makeVerdict("STAGE4_READINESS_SCHEMA_OR_SEMANTIC_DRIFT", packageSha256, bindingRoot);
  }

  for (const key of STAGE4_READINESS_ARTIFACT_KEYS) {
    const expected = parsed.artifact_bindings[DIGEST_FIELDS[key]];
    if (expected !== stage4OfflineReadinessSha256(artifacts[key])) {
      return makeVerdict("STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH", packageSha256, bindingRoot);
    }
  }
  if (!exactArtifactSemantics(parsed, artifacts)) {
    return makeVerdict("STAGE4_READINESS_ARTIFACT_BINDING_MISMATCH", packageSha256, bindingRoot);
  }
  if (!bytesEqual(artifacts.render, artifacts.repeatedRender)) {
    return makeVerdict("STAGE4_READINESS_RENDER_NONDETERMINISTIC", packageSha256, bindingRoot);
  }
  if (parsed.artifact_bindings.render_sha256 !== parsed.artifact_bindings.repeated_render_sha256) {
    return makeVerdict("STAGE4_READINESS_RENDER_NONDETERMINISTIC", packageSha256, bindingRoot);
  }
  if (stage4OfflineReadinessBindingRoot(parsed) !== bindingRoot) {
    return makeVerdict("STAGE4_READINESS_BINDING_ROOT_MISMATCH", packageSha256, bindingRoot);
  }

  return makeVerdict("STAGE4_LOCAL_PREPARATION_COMPLETE_CAMPAIGN_BLOCKED", packageSha256, bindingRoot);
}
