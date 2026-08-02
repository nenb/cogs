import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder, types } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const packageSchema = require("../schemas/stage4-offline-readiness-package-v1.json") as object;

export const STAGE4_READINESS_BLOCKERS = Object.freeze([
  "ISSUE_42_OPEN",
  "NIC_V0_11_0_MODULE_0_7_0_LAUNCH_TEMPLATE_CAPABILITY_MISSING",
  "EKS_AMI_IMAGE_RELEASE_KERNEL_UNRESOLVED",
  "PROPOSED_ACCOUNT_BINDING_ABSENT",
  "CURRENT_PRICE_NOT_REVALIDATED",
  "CURRENT_QUOTA_NOT_REVALIDATED",
  "SEPARATED_CAMPAIGN_IDENTITIES_ABSENT",
  "CAMPAIGN_ENVELOPE_AND_APPROVAL_ABSENT",
  "NO_EXECUTABLE_PROVIDER_ROUTE",
  "RELEASE_IMAGE_SET_ABSENT",
  "CONTAINERD_ARTIFACT_IDENTITY_UNRESOLVED",
  "QEMU_ARTIFACT_IDENTITY_UNRESOLVED",
] as const);

export const STAGE4_READINESS_ARTIFACT_KEYS = Object.freeze([
  "sourceInventory",
  "chartInventory",
  "values",
  "render",
  "repeatedRender",
  "renderReceipt",
  "imageLock",
  "nicContract",
  "runtimePins",
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
  nicContract: 128 * 1024,
  runtimePins: 16 * 1024,
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
  version: "cogs.stage4-offline-readiness-verdict/v1";
  authority: "local-static-stage4-readiness-classifier";
  local_preparation_complete: boolean;
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
  nicContract: "nic_contract_sha256",
  runtimePins: "runtime_pins_sha256",
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
  ["eks-cluster", "eks", "clusters-by-account-and-region"],
  ["eks-managed-addon", "eks", "addons-by-cluster"],
  ["vpc", "ec2", "vpcs-by-account-and-region"],
  ["subnet", "ec2", "subnets-by-vpc"],
  ["route-table", "ec2", "route-tables-by-vpc"],
  ["route", "ec2", "routes-by-each-route-table"],
  ["internet-gateway", "ec2", "internet-gateways-by-vpc-attachment"],
  ["network-acl", "ec2", "network-acls-by-vpc"],
  ["dhcp-options-association", "ec2", "dhcp-options-by-vpc-association"],
  ["nat-gateway", "ec2", "nat-gateways-by-vpc-all-lifecycle-states"],
  ["vpc-endpoint", "ec2", "vpc-endpoints-by-vpc"],
  ["elastic-ip", "ec2", "addresses-by-account-and-region"],
  ["load-balancer", "elasticloadbalancing", "load-balancers-by-account-and-region"],
  ["target-group", "elasticloadbalancing", "target-groups-by-account-and-region"],
  ["security-group", "ec2", "security-groups-by-vpc"],
  ["iam-role", "iam", "roles-by-exact-campaign-name-inventory"],
  ["iam-customer-managed-policy", "iam", "policies-by-account-and-exact-campaign-name-inventory"],
  ["iam-policy-attachment", "iam", "role-and-policy-attachments-by-enumerated-role"],
  ["instance-profile", "iam", "instance-profiles-by-enumerated-role"],
  ["launch-template", "ec2", "launch-templates-and-all-versions-by-account-and-region"],
  ["managed-node-group", "eks", "nodegroups-by-cluster"],
  ["autoscaling-group", "autoscaling", "groups-by-account-and-region"],
  ["trusted-node", "ec2", "instances-by-approved-trusted-launch-template"],
  ["sandbox-node", "ec2", "instances-by-approved-sandbox-launch-template"],
  ["network-interface", "ec2", "network-interfaces-by-vpc-and-attachment"],
  ["ebs-trusted-root-volume", "ec2", "volumes-by-trusted-node-attachment"],
  ["ebs-sandbox-root-volume", "ec2", "volumes-by-sandbox-node-attachment"],
  ["ebs-workspace-volume", "ec2", "workspace-volumes-by-exact-campaign-binding"],
  ["ebs-session-state-volume", "ec2", "session-volumes-by-exact-campaign-binding"],
  ["ebs-snapshot", "ec2", "snapshots-owned-by-account"],
  ["kms-key", "kms", "keys-and-key-state-by-account-and-region"],
  ["kms-alias", "kms", "aliases-by-account-and-region"],
  ["log-group", "logs", "log-groups-by-exact-campaign-name-inventory"],
  ["budget", "budgets", "budgets-by-account"],
  ["budget-notification", "budgets", "notifications-by-enumerated-budget"],
  ["ttl-schedule", "scheduler", "schedules-by-exact-campaign-group-inventory"],
  ["ttl-function", "lambda", "functions-by-account-and-region"],
  ["ttl-function-permission", "lambda", "resource-policies-by-enumerated-function"],
] as const);

const EXPECTED_IMAGE_REFERENCES = Object.freeze({
  worker: `registry.example.invalid/cogs/worker@sha256:${"a".repeat(64)}`,
  proxy: "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb",
  sandbox: `registry.example.invalid/cogs/sandbox@sha256:${"c".repeat(64)}`,
});

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

export function stage4OfflineReadinessSha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function domainHash(domain: string, value: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function copyBytes(value: unknown, maximum: number): Uint8Array | null {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    if (types.isProxy(value)) return null;
  }
  if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype) return null;
  if (value.byteLength === 0 || value.byteLength > maximum) return null;
  return new Uint8Array(value);
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
    aggregate += bytes.byteLength;
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

function makeVerdict(
  reasonCode: Stage4ReadinessReasonCode,
  packageSha256: string | null = null,
  bindingRootSha256: string | null = null,
): Stage4OfflineReadinessVerdict {
  const complete = reasonCode === "STAGE4_LOCAL_PREPARATION_COMPLETE_CAMPAIGN_BLOCKED";
  return Object.freeze({
    version: "cogs.stage4-offline-readiness-verdict/v1",
    authority: "local-static-stage4-readiness-classifier",
    local_preparation_complete: complete,
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
