import { createHash } from "node:crypto";

export const STAGE4_NIC_REASON_CODES = Object.freeze([
  "STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING",
  "STAGE4_NIC_INVALID_SHAPE",
  "STAGE4_NIC_INVALID_VERSION",
  "STAGE4_NIC_SOURCE_DRIFT",
  "STAGE4_NODE_IMAGE_DRIFT",
  "STAGE4_NODE_GROUP_DRIFT",
  "STAGE4_SCHEDULING_DRIFT",
] as const);

export type Stage4NicReasonCode = (typeof STAGE4_NIC_REASON_CODES)[number];
export type Stage4NicStatus = "blocked-missing-capability" | "reject-drift";

export type Stage4NicVerdict = Readonly<{
  version: "cogs.stage4-nic-sandbox-node-group-verdict/v1";
  authority: "local-static-nic-contract-classifier";
  campaign_authorized: false;
  cloud_execution_observed: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  contract_sha256: string | null;
  nic_source_pin_resolved: boolean;
  node_image_pin_resolved: boolean;
  launch_template_capability_resolved: boolean;
  status: Stage4NicStatus;
  reason_code: Stage4NicReasonCode;
}>;

const CONTRACT_VERSION = "cogs.stage4-nic-sandbox-node-group-contract/v1";
const ROOT_KEYS = [
  "authority",
  "nic_capability_assessment",
  "nic_source",
  "node_image",
  "sandbox_node_group",
  "scheduling",
  "version",
];
const AMI = /^ami-[0-9a-f]{8,17}$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u;
const MAX_DEPTH = 16;
const MAX_NODES = 256;

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export const STAGE4_PINNED_NIC_SOURCE = deepFreeze({
  identity: "nebari-infrastructure-core",
  repository: "https://github.com/nebari-dev/nebari-infrastructure-core.git",
  release_tag: "v0.11.0",
  commit_sha: "28221c652c56bb8d48a92538c01503a82f2f9321",
  tree_git_sha: "4dfb0333e5d91003e69881ca1dcf66e1ea9ff6c2",
  files: [
    {
      path: "pkg/providers/cluster/aws/config.go",
      git_blob_sha: "b607ccd28fea4fa9dbb1b5f2cab8035c88eb8ab8",
      content_sha256: "9926e0de378b488778e4975324a76c7d3ab3aaa5b4c661e81211a1efe382e920",
    },
    {
      path: "pkg/providers/cluster/aws/templates/main.tf",
      git_blob_sha: "719efb5d85b8247968f6965acd3911b3a0a93337",
      content_sha256: "eca59352b11fbcb48085a9276e5b01682256ce17f55fa7f4a23c0bcccfa443f4",
    },
    {
      path: "pkg/providers/cluster/aws/tofu.go",
      git_blob_sha: "934a1f92413ba7c758f57d779c3ad1049256b30d",
      content_sha256: "39e87c14203fa602568bcff4e64126271073484e531c21a83028eb104a9a506b",
    },
  ],
  eks_module: {
    registry_source: "nebari-dev/eks-cluster/aws",
    version: "0.7.0",
    commit_sha: "5d4cb31f07fda5c010b5be580258d32f6db75828",
    tree_git_sha: "240dd73f709f67706d60b35d3256661848736ad2",
    files: [
      {
        path: "variables.tf",
        content_sha256: "20a17ac8d6a76ebaf5708ac229a062697d277e283561e070f1aac378603e1d67",
      },
      {
        path: "locals.tf",
        content_sha256: "e21403a5cef4faf515c6179b221e690553f6ad22d012befb57e529b3ccceec5e",
      },
      {
        path: "main.tf",
        content_sha256: "e7f3107a21e597da972220993f25f38527af74999b6e44f370317938f7d732a0",
      },
    ],
  },
} as const);

export const STAGE4_NIC_CAPABILITY_ASSESSMENT = deepFreeze({
  source_revision_verified: true,
  managed_node_group_mapping_verified: true,
  supported_inputs: ["instance_type", "min_size", "max_size", "ami_type", "spot", "disk", "labels", "taints"],
  custom_launch_template_id: false,
  custom_launch_template_version: false,
  cpu_options_nested_virtualization: false,
  underlying_launch_template_mode: "module-auto-created-fixed-shape",
  outcome: "blocking-capability-gap",
  reason_code: "NIC_CUSTOM_LAUNCH_TEMPLATE_AND_CPU_OPTIONS_UNSUPPORTED",
} as const);

export const STAGE4_SANDBOX_NODE_GROUP = deepFreeze({
  provider: "aws",
  region: "us-east-1",
  name: "cogs-stage4-sandbox-kata",
  capacity_type: "ON_DEMAND",
  instance_type: "c8i-flex.large",
  architecture: "x86_64",
  bare_metal: false,
  scaling: { min: 0, max: 1 },
  required_labels: {
    "cogs.dev/node-domain": "sandbox-kata",
    "cogs.dev/nested-virtualization": "enabled",
    "cogs.dev/sandbox-runtime": "kata-qemu-kvm",
  },
  required_taints: [{ key: "cogs.dev/sandbox", value: "kata", effect: "NO_SCHEDULE" }],
  launch_template: {
    source: "custom-external",
    id_input: "sandbox_launch_template_id",
    version_input: "sandbox_launch_template_version",
    version_selection: "explicit-positive-integer",
    allow_default_version: false,
    allow_latest_version: false,
    preserve_id_and_version: true,
    reject_reconcile_drift: true,
    cpu_options: { nested_virtualization: "enabled", core_count: 1, threads_per_core: 2 },
  },
  runtime: {
    runtime_class_name: "kata-qemu-cogs",
    handler: "kata-qemu",
    cri_runtime_type: "io.containerd.kata.v2",
    kata_version: "3.32.0",
    kata_archive_sha256: "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
    containerd_version: "2.2.1",
    qemu_version: "8.2.2",
    accelerator: "kvm",
    allow_tcg_fallback: false,
    allow_runc_fallback: false,
  },
} as const);

export const STAGE4_DISJOINT_SCHEDULING = deepFreeze({
  trusted: {
    required_node_selector: { "cogs.dev/node-domain": "trusted" },
    tolerations: [],
  },
  sandbox: {
    required_node_selector: {
      "cogs.dev/node-domain": "sandbox-kata",
      "cogs.dev/nested-virtualization": "enabled",
      "cogs.dev/sandbox-runtime": "kata-qemu-kvm",
    },
    tolerations: [{ key: "cogs.dev/sandbox", operator: "Equal", value: "kata", effect: "NoSchedule" }],
  },
  domains_disjoint: true,
} as const);

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
  return JSON.stringify(value);
}

function snapshotJson(value: unknown): JsonValue | null {
  let nodes = 0;
  const visit = (candidate: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) throw new TypeError("bounded JSON shape exceeded");
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) throw new TypeError("only safe integers are accepted");
      return candidate;
    }
    if (typeof candidate !== "object") throw new TypeError("non-JSON value");

    const prototype = Object.getPrototypeOf(candidate);
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const ownKeys = Reflect.ownKeys(candidate);
    if (ownKeys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");

    if (Array.isArray(candidate)) {
      if (prototype !== Array.prototype) throw new TypeError("non-plain array");
      const lengthDescriptor = descriptors.length;
      if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) throw new TypeError("invalid array");
      const length = lengthDescriptor.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_NODES)
        throw new TypeError("invalid array length");
      const expected = [...Array.from({ length }, (_, index) => String(index)), "length"];
      if (ownKeys.length !== expected.length || expected.some((key) => !ownKeys.includes(key))) {
        throw new TypeError("sparse or extended array");
      }
      return Array.from({ length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
          throw new TypeError("accessor or hidden array item");
        }
        return visit(descriptor.value, depth + 1);
      });
    }

    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("non-plain object");
    const output: JsonRecord = Object.create(null) as JsonRecord;
    for (const key of ownKeys as string[]) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
        throw new TypeError("accessor or hidden property");
      }
      output[key] = visit(descriptor.value, depth + 1);
    }
    return output;
  };

  try {
    return visit(value, 0);
  } catch {
    return null;
  }
}

function record(value: JsonValue | undefined): JsonRecord | null {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function exactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function same(left: JsonValue | undefined, right: JsonValue): boolean {
  return left !== undefined && canonicalJson(left) === canonicalJson(right);
}

function nodeImagePinState(value: JsonValue | undefined): "pinned" | "unresolved" | null {
  const image = record(value);
  if (image === null) return null;
  if (image.pin_state === "unresolved") {
    return exactKeys(image, ["ami_id", "kernel_release", "pin_state", "reason_code", "release"]) &&
      image.ami_id === null &&
      image.release === null &&
      image.kernel_release === null &&
      image.reason_code === "EKS_NODE_IMAGE_PIN_NOT_RECORDED"
      ? "unresolved"
      : null;
  }
  return image.pin_state === "pinned" &&
    exactKeys(image, ["ami_id", "kernel_release", "pin_state", "release"]) &&
    typeof image.ami_id === "string" &&
    AMI.test(image.ami_id) &&
    typeof image.release === "string" &&
    RELEASE.test(image.release) &&
    typeof image.kernel_release === "string" &&
    RELEASE.test(image.kernel_release)
    ? "pinned"
    : null;
}

function makeVerdict(
  status: Stage4NicStatus,
  reasonCode: Stage4NicReasonCode,
  digest: string | null,
  nicPin: boolean,
  imagePin: boolean,
  launchTemplateCapability: boolean,
): Stage4NicVerdict {
  return Object.freeze({
    version: "cogs.stage4-nic-sandbox-node-group-verdict/v1",
    authority: "local-static-nic-contract-classifier",
    campaign_authorized: false,
    cloud_execution_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    contract_sha256: digest,
    nic_source_pin_resolved: nicPin,
    node_image_pin_resolved: imagePin,
    launch_template_capability_resolved: launchTemplateCapability,
    status,
    reason_code: reasonCode,
  });
}

/**
 * Classifies one decoded, metadata-only local contract. It performs no I/O,
 * discovery, rendering, provider operation, or campaign authorization.
 */
export function evaluateStage4NicSandboxNodeGroupContract(input: unknown): Stage4NicVerdict {
  const snapshot = snapshotJson(input);
  const root = record(snapshot ?? undefined);
  if (root === null) return makeVerdict("reject-drift", "STAGE4_NIC_INVALID_SHAPE", null, false, false, false);
  const digest = createHash("sha256").update(canonicalJson(root), "utf8").digest("hex");
  if (!exactKeys(root, ROOT_KEYS)) {
    return makeVerdict("reject-drift", "STAGE4_NIC_INVALID_SHAPE", digest, false, false, false);
  }
  if (root.version !== CONTRACT_VERSION) {
    return makeVerdict("reject-drift", "STAGE4_NIC_INVALID_VERSION", digest, false, false, false);
  }
  if (root.authority !== "local-static-source-contract") {
    return makeVerdict("reject-drift", "STAGE4_NIC_INVALID_SHAPE", digest, false, false, false);
  }

  if (!same(root.nic_source, STAGE4_PINNED_NIC_SOURCE as unknown as JsonValue)) {
    return makeVerdict("reject-drift", "STAGE4_NIC_SOURCE_DRIFT", digest, false, false, false);
  }
  const imageState = nodeImagePinState(root.node_image);
  if (imageState === null) {
    return makeVerdict("reject-drift", "STAGE4_NODE_IMAGE_DRIFT", digest, true, false, false);
  }
  if (!same(root.sandbox_node_group, STAGE4_SANDBOX_NODE_GROUP as unknown as JsonValue)) {
    return makeVerdict("reject-drift", "STAGE4_NODE_GROUP_DRIFT", digest, true, imageState === "pinned", false);
  }
  if (!same(root.scheduling, STAGE4_DISJOINT_SCHEDULING as unknown as JsonValue)) {
    return makeVerdict("reject-drift", "STAGE4_SCHEDULING_DRIFT", digest, true, imageState === "pinned", false);
  }
  if (!same(root.nic_capability_assessment, STAGE4_NIC_CAPABILITY_ASSESSMENT as unknown as JsonValue)) {
    return makeVerdict("reject-drift", "STAGE4_NIC_SOURCE_DRIFT", digest, true, imageState === "pinned", false);
  }

  // The exact pinned NIC source was authenticated externally, but it cannot
  // carry the mandatory launch-template ID/version or nested CPU option.
  // This fixed source assessment takes precedence over the still-unresolved AMI.
  return makeVerdict(
    "blocked-missing-capability",
    "STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING",
    digest,
    true,
    imageState === "pinned",
    false,
  );
}
