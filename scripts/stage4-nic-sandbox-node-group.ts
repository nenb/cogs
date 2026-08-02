import { createHash } from "node:crypto";

export const STAGE4_NIC_V2_REASON_CODES = Object.freeze([
  "STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING",
  "STAGE4_NIC_INVALID_SHAPE",
  "STAGE4_NIC_INVALID_VERSION",
  "STAGE4_NIC_SOURCE_DRIFT",
] as const);

export type Stage4NicV2ReasonCode = (typeof STAGE4_NIC_V2_REASON_CODES)[number];
export type Stage4NicV2Verdict = Readonly<{
  version: "cogs.stage4-nic-sandbox-node-group-verdict/v2";
  authority: "local-static-personal-fork-source-classifier";
  campaign_authorized: false;
  cloud_execution_observed: false;
  provider_truth_observed: false;
  launch_template_contents_observed: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  contract_sha256: string | null;
  nic_source_pin_resolved: boolean;
  node_image_pin_resolved: false;
  launch_template_selection_capability_resolved: boolean;
  status: "source-capability-satisfied-local-static" | "reject-drift";
  reason_code: Stage4NicV2ReasonCode;
}>;

const CONTRACT_VERSION = "cogs.stage4-nic-sandbox-node-group-contract/v2";
const CONTRACT_AUTHORITY = "local-static-personal-fork-source-contract";
const EXPECTED_CONTRACT_SHA256 = "5dfc1bb269868daf536598d3a80e9c4dfee51793ce3f391b3d5dc1ee753cbb29";
const MAX_DEPTH = 20;
const MAX_NODES = 1024;

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };

function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const b = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function canonical(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonical(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function snapshot(value: unknown): JsonValue | null {
  let nodes = 0;
  const visit = (candidate: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) throw new TypeError("bounded JSON shape exceeded");
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) throw new TypeError("non-integer number");
      return candidate;
    }
    if (typeof candidate !== "object") throw new TypeError("non-JSON value");
    const prototype = Object.getPrototypeOf(candidate);
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const keys = Reflect.ownKeys(candidate);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
    if (Array.isArray(candidate)) {
      if (prototype !== Array.prototype) throw new TypeError("non-plain array");
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_NODES) throw new TypeError("array bound");
      const expected = [...Array.from({ length }, (_, index) => String(index)), "length"];
      if (keys.length !== expected.length || expected.some((key) => !keys.includes(key)))
        throw new TypeError("array shape");
      return Array.from({ length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
          throw new TypeError("array accessor");
        return visit(descriptor.value, depth + 1);
      });
    }
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("non-plain object");
    const output: JsonRecord = Object.create(null) as JsonRecord;
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
        throw new TypeError("object accessor");
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

function reject(reason: Stage4NicV2ReasonCode, digest: string | null): Stage4NicV2Verdict {
  return Object.freeze({
    version: "cogs.stage4-nic-sandbox-node-group-verdict/v2",
    authority: "local-static-personal-fork-source-classifier",
    campaign_authorized: false,
    cloud_execution_observed: false,
    provider_truth_observed: false,
    launch_template_contents_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    contract_sha256: digest,
    nic_source_pin_resolved: false,
    node_image_pin_resolved: false,
    launch_template_selection_capability_resolved: false,
    status: "reject-drift",
    reason_code: reason,
  });
}

/** Pure source-capability classification. It performs no I/O, rendering, provider call, or observation. */
export function evaluateStage4NicSandboxNodeGroupContract(input: unknown): Stage4NicV2Verdict {
  const captured = snapshot(input);
  if (captured === null || Array.isArray(captured) || typeof captured !== "object") {
    return reject("STAGE4_NIC_INVALID_SHAPE", null);
  }
  const bytes = canonical(captured);
  const digest = createHash("sha256").update(bytes, "utf8").digest("hex");
  if (captured.version !== CONTRACT_VERSION) return reject("STAGE4_NIC_INVALID_VERSION", digest);
  if (captured.authority !== CONTRACT_AUTHORITY) return reject("STAGE4_NIC_INVALID_SHAPE", digest);
  if (digest !== EXPECTED_CONTRACT_SHA256) return reject("STAGE4_NIC_SOURCE_DRIFT", digest);
  return Object.freeze({
    version: "cogs.stage4-nic-sandbox-node-group-verdict/v2",
    authority: "local-static-personal-fork-source-classifier",
    campaign_authorized: false,
    cloud_execution_observed: false,
    provider_truth_observed: false,
    launch_template_contents_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    contract_sha256: digest,
    nic_source_pin_resolved: true,
    node_image_pin_resolved: false,
    launch_template_selection_capability_resolved: true,
    status: "source-capability-satisfied-local-static",
    reason_code: "STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING",
  });
}
