import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { types } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const planSchema = require("../schemas/stage4-campaign-plan-v1.json") as object;
const evidenceSchema = require("../schemas/stage4-campaign-evidence-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validatePlan = ajv.compile(planSchema) as ValidateFunction<Stage4CampaignPlan>;
const validateEvidence = ajv.compile(evidenceSchema) as ValidateFunction<Stage4CampaignEvidence>;

export const STAGE4_CAMPAIGN_QUALIFICATION_STEPS = Object.freeze({
  "S4-08/#359": Object.freeze([
    "topology.source-render-object-binding",
    "topology.launch-template-nested-kvm",
    "kata.active-kvm-distinct-guest-no-fallback",
    "storage.ebs-workspace-session-lifecycle",
    "storage.exclusive-writer-forced-loss",
    "cleanup.runtime-and-object-behavior",
  ]),
  "S4-09/#360": Object.freeze([
    "guest-root.real-dependencies-admitted",
    "guest-root.ipv4-ipv6-udp-quic-dns-denial",
    "guest-root.api-metadata-admin-cross-session-storage-denial",
    "guest-root.no-kubernetes-cloud-openbao-integration-model-or-ca-key-material",
    "functional.stage3-kata-ebs-openbao-otlp",
    "functional.api-key-samples-separately-authorized",
  ]),
  "S4-10/#361": Object.freeze([
    "performance.startup-p50-p95-p99",
    "performance.first-tool",
    "performance.storage-attach",
    "performance.cold-pulls-and-scale",
    "performance.idle-overhead",
    "performance.git-and-build",
    "performance.proxy-overhead",
    "performance.recycle-duration",
    "performance.startup-under-30s-or-reviewed-exception",
    "recovery.worker-failure",
    "recovery.sandbox-failure",
    "recovery.proxy-failure",
    "recovery.node-failure",
    "recovery.openbao-failure",
    "recovery.otlp-failure",
    "recovery.storage-failure",
    "recovery.audit-wal-failure",
    "recovery.policy-failure",
    "recovery.recycle-no-prompt-replay",
    "cost.capacity-observed-no-support-extrapolation",
  ]),
} as const);

export const STAGE4_CAMPAIGN_TERMINAL_ORDER = Object.freeze(["stop", "destroy", "independent-inventory"] as const);
export type Stage4CampaignIssue = keyof typeof STAGE4_CAMPAIGN_QUALIFICATION_STEPS;
export type Stage4CampaignOutcome = "claimed-satisfied" | "claimed-failed" | "uncertain";

type CampaignBindings = Readonly<{
  source_revision_sha256: string;
  source_inventory_sha256: string;
  offline_readiness_package_sha256: string;
  approval_draft_sha256: string;
  campaign_profile_sha256: string;
  artifact_manifest_sha256: string;
  artifact_set_root_sha256: string;
}>;

export type Stage4CampaignPlan = Readonly<{
  version: "cogs.stage4-campaign-plan/v1";
  authority: "local-static-campaign-plan-model";
  campaign_issue: Stage4CampaignIssue;
  execution_authorized: false;
  attempt: Readonly<{ number: 1; maximum_attempts: 1; retry: "prohibited"; approval_state: "absent" }>;
  bindings: CampaignBindings;
  qualification_steps: readonly Readonly<{
    id: string;
    state: "unexecuted";
    evidence_class: "future-digest-only-claim";
  }>[];
  terminal_order: readonly ["stop", "destroy", "independent-inventory"];
  evidence_policy: Readonly<{
    metadata_only: true;
    digest_only: true;
    uncertainty_is_sticky: true;
    failure_skips_to_stop: true;
    inventory_must_be_independent: true;
    max_events: number;
  }>;
  prohibited_surfaces: readonly string[];
}>;

export type Stage4CampaignEvent = Readonly<{
  phase: string;
  outcome: Stage4CampaignOutcome;
  producer_class: "caller-claimed-future-evidence" | "independent-inventory-observer";
  evidence_sha256?: string;
  uncertainty_artifact_sha256?: string;
}>;

export type Stage4CampaignEvidence = Readonly<{
  version: "cogs.stage4-campaign-evidence/v1";
  authority: "local-static-campaign-evidence-model";
  campaign_issue: Stage4CampaignIssue;
  execution_authorized: false;
  attempt_number: 1;
  retry_count: 0;
  plan_sha256: string;
  artifact_set_root_sha256: string;
  events: readonly Stage4CampaignEvent[];
}>;

export type Stage4CampaignModelReason =
  | "STAGE4_CAMPAIGN_AWAITING_CLAIMED_EVIDENCE"
  | "STAGE4_CAMPAIGN_STOP_REQUIRED"
  | "STAGE4_CAMPAIGN_DESTROY_REQUIRED"
  | "STAGE4_CAMPAIGN_INDEPENDENT_INVENTORY_REQUIRED"
  | "STAGE4_CAMPAIGN_MODEL_ORDER_COMPLETE_BLOCKED"
  | "STAGE4_CAMPAIGN_INVALID_SHAPE"
  | "STAGE4_CAMPAIGN_BINDING_MISMATCH"
  | "STAGE4_CAMPAIGN_INVALID_TRANSITION"
  | "STAGE4_CAMPAIGN_EVIDENCE_REPLAY"
  | "STAGE4_CAMPAIGN_UNCERTAIN";

export type Stage4CampaignModelVerdict = Readonly<{
  version: "cogs.stage4-campaign-model-verdict/v1";
  authority: "local-static-campaign-state-classifier";
  plan_valid: boolean;
  evidence_valid: boolean;
  execution_authorized: false;
  campaign_execution_observed: false;
  provider_truth_observed: false;
  kubernetes_truth_observed: false;
  cleanup_observed: false;
  zero_inventory_claimed: false;
  retry_authorized: false;
  stage4_exit_satisfied: false;
  plan_sha256: string | null;
  evidence_sha256: string | null;
  status:
    | "awaiting-claimed-evidence"
    | "stop-required"
    | "destroy-required"
    | "independent-inventory-required"
    | "model-order-complete-blocked"
    | "preserve-uncertain";
  next_phase: string | null;
  reason_code: Stage4CampaignModelReason;
}>;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };
const MAX_NODES = 4096;
const MAX_DEPTH = 16;

function snapshotJson(input: unknown): JsonRecord | null {
  let nodes = 0;
  const visit = (value: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) throw new TypeError("bounded shape exceeded");
    if (((typeof value === "object" && value !== null) || typeof value === "function") && types.isProxy(value)) {
      throw new TypeError("proxy rejected");
    }
    if (value === null || typeof value === "boolean" || typeof value === "string") {
      if (typeof value === "string" && Buffer.byteLength(value, "utf8") > 2048) throw new TypeError("string bound");
      return value;
    }
    if (typeof value === "number" && Number.isSafeInteger(value)) return value;
    if (typeof value !== "object") throw new TypeError("non-JSON value");
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype || value.length > 64) throw new TypeError("array bound");
      const expected = [...Array.from({ length: value.length }, (_, index) => String(index)), "length"];
      if (keys.length !== expected.length || expected.some((key) => !keys.includes(key))) {
        throw new TypeError("sparse or extended array");
      }
      return Array.from({ length: value.length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !("value" in descriptor)) throw new TypeError("array accessor");
        return visit(descriptor.value, depth + 1);
      });
    }
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("prototype rejected");
    if (keys.length > 64) throw new TypeError("property bound");
    const output: JsonRecord = Object.create(null) as JsonRecord;
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (!descriptor?.enumerable || !("value" in descriptor)) throw new TypeError("accessor rejected");
      output[key] = visit(descriptor.value, depth + 1);
    }
    return output;
  };
  try {
    const value = visit(input, 0);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
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
    return `{${Object.keys(value)
      .sort(compareCodePoints)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function semanticDigest(domain: string, input: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(input), "utf8")
    .digest("hex");
}

export function stage4CampaignArtifactSetRoot(bindings: Omit<CampaignBindings, "artifact_set_root_sha256">): string {
  return semanticDigest("cogs.stage4/campaign-artifact-set/v1", bindings as unknown as JsonValue);
}

export function stage4CampaignPlanSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  return snapshot === null ? null : semanticDigest("cogs.stage4/campaign-plan/v1", snapshot);
}

export function stage4CampaignEvidenceSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  return snapshot === null ? null : semanticDigest("cogs.stage4/campaign-evidence/v1", snapshot);
}

function makeVerdict(
  reason: Stage4CampaignModelReason,
  planValid: boolean,
  evidenceValid: boolean,
  planSha256: string | null,
  evidenceSha256: string | null,
  nextPhase: string | null,
): Stage4CampaignModelVerdict {
  const statuses: Partial<Record<Stage4CampaignModelReason, Stage4CampaignModelVerdict["status"]>> = {
    STAGE4_CAMPAIGN_AWAITING_CLAIMED_EVIDENCE: "awaiting-claimed-evidence",
    STAGE4_CAMPAIGN_STOP_REQUIRED: "stop-required",
    STAGE4_CAMPAIGN_DESTROY_REQUIRED: "destroy-required",
    STAGE4_CAMPAIGN_INDEPENDENT_INVENTORY_REQUIRED: "independent-inventory-required",
    STAGE4_CAMPAIGN_MODEL_ORDER_COMPLETE_BLOCKED: "model-order-complete-blocked",
  };
  return Object.freeze({
    version: "cogs.stage4-campaign-model-verdict/v1",
    authority: "local-static-campaign-state-classifier",
    plan_valid: planValid,
    evidence_valid: evidenceValid,
    execution_authorized: false,
    campaign_execution_observed: false,
    provider_truth_observed: false,
    kubernetes_truth_observed: false,
    cleanup_observed: false,
    zero_inventory_claimed: false,
    retry_authorized: false,
    stage4_exit_satisfied: false,
    plan_sha256: planSha256,
    evidence_sha256: evidenceSha256,
    status: statuses[reason] ?? "preserve-uncertain",
    next_phase: nextPhase,
    reason_code: reason,
  });
}

function expectedProducer(phase: string): Stage4CampaignEvent["producer_class"] {
  return phase === "independent-inventory" ? "independent-inventory-observer" : "caller-claimed-future-evidence";
}

/**
 * Classifies a bounded plan and claimed-evidence sequence. The model has no
 * command, executor, callback, provider, Kubernetes, retry, or discovery surface.
 */
export function classifyStage4CampaignModel(planInput: unknown, evidenceInput: unknown): Stage4CampaignModelVerdict {
  const planSnapshot = snapshotJson(planInput);
  const evidenceSnapshot = snapshotJson(evidenceInput);
  if (planSnapshot === null || !validatePlan(planSnapshot)) {
    return makeVerdict("STAGE4_CAMPAIGN_INVALID_SHAPE", false, false, null, null, null);
  }
  const plan = planSnapshot;
  const planSha256 = stage4CampaignPlanSha256(plan);
  if (planSha256 === null) return makeVerdict("STAGE4_CAMPAIGN_INVALID_SHAPE", false, false, null, null, null);

  const { artifact_set_root_sha256: _root, ...rootInputs } = plan.bindings;
  if (stage4CampaignArtifactSetRoot(rootInputs) !== plan.bindings.artifact_set_root_sha256) {
    return makeVerdict("STAGE4_CAMPAIGN_BINDING_MISMATCH", false, false, planSha256, null, null);
  }
  if (evidenceSnapshot === null || !validateEvidence(evidenceSnapshot)) {
    return makeVerdict("STAGE4_CAMPAIGN_INVALID_SHAPE", true, false, planSha256, null, null);
  }
  const evidence = evidenceSnapshot;
  const evidenceSha256 = stage4CampaignEvidenceSha256(evidence);
  if (
    evidence.campaign_issue !== plan.campaign_issue ||
    evidence.plan_sha256 !== planSha256 ||
    evidence.artifact_set_root_sha256 !== plan.bindings.artifact_set_root_sha256
  ) {
    return makeVerdict("STAGE4_CAMPAIGN_BINDING_MISMATCH", true, false, planSha256, evidenceSha256, null);
  }

  const qualification = STAGE4_CAMPAIGN_QUALIFICATION_STEPS[plan.campaign_issue];
  let qualificationIndex = 0;
  let expectedPhase: string = qualification[0] as string;
  let qualificationFailed = false;
  const digests = new Set<string>([
    planSha256,
    plan.bindings.artifact_set_root_sha256,
    ...Object.values(plan.bindings),
  ]);

  for (const event of evidence.events) {
    if (event.phase !== expectedPhase || event.producer_class !== expectedProducer(event.phase)) {
      return makeVerdict("STAGE4_CAMPAIGN_INVALID_TRANSITION", true, false, planSha256, evidenceSha256, expectedPhase);
    }
    const digest = event.evidence_sha256 ?? event.uncertainty_artifact_sha256;
    if (digest === undefined || digests.has(digest)) {
      return makeVerdict("STAGE4_CAMPAIGN_EVIDENCE_REPLAY", true, false, planSha256, evidenceSha256, expectedPhase);
    }
    digests.add(digest);

    if (event.outcome === "uncertain") {
      const requiredPhase = STAGE4_CAMPAIGN_TERMINAL_ORDER.includes(
        expectedPhase as (typeof STAGE4_CAMPAIGN_TERMINAL_ORDER)[number],
      )
        ? expectedPhase
        : "stop";
      return makeVerdict("STAGE4_CAMPAIGN_UNCERTAIN", true, true, planSha256, evidenceSha256, requiredPhase);
    }
    if (expectedPhase === "independent-inventory") {
      if (event.outcome !== "claimed-satisfied") {
        return makeVerdict("STAGE4_CAMPAIGN_UNCERTAIN", true, true, planSha256, evidenceSha256, expectedPhase);
      }
      expectedPhase = "complete";
      continue;
    }
    if (expectedPhase === "destroy") {
      if (event.outcome !== "claimed-satisfied") {
        return makeVerdict("STAGE4_CAMPAIGN_UNCERTAIN", true, true, planSha256, evidenceSha256, expectedPhase);
      }
      expectedPhase = "independent-inventory";
      continue;
    }
    if (expectedPhase === "stop") {
      if (event.outcome !== "claimed-satisfied") {
        return makeVerdict("STAGE4_CAMPAIGN_UNCERTAIN", true, true, planSha256, evidenceSha256, expectedPhase);
      }
      expectedPhase = "destroy";
      continue;
    }

    if (event.outcome === "claimed-failed") {
      qualificationFailed = true;
      expectedPhase = "stop";
      continue;
    }
    qualificationIndex += 1;
    expectedPhase = qualification[qualificationIndex] ?? "stop";
  }

  if (expectedPhase === "complete") {
    return makeVerdict("STAGE4_CAMPAIGN_MODEL_ORDER_COMPLETE_BLOCKED", true, true, planSha256, evidenceSha256, null);
  }
  if (expectedPhase === "stop") {
    return makeVerdict("STAGE4_CAMPAIGN_STOP_REQUIRED", true, true, planSha256, evidenceSha256, "stop");
  }
  if (expectedPhase === "destroy") {
    return makeVerdict("STAGE4_CAMPAIGN_DESTROY_REQUIRED", true, true, planSha256, evidenceSha256, "destroy");
  }
  if (expectedPhase === "independent-inventory") {
    return makeVerdict(
      "STAGE4_CAMPAIGN_INDEPENDENT_INVENTORY_REQUIRED",
      true,
      true,
      planSha256,
      evidenceSha256,
      "independent-inventory",
    );
  }
  return makeVerdict(
    qualificationFailed ? "STAGE4_CAMPAIGN_STOP_REQUIRED" : "STAGE4_CAMPAIGN_AWAITING_CLAIMED_EVIDENCE",
    true,
    true,
    planSha256,
    evidenceSha256,
    expectedPhase,
  );
}

/** Appends exactly one metadata-only event when it matches the derived next phase. */
export function advanceStage4CampaignModel(
  planInput: unknown,
  evidenceInput: unknown,
  eventInput: unknown,
): Stage4CampaignEvidence | null {
  const before = classifyStage4CampaignModel(planInput, evidenceInput);
  if (
    !before.plan_valid ||
    !before.evidence_valid ||
    before.status === "preserve-uncertain" ||
    before.next_phase === null
  ) {
    return null;
  }
  const evidence = snapshotJson(evidenceInput);
  const event = snapshotJson(eventInput);
  if (
    evidence === null ||
    event === null ||
    !validateEvidence({ ...evidence, events: [...(evidence.events as unknown[]), event] })
  ) {
    return null;
  }
  const candidate = {
    ...evidence,
    events: [...(evidence.events as unknown[]), event],
  } as unknown as Stage4CampaignEvidence;
  const after = classifyStage4CampaignModel(planInput, candidate);
  if (
    after.reason_code === "STAGE4_CAMPAIGN_INVALID_TRANSITION" ||
    after.reason_code === "STAGE4_CAMPAIGN_EVIDENCE_REPLAY"
  ) {
    return null;
  }
  return deepFreeze(structuredClone(candidate));
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
