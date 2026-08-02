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

type ArtifactRootInputs = Omit<CampaignBindings, "artifact_set_root_sha256">;

export type Stage4CampaignPlan = Readonly<{
  version: "cogs.stage4-campaign-plan/v1";
  authority: "local-static-campaign-plan-model";
  campaign_issue: Stage4CampaignIssue;
  campaign_id_sha256: string;
  execution_authorized: false;
  attempt: Readonly<{
    attempt_id_sha256: string;
    number: 1;
    maximum_attempts: 1;
    retry: "prohibited";
    approval_state: "absent";
  }>;
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
  campaign_id_sha256: string;
  attempt_id_sha256: string;
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
  | "STAGE4_CAMPAIGN_AUTHORITY_PROMOTION"
  | "STAGE4_CAMPAIGN_IDENTITY_MISMATCH"
  | "STAGE4_CAMPAIGN_BINDING_MISMATCH"
  | "STAGE4_CAMPAIGN_INVALID_TRANSITION"
  | "STAGE4_CAMPAIGN_EVIDENCE_REPLAY"
  | "STAGE4_CAMPAIGN_UNCERTAIN";

export type Stage4CampaignModelVerdict = Readonly<{
  version: "cogs.stage4-campaign-model-verdict/v1";
  authority: "local-static-campaign-state-classifier";
  campaign_issue: Stage4CampaignIssue | null;
  campaign_id_sha256: string | null;
  attempt_id_sha256: string | null;
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
const DIGEST = /^[0-9a-f]{64}$/u;
const MAX_NODES = 4096;
const MAX_DEPTH = 16;
const MAX_ARRAY_ITEMS = 32;
const MAX_PROPERTIES = 64;
const MAX_STRING_BYTES = 512;
const MAX_PROPERTY_KEY_BYTES = 128;
const MAX_CANONICAL_BYTES = 128 * 1024;
const ARTIFACT_ROOT_KEYS = Object.freeze([
  "approval_draft_sha256",
  "artifact_manifest_sha256",
  "campaign_profile_sha256",
  "offline_readiness_package_sha256",
  "source_inventory_sha256",
  "source_revision_sha256",
] as const);

function snapshotJson(input: unknown): JsonRecord | null {
  let nodes = 0;
  let aggregateBytes = 0;
  const consume = (bytes: number): void => {
    aggregateBytes += bytes;
    if (aggregateBytes > MAX_CANONICAL_BYTES) throw new TypeError("aggregate byte bound");
  };
  const visit = (value: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) throw new TypeError("bounded shape exceeded");
    if (((typeof value === "object" && value !== null) || typeof value === "function") && types.isProxy(value)) {
      throw new TypeError("proxy rejected");
    }
    if (value === null) {
      consume(4);
      return value;
    }
    if (typeof value === "boolean") {
      consume(value ? 4 : 5);
      return value;
    }
    if (typeof value === "string") {
      const bytes = Buffer.byteLength(value, "utf8");
      if (bytes > MAX_STRING_BYTES) throw new TypeError("string bound");
      consume(Buffer.byteLength(JSON.stringify(value), "utf8"));
      return value;
    }
    if (typeof value === "number" && Number.isSafeInteger(value)) {
      consume(Buffer.byteLength(JSON.stringify(value), "utf8"));
      return value;
    }
    if (typeof value !== "object") throw new TypeError("non-JSON value");

    const prototype = Object.getPrototypeOf(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
    if (keys.length > MAX_PROPERTIES + 1) throw new TypeError("property count bound");
    for (const key of keys as string[]) {
      if (Buffer.byteLength(key, "utf8") > MAX_PROPERTY_KEY_BYTES) throw new TypeError("property key bound");
    }

    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) throw new TypeError("array prototype rejected");
      const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor | undefined>;
      const lengthDescriptor = descriptors.length;
      if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) throw new TypeError("array length");
      const length = lengthDescriptor.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_ARRAY_ITEMS) throw new TypeError("array bound");
      const expected = [...Array.from({ length }, (_, index) => String(index)), "length"];
      if (keys.length !== expected.length || expected.some((key) => !keys.includes(key))) {
        throw new TypeError("sparse or extended array");
      }
      consume(2 + Math.max(0, length - 1));
      return Array.from({ length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !("value" in descriptor)) throw new TypeError("array accessor");
        return visit(descriptor.value, depth + 1);
      });
    }

    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("inherited properties rejected");
    for (const key in value) {
      if (!Object.hasOwn(value, key)) throw new TypeError("inherited enumerable property rejected");
    }
    if (keys.length > MAX_PROPERTIES) throw new TypeError("property count bound");
    consume(2 + Math.max(0, keys.length - 1));
    for (const key of keys as string[]) consume(Buffer.byteLength(JSON.stringify(key), "utf8") + 1);
    const descriptors = Object.getOwnPropertyDescriptors(value);
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

function exactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareCodePoints);
  const wanted = [...expected].sort(compareCodePoints);
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

/** Hashes only a strict, safely snapshotted six-digest artifact binding. */
export function stage4CampaignArtifactSetRoot(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  if (
    snapshot === null ||
    !exactKeys(snapshot, ARTIFACT_ROOT_KEYS) ||
    !ARTIFACT_ROOT_KEYS.every((key) => typeof snapshot[key] === "string" && DIGEST.test(snapshot[key]))
  ) {
    return null;
  }
  return semanticDigest("cogs.stage4/campaign-artifact-set/v1", snapshot);
}

export function stage4CampaignIdentitySha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  if (
    snapshot === null ||
    !exactKeys(snapshot, ["artifact_set_root_sha256", "campaign_issue"]) ||
    typeof snapshot.campaign_issue !== "string" ||
    !(snapshot.campaign_issue in STAGE4_CAMPAIGN_QUALIFICATION_STEPS) ||
    typeof snapshot.artifact_set_root_sha256 !== "string" ||
    !DIGEST.test(snapshot.artifact_set_root_sha256)
  ) {
    return null;
  }
  return semanticDigest("cogs.stage4/campaign-identity/v1", snapshot);
}

export function stage4CampaignAttemptIdentitySha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  if (
    snapshot === null ||
    !exactKeys(snapshot, ["approval_draft_sha256", "attempt_number", "campaign_id_sha256"]) ||
    snapshot.attempt_number !== 1 ||
    typeof snapshot.campaign_id_sha256 !== "string" ||
    !DIGEST.test(snapshot.campaign_id_sha256) ||
    typeof snapshot.approval_draft_sha256 !== "string" ||
    !DIGEST.test(snapshot.approval_draft_sha256)
  ) {
    return null;
  }
  return semanticDigest("cogs.stage4/campaign-attempt-identity/v1", snapshot);
}

function planAuthorityPromoted(plan: JsonRecord): boolean {
  const attempt = plan.attempt;
  return (
    plan.authority !== "local-static-campaign-plan-model" ||
    plan.execution_authorized !== false ||
    (attempt !== null &&
      typeof attempt === "object" &&
      !Array.isArray(attempt) &&
      (attempt.number !== 1 ||
        attempt.maximum_attempts !== 1 ||
        attempt.retry !== "prohibited" ||
        attempt.approval_state !== "absent"))
  );
}

function evidenceAuthorityPromoted(evidence: JsonRecord): boolean {
  return (
    evidence.authority !== "local-static-campaign-evidence-model" ||
    evidence.execution_authorized !== false ||
    evidence.attempt_number !== 1 ||
    evidence.retry_count !== 0
  );
}

function planIdentityFailure(
  plan: Stage4CampaignPlan,
): "STAGE4_CAMPAIGN_BINDING_MISMATCH" | "STAGE4_CAMPAIGN_IDENTITY_MISMATCH" | null {
  const rootInputs: ArtifactRootInputs = {
    source_revision_sha256: plan.bindings.source_revision_sha256,
    source_inventory_sha256: plan.bindings.source_inventory_sha256,
    offline_readiness_package_sha256: plan.bindings.offline_readiness_package_sha256,
    approval_draft_sha256: plan.bindings.approval_draft_sha256,
    campaign_profile_sha256: plan.bindings.campaign_profile_sha256,
    artifact_manifest_sha256: plan.bindings.artifact_manifest_sha256,
  };
  const artifactRoot = stage4CampaignArtifactSetRoot(rootInputs);
  if (artifactRoot === null || artifactRoot !== plan.bindings.artifact_set_root_sha256) {
    return "STAGE4_CAMPAIGN_BINDING_MISMATCH";
  }
  const campaignId = stage4CampaignIdentitySha256({
    campaign_issue: plan.campaign_issue,
    artifact_set_root_sha256: artifactRoot,
  });
  if (campaignId === null || campaignId !== plan.campaign_id_sha256) {
    return "STAGE4_CAMPAIGN_IDENTITY_MISMATCH";
  }
  const attemptId = stage4CampaignAttemptIdentitySha256({
    campaign_id_sha256: campaignId,
    attempt_number: plan.attempt.number,
    approval_draft_sha256: plan.bindings.approval_draft_sha256,
  });
  return attemptId === plan.attempt.attempt_id_sha256 ? null : "STAGE4_CAMPAIGN_IDENTITY_MISMATCH";
}

function exactPlanSteps(plan: Stage4CampaignPlan): boolean {
  const expected = STAGE4_CAMPAIGN_QUALIFICATION_STEPS[plan.campaign_issue];
  return (
    plan.evidence_policy.max_events === expected.length + STAGE4_CAMPAIGN_TERMINAL_ORDER.length &&
    plan.qualification_steps.length === expected.length &&
    plan.qualification_steps.every((row, index) => row.id === expected[index])
  );
}

export function stage4CampaignPlanSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  if (
    snapshot === null ||
    snapshot.version !== "cogs.stage4-campaign-plan/v1" ||
    planAuthorityPromoted(snapshot) ||
    !validatePlan(snapshot) ||
    planIdentityFailure(snapshot) !== null ||
    !exactPlanSteps(snapshot)
  ) {
    return null;
  }
  return semanticDigest("cogs.stage4/campaign-plan/v1", snapshot as unknown as JsonValue);
}

export function stage4CampaignEvidenceSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  if (
    snapshot === null ||
    snapshot.version !== "cogs.stage4-campaign-evidence/v1" ||
    evidenceAuthorityPromoted(snapshot) ||
    !validateEvidence(snapshot)
  ) {
    return null;
  }
  return semanticDigest("cogs.stage4/campaign-evidence/v1", snapshot as unknown as JsonValue);
}

function rejected(reason: Stage4CampaignModelReason): Stage4CampaignModelVerdict {
  return Object.freeze({
    version: "cogs.stage4-campaign-model-verdict/v1",
    authority: "local-static-campaign-state-classifier",
    campaign_issue: null,
    campaign_id_sha256: null,
    attempt_id_sha256: null,
    plan_valid: false,
    evidence_valid: false,
    execution_authorized: false,
    campaign_execution_observed: false,
    provider_truth_observed: false,
    kubernetes_truth_observed: false,
    cleanup_observed: false,
    zero_inventory_claimed: false,
    retry_authorized: false,
    stage4_exit_satisfied: false,
    plan_sha256: null,
    evidence_sha256: null,
    status: "preserve-uncertain",
    next_phase: null,
    reason_code: reason,
  });
}

function accepted(
  reason: Stage4CampaignModelReason,
  plan: Stage4CampaignPlan,
  planSha256: string,
  evidenceSha256: string,
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
    campaign_issue: plan.campaign_issue,
    campaign_id_sha256: plan.campaign_id_sha256,
    attempt_id_sha256: plan.attempt.attempt_id_sha256,
    plan_valid: true,
    evidence_valid: true,
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
    status: reason === "STAGE4_CAMPAIGN_UNCERTAIN" ? "preserve-uncertain" : (statuses[reason] ?? "preserve-uncertain"),
    next_phase: nextPhase,
    reason_code: reason,
  });
}

function expectedProducer(phase: string): Stage4CampaignEvent["producer_class"] {
  return phase === "independent-inventory" ? "independent-inventory-observer" : "caller-claimed-future-evidence";
}

/**
 * Classifies a bounded plan and claimed-evidence sequence. Authority and exact
 * campaign/attempt identity are admitted before any semantic document digest.
 * Rejected, replayed, mixed, or malformed evidence is never hashed into a verdict.
 */
export function classifyStage4CampaignModel(planInput: unknown, evidenceInput: unknown): Stage4CampaignModelVerdict {
  const planSnapshot = snapshotJson(planInput);
  if (planSnapshot === null || planSnapshot.version !== "cogs.stage4-campaign-plan/v1") {
    return rejected("STAGE4_CAMPAIGN_INVALID_SHAPE");
  }
  if (planAuthorityPromoted(planSnapshot)) return rejected("STAGE4_CAMPAIGN_AUTHORITY_PROMOTION");
  if (!validatePlan(planSnapshot)) return rejected("STAGE4_CAMPAIGN_INVALID_SHAPE");
  const plan = planSnapshot;
  const identityFailure = planIdentityFailure(plan);
  if (identityFailure !== null) return rejected(identityFailure);
  if (!exactPlanSteps(plan)) return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
  const planSha256 = semanticDigest("cogs.stage4/campaign-plan/v1", plan as unknown as JsonValue);

  const evidenceSnapshot = snapshotJson(evidenceInput);
  if (evidenceSnapshot === null || evidenceSnapshot.version !== "cogs.stage4-campaign-evidence/v1") {
    return rejected("STAGE4_CAMPAIGN_INVALID_SHAPE");
  }
  if (evidenceAuthorityPromoted(evidenceSnapshot)) return rejected("STAGE4_CAMPAIGN_AUTHORITY_PROMOTION");
  if (
    evidenceSnapshot.campaign_issue !== plan.campaign_issue ||
    evidenceSnapshot.campaign_id_sha256 !== plan.campaign_id_sha256 ||
    evidenceSnapshot.attempt_id_sha256 !== plan.attempt.attempt_id_sha256 ||
    evidenceSnapshot.attempt_number !== plan.attempt.number
  ) {
    return rejected("STAGE4_CAMPAIGN_IDENTITY_MISMATCH");
  }
  if (!validateEvidence(evidenceSnapshot)) return rejected("STAGE4_CAMPAIGN_INVALID_SHAPE");
  const evidence = evidenceSnapshot;
  if (
    evidence.plan_sha256 !== planSha256 ||
    evidence.artifact_set_root_sha256 !== plan.bindings.artifact_set_root_sha256
  ) {
    return rejected("STAGE4_CAMPAIGN_BINDING_MISMATCH");
  }
  if (evidence.events.length > plan.evidence_policy.max_events) {
    return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
  }

  const qualification = STAGE4_CAMPAIGN_QUALIFICATION_STEPS[plan.campaign_issue];
  let qualificationIndex = 0;
  let expectedPhase: string = qualification[0] as string;
  const terminalSeen = new Set<string>();
  let uncertaintySeen = false;
  const digests = new Set<string>([
    planSha256,
    plan.campaign_id_sha256,
    plan.attempt.attempt_id_sha256,
    ...Object.values(plan.bindings),
  ]);

  for (const event of evidence.events) {
    if (
      expectedPhase === "complete" ||
      event.phase !== expectedPhase ||
      event.producer_class !== expectedProducer(event.phase)
    ) {
      return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
    }
    if (STAGE4_CAMPAIGN_TERMINAL_ORDER.includes(event.phase as (typeof STAGE4_CAMPAIGN_TERMINAL_ORDER)[number])) {
      if (terminalSeen.has(event.phase)) return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
      terminalSeen.add(event.phase);
    }
    const eventDigest = event.evidence_sha256 ?? event.uncertainty_artifact_sha256;
    if (eventDigest === undefined || digests.has(eventDigest)) return rejected("STAGE4_CAMPAIGN_EVIDENCE_REPLAY");
    digests.add(eventDigest);

    if (event.outcome === "uncertain") uncertaintySeen = true;

    if (expectedPhase === "independent-inventory") {
      if (!uncertaintySeen && event.outcome !== "claimed-satisfied") {
        return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
      }
      expectedPhase = "complete";
      continue;
    }
    if (expectedPhase === "destroy") {
      if (!uncertaintySeen && event.outcome !== "claimed-satisfied") {
        return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
      }
      expectedPhase = "independent-inventory";
      continue;
    }
    if (expectedPhase === "stop") {
      if (!uncertaintySeen && event.outcome !== "claimed-satisfied") {
        return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
      }
      expectedPhase = "destroy";
      continue;
    }
    if (uncertaintySeen) {
      expectedPhase = "stop";
      continue;
    }
    if (event.outcome === "claimed-failed") {
      expectedPhase = "stop";
      continue;
    }
    qualificationIndex += 1;
    expectedPhase = qualification[qualificationIndex] ?? "stop";
  }

  const evidenceSha256 = semanticDigest("cogs.stage4/campaign-evidence/v1", evidence as unknown as JsonValue);
  if (uncertaintySeen) {
    return accepted(
      "STAGE4_CAMPAIGN_UNCERTAIN",
      plan,
      planSha256,
      evidenceSha256,
      expectedPhase === "complete" ? null : expectedPhase,
    );
  }
  if (expectedPhase === "complete") {
    if (terminalSeen.size !== STAGE4_CAMPAIGN_TERMINAL_ORDER.length) {
      return rejected("STAGE4_CAMPAIGN_INVALID_TRANSITION");
    }
    return accepted("STAGE4_CAMPAIGN_MODEL_ORDER_COMPLETE_BLOCKED", plan, planSha256, evidenceSha256, null);
  }
  if (expectedPhase === "stop") {
    return accepted("STAGE4_CAMPAIGN_STOP_REQUIRED", plan, planSha256, evidenceSha256, "stop");
  }
  if (expectedPhase === "destroy") {
    return accepted("STAGE4_CAMPAIGN_DESTROY_REQUIRED", plan, planSha256, evidenceSha256, "destroy");
  }
  if (expectedPhase === "independent-inventory") {
    return accepted(
      "STAGE4_CAMPAIGN_INDEPENDENT_INVENTORY_REQUIRED",
      plan,
      planSha256,
      evidenceSha256,
      "independent-inventory",
    );
  }
  return accepted("STAGE4_CAMPAIGN_AWAITING_CLAIMED_EVIDENCE", plan, planSha256, evidenceSha256, expectedPhase);
}

/** Appends exactly one metadata-only event when it matches the derived next phase. */
export function advanceStage4CampaignModel(
  planInput: unknown,
  evidenceInput: unknown,
  eventInput: unknown,
): Stage4CampaignEvidence | null {
  const before = classifyStage4CampaignModel(planInput, evidenceInput);
  if (!before.plan_valid || !before.evidence_valid || before.next_phase === null) {
    return null;
  }
  const evidence = snapshotJson(evidenceInput);
  const event = snapshotJson(eventInput);
  if (evidence === null || event === null || !Array.isArray(evidence.events)) return null;
  const candidate = { ...evidence, events: [...evidence.events, event] };
  if (!validateEvidence(candidate)) return null;
  const after = classifyStage4CampaignModel(planInput, candidate);
  if (!after.plan_valid || !after.evidence_valid) return null;
  return deepFreeze(structuredClone(candidate));
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
