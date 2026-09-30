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

/* S4-08 is a provider-free ordering model over caller-supplied JSON fixtures. */
export const STAGE4_S408_LIFECYCLE_PHASES = Object.freeze([
  "source",
  "discovery",
  "saved-plan",
  "approval-check",
  "apply",
  "stop",
  "destroy",
  "custody-inventory",
  "retained-state-retirement",
  "final-inventory",
] as const);

export const STAGE4_S408_DIRECT_PROPOSED_TOPOLOGY = deepFreeze({
  eks_clusters: 1,
  managed_addons: 5,
  vpcs: 1,
  public_subnets: 2,
  launch_templates: 2,
  managed_node_groups: 2,
  ebs_volumes: 2,
  retained_s3_buckets: 1,
  retained_s3_objects: 1,
});

export const STAGE4_S408_ZERO_PROHIBITIONS = deepFreeze({
  nat_gateways: 0,
  vpc_endpoints: 0,
  elastic_ips: 0,
  load_balancers: 0,
  public_inbound_rules: 0,
  mutable_launch_template_references: 0,
});

export const STAGE4_S408_UNRESOLVED_PROVIDER_CLASSES = Object.freeze([
  "internet-gateways-routes-and-route-tables",
  "security-groups-and-rules",
  "iam-roles-policies-attachments",
  "instance-profiles",
  "auto-scaling-groups",
  "network-interfaces",
  "log-groups",
  "other-provider-or-service-created-resources",
] as const);

export const STAGE4_S408_ADMISSION_BLOCKERS = deepFreeze({
  s407_acceptance: "absent",
  fresh_issue_specific_approval: "absent",
  authorized_saved_plan: "absent",
  provider_discovery: "not-performed",
});

export const STAGE4_S408_QUALIFICATION_REQUIREMENTS = deepFreeze({
  identity_binding: {
    source: "exact-approved-digest-required",
    render: "exact-approved-digest-required",
    artifacts: "exact-approved-digest-set-required",
    live_object_readback: "required",
  },
  runtime: {
    runtime_class: "kata",
    hypervisor_acceleration: "kvm",
    distinct_guest_kernel: "required",
    nested_virtualization: "required",
    prohibited_fallbacks: ["runc", "qemu-tcg", "trusted-sidecar"],
  },
  storage: {
    volumes: ["workspace", "session"],
    backing: "ebs",
    lifecycle: "create-attach-use-detach-delete",
    exclusive_writer: "required",
    forced_loss: "required",
  },
  cleanup: {
    trigger: "pass-failure-timeout-or-uncertainty",
    order: ["stop", "destroy", "custody-inventory", "retained-state-retirement", "final-inventory"],
    final_inventory: "independent-complete-deletion-blind-zero-required",
  },
});

export const STAGE4_S408_CUSTODY_INVENTORY_SCOPES = deepFreeze([
  { service: "s3", scope: "bound-state-all-versions-markers-multipart-locks" },
]);

export const STAGE4_S408_INVENTORY_SCOPES = deepFreeze([
  {
    service: "ec2",
    scope: "region-all-instances-volumes-snapshots-addresses-network-interfaces-and-network-resources-all-states",
  },
  { service: "eks", scope: "region-all-clusters-addons-access-associations-and-nodegroups" },
  { service: "elasticloadbalancing", scope: "region-all-load-balancers-and-target-groups" },
  { service: "autoscaling", scope: "region-all-groups" },
  { service: "iam", scope: "account-all-roles-policies-attachments-and-profiles" },
  { service: "kms", scope: "region-all-keys-aliases-and-key-states" },
  { service: "cloudwatch-logs", scope: "region-all-log-groups" },
  { service: "s3", scope: "account-buckets-and-bound-state-all-versions-markers-multipart-locks" },
  { service: "budgets", scope: "account-all-budgets-and-notifications" },
  { service: "scheduler", scope: "region-all-schedules" },
  { service: "lambda", scope: "region-all-functions-and-resource-policies" },
]);

const S408_TOPOLOGY_SHA256 = semanticDigest(
  "cogs.stage4/s408-direct-topology/v1",
  STAGE4_S408_DIRECT_PROPOSED_TOPOLOGY,
);
const S408_ZERO_SHA256 = semanticDigest("cogs.stage4/s408-zero-prohibitions/v1", STAGE4_S408_ZERO_PROHIBITIONS);
const S408_CREATE_SET_SHA256 = semanticDigest("cogs.stage4/s408-create-set/v1", {
  topology_sha256: S408_TOPOLOGY_SHA256,
});
export const STAGE4_S408_QUALIFICATION_REQUIREMENTS_SHA256 = semanticDigest(
  "cogs.stage4/s408-qualification-requirements/v1",
  STAGE4_S408_QUALIFICATION_REQUIREMENTS,
);

export const STAGE4_S408_FROZEN_PLAN_PROJECTION = deepFreeze({
  version: "cogs.stage4-s408-frozen-plan-projection/v1",
  direct_topology_sha256: S408_TOPOLOGY_SHA256,
  zero_prohibitions_sha256: S408_ZERO_SHA256,
  create_address_set_sha256: S408_CREATE_SET_SHA256,
  destroy_address_set_sha256: S408_CREATE_SET_SHA256,
  launch_template_references: [
    { node_role: "trusted", template_id: "lt-fixture-trusted", version: 7 },
    { node_role: "sandbox", template_id: "lt-fixture-sandbox", version: 11 },
  ],
  provider_created_counts: "unresolved-observation-only-uncapped",
});
export const STAGE4_S408_FROZEN_PLAN_SHA256 = semanticDigest(
  "cogs.stage4/s408-frozen-plan/v1",
  STAGE4_S408_FROZEN_PLAN_PROJECTION,
);
export const STAGE4_S408_RETIREMENT_RECORD = deepFreeze({
  ebs: { workspace: "detached-deleted", session: "detached-deleted" },
  s3: {
    all_versions: "deleted",
    all_delete_markers: "deleted",
    all_multipart_uploads: "aborted",
    all_object_locks: "removed",
    bucket: "deleted",
  },
});

export type Stage4S408LifecyclePolicy = Readonly<{
  version: "cogs.stage4-s408-policy/v1";
  authority: "local-provider-free-ordering-model";
  campaign_issue: "S4-08/#359";
  mode: "default-unresolved" | "explicit-hand-built-frozen-fixture";
  execution_authorized: false;
  maximum_attempts: 1;
  retry: "prohibited";
  continuation: "prohibited";
  direct_topology_sha256: string;
  zero_prohibitions_sha256: string;
  indirect_counts: "unresolved-observation-only-uncapped";
  frozen_plan_sha256: string | null;
  admission_blockers: typeof STAGE4_S408_ADMISSION_BLOCKERS;
  qualification_requirements_sha256: string;
  openbao: Readonly<{ deployment: "excluded-for-359"; integration_claimed: false; later_stages: "required" }>;
}>;

function s408Policy(mode: Stage4S408LifecyclePolicy["mode"]): Stage4S408LifecyclePolicy {
  return deepFreeze({
    version: "cogs.stage4-s408-policy/v1",
    authority: "local-provider-free-ordering-model",
    campaign_issue: "S4-08/#359",
    mode,
    execution_authorized: false,
    maximum_attempts: 1,
    retry: "prohibited",
    continuation: "prohibited",
    direct_topology_sha256: S408_TOPOLOGY_SHA256,
    zero_prohibitions_sha256: S408_ZERO_SHA256,
    indirect_counts: "unresolved-observation-only-uncapped",
    frozen_plan_sha256: mode === "default-unresolved" ? null : STAGE4_S408_FROZEN_PLAN_SHA256,
    admission_blockers: STAGE4_S408_ADMISSION_BLOCKERS,
    qualification_requirements_sha256: STAGE4_S408_QUALIFICATION_REQUIREMENTS_SHA256,
    openbao: { deployment: "excluded-for-359", integration_claimed: false, later_stages: "required" },
  });
}

export const STAGE4_S408_DEFAULT_POLICY = s408Policy("default-unresolved");
export const STAGE4_S408_FROZEN_FIXTURE_POLICY = s408Policy("explicit-hand-built-frozen-fixture");

type S408Outcome = "fixture-claimed-success" | "fixture-claimed-failed" | "unknown";
export type Stage4S408LifecycleEvent = Readonly<{
  phase: (typeof STAGE4_S408_LIFECYCLE_PHASES)[number];
  attempt_number: 1;
  prior_event_sha256: string | null;
  outcome: S408Outcome;
  payload: Readonly<Record<string, JsonValue>>;
}>;
export type Stage4S408LifecycleJournal = Readonly<{
  version: "cogs.stage4-s408-journal/v1";
  policy_sha256: string;
  attempt_number: 1;
  retry_count: 0;
  continuation_count: 0;
  events: readonly Stage4S408LifecycleEvent[];
}>;

export type Stage4S408LifecycleVerdict = Readonly<{
  version: "cogs.stage4-s408-verdict/v1";
  status: "AWAITING_FIXTURE_EVENT" | "STOPPED_UNRESOLVED" | "MODEL_ORDER_COMPLETE_BLOCKED" | "PRESERVE_UNCERTAIN";
  reason_code:
    | "S408_AWAITING_FIXTURE_EVENT"
    | "S408_UNRESOLVED_DERIVED_CAPS"
    | "S408_MODEL_ORDER_COMPLETE_BLOCKED"
    | "S408_PRESERVE_UNCERTAIN";
  next_phase: (typeof STAGE4_S408_LIFECYCLE_PHASES)[number] | null;
  policy_valid: boolean;
  journal_valid: boolean;
  execution_authorized: false;
  provider_truth_observed: false;
  custody_claimed: false;
  retirement_claimed: false;
  zero_inventory_claimed: false;
  retry_authorized: false;
}>;

function s408Same(left: JsonValue, right: JsonValue): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function s408PolicyValid(value: JsonRecord): value is JsonRecord & Stage4S408LifecyclePolicy {
  return s408Same(value, STAGE4_S408_DEFAULT_POLICY) || s408Same(value, STAGE4_S408_FROZEN_FIXTURE_POLICY);
}

export function stage4S408LifecyclePolicySha256(input: unknown): string | null {
  const value = snapshotJson(input);
  return value !== null && s408PolicyValid(value) ? semanticDigest("cogs.stage4/s408-policy/v1", value) : null;
}

export function stage4S408LifecycleEventSha256(input: unknown): string | null {
  const value = snapshotJson(input);
  return value === null ? null : semanticDigest("cogs.stage4/s408-event/v1", value);
}

function s408Object(value: JsonValue | undefined): JsonRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function s408RetainedState(value: JsonValue | undefined): value is JsonRecord {
  const state = s408Object(value);
  const bucket = s408Object(state?.bucket);
  const object = s408Object(state?.object);
  return Boolean(
    state &&
      exactKeys(state, ["bucket", "custody_claimed", "object"]) &&
      state.custody_claimed === false &&
      bucket &&
      exactKeys(bucket, ["bucket_name", "identity_sha256", "kind"]) &&
      bucket.kind === "aws-s3-bucket" &&
      typeof bucket.bucket_name === "string" &&
      typeof bucket.identity_sha256 === "string" &&
      DIGEST.test(bucket.identity_sha256) &&
      object &&
      exactKeys(object, ["bucket_identity_sha256", "bytes_sha256", "identity_sha256", "key", "kind"]) &&
      object.kind === "aws-s3-object" &&
      object.bucket_identity_sha256 === bucket.identity_sha256 &&
      typeof object.key === "string" &&
      typeof object.bytes_sha256 === "string" &&
      DIGEST.test(object.bytes_sha256) &&
      typeof object.identity_sha256 === "string" &&
      DIGEST.test(object.identity_sha256),
  );
}

function s408PayloadValid(
  phase: Stage4S408LifecycleEvent["phase"],
  payload: JsonRecord,
  events: readonly (JsonRecord & Stage4S408LifecycleEvent)[],
): boolean {
  const source = s408Object(events[0]?.payload);
  const discovery = s408Object(events[1]?.payload);
  const prior = events.at(-1);
  const priorSha = prior === undefined ? null : stage4S408LifecycleEventSha256(prior);
  if (phase === "source") {
    return (
      exactKeys(payload, ["operator_identity_sha256", "source_sha256"]) &&
      typeof payload.operator_identity_sha256 === "string" &&
      DIGEST.test(payload.operator_identity_sha256) &&
      typeof payload.source_sha256 === "string" &&
      DIGEST.test(payload.source_sha256)
    );
  }
  if (phase === "discovery") {
    return (
      exactKeys(payload, ["discovery_identity_sha256", "indirect_classes", "indirect_counts", "retained_state"]) &&
      typeof payload.discovery_identity_sha256 === "string" &&
      DIGEST.test(payload.discovery_identity_sha256) &&
      payload.discovery_identity_sha256 !== source?.operator_identity_sha256 &&
      s408Same(
        payload.indirect_classes as JsonValue,
        STAGE4_S408_UNRESOLVED_PROVIDER_CLASSES as unknown as JsonValue,
      ) &&
      payload.indirect_counts === "unresolved-observation-only-uncapped" &&
      s408RetainedState(payload.retained_state)
    );
  }
  if (phase === "saved-plan") {
    return (
      exactKeys(payload, ["plan_projection", "plan_sha256"]) &&
      payload.plan_sha256 === STAGE4_S408_FROZEN_PLAN_SHA256 &&
      s408Same(payload.plan_projection as JsonValue, STAGE4_S408_FROZEN_PLAN_PROJECTION)
    );
  }
  if (phase === "approval-check") {
    return (
      exactKeys(payload, ["bound_prior_event_sha256", "plan_sha256"]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      payload.plan_sha256 === STAGE4_S408_FROZEN_PLAN_SHA256
    );
  }
  if (phase === "apply") {
    return (
      exactKeys(payload, [
        "bound_prior_event_sha256",
        "fixture_observation_bundle_sha256",
        "plan_sha256",
        "provider_observation_claimed",
        "qualification_requirements_sha256",
      ]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      typeof payload.fixture_observation_bundle_sha256 === "string" &&
      DIGEST.test(payload.fixture_observation_bundle_sha256) &&
      payload.plan_sha256 === STAGE4_S408_FROZEN_PLAN_SHA256 &&
      payload.provider_observation_claimed === false &&
      payload.qualification_requirements_sha256 === STAGE4_S408_QUALIFICATION_REQUIREMENTS_SHA256
    );
  }
  if (phase === "stop") {
    return (
      exactKeys(payload, ["bound_prior_event_sha256", "cleanup_trigger", "plan_sha256"]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      payload.cleanup_trigger === "pass-failure-timeout-or-uncertainty" &&
      payload.plan_sha256 === STAGE4_S408_FROZEN_PLAN_SHA256
    );
  }
  if (phase === "destroy") {
    return (
      exactKeys(payload, ["bound_prior_event_sha256", "destruction_required_for", "plan_sha256"]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      payload.destruction_required_for === "all-outcomes" &&
      payload.plan_sha256 === STAGE4_S408_FROZEN_PLAN_SHA256
    );
  }
  if (phase === "custody-inventory") {
    return (
      exactKeys(payload, [
        "bound_prior_event_sha256",
        "complete_pagination",
        "custody_claimed",
        "retained_state",
        "scopes",
        "tag_only",
      ]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      payload.custody_claimed === false &&
      payload.complete_pagination === true &&
      payload.tag_only === false &&
      s408RetainedState(payload.retained_state) &&
      s408Same(payload.retained_state as JsonValue, discovery?.retained_state as JsonValue) &&
      s408Same(payload.scopes as JsonValue, STAGE4_S408_CUSTODY_INVENTORY_SCOPES)
    );
  }
  if (phase === "retained-state-retirement") {
    return (
      exactKeys(payload, ["bound_prior_event_sha256", "retirement_record"]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      s408Same(payload.retirement_record as JsonValue, STAGE4_S408_RETIREMENT_RECORD)
    );
  }
  return (
    exactKeys(payload, [
      "bound_prior_event_sha256",
      "claimed_identity_independent",
      "complete_pagination",
      "observer_identity_sha256",
      "residue_count",
      "scopes",
      "tag_only",
    ]) &&
    payload.bound_prior_event_sha256 === priorSha &&
    payload.claimed_identity_independent === true &&
    typeof payload.observer_identity_sha256 === "string" &&
    DIGEST.test(payload.observer_identity_sha256) &&
    payload.observer_identity_sha256 !== source?.operator_identity_sha256 &&
    payload.observer_identity_sha256 !== discovery?.discovery_identity_sha256 &&
    typeof payload.complete_pagination === "boolean" &&
    typeof payload.tag_only === "boolean" &&
    typeof payload.residue_count === "number" &&
    Number.isSafeInteger(payload.residue_count) &&
    payload.residue_count >= 0 &&
    s408Same(payload.scopes as JsonValue, STAGE4_S408_INVENTORY_SCOPES)
  );
}

function s408JournalValid(policy: Stage4S408LifecyclePolicy, journal: JsonRecord): boolean {
  if (
    !exactKeys(journal, [
      "attempt_number",
      "continuation_count",
      "events",
      "policy_sha256",
      "retry_count",
      "version",
    ]) ||
    journal.version !== "cogs.stage4-s408-journal/v1" ||
    journal.policy_sha256 !== stage4S408LifecyclePolicySha256(policy) ||
    journal.attempt_number !== 1 ||
    journal.retry_count !== 0 ||
    journal.continuation_count !== 0 ||
    !Array.isArray(journal.events) ||
    journal.events.length > STAGE4_S408_LIFECYCLE_PHASES.length
  )
    return false;
  const accepted: (JsonRecord & Stage4S408LifecycleEvent)[] = [];
  for (const [index, item] of journal.events.entries()) {
    const event = s408Object(item);
    const payload = s408Object(event?.payload);
    const prior = accepted.at(-1);
    if (
      !event ||
      !payload ||
      !exactKeys(event, ["attempt_number", "outcome", "payload", "phase", "prior_event_sha256"]) ||
      event.phase !== STAGE4_S408_LIFECYCLE_PHASES[index] ||
      event.attempt_number !== 1 ||
      !["fixture-claimed-success", "fixture-claimed-failed", "unknown"].includes(event.outcome as string) ||
      event.prior_event_sha256 !== (prior ? stage4S408LifecycleEventSha256(prior) : null) ||
      !s408PayloadValid(event.phase as Stage4S408LifecycleEvent["phase"], payload, accepted)
    )
      return false;
    accepted.push(event as JsonRecord & Stage4S408LifecycleEvent);
  }
  return policy.mode === "explicit-hand-built-frozen-fixture" || accepted.length <= 2;
}

function s408Verdict(
  status: Stage4S408LifecycleVerdict["status"],
  reason_code: Stage4S408LifecycleVerdict["reason_code"],
  next_phase: Stage4S408LifecycleVerdict["next_phase"],
  policy_valid: boolean,
  journal_valid: boolean,
): Stage4S408LifecycleVerdict {
  return {
    version: "cogs.stage4-s408-verdict/v1",
    status,
    reason_code,
    next_phase,
    policy_valid,
    journal_valid,
    execution_authorized: false,
    provider_truth_observed: false,
    custody_claimed: false,
    retirement_claimed: false,
    zero_inventory_claimed: false,
    retry_authorized: false,
  };
}

export function classifyStage4S408Lifecycle(policyInput: unknown, journalInput: unknown): Stage4S408LifecycleVerdict {
  const policy = snapshotJson(policyInput);
  if (!policy || !s408PolicyValid(policy))
    return s408Verdict("PRESERVE_UNCERTAIN", "S408_PRESERVE_UNCERTAIN", null, false, false);
  const journal = snapshotJson(journalInput);
  if (!journal || !s408JournalValid(policy, journal))
    return s408Verdict("PRESERVE_UNCERTAIN", "S408_PRESERVE_UNCERTAIN", null, true, false);
  const events = journal.events as unknown as Stage4S408LifecycleEvent[];
  const firstUncertain = events.findIndex((event) => event.outcome !== "fixture-claimed-success");
  if (firstUncertain !== -1)
    return s408Verdict(
      "PRESERVE_UNCERTAIN",
      "S408_PRESERVE_UNCERTAIN",
      firstUncertain >= 4 && events.length < STAGE4_S408_LIFECYCLE_PHASES.length
        ? (STAGE4_S408_LIFECYCLE_PHASES[events.length] ?? null)
        : null,
      true,
      true,
    );
  if (policy.mode === "default-unresolved" && events.length === 2)
    return s408Verdict("STOPPED_UNRESOLVED", "S408_UNRESOLVED_DERIVED_CAPS", null, true, true);
  if (events.length < STAGE4_S408_LIFECYCLE_PHASES.length)
    return s408Verdict(
      "AWAITING_FIXTURE_EVENT",
      "S408_AWAITING_FIXTURE_EVENT",
      STAGE4_S408_LIFECYCLE_PHASES[events.length] ?? null,
      true,
      true,
    );
  const custody = events[7]?.payload;
  const inventory = events[9]?.payload;
  if (
    custody?.complete_pagination !== true ||
    custody.tag_only !== false ||
    inventory?.complete_pagination !== true ||
    inventory.tag_only !== false ||
    inventory.residue_count !== 0
  )
    return s408Verdict("PRESERVE_UNCERTAIN", "S408_PRESERVE_UNCERTAIN", null, true, true);
  return s408Verdict("MODEL_ORDER_COMPLETE_BLOCKED", "S408_MODEL_ORDER_COMPLETE_BLOCKED", null, true, true);
}

/* S4-09 remains a provider-free, non-observing model over synthetic fixtures. */
export const STAGE4_S409_LIFECYCLE_PHASES = Object.freeze([
  "source",
  "dependency-admission",
  "guest-network-denial",
  "guest-surface-denial",
  "guest-material-denial",
  "stage3-functional",
  "api-key-sample-check",
  "stop",
  "destroy",
  "independent-inventory",
] as const);

export const STAGE4_S409_ADMISSION_BLOCKERS = deepFreeze({
  accepted_s408_evidence: "absent",
  fresh_issue_specific_approval: "absent",
  authorized_saved_plan: "absent",
  authenticated_release_image_set: "absent",
  provider_discovery: "not-performed",
});

export const STAGE4_S409_OPENBAO_CANDIDATE = deepFreeze({
  version: "2.7.0",
  image_index_sha256: "71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315",
  amd64_manifest_sha256: "6d575d906d70d40b9d789149c8dc09897291c5a1707d4d0ba8a459eaaa94c8c4",
  repository_evidence_bound: false,
  release_image_present: false,
  campaign_authority_granted: false,
});

export const STAGE4_S409_QUALIFICATION_REQUIREMENTS = deepFreeze({
  dependencies: {
    required_actual: ["cni", "ext-authz", "audit-wal", "openbao", "egress-proxy", "otlp"],
    mandatory_stub_count: 0,
  },
  guest_root_denials: {
    network: ["ipv4", "ipv6", "udp", "quic", "dns"],
    surfaces: ["api", "metadata", "admin", "cross-session", "storage"],
    material: ["kubernetes", "cloud", "openbao", "integration-model-secret", "ca-private-key"],
  },
  functional_scenario: {
    inherited_stage: "stage3",
    required_actual: ["kata", "ebs", "openbao", "otlp"],
    prompt_replay: "prohibited",
  },
  model_credentials: {
    api_key_samples: "separate-authorization-required-absent",
    subscription_oauth: "disabled",
  },
  cleanup: {
    trigger: "pass-failure-timeout-or-uncertainty",
    order: ["stop", "destroy", "independent-inventory"],
    final_inventory: "independent-complete-deletion-blind-zero-required",
  },
});

export const STAGE4_S409_QUALIFICATION_REQUIREMENTS_SHA256 = semanticDigest(
  "cogs.stage4/s409-qualification-requirements/v1",
  STAGE4_S409_QUALIFICATION_REQUIREMENTS,
);

export const STAGE4_S409_POLICY = deepFreeze({
  version: "cogs.stage4-s409-policy/v1",
  authority: "local-provider-free-ordering-model",
  campaign_issue: "S4-09/#360",
  execution_authorized: false,
  maximum_attempts: 1,
  retry: "prohibited",
  continuation: "prohibited",
  admission_blockers: STAGE4_S409_ADMISSION_BLOCKERS,
  openbao_candidate: STAGE4_S409_OPENBAO_CANDIDATE,
  qualification_requirements_sha256: STAGE4_S409_QUALIFICATION_REQUIREMENTS_SHA256,
});

export type Stage4S409Policy = typeof STAGE4_S409_POLICY;
type S409Phase = (typeof STAGE4_S409_LIFECYCLE_PHASES)[number];
type S409Outcome = "fixture-claimed-success" | "fixture-claimed-failed" | "unknown";
export type Stage4S409Event = Readonly<{
  phase: S409Phase;
  attempt_number: 1;
  prior_event_sha256: string | null;
  outcome: S409Outcome;
  payload: Readonly<Record<string, JsonValue>>;
}>;
export type Stage4S409Journal = Readonly<{
  version: "cogs.stage4-s409-journal/v1";
  policy_sha256: string;
  attempt_number: 1;
  retry_count: 0;
  continuation_count: 0;
  events: readonly Stage4S409Event[];
}>;
export type Stage4S409Verdict = Readonly<{
  version: "cogs.stage4-s409-verdict/v1";
  status: "AWAITING_FIXTURE_EVENT" | "MODEL_ORDER_COMPLETE_BLOCKED" | "PRESERVE_UNCERTAIN";
  reason_code: "S409_AWAITING_FIXTURE_EVENT" | "S409_MODEL_ORDER_COMPLETE_BLOCKED" | "S409_PRESERVE_UNCERTAIN";
  next_phase: S409Phase | null;
  policy_valid: boolean;
  journal_valid: boolean;
  execution_authorized: false;
  provider_truth_observed: false;
  kubernetes_truth_observed: false;
  conformance_claimed: false;
  functional_scenario_claimed: false;
  cleanup_observed: false;
  zero_inventory_claimed: false;
  retry_authorized: false;
}>;

export function stage4S409PolicySha256(input: unknown): string | null {
  const value = snapshotJson(input);
  return value !== null && s408Same(value, STAGE4_S409_POLICY)
    ? semanticDigest("cogs.stage4/s409-policy/v1", value)
    : null;
}

export function stage4S409EventSha256(input: unknown): string | null {
  const value = snapshotJson(input);
  return value === null ? null : semanticDigest("cogs.stage4/s409-event/v1", value);
}

function s409QualificationPhase(phase: S409Phase): boolean {
  return STAGE4_S409_LIFECYCLE_PHASES.indexOf(phase) >= 1 && STAGE4_S409_LIFECYCLE_PHASES.indexOf(phase) <= 6;
}

function s409PayloadValid(
  phase: S409Phase,
  payload: JsonRecord,
  priorSha: string | null,
  operator: JsonRecord | null,
): boolean {
  if (phase === "source") {
    return (
      exactKeys(payload, ["operator_identity_sha256", "source_sha256"]) &&
      typeof payload.operator_identity_sha256 === "string" &&
      DIGEST.test(payload.operator_identity_sha256) &&
      typeof payload.source_sha256 === "string" &&
      DIGEST.test(payload.source_sha256)
    );
  }
  if (s409QualificationPhase(phase)) {
    return (
      exactKeys(payload, [
        "bound_prior_event_sha256",
        "fixture_claim_sha256",
        "provider_observation_claimed",
        "qualification_requirements_sha256",
      ]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      typeof payload.fixture_claim_sha256 === "string" &&
      DIGEST.test(payload.fixture_claim_sha256) &&
      payload.provider_observation_claimed === false &&
      payload.qualification_requirements_sha256 === STAGE4_S409_QUALIFICATION_REQUIREMENTS_SHA256
    );
  }
  if (phase === "stop") {
    return (
      exactKeys(payload, ["bound_prior_event_sha256", "cleanup_trigger"]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      payload.cleanup_trigger === "pass-failure-timeout-or-uncertainty"
    );
  }
  if (phase === "destroy") {
    return (
      exactKeys(payload, ["bound_prior_event_sha256", "destruction_required_for"]) &&
      payload.bound_prior_event_sha256 === priorSha &&
      payload.destruction_required_for === "all-outcomes"
    );
  }
  return (
    exactKeys(payload, [
      "bound_prior_event_sha256",
      "campaign_tag_filter_used",
      "claimed_identity_independent",
      "complete_pagination",
      "deleted_ids_used",
      "observer_identity_sha256",
      "planned_addresses_used",
      "residue_count",
      "scopes",
    ]) &&
    payload.bound_prior_event_sha256 === priorSha &&
    payload.campaign_tag_filter_used === false &&
    payload.claimed_identity_independent === true &&
    payload.complete_pagination === true &&
    payload.deleted_ids_used === false &&
    typeof payload.observer_identity_sha256 === "string" &&
    DIGEST.test(payload.observer_identity_sha256) &&
    payload.observer_identity_sha256 !== operator?.operator_identity_sha256 &&
    payload.planned_addresses_used === false &&
    payload.residue_count === 0 &&
    s408Same(payload.scopes as JsonValue, STAGE4_S408_INVENTORY_SCOPES)
  );
}

function s409NextPhase(phase: S409Phase, outcome: S409Outcome): S409Phase | null {
  if (phase === "source") return outcome === "fixture-claimed-success" ? "dependency-admission" : "stop";
  if (s409QualificationPhase(phase) && outcome !== "fixture-claimed-success") return "stop";
  if (phase === "stop") return "destroy";
  if (phase === "destroy") return "independent-inventory";
  if (phase === "independent-inventory") return null;
  const index = STAGE4_S409_LIFECYCLE_PHASES.indexOf(phase);
  return STAGE4_S409_LIFECYCLE_PHASES[index + 1] ?? null;
}

function s409JournalValid(journal: JsonRecord): { valid: boolean; next: S409Phase | null; uncertain: boolean } {
  if (
    !exactKeys(journal, [
      "attempt_number",
      "continuation_count",
      "events",
      "policy_sha256",
      "retry_count",
      "version",
    ]) ||
    journal.version !== "cogs.stage4-s409-journal/v1" ||
    journal.policy_sha256 !== stage4S409PolicySha256(STAGE4_S409_POLICY) ||
    journal.attempt_number !== 1 ||
    journal.retry_count !== 0 ||
    journal.continuation_count !== 0 ||
    !Array.isArray(journal.events) ||
    journal.events.length > STAGE4_S409_LIFECYCLE_PHASES.length
  )
    return { valid: false, next: null, uncertain: true };
  let expected: S409Phase | null = "source";
  let prior: JsonRecord | null = null;
  let operator: JsonRecord | null = null;
  let uncertain = false;
  for (const item of journal.events) {
    const event = s408Object(item);
    const payload = s408Object(event?.payload);
    const priorSha = prior === null ? null : stage4S409EventSha256(prior);
    if (
      expected === null ||
      event === null ||
      payload === null ||
      !exactKeys(event, ["attempt_number", "outcome", "payload", "phase", "prior_event_sha256"]) ||
      event.phase !== expected ||
      event.attempt_number !== 1 ||
      !["fixture-claimed-success", "fixture-claimed-failed", "unknown"].includes(event.outcome as string) ||
      event.prior_event_sha256 !== priorSha ||
      !s409PayloadValid(expected, payload, priorSha, operator)
    )
      return { valid: false, next: null, uncertain: true };
    if (expected === "source") operator = payload;
    if (event.outcome !== "fixture-claimed-success") uncertain = true;
    expected = s409NextPhase(expected, event.outcome as S409Outcome);
    prior = event;
  }
  return { valid: true, next: expected, uncertain };
}

function s409Verdict(
  status: Stage4S409Verdict["status"],
  reason_code: Stage4S409Verdict["reason_code"],
  next_phase: S409Phase | null,
  policy_valid: boolean,
  journal_valid: boolean,
): Stage4S409Verdict {
  return {
    version: "cogs.stage4-s409-verdict/v1",
    status,
    reason_code,
    next_phase,
    policy_valid,
    journal_valid,
    execution_authorized: false,
    provider_truth_observed: false,
    kubernetes_truth_observed: false,
    conformance_claimed: false,
    functional_scenario_claimed: false,
    cleanup_observed: false,
    zero_inventory_claimed: false,
    retry_authorized: false,
  };
}

export function classifyStage4S409Lifecycle(policyInput: unknown, journalInput: unknown): Stage4S409Verdict {
  const policy = snapshotJson(policyInput);
  if (policy === null || !s408Same(policy, STAGE4_S409_POLICY))
    return s409Verdict("PRESERVE_UNCERTAIN", "S409_PRESERVE_UNCERTAIN", null, false, false);
  const journal = snapshotJson(journalInput);
  if (journal === null) return s409Verdict("PRESERVE_UNCERTAIN", "S409_PRESERVE_UNCERTAIN", null, true, false);
  const state = s409JournalValid(journal);
  if (!state.valid) return s409Verdict("PRESERVE_UNCERTAIN", "S409_PRESERVE_UNCERTAIN", null, true, false);
  if (state.uncertain) return s409Verdict("PRESERVE_UNCERTAIN", "S409_PRESERVE_UNCERTAIN", state.next, true, true);
  if (state.next === null)
    return s409Verdict("MODEL_ORDER_COMPLETE_BLOCKED", "S409_MODEL_ORDER_COMPLETE_BLOCKED", null, true, true);
  return s409Verdict("AWAITING_FIXTURE_EVENT", "S409_AWAITING_FIXTURE_EVENT", state.next, true, true);
}
