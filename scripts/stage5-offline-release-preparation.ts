import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder, types } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

export const STAGE5_DOCUMENT_KINDS = Object.freeze([
  "rc-freeze",
  "independent-review",
  "campaign",
  "load",
  "capacity-decision",
  "release-readiness",
] as const);
export type Stage5DocumentKind = (typeof STAGE5_DOCUMENT_KINDS)[number];

const SCHEMAS: Readonly<Record<Stage5DocumentKind, object>> = Object.freeze({
  "rc-freeze": require("../schemas/stage5-rc-freeze-manifest-v1.json") as object,
  "independent-review": require("../schemas/stage5-independent-review-template-v1.json") as object,
  campaign: require("../schemas/stage5-campaign-plan-v1.json") as object,
  load: require("../schemas/stage5-load-plan-v1.json") as object,
  "capacity-decision": require("../schemas/stage5-capacity-decision-template-v1.json") as object,
  "release-readiness": require("../schemas/stage5-release-readiness-template-v1.json") as object,
});

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const VALIDATORS = Object.fromEntries(
  STAGE5_DOCUMENT_KINDS.map((kind) => [kind, ajv.compile(SCHEMAS[kind])]),
) as Record<Stage5DocumentKind, ValidateFunction>;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const MAX_DOCUMENT_BYTES = 256 * 1024;

type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };

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

/** Code-point-key-sorted JSON with exactly one terminal LF. */
export function canonicalStage5Bytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

export function stage5Sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function copyBoundedBytes(input: unknown): Uint8Array | null {
  if ((typeof input === "object" && input !== null) || typeof input === "function") {
    if (types.isProxy(input)) return null;
  }
  if (!(input instanceof Uint8Array) || Object.getPrototypeOf(input) !== Uint8Array.prototype) return null;
  try {
    if (input.byteLength === 0 || input.byteLength > MAX_DOCUMENT_BYTES) return null;
    return new Uint8Array(input);
  } catch {
    return null;
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export type Stage5DocumentValidation = Readonly<{
  authority: "local-static-shape-validation-only";
  valid: boolean;
  document_sha256: string | null;
  campaign_authorized: false;
  cloud_execution_observed: false;
  release_eligible: false;
  reason_code: "VALID_PROVISIONAL_DOCUMENT" | "BOUNDED_INPUT_VIOLATION" | "NON_CANONICAL_JSON" | "SCHEMA_DRIFT";
}>;

/** Validates bounded canonical metadata only. It performs no filesystem, process, provider, cluster, or model action. */
export function validateStage5Document(kind: Stage5DocumentKind, input: unknown): Stage5DocumentValidation {
  const bytes = copyBoundedBytes(input);
  let reason: Stage5DocumentValidation["reason_code"] = "VALID_PROVISIONAL_DOCUMENT";
  let digest: string | null = null;
  if (bytes === null) {
    reason = "BOUNDED_INPUT_VIOLATION";
  } else {
    digest = stage5Sha256(bytes);
    try {
      const parsed = JSON.parse(decoder.decode(bytes)) as JsonValue;
      if (!bytesEqual(bytes, canonicalStage5Bytes(parsed))) reason = "NON_CANONICAL_JSON";
      else if (!VALIDATORS[kind](parsed)) reason = "SCHEMA_DRIFT";
    } catch {
      reason = "NON_CANONICAL_JSON";
    }
  }
  return Object.freeze({
    authority: "local-static-shape-validation-only",
    valid: reason === "VALID_PROVISIONAL_DOCUMENT",
    document_sha256: digest,
    campaign_authorized: false,
    cloud_execution_observed: false,
    release_eligible: false,
    reason_code: reason,
  });
}

const absentBinding = (): JsonRecord => ({ binding_sha256: null, state: "absent-blocking" });
const fixedClaims = (): JsonRecord => ({
  campaign_authorized: false,
  cloud_execution_observed: false,
  production_ready: false,
  release_eligible: false,
});

export const FREEZE_COMPONENTS = Object.freeze([
  "source",
  "locks",
  "chart",
  "skills",
  "schemas",
  "runtime",
  "images",
  "sbom",
  "signatures",
  "vulnerabilities",
  "licenses",
  "supported_aws_matrix",
] as const);
export type FreezeComponent = (typeof FREEZE_COMPONENTS)[number];
export type FreezeSnapshot = Readonly<Record<FreezeComponent, string>>;

export function generateProvisionalRcFreezeManifest(): JsonRecord {
  return {
    artifacts: Object.fromEntries(FREEZE_COMPONENTS.map((component) => [component, absentBinding()])) as JsonRecord,
    authority: "provisional-local-static-freeze-contract-only",
    blockers: [
      "S4_11_NOT_ACCEPTED",
      "S5_00_THROUGH_S5_03_NOT_ACCEPTED",
      "RELEASE_CANDIDATE_BINDING_ABSENT",
      "AUTHENTIC_ARTIFACT_EVIDENCE_ABSENT",
      "SEPARATE_CAMPAIGN_APPROVAL_ABSENT",
    ],
    claims: { ...fixedClaims(), rc_frozen: false },
    dependencies: {
      s4_11: "unmet-blocking",
      s5_00_through_s5_03: "unmet-blocking",
    },
    drift: {
      baseline_binding_sha256: null,
      current_state: "not-evaluable-no-authentic-baseline",
      invalidate_on_any_component_change: true,
      invalidates_campaign_results: true,
      invalidates_review_results: true,
      requires_refreeze: true,
    },
    freeze_binding_sha256: null,
    issue: 367,
    oauth: {
      advertised: false,
      refresh_token_path: "forbidden",
      status: "disabled-unadvertised",
    },
    version: "cogs.stage5-rc-freeze-manifest/v1",
  };
}

function freezeSnapshotRoot(snapshot: FreezeSnapshot): string {
  return createHash("sha256")
    .update("cogs.stage5/freeze-snapshot/v1\0", "utf8")
    .update(canonicalJson(snapshot), "utf8")
    .digest("hex");
}

/** Exact synthetic snapshot comparison. A missing or changed component always invalidates the baseline. */
export function compareFreezeSnapshots(baseline: Partial<FreezeSnapshot>, current: Partial<FreezeSnapshot>) {
  const digest = /^[0-9a-f]{64}$/u;
  const missing = FREEZE_COMPONENTS.filter(
    (component) => baseline[component] === undefined || current[component] === undefined,
  );
  const invalid = FREEZE_COMPONENTS.filter(
    (component) =>
      (baseline[component] !== undefined && !digest.test(baseline[component])) ||
      (current[component] !== undefined && !digest.test(current[component])),
  );
  const changed = FREEZE_COMPONENTS.filter(
    (component) =>
      baseline[component] !== undefined &&
      current[component] !== undefined &&
      baseline[component] !== current[component],
  );
  const complete = missing.length === 0 && invalid.length === 0;
  const status =
    invalid.length > 0
      ? "invalidated-invalid-binding"
      : missing.length > 0
        ? "invalidated-incomplete"
        : changed.length > 0
          ? "invalidated-drift"
          : "metadata-match-only";
  return Object.freeze({
    status,
    missing: Object.freeze(missing),
    invalid: Object.freeze(invalid),
    changed: Object.freeze(changed),
    baseline_binding_sha256: complete ? freezeSnapshotRoot(baseline as FreezeSnapshot) : null,
    current_binding_sha256: complete ? freezeSnapshotRoot(current as FreezeSnapshot) : null,
    rc_frozen: false,
    requires_refreeze: !complete || changed.length > 0,
    release_eligible: false,
  });
}

export const REVIEW_AREAS = Object.freeze([
  "pi-discovery",
  "ssh-sftp",
  "path-handling",
  "proxy",
  "proxy-capability",
  "openbao",
  "audit-wal",
  "policy",
  "guest-kata",
  "privacy",
  "integrity",
  "production-artifact-pinning",
  "project-dependency-isolation",
] as const);

export function generateIndependentReviewTemplate(): JsonRecord {
  return {
    authority: "provisional-local-static-review-template-only",
    blockers: ["RC_FREEZE_ABSENT", "INDEPENDENT_IDENTITIES_ABSENT", "CHECKLIST_UNEXECUTED"],
    checklist: REVIEW_AREAS.map((area) => ({ area, evidence_binding_sha256: null, result: "unexecuted" })),
    claims: { ...fixedClaims(), independent_review_accepted: false },
    findings: [],
    gate: {
      decision: "not-available",
      risk_acceptance_for_critical_or_high: "forbidden",
      unresolved_critical_or_high_count: null,
    },
    identities: {
      evidence_producer_principal_id: null,
      reviewer_identity_binding_sha256: null,
      reviewer_principal_id: null,
      state: "absent-blocking",
    },
    issue: 368,
    rc_binding_sha256: null,
    version: "cogs.stage5-independent-review-template/v1",
  };
}

export type ReviewFinding = Readonly<{
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  disposition: "open" | "fixed" | "false-positive" | "accepted-risk";
  owner_present: boolean;
  retest: "unexecuted" | "pass" | "fail";
  evidence_binding_present: boolean;
}>;

export function aggregateReviewFindings(findings: readonly ReviewFinding[]) {
  const unresolvedCriticalHigh = findings.filter(
    (finding) =>
      (finding.severity === "critical" || finding.severity === "high") &&
      !(
        (finding.disposition === "fixed" || finding.disposition === "false-positive") &&
        finding.owner_present &&
        finding.retest === "pass" &&
        finding.evidence_binding_present
      ),
  );
  return Object.freeze({
    finding_count: findings.length,
    unresolved_critical_or_high_count: unresolvedCriticalHigh.length,
    critical_high_gate: unresolvedCriticalHigh.length === 0 ? "metadata-pass" : "blocked",
    accepted_risk_can_resolve_critical_or_high: false,
    independent_review_accepted: false,
    release_eligible: false,
  });
}

export const CAMPAIGN_PHASES = Object.freeze([
  "exact-rc-conformance-real-dependencies",
  "recovery-destructive",
  "privacy-deletion-synthetic-sessions",
  "cleanup-destroy",
  "independent-zero-inventory",
] as const);
export type CampaignPhaseState = "unexecuted" | "pass" | "fail" | "uncertain";

export function generateCampaignPlan(): JsonRecord {
  return {
    aggregation: {
      accepted: false,
      current_state: "blocked-dependencies",
      evidence_root_sha256: null,
      uncertainty_blocks_acceptance: true,
    },
    authority: "offline-campaign-plan-and-state-machine-only",
    blockers: ["S5_05_NOT_ACCEPTED", "FRESH_EXACT_CAMPAIGN_APPROVAL_ABSENT", "RC_BINDING_ABSENT"],
    claims: { ...fixedClaims(), campaign_complete: false, zero_resources_claimed: false },
    dependencies: { fresh_exact_campaign_approval: "absent-blocking", s5_05: "unmet-blocking" },
    execution_route: {
      cluster: false,
      deployment: false,
      external_model: false,
      provider: false,
      scheduler: false,
    },
    issue: 369,
    model_auth: { api_key_only_required: true, oauth: "disabled", real_model_execution: "not-authorized" },
    phases: CAMPAIGN_PHASES.map((phase) => ({
      evidence_binding_sha256: null,
      execution: "unexecuted",
      phase,
      result: null,
    })),
    version: "cogs.stage5-campaign-plan/v1",
  };
}

function orderedState(states: readonly CampaignPhaseState[]) {
  let terminal = false;
  for (const [index, state] of states.entries()) {
    if (terminal && state !== "unexecuted") return "invalid-transition";
    if (state === "fail" || state === "uncertain") terminal = true;
    if (state === "unexecuted" && states.slice(index + 1).some((later) => later !== "unexecuted")) {
      return "invalid-transition";
    }
  }
  if (states.every((state) => state === "unexecuted")) return "unexecuted";
  if (states.includes("fail")) return "stopped-failed";
  if (states.includes("uncertain")) return "stopped-uncertain";
  if (states.every((state) => state === "pass")) return "metadata-complete-unaccepted";
  return "in-progress-metadata-only";
}

export function aggregateCampaignPhases(states: readonly CampaignPhaseState[]) {
  const state = states.length === CAMPAIGN_PHASES.length ? orderedState(states) : "invalid-transition";
  return Object.freeze({
    state,
    campaign_complete: false,
    zero_resources_claimed: false,
    campaign_authorized: false,
    release_eligible: false,
  });
}

export const LOAD_TARGETS = Object.freeze([10, 25, 50] as const);
export type LoadTarget = (typeof LOAD_TARGETS)[number];
export type LoadStepState = "unexecuted" | "pass" | "fail" | "uncertain";

function loadStep(target: LoadTarget, prior: LoadTarget | null): JsonRecord {
  return {
    evidence_binding_sha256: null,
    execution: "unexecuted",
    gates: {
      cross_user_isolation_required: true,
      exclusive_same_project_writer_required: true,
      four_session_user_probe_required: true,
      stop_before_next_on_failure_or_uncertainty: true,
    },
    metrics: [
      "startup",
      "scheduling",
      "resources",
      "proxy",
      "openbao",
      "ssh",
      "storage",
      "wal",
      "otlp",
      "cost",
      "cleanup",
    ],
    model_mode: "deterministic-mocked-only",
    per_user_session_limit: 4,
    prior_passing_target_required: prior,
    result: null,
    target_active_sessions: target,
  };
}

export function generateMockedLoadPlan(): JsonRecord {
  return {
    aggregation: {
      claimed_capacity: null,
      highest_planning_step_passed: null,
      state: "unexecuted",
    },
    authority: "offline-deterministic-mocked-load-plan-only",
    blockers: ["S5_06_NOT_ACCEPTED", "STEP_APPROVALS_ABSENT", "REAL_SANDBOX_RESULTS_ABSENT"],
    claims: { ...fixedClaims(), capacity_validated: false },
    execution_route: {
      cluster: false,
      deployment: false,
      external_model: false,
      provider: false,
      scheduler: false,
    },
    issues: [370, 371],
    steps: [loadStep(10, null), loadStep(25, 10), loadStep(50, 25)],
    version: "cogs.stage5-load-plan/v1",
  };
}

export function aggregateMockedLoadSteps(states: readonly LoadStepState[]) {
  const state = states.length === LOAD_TARGETS.length ? orderedState(states) : "invalid-transition";
  let highest: LoadTarget | null = null;
  for (const [index, target] of LOAD_TARGETS.entries()) {
    if (states[index] !== "pass") break;
    highest = target;
  }
  return Object.freeze({
    state,
    highest_planning_step_passed: highest,
    claimed_capacity: null,
    real_capacity_validated: false,
    scheduler_route_present: false,
    provider_route_present: false,
    release_eligible: false,
  });
}

export function generateCapacityDecisionTemplate(): JsonRecord {
  return {
    authority: "provisional-local-static-capacity-decision-template-only",
    claims: { ...fixedClaims(), capacity_decision_available: false },
    decision: {
      advertised_maximum: null,
      decision: "not-available",
      extrapolation_may_raise_capacity: false,
      selected_option: null,
    },
    dependencies: {
      real_50_result_binding_sha256: null,
      real_50_result_state: "absent-blocking",
    },
    issue: 372,
    optional_steps: {
      propose_100: false,
      propose_250: false,
      requires_100_pass_before_250_proposal: true,
      separate_budget_and_approval_required: true,
    },
    version: "cogs.stage5-capacity-decision-template/v1",
  };
}

export const RELEASE_EVIDENCE_CATEGORIES = Object.freeze([
  "source-artifacts",
  "acceptance-matrix",
  "independent-review",
  "security-campaign",
  "performance-load",
  "privacy-deletion",
  "zero-inventory",
  "cost-capacity",
  "operations-runbooks",
] as const);

export function generateReleaseReadinessTemplate(): JsonRecord {
  return {
    api_key_release: {
      advertised: false,
      providers: ["anthropic", "openai", "openrouter"].map((provider) => ({
        evidence_binding_sha256: null,
        provider,
        status: "provisional-unadvertised",
      })),
      status: "provisional-unadvertised",
    },
    authority: "provisional-local-static-release-readiness-template-only",
    blockers: [
      "RC_FREEZE_ABSENT",
      "INDEPENDENT_REVIEW_ABSENT",
      "CAMPAIGN_EVIDENCE_ABSENT",
      "REAL_50_LOAD_RESULT_ABSENT",
      "PRIVACY_DELETION_EVIDENCE_ABSENT",
      "ZERO_INVENTORY_EVIDENCE_ABSENT",
      "STAFF_DECISION_ABSENT",
    ],
    claims: { ...fixedClaims(), go_no_go_available: false },
    evidence: Object.fromEntries(
      RELEASE_EVIDENCE_CATEGORIES.map((category) => [category, absentBinding()]),
    ) as JsonRecord,
    highest_passing_real_concurrency: null,
    issue: 373,
    oauth: { advertised: false, refresh_token_path: "forbidden", status: "disabled-unadvertised" },
    recommendation: "not-available",
    release_scope: "cogs-agent-layer-only-if-a-future-decision-exists",
    residual_risks: [],
    version: "cogs.stage5-release-readiness-template/v1",
  };
}

export function generatedStage5Documents(): Readonly<Record<Stage5DocumentKind, JsonRecord>> {
  return Object.freeze({
    "rc-freeze": generateProvisionalRcFreezeManifest(),
    "independent-review": generateIndependentReviewTemplate(),
    campaign: generateCampaignPlan(),
    load: generateMockedLoadPlan(),
    "capacity-decision": generateCapacityDecisionTemplate(),
    "release-readiness": generateReleaseReadinessTemplate(),
  });
}
