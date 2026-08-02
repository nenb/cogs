/* biome-ignore-all lint/suspicious/noExplicitAny: hostile schema mutations intentionally cross strict JSON types */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import {
  aggregateCampaignPhases,
  aggregateMockedLoadSteps,
  aggregateReviewFindings,
  CAMPAIGN_PHASES,
  canonicalStage5Bytes,
  compareFreezeSnapshots,
  FREEZE_COMPONENTS,
  generatedStage5Documents,
  LOAD_TARGETS,
  RELEASE_EVIDENCE_CATEGORIES,
  REVIEW_AREAS,
  STAGE5_DOCUMENT_KINDS,
  type Stage5DocumentKind,
  stage5Sha256,
  validateStage5Document,
} from "../scripts/stage5-offline-release-preparation.ts";

const root = resolve(import.meta.dirname, "..");
const paths: Readonly<Record<Stage5DocumentKind, string>> = {
  "rc-freeze": "docs/security-evidence/stage5-offline-preparation/rc-freeze-manifest.provisional.json",
  "independent-review": "docs/security-evidence/stage5-offline-preparation/independent-review.template.json",
  campaign: "docs/security-evidence/stage5-offline-preparation/campaign-plan.unexecuted.json",
  load: "docs/security-evidence/stage5-offline-preparation/load-plan.mocked.unexecuted.json",
  "capacity-decision": "docs/security-evidence/stage5-offline-preparation/capacity-decision.unavailable.json",
  "release-readiness": "docs/security-evidence/stage5-offline-preparation/release-readiness.unavailable.json",
};
const bytes = (kind: Stage5DocumentKind): Uint8Array => new Uint8Array(readFileSync(resolve(root, paths[kind])));
const parse = (kind: Stage5DocumentKind): Record<string, any> =>
  JSON.parse(readFileSync(resolve(root, paths[kind]), "utf8")) as Record<string, any>;
const generated = generatedStage5Documents();

function mutation(kind: Stage5DocumentKind, mutate: (value: Record<string, any>) => void): Uint8Array {
  const value = structuredClone(parse(kind));
  mutate(value);
  return canonicalStage5Bytes(value);
}

test("all six committed templates are exact deterministic canonical generator output", () => {
  assert.deepEqual(Object.keys(generated), [...STAGE5_DOCUMENT_KINDS]);
  for (const kind of STAGE5_DOCUMENT_KINDS) {
    assert.deepEqual(bytes(kind), canonicalStage5Bytes(generated[kind]), kind);
    const verdict = validateStage5Document(kind, bytes(kind));
    assert.deepEqual(verdict, {
      authority: "local-static-shape-validation-only",
      valid: true,
      document_sha256: stage5Sha256(bytes(kind)),
      campaign_authorized: false,
      cloud_execution_observed: false,
      release_eligible: false,
      reason_code: "VALID_PROVISIONAL_DOCUMENT",
    });
  }
});

test("validation rejects non-canonical, oversized, proxied, getter, malformed, and wrong-domain input", () => {
  const canonical = bytes("rc-freeze");
  const text = new TextDecoder().decode(canonical);
  for (const hostile of [
    new TextEncoder().encode(JSON.stringify(parse("rc-freeze"))),
    canonical.slice(0, -1),
    new TextEncoder().encode(`${text}\n`),
    new TextEncoder().encode(`\uFEFF${text}`),
    new TextEncoder().encode(text.replace(/^\{/u, '{"issue":367,')),
    new TextEncoder().encode("not-json\n"),
  ]) {
    assert.equal(validateStage5Document("rc-freeze", hostile).valid, false);
  }
  assert.equal(
    validateStage5Document("rc-freeze", new Uint8Array(256 * 1024 + 1)).reason_code,
    "BOUNDED_INPUT_VIOLATION",
  );
  assert.equal(validateStage5Document("rc-freeze", new Proxy(canonical, {})).reason_code, "BOUNDED_INPUT_VIOLATION");
  const getter = Object.create(Uint8Array.prototype);
  Object.defineProperty(getter, "byteLength", { get: () => 1 });
  assert.equal(validateStage5Document("rc-freeze", getter).reason_code, "BOUNDED_INPUT_VIOLATION");
  assert.equal(validateStage5Document("load", bytes("campaign")).reason_code, "SCHEMA_DRIFT");
});

test("every authority promotion, invented binding, result, or unknown field fails closed", () => {
  const hostile: Array<[Stage5DocumentKind, (value: Record<string, any>) => void]> = [
    ["rc-freeze", (value) => (value.claims.rc_frozen = true)],
    ["rc-freeze", (value) => (value.artifacts.source.binding_sha256 = "a".repeat(64))],
    ["independent-review", (value) => (value.claims.independent_review_accepted = true)],
    ["independent-review", (value) => (value.identities.reviewer_principal_id = "reviewer")],
    ["campaign", (value) => (value.execution_route.provider = true)],
    ["campaign", (value) => (value.phases[0].execution = "pass")],
    ["load", (value) => (value.aggregation.claimed_capacity = 10)],
    ["load", (value) => (value.execution_route.scheduler = true)],
    ["capacity-decision", (value) => (value.decision.decision = "select-50")],
    ["capacity-decision", (value) => (value.decision.advertised_maximum = 50)],
    ["release-readiness", (value) => (value.recommendation = "go")],
    ["release-readiness", (value) => (value.highest_passing_real_concurrency = 50)],
    ["release-readiness", (value) => (value.api_key_release.advertised = true)],
    ["release-readiness", (value) => (value.evidence["zero-inventory"].binding_sha256 = "a".repeat(64))],
  ];
  for (const [kind, mutate] of hostile) {
    assert.equal(validateStage5Document(kind, mutation(kind, mutate)).reason_code, "SCHEMA_DRIFT", kind);
  }
  for (const kind of STAGE5_DOCUMENT_KINDS) {
    assert.equal(
      validateStage5Document(
        kind,
        mutation(kind, (value) => {
          value.unbounded_diagnostic = "forbidden";
        }),
      ).valid,
      false,
      kind,
    );
  }
});

test("the provisional freeze inventory is complete but authentically absent and any drift invalidates", () => {
  const freeze = parse("rc-freeze");
  assert.deepEqual(Object.keys(freeze.artifacts).sort(), [...FREEZE_COMPONENTS].sort());
  for (const component of FREEZE_COMPONENTS) {
    assert.deepEqual(freeze.artifacts[component], { binding_sha256: null, state: "absent-blocking" });
  }
  assert.equal(freeze.freeze_binding_sha256, null);
  assert.equal(freeze.oauth.status, "disabled-unadvertised");
  assert.equal(freeze.oauth.refresh_token_path, "forbidden");
  assert.equal(freeze.drift.invalidate_on_any_component_change, true);

  const baseline = Object.fromEntries(
    FREEZE_COMPONENTS.map((component, index) => [component, String(index).padStart(64, "0")]),
  ) as any;
  assert.deepEqual(compareFreezeSnapshots(baseline, baseline), {
    status: "metadata-match-only",
    missing: [],
    invalid: [],
    changed: [],
    baseline_binding_sha256: compareFreezeSnapshots(baseline, baseline).baseline_binding_sha256,
    current_binding_sha256: compareFreezeSnapshots(baseline, baseline).current_binding_sha256,
    rc_frozen: false,
    requires_refreeze: false,
    release_eligible: false,
  });
  const drifted = { ...baseline, chart: "f".repeat(64) };
  assert.deepEqual(compareFreezeSnapshots(baseline, drifted).changed, ["chart"]);
  assert.equal(compareFreezeSnapshots(baseline, drifted).requires_refreeze, true);
  const incomplete = { ...baseline };
  delete incomplete.sbom;
  assert.equal(compareFreezeSnapshots(baseline, incomplete).status, "invalidated-incomplete");
  assert.deepEqual(compareFreezeSnapshots(baseline, { ...baseline, source: "not-a-digest" }).invalid, ["source"]);
});

test("independent review covers every required area and never resolves critical/high through risk acceptance", () => {
  const review = parse("independent-review");
  assert.deepEqual(
    review.checklist.map((row: { area: string }) => row.area),
    [...REVIEW_AREAS],
  );
  assert.ok(review.checklist.every((row: { result: string }) => row.result === "unexecuted"));
  assert.deepEqual(review.findings, []);
  assert.equal(review.gate.unresolved_critical_or_high_count, null, "absence of findings is not a zero claim");
  assert.equal(review.identities.state, "absent-blocking");

  const acceptedHigh = aggregateReviewFindings([
    {
      id: "F-1",
      severity: "high",
      disposition: "accepted-risk",
      owner_present: true,
      retest: "pass",
      evidence_binding_present: true,
    },
  ]);
  assert.equal(acceptedHigh.critical_high_gate, "blocked");
  assert.equal(acceptedHigh.unresolved_critical_or_high_count, 1);
  const fixedHigh = aggregateReviewFindings([
    {
      id: "F-2",
      severity: "critical",
      disposition: "fixed",
      owner_present: true,
      retest: "pass",
      evidence_binding_present: true,
    },
  ]);
  assert.equal(fixedHigh.critical_high_gate, "metadata-pass");
  assert.equal(fixedHigh.independent_review_accepted, false, "metadata aggregation is not independent acceptance");
});

test("the issue 369 campaign is entirely unexecuted and its ordered state machine preserves uncertainty", () => {
  const campaign = parse("campaign");
  assert.deepEqual(
    campaign.phases.map((row: { phase: string }) => row.phase),
    [...CAMPAIGN_PHASES],
  );
  assert.ok(
    campaign.phases.every(
      (row: { execution: string; result: null }) => row.execution === "unexecuted" && row.result === null,
    ),
  );
  assert.deepEqual(aggregateCampaignPhases(["unexecuted", "unexecuted", "unexecuted", "unexecuted", "unexecuted"]), {
    state: "unexecuted",
    campaign_complete: false,
    zero_resources_claimed: false,
    campaign_authorized: false,
    release_eligible: false,
  });
  assert.equal(
    aggregateCampaignPhases(["pass", "fail", "unexecuted", "unexecuted", "unexecuted"]).state,
    "stopped-failed",
  );
  assert.equal(
    aggregateCampaignPhases(["pass", "uncertain", "unexecuted", "unexecuted", "unexecuted"]).state,
    "stopped-uncertain",
  );
  assert.equal(
    aggregateCampaignPhases(["pass", "unexecuted", "pass", "unexecuted", "unexecuted"]).state,
    "invalid-transition",
  );
  assert.equal(aggregateCampaignPhases(["pass", "pass", "pass", "pass", "pass"]).state, "metadata-complete-unaccepted");
});

test("mocked-model load planning is deterministic, gates each next step, and never claims capacity", () => {
  const load = parse("load");
  assert.deepEqual(
    load.steps.map((row: { target_active_sessions: number }) => row.target_active_sessions),
    [...LOAD_TARGETS],
  );
  assert.deepEqual(
    load.steps.map((row: { prior_passing_target_required: number | null }) => row.prior_passing_target_required),
    [null, 10, 25],
  );
  for (const step of load.steps) {
    assert.equal(step.model_mode, "deterministic-mocked-only");
    assert.equal(step.per_user_session_limit, 4);
    assert.equal(step.gates.four_session_user_probe_required, true);
    assert.equal(step.gates.exclusive_same_project_writer_required, true);
    assert.equal(step.gates.cross_user_isolation_required, true);
    assert.equal(step.gates.stop_before_next_on_failure_or_uncertainty, true);
    assert.equal(step.execution, "unexecuted");
  }
  assert.equal(load.execution_route.scheduler, false);
  assert.equal(load.execution_route.provider, false);
  assert.deepEqual(aggregateMockedLoadSteps(["pass", "fail", "unexecuted"]), {
    state: "stopped-failed",
    highest_planning_step_passed: 10,
    claimed_capacity: null,
    real_capacity_validated: false,
    scheduler_route_present: false,
    provider_route_present: false,
    release_eligible: false,
  });
  assert.equal(aggregateMockedLoadSteps(["pass", "unexecuted", "pass"]).state, "invalid-transition");
  const allMockPassed = aggregateMockedLoadSteps(["pass", "pass", "pass"]);
  assert.equal(allMockPassed.highest_planning_step_passed, 50);
  assert.equal(allMockPassed.claimed_capacity, null);
  assert.equal(allMockPassed.real_capacity_validated, false);
});

test("capacity and release decisions remain unavailable with no extrapolation or hidden evidence claim", () => {
  const capacity = parse("capacity-decision");
  assert.equal(capacity.dependencies.real_50_result_binding_sha256, null);
  assert.equal(capacity.decision.decision, "not-available");
  assert.equal(capacity.decision.advertised_maximum, null);
  assert.equal(capacity.decision.extrapolation_may_raise_capacity, false);
  assert.equal(capacity.optional_steps.propose_100, false);
  assert.equal(capacity.optional_steps.propose_250, false);

  const release = parse("release-readiness");
  assert.equal(release.recommendation, "not-available");
  assert.equal(release.highest_passing_real_concurrency, null);
  assert.equal(release.api_key_release.status, "provisional-unadvertised");
  assert.equal(release.api_key_release.advertised, false);
  assert.equal(release.oauth.status, "disabled-unadvertised");
  assert.deepEqual(Object.keys(release.evidence).sort(), [...RELEASE_EVIDENCE_CATEGORIES].sort());
  for (const category of RELEASE_EVIDENCE_CATEGORIES) {
    assert.deepEqual(release.evidence[category], { binding_sha256: null, state: "absent-blocking" });
  }
});

test("the operations document keeps every issue open or blocked and disclaims completion", () => {
  const document = readFileSync(resolve(root, "docs/operations/stage-5-offline-release-preparation.md"), "utf8");
  for (const issue of [367, 368, 369, 370, 371, 372, 373]) {
    assert.match(document, new RegExp(`\\| #${issue} \\| \\*\\*open \\/`, "u"));
  }
  assert.match(document, /All acceptance checkboxes in #367–#373 remain incomplete/u);
  assert.match(document, /no AWS\/provider\/cluster\/deployment\/OpenTofu\/external-model invocation/u);
});

test("documents contain bounded categorical metadata and no execution payload surface", () => {
  const source = readFileSync(resolve(root, "scripts/stage5-offline-release-preparation.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /node:(?:child_process|fs|http|https|net|tls)|\b(?:exec|execFile|spawn|fetch)\s*\(|process\.env/u,
  );
  const forbiddenKeys = new Set([
    "account_id",
    "command",
    "credential",
    "credential_value",
    "deployment_target",
    "endpoint",
    "log",
    "prompt",
    "provider_payload",
    "resource_id",
    "session_export",
    "source_text",
  ]);
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
    } else if (value !== null && typeof value === "object") {
      for (const [key, item] of Object.entries(value)) {
        assert.equal(forbiddenKeys.has(key), false, key);
        visit(item);
      }
    } else if (typeof value === "string") {
      assert.ok(value.length <= 128, value);
    }
  };
  for (const kind of STAGE5_DOCUMENT_KINDS) visit(parse(kind));
});
