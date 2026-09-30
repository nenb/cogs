// biome-ignore assist/source/organizeImports: preserve the historical v1 import block byte-for-byte
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import {
  advanceStage4CampaignModel,
  classifyStage4CampaignModel,
  STAGE4_CAMPAIGN_QUALIFICATION_STEPS,
  STAGE4_CAMPAIGN_TERMINAL_ORDER,
  type Stage4CampaignEvent,
  type Stage4CampaignEvidence,
  type Stage4CampaignIssue,
  type Stage4CampaignPlan,
  stage4CampaignArtifactSetRoot,
  stage4CampaignAttemptIdentitySha256,
  stage4CampaignIdentitySha256,
  stage4CampaignPlanSha256,
} from "../scripts/stage4-campaign-model.ts";
import {
  classifyStage4S408Lifecycle,
  STAGE4_S408_CUSTODY_INVENTORY_SCOPES,
  STAGE4_S408_DEFAULT_POLICY,
  STAGE4_S408_FROZEN_FIXTURE_POLICY,
  STAGE4_S408_FROZEN_PLAN_PROJECTION,
  STAGE4_S408_FROZEN_PLAN_SHA256,
  STAGE4_S408_INVENTORY_SCOPES,
  STAGE4_S408_LIFECYCLE_PHASES,
  STAGE4_S408_RETIREMENT_RECORD,
  STAGE4_S408_UNRESOLVED_PROVIDER_CLASSES,
  type Stage4S408LifecycleEvent,
  type Stage4S408LifecycleJournal,
  type Stage4S408LifecyclePolicy,
  stage4CampaignEvidenceSha256,
  stage4S408LifecycleEventSha256,
  stage4S408LifecyclePolicySha256,
} from "../scripts/stage4-campaign-model.ts";

type JsonObject = Record<string, unknown>;
const fixture = (name: string): JsonObject =>
  JSON.parse(readFileSync(resolve(import.meta.dirname, `fixtures/stage4-campaign/${name}`), "utf8")) as JsonObject;
const digest = (label: string): string => createHash("sha256").update(`stage4-local-fixture:${label}`).digest("hex");
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const fixtures = [
  ["S4-08/#359", "s4-08-plan-blocked-v1.json", "s4-08-evidence-empty-v1.json"],
  ["S4-09/#360", "s4-09-plan-blocked-v1.json", "s4-09-evidence-empty-v1.json"],
  ["S4-10/#361", "s4-10-plan-blocked-v1.json", "s4-10-evidence-empty-v1.json"],
] as const;

function requiredStep(issue: Stage4CampaignIssue, index: number): string {
  const step = STAGE4_CAMPAIGN_QUALIFICATION_STEPS[issue][index];
  assert.ok(step, `${issue}: missing step ${index}`);
  return step;
}

function event(phase: string, label: string, outcome: Stage4CampaignEvent["outcome"] = "claimed-satisfied") {
  const producer_class =
    phase === "independent-inventory"
      ? ("independent-inventory-observer" as const)
      : ("caller-claimed-future-evidence" as const);
  return outcome === "uncertain"
    ? { phase, outcome, producer_class, uncertainty_artifact_sha256: digest(label) }
    : { phase, outcome, producer_class, evidence_sha256: digest(label) };
}

test("#359-#361 fixtures bind exact artifacts and remain blocked before any claim", () => {
  for (const [issue, planName, evidenceName] of fixtures) {
    const plan = fixture(planName) as unknown as Stage4CampaignPlan;
    const evidence = fixture(evidenceName) as unknown as Stage4CampaignEvidence;
    const result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.plan_valid, true, issue);
    assert.equal(result.evidence_valid, true, issue);
    assert.equal(result.status, "awaiting-claimed-evidence", issue);
    assert.equal(result.next_phase, STAGE4_CAMPAIGN_QUALIFICATION_STEPS[issue][0], issue);
    assert.equal(result.execution_authorized, false, issue);
    assert.equal(result.campaign_execution_observed, false, issue);
    assert.equal(result.provider_truth_observed, false, issue);
    assert.equal(result.kubernetes_truth_observed, false, issue);
    assert.equal(result.cleanup_observed, false, issue);
    assert.equal(result.zero_inventory_claimed, false, issue);
    assert.equal(result.retry_authorized, false, issue);
    assert.equal(result.stage4_exit_satisfied, false, issue);
    assert.equal(evidence.plan_sha256, stage4CampaignPlanSha256(plan), issue);
    const { artifact_set_root_sha256, ...rootInputs } = plan.bindings;
    assert.equal(artifact_set_root_sha256, stage4CampaignArtifactSetRoot(rootInputs), issue);
    assert.equal(
      plan.campaign_id_sha256,
      stage4CampaignIdentitySha256({ campaign_issue: issue, artifact_set_root_sha256 }),
      issue,
    );
    assert.equal(
      plan.attempt.attempt_id_sha256,
      stage4CampaignAttemptIdentitySha256({
        campaign_id_sha256: plan.campaign_id_sha256,
        attempt_number: 1,
        approval_draft_sha256: plan.bindings.approval_draft_sha256,
      }),
      issue,
    );
    assert.equal(evidence.campaign_id_sha256, plan.campaign_id_sha256, issue);
    assert.equal(evidence.attempt_id_sha256, plan.attempt.attempt_id_sha256, issue);
    assert.equal(result.campaign_id_sha256, plan.campaign_id_sha256, issue);
    assert.equal(result.attempt_id_sha256, plan.attempt.attempt_id_sha256, issue);
    assert.deepEqual(plan.terminal_order, STAGE4_CAMPAIGN_TERMINAL_ORDER, issue);
    assert.deepEqual(plan.attempt, {
      attempt_id_sha256: plan.attempt.attempt_id_sha256,
      number: 1,
      maximum_attempts: 1,
      retry: "prohibited",
      approval_state: "absent",
    });
    assert.deepEqual(plan.prohibited_surfaces, [
      "executor",
      "provider",
      "opentofu",
      "kubernetes-api",
      "kubectl",
      "helm-install-apply",
      "external-model",
      "network-discovery",
    ]);
  }
});

test("the pure model requires stop, destroy, then independent inventory even after all claimed passes", () => {
  for (const [issue, planName, evidenceName] of fixtures) {
    const plan = fixture(planName) as unknown as Stage4CampaignPlan;
    let evidence = fixture(evidenceName) as unknown as Stage4CampaignEvidence;
    for (const [index, phase] of STAGE4_CAMPAIGN_QUALIFICATION_STEPS[issue].entries()) {
      const next = advanceStage4CampaignModel(plan, evidence, event(phase, `${issue}:qualification:${index}`));
      assert.ok(next, `${issue}: ${phase}`);
      evidence = next;
    }
    let result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.status, "stop-required", issue);
    assert.equal(result.next_phase, "stop", issue);

    evidence = advanceStage4CampaignModel(plan, evidence, event("stop", `${issue}:stop`)) as Stage4CampaignEvidence;
    result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.status, "destroy-required", issue);

    evidence = advanceStage4CampaignModel(
      plan,
      evidence,
      event("destroy", `${issue}:destroy`),
    ) as Stage4CampaignEvidence;
    result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.status, "independent-inventory-required", issue);

    evidence = advanceStage4CampaignModel(
      plan,
      evidence,
      event("independent-inventory", `${issue}:inventory`),
    ) as Stage4CampaignEvidence;
    result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.status, "model-order-complete-blocked", issue);
    assert.equal(result.next_phase, null, issue);
    assert.equal(result.execution_authorized, false, issue);
    assert.equal(result.campaign_execution_observed, false, issue);
    assert.equal(result.cleanup_observed, false, issue);
    assert.equal(result.zero_inventory_claimed, false, issue);
    assert.equal(result.stage4_exit_satisfied, false, issue);
    assert.equal(advanceStage4CampaignModel(plan, evidence, event("stop", `${issue}:retry`)), null, issue);
  }
});

test("a claimed qualification failure skips only to mandatory stop and never authorizes retry", () => {
  const plan = fixture("s4-08-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  let evidence = fixture("s4-08-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  const firstPhase = requiredStep("S4-08/#359", 0);
  evidence = advanceStage4CampaignModel(
    plan,
    evidence,
    event(firstPhase, "failure", "claimed-failed"),
  ) as Stage4CampaignEvidence;
  let result = classifyStage4CampaignModel(plan, evidence);
  assert.equal(result.status, "stop-required");
  assert.equal(result.next_phase, "stop");
  assert.equal(
    advanceStage4CampaignModel(plan, evidence, event(requiredStep("S4-08/#359", 1), "forbidden-next-test")),
    null,
  );
  for (const phase of STAGE4_CAMPAIGN_TERMINAL_ORDER) {
    evidence = advanceStage4CampaignModel(plan, evidence, event(phase, `failure:${phase}`)) as Stage4CampaignEvidence;
  }
  result = classifyStage4CampaignModel(plan, evidence);
  assert.equal(result.status, "model-order-complete-blocked");
  assert.equal(result.retry_authorized, false);
  assert.equal(result.campaign_execution_observed, false);
});

test("uncertainty is sticky while exact best-effort cleanup remains representable", () => {
  const plan = fixture("s4-09-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const empty = fixture("s4-09-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  let evidence = {
    ...empty,
    events: [event(requiredStep("S4-09/#360", 0), "uncertain", "uncertain")],
  } as Stage4CampaignEvidence;

  let result = classifyStage4CampaignModel(plan, evidence);
  assert.equal(result.status, "preserve-uncertain");
  assert.equal(result.reason_code, "STAGE4_CAMPAIGN_UNCERTAIN");
  assert.equal(result.next_phase, "stop");

  evidence = advanceStage4CampaignModel(
    plan,
    evidence,
    event("stop", "uncertain:stop-failed", "claimed-failed"),
  ) as Stage4CampaignEvidence;
  result = classifyStage4CampaignModel(plan, evidence);
  assert.equal(result.status, "preserve-uncertain");
  assert.equal(result.next_phase, "destroy");

  evidence = advanceStage4CampaignModel(
    plan,
    evidence,
    event("destroy", "uncertain:destroy", "uncertain"),
  ) as Stage4CampaignEvidence;
  result = classifyStage4CampaignModel(plan, evidence);
  assert.equal(result.status, "preserve-uncertain");
  assert.equal(result.next_phase, "independent-inventory");

  evidence = advanceStage4CampaignModel(
    plan,
    evidence,
    event("independent-inventory", "uncertain:inventory-failed", "claimed-failed"),
  ) as Stage4CampaignEvidence;
  result = classifyStage4CampaignModel(plan, evidence);
  assert.equal(result.status, "preserve-uncertain");
  assert.equal(result.reason_code, "STAGE4_CAMPAIGN_UNCERTAIN");
  assert.equal(result.next_phase, null);
  assert.equal(result.evidence_valid, true);
  assert.equal(result.execution_authorized, false);
  assert.equal(result.cleanup_observed, false);
  assert.equal(result.zero_inventory_claimed, false);
  assert.equal(result.retry_authorized, false);
  assert.equal(result.stage4_exit_satisfied, false);
  assert.equal(advanceStage4CampaignModel(plan, evidence, event("stop", "uncertain:retry")), null);
});

test("uncertainty in every terminal phase consumes that phase and requires only the remainder", () => {
  const plan = fixture("s4-08-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  for (const [uncertainIndex, uncertainPhase] of STAGE4_CAMPAIGN_TERMINAL_ORDER.entries()) {
    let evidence = fixture("s4-08-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
    evidence = advanceStage4CampaignModel(
      plan,
      evidence,
      event(requiredStep("S4-08/#359", 0), `terminal-uncertain:${uncertainPhase}:failure`, "claimed-failed"),
    ) as Stage4CampaignEvidence;
    for (const phase of STAGE4_CAMPAIGN_TERMINAL_ORDER.slice(0, uncertainIndex)) {
      evidence = advanceStage4CampaignModel(
        plan,
        evidence,
        event(phase, `terminal-uncertain:${uncertainPhase}:before:${phase}`),
      ) as Stage4CampaignEvidence;
    }
    evidence = {
      ...evidence,
      events: [
        ...evidence.events,
        event(uncertainPhase, `terminal-uncertain:${uncertainPhase}:uncertain`, "uncertain"),
      ],
    };

    let result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.status, "preserve-uncertain", uncertainPhase);
    assert.equal(result.reason_code, "STAGE4_CAMPAIGN_UNCERTAIN", uncertainPhase);
    assert.equal(result.next_phase, STAGE4_CAMPAIGN_TERMINAL_ORDER[uncertainIndex + 1] ?? null, uncertainPhase);
    for (const phase of STAGE4_CAMPAIGN_TERMINAL_ORDER.slice(uncertainIndex + 1)) {
      evidence = advanceStage4CampaignModel(
        plan,
        evidence,
        event(phase, `terminal-uncertain:${uncertainPhase}:after:${phase}`),
      ) as Stage4CampaignEvidence;
    }
    result = classifyStage4CampaignModel(plan, evidence);
    assert.equal(result.status, "preserve-uncertain", uncertainPhase);
    assert.equal(result.next_phase, null, uncertainPhase);
  }
});

test("the complete array after uncertainty rejects hostile order, duplicates, replay, completion, and retry tails", () => {
  const plan = fixture("s4-09-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const empty = fixture("s4-09-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  const uncertain = event(requiredStep("S4-09/#360", 0), "hostile:uncertain", "uncertain");
  const stop = event("stop", "hostile:stop");
  const destroy = event("destroy", "hostile:destroy");
  const inventory = event("independent-inventory", "hostile:inventory");
  const uncertaintyDigest = uncertain.uncertainty_artifact_sha256;
  const stopDigest = stop.evidence_sha256;
  assert.ok(uncertaintyDigest);
  assert.ok(stopDigest);
  const assertRejectedTail = (events: readonly Stage4CampaignEvent[], reason: string): void => {
    const result = classifyStage4CampaignModel(plan, { ...empty, events });
    assert.equal(result.reason_code, reason);
    assert.equal(result.plan_valid, false);
    assert.equal(result.evidence_valid, false);
    assert.equal(result.plan_sha256, null);
    assert.equal(result.evidence_sha256, null);
  };

  assertRejectedTail([uncertain, destroy], "STAGE4_CAMPAIGN_INVALID_TRANSITION");
  assertRejectedTail([uncertain, stop, stop], "STAGE4_CAMPAIGN_INVALID_TRANSITION");
  assertRejectedTail(
    [
      uncertain,
      {
        ...stop,
        evidence_sha256: uncertaintyDigest,
      },
    ],
    "STAGE4_CAMPAIGN_EVIDENCE_REPLAY",
  );
  assertRejectedTail([uncertain, stop, { ...destroy, evidence_sha256: stopDigest }], "STAGE4_CAMPAIGN_EVIDENCE_REPLAY");
  assertRejectedTail([uncertain, stop, destroy, inventory, stop], "STAGE4_CAMPAIGN_INVALID_TRANSITION");

  const complete = classifyStage4CampaignModel(plan, {
    ...empty,
    events: [...([uncertain, stop, destroy, inventory] as const), event("complete", "hostile:complete")],
  });
  assert.equal(complete.reason_code, "STAGE4_CAMPAIGN_INVALID_SHAPE");
  assert.equal(complete.evidence_valid, false);
  assert.equal(complete.evidence_sha256, null);

  const retry = classifyStage4CampaignModel(plan, {
    ...empty,
    retry_count: 1,
    events: [uncertain, stop, destroy, inventory],
  });
  assert.equal(retry.reason_code, "STAGE4_CAMPAIGN_AUTHORITY_PROMOTION");
  assert.equal(retry.evidence_valid, false);
  assert.equal(retry.evidence_sha256, null);
});

test("campaign models reject mixed bindings, replay, retries, skips, and executor surfaces", () => {
  const originalPlan = fixture("s4-10-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const originalEvidence = fixture("s4-10-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;

  const mixedEvidence = structuredClone(originalEvidence) as unknown as JsonObject;
  mixedEvidence.plan_sha256 = (fixture("s4-09-evidence-empty-v1.json") as JsonObject).plan_sha256;
  assert.equal(
    classifyStage4CampaignModel(originalPlan, mixedEvidence).reason_code,
    "STAGE4_CAMPAIGN_BINDING_MISMATCH",
  );

  for (const key of [
    "source_revision_sha256",
    "source_inventory_sha256",
    "offline_readiness_package_sha256",
    "approval_draft_sha256",
    "campaign_profile_sha256",
    "artifact_manifest_sha256",
  ]) {
    const driftedPlan = structuredClone(originalPlan) as unknown as JsonObject;
    (driftedPlan.bindings as JsonObject)[key] = digest(`binding-mutation:${key}`);
    assert.equal(
      classifyStage4CampaignModel(driftedPlan, originalEvidence).reason_code,
      "STAGE4_CAMPAIGN_BINDING_MISMATCH",
      key,
    );
  }

  const retry = structuredClone(originalEvidence) as unknown as JsonObject;
  retry.retry_count = 1;
  assert.equal(classifyStage4CampaignModel(originalPlan, retry).reason_code, "STAGE4_CAMPAIGN_AUTHORITY_PROMOTION");

  const executor = structuredClone(originalPlan) as unknown as JsonObject;
  executor.executor = { command: "apply" };
  assert.equal(classifyStage4CampaignModel(executor, originalEvidence).reason_code, "STAGE4_CAMPAIGN_INVALID_SHAPE");

  const first = requiredStep("S4-10/#361", 0);
  const replay = { ...originalEvidence, events: [event(first, "ignored")] } as unknown as JsonObject;
  ((replay.events as JsonObject[])[0] as JsonObject).evidence_sha256 = originalPlan.bindings.source_revision_sha256;
  assert.equal(classifyStage4CampaignModel(originalPlan, replay).reason_code, "STAGE4_CAMPAIGN_EVIDENCE_REPLAY");

  const skip = { ...originalEvidence, events: [event("stop", "skip")] };
  assert.equal(classifyStage4CampaignModel(originalPlan, skip).reason_code, "STAGE4_CAMPAIGN_INVALID_TRANSITION");

  const wrongProducer = structuredClone(originalEvidence) as unknown as JsonObject;
  const firstEvent = event(first, "wrong-producer") as unknown as JsonObject;
  firstEvent.producer_class = "independent-inventory-observer";
  wrongProducer.events = [firstEvent];
  assert.equal(classifyStage4CampaignModel(originalPlan, wrongProducer).reason_code, "STAGE4_CAMPAIGN_INVALID_SHAPE");
});

test("terminal completion is closed exactly once and cannot be reopened within the event bound", () => {
  const plan = fixture("s4-08-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  let evidence = fixture("s4-08-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  evidence = advanceStage4CampaignModel(
    plan,
    evidence,
    event(requiredStep("S4-08/#359", 0), "closed:failure", "claimed-failed"),
  ) as Stage4CampaignEvidence;
  for (const phase of STAGE4_CAMPAIGN_TERMINAL_ORDER) {
    evidence = advanceStage4CampaignModel(plan, evidence, event(phase, `closed:${phase}`)) as Stage4CampaignEvidence;
  }
  assert.equal(classifyStage4CampaignModel(plan, evidence).status, "model-order-complete-blocked");

  const reopened = { ...evidence, events: [...evidence.events, event("stop", "closed:reopen")] };
  assert.ok(reopened.events.length < plan.evidence_policy.max_events);
  const result = classifyStage4CampaignModel(plan, reopened);
  assert.equal(result.reason_code, "STAGE4_CAMPAIGN_INVALID_TRANSITION");
  assert.equal(result.plan_sha256, null);
  assert.equal(result.evidence_sha256, null);
  assert.equal(result.campaign_id_sha256, null);
  assert.equal(result.attempt_id_sha256, null);
  assert.equal(advanceStage4CampaignModel(plan, evidence, event("stop", "closed:retry")), null);
});

test("standalone campaign evidence and verdict schemas reject fabricated phases, claims, and contradictions", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  const evidenceSchema = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../schemas/stage4-campaign-evidence-v1.json"), "utf8"),
  ) as object;
  const verdictSchema = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../schemas/stage4-campaign-model-verdict-v1.json"), "utf8"),
  ) as object;
  const validateEvidenceSchema = ajv.compile(evidenceSchema) as ValidateFunction;
  const validateVerdictSchema = ajv.compile(verdictSchema) as ValidateFunction;
  const plan = fixture("s4-08-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const evidence = fixture("s4-08-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  const verdict = classifyStage4CampaignModel(plan, evidence);
  assert.equal(validateEvidenceSchema(evidence), true, JSON.stringify(validateEvidenceSchema.errors));
  assert.equal(validateVerdictSchema(verdict), true, JSON.stringify(validateVerdictSchema.errors));
  const rejectedVerdict = classifyStage4CampaignModel(plan, {
    ...evidence,
    events: [event("campaign.execute", "schema:rejected")],
  });
  assert.equal(validateVerdictSchema(rejectedVerdict), true, JSON.stringify(validateVerdictSchema.errors));
  const uncertainVerdict = classifyStage4CampaignModel(plan, {
    ...evidence,
    events: [event(requiredStep("S4-08/#359", 0), "schema:uncertain", "uncertain")],
  });
  assert.equal(validateVerdictSchema(uncertainVerdict), true, JSON.stringify(validateVerdictSchema.errors));
  const completedUncertainVerdict = classifyStage4CampaignModel(plan, {
    ...evidence,
    events: [
      event(requiredStep("S4-08/#359", 0), "schema:uncertain-complete", "uncertain"),
      event("stop", "schema:uncertain-stop"),
      event("destroy", "schema:uncertain-destroy"),
      event("independent-inventory", "schema:uncertain-inventory"),
    ],
  });
  assert.equal(completedUncertainVerdict.status, "preserve-uncertain");
  assert.equal(completedUncertainVerdict.next_phase, null);
  assert.equal(validateVerdictSchema(completedUncertainVerdict), true, JSON.stringify(validateVerdictSchema.errors));

  for (const phase of ["campaign.execute", "provider.apply", "complete", requiredStep("S4-09/#360", 0)]) {
    const mutation = { ...evidence, events: [event(phase, `schema:${phase}`)] };
    assert.equal(validateEvidenceSchema(mutation), false, phase);
  }
  const tooMany = {
    ...evidence,
    events: Array.from({ length: 10 }, (_, index) => event("stop", `schema:max:${index}`)),
  };
  assert.equal(validateEvidenceSchema(tooMany), false);

  const providerNext = { ...verdict, next_phase: "provider.apply" };
  assert.equal(validateVerdictSchema(providerNext), false);
  const executed = { ...verdict, campaign_execution_observed: true };
  assert.equal(validateVerdictSchema(executed), false);
  const contradictory = {
    ...verdict,
    status: "model-order-complete-blocked",
    next_phase: null,
    reason_code: "STAGE4_CAMPAIGN_STOP_REQUIRED",
  };
  assert.equal(validateVerdictSchema(contradictory), false);
  const fabricatedRejection = {
    ...verdict,
    status: "preserve-uncertain",
    reason_code: "STAGE4_CAMPAIGN_INVALID_TRANSITION",
    plan_valid: true,
  };
  assert.equal(validateVerdictSchema(fabricatedRejection), false);
});

test("authority, campaign identity, attempt identity, binding, and replay reject before evidence digest output", () => {
  const plan = fixture("s4-08-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const evidence = fixture("s4-08-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  const assertRejectedWithoutBindings = (
    value: ReturnType<typeof classifyStage4CampaignModel>,
    reason: string,
  ): void => {
    assert.equal(value.reason_code, reason);
    assert.equal(value.plan_valid, false);
    assert.equal(value.evidence_valid, false);
    assert.equal(value.campaign_id_sha256, null);
    assert.equal(value.attempt_id_sha256, null);
    assert.equal(value.plan_sha256, null);
    assert.equal(value.evidence_sha256, null);
  };

  assertRejectedWithoutBindings(
    classifyStage4CampaignModel({ ...plan, execution_authorized: true }, evidence),
    "STAGE4_CAMPAIGN_AUTHORITY_PROMOTION",
  );
  assertRejectedWithoutBindings(
    classifyStage4CampaignModel({ ...plan, unreviewed: true }, evidence),
    "STAGE4_CAMPAIGN_INVALID_SHAPE",
  );
  assertRejectedWithoutBindings(
    classifyStage4CampaignModel({ ...plan, campaign_id_sha256: digest("wrong-campaign") }, evidence),
    "STAGE4_CAMPAIGN_IDENTITY_MISMATCH",
  );
  assertRejectedWithoutBindings(
    classifyStage4CampaignModel(
      { ...plan, attempt: { ...plan.attempt, attempt_id_sha256: digest("wrong-attempt") } },
      evidence,
    ),
    "STAGE4_CAMPAIGN_IDENTITY_MISMATCH",
  );
  assertRejectedWithoutBindings(
    classifyStage4CampaignModel(plan, { ...evidence, campaign_id_sha256: digest("mixed-campaign") }),
    "STAGE4_CAMPAIGN_IDENTITY_MISMATCH",
  );
  assertRejectedWithoutBindings(
    classifyStage4CampaignModel(plan, { ...evidence, attempt_id_sha256: digest("mixed-attempt") }),
    "STAGE4_CAMPAIGN_IDENTITY_MISMATCH",
  );
  assertRejectedWithoutBindings(
    classifyStage4CampaignModel(plan, { ...evidence, plan_sha256: digest("mixed-plan") }),
    "STAGE4_CAMPAIGN_BINDING_MISMATCH",
  );
  const replay = {
    ...evidence,
    events: [
      {
        ...event(requiredStep("S4-08/#359", 0), "replay"),
        evidence_sha256: plan.bindings.source_revision_sha256,
      },
    ],
  };
  assertRejectedWithoutBindings(classifyStage4CampaignModel(plan, replay), "STAGE4_CAMPAIGN_EVIDENCE_REPLAY");
});

test("artifact-root and campaign snapshots reject getters, inherited fields, and bounds before descriptor values", () => {
  const plan = fixture("s4-08-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const { artifact_set_root_sha256: _root, ...inputs } = plan.bindings;
  let invoked = 0;

  const getter = { ...inputs } as JsonObject;
  Object.defineProperty(getter, "source_revision_sha256", {
    enumerable: true,
    get: () => {
      invoked += 1;
      return inputs.source_revision_sha256;
    },
  });
  assert.equal(stage4CampaignArtifactSetRoot(getter), null);
  assert.equal(invoked, 0);

  const proxy = new Proxy(inputs, {
    ownKeys: () => {
      invoked += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(stage4CampaignArtifactSetRoot(proxy), null);
  assert.equal(invoked, 0);

  const inherited = Object.assign(Object.create({ source_revision_sha256: inputs.source_revision_sha256 }), inputs);
  delete inherited.source_revision_sha256;
  assert.equal(stage4CampaignArtifactSetRoot(inherited), null);

  const tooMany: JsonObject = {};
  for (let index = 0; index < 66; index += 1) {
    Object.defineProperty(tooMany, `k${index}`, {
      enumerable: true,
      get: () => {
        invoked += 1;
        return digest(`many:${index}`);
      },
    });
  }
  assert.equal(stage4CampaignArtifactSetRoot(tooMany), null);
  assert.equal(invoked, 0);

  const longKey: JsonObject = {};
  Object.defineProperty(longKey, "k".repeat(129), {
    enumerable: true,
    get: () => {
      invoked += 1;
      return digest("long-key");
    },
  });
  assert.equal(stage4CampaignArtifactSetRoot(longKey), null);
  assert.equal(invoked, 0);
  assert.equal(stage4CampaignArtifactSetRoot({ ...inputs, source_revision_sha256: "x".repeat(513) }), null);
});

test("campaign model rejects getters and proxies without invoking traps", () => {
  const plan = fixture("s4-08-plan-blocked-v1.json");
  const evidence = fixture("s4-08-evidence-empty-v1.json");
  let invoked = 0;
  Object.defineProperty(evidence, "events", {
    enumerable: true,
    get: () => {
      invoked += 1;
      return [];
    },
  });
  assert.equal(classifyStage4CampaignModel(plan, evidence).evidence_valid, false);
  assert.equal(invoked, 0);
  const proxy = new Proxy(plan, {
    getPrototypeOf: () => {
      invoked += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(classifyStage4CampaignModel(proxy, fixture("s4-08-evidence-empty-v1.json")).plan_valid, false);
  assert.equal(invoked, 0);
});

function s408RetainedState(): JsonObject {
  const bucketIdentity = digest("s408-state-bucket");
  return {
    custody_claimed: false,
    bucket: { kind: "aws-s3-bucket", bucket_name: "fixture-stage3-state", identity_sha256: bucketIdentity },
    object: {
      kind: "aws-s3-object",
      bucket_identity_sha256: bucketIdentity,
      key: "stage3/state.json",
      bytes_sha256: digest("s408-state-bytes"),
      identity_sha256: digest("s408-state-object"),
    },
  };
}

function s408Event(
  events: Stage4S408LifecycleEvent[],
  phase: Stage4S408LifecycleEvent["phase"],
  payload: JsonObject,
): Stage4S408LifecycleEvent {
  const prior = events.at(-1);
  return {
    phase,
    attempt_number: 1,
    prior_event_sha256: prior ? stage4S408LifecycleEventSha256(prior) : null,
    outcome: "fixture-claimed-success",
    payload,
  } as Stage4S408LifecycleEvent;
}

function s408Journal(
  policy: Stage4S408LifecyclePolicy,
  phaseCount: number = STAGE4_S408_LIFECYCLE_PHASES.length,
): Stage4S408LifecycleJournal {
  const events: Stage4S408LifecycleEvent[] = [];
  const push = (phase: Stage4S408LifecycleEvent["phase"], payload: JsonObject): void => {
    events.push(s408Event(events, phase, payload));
  };
  push("source", { operator_identity_sha256: digest("s408-operator"), source_sha256: digest("s408-source") });
  push("discovery", {
    discovery_identity_sha256: digest("s408-discovery"),
    indirect_classes: structuredClone(STAGE4_S408_UNRESOLVED_PROVIDER_CLASSES),
    indirect_counts: "unresolved-observation-only-uncapped",
    retained_state: s408RetainedState(),
  });
  push("saved-plan", {
    plan_projection: structuredClone(STAGE4_S408_FROZEN_PLAN_PROJECTION),
    plan_sha256: STAGE4_S408_FROZEN_PLAN_SHA256,
  });
  for (const phase of ["approval-check", "apply", "stop"] as const) {
    push(phase, {
      bound_prior_event_sha256: stage4S408LifecycleEventSha256(events.at(-1)),
      plan_sha256: STAGE4_S408_FROZEN_PLAN_SHA256,
    });
  }
  push("destroy", {
    bound_prior_event_sha256: stage4S408LifecycleEventSha256(events.at(-1)),
    plan_sha256: STAGE4_S408_FROZEN_PLAN_SHA256,
  });
  push("custody-inventory", {
    bound_prior_event_sha256: stage4S408LifecycleEventSha256(events.at(-1)),
    complete_pagination: true,
    custody_claimed: false,
    retained_state: s408RetainedState(),
    scopes: structuredClone(STAGE4_S408_CUSTODY_INVENTORY_SCOPES),
    tag_only: false,
  });
  push("retained-state-retirement", {
    bound_prior_event_sha256: stage4S408LifecycleEventSha256(events.at(-1)),
    retirement_record: structuredClone(STAGE4_S408_RETIREMENT_RECORD),
  });
  push("final-inventory", {
    bound_prior_event_sha256: stage4S408LifecycleEventSha256(events.at(-1)),
    claimed_identity_independent: true,
    complete_pagination: true,
    observer_identity_sha256: digest("s408-observer"),
    residue_count: 0,
    scopes: structuredClone(STAGE4_S408_INVENTORY_SCOPES),
    tag_only: false,
  });
  const policySha256 = stage4S408LifecyclePolicySha256(policy);
  assert.ok(policySha256);
  return {
    version: "cogs.stage4-s408-journal/v1",
    policy_sha256: policySha256,
    attempt_number: 1,
    retry_count: 0,
    continuation_count: 0,
    events: events.slice(0, phaseCount),
  };
}

function s408Mutate(
  journal: Stage4S408LifecycleJournal,
  mutation: (copy: JsonObject & { events: JsonObject[] }) => void,
): Stage4S408LifecycleJournal {
  const copy = structuredClone(journal) as unknown as JsonObject & { events: JsonObject[] };
  mutation(copy);
  return copy as unknown as Stage4S408LifecycleJournal;
}

test("S4-08 default policy stops after discovery with provider-derived caps unresolved", () => {
  const result = classifyStage4S408Lifecycle(STAGE4_S408_DEFAULT_POLICY, s408Journal(STAGE4_S408_DEFAULT_POLICY, 2));
  assert.equal(result.status, "STOPPED_UNRESOLVED");
  assert.equal(result.reason_code, "S408_UNRESOLVED_DERIVED_CAPS");
  assert.equal(result.next_phase, null);
  assert.equal(result.execution_authorized, false);
});

test("S4-08 explicit frozen fixture proves order only and remains blocked", () => {
  const result = classifyStage4S408Lifecycle(
    STAGE4_S408_FROZEN_FIXTURE_POLICY,
    s408Journal(STAGE4_S408_FROZEN_FIXTURE_POLICY),
  );
  assert.equal(result.status, "MODEL_ORDER_COMPLETE_BLOCKED");
  assert.equal(result.reason_code, "S408_MODEL_ORDER_COMPLETE_BLOCKED");
  for (const field of [
    "execution_authorized",
    "provider_truth_observed",
    "custody_claimed",
    "retirement_claimed",
    "zero_inventory_claimed",
    "retry_authorized",
  ] as const)
    assert.equal(result[field], false, field);
});

test("S4-08 apply failure requires the complete cleanup suffix", () => {
  const journal = s408Mutate(s408Journal(STAGE4_S408_FROZEN_FIXTURE_POLICY, 5), (copy) => {
    (copy.events[4] as JsonObject).outcome = "fixture-claimed-failed";
  });
  const result = classifyStage4S408Lifecycle(STAGE4_S408_FROZEN_FIXTURE_POLICY, journal);
  assert.equal(result.status, "PRESERVE_UNCERTAIN");
  assert.equal(result.next_phase, "stop");
  assert.equal(result.execution_authorized, false);
  const denied = s408Mutate(s408Journal(STAGE4_S408_FROZEN_FIXTURE_POLICY, 4), (copy) => {
    (copy.events[3] as JsonObject).outcome = "fixture-claimed-failed";
  });
  assert.equal(classifyStage4S408Lifecycle(STAGE4_S408_FROZEN_FIXTURE_POLICY, denied).next_phase, null);
});

test("S4-08 hostile fixture mutations fail closed", () => {
  const policy = STAGE4_S408_FROZEN_FIXTURE_POLICY;
  const original = s408Journal(policy);
  const event = (copy: { events: JsonObject[] }, index: number): JsonObject => copy.events[index] as JsonObject;
  const payload = (copy: { events: JsonObject[] }, index: number): JsonObject =>
    event(copy, index).payload as JsonObject;
  const cases: readonly [string, Stage4S408LifecyclePolicy, (copy: JsonObject & { events: JsonObject[] }) => void][] = [
    [
      "failed outcome",
      policy,
      (copy) => {
        event(copy, 9).outcome = "fixture-claimed-failed";
      },
    ],
    [
      "unknown outcome",
      policy,
      (copy) => {
        event(copy, 9).outcome = "unknown";
      },
    ],
    [
      "incomplete inventory",
      policy,
      (copy) => {
        payload(copy, 7).complete_pagination = false;
      },
    ],
    [
      "retained-state byte loss",
      policy,
      (copy) => {
        ((payload(copy, 7).retained_state as JsonObject).object as JsonObject).bytes_sha256 = digest("lost");
      },
    ],
    [
      "residue",
      policy,
      (copy) => {
        payload(copy, 9).residue_count = 1;
      },
    ],
    [
      "mixed policy digest",
      policy,
      (copy) => {
        copy.policy_sha256 = digest("other-policy");
      },
    ],
    [
      "changed plan",
      policy,
      (copy) => {
        payload(copy, 4).plan_sha256 = digest("other-plan");
      },
    ],
    [
      "mutable launch template",
      policy,
      (copy) => {
        const projection = payload(copy, 2).plan_projection as JsonObject;
        const reference = (projection.launch_template_references as JsonObject[])[0];
        assert.ok(reference);
        reference.version = "$Latest";
      },
    ],
    [
      "discovery identity collapse",
      policy,
      (copy) => {
        payload(copy, 1).discovery_identity_sha256 = digest("s408-operator");
      },
    ],
    [
      "observer identity collapse",
      policy,
      (copy) => {
        payload(copy, 9).observer_identity_sha256 = digest("s408-discovery");
      },
    ],
    [
      "retry drift",
      policy,
      (copy) => {
        copy.retry_count = 1;
      },
    ],
    [
      "attempt drift",
      policy,
      (copy) => {
        event(copy, 5).attempt_number = 2;
      },
    ],
    [
      "continuation drift",
      policy,
      (copy) => {
        copy.continuation_count = 1;
      },
    ],
    [
      "skipped phase",
      policy,
      (copy) => {
        copy.events.splice(4, 1);
      },
    ],
    [
      "duplicate phase",
      policy,
      (copy) => {
        const duplicate = copy.events[3];
        assert.ok(duplicate);
        copy.events.splice(4, 0, structuredClone(duplicate));
      },
    ],
    [
      "incomplete retirement record",
      policy,
      (copy) => {
        ((payload(copy, 8).retirement_record as JsonObject).s3 as JsonObject).all_multipart_uploads = "retained";
      },
    ],
    [
      "tag-only inventory",
      policy,
      (copy) => {
        payload(copy, 9).tag_only = true;
      },
    ],
    [
      "caller-frozen caps",
      { ...policy, caller_frozen_caps: { iam: 3 } } as unknown as Stage4S408LifecyclePolicy,
      () => {},
    ],
  ];
  for (const [name, changedPolicy, mutate] of cases) {
    const changed = s408Mutate(original, mutate);
    const result = classifyStage4S408Lifecycle(changedPolicy, changed);
    assert.equal(result.status, "PRESERVE_UNCERTAIN", name);
    assert.equal(result.execution_authorized, false, name);
    assert.equal(result.retirement_claimed, false, name);
  }
});

test("historical Stage 4 v1 semantic digests remain unchanged", () => {
  const expected = [
    [
      "s4-08-plan-blocked-v1.json",
      "s4-08-evidence-empty-v1.json",
      "dacca859481c505e871e87f363ca1fab859b6f9d0f455761582f0603ca7f9bf6",
      "778d5db910e0214a9b43926933ccb8662c62df9feb878e1e7abb97edf4c5de89",
    ],
    [
      "s4-09-plan-blocked-v1.json",
      "s4-09-evidence-empty-v1.json",
      "5569a6381a7fdc11d45cfa6ee7f040f2123cb5bb54f0ca2c456a36e3dfde10ba",
      "eb04d3697c3eefdc6bfd5fefc862bee62fb18f91fbcaf5057cf3cf124951e0f0",
    ],
    [
      "s4-10-plan-blocked-v1.json",
      "s4-10-evidence-empty-v1.json",
      "1dc846f581802c4b67056e15a15d68264325281518d5ec2262c2d179dcb1c40e",
      "001f5035ba90c8a47081384466c1f40c8c3e3c8960683984e068b230f09ef964",
    ],
  ] as const;
  for (const [plan, evidence, planSha, evidenceSha] of expected) {
    assert.equal(stage4CampaignPlanSha256(fixture(plan)), planSha, plan);
    assert.equal(stage4CampaignEvidenceSha256(fixture(evidence)), evidenceSha, evidence);
  }
});
