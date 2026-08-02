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

test("uncertainty is sticky and directs qualification claims to stop without accepting later events", () => {
  const plan = fixture("s4-09-plan-blocked-v1.json") as unknown as Stage4CampaignPlan;
  const evidence = fixture("s4-09-evidence-empty-v1.json") as unknown as Stage4CampaignEvidence;
  const uncertain = {
    ...evidence,
    events: [event(requiredStep("S4-09/#360", 0), "uncertain", "uncertain")],
  };
  const result = classifyStage4CampaignModel(plan, uncertain);
  assert.equal(result.status, "preserve-uncertain");
  assert.equal(result.reason_code, "STAGE4_CAMPAIGN_UNCERTAIN");
  assert.equal(result.next_phase, "stop");
  assert.equal(advanceStage4CampaignModel(plan, uncertain, event("stop", "after-uncertainty")), null);
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
