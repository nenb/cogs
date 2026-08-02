import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
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
  stage4CampaignPlanSha256,
} from "../scripts/stage4-campaign-model.ts";

type JsonObject = Record<string, unknown>;
const fixture = (name: string): JsonObject =>
  JSON.parse(readFileSync(resolve(import.meta.dirname, `fixtures/stage4-campaign/${name}`), "utf8")) as JsonObject;
const digest = (label: string): string => createHash("sha256").update(`stage4-local-fixture:${label}`).digest("hex");
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
    assert.deepEqual(plan.terminal_order, STAGE4_CAMPAIGN_TERMINAL_ORDER, issue);
    assert.deepEqual(plan.attempt, { number: 1, maximum_attempts: 1, retry: "prohibited", approval_state: "absent" });
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
  assert.equal(classifyStage4CampaignModel(originalPlan, retry).reason_code, "STAGE4_CAMPAIGN_INVALID_SHAPE");

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
  assert.equal(
    classifyStage4CampaignModel(originalPlan, wrongProducer).reason_code,
    "STAGE4_CAMPAIGN_INVALID_TRANSITION",
  );
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
