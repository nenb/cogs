import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import {
  classifyStage4CampaignApprovalDraft,
  stage4CampaignApprovalDraftSha256,
} from "../scripts/stage4-campaign-approval.ts";

type JsonObject = Record<string, unknown>;
const fixturePath = resolve(import.meta.dirname, "fixtures/stage4-campaign/approval-draft-blocked-v1.json");
const fixture = (): JsonObject => JSON.parse(readFileSync(fixturePath, "utf8")) as JsonObject;

test("#358 draft is exact, one-attempt, entirely unapproved, and non-authorizing", () => {
  const value = fixture();
  const result = classifyStage4CampaignApprovalDraft(value);
  assert.equal(result.status, "valid-unapproved-blocked-draft");
  assert.equal(result.reason_code, "STAGE4_APPROVAL_DRAFT_VALID_BLOCKED");
  assert.equal(result.envelope_sha256, stage4CampaignApprovalDraftSha256(value));
  assert.equal(result.approval_present, false);
  assert.equal(result.execution_authorized, false);
  assert.equal(result.retry_authorized, false);
  assert.equal(result.provider_truth_observed, false);
  assert.equal(result.stage4_exit_satisfied, false);

  assert.deepEqual(value.attempt, {
    state: "unnamed",
    campaign_issue: null,
    attempt_id_sha256: null,
    attempt_number: 1,
    maximum_attempts: 1,
    retry: "prohibited",
  });
  assert.equal((value.approval as JsonObject).state, "unapproved");
  assert.equal(((value.dependencies as JsonObject).issue_42 as JsonObject).state, "evidence-absent");
  for (const field of ["source_binding", "account_binding"]) {
    assert.equal((value[field] as JsonObject).state, "absent");
  }
  for (const field of ["resource_envelope", "budget", "expiry", "destroy", "independent_inventory"]) {
    assert.equal((value[field] as JsonObject).state, "unapproved");
  }
  for (const identity of Object.values(value.identities as JsonObject)) {
    assert.deepEqual(identity, { state: "absent", subject_reference_sha256: null });
  }
});

test("#358 rejects every isolated approval or authority promotion", () => {
  const mutations: Array<[string, (value: JsonObject) => void, string]> = [
    ["execution", (value) => (value.execution_authorized = true), "STAGE4_APPROVAL_DRAFT_AUTHORITY_PROMOTION"],
    [
      "approval",
      (value) => ((value.approval as JsonObject).state = "approved"),
      "STAGE4_APPROVAL_DRAFT_AUTHORITY_PROMOTION",
    ],
    [
      "second attempt",
      (value) => ((value.attempt as JsonObject).maximum_attempts = 2),
      "STAGE4_APPROVAL_DRAFT_AUTHORITY_PROMOTION",
    ],
    [
      "retry",
      (value) => ((value.attempt as JsonObject).retry = "allowed"),
      "STAGE4_APPROVAL_DRAFT_AUTHORITY_PROMOTION",
    ],
    [
      "issue 42",
      (value) => (((value.dependencies as JsonObject).issue_42 as JsonObject).state = "accepted"),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    [
      "identity",
      (value) => (((value.identities as JsonObject).campaign_operator as JsonObject).state = "present"),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    [
      "source",
      (value) => ((value.source_binding as JsonObject).revision_sha256 = "a".repeat(64)),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    [
      "account",
      (value) => ((value.account_binding as JsonObject).region = "us-east-1"),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    ["budget", (value) => ((value.budget as JsonObject).spend_cap = 20), "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE"],
    [
      "expiry",
      (value) => ((value.expiry as JsonObject).expires_at = "2026-08-01T00:00:00Z"),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    [
      "destroy",
      (value) => ((value.destroy as JsonObject).path_artifact_sha256 = "b".repeat(64)),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    [
      "inventory",
      (value) => ((value.independent_inventory as JsonObject).zero_claimed = true),
      "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE",
    ],
    ["unknown executor", (value) => (value.executor = "apply"), "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE"],
  ];
  for (const [name, mutate, reason] of mutations) {
    const value = structuredClone(fixture());
    mutate(value);
    const result = classifyStage4CampaignApprovalDraft(value);
    assert.equal(result.draft_valid, false, name);
    assert.equal(result.execution_authorized, false, name);
    assert.equal(result.reason_code, reason, name);
  }
});

test("#358 snapshots hostile objects without invoking traps", () => {
  let invoked = 0;
  const getter = fixture();
  Object.defineProperty(getter, "execution_authorized", {
    enumerable: true,
    get: () => {
      invoked += 1;
      return true;
    },
  });
  assert.equal(classifyStage4CampaignApprovalDraft(getter).draft_valid, false);
  assert.equal(invoked, 0);

  const proxy = new Proxy(fixture(), {
    ownKeys: () => {
      invoked += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(classifyStage4CampaignApprovalDraft(proxy).draft_valid, false);
  assert.equal(invoked, 0);
});
