import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const schema = JSON.parse(
  readFileSync(resolve(root, "schemas/stage5-api-key-release-matrix-draft-v1.json"), "utf8"),
) as object;
const matrixPath = resolve(root, "docs/security-evidence/stage5-api-key-release-matrix.draft.json");
const matrix = JSON.parse(readFileSync(matrixPath, "utf8")) as Matrix;
const validate = new Ajv2020({ allErrors: true, strict: true, strictRequired: false }).compile(
  schema,
) as ValidateFunction;

type Requirement = Record<string, unknown> & { id: string };
type Matrix = Record<string, unknown> & {
  stage4_dependency: Record<string, unknown>;
  subscription_oauth: Record<string, unknown>;
  requirements: {
    local_tests: Requirement[];
    independent_review: Requirement[];
    approved_campaigns: Requirement[];
  };
};

function accepted(value: unknown): boolean {
  return validate(value) as boolean;
}

function mutation(mutator: (value: Matrix) => void): Matrix {
  const value = structuredClone(matrix);
  mutator(value);
  return value;
}

function requirementAt(rows: Requirement[], index: number): Requirement {
  const row = rows[index];
  assert.ok(row);
  return row;
}

test("the committed Stage 5 API-key matrix is a valid provisional non-release draft", () => {
  assert.equal(accepted(matrix), true, JSON.stringify(validate.errors));
  assert.equal(matrix.authority, "provisional-local-static-requirements-only");
  assert.equal(matrix.draft, true);
  assert.equal(matrix.provisional, true);
  assert.equal(matrix.qualified, false);
  assert.equal(matrix.matrix_finalized, false);
  assert.equal(matrix.release_eligible, false);
  assert.equal(matrix.go_no_go, "not-available");
  assert.deepEqual(matrix.stage4_dependency, {
    gate: "S4-11",
    state: "required-not-observed-by-this-draft",
    stage4_exit_satisfied: false,
    evidence_accepted: false,
  });
  assert.deepEqual(matrix.subscription_oauth, {
    status: "disabled-unadvertised",
    advertised: false,
    release_gate: false,
    deferred_issue: 13,
    worker_refresh_tokens: "forbidden",
  });
});

test("the three requirement authorities are disjoint, fixed, and entirely unobserved", () => {
  const { local_tests: local, independent_review: review, approved_campaigns: campaigns } = matrix.requirements;
  assert.equal(local.length, 8);
  assert.equal(review.length, 7);
  assert.equal(campaigns.length, 12);
  assert.equal(new Set([...local, ...review, ...campaigns].map((row) => row.id)).size, 27);

  for (const row of local) {
    assert.equal(row.execution, "unexecuted-by-this-draft");
    assert.equal(row.evidence, "not-observed-by-this-draft");
    assert.equal(row.review, "not-reviewed-by-this-draft");
    assert.equal(row.release_eligible, false);
    assert.equal("approval" in row, false);
    assert.equal("authority_required" in row, false);
  }
  for (const row of review) {
    assert.equal(row.authority_required, "independent-reviewer-bound-to-exact-release-candidate");
    assert.equal(row.review, "unperformed-by-this-draft");
    assert.equal(row.evidence, "not-observed-by-this-draft");
    assert.equal(row.release_eligible, false);
    assert.equal("execution" in row, false);
    assert.equal("approval" in row, false);
  }
  for (const row of campaigns) {
    assert.equal(row.approval_mode, "separate-exact-revision-manual-approval");
    assert.equal(row.approval, "not-present-in-this-draft");
    assert.equal(row.execution, "unexecuted-by-this-draft");
    assert.equal(row.evidence, "not-observed-by-this-draft");
    assert.equal(row.release_eligible, false);
    assert.equal("review" in row, false);
  }
});

test("the schema rejects authority promotion, premature finalization, and OAuth enablement", () => {
  const hostile: Matrix[] = [
    mutation((value) => {
      value.authority = "authoritative-production-profile";
    }),
    mutation((value) => {
      value.qualified = true;
    }),
    mutation((value) => {
      value.matrix_finalized = true;
    }),
    mutation((value) => {
      value.release_eligible = true;
    }),
    mutation((value) => {
      value.go_no_go = "go";
    }),
    mutation((value) => {
      value.stage4_dependency.state = "accepted";
    }),
    mutation((value) => {
      value.stage4_dependency.stage4_exit_satisfied = true;
    }),
    mutation((value) => {
      value.stage4_dependency.evidence_accepted = true;
    }),
    mutation((value) => {
      value.subscription_oauth.status = "enabled";
    }),
    mutation((value) => {
      value.subscription_oauth.advertised = true;
    }),
    mutation((value) => {
      value.subscription_oauth.release_gate = true;
    }),
    mutation((value) => {
      value.subscription_oauth.deferred_issue = 363;
    }),
    mutation((value) => {
      value.subscription_oauth.worker_refresh_tokens = "allowed";
    }),
  ];
  for (const value of hostile) assert.equal(accepted(value), false);
});

test("the schema rejects fabricated execution, review, approval, and evidence states", () => {
  const hostile: Matrix[] = [
    mutation((value) => {
      requirementAt(value.requirements.local_tests, 0).execution = "pass";
    }),
    mutation((value) => {
      requirementAt(value.requirements.local_tests, 0).evidence = "observed";
    }),
    mutation((value) => {
      requirementAt(value.requirements.independent_review, 0).review = "accepted";
    }),
    mutation((value) => {
      requirementAt(value.requirements.independent_review, 0).evidence = "reviewed";
    }),
    mutation((value) => {
      requirementAt(value.requirements.approved_campaigns, 0).approval = "approved";
    }),
    mutation((value) => {
      requirementAt(value.requirements.approved_campaigns, 0).execution = "pass";
    }),
    mutation((value) => {
      requirementAt(value.requirements.approved_campaigns, 0).evidence = "observed";
    }),
    mutation((value) => {
      requirementAt(value.requirements.approved_campaigns, 0).release_eligible = true;
    }),
  ];
  for (const value of hostile) assert.equal(accepted(value), false);
});

test("the exact requirement inventory and conditional concurrency gates fail closed", () => {
  for (const collection of ["local_tests", "independent_review", "approved_campaigns"] as const) {
    assert.equal(
      accepted(
        mutation((value) => {
          value.requirements[collection].pop();
        }),
      ),
      false,
      `${collection} missing row`,
    );
    assert.equal(
      accepted(
        mutation((value) => {
          value.requirements[collection].reverse();
        }),
      ),
      false,
      `${collection} reordered`,
    );
  }

  assert.equal(
    accepted(
      mutation((value) => {
        requirementAt(value.requirements.approved_campaigns, 6).gate = "mandatory-api-key-release";
      }),
    ),
    false,
  );
  assert.equal(
    accepted(
      mutation((value) => {
        requirementAt(value.requirements.approved_campaigns, 5).gate = "conditional-advertised-concurrency";
      }),
    ),
    false,
  );
  assert.equal(
    accepted(
      mutation((value) => {
        value.requirements.independent_review[0] = structuredClone(requirementAt(value.requirements.local_tests, 0));
      }),
    ),
    false,
  );
});

test("unknown fields and cross-domain Stage 4 artifacts cannot enter the draft contract", () => {
  const hostile: Matrix[] = [
    mutation((value) => {
      value.campaign_authorized = true;
    }),
    mutation((value) => {
      value.stage4_dependency.cloud_execution_observed = true;
    }),
    mutation((value) => {
      value.subscription_oauth.refresh_token = "forbidden";
    }),
    mutation((value) => {
      requirementAt(value.requirements.local_tests, 0).diagnostic = "arbitrary";
    }),
    mutation((value) => {
      requirementAt(value.requirements.independent_review, 0).reviewer = "self-asserted";
    }),
    mutation((value) => {
      requirementAt(value.requirements.approved_campaigns, 0).provider_target = "forbidden";
    }),
  ];
  for (const value of hostile) assert.equal(accepted(value), false);

  const stage4Static = JSON.parse(
    readFileSync(resolve(root, "schemas/stage4-static-preparation-evidence-v1.json"), "utf8"),
  );
  const stage4Verdict = JSON.parse(readFileSync(resolve(root, "schemas/stage4-teardown-verdict-v1.json"), "utf8"));
  assert.equal(accepted(stage4Static), false);
  assert.equal(accepted(stage4Verdict), false);
});

test("the human matrix preserves the machine inventory and uncertainty boundaries", () => {
  const document = readFileSync(resolve(root, "docs/operations/stage-5-api-key-release-acceptance-matrix.md"), "utf8");
  for (const row of [
    ...matrix.requirements.local_tests,
    ...matrix.requirements.independent_review,
    ...matrix.requirements.approved_campaigns,
  ]) {
    assert.match(document, new RegExp(`\\b${row.id.replaceAll(".", "\\.")}\\b`, "u"));
  }
  assert.match(document, /draft and provisional/u);
  assert.match(document, /S4-11 is a hard predecessor/u);
  assert.match(document, /stage4_exit_satisfied=false/u);
  assert.match(document, /Subscription OAuth is disabled and absent from the advertised support matrix/iu);
  assert.match(document, /subscription OAuth remains deferred to #13/iu);
  assert.match(document, /An approval is not execution evidence/u);
  assert.match(document, /future decision must use a new authority\/schema/u);
  assert.match(document, /All checklist items remain open/u);
});
