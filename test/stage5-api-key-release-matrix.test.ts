import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
) as Schema;
const matrixPath = resolve(root, "docs/security-evidence/stage5-api-key-release-matrix.draft.json");
const matrixBytes = readFileSync(matrixPath);
const matrix = JSON.parse(matrixBytes.toString("utf8")) as Matrix;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validate = ajv.compile(schema) as ValidateFunction;

type Data = Record<string, unknown>;
type Schema = Data & { $defs: Record<string, Data> };
type Criterion = Data & { id: string; dependencies: string[] };
type Matrix = Data & {
  stage4_dependency: Data;
  subscription_oauth: Data;
  release_candidate_binding: Data;
  principals: Data[];
  separation_constraints: Data[];
  support_claims: {
    posture: Data;
    api_key_providers: Data[];
    platform_profiles: Data[];
    unsupported_capabilities: Data[];
  };
  criterion_mappings: Criterion[];
};

type ExpectedCriterion = Readonly<{
  id: string;
  source_document: "DESIGN.md" | "IMPLEMENTATION.md";
  source_section: "24" | "45";
  source_ordinal: number;
  source_locator: string;
  accountable_owner_role: string;
  environment_profile: string;
  evidence_lane: string;
  evidence_contract: string;
  dependencies: readonly string[];
  blocker: string;
  applicability: string;
}>;

const local = (ordinal: number, environment = "local-static"): ExpectedCriterion =>
  criterion(ordinal, "design", "release-engineer", environment, "local-test", "future-local-test-reference-v1", [
    "S4-11",
    "release-candidate-binding",
  ]);
const eks = (ordinal: number, evidence = "future-eks-conformance-reference-v1"): ExpectedCriterion =>
  criterion(
    ordinal,
    "design",
    "campaign-operator",
    "eks-kata-release-candidate",
    "separately-approved-campaign",
    evidence,
    ["S4-11", "release-candidate-binding", "campaign-approval", "real-dependencies"],
    "s4-11-not-accepted",
  );
const load = (ordinal: number, source: "design" | "stage5" = "design"): ExpectedCriterion =>
  criterion(
    ordinal,
    source,
    "campaign-operator",
    "eks-kata-release-load",
    "separately-approved-campaign",
    "future-load-reference-v1",
    ["S4-11", "release-candidate-binding", "campaign-approval", "stage5-load-50"],
    "s4-11-not-accepted",
  );

function criterion(
  ordinal: number,
  source: "design" | "stage5",
  accountable_owner_role: string,
  environment_profile: string,
  evidence_lane: string,
  evidence_contract: string,
  dependencies: readonly string[],
  blocker = "release-candidate-binding-not-present",
  applicability = "mandatory-api-key-release",
): ExpectedCriterion {
  const design = source === "design";
  const prefix = design ? "DESIGN-24" : "STAGE5-45";
  const source_document = design ? "DESIGN.md" : "IMPLEMENTATION.md";
  const source_section = design ? "24" : "45";
  return {
    id: `${prefix}.${String(ordinal).padStart(2, "0")}`,
    source_document,
    source_section,
    source_ordinal: ordinal,
    source_locator: `${source_document}#${source_section}.${ordinal}`,
    accountable_owner_role,
    environment_profile,
    evidence_lane,
    evidence_contract,
    dependencies,
    blocker,
    applicability,
  };
}

const EXPECTED_CRITERIA: readonly ExpectedCriterion[] = [
  local(1),
  local(2),
  local(3, "linux-kvm"),
  eks(4),
  eks(5),
  eks(6),
  eks(7),
  eks(8),
  eks(9),
  eks(10),
  eks(11),
  eks(12),
  local(13),
  criterion(
    14,
    "design",
    "release-engineer",
    "local-static",
    "local-test",
    "future-local-test-reference-v1",
    ["S4-11", "release-candidate-binding", "oauth-disabled-branch"],
    "release-candidate-binding-not-present",
    "mandatory-api-key-disabled-oauth-branch",
  ),
  local(15, "linux-kvm"),
  local(16, "linux-kvm"),
  local(17, "linux-kvm"),
  local(18),
  local(19, "linux-kvm"),
  eks(20),
  criterion(
    21,
    "design",
    "campaign-operator",
    "eks-kata-release-load",
    "separately-approved-campaign",
    "future-load-reference-v1",
    ["S4-11", "release-candidate-binding", "campaign-approval", "real-dependencies"],
    "s4-11-not-accepted",
  ),
  load(22),
  criterion(
    1,
    "stage5",
    "independent-security-reviewer",
    "independent-review-exact-release-candidate",
    "independent-review",
    "future-acceptance-index-reference-v1",
    ["S4-11", "release-candidate-binding", "stage5-design-criteria", "real-dependencies"],
    "independent-identities-not-present",
  ),
  criterion(
    2,
    "stage5",
    "independent-security-reviewer",
    "independent-review-exact-release-candidate",
    "independent-review",
    "future-independent-review-reference-v1",
    ["release-candidate-binding", "independent-principal-bindings"],
    "independent-identities-not-present",
  ),
  criterion(
    3,
    "stage5",
    "independent-security-reviewer",
    "independent-review-exact-release-candidate",
    "independent-review",
    "future-independent-review-reference-v1",
    ["S4-11", "release-candidate-binding", "proxy-runtime-evidence"],
    "independent-identities-not-present",
  ),
  criterion(
    4,
    "stage5",
    "release-engineer",
    "local-static",
    "local-test",
    "future-local-test-reference-v1",
    ["S4-11", "release-candidate-binding", "provider-support-claims"],
    "release-candidate-binding-not-present",
    "mandatory-api-key-disabled-oauth-branch",
  ),
  load(5, "stage5"),
  criterion(
    6,
    "stage5",
    "staff-release-decider",
    "staff-release-decision",
    "staff-decision",
    "future-release-decision-reference-v1",
    ["stage5-load-50", "advertised-concurrency-claim"],
    "staff-decision-not-present",
  ),
  criterion(
    7,
    "stage5",
    "campaign-operator",
    "eks-kata-release-candidate",
    "separately-approved-campaign",
    "future-eks-conformance-reference-v1",
    ["S4-11", "release-candidate-binding", "campaign-approval", "real-dependencies"],
    "s4-11-not-accepted",
  ),
  criterion(
    8,
    "stage5",
    "independent-security-reviewer",
    "independent-review-exact-release-candidate",
    "independent-review",
    "future-independent-review-reference-v1",
    ["release-candidate-binding", "stage5-privacy-evidence", "independent-principal-bindings"],
    "independent-identities-not-present",
  ),
  criterion(
    9,
    "stage5",
    "campaign-operator",
    "eks-kata-release-candidate",
    "separately-approved-campaign",
    "future-privacy-deletion-reference-v1",
    ["S4-11", "release-candidate-binding", "campaign-approval", "real-dependencies"],
    "s4-11-not-accepted",
  ),
  criterion(10, "stage5", "release-engineer", "local-static", "local-test", "future-operations-reference-v1", [
    "S4-11",
    "release-candidate-binding",
    "operations-runbook-inventory",
  ]),
  criterion(
    11,
    "stage5",
    "zero-inventory-observer",
    "independent-zero-inventory",
    "independent-review",
    "future-zero-inventory-reference-v1",
    ["S4-11", "release-candidate-binding", "campaign-approval", "campaign-teardown-complete"],
    "independent-identities-not-present",
  ),
  criterion(
    12,
    "stage5",
    "independent-security-reviewer",
    "independent-review-exact-release-candidate",
    "independent-review",
    "future-independent-review-reference-v1",
    ["release-candidate-binding", "residual-risk-register", "independent-principal-bindings"],
    "independent-identities-not-present",
  ),
  criterion(
    13,
    "stage5",
    "staff-release-decider",
    "staff-release-decision",
    "staff-decision",
    "future-release-decision-reference-v1",
    ["stage5-design-criteria", "stage5-independent-review", "stage5-campaign-evidence", "stage5-zero-inventory"],
    "staff-decision-not-present",
  ),
];

const EXPECTED_SOURCE_HASHES = [
  "5e37e6e766300b80d8593254199bfa706fadc00366dfd4062cf60c67e6dd8d76",
  "ef56ad92cca734907faa373d98508b5cbc3f7711337e2c9ddf2a0e8019a56d15",
  "5a3dddb3c406fa3fa7fbb286eceae22dba2b05088e46917bc8b125e4791387e9",
  "118bf157e3361910b4021c28c4cf891d63ef7a8ba192fe8356f95d8d1af406d4",
  "745c9bfd7d706350025407655ec109ff0507d214d59366778114fc5668689e3f",
  "0f615a60d6f607f474a5c11b2c0218026f72665a756b2b4ee161bde8f7c4f8f4",
  "0a151572b5a5c230ae100b0c81c05a266560e6105a92d88cab81c101474d92be",
  "6896c63d9e05efd57e2514a2353eff1f725d5ef2f34c5a210b885c48f3bf0736",
  "b82b172a315be5b121c8f027b27fe046efc101c03b2d78b49bc6df9da1882cea",
  "dc7ec3603bc36b231f31a68573274ead359965aaf778cf49140b56ea96a50ecb",
  "9915715b4f1657557f00e7044d97cdd4c3466bf96fbca4915c4697066820d383",
  "7f58fa4ae0543f5096350e04d60acce174a1a2227bff5c30064312fc32b2691a",
  "cf865bb44097bbd9d822a0de1ac132a6f36bd6ff4861e1fce65d5a9bbb31c67d",
  "4c0bf5b2bbf34abbae162f5ac792ed22567e4fc222777640fbaf6e5ff3e11e22",
  "7b62d112e20e74920beab07acda4cf134631eb735819262579b2481ed8937a8b",
  "0dcc632dfffbc1f515f521bff61fa081502547fd947a247b4bfbd6ed15e354d4",
  "a458e6f3b3c7024fb209c6082420366d9d0f61e03adb5571176fa6151ebf1492",
  "ea67b8bff3a9fd9dd2407e49ec8f8fdc38ee2048171208dcd086b8fb499500e1",
  "96103ec947e100edf6933737837c9fe4da0b494de9aef29257f9f194411f55a4",
  "9c8f8ed4b1e2f726c4121628eab43a087f438f4d7b0e5a1e4af4fdd153d2bd2c",
  "5c749cfd476104529ed5ea605a26ed8f0a67221b9069ecc4314f0b9419a22f62",
  "17f197c49a1ea9d4f03e3f4c0c60a0c65bcf6ccbbe9a20a33b84a4fe8893b79f",
  "84a959a566db33ebedcf3c33136b1a0c7b6919a93b282c42afdd0325c23c9b97",
  "e0454d8936490ca6107365e7da7b28e9768149bd353cb4b8415a02e1b0c04bf3",
  "5dcc2b23388f082eef44a3c4ab59d2440f54101359a36993cc51b74ea8ce6549",
  "54e583a989c70f7b97d9ea57bc2810d9806eddcb6e41dc114ab731c36abb332c",
  "0b05c20c6a566581a2349a058a7259885d3d4554ac90b4c837166f82c2f7d933",
  "e972f39de9883e17647d722c6796b6c468d4dc6b42e89403be588bbf792122ba",
  "0bd4b45a32fcc19217fc17dcfd8ca3b3a5510edeed4cdfef825a2589415a0332",
  "9b9b49a2ea46609b24819579a8b85108cd3813edaa1617a6f8d4be8ef4e2471e",
  "01db3e7e33a296bbd41737162f39d9f0dd4600b3da8d43f78a3b54c0e8f38017",
  "328a40f0d9e52d0eec535ce621f14450a13e1b79205001ef1ba5e9fab71f1de2",
  "d551ec04cb838edd5112eebaa318653141203cd72d43541e3b714f20a5f984d5",
  "742f3d09c240fb50d448485de41634f04d20956b9e7624059e29e78538823a43",
  "07a9f6d0ddcd3faa9d098ee3ec73fc10bc78c22476a0741c5de642c1d34cd8f5",
] as const;

const EXPECTED_UNSUPPORTED = [
  "subscription-oauth",
  "production-daemon",
  "user-ingress",
  "session-sanitizer",
  "apps",
  "indexing-vector-search",
  "gcp-production",
  "azure-production",
  "hetzner-production",
  "other-cloud-production",
  "general-availability",
  "compliance-certification",
  "grpc-credential-injection",
  "non-http-egress",
] as const;

function accepted(value: unknown): boolean {
  return validate(value) as boolean;
}

function mutation(mutator: (value: Matrix) => void): Matrix {
  const value = structuredClone(matrix);
  mutator(value);
  return value;
}

function dataAt(rows: Data[], index: number): Data {
  const row = rows[index];
  assert.ok(row);
  return row;
}

function criterionSourceText(expected: ExpectedCriterion): string {
  const source = readFileSync(resolve(root, expected.source_document), "utf8");
  const sectionStart =
    expected.source_document === "DESIGN.md" ? "## 24. Acceptance criteria" : "## 45. Stage 5 exit criteria";
  const section = source.split(sectionStart)[1]?.split("\n---", 1)[0];
  assert.ok(section, `missing source section ${expected.source_locator}`);
  const pattern = expected.source_document === "DESIGN.md" ? /^([0-9]+)\. (.+)$/gmu : /^- \[ \] (.+)$/gmu;
  const rows = Array.from(section.matchAll(pattern), (match, index) => ({
    ordinal: expected.source_document === "DESIGN.md" ? Number(match[1]) : index + 1,
    text: expected.source_document === "DESIGN.md" ? match[2] : match[1],
  }));
  const row = rows.find((candidate) => candidate.ordinal === expected.source_ordinal);
  assert.ok(row?.text, `missing source criterion ${expected.source_locator}`);
  return row.text;
}

function inventoryProjection(row: Criterion): Data {
  return {
    id: row.id,
    source_document: row.source_document,
    source_section: row.source_section,
    source_ordinal: row.source_ordinal,
    source_locator: row.source_locator,
    accountable_owner_role: row.accountable_owner_role,
    environment_profile: row.environment_profile,
    evidence_lane: row.evidence_lane,
    evidence_contract: row.evidence_contract,
    dependencies: row.dependencies,
    blocker: row.blocker,
    applicability: row.applicability,
  };
}

function inventoryErrors(value: Matrix): string[] {
  const errors: string[] = [];
  if (value.criterion_mappings.length !== EXPECTED_CRITERIA.length) errors.push("criterion-count");
  for (const [index, expected] of EXPECTED_CRITERIA.entries()) {
    const actual = value.criterion_mappings[index];
    const expectedHash = EXPECTED_SOURCE_HASHES[index];
    if (
      actual === undefined ||
      expectedHash === undefined ||
      JSON.stringify(inventoryProjection(actual)) !== JSON.stringify(expected)
    ) {
      errors.push(`criterion-mismatch-${expected.id}`);
      continue;
    }
    const sourceHash = createHash("sha256").update(criterionSourceText(expected), "utf8").digest("hex");
    if (sourceHash !== expectedHash || actual.source_text_sha256 !== expectedHash) {
      errors.push(`source-digest-${expected.id}`);
    }
  }
  const ids = value.criterion_mappings.map((row) => row.id);
  if (new Set(ids).size !== ids.length) errors.push("duplicate-id");
  return errors;
}

function markdownScalar(value: unknown): string {
  if (value === null) return "`null`";
  if (typeof value === "boolean" || typeof value === "number") return `\`${String(value)}\``;
  assert.equal(typeof value, "string");
  return `\`${value}\``;
}

function renderSupportClaims(value: Matrix): string {
  const lines = [
    "<!-- BEGIN MACHINE-GENERATED SUPPORT CLAIMS -->",
    "## Machine-generated support and unsupported claims",
    "",
    "> Generated deterministically from `support_claims` and `subscription_oauth` in the machine JSON. The machine JSON is authoritative for support claims. The exact-render test covers this marked block; it does not claim to detect arbitrary natural-language paraphrases elsewhere.",
    "",
    "### Release posture",
    "",
    "| Claim | Value |",
    "|---|---:|",
  ];
  for (const [key, item] of Object.entries(value.support_claims.posture)) {
    lines.push(`| \`${key}\` | ${markdownScalar(item)} |`);
  }
  lines.push(
    "",
    "### Provisional API-key provider candidates",
    "",
    "| Provider | Auth class | Implementation state | Decision | Advertised | Real-provider evidence required | Evidence binding | Blocker |",
    "|---|---|---|---|---:|---:|---|---|",
  );
  for (const row of value.support_claims.api_key_providers) {
    lines.push(
      `| ${["provider", "auth_class", "implementation_state", "support_decision", "advertised", "real_provider_evidence_required", "evidence_binding_sha256", "blocker"].map((key) => markdownScalar(row[key])).join(" | ")} |`,
    );
  }
  lines.push("", "### Platform profiles", "", "| Profile | Status | Advertised |", "|---|---|---:|");
  for (const row of value.support_claims.platform_profiles) {
    lines.push(`| ${["profile", "status", "advertised"].map((key) => markdownScalar(row[key])).join(" | ")} |`);
  }
  lines.push(
    "",
    "### Unsupported capabilities and claims",
    "",
    "| Capability | Status | Advertised | Evidence binding | Reason |",
    "|---|---|---:|---|---|",
  );
  for (const row of value.support_claims.unsupported_capabilities) {
    lines.push(
      `| ${["capability", "status", "advertised", "evidence_binding_sha256", "reason_code"].map((key) => markdownScalar(row[key])).join(" | ")} |`,
    );
  }
  lines.push(
    "",
    "### Subscription OAuth blocker",
    "",
    "| Status | Advertised | Release gate | Deferred issue | Worker refresh tokens |",
    "|---|---:|---:|---:|---|",
    `| ${["status", "advertised", "release_gate", "deferred_issue", "worker_refresh_tokens"].map((key) => markdownScalar(value.subscription_oauth[key])).join(" | ")} |`,
    "<!-- END MACHINE-GENERATED SUPPORT CLAIMS -->",
  );
  return lines.join("\n");
}

function generatedSupportSection(document: string): string {
  const start = "<!-- BEGIN MACHINE-GENERATED SUPPORT CLAIMS -->";
  const end = "<!-- END MACHINE-GENERATED SUPPORT CLAIMS -->";
  const startIndex = document.indexOf(start);
  const endIndex = document.indexOf(end);
  assert.ok(startIndex >= 0 && endIndex > startIndex);
  assert.equal(document.indexOf(start, startIndex + 1), -1);
  assert.equal(document.indexOf(end, endIndex + 1), -1);
  return document.slice(startIndex, endIndex + end.length);
}

test("the committed matrix remains a bounded provisional draft with every authority false", () => {
  assert.equal(accepted(matrix), true, JSON.stringify(validate.errors));
  for (const field of [
    "qualified",
    "campaign_authorized",
    "cloud_execution_observed",
    "independent_review_observed",
    "release_evidence_observed",
    "matrix_finalized",
    "release_eligible",
  ]) {
    assert.equal(matrix[field], false, field);
  }
  assert.equal(matrix.draft, true);
  assert.equal(matrix.go_no_go, "not-available");
  assert.deepEqual(matrix.release_candidate_binding, {
    source_revision: null,
    artifact_root_sha256: null,
    binding_sha256: null,
    state: "not-present-blocking",
  });
});

test("all 22 DESIGN and 13 Stage 5 exit criteria match an independent immutable inventory", () => {
  assert.equal(EXPECTED_CRITERIA.length, 35);
  assert.equal(EXPECTED_SOURCE_HASHES.length, 35);
  assert.deepEqual(inventoryErrors(matrix), []);
  for (const row of matrix.criterion_mappings) {
    assert.equal(row.accountable_principal_id, null);
    assert.equal(row.evidence_binding_sha256, null);
    assert.equal(row.execution, "unexecuted-by-this-draft");
    assert.equal(row.release_eligible, false);
  }
});

test("criterion omission, duplicate substitution, and mapping drift fail closed", () => {
  const hostile = [
    mutation((value) => value.criterion_mappings.pop()),
    mutation((value) => {
      value.criterion_mappings[1] = structuredClone(value.criterion_mappings[0] as Criterion);
    }),
    mutation((value) => value.criterion_mappings.reverse()),
    mutation((value) => {
      (value.criterion_mappings[0] as Criterion).accountable_owner_role = "campaign-operator";
    }),
    mutation((value) => {
      (value.criterion_mappings[0] as Criterion).environment_profile = "eks-kata-release-load";
    }),
    mutation((value) => {
      (value.criterion_mappings[0] as Criterion).evidence_contract = "future-load-reference-v1";
    }),
    mutation((value) => {
      (value.criterion_mappings[0] as Criterion).dependencies = ["release-candidate-binding"];
    }),
    mutation((value) => {
      (value.criterion_mappings[0] as Criterion).applicability = "conditional-advertised-concurrency";
    }),
    mutation((value) => {
      (value.criterion_mappings[0] as Criterion).source_text_sha256 = "a".repeat(64);
    }),
  ];
  for (const value of hostile) {
    assert.notDeepEqual(inventoryErrors(value), []);
    assert.equal(accepted(value), false);
  }
});

test("the API-key and unsupported support-claim inventory is explicit and unadvertised", () => {
  assert.deepEqual(
    matrix.support_claims.api_key_providers.map((row) => row.provider),
    ["anthropic", "openai", "openrouter"],
  );
  for (const row of matrix.support_claims.api_key_providers) {
    assert.equal(row.auth_class, "api-key");
    assert.equal(row.support_decision, "provisional-candidate");
    assert.equal(row.advertised, false);
    assert.equal(row.real_provider_evidence_required, true);
    assert.equal(row.evidence_binding_sha256, null);
    assert.equal(row.blocker, "provider-real-evidence-not-present");
  }
  assert.deepEqual(
    matrix.support_claims.unsupported_capabilities.map((row) => row.capability),
    EXPECTED_UNSUPPORTED,
  );
  for (const row of matrix.support_claims.unsupported_capabilities) {
    assert.equal(row.status, "unsupported-unadvertised");
    assert.equal(row.advertised, false);
    assert.equal(row.evidence_binding_sha256, null);
  }
  assert.deepEqual(matrix.subscription_oauth, {
    status: "disabled-unadvertised",
    advertised: false,
    release_gate: false,
    deferred_issue: 13,
    worker_refresh_tokens: "forbidden",
  });
});

test("machine provider, OAuth, GA, compliance, daemon, and other-cloud contradictions are rejected", () => {
  const hostile = [
    mutation((value) => {
      value.support_claims.posture.general_availability = true;
    }),
    mutation((value) => {
      value.support_claims.posture.compliance_certified = true;
    }),
    mutation((value) => {
      dataAt(value.support_claims.api_key_providers, 0).advertised = true;
    }),
    mutation((value) => {
      dataAt(value.support_claims.unsupported_capabilities, 0).advertised = true;
    }),
    mutation((value) => {
      dataAt(value.support_claims.unsupported_capabilities, 6).status = "supported";
    }),
    mutation((value) => {
      value.subscription_oauth.status = "enabled";
    }),
  ];
  for (const value of hostile) assert.equal(accepted(value), false);
  for (const [index] of matrix.support_claims.api_key_providers.entries()) {
    assert.equal(
      accepted(
        mutation((value) => {
          dataAt(value.support_claims.api_key_providers, index).advertised = true;
        }),
      ),
      false,
    );
  }
  for (const [index] of matrix.support_claims.unsupported_capabilities.entries()) {
    assert.equal(
      accepted(
        mutation((value) => {
          dataAt(value.support_claims.unsupported_capabilities, index).status = "supported";
        }),
      ),
      false,
    );
  }
});

test("the marked support section is an exact deterministic rendering of authoritative machine claims", () => {
  const document = readFileSync(resolve(root, "docs/operations/stage-5-api-key-release-acceptance-matrix.md"), "utf8");
  assert.equal(generatedSupportSection(document), renderSupportClaims(matrix));
  assert.match(document, /machine JSON is authoritative for support claims/u);
  assert.match(document, /does not claim to detect arbitrary natural-language paraphrases elsewhere/u);
  const altered = document.replace("`anthropic`", "`anthropic-altered`");
  assert.notEqual(generatedSupportSection(altered), renderSupportClaims(matrix));
});

test("future principal fields and every required separation remain absent and explicitly blocking", () => {
  const expectedRoles = [
    "matrix-author",
    "release-engineer",
    "evidence-producer",
    "independent-security-reviewer",
    "campaign-operator",
    "campaign-approver",
    "budget-approver",
    "zero-inventory-observer",
    "staff-release-decider",
  ];
  assert.deepEqual(
    matrix.principals.map((row) => row.role),
    expectedRoles,
  );
  for (const principal of matrix.principals) {
    assert.equal(principal.principal_id, null);
    assert.equal(principal.identity_binding_sha256, null);
    assert.equal(principal.state, "not-present-blocking");
  }
  assert.equal(matrix.separation_constraints.length, 8);
  for (const separation of matrix.separation_constraints) {
    assert.equal(separation.relation, "must-be-distinct-authenticated-principals");
    assert.equal(separation.state, "blocked-identities-not-present");
  }
  assert.equal(
    accepted(
      mutation((value) => {
        dataAt(value.principals, 0).principal_id = "self-asserted";
      }),
    ),
    false,
  );
  assert.equal(
    accepted(
      mutation((value) => {
        dataAt(value.separation_constraints, 0).state = "satisfied";
      }),
    ),
    false,
  );
});

test("the provisional draft has no promotable evidence-reference instance or schema surface", () => {
  assert.equal("evidence_reference_contract" in matrix, false);
  assert.equal("evidence_reference_contract" in (schema.properties as Data), false);
  assert.equal("evidenceReference" in schema.$defs, false);
  assert.equal("evidenceReferenceSet" in schema.$defs, false);
  for (const field of ["evidence_reference_contract", "evidence_references", "report", "log", "diagnostics"]) {
    assert.equal(
      accepted(
        mutation((value) => {
          value[field] = [];
        }),
      ),
      false,
      field,
    );
  }
  const document = readFileSync(resolve(root, "docs/operations/stage-5-api-key-release-acceptance-matrix.md"), "utf8");
  assert.match(document, /No evidence-reference surface in this draft/u);
  assert.match(document, /separate future authority must define a new schema \*\*and reusable semantic validator\*\*/u);
  assert.match(document, /require exact criterion prefix\/order and unique criterion IDs/u);
  assert.match(document, /reject duplicate evidence, conflicting results/u);
});

test("authority promotion, evidence fabrication, unknown fields, and Stage 4 substitution fail closed", () => {
  const hostile: Matrix[] = [
    mutation((value) => {
      value.qualified = true;
    }),
    mutation((value) => {
      value.campaign_authorized = true;
    }),
    mutation((value) => {
      value.independent_review_observed = true;
    }),
    mutation((value) => {
      value.release_eligible = true;
    }),
    mutation((value) => {
      value.stage4_dependency.stage4_exit_satisfied = true;
    }),
    mutation((value) => {
      value.release_candidate_binding.source_revision = "a".repeat(40);
    }),
    mutation((value) => {
      dataAt(value.criterion_mappings, 0).evidence_binding_sha256 = "a".repeat(64);
    }),
    mutation((value) => {
      value.provider_target = "forbidden";
    }),
  ];
  for (const value of hostile) assert.equal(accepted(value), false);
  for (const file of ["stage4-static-preparation-evidence-v1.json", "stage4-teardown-verdict-v1.json"]) {
    assert.equal(accepted(JSON.parse(readFileSync(resolve(root, "schemas", file), "utf8"))), false);
  }
});

test("the human draft lists every source criterion and the corrected support, identity, and evidence boundaries", () => {
  const document = readFileSync(resolve(root, "docs/operations/stage-5-api-key-release-acceptance-matrix.md"), "utf8");
  for (const expected of EXPECTED_CRITERIA)
    assert.match(document, new RegExp(`\\b${expected.id.replaceAll(".", "\\.")}\\b`, "u"));
  for (const capability of EXPECTED_UNSUPPORTED) assert.match(document, new RegExp(`\\b${capability}\\b`, "u"));
  for (const provider of ["anthropic", "openai", "openrouter"])
    assert.match(document, new RegExp(`\\b${provider}\\b`, "iu"));
  assert.match(document, /35 immutable criterion mappings/u);
  assert.match(document, /principal identifiers and identity bindings are null/u);
  assert.match(document, /no evidence-reference instance or schema surface exists in this draft/u);
  assert.match(document, /S4-11 is a hard predecessor/u);
  assert.match(document, /#13 remains deferred/u);
  assert.match(document, /All checklist items remain open/u);
});
