import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const schemaDirectory = resolve(import.meta.dirname, "../schemas");
const sha = (digit: string): string => digit.repeat(64);

type JsonObject = Record<string, unknown>;
type RegistryEntry = {
  file: string;
  sample: () => JsonObject;
};

const STATIC_CHECK_IDS = [
  "static.source.exact-clean-revision",
  "static.source.complete-bounded-inventory",
  "static.config.strict-synthetic-values",
  "static.render.pinned-local-renderer",
  "static.render.deterministic-bounded-parse",
  "static.sandbox.explicit-kata-runtimeclass-no-fallback",
  "static.sandbox.no-trusted-sidecar-shape",
  "static.identity.sandbox-token-automount-disabled",
  "static.identity.scoped-trusted-worker-openbao-handles-sandbox-no-identity",
  "static.network.declarative-default-deny-shape",
  "static.network.no-public-ingress-or-provider-resource",
  "static.proxy.immutable-session-source-binding-revocation-no-fallback",
  "static.scheduling.trusted-sandbox-separation-shape",
  "static.storage.workspace-session-role-separation-shape",
  "static.limits.resource-and-lifecycle-bounds-present",
  "static.telemetry.metadata-only-otlp-and-bounded-audit-wal-failure",
  "static.material.no-inline-sensitive-content",
] as const;

const FUTURE_EKS_CHECK_IDS = [
  "eks.launch-template.nested-virtualization-applied",
  "eks.node.kvm-modules-device-and-active-acceleration",
  "eks.runtime.actual-kata-root-distinct-kernel-no-trusted-sidecar",
  "eks.network.guest-root-cni-bypass-resistance",
  "eks.identity.no-kubernetes-cloud-openbao-or-ca-credentials",
  "eks.isolation.api-admin-cross-session-and-storage-denial",
  "eks.conformance.real-authz-wal-openbao-proxy-otlp-dependencies",
  "eks.storage.ebs-attach-reattach-and-exclusive-writer",
  "eks.functional.real-pi-end-to-end",
  "eks.performance.scheduled-to-ssh-ready-and-first-tool-percentiles",
  "eks.recovery.stage4-failure-campaign",
  "eks.lifecycle.repeatable-install-destroy-and-no-runtime-fallback",
  "eks.teardown.independent-zero-resource-inventory-and-cost",
] as const;

// Keep evolving teardown terminology in one table so a contract rename is mechanical.
const TEARDOWN_CONTRACT = {
  planVersion: "cogs.stage4-teardown-plan/v1",
  verdictVersion: "cogs.stage4-teardown-verdict/v1",
  completeStatus: "evidence-order-complete",
  completeReason: "STAGE4_EVIDENCE_ORDER_COMPLETE",
  rows: [
    ["freeze-reconcilers", "control-observer"],
    ["close-admission", "admission-observer"],
    ["revoke-credentials", "credential-observer"],
    ["revoke-readiness", "readiness-observer"],
    ["remove-session-workloads", "workload-mutator"],
    ["verify-kubernetes-zero", "kubernetes-zero-observer"],
    ["remove-cluster-infrastructure", "infrastructure-mutator"],
    ["record-external-cloud-inventory-claim", "claimed-external-inventory-observer"],
  ],
} as const;

function staticSample(): JsonObject {
  return {
    version: "cogs.stage4-static-preparation-evidence/v1",
    authority: "static-only-stage4-preparation",
    qualified: false,
    campaign_authorized: false,
    cloud_execution_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    asserted_static_outcome: "conforming",
    artifacts: {
      source_sha256: sha("1"),
      chart_sha256: sha("2"),
      values_sha256: sha("3"),
      render_sha256: sha("4"),
      repeated_render_sha256: sha("4"),
      deterministic: true,
    },
    static_checks: STATIC_CHECK_IDS.map((id) => ({
      id,
      applicability: "static-shape-only",
      execution: "executed-local-static",
      outcome: "satisfied",
    })),
    future_eks_checks: FUTURE_EKS_CHECK_IDS.map((id) => ({
      id,
      applicability: "required-for-future-exact-run-eks",
      execution: "unexecuted",
      outcome: "not-observed",
    })),
  };
}

function teardownPlanSample(): JsonObject {
  return {
    version: TEARDOWN_CONTRACT.planVersion,
    source_sha256: sha("0"),
    profile_sha256: sha("1"),
    phases: TEARDOWN_CONTRACT.rows.map(([phase, producer_class], index) => ({
      phase,
      producer_class,
      state: "observed",
      evidence_sha256: sha((index + 2).toString(16)),
    })),
  };
}

function campaignFixture(name: string): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, `fixtures/stage4-campaign/${name}`), "utf8"),
  ) as JsonObject;
}

function campaignApprovalDraftSample(): JsonObject {
  return campaignFixture("approval-draft-blocked-v1.json");
}

function campaignApprovalVerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-campaign-approval-verdict/v1",
    authority: "local-static-unapproved-envelope-classifier",
    draft_valid: true,
    approval_present: false,
    execution_authorized: false,
    retry_authorized: false,
    provider_truth_observed: false,
    stage4_exit_satisfied: false,
    envelope_sha256: sha("a"),
    status: "valid-unapproved-blocked-draft",
    reason_code: "STAGE4_APPROVAL_DRAFT_VALID_BLOCKED",
  };
}

function campaignPlanSample(): JsonObject {
  return campaignFixture("s4-08-plan-blocked-v1.json");
}

function campaignEvidenceSample(): JsonObject {
  return campaignFixture("s4-08-evidence-empty-v1.json");
}

function campaignModelVerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-campaign-model-verdict/v1",
    authority: "local-static-campaign-state-classifier",
    campaign_issue: "S4-08/#359",
    campaign_id_sha256: sha("c"),
    attempt_id_sha256: sha("d"),
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
    plan_sha256: sha("a"),
    evidence_sha256: sha("b"),
    status: "awaiting-claimed-evidence",
    next_phase: "topology.source-render-object-binding",
    reason_code: "STAGE4_CAMPAIGN_AWAITING_CLAIMED_EVIDENCE",
  };
}

function exitReviewMatrixSample(): JsonObject {
  return campaignFixture("s4-11-exit-matrix-template-v1.json");
}

function exitReviewReportSample(): JsonObject {
  return campaignFixture("s4-11-exit-report-template-v1.json");
}

function exitReviewVerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-exit-review-verdict/v1",
    authority: "local-static-stage4-exit-template-classifier",
    template_valid: true,
    review_complete: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    matrix_sha256: sha("a"),
    report_sha256: sha("b"),
    status: "valid-blocked-template",
    reason_code: "STAGE4_EXIT_TEMPLATE_VALID_BLOCKED",
  };
}

function offlineReadinessPackageSample(): JsonObject {
  return JSON.parse(
    readFileSync(
      resolve(import.meta.dirname, "../docs/security-evidence/stage4-offline-readiness-package.json"),
      "utf8",
    ),
  ) as JsonObject;
}

function offlineReadinessVerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-offline-readiness-verdict/v1",
    authority: "local-static-stage4-readiness-classifier",
    local_preparation_complete: true,
    local_preparation_scope: "bounded-package-assembly-and-local-validation-only",
    trusted_render_preparation_complete: true,
    exact_image_runtime_closure_satisfied: false,
    campaign_request_ready: false,
    campaign_approved: false,
    cloud_authorized: false,
    cloud_execution_observed: false,
    provider_truth_observed: false,
    current_resources_observed: false,
    zero_resources_claimed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    package_sha256: sha("a"),
    binding_root_sha256: sha("b"),
    status: "local-preparation-complete-blocked",
    reason_code: "STAGE4_LOCAL_PREPARATION_COMPLETE_CAMPAIGN_BLOCKED",
    blockers: [
      "ISSUE_42_OPEN",
      "NIC_V0_11_0_MODULE_0_7_0_LAUNCH_TEMPLATE_CAPABILITY_MISSING",
      "EKS_AMI_IMAGE_RELEASE_KERNEL_UNRESOLVED",
      "PROPOSED_ACCOUNT_BINDING_ABSENT",
      "CURRENT_PRICE_NOT_REVALIDATED",
      "CURRENT_QUOTA_NOT_REVALIDATED",
      "SEPARATED_CAMPAIGN_IDENTITIES_ABSENT",
      "CAMPAIGN_ENVELOPE_AND_APPROVAL_ABSENT",
      "NO_EXECUTABLE_PROVIDER_ROUTE",
      "RELEASE_IMAGE_SET_ABSENT",
      "CONTAINERD_ARTIFACT_IDENTITY_UNRESOLVED",
      "QEMU_ARTIFACT_IDENTITY_UNRESOLVED",
    ],
  };
}

function policyContractSample(): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, "fixtures/stage4-policy/valid-contract-v1.json"), "utf8"),
  ) as JsonObject;
}

function policyProbeSample(): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, "fixtures/stage4-policy/hostile-probes-v1.json"), "utf8"),
  ) as JsonObject;
}

function policyPayloadSample(): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, "fixtures/stage4-policy/valid-audit-wal-record-v1.json"), "utf8"),
  ) as JsonObject;
}

function storageLaunchContractSample(): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, "fixtures/stage4-storage-launch/valid-active-v1.json"), "utf8"),
  ) as JsonObject;
}

function storageLaunchVerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-storage-launch-verdict/v1",
    authority: "local-static-storage-launch-classifier",
    qualified: false,
    campaign_authorized: false,
    cloud_execution_observed: false,
    kubernetes_execution_observed: false,
    provider_truth_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    graph_sha256: sha("d"),
    status: "admissible-static-graph",
    reason_code: "STAGE4_STORAGE_LAUNCH_GRAPH_VALID",
    preservation: null,
  };
}

function teardownVerdictSample(): JsonObject {
  return {
    version: TEARDOWN_CONTRACT.verdictVersion,
    authority: "local-teardown-order-classifier",
    cloud_execution_observed: false,
    cloud_inventory_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    source_sha256: sha("0"),
    profile_sha256: sha("1"),
    plan_sha256: sha("a"),
    evidence_root_sha256: sha("b"),
    status: TEARDOWN_CONTRACT.completeStatus,
    next_phase: null,
    accepted_phase_count: TEARDOWN_CONTRACT.rows.length,
    reason_code: TEARDOWN_CONTRACT.completeReason,
  };
}

function nicContractSample(): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../deploy/nic/stage4-sandbox-node-group-contract.json"), "utf8"),
  ) as JsonObject;
}

function nicVerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-nic-sandbox-node-group-verdict/v1",
    authority: "local-static-nic-contract-classifier",
    campaign_authorized: false,
    cloud_execution_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    contract_sha256: sha("c"),
    nic_source_pin_resolved: true,
    node_image_pin_resolved: false,
    launch_template_capability_resolved: false,
    status: "blocked-missing-capability",
    reason_code: "STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING",
  };
}

const STAGE4_SCHEMA_REGISTRY = [
  { file: "stage4-campaign-approval-draft-v1.json", sample: campaignApprovalDraftSample },
  { file: "stage4-campaign-approval-verdict-v1.json", sample: campaignApprovalVerdictSample },
  { file: "stage4-campaign-evidence-v1.json", sample: campaignEvidenceSample },
  { file: "stage4-campaign-model-verdict-v1.json", sample: campaignModelVerdictSample },
  { file: "stage4-campaign-plan-v1.json", sample: campaignPlanSample },
  { file: "stage4-exit-review-matrix-template-v1.json", sample: exitReviewMatrixSample },
  { file: "stage4-exit-review-report-template-v1.json", sample: exitReviewReportSample },
  { file: "stage4-exit-review-verdict-v1.json", sample: exitReviewVerdictSample },
  { file: "stage4-nic-sandbox-node-group-contract-v1.json", sample: nicContractSample },
  { file: "stage4-nic-sandbox-node-group-verdict-v1.json", sample: nicVerdictSample },
  { file: "stage4-offline-readiness-package-v1.json", sample: offlineReadinessPackageSample },
  { file: "stage4-offline-readiness-verdict-v1.json", sample: offlineReadinessVerdictSample },
  { file: "stage4-policy-contract-v1.json", sample: policyContractSample },
  { file: "stage4-policy-payload-v1.json", sample: policyPayloadSample },
  { file: "stage4-policy-probe-suite-v1.json", sample: policyProbeSample },
  { file: "stage4-static-preparation-evidence-v1.json", sample: staticSample },
  { file: "stage4-storage-launch-contract-v1.json", sample: storageLaunchContractSample },
  { file: "stage4-storage-launch-verdict-v1.json", sample: storageLaunchVerdictSample },
  { file: "stage4-teardown-plan-v1.json", sample: teardownPlanSample },
  { file: "stage4-teardown-verdict-v1.json", sample: teardownVerdictSample },
] as const satisfies readonly RegistryEntry[];

function compileRegistry(): Map<string, ValidateFunction> {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  return new Map(
    STAGE4_SCHEMA_REGISTRY.map(({ file }) => {
      const schema = JSON.parse(readFileSync(resolve(schemaDirectory, file), "utf8")) as object;
      return [file, ajv.compile(schema)];
    }),
  );
}

function validatorFor(validators: Map<string, ValidateFunction>, file: string): ValidateFunction {
  const validator = validators.get(file);
  assert.ok(validator, `missing Stage 4 schema validator for ${file}`);
  return validator;
}

function assertRejected(validator: ValidateFunction, sample: unknown, message: string): void {
  assert.equal(validator(sample), false, message);
}

test("the bounded Stage 4 registry compiles its strict positive samples", () => {
  assert.deepEqual(
    STAGE4_SCHEMA_REGISTRY.map(({ file }) => file),
    [
      "stage4-campaign-approval-draft-v1.json",
      "stage4-campaign-approval-verdict-v1.json",
      "stage4-campaign-evidence-v1.json",
      "stage4-campaign-model-verdict-v1.json",
      "stage4-campaign-plan-v1.json",
      "stage4-exit-review-matrix-template-v1.json",
      "stage4-exit-review-report-template-v1.json",
      "stage4-exit-review-verdict-v1.json",
      "stage4-nic-sandbox-node-group-contract-v1.json",
      "stage4-nic-sandbox-node-group-verdict-v1.json",
      "stage4-offline-readiness-package-v1.json",
      "stage4-offline-readiness-verdict-v1.json",
      "stage4-policy-contract-v1.json",
      "stage4-policy-payload-v1.json",
      "stage4-policy-probe-suite-v1.json",
      "stage4-static-preparation-evidence-v1.json",
      "stage4-storage-launch-contract-v1.json",
      "stage4-storage-launch-verdict-v1.json",
      "stage4-teardown-plan-v1.json",
      "stage4-teardown-verdict-v1.json",
    ],
  );

  const validators = compileRegistry();
  for (const { file, sample } of STAGE4_SCHEMA_REGISTRY) {
    const validator = validatorFor(validators, file);
    assert.equal(validator(sample()), true, `${file}: ${JSON.stringify(validator.errors)}`);
  }
});

test("every Stage 4 schema rejects unknown root fields and representative nested fields", () => {
  const validators = compileRegistry();
  for (const { file, sample } of STAGE4_SCHEMA_REGISTRY) {
    const mutation = sample();
    mutation.unreviewed = true;
    assertRejected(validatorFor(validators, file), mutation, `${file} accepted an unknown root field`);
  }

  const approvalMutation = campaignApprovalDraftSample();
  (approvalMutation.approval as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-campaign-approval-draft-v1.json"),
    approvalMutation,
    "campaign approval draft accepted an unknown approval field",
  );

  const campaignMutation = campaignPlanSample();
  (campaignMutation.bindings as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-campaign-plan-v1.json"),
    campaignMutation,
    "campaign plan accepted an unknown binding field",
  );

  const exitMutation = exitReviewReportSample();
  (exitMutation.decision as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-exit-review-report-template-v1.json"),
    exitMutation,
    "exit report template accepted an unknown decision field",
  );

  const staticMutation = staticSample();
  (staticMutation.artifacts as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-static-preparation-evidence-v1.json"),
    staticMutation,
    "static evidence accepted an unknown artifact field",
  );

  const nicMutation = nicContractSample();
  ((nicMutation.sandbox_node_group as JsonObject).runtime as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-nic-sandbox-node-group-contract-v1.json"),
    nicMutation,
    "NIC contract accepted an unknown runtime field",
  );

  const readinessMutation = offlineReadinessPackageSample();
  ((readinessMutation.campaign_proposal as JsonObject).account_binding as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-offline-readiness-package-v1.json"),
    readinessMutation,
    "offline readiness package accepted an unknown account-binding field",
  );

  const storageMutation = storageLaunchContractSample();
  ((storageMutation.storage as JsonObject).workspace as JsonObject).unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-storage-launch-contract-v1.json"),
    storageMutation,
    "storage/launch contract accepted an unknown workspace field",
  );

  const planMutation = teardownPlanSample();
  const firstPhase = (planMutation.phases as JsonObject[])[0];
  assert.ok(firstPhase);
  firstPhase.unreviewed = true;
  assertRejected(
    validatorFor(validators, "stage4-teardown-plan-v1.json"),
    planMutation,
    "teardown plan accepted an unknown phase field",
  );
});

test("Stage 4 schema validation uses own-property JSON semantics for inherited fields", () => {
  const validators = compileRegistry();
  const validateNic = validatorFor(validators, "stage4-nic-sandbox-node-group-contract-v1.json");
  const sample = nicContractSample();
  delete sample.version;
  const inherited = Object.assign(
    Object.create({ version: "cogs.stage4-nic-sandbox-node-group-contract/v1" }) as JsonObject,
    sample,
  );
  assert.equal(validateNic(inherited), false, "an inherited version must not satisfy a required own property");

  const inheritedUnknown = Object.assign(
    Object.create({ future_security_field: true }) as JsonObject,
    nicContractSample(),
  );
  assert.equal(validateNic(inheritedUnknown), true, "inherited fields are outside JSON own-property semantics");
});

test("Stage 4 schemas reject cross-domain version and authority substitution", () => {
  const validators = compileRegistry();
  const versions = STAGE4_SCHEMA_REGISTRY.map(({ sample }) => sample().version);

  for (const { file, sample } of STAGE4_SCHEMA_REGISTRY) {
    const validator = validatorFor(validators, file);
    const expectedVersion = sample().version;
    for (const version of versions.filter((candidate) => candidate !== expectedVersion)) {
      assertRejected(validator, { ...sample(), version }, `${file} accepted cross-domain version ${String(version)}`);
    }
  }

  const staticValidator = validatorFor(validators, "stage4-static-preparation-evidence-v1.json");
  for (const authority of ["authoritative-local", "aws-feasibility", "authoritative-production-profile"]) {
    assertRejected(staticValidator, { ...staticSample(), authority }, `static evidence accepted ${authority}`);
  }

  for (const file of ["stage4-teardown-plan-v1.json", "stage4-teardown-verdict-v1.json"]) {
    const entry = STAGE4_SCHEMA_REGISTRY.find((candidate) => candidate.file === file);
    assert.ok(entry);
    assertRejected(
      validatorFor(validators, file),
      { ...entry.sample(), authority: "static-only-stage4-preparation" },
      `${file} accepted authority from the static-evidence domain`,
    );
  }
});
