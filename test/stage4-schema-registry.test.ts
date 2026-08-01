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
  "static.network.declarative-default-deny-shape",
  "static.network.no-public-ingress-or-provider-resource",
  "static.scheduling.trusted-sandbox-separation-shape",
  "static.storage.workspace-session-role-separation-shape",
  "static.limits.resource-and-lifecycle-bounds-present",
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
  { file: "stage4-nic-sandbox-node-group-contract-v1.json", sample: nicContractSample },
  { file: "stage4-nic-sandbox-node-group-verdict-v1.json", sample: nicVerdictSample },
  { file: "stage4-static-preparation-evidence-v1.json", sample: staticSample },
  { file: "stage4-teardown-plan-v1.json", sample: teardownPlanSample },
  { file: "stage4-teardown-verdict-v1.json", sample: teardownVerdictSample },
] as const satisfies readonly RegistryEntry[];

function compileRegistry(): Map<string, ValidateFunction> {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
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

test("the bounded Stage 4 registry compiles its five strict positive samples", () => {
  assert.deepEqual(
    STAGE4_SCHEMA_REGISTRY.map(({ file }) => file),
    [
      "stage4-nic-sandbox-node-group-contract-v1.json",
      "stage4-nic-sandbox-node-group-verdict-v1.json",
      "stage4-static-preparation-evidence-v1.json",
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
