/* biome-ignore-all lint/suspicious/noExplicitAny: legacy-version sample derivation mutates strict JSON fixtures */
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

function offlineReadinessPackageV3Sample(): JsonObject {
  const value = offlineReadinessPackageSample() as Record<string, any>;
  value.version = "cogs.stage4-offline-readiness-package/v3";
  value.source.image_source.relation = "separately-bound-immutable-image-source";
  value.pins.images.worker.state = "exact-reviewed-candidate-not-runtime-observed";
  value.pins.images.sandbox.state = "exact-reviewed-candidate-not-runtime-observed";
  value.pins.images.release_image_set_present = true;
  value.pins.images.exact_image_closure_satisfied = true;
  value.blockers = value.blockers.filter((blocker: string) => blocker !== "RELEASE_IMAGE_SET_ABSENT");
  return value;
}

function offlineReadinessPackageV2Sample(): JsonObject {
  const value = offlineReadinessPackageV3Sample() as Record<string, any>;
  value.version = "cogs.stage4-offline-readiness-package/v2";
  delete value.artifact_bindings.release_image_assertion_sha256;
  delete value.artifact_bindings.release_image_review_sha256;
  delete value.source.image_source;
  value.pins.images.worker = {
    reference: `registry.example.invalid/cogs/worker@sha256:${"a".repeat(64)}`,
    state: "synthetic-placeholder-not-release-image",
  };
  value.pins.images.sandbox = {
    reference: `registry.example.invalid/cogs/sandbox@sha256:${"c".repeat(64)}`,
    state: "synthetic-placeholder-not-release-image",
  };
  value.pins.images.release_image_set_present = false;
  value.pins.images.exact_image_closure_satisfied = false;
  value.blockers = value.blockers.filter(
    (blocker: string) => blocker !== "RELEASE_IMAGE_SET_ABSENT" && blocker !== "OPENBAO_FIXED_RELEASE_IMAGE_ABSENT",
  );
  value.blockers.push("RELEASE_IMAGE_SET_ABSENT");
  return value;
}

function offlineReadinessPackageV1Sample(): JsonObject {
  const value = offlineReadinessPackageV2Sample() as Record<string, any>;
  value.version = "cogs.stage4-offline-readiness-package/v1";
  value.source = {
    integrated_predecessor_git_commit: "dc11c1f6f2e29a66c602b82d805c764a00517bf0",
    inventory_scope: "complete-stage4-source-closure",
    inventory_algorithm: "sha256-over-exact-file-bytes",
    source_closure_complete: true,
    excluded_self_referential_outputs: [
      "docs/security-evidence/stage4-offline-readiness-package.json",
      "docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json",
      "docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json",
    ],
    release_candidate_binding_present: false,
  };
  delete value.artifact_bindings.authenticated_runtime_artifacts_sha256;
  value.pins.runtime.qemu_version = "8.2.2";
  value.pins.runtime.eks_node_image_release = null;
  value.pins.runtime.node_image_state = "unresolved-blocking";
  value.pins.runtime.containerd_artifact_sha256 = null;
  value.pins.runtime.containerd_artifact_state = "unresolved-blocking";
  value.pins.runtime.qemu_artifact_sha256 = null;
  value.pins.runtime.qemu_artifact_state = "unresolved-blocking";
  value.pins.runtime.exact_runtime_artifact_closure_satisfied = false;
  value.blockers.push("CONTAINERD_ARTIFACT_IDENTITY_UNRESOLVED", "QEMU_ARTIFACT_IDENTITY_UNRESOLVED");
  return value;
}

function offlineReadinessVerdictV1Sample(): JsonObject {
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

function offlineReadinessVerdictV2Sample(): JsonObject {
  const value = offlineReadinessVerdictV1Sample() as Record<string, any>;
  value.version = "cogs.stage4-offline-readiness-verdict/v2";
  value.candidate_artifact_closure_complete = true;
  value.selected_runtime_artifacts_authenticated = true;
  value.blockers = value.blockers.slice(0, -2);
  return value;
}

function offlineReadinessVerdictV3Sample(): JsonObject {
  const value = offlineReadinessVerdictV2Sample() as Record<string, any>;
  value.version = "cogs.stage4-offline-readiness-verdict/v3";
  value.blockers = value.blockers.filter((blocker: string) => blocker !== "RELEASE_IMAGE_SET_ABSENT");
  value.blockers.splice(1, 0, "OPENBAO_FIXED_RELEASE_IMAGE_ABSENT");
  return value;
}

function offlineReadinessVerdictSample(): JsonObject {
  const value = offlineReadinessVerdictV3Sample() as Record<string, any>;
  value.version = "cogs.stage4-offline-readiness-verdict/v4";
  value.blockers.splice(2, 0, "RELEASE_IMAGE_SET_ABSENT");
  return value;
}

function authenticatedRuntimeArtifactSample(): JsonObject {
  return JSON.parse(
    readFileSync(
      resolve(
        import.meta.dirname,
        "../docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
      ),
      "utf8",
    ),
  ) as JsonObject;
}

function authenticatedRuntimeArtifactV1Sample(): JsonObject {
  const value = authenticatedRuntimeArtifactSample() as Record<string, any>;
  value.version = "cogs.stage4-authenticated-runtime-artifact-evidence/v1";
  delete value.static_candidate_freeze.release_images;
  delete value.static_candidate_freeze.openbao.retired_at;
  delete value.static_candidate_freeze.openbao.retirement_reason;
  value.static_candidate_freeze.openbao.security_disposition_expires_at = "2026-08-15T23:59:59Z";
  value.static_candidate_freeze.openbao.state = "exact-static-signed-not-runtime-observed";
  value.static_candidate_freeze.dependency_lock = {
    package_lock_sha256: "21fa5340665a5e2c04a5f185b2cae2ba550256c4c830fefcf000a42c89e358ea",
    pi_version: "0.80.6",
    pi_agent_core_sri:
      "sha512-Lvn89ko42h5ETUb6Z0Ku6ldskEqXaTdQBYvSa0+7bdG9V6rUEpXptv5e0OVZ1HDcvi8s6/2lGCQWsxKX+DFHNw==",
    pi_ai_sri: "sha512-7xfLk8sANBp+bpPEbjoOZTbPxsa+++b1JXAoSJsNa3vbs9AHHEclmvg54XLQcxH+fuwaeti/g2jeIfJ+mVYLpA==",
    pi_coding_agent_sri:
      "sha512-vcfD6tOk402isLl3Cm/qbn2O10TvgroMp1+/fEGM24ZdvETFCdOYv5VZ7m59EI5fPsjfSJh+CpQ5bhBrhfOg7g==",
  };
  value.claims.release_image_set_present = false;
  value.blockers = [
    "EKS_AMI_ID_AND_RUNNING_KERNEL_AWS_UNRESOLVED",
    "RELEASE_IMAGE_SET_ABSENT",
    "ENVOY_UPSTREAM_SIGNATURE_UNAVAILABLE",
    "CAMPAIGN_ENVELOPE_AND_APPROVAL_ABSENT",
  ];
  return value;
}

function authenticatedRuntimeArtifactV2Sample(): JsonObject {
  const value = authenticatedRuntimeArtifactSample() as Record<string, any>;
  value.version = "cogs.stage4-authenticated-runtime-artifact-evidence/v2";
  const historical = authenticatedRuntimeArtifactV1Sample() as Record<string, any>;
  value.static_candidate_freeze.dependency_lock = historical.static_candidate_freeze.dependency_lock;
  value.static_candidate_freeze.release_images = {
    state: "reviewed-static-identity-closure-not-runtime-observed",
    assertion_sha256: "ad45d6b0a114c481eb869daff38f4ddc669801e8a5b5d808c404b506ae33c450",
    review_sha256: "f6a607349062f5ca9211978600012b4cd16651af984c083a0329646a74da6a3a",
    workflow_run_id: 30852317459,
    image_source_sha: "d3ddb987ceeec0bae0fa2d89fdc134187a0d1de3",
    image_source_tree_sha: "6fb6dbe512280e906555b02d6367d6a43c1421a9",
    image_source_inventory_sha256: "e2f4a4ad970c6e1e68e995db96b26e35f85d752b41670acee2c9090c5e663b94",
    worker: "ghcr.io/nenb/cogs/worker@sha256:c2f240fa191fb22970f6b1ff0142448841401885c87f403efca152d9201004bc",
    sandbox: "ghcr.io/nenb/cogs/sandbox@sha256:b8827b17c73fac0ce869681fad4a01c625f068566a55f1aa7e3a9efc0e1bdc60",
  };
  value.claims.release_image_set_present = true;
  value.blockers = value.blockers.filter((blocker: string) => blocker !== "RELEASE_IMAGE_SET_ABSENT");
  return value;
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
    readFileSync(resolve(import.meta.dirname, "../deploy/nic/stage4-sandbox-node-group-contract-v1.json"), "utf8"),
  ) as JsonObject;
}

function nicV2ContractSample(): JsonObject {
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

function nicV2VerdictSample(): JsonObject {
  return {
    version: "cogs.stage4-nic-sandbox-node-group-verdict/v2",
    authority: "local-static-personal-fork-source-classifier",
    campaign_authorized: false,
    cloud_execution_observed: false,
    provider_truth_observed: false,
    launch_template_contents_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    contract_sha256: sha("d"),
    nic_source_pin_resolved: true,
    node_image_pin_resolved: false,
    launch_template_selection_capability_resolved: true,
    status: "source-capability-satisfied-local-static",
    reason_code: "STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING",
  };
}

function staticManifestRequestSample(): JsonObject {
  return JSON.parse(
    readFileSync(resolve(import.meta.dirname, "fixtures/stage4-static-manifest/valid-request-v1.json"), "utf8"),
  ) as JsonObject;
}

function staticManifestReceiptSample(): JsonObject {
  return {
    version: "cogs.stage4-static-manifest-receipt/v1",
    authority: "local-static-manifest-materialization-only",
    request_sha256: sha("1"),
    manifest_sha256: sha("2"),
    nic_config_sha256: sha("3"),
    chart_inventory_sha256: sha("4"),
    helm_executable_sha256: sha("5"),
    nic_contract_sha256: sha("6"),
    object_inventory: [
      "ConfigMap/stage4-cogs-contract",
      "ServiceAccount/stage4-cogs-trusted",
      "ServiceAccount/cogs-sandbox-inert",
      "Service/stage4-cogs-proxy",
      "NetworkPolicy/stage4-cogs-default-deny",
      "NetworkPolicy/stage4-cogs-trusted-allow",
      "NetworkPolicy/stage4-cogs-sandbox-allow",
      "PodTemplate/stage4-cogs-trusted-template",
      "PodTemplate/stage4-cogs-sandbox-template",
    ],
    manifest_render_route_present: true,
    deployment_execution_route_present: false,
    apply_route_present: false,
    kubernetes_client_present: false,
    kubernetes_execution_observed: false,
    provider_execution_observed: false,
    cloud_execution_observed: false,
    provider_truth_observed: false,
    launch_template_contents_observed: false,
    campaign_authorized: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
  };
}

const STAGE4_SCHEMA_REGISTRY = [
  { file: "stage4-authenticated-runtime-artifact-evidence-v1.json", sample: authenticatedRuntimeArtifactV1Sample },
  { file: "stage4-authenticated-runtime-artifact-evidence-v2.json", sample: authenticatedRuntimeArtifactV2Sample },
  { file: "stage4-authenticated-runtime-artifact-evidence-v3.json", sample: authenticatedRuntimeArtifactSample },
  { file: "stage4-campaign-approval-draft-v1.json", sample: campaignApprovalDraftSample },
  { file: "stage4-campaign-approval-verdict-v1.json", sample: campaignApprovalVerdictSample },
  { file: "stage4-campaign-evidence-v1.json", sample: campaignEvidenceSample },
  { file: "stage4-campaign-model-verdict-v1.json", sample: campaignModelVerdictSample },
  { file: "stage4-campaign-plan-v1.json", sample: campaignPlanSample },
  { file: "stage4-exit-review-matrix-template-v1.json", sample: exitReviewMatrixSample },
  { file: "stage4-exit-review-report-template-v1.json", sample: exitReviewReportSample },
  { file: "stage4-exit-review-verdict-v1.json", sample: exitReviewVerdictSample },
  { file: "stage4-nic-sandbox-node-group-contract-v1.json", sample: nicContractSample },
  { file: "stage4-nic-sandbox-node-group-contract-v2.json", sample: nicV2ContractSample },
  { file: "stage4-nic-sandbox-node-group-verdict-v1.json", sample: nicVerdictSample },
  { file: "stage4-nic-sandbox-node-group-verdict-v2.json", sample: nicV2VerdictSample },
  { file: "stage4-offline-readiness-package-v1.json", sample: offlineReadinessPackageV1Sample },
  { file: "stage4-offline-readiness-package-v2.json", sample: offlineReadinessPackageV2Sample },
  { file: "stage4-offline-readiness-package-v3.json", sample: offlineReadinessPackageV3Sample },
  { file: "stage4-offline-readiness-package-v4.json", sample: offlineReadinessPackageSample },
  { file: "stage4-offline-readiness-verdict-v1.json", sample: offlineReadinessVerdictV1Sample },
  { file: "stage4-offline-readiness-verdict-v2.json", sample: offlineReadinessVerdictV2Sample },
  { file: "stage4-offline-readiness-verdict-v3.json", sample: offlineReadinessVerdictV3Sample },
  { file: "stage4-offline-readiness-verdict-v4.json", sample: offlineReadinessVerdictSample },
  { file: "stage4-policy-contract-v1.json", sample: policyContractSample },
  { file: "stage4-policy-payload-v1.json", sample: policyPayloadSample },
  { file: "stage4-policy-probe-suite-v1.json", sample: policyProbeSample },
  { file: "stage4-static-manifest-receipt-v1.json", sample: staticManifestReceiptSample },
  { file: "stage4-static-manifest-request-v1.json", sample: staticManifestRequestSample },
  { file: "stage4-static-preparation-evidence-v1.json", sample: staticSample },
  { file: "stage4-storage-launch-contract-v1.json", sample: storageLaunchContractSample },
  { file: "stage4-storage-launch-verdict-v1.json", sample: storageLaunchVerdictSample },
  { file: "stage4-teardown-plan-v1.json", sample: teardownPlanSample },
  { file: "stage4-teardown-verdict-v1.json", sample: teardownVerdictSample },
] as const satisfies readonly RegistryEntry[];

function compileRegistry(): Map<string, ValidateFunction> {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  require("ajv-formats")(ajv);
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
      "stage4-authenticated-runtime-artifact-evidence-v1.json",
      "stage4-authenticated-runtime-artifact-evidence-v2.json",
      "stage4-authenticated-runtime-artifact-evidence-v3.json",
      "stage4-campaign-approval-draft-v1.json",
      "stage4-campaign-approval-verdict-v1.json",
      "stage4-campaign-evidence-v1.json",
      "stage4-campaign-model-verdict-v1.json",
      "stage4-campaign-plan-v1.json",
      "stage4-exit-review-matrix-template-v1.json",
      "stage4-exit-review-report-template-v1.json",
      "stage4-exit-review-verdict-v1.json",
      "stage4-nic-sandbox-node-group-contract-v1.json",
      "stage4-nic-sandbox-node-group-contract-v2.json",
      "stage4-nic-sandbox-node-group-verdict-v1.json",
      "stage4-nic-sandbox-node-group-verdict-v2.json",
      "stage4-offline-readiness-package-v1.json",
      "stage4-offline-readiness-package-v2.json",
      "stage4-offline-readiness-package-v3.json",
      "stage4-offline-readiness-package-v4.json",
      "stage4-offline-readiness-verdict-v1.json",
      "stage4-offline-readiness-verdict-v2.json",
      "stage4-offline-readiness-verdict-v3.json",
      "stage4-offline-readiness-verdict-v4.json",
      "stage4-policy-contract-v1.json",
      "stage4-policy-payload-v1.json",
      "stage4-policy-probe-suite-v1.json",
      "stage4-static-manifest-receipt-v1.json",
      "stage4-static-manifest-request-v1.json",
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
    validatorFor(validators, "stage4-offline-readiness-package-v4.json"),
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
