/* biome-ignore-all lint/suspicious/noExplicitAny: hostile evidence mutations intentionally cross strict JSON types */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import * as closureModule from "../scripts/stage4-runtime-artifact-closure.ts";
import {
  buildStage4RuntimeArtifactEvidence,
  canonicalStage4RuntimeArtifactBytes,
  classifyStage4RuntimeArtifactEvidence,
  STAGE4_RUNTIME_ARTIFACT_BLOCKERS,
  STAGE4_RUNTIME_ARTIFACT_MAX_BYTES,
  stage4RuntimeArtifactBinding,
  stage4RuntimeArtifactSha256,
} from "../scripts/stage4-runtime-artifact-closure.ts";

const root = resolve(import.meta.dirname, "..");
const evidencePath = resolve(
  root,
  "docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
);
const bytes = (): Uint8Array => new Uint8Array(readFileSync(evidencePath));
const object = (): Record<string, any> => JSON.parse(readFileSync(evidencePath, "utf8")) as Record<string, any>;

function rebind(value: Record<string, any>): Uint8Array {
  value.binding_sha256 = stage4RuntimeArtifactBinding(value);
  return canonicalStage4RuntimeArtifactBytes(value);
}

function assertUncertain(input: unknown): void {
  const result = classifyStage4RuntimeArtifactEvidence(input);
  assert.equal(result.status, "preserve-uncertain");
  assert.equal(result.candidate_artifact_closure_complete, false);
  assert.equal(result.selected_runtime_artifacts_authenticated, false);
  assert.equal(result.eks_public_candidate_selected, false);
  assert.equal(result.eks_ami_id_resolved, false);
  assert.equal(result.running_kernel_resolved, false);
  assert.equal(result.campaign_authorized, false);
  assert.equal(result.cloud_execution_observed, false);
  assert.equal(result.provider_truth_observed, false);
  assert.equal(result.kubernetes_truth_observed, false);
  assert.equal(result.exact_image_runtime_closure_satisfied, false);
  assert.equal(result.stage4_exit_satisfied, false);
  assert.equal(result.release_eligible, false);
  assert.deepEqual(result.blockers, []);
}

test("committed evidence is deterministic exact local closure with every authority claim false", () => {
  assert.deepEqual(bytes(), canonicalStage4RuntimeArtifactBytes(buildStage4RuntimeArtifactEvidence()));
  const result = classifyStage4RuntimeArtifactEvidence(bytes());
  assert.equal(result.status, "candidate-closure-complete-aws-blocked");
  assert.equal(result.reason_code, "STAGE4_RUNTIME_ARTIFACT_CANDIDATE_CLOSED_AWS_BLOCKED");
  assert.equal(result.candidate_artifact_closure_complete, true);
  assert.equal(result.selected_runtime_artifacts_authenticated, true);
  assert.equal(result.eks_public_candidate_selected, true);
  assert.equal(result.eks_ami_id_resolved, false);
  assert.equal(result.running_kernel_resolved, false);
  assert.equal(result.campaign_authorized, false);
  assert.equal(result.cloud_execution_observed, false);
  assert.equal(result.provider_truth_observed, false);
  assert.equal(result.kubernetes_truth_observed, false);
  assert.equal(result.exact_image_runtime_closure_satisfied, false);
  assert.equal(result.stage4_exit_satisfied, false);
  assert.equal(result.release_eligible, false);
  assert.equal(result.evidence_sha256, stage4RuntimeArtifactSha256(bytes()));
  assert.equal(result.binding_sha256, object().binding_sha256);
  assert.deepEqual(result.blockers, STAGE4_RUNTIME_ARTIFACT_BLOCKERS);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.blockers));
});

test("exact runtime selection is containerd attestation plus Kata-bundled QEMU and guest kernel", () => {
  const value = object();
  assert.deepEqual(value.containerd.artifact, {
    name: "containerd-static-2.2.1-linux-amd64.tar.gz",
    url: "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-static-2.2.1-linux-amd64.tar.gz",
    size: 33645699,
    sha256: "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883",
    checksum_url:
      "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-static-2.2.1-linux-amd64.tar.gz.sha256sum",
    checksum_sha256: "c5037c875eedd79908c006014fc32d7faf8d800412ee26f1ee25dee6c7b18fe4",
  });
  assert.equal(value.containerd.authentication.certificate_identity.endsWith("@refs/tags/v2.2.1"), true);
  assert.equal(value.containerd.authentication.verified, true);
  assert.deepEqual(value.kata.selected_qemu, {
    version: "11.0.1",
    provenance: "kata-bundled-release-member",
    path: "opt/kata/bin/qemu-system-x86_64",
    size: 73358392,
    sha256: "1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d",
    elf_build_id: "420987ca21dc0df30993f11ab11979a76838ee52",
  });
  assert.equal(value.kata.qemu_config.configured_qemu_path, "/opt/kata/bin/qemu-system-x86_64");
  assert.equal(value.kata.guest_kernel.sha256, "43701715ae2885f936bbe5c66a2de7c14dc51de7d19412d04833e4bbcf205bd0");
  assert.equal(value.historical_qemu_host_observation.version, "8.2.2");
  assert.equal(value.historical_qemu_host_observation.selected_runtime, false);
  assert.equal(value.historical_qemu_host_observation.artifact_identity_bound, false);
  assert.equal(value.historical_qemu_host_observation.upstream_source_reference.source_only_not_runtime_artifact, true);
});

test("public EKS candidate is exact while all AWS-resolved fields remain absent", () => {
  const candidate = object().eks_node_image_candidate;
  assert.equal(candidate.kubernetes_minor, "1.35");
  assert.equal(candidate.ami_type, "AL2023_x86_64_STANDARD");
  assert.equal(candidate.public_release_tag, "v20260728");
  assert.equal(candidate.public_release_commit, "80b4c870f33069dadf27e075f184c06cccfc7999");
  assert.equal(candidate.ami_name, "amazon-eks-node-al2023-x86_64-standard-1.35-v20260728");
  assert.equal(candidate.release_version, "1.35.6-20260728");
  assert.equal(candidate.public_kernel_package, "6.12.94-123.192.amzn2023");
  assert.equal(candidate.baked_containerd_package, "2.2.5-1.amzn2023.0.1");
  assert.equal(candidate.selected_containerd_override_required, true);
  assert.equal(candidate.ami_id, null);
  assert.equal(candidate.running_kernel_release, null);
  assert.equal(candidate.provider_truth_observed, false);
});

test("static candidate freeze is exact but cannot promote images, release, or expired security truth", () => {
  const freeze = object().static_candidate_freeze;
  assert.equal(freeze.envoy.publisher_signature_verified, false);
  assert.equal(
    freeze.envoy.linux_amd64_manifest_digest,
    "sha256:5f3e2f88bbeabefcdbc871f976529334aba158a3ffb17be021904f9d4c81f1c8",
  );
  assert.equal(freeze.openbao.publisher_signature_verified, true);
  assert.equal(
    freeze.openbao.certificate_identity,
    "https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.6.1",
  );
  assert.equal(freeze.openbao.security_disposition_expires_at, "2026-08-15T23:59:59Z");
  assert.equal(freeze.skills.policy, "no-bundled-release-skills");
  assert.equal(
    freeze.skills.shared_oci_manifest_digest,
    "sha256:726176e9bdb7524fbe935a0235fcbe5d509bf44592b9571421fc9fd8551ff1c1",
  );
  assert.equal(freeze.chart.inventory_sha256, "a3801a32d9f1a59864bd027aebf44554b087911c7d4a4486e7bcda697ff68617");
  assert.equal(freeze.schemas.scope, "all-stage4-stage5-and-production-runtime-image-contract-schemas");
  assert.equal(
    freeze.schemas.inventory_sha256,
    stage4RuntimeArtifactSha256(
      new Uint8Array(
        readFileSync(resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json")),
      ),
    ),
  );
  assert.equal(freeze.dependency_lock.pi_version, "0.80.6");
  assert.equal(
    freeze.dependency_lock.package_lock_sha256,
    "835d126c87bfedc30e2665aa8344abfb1a71948dbdd55cb4a7e8133512583645",
  );
  assert.equal(object().claims.release_image_set_present, false);
  assert.equal(object().claims.release_eligible, false);
});

test("evidence compiles under strict schema and rejects unknown fields", () => {
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  require("ajv-formats")(ajv);
  const schema = JSON.parse(
    readFileSync(resolve(root, "schemas/stage4-authenticated-runtime-artifact-evidence-v1.json"), "utf8"),
  );
  const validate = ajv.compile(schema);
  assert.equal(validate(object()), true, JSON.stringify(validate.errors));
  const rootUnknown = object();
  rootUnknown.unreviewed = true;
  assert.equal(validate(rootUnknown), false);
  const nestedUnknown = object();
  nestedUnknown.kata.selected_qemu.fallback = "tcg";
  assert.equal(validate(nestedUnknown), false);
});

test("hostile artifact, provenance, QEMU, EKS, freeze, and claim drift fail closed", () => {
  const mutations: Array<(value: Record<string, any>) => void> = [
    (value) => (value.containerd.artifact.sha256 = "0".repeat(64)),
    (value) => (value.containerd.authentication.certificate_identity = "https://github.com/hostile/workflow"),
    (value) => (value.containerd.authentication.verified = false),
    (value) => (value.kata.artifact.sha256 = "0".repeat(64)),
    (value) => (value.kata.authentication.certificate_identity = "https://hostile.invalid"),
    (value) => (value.kata.selected_qemu.version = "8.2.2"),
    (value) => (value.kata.selected_qemu.path = "/usr/bin/qemu-system-x86_64"),
    (value) => (value.kata.qemu_config.configured_qemu_path = "/usr/bin/qemu-system-x86_64"),
    (value) => (value.historical_qemu_host_observation.selected_runtime = true),
    (value) => (value.eks_node_image_candidate.kubernetes_minor = "latest"),
    (value) => (value.eks_node_image_candidate.public_release_tag = "latest"),
    (value) => (value.eks_node_image_candidate.ami_id = "ami-0123456789abcdef0"),
    (value) => (value.eks_node_image_candidate.running_kernel_release = "claimed"),
    (value) => (value.static_candidate_freeze.envoy.publisher_signature_verified = true),
    (value) => (value.static_candidate_freeze.skills.policy = "ambient-skills"),
    (value) => (value.claims.cloud_execution_observed = true),
    (value) => (value.claims.release_eligible = true),
  ];
  for (const mutate of mutations) {
    const value = object();
    mutate(value);
    const result = classifyStage4RuntimeArtifactEvidence(rebind(value));
    assert.ok(
      ["STAGE4_RUNTIME_ARTIFACT_SCHEMA_INVALID", "STAGE4_RUNTIME_ARTIFACT_SEMANTIC_DRIFT"].includes(result.reason_code),
      JSON.stringify(value),
    );
    assertUncertain(rebind(value));
  }
});

test("valid-shape digest substitution with a recomputed binding is semantic drift", () => {
  const value = object();
  value.containerd.selected_executables[0].sha256 = "a".repeat(64);
  const result = classifyStage4RuntimeArtifactEvidence(rebind(value));
  assert.equal(result.reason_code, "STAGE4_RUNTIME_ARTIFACT_SEMANTIC_DRIFT");
  assertUncertain(rebind(value));
});

test("canonical, binding, byte bound, typed-array, and introspection attacks preserve uncertainty", () => {
  const noncanonical = new TextEncoder().encode(JSON.stringify(object(), null, 2));
  assert.equal(
    classifyStage4RuntimeArtifactEvidence(noncanonical).reason_code,
    "STAGE4_RUNTIME_ARTIFACT_CANONICAL_INPUT_INVALID",
  );
  const binding = object();
  binding.binding_sha256 = "0".repeat(64);
  assert.equal(
    classifyStage4RuntimeArtifactEvidence(canonicalStage4RuntimeArtifactBytes(binding)).reason_code,
    "STAGE4_RUNTIME_ARTIFACT_BINDING_INVALID",
  );
  assertUncertain(new Uint8Array(STAGE4_RUNTIME_ARTIFACT_MAX_BYTES + 1));
  assertUncertain(new DataView(bytes().buffer));
  assertUncertain(
    new Proxy(bytes(), {
      get() {
        throw new Error("hostile get");
      },
    }),
  );
});

test("classifier exports no execution seam and source has no ambient authority", () => {
  assert.deepEqual(Object.keys(closureModule).sort(), [
    "STAGE4_RUNTIME_ARTIFACT_BLOCKERS",
    "STAGE4_RUNTIME_ARTIFACT_MAX_BYTES",
    "buildStage4RuntimeArtifactEvidence",
    "canonicalStage4RuntimeArtifactBytes",
    "classifyStage4RuntimeArtifactEvidence",
    "stage4RuntimeArtifactBinding",
    "stage4RuntimeArtifactSha256",
  ]);
  const source = readFileSync(resolve(root, "scripts/stage4-runtime-artifact-closure.ts"), "utf8");
  assert.doesNotMatch(source, /(?:node:(?:child_process|fs|http|https|net|tls|dns|dgram)|@aws|@kubernetes|aws-sdk)/u);
  assert.doesNotMatch(source, /\b(?:fetch|spawn|exec|writeFile|appendFile)\s*\(/u);
  assert.doesNotMatch(source, /\bprocess(?:\.|\[)/u);
});
