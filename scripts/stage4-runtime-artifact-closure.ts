import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes } from "./private-bytes.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const evidenceSchema = require("../schemas/stage4-authenticated-runtime-artifact-evidence-v2.json") as object;

export const STAGE4_RUNTIME_ARTIFACT_MAX_BYTES = 64 * 1024;
export const STAGE4_RUNTIME_ARTIFACT_BLOCKERS = Object.freeze([
  "OPENBAO_FIXED_RELEASE_IMAGE_ABSENT",
  "EKS_AMI_ID_AND_RUNNING_KERNEL_AWS_UNRESOLVED",
  "ENVOY_UPSTREAM_SIGNATURE_UNAVAILABLE",
  "CAMPAIGN_ENVELOPE_AND_APPROVAL_ABSENT",
] as const);

export type Stage4RuntimeArtifactReasonCode =
  | "STAGE4_RUNTIME_ARTIFACT_CANDIDATE_CLOSED_AWS_BLOCKED"
  | "STAGE4_RUNTIME_ARTIFACT_BOUNDED_INPUT_INVALID"
  | "STAGE4_RUNTIME_ARTIFACT_CANONICAL_INPUT_INVALID"
  | "STAGE4_RUNTIME_ARTIFACT_SCHEMA_INVALID"
  | "STAGE4_RUNTIME_ARTIFACT_SEMANTIC_DRIFT"
  | "STAGE4_RUNTIME_ARTIFACT_BINDING_INVALID";

export type Stage4RuntimeArtifactVerdict = Readonly<{
  version: "cogs.stage4-authenticated-runtime-artifact-verdict/v2";
  authority: "local-static-runtime-artifact-classifier";
  candidate_artifact_closure_complete: boolean;
  selected_runtime_artifacts_authenticated: boolean;
  eks_public_candidate_selected: boolean;
  eks_ami_id_resolved: false;
  running_kernel_resolved: false;
  release_image_set_present: boolean;
  exact_image_identity_closure_satisfied: boolean;
  campaign_authorized: false;
  cloud_execution_observed: false;
  provider_truth_observed: false;
  kubernetes_truth_observed: false;
  exact_image_runtime_closure_satisfied: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  evidence_sha256: string | null;
  binding_sha256: string | null;
  status: "candidate-closure-complete-aws-blocked" | "preserve-uncertain";
  reason_code: Stage4RuntimeArtifactReasonCode;
  blockers: readonly (typeof STAGE4_RUNTIME_ARTIFACT_BLOCKERS)[number][];
}>;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
require("ajv-formats")(ajv);
const validateEvidence = ajv.compile(evidenceSchema) as ValidateFunction;

/* stage4-runtime-schema-inventory-anchor-start */
const STAGE4_RUNTIME_SCHEMA_INVENTORY_SHA256 = "60ac14b79b90c8b43815c942ff8b4d1a8786808d5ad42d78d01b2ad20d6c0146";
/* stage4-runtime-schema-inventory-anchor-end */

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJson(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("non-JSON value");
  return encoded;
}

export function canonicalStage4RuntimeArtifactBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

export function stage4RuntimeArtifactSha256(bytes: Uint8Array): string {
  const captured = capturePrivateBytes(bytes, STAGE4_RUNTIME_ARTIFACT_MAX_BYTES, true);
  if (captured.bytes === null) throw new TypeError("invalid runtime artifact bytes");
  return createHash("sha256").update(captured.bytes).digest("hex");
}

export function stage4RuntimeArtifactBinding(value: JsonObject): string {
  const input = { ...value, binding_sha256: null } as JsonObject;
  return createHash("sha256")
    .update("cogs.stage4/authenticated-runtime-artifact-binding/v1\0", "utf8")
    .update(canonicalJson(input), "utf8")
    .digest("hex");
}

/** Exact local candidate assembled only from already measured public release and repository bytes. */
export function buildStage4RuntimeArtifactEvidence(): JsonObject {
  const value: JsonObject = {
    version: "cogs.stage4-authenticated-runtime-artifact-evidence/v2",
    authority: "local-static-public-release-artifact-closure",
    platform: { os: "linux", architecture: "amd64" },
    containerd: {
      version: "2.2.1",
      source_commit: "dea7da592f5d1d2b7755e3a161be07f43fad8f75",
      artifact: {
        name: "containerd-static-2.2.1-linux-amd64.tar.gz",
        url: "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-static-2.2.1-linux-amd64.tar.gz",
        size: 33645699,
        sha256: "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883",
        checksum_url:
          "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-static-2.2.1-linux-amd64.tar.gz.sha256sum",
        checksum_sha256: "c5037c875eedd79908c006014fc32d7faf8d800412ee26f1ee25dee6c7b18fe4",
      },
      authentication: {
        kind: "github-actions-slsa-v1",
        attestation_url:
          "https://github.com/containerd/containerd/releases/download/v2.2.1/containerd-2.2.1-attestation.intoto.jsonl",
        attestation_sha256: "5c0c491cf4fd397cd9578cc6af4722917c2ac50bba7aabdbbd073a95b998154a",
        predicate_type: "https://slsa.dev/provenance/v1",
        certificate_identity: "https://github.com/containerd/containerd/.github/workflows/release.yml@refs/tags/v2.2.1",
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com",
        workflow_run: "https://github.com/containerd/containerd/actions/runs/20345608481/attempts/1",
        verified: true,
      },
      selected_executables: [
        {
          path: "bin/containerd",
          size: 44050184,
          sha256: "f5d70cf9a249a70a70c379ba8f7259ea91122650cc06103bc0fc44a04dbc54da",
        },
        {
          path: "bin/ctr",
          size: 22143160,
          sha256: "448b1d7a2da84b6265dc4685afcc6c69a6299de43b942b8a3d6d540f6585d1db",
        },
      ],
    },
    kata: {
      version: "3.32.0",
      source_commit: "337b6002681479fb6a605ca8a7a1138e81b6098c",
      artifact: {
        name: "kata-static-3.32.0-amd64.tar.zst",
        url: "https://github.com/kata-containers/kata-containers/releases/download/3.32.0/kata-static-3.32.0-amd64.tar.zst",
        size: 1547940938,
        sha256: "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
      },
      authentication: {
        kind: "github-immutable-release-attestation-v0.2",
        attestation_api:
          "https://api.github.com/repos/kata-containers/kata-containers/attestations/sha256:1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
        predicate_type: "https://in-toto.io/attestation/release/v0.2",
        certificate_identity: "https://dotcom.releases.github.com",
        timestamp: "2026-06-22T10:06:28Z",
        verified: true,
      },
      versions_manifest: {
        path: "opt/kata/versions.yaml",
        size: 16690,
        sha256: "27a17423b643a3dcff6dfee18c7eb69179191fa9d4dfbeefeb1addde1b414fef",
      },
      selected_qemu: {
        version: "11.0.1",
        provenance: "kata-bundled-release-member",
        path: "opt/kata/bin/qemu-system-x86_64",
        size: 73358392,
        sha256: "1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d",
        elf_build_id: "420987ca21dc0df30993f11ab11979a76838ee52",
      },
      qemu_config: {
        path: "opt/kata/share/defaults/kata-containers/configuration-qemu.toml",
        size: 32218,
        sha256: "7ecd072a35da55f5abc76d604a610cf3f2d543c7de0cefc4d1a81028facd2cae",
        configured_qemu_path: "/opt/kata/bin/qemu-system-x86_64",
        configured_kernel_path: "/opt/kata/share/kata-containers/vmlinux.container",
      },
      guest_kernel: {
        version: "6.18.35",
        symlink_path: "opt/kata/share/kata-containers/vmlinux.container",
        member_path: "opt/kata/share/kata-containers/vmlinux-6.18.35-197",
        size: 40855000,
        sha256: "43701715ae2885f936bbe5c66a2de7c14dc51de7d19412d04833e4bbcf205bd0",
      },
    },
    historical_qemu_host_observation: {
      version: "8.2.2",
      reported_package: "1:8.2.2+ds-0ubuntu1.17",
      observed_command_path: "/usr/bin/qemu-system-x86_64",
      evidence_path: "docs/test-reports/stage-2-aws-measurement.md",
      selected_runtime: false,
      artifact_identity_bound: false,
      interpretation: "historical-host-distro-observation-not-kata-runtime-identity",
      upstream_source_reference: {
        url: "https://download.qemu.org/qemu-8.2.2.tar.xz",
        size: 129398020,
        sha256: "847346c1b82c1a54b2c38f6edbd85549edeb17430b7d4d3da12620e2962bc4f3",
        signature_url: "https://download.qemu.org/qemu-8.2.2.tar.xz.sig",
        signature_sha256: "4b3848575572cc3584bad4afd67e50470d52232c71efba3de4faaead83f45eb6",
        signer_fingerprint: "CEACC9E15534EBABB82D3FA03353C9CEF108B584",
        source_only_not_runtime_artifact: true,
      },
    },
    eks_node_image_candidate: {
      state: "public-candidate-aws-fields-unresolved",
      selection_reason:
        "kubernetes-1.35-matches-the-pinned-nebari-autoscaler-default-line-and-the-latest-non-abandoned-public-ami-catalog",
      kubernetes_minor: "1.35",
      ami_type: "AL2023_x86_64_STANDARD",
      public_release_tag: "v20260728",
      public_release_commit: "80b4c870f33069dadf27e075f184c06cccfc7999",
      public_release_url: "https://github.com/awslabs/amazon-eks-ami/releases/tag/v20260728",
      ami_name: "amazon-eks-node-al2023-x86_64-standard-1.35-v20260728",
      release_version: "1.35.6-20260728",
      source_ami_name: "al2023-ami-minimal-2023.12.20260727.0-kernel-6.12-x86_64",
      public_kernel_package: "6.12.94-123.192.amzn2023",
      baked_containerd_package: "2.2.5-1.amzn2023.0.1",
      selected_containerd_override_required: true,
      region: "us-east-1",
      ami_id: null,
      running_kernel_release: null,
      provider_truth_observed: false,
    },
    static_candidate_freeze: {
      envoy: {
        version: "1.38.3",
        index_digest: "sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb",
        linux_amd64_manifest_digest: "sha256:5f3e2f88bbeabefcdbc871f976529334aba158a3ffb17be021904f9d4c81f1c8",
        binary_sha256: "affffb8d08a14fdc375b1f7dd8d0f3004eacdf51ce07f5636d7e168a01c6b373",
        source_commit: "0ebfcfe5b0484b89ca85b761da9e05ce75dbda8d",
        publisher_signature_verified: false,
        state: "exact-static-digest-signature-unavailable-not-runtime-observed",
      },
      openbao: {
        version: "2.6.1",
        index_digest: "sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0",
        linux_amd64_manifest_digest: "sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0",
        binary_sha256: "736b8ecf354fda6b2af62e4ae064f12fe6c52d7db8425b9c6de22f286a5485ec",
        certificate_identity:
          "https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.6.1",
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com",
        publisher_signature_verified: true,
        retired_at: "2026-08-14T20:14:04Z",
        retirement_reason: "fixed-high-go-stdlib-no-fixed-upstream-image",
        state: "exact-static-signed-retired-fixed-high-findings",
      },
      skills: {
        policy: "no-bundled-release-skills",
        empty_bundle_digest: "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c",
        shared_oci_manifest_digest: "sha256:726176e9bdb7524fbe935a0235fcbe5d509bf44592b9571421fc9fd8551ff1c1",
        user_bundle_digest: "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c",
      },
      chart: {
        name: "cogs",
        version: "0.0.1",
        delivery: "notes-only-zero-submitted-manifests",
        inventory_sha256: "a3801a32d9f1a59864bd027aebf44554b087911c7d4a4486e7bcda697ff68617",
      },
      schemas: {
        scope: "all-stage4-stage5-and-production-runtime-image-contract-schemas",
        inventory_sha256: STAGE4_RUNTIME_SCHEMA_INVENTORY_SHA256,
      },
      dependency_lock: {
        package_lock_sha256: "21fa5340665a5e2c04a5f185b2cae2ba550256c4c830fefcf000a42c89e358ea",
        pi_version: "0.80.6",
        pi_agent_core_sri:
          "sha512-Lvn89ko42h5ETUb6Z0Ku6ldskEqXaTdQBYvSa0+7bdG9V6rUEpXptv5e0OVZ1HDcvi8s6/2lGCQWsxKX+DFHNw==",
        pi_ai_sri: "sha512-7xfLk8sANBp+bpPEbjoOZTbPxsa+++b1JXAoSJsNa3vbs9AHHEclmvg54XLQcxH+fuwaeti/g2jeIfJ+mVYLpA==",
        pi_coding_agent_sri:
          "sha512-vcfD6tOk402isLl3Cm/qbn2O10TvgroMp1+/fEGM24ZdvETFCdOYv5VZ7m59EI5fPsjfSJh+CpQ5bhBrhfOg7g==",
      },
      release_images: {
        state: "reviewed-static-identity-closure-not-runtime-observed",
        assertion_sha256: "ad45d6b0a114c481eb869daff38f4ddc669801e8a5b5d808c404b506ae33c450",
        review_sha256: "f6a607349062f5ca9211978600012b4cd16651af984c083a0329646a74da6a3a",
        workflow_run_id: 30852317459,
        image_source_sha: "d3ddb987ceeec0bae0fa2d89fdc134187a0d1de3",
        image_source_tree_sha: "6fb6dbe512280e906555b02d6367d6a43c1421a9",
        image_source_inventory_sha256: "e2f4a4ad970c6e1e68e995db96b26e35f85d752b41670acee2c9090c5e663b94",
        worker: "ghcr.io/nenb/cogs/worker@sha256:c2f240fa191fb22970f6b1ff0142448841401885c87f403efca152d9201004bc",
        sandbox: "ghcr.io/nenb/cogs/sandbox@sha256:b8827b17c73fac0ce869681fad4a01c625f068566a55f1aa7e3a9efc0e1bdc60",
      },
    },
    claims: {
      candidate_artifact_closure_complete: true,
      selected_runtime_artifacts_authenticated: true,
      local_candidate_freeze_complete: true,
      release_image_set_present: true,
      exact_image_runtime_closure_satisfied: false,
      campaign_authorized: false,
      cloud_execution_observed: false,
      provider_truth_observed: false,
      kubernetes_truth_observed: false,
      current_resources_observed: false,
      zero_resources_claimed: false,
      stage4_exit_satisfied: false,
      release_eligible: false,
    },
    blockers: [...STAGE4_RUNTIME_ARTIFACT_BLOCKERS],
    binding_sha256: null,
  };
  value.binding_sha256 = stage4RuntimeArtifactBinding(value);
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

function verdict(reason: Stage4RuntimeArtifactReasonCode, evidenceSha: string | null, binding: string | null) {
  const complete = reason === "STAGE4_RUNTIME_ARTIFACT_CANDIDATE_CLOSED_AWS_BLOCKED";
  return Object.freeze({
    version: "cogs.stage4-authenticated-runtime-artifact-verdict/v2" as const,
    authority: "local-static-runtime-artifact-classifier" as const,
    candidate_artifact_closure_complete: complete,
    selected_runtime_artifacts_authenticated: complete,
    eks_public_candidate_selected: complete,
    eks_ami_id_resolved: false as const,
    running_kernel_resolved: false as const,
    release_image_set_present: complete,
    exact_image_identity_closure_satisfied: complete,
    campaign_authorized: false as const,
    cloud_execution_observed: false as const,
    provider_truth_observed: false as const,
    kubernetes_truth_observed: false as const,
    exact_image_runtime_closure_satisfied: false as const,
    stage4_exit_satisfied: false as const,
    release_eligible: false as const,
    evidence_sha256: evidenceSha,
    binding_sha256: binding,
    status: complete ? ("candidate-closure-complete-aws-blocked" as const) : ("preserve-uncertain" as const),
    reason_code: reason,
    blockers: complete ? STAGE4_RUNTIME_ARTIFACT_BLOCKERS : Object.freeze([]),
  });
}

/** Pure bounded classifier: no filesystem, environment, process, network, provider, or Kubernetes access. */
export function classifyStage4RuntimeArtifactEvidence(input: unknown): Stage4RuntimeArtifactVerdict {
  const captured = capturePrivateBytes(input, STAGE4_RUNTIME_ARTIFACT_MAX_BYTES);
  if (captured.bytes === null) return verdict("STAGE4_RUNTIME_ARTIFACT_BOUNDED_INPUT_INVALID", null, null);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(captured.bytes));
  } catch {
    return verdict("STAGE4_RUNTIME_ARTIFACT_CANONICAL_INPUT_INVALID", null, null);
  }
  let canonical: Uint8Array;
  try {
    canonical = canonicalStage4RuntimeArtifactBytes(parsed as Json);
  } catch {
    return verdict("STAGE4_RUNTIME_ARTIFACT_CANONICAL_INPUT_INVALID", null, null);
  }
  if (!bytesEqual(captured.bytes, canonical)) {
    return verdict("STAGE4_RUNTIME_ARTIFACT_CANONICAL_INPUT_INVALID", null, null);
  }
  const evidenceSha = stage4RuntimeArtifactSha256(captured.bytes);
  if (!validateEvidence(parsed)) return verdict("STAGE4_RUNTIME_ARTIFACT_SCHEMA_INVALID", evidenceSha, null);
  const value = parsed as JsonObject;
  const binding = typeof value.binding_sha256 === "string" ? value.binding_sha256 : null;
  if (stage4RuntimeArtifactBinding(value) !== binding) {
    return verdict("STAGE4_RUNTIME_ARTIFACT_BINDING_INVALID", evidenceSha, binding);
  }
  const expected = canonicalStage4RuntimeArtifactBytes(buildStage4RuntimeArtifactEvidence());
  if (!bytesEqual(captured.bytes, expected)) {
    return verdict("STAGE4_RUNTIME_ARTIFACT_SEMANTIC_DRIFT", evidenceSha, binding);
  }
  return verdict("STAGE4_RUNTIME_ARTIFACT_CANDIDATE_CLOSED_AWS_BLOCKED", evidenceSha, binding);
}
