import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import {
  canonicalReleaseImageReceiptBytes,
  classifyReleaseImageReceipt,
  finalizeReleaseImageReceipt,
  type ReleaseReceiptJson,
} from "../scripts/release-image-receipt.ts";

const require = createRequire(import.meta.url);
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const workflowPath = resolve(root, ".github/workflows/release-images.yml");
const workflowSource = readFileSync(workflowPath, "utf8");
const identity = "https://github.com/nenb/cogs/.github/workflows/release-images.yml@refs/heads/main";
const issuer = "https://token.actions.githubusercontent.com";
const sha = "a".repeat(40);
const digest = (marker: string) => `sha256:${marker.repeat(64)}`;
const pinned = (name: string, marker: string) => `${name}@${digest(marker)}`;

function receiptFixture(): Record<string, unknown> {
  const image = (role: "worker" | "sandbox", counts: Record<string, number>) => {
    const repository = `ghcr.io/nenb/cogs/${role}`;
    const registryDigest = role === "worker" ? digest("1") : digest("2");
    const childDigest = role === "worker" ? digest("3") : digest("4");
    return {
      role,
      registry_repository: repository,
      candidate_tag: `candidate-${sha}-123-1`,
      release_tag: `sha-${sha}`,
      registry_digest: registryDigest,
      exact_reference: `${repository}@${registryDigest}`,
      linux_amd64_manifest_digest: childDigest,
      dockerfile: {
        path: `images/${role}/Dockerfile`,
        sha256: role === "worker" ? "5".repeat(64) : "6".repeat(64),
      },
      buildkit_provenance: {
        workflow_recorded_attached: true,
        mode: "max",
        predicate_type: "https://slsa.dev/provenance/v0.2",
        build_type: "https://mobyproject.org/buildkit@v1",
        workflow_recorded_platform_verified: true,
        readback_sha256: role === "worker" ? "c".repeat(64) : "d".repeat(64),
      },
      sbom: {
        format: "spdx-json",
        predicate_type: "https://spdx.dev/Document",
        spdx_json_sha256: role === "worker" ? "e".repeat(64) : "f".repeat(64),
        workflow_recorded_generated_for_exact_digest: true,
        workflow_recorded_attached: true,
        workflow_recorded_keyless_signed: true,
        workflow_recorded_signature_verified: true,
        certificate_identity: identity,
        certificate_oidc_issuer: issuer,
      },
      vulnerabilities: {
        scanned_reference: `${repository}@${registryDigest}`,
        report_sha256: role === "worker" ? "1".repeat(64) : "2".repeat(64),
        severities: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        ignore_unfixed: false,
        suppressions: false,
        counts,
        gate: {
          policy: "block-high-critical",
          severities: ["HIGH", "CRITICAL"],
          includes_unfixed: true,
          finding_count: 0,
          outcome: "pass",
        },
        disposition: {
          unknown: { count: counts.unknown, semantics: "recorded-non-gating-review-required-not-approved" },
          low_medium: {
            count: (counts.low ?? 0) + (counts.medium ?? 0),
            semantics: "recorded-non-gating-not-release-approval",
          },
          high_critical: { count: 0, semantics: "release-receipt-blocking-including-unfixed" },
        },
      },
      signature: {
        workflow_recorded_keyless: true,
        workflow_recorded_digest_signed: true,
        workflow_recorded_verified: true,
        certificate_identity: identity,
        certificate_oidc_issuer: issuer,
      },
    };
  };
  return {
    version: "cogs.release-image-receipt/v1",
    authority: "protected-main-github-actions-publication-assertion-record",
    repository: "nenb/cogs",
    source: {
      reviewed_sha: sha,
      default_branch: "main",
      protected: true,
      observed_head_sha: sha,
      tree_sha: "b".repeat(40),
      inventory_sha256: "c".repeat(64),
    },
    workflow: {
      path: ".github/workflows/release-images.yml",
      ref: "refs/heads/main",
      sha,
      event: "workflow_dispatch",
      run_id: 123,
      run_attempt: 1,
      certificate_identity: identity,
      certificate_oidc_issuer: issuer,
    },
    target: { os: "linux", architecture: "amd64", variant: null },
    tag_policy: {
      release_format: "sha-<full-40-character-commit>",
      candidate_format: "candidate-<full-40-character-commit>-<run-id>-<run-attempt>",
      preexisting_release_tags_rejected: true,
      candidate_run_unique: true,
      release_tags_created_after_recorded_gates: true,
      release_tag_readback_recorded: true,
      latest_written: false,
      mutable_release_alias_written: false,
    },
    tools: {
      buildkit_image: pinned("docker.io/moby/buildkit", "7"),
      syft_image: pinned("docker.io/anchore/syft", "8"),
      trivy_image: pinned("docker.io/aquasec/trivy", "9"),
      trivy_database: pinned("ghcr.io/aquasecurity/trivy-db:2", "a"),
      cosign_image: pinned("ghcr.io/sigstore/cosign/cosign", "b"),
    },
    images: [
      image("worker", {
        total: 3,
        unknown: 1,
        low: 1,
        medium: 1,
        high: 0,
        critical: 0,
        fixed_available: 1,
        unfixed: 2,
      }),
      image("sandbox", {
        total: 2,
        unknown: 0,
        low: 1,
        medium: 1,
        high: 0,
        critical: 0,
        fixed_available: 0,
        unfixed: 2,
      }),
    ],
    claims: {
      workflow_recorded_exact_protected_default_branch_source: true,
      workflow_recorded_publication_complete: true,
      workflow_recorded_buildkit_provenance_attached: true,
      workflow_recorded_sbom_attached: true,
      workflow_recorded_vulnerability_gate_passed: true,
      workflow_recorded_keyless_signatures_verified: true,
      static_parser_cryptographic_verification_performed: false,
      cloud_execution_observed: false,
      kubernetes_execution_observed: false,
      provider_execution_observed: false,
      external_model_execution_observed: false,
      runtime_qualification_observed: false,
      readiness_promoted: false,
      production_ready: false,
      release_eligible: false,
    },
    blockers: [
      "RUNTIME_CONFORMANCE_NOT_EXECUTED",
      "READINESS_PROMOTION_REQUIRES_SEPARATE_REVIEW",
      "RELEASE_ELIGIBILITY_UNCHANGED_FALSE",
    ],
    redaction: {
      actor_omitted: true,
      tokens_omitted: true,
      runner_details_omitted: true,
      raw_scanner_findings_omitted: true,
    },
  };
}

const canonical = (value: unknown) => canonicalReleaseImageReceiptBytes(value as ReleaseReceiptJson);

test("release record parser accepts canonical workflow assertions without elevating them to verified truth", () => {
  const value = receiptFixture();
  const schema = JSON.parse(readFileSync(resolve(root, "schemas/release-image-receipt-v1.json"), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  const validate = ajv.compile(schema);
  assert.equal(validate(value), true, ajv.errorsText(validate.errors));
  const bytes = canonical(value);
  assert.deepEqual(Buffer.from(finalizeReleaseImageReceipt(value)), Buffer.from(bytes));
  const result = classifyReleaseImageReceipt(Uint8Array.from(bytes));
  assert.equal(result.record_valid, true);
  assert.equal(result.reason_code, "VALID_WORKFLOW_ASSERTION_RECORD");
  assert.equal(result.workflow_recorded_publication_complete, true);
  assert.equal(result.workflow_recorded_vulnerability_gate_passed, true);
  assert.equal(result.workflow_recorded_signatures_verified, true);
  assert.equal(result.cryptographic_verification_performed, false);
  assert.equal(result.publication_truth_established, false);
  assert.equal(result.vulnerability_truth_established, false);
  assert.equal(result.signature_truth_established, false);
  assert.equal(result.readiness_promoted, false);
  assert.equal(result.production_ready, false);
  assert.equal(result.release_eligible, false);
  assert.match(result.record_sha256 ?? "", /^[0-9a-f]{64}$/u);
});

test("release record parser rejects noncanonical, promoted, mismatched, and incomplete assertions", () => {
  const valid = receiptFixture();
  assert.equal(
    classifyReleaseImageReceipt(Uint8Array.from(Buffer.from(`${JSON.stringify(valid, null, 2)}\n`))).reason_code,
    "NON_CANONICAL_JSON",
  );
  assert.equal(
    classifyReleaseImageReceipt(new Proxy(Uint8Array.from(canonical(valid)), {})).reason_code,
    "BOUNDED_INPUT_VIOLATION",
  );

  const forged = structuredClone(valid);
  const forgedResult = classifyReleaseImageReceipt(canonical(forged));
  assert.equal(forgedResult.record_valid, true);
  assert.equal(forgedResult.workflow_recorded_signatures_verified, true);
  assert.equal(forgedResult.signature_truth_established, false);
  assert.equal(forgedResult.cryptographic_verification_performed, false);

  const promoted = structuredClone(valid) as { claims: { readiness_promoted: boolean } };
  promoted.claims.readiness_promoted = true;
  assert.equal(classifyReleaseImageReceipt(canonical(promoted)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");

  const wrongHead = structuredClone(valid) as { source: { observed_head_sha: string } };
  wrongHead.source.observed_head_sha = "d".repeat(40);
  assert.equal(classifyReleaseImageReceipt(canonical(wrongHead)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");

  const wrongReference = structuredClone(valid) as { images: Array<{ exact_reference: string }> };
  const firstReference = wrongReference.images[0];
  assert.ok(firstReference);
  firstReference.exact_reference = `ghcr.io/nenb/cogs/worker@${digest("e")}`;
  assert.equal(classifyReleaseImageReceipt(canonical(wrongReference)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");

  const incomplete = structuredClone(valid) as {
    images: Array<{ vulnerabilities: { counts: { total: number } } }>;
  };
  const firstCounts = incomplete.images[0];
  assert.ok(firstCounts);
  firstCounts.vulnerabilities.counts.total += 1;
  assert.equal(classifyReleaseImageReceipt(canonical(incomplete)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");
});

type WorkflowStep = { uses?: string; run?: string; with?: Record<string, unknown> };
type WorkflowJob = {
  if?: string;
  permissions?: Record<string, string>;
  outputs?: Record<string, string>;
  steps: WorkflowStep[];
};
type Workflow = {
  on: Record<string, unknown>;
  permissions: Record<string, string>;
  jobs: Record<string, WorkflowJob>;
};

const workflow = parseYaml(workflowSource) as Workflow;
const workflowJob = (name: string): WorkflowJob => {
  const job = workflow.jobs[name];
  assert.ok(job, name);
  return job;
};

function runStep(job: WorkflowJob, marker: string): string {
  const source = job.steps.find((step) => step.run?.includes(marker))?.run;
  assert.ok(source, marker);
  return source;
}

test("release workflow has one manual protected-main authority and least-privilege effect job", () => {
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(workflow.permissions, {});
  const authority = workflowJob("authority");
  const publish = workflowJob("publish");
  assert.deepEqual(authority.permissions, { contents: "read" });
  assert.deepEqual(publish.permissions, { contents: "read", packages: "write", "id-token": "write" });
  assert.match(authority.if ?? "", /github\.run_attempt == 1/u);
  assert.match(authority.if ?? "", /github\.actor == vars\.RELEASE_IMAGE_PUBLISH_ACTOR/u);
  assert.match(authority.if ?? "", /github\.event\.repository\.default_branch == 'main'/u);
  assert.match(authority.if ?? "", /github\.ref == 'refs\/heads\/main'/u);
  assert.match(authority.if ?? "", /github\.ref_protected == true/u);
  assert.match(authority.if ?? "", /release-images\.yml@refs\/heads\/main/u);
  const authorityRun = runStep(authority, "observed_head");
  assert.match(authorityRun, /git\/ref\/heads\/main/u);
  assert.match(authorityRun, /test "\$REVIEWED_SHA" = "\$observed_head"/u);
  assert.equal(
    authority.steps.some((step) => step.uses?.startsWith("actions/checkout@")),
    false,
  );
});

test("release workflow pins every action and tool and promotes only full-SHA release tags after unique candidates", () => {
  const uses = Object.values(workflow.jobs).flatMap((job) => job.steps.map((step) => step.uses).filter(Boolean));
  assert.ok(uses.length >= 6);
  for (const action of uses) assert.match(action ?? "", /^[^@\s]+@[0-9a-f]{40}$/u, action);
  for (const variable of ["BUILDKIT_IMAGE", "SYFT_IMAGE", "TRIVY_IMAGE", "TRIVY_DATABASE", "COSIGN_IMAGE"]) {
    assert.match(workflowSource, new RegExp(`${variable}: [^\\s]+@sha256:[0-9a-f]{64}`, "u"), variable);
  }
  assert.doesNotMatch(workflowSource, /:latest(?:@|\s|$)/u);
  assert.match(workflowSource, /tags: ghcr\.io\/nenb\/cogs\/worker:candidate-\$\{\{/u);
  assert.match(workflowSource, /tags: ghcr\.io\/nenb\/cogs\/sandbox:candidate-\$\{\{/u);
  assert.match(workflowSource, /candidate-\$REVIEWED_SHA-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(workflowSource, /imagetools create --tag "\$repository:\$release_tag" "\$repository@\$digest"/u);
  assert.match(workflowSource, /Refusing to overwrite pre-existing tag/u);
  assert.match(workflowSource, /Refusing to overwrite raced release tag/u);
  assert.doesNotMatch(workflowSource, /tags:[^\n]*(?:latest|main|stable)/u);
});

test("release cleanup aggregates an early retained credential path instead of accepting later successes", () => {
  const publish = workflowJob("publish");
  const cleanup = runStep(publish, "Cleanup retained sensitive path");
  const temporary = mkdtempSync(join(tmpdir(), "cogs-release-cleanup-hostile-"));
  const bin = join(temporary, "bin");
  mkdirSync(bin);
  const fakeDocker = join(bin, "docker");
  const fakeRm = join(bin, "rm");
  writeFileSync(fakeDocker, "#!/bin/sh\nexit 0\n");
  writeFileSync(
    fakeRm,
    '#!/bin/sh\nfirst=1\nfor value in "$@"; do\n  case "$value" in -*) continue;; esac\n  if [ $first -eq 1 ]; then first=0; continue; fi\n  /bin/rm -rf -- "$value"\ndone\nexit 1\n',
  );
  chmodSync(fakeDocker, 0o700);
  chmodSync(fakeRm, 0o700);
  const paths = {
    DOCKER_CONFIG: join(temporary, "docker-config"),
    CONTEXT: join(temporary, "context"),
    WORK: join(temporary, "work"),
    CACHE: join(temporary, "cache"),
    RECEIPT: join(temporary, "receipt"),
    COSIGN_HOME: join(temporary, "cosign"),
  };
  for (const path of Object.values(paths)) mkdirSync(path);
  const workspace = join(temporary, "workspace");
  mkdirSync(join(workspace, "node_modules"), { recursive: true });
  try {
    const result = spawnSync("/bin/bash", ["-c", cleanup], {
      encoding: "utf8",
      env: {
        ...process.env,
        ...paths,
        GITHUB_WORKSPACE: workspace,
        RUNNER_TEMP: temporary,
        PATH: `${bin}:/usr/bin:/bin`,
        SYFT_IMAGE: "syft",
        TRIVY_IMAGE: "trivy",
        COSIGN_IMAGE: "cosign",
      },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Cleanup retained sensitive path:/u);
    assert.equal(readFileSync(fakeDocker, "utf8").includes("exit 0"), true);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("readiness remains blocked until successful digests are separately reviewed", () => {
  const imageLock = JSON.parse(
    readFileSync(resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json"), "utf8"),
  ) as {
    exact_image_closure_satisfied: boolean;
    release_image_set_present: boolean;
    images: Array<{ role: string; state: string; reference: string }>;
  };
  assert.equal(imageLock.exact_image_closure_satisfied, false);
  assert.equal(imageLock.release_image_set_present, false);
  for (const role of ["worker", "sandbox"]) {
    const image = imageLock.images.find((candidate) => candidate.role === role);
    assert.ok(image);
    assert.equal(image.state, "synthetic-placeholder-not-release-image");
    assert.match(image.reference, /^registry\.example\.invalid\//u);
  }
});

test("release workflow binds provenance, complete vulnerability semantics, signatures, and one receipt", () => {
  const publish = workflowJob("publish");
  assert.equal(publish.outputs?.worker_digest, "$" + "{{ steps.digests.outputs.worker_digest }}");
  assert.equal(publish.outputs?.sandbox_digest, "$" + "{{ steps.digests.outputs.sandbox_digest }}");
  assert.equal((workflowSource.match(/provenance: mode=max/gu) ?? []).length, 2);
  assert.equal((workflowSource.match(/platforms: linux\/amd64/gu) ?? []).length, 2);
  assert.match(workflowSource, /--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL/u);
  assert.match(workflowSource, /--ignore-unfixed=false/u);
  assert.match(workflowSource, /\.high == 0 and \.critical == 0/u);
  assert.match(workflowSource, /release-receipt-blocking-including-unfixed/u);
  assert.match(workflowSource, /cosign attest --yes --type spdxjson/u);
  assert.match(workflowSource, /cosign sign --yes "\$subject"/u);
  assert.match(
    workflowSource,
    /cosign verify[\s\S]*--certificate-identity "\$CERTIFICATE_IDENTITY"[\s\S]*--certificate-oidc-issuer "\$CERTIFICATE_OIDC_ISSUER"/u,
  );
  assert.match(workflowSource, /cosign verify-attestation --type spdxjson/u);
  const upload = publish.steps.find((step) => step.uses?.startsWith("actions/upload-artifact@"));
  assert.ok(upload);
  assert.equal(upload.with?.path, "$" + "{{ runner.temp }}/cogs-release-receipt/release-image-receipt.canonical.json");
  assert.doesNotMatch(workflowSource, /docs\/security-evidence\/stage4-offline-readiness-artifacts\/image-lock\.json/u);
  assert.doesNotMatch(workflowSource, /(?:tofu|terraform|kubectl|helm|aws |external model)/iu);
  assert.match(workflowSource, /static_parser_cryptographic_verification_performed:false/u);
  assert.match(workflowSource, /readiness_promoted:false,production_ready:false,release_eligible:false/u);
  assert.match(workflowSource, /docker logout ghcr\.io/u);
  assert.match(
    workflowSource,
    /rm -rf -- "\$DOCKER_CONFIG" "\$CONTEXT" "\$WORK" "\$CACHE" "\$RECEIPT" "\$COSIGN_HOME"/u,
  );
  assert.match(workflowSource, /status=0[\s\S]*docker logout ghcr\.io[^\n]*\|\| status=1/u);
  assert.match(workflowSource, /for path in "\$DOCKER_CONFIG"[\s\S]*exit "\$status"/u);
});
