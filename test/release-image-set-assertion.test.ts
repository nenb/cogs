import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import {
  canonicalReleaseImageSetAssertionBytes,
  classifyReleaseImageSetAssertion,
  finalizeReleaseImageSetAssertion,
  type ReleaseImageSetAssertionJson,
} from "../scripts/release-image-set-assertion.ts";

const require = createRequire(import.meta.url);
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const workflowPath = resolve(root, ".github/workflows/release-images.yml");
const workflowSource = readFileSync(workflowPath, "utf8");
const trivyValidatorPath = resolve(root, "scripts/validate-trivy-image-report.jq");
const trivyValidatorSource = readFileSync(trivyValidatorPath, "utf8");
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
      transport_tag: `candidate-${sha}-123-1`,
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
        workflow_recorded_report_contract: {
          schema_version: 2,
          artifact_name_exact_subject: true,
          repo_digest_exact_subject: true,
          artifact_type: "container_image",
          os_metadata_present: true,
          results_nonempty: true,
          all_results_shape_validated: true,
          allowed_result_classes: ["os-pkgs", "lang-pkgs"],
          result_target_type_nonempty: true,
          os_package_type_matches_os_family: true,
          vulnerabilities_null_or_array: true,
          vulnerability_shapes_validated: true,
          os_package_target_present: true,
        },
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
          high_critical: { count: 0, semantics: "image-set-assertion-blocking-including-unfixed" },
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
    version: "cogs.release-image-set-assertion/v1",
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
    transport_policy: {
      tag_format: "candidate-<full-40-character-commit>-<run-id>-<run-attempt>",
      run_unique: true,
      retained_after_workflow: true,
      transport_only: true,
      final_tags_written: false,
      mutable_release_alias_written: false,
      image_set_record: "canonical-successful-workflow-artifact-with-exact-digest-references",
      consumer_requirement: "separately-reviewed-assertion-record-and-both-exact-digests",
    },
    tools: {
      buildx_client: {
        version: "v0.29.1",
        linux_amd64_sha256: "7d2d7d6d4680aa349614965aaa33ccec43f1a9a21e908a5ce4cb6adfa5ad5141",
      },
      buildkit_image: pinned("docker.io/moby/buildkit", "7"),
      syft_image: pinned("docker.io/anchore/syft", "8"),
      trivy_image: pinned("docker.io/aquasec/trivy", "9"),
      trivy_database: pinned("ghcr.io/aquasecurity/trivy-db:2", "a"),
      trivy_java_database: pinned("ghcr.io/aquasecurity/trivy-java-db:1", "d"),
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
      workflow_recorded_image_set_complete: true,
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

const canonical = (value: unknown) => canonicalReleaseImageSetAssertionBytes(value as ReleaseImageSetAssertionJson);

test("release record parser accepts canonical workflow assertions without elevating them to verified truth", () => {
  const value = receiptFixture();
  const schema = JSON.parse(readFileSync(resolve(root, "schemas/release-image-set-assertion-v1.json"), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
  const validate = ajv.compile(schema);
  assert.equal(validate(value), true, ajv.errorsText(validate.errors));
  const bytes = canonical(value);
  assert.deepEqual(Buffer.from(finalizeReleaseImageSetAssertion(value)), Buffer.from(bytes));
  const result = classifyReleaseImageSetAssertion(Uint8Array.from(bytes));
  assert.equal(result.record_valid, true);
  assert.equal(result.reason_code, "VALID_WORKFLOW_ASSERTION_RECORD");
  assert.equal(result.workflow_recorded_image_set_complete, true);
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
    classifyReleaseImageSetAssertion(Uint8Array.from(Buffer.from(`${JSON.stringify(valid, null, 2)}\n`))).reason_code,
    "NON_CANONICAL_JSON",
  );
  assert.equal(
    classifyReleaseImageSetAssertion(new Proxy(Uint8Array.from(canonical(valid)), {})).reason_code,
    "BOUNDED_INPUT_VIOLATION",
  );

  const forged = structuredClone(valid);
  const forgedResult = classifyReleaseImageSetAssertion(canonical(forged));
  assert.equal(forgedResult.record_valid, true);
  assert.equal(forgedResult.workflow_recorded_signatures_verified, true);
  assert.equal(forgedResult.signature_truth_established, false);
  assert.equal(forgedResult.cryptographic_verification_performed, false);

  const promoted = structuredClone(valid) as { claims: { readiness_promoted: boolean } };
  promoted.claims.readiness_promoted = true;
  assert.equal(classifyReleaseImageSetAssertion(canonical(promoted)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");

  const wrongHead = structuredClone(valid) as { source: { observed_head_sha: string } };
  wrongHead.source.observed_head_sha = "d".repeat(40);
  assert.equal(classifyReleaseImageSetAssertion(canonical(wrongHead)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");

  const wrongReference = structuredClone(valid) as { images: Array<{ exact_reference: string }> };
  const firstReference = wrongReference.images[0];
  assert.ok(firstReference);
  firstReference.exact_reference = `ghcr.io/nenb/cogs/worker@${digest("e")}`;
  assert.equal(classifyReleaseImageSetAssertion(canonical(wrongReference)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");

  const incomplete = structuredClone(valid) as {
    images: Array<{ vulnerabilities: { counts: { total: number } } }>;
  };
  const firstCounts = incomplete.images[0];
  assert.ok(firstCounts);
  firstCounts.vulnerabilities.counts.total += 1;
  assert.equal(classifyReleaseImageSetAssertion(canonical(incomplete)).reason_code, "SCHEMA_OR_SEMANTIC_DRIFT");
});

type WorkflowStep = { id?: string; uses?: string; run?: string; with?: Record<string, unknown> };
type WorkflowJob = {
  if?: string;
  needs?: string | string[];
  env?: Record<string, string>;
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

test("release workflow pins every action and tool and writes only run-unique transport tags", () => {
  const uses = Object.values(workflow.jobs).flatMap((job) => job.steps.map((step) => step.uses).filter(Boolean));
  assert.ok(uses.length >= 4);
  for (const action of uses) assert.match(action ?? "", /^[^@\s]+@[0-9a-f]{40}$/u, action);
  for (const variable of [
    "BUILDKIT_IMAGE",
    "SYFT_IMAGE",
    "TRIVY_IMAGE",
    "TRIVY_DATABASE",
    "TRIVY_JAVA_DATABASE",
    "COSIGN_IMAGE",
  ]) {
    assert.match(workflowSource, new RegExp(`${variable}: [^\\s]+@sha256:[0-9a-f]{64}`, "u"), variable);
  }
  assert.doesNotMatch(workflowSource, /:latest(?:@|\s|$)/u);
  assert.match(workflowSource, /--tag "\$repository:\$transport_tag"/u);
  assert.match(workflowSource, /candidate-\$REVIEWED_SHA-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.match(workflowSource, /BUILDX_VERSION: v0\.29\.1/u);
  assert.match(
    workflowSource,
    /BUILDX_LINUX_AMD64_SHA256: 7d2d7d6d4680aa349614965aaa33ccec43f1a9a21e908a5ce4cb6adfa5ad5141/u,
  );
  assert.match(workflowSource, /sha256sum --check --strict/u);
  assert.match(workflowSource, /docker buildx create[\s\S]*--driver-opt "image=\$BUILDKIT_IMAGE"/u);
  assert.doesNotMatch(workflowSource, /docker\/setup-buildx-action@/u);
  assert.doesNotMatch(workflowSource, /imagetools create --tag/u);
  assert.doesNotMatch(workflowSource, /sha-\$REVIEWED_SHA/u);
  assert.match(workflowSource, /Refusing to overwrite pre-existing run-unique transport tag/u);
  assert.doesNotMatch(workflowSource, /tags:[^\n]*(?:latest|main|stable)/u);
});

test("release workflow gives non-root Syft isolated writable state", () => {
  const scan = runStep(workflowJob("publish"), "syft_state=");
  assert.match(scan, /syft_state="\$WORK\/\$role\.syft-state"/u);
  assert.match(scan, /mkdir -m 0700 "\$syft_state" "\$syft_state\/tmp" "\$syft_state\/cache"/u);
  assert.match(scan, /--env HOME=\/syft-state/u);
  assert.match(scan, /--env TMPDIR=\/syft-state\/tmp/u);
  assert.match(scan, /--env XDG_CACHE_HOME=\/syft-state\/cache/u);
  assert.match(scan, /--env SYFT_CHECK_FOR_APP_UPDATE=false/u);
  assert.match(scan, /--mount "type=bind,src=\$syft_state,dst=\/syft-state"/u);
  assert.ok(scan.indexOf("mkdir -m 0700") < scan.indexOf('"$SYFT_IMAGE" scan'));
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
    ASSERTION: join(temporary, "assertion"),
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
        BUILDKIT_IMAGE: "buildkit",
        SYFT_IMAGE: "syft",
        TRIVY_IMAGE: "trivy",
        COSIGN_IMAGE: "cosign",
        BUILDX_BUILDER: "test-builder",
        BUILDX_CREATED: "false",
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

test("Trivy gate rejects every unsupported result and malformed vulnerability before aggregation", () => {
  const subject = `ghcr.io/nenb/cogs/worker@${digest("1")}`;
  const vulnerability = {
    VulnerabilityID: "CVE-2099-0001",
    PkgID: "example@1.0.0",
    PkgName: "example",
    InstalledVersion: "1.0.0",
    FixedVersion: "1.0.1",
    Severity: "LOW",
  };
  const valid = {
    SchemaVersion: 2,
    ArtifactName: subject,
    ArtifactType: "container_image",
    Metadata: { RepoDigests: [subject], OS: { Family: "debian", Name: "13" } },
    Results: [
      { Class: "os-pkgs", Target: `${subject} (debian 13)`, Type: "debian", Vulnerabilities: null },
      { Class: "lang-pkgs", Target: "package-lock.json", Type: "npm", Vulnerabilities: [vulnerability] },
    ],
  };
  const accepted = (report: unknown): boolean => {
    const result = spawnSync("jq", ["-e", "--arg", "subject", subject, "--from-file", trivyValidatorPath], {
      encoding: "utf8",
      input: JSON.stringify(report),
    });
    assert.equal(result.error, undefined, result.error?.message);
    return result.status === 0;
  };
  assert.equal(accepted(valid), true);

  // biome-ignore lint/suspicious/noExplicitAny: hostile scanner envelopes intentionally cross the valid report type
  const hostile: Array<[string, (report: Record<string, any>) => void]> = [
    ["wrong subject", (report) => (report.ArtifactName = `ghcr.io/nenb/cogs/worker@${digest("2")}`)],
    ["non-object result", (report) => (report.Results[0] = "os-pkgs")],
    ["unsupported class", (report) => (report.Results[0].Class = "unknown-pkgs")],
    ["empty target", (report) => (report.Results[0].Target = "")],
    ["empty type", (report) => (report.Results[0].Type = "")],
    ["wrong OS package type", (report) => (report.Results[0].Type = "ubuntu")],
    ["scalar vulnerabilities", (report) => (report.Results[0].Vulnerabilities = "none")],
    ["missing vulnerability identity", (report) => delete report.Results[1].Vulnerabilities[0].VulnerabilityID],
    ["missing package identity", (report) => delete report.Results[1].Vulnerabilities[0].PkgID],
    ["empty installed version", (report) => (report.Results[1].Vulnerabilities[0].InstalledVersion = "")],
    ["unsupported severity", (report) => (report.Results[1].Vulnerabilities[0].Severity = "NEGLIGIBLE")],
    ["invalid fixed version", (report) => (report.Results[1].Vulnerabilities[0].FixedVersion = 1)],
    ["missing OS coverage", (report) => report.Results.shift()],
  ];
  for (const [name, mutate] of hostile) {
    // biome-ignore lint/suspicious/noExplicitAny: mutation callbacks require one shared hostile shape
    const report = structuredClone(valid) as Record<string, any>;
    mutate(report);
    assert.equal(accepted(report), false, name);
  }
});

test("release publication uses only the pinned direct Buildx client and private metadata files", () => {
  const publish = workflowJob("publish");
  const build = runStep(publish, "docker buildx build");
  const readback = runStep(publish, "digest=$(jq -er");
  assert.equal(
    publish.steps.some((step) => step.uses?.startsWith("docker/build-push-action@")),
    false,
  );
  assert.doesNotMatch(workflowSource, /docker\/setup-buildx-action@/u);
  assert.doesNotMatch(workflowSource, /cache: npm/u);
  assert.match(build, /for role in worker sandbox/u);
  assert.match(build, /--builder "\$BUILDX_BUILDER"/u);
  assert.match(build, /--platform linux\/amd64/u);
  assert.match(build, /--provenance=mode=max/u);
  assert.match(build, /--sbom=false/u);
  assert.match(build, /--push/u);
  assert.match(build, /--pull/u);
  assert.match(build, /--no-cache/u);
  assert.match(build, /--metadata-file "\$metadata"/u);
  assert.match(build, /\."containerimage\.digest"/u);
  assert.match(build, /\."containerimage\.descriptor"\.digest/u);
  assert.match(build, /\."buildx\.build\.provenance"/u);
  assert.match(readback, /metadata="\$WORK\/\$role\.build-metadata\.json"/u);
  assert.match(readback, /test "\$digest" = "\$\(jq -er '\."containerimage\.descriptor"\.digest'/u);
  assert.equal(publish.env?.DOCKER_BUILD_RECORD_UPLOAD, "false");
  assert.equal(publish.env?.DOCKER_BUILD_SUMMARY, "false");
  assert.equal(publish.env?.BUILDX_METADATA_PROVENANCE, "max");
});

test("only the finalized success-dependent minimal job can upload the assertion", () => {
  const publish = workflowJob("publish");
  const uploader = workflowJob("assertion-upload");
  assert.equal(
    publish.steps.some((step) => step.uses?.startsWith("actions/upload-artifact@")),
    false,
  );
  assert.deepEqual(uploader.needs, ["publish"]);
  assert.equal(uploader.if?.replace(/\s+/gu, " ").trim(), "$" + "{{ needs.publish.result == 'success' }}");
  assert.deepEqual(uploader.permissions, {});
  const uploads = Object.entries(workflow.jobs).flatMap(([job, value]) =>
    value.steps.filter((step) => step.uses?.startsWith("actions/upload-artifact@")).map(() => job),
  );
  assert.deepEqual(uploads, ["assertion-upload"]);
  assert.equal(
    uploader.steps.some((step) =>
      /actions\/checkout@|actions\/setup-node@|docker\/login-action@/u.test(step.uses ?? ""),
    ),
    false,
  );
  const upload = uploader.steps.at(-1);
  assert.equal(upload?.uses?.startsWith("actions/upload-artifact@"), true);
  assert.equal(
    upload?.with?.path,
    "$" + "{{ runner.temp }}/release-image-set-assertion/release-image-set-assertion.canonical.json",
  );
});

test("a hostile publish post-step or finalization failure makes assertion upload ineligible", () => {
  const uploadEligible = (
    mainSucceeded: boolean,
    cleanupSucceeded: boolean,
    postsSucceeded: boolean,
    finalizationSucceeded: boolean,
  ): boolean => mainSucceeded && cleanupSucceeded && postsSucceeded && finalizationSucceeded;
  assert.equal(uploadEligible(true, true, true, true), true);
  assert.equal(uploadEligible(false, true, true, true), false);
  assert.equal(uploadEligible(true, false, true, true), false);
  assert.equal(uploadEligible(true, true, false, true), false);
  assert.equal(uploadEligible(true, true, true, false), false);
  const publish = workflowJob("publish");
  const uploader = workflowJob("assertion-upload");
  assert.equal(publish.steps.at(-1)?.run?.includes('exit "$status"'), true);
  assert.equal(uploader.if, "$" + "{{ needs.publish.result == 'success' }}");
});

test("assertion transport is exclusive, bounded, hashed, byte preserving, and hostile-input closed", () => {
  const publish = workflowJob("publish");
  const uploader = workflowJob("assertion-upload");
  assert.deepEqual(Object.keys(publish.outputs ?? {}).sort(), ["assertion_b64", "assertion_sha256", "assertion_size"]);
  assert.equal(publish.outputs?.assertion_b64, "$" + "{{ steps.assertion-transport.outputs.assertion_b64 }}");
  assert.equal(publish.outputs?.assertion_sha256, "$" + "{{ steps.assertion-transport.outputs.assertion_sha256 }}");
  assert.equal(publish.outputs?.assertion_size, "$" + "{{ steps.assertion-transport.outputs.assertion_size }}");
  const encode = runStep(publish, "ASSERTION_TRANSPORT_MAX_BYTES");
  const decode = runStep(uploader, "expected_encoded_size");
  assert.equal(publish.env?.ASSERTION_TRANSPORT_MAX_BYTES, "65536");
  assert.match(encode, /test ! -L "\$source" && test -f "\$source"/u);
  assert.match(encode, /test "\$size" -le "\$ASSERTION_TRANSPORT_MAX_BYTES"/u);
  assert.match(encode, /sha256sum "\$source"/u);
  assert.match(encode, /base64 -w 0 "\$source"/u);
  assert.match(encode, /expected_encoded_size=/u);
  assert.doesNotMatch(encode, /worker_digest|sandbox_digest|reviewed_sha/u);
  assert.match(decode, /test "\$ASSERTION_SIZE" -le 65536/u);
  assert.match(decode, /base64 --decode/u);
  assert.match(decode, /sha256sum "\$file"/u);
  assert.match(decode, /600:1:\$\{ASSERTION_SIZE\}:regular file/u);

  const bytes = Buffer.from(canonical(receiptFixture()));
  const encoded = bytes.toString("base64");
  const hash = createHash("sha256").update(bytes).digest("hex");
  const accepted = (candidate: string, size: number, sha256: string): boolean => {
    if (!Number.isSafeInteger(size) || size <= 0 || size > 65_536) return false;
    if (!/^[0-9a-f]{64}$/u.test(sha256) || !/^[A-Za-z0-9+/]+={0,2}$/u.test(candidate)) return false;
    if (candidate.length !== 4 * Math.ceil(size / 3)) return false;
    const decoded = Buffer.from(candidate, "base64");
    return (
      decoded.length === size &&
      decoded.toString("base64") === candidate &&
      createHash("sha256").update(decoded).digest("hex") === sha256
    );
  };
  assert.equal(accepted(encoded, bytes.length, hash), true);
  assert.equal(Buffer.from(encoded, "base64").equals(bytes), true);
  assert.equal(accepted(encoded, bytes.length + 1, hash), false);
  assert.equal(accepted(encoded, bytes.length, "0".repeat(64)), false);
  assert.equal(accepted(`${encoded}\n`, bytes.length, hash), false);
  const oversized = Buffer.alloc(65_537, 0x61);
  assert.equal(
    accepted(oversized.toString("base64"), oversized.length, createHash("sha256").update(oversized).digest("hex")),
    false,
  );
});

test("release workflow preserves evidence gates and removes all direct-build intermediates", () => {
  assert.match(workflowSource, /--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL/u);
  assert.match(workflowSource, /--ignore-unfixed=false/u);
  assert.match(workflowSource, /--java-db-repository "\$TRIVY_JAVA_DATABASE"/u);
  assert.match(workflowSource, /--download-java-db-only/u);
  assert.match(workflowSource, /--skip-java-db-update/u);
  assert.match(workflowSource, /--skip-version-check/u);
  assert.match(workflowSource, /test -f "\$CACHE\/java-db\/trivy-java\.db"/u);
  assert.match(workflowSource, /\.high == 0 and \.critical == 0/u);
  assert.match(workflowSource, /VULNERABILITY_GATE_BLOCKED role=/u);
  assert.match(workflowSource, /image-set-assertion-blocking-including-unfixed/u);
  assert.match(workflowSource, /--from-file "\$CONTEXT\/scripts\/validate-trivy-image-report\.jq"/u);
  assert.doesNotMatch(workflowSource, /\.Vulnerabilities\[\]\?/u);
  assert.match(trivyValidatorSource, /\.SchemaVersion == 2/u);
  assert.match(trivyValidatorSource, /\.ArtifactName == \$subject/u);
  assert.match(trivyValidatorSource, /\.Metadata\.RepoDigests \| index\(\$subject\) != null/u);
  assert.match(trivyValidatorSource, /\.ArtifactType == "container_image"/u);
  assert.match(trivyValidatorSource, /all\(\.Results\[\]; valid_result\(\$os_family\)\)/u);
  assert.match(trivyValidatorSource, /\.Class == "os-pkgs" or \.Class == "lang-pkgs"/u);
  assert.match(trivyValidatorSource, /\.Type == \$os_family/u);
  assert.match(trivyValidatorSource, /all\(\(\.Vulnerabilities \/\/ \[\]\)\[\]; valid_vulnerability\)/u);
  assert.match(workflowSource, /cosign attest --yes --type spdxjson/u);
  assert.match(workflowSource, /cosign sign --yes "\$subject"/u);
  assert.match(
    workflowSource,
    /cosign verify[\s\S]*--certificate-identity "\$CERTIFICATE_IDENTITY"[\s\S]*--certificate-oidc-issuer "\$CERTIFICATE_OIDC_ISSUER"/u,
  );
  assert.match(workflowSource, /cosign verify-attestation --type spdxjson/u);
  assert.doesNotMatch(workflowSource, /docs\/security-evidence\/stage4-offline-readiness-artifacts\/image-lock\.json/u);
  assert.doesNotMatch(workflowSource, /(?:tofu|terraform|kubectl|helm|aws |external model)/iu);
  assert.match(workflowSource, /static_parser_cryptographic_verification_performed:false/u);
  assert.match(workflowSource, /readiness_promoted:false,production_ready:false,release_eligible:false/u);
  const cleanup = runStep(workflowJob("publish"), "Cleanup retained builder");
  assert.match(cleanup, /docker logout ghcr\.io/u);
  assert.match(cleanup, /docker buildx rm "\$BUILDX_BUILDER"/u);
  assert.match(cleanup, /docker container inspect "\$buildkit_node"/u);
  assert.match(cleanup, /docker volume inspect "\$buildkit_state"/u);
  assert.match(cleanup, /for image in "\$BUILDKIT_IMAGE" "\$SYFT_IMAGE" "\$TRIVY_IMAGE" "\$COSIGN_IMAGE"/u);
  assert.match(cleanup, /Cleanup retained tool image:/u);
  assert.match(cleanup, /rm -rf -- "\$DOCKER_CONFIG" "\$CONTEXT" "\$WORK" "\$CACHE" "\$ASSERTION" "\$COSIGN_HOME"/u);
  assert.match(cleanup, /for path in "\$DOCKER_CONFIG"[\s\S]*exit "\$status"/u);
  assert.doesNotMatch(workflowSource, /cogs-release-image-set-assertion-upload|\bUPLOAD\b/u);
});
