# Historical prepublication local image artifact transaction

**Authority:** historical unauthenticated local build and static artifact classification only

**Content profile:** exactly `stage0-scaffold-local-candidate`

**Current applicability:** none; the current production worker and Kata guest definitions are deliberately rejected by v1

**Release status:** blocked; not a release-candidate freeze, publication, signature, runtime qualification, or production-readiness decision

This v1 transaction was created for the earlier worker and sandbox scaffolds. It applies only when both OCI configs carry `dev.cogs.profile=stage0-scaffold`; it is historical/prepublication evidence and cannot truthfully classify the current `production-worker-release-candidate` or `kata-sandbox-guest` payloads. The retained manual workflow checks that historical label before any Docker operation, so a dispatch against the current protected branch stops without building. Production image build/publication belongs only to the separate protected-main release workflow and remains not-run-not-claimed by Stage 4 readiness.

A valid historical transaction intentionally does not alter or satisfy the Stage 4 offline-readiness image placeholders, Stage 4 image/runtime closure, Stage 5 freeze manifest, or Stage 5 release-readiness template. It fixes `production_payload_present=false`, `production_ready=false`, and `release_eligible=false`; using v1 for current payload bytes is semantic drift, not evidence.

## Digest namespaces

The transaction never substitutes one of these identities for another:

| Field | Exact meaning |
|---|---|
| `config_digest` | Digest of the OCI image configuration blob. Docker commonly exposes this as a local image ID after loading, but this transaction does not load the image. |
| `docker_image_id` | Daemon-local config identity. It is always `null` because the transaction exports directly to OCI layouts. |
| `oci_subject_manifest_digest` | Digest of the direct, verified linux/amd64 image-manifest blob selected by `index.json`. This is the local image graph subject. |
| `oci_layout_index_sha256` | Hash of exact OCI `index.json` bytes. It binds the layout entry point; it is not called a registry digest. |
| `oci_archive_sha256` | Optional transport-tar checksum. It remains `null`; temporary scan tar bytes are not an image identity. |
| `registry_digest` | Digest observed from a registry after publication and remote readback. It is always `null` here. |
| GitHub artifact digest | Checksum of GitHub's uploaded artifact archive. Workflow logs label it separately and never insert it into an image digest field. |

A local manifest digest might later equal a published manifest digest if a separate publication preserves exact bytes. Equality cannot be claimed until an independently authorized publisher pushes and reads back that registry subject.

## Transaction

The retained historical manual workflow [`.github/workflows/local-image-artifacts.yml`](../../.github/workflows/local-image-artifacts.yml) requires:

- the exact reviewed SHA, equal to the protected default-branch workflow envelope;
- one configured authorized transaction actor;
- exact `anchore/syft@sha256:...` and `aquasec/trivy@sha256:...` linux/amd64 tool images; and
- one exact `ghcr.io/aquasecurity/trivy-db:2@sha256:...` database reference.

The workflow has only `contents: read`. It has no package-write or OIDC permission, performs no login or push, and exposes no signing path. A first-attempt-only authority job validates all four immutable inputs before checkout or Docker effects.

The build job:

1. checks out the exact commit without credentials and rejects a dirty checkout or credential helper;
2. creates the Docker context from `git archive`, never from untracked worktree content;
3. computes a path/mode/size/content source inventory binding;
4. requires a linux/x86_64 Docker engine and linux/amd64 BuildKit support;
5. pulls exact digest-addressed evidence tools;
6. builds each role twice with `--platform linux/amd64`, `--pull`, `--no-cache`, `--network none`, `--provenance=false`, `--sbom=false`, and fixed `SOURCE_DATE_EPOCH`;
7. exports directly to OCI directories without `--load`, tagging, registry login, or push;
8. verifies both OCI graphs and requires exact graph and layout-index equality;
9. acquires the exact requested Trivy DB once, hashes its complete file inventory, and mounts it read-only for both offline scans;
10. generates SPDX JSON SBOMs, all-severity vulnerability JSON without ignoring unfixed findings, non-approving license inventories, unsigned local provenance, and explicit signature-absence evidence;
11. re-verifies the OCI layouts after evidence generation;
12. assembles and classifies the canonical package; and
13. uploads the package as a short-lived CI artifact while stating that the upload digest is not an image or registry digest.

`--network none` constrains Dockerfile `RUN` instructions. Base-image and evidence-tool acquisition are registry reads and are not described as offline. The vulnerability scan itself uses the frozen local DB with `--skip-db-update --offline-scan` and no network.

## Strict OCI verification

[`scripts/local-image-artifacts.ts`](../../scripts/local-image-artifacts.ts) applies bounded, no-follow filesystem inspection. It rejects:

- a symlink, hard-linked file, non-regular object, path escape, identity drift, unexpected file, unreachable blob, or exceeded count/size bound;
- an unsupported OCI layout version or unknown security-relevant JSON field;
- more than one top-level descriptor, an attestation descriptor, nested index, extra platform, or absent platform;
- any target other than direct `linux/amd64` with no variant;
- descriptor size/digest mismatch, duplicate reachable digest, unsupported manifest/config/layer media type, or unreferenced blob;
- a config not labelled `dev.cogs.profile=stage0-scaffold`; and
- any two-build difference in index bytes, subject, config, ordered layers, reachable blob inventory, or aggregate graph metadata.

The bounds are exported as `LOCAL_IMAGE_LIMITS` and covered by hostile tests. The verifier does not trust a Docker tag or daemon image inventory.

## Evidence semantics

### SBOM

The package binds exact SPDX JSON bytes and the digest-pinned Syft image. SPDX package inventory is required. SBOM generation is evidence inventory, not proof that every package or license was discovered.

### Vulnerabilities

The package binds the digest-pinned Trivy image, requested digest-pinned database reference, complete acquired DB-file inventory hash, exact report bytes, all five severities (`UNKNOWN` through `CRITICAL`), `ignore_unfixed=false`, and `offline_scan=true`. Findings are retained as evidence. This scaffold package does not convert an empty report into release approval and does not provide a vulnerability exception mechanism.

### Licenses

The license inventory preserves SPDX declared and concluded expressions. Missing or `NOASSERTION` data becomes `unknown-review-required`; other entries remain `declared-not-legally-approved`. It always fixes `legal_review_performed=false` and `release_approved=false`. It does not reuse the npm permissive-license allowlist for Debian operating-system packages.

### Provenance and signatures

The provenance is an in-toto Statement with the project-specific predicate `https://cogs.dev/attestations/local-build-record/v1`. It binds the local manifest subject, source, builder versions, invocation controls, and graph-comparison evidence. Its authority is fixed to `unauthenticated-local-build-observation`, with `signed=false` and `published=false`. It is not SLSA provenance and BuildKit's own attestations are disabled to keep the OCI image graph deterministic.

Signature evidence is an explicit absence record. Hashes, BuildKit metadata, Git identity, provenance, and the GitHub upload digest are not signatures. The transaction has no key-generation or signing command. A future package signature would still not be a registry image signature; registry signing requires a separate published subject and authority.

## Local verification commands

These commands inspect already-created artifacts; they do not publish or sign:

```sh
npm run images:local:verify -- verify worker /path/worker-a.oci /path/worker-b.oci /tmp/worker-graph.json
npm run images:local:verify -- licenses worker /path/worker.spdx.json /tmp/worker-licenses.json
npm run images:local:verify -- classify /path/package.canonical.json /path/artifact-root
```

Package assembly consumes a strict transaction input and refuses to overwrite its output:

```sh
npm run images:local:assemble -- transaction-input.json artifact-root package.canonical.json
```

## Mandatory blockers

A valid v1 package means only that complete bound local evidence exists for two equal historical scaffold builds. It cannot be generated for the current production payload and always retains:

- `PRODUCTION_IMAGE_PAYLOAD_ABSENT`;
- `REGISTRY_PUBLICATION_NOT_OBSERVED`;
- `IMAGE_SIGNATURE_NOT_VERIFIED`;
- `RUNTIME_CONFORMANCE_NOT_EXECUTED`;
- `STAGE4_IMAGE_RUNTIME_CLOSURE_UNCHANGED_FALSE`; and
- `STAGE5_RELEASE_FREEZE_UNCHANGED_ABSENT`.

Do not copy local digests into `docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json`, change `.invalid` placeholders, fill the provisional Stage 5 freeze bindings, or describe this workflow artifact as a release image.
