# Protected-main image-set publication

**Workflow:** [`.github/workflows/release-images.yml`](../../.github/workflows/release-images.yml)

**Transport destinations:** `ghcr.io/nenb/cogs/worker` and `ghcr.io/nenb/cogs/sandbox`

**Target:** exactly `linux/amd64`

**Authority:** a first-attempt manual dispatch by `vars.RELEASE_IMAGE_PUBLISH_ACTOR` from protected `main`

**Readiness status:** successful-workflow assertions only; neither transport tags nor the assertion artifact promote readiness or release eligibility

The separate [local image artifact workflow](local-image-artifacts.md) remains nonpublishing, unsigned, and limited to `contents: read`.

## Dispatch and source authority

The workflow has only `workflow_dispatch`. Before package-write effects it requires the actor, triggering actor, event sender, and configured publisher to be the same; attempt one; protected `refs/heads/main`; the workflow loaded from that ref; and exact equality among the reviewed SHA, event SHA, workflow SHA, and current default-branch HEAD. It repeats the API HEAD check after credential-free checkout and builds a tracked-only `git archive` context. The workflow permission set is empty; authority receives `contents: read`, while publication receives only `contents: read`, `packages: write`, and `id-token: write`.

## Run-unique transport, not release tags

Each run writes only `candidate-<full-sha>-<run-id>-<run-attempt>` transport tags. They are retained so the registry keeps the exact image graphs and attached artifacts. A failed run may leave one or two incomplete, unsigned, or unreceipted transport objects. Their `candidate-` name does not denote a complete image set, readiness, or release authority.

The workflow writes no `sha-<commit>`, `latest`, `main`, `stable`, shortened-SHA, or other final/release alias. Consequently two repository tag writes are never used as an atomic image-set transaction, and a new first-attempt dispatch can retry safely with a different run-unique transport identity.

A successful run's sole image-set record is the canonical GitHub workflow artifact `release-image-set-assertion.canonical.json`. Consumers must separately review that assertion record and use both exact `repository@sha256:...` references. A transport tag alone, one digest alone, or workflow success without the downloaded assertion artifact is insufficient.

## Pinned build and evidence tools

[`config/release-image-set-pins-v1.json`](../../config/release-image-set-pins-v1.json) is the sole reviewed source for the Buildx version/Linux-amd64 checksum and the exact BuildKit, Syft, Trivy, OS database, Java database, and Cosign OCI references. `npm run release-pins:regenerate` writes the schema constants and the workflow's static environment mirror; `npm run release-pins:check` rejects drift. The workflow also compares the complete static mirror with the manifest after exact-SHA checkout. It never appends manifest-derived executable names, checksums, or image references to `GITHUB_ENV`.

Buildx is manually installed from the manifest-selected exact Linux/amd64 bytes. The workflow verifies the checksum and reported version, creates a run-named builder, and uses the digest-pinned BuildKit image. It invokes that pinned client directly with a private metadata file for each image; no build action, build summary, or build-record artifact is enabled. The assertion schema and semantic parser require the entire recorded `tools` object to equal the manifest. Cosign is the immutable v3.0.5 multi-platform index `ghcr.io/sigstore/cosign/cosign@sha256:be924970ba7438c22e18067dec5637946d6566eac711f5bedd1584e7137008fb`; the workflow selects `linux/amd64`, verifies the pulled repository digest, and requires the binary to report exactly `v3.0.5`. This contract pins the two database OCI references only; extracted database hashes, metadata, and expiry remain outside this v1 change.

Each build publishes one direct `linux/amd64` child plus BuildKit `mode=max` provenance. The metadata-derived digest must equal the metadata descriptor digest. Registry readback then requires that digest to hash the exact top-level index, exactly one variant-free `linux/amd64` child, exactly one BuildKit attestation manifest referring to that child, and decoded BuildKit v1 provenance reporting `linux/amd64`.

The production sandbox fixes package policy `debian-trixie-snapshots-20260713-20260731-production-core-v2`: Bash, CA certificates, Git, OpenSSH client/key validation and server/internal SFTP, OpenSSL, and Python input capture are the only direct package roots. Node/npm, Java, curl, Python client/pip, DNS/firewall/socket probes, and other conformance tooling remain in the separately labelled `insecure-container` / `functional-only` image and cannot enter this publication subject without failing static package-policy checks.

## SBOM, scanner, and signature assertions

Digest-pinned Syft generates SPDX JSON from each exact digest. Cosign attaches it as an `spdxjson` attestation, signs each exact digest, and verifies the workflow certificate identity and GitHub Actions OIDC issuer.

Trivy scans each exact digest with every severity and `ignore_unfixed=false`. Before counting findings the workflow requires:

- `SchemaVersion == 2`;
- exact `ArtifactName` and a `Metadata.RepoDigests` member equal to the scanned digest reference;
- `ArtifactType == container_image`;
- nonempty OS family/name metadata;
- a nonempty `Results` array where every entry is an object;
- only exact `os-pkgs` or `lang-pkgs` classes, each with nonempty target and type;
- every `os-pkgs` type equal to `Metadata.OS.Family`, with at least one such OS-package result;
- `Vulnerabilities` equal to either `null` or an array for every result; and
- every vulnerability carrying nonempty vulnerability/package identity and installed-version strings, an allowed severity, and only an absent, null, or string fixed version.

`HIGH` and `CRITICAL` findings block, including unfixed findings. `UNKNOWN`, `LOW`, and `MEDIUM` are retained but non-gating and grant no risk, legal, readiness, or release approval. Counts must partition both severity and fixed/unfixed dimensions. The assertion records these as workflow observations only; the static parser does not independently inspect the omitted raw report.

## Canonical successful-workflow image-set assertion

The schema is [`schemas/release-image-set-assertion-v1.json`](../../schemas/release-image-set-assertion-v1.json), the parser is [`scripts/release-image-set-assertion.ts`](../../scripts/release-image-set-assertion.ts), and local classification is:

```sh
npx tsx scripts/release-image-set-assertion-cli.ts classify /path/release-image-set-assertion.canonical.json
```

The record binds protected-main source assertions, run-unique transport identities, exact digest references, child manifests, pinned tools, provenance/SBOM assertions, strict scanner-envelope assertions and counts, and keyless verification assertions. It deliberately omits credentials, actor identity, runner details, and raw scanner/SBOM/provenance content.

Static classification success (`VALID_WORKFLOW_ASSERTION_RECORD`) means only canonical, schema-valid, internally consistent assertions. It performs no registry, Cosign, transparency-log, scanner, or cryptographic verification and always leaves publication truth, signature truth, vulnerability truth, readiness, production readiness, and release eligibility false.

Do not update deployment image locks or readiness evidence until a separate reviewed change consumes the successful artifact and both exact digests. The workflow itself writes no repository file and performs no promotion.

The publication job exports only the canonical redacted assertion bytes, Base64 encoded and bounded to 65,536 decoded bytes, plus their exact byte size and SHA-256. It then removes and verifies removal of the named builder, BuildKit container and state volume, Buildx client and pinned tool images, Docker credentials, tracked context, scanner cache/database, raw evidence, Cosign state, assertion staging, and installed npm dependencies. Any cleanup or action post-step uncertainty fails the finalized publication job.

A separate minimal job, with no checkout, Node setup, registry credentials, OIDC permission, or package permission, becomes eligible only when `needs.publish.result == 'success'`. It reconstructs the bounded bytes, verifies Base64 length, ownership, mode, link count, file type, size, SHA-256, and sole-file containment, then performs the workflow's only artifact upload as its final step. Thus an assertion cannot be uploaded before the publication job's cleanup and action post steps have finalized successfully.
