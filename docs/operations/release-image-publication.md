# Protected-main image-set publication

**Workflow:** [`.github/workflows/release-images.yml`](../../.github/workflows/release-images.yml)

**Transport destinations:** `ghcr.io/nenb/cogs/worker` and `ghcr.io/nenb/cogs/sandbox`

**Target:** exactly `linux/amd64`

**Authority:** a first-attempt manual dispatch by `vars.RELEASE_IMAGE_PUBLISH_ACTOR` from protected `main`

**Readiness status:** successful-workflow assertions only; neither transport tags nor the assertion artifact promote readiness or release eligibility

The separate [local image artifact workflow](local-image-artifacts.md) remains nonpublishing, unsigned, and limited to `contents: read`. The [local vulnerability preflight](release-local-vulnerability-preflight.md) can scan already-existing exact local subjects with this workflow's Trivy policy, but cannot establish publication, signature, readiness, or release truth.

## Dispatch and source authority

The workflow has only `workflow_dispatch`. Before package-write effects it requires the actor, triggering actor, event sender, and configured publisher to be the same; attempt one; protected `refs/heads/main`; the workflow loaded from that ref; and exact equality among the reviewed SHA, event SHA, workflow SHA, and current default-branch HEAD. It repeats the API HEAD check after credential-free checkout and builds a tracked-only `git archive` context. The workflow permission set is empty; authority receives `contents: read`, while publication receives only `contents: read`, `packages: write`, and `id-token: write`.

## Run-unique transport, not release tags

Each run writes only `candidate-<full-sha>-<run-id>-<run-attempt>` transport tags. They are retained so the registry keeps the exact image graphs and attached artifacts. A failed run may leave one or two incomplete, unsigned, or unreceipted transport objects. Their `candidate-` name does not denote a complete image set, readiness, or release authority.

The workflow writes no `sha-<commit>`, `latest`, `main`, `stable`, shortened-SHA, or other final/release alias. Consequently two repository tag writes are never used as an atomic image-set transaction, and a new first-attempt dispatch can retry safely with a different run-unique transport identity.

A successful run's sole image-set record is the canonical GitHub workflow artifact `release-image-set-assertion.canonical.json`. Consumers must separately review that assertion record and use both exact `repository@sha256:...` references. A transport tag alone, one digest alone, or workflow success without the downloaded assertion artifact is insufficient.

## Pinned build and evidence tools

[`config/release-image-set-pins-v1.json`](../../config/release-image-set-pins-v1.json) is the sole reviewed source for the Buildx version/Linux-amd64 checksum and the exact BuildKit, Syft, Trivy, OS database, Java database, and Cosign OCI references. `npm run release-pins:regenerate` writes the schema constants and the workflow's static environment mirror; `npm run release-pins:check` rejects drift. The workflow also compares the complete static mirror with the manifest after exact-SHA checkout. It never appends manifest-derived executable names, checksums, or image references to `GITHUB_ENV`.

Buildx is manually installed from the manifest-selected exact Linux/amd64 bytes. The workflow verifies the checksum and reported version, creates a run-named builder, and uses the digest-pinned BuildKit image. It invokes that pinned client directly with a private metadata file for each image; no build action, build summary, or build-record artifact is enabled. The workflow exclusively creates each zero-byte `0600` metadata destination inside its `0700` work directory. Buildx rewrites that destination with mode `0644`, so the workflow verifies the resulting non-link, caller-owned, single-link regular file and its 4 MiB bound before restoring `0600` and parsing it. The assertion schema and semantic parser require the entire recorded `tools` object to equal the manifest. Cosign is the immutable v3.0.5 multi-platform index `ghcr.io/sigstore/cosign/cosign@sha256:be924970ba7438c22e18067dec5637946d6566eac711f5bedd1584e7137008fb`; the workflow selects `linux/amd64`, verifies the pulled repository digest, and requires the binary to report exactly `v3.0.5`.

### Reviewed local database refresh observation

On 2026-08-15, direct authenticated-read observations of the GHCR Aqua tags `trivy-db:2` and `trivy-java-db:1` resolved to the exact references below. Each exact OCI manifest was required to carry the recorded schema, artifact type, and sole database layer media type. The exact layers were downloaded, checked against their manifest SHA-256 digests, and their `metadata.json` members were inspected. These are bounded local observations used for source review; they do not establish continuing tag or registry truth after the observation. The protected-main publication workflow must independently acquire and validate these exact database subjects with the pinned Trivy image before it may scan or sign images.

| Database | Prior pin | Reviewed pin / local tag resolution | OCI manifest schema | OCI artifact type | OCI layer media type | Cache metadata version | `UpdatedAt` | `NextUpdate` (exclusive) | Layer `DownloadedAt` |
|---|---|---|---:|---|---|---:|---|---|---|
| OS vulnerability DB | `ghcr.io/aquasecurity/trivy-db:2@sha256:3d9ac2dcf97e923fad3065ddb2262b0790426a7f87b3ec06b70462dc7b5ddc6a` | `ghcr.io/aquasecurity/trivy-db:2@sha256:6c572fd3cd13d8a53dd77769bae83f0e3d01845478d39ce2bf8c163bf01ec5f6` | `2` | `application/vnd.aquasec.trivy.config.v1+json` | `application/vnd.aquasec.trivy.db.layer.v1.tar+gzip` | `2` | `2026-08-14T19:04:21.476442208Z` | `2026-08-15T19:04:21.476441957Z` | `0001-01-01T00:00:00Z` |
| Java DB | `ghcr.io/aquasecurity/trivy-java-db:1@sha256:8a8e6f28332f81c09f8cd575f8fda8b1c30fb5fe4c30f7f55ce06a01a6cc93c7` | `ghcr.io/aquasecurity/trivy-java-db:1@sha256:d0aedabd2fc7075e2c03c7db43f4932b8da08d51c6ed5c360b79966fe6e1930b` | `2` | `application/vnd.aquasec.trivy.config.v1+json` | `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` | `1` | `2026-08-14T01:11:46.85061936Z` | `2026-08-17T01:11:46.85061906Z` | `0001-01-01T00:00:00Z` |

The failed first publication dispatch for source `ccceb01b64c5dfe382709623a9c1355c53c0c154` stopped before scanning or signing because the prior OS database pin no longer had the required 60-minute validity. Its run-unique transport objects are incomplete and non-authorizing. They are not reused; a later dispatch requires this changed, separately reviewed protected-main source revision.

Database-pin rotation changes the schema used to finalize future publication assertions. It does not reinterpret an already independently reviewed historical assertion: that review remains bound to the assertion's exact canonical SHA-256, source identity, image identities, and review SHA-256.

### Current Pi 0.84.2 publication and independent review

Protected-main run `31856469035`, attempt one, published source `cb9ec3958f6f2571c7c3f90e25b645e49e288a3f`. Artifact `9239219656` contains the canonical assertion with SHA-256 `2368b09be02dc6e21debd8f047e58400173d62ff13edc27398ddbfe1708474d4`. The independently reproduced review has SHA-256 `9e3f9ababef58e8b4cc90e9f007251c05a2065eb2ff2e25f928e7c8b4d61e216` and selects only:

- `ghcr.io/nenb/cogs/worker@sha256:1e71b2d0cd65f16c9633e092311b885ff03f43f4036195326e1a9fc91ea57535`;
- `ghcr.io/nenb/cogs/sandbox@sha256:db475ee1d01d446fe79cc9efdad40c9589cefe60eb69bce2f35108ea44eb94fe`.

The independent review matched the protected-main tree and inventory, registry index digests, run-unique transport tags, Linux/amd64 children, BuildKit provenance hashes, exact GitHub workflow certificate constraints, transparency-log inclusion, and signed SPDX attestations. A separate scan with the exact pinned Trivy image and exact pinned OS/Java databases reproduced all assertion counts with zero HIGH and zero CRITICAL findings. Sandbox dpkg, Trivy, and independently generated Syft inventories each contained 140 Ubuntu packages; the worker inventory contained one `undici@8.9.0` installation at the Pi dependency path. These observations satisfy only current-source static image identity closure. They do not establish runtime qualification, OpenBao acceptability, cloud/provider/Kubernetes truth, production readiness, or release eligibility.

The publication workflow treats downloaded cache metadata as private ephemeral state. Immediately after each exact acquisition it requires a caller-owned, single-link, `0600`, regular non-symlink metadata file bounded to 64 KiB; strict UTF-8 JSON with exactly `Version`, `NextUpdate`, `UpdatedAt`, and `DownloadedAt`; contextual DB type and exact Trivy schema version (`2` for OS, `1` for Java); `UpdatedAt` no later than evaluation; and `NextUpdate` strictly later than `UpdatedAt`, evaluation, and a conservative 60-minute run bound. It snapshots the metadata hash and reviewed fields privately, then reopens and compares both files immediately before each scan, before signing, and before assertion finalization. Substitution, malformed metadata, future updates, expiry, or insufficient remaining validity fails the job. Raw cache metadata and private snapshots are deleted with scanner state and are never uploaded or inserted into the redacted assertion.

Each build publishes one direct `linux/amd64` child plus BuildKit `mode=max` provenance. The metadata-derived digest must equal the metadata descriptor digest. Registry readback then requires that digest to hash the exact top-level index, exactly one variant-free `linux/amd64` child, exactly one BuildKit attestation manifest referring to that child, and decoded BuildKit v1 provenance reporting `linux/amd64`.

The production sandbox fixes package policy `ubuntu-noble-snapshot-20260801-production-core-v1` on the exact Linux/amd64 Ubuntu 24.04 OCI index. Ubuntu's signed snapshot mechanism is fixed at `20260801T000000Z` for `noble`, `noble-updates`, and `noble-security`, using `main universe` only; the initial OpenSSL/CA artifacts are official snapshot URLs constrained by reviewed SHA-256 values and verified package identities. Bash, CA certificates, Git, OpenSSH client/key validation and server/internal SFTP, OpenSSL, and Python input capture are the only direct package roots. APT and dpkg metadata and `/etc/os-release` remain present for scanner visibility. Node/npm, Java, curl, Python client/pip, DNS/firewall/socket probes, and other conformance tooling remain in the separately labelled `insecure-container` / `functional-only` image and cannot enter this publication subject without failing static package-policy checks.

## SBOM, scanner, and signature assertions

Digest-pinned Syft generates SPDX JSON from each exact digest. Cosign attaches it as an `spdxjson` attestation, signs each exact digest, and verifies the workflow certificate identity and GitHub Actions OIDC issuer. Pinned Cosign v3 verification reports the image signature and the signed SPDX attachment together; the validator requires exactly one `https://sigstore.dev/cosign/sign/v1` record and one `https://spdx.dev/Document` record, in either order, both bound to the exact digest reference. The separate attestation verifier then requires exactly one valid in-toto SPDX statement for the same repository and digest.

Trivy scans each exact digest with every severity and `ignore_unfixed=false`. Before counting findings the workflow requires:

- `SchemaVersion == 2`;
- exact `ArtifactName` and a `Metadata.RepoDigests` member equal to the scanned digest reference;
- `ArtifactType == container_image`;
- nonempty OS family/name metadata;
- a nonempty `Results` array where every entry is an object;
- only exact `os-pkgs` or `lang-pkgs` classes, each with nonempty target and type;
- every `os-pkgs` type equal to `Metadata.OS.Family`, with at least one such OS-package result;
- `Packages` equal to an array for every result, with nonempty package identity/version fields and a nonempty OS-package inventory (the scan uses `--list-all-pkgs`);
- `Vulnerabilities` equal to either `null` or an array for every result; and
- every vulnerability carrying nonempty vulnerability/package identity and installed-version strings, an allowed severity, and only an absent, null, or string fixed version.

`HIGH` and `CRITICAL` findings block, including unfixed findings. For the sandbox, the workflow additionally requires Trivy to identify `ubuntu` 24.04, obtains the exact dpkg installed-package count from the digest subject, and compares it with nonempty Trivy and SPDX package evidence so an empty or materially incomplete OS inventory fails closed. `UNKNOWN`, `LOW`, and `MEDIUM` are retained but non-gating and grant no risk, legal, readiness, or release approval. Counts must partition both severity and fixed/unfixed dimensions. The assertion records these as workflow observations only; the static parser does not independently inspect the omitted raw report.

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
