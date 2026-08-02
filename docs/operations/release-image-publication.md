# Protected-main release image publication

**Workflow:** [`.github/workflows/release-images.yml`](../../.github/workflows/release-images.yml)

**Destinations:** `ghcr.io/nenb/cogs/worker` and `ghcr.io/nenb/cogs/sandbox`

**Target:** exactly `linux/amd64`

**Authority:** a first-attempt manual dispatch by `vars.RELEASE_IMAGE_PUBLISH_ACTOR` from the protected `main` branch

**Readiness status:** publication evidence only; a receipt never promotes production readiness or release eligibility

This is the only workflow authorized to publish the production worker and sandbox image definitions. The separate [local image artifact workflow](local-image-artifacts.md) remains nonpublishing, unsigned, and limited to `contents: read`.

## Dispatch contract

The workflow has only a `workflow_dispatch` trigger. It has no pull-request or push trigger. The operator must enter the full 40-character SHA that was reviewed.

Before checkout, login, build, or package-write effects, the authority job requires all of the following:

- `github.run_attempt == 1`;
- actor, triggering actor, event sender, and `vars.RELEASE_IMAGE_PUBLISH_ACTOR` are the same nonempty identity;
- the repository default branch is `main`, the selected ref is `refs/heads/main`, and GitHub reports that ref protected;
- `github.workflow_ref` identifies `.github/workflows/release-images.yml` on `refs/heads/main`;
- workflow SHA, event SHA, reviewed SHA, and the current default-branch HEAD read from the GitHub API are identical; and
- the reviewed SHA is syntactically a full lowercase Git SHA.

The publication job repeats the API HEAD comparison after checking out the exact SHA without credentials. A branch movement before this second check aborts publication.

The workflow-level permission set is empty. The authority job receives only `contents: read`. The effect job receives only `contents: read`, `packages: write`, and `id-token: write`; package and OIDC permissions are not granted to any other job.

## Immutable publication

Each destination receives only `sha-<full-40-character-commit>`. The workflow never writes `latest`, `main`, `stable`, a shortened SHA, or another mutable alias. Before either build it requires both full-SHA tags to be absent. An existing tag aborts the transaction rather than overwriting it. Per-SHA concurrency prevents two authorized runs in this workflow from racing that check.

All Actions are selected by full commit SHA. BuildKit, Syft, Trivy, the Trivy database, and Cosign are selected by OCI digest. Updating any pin is a reviewed source change. The build uses a tracked-only `git archive` context and publishes one direct `linux/amd64` image plus BuildKit `mode=max` provenance. Registry readback must prove:

- the output digest hashes the exact top-level registry index bytes;
- exactly one child is `linux/amd64` with no variant;
- exactly one BuildKit attestation manifest refers to that child; and
- decoded BuildKit provenance reports the BuildKit v1 build type and `linux/amd64` invocation platform.

The job exposes separate `worker_digest` and `sandbox_digest` outputs. These are registry index digests, not config digests, platform-child digests, GitHub artifact digests, or tags.

## SBOM, vulnerability gate, and dispositions

Digest-pinned Syft generates SPDX JSON from each exact registry digest. Keyless Cosign attaches that SPDX document as an `spdxjson` attestation. Both the image signature and SBOM attestation are verified against exactly:

- certificate identity `https://github.com/nenb/cogs/.github/workflows/release-images.yml@refs/heads/main`; and
- OIDC issuer `https://token.actions.githubusercontent.com`.

Digest-pinned Trivy scans the same exact registry digest with the digest-pinned database. The command includes every severity (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`), sets `ignore_unfixed=false`, uses no suppressions, and records fixed-available and unfixed counts. The workflow applies these explicit semantics:

| Finding class | Gate | Receipt disposition |
|---|---|---|
| `HIGH`, `CRITICAL` | Blocking, whether fixed or unfixed. A successful receipt requires a count of zero. | `release-receipt-blocking-including-unfixed` |
| `UNKNOWN` | Non-gating, but retained. | `recorded-non-gating-review-required-not-approved` |
| `LOW`, `MEDIUM` | Non-gating, but retained. | `recorded-non-gating-not-release-approval` |

“Non-gating” does not mean accepted risk, legal approval, production readiness, or release approval. It means only that this publication gate does not block those classes. The strict classifier requires severity counts and fixed/unfixed counts each to partition the complete finding total, and requires disposition counts to match the corresponding severity counts.

A failed gate can leave an unsigned, unreceipted full-SHA registry object because the scan operates on the exact pushed digest. Such an object is not successful publication evidence, cannot produce the canonical receipt, cannot be retried by overwriting its tag, and must not be promoted.

## Canonical redacted receipt

A successful run uploads exactly one file: `release-image-receipt.canonical.json`. The schema is [`schemas/release-image-receipt-v1.json`](../../schemas/release-image-receipt-v1.json), and the classifier is [`scripts/release-image-receipt.ts`](../../scripts/release-image-receipt.ts).

The receipt binds protected-main source identity, workflow authority, exact tag and digest namespaces, linux/amd64 child manifests, tool pins, provenance and SBOM attachment, complete vulnerability count semantics, and verified keyless authority. SHA-256 fields bind the exact decoded provenance readback, generated SPDX JSON, and raw vulnerability report used by the run. It deliberately omits actor identity, tokens, runner details, raw SBOM contents, raw provenance, and raw vulnerability records. Public run metadata can still make a run correlatable; “redacted” means the canonical receipt does not duplicate those fields or contain credentials.

Local inspection is nonpublishing:

```sh
npx tsx scripts/release-image-receipt-cli.ts classify /path/release-image-receipt.canonical.json
```

Classification success means `VALID_SIGNED_PUBLICATION_RECEIPT`. It still fixes all of these to false:

- `runtime_qualification_observed`;
- `readiness_promoted`;
- `production_ready`; and
- `release_eligible`.

## Readiness boundary

Do not change the Stage 4 image lock, offline-readiness evidence, Stage 5 freeze, deployment inputs, or readiness claims before a successful run supplies both exact digest outputs and its valid canonical receipt. Even after such a run, promotion requires a separate reviewed change that consumes those digests and closes the remaining runtime and readiness evidence. The publication workflow itself writes no repository file and performs no readiness promotion.

The cleanup step logs out of GHCR and removes Docker credentials, the tracked build context, scanner database/cache, raw scans, SBOM files, verification output, Cosign state, receipt staging directory, and locally installed npm dependencies after the receipt upload attempt.
