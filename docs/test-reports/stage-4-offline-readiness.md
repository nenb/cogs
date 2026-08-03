# Stage 4 bounded offline preflight/readiness evidence

## Scope

- Issue: #357.
- Pure authority: `local-static-stage4-readiness-package` / `local-static-stage4-readiness-classifier`.
- Trusted preparation authority: `trusted-local-static-render-preparation`.
- Local preparation: true, scoped only to `bounded-package-assembly-and-local-validation-only`.
- Authenticated selected-runtime candidate artifacts: true (public/static release bytes only).
- Exact image/runtime observation closure: false.
- Campaign request ready / approved / cloud authorized: false / false / false.
- Provider/cloud/Kubernetes/current-resource/zero-resource observation: none.
- Stage 4 exit / release eligible: false / false.

No AWS/provider API or CLI, provider discovery, OpenTofu init/plan/apply, SSM, EKS, Kubernetes API, `kubectl`, Helm install/apply, deployment, external model, price/quota discovery, campaign, or inventory operation was used.

## Trusted render preparation

The bounded preparation executable rejects loader/tsx execution and pins native Node `v22.22.2` (`darwin`/`arm64`) SHA-256 `5c899797c4eb8f1db5563eea56538342ddb3e9276ee1b04a5a1f0f1023d2b011`. It authenticates generator bytes only from `import.meta.filename`, the complete chart inventory, exact synthetic values, Helm `v4.1.1+g5caf004` SHA-256 `9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4`, and the fixed Helm-v4 NOTES wrapper. Helm, chart, and values are materialized from already authenticated bytes in a private directory; only the mode-0500 Helm copy is executed and it is reauthenticated after each bounded invocation. It performs strict lint, a client-only zero-submitted-manifest template, and two client-only review templates with no shell, DNS, kubeconfig, cluster operation, or unbounded output. Lint exits zero, the ordinary chart template contains only a newline and no manifest, and both fresh review digests equal the committed render digest.

Tests freshly rerun preparation through the exact pinned Node CLI. Identical forged committed render files and hostile package render-digest/root rewrites are rejected because fresh output remains independently derived from exact chart/values/tool bytes. Chart or values rewrites fail before trusted completion. Caller-selected generator paths, extra arguments, and tsx-loader invocation fail closed. The classifier independently canonical-parses and exact-anchor-validates receipt, local-validation, image, runtime, source, and schema records and checks all cross-bindings; opaque or internally rewritten artifact sets remain uncertain.

## Exact closure and honest blockers

The generated source inventory covers every tracked worktree file, including `src/`, `images/`, `third_party/`, `.github/workflows/ci.yml`, release workflows, build definitions, qualification inputs, schemas, tests, documentation, and evidence. It excludes only the readiness package, source inventory itself, and local-validation artifact to break generated-evidence recursion; those exclusions are machine-recorded and tested. Every entry records exact Git mode (`100644` or `100755`), path, and exact worktree-byte SHA-256; regeneration verifies Git mode against worktree executable bits. It records the complete tracked path-set digest and a domain-separated Merkle digest over all three entry fields. It makes no predecessor, immutable-commit, or clean-index claim; a later release candidate requires separate binding. Untracked files beneath every validation/build input root reject preparation; unrelated untracked outputs stay outside the closure, and the protected publication workflow excludes all untracked bytes by constructing its context with `git archive`. Source reads retain no-follow descriptors for every component and compare lstat/fstat identities before and after bounded reads; symlink components/finals, hard links, executable-mode mismatch, oversize files, and replacement drift reject.

The v3 package binds all exact local inputs, authenticated-runtime evidence, the protected-main image assertion and independent review records, and one domain-separated semantic root. Public candidate artifact closure is now exact:

- containerd `2.2.1` static archive SHA-256 `af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883` is bound to its release checksum, SLSA provenance, workflow identity/issuer/run, commit, and selected executable members;
- Kata `3.32.0` archive SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01` is bound to the GitHub immutable-release attestation and commit;
- Kata's selected bundled QEMU is `11.0.1`, member SHA-256 `1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d`, with exact configuration and guest-kernel member identities; QEMU `8.2.2` remains historical host/source context only; and
- Kubernetes `1.35` / AL2023 candidate `v20260728` is pinned to catalog commit `80b4c870f33069dadf27e075f184c06cccfc7999`, but its region-specific AMI ID and running kernel remain null.

The two runtime-artifact identity blockers are therefore removed. Active personal-fork NIC v2 also resolves source-level external launch-template selection, so the historical NIC capability blocker is removed. Protected-main run `30852317459` produced a canonical assertion and independently reviewed exact worker/sandbox digests; readiness v3 binds those records and the distinct image-source revision, so `RELEASE_IMAGE_SET_ABSENT` is also removed. This does **not** establish runtime observation closure: exact Envoy lacks a publisher signature; launch-template contents, the EKS AMI ID/running kernel, the selected containerd override, and the composed images remain AWS/EKS/Kata-unobserved. AWS image/kernel, account, price, quota, identity, approval, and provider-route blockers remain.

## Closed proposal and inventory

The package contains 38 fixed hard-maximum resource-class rows covering EKS, VPC/subnets/routes/IGW/default network resources, zero NAT/endpoints/EIP/load balancing, SG/IAM/LT/node-group/ASG, exact trusted/sandbox node types and disk sizes, ENIs, every EBS role and zero snapshots, KMS, logs, budget/notifications, and TTL scheduler/function/permission. Undeclared classes are forbidden.

It contains exactly 38 corresponding independent inventory rows in the same order. Every row is account-wide or account/region service-wide and identity-independent. Parent-keyed APIs first enumerate every parent service-wide. IAM profiles/attachments and EC2 root volumes/instances/ENIs cover orphaned or detached states without relying on a surviving role, node, launch template, attachment, campaign name, or tag. Tag-only inventory is forbidden. All rows remain future and unexecuted; no zero claim is made.

## Executed local evidence boundary

Regeneration executes and records nine pinned, bounded, no-shell commands: readiness formatting, repository typecheck, bounded Stage 4 contract tests, production runtime/image/static-route source-contract tests, Stage 4 schema-registry tests, all-schema validation, trusted Helm lint/zero-manifest/repeated-render checks, complete source inventory, and lockfile SRI integrity. Every record binds exact argv, executable/tool/version/digest, procedure source digests, exit code/signal, bounded stdout/stderr lengths and digests, normalization, and an outcome digest. The command performs no Docker operation. Production Docker builds, release-image publication, and the current npm-registry audit are explicitly recorded as `not-run-not-claimed`; local completion makes no image-build, publication, current audit, or advisory-discovery claim.

## Hostile coverage

Tests cover canonical bytes, every artifact digest, trusted receipt replacement, fresh-render forgery, complete mode-aware source and schema inventories, component/final symlinks, hard links, executable-mode mismatch, oversize source reads, exact closed resource/inventory mapping, prohibited nonzero resources, blocker order/uniqueness, reason/status coupling, all expanded revalidation triggers, source/pin/price/quota/graph replay, invented image/runtime artifacts, authority promotion, two-attempt approval, prior-approval retry, byte bounds, inherited/custom prototypes, symbols, getters, and root/recursive Proxy traps. Invalid or uncertain input preserves uncertainty and every campaign/cloud/release claim remains false.

## Required future work

After #42 closure—and after any source, pin, price/quota, campaign graph, Helm/chart/values/renderer/tool identity, validation/advisory expiry, account/principal/separation, approval/envelope/attempt, destroy, or inventory change—the complete package and trusted receipt must be freshly regenerated. A future authority must supply real release worker/sandbox images, an Envoy signature disposition, region-specific EKS AMI and running-kernel evidence, observation of active NIC v2's launch-template/CPU configuration and the selected containerd/QEMU/kernel bytes, current account/price/quota/support facts, separated identities, and one-attempt approval. This package cannot be promoted into those facts or authorities.
