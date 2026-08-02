# Stage 4 bounded offline preflight/readiness evidence

## Scope

- Issue: #357.
- Pure authority: `local-static-stage4-readiness-package` / `local-static-stage4-readiness-classifier`.
- Trusted preparation authority: `trusted-local-static-render-preparation`.
- Local preparation: true, scoped only to `bounded-package-assembly-and-local-validation-only`.
- Exact image/runtime closure: false.
- Campaign request ready / approved / cloud authorized: false / false / false.
- Provider/cloud/Kubernetes/current-resource/zero-resource observation: none.
- Stage 4 exit / release eligible: false / false.

No AWS/provider API or CLI, provider discovery, OpenTofu init/plan/apply, SSM, EKS, Kubernetes API, `kubectl`, Helm install/apply, deployment, external model, price/quota discovery, campaign, or inventory operation was used.

## Trusted render preparation

The bounded preparation executable rejects loader/tsx execution and pins native Node `v22.22.2` (`darwin`/`arm64`) SHA-256 `5c899797c4eb8f1db5563eea56538342ddb3e9276ee1b04a5a1f0f1023d2b011`. It authenticates generator bytes only from `import.meta.filename`, the complete chart inventory, exact synthetic values, Helm `v4.1.1+g5caf004` SHA-256 `9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4`, and the fixed Helm-v4 NOTES wrapper. Helm, chart, and values are materialized from already authenticated bytes in a private directory; only the mode-0500 Helm copy is executed and it is reauthenticated after each bounded invocation. It performs two client-only local `helm template` runs with no shell, DNS, kubeconfig, cluster operation, or unbounded output. Both fresh render digests equal the committed render digest.

Tests freshly rerun preparation through the exact pinned Node CLI. Identical forged committed render files and hostile package render-digest/root rewrites are rejected because fresh output remains independently derived from exact chart/values/tool bytes. Chart or values rewrites fail before trusted completion. Caller-selected generator paths, extra arguments, and tsx-loader invocation fail closed. The classifier independently canonical-parses and exact-anchor-validates receipt, local-validation, image, runtime, source, and schema records and checks all cross-bindings; opaque or internally rewritten artifact sets remain uncertain.

## Exact closure and honest blockers

The generated source inventory covers the complete Stage 4 closure, including Helm/NIC, every Stage 4 schema/script/test/fixture/doc, root build locks, all readiness generators/artifacts, the active `scripts/validate-schemas.ts` schema-pass executor, the committed regeneration procedure, and the later storage proxied-byte correction. It excludes only the readiness package, source inventory itself, and local-validation artifact to break explicit self-reference; those exclusions are machine-recorded and tested.

The package binds all exact local inputs and one domain-separated semantic root. This does **not** establish release artifact closure:

- worker and sandbox records are `.invalid` placeholders, so `RELEASE_IMAGE_SET_ABSENT` remains blocking;
- containerd `2.2.1` and QEMU `8.2.2` have null artifact SHA-256 values, so their separate artifact-identity blockers remain;
- the EKS AMI/image/kernel is unresolved;
- NIC `v0.11.0` / module `0.7.0` lacks custom launch-template/nested-CPU support.

Placeholder digests and version strings cannot satisfy these blockers.

## Closed proposal and inventory

The package contains 38 fixed hard-maximum resource-class rows covering EKS, VPC/subnets/routes/IGW/default network resources, zero NAT/endpoints/EIP/load balancing, SG/IAM/LT/node-group/ASG, exact trusted/sandbox node types and disk sizes, ENIs, every EBS role and zero snapshots, KMS, logs, budget/notifications, and TTL scheduler/function/permission. Undeclared classes are forbidden.

It contains exactly 38 corresponding independent inventory rows in the same order. Every row is account-wide or account/region service-wide and identity-independent. Parent-keyed APIs first enumerate every parent service-wide. IAM profiles/attachments and EC2 root volumes/instances/ENIs cover orphaned or detached states without relying on a surviving role, node, launch template, attachment, campaign name, or tag. Tag-only inventory is forbidden. All rows remain future and unexecuted; no zero claim is made.

## Hostile coverage

Tests cover canonical bytes, every artifact digest, trusted receipt replacement, fresh-render forgery, complete source and schema inventories, exact closed resource/inventory mapping, prohibited nonzero resources, blocker order/uniqueness, reason/status coupling, all expanded revalidation triggers, source/pin/price/quota/graph replay, invented image/runtime artifacts, authority promotion, two-attempt approval, prior-approval retry, byte bounds, inherited/custom prototypes, symbols, getters, and root/recursive Proxy traps. Invalid or uncertain input preserves uncertainty and every campaign/cloud/release claim remains false.

## Required future work

After #42 closure—and after any source, pin, price/quota, campaign graph, Helm/chart/values/renderer/tool identity, validation/advisory expiry, account/principal/separation, approval/envelope/attempt, destroy, or inventory change—the complete package and trusted receipt must be freshly regenerated. A future authority must supply real release images, exact containerd/QEMU artifacts, a capable NIC revision, exact EKS image/kernel, current account/price/quota/support facts, separated identities, and one-attempt approval. This package cannot be promoted into those facts or authorities.
