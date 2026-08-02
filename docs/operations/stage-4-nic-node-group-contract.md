# Stage 4 NIC sandbox node-group static source contract

Cogs records two distinct local/static NIC source authorities. Neither performs provider discovery, initializes infrastructure tooling, or authorizes a campaign.

- Historical v1: [`stage4-sandbox-node-group-contract-v1.json`](../../deploy/nic/stage4-sandbox-node-group-contract-v1.json), pinned to NIC `v0.11.0` and module `0.7.0`, remains `blocked-missing-capability`.
- Active v2: [`stage4-sandbox-node-group-contract.json`](../../deploy/nic/stage4-sandbox-node-group-contract.json), accepted from personal immutable forks, resolves only source-level external launch-template selection capability.

The v1 schema/classifier remain preserved. Active v2 uses:

- [`stage4-nic-sandbox-node-group-contract-v2.json`](../../schemas/stage4-nic-sandbox-node-group-contract-v2.json);
- [`stage4-nic-sandbox-node-group-verdict-v2.json`](../../schemas/stage4-nic-sandbox-node-group-verdict-v2.json); and
- [`stage4-nic-sandbox-node-group.ts`](../../scripts/stage4-nic-sandbox-node-group.ts).

## Accepted personal-fork closure

| Source | Immutable identity |
|---|---|
| NIC | `nenb/nebari-infrastructure-core` commit `53b1a791ed1ff394969e0aeaa6379be955244b62`, parent `89235de0f660413978ca76dc1633a499c9952b22`, tree `32c14bd9a19c0519006a9b86284402f9e0187947` |
| EKS module | `nenb/terraform-aws-eks-cluster` commit `c3017c0e15b538cd4e04c0786809a861ea82c621`, parent `8d41b1b02d800dc8e71fc8f06b9aade936c07cf0`, tree `59105ac6f037977d0dddebf844affa06e0b01236` |

Both are unsigned commits on unprotected personal-fork branches. The owner explicitly accepts them for this Cogs local/static contract. This is not an upstream merge or release claim. The active contract pins Git blob SHA, content SHA-256, and byte length for ten NIC files and nine module files, including implementation, module boundary, tests, dependency locks, and the module static-contract workflow.

The module's exact static-contract check passed. No Cogs verdict promotes that check to provider observation.

## Capability resolved by v2

The accepted source can:

- receive a caller-owned launch-template ID matching exact `lt-` plus 17 lowercase hexadecimal characters;
- receive an explicit positive integer version at NIC's Go/YAML boundary;
- reject null, partial, quoted, fractional, `$Latest`, and `$Default` selections;
- preserve ID/version through NIC's JSON and the pinned module mapping;
- disable module launch-template creation on the external path;
- require an operator attestation that nested virtualization is exactly `enabled`; and
- reject `disk_size` when an external template owns the block-device configuration.

The active classifier therefore returns `source-capability-satisfied-local-static` and `STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING` for the exact contract.

## Non-observation boundary

`operator_review` is an attestation. NIC performs no AWS lookup and the module output only echoes configuration. Therefore every v2 verdict fixes:

- `launch_template_contents_observed=false`;
- `provider_truth_observed=false`;
- `cloud_execution_observed=false`;
- `campaign_authorized=false`;
- `stage4_exit_satisfied=false`; and
- `release_eligible=false`.

Cogs separately binds `core_count=1` and `threads_per_core=2` in the static manifest request. Those fields are not invented in NIC configuration because the accepted NIC input accepts only `nested_virtualization`. A future authorized observer must compare the exact ID/version and all CPU options with provider state.

The EKS node AMI, image release, kernel, KVM modules, runtime artifacts, release images, placement, CNI, storage, and cleanup remain unresolved or unobserved elsewhere.

## Exact node-group contract

The active contract retains `c8i-flex.large` in `us-east-1`, On-Demand, `x86_64`, non-metal, scale `0..1`, the three sandbox labels, `cogs.dev/sandbox=kata:NO_SCHEDULE`, the matching pod toleration, Kata `3.32.0`, `io.containerd.kata.v2`, KVM-only acceleration, and no runc or TCG fallback. Trusted placement has only `cogs.dev/node-domain=trusted` and no sandbox toleration.

Any source digest, capability, launch-template selection, Spot/metal/scale, placement, runtime, or non-observation change rejects as drift.

## Static manifest handoff

ADR 0094 authorizes [`stage4-static-manifest-package.ts`](../../scripts/stage4-static-manifest-package.ts) to materialize deterministic local handoff bytes. It emits manifests, NIC configuration, and a receipt, but has no apply, Kubernetes client, provider, or deployment-execution route. See [`stage-4-static-manifest-package.md`](stage-4-static-manifest-package.md).
