# Stage 4 NIC sandbox node-group static source contract

Cogs records two distinct local/static NIC source authorities. Neither performs provider discovery, initializes infrastructure tooling, or authorizes a campaign.

- Historical v1: [`stage4-sandbox-node-group-contract-v1.json`](../../deploy/nic/stage4-sandbox-node-group-contract-v1.json), pinned to NIC `v0.11.0` and module `0.7.0`, remains `blocked-missing-capability`.
- Active v2: [`stage4-sandbox-node-group-contract.json`](../../deploy/nic/stage4-sandbox-node-group-contract.json), accepted from personal immutable forks, resolves only source-level external launch-template selection capability.

The v1 artifacts remain preserved. Active v2 uses:

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

The node image remains a separate honest uncertainty. The public candidate is Kubernetes `1.35`, `AL2023_x86_64_STANDARD`, release `1.35.6-20260728` at public catalog commit `80b4c870f33069dadf27e075f184c06cccfc7999`; region-specific AMI ID and running kernel remain null. The standalone Stage 2 Ubuntu AMI is historical evidence only and is not an EKS pin.

## Capability resolved by v2

The accepted source can:

- receive a caller-owned launch-template ID matching exact `lt-` plus 17 lowercase hexadecimal characters;
- receive an explicit positive integer version at NIC's Go/YAML boundary;
- reject null, partial, quoted, fractional, `$Latest`, and `$Default` selections;
- preserve ID/version through NIC's JSON and the pinned module mapping;
- disable module launch-template creation on the external path;
- require an operator attestation that nested virtualization is exactly `enabled`; and
- reject `disk_size` when an external template owns block-device configuration.

The active classifier therefore returns `source-capability-satisfied-local-static` and `STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING` for the exact contract. The NIC capability blocker applies only to historical v1 and is absent from active readiness v2.

## Non-observation boundary

`operator_review` is an attestation. NIC performs no provider lookup and the module output only echoes configuration. Every v2 verdict fixes:

- `launch_template_contents_observed=false`;
- `provider_truth_observed=false`;
- `cloud_execution_observed=false`;
- `campaign_authorized=false`;
- `stage4_exit_satisfied=false`; and
- `release_eligible=false`.

Cogs separately binds `core_count=1` and `threads_per_core=2` in the static manifest request. Those fields are not invented in NIC configuration because the accepted NIC input accepts only `nested_virtualization`. A future authorized observer must compare the exact ID/version and all CPU options with provider state.

## Exact node-group contract

| Field | Required value |
|---|---|
| Provider / region | `aws` / `us-east-1` |
| Group name | `cogs-stage4-sandbox-kata` |
| Capacity | `ON_DEMAND`; Spot is rejected |
| Instance / scale | `c8i-flex.large`, `x86_64`, non-metal, minimum `0`, maximum `1` |
| Required labels | `cogs.dev/node-domain=sandbox-kata`; `cogs.dev/nested-virtualization=enabled`; `cogs.dev/sandbox-runtime=kata-qemu-kvm` |
| Required taint / toleration | `cogs.dev/sandbox=kata:NO_SCHEDULE`; matching `Equal`/`NoSchedule` pod toleration |
| Launch template | caller-owned external ID plus explicit positive-integer version; no latest/default |
| CPU options | nested virtualization `enabled`, core count `1`, threads per core `2` |
| RuntimeClass / CRI | `kata-qemu-cogs`; `io.containerd.kata.v2`; Kata `3.32.0` |
| Kata archive | SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01` |
| Runtime artifacts | containerd `2.2.1` SHA-256 `af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883`; Kata-bundled QEMU `11.0.1` SHA-256 `1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d` |
| Fallbacks | KVM only; TCG `false`; runc `false` |

QEMU `8.2.2` is retained only as the historical Stage 2 Ubuntu host observation and source reference. It is not the active Kata runtime artifact. Authenticated candidate bytes are not runtime observations; node image, active KVM, release images, placement, networking, storage, and cleanup still require future evidence.

Trusted placement has only `cogs.dev/node-domain=trusted` and no sandbox toleration. Any source digest, capability, launch-template selection, Spot/metal/scale, placement, runtime, or non-observation change rejects as drift.

## Static manifest handoff

ADR 0094 authorizes [`stage4-static-manifest-package.ts`](../../scripts/stage4-static-manifest-package.ts) to materialize deterministic local handoff bytes. It emits manifests, NIC configuration, and a receipt, but has no apply, Kubernetes client, provider, or deployment-execution route. Helm remains a NOTES-only chart with zero submitted manifests. See [`stage-4-static-manifest-package.md`](stage-4-static-manifest-package.md).
