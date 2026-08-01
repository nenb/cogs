# Stage 4 NIC sandbox node-group static source contract

This repository defines a **local/static semantic contract**, not NIC configuration syntax and not an EKS deployment. The checked artifact is [`deploy/nic/stage4-sandbox-node-group-contract.json`](../../deploy/nic/stage4-sandbox-node-group-contract.json). Its schemas and pure classifier are:

- [`stage4-nic-sandbox-node-group-contract-v1.json`](../../schemas/stage4-nic-sandbox-node-group-contract-v1.json);
- [`stage4-nic-sandbox-node-group-verdict-v1.json`](../../schemas/stage4-nic-sandbox-node-group-verdict-v1.json); and
- [`stage4-nic-sandbox-node-group.ts`](../../scripts/stage4-nic-sandbox-node-group.ts).

The contract is intentionally provider-operation-free. It neither discovers NIC source nor proves that NIC can express the contract. It contains no resource identifier, credential, command, callback, or apply path. Every verdict fixes `campaign_authorized`, `cloud_execution_observed`, `stage4_exit_satisfied`, and `release_eligible` to `false`. This v1 classifier has no ready status: it can only report the authenticated release's missing capability or reject drift.

## Authenticated public-source pin and current blockers

A lead performed read-only public GitHub source authentication outside this implementation session. The checked contract records exactly the supplied closure; the local classifier does not fetch or independently authenticate it.

| Source | Immutable pin |
|---|---|
| NIC | `nebari-dev/nebari-infrastructure-core` tag `v0.11.0`, commit `28221c652c56bb8d48a92538c01503a82f2f9321`, tree `4dfb0333e5d91003e69881ca1dcf66e1ea9ff6c2` |
| NIC `config.go` | blob `b607ccd28fea4fa9dbb1b5f2cab8035c88eb8ab8`, content SHA-256 `9926e0de378b488778e4975324a76c7d3ab3aaa5b4c661e81211a1efe382e920` |
| NIC template `main.tf` | blob `719efb5d85b8247968f6965acd3911b3a0a93337`, content SHA-256 `eca59352b11fbcb48085a9276e5b01682256ce17f55fa7f4a23c0bcccfa443f4` |
| NIC `tofu.go` | content SHA-256 `39e87c14203fa602568bcff4e64126271073484e531c21a83028eb104a9a506b`; no blob ID was supplied, so the contract records `null` rather than inventing one |
| EKS module | registry source `nebari-dev/eks-cluster/aws` `0.7.0`, commit `5d4cb31f07fda5c010b5be580258d32f6db75828`, tree `240dd73f709f67706d60b35d3256661848736ad2` |
| Module files | `variables.tf` `20a17ac8d6a76ebaf5708ac229a062697d277e283561e070f1aac378603e1d67`; `locals.tf` `e21403a5cef4faf515c6179b221e690553f6ad22d012befb57e529b3ccceec5e`; `main.tf` `e7f3107a21e597da972220993f25f38527af74999b6e44f370317938f7d732a0` |

The same source review verified that NIC exposes instance type, minimum/maximum size, AMI type, Spot selection, disk, labels, and taints and maps them into EKS managed node groups. It also found the decisive gap: **NIC v0.11.0 does not expose custom launch-template ID/version or `CpuOptions.NestedVirtualization`; module 0.7.0 auto-creates launch templates only for its fixed shape.** The verdict is therefore `blocked-missing-capability` / `STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING`. Pinning an AMI cannot make this revision ready.

The EKS node image remains a separate honest uncertainty: no Stage 4 AMI ID, image release, or kernel release is recorded. The standalone Stage 2 Ubuntu AMI belongs only to that EC2 evidence and must not be reused as an EKS pin by inference. Tests use a clearly synthetic AMI only to prove that the NIC capability blocker remains sticky.

The exact Kata archive digest is known from ADR 0012. `containerd` 2.2.1 and QEMU 8.2.2 are exact compatibility-version requirements inherited from accepted Stage 2 evidence, but this contract does not claim package-artifact digests for them. The unresolved node-image pin and future exact-run runtime measurements remain required; version strings are not a substitute for binary identity.

## Exact node-group contract

| Field | Required value |
|---|---|
| Provider / region | `aws` / `us-east-1` |
| Group name | `cogs-stage4-sandbox-kata` |
| Capacity | `ON_DEMAND`; Spot is rejected |
| Instance | `c8i-flex.large`, `x86_64`, `bare_metal=false` |
| Scale | minimum `0`, maximum `1`; no unsupported desired-size field is invented |
| Required labels | `cogs.dev/node-domain=sandbox-kata`; `cogs.dev/nested-virtualization=enabled`; `cogs.dev/sandbox-runtime=kata-qemu-kvm` |
| Required taint | `cogs.dev/sandbox=kata:NO_SCHEDULE` in the infrastructure source |
| Pod toleration | `cogs.dev/sandbox`, `Equal`, `kata`, `NoSchedule` |
| Launch template | custom external ID input plus explicit positive-integer version input |
| CPU options | nested virtualization `enabled`, core count `1`, threads per core `2` |
| RuntimeClass / handler | `kata-qemu-cogs` / `kata-qemu` |
| CRI runtime | `io.containerd.kata.v2`; Kata `3.32.0` |
| Kata archive | SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01` |
| Runtime versions | containerd `2.2.1`; QEMU `8.2.2`; accelerator `kvm` |
| Fallbacks | TCG `false`; runc `false` |

`min=0, max=1` is the static bounded campaign ceiling using the two scaling inputs verified in NIC v0.11.0. NIC desired-size support was not reported, so the contract does not invent that field. The bound grants no autoscaler or campaign authority. Any larger maximum, nonzero minimum, added desired-size field, second group, Spot capacity, bare metal, larger instance, other region, or architecture is drift requiring a new review.

## Launch-template preservation

NIC source must accept both `sandbox_launch_template_id` and `sandbox_launch_template_version`. The version must be an explicit positive integer. `$Latest`, `$Default`, implicit latest/default behavior, ID-only references, version rewriting, and reconciliation onto another template/version are forbidden.

The pinned v0.11.0 source cannot satisfy this requirement. A reviewed NIC extension must add the interface, preserve both values through its template and the pinned module boundary, and expose nested CPU options. That extension requires a new immutable source/module closure and contract review; changing only this classifier or setting a capability flag is drift. A future campaign must then compare the approved ID/version with rendered and observed values and verify `CpuOptions.NestedVirtualization=enabled`. This repository currently supplies none of those observations.

## Disjoint scheduling

Trusted Cogs/proxy resources require only `cogs.dev/node-domain=trusted` and have no sandbox taint toleration. Sandbox resources require all three node-group labels (`node-domain`, `nested-virtualization`, and `sandbox-runtime`) and the one exact Kata toleration. The node group has the corresponding labels and taint.

This matches the Helm NOTES-only source shape. The separation is declarative only: it does not prove node labels, scheduler behavior, RuntimeClass existence, admission behavior, or CNI enforcement. Adding the sandbox toleration to trusted resources, changing either selector, removing the taint, or merging the domains is rejected as scheduling drift.

## Security transitions

```text
exact NIC v0.11.0 pin + verified missing launch-template/CPU-options interface
  -> blocked-missing-capability (preserve; no campaign authority)

reviewed NIC extension + new immutable source/module closure
  -> new contract review (never mutate the v0.11.0 assessment to "supported")

new capable source closure + exact EKS AMI/kernel pin + exact contract
  -> new schema/classifier review (v1 cannot emit readiness)

any source/config/runtime/scheduling mismatch
  -> reject-drift (preserve; do not plan, apply, or reconcile)

separately approved exact future campaign + independent observations
  -> a different future evidence authority (never this verdict)
```

A ready verdict does not exist in this v1 authority domain. Any getter/proxy trap, malformed or unknown field, tag/commit/tree/file/module digest change, false claim that the missing interface exists, invalid AMI, Spot, metal, scaling expansion, nested-virtualization change, launch-template latest/default behavior, label/taint overlap, runc, TCG, or runtime substitution fails closed with a bounded reason code.

## NIC adapter acceptance requirements

The v0.11.0 review closes source uncertainty but fails capability admission. A future NIC change must first be reviewed and repinned. A separate local adapter for that new immutable revision must remain deterministic and reject unsupported source shapes rather than dropping fields. It must establish locally that the new pinned source can represent:

- the custom launch-template ID **and explicit version** without reconciliation drift;
- the exact labels, taint, On-Demand type, instance, region, and 0..1 scale bounds;
- a pinned EKS node image and runtime installation/configuration inputs; and
- separation from the ordinary trusted node group.

Pinned NIC v0.11.0 cannot preserve the mandatory fields and is already a blocker. Until a reviewed extension exists, ADR 0012's NIC path cannot enter a campaign. This is never permission to use Spot, bare metal, runc, TCG, an implicit launch-template version, or overlapping scheduling.
