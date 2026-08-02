# Draft NIC and platform matrix

This matrix records evidence posture, not supported-platform advertising. Read the [runbook authority rules](README.md) first.

## Assumptions

- Portability of the SSH/SFTP and explicit-proxy contracts may permit later integrations on additional VM-capable environments.
- Comparable APIs or a successful local render are not proof of isolation, CNI, storage, lifecycle, or support.

## Static contract facts

| Profile | Intended use | Static posture | Current blocker or boundary | Advertised |
|---|---|---|---|---:|
| `linux-kvm` | authoritative local guest-root profile | implemented contract | local scope only | no |
| `insecure-container` | fast functional development | explicitly insecure | no VM isolation authority | no |
| `macos-vm-dev` | optional convenience | development only | no authoritative external default-deny claim | no |
| `aws-eks-kata` through NIC | future reference topology | pending and blocked | NIC `v0.11.0` capability gap; EKS image unresolved; S4-11 absent | no |
| standalone Stage 2 EC2 | historical feasibility | bounded evidence only | not EKS, CNI, installation, or current-resource evidence | no |
| generic Kubernetes with Kata | design portability target | unqualified | cluster-scoped runtime, CNI, CSI, identity, lifecycle evidence absent | no |
| local Linux k3s/Kata | possible local target | unqualified | no accepted exact profile evidence | no |
| Hetzner Cloud full VM | deferred external provisioner profile | unimplemented here | no provider integration or validation | no |
| Hetzner dedicated/k3s Kata | deferred | unvalidated | runtime/network/storage evidence absent | no |
| GCP | deferred | unsupported and unadvertised | production validation absent | no |
| Azure | deferred | unsupported and unadvertised | production validation absent | no |
| software-emulated QEMU/TCG | development compatibility only | forbidden fallback | not accepted isolation/performance path | no |

For NIC's exact required source and node-group shape, use the [NIC configuration guide](nic-configuration.md).

## Authoritative-local facts

- Accepted `linux-kvm` evidence is authoritative-local only. It demonstrates a distinct KVM guest and host-controlled network boundary for that run and profile.
- `insecure-container` evidence remains functional-only even when protocol tests pass.
- macOS development VMs and TCG do not inherit Linux/KVM authority.

See the [Stage 3 Linux/KVM exit report](../../test-reports/stage-3-s3-09-linux-kvm-exit.md).

## Future cloud evidence

For any profile to move beyond this draft, a separate future authority must bind:

- immutable source, images, runtime, kernel, architecture, region, and platform version;
- guest-root isolation, external network enforcement, identity, secret, storage, lifecycle, and cleanup observations with real dependencies;
- repeatable failure, upgrade, privacy/deletion, capacity, cost, and independent inventory results;
- an exact support decision that does not exceed measured profiles or concurrency.

No row currently has those bindings. The provisional [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md) fixes every platform advertisement to false.

## Matrix update rule

Change a row only through reviewed evidence bound to its exact profile. Never promote a profile from architectural similarity, provider documentation, source capability, static rendering, a different provider, a different node image, or a development fallback. Unknown means blocked, not provisionally supported.
