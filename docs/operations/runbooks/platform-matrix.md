# Draft NIC and platform matrix

This matrix records evidence posture, not supported-platform advertising. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| Portable SSH/SFTP and explicit-proxy contracts may permit later VM-capable integrations. | [Authority: DESIGN runtime and platform profiles](../../../DESIGN.md#6-runtime-and-platform-profiles) |
| Comparable APIs or a local render do not prove isolation, CNI, storage, lifecycle, or support. | [Authority: IMPLEMENTATION cross-stage test matrix](../../../IMPLEMENTATION.md#46-cross-stage-test-matrix) |

## Static contract facts

| Profile | Static posture and boundary | Advertised | Specific authority |
|---|---|---:|---|
| `linux-kvm` | authoritative-local guest-root profile; local scope only | no | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| `insecure-container` | explicitly insecure functional development | no | [Authority: CI schedule](../ci-schedule.md#ci-and-conformance-schedule) |
| `macos-vm-dev` | convenience only; no authoritative default-deny claim | no | [Authority: IMPLEMENTATION §10.2](../../../IMPLEMENTATION.md#102-macos-vm-convenience-driver) |
| `aws-eks-kata` through NIC | source capability present in accepted NIC v2; provider/template contents, EKS image, and S4-11 remain unresolved | no | [Authority: provisional matrix platform profiles](../stage-5-api-key-release-acceptance-matrix.md#platform-profiles) |
| standalone Stage 2 EC2 | historical bounded feasibility; not EKS/CNI/install/current-resource evidence | no | [Authority: IMPLEMENTATION Stage 2 boundary](../../../IMPLEMENTATION.md#stage-2-short-lived-aws-nested-virtualization-feasibility) |
| generic Kubernetes or local k3s/Kata | design target without exact accepted profile | no | [Authority: DESIGN other environments](../../../DESIGN.md#63-other-environments) |
| Hetzner Cloud/full VM or dedicated/k3s | deferred and unvalidated | no | [Authority: DESIGN typical Hetzner Cloud](../../../DESIGN.md#62-typical-hetzner-cloud) |
| GCP or Azure | unsupported and unadvertised | no | [Authority: provisional unsupported capabilities](../stage-5-api-key-release-acceptance-matrix.md#unsupported-capabilities-and-claims) |
| software-emulated QEMU/TCG | development compatibility only; forbidden runtime fallback | no | [Authority: DESIGN other environments](../../../DESIGN.md#63-other-environments) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Accepted `linux-kvm` evidence demonstrates a distinct KVM guest and host-controlled network boundary only for that run/profile. | [Authority: Stage 3 exit evidence](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#automatic-acceptance) |
| `insecure-container` remains functional-only even when protocol tests pass. | [Authority: CI schedule](../ci-schedule.md#ci-and-conformance-schedule) |
| macOS development VMs and TCG inherit no Linux/KVM authority. | [Authority: IMPLEMENTATION cross-stage matrix](../../../IMPLEMENTATION.md#46-cross-stage-test-matrix) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Bind immutable source/images/runtime/kernel/architecture/region/platform. | [Planned DESIGN-24.3–.5 / `future-local-test-reference-v1`, `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe guest-root isolation, external networking, identity, secrets, storage, lifecycle, and cleanup with real dependencies. | [Planned DESIGN-24.4–.12, .19–.20 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Demonstrate failures, upgrades, privacy/deletion, capacity, cost, and independent inventory. | [Planned STAGE5-45.05–.12 / `future-load-reference-v1`, `future-privacy-deletion-reference-v1`, `future-operations-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Limit any future support decision to measured profiles/concurrency. | [Planned STAGE5-45.06, .13 / `future-release-decision-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| No row currently has those bindings; every advertisement remains false. | [Authority: provisional matrix platform profiles](../stage-5-api-key-release-acceptance-matrix.md#platform-profiles) |

## Matrix update rule

**Section authority:** [Authority: matrix finalization rule](../stage-5-api-key-release-acceptance-matrix.md#finalization-rule-for-a-future-authority).

Change a row only through reviewed evidence bound to its exact profile. Never promote a profile from architectural similarity, provider documentation, source capability, static rendering, a different provider, a different node image, or a development fallback. Unknown means blocked, not provisionally supported.
