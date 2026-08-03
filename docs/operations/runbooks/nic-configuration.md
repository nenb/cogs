# Draft NIC configuration guide

This guide describes the required semantic shape. It is not NIC syntax, a provider plan, or a deployment procedure. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| Accepted NIC v2 can preserve external launch-template ID/version with operator attestation only. | [Authority: NIC capability](../stage-4-nic-node-group-contract.md#capability-resolved-by-v2) |
| A future EKS-compatible node image may supply the required kernel and KVM modules. | [Authority: NIC non-observation boundary](../stage-4-nic-node-group-contract.md#non-observation-boundary) |
| Launch-template contents, provider truth, and node/runtime state are not established. | [Authority: NIC non-observation boundary](../stage-4-nic-node-group-contract.md#non-observation-boundary) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Historical v1 preserves NIC `v0.11.0` / module `0.7.0` as blocked. Active v2 pins NIC `53b1a791…` and module `c3017c0e…`. | [Authority: accepted closure](../stage-4-nic-node-group-contract.md#accepted-personal-fork-closure) |
| V2 source capability is present but non-observing; an AMI pin or attestation cannot establish launch-template/provider truth. | [Authority: NIC non-observation boundary](../stage-4-nic-node-group-contract.md#non-observation-boundary) |
| Proposed bound is `us-east-1`, On-Demand `c8i-flex.large`, `x86_64`, non-metal, one named group, scale 0..1. | [Authority: NIC exact node-group contract](../stage-4-nic-node-group-contract.md#exact-node-group-contract) |
| Launch template requires external ID and explicit positive version with no latest/default; CPU options require nested virtualization, one core, two threads. | [Authority: NIC launch-template preservation](../stage-4-nic-node-group-contract.md#capability-resolved-by-v2) |
| Runtime is `kata-qemu-cogs`, `io.containerd.kata.v2`, KVM-only, with no Spot, metal, TCG, or `runc`. | [Authority: NIC exact node-group contract](../stage-4-nic-node-group-contract.md#exact-node-group-contract) |
| Sandbox labels/taint and trusted selector/no-toleration are exact and disjoint. | [Authority: NIC disjoint scheduling](../stage-4-nic-node-group-contract.md#exact-node-group-contract) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Linux/KVM evidence supports KVM-backed guest-root testing only, not NIC mapping, managed groups, EKS scheduling/image, or CNI behavior. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Selected containerd `2.2.1` and Kata-bundled QEMU `11.0.1` candidate binaries are authenticated but not runtime-observed; standalone Ubuntu/QEMU `8.2.2` is historical and is not an EKS pin. | [Authority: NIC exact node-group contract](../stage-4-nic-node-group-contract.md#exact-node-group-contract) |

## Future cloud evidence

| Ordered future requirement | Planned criterion, evidence contract, and location |
|---|---|
| Revalidate the immutable v2 closure without rewriting the historical `v0.11.0` assessment. | [Planned DESIGN-24.4 and STAGE5-45.03 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove locally that the adapter preserves launch-template, CPU, placement, capacity, instance, and image inputs. | [Planned DESIGN-24.2–.4 / `future-local-test-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Rebuild digests and seek one-attempt approval only after #42 and all blockers resolve. | [Planned DESIGN-24.04 / `future-eks-conformance-reference-v1` S4-11 and campaign-approval lane](../stage-5-api-key-release-acceptance-matrix.md#evidence-lanes-remain-separate) |
| Compare approved, rendered, and observed launch-template ID/version and nested CPU options. | [Planned DESIGN-24.4 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe exact image/kernel/KVM, scheduler separation, RuntimeClass, and no fallback. | [Planned DESIGN-24.4–.5 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind teardown and independent inventory to that attempt. | [Planned STAGE5-45.11 / `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |

## Configuration drift response

**Section authority:** [Authority: NIC security transitions](../stage-4-nic-node-group-contract.md#non-observation-boundary).

Any source, module, image, region, instance, scale, label, taint, launch-template, runtime, or fallback difference is drift. Stop, preserve the exact input and diagnostics without credentials, regenerate the static closure, and obtain review. Do not reconcile in place, silently default a field, or widen capacity.
