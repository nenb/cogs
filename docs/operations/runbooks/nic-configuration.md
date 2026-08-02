# Draft NIC configuration guide

This guide describes the required semantic shape. It is not NIC syntax, a provider plan, or a deployment procedure. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future reviewed NIC revision may expose a custom launch-template ID, an explicit launch-template version, and nested-virtualization CPU options through its pinned module boundary.
- A future EKS-compatible node image may supply the required kernel and KVM modules.
- Those possibilities have not been established.

## Static contract facts

The authenticated public-source pin recorded by the [NIC source contract](../stage-4-nic-node-group-contract.md) is NIC `v0.11.0`, commit `28221c652c56bb8d48a92538c01503a82f2f9321`, with module `nebari-dev/eks-cluster/aws` `0.7.0`, commit `5d4cb31f07fda5c010b5be580258d32f6db75828`.

That exact source **cannot** carry the required custom launch-template ID/version or `CpuOptions.NestedVirtualization`. Its classifier has no ready state and returns `blocked-missing-capability`. Pinning an AMI alone cannot resolve this blocker.

### Proposed bounded node-group shape

| Field | Required static value |
|---|---|
| Region / capacity | `us-east-1` / `ON_DEMAND` |
| Group | `cogs-stage4-sandbox-kata` |
| Instance | `c8i-flex.large`, `x86_64`, CPU-only, non-metal |
| Scale | minimum `0`, maximum `1`; no invented desired-size field |
| Launch template | external custom ID plus explicit positive-integer version; no latest/default |
| CPU options | nested virtualization enabled, one core, two threads per core |
| Runtime | `kata-qemu-cogs`; `io.containerd.kata.v2`; KVM only |
| Fallback | no Spot, metal, TCG, or `runc` |

Sandbox labels are exactly `cogs.dev/node-domain=sandbox-kata`, `cogs.dev/nested-virtualization=enabled`, and `cogs.dev/sandbox-runtime=kata-qemu-kvm`, with taint `cogs.dev/sandbox=kata:NO_SCHEDULE`. Trusted resources select only `cogs.dev/node-domain=trusted` and carry no sandbox toleration.

## Authoritative-local facts

- Local Linux/KVM evidence supports KVM-backed guest-root testing only. It does not prove NIC mapping, a managed node group, EKS scheduling, an EKS node image, or CNI behavior.
- The exact Kata archive was accepted from Stage 2 evidence, but containerd/QEMU version strings are not binary identity and the standalone Ubuntu AMI is not an EKS image pin.

## Future cloud evidence

A future NIC path requires this order:

1. Review and pin a new immutable NIC/module source closure; never mutate the `v0.11.0` assessment to supported.
2. Establish locally that the new adapter preserves launch-template ID and explicit version, CPU options, labels, taint, scale, capacity, instance, and node-image inputs without dropping or rewriting them.
3. Rebuild static package digests and request a separate one-attempt campaign approval only after #42 and every blocker are resolved.
4. In the approved campaign, compare approved, rendered, and observed launch-template ID/version and nested-virtualization CPU options.
5. Observe exact node image/kernel/KVM state, scheduler domain separation, RuntimeClass behavior, and absence of fallback.
6. Bind teardown and independent inventory evidence to that same attempt.

Each item remains future evidence under the [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md).

## Configuration drift response

Any source, module, image, region, instance, scale, label, taint, launch-template, runtime, or fallback difference is drift. Stop, preserve the exact input and diagnostics without credentials, regenerate the static closure, and obtain review. Do not reconcile in place, silently default a field, or widen capacity.
