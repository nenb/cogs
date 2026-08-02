# Draft installation guide

This guide stops at local/static preparation. It does not install into a cluster and contains no provider operation or deployment target. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future platform team supplies daemon, identity, scheduling, cluster-scoped Kata, CNI, CSI, OpenBao, and OTLP dependencies; Cogs does not supply them. | [Authority: DESIGN §5.1 logical session resources](../../../DESIGN.md#51-logical-session-resources) and [IMPLEMENTATION §33 pack boundary](../../../IMPLEMENTATION.md#33-helm-software-pack) |
| Synthetic data remains the only proposed installation data until a separate handling decision exists. | [Authority: IMPLEMENTATION §38 candidate controls](../../../IMPLEMENTATION.md#38-release-candidate-controls) |
| Accounts, principals, regions, prices, quotas, images, node images, and campaign approval are absent. | [Authority: Stage 4 offline readiness current blockers](../stage-4-offline-readiness.md#honest-image-nic-and-runtime-blockers) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Chart `0.0.1` is a NOTES-only zero-manifest scaffold; enabled notes are not an installer. | [Authority: offline readiness exact bounded closure](../stage-4-offline-readiness.md#exact-bound-inputs-and-source-closure) |
| Worker/sandbox image references are synthetic `.invalid` values; no image set or executable provider route exists. | [Authority: offline readiness exact bounded closure](../stage-4-offline-readiness.md#exact-bound-inputs-and-source-closure) |
| Sandbox runtime is exactly `kata-qemu-cogs`, KVM-only, without `runc` or TCG fallback; scheduling domains are disjoint. | [Authority: NIC exact node-group contract](../stage-4-nic-node-group-contract.md#exact-node-group-contract) |
| Workspace and trusted session state are distinct retained roles. | [Authority: storage/launch separate durable roles](../stage-4-storage-launch-contract.md#separate-durable-storage-roles) |
| NIC source capability and EKS image/kernel pins remain blocked. | [Authority: NIC current blockers](../stage-4-nic-node-group-contract.md#authenticated-public-source-pin-and-current-blockers) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Node.js `22.22.2` is the checked local baseline. | [Authority: README local checks](../../../README.md#local-checks) |
| Accepted Linux/KVM evidence is authoritative only for its exact local guest-root profile. | [Authority: Stage 3 Linux/KVM exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Insecure container is functional-only; macOS VM has no authoritative host-network/default-deny claim. | [Authority: CI profile schedule](../ci-schedule.md#ci-and-conformance-schedule) |
| No local fact proves cluster installation behavior. | [Authority: IMPLEMENTATION cross-stage matrix](../../../IMPLEMENTATION.md#46-cross-stage-test-matrix) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Bind exact source/images, node image/kernel, Kata/QEMU/containerd identity, and active KVM acceleration. | [Planned DESIGN-24.3–.5 / `future-local-test-reference-v1` and `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe RuntimeClass, dual-stack CNI default deny, CSI modes, OpenBao workload identity, OTLP, audit WAL, and scheduler separation with real dependencies. | [Planned DESIGN-24.4–.12 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Demonstrate repeatable install, readiness, failures, destroy, and independent inventory. | [Planned STAGE5-45.07, .10, .11 / `future-eks-conformance-reference-v1`, `future-operations-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind S4-11 and every applicable Stage 5 item to one exact candidate. | [Planned STAGE5-45.01 / `future-acceptance-index-reference-v1` finalization rule](../stage-5-api-key-release-acceptance-matrix.md#finalization-rule-for-a-future-authority) |
| This table authorizes no campaign. | [Authority: offline package required identities and one-attempt authority](../stage-4-offline-readiness.md#stopdestroy-and-identities) |

## Local/static preparation procedure

1. Confirm a clean checkout and Node.js `22.22.2` without introducing credentials or user data.
2. Read [prerequisites](prerequisites.md), [NIC configuration](nic-configuration.md), and the [platform matrix](platform-matrix.md). Stop on every unresolved item; do not substitute a component.
3. Perform dependency installation and repository checks only:

   ```bash
   npm ci --ignore-scripts
   npm run check
   ```

4. Inspect the non-deploying chart source locally only:

   ```bash
   helm lint deploy/helm/cogs
   helm template cogs deploy/helm/cogs
   ```

   The render submits nothing. Do not reinterpret rendered notes as deployable manifests.
5. Confirm the machine [runbook index](index.json) and all linked static contracts agree. A passing check closes only documentation/static consistency.
6. Record unresolved prerequisites and stop. Do not initialize a provider, contact a cluster, call an external model, or create a resource.

## Future installation hold points

**Section authority:** [Planned STAGE5-45.10 / `future-operations-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability).

A future authority must stop before each of these transitions: campaign request, cluster-scoped runtime change, identity/secret binding, first sandbox admission, first credentialed egress, and first persistent-data use. Each transition needs exact evidence, a named accountable principal, and a separately scoped approval. Missing or stale evidence leaves readiness false.
