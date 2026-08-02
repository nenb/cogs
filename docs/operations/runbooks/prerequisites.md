# Draft prerequisites guide

This is a requirements checklist, not a discovery script or installation authorization. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future environment may provide dedicated trusted/KVM nodes, external network enforcement, CSI block storage, OpenBao, and OTLP. | [Authority: DESIGN §19 pack responsibilities](../../../DESIGN.md#191-pack-responsibilities) |
| Required campaign and review roles may later be bound to distinct authenticated principals. | [Authority: ownership separation requirements](../ownership.md#initial-ownership-and-approval-register) |
| Current price, quota, capacity, account suitability, and service availability are unknown and blocking. | [Authority: offline readiness proposal-only envelope](../stage-4-offline-readiness.md#closed-proposal-only-resource-graph) |

## Static contract facts

| Static prerequisite | Specific authority |
|---|---|
| Issue #42 blocks cloud entry; closure alone grants no campaign authority. | [Authority: offline readiness current blockers](../stage-4-offline-readiness.md#honest-image-nic-and-runtime-blockers) |
| Campaigns are one-attempt, exact-revision, bounded, destroyed, and independently inventoried. | [Authority: offline readiness one-attempt authority](../stage-4-offline-readiness.md#stopdestroy-and-identities) |
| Account, principals, envelope, attempt, approval, and executable provider route are absent. | [Authority: offline readiness pure classifier boundary](../stage-4-offline-readiness.md#pure-classifier-boundary) |
| Runtime pins are Kata `3.32.0` at the fixed archive digest, containerd `2.2.1`, QEMU `8.2.2`, `io.containerd.kata.v2`, and KVM only. | [Authority: NIC exact node-group contract](../stage-4-nic-node-group-contract.md#exact-node-group-contract) |
| RuntimeClass is exactly `kata-qemu-cogs`; `runc` and TCG are forbidden; trusted/sandbox placement is disjoint. | [Authority: NIC disjoint scheduling](../stage-4-nic-node-group-contract.md#disjoint-scheduling) |
| Sandbox receives no service-account token, cloud/OpenBao identity, real credential, or CA private key. | [Authority: DESIGN mandatory invariants](../../../DESIGN.md#44-mandatory-invariants) |
| Egress is explicit HTTP/HTTPS proxy only, externally default-denied, dual-stack covered or IPv6 disabled, and UDP blocked. | [Authority: DESIGN secret-injected egress placement](../../../DESIGN.md#111-placement) |
| Credential authorization/WAL append fails closed; ordinary OTLP failure does not stop uncredentialed work. | [Authority: DESIGN audit fail-closed behavior](../../../DESIGN.md#114-audit-fail-closed-behavior) |
| Subscription OAuth is disabled/unadvertised; issue #13 is future post-MVP only; API keys are the planned Stage 4/5 class. | [Authority: provisional matrix OAuth blocker](../stage-5-api-key-release-acceptance-matrix.md#subscription-oauth-blocker) |
| Workspace is distinct retained 20 GiB sandbox-only storage; trusted Pi state is distinct retained 5 GiB trusted-only storage with 30-day default. | [Authority: storage/launch separate durable roles](../stage-4-storage-launch-contract.md#separate-durable-storage-roles) |
| One fenced writer is required; expiry or uncertainty grants no takeover. | [Authority: storage/launch exclusive writer lease](../stage-4-storage-launch-contract.md#exclusive-writer-lease) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Linux/KVM is the sole authoritative-local profile, only for accepted local guest-root evidence. | [Authority: CI and conformance schedule](../ci-schedule.md#ci-and-conformance-schedule) |
| Stage 3 local evidence covers worker boundary, SSH/SFTP, API-key path, proxy controls, metadata-only telemetry, state/Git/export, and cleanup only within report applicability. | [Authority: Stage 3 exit criteria coverage](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#criterion-mapping) |
| Local OpenBao smoke is functional-only and proves no Kubernetes auth, multi-tenant policy, or cluster revocation behavior. | [Authority: Stage 3 model-auth local smoke](../stage-3-model-auth.md) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Capable NIC revision preserves exact launch-template ID/version and nested virtualization. | [Planned DESIGN-24.4 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind immutable EKS node image/release/kernel and active KVM modules/device. | [Planned DESIGN-24.4 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe exact RuntimeClass, no trusted sandbox sidecar, and no runtime fallback. | [Planned DESIGN-24.4–.5 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove real CNI denial for IPv4/IPv6, UDP/QUIC, metadata, API/admin, cross-session, and direct bypass. | [Planned DESIGN-24.5, .12 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe CSI attach/detach/reattach, retention/deletion, fencing, and forced loss. | [Planned DESIGN-24.19–.20 and STAGE5-45.09 / `future-privacy-deletion-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe scoped OpenBao identity/PKI/retrieval/revocation, audit WAL, and metadata-only OTLP. | [Planned DESIGN-24.4–.14 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind startup, capacity, failure, privacy/deletion, cost, and independent zero inventory. | [Planned DESIGN-24.20–.22 and STAGE5-45.05–.11 / `future-load-reference-v1`, `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |

## Admission decision

**Section authority:** [Authority: offline readiness pure classifier boundary](../stage-4-offline-readiness.md#pure-classifier-boundary).

A prerequisite is `present` only when its designated future authority binds a truthful observation to the exact candidate and principal. `Unknown`, stale, inferred, static-only, functional-only, or mismatched observations are `blocking`. Do not downgrade them to warnings or compensate with broader privileges, fallback runtimes, shared storage, or open networking.
