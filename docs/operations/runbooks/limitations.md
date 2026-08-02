# Draft known limitations and residual risks

These boundaries must accompany every future evaluation. They are not defects silently waived by a successful test. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| Operators/users understand model-directed code is untrusted and allowlists are not information-flow control. | [Authority: DESIGN narrow credential guarantee](../../../DESIGN.md#41-narrow-credential-guarantee) |
| Configured model provider and platform administrators remain trusted. | [Authority: DESIGN trust domains](../../../DESIGN.md#42-trust-domains) |
| Future daemon/identity/storage/cluster/provider implementations may add unrepresented risk. | [Authority: DESIGN logical session resources](../../../DESIGN.md#51-logical-session-resources) |

## Static contract facts

| Static limitation | Specific authority |
|---|---|
| Agent may misuse granted capability; approved write endpoint may receive source; no DLP. | [Authority: DESIGN narrow credential guarantee](../../../DESIGN.md#41-narrow-credential-guarantee) |
| Model provider receives prompt/selected source by design. | [Authority: DESIGN residual risks](../../../DESIGN.md#26-residual-risks-to-state-publicly) |
| Hypervisor/QEMU/Kata/kernel/proxy/worker/OpenBao/CNI/CSI/platform remain trusted-computing-base risks. | [Authority: DESIGN trust domains](../../../DESIGN.md#42-trust-domains) |
| Compromised trusted worker can access session credentials; proxy-bootstrap separation is deferred. | [Authority: DESIGN residual risks](../../../DESIGN.md#26-residual-risks-to-state-publicly) |
| Guest root may copy short-lived proxy capability; source binding/route policy only limit it. | [Authority: DESIGN residual risks](../../../DESIGN.md#26-residual-risks-to-state-publicly) |
| Pinned/custom trust fails closed; unsupported auth/protocol does not become safe by generic config. | [Authority: DESIGN compatibility classes](../../../DESIGN.md#115-supported-compatibility-classes) |
| Git mapping records untrusted observation, not repository attestation. | [Authority: DESIGN mapping record](../../../DESIGN.md#151-mapping-record) |
| Checkpoints/metadata/wrappers are not complete filesystem/syscall audit. | [Authority: DESIGN execution and filesystem audit](../../../DESIGN.md#163-mvp-execution-and-filesystem-audit) |
| Subscription OAuth/refresh handling, daemon/ingress/sanitizer/apps/indexing/restoration/audit and advanced/non-HTTP egress are deferred or unsupported. | [Authority: provisional unsupported capabilities](../stage-5-api-key-release-acceptance-matrix.md#unsupported-capabilities-and-claims) |
| GCP/Azure/Hetzner/other-cloud/generic Kubernetes/AWS EKS profiles are unadvertised. | [Authority: provisional platform profiles and unsupported capabilities](../stage-5-api-key-release-acceptance-matrix.md#platform-profiles) |
| Prompt replay, outside-observation exact Git mapping, and crash-consistent per-turn object backup are unavailable. | [Authority: DESIGN failure behavior and residual risks](../../../DESIGN.md#21-failure-behavior) |
| Subscription OAuth remains disabled/unadvertised; issue #13 is future post-MVP only. | [Authority: provisional OAuth blocker](../stage-5-api-key-release-acceptance-matrix.md#subscription-oauth-blocker) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Linux/KVM authority is local only and establishes no EKS/CNI/provider/cloud-storage/release/production/GA/compliance/general guarantee. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Insecure container and macOS VM are development profiles without authoritative isolation. | [Authority: CI profile schedule](../ci-schedule.md#ci-and-conformance-schedule) |
| Standalone Stage 2 EC2 evidence establishes neither EKS nor current resources. | [Authority: Stage 2 feasibility report scope](../../test-reports/stage-2-aws-feasibility.md#claim-boundary) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Bind NIC capability, EKS image/kernel/KVM/runtime, scheduling, CNI, CSI, OpenBao/revocation, and OTLP. | [Planned DESIGN-24.4–.12, .19–.22 / `future-eks-conformance-reference-v1`, `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind capacity/cost, upgrade, incident, deletion, teardown, and independent review. | [Planned STAGE5-45.02–.12 / `future-independent-review-reference-v1`, `future-operations-reference-v1`, `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Matrix has no accepted evidence or final decision. | [Authority: matrix purpose and non-authority](../stage-5-api-key-release-acceptance-matrix.md#purpose-and-non-authority) |

## Public wording guardrails

**Section authority:** [Authority: provisional matrix support claims](../stage-5-api-key-release-acceptance-matrix.md#machine-generated-support-and-unsupported-claims).

Do not say or imply that Cogs:

- prevents source exfiltration, prompt injection, confused-deputy actions, or all hypervisor escape;
- supports a provider, platform, model provider, concurrency level, auth class, or protocol without exact accepted evidence;
- has a production daemon, scheduler, ingress, deployment, release, GA status, compliance certification, or general security guarantee;
- deletes all copies, provides anonymous exports, captures every filesystem action, or restores every turn;
- makes revocation instant for existing streams or makes explicit-proxy TLS compatible with every client.

Use bounded statements with profile, exact revision/artifact, evidence link, applicability, date, and residual risk.

## Operator stop conditions

**Section authority:** [Authority: DESIGN mandatory invariants](../../../DESIGN.md#44-mandatory-invariants).

Stop and preserve uncertainty on any request to bypass the VM, use a container fallback, expose cloud/Kubernetes/OpenBao credentials, permit direct/wildcard egress, disable audit, share trusted and sandbox mounts, broaden OpenBao paths, persist refresh tokens, centralize sensitive content, infer ownership, perform broad deletion, or advertise beyond evidence. Such a request requires architecture/security review and may be prohibited outright.
