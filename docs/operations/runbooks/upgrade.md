# Draft runtime and proxy upgrade runbook

This is a review and evidence plan. It does not change a runtime, node, cluster, provider, or deployment. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future process may produce immutable worker/sandbox/proxy/runtime/node-image artifacts with digests, signatures, and SBOMs. | [Authority: IMPLEMENTATION candidate controls](../../../IMPLEMENTATION.md#38-release-candidate-controls) |
| A future platform may drain at settled boundaries and replace bounded resources without replaying unknown outcomes. | [Authority: DESIGN resource lifecycle](../../../DESIGN.md#18-resource-lifecycle-and-scale) |
| Rollback safety is untested for the future EKS topology. | [Authority: IMPLEMENTATION recovery campaign](../../../IMPLEMENTATION.md#354-recovery-campaign) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Baseline pins include Node.js `22.22.2`, Pi `0.80.6`, Envoy `1.38.3` digest, Kata `3.32.0` digest, containerd `2.2.1`, Kata-bundled QEMU `11.0.1`, and OpenBao `2.6.1` fixture digest. | [Authority: offline readiness exact bounded closure](../stage-4-offline-readiness.md#exact-bound-inputs-and-source-closure) and [model-auth fixture](../stage-3-model-auth.md) |
| Selected containerd and Kata-bundled QEMU candidate binaries have authenticated identities; they remain unobserved in a release runtime, and Envoy lacks publisher-signature closure. | [Authority: offline readiness authenticated runtime candidate](../stage-4-offline-readiness.md#authenticated-runtime-candidate-frozen-static-pins-and-remaining-blockers) |
| Integration/mount change requires replacement; secret version change denies, drains, and requests replacement. | [Authority: DESIGN MVP proxy construction](../../../DESIGN.md#112-mvp-proxy-construction) |
| Upgrade cannot introduce TCG, `runc`, local-tool, open-egress, audit, identity, secret-source, or container fallback. | [Authority: IMPLEMENTATION required ADR points](../../../IMPLEMENTATION.md#47-required-adr-decision-points) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Linux/KVM tests cover the pinned local Stage 3 composition only within report applicability. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Local OpenBao/Envoy fixtures establish no cluster rollout, node drain, CSI attach, or EKS rollback behavior. | [Authority: IMPLEMENTATION cross-stage matrix](../../../IMPLEMENTATION.md#46-cross-stage-test-matrix) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Bind immutable source/lock/image/SBOM/signature and vulnerability disposition. | [Planned STAGE5-45.02–.03 / `future-independent-review-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Demonstrate compatibility across worker, Pi, SSH, Envoy, OpenBao, Kata, QEMU, containerd, kernel, CNI, CSI, and NIC. | [Planned DESIGN-24.1–.20 / `future-local-test-reference-v1`, `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove no-drift placement/runtime/network/identity and no fallback. | [Planned DESIGN-24.4–.12 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe canary startup, settled drain, revocation, state continuity, failure, and exact rollback. | [Planned STAGE5-45.07 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Rerun conformance, privacy, capacity, cost, destroy, and independent inventory. | [Planned STAGE5-45.05, .08–.11 / `future-load-reference-v1`, `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Matrix remains unexecuted; local version change cannot satisfy it. | [Authority: matrix non-authority](../stage-5-api-key-release-acceptance-matrix.md#purpose-and-non-authority) |

## Static preparation sequence

1. **Open a bounded change record.** Name the component, old/new immutable identities, reason, CVEs, dependencies, owner, rollback candidate, and evidence profiles. Do not include secrets or provider targets.
2. **Freeze one candidate.** Update exact source/package/image/runtime pins and regenerate affected static contracts. Floating tags, latest/default launch templates, and inferred node images are forbidden.
3. **Review trust-boundary changes.** Stop for an ADR if proxy, Kata, SSH, secret config, default deny, trusted mounts, central logging, OAuth refresh ownership, controllers, databases, or VM fallback changes.
4. **Run local checks.** Execute the safe local procedure only through the [installation guide](installation.md); do not duplicate or expand commands here.
5. **Rerun applicable Linux/KVM evidence.** Preserve the exact applicability. A local pass does not authorize cloud rollout.
6. **Prepare future canary and rollback evidence plans.** Define settled-turn drain, no prompt replay, old/new identity separation, storage fencing, revocation, and independent teardown before requesting any campaign.
7. **Stop on mismatch.** Preserve diagnostics and the old pin. Do not repair the candidate in place or continue from partial evidence.

## Future rollout and rollback contract

A separately authorized future operator would admit no new sessions to the changing cohort, drain only at settled boundaries, replace immutable resources, and verify readiness before any bounded expansion. Unknown model-call outcomes are reported and never replayed. Rollback is another immutable replacement to the previously qualified candidate, not a downgrade in place. Failure or ownership uncertainty invokes [incident response](incident-response.md) and [teardown](teardown.md), with no broad deletion.
