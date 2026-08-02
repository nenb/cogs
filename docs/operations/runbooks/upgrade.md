# Draft runtime and proxy upgrade runbook

This is a review and evidence plan. It does not change a runtime, node, cluster, provider, or deployment. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future release process will produce immutable worker, sandbox, proxy, runtime, and node-image artifacts with signatures/digests and SBOMs.
- A future platform will support draining at settled turn boundaries and bounded replacement without replaying an unknown prompt outcome.
- Rollback safety is untested for the future EKS topology.

## Static contract facts

- Current repository baseline includes Node.js `22.22.2`, Pi packages `0.80.6`, Envoy `1.38.3` at the pinned image digest, Kata `3.32.0` at its fixed archive digest, containerd `2.2.1`, QEMU `8.2.2`, and OpenBao `2.6.1` at its pinned fixture image digest.
- The Envoy pin is a static input, not a runtime observation. Containerd and QEMU have version requirements but no bound binary digest in the offline package.
- Session integration and mount changes require resource replacement. Secret or credential-version change denies new requests, drains connections, and requests replacement.
- No upgrade may introduce TCG, `runc`, local-tool, open-egress, audit, identity, secret-source, or container fallback.

## Authoritative-local facts

- Current Linux/KVM tests cover the pinned local Stage 3 composition within their report applicability.
- The local fixture can exercise OpenBao retrieval/revocation and Envoy behavior, but does not establish cluster rollout, node drain, CSI attach, or EKS rollback.

## Future cloud evidence

Every component upgrade needs candidate-specific evidence for:

- immutable source, lock, image, SBOM, signature, and vulnerability disposition;
- compatibility across worker, Pi, SSH, Envoy, OpenBao, Kata, QEMU, containerd, kernel, CNI, CSI, and NIC closure;
- no-drift scheduling/runtime/network/identity policies and no fallback;
- canary startup, settled-turn drain, connection revocation, persistent-state continuity, failure behavior, and exact rollback;
- post-change conformance, privacy inspection, capacity, cost, destroy, and independent inventory.

The [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md) remains unexecuted and cannot be satisfied by a local version bump.

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
