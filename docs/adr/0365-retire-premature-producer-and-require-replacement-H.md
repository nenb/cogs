# ADR 0365: Retire premature producer and require replacement H

## Status

Accepted

## Context

ADR 0360 requires a fresh implementation H to complete independent review, protected pull-request checks, and fresh exact-main checks before its sole audited producer runs. ADR 0364 retained that ordering and required a wholly fresh H/G/Q chain after the stale-binding preflight failure.

PR 583 merged reviewed head `390898944767e2f096fe121630ab1a99e02c089a` as protected squash result `56fdd694c1a0c6967bf09156d44260f18a28888d`. That candidate's first PR CI attempt failed only when Ubuntu Snapshot returned HTTP 503; the generic failed-job attempt-two revalidation passed and granted no Stage 2 authority. The merge result's tree is `0f811ce31fdc113c11534e41abecb5ccb9f05d9b` and its sole parent is retired Q `f75d3f09990de4635cc3890efe0f5f6e783312bd`.

Protected-main CI `35957194190` and Linux foundations `35957194239` were both created at 2026-09-24T04:48:13Z. Producer run `35957236430` was created at 2026-09-24T04:48:48Z while both required exact-main runs were still in progress. CI completed at 05:02:10Z and Linux foundations completed at 05:39:30Z. Their later success cannot retroactively authorize the producer. The producer passed at attempt 1 and emitted artifact `10791707159`, but it violated the required ordering and therefore grants no authority.

The non-authorizing artifact is named `stage2-prebuilt-rootfs-56fdd694c1a0c6967bf09156d44260f18a28888d`, is 137,959,274 bytes, and has Actions archive digest `sha256:0898e5585c219d1884bc94547dc6a2fac3996c02da924f38cfd429cf5b6e2961`. Independent local diagnosis found internally consistent producer bytes, including source manifest `0bdc9ac2cbaf2d4fc06eb094cb949c07a9bdda95a75c952408581361e7f22fdd` and canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`, but successful subordinate bytes cannot repair missing predecessor authority. No publisher, static observation, KVM, provider, OpenTofu, SSM, AWS, or production effect followed.

## Decision

Retire implementation revision `56fdd694c1a0c6967bf09156d44260f18a28888d`, producer run `35957236430`, and producer artifact `10791707159`. They are terminal diagnostic history and cannot be retried, resumed, stitched, reinterpreted, republished, or used as a handoff to G.

Add predecessor-bound retirement policy V8. V8 must preserve V1 through V7 byte-for-byte, authenticate exact V7 SHA-256 `d0d74eab6a47062db91a1e0e45aa1fae102614a3f5253253450bb11336c96d1c`, and add only the three ADR 0365 identities above. Every occurrence of the authoritative inline deny list in all twelve Stage 2 workflows must include all three identities. The retirement validator must reject them before any source or external effect.

Establish the protected squash result containing this decision, its indexes, V8 retirement enforcement, future ADR 0366/0367 accounting paths, focused assertions and exact test goldens, and deterministic non-authorizing Stage 4 refresh as the next implementation revision **H** only if it is one commit whose sole parent is terminal `56fdd694c1a0c6967bf09156d44260f18a28888d`, its tree equals the reviewed candidate tree, and every required protected pull-request check passes. The only Stage 2 executable/workflow change is additive fail-closed retirement; the previously reviewed producer, publisher, static-control, preflight, qualification, runtime, campaign, provider, and production behavior is otherwise unchanged.

After that replacement H is protected `main`, wait until every required fresh exact-H main CI and Linux-foundations check has completed successfully. Recheck that no producer dispatch exists for H. Only then may exactly one first-created attempt-one producer run. Its artifact and all control-plane, ZIP, source, member, manifest, raw-ustar, equality, and cleanup bindings require independent acceptance before G is proposed.

ADR 0366 may establish only G as H's sole direct child and then authorize one publisher followed by one static observation. ADR 0367 may establish only Q as G's sole direct child after that complete static handoff is independently accepted. Q must bind H, G, static run, artifact, artifact digest, control digest, source manifest, and reviewed source/workflow hashes. Neither later ADR exists or has authority now.

Accounting remains gross and deletion-blind. This unexpected replacement H consumes another complete source-inventory line, so ADR 0364's remaining readiness bytes would not fit both required future G and Q regenerations. Each deterministic regeneration also adds three readiness-accounted lines: one source inventory and two authenticated anchor lines. Move 250,000 bytes zero-sum from `product` to `readiness-ci`, making their byte ceilings 1,950,000 and 10,250,000, and move four lines zero-sum from `product` to `readiness-ci`, making their line ceilings 5,056 and 282. The other three byte ceilings, other three line ceilings, 24,782-line / 21,500,000-byte tranche, 42,782-line / 29,500,000-byte forecast, post-H reserve, tracked-file limit, and source limits remain unchanged. The checker reserves two additional complete serialized source-inventory generations plus each regeneration's three readiness, three governance, and one product line; ADR 0366 may consume one generation and reduce the pending count to one, and ADR 0367 may consume the other and reduce it to zero.

## Consequences

Any failure, cancellation, retry, malformed evidence, stale input, image rejection, or cleanup uncertainty in the replacement producer or later publisher, static observation, preflight, or qualification is terminal for that generation. Recovery remains cleanup-only.

This decision grants no G, publisher, static observation, Q, mixed preflight, qualification, IAM, AWS credentials, planning, approval, provider initialization, OpenTofu, SSM, inventory, deployment, campaign, production evidence, release, Stage 4 execution, or Issue 42 closure authority. Stop after independent acceptance of the ordered replacement-H producer for ADR 0366.
