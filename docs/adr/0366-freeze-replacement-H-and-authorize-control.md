# ADR 0366: Freeze replacement H and authorize control

- Status: Accepted
- Date: 2026-09-24
- Decider: Nick Byrne
- Scope: exact replacement H and producer, direct-child G, one publisher, and one static observation; no AWS

## Context

ADR 0365 retired H `56fdd694c1a0c6967bf09156d44260f18a28888d`, its prematurely dispatched producer, and that producer artifact. PR 584 then passed corrected protected CI `35978959012` and all Linux-foundations shards plus aggregate `35978958994` against reviewed head `5a3bd7175e300e224f5f5ea04e5c81c172e72d97`. It merged as protected squash result **H** `ba085947eaee321dfb724d94169d42bc36d397b0`, whose sole parent is terminal H `56fdd694c1a0c6967bf09156d44260f18a28888d`, whose tree is `6e45fdf3d6e7f944d3aba4b82501cc1ac1739a5a`, and whose reviewed head has the identical tree.

Exact-H protected-main CI `35984488769` completed successfully at 2026-09-24T10:14:45Z. All Linux-foundations shards and aggregate in `35984488928` completed successfully at 10:46:30Z. Only afterwards, at 11:01:17Z, producer run `35990583990`, attempt 1, was created. It is the sole first-created producer at H; admission, build, and readback passed without retry.

Artifact `10804234912`, named `stage2-prebuilt-rootfs-ba085947eaee321dfb724d94169d42bc36d397b0`, is unexpired through 2026-10-01T11:24:47Z, is 137,959,274 bytes, and has Actions archive digest `sha256:384d3e5ff819fa706bd6e793e29d2b7ab71b33f339ccec89c57248db7bf2b88c`. Independent authenticated control-plane, archive, source, exact-member, and raw-ustar readback accepted:

- source manifest `cf15e437888f7c1c2808e113576d3592bef40e39c9a88db199f0ca6a38986bb9`;
- producer workflow `8cad69e403224889675af97ad16f29da5177c3a8fd61536f54adb2c11f3e5304`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `bbbe53d39130d52bfa447ce64f954e0ddc63f4279d192829d1a6bb1558cd26af`;
- package `169d6979f85d6ee6c08c0ff5b4b7364fcb319eccb92a39f5227c1c085d2fc0ad`;
- provenance `2c4d26c7a9ead7f87ce712cbbf30a36f8136d9378771e5fb535e14dec65a5538`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- marker `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- all 4,353 entries and two byte-identical builds.

The independent audit record has SHA-256 `5846774fe44831789a00925f8cd87abe46b647798dddf0fb734240bf7f2c2e1b`. No producer KVM, AWS, provider, OpenTofu, SSM, remote publication, deployment, or campaign operation occurred.

## Decision

Freeze exact H `ba085947eaee321dfb724d94169d42bc36d397b0`, producer run `35990583990`, artifact `10804234912`, and archive digest `sha256:384d3e5ff819fa706bd6e793e29d2b7ab71b33f339ccec89c57248db7bf2b88c`.

Establish the protected-main squash result containing only this decision, its index, the exact pending-regeneration accounting transition, and deterministic non-authorizing Stage 4 readiness refresh as control revision **G** only if it is one commit whose sole parent is exact H, its tree equals the reviewed candidate tree, and every required protected pull-request and exact-G protected-main check passes. H remains the executable implementation and producer identity. G changes no H-owned executable or runtime behavior, workflow, Dockerfile, ordinary test, qualification constant, static package, retirement policy, campaign, provider, or production behavior.

After G is established and independently checked, authorize exactly one first-created attempt-one trusted publisher at G using only frozen H, producer run `35990583990`, artifact `10804234912`, artifact name, and archive digest above. Only after independent audit accepts the publisher's exact custody, readback, signature, and cleanup may exactly one first-created attempt-one no-KVM static observation run at G. It must authenticate its assigned official runner image before source effects, execute H's exact-current-workflow boundary, preserve the accepted thirteen-member package byte-for-byte, and publish exact cleanup evidence. Its artifact and cleanup must be independently audited before Q is created. No publisher or static dispatch is performed by this decision commit.

The final-HGQ matrix already anticipates only `docs/adr/0367-establish-replacement-Q-and-authorize-qualification.md`; do not create ADR 0367 now. Q must be G's sole direct child and requires a separate decision based on independently accepted publisher and static members. It must bind exact H, G, static run, artifact ID, artifact archive digest, static-control digest, source manifest, and reviewed source/workflow hashes. It must not alter H-owned executable authority.

Consume one of ADR 0365's two reserved deterministic readiness generations by reducing `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS` from 2 to 1. The regeneration adds exactly the reserved three governance lines, one product line, three readiness-ci lines, one complete serialized source inventory, and this already-budgeted final-HGQ decision. No task or global ceiling, source limit, tracked-file limit, tranche, forecast, or post-H cap changes, and deletion earns no credit.

## Consequences

A failed, cancelled, retried, malformed, expired, mismatched, image-rejected, or cleanup-uncertain publisher or static observation retires this generation and grants no downstream authority. There is no fallback, stitching, or same-generation replacement.

This decision grants no mixed preflight, qualification, IAM, AWS credentials, planning, approval, provider initialization, OpenTofu, SSM, inventory, deployment, campaign, production evidence, release, Stage 4 execution, or Issue 42 closure authority. After successful static observation and independent audit, stop for ADR 0367.
