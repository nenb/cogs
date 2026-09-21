# ADR 0352: Freeze fresh H and authorize G control

- Status: Accepted
- Date: 2026-09-21
- Decider: Nick Byrne
- Scope: exact fresh H and producer, direct-child G, one publisher, and one static observation; no AWS

## Context

ADR 0351 authorized a bounded host-boundary correction followed by a fresh
H/G/Q chain. PR 565 merged the reviewed correction as protected squash result
**H** `5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c`, whose sole parent is
`ede3c228eea1efb4cd3a435b969f59aeb7f71c10` and whose tree is
`b8734d91e693a01a29d49a9a4d5f9eb3843ad374`. Reviewed PR head
`90d8dbb3d72f7b9d65c0a0a3835fe1345340375f` has the identical tree.
PR exact-head CI `35556912716` and Linux foundations `35556912695` passed;
exact-H protected-main CI `35559912972` and Linux foundations `35559912952`
also passed.

Producer run `35562735335`, attempt 1, is the sole first-created producer at H.
Its admit, build, and readback jobs passed. Artifact `10622494382`, named
`stage2-prebuilt-rootfs-5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c`, is
unexpired through 2026-09-28 and has Actions archive digest
`sha256:4fabbd57798aec3d5d72ebf5be578f7706c25852f9b115fd16ab0b8093fab535`.
Independent readback accepted the exact producer members and bindings:

- source manifest `6bfa809d592d1c98b0e36605791b21ff454d3b1f45b512d9145fc3de6ec75b2f`;
- producer workflow `4f2dd520994cc93ab4705f5e7225a6078c35616f122ecd69caac84dfe97119af`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `071fb3fdd8db342042ab6b357efef150782b8b2c91025b8ae653585ee4825025`;
- package `501753b0f803fe7b6583ba59cd099a42d2fb6652df60ee5b4592981b3d89706e`;
- provenance `1583f6a4612ed3f8d77416f474ae5cfddc739694fdd3af90c12f049bca3a9f52`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- marker `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- 4,353 entries and two byte-identical builds.

No producer KVM, AWS, provider, OpenTofu, SSM, remote publication, deployment,
or campaign operation occurred.

## Decision

Freeze exact H `5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c`, producer run
`35562735335`, artifact `10622494382`, and archive digest
`sha256:4fabbd57798aec3d5d72ebf5be578f7706c25852f9b115fd16ab0b8093fab535`.

Establish the protected-main squash result containing only this decision and
index, the accounting enforcement and exact assertions, and deterministic
non-authorizing Stage 4 readiness refresh as control revision **G** only if it
is one commit whose sole parent is exact H, its tree equals the reviewed
candidate tree, and every required protected check passes. H remains the
executable implementation and producer identity. G changes no H-owned
executable or runtime behavior, campaign, production, provider, workflow,
static package, or qualification constant.

After G is established and independently checked, authorize exactly one
first-created attempt-one trusted publisher at G using only the frozen H,
producer run, artifact ID, name, and archive digest above. Only after
independent audit accepts the publisher's complete exact artifact custody,
readback, signature, and cleanup may exactly one first-created attempt-one
no-KVM static observation run at G. Its exact artifact and cleanup must be
independently audited before Q is created. No publisher or static dispatch is
performed by this decision commit.

Anticipate only the literal
`docs/adr/0353-establish-fresh-Q-and-authorize-qualification.md` path in the
final-HGQ allowlist; do not create ADR 0353 now. Q must be G's sole direct child
and requires a separate decision based on the independently read-back static
members. It must not alter H-owned executable authority.

Correct enforcement of ADR 0351's existing allocation without reallocating it:
freeze the exact-H pre-H final-HGQ consumption under the immutable 607-line and
1,700,000-byte cap; admit after H at most the separate 900-line and
3,500,000-byte reserve; and continue to enforce the combined final-HGQ maximum
of 1,507 lines and 5,200,000 bytes. Exact H consumes 576 lines and 241,849 bytes
of the pre-H slice. The five-task tranche remains exactly 22,157 lines and
21,500,000 bytes, with every task allocation otherwise unchanged and no
deletion credit. Adding this ADR raises only the tracked-file source limit from
1,558 to 1,559; source byte limits and aggregate allocations do not change.

## Consequences

A failed, cancelled, retried, malformed, expired, mismatched, or
cleanup-uncertain publisher or static observation retires this generation and
grants no downstream authority. There is no fallback or same-generation
replacement.

This decision grants no mixed preflight, qualification, AWS, credentials,
provider initialization, OpenTofu, SSM, inventory, deployment, campaign,
production, release, or Issue 42 closure authority. After successful static
observation and independent audit, stop for the separate Q decision.
