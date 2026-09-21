# ADR 0355: Freeze timeout-corrected H and authorize control

- Status: Accepted
- Date: 2026-09-21
- Decider: Nick Byrne
- Scope: exact timeout-corrected H and producer, direct-child G, one publisher, and one static observation; no AWS

## Context

ADR 0354 authorized only two test-fixture deadline corrections followed by a
fresh protected H, producer, and separate G/Q chain. PR 569 passed CI
`35615519013` and Linux foundations `35615519048`, then merged as protected
squash result **H** `d98571b9f2be446ed478464d23df532d91b94e53`, whose sole
parent is `6c200c6fcd87616244b38b6676d07c513aeb42fd` and whose tree is
`b022a4c5a3b8c99626c8d3e45d9101368d18f9f1`. Reviewed PR head
`f7c226057e8d849bb3ab0442e772162c8ee4692b` has the identical tree.
Exact-H protected-main CI `35621306535` passed.

Exact-H Linux-foundations run `35621306446` initially failed in a fail-closed
filesystem identity guard. No producer or downstream action followed that
failure. The exact target then passed 500 unforced repetitions on Ubuntu
ARM64 and 500 on native Ubuntu x86_64. Deliberate `/tmp` mutation triggered
different earlier fail-closed guards and was not treated as reproduction.
After that bounded diagnosis was recorded, the one unchanged full-workflow
revalidation, attempt 2 of `35621306446`, passed all 22 matrix shards and the
aggregate job. H's executable/runtime bytes were not changed or retried into a
new candidate.

Producer run `35638724656`, attempt 1, is the sole first-created producer at H.
Its admit, build, and readback jobs passed. Artifact `10658466954`, named
`stage2-prebuilt-rootfs-d98571b9f2be446ed478464d23df532d91b94e53`, is
unexpired through 2026-09-28T18:54:58Z, is 137,959,274 bytes, and has Actions
archive digest
`sha256:b9cc3b2a41b93f683e794f2553aad2d2b8ac5f4a09bcef9718dbf508c7e903fa`.
Independent archive, source, exact-member, and raw-ustar readback accepted:

- source manifest `de3adf761aac2a4b7ff33b6064814fe86c2fccd04bd4c3020ce2e7b469e13a3b`;
- producer workflow `aa09f014eea346f01cc48d87899b63061fc082020825c64a78c561d9c4ff8fa3`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `56bf1eeb430e6dd706df22b796158974635f97ebc5ffe9b0ad50f6721d39ea14`;
- package `7a6a32daba42153741cce6c9c2f11bc273d27a73cf9dfc567fff82a2efcef36c`;
- provenance `c6fae49b00f7a9c3cf32ada2a956802eba8a6c15e4ee5150cb605b7e77819331`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- marker `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- all 4,353 entries and two byte-identical builds.

The independent audit record has digest
`sha256:6f0f88e456b3e92a9a353af32b0c29ed5662e7040f9c72f37993c268f5c0a157`.
No producer KVM, AWS, provider, OpenTofu, SSM, remote publication, deployment,
or campaign operation occurred.

## Decision

Freeze exact H `d98571b9f2be446ed478464d23df532d91b94e53`, producer run
`35638724656`, artifact `10658466954`, and archive digest
`sha256:b9cc3b2a41b93f683e794f2553aad2d2b8ac5f4a09bcef9718dbf508c7e903fa`.

Establish the protected-main squash result containing only this decision and
index, exact accounting assertions, and deterministic non-authorizing Stage 4
readiness refresh as control revision **G** only if it is one commit whose sole
parent is exact H, its tree equals the reviewed candidate tree, and every
required protected pull-request and exact-G protected-main check passes. H
remains the executable implementation and producer identity. G changes no
H-owned executable or runtime behavior, campaign, production, provider,
workflow, Dockerfile, ordinary test, static package, qualification constant,
or retirement policy.

After G is established and independently checked, authorize exactly one
first-created attempt-one trusted publisher at G using only the frozen H,
producer run, artifact ID, name, and archive digest above. Only after
independent audit accepts the publisher's complete exact artifact custody,
readback, signature, and cleanup may exactly one first-created attempt-one
no-KVM static observation run at G. The observation must execute H's corrected
exact-current-workflow boundary. Its exact artifact and cleanup must be
independently audited before Q is created. No publisher or static dispatch is
performed by this decision commit.

The final-HGQ allowlist already anticipates only the literal
`docs/adr/0356-establish-timeout-corrected-Q-and-authorize-qualification.md`;
do not create ADR 0356 now. Q must be G's sole direct child and requires a
separate decision based on the independently read-back static members. It must
not alter H-owned executable authority.

Use ADR 0351's existing allocation without reallocation: the immutable pre-H
slice remains 607 lines and 1,700,000 bytes; the separate post-H reserve remains
900 lines and 3,500,000 bytes; and the combined final-HGQ maximum remains 1,507
lines and 5,200,000 bytes. The five-task tranche remains exactly 22,157 lines
and 21,500,000 bytes, with every task allocation otherwise unchanged and no
deletion credit. Adding this ADR raises only the tracked-file source limit from
1,562 to 1,563; source byte limits and aggregate allocations do not change.

## Consequences

A failed, cancelled, retried, malformed, expired, mismatched, or
cleanup-uncertain publisher or static observation retires this generation and
grants no downstream authority. There is no fallback, stitching, or
same-generation replacement.

This decision grants no mixed preflight, qualification, AWS credentials,
planning, approval, provider initialization, OpenTofu, SSM, inventory,
deployment, campaign, production evidence, release, or Issue 42 closure
authority. After successful static observation and independent audit, stop for
the separate Q decision.
