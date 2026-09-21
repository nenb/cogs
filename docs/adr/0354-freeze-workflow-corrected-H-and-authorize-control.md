# ADR 0354: Freeze workflow-corrected H and authorize control

- Status: Accepted
- Date: 2026-09-21
- Decider: Nick Byrne
- Scope: exact workflow-corrected H and producer, direct-child G, one publisher, and one static observation; no AWS

## Context

ADR 0353 retired the failed H/G static generation and authorized one bounded
exact-workflow correction followed by a replacement H/G/Q chain. PR 567 passed
CI `35579593283` and Linux foundations `35579593278`, then merged as protected
squash result **H** `6c200c6fcd87616244b38b6676d07c513aeb42fd`, whose sole
parent is `4452a96acb1ad31ea8f6b242334f258ce0b0abab` and whose tree is
`37bd49e61143f8ed886dd229189a57e91f6570bc`. Reviewed PR head
`5a3e6b97d72d1ce72d8c823f4dacdb240cf278a0` has the identical tree.
Exact-H protected-main CI `35583156058` and Linux foundations `35583156105`
passed.

Producer run `35587992926`, attempt 1, is the sole first-created producer at H.
Its admit, build, and readback jobs passed. Artifact `10634535621`, named
`stage2-prebuilt-rootfs-6c200c6fcd87616244b38b6676d07c513aeb42fd`, is
unexpired through 2026-09-28 and has Actions archive digest
`sha256:3a8529568eff01bc8273b01db375fccc59af744a40efc2d35e5d55dd01de4437`.
Independent archive and exact-member readback accepted these bindings:

- source manifest `977863e11322f503a5041d73a962c9058b4f2a65aff2146ad167ecdb56700e4c`;
- producer workflow `aa09f014eea346f01cc48d87899b63061fc082020825c64a78c561d9c4ff8fa3`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `58be4362a9938b700cfb57a8a2a9db5d0f76490b5801cfaef04bbe69f13a7169`;
- package `6c5de07630a60cd639e3f6cfa4435e1373be0336377f6ab3cfcf465154671e2f`;
- provenance `fbaa0f8c6bc450ca570974fcf00ceae005fd3f3a77c3de76c0ba428a4ecb8131`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- marker `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- 4,353 entries and two byte-identical builds.

No producer KVM, AWS, provider, OpenTofu, SSM, remote publication, deployment,
or campaign operation occurred.

## Decision

Freeze exact H `6c200c6fcd87616244b38b6676d07c513aeb42fd`, producer run
`35587992926`, artifact `10634535621`, and archive digest
`sha256:3a8529568eff01bc8273b01db375fccc59af744a40efc2d35e5d55dd01de4437`.

Establish the protected-main squash result containing only this decision and
index, exact accounting assertions, the anticipated Q path, and deterministic
non-authorizing Stage 4 readiness refresh as control revision **G** only if it
is one commit whose sole parent is exact H, its tree equals the reviewed
candidate tree, and every required protected check passes. H remains the
executable implementation and producer identity. G changes no H-owned
executable or runtime behavior, campaign, production, provider, workflow,
static package, qualification constant, or retirement policy.

After G is established and independently checked, authorize exactly one
first-created attempt-one trusted publisher at G using only the frozen H,
producer run, artifact ID, name, and archive digest above. Only after
independent audit accepts the publisher's complete exact artifact custody,
readback, signature, and cleanup may exactly one first-created attempt-one
no-KVM static observation run at G. The observation must execute H's corrected
exact-current-workflow boundary and its exact artifact and cleanup must be
independently audited before Q is created. No publisher or static dispatch is
performed by this decision commit.

Anticipate only the literal
`docs/adr/0355-establish-workflow-corrected-Q-and-authorize-qualification.md`
path in the final-HGQ allowlist; do not create ADR 0355 now. Q must be G's sole
direct child and requires a separate decision based on the independently
read-back static members. It must not alter H-owned executable authority.

Use ADR 0351's existing allocation without reallocation: the immutable pre-H
slice remains 607 lines and 1,700,000 bytes; the separate post-H reserve remains
900 lines and 3,500,000 bytes; and the combined final-HGQ maximum remains 1,507
lines and 5,200,000 bytes. The five-task tranche remains exactly 22,157 lines
and 21,500,000 bytes, with every task allocation otherwise unchanged and no
deletion credit. Adding this ADR raises only the tracked-file source limit from
1,561 to 1,562; source byte limits and aggregate allocations do not change.

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
