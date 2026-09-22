# ADR 0358: Freeze host-scoped H and authorize control

- Status: Accepted
- Date: 2026-09-22
- Decider: Nick Byrne
- Scope: exact host-scoped H and producer, direct-child G, one publisher, and one static observation; no AWS

## Context

ADR 0357 retired the terminal timeout-corrected H/G/Q generation and formal
qualification `35685410662` after all seven KVM cycles passed but the aggregate
incorrectly treated host-local observations as globally unique. It authorized
one fresh implementation that scopes QEMU runtime identity, live mapping, and
pre/post-SSH process observations by `host_boot_commitment` while preserving
global freshness for actual cross-host identities and same-cycle pre/post
inequality.

PR 572 passed CI `35706660527` and Linux foundations `35706660474`, then
merged as protected squash result **H**
`306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c`. Its sole parent is retired Q
`17380562a9fb9f7d08bea0269a9fdc5812b1faf7`, its tree is
`4a29519628b3435e4ad32d57ce58844e3d3ce52b`, and reviewed PR head
`329acaa4a95a1f9dfb826c0db019d6ed377f521d` has the identical tree. Exact-H
protected-main CI `35712137203` and all 22 Linux-foundations shards plus the
aggregate in `35712137221` passed. There was no retry or unchanged-candidate
reinterpretation.

Producer run `35716917245`, attempt 1, is the sole first-created producer at H.
Its admission, build, and readback jobs passed. Artifact `10690851656`, named
`stage2-prebuilt-rootfs-306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c`, is
unexpired through 2026-09-29T11:06:29Z, is 137,959,274 bytes, and has Actions
archive digest
`sha256:e52f96ec18b47fa9b069a168615b55ade95cfcf3b9583473f00268c7765311b1`.
Independent authenticated control-plane, archive, source, exact-member, and
raw-ustar readback accepted:

- source manifest `2de628a79518603613c6a27816dfb06411a7a5a2e73f41a08962ac54b15da92c`;
- producer workflow `30a108dc58a1ce6389df1f53a3f39796dbc854a1f4a1f4dac6c1102083a576df`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `1f4ebcb284dd015a75fe5c87629a71955da3a3f2911dd130c95b49dc69d73dfe`;
- package `5290a1ac6a863e7b462934f8979c9512bcfaf81ed9eab7a3ba3ff4bfe4a5a5d0`;
- provenance `675a78029e582e59b2be3ce9445a177d496c227235e16335fe38cab780851fb9`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- marker `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- all 4,353 entries and two byte-identical builds.

The independent audit record has digest
`sha256:74ad2b84d8384895c9bb43cb00e19e3fdec793bcebbcd5df54e2186e4a8f134a`.
No producer KVM, AWS, provider, OpenTofu, SSM, remote publication, deployment,
or campaign operation occurred.

## Decision

Freeze exact H `306727e28ed8b0257d84b7c6fdfd6ba1fde5a22c`, producer run
`35716917245`, artifact `10690851656`, and archive digest
`sha256:e52f96ec18b47fa9b069a168615b55ade95cfcf3b9583473f00268c7765311b1`.

Establish the protected-main squash result containing only this decision and
index, exact accounting assertions, and deterministic non-authorizing Stage 4
readiness refresh as control revision **G** only if it is one commit whose sole
parent is exact H, its tree equals the reviewed candidate tree, and every
required protected pull-request and exact-G protected-main check passes. H
remains the executable implementation and producer identity. G changes no
H-owned executable or runtime behavior, workflow, Dockerfile, ordinary test,
qualification constant, static package, retirement policy, campaign,
provider, or production behavior.

After G is established and independently checked, authorize exactly one
first-created attempt-one trusted publisher at G using only the frozen H,
producer run, artifact ID, name, and archive digest above. Only after
independent audit accepts the publisher's exact custody, readback, signature,
and cleanup may exactly one first-created attempt-one no-KVM static observation
run at G. The static observation must execute H's exact-current-workflow
boundary and preserve the accepted thirteen-member package byte-for-byte. Its
artifact and cleanup must be independently audited before Q is created. No
publisher or static dispatch is performed by this decision commit.

The final-HGQ path matrix anticipates only the literal
`docs/adr/0359-establish-host-scoped-Q-and-authorize-qualification.md`; do not
create ADR 0359 now. Q must be G's sole direct child and requires a separate
decision based on the independently read-back publisher and static members. It
must not alter H-owned executable authority.

Use ADR 0357's existing allocation without reallocation. The final-HGQ maximum
remains 2,150 lines and 5,200,000 bytes, including its 607-line pre-H cap and
1,500-line post-H reserve. The five-task tranche remains exactly 22,157 lines
and 21,500,000 bytes, every byte high remains unchanged, and deletion earns no
credit. The source limits remain 1,564 tracked files, 34,000,000 aggregate
bytes, and 262,144 serialized inventory bytes.

## Consequences

A failed, cancelled, retried, malformed, expired, mismatched, or
cleanup-uncertain publisher or static observation retires this generation and
grants no downstream authority. There is no fallback, stitching, or
same-generation replacement.

This decision grants no mixed preflight, qualification, AWS credentials, IAM
setup, planning, approval, provider initialization, OpenTofu, SSM, inventory,
deployment, campaign, production evidence, release, or Issue 42 closure
authority. After successful static observation and independent audit, stop for
the separate Q decision.
