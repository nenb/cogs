# ADR 0361: Freeze authenticated-runner H and authorize control

- Status: Accepted
- Date: 2026-09-22
- Decider: Nick Byrne
- Scope: exact authenticated-runner H and producer, direct-child G, one publisher, and one static observation; no AWS

## Context

ADR 0360 retired the terminal host-scoped H/G producer/publisher generation
after static run `35733919360` rejected an admissible GitHub-hosted runner image
before checkout. It replaced unselectable `ImageVersion` equality with
fail-closed authentication of each assigned image against the official
`actions/runner-images` release and tag-ref APIs, preserved historical evidence
bytes, added current envelope V4, status V3, package V6, and retirement V5, and
required a wholly fresh H/G/Q chain.

PR 574 passed protected CI `35785038570` and all Linux-foundations shards plus
the aggregate in `35785038569`, then merged as protected squash result **H**
`2076c2bd781a663d2b27fa478792fc133fa9fd42`. Its sole parent is terminal G
`21848f84f01d42f28ce2f6f2a177bfe62af8fc58`, its tree is
`de2319f96d56b0b4e7eb67dbd98d4d2fa13d2aa4`, and reviewed PR head
`4877fc5a001d730473e0706a52189b2b3f9d1c9f` has the identical tree. Exact-H
protected-main CI `35790461281` and all 22 Linux-foundations shards plus the
aggregate in `35790461280` passed. There was no retry, stitching, or
reinterpretation of a failed generation.

Producer run `35795093115`, attempt 1, is the sole first-created producer at H.
Its admission, build, and readback jobs passed. Artifact `10724846408`, named
`stage2-prebuilt-rootfs-2076c2bd781a663d2b27fa478792fc133fa9fd42`, is
unexpired through 2026-09-29T23:22:52Z, is 137,959,274 bytes, and has Actions
archive digest
`sha256:0a9c5afdc12f4ccdda6e631d99bfdc6ee75c0092a46711b980baf9179928552c`.
Independent authenticated control-plane, archive, source, exact-member, and
raw-ustar readback accepted:

- source manifest `f4f4fee0eea79315a7079240a1df0a90e7da52adf3189e33d0326cf5339dbc2a`;
- producer workflow `d4fb9f013d8c4f83677aec94715f3307ece377b96bf2ff39d77d33aba7da390f`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `ff96752505e566f7e82f58758a5034bb548c409c04e9b37e98123341c0977a27`;
- package `22a702a551bc8185e30b7b767a6daf22786c323f69034bd1710d90d74093c3f4`;
- provenance `aa60879c9bee3a34181ca1151a67cf2dfcab78663e5ca378f51b3b8ce5bbe1a8`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- marker `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- all 4,353 entries and two byte-identical builds.

The independent audit record has digest
`sha256:e89ff4e067ab39b7342dc30fb06e833bf5204884e19e4021a798a344af2487d6`.
No producer KVM, AWS, provider, OpenTofu, SSM, remote publication, deployment,
or campaign operation occurred.

At exact H, cumulative gross accounting places `readiness-ci` at 293 lines and
9,398,247 bytes of its unchanged 400-line / 9,500,000-byte high. Each required
exact-index readiness refresh replaces the 243,032-byte serialized inventory.
The already-owned `local-validation.json` history accounts for 35 lines and
912,247 bytes. The unchanged production V4 fixture accounts for 5 gross lines
and 465,280 bytes in the nearly full `governance` allocation, while
`final-HGQ` has 438 lines and more than 4.5 MB remaining. Keeping both G and Q
index-derived and their governance indexed therefore requires classification,
not a higher task or global ceiling.

## Decision

Freeze exact H `2076c2bd781a663d2b27fa478792fc133fa9fd42`, producer run
`35795093115`, artifact `10724846408`, and archive digest
`sha256:0a9c5afdc12f4ccdda6e631d99bfdc6ee75c0092a46711b980baf9179928552c`.

Establish the protected-main squash result containing only this decision and
index, exact accounting assertions, and deterministic non-authorizing Stage 4
readiness refresh as control revision **G** only if it is one commit whose sole
parent is exact H, its tree equals the reviewed candidate tree, and every
required protected pull-request and exact-G protected-main check passes. H
remains the executable implementation and producer identity. G changes no
H-owned executable or runtime behavior, workflow, Dockerfile, ordinary test,
qualification constant, static package, retirement policy, campaign,
provider, or production behavior.

Reclassify only `test/fixtures/stage2-completion/production-v4-test-only.json`
from `governance` and
`docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json`
from `readiness-ci` to `final-HGQ`. Against exact H history this changes the
three task views to 8,367 lines / 650,683 bytes, 258 lines / 8,486,000 bytes,
and 3,402 lines / 2,040,878 bytes, respectively. It changes no retained source
byte, fixture byte, validation meaning, task high, or global sum; deletion
still earns no credit. Add this ADR and the anticipated Q decision path to the
same `final-HGQ` and integration-owner matrices. The five task highs remain
8,400, 5,050, 6,300, 400, and 3,800 lines;
the task byte highs, 41,950-line / 29,500,000-byte global highs, 78,000-line /
35,000,000-byte remediation highs, and all source limits remain unchanged.

After G is established and independently checked, authorize exactly one
first-created attempt-one trusted publisher at G using only the frozen H,
producer run, artifact ID, name, and archive digest above. Only after
independent audit accepts the publisher's exact custody, readback, signature,
and cleanup may exactly one first-created attempt-one no-KVM static observation
run at G. It must authenticate its assigned official runner image before source
effects, execute H's exact-current-workflow boundary, and preserve the accepted
thirteen-member package byte-for-byte. Its artifact and cleanup must be
independently audited before Q is created. No publisher or static dispatch is
performed by this decision commit.

The path matrix anticipates only
`docs/adr/0362-establish-authenticated-runner-Q-and-authorize-qualification.md`;
do not create ADR 0362 now. Q must be G's sole direct child and requires a
separate decision based on independently read-back publisher and static
members. It must not alter H-owned executable authority.

## Consequences

A failed, cancelled, retried, malformed, expired, mismatched, image-rejected,
or cleanup-uncertain publisher or static observation retires this generation
and grants no downstream authority. There is no fallback, stitching, or
same-generation replacement.

This decision grants no mixed preflight, qualification, AWS credentials, IAM
setup, planning, approval, provider initialization, OpenTofu, SSM, inventory,
deployment, campaign, production evidence, release, or Issue 42 closure
authority. After successful static observation and independent audit, stop for
the separate Q decision.
