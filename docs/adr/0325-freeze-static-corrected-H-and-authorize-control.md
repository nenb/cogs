# ADR 0325: Freeze static-corrected H and authorize control

- Status: Accepted
- Date: 2026-09-08
- Deciders: Nick Byrne
- Scope: replacement Stage2 H, exact producer, direct-child G, publisher, and static observation; no AWS

## Context

ADR 0326 retired H `6276eae08e29ee577f3d9b2c739ceadfe467a769` and its otherwise successful producer after finding incomplete historical retirement enforcement. PR 527 reconciled every in-scope selected tombstone into the central policy, closed Python copy, and all 19 pre-effect workflow mirrors; added nested production-provenance rejection before credentials or effects; repaired archival Linux fixture coverage; and regenerated deterministic non-authorizing readiness evidence. Protected main produced replacement implementation **H** `c10fc103532f3e3a8b746727bd0f48c6d8498148`, tree `ac76d3f83e57b9c227c74e3085bfbab6a7986f28`, whose sole parent is the retired predecessor. The reviewed candidate and protected H trees are equal.

All required protected checks passed. CI run `34278560569` passed quality and secret checks; its image, vulnerability, and SBOM job passed on attempt 2 after attempt 1 encountered a transient Debian Snapshot connection close. Linux/root run `34278560512`, KVM run `34278560513`, and insecure-container run `34278560528` passed. The protected Linux baseline specifically proved that current staging rejects the retired historical v4 fixture before a narrow test-only adapter exercises its archival filesystem assertions.

Producer run `34282898803`, attempt 1, is the sole first-created producer at H. Its `admit`, `build`, and `readback` jobs passed. GitHub artifact `10079099187`, named `stage2-prebuilt-rootfs-c10fc103532f3e3a8b746727bd0f48c6d8498148`, is unexpired and has Actions archive SHA-256 `0d4000ea50f8c2f70e341e11e7e0ba49c537800a14bf35aa63f0f0f21c8c62e1`.

The exact producer custody binds:

- source manifest `ee96c1cfae2ffb1a2d8e8fc69c94d6bd792576c8885a20a78379ecfb52d2661c`;
- workflow `da7ca7b81b6385396c718cff97ccfe42ba0efd7e0e4a88d6c7cd9c9fc3db39d8`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `9eec69c5fa7547c8a7dec86c5dfc4db7929f246e94198f5d93a1209a51d96dc3`;
- package `bb02bc159ed5f9f42fd7ceaf6d7318a5a8455dfa17bcfe66adda23e8debb5299`;
- provenance `594f1136870308b95ae5f618f1a18c2b4c4a6a2e3e7a21ee7910e40a53c5f74d`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- sentinel `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- 4,353 logical entries and two byte-identical builds.

The downloaded run log SHA-256 is `2919faaef5a419a176b1112b508d0ca82745843b586a9c97a98b6cd3e6445586`. Two independent audits found no P0–P3 issue, reconstructed the complete fixed source and canonical tar, verified the exact seven-member archive, found no selected identity in retirement policy, and confirmed no AWS, provider, OpenTofu, SSM, KVM, deployment, campaign, remote OCI publication, or production operation.

## Decision

Freeze H `c10fc103532f3e3a8b746727bd0f48c6d8498148` and exact producer run `34282898803`, artifact `10079099187`, and archive SHA-256 `0d4000ea50f8c2f70e341e11e7e0ba49c537800a14bf35aa63f0f0f21c8c62e1`.

Establish the protected-main result containing only this decision, its index update, the focused reservation/accounting assertion transition, and deterministic non-authorizing evidence refresh as control revision **G** only if it is one commit whose sole parent is H, its tree equals the reviewed candidate tree, and every required protected check passes. H remains the executable implementation and producer identity. G records the producer observation and does not alter H-owned runtime, rootfs, grant codec, workflow, retirement, or qualification source.

After G is established and independently checked, authorize exactly one first-created attempt-one trusted publisher at G with these immutable inputs:

- implementation H `c10fc103532f3e3a8b746727bd0f48c6d8498148`;
- producer run `34282898803`;
- producer artifact `10079099187`;
- producer archive digest `sha256:0d4000ea50f8c2f70e341e11e7e0ba49c537800a14bf35aa63f0f0f21c8c62e1`.

The publisher must preserve exact GitHub artifact custody, canonical descriptor construction, ORAS manifest/layer/config identity, keyless Sigstore identity and issuer restrictions, offline bundle verification, and exact readback. Its first-created query counts every workflow-dispatch run at exact G without caller-controlled title or input partitioning.

Only after the publisher succeeds and two independent audits accept its exact custody may one first-created attempt-one prebuilt no-KVM static observation run at the same G using the exact publisher run, artifact, and archive digest. The static workflow commitment remains `839d0b4ba420f80d0025b30528f00b6e4f5f1872471ae27ffb8a50122d72b10c`. Audit the static observation twice before creating Q.

ADR 0322 remains reserved for committing only the exact independently read-back static package as sole-parent Q and authorizing exact H/G/Q mixed preflight followed by seven-runner qualification. Q must not change H-owned executable authority.

## Consequences

A failed, cancelled, retried, malformed, expired, residue-uncertain, or cleanup-uncertain publisher or static run retires this complete generation. It cannot be rerun or reused for authority. H, producer custody, or G alone grants no mixed preflight, qualification, production, release, Stage3/Stage4 exit, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority.

Model-key revocation after hydration into a live worker remains unresolved; OpenBao deletion alone is not provider-key revocation. This decision implements the owner's explicit authorization to continue the complete non-AWS chain and stop before AWS. It grants no AWS operation under any circumstance.
