# ADR 0328: Freeze runtime-corrected H and authorize control

- Status: Accepted
- Date: 2026-09-09
- Deciders: Nick Byrne
- Scope: replacement Stage2 H, exact producer, direct-child G, publisher, and static observation; no AWS

## Context

ADR 0327 retired the failed formal generation and required a versioned static/live runtime-contract split before one complete fresh non-AWS chain. PR 530 passed two exact-tree reviews, the full local suite, protected checks, Linux/root lifecycle shards, KVM, and insecure-container checks. Protected main produced replacement implementation **H** `c30e0d69ec374cd812ff361e670e974d51b661c4`, tree `3d7d09811a780ec4d3eef99d8afac5f1ec4dcd32`, whose sole parent is retired Q `b11adc47c454bde0dc0e2930012e418b90917555`. The reviewed candidate and protected H trees are equal.

The final local check passed 1,514 tests with 11 expected skips and zero failures; its log SHA-256 is `46e4ebfef26c5a0139a8b4bebf076ac04a002fc9eff3d9cd66647c32e539d068`. Required PR CI run `34370645229`, Linux/root run `34370645255`, KVM run `34370645156`, and insecure-container run `34370645234` passed. Protected-H CI `34375871721` and Linux/root run `34375871774` also passed. The final exact-tree reviews are `/tmp/h-finalx-a.md` SHA-256 `a0b6dbf7155b78946f26fa638776503db65ce3754c67247a6f31f649108fdc43` and `/tmp/h-finalx-b.md` SHA-256 `edbfe6a162f85aea719cdececa81339f96376a851cd5b748e423d86b8c02565e`; the older PR description is not substituted for those exact reviews.

Producer run `34375934829`, attempt 1, is the sole first-created producer at H. Its `admit`, `build`, and `readback` jobs passed. GitHub artifact `10114901253`, named `stage2-prebuilt-rootfs-c30e0d69ec374cd812ff361e670e974d51b661c4`, is unexpired and has Actions archive SHA-256 `0c302383fc9c02d1be9bf8285e61a5ae10c5036f4e8885ddebfaa602e8ec0102`.

The exact producer custody binds:

- source manifest `a5ebebaf515805f65bb2ff7c4ffa79ff1506ee8859e5257763c98dd00114503f`;
- workflow `1f41ac1fce30cb44f12bf0d852a767df4b705c155d5619421bedb5a14cfdd6b2`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `7cd350908ecb436f49def3acd377cf5b720eec1652eb351ad950ff5c5356c2e6`;
- package `201d03054f6fea4c8811d9c06966754c710e3ca44c61ef69fbd93987020eee1b`;
- provenance `4b314ae85ecf21ead5bc1a553cca129a374ae9a55c51e32f9d41eb42183546f3`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- sentinel `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- 4,353 logical entries and two byte-identical builds.

The downloaded textual run log SHA-256 is `c821c71cb91f0889867d0de09974e3a5337d533ffed3e86b399aa0652274d62b`. Two independent audits found no blocking P0–P3 issue, reconstructed the complete fixed source and canonical tar, verified complete singleton history and the exact seven-member artifact, found no selected retired identity, and confirmed no AWS, provider, OpenTofu, SSM, KVM, deployment, campaign, remote OCI publication, or production operation. The artifact expires on 2026-09-16; expiry cannot authorize a producer retry or substitute local custody for publisher/readback custody.

## Decision

Freeze H `c30e0d69ec374cd812ff361e670e974d51b661c4` and exact producer run `34375934829`, artifact `10114901253`, and archive SHA-256 `0c302383fc9c02d1be9bf8285e61a5ae10c5036f4e8885ddebfaa602e8ec0102`.

Establish the protected-main result containing only this decision, its index, the focused reservation/accounting assertion transition, and deterministic non-authorizing evidence refresh as control revision **G** only if it is one commit whose sole parent is H, its tree equals the reviewed candidate tree, and every required protected check passes. H remains the executable implementation and producer identity. G records the producer observation and must not alter H-owned runtime, rootfs, grant codec, workflow, retirement, or qualification source.

After G is established and independently checked, authorize exactly one first-created attempt-one trusted publisher at G with these immutable inputs:

- implementation H `c30e0d69ec374cd812ff361e670e974d51b661c4`;
- producer run `34375934829`;
- producer artifact `10114901253`;
- producer archive digest `sha256:0c302383fc9c02d1be9bf8285e61a5ae10c5036f4e8885ddebfaa602e8ec0102`.

The publisher must preserve exact GitHub artifact custody, canonical descriptor construction, ORAS manifest/layer/config identity, keyless Sigstore identity and issuer restrictions, offline bundle verification, and exact readback. Its first-created query counts every workflow-dispatch run at exact G without caller-controlled title or input partitioning.

Only after the publisher succeeds and two independent audits accept its exact custody may one first-created attempt-one prebuilt no-KVM static observation run at the same G using the exact publisher run, artifact, and archive digest. The static workflow commitment is `95b65c998b70f028b091de60c868de5e94b68703327cf5f66760a9e5b0fae438`. Audit the static observation twice before creating Q.

ADR 0329 remains reserved for committing only the exact independently read-back v6 static package as sole-parent Q and authorizing exact H/G/Q mixed preflight followed by seven-runner qualification. Q must not change H-owned executable authority.

## Consequences

A failed, cancelled, retried, malformed, expired, residue-uncertain, or cleanup-uncertain publisher or static run retires this complete generation. It cannot be rerun or reused for authority. H, producer custody, or G alone grants no mixed preflight, qualification, production, release, Stage3/Stage4 exit, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority.

Model-key revocation after hydration into a live worker remains unresolved; OpenBao deletion alone is not provider-key revocation. This decision implements the owner's explicit authorization to continue the complete non-AWS chain and stop before AWS. It grants no AWS operation under any circumstance.
