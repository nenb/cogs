# ADR 0331: Freeze image-bound H and authorize control

- Status: Accepted
- Date: 2026-09-10
- Deciders: Nick Byrne
- Scope: replacement Stage2 H, exact producer, direct-child G, publisher, and static observation; no AWS

## Context

ADR 0330 retired the runner-rollover generation and required exact hosted-image admission, early ambient executable-closure verification, corrected `/opt` custody, and one complete fresh non-AWS chain. PR 533 passed two exact-tree source reviews, two deterministic-readiness reviews, the full local suite, required checks, and Linux/root diagnostics. Protected main produced replacement implementation **H** `11c03441468d4c3130667321018e1cb6f626a303`, tree `d6a0d7f9189bcc37abcfb597a0220a7789f53d4c`, whose sole parent is retired Q `d0e29eb359f0c1678c18f676e312276eff3aa3f8`. The reviewed candidate and protected H trees are equal.

The final local check passed 1,517 tests with 11 expected skips and zero failures; its log SHA-256 is `942bc0bee43caf5d442439cf392470ce0d497c34a9c2b3ad676694f402441bc1`. Final exact-tree reviews are `/tmp/h330-readiness-a.md` SHA-256 `340115aadf68f26c0208753ec57cd80d5485221a27d682bdef4b19b2b4c23a96` and `/tmp/h330-readiness-b.md` SHA-256 `04b93cd4a4b8cf0b64ae25bfc354f8de9b75770794ae5057e76c3ad2ba016c00`. Candidate CI `34430231345` and Linux/root run `34430231336` passed. Protected-H Linux/root run `34447940579` passed. Protected-H CI `34447940549` passed on attempt 2 after attempt 1 failed only while Ubuntu Snapshot returned HTTP 500 for six deterministic sandbox packages; quality and secret jobs passed on attempt 1, and no Stage2 authority was attempted by either CI attempt.

Producer run `34452651886`, attempt 1, is the sole first-created producer at H. Its `admit`, `build`, and `readback` jobs passed. GitHub artifact `10143009714`, named `stage2-prebuilt-rootfs-11c03441468d4c3130667321018e1cb6f626a303`, is unexpired and has Actions archive SHA-256 `61e2a99a2ad651b954285a1310916ec22abca8300035f71a1544cfb942e25fe7`.

The exact producer custody binds:

- source manifest `e2e092bd14161425aacaead2abbe1eb41de50c2f78fdea3d6fffdcaf6711115f`;
- workflow `517173a63ad7379fbeef762ae61865ceaac9b275798ce22512f60ceefda3dcef`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `48e6f27f24b09a01888e520ad7a883072dafb44dcf0bb33ece3fdfebed41b733`;
- package `aca1505ac7065a106d21b9dc6399257c075a89c21a90398038a480588dcbb964`;
- provenance `96f8b86bd3a5d9634295154c77c571636f6d94f9bc34e2f63e096306f9132376`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- sentinel `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- 4,353 logical entries and two byte-identical builds.

The downloaded textual run log SHA-256 is `2aab5632dc0b6a0b154387aee53d9b45c4405e7d9fa84ceb79043c9a854854be`. Two independent audits reconstructed the complete fixed source and canonical tar, verified complete singleton history and the exact seven-member artifact, found no selected retired identity, and confirmed no AWS, provider, OpenTofu, SSM, KVM, deployment, campaign, remote OCI publication, or production operation.

Ordinary runner observations still show a mixed `20260831.293.1` / `20260907.300.1` rollout. That does not invalidate H or its deterministic producer, but ADR 0330 prohibits starting the successor static observation until broad fresh observations show convergence on H's admitted `20260907.300.1` image.

## Decision

Freeze H `11c03441468d4c3130667321018e1cb6f626a303` and exact producer run `34452651886`, artifact `10143009714`, and archive SHA-256 `61e2a99a2ad651b954285a1310916ec22abca8300035f71a1544cfb942e25fe7`.

Establish the protected-main result containing only this decision, its index, the focused reservation/accounting assertion transition, and deterministic non-authorizing evidence refresh as control revision **G** only if it is one commit whose sole parent is H, its tree equals the reviewed candidate tree, and every required protected check passes. H remains the executable implementation and producer identity. G records the producer observation and must not alter H-owned runtime, rootfs, image admission, host closure, grant codec, workflow, retirement, or qualification source.

After G is established and independently checked, authorize exactly one first-created attempt-one trusted publisher at G with these immutable inputs:

- implementation H `11c03441468d4c3130667321018e1cb6f626a303`;
- producer run `34452651886`;
- producer artifact `10143009714`;
- producer archive digest `sha256:61e2a99a2ad651b954285a1310916ec22abca8300035f71a1544cfb942e25fe7`.

Only after two independent audits accept publisher custody **and** broad fresh non-authorizing runner observations show `ImageOS=ubuntu24`, `ImageVersion=20260907.300.1` convergence may one first-created attempt-one prebuilt no-KVM static observation run at G. It must use the exact publisher run, artifact, and archive digest. The static workflow commitment is `3b3d9f95ad41b84bf2480b61a360d52c46d2624298ca8df9e76a3171af814fdb`. Audit the static observation twice before creating Q.

ADR 0332 remains reserved for committing only the exact independently read-back v7 static package as sole-parent Q and authorizing exact H/G/Q mixed preflight followed by seven-runner qualification. Q must not change H-owned executable authority.

## Consequences

A failed, cancelled, retried, malformed, expired, residue-uncertain, or cleanup-uncertain publisher or static run retires this complete generation. It cannot be rerun or reused for authority. H, producer custody, or G alone grants no mixed preflight, qualification, production, release, Stage3/Stage4 exit, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority.

Model-key revocation after hydration into a live worker remains unresolved; OpenBao deletion alone is not provider-key revocation. This decision implements the owner's explicit authorization to continue the complete non-AWS chain and stop before AWS. It grants no AWS operation under any circumstance.
