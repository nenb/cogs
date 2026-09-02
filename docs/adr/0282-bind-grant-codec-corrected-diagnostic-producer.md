# ADR 0282: Bind the grant-codec-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

No-mint rehearsal `33579065987` completed authenticated prebuilt acquisition and operation opening, then failed before KVM launch because durable route validation hashed a decoded production launch grant with a trailing newline while the established production issuer and grant type exclude it. Cleanup uncertainty granted no authority; readiness was not entered, no evidence was minted, and no AWS/provider operation occurred.

PR #491 aligned operation validation with the production commitment codec and added cross-module full/readiness grant tests. Complete local validation passed 1,325 tests with seven explicit skips and zero failures, and protected CI passed. The protected-main implementation revision is `a59b7ec0b9eb09d11bc9c040fcd36057215f17a9`.

Attempt-one producer `33582066423` completed two byte-identical builds and independent seven-member readback. Artifact `9829259549` has Actions digest `sha256:ac34fec3672057e1d52eb381888e419274f1bfd27abc1edce0c14ad2bccbecdf`.

## Decision

This ADR must be the direct protected-main child of `a59b7ec0b9eb09d11bc9c040fcd36057215f17a9`. It authorizes one first-created diagnostic publisher bound only to run `33582066423`, artifact `9829259549`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed rehearsals remain non-authorizing. No complete full/readiness KVM rehearsal has occurred.
