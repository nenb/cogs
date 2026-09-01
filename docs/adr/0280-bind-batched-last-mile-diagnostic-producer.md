# ADR 0280: Bind the batched last-mile diagnostic producer

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Pre-H rehearsal `33561312093` reached the full-route entry after immutable preparation, control staging, NFT ownership, and grant issuance, but isolated Python could not import its sibling coordinator. A batched last-mile review then covered every isolated rehearsal and final cycle entry, route conditions, recovery, settlement, root custody, and producer/publisher boundary. PR #487 corrected full, readiness, and both no-mint entries together. Complete local validation passed 1,325 tests with seven explicit skips and zero failures; retained accounting remains below its preferred limit. The protected-main implementation revision is `4bd0fd3f4964cb8684245a958667d7a98f14c95d`.

Attempt-one producer `33566771482` completed two byte-identical builds and independent seven-member readback. Artifact `9824139305` has Actions digest `sha256:ba24bf48c1cd6dc72476fcc0e58dd3c5e955c32dd85a0b1bf80d45cd86812531`.

## Decision

This ADR must be the direct protected-main child of `4bd0fd3f4964cb8684245a958667d7a98f14c95d`. It authorizes one first-created diagnostic publisher bound only to run `33566771482`, artifact `9824139305`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed rehearsals remain non-authorizing. No successful KVM lifecycle has occurred.
