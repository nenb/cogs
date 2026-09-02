# ADR 0283: Bind the runtime-mode-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

No-mint rehearsal `33585218945` passed authenticated prebuilt acquisition, operation opening, and production grant binding, then failed before KVM launch because prepared-runtime custody expected a stale writable-owner mode rather than the immutable publisher's exact read/execute-only mode. Cleanup uncertainty granted no authority; readiness was not entered, no evidence was minted, and no AWS/provider operation occurred.

PR #493 aligned the claimant with the immutable runtime root's root-owned mode `0500` while preserving exact descendants, links, digests, xattrs, and retained descriptors. Complete local validation passed 1,325 tests with seven explicit skips and zero failures, and protected CI passed. The protected-main implementation revision is `026b5ec687267b2780db730a5ff755fe7c3f8273`.

Attempt-one producer `33588868878` completed two byte-identical builds and independent seven-member readback. Artifact `9831552535` has Actions digest `sha256:f161326229ae8570b52878b2242d7a8d4adc0a7578a8a3ca3813a231496004a9`.

## Decision

This ADR must be the direct protected-main child of `026b5ec687267b2780db730a5ff755fe7c3f8273`. It authorizes one first-created diagnostic publisher bound only to run `33588868878`, artifact `9831552535`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed rehearsals remain non-authorizing. No complete full/readiness KVM rehearsal has occurred.
