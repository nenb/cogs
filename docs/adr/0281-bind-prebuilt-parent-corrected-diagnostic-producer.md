# ADR 0281: Bind the prebuilt-parent-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

No-mint rehearsal `33570919609` authenticated and materialized the immutable prebuilt rootfs, staged directional control, issued the sole full-route grant, and entered the authentic KVM full route. It then failed during operation open because the parent transition required the legacy producer-only `artifacts` directory even for a descriptor-bound prebuilt lease. Readiness was not entered, no evidence was minted, cleanup uncertainty granted no authority, and no AWS/provider operation occurred.

PR #489 preserved the exact parent-name, inode, ownership, mode, link-count, and timestamp checks while requiring `artifacts` only for legacy rebuild leases and requiring its absence for authenticated prebuilt leases. Complete local validation passed 1,325 tests with seven explicit skips and zero failures, and protected CI passed. The protected-main implementation revision is `db13f9a466c4031360e61d9f4c0cfd522707aae6`.

Attempt-one producer `33574545838` completed two byte-identical builds and independent seven-member readback. Artifact `9826621548` has Actions digest `sha256:ca2ba9a8367e2052f748fad5f0351b36af4c2c51ca839cee0b8f8f112e8ffcc3`.

## Decision

This ADR must be the direct protected-main child of `db13f9a466c4031360e61d9f4c0cfd522707aae6`. It authorizes one first-created diagnostic publisher bound only to run `33574545838`, artifact `9826621548`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed rehearsals remain non-authorizing. No complete full/readiness KVM rehearsal has occurred.
