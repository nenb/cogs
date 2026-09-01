# ADR 0278: Bind the canonical import-order diagnostic producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Pre-H rehearsal `33544800095` authenticated and downloaded the exact rootfs, then failed package verification before KVM because the importer treated canonical ustar emission order as canonical manifest order. PR #483 now separately proves directories/files/symlinks/hardlinks archive order and reconstructs globally path-sorted manifest entries. The exact 4,353-entry published archive passes. The protected-main implementation revision is `21a07b3da8bb70282cb3b15b06c91134704f8a09`.

Attempt-one producer `33547791052` completed two byte-identical builds and independent seven-member readback. Artifact `9817104846` has Actions digest `sha256:dd1bb48adcf0f458c0e934402a45d174e277428663f48329f8246181426e83a9`.

## Decision

This ADR must be the direct protected-main child of `21a07b3da8bb70282cb3b15b06c91134704f8a09`. It authorizes one first-created diagnostic publisher bound only to run `33547791052`, artifact `9817104846`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed pre-entry rehearsals remain non-authorizing. No KVM lifecycle has yet occurred.
