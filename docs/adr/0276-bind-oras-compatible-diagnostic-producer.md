# ADR 0276: Bind the ORAS-compatible diagnostic producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Pre-H rehearsal `33529351160` failed during rootfs acquisition before any KVM lifecycle because the importer rejected ORAS v1.3.0's exact inline empty OCI config. PR #479 now requires its complete fixed four-field shape, including `data: e30=`, and rejects missing or additional fields. The protected-main implementation revision is `5f78367c3e4f93106d54593d6e761dad7cf6dac1`.

Attempt-one producer `33531630894` completed two byte-identical builds and independent seven-member readback. Artifact `9810904549` has Actions digest `sha256:a1b76a2a82f7e7d8106e4f7aa4a10ebce5ca0b4e127b27f1c34945ecce6adbc0`.

## Decision

This ADR must be the direct protected-main child of `5f78367c3e4f93106d54593d6e761dad7cf6dac1`. It authorizes one first-created diagnostic publisher bound only to run `33531630894`, artifact `9810904549`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and the failed pre-entry rehearsal remain non-authorizing. No KVM lifecycle has yet occurred.
