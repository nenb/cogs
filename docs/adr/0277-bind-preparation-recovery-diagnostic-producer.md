# ADR 0277: Bind the preparation-recovery diagnostic producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Pre-H rehearsal `33536817754` stopped on a non-retried GHCR acquisition refusal before KVM. Native and Linux-root diagnostics subsequently acquired and verified the exact immutable subject. The run also exposed that cleanup-only recovery was incorrectly skipped after preparation refusal, preventing residue proof. PR #481 now runs recovery after every non-skipped preparation attempt. The protected-main implementation revision is `06d551c8ecf3805a1ce32178888d0465b75c6e60`.

Attempt-one producer `33539974936` completed two byte-identical builds and independent seven-member readback. Artifact `9813959711` has Actions digest `sha256:d5d28015e795bf7e883a160da6437b1e75c7ab040c25a29e9467591f16d499c5`.

## Decision

This ADR must be the direct protected-main child of `06d551c8ecf3805a1ce32178888d0465b75c6e60`. It authorizes one first-created diagnostic publisher bound only to run `33539974936`, artifact `9813959711`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed pre-entry rehearsals remain non-authorizing. No KVM lifecycle has yet occurred.
