# ADR 0275: Bind the rehearsal-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Pre-dispatch review found that the no-mint rehearsal's depth-one checkout could not verify its required direct H parent. PR #477 corrected it to fetch exactly two commits before any KVM execution. The protected-main implementation revision is `661c4545b51b3015bc2299c261c0a57eaa65e0e7`.

Attempt-one producer `33523948937` completed two byte-identical builds and independent seven-member readback. Artifact `9807877005` has Actions digest `sha256:1f8c5fa93674138bd3fc0acb2a11441af5b33907dc2db7a146b61f82403674e5`.

## Decision

This ADR must be the direct protected-main child of `661c4545b51b3015bc2299c261c0a57eaa65e0e7`. It authorizes one first-created diagnostic publisher bound only to run `33523948937`, artifact `9807877005`, and the exact archive digest above, followed by the already-authorized one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations remain non-authorizing. No KVM rehearsal has yet occurred. Failure, cancellation, cleanup uncertainty, or residue requires correction before another generation.
