# ADR 0273: Bind the corrected pre-H diagnostic rootfs producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

The first diagnostic publisher (`33499304913`) failed before credentials because its depth-one checkout could not verify `HEAD^ == H`. PR #473 corrected both diagnostic and final publishers to fetch exactly two commits. The resulting protected-main implementation ancestor is `3c38059586064059d73bb9d40598eb9fd7b2f59c`.

Diagnostic producer run `33507700499` then succeeded at attempt one: two builds were byte-identical, exact fixed identities passed, seven members entered upload custody, and a separate job read them back. Its artifact is `9801217893`, with Actions archive digest `sha256:1d17de8084975ce9be18636bb6d9c82fc7a825ee610e176a03386f3666a71621`.

## Decision

This ADR commit must be the direct protected-main child of `3c38059586064059d73bb9d40598eb9fd7b2f59c`. It authorizes exactly one first-created diagnostic publisher invocation bound to producer run `33507700499`, artifact `9801217893`, and the exact archive digest above.

The result remains non-authoritative and may feed only the one no-mint full/readiness KVM rehearsal. It cannot freeze H or G, consume final producer/publisher authority, authorize qualification, or authorize AWS/provider activity.

## Consequences

The earlier producer and publisher generations remain historical diagnostics. Failure, cancellation, rerun, replacement, cleanup uncertainty, or residue requires correction before a new generation; none may be relabelled.
