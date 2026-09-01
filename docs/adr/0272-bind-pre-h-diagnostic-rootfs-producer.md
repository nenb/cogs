# ADR 0272: Bind the pre-H diagnostic rootfs producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing instruction to continue the corrected non-AWS sequence autonomously through one diagnostic producer, publisher, consumer seam, and no-mint KVM rehearsal

## Context

Protected-main candidate `c95afa5cedf334b8df16327a1f16db3c91de9a5e` passed complete local validation, adversarial rereview, pull-request CI, and the diagnostic two-build producer run `33493595210`. That run built the canonical rootfs twice, proved byte equality and all fixed identities, copied exactly seven members into unprivileged custody, uploaded artifact `9795369183`, and independently read it back. The Actions artifact digest is `sha256:af6f5cb644f8298f1a549cc335e288b40847bd4c2d71d18e45b42b607dfd96a5`.

Earlier diagnostic runs `33482118028`, `33484088178`, `33486146824`, and `33488896416` failed and remain non-authorizing. Their corrections produced new implementation generations; none may be retried or relabelled.

## Decision

Treat `c95afa5cedf334b8df16327a1f16db3c91de9a5e` only as the provisional pre-H implementation ancestor for the diagnostic publisher and rehearsal. This ADR commit must be its direct protected-main child. It authorizes one first-created diagnostic publisher invocation bound to run `33493595210`, artifact `9795369183`, and the exact digest above.

The publication remains diagnostic and non-authoritative. It may sign, publish, pull by immutable manifest digest, and prove exact five-member readback solely to exercise the authenticated producer-to-consumer seam. It cannot consume final producer/publisher first-created history, freeze H or G, issue qualification evidence, or authorize AWS/provider/SSM activity.

## Consequences

A successful diagnostic publisher may feed exactly one first-created no-mint KVM rehearsal containing one full route and one readiness route. Failure, cancellation, rerun, replacement, cleanup uncertainty, or residue starts a new implementation generation. Independent readiness audit and explicit H freeze remain later gates.
