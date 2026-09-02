# ADR 0284: Bind the runtime-staged-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

No-mint rehearsal `33593351764` passed authenticated prebuilt acquisition, production grant binding, and immutable prepared-runtime custody, then failed before daemon/KVM launch because the runtime-staged journal validator still required legacy mode `0700` for the immutable runtime root sealed at `0500`. Cleanup uncertainty granted no authority; readiness was not entered, no evidence was minted, and no AWS/provider operation occurred.

PR #495 aligned the durable runtime-staged identity with the same exact immutable root mode and corrected its native fixture. Complete local validation passed 1,325 tests with seven explicit skips and zero failures, and protected CI passed. The protected-main implementation revision is `5bced6bdc54756761f28a393970301b9b24341cc`.

Attempt-one producer `33599541457` completed two byte-identical builds and independent seven-member readback. Artifact `9835350186` has Actions digest `sha256:8f9c38779d5fe4ebc2cff2aead7a485faeb2988d77c1e87c06f70ed5c8737473`.

## Decision

This ADR must be the direct protected-main child of `5bced6bdc54756761f28a393970301b9b24341cc`. It authorizes one first-created diagnostic publisher bound only to run `33599541457`, artifact `9835350186`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed rehearsals remain non-authorizing. No complete full/readiness KVM rehearsal has occurred.
