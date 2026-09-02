# ADR 0286: Retire the malformed launch-observation publisher dispatch

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

The first-created diagnostic publisher dispatch for launch-observation generation `9f6e79140e4df284588182c96b5044bb52f50ef9`, run `33630868892`, supplied the malformed artifact digest value `sha256`. Admission rejected it before checkout, artifact access, credentials, publication, or any other source effect. The run is permanently non-authorizing and cannot be retried or replaced within that generation.

No evidence was minted and no AWS/provider operation occurred.

## Decision

Retire the complete `9f6e7914` diagnostic producer/publisher generation without reusing its successful producer artifact. This ADR and its regenerated offline-readiness closure form a fresh provisional implementation H only after protected-main merge. One first-created diagnostic dual-build producer may then be dispatched for that exact H under the corrected prerequisite authority.

A later direct-child ADR must bind any successful producer before a publisher or rehearsal. This ADR freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

Producer `33626103650`, artifact `9845676644`, and failed publisher `33630868892` remain historical and non-authorizing. No publication, rehearsal, qualification, or AWS authority follows from them.
