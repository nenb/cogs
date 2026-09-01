# ADR 0279: Bind the root-custody control diagnostic producer

- Status: Accepted
- Date: 2026-09-01
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

Pre-H rehearsal `33552996153` completed immutable preparation and root-owned control staging, then its unprivileged shell could not traverse the intentionally mode-0700 `/var/lib/cogs` root to check the staged file. PR #485 moves that read-only check through `sudo -n /usr/bin/test`. The protected-main implementation revision is `4cf08556a015ec218f1c090826259a7e13d6b110`.

Attempt-one producer `33556127705` completed two byte-identical builds and independent seven-member readback. Artifact `9820312327` has Actions digest `sha256:7195d0237b3bab618e107a9aa56d4bdeb481f35d157ca828b828875092009185`.

## Decision

This ADR must be the direct protected-main child of `4cf08556a015ec218f1c090826259a7e13d6b110`. It authorizes one first-created diagnostic publisher bound only to run `33556127705`, artifact `9820312327`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed pre-entry rehearsals remain non-authorizing. No KVM lifecycle has yet occurred.
