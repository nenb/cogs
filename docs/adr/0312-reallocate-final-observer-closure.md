# ADR 0312: Reallocate final observer closure

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval for required non-AWS correction and integration
- Measurement: combined endpoint through commits `d772f139`, `f0f9045b`, `b9a90d4e`, `6356533e`, `71ea8e52`, and `847103c7`

## Context

The first complete local integration of the six application/native/driver workstreams passes 400 focused tests with four intentional platform skips. Baseline-to-endpoint no-deletion accounting measures: route 1,391; revocation 2,104; relay 1,110; lifecycle 5,138; completion 1,763; integration 2,197; total 13,703 of 16,000.

All current owner ceilings pass, but the S3-09 implementation correctly reports that complete final WAL/completion observation remains missing. Closing that interface requires lifecycle and completion additions beyond the small remaining lifecycle/completion margins. Unused integration and revocation capacity can be reallocated without raising the global ceiling. The baseline-absent `src/api/history-fragments.ts` reservation is no longer needed because the accepted history-fragment implementation uses existing files.

## Decision

Before final-observer implementation, supersede only the owner ceiling vector:

| Owner | Ceiling |
|---|---:|
| route | 1,500 |
| revocation | 2,800 |
| relay | 1,300 |
| lifecycle | 5,700 |
| completion | 2,000 |
| integration | 2,700 |
| **Total** | **16,000** |

Retain every global, Stage2, source-byte/cardinality, mutable-owner and future-v5 limit. No deletion credit, wildcard allocation, test removal, or path reassignment is permitted.

Release the unused absent `src/api/history-fragments.ts` reservation. Transfer that one new-file slot from completion to integration and use it for this ADR, preserving the total forty-file ceiling. Future replacement-H freeze/control and Q/qualification decisions become ADR 0313 and ADR 0314.

Authorize a narrow final-observer correction in existing allocated files only:

1. preserve a complete bounded final WAL identity/suffix and completion accounting after authorization/completion producers actually retire;
2. expose only immutable metadata needed by the trusted S3-09 proof—never credentials, bodies, arbitrary headers or an alternate audit store;
3. distinguish retained, drained and dropped optional diagnostics; a dropped/missing required S3-09 completion fails rather than being inferred;
4. bind exact session, route, intent, sequence and generation to the positive fixture/relay observation;
5. reject extra, duplicate, malformed, late or unretired observations;
6. keep durable WAL authorization fail-closed and material release behind actual user retirement;
7. preserve fresh close observations and sticky lifecycle failure from the integrated close owner.

A final retired snapshot is not permission to replay, replace, or heal an earlier failed run. The historical S3-09 report remains historical.

## Validation

The correction must add regression-first tests for missing/dropped/extra completion, late WAL append, final snapshot before producer retirement, repeated drains, close timeout versus actual retirement, wrong generation and exact positive success. Re-run all six integrated focused suites, full checks, exact accounting, pinned Envoy/OpenBao evidence applicable to the final source, and independent hostile review.

## Authority boundary

This ADR authorizes local code, tests, integration and ordinary protected CI only. It grants no producer, publisher, preflight, qualification, image publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production or release authority. Work stops before the authoritative chain.
