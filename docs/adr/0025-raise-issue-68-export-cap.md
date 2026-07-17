# ADR 0025: Raise issue #68 export completion line-budget cap

## Header

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Reviewed by: delegated project lead
- Acceptance: Accepted under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.
- Supersedes: ADR 0024 numeric issue #68 production `src/**/*.ts` line cap only.

## Context

ADR 0024 raised only the issue #68 production TypeScript cap to **18,300** lines. The current implementation on `main` at `e60a310` is **17,658** production `src/**/*.ts` lines.

The completed observer and checkpoint slices were deliberately strict and measured higher than the ADR 0024 estimates:

| Completed area | ADR 0024 estimate | Measured production lines | Delta |
|---|---:|---:|---:|
| Fixed SSH Git observer and Pi boundary integration | 560 | 941 | +381 |
| Hidden checkpoint status/SFTP preflight, temporary index, limits, deadline, and warnings | 460 | 1,003 | +543 |

The remaining issue #68 work is now limited to deterministic local export/API integration, shutdown/cleanup integration, and evidence helpers:

| Remaining area | Production estimate |
|---|---:|
| Deterministic local export, hashes, manifest, skill metadata, and API descriptor | 700 |
| Shutdown integration and cleanup | 180 |
| Benchmark/evidence metadata helpers | 140 |
| **Remaining estimate** | **1,020** |
| **50% contingency** | **510** |
| **Required remaining allowance** | **1,530** |

The current **18,300** cap leaves `18,300 - 17,658 = 642` lines of headroom, which is `1,020 - 642 = 378` lines below the remaining estimate before contingency. Applying the 50% contingency requires `17,658 + 1,530 = 19,188` total production lines. Rounding to the nearest practical cap gives **19,200** lines.

This overrun is numeric planning variance from measured strict security implementation, not architecture or scope expansion.

## Decision

Amend only ADR 0024's numeric issue #68 production `src/**/*.ts` cap from **18,300** to **19,200** lines.

ADR 0022 remains authoritative for architecture, trust boundaries, API scope, evidence, and exclusions. This ADR preserves all existing ADR 0022 and ADR 0024 boundaries and authorizes no new dependency, cloud/object storage, archive format, restore, sanitization/anonymization, Git transport expansion, launch-schema expansion, public Git lookup endpoint, release, deployment, or production-readiness claim.

No security compression is authorized. If implementation would exceed **19,200** production `src/**/*.ts` lines, stop for another measured decision rather than weakening validation, cleanup, fail-closed behavior, redaction, metadata-only constraints, or other security boundaries.

## Consequences

Issue #68 has 1,542 lines of measured headroom from the current 17,658-line implementation, including 522 lines above the remaining estimate. This is a numeric-only amendment and no later issue may reuse it.
