# ADR 0024: Raise issue #68 cap after detailed integration replan

## Header

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Reviewed by: delegated project lead
- Acceptance: Accepted under Nick Byrne's explicit delegation to continue autonomously and make project decisions without waiting.
- Supersedes: ADR 0023 numeric issue #68 production `src/**/*.ts` line cap only.

## Context

ADR 0023 raised only the issue #68 production TypeScript cap to **18,100** lines from the current **15,714**-line baseline. Its preliminary remaining-work table estimated 1,820 lines plus contingency.

A subsequent file-by-file integration replan against merged `main` at `9a434c3` measured the remaining readable work more precisely:

| Remaining area | Production estimate |
|---|---:|
| Git boundary coordinator, fixed SSH observer, ancestry, pending first turn, notes, and events | 560 |
| Hidden checkpoint status/SFTP preflight, temporary index, limits, deadline, and warnings | 460 |
| Deterministic local export, hashes, manifest, skill metadata, and API descriptor | 700 |
| Shutdown integration and cleanup | 180 |
| Benchmark/evidence metadata helpers | 140 |
| **Remaining estimate** | **2,040** |
| **25% contingency** | **510** |
| **Required remaining allowance** | **2,550** |

`15,714 + 2,550 = 18,264`. ADR 0023 provides only 2,386 lines of headroom, 164 lines below the measured allowance. The difference is numeric planning precision, not architecture or scope expansion.

## Decision

Amend only ADR 0023's numeric issue #68 production `src/**/*.ts` cap from **18,100** to **18,300** lines.

ADR 0022 remains authoritative for architecture, trust boundaries, API scope, evidence, and exclusions. ADR 0023's preserved-boundary list also remains unchanged. This ADR authorizes no new dependency, cloud/object storage, archive, restore, sanitization, Git transport, launch schema, public endpoint, release, deployment, or production-readiness work.

If implementation would exceed **18,300** lines, stop for another measured decision rather than compressing validation or cleanup.

## Consequences

Issue #68 has 2,586 lines of measured headroom from the current baseline, including 546 lines above the readable remaining estimate. This is a numeric-only amendment and no later issue may reuse it.
