# ADR 0023: Raise issue #68 remaining-work line budget

## Header

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Reviewed by: delegated project lead
- Acceptance: Accepted under Nick Byrne's explicit delegation to continue autonomously and make project decisions without waiting.
- Supersedes: ADR 0022 numeric issue #68 production `src/**/*.ts` line cap only.

## Context

ADR 0022 accepted the issue #68 native Pi JSONL, Git observation/checkpoint, and local raw-export architecture with an absolute production TypeScript cap of **17,200** lines. Its clean baseline was **14,495** lines.

Two independently reviewed slices are now merged:

1. durable native Pi JSONL paging and file/directory fsync before settled acknowledgment; and
2. the trusted append-only Git mapping sidecar and internal exact/inferred/pre-Cogs resolver.

The current clean `main` baseline at `9a434c3` is **15,714** production `src/**/*.ts` lines. The two strict slices added **1,219** lines against their initial combined estimate of 690. The extra lines preserve streaming validation, inode and directory identity checks, hostile-object snapshotting, append uncertainty poisoning, canonical sidecar records, non-fabricated lookup results, and cleanup. They are not scope expansion.

Only **1,486** lines remain under ADR 0022. A measured replan of the still-required acceptance work is:

| Remaining area | Readable production estimate |
|---|---:|
| Fixed-command SSH Git observer, Pi boundary coordinator, ancestry, notes, and events | 500 |
| Optional hidden checkpoint with temporary index, SFTP preflight, limits, deadline, and warnings | 600 |
| Deterministic local export directory, hashes, skill metadata, transform report, and API descriptor | 470 |
| Graceful-shutdown integration, cleanup, and benchmark/evidence helpers | 250 |
| **Remaining estimate** | **1,820** |
| **25% contingency** | **455** |
| **Required headroom from current baseline** | **2,275** |

`15,714 + 2,275 = 17,989`. A rounded cap of **18,100** leaves 2,386 lines from the current baseline, including 566 lines of contingency over the readable estimate. The cap remains below a general Stage 3 allowance and applies only until issue #68 closes.

## Decision

Amend only ADR 0022's numeric issue #68 production TypeScript cap from **17,200** to **18,100** lines.

ADR 0022 remains authoritative for all architecture, trust, API, evidence, and non-expansion decisions. In particular, this amendment does not authorize:

- a second transcript or rewriting native Pi JSONL;
- treating guest-reported Git state as attested;
- failing completed turns merely because optional Git observation, notes, or checkpoint work is unavailable;
- false exact mappings after trusted sidecar failure;
- arbitrary shell/model-command parsing, note pushing, remote configuration, or broader Git transport;
- launch-schema expansion, multiple repositories, submodules, Git LFS restoration, or workspace/chat restore;
- archives, compression, new production dependencies, object storage, cloud credentials, AWS/EKS work, or share links;
- sanitization/anonymization, release, deployment, production-readiness, or distribution claims;
- exposing raw export as a model-callable tool or adding a public Git lookup endpoint.

The remaining implementation must preserve readable validation and cleanup. If it would exceed **18,100** lines, stop for another measured decision rather than compressing security boundaries.

## Consequences

Issue #68 can complete its measured local session/Git/export work without weakening durability, untrusted-observation semantics, checkpoint resource limits, deterministic export validation, or cleanup.

This ADR changes one number only. It does not amend any other ADR 0022 decision and creates no reusable budget for later issues.
