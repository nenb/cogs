# ADR 0021: Raise issue #67 final integration line budget

## Header

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Reviewed by: delegated project lead
- Acceptance: Accepted by delegated project lead on 2026-07-17 under Nick Byrne’s explicit instruction: when a decision is required I let you make it based on what you think best.
- Supersedes: ADR 0020 numeric issue #67 production `src/**/*.ts` line cap only.

## Context

ADR 0020 accepted the issue #67 skill provenance and project context architecture, stop gates, and an absolute production TypeScript cap of **14,400** lines measured from the clean issue #67 baseline of **11,862** lines.

After the accepted bounded slices for canonical skill bundles, private user snapshots/store, and local shared OCI Image Layout resolution, the current measured production TypeScript count is **13,287** lines. The remaining ADR 0020 headroom is therefore **1,113** lines.

A docs-only final integration plan measured the remaining strict implementation work against clean `main` at `fcd3754f38d9644877f7c9f84df49d3d1d93eec6`. The high estimate for the required final integration is **1,450** production lines, with approximately **350** lines of contingency recommended so the implementation does not compress security-critical validation, startup ordering, SFTP materialization, Pi prompt provenance, metadata handoff, or cleanup paths.

The delegated project lead accepted the measured need for a cap amendment to **15,100** lines and clarified that ADR 0020 architecture, stop gates, and non-expansion constraints remain in force.

## Decision

Amend only the numeric issue #67 production TypeScript line cap from ADR 0020.

Until issue #67 is closed, production TypeScript under `src/` may grow up to an absolute cap of **15,100** lines.

The amended cap is based on:

| Item | Production `src/` TypeScript lines |
|---|---:|
| Clean issue #67 baseline from ADR 0020 | 11,862 |
| Current measured count after accepted issue #67 slices | 13,287 |
| Remaining strict final integration high estimate | 1,450 |
| Approximate contingency for strict review changes | 350 |
| Accepted amended absolute cap | 15,100 |

This ADR does not authorize any architecture, scope, artifact, dependency, runtime, distribution, telemetry, persistence, or release expansion beyond ADR 0020. ADR 0020 remains authoritative for issue #67 except where its numeric production line cap and numeric stop gate are superseded by this ADR.

## Preserved ADR 0020 constraints

The following ADR 0020 constraints remain unchanged:

- canonical uncompressed JSON skill bundles only;
- shared skills resolved only from trusted local OCI Image Layout with `shared_revision` as an OCI manifest digest;
- private skills snapshotted at startup from trusted local user source and matched to required `user_revision`;
- strict closed Pi resource loading and trusted eager prompt provenance;
- bounded SFTP guest materialization with no shell, no tar, no guest unpacker, no remote registry, and no read-only enforcement claim without runtime support and evidence;
- bounded nonfatal `/workspace/AGENTS.md` handling as untrusted project context;
- required skill provenance before model API key resolution;
- metadata-only telemetry/export boundaries, with issue #68 owning persistence/export inclusion;
- no production dependencies, cloud resources, AWS/EKS/deployment work, remote registry access, object-store credentials, guest registry/object-store capabilities, release artifacts, production-readiness claims, or artifact distribution claims.

## Stop gates and non-expansion

Stop for a new ADR or explicit owner/lead review before any of the following:

- exceeding **15,100** production `src/` TypeScript lines for issue #67;
- changing any ADR 0020 architecture, scope, startup-ordering, provenance, SFTP, Pi-loading, project-context, metadata, telemetry/export, dependency, cloud, remote-registry, object-store, release, or production-readiness boundary.

All other ADR 0020 stop gates continue to apply as written.

## Consequences

Issue #67 can complete the measured final integration without weakening validation, prompt provenance, SFTP integrity checks, metadata minimization, or cleanup paths.

This is an issue-specific line-budget amendment only. It does not reopen or reuse issue #66 line-budget exceptions and does not create a general Stage 3 budget.
