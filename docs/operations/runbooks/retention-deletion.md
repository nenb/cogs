# Draft backup, retention, export, and deletion guide

This guide describes data-lifecycle intent and validation. It contains no storage or deletion command. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| Future daemon/platform may authenticate subjects/admins, map opaque IDs, perform backend deletion/version handling, and disclose holds. | [Authority: DESIGN active state and deletion boundary](../../../DESIGN.md#141-authoritative-active-state) |
| Object storage may hold graceful-shutdown bundles; crash recovery and version deletion remain unverified. | [Authority: DESIGN active state recovery point](../../../DESIGN.md#141-authoritative-active-state) |
| A future organization defines jurisdictional policy; this draft makes no compliance claim. | [Authority: provisional unsupported compliance claim](../stage-5-api-key-release-acceptance-matrix.md#unsupported-capabilities-and-claims) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Workspace is sandbox-only retained 20 GiB and persists until explicit workspace deletion. | [Authority: storage/launch durable roles](../stage-4-storage-launch-contract.md#separate-durable-storage-roles) |
| Pi state is trusted-only retained 5 GiB with 30-day post-close default. | [Authority: storage/launch durable roles](../stage-4-storage-launch-contract.md#separate-durable-storage-roles) |
| Configured graceful-shutdown object bundle has 30-day default; declared recovery point is graceful shutdown. | [Authority: DESIGN active state](../../../DESIGN.md#141-authoritative-active-state) |
| Raw export requires authenticated non-tool action, is sensitive, and omits attachments by default. | [Authority: DESIGN export bundle](../../../DESIGN.md#142-export-bundle) |
| Skill snapshots are immutable/revisioned; their lifecycle is external to session state. | [Authority: DESIGN skills and context](../../../DESIGN.md#13-skills-and-context) |
| Central telemetry is metadata-only with separately configured/disclosed retention. | [Authority: DESIGN privacy defaults](../../../DESIGN.md#162-privacy-defaults) |
| Guest rootfs and `/tmp` are ephemeral and not durable backup. | [Authority: DESIGN guest filesystem](../../../DESIGN.md#95-guest-filesystem) |
| Deletion includes active/object versions where supported, except disclosed hold/retention; uncertainty preserves attachments/lease and forbids expiry takeover. | [Authority: DESIGN active state deletion](../../../DESIGN.md#141-authoritative-active-state) and [storage lease](../stage-4-storage-launch-contract.md#exclusive-writer-lease) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Stage 3 covers trusted JSONL, paged history, raw export package, attachment exclusion, Git/skill references, and local cleanup within profile. | [Authority: Stage 3 exit evidence](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#automatic-acceptance) |
| It proves no cloud object versions, CSI reclaim, snapshots, legal holds, restoration, multi-tenant authorization, or retention automation. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Use synthetic subjects; prove exact subject/admin authorization and cross-user denial. | [Planned DESIGN-24.19 and STAGE5-45.09 / `future-privacy-deletion-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Inventory active state, retained volumes, objects/versions, exports, snapshots, logs/audit/crash artifacts, and later indexes. | [Planned STAGE5-45.09, .11 / `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe timers, close time, hold separation, per-object receipt, partial failure, retry authority, and independent absence. | [Planned STAGE5-45.09, .11 / `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Distinguish explicit workspace deletion from session close. | [Planned STAGE5-45.09 / `future-privacy-deletion-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Verify declared restoration point/integrity without calling graceful bundle crash-consistent. | [Planned STAGE5-45.09 / `future-privacy-deletion-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Scan central sinks for forbidden prompt/source/secret/query/body/command/path/tool content. | [Planned DESIGN-24.22 and STAGE5-45.08–.09 / `future-load-reference-v1`, `future-independent-review-reference-v1`, `future-privacy-deletion-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |

## Retention review

**Section authority:** [Authority: DESIGN authoritative active state](../../../DESIGN.md#141-authoritative-active-state).

For each data class, bind owner, opaque subject/workspace/session reference, purpose, trust domain, creation/close timestamp, retention basis, expiry, legal hold, backend/versioning behavior, access roles, and evidence reference. Missing mapping or conflicting ownership is `preserve-uncertain`; it does not authorize deletion.

## Explicit deletion flow

**Section authority:** [Planned STAGE5-45.09 / `future-privacy-deletion-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability).

1. Authenticate the requester and authorization purpose outside Cogs.
2. Resolve exact kind-specific subject, workspace, session, and storage references; prove they belong to the same immutable ownership graph.
3. Freeze new writes and admissions for that exact scope. Set a deletion intent with fencing; concurrent writer, attachment, detach, or lease uncertainty blocks mutation.
4. Enumerate the fixed data classes from the approved lifecycle record, not a discovered prefix or wildcard.
5. Apply legal hold before ordinary retention. A hold blocks deletion but must not be represented as successful deletion.
6. Delete only per-object identities whose ownership and lifecycle state are exact. Preserve mismatches and escalate; never recursively delete a parent discovered at runtime.
7. Record categorical per-object outcomes and independently verify the expected absence/preservation split.
8. Report partial or unknown outcomes as incomplete. Do not issue a blanket success receipt.

Raw exports already delivered to a user or external share destination may be outside platform custody; disclose that limitation rather than claiming deletion.
