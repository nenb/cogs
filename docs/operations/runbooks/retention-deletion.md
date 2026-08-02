# Draft backup, retention, export, and deletion guide

This guide describes data-lifecycle intent and validation. It contains no storage or deletion command. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future daemon/platform will authenticate the data subject or authorized administrator, map opaque IDs to owned storage, execute backend-specific deletion, handle object versions, and disclose legal holds.
- Object storage may be configured for graceful-shutdown bundles; crash-consistent recovery and backend version deletion vary and are unverified.
- A future organization will define jurisdictional policy. This draft makes no compliance claim.

## Static contract facts

| Data | Location/trust | Default lifecycle |
|---|---|---|
| Workspace | sandbox-only retained 20 GiB role | persists across session end until explicit workspace deletion |
| Pi JSONL/session state | trusted-only retained 5 GiB role | active authority; retain 30 days after session close |
| Graceful-shutdown bundle/object copy | platform object store if configured | default 30 days; initial declared recovery point is graceful shutdown |
| Raw export | authenticated non-tool API | explicit user action; sensitive; attachments omitted by default |
| Shared/private skill snapshots | trusted materialized immutable artifact | revision recorded; lifecycle external to this session-state guide |
| Central telemetry/audit | metadata only | retention must be separately configured and disclosed |
| Guest rootfs and `/tmp` | ephemeral | removed with compute; not a durable backup |

Deletion removes active state and object copies, including versions where the backend allows it, unless a disclosed legal hold or separate retention requirement applies. The [storage/launch contract](../stage-4-storage-launch-contract.md) preserves attachments and lease under uncertainty and forbids takeover based on expiry alone.

## Authoritative-local facts

- Stage 3 local evidence covers trusted JSONL, paged history, raw export packaging, attachment exclusion, Git/skill references, and local cleanup within its profile.
- It does not prove cloud object version deletion, CSI reclaim semantics, snapshots, legal holds, backup restoration, multi-tenant authorization, or 30-day automation.

## Future cloud evidence

A future privacy/deletion campaign must use synthetic subjects and establish:

- exact subject/administrator authorization and cross-user denial;
- inventory across active state, retained volumes, object copies/versions, exports, snapshots if any, logs, audit, crash artifacts, and indexes if later added;
- retention timers, close timestamps, legal-hold separation, deletion receipts, failed/partial deletion, retry authority, and independent absence checks;
- workspace explicit-deletion behavior versus ordinary session close;
- restoration point and integrity from a declared backup, without calling a graceful bundle crash-consistent;
- scans proving prompts, source, secrets, query/body data, complete commands, arbitrary paths, and tool output are absent from central sinks.

These are unexecuted `future-privacy-deletion-reference-v1` requirements in the [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md).

## Retention review

For each data class, bind owner, opaque subject/workspace/session reference, purpose, trust domain, creation/close timestamp, retention basis, expiry, legal hold, backend/versioning behavior, access roles, and evidence reference. Missing mapping or conflicting ownership is `preserve-uncertain`; it does not authorize deletion.

## Explicit deletion flow

1. Authenticate the requester and authorization purpose outside Cogs.
2. Resolve exact kind-specific subject, workspace, session, and storage references; prove they belong to the same immutable ownership graph.
3. Freeze new writes and admissions for that exact scope. Set a deletion intent with fencing; concurrent writer, attachment, detach, or lease uncertainty blocks mutation.
4. Enumerate the fixed data classes from the approved lifecycle record, not a discovered prefix or wildcard.
5. Apply legal hold before ordinary retention. A hold blocks deletion but must not be represented as successful deletion.
6. Delete only per-object identities whose ownership and lifecycle state are exact. Preserve mismatches and escalate; never recursively delete a parent discovered at runtime.
7. Record categorical per-object outcomes and independently verify the expected absence/preservation split.
8. Report partial or unknown outcomes as incomplete. Do not issue a blanket success receipt.

Raw exports already delivered to a user or external share destination may be outside platform custody; disclose that limitation rather than claiming deletion.
