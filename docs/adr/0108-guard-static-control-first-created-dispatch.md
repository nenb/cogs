# ADR 0108: Guard the static-control first-created dispatch

- Status: Accepted by the owner's issue-42 round-three correction instruction
- Date: 2026-08-21
- Scope: Static-control workflow admission only

## Context

At reviewed implementation head `26af976022d559ebc2dc5434dd0df45fe976be77`, the optional no-KVM static-control workflow relied on `run_attempt == 1` and a concurrency group. Those controls do not prevent two separately created workflow-dispatch runs from reaching source checkout and immutable acquisition.

## Decision

Before checkout, materialization, or acquisition, run a separate fixed static-control guard embedded byte-for-byte in the workflow. It accepts only the globally earliest numeric run ID in a complete, single-page, at-most-100-run Actions history for the fixed same-repository workflow. Every observed run must be an attempt-one `workflow_dispatch` at the same workflow head, path, repository, head repository, and reviewed-H run title. The current event must independently bind protected `main`, the fixed repository, fixed workflow reference, and exact reviewed H. A rerun, second run ID, foreign identity, duplicate, pagination, count/list mismatch, over-bound history, malformed response, or API failure rejects.

The guard uses the unauthenticated public Actions API. Workflow permissions are `actions: read` only; no contents/write/OIDC permission, GitHub token, secret, or credential is supplied. Exact H is subsequently fetched from the fixed public repository without credentials.

The guard is added to centralized retained accounting. The corrected tree measures 61,676 current physical lines and 64,101 conservative no-deletion-credit lines. Gate-0 correction slices are 6,165 deployment, 1,907 explicitly retained, 675 workflow, and 8,747 global gross added lines, all below ADR 0107's non-transferable highs and the 67,000 hard limit.

## Authority boundary

This correction authorizes no dispatch, rerun, source materialization, acquisition, artifact, KVM action, runtime change, AWS action, campaign, production use, or release. It changes static-control admission and its hostile/static tests only. The final KVM guard remains separate and unchanged.
