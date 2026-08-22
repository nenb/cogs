# ADR 0126: Authenticate and stabilize the KVM dispatch observation

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Pre-effect first-created guard for the replacement local KVM qualification
- Supersedes: ADR 0125's qualification-workflow hash only

## Context

Independent hostile review of control revision `d9ce4a44cde11c755c656a1d72c8655f1f448394` found that the irreversible first-created guard used one unauthenticated Actions API read. Shared-IP rate limiting or ordinary workflow-list visibility lag could therefore consume the sole authorized dispatch before KVM without providing a meaningful observation. No KVM workflow had been dispatched.

## Decision

Pass the job-scoped `${{ secrets.GITHUB_TOKEN }}` only to the guard as `ACTIONS_READ_TOKEN` under existing `actions: read` and `contents: read` permissions. Reject missing, non-ASCII, whitespace-bearing, or over-1,024-byte token values. Deny ambient `GITHUB_TOKEN` and `GH_TOKEN` names outside this explicit seam.

Use an opener with an empty proxy map and fatal redirects. Send the token only in the HTTPS `Authorization: Bearer` header to the fixed same-repository Actions endpoint. Keep response and history bounds. Before any H checkout, immutable preparation, KVM, runtime, network, or task effect, require the current run ID to appear in two consecutive identical bounded snapshots. Permit at most six visibility observations two seconds apart; any API error, malformed/incomplete history, unstable final state, or token defect fails closed. This is pre-effect admission consistency, not a qualification retry.

The reviewed qualification-workflow SHA-256 becomes `a3b332f2dd951afe380ea9fe80589780e0dff841320c36422d0af3f52805d092`. All H, source-manifest, control, and result-schema bindings remain unchanged.

## Authority boundary

This correction authorizes no extra dispatch. It preserves exactly one first-created attempt-one replacement Stage 2 KVM/Kata qualification after exact-head review and CI. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, or release authority.
