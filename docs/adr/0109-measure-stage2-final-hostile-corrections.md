# ADR 0109: Measure final Stage 2 hostile-review corrections

- Status: Accepted by the owner's standing non-AWS instruction in this conversation
- Date: 2026-08-21
- Scope: Exact-head runtime, recovery, failure-evidence, and static-event guard corrections

## Context

Hostile review of `26af976022d559ebc2dc5434dd0df45fe976be77` found deterministic defects in usr-merged executable closure collection, retained-containerd command transactions, post-containerd cleanup recovery, exact first-failure receipts, preparation rollback, and first-created static-event enforcement. Their readable corrections raise the Gate-0 deployment slice to 7,188 lines, 188 above ADR 0107's 7,000 high. Retained and workflow slices, the global high, and the 67,000 hard limit remain satisfied. Current physical and conservative no-deletion-credit measurements are 62,651 and 65,124 lines.

## Decision

Retain exact Gate-0 and complete-workflow accounting. Set non-transferable highs to 8,000 deployment lines, 3,200 retained lines, 900 workflow lines, and 11,000 global post-Gate-0 lines. Set the preferred limit to 66,500 and retain the mandatory hard limit at 67,000. Retain the 1,200-line mutable-owner bridge high.

These highs authorize ordinary final integration and exact-head review only. Deletion, relocation, compressed multi-effect logic, generated/data indirection, and test movement receive no credit.

## Authority boundary

This decision carries the owner's standing authorization through all non-AWS implementation, Docker/Linux tests, exact-head CI, one non-KVM static-control event, reviewed data-only G revision, one Stage 2 KVM qualification, local-result review, and seven-cycle controller implementation/freeze. It grants no AWS credentials, API/provider/OpenTofu/SSM/inventory/campaign execution, deployment, production, release, retry, or fallback. Work stops before AWS execution for fresh authorization.
