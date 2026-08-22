# ADR 0107: Measure Stage 2 preparation and recovery integration

- Status: Accepted by the owner's standing non-AWS instruction in this conversation
- Date: 2026-08-21
- Scope: Review-mandated fresh-runner preparation, durable recovery, and their exact integration

## Context

Hostile exact-head review of `b5750556bfd8a65b3cd32b9c7179e438b74c3611` found that a fresh qualification runner had no exact route to acquire and stage the 16 rootfs inputs, two runtime archives, or Kata installation; executable custody required containerd and ctr before their staging route; and cleanup-only recovery could not reconstruct process-local owner state from a durable operation. The review also required complete tokenized outer settlement and certain typed failure evidence, measured by ADR 0106.

The three independently implemented corrections were integrated without deletion credit. At the integrated pre-readiness worktree they measure 61,325 current physical lines and 63,750 conservative no-deletion-credit lines. Relative to ADR 0105 Gate 0, the slices are 6,165 deployment, 1,742 explicitly retained, 489 workflow, and 8,396 global gross added lines. The deployment slice exceeds ADR 0106's 5,750 high by 415 lines while its global and hard limits remain satisfied. Mutable owner bridges measure 795 lines against the prior 900-line high.

This is additional readable implementation of review-mandated ownership, acquisition, archive verification, staging, recovery reconstruction, settlement, and evidence behavior. It is not deletion credit or authority to compress or relocate security logic.

## Decision

Retain the exact Gate 0 checkpoint and complete workflow accounting. Set non-transferable gross-addition highs to 7,000 deployment lines, 3,000 explicitly retained lines, 700 workflow lines, and 10,500 global post-Gate-0 lines. Raise the mutable-owner bridge high to 1,200 lines. Set the complete preferred limit to 66,000 and mandatory hard limit to 67,000 for both physical and conservative no-deletion-credit measurements.

The highs allow ordinary exact-head integration and hostile-review corrections while preserving independent slice enforcement. Deletion, test relocation, workflow relocation, generated/data indirection, compressed multi-effect lines, and renaming remain ineligible for credit.

Fresh-runner preparation must finish before executable custody and before KVM, QMP, network, containerd start, task, or SSH. It may acquire only the already pinned immutable public assets through fixed bounded routes and must remove transaction-owned staging on every failure. Durable recovery may reopen only exact existing ownership and continue historical cleanup; it cannot acquire, create, launch, authenticate, sample, retry, or mint a passing receipt.

## Authority boundary

This decision authorizes all remaining non-AWS correction, local/Docker tests, exact-head CI, the one non-KVM static-control candidate event, data-only reviewed control revision, and one replacement Stage 2 KVM qualification under the owner's standing instruction. It grants no AWS credential, API, provider, OpenTofu, SSM, inventory, campaign, deployment, production, release, or retry authority. Work must stop before AWS execution and request fresh authorization.
