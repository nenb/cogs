# ADR 0336: Reconcile the remaining product tranche from an immutable checkpoint

## Status
Plan-only amendment. It supersedes only ADR0335's prospective charging: no runtime, readiness, full suite, workflow, Docker, KVM, H/G/Q, release, deployment, provider, or AWS authority is granted.

## Immutable retained accounting
Checkpoint `8ca95b1e97447466587bbfae63318d9fce620e68`, tree `dff53b023e8e4ee4bac4897f200124b3daed9de7`, fixes retained product/remediation allocations at 15,537/5,120,000 and 45,200/7,200,000 gross lines/raw UTF-8 added-line bytes. The checker rejects every merge reachable from that checkpoint to the `HEAD` worktree base (`rev-list --min-parents=2`) and requires each successor's sole parent to be its exact predecessor. It then charges every commit and the final staged/worktree diff. Repeated committed replacements are charged each time. It never subtracts deletion or net-size changes; mode-only and deletion changes charge zero, cannot lower prior totals, and still undergo exact path closure.

Identical uncommitted deterministic verification reruns are validation observations, not retained repository additions and receive no future charge. A failed uncommitted draft is recorded only when it is actual replan evidence. Historical measurements remain pinned to the checkpoint; live tests assert bounds, not equality with a historical endpoint.

The one remaining tranche is <=2,000 lines and <=2,000,000 bytes. Retained plus actual consumed additions independently remain below product 18,000/8,000,000, remediation 48,000/11,000,000, and the existing 115,000 hard proof. Its non-transferable allocation is helper 350 (integration 250, lifecycle 100), Docker workflow/tests 550 (the workflow itself <=300), KVM relay 300, governance 500, and final controls/evidence 300. Remaining owner limits are lifecycle 100, relay 300, and integration 1,600.
## Exact closure
The independently hashed path/owner matrix is closed. ADR0336, the ADR index, budget JSON, checker, and every budget-governance test are governance paths, never final-controls complement. `scripts/check-image-pins.ts` remains remediation-owned but is not product-admitted: it has no Q-relative added bytes requiring reviewed admission. All operational AWS, provider, release, deploy, and image paths are denied; the retained AWS-named bookkeeping tests are inert tests, not provider surfaces. Unknown content, mode, deletion, rename, copy, or ordinary-file mutations reject. The Docker path and every task allocation are independently mutation-tested.

The source-inventory producer serializes at most 262,144 bytes, exactly its consumer cap; boundary tests cover the inclusive limit and limit plus one. This does not enlarge tracked-file or aggregate-byte limits. Correction workflow 6,500 and the independent post-H reserves are unchanged.

## Validation boundary
Change only this plan, the existing budget/checker/test controls, and the bounded producer check. Run targeted governance, budget, format, and diff checks only; do not regenerate readiness evidence or run runtime/full/Docker/KVM/AWS/provider/release work. Commit only if those checks are green.
