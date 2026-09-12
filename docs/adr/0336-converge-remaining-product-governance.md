# ADR 0336: Reconcile the remaining product tranche from an immutable checkpoint

## Status
Accepted integrated non-AWS implementation tranche. It supersedes ADR0335's prospective denial only for the exact protected-main Docker and KVM workflow code, retained root custody, and portable tests. AWS, provider, deployment, release, H/G/Q, readiness and every unlisted path remain denied.

## Immutable retained accounting
Checkpoint `8ca95b1e97447466587bbfae63318d9fce620e68`, tree `dff53b023e8e4ee4bac4897f200124b3daed9de7`, fixes retained product/remediation allocations at 15,537/5,120,000 and 45,200/7,200,000 gross lines/raw UTF-8 added-line bytes. The checker rejects every merge reachable from that checkpoint to the `HEAD` worktree base (`rev-list --min-parents=2`) and requires each successor's sole parent to be its exact predecessor. It then charges every commit and the final staged/worktree diff. Repeated committed replacements are charged each time. It never subtracts deletion or net-size changes; mode-only and deletion changes charge zero, cannot lower prior totals, and still undergo exact path closure.

Identical uncommitted deterministic verification reruns are validation observations, not retained repository additions and receive no future charge. A failed uncommitted draft is recorded only when it is actual replan evidence. Historical measurements remain pinned to the checkpoint; live tests assert bounds, not equality with a historical endpoint.

The one remaining tranche is <=2,000 lines and <=2,000,000 bytes. Retained plus actual consumed additions independently remain below product 18,000/8,000,000, remediation 48,000/11,000,000, and the existing 115,000 hard proof. Its non-transferable allocation is helper 452 (integration 352, lifecycle 100), Docker workflow/tests 550 (the workflow itself <=300), KVM relay 300, governance 553, and final controls/evidence 145; their byte split is 600,000/100,000 after measured final regeneration. Remaining owner limits are lifecycle 100, relay 300, and integration 1,600.
## Exact closure
The independently hashed path/owner matrix is closed. ADR0336, the ADR index, budget JSON, checker, and every budget-governance test are governance paths, never final-controls complement. The exact protected workflows, host custody, KVM driver and their existing portable controls are admitted; no legacy driver/envoy, AWS, provider, release or deploy path is admitted. `scripts/check-image-pins.ts` remains remediation-owned but is not product-admitted. Unknown content, mode, deletion, rename, copy, or ordinary-file mutations reject. The Docker path and every task allocation are independently mutation-tested.

The source-inventory producer serializes at most 262,144 bytes, exactly its consumer cap; boundary tests cover the inclusive limit and limit plus one. This does not enlarge tracked-file or aggregate-byte limits. Correction workflow 6,500 and the independent post-H reserves are unchanged.

## Validation boundary
Implement the complete retained tranche in one integrated change: descriptor-relative helper retirement, protected manual-only product and KVM gates, exact root receipts/restrictions, source-inventory serialization bounds, and portable race/crash/mutation controls. Run only focused tests, type, format, shell, Python, and budget checks. Do not run readiness, a full suite, Docker, KVM, AWS/provider work locally, or dispatch workflows. Commit only after a separately authorized readiness/full gate.
