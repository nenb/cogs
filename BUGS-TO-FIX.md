# Bugs to Fix

Status: explicitly accepted and deferred by the owner for the single bounded Issue #42 Stage 2 campaign. These findings remain recorded work; this disposition does not claim that they are fixed, authorize a retry, close Issue #42, or grant Stage 4 authority.

This post-Q revision is documentation/governance only. It does not change H, G, Q, the qualified implementation, any workflow, or any campaign executable.

## 1. Create protected planning revision R

- R must differ from H, G, and Q.
- It should record your explicit risk overrides and contain no unintended campaign implementation changes.
- Pass protected CI and review the complete R tree.

Disposition: the protected commit containing this document is intended to establish R after CI and complete-tree review.

## 2. Resolve or explicitly accept the remaining P2 findings

- fixed/ungrounded pricing;
- budget-email artifact retention;
- non-reconstructable published inventory pages;
- stale campaign runbook.

The inventory finding is particularly relevant to closing #42: a successful campaign could still lack the independently reviewable zero-resource evidence required by the binding map.

Disposition: the owner explicitly accepts and defers all four findings for this single campaign.

## Additional accepted review findings

The owner also explicitly accepts and defers, for this single campaign:

- the absence of distinct human role holders;
- incomplete automated saved-plan semantic validation, with exact manual plan review used as the compensating control;
- the post-Q campaign revision's credentialed/root stager not being mechanically required to equal the qualified H copy, with complete-R review and unchanged executable bytes used as compensating controls.

The existing runner-loss policy remains unchanged: runner loss is failed or uncertain, grants no success or retry authority, and may require separately verified manual cleanup. The AWS planning and destructive campaign authorization phrases remain separate mandatory gates.

## 3. Retire the first protected planning generation unused

Protected R `73e4188ff306ead82cfa1b9c35729a7e25030c17` produced the sole successful attempt-one read-only planning run `35041075222` and artifact `10424913996` (`sha256:5b758ef52b8d042ca9c4de7e00dc3251dc6afe17b22663f97a56578e13db559c`). Independent readback and expanded review accepted all seven exact saved plans, but the operator intentionally did not issue approval or dispatch the campaign before their admission window closed. No campaign resource was created, and the read-only planning role was removed.

Disposition: that planning generation is historical, non-authorizing, expired, and must never be reused or retried at R. A protected documentation/governance-only direct successor R2 may support one separately authorized fresh planning observation only after the planning, executor, and inventory-observer roles are preconfigured and verified and a fully supervised campaign window is available. R2 does not change or repeat H/G/Q, alter campaign or workflow bytes, approve resource creation, authorize the destructive campaign, or close Issue #42.
