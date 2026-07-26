# ADR 0061: Raise the hosted failure-path cap after exact-head review

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after independent hostile review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #232](https://github.com/nenb/cogs/pull/232).
- Amendment scope: This ADR amends only ADR 0060's absolute gross-addition maximum for `test/aws-stage2-completion-rootfs-candidate.py`, from 470 to 570, and the corresponding excluded three-file total maximum, from 610 to 710. The TypeScript wrapper maximum remains 30 and the workflow maximum remains 110. Every other ADR 0057–0060 requirement remains binding.

## Context

ADR 0060 authorized ordinary-readable corrections for the hosted qualification driver's already-required acquisition, absolute budget, baseline bootstrap, two-build sequencing, bounded recovery, exact cleanup, final descriptor observation, and per-F1–F6 descriptor restoration. It raised the candidate Python maximum to 470 and the excluded three-file total to 610 without changing the workflow maximum or any production or execution boundary.

A fresh exact-head review found two unresolved P1 failure-path gaps in that excluded driver:

1. the guard for the absolute `anchor + 600` acquisition boundary was armed only after work capable of consuming that interval had begun, so the driver did not independently enforce the boundary across the complete acquisition envelope; and
2. if acquisition failed after one or more fixed artifacts had completed, those files lacked exact partial-cache cleanup authority because the coordinator had not incrementally captured their exact post-verified identities for the already-required cleanup route.

The first gap is a guard-placement defect, not a request for a longer or resettable deadline. The second is a missing handoff of exact cleanup evidence, not authority for broad deletion: unknown, incomplete, changed, or mismatched files must still be preserved as uncertainty.

The ordinary-readable tested correction is 541 gross added physical lines in the candidate Python file, compared with ADR 0060's 470-line maximum:

| Candidate-driver responsibility | Gross lines |
| --- | ---: |
| Retained reviewed driver behavior | 323 |
| Qualification fd inventory | 14 |
| Absolute-deadline envelope | 15 |
| Exact partial-cache capture | 38 |
| Hosted coordinator | 151 |
| **Measured candidate-driver total** | **541** |

The correction does not fit 470 without deleting or compressing reviewable deadline, identity, cleanup, and error-aggregation logic. Neither deletion nor presentation compression is valid budget credit.

## Decision

If accepted, raise only the two excluded numeric maxima needed to retain the tested correction in ordinary-readable form.

The candidate driver's existing `--hosted-exact` route must arm its guard before any checkout, source preparation, acquisition, or post-verification work that is charged to the inherited absolute `anchor + 600` envelope. The guard remains derived from the original monotonic anchor and the unchanged absolute boundary. It may not reset, borrow from a later reserve, extend a production deadline, add a retry, or create another invocation route.

As each fixed artifact completes the existing hardened acquisition and exact post-verification, the driver must capture the exact identity required by the inherited cleanup contract. On a mid-acquisition failure, it may pass only those captured, completed fixed files to the existing exact cleanup path. Cleanup must remain identity-bound and preserve every incomplete, uncaptured, changed, mismatched, or uncertain file. This supplies evidence for already-required partial-cache cleanup; it does not create new ownership, deletion, recovery, or production authority.

These two corrections remain excluded qualification coordination. They may not define or change production acquisition, transaction, parser, automaton, ownership, reconciliation, recovery, cleanup, canonicalization, publication, pin, or report semantics.

The reviewed exact head remains blocked and is not ADR 0057's signed-off `H`. After this bounded correction and exact remeasurement, the complete new exact head requires the inherited clean independent exact-head review. Any subsequent change invalidates that signoff. This ADR adds no review, event, candidate, rerun, or execution authority.

## Revised excluded maxima and honest headroom

Gross additions remain measured against exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`; deletions create no credit. File allowances are non-transferable.

| Excluded file | Absolute maximum gross additions |
| --- | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **570** |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **110** |
| **Excluded three-file total** | **710** |

The candidate correction measures 541 lines, so 570 leaves **29 lines** of honest file headroom. At the reviewed exact head, the unchanged TypeScript wrapper and workflow consume 138 gross additions combined; therefore the measured corrected three-file total is `541 + 138 = 679`, and 710 leaves **31 lines** of honest total headroom. The two extra total lines reflect only the unused portion of the unchanged wrapper/workflow maxima. Neither margin is deletion credit, compression credit, transferable allowance, or authority for another behavior.

Only the candidate Python maximum changes from 470 to 570 and the excluded total changes from 610 to 710. The TypeScript maximum of 30 and workflow maximum of 110 remain unchanged. Stop and replan before exceeding a file maximum or the total, changing another implementation file, moving logic into the wrapper or workflow, or requiring behavior beyond the two exact P1 corrections.

ADR 0057's six production files and 565-line production maximum, ADR 0049's preferred 32,000 and hard 34,000 cumulative counted caps, and every other hard production, companion, workflow, and cumulative cap remain unchanged. These excluded lines create no counted-set credit, production funding, or later-stage allowance.

## Acceptance criteria

This amendment is satisfied only when all of the following hold:

- exact-baseline gross additions are at most 570 for the candidate Python file, at most 30 for the TypeScript wrapper, at most 110 for the workflow, and at most 710 across the three files, with no deletion credit;
- the Python remains ordinarily formatted and reviewable at the measured 541-line correction rather than being compressed to manufacture margin;
- the absolute `anchor + 600` guard encloses all work charged to that boundary from before the first such operation, while every inherited `+600`, `+3900`, `+4500`, `+5100`, and `+5400` boundary remains unchanged and non-borrowing;
- a failure after any completed fixed-file acquisition has exact post-verified partial-cache evidence for inherited cleanup, while incomplete, uncaptured, changed, mismatched, and uncertain files remain preserved;
- tests cover guard activation before acquisition, failure within the acquisition envelope, completed-file capture across mid-acquisition failure, exact cleanup, mismatch preservation, and aggregated failure/close behavior without adding a command, retry, recovery pass, or execution route;
- the new exact head receives the inherited clean independent final review with no unresolved P0–P3 finding, and its review records the exact gross counts and both corrected P1 paths; and
- no production, authority, event, deadline, recovery, workflow, candidate, report, stage, campaign, cloud, or AWS behavior changes.

## Retained scope and consequences

Every non-conflicting ADR 0057–0060 requirement remains binding, including the exact base and branch, six F1–F6 faults, one clean final exact-head signoff, one ready event, one hosted run at attempt 1, exact 5,400-second allocation, exact 16 artifacts, two builds, mandatory stop, and all Phase B, later-stage, step-5, campaign, production, release, issue-closure, cloud, and AWS prohibitions.

The consequence is a larger excluded-code allowance for a tested, readable implementation of two inherited failure-path obligations. The acquisition deadline becomes enforceable over its complete existing envelope, and completed fixed files can be cleaned exactly after a mid-acquisition failure without broadening cleanup authority. The cost is 100 additional lines of candidate-file and excluded-total capacity; every fixed behavior, hard counted cap, and operational stop remains unchanged.

This documentation-only proposal creates no implementation, test change, workflow change, command, test execution, review, branch, commit, pull request, event, acquisition, network operation, hosted run, candidate, report, cloud resource, or AWS action.
