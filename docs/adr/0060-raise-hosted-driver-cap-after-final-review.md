# ADR 0060: Raise the hosted qualification driver cap after final review

- Status: Proposed
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Amendment scope: This ADR amends only ADR 0057's absolute gross-addition maximum for `test/aws-stage2-completion-rootfs-candidate.py`, from 370 to 470, and the corresponding excluded three-file total maximum, from 510 to 610. It authorizes only the P1 hosted-driver and P2 per-fault fd-observation corrections below. The workflow maximum remains 110. Every other ADR 0057–0059 requirement remains binding.

## Context

ADR 0057 authorizes one excluded hosted driver to perform its single exact-16-artifact two-build qualification and one excluded six-fault local matrix. ADRs 0058 and 0059 add only the necessary existing Python and TypeScript companions. They do not change the new driver's 370-line maximum, the workflow's 110-line maximum, or ADR 0057's required clean final exact-head signoff.

The independent final review inspected exact blocked head `f40588eae988eb3236bdf654d8db32158621c96f` (`f40588e`) on `feat/issue42-candidate-tar-remediation`. It did not sign off that head. The review blocked on:

- **P1:** the hosted path does not itself close ADR 0057's required hardened acquisition, absolute non-borrowing budget, baseline bootstrap, two-build sequencing, bounded recovery, cache cleanup, and independent final descriptor observation; and
- **P2:** the F1–F6 synthetic cases rely on an end-state inventory rather than a separate fd snapshot around each fault case, so one case can fail to prove its own descriptor restoration.

These are defects in the already-authorized excluded qualification driver. They do not identify or authorize a production transaction, ledger, builder, publication, cleanup, candidate, stage, or workflow-semantics change.

The measured ordinary-readable correction no longer fits the 370-line file maximum. The worker breakdown is exact:

| Driver responsibility | Gross lines |
| --- | ---: |
| Retained reviewed driver behavior | 323 |
| Qualification fd inventory | 14 |
| Absolute-deadline helpers | 15 |
| Direct no-candidate-state hosted coordinator | 118 |
| **Measured driver total** | **470** |

Compressing the hosted coordinator or per-fault fd proofs to retain 370 would make the security-sensitive acquisition, deadline, recovery, cleanup, and descriptor behavior harder to review.

## Decision

If accepted, require only the two blocked-review corrections below and raise only the excluded numeric maxima needed to express them readably.

### P1: close the already-authorized hosted path

Correct `test/aws-stage2-completion-rootfs-candidate.py` so its existing `--hosted-exact` mode directly coordinates all and only the hosted responsibilities already required by ADR 0057:

1. use the existing one-use hardened route to acquire and post-verify exactly the fixed 16 public artifacts within the existing `anchor + 600` source boundary;
2. validate the fixed source approval, bootstrap the exact sentinel/lock rootfs baseline, and establish the pre-run cache, qualification-temporary-state, and process-fd observations required by ADR 0057;
3. derive every phase guard from the existing monotonic anchor and absolute `+600`, `+3900`, `+4500`, `+5100`, and `+5400` boundaries, without borrowing, resetting, extending, or replacing a production deadline;
4. coordinate the existing authentic route directly, without introducing hosted candidate state: build one must finish and clean exactly before build two begins; build-two authority is blocked by build-one failure; both builds use fresh plans, tokens, operation state, and anonymous candidate inodes; and the existing equality and fixed-pin requirements remain exact;
5. permit at most the one already-authorized fresh exact recovery pass, only when it was not consumed inline and its complete permitted interval fits the existing recovery boundary;
6. on success or failure, perform only the already-required exact qualification-temporary and cache cleanup, preserving uncertainty and aggregating primary, recovery, cleanup, and close failures; and
7. finish with the existing independent read-only sentinel/lock, pre-run-cache-baseline, temporary-state, and driver/workflow-created-fd observations before the unchanged final boundary.

The direct coordinator is excluded qualification code only. It may call existing fixed production capabilities but may not define or change production acquisition, transaction, parser, automaton, reconciliation, recovery, cleanup, canonicalization, pin, publication, or ownership semantics. It emits no Phase A candidate or accepted/campaign report and creates no candidate-state model or alternate execution route.

### P2: prove descriptor restoration for each F1–F6 case

In the same file, add a stable qualification-process fd inventory and take separate snapshots around each existing F1, F2, F3, F4, F5, and F6 case. Each case must independently prove restoration after its required close, mismatch-preservation probe where applicable, fresh builder recovery, authorized cleanup, and fixture restoration. An end-only snapshot, a snapshot shared across cases, or proof only for the anonymous candidate fd is insufficient.

This correction does not add a fault boundary, vary a cut, change an expected ledger terminal, broaden mismatch behavior, or alter production recovery authority. The six rows, their cuts, and their required outcomes remain exactly those of ADR 0057.

### Blocked head and branch correction remain distinct

`f40588eae988eb3236bdf654d8db32158621c96f` remains the exact blocked review head and is not ADR 0057's signed-off `H`. Apply only the corrections authorized here as subsequent correction work on the existing `feat/issue42-candidate-tar-remediation` branch. Do not amend, relabel, or cite the blocked review as final signoff.

After correction and exact remeasurement, record the new full 40-hex branch head separately and obtain ADR 0057's clean independent final review of the complete exact range `8caab23bb4277121a77d80dc043b3c2c43b07ced..H`. That rereview must resolve the P1 and P2 findings and cover all previously required ADR 0057–0059 scope. Any later correction invalidates that signoff as before. This amendment creates no additional review, ready transition, or execution authority.

## Revised excluded maxima

Gross additions remain measured against exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`; deletions create no credit and allowances are non-transferable.

| Excluded file | Absolute maximum gross additions |
| --- | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **470** |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **110** |
| **Excluded three-file total** | **610** |

Thus only the candidate-driver maximum changes from 370 to 470 and the excluded total maximum changes from 510 to 610. The wrapper maximum remains 30 and the workflow maximum remains 110. The workflow implementation, trigger, permissions, gates, job count, timeout, and semantics receive no correction authority under this ADR. Stop and replan before exceeding either revised maximum, changing another file, moving logic into the wrapper or workflow, or requiring behavior beyond P1 and P2.

These excluded lines create no deletion credit, counted-set credit, production funding, or later-stage allowance. ADR 0057's six production files and 565-line production maximum and ADR 0049's accepted 32,000 preferred and 34,000 hard cumulative caps remain unchanged.

## Retained scope and stops

Every non-conflicting ADR 0057–0059 requirement remains binding, including the exact base and branch, six F1–F6 faults, one clean final exact-head signoff, one ready event, one hosted run at attempt 1, exact 5,400-second allocation, exact 16 artifacts, two builds, mandatory stop, and all Phase B, later-stage, step-5, campaign, production, release, issue-closure, cloud, and AWS prohibitions.

This ADR authorizes no production change, other file, new command or wrapper, workflow change, execution-count increase, timeout increase, counted-cap change, stage change, candidate or report, AWS action, or semantic expansion. No implementation defect outside the exact P1/P2 driver corrections may be fixed under it.

This documentation-only proposal creates no implementation, test change, workflow change, command, test execution, review, branch, commit, pull request, event, acquisition, network operation, hosted run, candidate, report, cloud resource, or AWS action.

## Consequences

The excluded driver can express the already-required hosted lifecycle and independent per-fault fd proofs in ordinary readable code. The review-blocked head remains historical, the corrected branch head requires a new clean exact-head signoff, and every execution, production, counted-cap, stage, candidate, cloud, and AWS boundary remains unchanged.
