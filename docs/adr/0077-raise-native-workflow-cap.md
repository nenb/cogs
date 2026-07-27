# ADR 0077: Raise the native workflow cap after measured readable implementation

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Raise only ADR 0076's gross-addition high for `.github/workflows/ci.yml` from 280 to 360 and the exact five-file excluded aggregate from 2,560 to 2,640. The other four file highs, production caps, Phase B aggregate high, and global projection remain unchanged. This is a cap-only amendment and changes no behavior, scope, run, event, or AWS boundary.

## Context

The readable ADR 0076 checkout-descriptor implementation prepared directly on exact integration predecessor `f422de12756bad20a34aee45a7f622a5b113ab40` measures **345** gross additions in `.github/workflows/ci.yml` from exact excluded-surface baseline `18f26441b6115091233d0c4cd44ced8f058d014f`. The accepted workflow high is 280. The implementation therefore exceeds that high by 65 lines even before final ordinary-readable presentation.

The additional workflow text expresses ADR 0076's already-authorized descriptor authentication, bind verification, closure, and fail-closed transitions. Removing checks, combining transitions, or compressing control flow merely to satisfy the 280-line high is prohibited and would make the trusted boundary harder to review. This measured overage does not identify new behavior or new implementation scope.

## Decision

Raise only these two numeric maxima:

| Excluded surface | ADR 0076 high | ADR 0077 high |
| --- | ---: | ---: |
| `.github/workflows/ci.yml` | 280 | **360** |
| **Exact five-file aggregate** | 2,560 | **2,640** |

Retain every other exact-five-file high unchanged:

| Excluded file | Retained gross-addition high from `18f2644` |
| --- | ---: |
| `test/aws-stage2-completion-kata-process.py` | **750** |
| `test/aws-stage2-completion-kata-process.test.ts` | **80** |
| `test/stage2-phase-a-candidate.py` | **850** |
| `test/stage2-phase-a-candidate.test.ts` | **600** |

The revised per-file maxima sum exactly to the revised aggregate: `360 + 750 + 80 + 850 + 600 = 2,640`. Highs remain non-transferable. Gross additions remain the addition column of the no-rename diff from exact `18f26441b6115091233d0c4cd44ced8f058d014f` to final head. Deletion, replacement, movement, splitting, generated placement, or removal creates no credit.

The final workflow must present security-relevant state and failure transitions in ordinary readable form. It must not collapse transitions, chain unrelated checks, obscure ordering, or compress presentation merely to fit the superseded 280-line high. This readability requirement authorizes no transition, check, command, branch, behavior, or scope beyond ADR 0076; all exact ADR 0076 semantics and fail-closed ordering remain binding.

## Exact correction ancestry

The exact implementation predecessor is current branch integration merge `f422de12756bad20a34aee45a7f622a5b113ab40`. Its first parent is exact ADR 0076 implementation predecessor `d87ff2e3c01ab79505491cb06bbf3cb4efb019e8`, and its second parent is accepted ADR 0076 commit `e32ec35b3e92b01bcda391afa53f42bc3bbeaf56`.

Implementation must start at exactly `f422de12756bad20a34aee45a7f622a5b113ab40` and integrate the exact accepted commit containing this ADR by a history-preserving merge before any ADR 0076 implementation commit. That integration merge must have `f422de12756bad20a34aee45a7f622a5b113ab40` as first parent and the accepted ADR 0077 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from this documentation branch is prohibited. Final implementation head must descend from both exact parents.

## Evidence and retained boundaries

Final review must report the no-rename gross additions for all exact five excluded files from `18f2644`, verify `.github/workflows/ci.yml` is at most 360 and the aggregate is at most 2,640, and confirm ordinary-readable transitions without behavior or scope change. It must also verify the required first/second-parent integration and every non-conflicting ADR 0065–0076 requirement. Any later implementation change invalidates signoff.

This amendment affects only excluded test/workflow capacity. Every production per-file high and the production aggregate remain unchanged. The Phase B aggregate high remains **3,310**, and the conservative global projection remains **33,344 < 34,000** because this excluded-surface increase does not enter that projection. The preferred 32,000 target, hard 34,000 cap, and 656-line margin remain unchanged.

This is an accepted cap-only ADR. It changes no descriptor protocol, mount, process, sandbox, test semantics, production code, schema, timeout, retry, acquisition, artifact, candidate, authority, workflow behavior, run, attempt, event, trigger, stage, campaign, release, deployment, cloud boundary, or AWS authority. Every stop and prohibition in ADR 0065–0076 remains binding.
