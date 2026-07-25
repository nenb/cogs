# Stage 2 Phase A bounds implementation count

Measured on 2026-07-25 from the ADR 0047 implementation worktree. This is line-accounting metadata only; it is not qualification, campaign, or cloud authority.

The ADR 0039 frozen physical-line method is applied conservatively. In addition to the complete `deploy/aws-feasibility/**/*.{sh,py,tf}` set and the frozen 591 historical schema/validator/renderer lines, the new fixed-source preparer, Phase A candidate runner, scheduling budget guard, and candidate schema are counted. Their placement outside `deploy/aws-feasibility` creates no exclusion or anti-evasion credit.

| Frozen counted set | Physical lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 16,908 |
| Frozen historical schema/validator/renderer files named by ADR 0039 | 591 |
| `scripts/prepare-stage2-fixed-source.py` | 1,049 |
| `scripts/run-stage2-phase-a-candidate.py` | 1,673 |
| `scripts/stage2-phase-a-budget.py` | 73 |
| `schemas/stage2-phase-a-candidate-v1.json` | 268 |
| **Measured cumulative total** | **20,562** |

The preferred target remains **24,000** and the hard cap remains **25,500**. The measured total is 3,438 lines below the preferred target and 4,938 below the hard cap. No deletion credit was taken for excluded tests, workflow, documentation, reports, or generated material.

ADR 0045's unrevised remaining high estimate of 6,140 lines would produce `20,562 + 6,140 = 26,702`, above the unchanged hard cap. Therefore this measurement grants no further counted production scope: replan before any later counted production slice, and retain the ADR 0047 stop after the single next non-authoritative candidate.
