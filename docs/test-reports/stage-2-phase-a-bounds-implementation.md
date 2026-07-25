# Stage 2 Phase A bounds and evidence-correction count

Measured on 2026-07-25. This is line-accounting metadata only; it is not qualification, campaign, workflow-execution, or cloud authority.

The ADR 0047 implementation worktree established the frozen **20,562-line** baseline. The ADR 0048 evidence-correction worktree measured here is separate from the D1/D2 rootfs optimization worktree. The ADR 0039 frozen physical-line method remains conservative: retained files are counted at their complete current physical size, the historical v1 schema remains counted, and excluded tests, workflow, documentation, reports, or generated material create no deletion credit.

## Current ADR 0048 evidence worktree

| Frozen counted set | Physical lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 16,908 |
| Frozen historical schema/validator/renderer files named by ADR 0039 | 591 |
| `scripts/prepare-stage2-fixed-source.py` | 1,049 |
| `scripts/run-stage2-phase-a-candidate.py` | 2,080 |
| `scripts/stage2-phase-a-budget.py` | 75 |
| Retained `schemas/stage2-phase-a-candidate-v1.json` | 268 |
| New `schemas/stage2-phase-a-candidate-v2.json` | 1,563 |
| **Measured cumulative total** | **22,534** |

The exact evidence-slice increase over the 20,562-line ADR 0047 baseline is **1,972 physical lines**:

- Phase A runner growth: `2,080 - 1,673 = 407`;
- scheduling budget growth: `75 - 73 = 2`; and
- new retained v2 evidence schema: `1,563`.

Thus `407 + 2 + 1,563 = 1,972`, and `20,562 + 1,972 = 22,534`. The v1 schema was retained byte-for-byte. No file-deletion or excluded-surface credit was taken.

ADR 0048 supersedes the old numeric limits with a **29,500 preferred target** and **31,500 hard cap**. The current measured total is 6,966 lines below the preferred target and 8,966 below the hard cap.

## Revised remaining arithmetic

| Remaining named work | Conservative high |
| --- | ---: |
| D1/D2 actual-known implementation from the separate rootfs worktree, pending final review and integration | 848 |
| D3 cleanup-session work | 400 |
| Separately gated Phase B committed-attestation qualification | 3,270 |
| Steps 3–4 closure, candidate, qualification, and workload plan | 1,900 |
| Retained steps 5–7 controller, evidence, and readiness highs | 2,060 |
| **Revised remaining high** | **8,478** |

The conservative projection is `22,534 + 8,478 = 31,012`. That is 1,512 lines above the preferred target and **488 lines below the 31,500 hard cap**.

The D1/D2 value is an actual-known count from a different worktree; it is not present in this evidence worktree and remains pending final review. The strict counter interface in this worktree intentionally remains fail-closed until that production provider integration is reviewed. Worktree combination can change physical counts through conflicts or retained integration corrections, so the complete frozen set must be remeasured after integration before any candidate or further counted slice. This arithmetic grants no Phase A execution, later stage, step-5, campaign, or cloud authority.
