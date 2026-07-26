# Stage 2 Phase A integrated bounds remeasurement

Measured on 2026-07-26 at production head `0c247adb1350133860d5d13e5256ec4d2ad250ef` (`0c247ad`), before this report-only replacement. The working tree was clean (`git status --short` produced no output). This report is line-accounting and local-test metadata only; it is not candidate, qualification, workflow-execution, campaign, production, or cloud authority.

ADR 0049's frozen physical-line method remains binding. Retained files are counted at their complete current physical size. Historical and replacement evidence versions remain counted together. Tests, workflows, documentation, reports, generated evidence, and fixed artifact or pin contracts are excluded, but they create no deletion credit and may not carry production behavior to evade the cap.

## Exact current frozen count

The complete frozen set was independently remeasured on the current tree:

| Frozen counted set | Physical lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` (40 files) | 17,978 |
| Five historical files frozen by ADR 0039 | 591 |
| `scripts/prepare-stage2-fixed-source.py` | 1,049 |
| `scripts/run-stage2-phase-a-candidate.py` | 2,184 |
| `scripts/stage2-phase-a-budget.py` | 75 |
| Retained `schemas/stage2-phase-a-candidate-v1.json` | 268 |
| Retained `schemas/stage2-phase-a-candidate-v2.json` | 1,563 |
| **Exact actual retained total** | **23,708** |

The historical 591-line subtotal is the exact five-file set: `schemas/aws-stage2-measurement-evidence-v1alpha1.json` (192), `scripts/validate-aws-stage2-measurement-report.ts` (169), `scripts/render-aws-stage2-measurement-report.ts` (105), `schemas/aws-feasibility-report-v1alpha1.json` (88), and `scripts/validate-aws-feasibility-report.ts` (37).

The checked arithmetic is `17,978 + 591 + 1,049 + 2,184 + 75 + 268 + 1,563 = 23,708`.

## Integrated commits and conservative reserve

ADR 0049 established a 23,931-line no-deletion planning reserve for the D1/D2 commit `8627ee4464e2eaba9de2b0a521b3184bfec138d3` (`8627ee4`), the evidence-v2 commit `7d6448e9f95df3a9983be9f5209d6b3074e0b653` (`7d6448e`), and its counted schema registration. The subsequent counted production commits are:

| Commit | Counted production change | Raw additions | Deletions | Actual retained change |
| --- | --- | ---: | ---: | ---: |
| `f3eb53ce4626872d75a11277fe72d3402860083f` (`f3eb53c`) | Phase A structural-counter integration | 212 | 58 | 154 |
| `0c247adb1350133860d5d13e5256ec4d2ad250ef` (`0c247ad`) | D3 cleanup-session linearization | 540 | 421 | 119 |

For `f3eb53c`, the 212 counted additions are 50 lines under `deploy/aws-feasibility` and 162 in the retained Phase A runner; excluded test additions are not charged or credited. For `0c247ad`, the 540 counted additions are 494 builder lines and 46 ledger lines; excluded test additions likewise create no credit.

The current actual total also reconciles as `23,435 + (212 - 58) + (540 - 421) = 23,708`, using ADR 0049's exact actual retained total as the starting point.

The conservative no-deletion reserve is:

| Reserve component | Lines |
| --- | ---: |
| ADR 0049 planning reserve | 23,931 |
| Counter-integration raw counted additions | 212 |
| D3 raw production additions | 540 |
| **Current conservative planning reserve** | **24,683** |

Thus `23,931 + 212 + 540 = 24,683`. The reserve exceeds the exact current retained count by **975 lines**: ADR 0049's prior 496-line reserve difference, 58 counter-integration deletions, and 421 D3 deletions. Therefore `24,683 - 23,708 = 975` and `496 + 58 + 421 = 975`. No deletion or excluded-surface credit reduces the planning reserve.

## Clean-head local signoff

At clean production head `0c247ad`, before this report-only replacement, the integrated counter and D3 slices received the following local signoff on 2026-07-26:

- `npm run check` — 884 tests passed, 3 skipped, with schemas, presets, static egress bindings, image pins, lock integrity, licenses, and the bounded audit disposition all passing;
- `python3 test/stage2-phase-a-candidate.py` — passed;
- the focused rootfs builder, ledger, lease, materializer, filesystem, canonical, and publication Python suites — passed, including 202 finite lease behavioral-matrix cases; the host EUID-0 Linux filesystem matrix was explicitly skipped;
- the focused TypeScript rootfs wrappers — 15 tests passed; and
- the D3 Linux fault matrix — passed in the local `python:3.11.7-slim-bookworm` image with `--pull never`, `--platform linux/amd64`, `--network none`, a read-only container root and source bind, and disposable `/tmp` and `/var/lib/cogs` tmpfs mounts.

The D3 implementation also received independent final hostile-review signoff with no P0–P3 findings. The Docker run is strong non-authoritative functional evidence only: this macOS/ARM64 host cannot establish native Linux-amd64, host KVM, Kata, timing, candidate, or Phase B qualification.

## Revised remaining arithmetic

Counter integration and D3 are now measured completed slices and are removed from the remaining estimate.

| Remaining named work | Conservative high |
| --- | ---: |
| Separately gated Phase B committed-attestation qualification | 3,270 |
| Steps 3–4 closure, candidate, qualification, and workload plan | 1,900 |
| Retained steps 5–7 controller, evidence, and readiness highs | 2,060 |
| **Revised remaining high** | **7,230** |

`3,270 + 1,900 + 2,060 = 7,230`.

| Projection basis | Exact actual basis | No-deletion reserve basis |
| --- | ---: | ---: |
| Current count or reserve | 23,708 | 24,683 |
| Revised remaining high | 7,230 | 7,230 |
| **Projected cumulative** | **30,938** | **31,913** |
| Below ADR 0049 preferred target of 32,000 | 1,062 | **87** |
| Below ADR 0049 hard cap of 34,000 | 3,062 | **2,087** |

The conservative reserve projection is `24,683 + 7,230 = 31,913`, **87 lines below the 32,000 preferred target** and **2,087 lines below the 34,000 hard cap**. The exact-actual projection is `23,708 + 7,230 = 30,938`. These margins grant no authority and are not requirements to consume lines.

## Retained stops and boundaries

Exactly one next non-authoritative Phase A candidate remains the limit, and only after every ADR 0048–0049 pre-candidate integration, review, exact-clean-revision, and qualification condition passes. Whether that candidate succeeds, fails, times out, or remains uncertain, stop immediately afterward for explicit measurement and replan. This report does not itself authorize that candidate or any workflow execution.

Phase B remains separately gated on reviewed committed attestations and independent reproduction at a later exact clean revision. Its 3,270-line estimate is accounting only and does not authorize Phase B implementation or execution. Steps 3–4 retain every preceding qualification gate and staged dependency. **Stop before step 5**: the seven-cycle controller and all steps 5–7 remain unauthorized accounting scope regardless of available line margin.

After every future counted production slice, remeasure the complete frozen set and revise every remaining named range. ADR 0049's stop applies before further counted implementation whenever `actual frozen count + revised remaining high >= 34,000`, or whenever implementation itself would reach 34,000. Margin below either cap cannot weaken behavior, move production behavior into excluded surfaces, or bypass review or qualification.

No AWS credential, CLI, account lookup, provider, OpenTofu plan/inventory/apply, SSM action, workflow dispatch or edit, deployment, resource creation, cloud cleanup, campaign, evidence publication, release, production, or issue-closure authority is granted by the count, tests, projections, or unused margin.
