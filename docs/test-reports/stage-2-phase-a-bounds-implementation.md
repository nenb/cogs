# Stage 2 Phase A integrated bounds remeasurement

Measured on 2026-07-26 at production head `3f1b186969c0841673bdaaba713aa820b4e7ae31` (`3f1b186`), before this report-only replacement. The working tree was clean (`git status --short` produced no output). This report is line-accounting and local-test metadata only; it is not candidate, qualification, workflow-execution, campaign, production, or cloud authority.

ADR 0049's frozen physical-line method, retained by ADRs 0050–0052, remains binding. Retained files are counted at their complete current physical size. Historical and replacement evidence versions remain counted together. Tests, workflows, documentation, reports, generated evidence, and fixed artifact or pin contracts are excluded, but they create no deletion credit and may not carry production behavior to evade the cap.

## Exact current frozen count

The complete frozen set was independently remeasured on the current tree:

| Frozen counted set | Physical lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` (40 files) | 18,107 |
| Five historical files frozen by ADR 0039 | 591 |
| `scripts/prepare-stage2-fixed-source.py` | 1,049 |
| `scripts/run-stage2-phase-a-candidate.py` | 2,490 |
| `scripts/stage2-phase-a-budget.py` | 75 |
| Retained `schemas/stage2-phase-a-candidate-v1.json` | 268 |
| Retained `schemas/stage2-phase-a-candidate-v2.json` | 1,955 |
| **Exact actual retained total** | **24,535** |

The historical 591-line subtotal is the exact five-file set: `schemas/aws-stage2-measurement-evidence-v1alpha1.json` (192), `scripts/validate-aws-stage2-measurement-report.ts` (169), `scripts/render-aws-stage2-measurement-report.ts` (105), `schemas/aws-feasibility-report-v1alpha1.json` (88), and `scripts/validate-aws-feasibility-report.ts` (37).

Independent `wc -l` and byte-newline counts agreed on every subtotal. The checked arithmetic is `18,107 + 591 + 1,049 + 2,490 + 75 + 268 + 1,955 = 24,535`.

## Integrated decisions, commits, and conservative reserve

The correction authority is the integrated accepted ADR sequence: ADR 0050 commit `7d9d4845f6c2671f9fe5b9fcdb30f3766b43646c` (`7d9d484`), ADR 0051 commit `10c5bbc6c6d255069855eece1946cda9c782e1c7` (`10c5bbc`), and ADR 0052 commit `d76f8b7005efc78e165dc52b0d616e1ded91a481` (`d76f8b7`). Their exact implementation baseline was `0017ac2ec441301a252363b2b9ee90db65fda41e` (`0017ac2`), with 23,708 actual retained lines and a 24,683-line no-deletion reserve. The relevant baseline blobs remained byte-equivalent through the documentation merges before implementation.

The counted production corrections integrated at current head are:

| Commit | Counted production surface | Raw additions | Deletions | Actual retained change |
| --- | --- | ---: | ---: | ---: |
| `04981a5b7108b91a41b4dcd92b0973f7fdb12c54` (`04981a5`) | Rootfs builder C1/R1 rebinding | 139 | 10 | 129 |
| `3f1b186969c0841673bdaaba713aa820b4e7ae31` (`3f1b186`) | Phase A runner C2/C3 ownership and evidence | 420 | 114 | 306 |
| `3f1b186969c0841673bdaaba713aa820b4e7ae31` (`3f1b186`) | Phase A v2 C3 schema causality | 392 | 0 | 392 |

The changes use no counted `completion_rootfs_build.py` addition. Against ADR 0052's exact-baseline highs, builder 139 is at or below 155, runner 420 equals 420, schema 392 is at or below 400, and total raw counted additions are `139 + 420 + 392 = 951`, at or below 990. Excluded workflow, native-invoker, test, and documentation additions are neither charged nor credited.

The actual retained total reconciles as `23,708 + (139 - 10) + (420 - 114) + 392 = 24,535`.

The conservative no-deletion reserve is:

| Reserve component | Lines |
| --- | ---: |
| Pre-correction no-deletion reserve | 24,683 |
| Rootfs builder raw counted additions | 139 |
| Phase A runner raw counted additions | 420 |
| Phase A v2 schema raw counted additions | 392 |
| **Current conservative planning reserve** | **25,634** |

Thus `24,683 + 139 + 420 + 392 = 25,634`. The reserve exceeds the exact current retained count by **1,099 lines**: the prior 975-line difference, 10 builder deletions, and 114 runner deletions. Therefore `25,634 - 24,535 = 1,099` and `975 + 10 + 114 = 1,099`. No deletion or excluded-surface credit reduces the planning reserve.

## Clean-head local signoff

At clean production head `3f1b186`, before this report-only replacement, the integrated ADR 0050–0052 correction slices received the following local signoff on 2026-07-26:

- `npm run check` — 885 tests passed, 3 skipped, with the ordinary schema, formatter, static, pin, lock-integrity, license, and bounded-audit gates passing; and
- the full offline Docker materializer fault/recovery suite — passed.

Independent final code and hostile reviews were clean, with no P0–P3 findings. These local checks and reviews do not satisfy ADR 0052's workflow-bound native authority. The exact same-repository GitHub `quality`-job run, external execution-envelope record, exact reviewed source/head and workflow-blob binding, and direct tracked native-gate result remain pending. Docker is strong non-authoritative functional evidence only and cannot establish native Linux host authority, KVM, Kata, candidate, or Phase B qualification.

## Revised remaining arithmetic

The ADR 0050–0052 corrections are now measured completed slices. The retained later named high remains unchanged.

| Remaining named work | Conservative high |
| --- | ---: |
| Separately gated Phase B committed-attestation qualification | 3,270 |
| Steps 3–4 closure, candidate, qualification, and workload plan | 1,900 |
| Retained steps 5–7 controller, evidence, and readiness highs | 2,060 |
| **Revised remaining high** | **7,230** |

`3,270 + 1,900 + 2,060 = 7,230`.

| Projection basis | Exact actual basis | No-deletion reserve basis |
| --- | ---: | ---: |
| Current count or reserve | 24,535 | 25,634 |
| Revised remaining high | 7,230 | 7,230 |
| **Projected cumulative** | **31,765** | **32,864** |
| Relation to ADR 0049 preferred target of 32,000 | 235 below | **864 above** |
| Below ADR 0049 hard cap of 34,000 | 2,235 | **1,136** |

The conservative reserve projection is `25,634 + 7,230 = 32,864`, **864 lines above the 32,000 preferred target** and **1,136 lines below the 34,000 hard cap**. The exact-actual projection is `24,535 + 7,230 = 31,765`, **235 lines below the preferred target** and **2,235 lines below the hard cap**. Crossing the preferred target on the no-deletion basis consumes review margin but does not amend the unchanged hard cap. These margins grant no authority and are not requirements to consume lines.

## Retained stops and boundaries

Exactly one operationally selected, non-authoritative Phase A candidate remains unconsumed. The `security` label must remain absent throughout implementation, ordinary CI, the pending native qualification, remeasurement, and review. Nothing in this report authorizes adding it. ADR 0052's exact workflow-bound native run and all other ADR 0048–0052 pre-candidate integration, clean-review, exact-clean-revision, and qualification conditions must first pass and be reviewed.

Only after those gates pass may the open pull request be frozen at the exact reviewed head, with no later synchronize or reopen event, and ADR 0050's one authorized `labeled` event be considered under its exact run-attempt and duplicate-run rules. This report does not authorize the freeze, label event, candidate, or any workflow execution. Whether the eventual one candidate succeeds, fails, skips, times out, cancels, or remains uncertain, stop immediately afterward for durable recording, exact measurement, and replan; there is no retry, rerun, or second candidate.

Phase B remains separately gated on reviewed committed attestations and independent reproduction at a later exact clean revision. Its 3,270-line estimate is accounting only and does not authorize Phase B implementation or execution. Steps 3–4 retain every preceding qualification gate and staged dependency. **Stop before step 5**: the seven-cycle controller and all steps 5–7 remain unauthorized accounting scope regardless of available line margin.

After every future counted production slice, remeasure the complete frozen set and revise every remaining named range. Stop before further counted implementation or candidate selection whenever either `actual frozen count + revised remaining high >= 34,000` or the stricter ADR 0050 rule `current no-deletion reserve + revised remaining high >= 34,000`; the no-deletion-reserve rule controls whenever it stops earlier. Stop as well whenever implementation itself would reach 34,000. Margin below the hard cap, or an exact-actual projection below the preferred target, cannot weaken behavior, move production behavior into excluded surfaces, consume the candidate, or bypass review or qualification.

No additional workflow edit or execution, AWS credential, CLI, account lookup, provider, OpenTofu plan/inventory/apply, SSM action, deployment, resource creation, cloud cleanup, campaign, evidence publication, release, production, or issue-closure authority is granted by the count, tests, projections, reviews, or unused margin.
