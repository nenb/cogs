# ADR 0049: Raise Stage 2 cap after local rootfs and evidence slices

- Status: Accepted
- Date: 2026-07-25
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's standing instruction to continue bounded local qualification and stop before AWS. This decision amends only the numeric Stage 2 preferred target and hard cap after conservative accounting of two local slices. It grants no implementation, qualification, workflow, campaign, production, or cloud authority.

## Context

ADR 0048 set a preferred cumulative target of **29,500 physical lines** and a hard cumulative cap of **31,500 physical lines**. It authorized the narrowly specified D1–D3 rootfs work, structural counters, minimal evidence correction, and exactly one subsequent non-authoritative Phase A candidate, followed by a mandatory stop and replan. It did not authorize Phase B, batching, another timing increase, later stages, the step-5 controller, or cloud activity.

Two implementation slices now exist on the local issue branch:

- `8627ee4464e2eaba9de2b0a521b3184bfec138d3` (`8627ee4`), the D1/D2 rootfs replay and parent-snapshot slice; and
- `7d6448e9f95df3a9983be9f5209d6b3074e0b653` (`7d6448e`), the Phase A evidence-v2 slice.

These commits remain local and unpushed. Although the local issue branch places `7d6448e` after `8627ee4`, neither slice is accepted integration or a candidate-ready exact head merely because it is included in this accounting. The combined changes still require clean integration, complete frozen-set remeasurement, portable and hostile review, and correction of any integration findings. In particular, the strict evidence counter consumer remains fail-closed pending the named production counter integration.

The checked-in report at `7d6448e:docs/test-reports/stage-2-phase-a-bounds-implementation.md` is **stale pre-linearization slice accounting**. It says the D1/D2 work is separate and absent and reports 22,534 lines, even though `7d6448e` directly follows `8627ee4` and its tree contains both slices. It is not combined-tree count authority. Before integration continues, that report must be replaced with a reviewed combined-tree report that remeasures the complete frozen set and clearly separates actual retained physical lines from the no-deletion planning reserve.

## Actual retained count and conservative planning reserve

The exact actual retained physical count in the combined `7d6448e` tree is **23,435 lines**. It is the current physical size of the documented retained files after additions and deletions. For cap planning, this decision applies one uniform no-deletion method instead: every counted addition is charged and no deleted or replaced line offsets it.

| Conservative counted component | Lines |
| --- | ---: |
| ADR 0048 measured baseline | 20,562 |
| Raw D1/D2 additions in `8627ee4` | 1,220 |
| Raw evidence-v2 additions in `7d6448e` | 2,145 |
| `scripts/validate-schemas.ts` Stage 2 schema-registration additions | 4 |
| **Evidence and validator additions** | **2,149** |
| **Conservative planning total** | **23,931** |

Thus `20,562 + 1,220 + 2,149 = 23,931`.

The 1,220 D1/D2 charge takes no credit for 319 deleted production lines. The 2,145 evidence-v2 charge is the raw `579 + 3 + 1,563` additions to the Phase A runner, scheduling budget, and new retained v2 schema; it takes no credit for the runner's 172 deletions or the budget's one deletion. Although `scripts/validate-schemas.ts` is in a generic script location, its four new lines register and compile the Stage 2 evidence schema. They are explicitly counted under the anti-evasion rule rather than treated as excluded generic CI support.

The difference between the 23,435 exact actual retained count and the 23,931 conservative planning reserve is **496 lines**: 319 D1/D2 deletions, 173 evidence-file deletions, and the four anti-evasion validator additions charged outside the documented retained current-size set. Excluded tests, workflow, documentation, reports, and generated fixtures create no cap credit.

The planning reserve is deliberately not described as the tree's actual physical count, and neither number is qualification authority. The stale report's 22,534 figure and earlier separate-worktree estimates do not replace either combined figure. A replacement combined report and complete retained-file remeasurement are mandatory before integration continues.

## Revised remaining plan

Reviews leave the following named high estimates, again with no deletion credit:

| Remaining named work | Conservative high |
| --- | ---: |
| Production structural-counter integration | 121 |
| D3 poisoned cleanup-session implementation and local proofs | 400 |
| Separately gated Phase B committed-attestation qualification | 3,270 |
| Steps 3–4 closure, candidate, qualification, and workload plan | 1,900 |
| Retained steps 5–7 controller, evidence, and readiness highs | 2,060 |
| **Remaining high** | **7,751** |
| **Projected cumulative** | **31,682** |

The 121-line counter-integration high comes from the reviewed exact production-file plan:

| Counter-integration production surface | High |
| --- | ---: |
| `completion_rootfs_fs.py` sealed provider factory and projection | 46 |
| `completion_rootfs_build.py` exact build-phase provider wiring | 10 |
| `completion_rootfs_builder.py` exact recovery provider wiring | 8 |
| `scripts/run-stage2-phase-a-candidate.py` counter arithmetic, scoping, and recovery corrections | 57 |
| **Counter-integration high** | **121** |

The projection is `23,931 + 7,751 = 31,682`, which exceeds ADR 0048's 31,500 hard cap by **182 lines**. The later-stage figures are accounting only. They do not authorize Phase B, steps 3–7, or any work out of the retained staged order.

## Decision

Amend only ADR 0048's numeric cumulative Stage 2 limits:

- preferred cumulative target: **32,000 physical lines**;
- hard cumulative cap: **34,000 physical lines**.

The preferred target is **318 lines** above the 31,682 projected cumulative high. The hard cap is **2,318 lines** above that projection. The hard-cap review margin is **29.9%** of the 7,751-line remaining high estimate.

The margins are reserved for readable, review-driven corrections within already accepted scope. They are not requirements to consume lines and grant no scope, module, mechanism, execution, or qualification authority.

Every 29,500 preferred-target and 31,500 hard-cap reference, projection, and numeric stop threshold in ADR 0048 is superseded by 32,000 and 34,000. The frozen counted set, retained-file accounting, physical-line method, exclusions, anti-evasion rule, no-deletion-credit planning method, and every non-numeric requirement remain unchanged.

After each counted production slice, report the complete frozen count and revise every remaining named range. Stop before further counted implementation whenever `actual frozen count + revised remaining high >= 34,000`, or whenever implementation itself would reach 34,000. Reaching 32,000 is not permission to weaken behavior, compress security code, relocate code into excluded surfaces, or skip integration, review, qualification, or a retained stop.

## Retained stops and non-authority

This is a cap-only decision. In particular:

- it grants no immediate Phase A or Phase B qualification and does not promote either local commit, a schema, a report, a workflow result, or a future candidate into authority;
- the two local, unpushed slices must be integrated and reviewed, the stale pre-linearization report must be replaced by a reviewed combined-tree report, the complete frozen set must be remeasured, and all ADR 0048 pre-candidate conditions must pass before the one already authorized candidate can run;
- exactly one next non-authoritative Phase A candidate remains the limit, followed by the mandatory stop for explicit measurement and replan, whether that candidate succeeds, fails, times out, or remains uncertain;
- Phase B still requires separately reviewed committed attestations and independent reproduction at a later exact clean revision; this cap does not implement, execute, bypass, or weaken that gate;
- D3 and counter integration remain only their already accepted local scope and cannot be inferred complete from D1/D2 or evidence-v2;
- no batching, group commit, paired or buffered ledger transition, `fsync` deduplication, second recovery attempt, retry, fallback, timeout increase, or timing-reserve change is authorized;
- steps 2–4 retain every preceding qualification gate and staged dependency; and
- **stop before step 5**. The seven-cycle controller remains unauthorized regardless of unused line margin, and steps 5–7 remain accounting rather than present scope.

Every non-numeric requirement and stop gate in ADRs 0038–0048 remains binding. This decision grants no AWS credential, CLI, account lookup, provider, OpenTofu plan/inventory/apply, SSM action, workflow dispatch, workflow edit, deployment, resource creation, cloud cleanup, campaign, evidence publication, release, production, or issue-closure authority.

## Consequences

The accepted numeric cap can contain the conservative combined local-slice planning reserve and the revised named high estimate without compressing security-critical integration and review corrections. The 182-line overrun against the former hard cap is resolved without treating deletions, excluded files, generic validator placement, or unreviewed local work as credit or authority.

No code, workflow, dependency, lockfile, network, provider, cloud, deployment, campaign, or production state changes under this ADR. The next work remains local integration and review under the retained ADR 0048 gates, not candidate execution or qualification by implication.
