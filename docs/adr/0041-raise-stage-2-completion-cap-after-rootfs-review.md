# ADR 0041: Raise Stage 2 completion cap after rootfs hostile review

- Status: Accepted
- Date: 2026-07-23
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead on 2026-07-23 under Nick Byrne's explicit instruction to continue local work, make the required decisions, and wait for further instructions before any AWS deployment activity. Nick Byrne separately authorized unrestricted local Docker use on the same date; that explicit-owner decision satisfies ADR 0040's Docker stop gate but is not created or broadened by this ADR.

## Context

ADR 0039 set an 8,500-line preferred cumulative target and a 9,500-line hard cap for the issue #42 Stage 2 completion capability. Its estimate allowed 650–950 net production lines for deterministic rootfs composition, postwalk, normalization, and two-build pinning. ADR 0040 later superseded the composition mechanism and estimated 850–1,160 lines for R2, 480–660 for R3, 1,330–1,820 combined, 6,410–6,900 cumulative after R3, and 8,910–10,650 for the provisional whole roadmap. ADR 0040 required remeasurement when a slice exceeded its high estimate by more than 20%, at exact R2 head, and again at R3 exit.

The clean merged baseline at `2b13d6f77a583dffb3e38c463ea94feb4c9c9699` is 5,318 lines under ADR 0039's frozen count. The complete local rootfs milestone and first hostile-review correction at `f464d08871b378841c282257b68dd2bdbdf44342` measure 9,059 lines: 8,468 physical lines under `deploy/aws-feasibility/**/*.{sh,py,tf}` plus the frozen 591 schema, validator, and renderer lines. Tests, documentation, reports, generated evidence, and fixed pin contracts remain excluded exactly as ADR 0039 requires.

The rootfs delta is therefore 3,741 lines. It exceeds ADR 0039's high rootfs estimate by 2,791 lines and ADR 0040's combined R2/R3 high estimate by 1,921 lines, or 105.5%.

The stop chronology was not followed correctly. The ADR 0040 R2 high estimate was 1,160 lines. At `2ca1ae54728afae95bf2dfd6afa8be89f0a4d5c3`, the cumulative count was already 7,001 and the rootfs delta from the 5,318-line baseline was 1,683: 523 lines, or 45.1%, over that high estimate. The greater-than-20% stop was crossed no later than that commit, but five further production commits followed. An R2 implementation-head count was taken at `54d1b67fb4ffaa5fa0440a21fabfacab2c3e69ae` and measured 8,269 lines, but implementation again continued without the required cap ADR because the old absolute hard cap had not yet been exceeded. That was incorrect process. This ADR is the belated corrective stop before any further production implementation. ADR 0040's R3-exit remeasurement remains pending because authoritative R2 Linux qualification, second-review crash closure, and therefore R3 exit are not complete.

The difference is not package, input, or deployment scope expansion. It comes from the accepted ADR 0040 direct-materialization mechanism and review-required explicit security behavior: fd-relative stable identities, fresh source authority, mount and xattr rejection, crash-recoverable ownership records, hardlink generation transitions, exact-owned cleanup, complete postwalk, canonical ustar output, two-build comparison, strict pins, and no-overwrite publication. Repeatable Docker observations remain functional and non-authoritative; authoritative Linux qualification remains open.

A second independent hostile review of exact `f464d08871b378841c282257b68dd2bdbdf44342`, completed on 2026-07-23 after that commit, found further required crash-closure work before merge:

- publication must reconcile pre-sentinel, partial-file, uncertain-rename, and exact accepted states rather than only make the final directory rename atomic;
- every durable `*-observed` identity must have an exact revalidation-and-settle recovery path;
- operation-startup failures must transfer cleanup ownership before the public start call can fail.

The review also found test-harness safety defects. Those excluded test changes are required under Nick Byrne's separate explicit Docker authorization, but they do not enter this production count or receive authority from this cap-only ADR.

Only 441 lines remain under ADR 0039's hard cap. Compressing those state transitions, combining unknown with absent, omitting close/error aggregation, or weakening hostile tests to fit that obsolete remainder is forbidden.

### Measured remaining implementation

The remaining net production estimate uses the current module boundaries and the second-review findings for rootfs closure; ADR 0038's fixed fixture, Kata, workload, controller, evidence, and readiness contracts for later slices; and the already merged controller/evidence primitives identified by ADR 0039 for safe reuse. Ranges include review-driven hardening but no deletion credit, dependency, fallback, package expansion, or cloud behavior:

| Remaining slice | Net lines |
| --- | ---: |
| Rootfs second-review crash closure | 350–650 |
| Deterministic fixtures and exact-package runtime closure | 350–600 |
| Standalone Kata SSH/network lifecycle and identity-bound cleanup | 850–1,250 |
| Fixed guest Git and package workloads | 250–450 |
| Seven-cycle controller and fake state-machine behavior | 450–750 |
| Separate strict completion evidence, validation, and rendering | 650–950 |
| Local readiness aggregation and final integration | 150–300 |
| **Total remaining** | **3,050–4,950** |

Applied to the measured 9,059-line milestone, the projected cumulative range is **12,109–14,009 lines**.

## Decision

Amend only ADR 0039's numeric cumulative Stage 2 targets:

- preferred cumulative target: **14,000 lines**;
- hard cumulative cap: **15,000 lines**.

The preferred target lies inside the measured range, nine lines below its high case. The hard cap is 991 lines, or 20.0% of the 4,950-line remaining high estimate, above the projected cumulative high case. That contingency is deliberately larger than ADR 0039's obsolete margin after two rootfs forecast misses; it is for readable review corrections, not added scope. Implementation must stop for another measured decision rather than exceed 15,000 lines.

All numeric 8,500 preferred-target and 9,500 hard-cap references, projections, and stop gates in ADRs 0039 and 0040 are superseded by 14,000 and 15,000 respectively. ADR 0038's older 4,600/5,100 references remain transitively superseded through ADR 0039 and now this decision. Every non-numeric ADR 0038–0040 requirement remains unchanged. The frozen count set, exclusions, anti-evasion rule, and physical-line method remain unchanged.

This is a cap-only decision. It does not change immutable inputs, the exact ten-package set, rootfs semantics, standalone Kata authenticated-SSH semantics, network topology, seven-cycle campaign shape, evidence requirements, cleanup ownership, cost/time/resource bounds, or any cloud gate.

## Required discipline

- Keep every durable ownership phase independently parseable, revalidated, and crash-recoverable; uncertain named identities remain preserved.
- Publish only a completely verified accepted directory, reconcile uncertain rename outcomes by exact identity, and never replace an existing accepted result.
- Use fresh bounded cleanup deadlines and aggregate primary, cleanup, and close errors.
- Under the separate explicit owner authorization, keep any local Docker use functional and non-authoritative; this ADR neither creates nor broadens that route. Authoritative claims require the unpatched approved Linux/EUID-0 and Kata/KVM gates.
- Preserve readable security code. No dense formatting, generic path/command seam, broad deletion, host-library fallback, package expansion, external extractor, or weaker fallback is authorized.
- Continue reporting the frozen cumulative count at each complete milestone.

## Retained gates and non-claims

Every non-numeric requirement and stop gate in ADRs 0038–0040 remains binding. ADR 0040's stop-before-Docker condition was separately satisfied by Nick Byrne's explicit local Docker authorization; this ADR does not supersede that gate or turn Docker into qualification evidence. In particular:

- no AWS plan, inventory, provider call, apply, execution, workflow dispatch, or cleanup is authorized by this decision;
- AWS deployment remains closed until Nick Byrne gives separate instructions for one exact named batch;
- Docker cannot establish authoritative standalone Kata/KVM, production-workspace, or AWS evidence;
- missing package closure, SSH, network, identity, cleanup, or evidence proof remains a stop-and-replan condition; and
- this decision does not close issue #42 or establish Stage 4, EKS, release, production, compliance, or availability claims.

## Consequences

Local issue #42 implementation may continue through the required rootfs recovery fixes, deterministic fixtures, standalone Kata qualification capability, bounded controller, and evidence implementation without compressing security-critical behavior under ADR 0039's exhausted cap. The cumulative preferred target is 14,000 lines and the hard cap is 15,000 lines. The campaign itself remains separately gated and must not start without new explicit AWS instructions.
