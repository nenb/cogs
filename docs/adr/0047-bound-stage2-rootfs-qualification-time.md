# ADR 0047: Bound Stage 2 rootfs qualification time from Phase A evidence

- Status: Accepted
- Date: 2026-07-25
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's standing instruction to continue bounded local qualification and stop before AWS. This decision authorizes only the evidence-backed numeric rootfs qualification changes and one minimal workflow budget guard below, and retains the separate Phase B, step-5, campaign, and cloud gates.

## Context

ADR 0046 authorized a narrow, security-label, pull-request-only GitHub KVM qualification route. Its Phase A output is explicitly candidate observation, not qualification authority. ADR 0045 retains the issue #42 preferred cumulative target of **24,000 physical lines**, hard cumulative cap of **25,500**, staged order through steps 2–4, and mandatory stop on arrival at step 5 before the seven-cycle controller.

Phase A run [30157183403](https://github.com/nenb/cogs/actions/runs/30157183403) executed revision `807690c160cfe0d18ee37bfec28115decb4f778a` (`807690c`). Its validated metadata-only candidate report and job log record exactly:

- candidate `duration_ms` **448,797** and observation failure category `rootfs-build`;
- exact-owned cleanup started after the observation and failed closed at `cleanup-uncertainty` after **124.5 seconds** (124.481 seconds from the workflow step timestamps, rounded to one decimal place);
- the independent read-only residue step separately failed closed at `residue-uncertainty`, with categorical `cache-residue` and `rootfs-baseline-not-restored` diagnostics;
- observation, cleanup, and residue outcomes were all `failure`; `qualified` was `false`; authority was `candidate`; and runtime, network, SSH, and coordinator-invocation claims were all `false`.

The 448,797 ms value is the candidate observation duration through its `rootfs-build` failure, not proof that a rootfs build completed in that time. The run produced no first build, second build, deterministic-equality, pin, cleanup, or residue authority. Artifact rendering and validation succeeding does not promote the failed candidate.

Two earlier Phase A runs exposed deterministic integration drift before this measurement. Run `30156175807` at `261f620` stopped before rootfs work; revision `028bf9f` then corrected the exact fixed-source artifact-contract mode. Run `30156593245` at `028bf9f` stopped after reaching the rootfs route; revision `807690c` then added the required fixed rootfs bootstrap and lifecycle ownership before build. Those mode and bootstrap corrections explain why run 30157183403 reached bounded rootfs materialization. They are development history, not qualification evidence.

At revision `807690c`, the rootfs limits are too short for the observed local qualification path and are not coherently layered:

- `completion_rootfs_build.BUILD_SECONDS = 300`;
- `completion_rootfs_materializer.MATERIALIZE_SECONDS = 300`;
- `completion_rootfs_materializer.CLEANUP_SECONDS = 120`;
- `completion_rootfs_builder.RECOVER_SECONDS = 120`; and
- `completion_rootfs_build.OUTER_SECONDS = 1200` for the two-build qualification route.

The 124.5-second cleanup outcome is consistent with exhausting a 120-second recovery bound plus setup and reporting overhead. It supports a bounded increase for exact recovery; it does not identify a safe retry, fallback, or successful build duration. The failed run therefore justifies one measured local qualification adjustment followed by a new observation and replan, not repeated attempts under changing limits.

## Decision

Authorize only the following bounded numeric changes for the existing local rootfs qualification mechanism and Phase A observer:

| Bound | Authorized value | Meaning |
| --- | ---: | --- |
| `completion_rootfs_build.BUILD_SECONDS` | **900 seconds** | Maximum work time for each independently identified first or second rootfs build |
| `completion_rootfs_materializer.MATERIALIZE_SECONDS` | **900 seconds** | The same per-build work deadline as `BUILD_SECONDS`, not an additional nested 900 seconds |
| `completion_rootfs_materializer.CLEANUP_SECONDS` | **600 seconds** | Fresh maximum for one inline exact-owned materializer cleanup pass |
| `completion_rootfs_builder.RECOVER_SECONDS` | **600 seconds** | Fresh maximum for one exact resumable rootfs recovery pass |
| `completion_rootfs_build.OUTER_SECONDS` | **2400 seconds** | Aggregate local two-build qualification envelope: two 900-second build-work bounds plus 600 seconds for fixed bootstrap, comparison, settlement, and bounded failure handling |
| Phase A `OBSERVE_SECONDS` | **3300 seconds** | Observation bound nested beneath the absolute workflow guard; it does not include the reserved post-observation `always()` envelope |

`BUILD_SECONDS` and `MATERIALIZE_SECONDS` must resolve to one shared absolute deadline for a given build. They are two enforcement points for the same **900-second per-build work bound** and must never be summed into 1,800 seconds for one build. Materialization receives the earlier of its matching 900-second deadline, the 2,400-second two-build deadline, and the candidate observation deadline.

Keeping `OUTER_SECONDS` at 1,200 would not be coherent with two sequential builds each entitled to an independent 900-second work ceiling. The authorized 2,400-second value is bounded: at most 1,800 seconds is build work, and the remaining 600 seconds is transaction margin, not a third build, retry, or fallback allowance. A first-build failure stops the second build. A second build starts only after the first completed successfully, settled exactly, and remained within the aggregate deadline.

An inline cleanup or recovery operation receives a fresh deadline of at most 600 seconds. This fresh cleanup/recovery deadline may intentionally outlive the failed build's expired 900-second work deadline: cleanup must not inherit an already-expired work deadline and become a no-op. It may never outlive the absolute observe-cleanup boundary or job guard defined below.

A cleanup step may make **at most two** exact resumable recovery passes. A second pass is permitted only after the first pass has returned, the durable ledger and exact identities have been independently reopened and revalidated, and the absolute cleanup guard can still provide its bounded pass while preserving the final 300 seconds for mandatory independent cache cleanup, residue observation, reporting, upload, and export cleanup. Passes are resumptions of the same exact-owned transaction, never retries of a build. Per-pass ceilings are not additive authority to extend an absolute boundary.

No timeout, close error, malformed ledger, unknown identity, replacement, contradictory state, or incomplete observation may be converted to absence. Deadline exhaustion preserves exact state and fails closed.

## Coherent candidate and workflow allocation

Authorize one minimal timing-guard edit to the existing ADR 0046 Phase A workflow. It must record one monotonic job-budget anchor immediately after job start and **before checkout**. The anchor is scheduling data only: it records no source revision, manifest, artifact, identity, qualification fact, or authority, and no production preflight may consume it.

Using that one anchor, the workflow must enforce these absolute boundaries under the unchanged **5,400-second (90-minute)** job timeout:

1. checkout plus fixed-source materialization and binding must finish by `anchor + 600 seconds`; otherwise stop before invoking `observe`;
2. Phase A uses `OBSERVE_SECONDS = 3300`, and `observe`, including any inline exact cleanup it performs, must end no later than `anchor + 3900 seconds`;
3. the interval from `anchor + 3900` through `anchor + 5400` is a **1,500-second** `always()` cleanup/residue/report/upload envelope; and
4. the absolute cleanup guard reserves at least the final **300 seconds** of that envelope for independently safe exact cache cleanup, independent read-only residue observation, metadata-only render/validation/export/upload, and exact export cleanup.

The 2,400-second rootfs envelope is nested inside the 3,300-second observation bound. The observation bound is in turn nested inside the absolute `anchor + 3900` observe-cleanup boundary. Checkout or setup finishing early does not extend any later boundary, and a late setup cannot borrow from the 1,500-second reserve.

The 1,500-second reserve coherently accommodates at most two 600-second exact recovery passes plus 300 seconds of mandatory cache/residue/report work. A second pass may start only when the absolute cleanup guard proves that its full permitted interval ends by `anchor + 5100`; otherwise it is skipped, uncertainty is preserved, and independently safe mandatory cleanup and reporting proceed. The same guard bounds recovery started inline before observation exits: a fresh 600-second recovery may continue after its build-work deadline, but not past `anchor + 3900` while inside `observe`, and never past the applicable cleanup guard in `always()` handling.

The 600-second cleanup/recovery constants are maxima, not promises that a pass may cross an absolute boundary. Job timeout, platform cancellation, guard failure, or inability to complete mandatory final work can never produce authority.

## Required next qualification evidence

The next Phase A candidate after implementing these numeric changes must produce bounded categorical timing without exposing raw sensitive state:

1. record separate `first-build` and `second-build` outcomes and elapsed milliseconds; never report only a pooled two-build duration;
2. distinguish work timeout, inline cleanup, first recovery pass, optional second recovery pass, equality, pin, post-verification, and settlement categories;
3. prove that any recovery resumes the exact durable operation and ledger after complete identity revalidation, without creating a new token, operation, root, or build sample;
4. continue independently safe exact cache cleanup even when rootfs recovery remains uncertain, aggregate both outcomes, and never skip cache cleanup because an earlier rootfs cleanup failed;
5. perform a separate read-only final residue observation covering the rootfs baseline, exact 16-artifact cache, candidate assets, state, and exported report;
6. preserve failed, timed-out, or uncertain state exactly where ownership cannot be proven; and
7. stop after that one candidate for a new measurement and explicit replan. The candidate itself may not tune another bound, trigger a rerun, or become authority.

A candidate is still non-authoritative even if both builds, cleanup, and residue pass. Production qualification or campaign use requires Phase B: separately reviewed committed attestations for the exact source, tools, runtime, network, SSH, KVM, output, timing categories, and residue contracts, followed by independent reproduction at a clean revision. Phase B reviewed attestation is required before these numeric bounds can be adopted by any production campaign path.

## Retained boundaries

This ADR supersedes ADR 0046 **only** on the numeric local rootfs qualification bounds, the Phase A observation bound, and the minimal monotonic workflow budget guard listed above. Every other ADR 0046 requirement remains binding, including its pull-request-only candidate/attestation distinction, trigger and permission restrictions, exact source and asset rules, metadata-only artifacts, cleanup semantics, and no-authority result.

ADR 0045 remains unchanged:

- preferred cumulative Stage 2 target: **24,000 physical lines**;
- hard cumulative cap: **25,500 physical lines**;
- frozen counted set, retained-file accounting, physical-line method, exclusions, anti-evasion rule, no-deletion-credit method, and `actual frozen count + revised remaining high >= 25,500` stop;
- staged work only through steps 2–4 after their preceding gates; and
- mandatory stop on arrival at **step 5**, before implementation or execution of the seven-cycle controller.

All non-numeric requirements and stop gates in ADRs 0038–0045 remain binding. In particular, longer bounds do **not** permit:

- retrying an unknown, failed, timed-out, or cleanup-uncertain build;
- starting the second build after any first-build uncertainty;
- fallback materializers, writers, extractors, tools, packages, host paths, runtime modes, software emulation, or cleanup routes;
- broad deletion, force/lazy/recursive cleanup, unknown-to-absent conversion, or runner disposal as residue proof;
- runtime, network, SSH, controller, evidence-publication, campaign, release, production, or issue-closure authority;
- any AWS credential, CLI, account lookup, provider, OpenTofu plan/inventory/apply, SSM action, deployment, resource, cloud cleanup, or campaign operation; or
- any workflow change beyond recording and enforcing the exact monotonic timing guard above, or any workflow dispatch.

This decision authorizes that one future workflow timing-guard edit but implements none here. It changes no code, workflow, dependency, lockfile, cloud state, production state, or frozen Stage 2 line count in this documentation-only task.

## Consequences

Local implementation may replace only the six numeric qualification limits above, add only the specified workflow budget guard, and add the minimum timing/recovery/cache-cleanup observations necessary to measure the next candidate. The next run must remain one non-authoritative Phase A observation and then stop for review and replan.

A longer deadline can reveal whether the fixed rootfs transaction completes and whether exact recovery converges; it cannot prove in advance that it will. Any new timeout, uncertain cleanup, residue, drift, or inability to preserve the reserve fails closed and requires another decision. Production campaign adoption remains separately closed until Phase B reviewed attestation and all retained human/cloud gates are satisfied.
