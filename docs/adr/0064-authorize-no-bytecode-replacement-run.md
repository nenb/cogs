# ADR 0064: Authorize a no-bytecode replacement hosted run

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing authorization to proceed through non-AWS qualification, after independent review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #235](https://github.com/nenb/cogs/pull/235).
- Amendment scope: A bytecode-free correction in the excluded candidate driver, `-I -B` for its hosted invocation, and exactly one replacement run. Every non-conflicting ADR 0057–0063 boundary remains binding.

## Context

ADR 0057's sole hosted authority was consumed by run [`30217525176`](https://github.com/nenb/cogs/actions/runs/30217525176), attempt 1, at exact reviewed head `79665f53f9c7ec1652d42d6c004159ad52b37b45`. The run failed before acquisition and before `fork`.

The excluded candidate driver's dynamic import created `scripts/__pycache__` beneath the verified fixed source. Python `-I` isolates imports but does not disable bytecode writes. The first source re-verification then rejected that unexpected entry at exact `completion_rootfs_fs.py:895`; the driver exposed only `parent-failure`. Independent static analysis and an offline Linux reproduction confirm this sequence. Both `-B` and setting `sys.dont_write_bytecode` before dynamic loading leave the source clean.

The failure exercised no artifact acquisition, child, build, recovery, candidate, Phase B, production, cloud, or AWS authority. The consumed run must not be retried or rerun.

## Decision

If accepted, authorize only these corrections on PR #230's existing head branch:

1. In `test/aws-stage2-completion-rootfs-candidate.py`, establish `sys.dont_write_bytecode = True` early, before any project-source dynamic load. Keep the loader portable, preserve its existing fixed-path and module semantics, and produce no `.pyc`.
2. Add a portable, offline regression through that loader which proves the module executes and no `__pycache__` directory or `.pyc` file is created. It may use only fresh temporary state and performs no acquisition or network operation.
3. In `.github/workflows/stage2-rootfs-full-build-qualification.yml`, invoke the hosted candidate driver with `/usr/bin/python3 -I -B`. No other workflow behavior changes.

No TypeScript change is authorized. Gross additions remain measured from `8caab23bb4277121a77d80dc043b3c2c43b07ced`, without deletion or compression credit, and must remain within every per-file maximum:

| Excluded file | Unchanged maximum |
| --- | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **1,150** |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **110** |
| **Excluded three-file total** | **1,300** |

Stop and replan rather than cross a cap, change another file, or broaden behavior.

## Review and one replacement execution

Use PR #230 only. Convert it from ready to draft exactly once before the correction. While it remains draft, apply only the changes above and require normal CI, the inherited local/offline checks, exact count remeasurement, and one clean independent review of the complete exact-base-to-new-head range with no unresolved P0–P3 finding. Record the new full 40-hex reviewed head `H`; any later change invalidates review and grants no run.

After those gates pass, set `STAGE2_ROOTFS_REVIEWED_HEAD` to exactly `H`, verify the frozen base ref/SHA, absent `security` label, exact PR head, attempt-1 eligibility, and absence of any prior replacement run for `H`, then convert PR #230 from draft to ready exactly once. That single `ready_for_review` event authorizes exactly one replacement GitHub-hosted run at `H`, attempt 1.

The replacement retains without change the same-repository and exact-head gates, frozen base `feat/issue42-deterministic-rootfs` at `8caab23bb4277121a77d80dc043b3c2c43b07ced`, permissions, Ubuntu 24.04 job, one-job workflow, 5,400-second non-borrowing boundaries, outer timeout, exact 16 public artifacts, one trusted child, at most one already-defined authentic recovery, two fresh builds, exact pins and equality checks, cleanup, independent final observations, and deterministic final accounting.

Authority is consumed when the first matching run for that replacement event and `H` is created, regardless of whether it runs, skips, succeeds, fails, times out, is cancelled, or remains uncertain. Do not rerun or retry run `30217525176`, rerun the replacement, use an attempt above 1, push after review, perform another ready transition, or choose among runs. A missing or duplicate run, metadata mismatch, residue, or cleanup uncertainty grants nothing. Every outcome requires an immediate mandatory stop.

## Retained boundaries and consequences

This ADR changes no timeout, deadline, recovery predicate or count, artifact contract, build, cleanup authority, production code, counted cap, Phase B gate, later stage, step-5 stop, campaign, release, issue closure, cloud boundary, or AWS authority. It authorizes no production, credential, AWS CLI, account, provider, OpenTofu, SSM, deployment, cloud resource, or cloud-cleanup action.

The consequence is one narrowly corrected opportunity to run the already-approved authentic regression without import-generated source mutation. This documentation-only proposal remains uncommitted and creates no implementation, review, variable update, PR transition, event, run, acquisition, network, production, cloud, or AWS action until accepted.
