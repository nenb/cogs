# ADR 0092 exact-head hostile review — Job D lifecycle

## Verdict

**BLOCKED** — exact implementation head `3846383f0d88c190226356ca9aeeeda402943aaa` has unresolved P1 defects in descendant preregistration/failure settlement, exact signal identity, and production-path portable acceptance. It is not eligible for ADR 0092 signoff or native execution.

**SIGNOFF: BLOCKED**

## Scope and boundary

Reviewed Job D's admitted production lifecycle owner, its three case orchestration, planned `setsid` second gate, credentialed `SCM_RIGHTS` pidfd handoff, identity census/adoption, TERM/KILL and PDEATH outcomes, wait/reap, subreaper restoration, baseline settlement, thin driver, and focused/portable tests at exact head `3846383f0d88c190226356ca9aeeeda402943aaa`.

This review was static/portable only. I invoked no `--workflow-bound` route, native qualification, sudo/native primitive, workflow, provider, cloud, or AWS operation. No production source was edited.

## Severity summary

- **P0:** none found.
- **P1:** three unresolved findings.
- **P2:** none separate from the P1 acceptance failures.
- **P3:** none found.

## Findings

### P1-1 — The descendant is not preregistered before its lifecycle effects, and the surviving aggregate owner cannot settle every pre-transfer cut

The outer leader is correctly preregistered behind `_ProcessOwner.spawn()` and does not create its descendant until the parent confirms the post-`setsid` identity and sends the second gate (`completion_trusted_runtime_launcher.py:3231-3249`). The descendant does not receive the same ownership treatment.

`_lifecycle_leader` calls raw `ops.clone_pidfd()` and lets the child immediately close descriptors, inspect its parent, arm PDEATHSIG, alter TERM handling, and publish status (`:3147-3154`, with the child effects at `:3063-3091`). Only afterward does the leader call `local_owner.register()` (`:3154`). There is no preinserted lease or initial registration gate. A cut after clone returns but before/during registration therefore leaves the pidfd as an unleased local integer and lets the child execute the very PDEATH mechanism being claimed before any owner records it. The outer/subreaper owner does not obtain that pidfd until the later SCM transfer (`:3249-3261`).

The failure path makes this an all-cut settlement defect rather than merely an ordering label. The leader catches its primary, but suppresses both `local_owner.cleanup()` and descriptor-cleanup failures before `_exit(125)` (`:3181-3191`). Those failures and any still-untransferred descendant authority never reach `_run_lifecycle_case`'s aggregate (`:3309-3329`). The outer owner can reap the known leader and can eventually detect a changed child baseline, but detection is not retained pidfd authority, safe TERM/KILL, exact wait/reap, or aggregation for the unknown descendant. This violates ADR 0092's “each child is blocked and registered before effects” and one aggregate all-cut settlement requirements.

### P1-2 — `siginfo_exact` accepts a signal record for the wrong process/credential identity

`_exact_signal_reap` checks only `si_code == CLD_KILLED` and `si_status == SIGKILL`; it never checks `si_pid == descendant.pid` or the expected `si_uid` (`completion_trusted_runtime_launcher.py:3201-3213`). It then labels that partial predicate `siginfo_exact`, and all three case results are folded into the published `siginfo_exact` authority (`:3291-3306`, `:3404-3422`). The subsequent `waitpid` PID/status check does not make the separately claimed siginfo record exact.

A portable replacement of `waitid` returning `si_pid=999`, `si_uid=999`, `CLD_KILLED`, and `SIGKILL`, together with the expected `waitpid(124)` result, made `_exact_signal_reap` return `(True, True)`. Thus isolated wrong-PID/wrong-UID siginfo mutants are accepted. ADR 0092 requires exact siginfo/wait/reap observations, not inference from only signal class/status plus a different wait API.

### P1-3 — No portable corpus invokes the complete D production state machine or covers the mandated D cut set

The lifecycle fixture remains a six-row **ADR 0091** helper ledger (`test/fixtures/outcome-two/lifecycle/owner-cases.jsonl:1-7`). Its portable consumer directly exercises only `confirm_setsid`, the legacy no-deadline/no-case/no-role form of `receive_descendant`, and the PID-only `stable_census` helper (`test/outcome-two-lifecycle-portable.py:505-611`). It never invokes `_qualify_admitted_fixed_process_lifecycle`, `_run_lifecycle_case`, `_lifecycle_leader`, or `_lifecycle_descendant`; it never executes any before-release, after-release, or TERM-then-KILL transaction.

The suite's declared/selected/consumed/oracle equality at `test/outcome-two-lifecycle-portable.py:665-687` therefore covers only old fd/helper/stop/cleanup rows plus those six isolated helper calls. There are no production-owner rows for descendant preregistration, clone/register cuts, second-gate sequencing, strict deadline receive, rights/credentials cardinality, case/role/identity binding, replay/extra packet and EOF closure, acknowledgement, recursive identity edges, spawn-after stages, stable adoption, TERM survival, KILL, PDEATH before/after release, waitid identity/status, waitpid/reap, subreaper set/read/restore, endpoint/pipe/close uncertainty, or final process/fd baselines.

The cross-file adapter test explicitly substitutes an all-true `LifecycleQualificationResult` (`test/outcome-two-trusted-launcher-portable.py:762-781`) and replaces `invoke_fixed_admitted_operation` instead of running D (`:816-863`). The focused D test decodes a preassembled all-true dictionary and checks only routing/source tokens (`test/native-qualification-d.test.ts:25-83`, `:85-156`). Removing any of the three cases, second gate, strict SCM protocol, census/adoption, signal/wait/reap, subreaper restore, or aggregate cleanup branches can remain green. This directly fails ADR 0092's production-path and declared = selected = consumed = oracle acceptance rule for D.

## Positive observations

The happy-path source now has three separately constructed case calls and does not alias one result across before-release, after-release, and TERM/KILL (`completion_trusted_runtime_launcher.py:3351-3406`). The leader is held behind a parent-confirmed post-`setsid` gate before descendant creation (`:3231-3249`). The strict production receive is deadline-driven, checks kernel credentials and one received right, binds case/role/sequence/full asserted identity, and checks EOF before outer acknowledgement (`:806-878`, `:3249-3261`). The outer path also retains transferred pidfd authority through adoption and exact `waitpid` reap, and the top-level qualifier attempts owner cleanup, subreaper restore/readback, and fd/child baseline checks after primary failures (`:3282-3293`, `:3333-3389`). These improvements do not resolve the findings above.

## Verification performed

Portable/static only:

- Exact `HEAD`: `3846383f0d88c190226356ca9aeeeda402943aaa`; worktree was clean before this report.
- `/usr/bin/python3 -I -B test/outcome-two-lifecycle-portable.py`: passed.
- `/usr/bin/python3 -I -B test/outcome-two-trusted-launcher-portable.py`: passed.
- Wrong-identity `waitid` portable probe against `_exact_signal_reap`: returned `(True, True)`.
- `git diff --check 3846383^ 3846383`: passed.
- Focused TypeScript/Node tests were not run because locked dependencies are not provisioned (`tsx: command not found`). This is an unexecuted gate, not native evidence and not the basis of the findings.

## Required before rereview

1. Create the descendant through an owner primitive that installs a blocked lease and atomic pidfd authority before child effects; transfer every primary and cleanup failure to the surviving aggregate owner, and preserve exact settlement authority at every clone/register/transfer cut.
2. Bind `waitid` observations to the exact descendant PID and expected UID as well as exact code/status, then compare them with the exact wait/reap outcome.
3. Add a closed ADR 0092 D ledger whose rows invoke the complete production D owner over mocked native boundaries and cover all three independent transactions, preregistration, second gate, strict transfer/replay/EOF, identity-edge censuses, adoption, TERM/KILL/PDEATH, wait/siginfo/reap, subreaper restore, every process/fd/protocol cut, and final baselines. Eliminate completed-result substitution as acceptance evidence.
4. Rerun all ordinary portable/static gates at one exact clean head and obtain a fresh hostile D review. Native execution remains forbidden.
