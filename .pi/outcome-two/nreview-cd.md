# Outcome 2 native review — Jobs C/D

Reviewed exact head `6d7d86401d96dfc9971fd9a4e0f784d0169cda62` statically. Scope: Jobs C/D Linux primitives, lifecycle, workflow/common report integration, cleanup/schema, and ADR 0089 highs. No native selector was executed.

## Findings

### P1 — C and D are not executable workflow jobs and cannot produce their declared artifacts

The workflow invokes both drivers with `--workflow-bound` (`.github/workflows/ci.yml:227-239`, `:252-264`), but C and D accept only `--native` (`scripts/native-qualification/job-c-descriptors.py:130-137`, `scripts/native-qualification/job-d-process-lifecycle.py:171-178`). Both therefore exit 2 before doing work. Even under their accepted selector, they print a reduced ad-hoc object containing schema-forbidden `unobserved` outcomes and only two cleanup keys; neither loads `common.py`, constructs `WorkflowContext`, calls `finalize_report`, or creates `/tmp/cogs-native-qualification-{C,D}.json`. The `always()` uploads consequently fail too, and integration can never become eligible.

### P1 — failure before registration can strand C/D children

C forks an effectful child at `job-c-descriptors.py:45`, but does not retain a pidfd or set `self.child` until `:64-67`. A `pidfd_open` failure leaves an untracked child/zombie; `restore()` has no child authority to reap it. Its timeout cleanup at `:94-95` also short-circuits `waitpid` when readiness is false.

D is worse: `terminate_tree()` forks a leader and descendant at `job-d-process-lifecycle.py:104-110`, both can execute effects, and the leader then pauses forever, but neither is registered until after the descendant handshake at `:119-121`. Descendant setup/write failure or a malformed/timed-out handshake routes to `restore()` with an empty process registry and leaves the unarmed leader alive. Failed PDEATH setup can likewise leave an unregistered adopted zombie. Disposable-runner teardown is not cleanup evidence.

### P2 — Job D does not prove the reported death mechanism

`_reap()` discards the `waitid` result (`job-d-process-lifecycle.py:46-53`). Thus the before/after PDEATH cases accept any child exit after the handshake, rather than requiring `CLD_KILLED`/`SIGKILL`; parent exit status is also unchecked. `qualify()` then marks every lifecycle fact through `all_reaped` pass as one blanket update (`:159-164`). The report can claim `before_release_death`, `after_release_death`, and bounded TERM/KILL without an outcome-specific oracle.

### P2 — cleanup claims lack the required exact baselines

C snapshots only an rlimit and a non-exact fd set (`job-c-descriptors.py:19-22`); D snapshots only fds/direct children and changes subreaper state without final readback (`job-d-process-lifecycle.py:22-30`, `:150-156`). Both `_fds()` implementations enumerate `/proc/self/fd` by pathname and include the transient enumeration descriptor (`job-c-descriptors.py:16-17`; `job-d-process-lifecycle.py:18`). Neither proves checkout, mount, namespace, path, or full common cleanup domains, although `common.py:22,175-179` requires all seven cleanup booleans to be true for a pass. Filling those fields with constants after wiring the common API would create placeholder cleanup evidence.

No P0 or P3 finding.

## Exact fix list

1. Change C/D production entry to the one workflow selector `--workflow-bound`; load `common.py`, call `WorkflowContext.from_environ`, and emit pass/fail only through `finalize_report` at the exact artifact path. Remove stdout/ad-hoc report production and all `unobserved` schema values.
2. Add portable/static tests that bind each YAML invocation argument to its driver's accepted entry, require the common context/finalizer path, validate C/D artifacts against the tracked schema and semantic coupling, and reject the current reduced reports.
3. Put every C/D fork behind a release gate. Register pidfd, start-time/session/group identity, descriptors, and ownership before release. For D descendants, have the registered leader report a still-blocked descendant, require outer registration/acknowledgement, then release. Every failure path must boundedly stop and reap all registered/adopted children.
4. Never short-circuit reap attempts. Preserve close/signal/wait errors, inspect `waitid` siginfo/exit status, require exact normal parent exits and exact SIGKILL deaths where claimed, and derive each D check from its own typed observation.
5. Replace `_fds()` with an explicitly opened, tracked `/proc/self/fd` enumerator, exclude exactly that fd, validate live entries, and treat enumerator close uncertainty as cleanup failure.
6. Capture and recompare the required common fd/child/mount/namespace/limit/path/checkout baselines; reread restored subreaper state. Mark a cleanup key true only from its observation, including unchanged non-mutated domains.
7. Preserve the ADR 0089 highs or stop for a new ADR before crossing them. Current gross additions are workflow `150/180`, schema `144/150`, common `219/220`, C `139/140`, D `180/180`, C test `59/60`, D test `70/70`, and native aggregate `2086/2200`; D has no per-file margin.

Portable Node tests were not runnable in this checkout because `node_modules`/`tsx` is absent; static source/diff checks completed without native execution.

NREVIEW COMPLETE
