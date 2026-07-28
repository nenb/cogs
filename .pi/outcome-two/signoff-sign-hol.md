# Outcome 2 exact-head holistic signoff

- Signoff ID: `O2-SIGN-HOL`
- Exact reviewed implementation head: `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`
- Review scope: only the findings in the five final-review reports at `3135c16` and corrections through `aa45a04`; no broad re-audit
- Native or privileged execution: not performed
- Verdict: **BLOCKED — native Jobs A–E implementation is not ready**

## Unresolved findings

### P1-1 — Failure cuts can still escape before transaction ownership and cleanup are active

**Exact symbols:**

- `completion_trusted_runtime_launcher._ProcessOwner.spawn` at `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:750-759`
- `completion_trusted_runtime_launcher._RootOwner.prepare` at `:1052-1063`
- `completion_trusted_runtime_launcher._run_tool_with_ops` at `:1483-1496`
- `completion_trusted_runtime_launcher._coordinate_with_ops` at `:1672-1686`

`_ProcessOwner.spawn()` creates both release-pipe leases before `clone_pidfd()`, but has no enclosing failure cleanup. A clone failure leaks both descriptors. More importantly, a close-after-effect failure at `read_lease.close()` occurs after the child and pidfd exist but before `register()` places either under `_ProcessOwner`; the gated live child, pidfd, and uncertain descriptor therefore escape the surviving owner.

`_run_tool_with_ops()` similarly creates four pipe leases, two socket endpoints, and root authority before entering its `try` block. `_RootOwner.prepare()` itself has no rollback around parent open, root creation, root open, stat, and assignment. Any fault in those cuts bypasses the function's process/fd/root cleanup. `_coordinate_with_ops()` creates its issuance and helper socketpairs before its `try`, so failure of the second pair also bypasses recovery.

These are the same final-review lifecycle/root/fd/unavailability cuts, not a new broad issue. They also permit `RuntimeLauncherUnavailable` to escape without proved cleanup instead of being converted to terminal cleanup uncertainty. `AT-ROOT-01`, `AT-LIFE-01`, `AT-FD-CLOSE-01`, and `AT-UNAV-01` remain open.

### P1-2 — Launcher and recovery fixtures still manufacture typed codes and sentinels instead of exercising their named production branches

**Exact test symbols:**

- `test/outcome-two-trusted-launcher-portable.py:204-212` — `PrimitiveModel.trip`
- `test/outcome-two-trusted-launcher-portable.py:228-284` — generic early primitive trips
- `test/outcome-two-trusted-launcher-portable.py:384-412` — per-name handler dispatch
- `test/outcome-two-trusted-launcher-portable.py:615-655` — production entry wrappers
- `test/outcome-two-recovery-portable.py:99-151` — fabricated authority registration and crash marker

`PrimitiveModel.trip()` constructs `RuntimeLauncherError` directly from each fixture's `intended_code` and records the fixture's `sentinel` itself. Rows sharing a production method consequently collapse at one early operation regardless of `primitive_fault`: `_enter_boundary` rows fail at modeled `chroot`, `_run_tool_with_ops` rows fail at `socketpair`, `_coordinate_with_ops` rows fail during the initial descriptor open, and `_materialize_root` rows fail at the first mount. The declared exec, seccomp, observation, root-cut, unavailable, and cleanup branches are not reached.

Recovery manually registers three synthetic process leases and raises the row error from `AuthorityTransaction.crash()`; it does not crash `_worker_main`, closure helper preparation, namespace/root construction, or another authority-bearing production cut. The production recovery helper is exercised only after the fixture has fabricated both the cut and typed outcome.

Thus the correction replaces set insertion with production-entry dispatch but retains the final-review label-player defect. `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01`, and the launcher/recovery portions of `AT-FIXTURE-01` remain open.

### P2-1 — Remaining lifecycle/report sentinels are metadata, not branch-removal oracles

**Exact test symbols:**

- `test/outcome-two-lifecycle-portable.py:535-546`
- `test/outcome-two-runtime-report-portable.py:226-248,357-386`
- `test/fixtures/outcome-two/lifecycle/faults.jsonl`
- `test/fixtures/outcome-two/reports/mutations.jsonl`

The lifecycle and report suites require only that `production_method` and `sentinel` are nonempty, execute their normal runners, and compare declared/executed IDs. Their fixture sentinels repeat the same production-method labels; no test removes or independently challenges the named branch. Lifecycle rejection rows also retain the generic `typed-rejection` code. This leaves the explicit branch-removal and exact typed-code portion of `AT-FIXTURE-01` unresolved.

## Focused checks

- Exact pre-signoff head: **PASS** — `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`.
- Seven isolated `/usr/bin/python3 -I -B` portable suites: **PASS**.
- Seven optimized `-O -I -B` rejection runs: **PASS**.
- Correction-range `git diff --check de7f0e4..aa45a04`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Native Linux Jobs A–E, thin integration, namespace, mount, seccomp, `map_files`, compression qualification, workflow, provider, cloud, AWS, and deployment actions: **not run**.

## Native implementation readiness

**NO.** The exact head retains two P1 findings and one P2 finding. Green portable output is non-accepting because the mandatory hostile adapters can synthesize the expected result before reaching the named branch, while production still loses ownership at pre-`try` and spawn-registration cuts. Native execution cannot correct either defect.

SIGNOFF COMPLETE
