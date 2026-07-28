# Outcome 2 exact-head lifecycle signoff

- Signoff ID: `O2-SIGN-LIFE`
- Exact reviewed head: `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`
- Scope: only final-review findings and the corrections through this head, focused on clone3, process/root preregistration, deadlines, close uncertainty, strict records, and their portable acceptance evidence
- Native/privileged execution: not performed

## Unresolved findings

### P1-1 — Process and root write-ahead ownership still has unrecoverable cuts

`_ProcessOwner.spawn()` creates the gated child and pidfd, then closes `read_lease` before calling `self.register(...)` (`completion_trusted_runtime_launcher.py:750-759`). An after-effect close failure at line 758 leaves the live gated child, pidfd, and write gate outside `processes`; caller cleanup has no process authority to recover.

`_RootOwner.prepare()` records create intent before `mkdir`, but records root identity only after the following `os.open`/`fstat` (`:1052-1062`). Cleanup removes the created directory only when `identity is not None` (`:1064-1078`). A fault after successful `mkdir` but before identity assignment therefore skips removal and sets `cleaned = True`. A focused injected check at this head produced `root_exists_after_claimed_cleanup=True`, `cleaned=True`, and `identity=None`. `_run_tool_with_ops()` also calls `root_owner.prepare()` before entering its recovery `try` (`:1479-1496`), so preparation failures bypass cleanup of the already-created pipe, socket, and root authorities.

These are the exact registration/root failure cuts challenged by the final reviews; preregistration is not complete on every path.

### P1-2 — The surviving owner still has unbounded issuance waits

The worker issuer performs blocking acknowledgement `recvmsg` and trailing `recv(1)` (`completion_trusted_runtime_launcher.py:708-719`). The outer consumer performs blocking initial `recvmsg` and trailing `recv(1)` (`:941-970`). `_consume_worker_handoff()` applies an absolute deadline only before entering `_consume_issuance`; once the initial packet is readable, a stalled worker can hold the outer in the trailing receive indefinitely. The outer therefore cannot enforce the accepted transaction deadline or reach its retained process authority to terminate/reap the worker. The workflow timeout remains the effective supervisor for these cuts.

### P1-3 — Close uncertainty can become success on a repeated process-owner cleanup

`_ProcessOwner.cleanup()` does not replay its stored poison (`completion_trusted_runtime_launcher.py:771-779`). `_stop_process()` records a close failure by leaving the pidfd lease `CLOSE_UNCERTAIN`, but on the next call it handles only an `OWNED` pidfd (`:899-907`) and returns success; `ProcessOwner.stop()` then removes the process lease. A focused check at this head produced:

```text
cleanup 1 RuntimeLauncherCleanupError 1 CLOSE_UNCERTAIN
cleanup 2 SUCCESS 0 CLOSE_UNCERTAIN
```

Thus the correction does not preserve permanent close uncertainty or the same immutable failure across retries, as required by the final lifecycle findings.

### P1-4 — Launcher and recovery fixtures still manufacture branch proof instead of challenging the selected production cuts

The launcher suite now calls named production entries, but `PrimitiveModel.trip()` itself inserts the row sentinel and raises an error carrying the fixture's requested `intended_code` (`test/outcome-two-trusted-launcher-portable.py:202-211`). Cases sharing `_run_tool_with_ops`, for example, all fail at the same modeled `ops.socketpair` operation regardless of their declared primitive fault (`:267-268`). This cannot detect removal or breakage of the named root, exec, lifecycle, deadline, unavailable, or strict-record branch.

Recovery similarly registers three fabricated process leases and turns each declared cut into `model.trip("transaction.<label>")` (`test/outcome-two-recovery-portable.py:93-151`); it does not crash the authority-bearing worker/helper/root/namespace production transaction. The generated sentinel and generated intended code make selected/consumed/oracle equality self-fulfilling. The final-review adapter/recovery finding therefore remains open despite all seven direct suites passing.

### P2-1 — Strict mapping and control-record enforcement remains incomplete

`_parse_maps()` parses device and inode fields (`completion_trusted_runtime_launcher.py:1279-1298`), but `_final_mapping_check()` opens the corresponding `map_files` object and checks only its bytes/digest (`:1303-1329`); it never compares parsed device/inode identity with `fstat(map_lease.fd)`. The accepted strict complete-record/device/inode/generation predicate is therefore not enforced.

The sandbox status parser closes top-level key sets and sequence, but validates scalar types only for `pid` and `status` (`:1453-1485`); `error` and `unavailable` string fields and nested `observations` do not receive event-specific strict type/shape validation. The final strict-record finding is only partially corrected.

## Verification

- Seven direct isolated Python portable suites: pass.
- `git diff --check`: pass.
- `git fsck --no-progress --no-dangling`: pass.
- Locked Node/AJV/typecheck/formatter toolchain: unavailable in this worktree; not installed.
- No native Linux primitive or privileged operation was run.

## Native implementation readiness

**NOT READY.** Exact head `aa45a04` retains four genuine P1 findings and one P2 finding in the final-review correction scope. ADR 0089's zero-unresolved-P0–P3 prerequisite is not met, so native Jobs A–E implementation may not begin.

SIGNOFF COMPLETE
