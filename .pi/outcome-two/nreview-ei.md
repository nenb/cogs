# Outcome Two native E/integration hostile review

- Reviewed head: `6d7d86401d96dfc9971fd9a4e0f784d0169cda62`
- Scope: Job E, thin integration, workflow/common-report integration, cleanup, schema, and ADR 0089 highs
- Method: static/portable only; no native selector, sudo, namespace, mount, seccomp, compression, or production launcher execution
- Disposition: **BLOCKED** — no P0; three P1 and one P2 findings

## P1

### P1-1 — Job E qualifies a test-owned substitute boundary, not production T2

`scripts/native-qualification/job-e-sandbox.py:61` imports private launcher details `_SystemOps` and `_enter_boundary`; `_root_setup()` itself owns unshare, tmpfs/bind/remount, PID-1 creation, chroot inputs, and teardown. It never drives the production T2 coordinator/root/process/final-authority state machine, and the accepted `launch_fixed_sandbox_probe` production entry does not exist. A defect in production namespace ownership, root materialization, exec/fd/map barriers, descendant ownership, or cleanup can therefore coexist with a passing E artifact. The emitted `sandbox-policy` digest is additionally only SHA-256 of the literal `sandbox-t2-x86-64-v1`, not the observed installed production policy.

### P1-2 — Thin integration accepts an open, substitutable production result

`scripts/native-qualification/thin-integration.py:130-145` treats `len([boolean values]) == 35 and all(...)` as `handoff_exact`. It does not require the production result's exact key set or version. Removing a required security observation and adding an unrelated true boolean still passes; unknown non-boolean fields also pass unless named exactly `evidence`. This can publish authoritative integration success for an incompatible or weakened result shape despite executing the real bootstrap route.

### P1-3 — E and integration do not own bounded cleanup on failure paths

Job E uses unbounded `subprocess.run`, pipe reads, and `waitpid(..., 0)`; its cleanup kill is followed by another unbounded wait. Integration acquires pipes/fds and forks without one enclosing ownership transaction; an admission-write failure bypasses `_read_pipes()` and leaves the child/read fds unmanaged, while `_read_pipes()` can lose close/reap cleanup if `kill` races with child exit and also uses blocking `waitpid`. These paths can leave resources until runner disposal or hit the workflow timeout without the required failure report, contrary to the exact cleanup contract.

## P2

### P2-1 — The native report schema does not encode its advertised semantics

`schemas/native-qualification-report-v1alpha1.json` permits arbitrary check IDs, duplicate IDs with different outcomes, any ordering/job combination, and `result: "pass"` with failed checks, false cleanup, or non-null failure data. `common.py` rejects those values when it is the producer, but schema-only artifact validation accepts them, and the portable test covers only one generated A/pass document rather than a hostile mutation corpus.

## Confirmed

- Workflow gates exact same-repository PR head and attempt 1, runs A-E after Quality on separate jobs, and runs integration only through `needs` on all A-E; integration downloads no A-E evidence.
- Static search confirms Job E is the sole native script containing `sudo`; its command is fixed noninteractive `--close-from=3` with `env -i`.
- `common.py` fixes driver identity, allowlists the complete environment, binds source/workflow/driver/common digests, orders checks, couples producer result/cleanup/failure fields, and writes one canonical metadata-only `O_EXCL` report.
- ADR 0089 accounting is within current highs: trusted/portable `7,739/8,930`, native `2,086/2,200`, aggregate `9,825/11,200`. Job E (`240/240`), integration (`170/170`), and common test (`120/120`) have no remaining per-file allowance; schema has `6` lines remaining.
- Static Python compilation passed. The portable E/integration tests passed. Common/AJV and `npm run schemas` were not executable in this checkout because dependencies are absent (`ajv`/`tsx`); this is not native evidence and was not treated as a product finding.

## Exact fix list

1. Restore an admitted fixed production sandbox-probe entry that owns the real production T2 transaction and returns observed facts only; make Job E invoke only that entry. Delete Job E's duplicate mount/namespace/chroot construction and private `_enter_boundary` import. Bind metadata to the actual observed seccomp/policy digest.
2. In thin integration, define the exact production result version and exact ordered string/boolean field sets; reject every missing, renamed, extra, wrongly typed, false, or malformed field before deriving checks. Add portable mutations for version, each required field, substitution, and extras.
3. Give both drivers write-ahead fd/child ownership and one all-path cleanup transaction with fixed monotonic deadlines, identity-safe TERM/KILL/reap, bounded nonblocking waits, and aggregate close errors. Cover failures at every pipe/open/dup/fork/write/read/close/reap boundary and require a cleanup-proved failure report.
4. Make the report schema conditionally fix the exact ordered check IDs per job and couple pass/fail, outcomes, cleanup, `failure_phase`, and diagnostics. Add schema mutations for wrong job/order/ID, duplicate ID with changed outcome, pass/fail contradiction, and cleanup/failure contradiction.
5. Adopt a cap-only ADR before these readable corrections: the directly affected Job E, integration, and common-test files are already at their exact highs, and the schema's six-line margin is not sufficient for the required closed semantics plus tests. Re-run portable/static gates and obtain a fresh exact-head review before any native selector.
