# ADR 0092 exact-head hostile portable review

- **Reviewed head:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** portable acceptance, declared/selected/consumed/oracle equality, production branch reachability, readable-transition enforcement, and ADR highs
- **Execution boundary:** static and portable Python only; no native selector, sudo, namespace/mount/seccomp qualification, workflow dispatch, provider, network, cloud, or production edit
- **Verdict:** **BLOCKED**

## P0–P3 summary

| Severity | Count | Verdict |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 4 | blocking |
| P2 | 1 | blocking |
| P3 | 0 | none found |

## Findings

### P1-1 — The trusted-launcher CLI still turns a successful bootstrap into exit 1

`completion_trusted_runtime_launcher.py:3492-3500` raises `SystemExit(_bootstrap_main())` inside a `try` and catches it with `except BaseException`. A successful `_bootstrap_main()` return of zero is therefore caught, emits `runtime-launcher-failed`, and exits one. This is the exact CLI defect ADR 0092 section 3 requires every wrapper to remove.

The portable launcher suite imports the module and calls `_bootstrap_with_ops()` directly (`test/outcome-two-trusted-launcher-portable.py:427-489`); it never executes the `__main__` wrapper, so its green result cannot detect this branch.

### P1-2 — D and E have no portable execution of their complete production state machines

The D production authority is `_qualify_admitted_fixed_process_lifecycle()` → three `_run_lifecycle_case()` transactions (`completion_trusted_runtime_launcher.py:3216-3427`). The portable lifecycle suite instead invokes isolated `_ProcessOwner.confirm_setsid`, `receive_descendant`, and census helpers (`test/outcome-two-lifecycle-portable.py:507-610`). No test calls either complete D production function. Consequently the three independent cases, aggregate owner cleanup, subreaper restoration, case ordering/cardinality, transfer EOF/replay, adoption, exact signal/wait/reap, and final descriptor/child baselines can all regress outside portable reach.

The E authority is `_launch_admitted_fixed_sandbox_qualification()` → root capsule → `_root_capsule_entry()` → `_sandbox_only_transaction()` (`completion_trusted_runtime_launcher.py:2855-3045`). No portable test calls `_sandbox_only_transaction()` or drives this chain over a syscall model. `production_operation_contracts()` constructs an already-completed all-true `SandboxQualificationResult` (`test/outcome-two-trusted-launcher-portable.py:652-668`), while `capsule_contract()` calls `_decode_root_capsule()` directly and searches bootstrap source tokens (`674-733`). Those are precisely the completed-result/helper/token substitutes forbidden by ADR 0092 section 9.

### P1-3 — Common, admission, and custodian acceptance still terminate at high-level substitutes

The supposed six-route common adapter replaces `invoke_fixed_admitted_operation()` with a function that returns `result_for(...)`, an already-completed typed result (`test/outcome-two-trusted-launcher-portable.py:762-875`). The common companion goes higher still: its fake `Ops.run_fixed_operation()` returns a completed result dictionary (`test/native-qualification-common.test.ts:188-272`). Neither test reaches the complete launcher/closure owner above mocked syscalls, so immutable operation receipts and publication are accepted without proving that an exact production transaction generated the receipt.

Held/root admission is likewise incomplete as a closed case set. The self-consistent unauthorized root mutation loop calls `_decode_root_capsule()` directly (`test/outcome-two-trusted-launcher-portable.py:695-714`), and common admission checks `_blob_matches()` plus AST call order rather than a complete unauthorized `NativeSession` production route (`test/native-qualification-common.test.ts:188-205`).

Custodian coverage directly calls `_cleanup_owned()` with a fabricated receipt and patches `_enumerate_directory`, `_identity_at`, `_exchange_verified`, and `_remove_report_directory`—production helper boundaries, not syscalls (`test/native-qualification-common.test.ts:290-347`). It does not drive custodian startup, publish intent, staging, publication, upload failure, custodian loss, retirement, and replacement through the complete production custodian state machine. ADR 0092's production-path acceptance requirement remains unmet.

### P1-4 — The new case-equality ledgers do not prove consumption or their declared oracles

`outer_process_corpus()` mechanically inserts every row ID into `consumed` and `oracle` after accepting any listed exception (`test/outcome-two-trusted-launcher-portable.py:1094-1120`). It never checks `row["sentinel"]`, `cleanup_domains`, exact rejection code, or that a reject-row fault fired. This is observable in the checked-in fixture: close rows declare `outer:close-before`/`outer:close-after`, but `OuterKernel.consume_fault("close")` records only `outer:close` (`981-989`). The suite still passes. The accept row's `outer:complete` sentinel is never emitted either.

The outer model also only drives the parent side of `_run_held_python_with_ops()` because `clone_pidfd()` always returns a parent PID (`938-940`). The child-side release/setsid/transition, fd duplication, complement closure, and `execve` branches at production lines 2030-2051 are unreachable. Its fixture has only first-invocation generic memfd/pipe/close cuts, omitting the second memfd, each pipe allocation, lseek/fchmod, child dup/dup2/exec/exit, cleanup signal/wait, and per-descriptor close cuts. Reject rows do not assert descriptor/process baseline restoration or foreign-fd preservation.

The new C corpus does invoke the complete C owner, which is a material improvement, but its equality is still nominal: `sentinel` and `cleanup_domains` are never checked and `oracle` is populated unconditionally (`test/outcome-two-runtime-closure-portable.py:635-693`). A generic rejection after the selected fault is enough to mark the row oracle-proved. The older process-owner matrix similarly has only one `selected` list and does not compare declared/selected/consumed/oracle sets (`test/outcome-two-lifecycle-portable.py:507-611`). Thus ADR 0092's required four-way equality is not established.

### P2-1 — The mandatory readable-transition gate does not enforce the stated surfaces or rule

`test/outcome-two-portable.test.ts:119-140` scans closure, launcher, and portable test source with token/semicolon regexes, but omits `common.py` and all six clients despite ADR 0092 requiring AST/static checks on closure, launcher, common, and every client. The separate common check only enforces 160-character width and multi-line `Try`/`With` nodes starting at line 800 (`test/native-qualification-common.test.ts:400-407`); it does not cover clients or reject packed `if`, loop, assignment, cleanup, or claim derivations.

Concrete accepted packing remains in security-critical production:

- launcher line 1944 derives all seven cleanup authorities in one 580-character physical line;
- launcher line 3040 constructs every E claim positionally on one line;
- launcher lines 2335-2339 pack dispatch conditions and returns;
- common lines 116, 127-129, and 151-157 pack lease state/descriptor declarations, while lines 553-589 pack schema decisions/effects.

The launcher contains 79 single-line compound AST nodes overall, yet the current static gate passes. This is the readability failure ADR 0092 section 8 was intended to make mechanically unreachable.

## High accounting

No numeric high breach was found. Gross additions from `bec0a19` are:

- trusted/portable listed files: **10,775** lines;
- Outcome Two fixtures: **392 / 1,200** newline-counted lines;
- trusted/portable subtotal: **11,167 / 14,500**.

Notable individual positions are launcher **3,500 / 3,500**, closure **2,647 / 2,650**, runtime-closure portable **700 / 700**, and trusted-launcher portable **1,200 / 1,650**. Numeric compliance does not cure unreachable state machines or unreadable packed transitions.

## Portable verification

Passed directly under `/usr/bin/python3 -I -B`:

- all seven Outcome Two Python portable suites;
- focused runtime-closure and trusted-launcher suites after the ADR 0092 additions;
- Python compilation of closure, launcher, common, and all six clients;
- correction-head targeted `git diff --check` for changed portable surfaces.

The TypeScript wrappers could not be rerun in this clean worktree because the `tsx` package is not installed (`ERR_MODULE_NOT_FOUND`). Their source and embedded Python probes were reviewed statically. The green Python suites are not acceptance because the findings above show completed-result/helper substitutions and unobserved branches.

# Final verdict: BLOCKED

`3846383f0d88c190226356ca9aeeeda402943aaa` has four unresolved P1 findings and one unresolved P2 finding. ADR 0092 portable signoff is denied; this review grants no native, workflow, sudo, provider, cloud, production, release, or later execution-ADR authority.
