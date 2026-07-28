# Outcome 2 final trusted-closure hostile review — holistic

- Review ID: `O2-FINAL-R-HOL`
- Exact reviewed implementation head: `3135c16add3abe1b32785f3d577cccd811ce5e54`
- Governing decision: accepted ADR 0089, with its non-conflicting ADR 0087/0088 boundaries
- Acceptance gate: `.pi/outcome-two/closure-second-correction-gate.md`
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Scope: review only; no production, schema, test, fixture, workflow, or native implementation was changed or executed
- Native readiness: **NO — native Jobs A–E implementation may not begin**

## Review basis

Read all five first `closure-review-*.md` reports, all five second `closure-rereview-*.md` reports, the second-correction acceptance gate, ADR 0087, ADR 0088, ADR 0089, the Outcome Two plan/design, and the exact parser, closure, launcher, schema/registration, seven portable suites, TypeScript wrapper, and complete fixture tree at `3135c16`.

The final correction materially improves source admission, read-only issuance, ancillary cardinality, generation rows, exec EOF ordering, descriptor enumeration, observed-fact construction, UID/GID ordering, closure-side lifecycle, and deletion of the old transcript-player symbols. Those changes do not close the production composition or the hostile acceptance gate.

## Findings

### P0-1 — The production result still promotes an incomplete policy/observation set to exact T2 facts

**Exact symbols:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:61-109` — `_DENIED_SYSCALLS`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:613-675` — `_SystemOps.drop_bounding`, `install_seccomp`, `seccomp_mode`, `probe_seccomp_denials`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1140-1165` — `_enter_boundary`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1366-1388` — `_namespace_facts`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1493-1508` — `_run_tool_with_ops` acquisition conclusion
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1674-1688` — `_coordinate_with_ops` fact publication

The fixed filter does not constrain `execveat` to fd 198 plus `AT_EMPTY_PATH`; it admits every `execveat` shape. It also permits `prctl`, so the required `PR_SET_SECCOMP` route is not denied. Its socket table omits `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`, `recvmmsg`, and `sendmmsg`. Only four denial outcomes are probed.

`capget_zero()` observes effective/permitted/inheritable sets, but bounding and ambient sets are not independently reread after mutation. `_namespace_facts()` proves only that four namespace inode pairs differ from the outer baseline and that UID/GID maps each have one line; it does not prove exact map values or required namespace ownership relations. Nevertheless `capabilities_zero`, each `*_namespace_exact`, `seccomp_denials_exact`, and `no_acquisition_route` become successful result fields. `no_acquisition_route` is derived only from the final fd table, root flags/no-proc, and two denial probes, not every route in the accepted policy table.

This is the same confused-deputy failure ADR 0089 forbids: Jobs E/integration would consume exact-looking production booleans that the production owner did not establish. Native execution cannot repair the result semantics.

### P1-1 — The production `clone3` request places `SIGCHLD` in the stack field, not `exit_signal`

**Exact symbol:** `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:454-460`, `_Ops.clone3_pidfd`.

Linux `struct clone_args` orders the relevant fields as `flags, pidfd, child_tid, parent_tid, exit_signal, stack, ...`. The production tuple is:

```text
(_CLONE_PIDFD, &pidfd, 0, 0, 0, SIGCHLD, 0, ...)
```

It therefore requests `exit_signal=0` and a non-null numeric stack address of `SIGCHLD`. The real helper route can fail with an invalid clone request instead of returning the child/pidfd pair required by `_spawn_helper`; even an accepted request would not have the intended wait/reap contract. Portable `KernelOps.clone3_pidfd()` returns a prebuilt pair and cannot expose this ABI defect. The trusted closure is not natively runnable as specified.

### P1-2 — Launcher process and descriptor ownership is still lost across registration and failure cuts

**Exact symbols:**

- `completion_trusted_runtime_launcher.py:883-1032` — `_ProcessLease`, `_ProcessOwner`, `_register_process`, `_stop_process`
- `completion_trusted_runtime_launcher.py:1400-1543` — `_run_tool_with_ops`
- `completion_trusted_runtime_launcher.py:1613-1709` — `_coordinate_with_ops`

`_run_tool_with_ops()` forks the authority-bearing namespace owner and only afterward calls `_register_process(pid)`; unlike the worker and inner T2 child, that process has no release gate. `_register_process()` closes the pidfd if start-time/session/group/executable observation fails, even though the process may still be live. On T2 failures, the separately opened `child_lease` is not owned by a `_ProcessOwner` and is neither stopped nor closed in `finally`. On success it is marked `reaped=True` solely because the namespace owner sent an exit record, without an outer pidfd death observation or explicit authority transfer.

The `descendants` field is never populated by a recursive census, no subreaper/equivalent is installed, and `descendants_reaped`/`namespaces_released` are inferred from an empty direct `process_owner.processes` list. The launcher also retains many raw `os.close()` paths, including issuance and tool-pipe failure paths, outside `_FdLease`; after-effect close uncertainty can therefore still be retried or suppressed.

A registration fault, child-status fault, mapping fault, close-after-effect fault, or crashed worker can leave live authority or an uncertain descriptor while cleanup is reported from a narrower direct-owner inventory. This fails `AT-LIFE-01/02` and `AT-FD-CLOSE-01` end to end.

### P1-3 — Root rollback and typed unavailability are still discarded inside `_namespace_owner`

**Exact symbols:**

- `completion_trusted_runtime_launcher.py:1111-1131` — `_materialize_root`
- `completion_trusted_runtime_launcher.py:1206-1295` — `_namespace_owner`
- `completion_trusted_runtime_launcher.py:1389-1399` — `_recv_status`

`root` is assigned only after `_materialize_root()` returns. A failure after `mkdir`, tmpfs mount, directory creation, object copy/readback, or assignment leaves `root is None`; the exception path therefore skips unmount/rmdir. The mount namespace eventually dies, but the host-visible fixed root directory can remain, and no surviving owner has retained parent/root/mount-namespace authority to authenticate and remove it.

The same exception path catches `RuntimeLauncherUnavailable`, sends only its class name, suppresses child/root cleanup errors, and exits 125. `_run_tool_with_ops()` then treats the record as generic launcher failure. The exact unavailable primitive and whether cleanup was observed are lost; cleanup uncertainty cannot be distinguished from unavailable. This directly leaves `AT-ROOT-01`, `AT-ADAPT-REC-01`, and `AT-UNAV-01` unsatisfied.

### P1-4 — The portable launcher/recovery gate still certifies labels and reachability rather than the named production state machines

**Exact test symbols:**

- `test/outcome-two-trusted-launcher-portable.py:435-453` — `prove_fixture_oracles`
- `test/outcome-two-trusted-launcher-portable.py:456-465` — `parent`
- `test/outcome-two-recovery-portable.py:125-203` — `crash_inner_transaction`

The launcher suite directly challenges only a small admission/ancillary/fd/boundary subset. For every other acceptance family it checks that the declared `production_method` is callable, classifies it as `static_evidence`, and inserts every row into `consumed`, `oracle`, and `sentinel` sets without invoking the method or removing/challenging its named branch. It never drives `_bootstrap_with_ops`, `_WorkerIssuer._accept_runtime_closure`, `_consume_issuance`, `_run_tool_with_ops`, `_coordinate_with_ops`, `_materialize_root`, `_ProcessOwner.register/cleanup`, or `_recv_status`.

The recovery suite forks a harmless stopped pipe child, manually constructs `_ProcessLease`, and monkeypatches `_process_matches` and `pidfd_send_signal`. It does not crash `_worker_main` or the authority-bearing closure/root/namespace transaction at the declared cuts. Thus the old transcript players are deleted by name, but their acceptance role has been replaced by call-graph/ledger assertions rather than production primitive adapters. The exact clone ABI, root rollback, lifecycle, T2 observation, and unavailable defects above all remain green as a result.

### P2-1 — Accepted strict process/control-record predicates remain loose

**Exact symbols:**

- `completion_trusted_runtime_launcher.py:950-956` — `_start_time`
- `completion_trusted_runtime_launcher.py:1389-1399` — `_recv_status`
- `completion_trusted_runtime_launcher.py:1366-1388` — `_namespace_facts`

`_start_time()` does not require the requested PID prefix, exactly one complete record, strict state/fields through field 22, or integer bounds. `_recv_status()` accepts any canonical JSON object containing the version; callers check selected keys but do not enforce exact message shapes, sequence numbers, cardinality, or absence of extra fields. UID/GID map readback checks line count rather than exact singular values. The required one-byte parser mutants do not reach exact typed production errors because the launcher suite does not invoke these parsers. `AT-RECORD-01` and the exact identity basis used by lifecycle facts remain open.

## Acceptance-gate disposition

The implementation does not satisfy `AT-SECCOMP-01`, `AT-T2-OBS-01/02`, `AT-ROOT-01`, `AT-LIFE-01/02`, `AT-FD-CLOSE-01`, `AT-RECORD-01`, `AT-UNAV-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01`, or the branch-removal portion of `AT-FIXTURE-01`. Green fixture-set equality and symbol reachability are not substitutes for those production predicates.

## Focused portable/static checks

Review host: Darwin arm64. No Linux native primitive, production invocation, compression tool, sudo, namespace, mount, seccomp, `map_files`, workflow, provider, cloud, AWS, deployment, or Jobs A–E action was run.

- Exact initial head: **PASS**, `3135c16add3abe1b32785f3d577cccd811ce5e54`.
- Seven direct isolated `/usr/bin/python3 -I -B` portable suites: **PASS**.
- Seven optimized `-O -I -B` rejection runs: **PASS**, 7/7 rejected.
- AST parse of three production modules and seven Python portable suites: **PASS**.
- Obsolete production transcript symbols (`_drive_fixed_*`, `_T2_SEQUENCE`, `_seal_source`): **absent**; the matching strings remain only in tests that assert absence.
- Static `clone_args` field check: **FAIL contract**, `SIGCHLD` occupies tuple index 5 (`stack`) while index 4 (`exit_signal`) is zero.
- Static seccomp check: **FAIL contract**, no `execveat` argument check, no `prctl` denial, and the socket operations listed in P0-1 are absent.
- Static launcher descendant-owner check: **FAIL contract**, no recursive descendant/subreaper implementation is reachable; only the result field and unused lease tuple exist.
- TypeScript wrapper/AJV run: **BLOCKED**, locked `node_modules/.bin/tsx` is absent. The direct Python producer/schema/consumer suite passed, but this is not an AJV pass.
- `git diff --check d111eac..3135c16` and ADR 0089 correction range: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Native schema/scripts/tests: **absent as expected before this decision**.

## Line accounting

Gross additions from `bec0a19` are within ADR 0089's individual highs: parser `306/320`, closure `2078/2100`, launcher `1889/1900`, schema `134/260`, schema registration `27/30`, all seven Python suites and wrapper within their highs, and fixtures `680/900`. The trusted/portable gross subtotal is `7783/8930`.

Numeric compliance does not close the findings.

## Native implementation readiness

**NO. Do not begin native Jobs A–E implementation.** ADR 0089 requires a fresh exact-head review with no unresolved P0–P3. This head has one P0, four P1, and one P2 finding. Native jobs would either fail on the malformed production clone request or qualify production booleans and cleanup claims that are not backed by the accepted exact observations/owners. Thin integration remains blocked as well. This report grants no execution authority.

O2-FINAL-R-HOL COMPLETE
