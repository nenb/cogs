# Outcome 2 final exact-head hostile review — sandbox

- Review ID: `O2-FINAL-R-SANDBOX`
- Exact reviewed implementation head: `3135c16add3abe1b32785f3d577cccd811ce5e54`
- Governing decision: accepted ADR 0089, with its incorporated `O2-FIX2-AUDIT` acceptance catalog
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Scope: review only; all five first closure reviews, all five second rereviews, the acceptance gate, ADR 0089, and the exact production/portable closure surfaces were read before this decision.
- Native/privileged execution: not performed.

## Decision

**BLOCKED — not ready to implement native Jobs A–E or thin integration.**

No P0 or standalone P3 was established at this exact head. Five genuine P1 findings and one P2 finding remain. The direct portable suites are green, but the launcher and recovery suites do not drive the production T2 transaction through a shared primitive protocol, and the production system path is both non-runnable on its nominal success finalizer and materially short of ADR 0089's observed security/ownership contract.

## Findings

### P1-1 — The nominal successful tool run always becomes `cleanup-uncertain`

**Production symbols:** `_run_tool_with_ops`, `_ProcessLease.pidfd`, `_FdLease.close`  
**Locations:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1482-1511,1515-1544`

After the namespace owner has been reaped, `_wait_bounded(lease, deadline)` sets `lease.reaped = True`. The `finally` branch then executes `os.close(lease.pidfd)` at line 1535, but `lease.pidfd` is an `_FdLease`, not an integer. Python raises `TypeError: '_FdLease' object cannot be interpreted as an integer`; that error is appended to `failures` and line 1544 replaces the otherwise successful return with `RuntimeLauncherCleanupError`.

A focused no-effect diagnostic reproduced the exact type failure. Thus neither gzip nor zstd can return successfully through the production `_SystemOps` route, independently of native kernel availability. The portable launcher suite never calls `_run_tool_with_ops`, so its green result cannot detect this.

There is a second ordering defect in this same path: `_namespace_owner` releases the PID-1 child at line 1253 before sending the outer `child` record at line 1254. The released child can send its `boundary` record first, while `_run_tool_with_ops` requires `child` to be the first packet at lines 1427-1434. That is a scheduler-dependent fail-closed race even after the deterministic finalizer defect is fixed.

### P1-2 — T2 security facts are still derived from incomplete or non-equivalent observations

**Production symbols:** `_enter_boundary`, `_namespace_facts`, `_final_mount_check`, `_coordinate_with_ops`, `_ObservedFacts`  
**Locations:** `completion_trusted_runtime_launcher.py:604-623,1140-1165,1344-1387,1492-1511,1663-1706`

`_ObservedFacts` prevents an omitted result field, but several values supplied to it are not the independent facts ADR 0089 requires:

- `capget_zero()` observes only effective/permitted/inheritable words. Bounding capabilities are dropped but never reread as a complete zero set; ambient capabilities and supplementary groups are cleared but never reread.
- `_namespace_facts()` proves only that four namespace inode pairs differ from the outer process. It does not prove namespace type, parent/user-namespace ownership relations, or equality to retained transaction handles. It treats one UID-map line and one GID-map line as exact without checking their bytes or parent IDs.
- `pid_one` is reduced to the final `NSpid` token, without the complete required PID-1 metadata/ownership conjunction.
- `_final_mount_check()` checks root flags and absence of any proc filesystem, but does not inspect the required host-checkout/host-executable pathname exposure set.
- `descendants_reaped` and `namespaces_released` are both inferred from an empty direct `_ProcessOwner.processes` list. There is no recursive descendant census, retained namespace-handle inventory, or namespace baseline comparison. `mounts_restored`/`paths_restored` are only `ismount`/`lexists` checks of one pathname; checkout and limit baselines are absent from `RuntimeQualificationResult` entirely.

Consequently, once P1-1 is repaired, `_coordinate_with_ops` could turn these weaker observations into authoritative fields named `capabilities_zero`, namespace `*_exact`, `descendants_reaped`, and `namespaces_released`. Native execution cannot make that semantic promotion truthful; the production observation contract and portable mutation model must be corrected first.

### P1-3 — The consumed-exec/seccomp authority contract is not the ADR 0089 contract

**Production symbols:** `_DENIED_SYSCALLS`, `_SystemOps.install_seccomp`, `_SystemOps.probe_seccomp_denials`, `_child_fd_install`, `_run_tool_with_ops`  
**Locations:** `completion_trusted_runtime_launcher.py:60-109,624-683,1166-1205,1441-1455,1492-1508`

The architecture check is first and the successful `CLOEXEC` fd/map/input ordering is directionally present. The remaining exact defects are:

1. `_child_fd_install` receives the complete issued descriptor tuple, including executable objects for both tools, loaders, and libraries, then creates another executable duplicate before closing the complement. The pre-exec child therefore does not receive exactly one executable-authority descriptor and “no second executable descriptor.”
2. The filter never inspects `seccomp_data.args`; it simply allows every `execveat` syscall. It does not admit only fd 198, the empty path, and `AT_EMPTY_PATH` for the fixed trusted attempt.
3. The accepted socket table is incomplete. Static comparison found these required routes absent: `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, and `getsockopt`.
4. `probe_seccomp_denials()` observes only `execve`, `socket`, `memfd_create`, and `seccomp`. `seccomp_denials_exact` and `no_acquisition_route` are then constructed from those four/two probes plus fd/root booleans, not from every route in the accepted exhaustive table and the complete authority inventory.

The final post-exec fd/map/noexec checks are useful fail-closed defenses, but they do not satisfy the specified pre-exec authority shape or make the broader policy observations true.

### P1-4 — Root, process, descriptor, namespace, and unavailable ownership is not recoverable end to end

**Production symbols:** `_materialize_root`, `_namespace_owner`, `_run_tool_with_ops`, `_recover_transaction_with_ops`, `_consume_issuance`, `_ProcessOwner`  
**Locations:** `completion_trusted_runtime_launcher.py:1034-1110,1111-1139,1206-1295,1400-1544,1595-1611`

- `_materialize_root` has no write-ahead owner. `_namespace_owner.root` is assigned only after mkdir, tmpfs mount, all copies, and readbacks return. A failure after creation/mount/copy leaves `root is None`, so its cleanup skips the owned state. The surviving outer owner has no retained parent fd, mount-namespace fd, root/mount identity, or intent record.
- The namespace owner is created by plain `fork()` and can execute effects before `_register_process`; it has no preregistered release gate or atomic pidfd creation. The outer PID-1 lease is obtained only after that child has already been released by the inner owner.
- `_ProcessOwner` owns direct processes only. It performs no stable recursive descendant census, retains no adopted-descendant pidfds, and is not a subreaper. The best-effort `waitpid(namespace_pid, WNOHANG)` at lines 1538-1542 ignores lost ownership.
- Numerous launcher descriptors still use raw `os.close`/socket close paths rather than leases, including issuance error cleanup, root copy/readback, pipes, status sockets, map files, and proc files. Close-after-effect uncertainty can be suppressed or retried, contrary to ADR 0089's every-descriptor rule.
- `_namespace_owner` catches `RuntimeLauncherUnavailable`, emits only the class name, suppresses child/root cleanup failures, and exits 125. The tool owner converts that to generic rejection. `RuntimeLauncherUnavailable.cleanup_restored` is never derived by the production transaction.

`_recover_transaction_with_ops` can stop only processes already in one list and close supplied leases. It has no helper/root/mount/namespace/path transaction to recover, so it cannot establish the cleanup claims required for unavailable or failure outcomes.

### P1-5 — The mandatory launcher/recovery acceptance corpus is bookkeeping, not production primitive-adapter evidence

**Test symbols:** `prove_fixture_oracles`, `prove_ledger`, `BoundaryOps`, `crash_inner_transaction`  
**Locations:** `test/outcome-two-trusted-launcher-portable.py:54-93,164-215,254-306,309-464`; `test/outcome-two-recovery-portable.py:125-190,225-301`; `completion_trusted_runtime_launcher.py:552-556`

The claimed common protocol does not exist: `_LauncherOps` declares only `close()`, while `_coordinate_with_ops`, `_run_tool_with_ops`, `_namespace_owner`, root construction, process creation, map/proc reads, input, and cleanup call `os`, `socket`, `fcntl`, and `_SystemOps` directly. A portable model therefore cannot implement the same transaction protocol.

The launcher manifest declares 127 cases across 23 acceptance families. The suite checks that each `production_method` symbol is callable, runs a small fixed collection of independent unit predicates, and then `prove_fixture_oracles()` inserts every row into `consumed`, `oracle`, and `sentinel` sets without using the row's `primitive_fault`, `intended_code`, cleanup domains, or production method. Repository search found no portable call to `_bootstrap_with_ops`, `_coordinate_with_ops`, `_run_tool_with_ops`, `_namespace_owner`, `_materialize_root`, `_child_fd_install`, `_final_mapping_check`, `_consume_issuance`, or `_WorkerIssuer._accept_runtime_closure`.

Recovery repeats the prohibited shape. `crash_inner_transaction()` forks a pipe-blocked process that never enters the closure, issuer, root, namespace, mount, or T2 state machine; its PID identity and pidfd are hand-constructed and production identity checks are monkeypatched. Only the 17 `AT-ADAPT-REC-01` labels select that harmless child; `prove_ledger()` marks every remaining recovery row consumed without executing it. `typed_unavailable()` manually sets `unavailable.cleanup_restored = True` rather than obtaining the observation from production.

This is exactly the transcript/harmless-worker evidence ADR 0089 section 7 forbids. Green fixture-set equality supplies no branch-removal sentinel for the named production predicates.

### P2-1 — Process and sandbox control records remain permissive

**Production symbols:** `_start_time`, `_recv_status`, `_maps_snapshot`  
**Locations:** `completion_trusted_runtime_launcher.py:950-956,1296-1299,1389-1399`

`_start_time(pid)` does not require the record's numeric PID to equal `pid`, does not validate the process state or the complete lexical fields through field 22, accepts extra records/fields, and places no explicit integer bound on start time. `_recv_status()` accepts any canonical object with the version; it does not enforce event-specific exact keys, sequence, or cardinality. `_maps_snapshot()` checks only final LF and line count before the later partial row parser. These are materially weaker than `AT-RECORD-01`, and the launcher suite does not run its one-byte record mutations through these production parsers.

## Focused checks

| Check | Result |
| --- | --- |
| Exact head before report | PASS — `3135c16add3abe1b32785f3d577cccd811ce5e54` |
| Python compile, three production modules plus seven suites | PASS |
| Seven direct `/usr/bin/python3 -I -B` suites | PASS |
| Seven optimized `-O -I -B` rejection runs | PASS |
| Exact held-byte private closure load with `sys.path=[]` and preloaded fixed stdlib | PASS |
| Production/portable symbol search | **FAIL contract** — no portable calls to the real bootstrap/issuer/T2 methods listed in P1-5 |
| `_LauncherOps` protocol inspection | **FAIL contract** — only `close` is declared |
| Seccomp policy static comparison | **FAIL contract** — 11 accepted socket routes missing; no argument-field loads |
| Success-finalizer type diagnostic | **FAIL contract** — `os.close(_FdLease)` raises `TypeError` |
| Fixture JSON parsing | PASS |
| ADR 0089 gross accounting | PASS — trusted/portable 7,783/8,930; fixtures 680/900 newline bytes; every file high passes |
| `git diff --check 7ed5e75..HEAD`, exact-head commit check, and `git fsck` | PASS |
| TypeScript wrapper/AJV checks | Not run: locked `node_modules` is absent |
| Native Linux, sudo, namespace, mount, seccomp, `map_files`, gzip/zstd qualification | Not run; review did not claim native applicability |

## Native implementation readiness

**NO.** ADR 0089 requires zero unresolved P0–P3 before native implementation begins. P1-1 alone makes the current production system path incapable of returning success; P1-2 through P1-5 show that native work would qualify an under-observed, incorrectly owned transaction for which the mandatory portable evidence does not exist. Native execution cannot repair those defects.

This report grants no native run, thin-integration, workflow, AWS/provider, deployment, production, release, or issue-closure authority.

O2-FINAL-R-SANDBOX COMPLETE
