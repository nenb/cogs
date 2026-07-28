# Outcome 2 final trusted-closure hostile review — lifecycle

- Review ID: `O2-FINAL-R-LIFE`
- Exact reviewed head: `3135c16add3abe1b32785f3d577cccd811ce5e54`
- Governing authority: accepted ADR 0089, with non-conflicting ADR 0088/0087 rules
- Acceptance gate: `.pi/outcome-two/closure-second-correction-gate.md`
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Scope: review only; closure/launcher descriptor leases, child preregistration, surviving outer recovery, descendant ownership, deadlines/reap, close uncertainty, getdents snapshots, strict records, exact fixture binding, and native-implementation readiness
- Native/privileged execution: not attempted and not authorized

## Inputs read

All prior Outcome 2 review and rereview reports under `.pi/outcome-two/` were read, including the capability reviews/rereviews and disposition, Wave 1 closure/portable audits, all five first closure reviews, all five second closure rereviews, the four correction designs, the exact second-correction acceptance gate, and accepted ADR 0089. The exact current parser, closure, launcher, seven portable suites, TypeScript wrapper, schema/registration, and fixture manifests were then inspected by production symbol and call path rather than by fixture label.

## Verdict

**BLOCKED — native Jobs A–E implementation may not begin.**

No P0 finding is reported because the exact production happy path currently fails closed before it can publish a qualification result. Five P1 findings and one P2 finding remain. The direct portable suites are green, but the launcher/recovery suites do not execute most declared acceptance predicates against the named production state machines.

## Findings

### P1-1 — The launcher’s successful tool path deterministically turns into cleanup failure, and launcher fd leasing remains incomplete

**Exact symbols/lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1400-1544` — `_run_tool_with_ops`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1531-1536`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1034-1076` — `_consume_issuance`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1415-1527`

After `_wait_bounded(lease, deadline)` reaps the namespace owner, the `finally` branch executes `os.close(lease.pidfd)`. `lease.pidfd` is an `_FdLease`, not its integer `fd`. The exact expression raises `TypeError`; a focused static/runtime check reproduced that result. Therefore every otherwise-successful `_run_tool_with_ops` call raises `RuntimeLauncherCleanupError` from its finalizer, so `_coordinate_with_ops` cannot produce a successful result.

This is also not an isolated typo in an otherwise complete lease conversion. Issued descriptors are raw-closed in `_consume_issuance`; close errors are either unaggregated or suppressed. Tool pipes, socket endpoints, map fds, root-copy fds, exec-status fds, and bootstrap fds are primarily raw integers. Several `finally` paths retain a number until only after `os.close()` returns, so an after-effect close failure can be retried or silently lose permanent uncertainty. Closure `FdLease` and launcher `_FdLease` themselves preserve `OWNED -> CLOSE_UNCERTAIN` correctly, but the accepted end-to-end launcher lease contract is not implemented.

### P1-2 — The surviving outer owner does not preregister or recover the complete worker/helper/root/namespace/descendant transaction

**Exact symbols/lines:**

- closure `_spawn_helper`: `completion_trusted_runtime_closure.py:978-1138`
- launcher `_worker_main` / `_coordinate_with_ops`: `completion_trusted_runtime_launcher.py:1545-1594,1613-1709`
- launcher `_materialize_root` / `_namespace_owner`: `completion_trusted_runtime_launcher.py:1111-1132,1206-1294`
- launcher `_run_tool_with_ops`: `completion_trusted_runtime_launcher.py:1400-1544`

The closure helper is atomically created by `clone3(CLONE_PIDFD)` and blocks until its **worker-local** `PreparationLease` registers it. That local correction is real. The surviving outer launcher, however, owns only the closure worker; no helper pidfd, identity, release gate, or descendant authority is transferred to it. If the worker dies while a helper exists, `PDEATHSIG` is only a termination request: the outer is not the helper’s subreaper and cannot prove exact reap or descendant absence.

The same gap recurs in the launcher. `_run_tool_with_ops` forks the namespace owner without a release gate; `_namespace_owner` can call `prctl`, `setsid`, `setgroups`, `unshare`, map writes, and mounts before the parent reaches `_register_process(pid)` at line 1426. The PID-namespace child lease created at line 1431 is a local variable, is not attached to the outer `_ProcessOwner`, and has no recovery branch if the namespace owner dies. `_ProcessLease.descendants` is never populated or recursively censused.

Root setup is not write-ahead either. `_materialize_root` performs `mkdir`, mount, directory creation, and object copies before returning; `_namespace_owner.root` remains `None` until the whole function succeeds. A fault after creation/mount but before return therefore skips even the namespace owner’s best-effort cleanup, and the outer retains no parent-fd, mount-namespace, mount-identity, or root-intent authority. This does not satisfy `AT-LIFE-01`, `AT-ADAPT-REC-01`, or `AT-ROOT-01`.

### P1-3 — Fixed transaction deadlines and exact reap ownership do not cover issuance, preparation, or the grandchild topology

**Exact symbols/lines:**

- `_WorkerIssuer._accept_runtime_closure`: `completion_trusted_runtime_launcher.py:844-880`
- `_consume_issuance`: `completion_trusted_runtime_launcher.py:1034-1076`
- `_worker_main`: `completion_trusted_runtime_launcher.py:1545-1594`
- `_wait_bounded` / `_stop_process`: `completion_trusted_runtime_launcher.py:997-1033`
- `_run_tool_with_ops`: `completion_trusted_runtime_launcher.py:1426-1541`

The issuer’s `sendmsg`, acknowledgement `recvmsg`, trailing `recv`, and the consumer’s initial `recvmsg`/trailing `recv` are blocking and have no fixed absolute deadline. Closure preparation inside `_worker_main` likewise has no outer operation deadline. The outer can block in `_consume_issuance` before it reaches any bounded wait, leaving the workflow timeout as the actual supervisor.

The bounded direct-process loops are not an exact grandchild reap protocol. The outer opens a pidfd for the PID-namespace child even though it is not that child’s parent, later sets `child_lease.reaped = True` from a trusted status packet, and closes the pidfd without obtaining reap ownership. On error it performs only a raw `waitpid(namespace_pid, WNOHANG)` and ignores `ChildProcessError`. Registration failure after `fork()` also leaves the gated numeric PID outside `_ProcessOwner`, so closing the gate may make it exit but does not prove reap. The fixed monotonic TERM/KILL/reap and retained-authority requirements remain open.

### P1-4 — `RuntimeQualificationResult` still promotes incomplete observations to exact T2 and cleanup facts

**Exact symbols/lines:**

- `_DENIED_SYSCALLS` / `probe_seccomp_denials`: `completion_trusted_runtime_launcher.py:61-107,657-676`
- `_enter_boundary`: `completion_trusted_runtime_launcher.py:1140-1166`
- `_namespace_facts`: `completion_trusted_runtime_launcher.py:1366-1387`
- `_coordinate_with_ops`: `completion_trusted_runtime_launcher.py:1667-1693`

`_enter_boundary` clears/drops ambient and bounding capabilities but rereads only effective/permitted/inheritable words through `capget_zero`; it never independently enumerates the final bounding set or reads each ambient capability. Supplementary groups are not reread. `_namespace_facts` proves only that namespace inode pairs differ from the outer baselines; it does not prove the required ownership relationship, and it treats one-line UID/GID maps as exact without comparing their bytes.

The fixed seccomp table still omits accepted socket-operation routes including `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`, socket-name/option calls, and batched message calls. Native denial observation covers only `execve`, `socket`, `memfd_create`, and `seccomp`; `seccomp_denials_exact` explicitly requires only those four. `no_acquisition_route` is then derived from that four-probe subset plus fd/root facts.

Finally, `descendants_reaped` and `namespaces_released` are both derived from `not process_owner.processes`; `mounts_restored` and `paths_restored` are pathname booleans for one fixed leaf. None observes the unregistered closure helpers, PID-namespace child, descendants, retained namespace handles, mount identities, or foreign/replaced state described in P1-2. `_ObservedFacts` prevents an absent value from being directly read, but several supplied “observations” are not the accepted fact.

### P1-5 — The closed launcher/recovery fixture ledgers do not execute their named production predicates

**Exact test symbols/lines:**

- `test/outcome-two-trusted-launcher-portable.py:252-295` — `source_reachability`
- `test/outcome-two-trusted-launcher-portable.py:435-464` — `prove_fixture_oracles`
- `test/outcome-two-recovery-portable.py:125-197` — `crash_inner_transaction`
- `test/outcome-two-recovery-portable.py:280-300` — `prove_ledger` / `parent`

The launcher suite directly exercises only narrow admission, ancillary, fd snapshot/lease, boundary-readback, and `_ObservedFacts` helpers. `source_reachability` is an AST name-reachability check. `prove_fixture_oracles` assigns every remaining acceptance family to `static_evidence` and then marks every row consumed/oracle-proved/sentinel-proved without invoking its `production_method` or `primitive_fault`. In particular it never executes `_bootstrap_with_ops`, `_coordinate_with_ops`, `_run_tool_with_ops`, `_materialize_root`, `_recv_status`, or production recovery for their manifest rows.

The recovery suite forks a harmless pipe/stopped child, manually constructs `_ProcessLease`, patches `_process_matches` and `pidfd_send_signal`, and invokes only `_recover_transaction_with_ops`. It does not crash `_worker_main` or an authority-bearing closure/helper/root/mount/namespace transaction. `prove_ledger` then adds every non-crash row to the consumed set without running it.

Thus manifest callable reachability and set equality are being presented as `AT-ADAPT-BOOT-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01`, `AT-ROOT-01`, `AT-RECORD-01`, and other branch evidence. ADR 0089 expressly forbids that substitution. The green suites cannot close the production findings above.

### P2-1 — Launcher proc/maps/mount/control records remain weaker than the strict accepted grammars

**Exact symbols/lines:**

- `_start_time`: `completion_trusted_runtime_launcher.py:950-956`
- `_final_mapping_check`: `completion_trusted_runtime_launcher.py:1300-1342`
- `_final_mount_check`: `completion_trusted_runtime_launcher.py:1344-1365`
- `_namespace_facts`: `completion_trusted_runtime_launcher.py:1366-1387`
- `_recv_status`: `completion_trusted_runtime_launcher.py:1389-1399`

`_start_time` does not require the requested PID prefix, exactly one record, a strict state byte, or lexical fields through stat field 22. The final maps and mountinfo readers split selected fields but do not apply the closure module’s strict complete-record/device/inode/generation grammar. `_recv_status` requires canonical JSON and a version, but accepts arbitrary extra keys and has no event-specific closed shape or sequence number.

The explicit closure and launcher fd snapshots do use the production `getdents64` syscall through the exact opened directory fd, exclude exactly that enumerator, bound the entry set, and close through a lease. No separate getdents implementation finding is reported. The strict-record gate remains open around the lifecycle and sandbox records that consume those identities.

## Checks

Review host: Darwin arm64. No native Linux primitive, sudo, namespace, mount, chroot, seccomp, `map_files`, compression-tool qualification, provider, cloud, AWS, workflow, or deployment operation was invoked.

- Exact head and clean initial worktree: **PASS** — `3135c16add3abe1b32785f3d577cccd811ce5e54`.
- Seven direct `/usr/bin/python3 -I -B` portable suites in a minimal environment: **PASS**.
- Seven optimized `-O -I -B` rejection runs: **PASS**; every suite rejected optimized mode.
- In-memory `compile()` of the three production modules and seven Python suites: **PASS**; no bytecode/cache residue.
- Focused exact-expression check for `os.close(lease.pidfd)`: **FAIL contract**, deterministic `TypeError`.
- `git diff --check 7808b71^..HEAD`: **PASS** for the final ADR 0089 correction range.
- `git fsck --no-progress --no-dangling`: **PASS**.
- `npx --no-install tsx --test test/outcome-two-portable.test.ts`: **environment blocked**, locked `ajv/dist/2020.js` is absent.
- `npm run schemas`, `npm run typecheck`, `npm run format:check`: **environment blocked**, local `tsx`, `tsc`, and `biome` are absent.

Green direct portable results are non-accepting for P1-5.

## ADR 0089 accounting

Gross physical/LF additions from `bec0a19` remain within every trusted/portable high:

| Surface | Actual | High |
| --- | ---: | ---: |
| parser / closure / launcher | 306 / 2,078 / 1,889 | 320 / 2,100 / 1,900 |
| schema / schema registration | 134 / 27 | 260 / 30 |
| runtime-closure / mapped / sealing suites | 350 / 256 / 265 | 350 / 300 / 300 |
| lifecycle / recovery / report / launcher suites | 538 / 308 / 326 / 471 | 550 / 550 / 400 / 800 |
| TypeScript wrapper / fixture LF aggregate | 155 / 680 | 170 / 900 |
| **Trusted/portable subtotal** | **7,783** | **8,930** |

Numeric compliance does not cure the findings. No native implementation surface exists yet, and no native line or execution authority was used.

## Native implementation readiness

**NOT READY.** ADR 0089 requires a fresh exact-head hostile review with no unresolved P0–P3 before native Jobs A–E implementation begins. This exact head retains five P1 and one P2 findings. Correct the launcher happy-path fd bug and complete launcher lease ownership; transfer helper/root/namespace/descendant authority to a surviving owner before release; add fixed transaction deadlines and exact reap; derive every T2/cleanup fact from the accepted observation; replace static fixture credit and harmless-child recovery with production state-machine adapters; and enforce strict records. Then obtain another exact-head review.

This report grants no native run, workflow, capability observation, thin integration, AWS/provider/OpenTofu/deployment, production, release, or issue-closure authority.

O2-FINAL-R-LIFE COMPLETE
