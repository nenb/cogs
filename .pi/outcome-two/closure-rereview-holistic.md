# Outcome 2 trusted-closure second hostile rereview — holistic

**Disposition:** **BLOCKED — native Jobs A–E implementation may not begin**

**Exact reviewed head:** `d845cb13111cc3077141d84a3796537bd125dd0b` (`d845cb1`)

**Accepted authority:** ADR 0088

**Review mode:** review only; no production, schema, test, fixture, workflow, or native implementation changed

**Native execution:** not attempted and not authorized

## Scope

Read in full before reviewing:

- all five first closure reviews: `.pi/outcome-two/closure-review-{parser-auth,mapping-cleanup,launcher-schema,portable-tests,holistic}.md`;
- all four correction designs: `.pi/outcome-two/closure-{bootstrap,lifecycle,sandbox,portable}-correction.md`;
- `.pi/outcome-two/closure-audit.md` and accepted `docs/adr/0088-correct-first-trusted-closure-implementation-review.md`;
- the exact parser, closure, launcher, schema/registration, seven portable suites, wrapper, and Outcome 2 fixture tree at `d845cb1`.

The correction materially improves pre-import held-byte loading, page-granular ELF parsing, component traversal, descriptor enumeration, complete-object sealing, private SCM_RIGHTS issuance, report/schema checks, and many closure-level fault models. Those improvements do not close the accepted T0/T1/T2 composition.

## Findings

### P0-1 — The production T2 child cannot pass its privilege transition, and there is no exec-readiness barrier

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:739-744`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:680-700`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:747-756`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:855-867`

The namespace owner writes `deny\n` to `/proc/self/setgroups` before forking. The child then calls `os.setgroups([])`. On Linux, `setgroups(2)` is denied after that control is set to `deny`, including an empty list, so the child exits through the generic status-126 path before chroot/capability/seccomp/exec completion.

Independently, the namespace owner sends the child PID immediately after `fork()` without any child-to-parent setup or CLOEXEC readiness acknowledgement. The outer process therefore races `_final_mapping_check()` against child setup/exec. `exec.blocked` at line 862 is only a label with no system effect. The accepted requirement that final gzip/zstd execution be blocked after exec and mapped before input release is not implemented as a synchronized transition.

This leaves prior P0-3 unresolved and makes a successful native qualification path impossible or scheduler-dependent rather than fail-closed and deterministic.

### P0-2 — T2 and cleanup result fields are asserted, not established by the production owner

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:263-268`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:733-755`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:815-818`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:988-1000`

For `_SystemOps`, `_security_operation()` executes only a supplied callback; names without callbacks are no-ops. Consequently `namespace.pid`, `namespace.mount`, `namespace.network`, `child.pid-one`, `final-map.bind-generations`, and several capability/seccomp labels do not observe the named fact. The implementation does not compare namespace identities, observe PID 1 from the child namespace, retain a materialized-generation identity table for final mappings, or independently prove every result cleanup domain.

Nevertheless `_coordinate()` constructs `RuntimeQualificationResult` with every boundary and cleanup boolean set to `True`. Direct-child bytes, one fd snapshot, and path absence do not prove namespace exactness, PID-one semantics, descendant reaping, mount restoration, or source-generation equality. This is the same trusted-result overclaim prohibited by ADR 0088 P0-3/P2-7.

### P1-1 — The new issuer path rejects every production sealed-object descriptor before SCM_RIGHTS transfer

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1153-1186`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:388-404`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:457-474`

`_seal_object()` returns the original descriptor from `memfd_create()`. That descriptor is opened read/write and is never reopened as a distinct read-only reference. `_WorkerIssuer` calls `_verify_bundle()`, whose `_inspect_fd()` requires every issued executable/loader/library descriptor to have `F_GETFL & O_ACCMODE == O_RDONLY`.

Seals do not change a descriptor's access mode. Therefore the trusted closure's own bundle cannot pass its issuer's pre-send check. The report descriptor has an explicit read-only reopen; execution objects do not. The SCM_RIGHTS/report-binding design is directionally correct, but its production route is dead at this exact head. The label-only issuer matrix did not detect this contradiction.

### P1-2 — The outer owner still loses exact process/descendant authority on failure

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:526-532`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:553-573`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:747-781`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:855-865,920-932`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:935-983`

After `fork()`, `_register_process()` closes the pidfd and raises if start-time/session/group/executable observation fails; it does not retain or transfer recovery authority for the possibly live child. `_stop_process()` also closes the pidfd even after identity, signal, or reap failure, directly violating ADR 0088's requirement not to discard a pidfd while a process may remain live.

The namespace owner uses raw `kill(pid)` and blocking `waitpid(pid, 0)` in its error path. The outer process closes the final child's pidfd immediately after the map check and later ignores `ChildProcessError`; it owns only the namespace-owner PID. The closure worker's helpers and the namespace owner's child are not registered with the fixed outer supervisor through a write-ahead protocol. The final `/proc/self/task/self/children` comparison covers only current direct children and does not recover descendants from a crashed worker/namespace owner.

Prior P1-1 and P1-2 are unresolved.

### P1-3 — Launcher close handling still retries uncertain fd numbers

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:874-875,905-911`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:984-986,1004-1009`

Several production closes clear ownership bookkeeping only after `os.close()` returns. If close took effect and then reported an error, `finally` retries the same numeric fd. The descriptor bundle loop similarly leaves the whole tuple populated until all closes return, so a mid-loop after-effect error causes the finalizer to close already-released numbers again.

The closure's `FdLease` and report close path now model permanent uncertainty correctly, but the launcher does not use that ownership rule. Prior P1-4 remains unresolved at the cross-file consumer boundary.

### P1-4 — Portable launcher/issuer/recovery coverage is a parallel label interpreter, not the production state machines

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1029-1053`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1059-1094`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1095-1138`
- `test/outcome-two-trusted-launcher-portable.py:98-114,170-214`
- `test/outcome-two-recovery-portable.py:287-319`

`_drive_fixed_issuer_with_adapter_for_tests()` iterates attack names and then returns `consumed`; it never invokes `_WorkerIssuer`, `_consume_issuance`, `_verify_bundle`, `sendmsg`, or descriptor inspection. `_drive_fixed_t2_with_adapter_for_tests()` iterates `_T2_SEQUENCE`, mutates test-owned sets, sets every claim true, and returns complete; it never invokes `_run_one_tool`, `_namespace_owner`, `_enter_boundary`, `_final_mapping_check`, or `_SystemOps`. The recovery route kills and reaps one harmless pipe-blocked worker, then iterates synthetic recovery labels; it does not crash or recover `_coordinate`, closure helpers, namespace state, mounts, or descendants.

A static reference check found none of these production launcher surfaces referenced by any seven portable suites: `_bootstrap_main`, `_coordinate`, `_WorkerIssuer`, `_consume_issuance`, `_verify_bundle`, `_run_one_tool`, `_namespace_owner`, `_materialize_root`, `_enter_boundary`, `_child_fd_install`, `_final_mapping_check`, or `_SystemOps`.

The fixtures execute exactly once as labels, but the security predicates are dead with respect to production. This directly violates ADR 0088 P1-6 and explains why P0-1 and P1-1 remained green.

### P1-5 — Producer “independence” still calls one semantic decoder twice

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1630-1637`
- `test/outcome-two-runtime-report-portable.py:153-201`

The corrected producer does apply the admitted tracked-schema validator and the launcher has a separate consumer codec. However, the producer's claimed independent re-encoding calls the same `_decode_report()` implementation twice and merely checks that Python returned distinct objects. ADR 0088 P1-5 explicitly forbids treating two calls to one decoder as independence.

The report suite drives `_canonical_report_for_tests`, `_validate_report_bytes`, and launcher `_decode_report` over a golden fixture; it does not drive report construction from the production closure state machine. This is useful codec/schema evidence, not proof that the actual producer, schema gate, sealed report, issuer, and consumer agree in one transaction.

### P2-1 — Required-kernel unavailability inside the namespace owner loses its typed outcome

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:765-782`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:855-858`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1288-1296`

A `RuntimeLauncherUnavailable` raised by unshare/mount/chroot/capability/seccomp code is caught in the namespace-owner child, reduced to an `{"event":"error"}` packet, and then converted by the parent into generic `RuntimeLauncherError`. The top-level typed-unavailable exit is therefore not preserved for most required primitives, and the child cleanup path suppresses cleanup failures. ADR 0088 requires a typed unavailable result only after proved cleanup, never a generic failure or success placeholder.

### P2-2 — Compatibility and transcript-only surfaces overstate exercised production behavior

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1191-1194`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1033-1042`
- `test/outcome-two-trusted-launcher-portable.py:25-80`

`_seal_source()` is compatibility-only and unused by production; actual production uses `_seal_object()`. `_T2_SEQUENCE` includes operations such as `mount.root`, `mount.proc-owner`, cleanup namespaces/mounts, and checkout restoration that do not correspond to the native production call graph. The portable model returns preselected observations from operation names. These helpers may remain narrow unit scaffolding, but they cannot be counted as hostile coverage of the accepted adapter contract.

### P3

No new standalone P3 finding. The correction-range diff is clean. ADR 0088 explicitly dispositions retained predecessor-wide trailing whitespace in historical review records.

## Prior finding disposition

| ADR 0088 area | Exact-head disposition |
|---|---|
| P0-1 pre-import exact-source admission | **Materially corrected in the fixed bootstrap:** held source bytes, Git blob/source-set checks, private in-memory module loading, and ambient constructor rejection are present at launcher `1213-1279` and closure `1693-1695`. Actual T0 invocation remains a later native-envelope responsibility and was not run. |
| P0-2 issuer-bound descriptor/report binding | **Architecture present but not closed:** SCM_RIGHTS, credentials, nonce, acknowledgement, and complete-byte/report checks exist; P1-1 makes the real route unusable and P1-4 leaves attacks untested against it. |
| P0-3 real T2/final generation binding | **Unresolved:** P0-1 and P0-2. |
| P1-1 outer recovery | **Unresolved:** P1-2/P1-4. |
| P1-2 exact lifecycle/descendants | **Unresolved:** P1-2. |
| P1-3 fd enumeration | **Corrected in closure:** explicit directory-fd/getdents enumeration excludes the exact enumerator; no contrary defect found. |
| P1-4 permanent close uncertainty | **Corrected in closure, unresolved in launcher:** P1-3. |
| P1-5 independent schema/codecs | **Partial:** tracked schema and separate launcher codec exist; producer still double-calls one codec. |
| P1-6 full hostile production adapters | **Unresolved:** P1-4. |
| P2 page-granular ELF | **Materially corrected;** no new parser blocker found in this rereview. |
| P2 component/closure/map hostile coverage | **Substantially improved, but native-launcher composition remains unexercised.** |
| P2 fixture truth/result truth/unavailable | **Unresolved for launcher:** fixtures are label-live but production-predicate-dead; result/unavailable overclaim remains. |
| P3 retained whitespace | **Accepted ADR disposition applies; no new defect.** |

## Line-high accounting

Gross/current physical lines from `bec0a19b0b984f88ab9c2effc5059f3737915caa` remain within ADR 0088, but several files have almost no correction room:

| Surface | Actual | High | Margin |
|---|---:|---:|---:|
| `completion_elf.py` | 306 | 320 | 14 |
| `completion_trusted_runtime_closure.py` | 1,696 | 1,700 | 4 |
| `completion_trusted_runtime_launcher.py` | 1,296 | 1,300 | 4 |
| trusted closure schema | 134 | 260 | 126 |
| schema registration addition | 27 | 30 | 3 |
| runtime-closure portable | 336 | 350 | 14 |
| mapped-closure portable | 232 | 300 | 68 |
| sealing portable | 250 | 300 | 50 |
| lifecycle portable | 394 | 400 | 6 |
| recovery portable | 378 | 400 | 22 |
| runtime-report portable | 225 | 300 | 75 |
| trusted-launcher portable | 238 | 500 | 262 |
| TypeScript wrapper | 83 | 150 | 67 |
| `test/fixtures/outcome-two/**` LF/physical aggregate | 433 | 700 | 267 |
| **Trusted/portable subtotal** | **6,028** | **7,010** | **982** |

The subtotal cannot be transferred. Fixing the production blockers readably will likely require a new ADR before either four-line production margin is crossed.

## Checks

Review host: Darwin 24.6.0 arm64. No Linux native primitive, sudo, namespace, mount, seccomp, compression-tool, provider, cloud, workflow, or Jobs A–E action was run.

- Exact head and clean initial worktree: **PASS**, `d845cb13111cc3077141d84a3796537bd125dd0b`.
- Seven direct `/usr/bin/python3 -I -B` portable suites with fixed minimal environment: **PASS**.
- Seven optimized runs: **PASS rejection**; all exited nonzero.
- In-memory `compile()` of the three production and seven portable Python files: **PASS**, no bytecode written.
- Static production-launcher reachability check from the portable suites: **FAIL contract**, all twelve security-sensitive production surfaces listed in P1-4 are unreferenced.
- `git fsck --no-progress --no-dangling`: **PASS**.
- `git diff --check 32ba6e0..d845cb1`: **PASS** for the accepted correction implementation range.
- `git diff --check bec0a19..d845cb1`: historical retained whitespace only, dispositioned by ADR 0088 P3.
- `npx tsx --test test/outcome-two-portable.test.ts`: **BLOCKED**, local locked dependencies are absent (`ajv/dist/2020.js` unavailable).
- `npm run schemas`, `npm run typecheck`, `npm run format:check`: **BLOCKED**, local `tsx`, `tsc`, and `biome` are absent.
- Repository worktree after checks and before this report: **clean**; no cache residue.

Green direct portable suites establish bounded parser/model behavior only. They do not contradict the production-path findings.

## Native readiness and gate decision

No native qualification schema, `scripts/native-qualification/`, Outcome 2 native tests, or Jobs A–E workflow implementation exists at this head. That absence is expected before this gate and supplies no native evidence.

**Native Jobs A–E implementation may not begin.** ADR 0088 requires a fresh exact-head review with no unresolved P0–P3. This head retains two P0, five P1, and two P2 findings. Correct the production descriptor access contract, child readiness/T2 observations, outer ownership and close uncertainty, typed unavailable propagation, and the real production adapter tests; then obtain another exact-head hostile review. This report grants no run authority.

O2-R2-HOL COMPLETE
