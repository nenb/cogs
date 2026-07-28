# Outcome 2 second trusted-closure hostile rereview — lifecycle

**Review ID:** `O2-R2-LIFE`

**Exact reviewed head:** `d845cb13111cc3077141d84a3796537bd125dd0b` (`d845cb1`)

**Accepted authority:** ADR 0088, with non-conflicting ADR 0087 rules

**Inputs read:** all five `closure-review-*.md` first reviews, all four `closure-*-correction.md` designs, and ADR 0088

**Scope:** parser page model, component authentication/aliasing, fd leases/baselines, helper and outer-worker registration, strict records, pidfd identity/descendants/deadlines/reap, close uncertainty/poison, production launcher versus portable adapters, and native readiness
**Disposition:** **BLOCKED — two P0, four P1, and two P2 findings.** Review only; no production, schema, fixture, or test file was changed.

## Executive decision

The correction materially fixes the parser page profile, descriptor-relative runtime-object traversal, same-identity provider handling, explicit `/proc/self/fd` enumeration, closure-side fd leases, report close poisoning, pre-import held-byte admission, complete-object sealing, SCM_RIGHTS issuance, and report/descriptor byte binding. Those are real improvements, not merely renamed tests.

The exact head is nevertheless **not ready for native Jobs A–E**. The production T2 filter leaves execution and seccomp-replacement routes open, and the launcher has no exec-complete barrier before its final mapping check. Helper, worker, namespace-owner, and PID-1 registration still occurs after child effects; the actual outer owner does not own helper/grandchild recovery; descendant cleanup and several waits remain inexact or unbounded; and launcher closes can retry uncertain fd numbers. The green portable launcher/recovery routes are separate scripted functions that do not drive those production paths and set claims true without validating their observations.

## Findings

### P0-1 — The production T2 filter leaves forbidden acquisition/replacement routes available and reports them as proved

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:322-337`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:698-700`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:701-723`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:995-1000`

`install_seccomp()` denies a short syscall-number tuple. It omits x86-64 `execve` (59), `prctl` (157), `seccomp` (317), `execveat` (322), and multiple socket operations: `sendto` (44), `recvfrom` (45), `sendmsg` (46), `recvmsg` (47), `shutdown` (48), `getsockname` (51), `getpeername` (52), `setsockopt` (54), `getsockopt` (55), and batched message calls. Only the `seccomp.socket` label invokes the filter installer; the subsequent io_uring/namespace/mount/replacement/acquisition operations are no-op labels. No real denial probe is made.

The child must initially retain `execveat` to enter gzip/zstd, but no second post-exec filter or equivalent one-shot execution gate exists. `_child_fd_install()` leaves both sealed executables at fds 198 and 199 and the private root also contains the loader and libraries. The workload can therefore attempt further execution or seccomp replacement after the claimed irreversible boundary. `_coordinate()` nevertheless constructs an all-true result.

This is the prior P0-3/Job-E overclaim in a new implementation shape. A real namespace and chroot do not cure an incomplete irreversible transition.

### P0-2 — Final mapping validation is raced against child setup/exec; `exec.blocked` is only a label

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:747-756`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:822-833`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:860-867`

The namespace owner forks the PID-namespace child and immediately reports its PID. The child independently performs chroot, privilege transition, fd installation, and `execveat`. There is no CLOEXEC status pipe, stopped-child release, or other exec-complete handshake. The outer process receives only the owner’s `{"event":"child"}` packet, calls `_security_operation(..., "exec.blocked")` with no effect, and immediately reads mappings.

Depending on scheduling, `_final_mapping_check()` sees the pre-exec Python child, a partially transitioned child, or the intended tool. Failure is nondeterministic; success does not prove the required blocked-after-exec state. Input ordering in source text is therefore not an execution barrier.

### P1-1 — Child and outer-worker authority is still registered after effects, and the real outer owner cannot recover closure helpers

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:910-936`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:966-980`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:936-978`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:844-855`
- `test/outcome-two-lifecycle-portable.py:167-178,301-305`

After `clone3`, the helper child can close fds, create a session, set PDEATHSIG, duplicate stdio, emit status, and wait before the parent registers the pidfd and `HelperLease`. If parent-side registration fails, cleanup closes local fds but has no registered helper branch. The portable `spawn-after` case explicitly exempts a live process without retained recovery authority.

The same defect exists one level out: `_coordinate()` forks the authority-bearing worker; `_worker_main()` can set process state and begin full closure preparation before `_register_process(pid)` runs. `_run_one_tool()` likewise forks a namespace owner before registering it. No pre-registered release gate closes these windows.

More importantly, the production outer coordinator receives no helper pidfd/start-time/SID/PGID/descendant authority from the closure worker. Killing the worker and relying on PDEATHSIG is not exact helper recovery or reap proof. The accepted outer-supervisor P1 is unresolved.

### P1-2 — Descendant ownership, identity-safe escalation, deadlines, and reap are incomplete

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1003-1041,1061-1097`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:543-570`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:747-778`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:860-865,896-932`

The closure census retains only descendant PID numbers. If any descendant exists, `_matching_child()` returns false and `_stop_helper()` refuses even the direct-child TERM; it never opens descendant pidfds, captures descendant identities, terminates them, or reaps them. In the incomplete-identity startup branch, it sends SIGKILL through the pidfd without a complete identity revalidation.

The namespace owner uses blocking `waitpid(child, 0)` on both normal and cleanup paths and raw `kill(child, SIGKILL)`. The outer closes the PID-1 child pidfd immediately after mapping validation while that child is still live, then later performs only a best-effort `waitpid(..., WNOHANG)` and ignores lost reap ownership. `_stop_process()` closes its pidfd even after signaling/reap failure. These paths do not satisfy exact descendants, fixed TERM/KILL/reap deadlines, or retained recovery authority.

### P1-3 — Launcher close failures can retry a released/reused descriptor number

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:553-570`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:908-925`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:984-1008`

The corrected `FdLease` discipline is confined to the closure module. Launcher fds remain raw integers. For example, `_coordinate()` closes each issued descriptor and clears `descriptors` only after the loop. If a close has effect and raises, control reaches `finally` with the original tuple and closes the same numbers again. A concurrent reuse can therefore close an unrelated object. Similar raw close/finally paths exist for tool pipes and pidfds.

`_stop_process()` also closes the pidfd after any signaling/reap failure rather than retaining identity authority or marking it permanently uncertain. This violates ADR 0088 P1-4 and means closure-side poison stability is not end-to-end.

### P1-4 — The production user-namespace identity map is derived after entering the unmapped namespace

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:733-744`.

`original_uid` and `original_gid` are read after `unshare(CLONE_NEWUSER | ...)`. Before a uid/gid map exists, those calls observe the namespace overflow identities rather than the pre-unshare caller identities. The launcher then writes those post-unshare values as parent IDs. It neither retained nor verifies the intended pre-unshare root mapping. This is incompatible with the fixed singular identity map and is a direct native-readiness defect even before the remaining lifecycle issues.

### P2-1 — Portable launcher/recovery “production adapters” are parallel scripted claim generators

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1043-1094`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1095-1138`
- `test/outcome-two-trusted-launcher-portable.py:25-80,155-225`
- `test/outcome-two-recovery-portable.py:303-365`

The four `_drive_fixed_*_with_adapter_for_tests` functions are not called by `_bootstrap_main`, `_coordinate`, `_consume_issuance`, `_run_one_tool`, `_namespace_owner`, or `_final_mapping_check`. Static AST/name-use inspection confirmed they are test-only surfaces.

The bootstrap route merely loops over attack names. The issuer route invokes every `attack.*` label on its success path and never exercises SCM_RIGHTS or descriptor inspection. The T2 route ignores every modeled observation except architecture and unconditionally changes every claim to `True` after traversing a string list. A model returning nonzero capabilities, a successful forbidden syscall, wrong namespaces, or mapping mismatch would still produce complete claims unless it raises at the label. The recovery route kills a harmless blocked process by raw PID and loops over recovery labels; it does not run `_coordinate`, own a closure helper, retain pidfds/namespaces/mounts, or exercise production cleanup.

The tests prove fixture name dispatch and transcript order, not the production mechanisms claimed by ADR 0088 P1-6. This is adapter overclaim, and the scripted routes are dead code with respect to production.

### P2-2 — Strict process/control records and fixture predicates remain incomplete

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:512-520`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:822-833`
- `test/outcome-two-lifecycle-portable.py:373-381`

The launcher’s process-stat parser checks only a final newline, a `") "` marker, twenty fields, and decimal start time. It does not require the requested PID prefix, strict state, lexical fields through field 22, one record, or bounded integer semantics. Sandbox status accepts any object with the version and later selected fields; it does not enforce one closed message shape or sequence.

The manifest row named `cleanup-after-poison` does not call `PreparedRuntimeClosure.close()` or inject `cleanup.after`; it only closes a standalone `FdLease` and checks `CLOSED`. Thus fixture dispatch is live by name but its intended poison predicate is dead. Closure owner publication itself is correctly ordered at `completion_trusted_runtime_closure.py:1481-1489`, but this declared test does not prove it.

## Prior P0–P3 disposition

| First-review / ADR 0088 area | Exact-head result |
| --- | --- |
| Pre-effect exact launcher/parser/closure/schema admission | **Materially resolved in production shape.** Fixed isolated bootstrap, held-byte Git-blob/source-set authentication, synthetic package loading, and inert ambient constructor exist at launcher `1139-1279` and closure `1676-1696`. Native T0 invocation is not yet evidence. |
| Forgeable public handoff / executable unrelated to report | **Materially resolved in production shape.** Public raw-fd handoff is gone; SCM_RIGHTS, credentials, nonce, one-shot issuer, full descriptor reads, seals, size/digest/report/generation rows are at launcher `384-499,574-626`. Portable hostile authority is still fake under P2-1. |
| Actual T2 and final generation binding | **Not resolved:** P0-1 and P0-2. Complete objects are copied into a private root and final maps are attempted, but the irreversible filter and exec barrier are invalid. |
| Real outer crash recovery | **Not resolved:** P1-1/P1-2. The production coordinator owns only the direct worker; helper and PID-1/grandchild authority are not registered/recovered end-to-end. |
| Helper/tool pidfd identity, descendants, deadlines, reap | **Not resolved:** P1-1/P1-2. Direct identity checks and bounded loops improved, but startup, descendants, namespace-child waits, and retained pidfds do not meet the contract. |
| Linux fd enumeration baseline | **Resolved for closure; partial overall.** Closure uses explicit getdents and excludes the exact enumeration fd (`closure.py:697-739`); launcher explicitly opens a directory fd (`launcher.py:237-255`). Launcher resource ownership remains raw and close-unsafe. |
| Close uncertainty and poison | **Resolved locally in closure, not end-to-end:** closure `FdLease` and owner poison are sound in the reviewed branches; launcher remains P1-3. |
| Page-granular ELF | **Resolved portably.** Fixed 4096-byte congruence, rounded overlap/BSS/file-backed resolution are at `completion_elf.py:63-214`; the expanded direct matrix is at `test/outcome-two-runtime-closure-portable.py:75-183`. Real-host compatibility remains native Job A scope. |
| Component authentication and aliases | **Substantially resolved portably.** Descriptor-relative no-follow traversal, stable component transcripts, symlink bounds/races, same-identity alias acceptance, distinct ambiguity, and global cross-role identity checks exist. No native host-generation claim is made. |
| Strict records and tracked schema | **Partial.** Closure stat/children/maps and independent tracked-schema application improved; launcher process/control records remain P2-2. AJV corpus passes. |
| Dead fixtures / mocked security boundary | **Not resolved:** fixture selectors are mostly exact, but launcher/recovery are parallel claim scripts and `cleanup-after-poison` has a false predicate. |
| Prior standalone P3 whitespace | **Dispositioned by ADR 0088.** `git diff --check 32ba6e0..d845cb1` is clean. The broader review-head range remains red on four trailing-space lines in `closure-sandbox-correction.md`; this review does not rewrite historical design evidence. |

## Line-high accounting

Gross/current physical additions from `bec0a19b0b984f88ab9c2effc5059f3737915caa` remain within ADR 0088:

| Surface | Actual | High | Margin |
| --- | ---: | ---: | ---: |
| parser | 306 | 320 | 14 |
| closure | 1,696 | 1,700 | 4 |
| launcher | 1,296 | 1,300 | 4 |
| schema | 134 | 260 | 126 |
| seven Python portable suites | 2,053 | 2,550 aggregate file highs | — |
| TypeScript wrapper | 83 | 150 | 67 |
| fixture tree (LF convention) | 433 | 700 | 267 |
| schema registration gross addition | 27 | 30 | 3 |
| **Trusted/portable subtotal** | **6,028** | **7,010** | **982** |

Numeric compliance does not cure the findings. Closure and launcher each have four physical lines of headroom, and both still contain compressed multi-declaration/security control flow. The required fixes cannot be hidden in the unused subtotal or the test-only routes.

## Checks

Review host: Darwin 24.6.0 arm64. No native Linux primitive, sudo, namespace, mount, seccomp, gzip/zstd qualification, provider, cloud, AWS, workflow, or deployment action was run.

- Exact head and initial clean tracked worktree: **PASS** — `d845cb13111cc3077141d84a3796537bd125dd0b`.
- Python compile for parser/closure/launcher: **PASS**; generated caches removed.
- Seven direct `/usr/bin/python3 -I -B` portable suites: **PASS**.
- Seven optimized-mode rejection checks: **PASS**; every suite exited nonzero under `-O`.
- `npx tsx --test test/outcome-two-portable.test.ts`: **PASS**, 2/2, including AJV mutation corpus.
- `npm run schemas`: **PASS**, 15 schemas and report semantics.
- `npm run typecheck`, `npm run lint`, `npm run format:check`: **PASS**.
- `git diff --check 32ba6e0..d845cb1`: **PASS**.
- `git diff --check 2023e65..d845cb1`: **FAIL**, four retained trailing-space lines in `.pi/outcome-two/closure-sandbox-correction.md:3-6`; disclosed above.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Full `npm run check`: **FAIL** at `npm test` with 886 pass, 2 fail, 3 skip of 891. The two failures are the pre-existing Darwin fake-Docker log cases in `test/dev-launcher-profiles.test.ts` (`insecure driver isolates docker tool state...` and `...preflights stale docker resources...`). Both Outcome 2 tests passed in that run.
- Static production/test call-graph inspection: **FAIL contract** — the four launcher `_drive_fixed_*_with_adapter_for_tests` routes are test-only and disconnected from the production coordinator/system paths.

## Native readiness

**NOT READY. Do not begin Jobs A–E.** Job A could test parser/host compatibility, but the accepted gate requires all P0–P3 resolved first. Jobs C/D/E would currently qualify the wrong lifecycle and sandbox implementation, and a native failure caused by the post-unshare identity map or pre-exec mapping race would not be an environment skip.

Before another review: complete the real seccomp/acquisition transition and exec barrier; register workers/helpers/namespace children before release; give the outer owner exact helper/descendant authority and bounded reap; carry fd leases and permanent close uncertainty through the launcher; correct the user-map identity capture; replace test-only transcript drivers with primitive adapters used by production; and make strict record/poison fixtures challenge the actual production methods.

O2-R2-LIFE COMPLETE
