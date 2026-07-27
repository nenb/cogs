# Outcome 2 second trusted-closure hostile rereview — production T2 sandbox

- Review ID: `O2-R2-SANDBOX`
- Exact reviewed head: `d845cb13111cc3077141d84a3796537bd125dd0b`
- Governing decision: accepted ADR 0088, with non-conflicting ADR 0087 and `OUTCOME-TWO-PLAN.md` rules retained
- Inputs read in full: all five `closure-review-*.md` first reviews, all four `closure-*-correction.md` designs, ADR 0088, and the corrected parser/closure/launcher/schema/portable surfaces
- Scope: review only, with emphasis on the real production T2 route, fixed-root materialization, user/PID/mount/network namespaces, PID 1, chroot, all capability sets, `noroot`, NNP, seccomp, final mapped generations before input, truthful claims, exact cleanup, and unsupported architecture
- Host: Darwin 24.6.0 arm64; no native, sudo, namespace, mount, chroot, seccomp, provider, cloud, AWS, workflow, or deployment action was run
- Verdict: **BLOCKED — one P0, four P1, and two P2 findings remain. No standalone P3 was found.**

## Executive decision

The correction materially fixes pre-effect source admission, public handoff forgery, descriptor/report byte binding, complete closure-object sealing, tracked-schema application, page-granular ELF parsing, descriptor enumeration, and many closure-owner lifecycle faults.

The production T2 route is not ready. Its seccomp policy does not implement the accepted replacement/acquisition contract, yet the final result is populated with unconditional success booleans. Its user-namespace identity map is built from IDs observed only after entering the unmapped namespace. Its child status does not prove `execveat` completed before final-map capture. Partial root setup and failed child cleanup are not recoverable by the outer owner. The green launcher suite drives a separate event player containing claims and cleanup domains absent from production.

Do not begin native Jobs A–E or thin integration at this head.

## Findings

### P0-1 — Production can publish T2 success for a seccomp/namespace contract it never proves and does not fully implement

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:263-269,291-337,679-700,733-736,755-756,995-1000`.

For `_SystemOps`, `_security_operation()` executes a supplied callable or returns `None`; labels without callables are not observations. Consequently `namespace.pid`, `namespace.mount`, `namespace.network`, `capability.permitted`, `capability.inheritable`, `capability.ambient`, all seccomp checks after `seccomp.socket`, and `child.pid-one` are no-ops. The only capability readback is `capget`, which covers effective/permitted/inheritable but not bounding or ambient sets. There is no namespace identity/ownership readback, PID-namespace observation, seccomp mode/program readback, denied-syscall probe, or replacement-denial probe.

The literal x86-64 filter at lines 323-330 denies `socket(41)`, io_uring, namespace, mount, chroot, and selected acquisition calls, but allows both seccomp replacement entry points: `prctl(157)` and `seccomp(317)`. It also allows unrestricted `execve(59)` and `execveat(322)` rather than permitting only the fixed descriptor/argument execution. This contradicts ADR 0088's fixed replacement/acquisition contract.

Despite those missing facts, `_coordinate()` sets every result field to `True` at lines 998-999. A fixed-output run can therefore become a qualification result without proving the named T2 policy. This is a real production overclaim, not merely missing test depth.

### P1-1 — The user-namespace map uses IDs read after `CLONE_NEWUSER`, so the intended singular parent mapping is not established

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:291-293,733-744`.

`unshare_boundary()` enters the new user namespace as part of the combined tuple. Only afterward does `_namespace_owner()` call `os.getuid()`/`os.getgid()` and use those values as the parent-namespace IDs in `uid_map`/`gid_map`. Before a mapping exists, those calls do not recover the creator's original parent-namespace identities; an unmapped ID is represented by the overflow ID. The code must retain the original IDs before `unshare` and independently reread the exact maps afterward.

On the intended Linux route this is expected to reject the map write or create the wrong map, so the corrected T2 path is not natively runnable as written. The portable adapter never executes these calls.

### P1-2 — Final mapping is ordered before input, but there is no exec-completion gate and the check races the pre-exec Python child

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:747-756,787-821,856-867`.

The namespace owner sends the child PID immediately after `fork()`. The child concurrently performs chroot, privilege drop, seccomp, fd installation, and `execveat`. There is no CLOEXEC status pipe or other exact exec-completion record. The parent treats receipt of the fork PID as `exec.blocked` and immediately snapshots mappings.

Thus `_final_mapping_check()` can inspect the still-running Python launcher child and fail closure equality nondeterministically. A successful equality check remains before the first write at lines 863-870, which is a useful fail-closed property, but the accepted deterministic sequence `exec complete -> stable exact final mappings -> input release` is not implemented. The child pidfd is then closed at line 865 without a final identity, namespace, boundary, or descendant revalidation before input.

### P1-3 — Fixed-root and process cleanup are not registered/recoverable at the cuts that matter

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:553-573,647-671,724-782,833-934,962-1027,1095-1138`.

`root` in `_namespace_owner()` is assigned only if `_materialize_root()` returns. A failure after `mkdir`, after the tmpfs mount, during object copy, readback, or read-only remount leaves the caller's `root` as `None`; lines 776-781 then skip cleanup. The outer process retains no mount-namespace handle, parent-directory authority, mount identity, or write-ahead root intent with which to recover that cut.

Child cleanup also retains prior defects: the namespace owner uses unbounded raw `waitpid(child, 0)` and raw PID KILL on failure; `_stop_process()` closes the pidfd even after identity/reap failure; `_run_one_tool()` cannot reap the namespace grandchild and ignores `ChildProcessError`; and `_coordinate()` compares only direct-child bytes, fds, and pathname absence, not mount/namespace identities or descendants.

The supposed outer-recovery route at lines 1095-1138 is test-only and is never called by `_coordinate()`. It owns a harmless pipe-blocked child, not the production worker, T2 child, root, mount namespace, or named state. Exact cleanup and ADR 0088 outer recovery therefore remain unresolved.

### P1-4 — The portable launcher adapter is a parallel claim generator, not an adapter over the production T2 state machine

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1033-1094`; `test/outcome-two-trusted-launcher-portable.py:28-64,188-214`.

`_drive_fixed_t2_with_adapter_for_tests()` iterates `_T2_SEQUENCE`, mutates synthetic sets, then replaces every claim with `True`. It does not call `_coordinate`, `_run_one_tool`, `_namespace_owner`, `_materialize_root`, `_enter_boundary`, `_child_fd_install`, `_final_mapping_check`, or production cleanup.

A static event comparison found **51** portable T2 events versus **25** literal production `_security_operation` events. Twenty-six portable-only events include all mount/namespace/path/checkout baselines, `mount.root`, `mount.proc-owner`, five seccomp subchecks, child wait, every cleanup-domain proof, and result publication. The test supplies `EPERM`, zero capabilities, stable mappings, and empty baselines directly. Its unavailable cuts therefore test labels, not denied syscalls or production rollback.

The bootstrap and issuer portable routes at lines 1043-1053 use the same pattern: they iterate attack names rather than driving the production source and `SCM_RIGHTS` implementations. This violates ADR 0088 P1-6 and explains why P0-1 through P1-3 remain green.

### P2-1 — Required primitive unavailability inside T2 is collapsed into generic failure, and the fixed Python identity check is incompatible with a symlinked `/usr/bin/python3`

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:274-279,765-782,856-858,1246-1252,1291-1295`.

`_SystemOps._checked()` correctly creates `RuntimeLauncherUnavailable`, but `_namespace_owner()` catches it with every other exception, sends only its class name, and exits 125. `_run_one_tool()` then rejects the non-`child` status as generic `RuntimeLauncherError`; `_bootstrap_main()` exits 1 rather than the typed unavailable exit 78. Required primitive denial therefore does not preserve the accepted unavailable outcome or prove cleanup.

Separately, `/proc/self/exe` resolves the executing file identity, while `/usr/bin/python3` is normally a versioned symlink on the fixed Ubuntu target. Exact string equality at lines 1250-1252 can reject a process that was correctly invoked through `/usr/bin/python3`. The correct check is descriptor identity against the admitted fixed logical path, not resolved-path spelling.

The top-level architecture gate itself is correctly before `_SystemOps` libc/syscall use and returns typed unavailable on non-Linux/non-x86-64. That narrow unsupported-architecture property is resolved; primitive-level unavailable semantics are not.

### P2-2 — ADR 0088's readable-control-flow correction remains incomplete

**Lines:** examples at `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:3-4,72-73,80-82,88-94,326,341-344,995-1000`.

The launcher is 1,296/1,300 lines and still uses comma-compressed imports, semicolon-packed dataclass fields, dense BPF construction, and positional all-boolean result construction. These are precisely the authority-bearing areas where ADR 0088 required cap-driven compression to be undone. Numeric compliance is not readable-flow sign-off.

## Prior P0–P3 resolution matrix

| First-review contract | Exact-head disposition |
| --- | --- |
| Pre-effect exact-source/import admission | **Materially resolved in ordering and held-byte loading**, subject to P2-1 native Python-path viability. Ambient closure entry is inert. |
| Forgeable handoff and executable/report mismatch | **Materially resolved:** private `SOCK_SEQPACKET`/`SCM_RIGHTS`, credentials/nonce, one-shot receipt, complete descriptor reads, seals, sizes, and report digests are present. |
| Complete loader/library generation carried into T2 | **Materially improved:** all gzip/zstd closure objects are sealed, copied into a private root, and hashed. Final execution sequencing remains P1-2. |
| Actual namespace/chroot/capability/NNP/seccomp T2 | **Not resolved:** P0-1 and P1-1. |
| Fixed helper inherited fds/closed stdio | **Resolved in the closure helper path:** stdio reservation and close-range allowlisting are present. |
| Real fd enumeration can reach `READY` | **Resolved in production shape:** explicit `/proc/self/fd` directory enumeration excludes its exact fd. |
| Exact launcher child/descendant deadlines and retained identity | **Not resolved:** P1-3. |
| Fresh outer recovery rather than fresh retry | **Not resolved:** disconnected test-only route under P1-3/P1-4. |
| Tracked schema plus independent producer/consumer semantics | **Materially resolved:** authenticated schema bytes, in-process schema application, producer codec, and launcher codec are distinct paths. |
| Close uncertainty and primary-plus-cleanup | **Improved in closure owner; not complete in launcher:** raw close/wait/root failure ownership remains under P1-3. |
| Page-granular ELF profile | **Resolved in implementation shape and expanded portable matrix.** |
| Component/symlink/alias hostility and fixture truth | **Materially improved.** Launcher T2 fixtures still overstate production coverage under P1-4. |
| Architecture gate before hard-coded syscall numbers | **Resolved for top-level production entry and `_SystemOps` construction.** Native availability is unproved; inner primitive unavailable classification is P2-1. |
| Truthful result shape / no prefilled booleans | **Not resolved:** P0-1. |
| Readable non-compressed security flow | **Not resolved:** P2-2. |
| Historical predecessor whitespace P3 | **Disposition accepted by ADR 0088.** Exact correction-range and exact-head diff checks are clean. |

## Fixed-root/T2 path assessment

| Stage | Result |
| --- | --- |
| Issuer descriptor/report verification | Present and materially bound |
| Exact executable/loader/library copies | Present; per-copy digest readback |
| Root read-only transition | Attempted, but no independent mount observation and partial setup is unrecoverable |
| User/PID/mount/network namespaces | Combined unshare present; identity-map bug and no identity/ownership proof |
| PID 1 | Kernel topology intends first child; no production observation before claim |
| Chroot | Present before final drop |
| Supplementary groups | Clear attempted |
| Effective/permitted/inheritable caps | Zeroed and read through `capget` |
| Bounding/ambient caps | Drop/clear attempted, not independently read back |
| `noroot` securebits | Set and reread |
| NNP | Set and reread |
| Seccomp | Filter installed, but replacement/execution policy incomplete and denial facts unobserved |
| Final mappings before input | Source order is correct; missing exec gate makes it racy |
| Normal/error cleanup | Normal happy path attempts unmount/rmdir; failure/recovery ownership is incomplete |

## Checks

| Check | Result |
| --- | --- |
| Exact head before report | PASS — `d845cb13111cc3077141d84a3796537bd125dd0b` |
| Seven direct `/usr/bin/python3 -I -B` portable suites | PASS |
| Seven optimized-mode rejection runs | PASS — every suite exited nonzero |
| `py_compile` for three production modules and seven portable suites | PASS; generated caches removed |
| Static production/portable T2 event comparison | FAIL contract — 26 portable-only claimed events |
| Static x86-64 seccomp spot check | FAIL contract — `prctl(157)`, `seccomp(317)`, `execve(59)`, and unrestricted `execveat(322)` are allowed |
| `git diff --check 32ba6e0..HEAD` and `HEAD^..HEAD` | PASS |
| `git fsck --no-progress --no-dangling` | PASS |
| `npm run schemas`, `typecheck`, `lint` | NOT RUN / environment blocked — locked `node_modules` is absent (`tsx`, `tsc`, and `biome` not found) |
| Native Linux x86-64 route | NOT RUN — review host is unsupported Darwin arm64 and the request authorized portable/static checks only |

## ADR 0088 line accounting

All current trusted/portable surfaces remain within their individual highs: parser 306/320, closure 1,696/1,700, launcher 1,296/1,300, schema 134/260, schema registration 27/30, all seven Python suites and the TypeScript wrapper within their highs, fixtures 433/700, and trusted/portable subtotal 6,028/7,010. This is numeric compliance only; P2-2 prevents readability sign-off.

## Native readiness

**NOT READY.** There is no exact-head native A–E or thin-integration evidence, and native implementation remains gated by ADR 0088's zero-unresolved-P0–P3 rule. The current host is intentionally rejected by the production architecture gate. The Linux x86-64 path must not be run for qualification until the production T2 owner, final-exec gate, seccomp facts, unavailable semantics, and exact cleanup/recovery are corrected and a fresh exact-head hostile review is clean.

O2-R2-SANDBOX COMPLETE
