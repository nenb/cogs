# Outcome 2 closure correction — production fixed sandbox launcher design

**Status:** design only; no implementation or native execution is authorized by this record  
**Design source:** `2023e650e88767e0bd7574f0c302e780743eab5a`  
**Authorities read:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, all five `closure-review-*.md` reports at this head, and the exact parser/closure/launcher/schema/portable implementation  
**Target production API:** `launch_fixed_sandbox_probe()` in `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py`  

## 1. Decision

The current `_run_fixed_sandbox()` is not retained as the production mechanism. It observes the calling process and fabricates cleanup success; it does not create or own Job E's boundary.

`launch_fixed_sandbox_probe()` will instead be a fixed outer supervisor for one privileged, isolated transaction. It will:

1. require the separately authenticated T0/T1 root entry;
2. capture descriptor, child, namespace, mount, checkout, and fixed-state-root baselines;
3. create one trusted namespace owner;
4. create the **user, mount, PID-for-children, and network namespaces in one `unshare` tuple**;
5. construct and verify the complete fixed mount view inside that mount namespace;
6. fork exactly one metadata child, which is PID 1 in the new PID namespace;
7. chroot that child, clear all five capability sets, lock `noroot`, set NNP, install the fixed Job E seccomp profile, and expose only fds 0–3;
8. receive one bounded canonical metadata record;
9. reap the metadata child, unmount every exact owned mount in reverse order, release namespace handles, remove only the exact owned state root, and recompare all baselines; and
10. return `SandboxQualificationResult` only after cleanup succeeds.

There is no unprivileged fallback, util-linux fallback, container fallback, alternate mount table, procfs fallback, retry, or environment-limited pass.

Job E will call this production API. Its native driver may establish the exact-head envelope and fixed `sudo` entry, but may not implement namespaces, mounts, capability removal, seccomp, probe semantics, process supervision, or cleanup itself.

## 2. What this corrects—and what it does not

### Corrected by this design

This design directly closes the sandbox portions of the closure reviews:

- construction rather than observation of T2;
- exact user/mount/PID/network namespace ownership;
- PID 1 metadata execution;
- fixed chroot and mount view;
- read-only checkout and unchanged-checkout proof;
- effective, permitted, inheritable, bounding, and ambient capability sets all zero;
- locked `noroot`, NNP, and seccomp replacement denial;
- exact child fd table;
- real child/descendant ownership;
- outer crash recovery; and
- exact mount, namespace, path, descriptor, process, and checkout cleanup.

### Separate blockers remain separate

This design does not pretend to fix the other holistic findings:

- pre-effect exact-source/import admission;
- forgeable/substitutable `RuntimeClosureHandoff`;
- executable-fd/report binding;
- execution-time loader/library generation binding;
- closure helper descriptor inheritance and lifecycle defects;
- tracked-schema/independent-codec validation; or
- parser and remaining portable matrices.

The sandbox implementation may be developed in parallel with those corrections, but no thin integration or Outcome 2 sign-off can occur until all are resolved and re-reviewed.

The present launcher is at 599/600 lines and the closure/parser highs are exhausted. A new accepted ADR must authorize readable launcher and portable-test growth before implementation. Security control flow must not be compressed to fit ADR 0087's remaining one-line launcher margin.

## 3. Admission and invocation boundary

`launch_fixed_sandbox_probe()` accepts no arguments. In production it refuses to begin unless all of these fixed preconditions are true:

- Linux x86-64;
- effective, real, and saved UID/GID are the fixed sudo-root identity;
- the process is single-threaded and is a dedicated helper, not a long-lived application process;
- startup descriptors are exactly 0, 1, and 2 because Job E used `/usr/bin/sudo -n --close-from=3`;
- the environment is the fixed empty/allowlisted environment;
- isolated no-bytecode `/usr/bin/python3 -I -B` is in use;
- the checkout, launcher, parser dependencies used by the bootstrap, and Job E driver have been admitted before import/effect by the separately corrected exact-source bootstrap; and
- the checkout head and porcelain baseline are exact and clean.

The public function does not invoke `sudo`. The only native caller is the fixed Job E root entry created after the workflow's same-repository exact-head gate. An ordinary unprivileged call fails before creating a path, child, namespace, pipe, or mount.

Runtime self-hashing after import is not admission. The current post-handoff source check cannot authorize this function. Until pre-import admission exists, the system implementation remains fail-closed even if its portable suite passes.

## 4. Fixed constants and no policy inputs

All production choices are module constants. No value below comes from argv, environment, a report, repository data, or the caller.

```text
state parent       /run
state leaf         cogs-o2-job-e-sandbox-v1
sandbox root       /run/cogs-o2-job-e-sandbox-v1
checkout target    /src
metadata fd        3
metadata maximum   4096 bytes, exactly one canonical JSON line
setup deadline     10 seconds
probe deadline     5 seconds
TERM deadline      1 second
KILL/reap deadline 1 second
mountinfo maximum  1 MiB / 4096 rows
namespace maximum  exactly one owner and one PID-1 child
```

A pre-existing state leaf is not adopted, renamed, cleaned speculatively, or treated as stale. It is a terminal ownership conflict. A second concurrent invocation therefore fails closed.

The fixed mount plan is:

| Order | Source authority | Target | Final policy |
| ---: | --- | --- | --- |
| 1 | new tmpfs | `/` | `ro,nosuid,nodev,noexec`, mode 0755, fixed size/inode bounds |
| 2 | new tmpfs | `/tmp` | `rw,nosuid,nodev,noexec`, mode 1777, fixed size/inode bounds |
| 3 | authenticated checkout directory | `/src` | bind, `ro,nosuid,nodev,noexec` |
| 4 | authenticated `/usr` directory | `/usr` | bind, `ro,nosuid,nodev,noexec` |
| 5 | authenticated `/lib/x86_64-linux-gnu` directory | `/lib/x86_64-linux-gnu` | bind, `ro,nosuid,nodev,noexec` |
| 6 | authenticated `/lib64/ld-linux-x86-64.so.2` file | `/lib64/ld-linux-x86-64.so.2` | bind, `ro,nosuid,nodev,noexec` |
| 7 | authenticated `/dev/null` device | `/dev/null` | bind, `ro,nosuid,noexec` |
| 8 | authenticated `/dev/urandom` device | `/dev/urandom` | bind, `ro,nosuid,noexec` |

The root tmpfs is writable only while trusted setup creates the literal targets. It is remounted read-only before the metadata child is released. `/tmp` is the only writable final mount. There is no `/proc`, `/sys`, `/run`, `/home`, `/etc`, daemon socket, KVM device, old-root fd, or host root alias inside the chroot.

The `/usr` and loader/library binds satisfy Job E's fixed host-view contract but are `noexec`; Job E executes no tool after chroot. The later integration sandbox needs its own already-authorized execution profile bound to authenticated closure generations. It may not infer loader/library authority from these Job E binds.

Every source is opened after mount-namespace entry by a component-by-component, descriptor-relative fixed-path resolver. Final directory/file/device identity and security policy are checked before and after bind setup. Bind mounting uses the held source descriptor in the same mount namespace. `realpath`, `PATH`, source pathname reopen, recursive bind, and external `/usr/bin/mount` are prohibited.

A source with an unexpected nested mount is rejected. Each bind is remounted with the exact final flags and then independently re-observed through a complete bounded mountinfo parser. Missing, duplicate, extra, propagated, writable, wrong-root, wrong-type, wrong-source-identity, or wrong-option mounts are terminal.

## 5. Exact process and namespace topology

The implementation has three roles, all in one dedicated root helper process tree:

```text
S0  outer supervisor (initial user/mount/PID/network namespaces)
 └─ S1 trusted namespace and mount owner
     └─ S2 metadata child (PID 1 in final PID namespace)
```

### 5.1 S0 — outer supervisor

Before the first effect, S0 records:

- descriptors and descriptor identities;
- direct-child baseline;
- process session/group and subreaper state;
- initial user, mount, PID, and network namespace descriptor identities;
- complete bounded mountinfo digest and exact absence of the fixed state leaf mount;
- fixed state-parent identity;
- checkout head, tracked/untracked porcelain, and authenticated checkout-directory identity; and
- original soft/hard `RLIMIT_NOFILE` without changing it.

S0 opens `/run` descriptor-relatively, verifies its fixed root-owned/non-writable policy, registers the literal state-leaf intent, creates the leaf with `mkdirat` and mode 0700, opens it no-follow, and retains its exact identity. No `mkdtemp`, random suffix, caller run ID, or broad cleanup is used.

S0 sets and later restores `PR_SET_CHILD_SUBREAPER` in this dedicated process. It creates only CLOEXEC control/metadata pipes, then forks S1. S1 is registered immediately by PID, pidfd, start time, session, process group, and expected executable identity before receiving release.

### 5.2 S1 — one combined namespace tuple

Before namespace entry, S1:

- sets `PR_SET_PDEATHSIG=SIGKILL` and rechecks its parent;
- starts a new fixed session/process group;
- clears supplementary groups while still privileged in the initial user namespace; and
- blocks on the S0 control gate.

S1 makes exactly one namespace call:

```text
unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)
```

Linux creates the user namespace first for this combined call; the mount, PID-for-children, and network namespaces are therefore owned by that new user namespace. S1 remains in the ancestor PID namespace, while its next child enters the new PID namespace.

S1 reports the completed transition and blocks. Before releasing it, S0:

1. revalidates S1's exact identity;
2. writes `deny\n` once to `/proc/<S1>/setgroups`;
3. writes the singular maps `0 0 1\n` to both UID and GID maps;
4. rereads and requires those exact bytes;
5. opens S1's user, mount, network, and `pid_for_children` namespace descriptors;
6. requires user/mount/network identities to differ from S0 and the PID-for-children identity to differ from S0's PID namespace;
7. uses `NS_GET_NSTYPE`, `NS_GET_USERNS`, and `NS_GET_PARENT` ioctls to prove that mount, PID-for-children, and network are all owned by the one final user namespace and that this user namespace's parent is S0's initial user namespace; and
8. retains every namespace fd for cleanup/recovery.

Any denied or unsupported namespace, map, pidfd, or namespace-owner primitive fails. There is no broad identity map, subordinate-ID helper, `newuidmap`, `newgidmap`, second user namespace, second mount namespace, `nsenter`, or fallback order.

S1 then makes mount propagation recursively private and constructs the complete mount plan. It remains outside the future chroot, with exact mount ownership, until cleanup.

### 5.3 S2 — final PID-1 metadata child

After mount verification, S1 writes a child-creation intent to S0 and receives an acknowledgement. It forks exactly once. S2:

- is PID 1 in the final PID namespace;
- sets `PDEATHSIG=SIGKILL` and verifies S1 still exists;
- starts no new session or process group beyond the one already owned by S1;
- maps `/dev/null` to fds 0, 1, and 2 with fixed read/write modes;
- maps the metadata pipe write end to fd 3;
- calls genuine `close_range(4, UINT_MAX, 0)`; and
- retains no source, root, namespace, mount, checkout, control, old-root, or recovery descriptor.

S2 performs `chdir(fixed-root)`, `chroot(".")`, and `chdir("/")` while it still has the transitional capabilities of the final user namespace. It verifies `/` is the fixed root and no old-root handle exists.

S2 then applies the irreversible privilege sequence in this exact order:

1. require real/effective/saved UID and GID all zero in the singular namespace map;
2. require supplementary groups empty;
3. set dumpability to zero;
4. set securebits exactly to `SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED` (`0x0f`) and reread exactly;
5. clear all ambient capabilities;
6. enumerate the kernel-supported capability range under a fixed 256-entry bound and drop every bounding capability with `PR_CAPBSET_DROP`;
7. call `capset` once with effective, permitted, and inheritable words all zero;
8. verify effective, permitted, inheritable, bounding, and ambient sets are all zero;
9. set `PR_SET_NO_NEW_PRIVS=1` and reread exactly; and
10. install the fixed Job E seccomp program once.

S2 then stops itself with `SIGSTOP`. S0, using retained exact authority, proves before release that:

- S2 is the registered child of S1 and has the expected start time/session/group/executable identity;
- S2's PID namespace identity equals S1's retained `pid_for_children` namespace;
- S2's user, mount, and network identities equal S1's retained tuple;
- its host-visible status has final NSpid component 1;
- its credentials, groups, five capability sets, securebits, NNP, and seccomp mode match the fixed post-drop state;
- its fd directory contains exactly 0, 1, 2, and 3; and
- the final mount view still matches the fixed plan.

Only then does S0 send `SIGCONT`. This release carries no descriptor and gives S2 no setup authority.

S2 installs a fixed TERM handler solely so PID 1 can participate in bounded cleanup. Seccomp denies clone/fork/vfork/clone3, so S2 can have no descendant. An attempted child-creating syscall is itself part of the denial probe and must return `EPERM` without creating a process.

## 6. Fixed Job E seccomp profile

The production filter is a literal x86-64 classic-BPF program in the launcher. It first verifies `AUDIT_ARCH_X86_64`; an architecture mismatch kills the process. It returns `EPERM` for the complete fixed groups below and allows only other syscalls needed by the loaded metadata probe:

- socket operations: `socket`, `connect`, `accept`, `accept4`, `bind`, `listen`, `socketpair`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`;
- io_uring: `io_uring_setup`, `io_uring_enter`, `io_uring_register`;
- namespace/process creation or entry: `clone`, `clone3`, `fork`, `vfork`, `unshare`, `setns`;
- sandbox replacement: `seccomp` and only `prctl(PR_SET_SECCOMP, ...)`, while query-only `prctl` operations remain available;
- post-boundary mount/root changes: `mount`, `umount2`, `pivot_root`, `chroot`;
- acquisition/authority expansion: `execve`, `execveat`, `bpf`, `userfaultfd`, `perf_event_open`, `ptrace`, `add_key`, `request_key`, `keyctl`.

Job E and integration use distinct fixed profiles. The Job E profile deliberately denies all execution because the metadata code is already resident. This profile must not be reused for gzip/zstd integration, and Job E cannot be weakened to accommodate integration.

After installation, S2 performs real effect-minimal denials and requires `-1/EPERM` for:

- IPv4 and Unix-domain socket creation;
- `io_uring_setup`;
- `unshare(0)` and `setns(-1, 0)`;
- `clone3` with the fixed test shape;
- `seccomp(SECCOMP_SET_MODE_FILTER, ...)`;
- `prctl(PR_SET_SECCOMP, ...)`;
- `mount`, `chroot`, `execve`, and `execveat` fixed probes.

A different errno, successful syscall, signal death before metadata, unavailable seccomp, filter mode other than 2, or a changed instruction program is failure. No socket is created and no network packet is attempted.

## 7. Metadata-child contract

S2 does not import or execute checkout content, parse ELF, inspect `maps`/`map_files`, run gzip/zstd, test fd 4096, or repeat Job D's parent-death timing matrix.

It verifies only Job E facts:

- PID and parent semantics are PID 1 / namespace parent 0;
- exact root and cwd;
- `/src` is read-only and `nosuid,nodev,noexec`;
- fixed create, overwrite, unlink, and rename attempts under `/src` fail read-only;
- fixed create under `/` fails read-only;
- `/tmp` is the sole writable mount and a fixed create/fsync/unlink round trip succeeds;
- `/proc`, `/sys`, `/run`, `/home`, `/etc`, and old-root paths are absent;
- `/usr` and fixed loader/library views are read-only/noexec;
- only fixed devices are visible;
- all five capability sets are zero;
- securebits are exactly locked as above;
- NNP and seccomp mode are exact;
- every fixed denial returns `EPERM`; and
- fd 3 remains the sole metadata channel.

On success S2 writes exactly one canonical JSON line, at most 4096 bytes, with fixed keys and literal booleans. It contains no path, PID, UID/GID, namespace or mount identity, command, exception, errno text, environment, host metadata, or raw diagnostic. It closes fd 3 and exits zero. Partial, duplicate, noncanonical, oversized, extra, or success-after-nonzero-exit metadata is rejected.

A corrected `SandboxQualificationResult` is derived from independent trusted observations plus this record. It must expose, rather than fabricate, at least:

```text
mount_view_exact
checkout_read_only
user_namespace_exact
pid_namespace_exact
mount_namespace_exact
network_namespace_exact
pid_one
fd_map_exact
capabilities_zero
noroot_locked
nnp_set
seccomp_socket_denied
seccomp_io_uring_denied
seccomp_namespace_denied
seccomp_replacement_denied
no_acquisition_route
checkout_unchanged
descriptors_restored
children_reaped
mounts_restored
namespaces_released
paths_restored
cleanup_restored
```

No result object is constructed until every cleanup field is true.

## 8. Ownership, recovery, and cleanup

### 8.1 Registries and write-ahead protocol

The launcher uses owner-local registries, not module-global sets:

- descriptors, each with role and expected identity;
- children, each with pidfd, PID/start-time/session/group/executable identity and reap state;
- namespace descriptors and their owner tuple;
- mounts, each with fixed target, source identity, expected mount identity/options, and state;
- named directories/files, each relative to a retained parent fd with exact identity; and
- checkout and process baselines.

S1 sends a bounded fixed write-ahead event to S0 before every mount and before the S2 fork. S0 acknowledges each intent before S1 performs the effect. S1 then sends the observed settled identity. Events contain fixed enums and private numeric identities only; they never enter metadata or native reports.

A crash between intent and settlement is `uncertain`, not `absent`. Recovery inspects only the exact intended target/child under retained authority.

### 8.2 Normal cleanup

Cleanup always preserves the primary error and attempts every independently safe step:

1. close release/control gates so no unreleased child can continue;
2. revalidate S2 through pidfd plus PID/start-time/session/group/executable identity;
3. send TERM, wait to the fixed deadline, then KILL only if the same identity remains;
4. reap S2 and every exact adopted descendant; an unexpected descendant is terminal;
5. require S1 to verify the final fixed mount view and unmount entries 8 through 2, then 1, using `umount2(target, 0)` only;
6. forbid lazy, force, expire, recursive, wildcard, and path-prefix unmount;
7. require complete mountinfo proof that every owned mount is absent and no unexpected mount appeared;
8. close namespace, pidfd, pipe, source, state-root, and parent descriptors once, aggregating close uncertainty without retrying a possibly reused fd number;
9. remove the fixed state leaf only with `unlinkat(..., AT_REMOVEDIR)` after retained-parent-fd identity revalidation and exact emptiness;
10. restore subreaper state and any other changed process-local baseline;
11. re-read exact checkout HEAD/porcelain and require the authenticated checkout identity unchanged; and
12. recompare fd, child, mount, namespace, limit, state-path, and checkout baselines and require all registries empty.

S1 remains in the owning mount namespace and outside the chroot specifically so normal unmount is possible.

### 8.3 Outer crash recovery

S0 is the fixed outer recovery owner. Anonymous descriptors close when a crashed child exits, but that fact alone is not reported as cleanup proof.

If S1 crashes or cannot clean mounts, S0:

1. closes all release gates;
2. revalidates and terminates/reaps S2 as above, using subreaper adoption if S1 died;
3. forks one dedicated recovery child;
4. in that recovery child only, enters the retained final user namespace and then the retained mount namespace;
5. parses complete bounded mountinfo and classifies each exact write-ahead target as absent, exact-owned, foreign/replaced, or uncertain;
6. unmounts only exact-owned entries in reverse order with ordinary `umount2(..., 0)`;
7. proves exact absence and exits; and
8. lets S0 close the retained user/mount/PID/network namespace descriptors and prove namespace/process absence.

The recovery child never returns to the initial user namespace; it exits after recovery. S0 never changes namespace.

A target whose identity cannot be matched is preserved and makes the transaction terminally poisoned. An unknown descendant, lost namespace fd, failed `setns`, failed ordinary unmount, busy mount, failed reap, close uncertainty, checkout drift, or inability to compare any baseline prevents a result. Runner disposal is not cleanup evidence.

The state machine is:

```text
NEW -> BASELINED -> STATE_OWNED -> OWNER_RUNNING -> SANDBOX_READY
    -> PROBE_RUNNING -> CLEANING -> COMPLETE

any effect state -> RECOVERING -> FAILED
any uncertainty  -> POISONED  -> FAILED only
```

`POISONED` never becomes `COMPLETE`, and the public zero-argument call has no retry API.

## 9. Portable `_SandboxOps` design

The present `_ScriptedLauncherAdapter.run_sandbox()` returning a prebuilt all-true result is removed. Portable tests must drive the same supervisor, namespace-owner, metadata-child, and recovery state machines used by production.

A private `_SandboxOps` adapter will expose typed primitives, not success claims. The system implementation wraps exact syscalls. The scripted implementation models descriptors, processes, namespace ownership, maps, mount tables, credentials, capabilities, seccomp decisions, metadata bytes, and named identities.

Required adapter groups are:

```text
platform/admission     architecture, credentials, thread count, source admission
baseline               fds, children, namespaces, mountinfo, limits, checkout, paths
fd                      openat/fstat/read/write/dup3/close_range/close
process                 fork/pidfd/identity/wait/signal/subreaper/deadlines
namespace               unshare/setns/ns-ioctl/uid-map/gid-map/setgroups
mount                    propagation/mount/remount/umount/mountinfo/statfs
filesystem              mkdirat/unlinkat/chroot/chdir/fixed write probes
privilege                groups/securebits/capget/capset/bounding/ambient/NNP
seccomp                  install/query/fixed denied-syscall probes
metadata                 bounded canonical pipe read/write
clock                    monotonic fixed deadlines
```

Production public functions construct `_SystemSandboxOps` internally. Only a private test function accepts `_SandboxOps`; no adapter, path, policy, fd target, timeout, or fault selector is reachable from `launch_fixed_sandbox_probe()`.

Portable hostile coverage must include:

- every before-effect and after-effect cut for state-root creation, fork, unshare, map write, namespace-fd acquisition, every mount/remount, chroot, capability step, filter install, metadata write, child exit, every unmount, every close, and state-root removal;
- unsupported/wrong architecture, non-root entry, extra startup fd, extra thread, dirty checkout, and missing source admission with zero effects;
- namespace aliasing, wrong owner user namespace, broad/duplicate maps, map drift, and PID-not-one;
- missing/duplicate/extra mount rows, propagation, nested source mount, wrong bind identity, writable checkout, and successful forbidden write;
- one-bit mutations in each of the five capability sets, every securebit mismatch, groups present, NNP zero, wrong seccomp mode, changed filter instruction, wrong errno, and successful denied syscall;
- fd substitution/reuse, partial metadata, duplicate key, noncanonical bytes, extra bytes, nonzero child exit, timeout, identity drift, unexpected descendant, wait/reap failure, and TERM/KILL escalation;
- S1 crash before/after each mount and before/after S2 fork, recovery-child failure, foreign/replaced mount/path preservation, primary-plus-cleanup aggregation, and repeat-after-poison rejection; and
- exact restoration of descriptors, children, mounts, namespace handles, named paths, process settings, and checkout in every success/failure model.

Portable tests perform no real sudo, unshare, mount, chroot, capability change, seccomp install, network syscall, or namespace entry. Static assertions alone are insufficient, but the adapter also records exact ordering so tests can prove no checkout probe runs before chroot/drop/filter and no pass is encoded before cleanup.

## 10. What can be implemented before native proof

After a revised ADR authorizes the lines/surfaces, all of the following can and should be implemented and hostile-tested before any native run:

- fixed constants, mount plan, fd map, state/result types, and owner state machine;
- strict private metadata codec and independent mutation tests;
- bounded UID/GID-map, namespace-owner, mountinfo, status, and checkout-baseline parsers;
- literal x86-64 seccomp assembler/table and instruction-level expected digest;
- descriptor/path/child/mount/namespace registries and cleanup aggregation;
- complete supervisor, owner, metadata-child, normal-cleanup, and recovery control flow through `_SandboxOps`;
- every system syscall wrapper, with production public entry fail gates;
- all portable fault, crash-cut, fd-reuse, malformed-observation, and residue matrices; and
- static Job E driver/workflow checks proving that native code only establishes the exact-head/sudo envelope and calls the production API.

Portable evidence can prove fixed policy, sequencing, parser/codec semantics, state transitions, fail-closed classification, cleanup attempts, and that no caller-controlled authority reaches production.

Portable evidence cannot prove that the hosted kernel actually:

- permits the combined user/mount/PID/network tuple and singular maps;
- assigns namespace ownership as required;
- supports the exact namespace ioctls, pidfds, `close_range`, seccomp, capability operations, and ordinary unmount behavior;
- honors descriptor-source bind/remount flags and chroot semantics;
- presents the expected Ubuntu fixed `/usr`/loader/library/device sources;
- makes S2 PID 1 with the observed proc/status semantics;
- enforces every BPF denial with `EPERM`; or
- leaves the real runner's mount/process/checkout baselines unchanged.

Those are later Job E native claims. Job E must call the exact production `launch_fixed_sandbox_probe()` once on a fresh runner. It may compare the returned fixed check set with the native-report schema, but it may not reproduce setup or turn `EPERM`, `ENOSYS`, `EINVAL`, missing source, unsupported ioctl, timeout, or cleanup uncertainty into skip/pass.

## 11. Native Job E and integration boundary

The later native Job E remains small:

1. pass Quality and all portable suites;
2. establish the accepted same-repository exact-head/workflow/driver/launcher gate;
3. invoke fixed `sudo -n --close-from=3` into the admitted dedicated launcher root entry;
4. call `launch_fixed_sandbox_probe()` exactly once;
5. require every returned Job E and cleanup fact true;
6. encode only the accepted metadata-only native report; and
7. upload only the exact report artifact after cleanup.

It does not parse mountinfo, assemble BPF, invoke `unshare`/`mount`/`setpriv`, supervise children, or clean mounts. Those behaviors belong to the launcher it is qualifying.

Thin integration remains later and separate. It may reuse the corrected supervisor/namespace/mount owner, but its fixed mount and seccomp profiles must bind the authenticated loader/library generations and permit only the fixed gzip/zstd execution path. A Job E pass does not cure the current handoff or execution-generation defects and does not authorize integration.

## 12. Fail-closed table

| Condition | Required behavior |
| --- | --- |
| source bootstrap absent or post-import only | fail before first effect |
| not Linux x86-64, not dedicated root, extra startup fd/thread/env | fail before first effect |
| fixed state leaf exists | preserve it; fail ownership conflict |
| any fixed source missing, mutable, replaced, or unexpectedly mounted | no alternate source; clean exact owned state; fail |
| combined namespace or exact singular map unavailable | no reordered/separate/fallback tuple; fail |
| namespace ownership/identity cannot be proved | do not release S2; recover; fail |
| mount/remount/reverification mismatch | do not chroot/release; exact cleanup; fail |
| PID 1, fd map, capability, securebit, NNP, or seccomp mismatch | no metadata success; terminate/reap; fail |
| denied syscall succeeds or returns another errno | fail, even if all other checks pass |
| metadata absent, partial, noncanonical, oversized, or inconsistent with exit | fail |
| checkout write succeeds or final checkout differs | fail; never repair checkout |
| child identity changes or descendant is unexpected | do not signal by raw PID; preserve uncertainty; fail |
| ordinary unmount fails or target is foreign/replaced | no lazy/force/recursive cleanup; preserve; poisoned failure |
| close reports failure after effect | do not retry fd number; poisoned failure |
| native primitive reports `ENOSYS`, `EINVAL`, `EPERM`, or environment limitation | fail, never skip/pass |
| any cleanup/baseline comparison is unavailable | no `SandboxQualificationResult`; fail |

## 13. Implementation gate

Before production edits:

1. accept a new ADR that binds this topology, fixed mount table, fd map, seccomp profile, metadata fields, recovery behavior, exact implementation predecessor, and readable line highs;
2. resolve how the pre-import authenticated bootstrap enters the launcher root process;
3. retain Job E's sole-sudo and no-workflow-security-code rules; and
4. assign sufficient launcher and portable-test budget rather than moving behavior into YAML, the native driver, generated fixtures, or compressed one-line control flow.

After portable implementation, obtain a fresh hostile review of source admission, namespace ownership, mounts/filesystem, credentials/seccomp, fd/process/recovery, and portable coverage. Only a clean review with no unresolved P0–P3 permits one exact-head native Job E run.

No production, test, schema, workflow, sudo, namespace, mount, chroot, seccomp, network, provider, cloud, or AWS action was performed for this design.
