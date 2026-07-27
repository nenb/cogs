# ADR 0075: Correct native sandbox UID mapping

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only the trusted `native-runtime-preflight` launcher identity map and close the resulting host-root pathname-socket boundary. Retain host UID/GID 0 through the fixed `sudo`/`setpriv` setup, map exactly initial-namespace UID/GID 0 to new-user-namespace UID/GID 0, prove the final capability drop, and install one exact inherited x86_64 seccomp-BPF filter before checked-out code. Authorize only the corresponding existing CI workflow and two TypeScript static-companion changes under ADR 0074's retained highs. Checked-in Python test behavior, production code, schema, events, runs, acquisition, and AWS boundaries do not change.

## Context

ADR 0074 requires genuine fixed host tools and their exact root-owned executable, loader, library, and device closure. The prior trusted launcher instead captured the ordinary runner identity, used host-root `sudo` only to enter `setpriv`, changed all host UIDs/GIDs to that runner identity, and then used `unshare --user --map-root-user`. That map makes the host runner UID/GID namespace UID/GID 0, but leaves initial-namespace UID/GID 0 unmapped. Consequently, read-only host-root binds such as `/usr`, existing `/lib` and `/lib64`, `/dev/null`, and `/dev/urandom` appear inside the sandbox with overflow UID/GID 65534 rather than their genuine UID/GID 0 identity.

Accepting overflow ownership would contradict the exact host-tool trust closure. Mocking ownership, changing it with `chown`, or copying host objects into a different tree would test a substitute and is prohibited. The identity correction belongs only in the trusted launcher map. It does not require a production or checked-in Python-companion change.

Host-root DAC identity also makes a recursively exposed pathname socket security-critical. A read-only bind prevents mutation but does not prove that `/usr`, existing `/lib` or `/lib64`, or `/src` contains no socket inode, and a fresh network namespace does not by itself isolate a pathname Unix socket reached through the mount namespace. Filesystem scanning cannot supply an exact race-free invariant over those broad binds. The executable invariant is instead that checked code can neither create a socket descriptor nor perform any socket operation: one trusted in-chroot launcher must install an exact inherited seccomp filter after the final capability/`no_new_privs` boundary and before resolving or executing either checked-in Python companion.

## Decision

### Exact correction ancestry

The exact implementation predecessor is `779948d97c62a44ff9cdba357375a0b652febc00`. It is the history-preserving integration merge whose first parent is `96c244d2353903bfae0d7487916ed6987b8fa485` and whose second parent is accepted ADR 0074 commit `ddb93aaf53ca26fc1f37e09e805f49423a6618ae`.

Implementation must start at exactly `779948d97c62a44ff9cdba357375a0b652febc00` and integrate the exact accepted commit containing this ADR by a history-preserving merge before any implementation commit. That integration merge must have `779948d97c62a44ff9cdba357375a0b652febc00` as first parent and the accepted ADR 0075 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from this documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Exact trusted root identity map

The outer workflow retains the validated ordinary runner UID/GID and its runner-owned anonymous expected, output, and parent descriptors. Those values remain mandatory for outer evidence identity checks, but they must no longer select the child user-namespace map.

For each invocation, the launcher prefix must be exactly `/usr/bin/sudo -n --close-from=3 /usr/bin/setpriv --reuid 0 --regid 0 --clear-groups --no-new-privs /usr/bin/unshare --user --map-users=0:0:1 --map-groups=0:0:1 --net --pid --fork --mount`. Thus `sudo` directly executes exact `setpriv`; before `unshare`, `setpriv` sets real, effective, and saved host UID 0 and real, effective, and saved host GID 0, clears every supplementary group, and sets `no_new_privs`. `unshare` then executes the retained empty-environment trusted sandbox shell. The resulting `/proc/self/uid_map` and `/proc/self/gid_map` must each contain only the extent `0 0 1`. `--map-root-user`, a runner-UID/GID map, a subordinate or multi-extent map, a caller-selected map, and an omitted or normalized substitute are prohibited.

Only this fixed trusted `sudo`/`setpriv`/`unshare` setup runs with initial-namespace host-root identity. No shell selected by the caller and no checked-out code may run before creation of the new user namespace. Entering that user namespace grants capabilities only with respect to that namespace and its descendant namespaces; it grants none in the initial user namespace. After entry, the trusted setup cannot use its namespace capabilities against the initial namespace and cannot `setns` into a host namespace. Descriptor closure leaves it no inherited host namespace or control-socket descriptor.

With the exact one-ID map, genuine host-root bind sources appear inside the sandbox as UID/GID 0. Trusted setup and native evidence must verify that identity directly for the complete required host-tool and device closure. Overflow UID/GID 65534, mocked or rewritten stat results, `chown`, ownership-relaxation, copied executables/libraries/devices, or a generated substitute fails and grants no evidence.

### Retained chroot and final capability boundary

All non-conflicting ADR 0071–0074 isolation remains mandatory. Trusted setup alone closes descriptors, creates fresh network/PID/mount namespaces, makes propagation recursively private, hides host `/tmp`, constructs and completely verifies the exact tmpfs/chroot mount allowlist, and terminally enters that chroot. No host `/run`, writable checkout, host procfs, old-root path, extra bind, or extra descriptor may become reachable. The recursively read-only host-backed binds are not assumed or required to be free of socket inodes; the syscall boundary below makes any such inode unusable by checked code.

Inside the verified chroot, exact `setpriv` must retain namespace UID/GID 0 while setting and locking `noroot`, emptying the bounding, inheritable, and ambient capability sets, clearing supplementary groups, and setting `no_new_privs`. It must invoke only the fixed timeout around exact trusted `/usr/bin/python3 -I -B -c <literal-seccomp-launcher>` with one of the two literal companion paths as inert data. Isolated mode must prevent the launcher from importing or resolving checkout content. Before checked-out code is resolved or executed, that launcher must prove from the running process that `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and `CapAmb` are all zero, `NoNewPrivs` is one, all real/effective/saved UID/GID values are zero, and supplementary groups are empty. Any unsupported operation, ambiguous observation, nonzero capability set, identity mismatch, or setup failure is terminal; skip, fallback, retry under another map, or environment-limited acceptance is prohibited.

### Exact inherited x86_64 seccomp-BPF boundary

The workflow must contain one complete literal trusted Python launcher; it may use only trusted in-chroot standard-library `os`/`ctypes` functionality and literal Linux UAPI values. It may not use `libseccomp`, a compiler, generated or downloaded code, `PATH` lookup, caller input other than the already-fixed literal companion path, or any source, module, helper, configuration, or data from `/src`. After the identity/capability checks above, it must construct one classic seccomp-BPF `sock_fprog` whose first decision loads `seccomp_data.arch` and permits the native table only when it equals `AUDIT_ARCH_X86_64` (`0xc000003e`). An architecture mismatch must return `SECCOMP_RET_KILL_PROCESS`. A set x32 syscall-number bit must also return `SECCOMP_RET_KILL_PROCESS` rather than permit an alternate table under the same audit architecture.

For the native x86_64 table, the filter must return exactly `SECCOMP_RET_ERRNO | EPERM` for this complete socket syscall map and no normalized or name-resolved substitute:

| Syscall | Number | Syscall | Number |
| --- | ---: | --- | ---: |
| `socket` | 41 | `connect` | 42 |
| `accept` | 43 | `sendto` | 44 |
| `recvfrom` | 45 | `sendmsg` | 46 |
| `recvmsg` | 47 | `shutdown` | 48 |
| `bind` | 49 | `listen` | 50 |
| `getsockname` | 51 | `getpeername` | 52 |
| `socketpair` | 53 | `setsockopt` | 54 |
| `getsockopt` | 55 | `accept4` | 288 |
| `recvmmsg` | 299 | `sendmmsg` | 307 |
| `io_uring_setup` | 425 | `io_uring_enter` | 426 |
| `io_uring_register` | 427 |  |  |

As defense against namespace, filter, or indirect socket manipulation, the same `EPERM` result is mandatory for `unshare` (272), `setns` (308), and `seccomp` (317), and for `prctl` (157) only when `seccomp_data.args[0]` is `PR_SET_SECCOMP` (22). Denying all three io_uring syscalls is mandatory even when no ring descriptor is inherited, so `IORING_OP_SOCKET` and `IORING_OP_CONNECT` cannot bypass the direct socket table. Other `prctl` operations and every other native x86_64 syscall must return `SECCOMP_RET_ALLOW`. The BPF instruction sequence, offsets, jumps, constants, table, special `prctl` argument branch, x32 rejection, error action, architecture action, and final allow action must be complete literals in the workflow; duplicate, omitted, added, reordered, dynamically derived, host-header-derived, or architecture-normalized rules are prohibited.

Only after constructing that exact program, the launcher must call libc `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` and require an exact zero return, then call `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)` and require an exact zero return. `PR_SET_NO_NEW_PRIVS` is 38 and `SECCOMP_MODE_FILTER` is 2. The order is immutable: final capability and identity proof, NNP `prctl`, filter `prctl`, post-install proof, then exec. The launcher must prove `/proc/self/status` still has the required identity, five zero capability sets, `NoNewPrivs: 1`, and `Seccomp: 2` after installation. Any nonzero return (with captured `errno` on failure), malformed or ambiguous status, unexpected mode, exception, or later exec failure is terminal after at most a fixed diagnostic to fd 2; there is no unfiltered retry, alternate API, relaxed filter, skip, or fallback.

The launcher must then call `os.execve` with exact executable `/usr/bin/python3`, exact argv `/usr/bin/python3 -I -B <literal-companion-path>`, and the exact two-entry environment `COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1=1` and `PYTHONDONTWRITEBYTECODE=1`. The only permitted companion paths remain `/src/test/aws-stage2-completion-kata-process.py` and `/src/test/stage2-phase-a-candidate.py`, each fixed by its separate invocation. The retained exact `/usr/bin/timeout --signal=KILL 240` is the trusted parent of this launcher and remains outside checked code; it does not weaken filter inheritance. The successful `execve`, every fork/clone, and every later exec inherit the filter, and checked code cannot replace it through either seccomp installation API or escape through `setns`/`unshare`.

The checked code therefore has namespace UID/GID 0 backed by initial-namespace kernel UID/GID 0, but has no capabilities in the initial user namespace and, after the final drop, none in its own user namespace. It receives no socket or io_uring descriptor, cannot create one with direct socket syscalls or indirect io_uring operations, and receives `EPERM` from every listed operation needed to open, connect, accept, configure, or use a pathname socket. Thus an existing socket inode beneath a read-only bind is unreachable regardless of DAC UID/GID 0; no dynamic socket-free scan is required. The exact read-only allowlist, old-root cutoff, both descriptor-3-and-above closures, no inherited namespace or socket descriptor, final zero-capability proof, and inherited filter are all mandatory. The only retained writable outer object visible to the child is the already-open runner-owned anonymous output file description through fd 1 and fd 2; its outer runner-owned descriptors and identity checks remain unchanged.

### Exact authorized files and retained highs

Only these exact three files may change under ADR 0075:

| File | Authorized correction | Retained gross-addition maximum from `18f2644` |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Replace only the trusted host-runner identity drop/map with the exact host-root one-ID map; add the fixed pre-code identity/capability proof and literal trusted seccomp launcher/filter/install/exec chain. | **280** |
| `test/aws-stage2-completion-kata-process.test.ts` | Assert the exact corrected map/root closure and the complete literal filter syscall table, x86_64 architecture gate, BPF actions, install order, terminal failures, inheritance, and exact `os.execve`; reject predecessor and weakened variants. | **80** |
| `test/stage2-phase-a-candidate.test.ts` | Assert the same exact corrected launcher/map/filter/install/exec chain and retained anonymous-publication/chroot boundary; reject predecessor maps, ownership substitutes, and weakened filter variants. | **600** |

ADR 0074's untouched Python-companion highs of 750 and 850 and exact-five-file aggregate high of 2,560 remain unchanged, non-transferable, and measured from exact `18f26441b6115091233d0c4cd44ced8f058d014f`. Deletion creates no credit. No checked-in Python companion, production module, production runner, budget script, qualification module, runtime module, schema, candidate workflow, package file, lockfile, fixture, or new file may change under this ADR. The literal trusted Python launcher exists only inside the authorized workflow and is not production or test-companion Python. The native primitive matrix, separate portable suites, selector, markers, output protocol, resource bounds, retained production highs, and 3,310 production aggregate do not change.

## Evidence and gates

The retained exact final implementation commit must descend through the required first/second-parent integration, contain all prior reviewed implementation and the tracked Phase B schema, remain clean, pass the complete ordinary portable checks, and later pass the separately permitted exact-head native preflight. Final hostile review must inspect the retained no-rename ranges and additionally verify the exact root map, root-owned genuine closure without mock/`chown`/copy, trusted-only pre-namespace setup, no initial-user-namespace capability after `unshare`, complete chroot allowlist, pre-code zero capability sets, and the complete literal x86_64 seccomp program. It must verify the exact socket/namespace/filter syscall numbers, architecture and x32 gates, `EPERM`/kill/allow actions, `prctl` argument branch, capability-proof/NNP/filter/post-proof/`os.execve` order, terminal failures, inheritance by all checked-code descendants, old-root/fd/socket-descriptor absence, unchanged runner-owned outer output descriptors, exact three-file-only ADR 0075 correction, retained highs, no checked-in Python or production change, and no unresolved P0–P3 finding. Any later change invalidates signoff.

Until that final commit, checks, separately permitted native result, and clean review exist, `native-runtime-preflight` is not valid evidence, ADR 0069's sole local actual-size execution remains ineligible, and `phase-b-runtime-discovery` remains closed.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0074 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The conservative projection remains `33,344 < 34,000`; the 32,000 preferred target, 34,000 hard cap, and 656-line margin remain unchanged and grant no implementation authority.
