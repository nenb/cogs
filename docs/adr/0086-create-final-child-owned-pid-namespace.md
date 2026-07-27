# ADR 0086: Create a final child-user-namespace-owned PID namespace

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only ADR 0085's terminal namespace tuple after native execution at exact clean head `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9` reached the fixed final util-linux `--mount-proc` transition and failed with `EPERM`. ADR 0085 made the final user namespace own the fresh mount namespace, but that user namespace did not own the retained outer PID namespace whose proc superblock it attempted to create. The one terminal `unshare` now creates the exact root-only user namespace together with fresh mount and PID namespaces and uses `--fork`; the child user namespace therefore owns both final namespaces, and the forked child is PID 1 in the final PID namespace before util-linux mounts proc at the unchanged exact target. The fixed launcher verifies the exact maps, final `NSpid` PID-1 identity, and new proc identity, then performs the unchanged read-only remount and reverification before chroot and capability removal. The outer PID namespace remains trusted setup isolation and dies with its waiter. No fallback, capability, file-scope, or numeric-cap change is authorized; CI remains 386 and no run or AWS action is authorized.

## Context

ADR 0085 correctly moved creation of the final proc superblock after the root-only user-namespace transition and into a mount namespace owned by that user namespace. Its implementation at exact head `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9` retained complete parent mount verification, checkout fd closure, the post-closure observer, and the terminal zero-capability chain. Native execution reached the exact fixed invocation:

```text
unshare --user --map-user=0 --map-group=0 --mount --mount-proc=<exact-target> ...
```

and `--mount-proc` failed with `EPERM` before the final trusted launcher or checked code ran.

A proc superblock is associated with a PID namespace, and mounting it requires the relevant privilege in that PID namespace's owning user namespace. ADR 0085 created a child-owned mount namespace but retained ADR 0083's outer PID namespace. That outer PID namespace was created while setup remained in the initial user namespace, so the new root-only user namespace did not own it. Root and transitional `CAP_SYS_ADMIN` in the final child user namespace consequently could not authorize proc creation for the outer PID namespace. Making the mount namespace child-owned alone was insufficient.

Retaining a capability across the checked boundary, mounting host or outer proc, weakening proc or mapped-closure evidence, retrying outside the child user namespace, or removing PID isolation is not acceptable. The narrow correction is to create a fresh PID namespace in the same terminal transition as the final user and mount namespaces and enter it with `--fork` before `--mount-proc`.

## Decision

### Exact correction ancestry

The exact implementation predecessor is clean branch head `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9` on `feat/issue42-candidate-tar-remediation`. It contains the ADR 0085 terminal proc transition and its final capability-transition assertion. Its parent `cbbb4fb63403519ce3c37bc82211d5964d3e2e01` contains the proc implementation and descends directly from ADR 0085's implementation predecessor `86e6974d7ae2b39fb9ef40a06921db815ba9283f`.

The exact accepted documentation parent for ADR 0086 is current main commit `152d866f5603e09b981e761438bd6febf3035a96`, containing accepted ADR 0085. The accepted commit containing this ADR must be based directly on that exact parent. Implementation must start at exactly `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9` and integrate the accepted ADR 0086 commit by a history-preserving merge before the correction commit. That integration merge must have `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9` as first parent and the accepted ADR 0086 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or starting implementation from the documentation branch is prohibited. Final implementation must descend from both exact parents. Any replacement parent requires another accepted amendment.

### Superseded terminal namespace tuple only

ADR 0085 is superseded only where its final terminal `unshare` creates a user and mount namespace without a PID namespace or fork. After the unchanged complete trusted parent setup, full mount verification, fd-3 closure, and synchronous post-closure descriptor observation, the only successful continuation is one fixed terminal util-linux invocation with this effective shape:

```text
/usr/bin/unshare
  --user --map-user=0 --map-group=0
  --mount --pid --fork
  --mount-proc=/tmp/cogs-native-runtime-root/proc
/usr/bin/python3 -I -c <fixed-final-launcher>
```

The user, mount, and PID namespace flags are supplied together to this one transition. The root map remains exactly one UID row and one GID row `0 0 1`. The fresh mount and PID namespaces are owned by that final child user namespace. `--fork` is mandatory: the fixed launcher runs as PID 1 inside the final PID namespace, and util-linux performs the exact proc mount for that final PID namespace before executing the launcher. The proc target remains the literal existing `/tmp/cogs-native-runtime-root/proc` and covers the unchanged verified read-only parent proc only in the final mount namespace.

No second user or mount transition, separate PID helper, `nsenter`, `setns`, namespace descriptor, named namespace, map helper, subordinate-ID source, caller-selected target, alternate proc mount, external fallback, or reordered mount is permitted. Failure to create any namespace, write either singular map, fork into the final PID namespace, mount proc, or exec the launcher is terminal.

### Exact final PID, map, and proc verification

The fixed final launcher remains trusted workflow text and reads no checkout content. Before remount or chroot it must verify through the newly selected proc superblock:

1. `/proc/self/uid_map` and `/proc/self/gid_map` each contain exactly the canonical root-only row `0 0 1` and no other row.
2. `os.getpid()` is exactly 1, `/proc/self/status` contains exactly one well-formed `NSpid` field, every component is canonical decimal, and its final component is exactly `1`. A missing, duplicate, malformed, empty, or non-PID-1 observation fails.
3. The exact target selects one new proc mount with identity distinct from the captured parent proc mount, root `/`, type and source `proc`, no optional field or `hidepid` policy, the expected initial writable VFS/superblock options, and device identity for that exact target.
4. The complete allowed chroot mount view remains unchanged apart from the expected proc overmount; the verified parent proc is covered only at that target and no outer or host proc alias is reachable in the future chroot.

Only after all four checks succeed may the launcher perform ADR 0085's unchanged single exact remount of that target to `ro,nosuid,nodev,noexec`. It must then reverify the same proc identity and exact read-only VFS and superblock options. The final PID-1 and root-map assertions remain true through this verification. No checked byte runs and no capability is dropped or retained selectively during this bounded setup interval.

### Unchanged terminal drop and checked evidence

After proc reverification, the fixed launcher terminally execs ADR 0085's unchanged chroot, locked-`noroot`, all-zero bounding/inheritable/ambient/permitted/effective capability, NNP, timeout, seccomp, and exact checked-module chain. The in-root launcher independently retains the exact root-only maps, all-five-zero capability sets, empty groups, NNP, seccomp, exact fds 0–2, and no-socket assertions before checked code.

The two checked-in Python files remain byte-identical to predecessor `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9`. Genuine direct `map_files`, production self mapped closure, gzip and zstd child mapped closure, fd-198/fd-4,096 closure, child reaping, descriptor restoration, anonymous evidence, and every other native requirement remain unchanged. A mock, skip, accepted `EPERM`, maps-only substitute, pathname reconstruction, privileged checked route, reduced closure, or capability retention remains failure.

### Outer PID namespace lifecycle and no fallback

ADR 0083's outer PID namespace remains the fixed trusted setup isolation. Its namespace PID 1 performs only the already-authorized trusted setup and then terminally becomes the util-linux parent waiting for the final PID-namespace child. It runs no checked code, mounts no fallback proc, enters no final namespace, and has no successful continuation after reaping that child. When the final child exits, the waiter exits and the outer PID namespace and its mount namespace die. The final child-owned user, PID, and mount namespaces and proc superblock also die with the child process tree. No namespace handle, host mount, helper state, file, service, or other residue remains.

There is exactly one final target and one attempt. `EPERM` or any other failure at namespace creation, map creation, fork, proc mount, PID/map/proc verification, remount, reverification, chroot, capability drop, seccomp, or checked evidence terminates the process tree. It may not retry in the outer PID namespace, use the parent proc, retain `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_CHECKPOINT_RESTORE`, or any other capability, change proc policy, or run checked code before the complete drop.

### Exact files and unchanged highs

Only ADR 0085's existing implementation surfaces remain authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Add the final PID namespace and mandatory fork to the one terminal tuple; make the fixed launcher verify final `NSpid` PID 1 while retaining exact map/proc/remount/reverification/drop ordering. | Retained **386** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact final user/mount/PID/fork/proc tuple, PID-1 proof, unchanged drop, and unchanged genuine mapped-closure evidence. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same terminal tuple, `NSpid` PID-1 verification, outer-waiter lifecycle, and no fallback while retaining all prior sandbox assertions. | Retained **600** gross additions from `18f2644` |

The checked-in Python highs remain 750 and 850, and neither Python file may change. The exact five non-transferable no-rename maxima remain `386 + 750 + 80 + 850 + 600 = 2,666` gross additions from `18f26441b6115091233d0c4cd44ced8f058d014f`. Deletion, movement, replacement, consolidation, generated placement, or removal creates no credit, and compression to fit a high is prohibited.

No production module, runner, schema, package file, lockfile, deterministic fixture, Gitleaks surface, other workflow, or new implementation file may change. No capability, timeout, trigger, event, execution, or numeric-cap change is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove exact ancestry and first/second-parent integration; the unchanged trusted setup through post-closure observation; one terminal combined root-only user/fresh mount/fresh PID/mandatory-fork transition; final child-user-namespace ownership of both final namespaces; literal exact-target `--mount-proc`; final `os.getpid()` and `NSpid` PID 1; exact maps; distinct new proc identity; exact read-only remount and reverification; terminal chroot and all-zero-capability drop; and no early checked code, alternate target, retained capability, fallback, or residue.

Review must byte-compare both checked-in Python files with `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9`, retain the complete genuine mapped-closure and descriptor evidence, and verify that implementation stays within unchanged highs 386/750/80/850/600 and aggregate 2,666. The final implementation head must be clean and separately reviewed. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0085 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The Phase B aggregate remains 3,310; the exact-five-file aggregate remains 2,666; and the conservative global projection remains at most `33,370 <= 34,000`. The 32,000 preferred target and 34,000 hard cap remain unchanged, with at least 630 lines of hard-cap margin. These bounds grant no implementation or execution authority.
