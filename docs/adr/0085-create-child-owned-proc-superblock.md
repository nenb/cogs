# ADR 0085: Create a child-user-namespace-owned proc superblock

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct the native runtime preflight after execution at exact clean head `86e6974d7ae2b39fb9ef40a06921db815ba9283f` reached fixed phase `mapped-files`. That result proved that the read-only proc superblock mounted by the trusted parent in the initial user namespace denies the retained `/proc/<pid>/map_files` operation after the child has entered its root-only user namespace and dropped all capabilities. After complete parent mount verification, fd-3 closure, and the post-closure descriptor observation, the trusted process now terminally creates the exact root-only user namespace together with a fresh mount namespace owned by it and uses util-linux `--mount-proc` at the exact existing chroot proc target. A fixed trusted launcher immediately verifies the new proc and user-namespace identity, remounts that exact proc target `ro,nosuid,nodev,noexec`, re-verifies it, and terminally execs the retained chroot, locked-`noroot`, all-zero-capability, NNP, timeout, seccomp, and checked-module chain. The old read-only parent proc is only covered in the child mount namespace; the parent mount namespace dies without residue. No checked code runs before the complete drop, no fallback exists, and the native workload retains its exact genuine `map_files` and mapped-closure evidence. The CI high rises 376→386, the exact-five-file aggregate rises 2,656→2,666, and the conservative global projection rises to at most `33,370 <= 34,000`. All other caps and every run, cloud, and AWS boundary remain unchanged.

## Context

ADR 0084 was integrated history-preservingly and its exact soft-descriptor-limit transition succeeded. Native execution at exact clean implementation head `86e6974d7ae2b39fb9ef40a06921db815ba9283f` then passed the fixed descriptor limit, checkout authentication, direct descriptor bind, read-only mount verification, fd closure, late root-only user namespace, chroot, locked `noroot`, all-five-zero capability, NNP, and seccomp envelope checks. The checked native process also created exact inheritable fds 198 and 4,096 and completed the fixed host-closure setup through the parser closure.

The checked workload then isolated proc access in ordered phases. It opened its own proc directory, read `maps`, authenticated `exe`, and attempted to open each genuine executable nonzero-inode mapping through `map_files/<address-range>`. Execution failed at the fixed terminal report `native-process-failure:mapped-files`. It had not yet called the production `_mapped_closure` wrapper, so the direct operation localizes the defect independently of production wrapper behavior, archive-child timing, descriptor cleanup, or compression.

The existing `/tmp/cogs-native-runtime-root/proc` was created and verified while the trusted mount setup still ran as host root in the initial user namespace. It was correctly mounted and verified read-only with `nosuid,nodev,noexec`, then inherited across ADR 0083's late user-namespace transition. Its proc superblock therefore retained the parent user-namespace ownership semantics. After the terminal `setpriv` transition, the checked process had UID/GID 0 only in its one-row child user namespace and had `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and `CapAmb` all zero. The parent-owned proc permission boundary consequently denied the genuine `map_files` open even for the retained self-observation case.

Making proc writable, retaining a capability, moving checked code before the drop, replacing `map_files` with pathname reads, or weakening mapped-closure evidence would invalidate the native qualification boundary. The narrow correction is instead to create the proc superblock only after entering the child user namespace and in a new mount namespace owned by that user namespace, harden it read-only before chroot, and retain the all-zero-capability workload unchanged.

## Decision

### Exact correction ancestry

The exact implementation predecessor is clean branch head `86e6974d7ae2b39fb9ef40a06921db815ba9283f` on `feat/issue42-candidate-tar-remediation`. It contains the direct ordered `mapped-proc`, `mapped-maps`, `mapped-exe`, and `mapped-files` isolation and descends from merge `c990592a7e311f2500201f9db7b881c068e6ddd8`, whose first parent is ADR 0084 implementation predecessor `7282309a240b1a9314e0bcd57e2b8763415a492c` and whose second parent is accepted main commit `b28ef9779a6f307ebaaf026d77256a0569980714`, containing ADR 0084.

The exact accepted documentation parent for ADR 0085 is that same current main commit, `b28ef9779a6f307ebaaf026d77256a0569980714`. The accepted commit containing this ADR must be based directly on that exact parent. Implementation must start at exactly `86e6974d7ae2b39fb9ef40a06921db815ba9283f` and integrate the exact accepted ADR 0085 commit by a history-preserving merge before the correction commit. That integration merge must have `86e6974d7ae2b39fb9ef40a06921db815ba9283f` as first parent and the accepted ADR 0085 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from the documentation branch is prohibited. Final implementation head must descend from both exact parents. If either line advances before integration, an explicit accepted amendment must bind the replacement; a moving-head substitution is prohibited.

### Retained parent setup and read-only proc

The fixed outer sudo, root/NNP transition, and first fresh network/PID/mount namespace remain unchanged. The fixed embedded final-parent-mount-namespace child remains trusted host root in the initial user namespace. Before opening or executing checked code, it retains ADR 0084's exact soft-limit normalization, opens and authenticates the checkout once, normalizes sole inheritable fd 3, terminally enters the trusted sandbox, completes the direct descriptor bind, remounts the checkout read-only with `nosuid,nodev,noexec`, and re-verifies it.

The parent trusted sandbox must continue to mount proc exactly once at the existing literal target `/tmp/cogs-native-runtime-root/proc` with `ro,nosuid,nodev,noexec`. The complete existing parent mount verifier must still authenticate that proc mount's target, parent, root, filesystem type, source, VFS options, read-only superblock options, optional fields, and device identity as part of the complete allowlisted chroot view. It must continue to reject `rw`, every `hidepid` form, an extra superblock option, an old mount alias, a duplicate or missing expected parent mount, or any unverified mount beneath the future root.

Only after the complete parent mount verification succeeds may fd 3 close and the retained synchronous post-closure observer run. That observer must still prove fd 3 absent, all remaining trusted-shell high descriptors close-on-exec and safe, the parent remains in the initial user namespace, and every observer child has been reaped. The checkout pathname, descriptor, or content cannot reach the later proc transition. No checked-out byte may be opened, scanned, read, imported, parsed, interpreted, resolved as a module, or executed during this parent phase.

The parent proc mount is not made writable, unmounted, or replaced in this namespace. It remains a verified read-only lower mount until the terminal transition. The retained outer `unshare --fork` waiter may remain only to reap namespace PID 1; it performs no mount operation and cannot enter the child mount namespace. No setup or checked process returns to the parent mount namespace.

### Exact terminal user-and-mount-namespace transition

After full parent mount verification, fd-3 closure, and post-closure observation, namespace PID 1's only successful continuation is terminal exec through fixed util-linux `unshare`. That invocation creates, together in one transition:

- exactly one new user namespace with singular fixed `--map-user=0` and `--map-group=0`, producing only UID and GID rows `0 0 1`;
- exactly one fresh mount namespace, created after and owned by that new user namespace; and
- exactly one new proc mount through util-linux `--mount-proc` at the literal existing target `/tmp/cogs-native-runtime-root/proc`.

The effective fixed shape is:

```text
/usr/bin/unshare
  --user --map-user=0 --map-group=0
  --mount --mount-proc=/tmp/cogs-native-runtime-root/proc
/usr/bin/python3 -I -c <fixed-child-proc-launcher>
```

The existing isolated network and PID namespaces are retained; this second invocation does not create or join another network or PID namespace and does not fork. It has no plural mapping option, owner-derived mapping, count or range, subordinate-ID source, `newuidmap`, `newgidmap`, direct proc-map writer, namespace file, helper selection, caller-selected proc target, alternate mount target, or alternate executable. The exact literal `--mount-proc` target already exists as the verified mode-0755 directory beneath the fresh chroot tmpfs. A missing target, failed user or mount namespace creation, failed map, failed proc mount, or unexpected option behavior is terminal.

Creating the user and mount namespaces in one fixed transition is binding. Creating the mount namespace before the user namespace, retaining the parent mount namespace, mounting proc from the parent user namespace, bind-mounting another proc, or creating the proc superblock before the root-only user namespace is not equivalent.

### Immediate child proc verification and hardening

The program reached by `unshare` is fixed trusted workflow text. It runs only with transitional namespace-root capabilities in the new child user namespace and before chroot. It accepts no checkout pathname, reads no checkout content, imports no checkout module, and can select no program. Its first actions are bounded verification of the exact new proc mount and the namespace transition through the literal target, not ambient host proc paths.

The launcher must establish all of the following before any remount or later exec:

1. The current UID and GID maps observed through the new proc are each exactly one canonical newline-terminated row `0 0 1`, with no broad, owner, subordinate, additional, or malformed row.
2. The new proc exposes the current namespace PID-1 process and its current user and mount namespace identities, rather than a host or foreign PID view. The observed user namespace is the new root-only namespace, and the mount namespace is distinct from the verified parent mount namespace.
3. The visible mount selected by opening the exact proc target is the new top proc mount created by `--mount-proc`, with root `/`, filesystem type `proc`, fixed proc source, no propagation/optional field, no `hidepid` or other policy option, and identity distinct from the captured parent proc mount.
4. The inherited parent proc remains the already-verified read-only lower mount and is covered only at this exact target in the child mount namespace. It is not selected by an exact-target descriptor and is not reachable through another path in the future chroot.
5. The complete chroot mount allowlist remains unchanged apart from this one expected proc overmount. No checkout, tool, library, device, tmpfs, old-root, or source identity changes across the transition.

The child mount may initially be writable only for the bounded interval inherently required to create and harden it. Immediately after the first verification, the fixed launcher invokes the fixed absolute mount utility once to remount the exact literal `/tmp/cogs-native-runtime-root/proc` with `ro,nosuid,nodev,noexec`. It then repeats the exact-target verification and requires the same selected child proc identity, exact root/type/source/device/user-namespace semantics, no optional or `hidepid` policy, VFS options exactly `ro,nosuid,nodev,noexec,relatime`, and superblock options exactly `ro`. The lower parent proc must remain covered and unchanged. A different mount, target, device, namespace, map, option set, or identity is terminal.

No checked code, `/src` module, hook, configuration, helper, or caller-selected byte runs between namespace creation and the completed post-remount verification. The transitional capabilities are used only to verify and harden this one child-owned proc mount. They may not mount another path, make any mount writable, alter checkout metadata or content, retain a namespace handle, or be passed to the checked process.

### Terminal drop and checked-code boundary

After successful post-remount verification, the fixed child proc launcher has only one successful action: terminal `execve` through the retained exact sequence:

```text
/usr/sbin/chroot /tmp/cogs-native-runtime-root
/usr/bin/setpriv
  --securebits +noroot,+noroot_locked
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  --reuid=0 --regid=0 --keep-groups --no-new-privs
/usr/bin/timeout --signal=KILL 240
/usr/bin/python3 -I -B -c <literal-seccomp-launcher>
```

The already-cleared supplementary-group invariant is retained. Chroot resets root and cwd to `/`; the parent old-root view is absent; and the newly hardened child proc becomes exact `/proc`. `setpriv` locks `noroot`, empties bounding, inheritable, and ambient capabilities, retains NNP, and causes permitted/effective capabilities to become zero. The literal trusted seccomp launcher independently verifies real/effective/saved UID/GID 0, empty groups, exact one-row `0 0 1` maps through the new proc, all five capability sets zero, NNP one, exact inherited fds 0–2, and seccomp mode before and after installing the unchanged filter. It then terminally execs only the exact selected checked Python module with the retained fixed environment.

Checked code therefore first runs only after chroot, child-proc read-only hardening and reverification, locked `noroot`, all-zero capabilities, NNP, timeout, and seccomp. It receives no transitional capability, fd 3, namespace descriptor, old proc path, old-root path, host checkout pathname, mount helper, or fallback route.

### Retained genuine map-files and closure evidence

The bytes of both checked-in Python files at predecessor `86e6974d7ae2b39fb9ef40a06921db815ba9283f` are unchanged by this correction. In particular, `test/aws-stage2-completion-kata-process.py` must retain the ordered direct phases that:

- open the current process proc directory;
- read the genuine `maps` file and authenticate `exe`;
- open `map_files/<address-range>` for each executable nonzero-inode mapping and close every resulting descriptor; and
- only after that independent isolation call the genuine production `_mapped_closure` against the current process and its exact closure.

The retained archive cases must then run genuine zstd and gzip children, gate each child after loader mapping and before archive input, invoke the same production mapped-closure path, prove inherited fds 198 and 4,096 absent, close every proc/maps/map-files descriptor, reap every child, and restore the parent descriptor baseline. The map-files proof runs after all five capability sets are zero. A privileged checked route, maps-only or `exe`-only substitute, pathname reconstruction, copied closure, mock, skip, accepted `EPERM`, reduced mapping set, root fallback, no-map-files branch, or descriptor-leak uncertainty is failure.

### No fallback and zero residue

There is one transition and one proc target. Failure before `unshare`, during combined namespace creation, during `--mount-proc`, during either child verification, during the exact remount, during terminal exec, or in the checked evidence exits the namespace process tree. It may not retry with the parent proc, remount the old proc, retain `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_CHECKPOINT_RESTORE`, or any other capability, run checked code as transitional namespace root, change proc policy, add `hidepid`, use host proc, create a named namespace handle, or select an alternate test.

The new proc overmount exists only in the fresh child mount namespace. The verified read-only parent proc is covered there and remains unchanged in the parent mount namespace. The retained outer waiter only reaps namespace PID 1 and exits; it retains no namespace descriptor, performs no mount operation, and has no successful continuation. The parent mount namespace then dies. On success or failure, the child process tree exits, its child user and mount namespaces and proc overmount die, and no host mount, named evidence, checkout mutation, helper state, service, file, or other residue remains. No cleanup command outside the retained descriptor-close and process-reaping lifecycle is required or authorized.

### Exact authorized files and revised highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | In the fixed trusted sandbox only, replace the direct late-userns-to-chroot edge with the exact combined root-only user/fresh child-owned mount namespace and literal util-linux `--mount-proc` transition; add the fixed immediate child proc identity verification, exact read-only remount, reverification, and terminal exec to the unchanged chroot/drop/seccomp chain. | **386** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact terminal combined transition, child-owned proc verification/hardening order, unchanged zero-capability `map_files` workload, no checked-code-before-drop boundary, and no fallback or residue. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same complete parent verification, fd closure, exact proc overmount and terminal drop lifecycle while retaining every descriptor, mount, chroot, capability, seccomp, and anonymous-evidence assertion. | Retained **600** gross additions from `18f2644` |

The CI maximum rises only from 376 to 386 so the exact namespace/proc identity checks, remount, reverification, and terminal transition remain ordinarily readable. The checked-in Python highs remain 750 and 850, and neither checked-in Python file may change from the exact predecessor. The five non-transferable no-rename gross-addition maxima from exact `18f26441b6115091233d0c4cd44ced8f058d014f` are therefore `386 + 750 + 80 + 850 + 600 = 2,666`. Deletion, movement, replacement, consolidation, generated placement, or removal creates no credit. Compression to fit a high is prohibited.

No production module, production runner, checked-in Python file, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new implementation file may change. No behavior beyond the exact child-user-namespace-owned proc correction and its directly dependent static assertions is authorized. All other per-file and aggregate caps remain unchanged.

## Evidence and gates

Portable static companions and final hostile review must prove exact ancestry and first/second-parent integration; complete verification of the unchanged read-only parent proc and full parent mount view; fd-3 closure and synchronous post-closure observation before the transition; exact singular root map; a fresh mount namespace owned by the child user namespace; literal util-linux `--mount-proc` at the exact existing chroot target; and no second PID/network namespace, mapping helper, alternate target, or fallback.

Review must separately prove that the fixed trusted child launcher is reached directly, reads no checkout content, verifies exact child proc/current-user/current-mount identity before mutation, distinguishes the selected child proc from the covered verified parent proc, remounts only that selected target exactly `ro,nosuid,nodev,noexec`, re-verifies exact options and identity, and terminally execs chroot. The complete locked-`noroot`, empty capability, NNP, timeout, seccomp, exact-exec, inherited-fd, and no-socket assertions must remain after that transition and before checked code.

Review must byte-compare both checked-in Python files with predecessor `86e6974d7ae2b39fb9ef40a06921db815ba9283f` and prove the direct `mapped-files` isolation, production self mapped closure, both genuine archive-child mapped closures, exact fd-4,096 closure, complete proc descriptor closure, child reaping, and baseline restoration remain mandatory after zero capabilities. It must reject retaining capabilities, writable proc after setup, remounting or using parent proc, early checked code, `maps`/`exe` substitution, pathname reconstruction, mock, skip, retry, alternate target, helper, host mutation, or namespace residue.

The final implementation commit must retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 386/750/80/850/600 and aggregate 2,666. Production, checked-in Python, schema, Gitleaks bytes, and every unauthorized surface must be unchanged from predecessor `86e6974d7ae2b39fb9ef40a06921db815ba9283f`. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0084 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The Phase B aggregate high remains 3,310. The conservative global projection rises only ten lines from 33,360 to at most `33,370 <= 34,000`; the 32,000 preferred target and 34,000 hard cap remain unchanged, with at least 630 lines of hard-cap margin. Those numeric bounds grant no implementation or execution authority.
