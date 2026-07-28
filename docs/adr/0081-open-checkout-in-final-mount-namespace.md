# ADR 0081: Open the checkout descriptor in the final mount namespace

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only ADR 0078's timing for opening and normalizing the checkout descriptor after native execution at exact head `bed2d05b402e6aa7c5ebcd919b607c254fe5fdb7` failed with the fixed `bind-einval` classification. Ordinary `sudo -n --close-from=3` invokes a fixed trusted outer launcher with no checkout descriptor. That launcher validates the exact canonical pathname and pre-sudo identity, then terminally enters the retained user/network/PID/mount namespaces. A fixed embedded child launcher running inside the final mount namespace opens and reauthenticates the checkout, normalizes only fd 3 as inheritable, closes every alias, proves the exact descriptor state, and terminally execs the trusted sandbox. ADR 0079's observers, ADR 0080's direct bind, and all read-only, closure, chroot, capability, seccomp, and terminal checks remain unchanged. Only the CI excluded high rises from 360 to 365 and the exact five-file aggregate from 2,640 to 2,645 for the readable two-stage transition; TypeScript highs remain 80 and 600. No run, event, cloud, or AWS authority changes.

## Context

The accepted ADR 0080 implementation reached exact clean head `bed2d05b402e6aa7c5ebcd919b607c254fe5fdb7`. Native execution passed the permitted sudo boundary, checkout identity checks, fd-3 normalization, namespace maps, and trusted descriptor observation. The exact direct libc `mount(2)` then failed with `EINVAL`, recorded by the fixed `bind-einval` classification.

Because ADR 0080 removed the util-linux frontend and made one exact `MS_BIND` syscall, this result is evidence about the descriptor source rather than command-line canonicalization. Fd 3 was opened before `unshare` created the final mount namespace. Its `O_PATH` reference therefore retained a source path rooted in the outer mount namespace, and Linux rejected that cross-mount-namespace source when namespace root attempted the bind. Retrying, replacing `O_PATH`, reopening through `/proc/self/fd/3`, recovering a pathname from the descriptor, or falling back to an external mount would weaken the fixed boundary and would not correct the source namespace.

The canonical checkout pathname and exact device/inode/ordinary-runner ownership are already captured before sudo. The narrow correction is to keep those values inert through sudo and namespace creation, then perform the one non-reading `O_PATH` open from a fixed trusted launcher after the final mount namespace exists. This places both the descriptor source and bind target in the same mount namespace while preserving the exact one-ID mapping and every later sandbox boundary.

## Decision

### Exact correction ancestry

The exact implementation predecessor is current clean branch head `bed2d05b402e6aa7c5ebcd919b607c254fe5fdb7` on `feat/issue42-candidate-tar-remediation`. It contains the exact native `bind-einval` result and descends through the required accepted ADR 0080 integration. If that implementation branch advances before integration, a new ADR or explicit accepted amendment must bind the replacement exact head; an unrecorded moving-head substitution is prohibited.

Implementation must start at exactly `bed2d05b402e6aa7c5ebcd919b607c254fe5fdb7` and integrate the exact accepted commit containing this ADR by a history-preserving merge before the correction commit. That integration merge must have `bed2d05b402e6aa7c5ebcd919b607c254fe5fdb7` as first parent and the accepted ADR 0081 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from the documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Narrow supersession of ADR 0078 timing

ADR 0081 supersedes only ADR 0078's requirement that the first trusted post-sudo launcher open, normalize, authenticate, and retain checkout fd 3 before entering the user/network/PID/mount namespaces. It also supersedes the corresponding placement of ADR 0078's exact launcher descriptor-table proof. The open, normalization, and proof move together to the fixed child launcher inside the final mount namespace.

ADR 0078's ordinary-runner capture of the exact canonical checkout pathname and its no-follow device, inode, nonzero runner UID, and nonzero runner GID remains mandatory. Its anonymous evidence lifecycle, empty supplied environment, `stdin=DEVNULL`, output-only fd 1/2, `close_fds=True`, no `pass_fds`, no `preexec_fn`, and exact `/usr/bin/sudo -n --close-from=3 /usr/bin/python3 -I -c` prefix remain unchanged. No checkout, evidence, private-parent, runner-temp, or other descriptor at or above 3 crosses sudo.

The post-sudo program remains one fixed absolute isolated trusted outer launcher embedded literally in the workflow. It accepts only the exact ordered canonical pathname, four canonical unsigned decimal identity values, exact allowed test path, and fixed embedded child/sandbox text. It derives no authority from the environment, current directory, standard input, checked-out source, module path, caller-selected program, or dynamic option.

Before namespace creation, the outer launcher requires the checkout pathname to be absolute and byte-for-byte canonical; the captured device/inode/UID/GID to be canonical, in range, and exactly the retained pre-sudo values; the UID/GID to be the same nonzero ordinary runner identity; and a fresh no-follow stat of the exact pathname to identify that exact directory and owner. It also fails if any descriptor at or above 3 survived the sudo boundary. It does not open, duplicate, normalize, or retain the checkout and does not read any checkout content.

Its only successful terminal action is exact empty-environment `os.execve` of the retained `/usr/bin/setpriv` and `/usr/bin/unshare` chain. The chain retains host real/effective/saved UID/GID 0, clears supplementary groups, sets `no_new_privs`, creates the exact one-ID user mapping `0:0:1`, and creates the fresh network, PID-with-fork, and mount namespaces. Instead of entering Bash directly, `unshare` invokes exact `/usr/bin/python3 -I -c` with the fixed embedded child launcher. No shell, checked-out code, source import, alternate executable, retry, or fallback runs between the outer and child launchers.

### Final-mount-namespace child launcher

The embedded child launcher starts only after all retained `unshare` namespace operations have succeeded and therefore runs as namespace PID 1 in the final user, network, PID, and mount namespaces. Its source, interpreter, argv shape, checkout pathname, expected identity, test selector, and terminal trusted-sandbox text are fixed by the outer launcher; none is recovered from the environment, current directory, `/proc` symlink text, or checked-out data.

The child repeats exact argument-count, canonical-decimal, canonical-pathname, allowed-test, one-ID `uid_map`/`gid_map`, and nonzero captured runner-identity checks. It opens the exact checkout pathname once with `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. Before normalization it compares the new descriptor with fresh no-follow pathname stats and requires stable exact device, inode, and directory identity. It reauthenticates the captured pre-sudo ownership under the exact one-ID map: the expected host UID/GID remain the exact captured nonzero ordinary-runner values, while both the descriptor and pathname must expose the kernel overflow UID/GID that exactly represent those unmapped owners in this user namespace. A changed path, object, owner representation, map, type, flag, or identity fails closed.

The child normalizes that authenticated reference to fd 3 with `os.dup2(..., 3, inheritable=True)` and immediately closes the original when it is a distinct alias. If the open returned fd 3, it explicitly makes fd 3 inheritable. It closes every unexpected descriptor or alias above 3 and then proves the live descriptor set is exactly 0, 1, 2, and 3; fd 3 is the sole checkout reference; fd 3 still has the authenticated identity and required `O_PATH|O_DIRECTORY|O_NOFOLLOW` state; and `FD_CLOEXEC` is clear only for that intended inherited reference. Missing state, an alias, an unclosed descriptor, instability, or an allow-on-error scan is terminal.

The child's only successful terminal action is exact empty-environment `os.execve` of the retained trusted `/usr/bin/env -i /usr/bin/bash --noprofile --norc -c` sandbox with only the exact identity values and allowed test path after the fixed script. The checkout pathname is not supplied to Bash and cannot be used by later setup. There is no return, subprocess wrapper, additional open, alternate exec, retry, or fallback.

This transition opens no checkout file and reads, imports, or executes no checked-out byte. Checked-out code remains unreachable as executable behavior until the unchanged trusted sandbox has completed the mount/chroot lifecycle, terminally entered chroot, removed capabilities, installed and verified the retained seccomp filter, and executed the exact isolated test companion. No checked-out code may run before capability removal, chroot, and seccomp.

### Unchanged observer, mount, and terminal lifecycle

Every non-conflicting ADR 0079 and ADR 0080 requirement remains exact. The first synchronous independent observer still inspects quiescent trusted Bash namespace PID 1, proves the one-ID maps, authenticates fd 3 as the sole high descriptor without `FD_CLOEXEC`, and rejects socket, namespace, checkout-alias, or other unsafe setup descriptors. Moving the authenticated open into the preceding final-namespace child launcher does not weaken or replace that independent proof.

The initial checkout bind remains the exact fixed trusted namespace-root standard-library Python direct libc call from ADR 0080: exact source `b"/proc/self/fd/3"`, exact target `b"/tmp/cogs-native-runtime-root/src"`, null filesystem type, exactly `MS_BIND=4096`, null data, one call, immediate errno capture, and success only on return zero. Fd 3 is still authenticated before and after the call. No canonicalization, readlink, realpath, source reopen, pathname recovery, external descriptor-bind process, second attempt, retry, or fallback is authorized.

The unchanged `rw` target verifier, exact trusted read-only `ro,nosuid,nodev,noexec` bind remount, unchanged `ro` reverification, mount allowlist, old-root exclusion, child reaping, parent fd-3 closure, second independent descriptor observer, and immediate terminal chroot exec remain in the same order. Every tolerated trusted-shell high descriptor remains close-on-exec and is closed by the terminal exec. The in-root launcher and selected test still independently prove exact inherited fds 0–2 and no inherited socket before opening their own bounded evidence. No observer, direct-mount, target-authentication, read-only, descriptor-closure, capability, seccomp, or terminal check is relaxed.

### Exact authorized files and revised highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Split only ADR 0078's trusted post-sudo launcher into the fixed no-checkout-fd outer validator/namespace transition and fixed final-mount-namespace child open/normalize/terminal-sandbox transition. | **365** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact two-stage timing, same-namespace open, identity/alias/fd proof, and no checked-out-code boundary; reject pre-namespace open and alternate launch paths. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact two-stage transition while retaining every observer, mount, read-only, closure, and terminal assertion. | Retained **600** gross additions from `18f2644` |

The checked-in Python highs remain 750 and 850. The five non-transferable no-rename gross-addition maxima from exact `18f26441b6115091233d0c4cd44ced8f058d014f` therefore sum exactly to the revised aggregate: `365 + 750 + 80 + 850 + 600 = 2,645`. Deletion, movement, replacement, consolidation, generated placement, or removal creates no credit. The five-line increase exists only so the two trusted launch stages and their failure transitions remain ordinarily readable; it grants no additional behavior or surface.

No checked-in Python file, production module, production runner, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new file may change. No behavior beyond the corrected checkout-open timing and corresponding static assertions is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove: exact ancestry and first/second-parent integration; no outer or sudo-crossing checkout fd; exact close-from-3 launch to fixed isolated outer source; canonical pre-sudo identity and pathname reauthentication before namespace creation; no outer checkout open; empty-environment terminal `setpriv`/one-ID `unshare` transition; fixed isolated child source running inside the final mount namespace; one exact `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` checkout open there; exact fd/path/device/inode/type and namespace-translated nonroot-owner reauthentication; sole inheritable fd-3 normalization; alias and unexpected-fd closure; exact fds 0–3; and terminal trusted-sandbox exec without the checkout pathname.

Review must reject an open before the final mount namespace, a descriptor passed through sudo or `unshare`, multiple checkout opens, a non-`O_PATH` authority, a changed map or owner, pathname recovery, environment or current-directory authority, checked-out import, shell before the child, dynamic source/program/target, extra inheritable fd, tolerated alias, subprocess handoff, fallback, or checked-out execution before chroot/capability removal/seccomp. It must separately prove ADR 0079's observer lifecycle, ADR 0080's one direct bind, both target verifications, exact read-only remount, fd-3 closure, second observer, immediate chroot exec, all-zero capability sets, inherited seccomp, and in-root exact-fd/no-socket boundary are unchanged.

The final implementation commit must descend through the required first/second-parent integration, retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 365/750/80/850/600 and aggregate 2,645. Production, schema, Gitleaks bytes, and every unauthorized surface must be unchanged from the predecessor. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0080 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The Phase B aggregate high remains 3,310. The conservative global projection rises only five lines from 33,344 to at most `33,349 < 34,000`; the 32,000 preferred target and 34,000 hard cap remain unchanged, with at least 651 lines of hard-cap margin. Those numeric bounds grant no implementation or execution authority.
