# ADR 0078: Create the checkout descriptor after sudo

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only ADR 0076's outer-runner checkout-descriptor creation and `sudo --close-from=4` handoff after native execution at exact head `e4650ab106fb3d69571ad9a4356c62b3aeb67100` failed at the host sudo close-from policy. The ordinary runner instead passes the already-proved canonical checkout pathname and its captured device/inode/runner-UID/runner-GID decimal identity as inert arguments through permitted default `sudo -n --close-from=3` to one fixed absolute isolated trusted root Python launcher. That launcher authenticates and creates fd 3 after sudo, then terminally execs the retained `setpriv`/`unshare`/trusted-shell chain with an empty environment. ADR 0076's descriptor-backed non-canonical bind, target authentication, fd-3 closure, and terminal chroot protocol are unchanged. Only CI and the two existing TypeScript static companions may change under retained highs; checked-in Python, production, Gitleaks, schema, run, event, acquisition, and AWS boundaries do not change.

## Context

The corrected native workflow reached exact clean implementation head `e4650ab106fb3d69571ad9a4356c62b3aeb67100`, but its fixed `sudo -n --close-from=4` launch failed before `setpriv`. The hosted runner's sudo policy permits the default close boundary at descriptor 3 but does not permit a caller to override that boundary to 4. This is a host policy failure, not evidence from the sandbox or the native test.

ADR 0076 created checkout fd 3 under the ordinary runner identity and required sudo to preserve it by moving the close boundary to 4. Enabling or depending on `closefrom_override`, a sudoers change, `-C 4`, another spelling of close-from 4, a preserved environment, or a broader inherited-descriptor channel is not available and would make the workflow depend on authority it does not have.

The root process immediately after successful default-close sudo can still open the exact canonical checkout: host root exists before the one-ID user-namespace transition and can traverse the runner-owned ancestors. Creating and authenticating fd 3 at that narrow point preserves ADR 0076's one-ID mapping and descriptor-only namespace use without asking sudo to preserve any descriptor at or above 3.

## Decision

### Exact correction ancestry

The exact implementation predecessor is current clean branch head `e4650ab106fb3d69571ad9a4356c62b3aeb67100` on `feat/issue42-candidate-tar-remediation`. It contains the exact native failure classification and descends through the required accepted ADR 0077 integration. If that branch advances before integration, a new ADR or explicit accepted amendment must bind the replacement exact head; an unrecorded moving-head substitution is prohibited.

Implementation must start at exactly `e4650ab106fb3d69571ad9a4356c62b3aeb67100` and integrate the exact accepted commit containing this ADR by a history-preserving merge before the correction commit. That integration merge must have `e4650ab106fb3d69571ad9a4356c62b3aeb67100` as first parent and the accepted ADR 0078 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from the documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Outer pathname and inert identity handoff

The retained exact-head, same-repository, canonical-checkout, ordinary runner UID/GID, anonymous expected/output, and clean-tree checks remain mandatory. The ordinary outer isolated Python runner must not open, normalize, retain, or pass the checkout descriptor. Before opening retained evidence, it must strictly require the supplied checkout pathname to be absolute and canonical, obtain a no-follow stat of that exact pathname, require a directory owned by the captured nonzero ordinary runner UID/GID, and capture its exact device, inode, UID, and GID. The pathname and those four values are passed as arguments; each identity value must use its canonical unsigned decimal representation. They confer no authority before the trusted root launcher reauthenticates them.

The one direct subprocess launch retains `stdin=subprocess.DEVNULL`, the anonymous output descriptor as `stdout`, `stderr=subprocess.STDOUT`, `close_fds=True`, an empty supplied environment, and no `preexec_fn`. It must have no `pass_fds` argument and no inheritable descriptor at or above 3. Sudo must be exactly `/usr/bin/sudo`, `-n`, `--close-from=3`, followed directly by the fixed absolute `/usr/bin/python3`, `-I`, `-c`, and the literal trusted root descriptor-launcher source. No shell, `env`, caller-selected executable, source file, standard-input program, module, site initialization, or checkout import may run between sudo and that isolated launcher.

`--close-from=3` expresses sudo's permitted default boundary and closes every inherited descriptor at or above 3. The workflow must not use `--close-from=4`, `-C 4`, another close-from value, `closefrom_override`, sudoers mutation, `--preserve-env`, a general descriptor allowlist, or any alternate preservation mechanism. Fd 0 is `/dev/null`, and fd 1 and fd 2 are subprocess-created references to the retained anonymous output open description; no outer evidence, runner-temp, private-parent, or checkout descriptor survives as descriptor 3 or higher.

### Fixed trusted root descriptor launcher

The literal `/usr/bin/python3 -I -c` launcher is trusted workflow source, not checked-out Python. It must fail closed unless its exact argument count and order are fixed; the checkout pathname is absolute and byte-for-byte canonical; each of device, inode, UID, and GID is nonempty canonical unsigned decimal; the expected UID/GID are nonzero and equal the captured runner identity; and the test path is one of the two exact native companions. It must use no environment value, current-directory module, source import, dynamic program, caller-selected option, pathname recovery, or fallback.

Only after sudo, the launcher opens the exact pathname once with `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. It compares `fstat` with both the four captured values and a fresh no-follow stat of the same exact canonical pathname, and requires the exact directory type and captured nonzero owner. A symlink, non-directory, noncanonical pathname, malformed decimal, identity change, owner change, open flag failure, unavailable `O_PATH`, alternate worktree, or extra argument fails before `setpriv`.

The launcher normalizes that authenticated reference to fd 3 with `os.dup2(checkout_fd, 3, inheritable=True)` and closes the original when it is a distinct alias. If the authenticated open returned 3, it explicitly makes fd 3 inheritable. It then reauthenticates fd 3, closes every alias or unexpected descriptor above 3, and proves the live descriptor set is exactly 0, 1, 2, and 3, with fd 3 the sole checkout reference and `FD_CLOEXEC` clear. Failure to close or prove any descriptor is terminal. No observer, child, shell, or checked-out code assists this root-launcher proof.

The launcher's only successful terminal action is exact `os.execve` of `/usr/bin/setpriv` with an empty environment. Its fixed argv retains host real/effective/saved UID/GID 0, performs `--reuid 0 --regid 0 --clear-groups --no-new-privs`, then invokes exact `/usr/bin/unshare --user --map-users=0:0:1 --map-groups=0:0:1 --net --pid --fork --mount`, and then the exact trusted `/usr/bin/env -i /usr/bin/bash --noprofile --norc -c` sandbox. The shell receives only the captured device, inode, UID, GID, and exact test path after its fixed script; it does not receive or need the checkout pathname. There is no return, subprocess wrapper, alternate exec, retry, or fallback.

Fd 3 is therefore created only after sudo has applied its default close-from-3 boundary, and its explicitly inheritable state preserves it through the subsequent exact `setpriv`, `unshare`, `env -i`, and trusted-shell execs. No later command broadens descriptor inheritance.

### Retained ADR 0076 namespace protocol

Once the trusted shell starts, every non-conflicting ADR 0076 rule remains byte-for-byte and semantically unchanged. The first synchronous trusted observer still proves namespace PID 1 has exactly fds 0–3, authenticates fd 3 and its overflow-mapped checkout ownership, and proves the exact one-ID maps. The checkout bind remains exactly:

```sh
/usr/bin/mount --no-canonicalize --bind /proc/self/fd/3 "$root/src"
```

Both target authentications, the read-only `nosuid,nodev,noexec` remount, child reaping, `exec 3>&-`, second exact-fds-0–2 observer, and immediate terminal chroot exec remain unchanged. The checkout pathname is not supplied to the shell and cannot be used there. Default/canonicalizing bind, path reconstruction, source reopening, fallback, checkout copying, ancestor traversal, identity-map expansion, extra group, mode/ACL change, capability expansion, or fd inheritance into checked code remains prohibited.

### Exact authorized files and retained highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Replace only ADR 0076's outer fd-3 open/pass and sudo close-from-4 prefix with the exact inert pathname/identity handoff and trusted post-sudo fd-3 launcher. | Retained **360** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact post-sudo launcher lifecycle and reject sudo override, outer descriptor passing, source import, environment, and alternate-exec variants. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact launcher-to-existing-bind lifecycle and retained mount/closure boundary. | Retained **600** gross additions from `18f2644` |

The three highs are non-transferable no-rename gross additions from exact `18f26441b6115091233d0c4cd44ced8f058d014f`. ADR 0077's checked-in Python highs of 750 and 850 and exact-five-file aggregate high of 2,640 remain unchanged. Deletion, movement, replacement, consolidation, or removal creates no credit. Ordinary readable state and failure transitions remain mandatory.

No checked-in Python file, production module, production runner, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks rule/configuration, workflow other than `.github/workflows/ci.yml`, or new file may change. No behavior beyond this post-sudo descriptor creation is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove the exact canonical pathname and canonical decimal argument validation; no outer checkout open, fd normalization, `pass_fds`, or inherited descriptor at or above 3; exact `sudo -n --close-from=3 /usr/bin/python3 -I -c`; no close-from override, environment preservation, source import, shell, or dynamic executable before the trusted launcher; exact post-sudo `O_PATH|O_DIRECTORY|O_NOFOLLOW` open and pathname/fstat/captured-runner identity equality; inheritable fd-3 normalization, alias closure, exact 0–3 proof, and empty-environment terminal `os.execve`; and the exact root-retaining `setpriv`, one-ID `unshare`, `env -i`, and trusted-shell chain without the checkout pathname.

Review must separately verify ADR 0076's unchanged namespace observer, no-canonical bind, target identity, read-only remount, fd-3 closure, second observer, and immediate chroot boundaries. It must reject outer `pass_fds`, `--close-from=4`, `-C`, any close-from value other than 3, sudo policy changes, inherited environment, checked-out/root source file, stdin program, module import, alternate interpreter, dynamic command, descriptor scan that silently tolerates an open alias, pathname use in the shell, default bind, fallback, and map/group/mode/capability expansion.

The final implementation commit must descend through the required first/second-parent integration, retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 360/80/600 and aggregate 2,640. Checked-in Python, production, schema, Gitleaks bytes, and every unauthorized surface must be unchanged from the predecessor. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0077 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. Production caps and the Phase B aggregate high remain unchanged. The conservative global projection remains `33,344 < 34,000`; the 32,000 preferred target, 34,000 hard cap, and 656-line margin remain unchanged and grant no implementation authority.
