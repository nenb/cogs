# ADR 0080: Use a direct libc descriptor bind

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only ADR 0076's fixed external-mount wrapper for the checkout descriptor after native execution at exact head `3dd2b0ecb1d787b7d6e21b30fc0c4470de47ee99` failed at `mount-fd3` with exit 32. Fixed trusted namespace-root standard-library Python uses `ctypes` to call libc `mount(2)` directly with exact source `b"/proc/self/fd/3"`, exact target `b"/tmp/cogs-native-runtime-root/src"`, null filesystem type, exactly `MS_BIND` (`4096`) as flags, and null data. The wrapper authenticates fd 3 before and after the successful call, and the existing target verifier, trusted read-only remount, and second target verification remain unchanged. Only `.github/workflows/ci.yml` and the two existing TypeScript static companions may change under retained highs 360/80/600. No behavior elsewhere, run/event authority, cloud boundary, or AWS boundary changes.

## Context

The accepted ADR 0079 implementation reached exact clean head `3dd2b0ecb1d787b7d6e21b30fc0c4470de47ee99`. Native execution passed the post-sudo descriptor creation and trusted namespace descriptor observation, then the exact ADR 0076 command `/usr/bin/mount --no-canonicalize --bind /proc/self/fd/3 "$root/src"` failed with exit 32 and the fixed `mount-fd3` classification. This is a failure of the external mount frontend at the descriptor bind, not evidence that fd 3 changed identity or that the target verifier accepted a different source.

ADR 0076 selected the external command because `--no-canonicalize` was intended to prevent util-linux from resolving or reopening the proc descriptor path. The observed frontend failure shows that retaining that wrapper does not provide a usable descriptor bind on the hosted native environment. Trying alternate mount options, another external wrapper, pathname recovery, or a fallback would broaden and obscure the security boundary. Linux already exposes the required narrow operation through `mount(2)`: trusted namespace root can submit the exact proc descriptor source and fixed target to the kernel without a user-space canonicalization or reopen step.

## Decision

### Exact correction ancestry

The exact implementation predecessor is current clean branch head `3dd2b0ecb1d787b7d6e21b30fc0c4470de47ee99` on `feat/issue42-candidate-tar-remediation`. It contains the exact native `mount-fd3` exit-32 classification and descends through the required accepted ADR 0079 integration. If that implementation branch advances before integration, a new ADR or explicit accepted amendment must bind the replacement exact head; an unrecorded moving-head substitution is prohibited.

Implementation must start at exactly `3dd2b0ecb1d787b7d6e21b30fc0c4470de47ee99` and integrate the exact accepted commit containing this ADR by a history-preserving merge before the correction commit. That integration merge must have `3dd2b0ecb1d787b7d6e21b30fc0c4470de47ee99` as first parent and the accepted ADR 0080 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from this documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Narrow supersession of the external bind wrapper

ADR 0080 supersedes only ADR 0076's requirement to perform the initial checkout bind with the fixed external command `/usr/bin/mount --no-canonicalize --bind /proc/self/fd/3 "$root/src"`, its requirement that lack of `--no-canonicalize` fail, and its prohibition on a direct `mount(2)` substitution. It does not supersede any fd-3 authentication, parent observation, target identity, mount-record, child-reaping, read-only remount, fd closure, terminal chroot, capability, seccomp, or checked-code inherited-descriptor boundary in ADRs 0076–0079.

The replacement is one fixed inline trusted standard-library Python wrapper run as namespace root with isolated `/usr/bin/python3 -I -c`. It imports no checked-out or third-party code and derives neither source nor target from arguments, environment, current directory, symlink text, or caller input. Through `ctypes.CDLL(None, use_errno=True)`, it resolves libc's `mount` symbol and must set exactly these declarations before use:

```python
mount.argtypes = (
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
)
mount.restype = ctypes.c_int
```

It invokes that symbol exactly once for the descriptor bind with this effective call:

```python
result = mount(
    b"/proc/self/fd/3",
    b"/tmp/cogs-native-runtime-root/src",
    None,
    4096,
    None,
)
error = ctypes.get_errno()
```

The source bytes, target bytes, null filesystem type, numeric flags, and null data are exact. `4096` is Linux `MS_BIND` and is the only flag in this call; no string option, recursive bind, remount flag, security flag, or additional bit is permitted. Success requires `result == 0`. On any other return, the wrapper uses the errno captured immediately after the call, emits only the fixed diagnostic `descriptor-bind-mount errno=<decimal>` for that captured value, and exits nonzero. It must not use `strerror`, locale-dependent text, a second mount attempt, or an allow-on-error path.

### Authentication and retained mount sequence

Before the syscall, the wrapper must authenticate its inherited fd 3 against the already captured exact checkout device/inode/directory/namespace-visible ownership and required `O_PATH`/descriptor-flag state. On syscall success, it must repeat the same fd-3 authentication before exiting. A missing, replaced, aliased, wrongly owned, non-directory, wrongly flagged, unreadable, or unstable fd 3 fails closed. These wrapper checks supplement rather than replace ADR 0079's independent pre-bind parent observer. The wrapper opens no checkout path and does not recover a path from fd 3. Namespace PID 1 synchronously waits for and reaps the wrapper, so no bind child survives.

After successful wrapper exit, the existing trusted target verifier runs unchanged in `rw` mode and continues to compare the exact mounted target and mount record with authenticated fd 3. The existing trusted external remount then remains exactly the read-only bind remount with `ro,nosuid,nodev,noexec`, and the same verifier runs unchanged again in `ro` mode. Thus the authorized sequence is: independent parent/fd-3 proof; wrapper fd-3 proof; one direct descriptor bind syscall; wrapper fd-3 reproof and reap; unchanged target verification; unchanged trusted read-only remount; unchanged target reverification; and only then the retained fd-3 closure and terminal lifecycle.

No `realpath`, `readlink`, path canonicalization, `/proc` symlink interpretation, source reopening, checkout pathname recovery, checkout ancestor traversal, alternate target, fallback, retry, shell mount builtin, external `mount` process, `subprocess`, or other helper is permitted for the initial descriptor bind. This prohibition does not remove or replace the already trusted external read-only remount after the direct bind. The exact target remains `/tmp/cogs-native-runtime-root/src`; no variable, equivalent normalized spelling, relative path, alternate runtime root, or caller-selected target is authorized.

### Exact authorized files and retained highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Replace only the initial ADR 0076 external descriptor-bind command with the exact trusted `ctypes` libc call, fd-3 before/after authentication, captured-errno diagnostic, and unchanged verify/remount/reverify sequence. | Retained **360** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact direct-call ABI, constants, fd authentication, failure diagnostic, and retained mount lifecycle; reject canonicalization, reopen, fallback, or external descriptor bind. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact descriptor-bind syscall and unchanged target verification/read-only remount lifecycle while retaining every sandbox boundary. | Retained **600** gross additions from `18f2644` |

The three highs remain non-transferable no-rename gross additions from exact `18f26441b6115091233d0c4cd44ced8f058d014f`. ADR 0077's checked-in Python highs of 750 and 850 and exact-five-file aggregate high of 2,640 remain unchanged. Deletion, movement, replacement, consolidation, or removal creates no credit. Ordinary readable state, authentication, errno handling, and failure transitions remain mandatory.

No checked-in Python file, production module, production runner, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new file may change. No behavior beyond replacement of the initial descriptor-bind wrapper and its corresponding static assertions is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove: exact ancestry and integration order; fixed trusted namespace-root standard-library Python; isolated inline source; `ctypes.CDLL(None, use_errno=True)`; explicit five-argument `argtypes` and integer `restype`; exact source and target byte strings; null filesystem type; exactly numeric `MS_BIND=4096`; null data; one call only; immediate errno capture; success only on return zero; and the fixed nonzero failure diagnostic. Review must reject a missing or different ABI declaration, truthiness-based success, stale errno, `os.strerror`, a second attempt, another flag, a string option, a variable source or target, checked-out import, or third-party/native helper.

Review must separately prove fd 3 is authenticated before and after the successful syscall, the wrapper is reaped, the existing `rw` target verifier is unchanged, the existing trusted read-only `ro,nosuid,nodev,noexec` remount remains after that verification, and the unchanged `ro` verifier follows it. It must reject canonicalization, `readlink`, `realpath`, fd-source reopening, pathname reconstruction, fallback, retry, an external process for the descriptor bind, target-verifier weakening, remount weakening, delayed closure, or any change to ADR 0079's terminal descriptor lifecycle.

The final implementation commit must descend through the required first/second-parent integration, retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 360/80/600 and aggregate 2,640. Checked-in Python, production, schema, Gitleaks bytes, caps, and every unauthorized surface must be unchanged from the predecessor. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0079 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. No cap changes: workflow/TypeScript highs remain 360/80/600, checked-in Python highs remain 750/850, the exact-five-file aggregate remains 2,640, the Phase B aggregate remains 3,310, and the conservative global projection remains `33,344 < 34,000`. The 32,000 preferred target, 34,000 hard cap, and 656-line margin remain unchanged and grant no implementation authority.
