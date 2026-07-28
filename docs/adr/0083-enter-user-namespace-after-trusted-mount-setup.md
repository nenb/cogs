# ADR 0083: Enter the user namespace after trusted mount setup

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct ADR 0082 after util-linux 2.39 source and the exact bounded diagnostic at implementation head `712857918e64663699bcf8d5d13fb4319a3a94d8` proved that repeated `--map-users`/`--map-groups` options overwrite the retained range and that an arbitrary checkout-owner range depends on subordinate-ID authorization. The fixed post-sudo launcher now enters only fresh network, PID-with-fork, and mount namespaces while trusted setup remains host root in the initial user namespace. Its fixed child opens the authenticated runner-owned checkout in the final mount namespace and completes the descriptor bind, mount verification, read-only remount, reverification, and descriptor closure without reading or executing checkout code. Only then does one terminal `unshare --user --map-user=0 --map-group=0` create the exact direct root map before chroot, the retained zero-capability/`noroot`/NNP transition, timeout, seccomp launcher, and checked module. No owner map, subordinate ID, map helper, fallback, residue, run, cloud, or AWS authority is permitted. The CI high rises from 365 to 372, the exact-five-file aggregate from 2,645 to 2,652, and TypeScript highs remain 80 and 600.

## Context

ADR 0082 required util-linux 2.39 to construct two UID extents and two GID extents by repeating `--map-users` and `--map-groups`: one direct root extent and one direct authenticated-checkout-owner extent. The accepted implementation and bounded diagnostic reached exact clean head `712857918e64663699bcf8d5d13fb4319a3a94d8`. Source-level examination then established two facts that invalidate that architecture rather than merely its diagnostics.

First, this util-linux implementation retains one range specification for each repeated mapping option, so the later `--map-users` or `--map-groups` value overwrites the earlier value rather than appending a second extent. The required two-row map therefore cannot be obtained by ADR 0082's argv. Second, asking util-linux to install the arbitrary authenticated owner as a separate outer range selects delegated mapping behavior whose authorization depends on `/etc/subuid` or `/etc/subgid` and the corresponding helper path. The ordinary runner's checkout ownership is authentication evidence, not a subordinate-ID allocation. Adding host allocation state, `newuidmap`, `newgidmap`, a broad owner range, or an environment-specific retry would violate the fixed portable boundary.

The checkout does not need to be mapped while trusted mount setup runs. The fixed post-sudo process already has authenticated host UID/GID 0 and executes only literal trusted workflow launchers. If user-namespace creation is delayed, that trusted process can traverse and open the already-authenticated runner-owned checkout in the final mount namespace using initial-user-namespace root authority, bind it by the retained descriptor syscall, make it read-only, verify the complete mount view, and close the descriptor. A new user namespace is needed only before chrooted checked code. Creating it at that terminal boundary restores the exact one-row direct root map without any checkout-owner or subordinate-ID dependency.

This correction deliberately makes the host-root phase longer than ADR 0082. That authority is acceptable only because it is a fixed trusted setup workflow inside fresh network, PID, and mount namespaces, performs metadata and mount operations only, and cannot import, resolve, interpret, or execute any checked-out byte. The checkout becomes code only after the late user namespace, chroot, capability removal, NNP, and inherited seccomp boundary are independently proved.

## Decision

### Exact correction ancestry

The exact implementation predecessor is current diagnostic head `712857918e64663699bcf8d5d13fb4319a3a94d8` on `feat/issue42-candidate-tar-remediation`. It descends through the history-preserving ADR 0082 integration and contains the exact bounded diagnostics that led to source examination. If that implementation branch advances before integration, a new ADR or explicit accepted amendment must bind the replacement exact head; an unrecorded moving-head substitution is prohibited.

The exact accepted documentation parent for ADR 0083 is `dd5b9092a19abf1fe33991e23546f5e170b0cc67`, accepted ADR 0082. The accepted commit containing this ADR must descend directly from that exact parent. Implementation must start at exactly `712857918e64663699bcf8d5d13fb4319a3a94d8` and integrate the exact accepted ADR 0083 commit by a history-preserving merge before the correction commit. That integration merge must have `712857918e64663699bcf8d5d13fb4319a3a94d8` as first parent and the accepted ADR 0083 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from the documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Narrow supersession of ADR 0082

ADR 0083 supersedes ADR 0082's two-row UID/GID maps, repeated plural mapping options, checkout-owner map eligibility bound, mapped-owner observers, and requirement to create the user namespace together with the network, PID, and mount namespaces. It also supersedes directly dependent ADR 0075–0081 wording that places trusted mount setup in the final user namespace or requires overflow or specially mapped checkout ownership there.

The authenticated checkout UID and GID remain exact canonical nonzero unsigned decimal values no greater than `2^64-1`, captured before sudo and reauthenticated after sudo. ADR 0082's additional `2^32-2` ceiling existed only to select owner-map extents and is removed. Device, inode, UID, GID, directory type, canonical pathname, no-follow behavior, stable identity, and same-final-mount-namespace descriptor requirements remain exact. Every non-conflicting descriptor, mount, chroot, process, capability, seccomp, evidence, timeout, and operational boundary from ADRs 0071–0082 remains binding.

### Fixed outer transition without a user namespace

The ordinary runner retains the exact canonical checkout and anonymous evidence protocol. No checkout or evidence descriptor crosses sudo. The sole privilege transition remains the permitted exact prefix:

```text
/usr/bin/sudo -n --close-from=3 /usr/bin/python3 -I -c <fixed-outer-launcher>
```

The fixed isolated outer launcher accepts only the canonical checkout pathname, exact captured device/inode/UID/GID decimals, one literal allowed test path, and fixed embedded child and sandbox text. It reauthenticates the pathname and owner, proves no descriptor at or above 3 survived sudo, reads no checkout content, and imports no checkout module.

Its only successful terminal transition is empty-environment `execve` through this exact trusted shape:

```text
/usr/bin/setpriv
  --reuid 0 --regid 0 --clear-groups --no-new-privs
/usr/bin/unshare
  --net --pid --fork --mount
/usr/bin/python3 -I -c <fixed-final-mount-namespace-child>
```

The first `unshare` invocation contains only `--net`, `--pid`, `--fork`, and `--mount` namespace options in that order. It contains no `--user`, mapping option, setgroups option, owner-derived option, namespace file, or alternate namespace mechanism. `setpriv` retains real/effective/saved host UID/GID 0, clears supplementary groups, and establishes NNP before namespace creation. The embedded child is namespace PID 1 in the final network, PID, and mount namespaces, but remains trusted host root in the initial user namespace.

### Bounded host-root setup in the final mount namespace

The fixed child repeats the exact authority and identity checks, then opens the checkout once with `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. Because no user namespace yet translates ownership, fresh pathname and descriptor stats must equal the exact captured host device, inode, nonzero runner UID, nonzero runner GID, and directory type. It normalizes only fd 3 as inheritable, closes every alias and unexpected descriptor, proves exact descriptor state, and terminally execs only the fixed trusted sandbox text. The checkout pathname does not pass to that sandbox or any later stage.

Both synchronous descriptor observers must prove that namespace PID 1 is still in the initial user namespace by reading its proc files and requiring each map to contain exactly the single Linux initial-user-namespace dummy row:

```text
0 0 4294967295
```

Each observer must parse exactly one newline-terminated row and exactly three canonical unsigned-decimal fields from both `uid_map` and `gid_map`; reject a count of one, an owner row, an additional or malformed row, a translated value, or any other text; and retain all ADR 0079 parent-PID, descriptor-object, `FD_CLOEXEC`, socket, namespace-fd, alias, stability, and synchronous-reaping checks. The initial dummy row is an observation of the initial namespace, not an authorized configurable map.

While this fixed trusted process alone has initial-user-namespace root authority, it performs the retained mount workflow in the same final mount namespace as fd 3. It makes propagation recursively private; creates and verifies the fresh tmpfs staging and chroot roots; binds and verifies only the exact genuine root-owned host tool, loader, library, and device closure; mounts fresh proc for the new PID namespace; and executes ADR 0080's one exact direct `MS_BIND=4096` libc call from `/proc/self/fd/3` to `/tmp/cogs-native-runtime-root/src`. Descriptor authentication before and after that call and both target verifiers now require the captured ordinary-runner UID/GID exactly, with no overflow or mapped substitute.

The checkout bind is then remounted exactly read-only with `nosuid,nodev,noexec` and reverified. The complete mount allowlist, fresh-proc identity, old-root exclusion from the future chroot, source and target identity, and genuine root-owned closure are proved before fd 3 closes. Every mount or observer child is synchronously reaped. The post-closure observer proves fd 3 absent and every remaining high trusted-shell descriptor close-on-exec. No checkout content is opened, scanned, read, hashed, imported, parsed, resolved as a module, interpreted, or executed in this phase. No checked-out executable, shell fragment, configuration, helper, hook, or library may influence it.

Initial-user-namespace root authority is limited to this fixed workflow phase. It has a fresh network namespace with no inherited socket, a fresh mount namespace, and the fixed PID-with-fork lifecycle. It receives no credential or daemon-control descriptor. It may not bind an additional host path, alter checkout ownership/mode/ACL/content, use the checkout pathname after fd normalization, execute a caller-selected program, or return to an outer shell. Failure exits the namespace process and destroys its namespace-scoped tmpfs and mounts; it must leave no namespace handle, named evidence file, host mount, checkout mutation, or other residue.

### Terminal late user namespace and checked-code boundary

After read-only reverification, fd-3 closure, child reaping, and the second descriptor observation, namespace PID 1's only successful action is one terminal exec with this exact effective ordering:

```text
/usr/bin/unshare --user --map-user=0 --map-group=0
/usr/sbin/chroot /tmp/cogs-native-runtime-root
/usr/bin/setpriv
  --securebits +noroot,+noroot_locked
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all
  --reuid=0 --regid=0 --clear-groups --no-new-privs
/usr/bin/timeout --signal=KILL 240
/usr/bin/python3 -I -B -c <literal-seccomp-launcher>
```

The singular decimal options `--map-user=0` and `--map-group=0` each map the current initial-namespace root identity directly to namespace ID 0. They occur exactly once, derive from no checkout or ambient identity, and produce exactly one UID row and one GID row, each `0 0 1`. This invocation has no plural `--map-users`/`--map-groups`, range/count argument, owner map, repeated option, helper selection, retry, fallback, or alternate executable. User-namespace creation cannot occur earlier, and no mount operation or checkout descriptor remains after it.

The late user namespace preserves the already isolated network, PID, and mount namespaces. Before the final capability drop, its root capabilities are only capabilities in the new user namespace; they grant no initial-user-namespace authority and cannot modify the mount namespace owned by the initial user namespace. The exact chroot resets root and cwd to `/` with the old root absent from the verified mount view. The retained in-root `setpriv` then locks `noroot`, empties bounding, inheritable, and ambient sets, clears groups, retains UID/GID 0 and NNP, and invokes the fixed timeout and literal trusted seccomp launcher.

Before opening, resolving, importing, or executing the checked module, the isolated seccomp launcher must independently inspect its own maps through the already verified fresh proc mount. `/proc/self/uid_map` and `/proc/self/gid_map` must each parse as exactly one newline-terminated row with exactly the canonical fields `0 0 1`; every additional, absent, broad, owner, malformed, or alternate row is terminal. The launcher must also retain ADR 0075's independent checks that real/effective/saved UID/GID are zero, supplementary groups are empty, NNP is one, and `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and `CapAmb` are all zero.

Only after those map, identity, and capability assertions may the launcher install and verify the unchanged exact x86_64 seccomp-BPF filter and terminally `execve` the selected isolated checked module. Checked code therefore inherits only fds 0–2, the verified chroot and read-only checkout, the exact one-row root map, no capabilities, locked `noroot`, NNP, and the exact filter. It never executes with initial-user-namespace root authority.

### No subordinate-ID, helper, fallback, or residue path

Neither `/etc/subuid` nor `/etc/subgid` may be read, required, generated, changed, or assumed. `newuidmap`, `newgidmap`, direct invocation of either helper, a setuid mapping helper, plural map option, direct `/proc/*_map` writer, owner map, subordinate range, identity range, count other than one, `--map-root-user`, `--map-current-user`, environment-derived identity, retry, root-only fallback, alternate namespace order, or host-specific branch is prohibited.

There is no fallback to opening the checkout after the late user namespace, mapping its owner, accepting overflow ownership, copying the checkout, changing ownership or mode, adding a group, retaining fd 3 across chroot, or running checked code in the trusted host-root phase. Successful and failed invocations leave no host namespace handle, persistent mount, helper state, subordinate-ID state, checkout mutation, named evidence, or other new residue.

### Exact authorized files and revised highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Move only user-namespace creation to the terminal post-mount boundary; require initial dummy maps during trusted descriptor/mount setup and exact one-row direct-root maps in the zero-capability seccomp launcher; replace mapped/overflow owner observations with exact host ownership; retain every fixed mount, chroot, timeout, filter, and evidence transition. | **372** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact host-root-only trusted setup, initial dummy-map observers, terminal singular direct-root map, fresh-proc independent map/capability proof, and no subordinate/helper/fallback/residue path. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact namespace order and identities while retaining the complete descriptor, mount, read-only, chroot, seccomp, anonymous-evidence, and terminal checked-code boundaries. | Retained **600** gross additions from `18f2644` |

The CI maximum rises only from 365 to 372 so the outer transition, host-root phase boundary, late user-namespace exec, and independent final map assertion can remain ordinarily readable. The checked-in Python highs remain 750 and 850. The five non-transferable no-rename gross-addition maxima from exact `18f26441b6115091233d0c4cd44ced8f058d014f` are therefore `372 + 750 + 80 + 850 + 600 = 2,652`. Deletion, movement, replacement, consolidation, generated placement, or removal creates no credit. Compression to fit a high is prohibited.

No checked-in Python file, production module, production runner, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new implementation file may change. No behavior beyond the corrected namespace order, directly dependent identity assertions, and necessary static companions is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove: exact ancestry and first/second-parent integration; no descriptor crossing sudo; exact fixed outer root/NNP transition; first `unshare` containing network, PID, fork, and mount options only; child and trusted sandbox in the final mount namespace but initial user namespace; exact one-row `0 0 4294967295` UID/GID observations during both descriptor phases; one exact same-namespace `O_PATH` checkout open; exact host owner authentication; direct descriptor bind; read-only remount and reverification; complete mount allowlist; fd closure; child reaping; and no checkout content use or checked execution while host-root authority remains.

Review must then prove the only successful continuation is terminal singular `unshare --user --map-user=0 --map-group=0`, followed in order by exact chroot, `setpriv` locked `noroot` and zero capabilities, timeout, and the literal seccomp launcher. The launcher must independently read the fresh proc mount and exact-assert one `0 0 1` row for each map before checked code, in addition to the retained identity, group, five-zero-capability, NNP, seccomp-installation, post-installation, exact-exec, inherited-fd, and no-socket proofs.

Review must reject repeated or plural mapping options, owner or overflow identity acceptance, a user namespace before mount completion, missing initial dummy-map observation, a broad map, subordinate allocation, `newuidmap`/`newgidmap`, helper or configuration dependence, direct map writing, retry/fallback, surviving fd 3, changed checkout metadata, host-root checkout read/import/exec, caller-selected trusted-phase behavior, extra host bind, weakened read-only/chroot/capability/seccomp order, or any residue.

The final implementation commit must descend through the required first/second-parent integration, retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 372/750/80/850/600 and aggregate 2,652. Checked-in Python, production, schema, Gitleaks bytes, and every unauthorized surface must be unchanged from the predecessor. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0082 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The Phase B aggregate high remains 3,310. The conservative global projection rises only seven lines to at most `33,356 <= 34,000`; the 32,000 preferred target and 34,000 hard cap remain unchanged, with at least 644 lines of hard-cap margin. Those numeric bounds grant no implementation or execution authority.
