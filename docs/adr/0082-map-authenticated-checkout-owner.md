# ADR 0082: Map the authenticated checkout owner in the native sandbox

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only ADR 0075's root-only native user-namespace map after native execution at exact head `9cb67fdad3dcd175f9931c42dcf4ff6b7704c758` failed with the fixed `permission` classification. Each UID and GID map instead contains exactly two nonoverlapping one-ID extents: namespace 0 to initial-namespace 0, and the authenticated checkout UID or GID to the same numeric initial-namespace ID. This permits the fixed trusted child in the final mount namespace to open and reauthenticate the checkout before the unchanged descriptor bind, read-only remount, verification, descriptor closure, chroot, capability removal, and seccomp boundary. Only CI and the two existing TypeScript static companions may change under retained highs 365/80/600 and retained exact-five-file aggregate 2,645. No run, event, cloud, or AWS authority changes.

## Context

ADR 0081 moved the checkout `O_PATH` open into the final mount namespace, but retained ADR 0075's map containing only `0 0 1`. The accepted implementation reached exact clean head `9cb67fdad3dcd175f9931c42dcf4ff6b7704c758`; native execution entered the namespaces and then failed with the fixed `permission` classification when the trusted child attempted the authenticated checkout open. Moving the open corrected the cross-mount-namespace descriptor defect but did not map the checkout's nonzero owner into the new user namespace.

The ordinary runner already authenticates the exact canonical checkout pathname and captures its exact device, inode, nonzero UID, and nonzero GID before sudo. The fixed post-sudo outer launcher reauthenticates that same directory and those inert values before namespace creation. Mapping only those already-authenticated owner IDs lets trusted namespace setup traverse and open the same checkout while it still has capabilities in the new user namespace. It does not map a caller-selected identity, a range, a subordinate allocation, or any additional host principal.

The root extent remains necessary. Genuine host-root tools, loaders, libraries, and devices must continue to appear as UID/GID 0 and pass their exact ownership checks. The checkout-owner extent supplements that root identity; it does not replace it or authorize checked-out code before the final sandbox boundary.

## Decision

### Exact correction ancestry

The exact implementation predecessor is current clean branch head `9cb67fdad3dcd175f9931c42dcf4ff6b7704c758` on `feat/issue42-candidate-tar-remediation`. It contains the exact native `permission` result and descends through the required accepted ADR 0081 integration. If that implementation branch advances before integration, a new ADR or explicit accepted amendment must bind the replacement exact head; an unrecorded moving-head substitution is prohibited.

Implementation must start at exactly `9cb67fdad3dcd175f9931c42dcf4ff6b7704c758` and integrate the exact accepted commit containing this ADR by a history-preserving merge before the correction commit. That integration merge must have `9cb67fdad3dcd175f9931c42dcf4ff6b7704c758` as first parent and the accepted ADR 0082 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from the documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Narrow supersession of the root-only map

ADR 0082 supersedes only ADR 0075's requirement that `/proc/self/uid_map` and `/proc/self/gid_map` each contain only `0 0 1`, and the directly dependent requirements in ADRs 0076–0081 that the authenticated checkout owner remain unmapped and appear as overflow UID/GID. Every other identity, descriptor, namespace, mount, chroot, capability, seccomp, process, and evidence requirement remains binding.

The ordinary runner must continue to require an absolute byte-for-byte canonical checkout pathname and a no-follow stat identifying an exact directory owned by its captured nonzero ordinary UID and GID. Device, inode, UID, and GID remain canonical unsigned decimal values no greater than `2^64-1` before sudo. In addition, each authenticated checkout UID and GID must be no greater than `2^32-2` before it can select a map extent. Zero, `2^32-1`, an out-of-range value, a sign, whitespace, leading zero, alternate decimal spelling, malformed value, changed owner, or identity mismatch fails before namespace creation. The final-mount-namespace child must again match the opened descriptor and fresh no-follow pathname stat to the exact captured device, inode, UID, GID, and directory type.

The retained fixed `/usr/bin/setpriv` transition still sets host real/effective/saved UID/GID 0, clears supplementary groups, and sets `no_new_privs`. Its `/usr/bin/unshare` argv must use repeated util-linux mapping arguments in this exact order:

```text
--user
--map-users=0:0:1
--map-users=<authenticated-checkout-uid>:<same-authenticated-checkout-uid>:1
--map-groups=0:0:1
--map-groups=<authenticated-checkout-gid>:<same-authenticated-checkout-gid>:1
--net --pid --fork --mount
```

The two variable arguments must be constructed only from the already-authenticated canonical decimal UID and GID strings. They may not be derived from an ambient process identity, environment, current stat without equality to the captured identity, caller-selected map text, arithmetic range, subordinate-ID source, or normalized substitute. The root arguments and count `1` are fixed literals. A combined range, count other than one, reversed inner/outer ID, reordered or missing extent, `--map-root-user`, `--map-current-user`, direct `newuidmap`/`newgidmap` invocation, retry, or alternate mapping mechanism is prohibited.

The resulting UID map must contain exactly the two unordered rows `(0, 0, 1)` and `(checkout_uid, checkout_uid, 1)`. The resulting GID map must contain exactly the two unordered rows `(0, 0, 1)` and `(checkout_gid, checkout_gid, 1)`. Each observer must parse exactly two rows with exactly three unsigned-decimal fields per row, require count one, require the rows to be distinct and nonoverlapping in both namespace and initial-namespace space, and reject every missing, duplicate, additional, broad, malformed, or overlapping row. It must not accept only a root row, only an owner row, an overflow identity, or equivalent aggregate text.

### Mapped checkout identity and retained terminal boundary

The fixed child launcher still begins only inside the final user, network, PID, and mount namespaces. While it remains trusted namespace setup, it opens the exact canonical checkout once with `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`; requires fresh pathname stat and descriptor stat to equal the captured device, inode, authenticated numeric UID, authenticated numeric GID, and directory type; normalizes only fd 3 as inheritable; closes every alias and unexpected descriptor; proves exact descriptor state; and terminally execs the trusted sandbox without the checkout pathname. The first independent parent observer must prove the exact two-row maps and authenticate fd 3 with that same mapped numeric UID/GID, not the overflow IDs. No checked-out byte is read, imported, or executed by either launcher.

The retained ADR 0080 direct bind remains one exact `MS_BIND=4096` libc call from `/proc/self/fd/3` to `/tmp/cogs-native-runtime-root/src` in that same final mount namespace. Fd 3 is reauthenticated before and after the call. The target verifier must compare the descriptor and mounted target with the exact captured device, inode, mapped checkout UID, mapped checkout GID, and directory type. The bind is then remounted exactly read-only with `nosuid,nodev,noexec` and reverified before fd 3 closes. Every bind child and observer is synchronously reaped; the second observer proves every remaining high descriptor is close-on-exec; and namespace PID 1 immediately terminally execs chroot.

The host checkout pathname is passed only to the fixed pre-chroot outer and child launchers for the authenticated open. It is not passed to trusted Bash, written into the chroot, exposed through an environment or descriptor, supplied to the in-root launcher, or available to checked-out code. There is no pathname bind, reopen through the host pathname, checkout copy, owner or mode change, ACL, supplementary group, extra identity extent, broader map, root-only retry, alternate open, fallback, or post-chroot recovery path.

Root-owned host tools, loaders, libraries, and devices remain mapped to and authenticated as exact UID/GID 0. Before checked-out code, fd 3 is closed, the checkout bind is read-only and reverified, the old root is unreachable, and chroot has reset root and cwd to `/`. The retained in-root `setpriv` locks `noroot`, empties bounding, inheritable, and ambient capability sets, clears groups, retains UID/GID 0 and `no_new_privs`, and the trusted launcher proves all five capability sets zero before installing and verifying the exact inherited seccomp filter. Checked-out code still inherits only fds 0–2, no socket, no host checkout pathname, zero capabilities, NNP, and the exact filter. Mapping the checkout owner grants no post-setup capability or initial-user-namespace authority.

### Exact authorized files and retained highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Replace only the root-only map construction and dependent overflow-owner observations with exact authenticated two-extent UID/GID arguments, map observation, and mapped checkout reauthentication. | Retained **365** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact two unordered one-ID rows and mapped checkout identity while rejecting every broader, overlapping, root-only, overflow, dynamic, or fallback variant. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact map construction, observer, same-mount-namespace open/bind identity, and retained terminal sandbox lifecycle. | Retained **600** gross additions from `18f2644` |

The checked-in Python highs remain 750 and 850. The five non-transferable no-rename gross-addition maxima from exact `18f26441b6115091233d0c4cd44ced8f058d014f` remain `365 + 750 + 80 + 850 + 600 = 2,645`. Deletion, movement, replacement, consolidation, generated placement, or removal creates no credit. Ordinary-readable validation, map construction, row parsing, identity comparison, and failure transitions are mandatory; compression to fit a high is prohibited.

No checked-in Python file, production module, production runner, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new implementation file may change. No behavior beyond the exact authenticated-owner map and its directly dependent ownership assertions is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove: exact ancestry and first/second-parent integration; canonical pre-sudo device/inode/UID/GID capture and post-sudo reauthentication; nonzero owner IDs at most `2^32-2`; repeated fixed util-linux arguments constructed only from the authenticated decimal strings; exactly two unordered, nonoverlapping count-one UID rows and exactly two such GID rows; no other mapping; and exact mapped numeric ownership in the final-namespace child, parent observer, descriptor-bind wrapper, and both target verifications. Review must separately prove genuine root-owned closure remains UID/GID 0.

Review must reject a root-only or owner-only map, overflow-owner acceptance, a range or count greater than one, an overlap, subordinate IDs, ambient UID/GID derivation, a third extent, map normalization, direct map helper, retry, fallback, changed checkout identity, checkout pathname reaching Bash or chroot, early checked-out code, or weakening of fd authentication, direct bind, read-only remount, reverification, fd closure, immediate chroot, zero capabilities, `noroot`, NNP, seccomp, and exact inherited-fd boundaries.

The final implementation commit must descend through the required first/second-parent integration, retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 365/750/80/850/600 and aggregate 2,645. Production, checked-in Python, schema, Gitleaks bytes, and every unauthorized surface must be unchanged from the predecessor. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0081 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The Phase B aggregate high remains 3,310, and the conservative global projection remains at most `33,349 < 34,000`. The 32,000 preferred target, 34,000 hard cap, and at least 651 lines of hard-cap margin remain unchanged and grant no implementation or execution authority.
