# ADR 0043: Use Kata guest tmpfs and exact read-only input binds

- Status: Accepted
- Date: 2026-07-24
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's explicit instruction to continue local issue #42 work and make required decisions while retaining the separate AWS deployment gate.

## Context

ADR 0038 requires one guest-visible read-only input interface and one read-write work interface for standalone Kata SSH qualification. ADR 0042 planned to implement the work interface as a separately owned host tmpfs. Hostile planning review found that design unnecessarily makes guest-mutated data a host mount-lifecycle problem. Exact recovery would need to distinguish intended mutations from replacement, preserve attachment uncertainty across crashes, and bound a normal host unmount without recursive cleanup.

The pinned runtime can instead create the work filesystem inside the Kata guest. OCI Runtime Specification 1.3.0 applies Linux mounts in listed order and permits bind sources that are files or directories. Containerd 2.2.1 preserves repeated `ctr run --mount` order after its fixed default Linux mounts when building the OCI spec. Kata 3.32.0 preserves the ordered mount list, shares regular files and directories through its configured shared filesystem, and has the guest agent create file or directory bind destinations before mounting them. The agent derives bind behavior from an explicit `bind` option and supports `ro`, `rw`, `nodev`, `noexec`, `nosuid`, and propagation flags.

The exact source revisions reviewed for this decision are:

- OCI runtime-spec `v1.3.0`, commit `92249139eea7161e13745abd4cb6d0ea02a3227a`;
- containerd `v2.2.1`, commit `dea7da592f5d1d2b7755e3a161be07f43fad8f75`; and
- Kata Containers `3.32.0`, commit `337b6002681479fb6a605ca8a7a1138e81b6098c`.

Relevant upstream paths are runtime-spec `config.md`; containerd `pkg/oci/mounts.go`, `cmd/ctr/commands/run/run.go`, `pkg/oci/spec_opts.go`, and `cmd/ctr/commands/run/run_unix.go`; and Kata `src/runtime/pkg/oci/utils.go`, `src/runtime/virtcontainers/fs_share_linux.go`, `src/runtime/virtcontainers/container.go`, `src/runtime/virtcontainers/kata_agent.go`, `src/agent/rustjail/src/mount.rs`, and `src/agent/rustjail/src/container.rs`. This is source verification, not runtime qualification.

The reviewed containerd CLI route produces seven default mounts before supplied mounts. Its default `/run` tmpfs hides the pinned rootfs's `/run/cogs-stage2-ssh` and `/run/sshd`, so those directories must be recreated in the effective guest `/run`; their presence in the deterministic rootfs is not used as mount authority. The rootfs graph and accepted pins remain unchanged.

## Decision

Supersede these dependent ADR 0042 clauses together:

- the separately owned host guest-work tmpfs mechanism;
- the planned `completion_work_mount_state.py` and `completion_guest_work_mount.py` modules and their 420–650-line range;
- the phrase “two fixed guest mounts” where it means two OCI entries rather than the two fixed guest data interfaces;
- project-owned detach/normal-unmount guest-work teardown wording;
- the no-lazy/detach wording only for the enumerated pinned-runtime dependency calls accepted below; and
- staged-remeasurement step 1's separate guest-work owner.

Their replacement is one fixed input/control owner, one retained rootfs lease, the canonical OCI mount contract below, and pinned Kata lifecycle observation. Every other ADR 0038–0042 requirement remains binding.

### Canonical OCI mount contract

The complete stored OCI mount list must equal the following eleven entries in this exact order, with exact type, source, destination, and ordered option arrays. The first seven are the reviewed containerd 2.2.1 Linux defaults; the final four are the only custom entries and form one contiguous suffix.

| # | Type | Source | Destination | Ordered options |
| -: | --- | --- | --- | --- |
| 1 | `proc` | `proc` | `/proc` | `nosuid,noexec,nodev` |
| 2 | `tmpfs` | `tmpfs` | `/dev` | `nosuid,strictatime,mode=755,size=65536k` |
| 3 | `devpts` | `devpts` | `/dev/pts` | `nosuid,noexec,newinstance,ptmxmode=0666,mode=0620,gid=5` |
| 4 | `tmpfs` | `shm` | `/dev/shm` | `nosuid,noexec,nodev,mode=1777,size=65536k` |
| 5 | `mqueue` | `mqueue` | `/dev/mqueue` | `nosuid,noexec,nodev` |
| 6 | `sysfs` | `sysfs` | `/sys` | `nosuid,noexec,nodev,ro` |
| 7 | `tmpfs` | `tmpfs` | `/run` | `nosuid,strictatime,mode=755,size=65536k` |
| 8 | `tmpfs` | `tmpfs` | `/run/cogs-stage2-ssh` | `rw,nosuid,nodev,noexec,mode=0700,size=67108864,nr_inodes=16384` |
| 9 | `bind` | fixed server-key path | `/run/cogs-stage2-ssh/ssh_host_ed25519_key` | `bind,ro,nosuid,nodev,noexec,private` |
| 10 | `bind` | fixed authorized-keys path | `/run/cogs-stage2-ssh/authorized_keys` | `bind,ro,nosuid,nodev,noexec,private` |
| 11 | `bind` | fixed fixture path | `/run/cogs-stage2-ssh/input` | `bind,ro,nosuid,nodev,noexec,private` |

The fixed source paths are direct children of the one operation root:

- `/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/kata-input-v1/share/ssh_host_ed25519_key`;
- `/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/kata-input-v1/share/authorized_keys`; and
- `/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/kata-input-v1/share/fixture`.

Order, fields, source paths, destinations, option order, byte limit, and inode limit are fixed local implementation constants. No caller, CLI flag, environment value, configuration file, batch input, or recovery path may select or weaken them. `ctr run --config` is forbidden because it bypasses the reviewed CLI mount-construction path. Default-mount drift, an extra mount, a missing explicit `bind`, or any reordering is a stop condition rather than a compatibility fallback.

The mount-list digest is SHA-256 over the UTF-8 bytes of one canonical JSON array plus a final newline. Each array item is an object with exactly `destination`, `options`, `source`, and `type`; keys are lexicographically sorted, options retain table order, strings use JSON's shortest required escapes, and separators contain no insignificant whitespace. `storedSpec.mounts`, not the whole OCI spec, must equal the eleven-item array and digest. The rest of the stored OCI spec remains subject to separate fixed lifecycle checks.

These eleven OCI entries implement the same two guest data interfaces required by ADR 0038: read-only `input` and read-write `work`. Fixed guest bootstrap, before `sshd`, creates and verifies root-owned `/run/sshd` mode `0755` and `/run/cogs-stage2-ssh/work` mode `0700`. `sshd` creates its configured `/run/cogs-stage2-ssh/sshd.pid`; bootstrap does not pre-create it. All clones, package build/install roots, per-sample state, and sample output stay in `work`. No guest-writable path has a host source.

### Host input and credential ownership

The fresh server host private key is the sole intentionally guest-visible ephemeral private credential. Its source is an exact root-owned regular file, mode `0400`, link count one, with no symlink, hardlink, xattr, or extra name. The exact restricted `authorized_keys` source is root-owned, regular, mode `0400`, link count one. Fixture directories are root-owned mode `0555`; fixture files are root-owned regular files mode `0444`, and the canonical fixture manifest records their exact link counts, sizes, and digests.

Host-private client key, client public key, `known_hosts`, operation state, raw output, candidate results, source checkout, cache, rootfs source, and ownership ledgers are never OCI mount sources. The host owns a fixed root-private operation tree with separate `private` and sealed `share` subgraphs. It verifies the share graph through a bounded canonical manifest before launch, after readiness and workload groups, and before cleanup. Cleanup removes only manifest-recorded exact-owned entries fd-relatively in recorded postorder; it performs no recursive discovery and preserves replacement or uncertainty.

Key bytes, private-key fingerprints, authorized-key material, and sensitive derived output are excluded from generated evidence and logs. Evidence may contain only the accepted bounded non-sensitive identity fields and digests whose disclosure is explicitly allowed by the later schema.

### Runtime ownership and teardown

The exact Kata lifecycle, not a caller-provided proof or boolean, owns the canonical mount-list digest and input-manifest digest. This decision supersedes ADR 0042's no-lazy/detach wording only for these route-relevant Kata 3.32.0 dependency actions: creating and releasing each temporary private read-only bind; per-input `UnshareFile`; sandbox shared-path teardown; host shared-rootfs and container-share-directory teardown; and guest container-root teardown. These pinned paths use `MNT_DETACH|UMOUNT_NOFOLLOW` or `MNT_DETACH`. They are not project cleanup actions. A successful or ignored-error detach, including the deferred temporary-bind detach, is never zero-reference or cleanup evidence.

Project code issues no host mount, unmount, lazy/detach/force unmount, or recursive cleanup for the input/work interface. This does not prohibit the separately accepted exact network-namespace mount lifecycle. Project code also performs no broad process kill, broad firewall command, or unknown-to-absent conversion.

Guest tmpfs disposal and input detachment are established only after this exact teardown prefix:

1. revoke readiness and prohibit new SSH commands;
2. stop and independently observe the exact task as `STOPPED`;
3. remove the exact caller-owned network namespace and observe its namespace links, veth, TAP, tc-filter, and mount baselines absent;
4. delete the stopped task and then its exact container without force, observing both absent;
5. observe the exact QEMU, shim, virtiofsd, and relevant mount-namespace identities absent;
6. prove the canonical host mountinfo baseline and the exact deterministic Kata sandbox share root `/run/kata-containers/shared/sandboxes/<write-ahead-sandbox-id>` absent, including its `mounts`, `shared`, and `private` children and all container-rootfs/share state; and
7. remove only exact owned firewall state and prove its baseline.

QEMU exit is the conclusive guest-memory disposal boundary, but it does not replace the later share-path and mount-baseline checks. Only after all seven steps are conclusively complete may the owner reverify and remove exact host inputs and private controls, release the rootfs lease, close proof descriptors, reset durable operation state, and re-observe every baseline.

A failed or unknown task/container deletion, live or replaced process, namespace uncertainty, changed input, surviving share path or mount, or any possible reference preserves the input tree, private controls needed for recovery, rootfs lease, durable operation state, ownership ledger, and proof descriptors. Independently safe exact network or firewall cleanup continues in order.

The sandbox and container IDs are fixed and durable before runtime start. Because Kata chooses random share-leaf names after start, recovery does not assume every leaf was recorded. It performs bounded, fd-relative, no-follow, read-only classification of only the exact deterministic sandbox root above: at most 64 entries per level, four levels, 256 total entries, with complete host mountinfo correlation. Unknown, replaced, over-limit, over-depth, nested-mount, or creation-before-record residue preserves ownership and fails readiness. This enumeration authorizes no unmount, unlink, recursive deletion, or adoption of runtime-owned state. Fault qualification covers a crash after each random path/mount creation and before project observation. After any crash, recovery reacquires the operation lock and re-observes every exact task, container, process, namespace, mount, deterministic share root, bounded discovered leaf, network, and firewall identity before advancing retained ownership to removable state.

The local qualification route, and any later separately approved batch using it, requires the installed pinned Kata configuration to be exactly `shared_fs = "virtio-fs"`. A copy path, disabled sharing, 9p, guest fetch, mutable host work bind, block-image substitution, rootfs change, alternate mount list, or automatic fallback is forbidden.

## Qualification gates

Before this route can support readiness or campaign evidence, authoritative Linux-amd64, EUID-0, KVM qualification on the pinned versions must prove:

- `storedSpec.mounts` equals the canonical eleven-entry array and its defined SHA-256 digest, while the remaining stored spec passes separate fixed checks;
- guest mountinfo shows default `/run`, the bounded nested parent tmpfs, and three distinct read-only children with required security semantics;
- `/run/sshd` and `work` have the fixed owner/mode before SSH, and the PID file is created only by the exact `sshd`;
- writes, renames, links, metadata changes, and child creation against every input fail, while fixed work operations succeed;
- file binds are regular files with exact metadata/content and fixture input matches its manifest;
- only the three enumerated source objects are guest-visible, including the intentionally exposed server key, while every forbidden host-private object is absent;
- the rootfs graph and pins remain unchanged, strict authenticated SSH and fixed Git/package workloads pass; and
- normal, startup-failure, timeout, interrupt, and recovery paths complete the exact teardown and prove zero task, container, QEMU, shim, virtiofsd, namespace, network, firewall, Kata share-path, host mount, host-input/control, and rootfs-lease residue.

Failure of ordered nesting, regular-file sharing, read-only enforcement, option enforcement, exact lifecycle observation, or zero-residue cleanup is a stop condition. One exact read-only seed-directory bind beneath the same parent tmpfs may be proposed only by a later reviewed decision; it is not an automatic fallback.

Disposable privileged Docker may functionally test generic ordered tmpfs and nested bind behavior and host-manifest ownership, but remains explicitly nonauthoritative. It cannot qualify containerd/Kata spec construction, virtiofs, guest agent behavior, KVM, QEMU-bound lifetime, network cleanup, or campaign readiness.

## Scope, accounting, staging, and non-authority

This decision replaces ADR 0042's 420–650-line host-mount slice with a 320–500-line fixed input/control owner. The Kata lifecycle range becomes 1,500–2,300 lines. Revised remaining implementation is 4,370–6,740 lines, yielding a projected cumulative 15,225–17,595 from the unchanged 10,855-line baseline. ADR 0042's preferred 17,500 and hard 19,000 cumulative caps, counting method, remeasurement gate, and anti-evasion rule remain unchanged.

ADR 0042's staged remeasurement sequence is retained except step 1 becomes: “fixed host input/control ownership, retained verified rootfs lease, canonical eleven-entry mount-list construction, and static/fake validation.” Steps 2–7 remain in order. Kata lifecycle implementation and authoritative stored-spec, guest-mountinfo, and cleanup qualification occur in step 2, with a stop before step 3 unless every gate passes.

Every other ADR 0038–0042 requirement remains binding, including exact immutable inputs and packages, deterministic rootfs and fixtures, closure and candidate pinning, standalone strict SSH, `/30` networking, immediate sample cleanup, exact-owned lifecycle recovery, seven sequential cycles, expiry, cost, strict evidence, and separate authoritative qualification.

This decision grants no AWS CLI, provider, OpenTofu, workflow-dispatch, deployment, campaign, release, or production authority. Local implementation may proceed, but the AWS gate remains closed until Nick Byrne separately approves one exact named batch.
