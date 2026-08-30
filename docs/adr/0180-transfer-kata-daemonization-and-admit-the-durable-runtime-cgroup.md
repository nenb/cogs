# ADR 0180: Transfer Kata daemonization and admit the durable runtime cgroup

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

The H23 replay passed the retained-containerd probe and launched a real Kata VM. It observed the exact fixed container, containerd-shim-kata-v2, virtiofsd, QEMU/KVM process, and runtime-created cgroups. The `ctr run` command supervisor nevertheless failed closed because its process-wide subreaper adopted Kata's deliberately daemonized shim and classified that persistent runtime process as an unrelated command child.

For `CTR_RUN` only, temporarily disable command-supervisor subreaping before fork/release and restore the prior state after bounded command settlement. The persistent shim reparents to PID 1 and is subsequently inventoried by the independent runtime owner; ordinary commands retain subreaping and must still reap all command descendants.

Kata also creates the deterministic `kata_cogs-stage2-ssh-v1` cgroup below the already authenticated private containerd base. Admit that one exact name only after a durable `CTR_LAUNCH_ISSUED_V1` record. Before launch, after runtime cleanup, or under any different name, the existing exact leaf census remains fail closed. The external deterministic `kata_overhead/cogs-stage2-ssh-v1` residue remains runtime-cleanup state and is not absorbed into command ownership.

The root Linux retained-daemon matrix proves the extra leaf is denied before durable launch, admitted after the durable launch predicate, and does not weaken foreign-leaf rejection. H23 remains diagnostic-only and grants no qualification claim. Its task, container, QEMU, shim, virtiofsd, cgroups, daemon, network, mounts, roots, and aliases were removed and independently residue-checked.

This decision grants no production fast path, retry claim, AWS, provider, deployment, campaign, or release authority.
