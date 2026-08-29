# ADR 0181: Admit exact containerd accepted Unix sockets

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

H24 completed `CTR_RUN` successfully and launched the real Kata shim, QEMU/KVM, and virtiofsd. The retained containerd verification then failed because Linux reports containerd's accepted persistent ttrpc connection with the listener pathname in `/proc/net/unix`. The original verifier required the pathname to occur only on the listening row, a condition true before the first client but false while a real runtime is active.

Continue requiring exactly one root-owned, link-count-one filesystem socket and exactly one listening Unix-table row with the retained listener inode. Additionally admit at most 64 distinct connected stream rows for that exact pathname, only in the exact Linux connected state, and require every listener and accepted inode to occur exactly once among the retained containerd process's descriptors. Rows of any other type, state, path, syntax, cardinality, ownership, or descriptor custody remain denied. Only the listener identity enters the durable daemon identity.

The root native retained-daemon matrix now creates and retains a real accepted Unix connection, proves verification while it is active, and continues to exercise foreign process/leaf failures. H24 remains diagnostic-only. Its task, container, VM processes, daemon, cgroups, network, mounts, roots, and aliases were removed and independently residue-checked.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
