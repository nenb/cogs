# ADR 0185: Accept exact Kata TAP and nested virtiofsd shapes

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H27 advanced through certain launch, `RUNTIME_READY`, and all four post-launch host/namespace link and address observations. Native Kata 3.32 then exposed three representation facts that older offline fixtures did not contain.

First, `ip -j -d` reports Kata's TAP as a root-owned persistent, multi-queue tun object with one enabled queue and zero disabled queues. Accept that complete exact dictionary in addition to the immutable historical fixture shape; changed users, groups, queue counts, booleans, or extra/missing fields remain denied.

Second, `/proc/<pid>/exe` descriptors report mount IDs from each process's mount namespace. Those IDs are not comparable to the host-namespace mount ID retained before launch. Require every other generation field, backing device/inode, mode, ownership, links, size, timestamps, digest, executable pathname, command line, and namespace correlation to remain exact; do not equate namespace-relative mount IDs.

Third, this virtiofsd version retains an outer launcher directly parented by the exact shim and an inner worker parented by that launcher in a distinct PID namespace. Admit and collapse the worker only after verifying identical attested executable identity, digest, command line, start ordering, and equal IPC/mount/network/user/UTS namespaces with a distinct PID namespace. Any partial, duplicate, or changed relationship remains `PRESERVE`; durable role ownership continues to name the outer launcher.

Portable hostile tests cover the native TAP dictionary, changed ownership, mount-ID-only executable equivalence, changed backing identity, and exact versus hostile nested-worker relationships. The native root network and retained-daemon matrices pass. H27 remains diagnostic-only and was independently cleaned to zero residue.

This decision grants no qualification claim, production fast path, AWS, provider, deployment, campaign, or release authority.
