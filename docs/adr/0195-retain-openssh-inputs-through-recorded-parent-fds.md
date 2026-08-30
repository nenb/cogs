# ADR 0195: Retain OpenSSH inputs through recorded parent FDs

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H39 reached the first production SSH transaction. Native OpenSSH closes inherited descriptors before resolving `IdentityFile` and `UserKnownHostsFile`, so `/proc/self/fd/200` and `/proc/self/fd/201` were unavailable and SSH exited before consuming stdin.

Retain exact, non-inheritable duplicates at fixed parent descriptors 1000 and 1001 for the transaction duration. The fixed SSH argv uses `/proc/{command-parent-pid}/fd/1000` and `/proc/{command-parent-pid}/fd/1001`; the placeholder is resolved only in the child, and the durable preexec already records and binds that exact parent PID. Child descriptors 200/201 are still installed, identity-proved before release, and closed by OpenSSH; the parent paths expose the same revalidated generations without a mutable filesystem pathname. Occupied fixed parent descriptors fail closed, and all duplicates close in transaction settlement.

The portable, Linux supervisor, root-cgroup crash, and retained-daemon matrices pass, including a native child opening both exact parent paths. H39 and its uncertain NFT state were preserved as diagnostic evidence before exact manual residue cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
