# ADR 0209: Bind Kata overhead to the exact container ID

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H53 reached the new Kata-overhead cleanup and preserved uncertainty because ADR 0208 initially reused the private containerd runtime leaf name, `kata_cogs-stage2-ssh-v1`. Native Kata instead created the overhead leaf from the exact OCI container ID, `cogs-stage2-ssh-v1`, under `/sys/fs/cgroup/kata_overhead`.

Keep the successful-runtime predicate from ADR 0208, but derive the overhead leaf independently as the exact pinned container ID. All singleton-parent, held-descriptor, generation, double-empty-census, and fd-relative removal requirements remain unchanged. A focused retained-state execution removed exactly the H53 overhead leaf and parent; independent settlement then returned zero residue. The full Linux supervisor, root-cgroup crash, retained-daemon, portable, TypeScript, formatting, and line-bound matrices pass.

H53 remains a private non-authoritative diagnostic and minted no qualification. This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
