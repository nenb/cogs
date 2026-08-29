# ADR 0208: Remove the exact empty Kata overhead cgroup

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

Independent settlement after both H51 and H52 found no runtime processes but retained `/sys/fs/cgroup/kata_overhead/kata_cogs-stage2-ssh-v1`. The leaf and parent were empty and were the only Kata-overhead cgroups. This residue would directly prevent the required independent zero-cgroup verdict.

After durable successful CTR_RUN history and exact runtime retirement identify the deterministic Kata runtime leaf, daemon cleanup now opens the cgroup root, requires the exact singleton Kata-overhead leaf, holds and generation-checks the leaf, and proves its member census empty twice. It removes that leaf fd-relatively, requires the held parent to have no children or members, refreshes only the parent generation changed by the authorized child removal, then removes the parent fd-relatively. Foreign siblings, population, replacement, or any removal difference preserve uncertainty.

The Linux AMD64 supervisor, root-cgroup crash, retained-daemon runtime-leaf, portable, TypeScript, formatting, and retained-line matrices pass. H51 and H52 remain private non-authoritative diagnostics and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
