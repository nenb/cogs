# ADR 0206: Remove the empty runtime cgroup before the daemon base

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H51 completed network, container, share, and firewall cleanup. Containerd exited cleanly, but removing its cgroup base returned `EBUSY` because the deterministic empty `kata_cogs-stage2-ssh-v1` leaf remained.

Before settling the retained daemon cgroup, use the successful durable CTR_RUN predicate to require exactly the retained daemon leaf and deterministic runtime leaf under the unchanged held base. Open and generation-check the runtime leaf, prove its member census empty twice, remove it fd-relatively, and require the remaining leaf set to contain only the daemon. Any population, replacement, foreign leaf, or removal difference preserves uncertainty.

The Linux supervisor, root-cgroup crash, retained-daemon, runtime-leaf, and portable matrices pass. H51 reached a durable FREE NFT owner and physical network/firewall absence; its remaining state was preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
