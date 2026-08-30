# ADR 0176: Bind runtime mount before launch and accelerate private replays

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

H19 confirmed that descriptor-held ancestor refresh works: all six complete rootfs checks passed, including the post-containerd sibling-staging check. It then failed while recording `RUNTIME_MOUNT_V2`. The coordinator intentionally binds the exact input mount before `CTR_RUN`, while the journal validator incorrectly required phase `RUNTIME_READY`, which is reached only after successful `CTR_RUN`. This made the required pre-launch ordering impossible.

Admit the sole runtime-mount record at `NETWORK_READY`, with no command pending. When a production runtime was staged, also require the retained containerd daemon identity. Preserve one-shot issuance, exact input-manifest binding, exact mount generation, and the later requirement that SSH/runtime evidence bind that record. Tests now reject duplicate and post-`RUNTIME_READY` insertion.

Subsequent private diagnostics use a separate `/tmp`-resident, non-authoritative accelerator. It performs one complete retained-rootfs verification, uses stable retained-lease checks thereafter, elides Python-process fsync calls, and replaces the receipt boundary with a forced diagnostic-only exit. It may locate downstream defects but can never mint a result. Production and the one final strict replay retain every fsync and complete verification.

H19 failed and grants no qualification or promotion claim. Its retained daemon, cgroup, tokenized network, fixed roots, and private parent mount were identity-checked, removed, and independently checked for zero residue.

This decision grants no production fast path, retry within an observation, evidence, promotion, AWS, provider, deployment, or release authority.
