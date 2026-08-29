# ADR 0216: Preserve retired rootfs-ledger infrastructure

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H60 authorized rootfs release, removed the exact leased rootfs operation, proved no `operation-*` rootfs residue, and appended `ROOTFS_ABSENT`. Post-append layout validation incorrectly required the shared `rootfs-v1` ledger directory itself to be absent. The rootfs owner intentionally preserves that directory with exactly its state sentinel and lock after removing the ledger and leased operation; independent residue classification likewise treats only `rootfs-v1/operation-*` as rootfs residue.

Require the reviewed `rootfs-v1` infrastructure name to remain present while the Kata operation journal exists, including `ROOTFS_ABSENT`, final baselines, and journal retirement. Exact leased-operation absence continues to be established by `_kata_authorized_absence`: only state sentinel and lock may remain, no ledger or operation may remain, and their held generation and authorization binding feed the absence proof. This does not admit a retained rootfs operation or weaken independent residue checks.

Focused operation, the 225-case rootfs lease matrix, coordinator, TypeScript, formatting, and retained-line checks pass. H60 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
