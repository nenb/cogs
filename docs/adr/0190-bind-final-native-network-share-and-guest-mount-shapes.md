# ADR 0190: Bind final native network, share, and guest mount shapes

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H32 reached complete runtime network and ownership observation. Focused diagnostics against its live VM also authenticated the exact SSH key and host key, emitted the readiness marker, and completed the first three guest network probes.

Native `tc -j` repeats `parent:"ffff:"` on all three u32 filter rows. Accept it only when present and exact on every row; mixed or changed parents remain denied. Complete Linux mountinfo may contain stacked mounts with distinct mount IDs at one mountpoint, so require globally unique mount IDs but do not reject legitimate duplicate mountpoints outside the owned share.

Kata's bounded share is a root-owned directory tree rather than a share-root mountpoint on this host. Admit its observed root-owned directory modes 0700/0750/0755 and file modes 0600/0755 under the existing descriptor walk, depth, per-directory, total-entry, mount-correlation, and retained layout hash bounds. A populated exact bounded tree is active even without a mount exactly at its root; empty-residue cleanup still requires the retained root and parent generations.

Inside the guest, native Kata exposes key files as exact `/cogs-stage2-ssh-v1-<16hex>-<role>` virtiofs/kataShared roots and the input directory as root `/` on virtiofs source `none`. Accept those exact forms in addition to immutable historical `/mounts/<leaf>` fixtures, while preserving exact read-only/nosuid/nodev/noexec options, distinct key leaves, role suffixes, and cardinality.

The direct guest route mutation then failed because ctr 2.2.1 replaces candidate capabilities with defaults unless a capability is explicitly added. Add only `--cap-add CAP_NET_ADMIN` to the fixed `CTR_RUN` argv. The reviewed OCI candidate already requests this capability, and the native stored normalization must now retain it in bounding/effective/permitted sets while continuing to omit ambient/inheritable sets and retain `noNewPrivileges=true`. This capability is confined to the guest container network namespace; host nft default-deny remains independent and exact.

The V3 guest stdin, source/config hashes, SSH policy digest, and immutable fixture snapshot were updated additively; V1/V2 bytes remain unchanged. Portable hostile matrices pass. H32 remains diagnostic-only; no qualification was minted.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
