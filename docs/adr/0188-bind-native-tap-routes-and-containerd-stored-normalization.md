# ADR 0188: Bind native TAP routes and containerd stored normalization

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H30 completed the discovered runtime link/address snapshot and all subsequent route, qdisc, filter, mount, namespace, and nft observer commands. Two exact native representations remained.

For an admitted EUI-64 TAP, require the complete IPv6 route additions: the kernel `fe80::/64` unicast route, the local route for the exact MAC-derived address, and the TAP multicast route, with exact tables, protocols, metrics, flags, and preference. Historical no-addrgen TAP route sets remain unchanged. Missing, duplicate, extra, or changed routes fail closed.

Containerd 2.2.1 stores a deterministic normalized OCI document rather than byte-for-byte source JSON. Admit either the historical source form or the complete native normalization. The native form is derived from the reviewed candidate and requires the durable `CTR_RUN` intent's exact rootfs path as well as its preexec namespace-fd path. It exactly binds containerd's default device list and CPU shares, cgroup path, added powercap mask, dropped defaults, reduced capability sets, canonical one-line bootstrap, absolute root path, `noNewPrivileges=true`, null labels, and empty sandbox ID. Any changed field remains denied. The rootfs binding is no longer inferred from the unrelated operation-journal token.

Focused native diagnostics validated the complete observed address/route set and the actual stored JSON against these derivations. Portable hostile tests cover changed EUI address, route omission, CPU shares, backing root, and launch binding. H30 remained diagnostic-only and was independently cleaned to zero residue.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
