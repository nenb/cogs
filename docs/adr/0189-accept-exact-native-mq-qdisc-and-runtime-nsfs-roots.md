# ADR 0189: Accept exact native mq qdisc and runtime nsfs roots

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H31 validated the complete native address/routes and stored OCI normalization, then reached qdisc and runtime share observation.

For the admitted multi-queue TAP, accept exactly three qdisc rows in order: an `mq` root with empty options, its `fq_codel` child at parent `:1` with the already pinned native option dictionary, and the existing exact ingress qdisc. Preserve historical noqueue and root-fq_codel profiles. Any changed count, parent, handle, options, or ordering remains denied.

Runtime share observation reads complete host mountinfo, which includes root-owned nsfs mounts outside the Kata share. As already established for preparation/input census, accept mount roots only when they are exact positive-decimal `mnt:[inode]` or `net:[inode]` forms and both filesystem type and source are exactly `nsfs`. Mountpoints remain canonical absolute paths. Other prefixes, zero/malformed inodes, changed sources/types, and all other non-path roots remain denied.

Portable hostile matrices and the root Linux network matrix pass. H31 remained diagnostic-only and was independently cleaned to zero residue.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
