# ADR 0170: Census named nsfs descriptors by identity

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

The fast private Linux network fixture proved that an open descriptor to a still-named or quarantined `/run/netns/...` bind mount is rendered by procfs as that pathname, not `net:[inode]`. The production process census considered only `net:[inode]` fd links, so it could omit exact runtime-owner and launch-duplicate holds before namespace-name retirement.

For fd links rendered as `net:[inode]`, retain the exact grammar and target checks. Also inspect fd links under `/run/netns/`, including deleted suffixes, and count them only when opening the proc fd proves the exact expected nsfs device and inode. A pathname with any other identity is unrelated and grants no ownership. The two-pass stable process and fd census remains unchanged.

This closes an absence-proof gap without adopting a pathname identity. It grants no retry, caller-selected namespace, AWS, provider, deployment, evidence, promotion, or release authority.
