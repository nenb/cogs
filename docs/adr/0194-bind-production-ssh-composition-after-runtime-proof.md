# ADR 0194: Bind production SSH composition after runtime proof

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H38 completed real runtime proof and reached production SSH composition. The SSH owner still admitted only historical pre-runtime phases, while the fixed coordinator intentionally authenticates only after `RUNTIME_READY`. Require that exact phase. No earlier phase remains accepted.

The automatic failure recovery timed out after preserving uncertainty. Diagnostic state was retained, the task/container/daemon/VM/network/cgroups and mounts were independently identity-checked and removed, and the ACTIVE NFT state was preserved before its exclusively locked files were discarded solely to reset private diagnostic infrastructure. H38 minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
