# ADR 0218: Read retired phase from the existing cleanup capability

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H62 completed `RETIRE_INTENT` and `RETIRED`. Operation removal then asked for the durable phase through an already issued `CleanupAuthority`, but the public wrapper attempted to claim a new non-retired cleanup capability and correctly rejected the now-retired phase.

When `durable_phase` receives an existing sealed `CleanupAuthority`, read through that authority directly. Original production authorities still pass through the full production claim path. This does not create or upgrade a capability: the cleanup authority remains registered to the same retained operation, its method still performs exact durable reload and validation, and retired journal removal still requires `RETIRED`, exact generation, unlink, and absence readback.

Focused operation, coordinator, local-result/schema, TypeScript, formatting, and retained-line matrices pass. H62 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
