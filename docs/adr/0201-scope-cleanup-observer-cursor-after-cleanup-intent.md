# ADR 0201: Scope the cleanup observer cursor after cleanup intent

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H46 confirmed the pre-removal netns prefix but showed that a cursor beginning at the last runtime snapshot also includes three earlier causal `NFT_TABLE` observations. Teardown identity observation must start after the durable `NETWORK_CLEANUP_INTENT_V2`, where the exact source sequence is `MOUNTINFO`, `NETNS_STAT`, followed by the complete runtime-network pass. Forward observation continues to start after the runtime snapshot.

The cursor marker now changes only for teardown, and the complete cleanup source set remains bound into the identity. H46 and its uncertain cleanup state were preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
