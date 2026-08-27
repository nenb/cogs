# ADR 0204: Normalize DHCP lease countdown in the host baseline

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H49 completed tokenized network removal and then compared the complete host baseline. The only host-address difference was the Wi-Fi DHCP lease countdown: `valid_life_time` and `preferred_life_time` decreased from 65096 to 63469 while the interface, address, prefix, scope, flags, and every other field remained identical.

Normalize only those two nonnegative, ordered 32-bit metrics on addresses explicitly marked `dynamic: true`. Address identity and every other complete field remain hashed; permanent address lifetimes remain exact; malformed or inverted leases fail closed. This matches the existing treatment of bridge timer and NFT counter metrics and makes a long lifecycle comparable without hiding address replacement.

H49 and its uncertain post-network-removal state were preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
