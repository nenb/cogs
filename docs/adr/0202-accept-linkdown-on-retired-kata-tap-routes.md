# ADR 0202: Accept linkdown on retired Kata TAP routes

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H47 completed the corrected cleanup cursor and reached runtime-network identity derivation after task and VM retirement. Native Linux adds `linkdown` to the TAP's IPv6 `fe80::/64` and multicast routes once QEMU closes the TAP while the exact retained interface still exists.

Allow exactly that flag on those two TAP routes only during teardown identity observation. Forward runtime observation still requires no route flags; the TAP local route remains unchanged; every route, interface, address, qdisc, filter, mount, netns, and NFT identity remains complete and exact.

H47 and its uncertain cleanup state were preserved before exact diagnostic cleanup. It minted no qualification.

The prior temporary worktree was also moved to a stable home-directory clone after macOS pruned its `/private/tmp` metadata; committed history and the two uncommitted corrected files were recovered exactly before tests resumed.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
