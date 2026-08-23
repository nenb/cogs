# ADR 0141: Refine rootfs acquisition diagnostic

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-23

Run `32622048772`, attempt 1, passed admission and immutable preparation, then emitted the bounded H diagnostic `rootfs-acquire`. Recovery, fixed cleanup, independent residue, and output cleanup passed; no artifact was produced. Private custody SHA-256 is `b740f1158d04f065167b3eca7163ccd5271b514b5a5fa72caacf4e4ef489a6fa`.

Refine only the rootfs acquisition primary with a typed, fixed allowlist covering pins, first build, second build, equality, pin check, topology, lease mark, and lease verification. Keep the stage on the typed primary and map it into the lifecycle-bound terminal diagnostic. Never render underlying exception text, tokens, paths, build bytes, or cleanup errors. Preserve all existing cleanup and sticky-uncertainty behavior.

The typed wrapper and direct fault matrix raise the measured integrated operation/rootfs ownership count from 3,159 to 3,188 lines. Raise that local enforced bound only from 3,170 to 3,220; all global correction and hard bounds remain independently enforced.

This diagnostic H change requires another exact static-control cycle before a distinct local observation. The correction does not assert which substage failed and grants no qualification claim. The owner's standing non-AWS authorization permits this bounded diagnosis cycle.

This grants no AWS/API/credential/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
