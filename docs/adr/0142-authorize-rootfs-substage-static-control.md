# ADR 0142: Authorize rootfs-substage static control

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-23

Exact implementation H `e2854b30549ade94e34755dddc0fb2c83f4dacc0` adds only typed bounded rootfs acquisition substages and their fault matrix under ADR 0141. Exact-head CI and hostile review passed. Because selected H bytes changed, authorize one no-KVM static-control observation.

Extend authenticated static history with successful run `32620087277`, attempt 1, workflow head `0c4c698ed7c8a4d28f350293102012a1dd9d869c`, reviewed H `4bced3fb4b768f5dc67f919ae8d579059739b126`. Update the exact embedded v18 guard and static runtime-boundary digest. Every outcome consumes the observation.

This grants no KVM claim by itself and no AWS/API/credential/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
