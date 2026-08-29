# ADR 0172: Correct post-runtime-removal recovery and native fixtures

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

The complete local suite and fast native shards exposed stale test assumptions after additive runtime-preparation and cleanup corrections. Native operation fixtures omitted the prepared `kata-runtime-v1` generation during active phases and retained it during rootfs-absent phases. Synthetic memfds on this kernel use mount ID zero, which is valid for the test issuer but not a durable operation-journal host generation. The runtime-removal crash fixture also modeled `SHARE_ABSENT`, although daemon-tree removal now occurs after durable `FIREWALL_ABSENT`.

Align fixtures with the reviewed lifecycle, normalizing only synthetic journal generations to a positive test mount ID. In production recovery at `FIREWALL_ABSENT`, inspect the exact completion directory generation. If `kata-runtime-v1` remains, reconstruct the complete runtime owner. If it is absent after a crash following exact daemon shutdown, skip complete runtime reconstruction and use the existing daemon-only absence settlement route. No pathname is adopted; the completion directory remains descriptor-held and stably enumerated.

This preserves crash recovery after the runtime tree has already been removed. It grants no retry, production fast path, AWS, provider, deployment, evidence, promotion, or release authority.
