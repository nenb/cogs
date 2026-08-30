# ADR 0177: Start command deadlines after read-only runtime custody

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

The accelerated H20 replay crossed the corrected runtime-mount boundary and reached the pre-launch `CTR_CONTAINER_LIST` probe. That five-second observer expired before release because its deadline was created before complete retained-rootfs, input, network, daemon, and executable custody verification. The rootfs check alone takes roughly 38 seconds in the diagnostic stable route and roughly 138 seconds in strict mode. A separate reviewed-binary native probe showed containerd's socket and first successful `ctr containers list` response in approximately 103 ms and 134 ms respectively; containerd readiness was not the cause.

Perform all expensive, read-only runtime custody verification before creating the command's absolute deadline or durable intent. After the deadline begins, retain the existing write-ahead intent/preexec ordering, child and cgroup census, daemon revalidation, release, bounded work window, reverse cleanup, output capture, and durable outcome. No mutation or child launch moves before the intent.

The native retained-daemon matrix now includes a three-second custody delay against a five-second observer. It proves that prerequisite time does not consume the execution deadline, while foreign-child, foreign-cgroup, and post-fork cuts remain denied. Synthetic memfd generations are normalized only inside that test route; production generations remain unchanged.

H20 failed and grants no qualification or promotion claim. Its exact retained state was privately settled and independently checked for residue before the native probe.

This decision grants no retry within an observation, production fast path, evidence, promotion, AWS, provider, deployment, or release authority.
