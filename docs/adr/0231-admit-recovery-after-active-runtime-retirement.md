# ADR 0231: Admit recovery after active-runtime retirement

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-29

H73 confirmed the known fresh-recovery blocker: after exact forward cleanup consumes the prepared source and removes active `kata-runtime-v1`, recovery still requested ordinary forward static admission, which requires the live active observer configuration and eagerly claims every runtime executable role.

Add a distinct one-shot recovery static issuer. It authenticates the same reviewed control package and complete fixed source. If the active configuration exists, ordinary exact live configuration custody remains required. If it is absent, derive the expected active bytes from the exact held base configuration and require a stable descriptor-held census proving the sole `kata-runtime-v1` child absent; preserve only a digest-bound retired configuration proof. Recovery opens a lazy static executable owner, so journal parsing precedes role-specific cleanup claims and removed containerd/ctr paths are never reopened unless the durable phase actually requires them. The owner is recorded for exact abort, and lazy-owner abort discards its internal static-custody marker before closing claimed descriptors.

No absent pathname is recreated or adopted. Any malformed, replaced, live-but-unopenable, unstable, foreign, or phase-inconsistent state fails closed. Recovery remains cleanup-only and cannot issue evidence or success receipts.

Focused admission, process, runtime, bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. Native confirmation remains required.

This grants no AWS, provider, deployment, campaign, production, release, qualification, or promotion authority.
