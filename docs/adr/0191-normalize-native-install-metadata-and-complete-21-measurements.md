# ADR 0191: Normalize native install metadata and complete 21 measurements

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

Focused execution against H33's live, non-authoritative VM established the complete guest boundary. Exact SSH authentication, all eight network markers, seven Git samples, seven deterministic package builds, and seven install samples completed successfully, producing all 21 measurements with exact deletion markers.

Two install representations required correction. Native dpkg attempts its default `/var/log/dpkg.log` under the read-only guest root and emits a warning despite a successful isolated install. Set its fixed log path to `/dev/null`; stdout, status-database fields, installed content, package identity, and cleanup remain independently exact. Dpkg also updates installed directory timestamps while extracting. Normalize the isolated installed tree after dpkg to the already reviewed root ownership, 0755/0644 modes, and `SOURCE_DATE_EPOCH`, then run the complete metadata and content verification again. This affects only the disposable per-sample install root.

Containerd appends the explicitly added `CAP_NET_ADMIN` after its default capability list. Bind that exact native order. Native multi-queue qdisc ownership includes both the `mq` root and its `fq_codel` child in addition to ingress; include all five guest/TAP qdisc records in the exact runtime difference.

The final focused guest run exited zero in approximately 210 seconds, emitted no stderr, returned eight network markers and 21 parseable samples, matched the pinned DEB and installed-tree identities, and proved every sample deleted. It remains diagnostic-only and minted no qualification. The V3 stdin, source/config hashes, immutable fixture, and SSH policy digest were updated again; historical V1/V2 bytes remain unchanged.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
