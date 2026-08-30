# ADR 0240: Raise the portable supervisor test window from hosted measurement

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

PR 439 run `33288063443` failed only the synthetic portable rootfs-supervisor matrix while all Linux foundations, images, secrets, and other quality tests passed. The hosted test consumed 13.4 seconds across 21 cases and one child did not complete within the 500-millisecond per-phase synthetic scheduling window. Eight simultaneous local matrices passed, so there is no evidence of a production supervisor defect or deterministic protocol failure.

Raise only that portable test's acquisition and build windows to one second each and its outer test-process bound from 30 to 45 seconds. These bounds cover the observed hosted scheduling demand, remain finite, and leave every production acquisition, preparation, cleanup, recovery, journal, and lifecycle deadline unchanged. The failed run grants no review, qualification, retry, or promotion claim; validate the correction through a fresh commit and attempt-1 CI observation.

Recording this superseding decision raises the complete tracked-source cardinality bound from 1,200 to exactly 1,201 files. Keep the complete inventory, three explicit generated-evidence exclusions, 4 MiB per-file bound, 18 MiB aggregate bound, canonical ordering, pinned Git identity, and no-symlink/single-link policy unchanged.

This correction does not alter frozen implementation H, static-control authority, or any AWS, provider, deployment, campaign, production, release, qualification, or promotion boundary.
