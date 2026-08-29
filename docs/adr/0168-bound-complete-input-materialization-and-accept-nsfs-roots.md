# ADR 0168: Bound complete input materialization and accept nsfs roots

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

After indexed legal validation, a fresh private observation completed all 3,282 input records and exact graph materialization in approximately 24 minutes. The complete pre-runtime path requires more than the former 3,470-second step once deterministic rootfs construction and four measured rootfs verifications are included. Exact graph verification then rejected Linux `nsfs` mountinfo rows whose kernel-defined root is `mnt:[namespace-id]` rather than a pathname.

Raise the enclosing full lifecycle command to 4,500 seconds and its workflow step/job arithmetic only. No sub-operation deadline or retry changes. In mountinfo, continue to require an absolute mountpoint; permit a non-absolute root only for exact `nsfs nsfs` rows with `mnt:[positive-decimal]` grammar. Such a pseudo-root cannot equal or descend from the absolute fixed input source. All malformed pseudo-roots and any source match remain failures.

This grants no omitted record, batching, removed fsync, retry, AWS, provider, deployment, evidence, promotion, or release authority.
