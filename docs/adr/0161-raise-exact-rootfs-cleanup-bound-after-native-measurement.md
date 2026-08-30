# ADR 0161: Raise exact rootfs cleanup bound after native measurement

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

After removal of the redundant terminal reparse, a second clean native observation deleted all 4,353 entries and the candidate tar, then durably settled the candidate manifest at the 600-second cleanup boundary. It had not yet removed the now-empty operation directory. A prior observation completed that final transition, demonstrating bounded timing variance rather than foreign state, retry, or additional build work.

Raise one exact cleanup/recovery pass from 600 to 720 seconds. The additional 120 seconds applies only after build work has terminally settled or to cleanup-only recovery. Keep the 900-second build/materialization bound, single materialization, per-entry ledger/fsync semantics, no retry, and fixed ownership checks unchanged. Expose the same 720-second ceiling in the formal workflow and raise only its enclosing step/job arithmetic. Cleanup that does not finish remains uncertainty and produces no artifact.

This supersedes ADRs 0047, 0159, and 0160 only for the numeric cleanup/recovery maximum. It grants no AWS, provider, deployment, evidence, promotion, or release authority.
