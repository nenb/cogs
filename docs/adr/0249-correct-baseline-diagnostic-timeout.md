# ADR 0249: Correct the baseline diagnostic timeout

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Baseline diagnostic run `33302371137`, attempt 1, timed out at its inherited two-minute static-observation step while performing the intentionally unchanged dual rootfs acquisition, which the formal run measured at roughly 32 minutes. It emitted no baseline observation, performed final cleanup, and grants no claim.

Set only the diagnostic observation step to 70 minutes within its existing 90-minute job bound and line-buffer bounded stage output so progress survives a timeout. Keep every production and qualification deadline unchanged. Authorize one corrected baseline diagnostic observation.

This decision raises only the complete tracked-source cardinality bound from 1,210 to exactly 1,211 files. It grants no AWS, provider, deployment, campaign, production, release, qualification, retry, or promotion operation.
