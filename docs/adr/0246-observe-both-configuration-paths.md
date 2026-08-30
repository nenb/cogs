# ADR 0246: Observe both configuration paths

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Path diagnostic run `33297568251`, attempt 1, proved every fixed-source active-configuration ancestor is root-owned mode 0700, so the rejection occurs on the separate immutable base configuration path under `/opt/kata`. Cleanup passed and no qualification claim exists.

Extend the same bounded identity output to both reviewed configuration paths and no others. Preserve read-only validation, descriptor close, exact cleanup, and all no-lifecycle/no-provider restrictions.

This decision raises only the complete tracked-source cardinality bound from 1,207 to exactly 1,208 files. Authorize one final path-identity diagnostic; it grants no AWS, provider, deployment, campaign, production, release, qualification, retry, or promotion operation.
