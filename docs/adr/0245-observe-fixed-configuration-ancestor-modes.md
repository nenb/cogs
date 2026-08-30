# ADR 0245: Observe fixed configuration ancestor modes

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Refined diagnostic run `33296412533`, attempt 1, proved that exact control-package and complete-source validation pass and that rejection occurs while retaining the active observer configuration. Cleanup again passed and the run grants no qualification or replacement claim.

Before repeating the unchanged configuration validator, emit the bounded fixed path, uid, gid, and mode of only the root-owned ancestors under `/var/lib/cogs` leading to the reviewed active configuration. Do not read arbitrary paths or file contents, and retain all no-lifecycle, no-KVM, cleanup, and no-provider restrictions.

This decision raises only the complete tracked-source cardinality bound from 1,206 to exactly 1,207 files. Authorize one path-identity diagnostic observation; it grants no AWS, provider, deployment, campaign, production, release, qualification, retry, or promotion operation.
