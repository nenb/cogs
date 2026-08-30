# ADR 0257: Add bounded terminal trace location

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Consumed-receipt diagnostic run `33331563533`, attempt 1, reproduced the terminal failure with exact final H/G and completed exact recovery and scaffolding cleanup. The cause chain narrowed the failure to `LocalEvidenceError` during the transactional receipt derivation, but that internal invariant intentionally uses a generic message. Nothing was minted or published and the run grants no claim.

For one replacement diagnostic, emit at most the final eight traceback frames per bounded cause and only when the source path is beneath the fixed authenticated source root. Emit basename, line number, and function name; emit no source line, locals, arguments, report bytes, journal bytes, paths outside the fixed root, or environment. Preserve the existing bounded cause count, immediate receipt consumption, no publication, and exact cleanup.

PR observation `33337136817` failed only because the unrelated portable recovery fixture's selected `pidfd-close-before-effect` cut did not fire exactly; its other jobs and complete Linux foundations observation `33337136794` passed. A fresh local execution of the exact portable hostile suite passed all five gates. The failed PR observation grants no claim and does not alter this diagnostic.

Authorize exactly one replacement terminal diagnostic. Raise only the complete tracked-source cardinality bound from 1,218 to exactly 1,219 files and retain all other bounds. This grants no qualification, retry claim, AWS, provider, deployment, campaign, production, release, or promotion operation.
