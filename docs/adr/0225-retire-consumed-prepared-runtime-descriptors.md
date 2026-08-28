# ADR 0225: Retire consumed prepared-runtime descriptors

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H69 completed observer-configuration retirement but still reported only runtime-marked descriptors. The remaining exact owner is the consumed prepared-runtime custody: static admission retains the immutable source-tree `deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1` ancestors, directories, configuration, containerd, and ctr descriptors separately from executable roles and the active deployed configuration.

At the same post-final-baseline boundary, require exactly one prepared-runtime claim belonging to static custody and require it to be consumed. Reopen and revalidate the sole immutable prepared source tree against its original facts, then require every original prepared descriptor to be unique and present in static custody. Remove the claim and descriptors from custody and close them together with the executable-role and observer-configuration descriptors. Missing, unconsumed, changed, foreign, duplicate, or unstable prepared custody fails closed, and whole-custody abort cannot double-close retired descriptors.

Focused admission, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. H69 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
