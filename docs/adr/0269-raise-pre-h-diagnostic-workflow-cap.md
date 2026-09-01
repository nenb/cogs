# ADR 0269: Raise the pre-H diagnostic workflow cap

- Status: Accepted
- Date: 2026-08-31
- Accepted by: Nick Byrne through the explicit instruction to implement the pre-H diagnostic supply chain and authentic no-mint KVM rehearsal, updating the line cap through a measured ADR if required

## Context

At the ADR 0268 implementation head, measured no-deletion-credit additions are 17,522 deployment lines, 8,641 retained schema/script lines, 2,727 workflow lines, and 28,890 global lines. Current physical total is 81,035 and conservative total is 84,244. The deployment, retained, global, preferred-total, hard-stop, and tracked-file limits can hold the mapped pre-H diagnostic slice, but the 3,000-line workflow high leaves only 273 lines.

The required identities cannot share the final producer or publisher workflow path because doing so could consume final first-created authority. The bounded implementation therefore needs separate diagnostic producer and publisher entries plus one separately guarded two-route no-mint rehearsal entry. Measured existing owner workflows are 184 producer lines and 273 publisher lines; the new rehearsal is bounded to 350 lines. Even with reuse of existing fixed owner scripts, that 807-line workflow slice cannot fit the remaining 273 lines.

## Decision

Raise only the correction workflow high from 3,000 to 3,700 lines. Retain the 19,500 deployment, 9,500 retained schema/script, and 32,000 global highs, the 90,000 preferred total, 94,000 hard stop, and 1,300 tracked-source bound.

The added capacity is restricted to distinct pre-H diagnostic producer/publisher identities, immutable signed publication and exact readback, provisional directional-control custody, one first-created attempt-one rehearsal containing exactly one full-route and one readiness-route lifecycle, cleanup-only recovery, residue enforcement, and source-shape/hostile tests. It cannot fund final producer/publisher history consumption, qualification receipt or evidence issuance, AWS/provider/SSM/credential activity, retry, replacement, or promotion.

## Post-implementation measurement

The completed slice measures 17,522 deployment, 8,795 retained schema/script, 3,470 workflow, and 29,787 global no-deletion-credit added lines. Physical total is 81,932 and conservative total is 85,141. All unchanged highs, the new 3,700 workflow high, preferred total, and hard stop remain satisfied.

## Consequences

The diagnostic observations remain non-authoritative and cannot freeze H or G. Failure, cancellation, rerun, stale input, uncertain cleanup, or residue makes the singular rehearsal non-authorizing. Formal qualification and all AWS boundaries from ADR 0267 remain unchanged.
