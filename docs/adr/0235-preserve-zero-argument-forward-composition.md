# ADR 0235: Preserve zero-argument forward composition

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-29

The full suite rejected passing a recovery boolean through the forward static-preparation composition surface. Forward composition is intentionally zero-argument and tests use that exact shape to prove callers cannot select behavior.

Keep `_claim_fixed_static_preparation()` as the historical zero-argument forward route. Add a separate package-private zero-argument `_claim_fixed_recovery_static_preparation()` route backed by the separately consumed recovery issuer. The coordinator chooses between those sealed methods only from its internally constructed lifecycle recovery state; no public caller selector, path, command, or provider input is introduced.

Focused Linux-container composition, admission, process, coordinator, TypeScript, formatting, and retained-line checks pass.

This grants no AWS, provider, deployment, campaign, production, release, qualification, or promotion authority.
