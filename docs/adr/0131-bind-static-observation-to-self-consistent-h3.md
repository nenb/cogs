# ADR 0131: Bind static observation to self-consistent H3

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Correct directional H selection before the non-KVM observation

## Context

Hostile review found that proposed H2 `fdb09e4beae9eeae0f2715d8869858385b6fd5e6` contained the corrected immutable-preparation source but still pinned the predecessor digest in its static runtime-boundary policy. The later binding head corrected that policy, but the workflow checks out H after admission and therefore would have selected the stale boundary from H2. No corrected-H static workflow was dispatched.

## Decision

Treat `33314a9999cbe1e0eb927ba4a1e6f1ee10fcd5df` as implementation H3. That exact revision contains both immutable-preparation SHA-256 `cf1757832fdfd443dcb8265c32dec68e7a7e7c4d3c28e4246f00c27120a554c9` and a runtime-boundary policy requiring the same digest. Create a later binding revision that changes only the reviewed-H value and regenerated readiness bindings. Require focused regression to evaluate the runtime-boundary policy from exact H3 rather than only from the binding worktree.

The old successful static observation remains an exact predecessor and cannot describe H3. The single corrected static generation remains unconsumed.

## Authority boundary

This correction grants only the already-authorized non-KVM static observation after exact-head CI/review. It grants no KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
