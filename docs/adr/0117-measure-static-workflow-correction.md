# ADR 0117: Measure the static-workflow correction

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Stage 2 correction workflow accounting only

## Context

The six exact predecessor bindings and static non-use census bring the no-deletion-credit workflow slice to 903 lines, three lines above ADR 0109's 900-line high. All deployment, retained, global, preferred, and hard limits remain satisfied.

## Decision

Raise only the workflow correction high to 1,000 lines. Keep the 8,000 deployment, 3,200 retained, 11,000 global, 66,500 preferred, and 67,000 hard limits unchanged. Compression, relocation, deletion, generated indirection, and test movement receive no credit.

## Authority boundary

This is measured non-AWS correction authority only. It grants no KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority.
