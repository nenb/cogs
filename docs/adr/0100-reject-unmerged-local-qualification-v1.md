# ADR 0100: Reject unmerged local qualification v1 false-authority material

- Status: Accepted by explicit owner instruction
- Date: 2026-08-17
- Scope: Stage 2 local-result schema history only

## Context

A `stage2-workload-local-qualification-v1.json` existed only on rejected, unmerged development history (including `6c24c15b89c5ac988f02613b8f3dffd837358789`). It allowed caller-built report data to appear authoritative. Protected main at `69eccf1` did not contain that path, and no accepted evidence used it.

ADR 0099 preserves accepted historical schemas and evidence. Restoring rejected false-authority bytes would create a new validation surface, not preserve protected-main history.

## Decision

The v1 bytes remain absent intentionally. They are not an accepted historical schema and must not be registered, reconstructed, or accepted as authority. Tests bind this decision to the path's absence at protected-main commit `69eccf1`, rather than making claims about arbitrary branch history.

V2 is non-authoritative report data. Schema validation alone is insufficient; its independent semantic validator and an exact private receipt/custody validation are mandatory before any future local authority can exist. This decision grants no receipt, coordinator, KVM run, retry, controller, AWS, production, release, or promotion authority.
