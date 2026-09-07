# ADR 0317: Reallocate worker transport integration

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance non-AWS correction authority
- Measurement: `/tmp/cogs42-finaltransport.md`, commit `1936eeb7b3618db17554eeb5b9f206fbb08e544d`

## Context

ADR 0316 authorized worker-telemetry transport and exceptional OpenBao response custody before implementation. The isolated patch closes both reproduced defects and passes 503 broad lifecycle tests, but measured baseline-to-endpoint lifecycle additions are 6,772 against the 6,700 owner ceiling. Global additions are 17,668 against 18,500. Compressing actual-work ownership or deleting regressions would weaken the correction.

## Decision

Before integration, raise only the lifecycle owner ceiling from 6,700 to **6,800**. Keep the global 18,500 ceiling and every other owner, Stage2, post-H reserve, source, mutable-owner and v5 limit unchanged.

Allocate one additional decision-file slot, bringing the exact new-file ceiling to thirty-seven, still below the original forty. Future freeze/control and Q/qualification records move to ADR 0318 and ADR 0319.

Integrate only the measured transport patch, rerun its held-work reproductions and full tests, regenerate exact evidence after the final source change, and obtain fresh independent review. No later source change may use this measurement as transferable capacity.

## Authority boundary

This accounting adjustment permits local integration, tests, evidence regeneration and ordinary protected CI only. It grants no producer, publisher, preflight, qualification, image publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release or Stage4 authority. Work stops before the authoritative chain.
