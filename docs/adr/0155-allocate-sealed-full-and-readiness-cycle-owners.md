# ADR 0155: Allocate sealed full and readiness cycle owners

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

The fake controller, closed receipts/evidence, QMP observer, exact teardown, and recovery are implemented. A source audit found the remaining freeze gap: the existing local V3 report cannot be relabeled as a future cycle receipt, and a readiness cycle cannot counterfeit the full guest causal proof. Separate closure-issued full and marker-only readiness routes must reuse the same typed lifecycle while recording the sole launch, first complete authenticated marker, and final command settlement under boottime lineage. Distinct sealed receipt types must be wired through fake custody; report bytes and mode selectors remain non-authoritative.

Measured before this decision: physical 70,267, conservative no-deletion-credit 73,149, deployment gross 12,531, global gross 17,795, mutable bridges 1,003, runtime owner 2,116, and integrated operation/rootfs 3,809. The reviewed implementation estimate is 1,500 counted gross lines. Allocate readable closure by raising preferred/hard limits to 76,000/78,000, deployment gross to 14,500, global gross to 19,500, mutable bridges to 2,000, runtime owner to 2,500, and integrated operation/rootfs to 4,500. Retained and workflow highs remain unchanged.

This allocation permits only the two fixed zero-argument owner routes, exact timing/journal lineage, sealed full/readiness receipts, fake custody wiring, stale teardown-order correction, hostile tests, and deterministic contract regeneration. It permits no caller-selected mode, retry, production adapter, provider initialization, AWS API/CLI, credentials, inventory, planning, deployment, campaign, promotion, or release.
