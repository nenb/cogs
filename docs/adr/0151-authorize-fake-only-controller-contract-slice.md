# ADR 0151: Authorize the fake-only controller contract slice

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24
- Scope: Issue #42 Slice A contracts, pure reducer, local fake tests, and retained accounting only

ADR 0150 reserves readable capacity for downstream integration and fake-only controller closure. Implement the first controller slice as three pure Python modules, one private closed schema, and exhaustive fake/local tests. Add the schema atomically to retained accounting. This slice has no production controller, custody coordinator, shell entry, provider adapter, public evidence, renderer, workflow, or cloud interface.

The reducer is fixed to seven sequential cycles with modes `[full, readiness, readiness, readiness, readiness, readiness, readiness]`. It admits no selector, retry, replacement, overlap, or forward recovery. Uncertainty is sticky. A failure permits only the fixed one-destroy/one-independent-observation suffix when apply might have occurred, then a terminal state with no outgoing transition.

The codec accepts only bounded strict canonical JSON and local immutable record publication. Fake ports and fake records cannot establish provider truth, cloud execution, zero resources, local qualification, or completion evidence.

Measured at the isolated slice commit, the addition is 1,385 counted gross lines: 995 deployment and 390 explicitly retained. Combined integration is governed by ADR 0150's 9,500 deployment, 4,500 retained, 1,320 workflow, 13,000 global, 69,000 preferred, and 70,000 hard limits.

No AWS CLI/API, credentials, provider, OpenTofu, inventory, plan, deployment, campaign, network, promotion, production, or release authority follows.
