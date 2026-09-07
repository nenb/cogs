# ADR 0315: Authorize final asynchronous transport ownership

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval for required non-AWS correction
- Input: independent lifecycle re-review `/tmp/cogs42-rereview-life.md` at `8f5edd126be62302e3d68ca2d4a2c32c706ae03f`

## Context

The ADR 0313 correction closed the reproduced OpenBao metadata/data cancellation, token-wrapper, watcher-registration, egress-factory and requested-shutdown defects. Re-review confirmed those exact regressions now retain actual work. It found three analogous asynchronous boundaries that still let transport work outlive a successful retirement fact: production Kubernetes workload-identity login, unpinned model-auth reads, and optional OTLP requests/body cancellation.

These are not permission to make ordinary telemetry outage fatal. The defect is loss of actual-work ownership, not the bounded caller observation or optional result classification.

## Decision

Authorize regression-first correction in exact existing files:

- `src/auth/openbao-workload-identity.ts` and its test;
- `src/auth/model-auth.ts` and its test;
- `src/telemetry/otlp-http.ts`, `src/egress/otlp-telemetry.ts` and their tests;
- narrowly necessary runtime-manager/production composition tests already allocated.

Every effectful fetch, response read, and original stream cancellation must be registered before callbacks or abort reentry and joined on all success, failure, timeout, malformed, duplicate, late and exceptional exits. A bounded observation may reject while actual work remains pending. It cannot certify retirement, release a dependent credential/material scope, or be cached as the actual owner.

Expose actual retirement through private identity-bound ownership, not new public secret-bearing fields. Production auth/Pi startup and runtime-manager telemetry retirement must join actual work. Optional OTLP delivery remains bounded, loss-accounted and nonfatal to an otherwise valid request; manager retirement waits only for the transport owner, not for successful export.

Permanent tests must preserve held fetch and held cancellation promises through manager/lifecycle close, prove no WAL/material/SSH/telemetry dependency release before settlement, and prove eventual retirement without healing a historically failed lifecycle.

### Accounting

Raise the unchanged baseline-to-endpoint remediation global ceiling from 18,000 to **18,500** lines and set owner ceilings to route 1,800; revocation 3,000; relay 1,800; lifecycle 6,700; completion 2,300; integration 2,900. Their sum is 18,500. All Stage2, post-H reserve, source, mutable-owner and v5 limits remain unchanged.

Allocate the previously existing workload-identity and OTLP HTTP source/tests to their corresponding owners. Increase the exact allocated new-file total from thirty-four to thirty-five for this ADR; this remains below ADR 0308's original forty-file maximum. Future freeze/control and Q/qualification records move to ADR 0316 and ADR 0317.

## Validation

Run the three independent held-work reproductions, permanent focused tests, the complete integrated lifecycle/S3 suites, full repository checks, exact accounting and fresh hostile re-review. Timeout or collector failure cannot become transport retirement; transport failure cannot be promoted to successful authorization evidence.

## Authority boundary

This ADR permits local source correction, testing, evidence regeneration and ordinary protected CI only. It grants no producer, publisher, preflight, qualification, image publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release or Stage4 authority. Work stops before the authoritative chain.
