# ADR 0311: Reallocate the integrated post-H closure

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval for every required non-AWS correction before the authoritative-chain stop
- Inputs: measured isolated implementation handoffs `/tmp/cogs42-{s309,close,openbao,envoy,x32,serial}-impl.md`

## Context

ADR 0309 allocated the newly discovered correction wave before implementation. Isolated whole-file owners then produced measured patches. No-deletion accounting showed that the lifecycle work is necessarily larger than its forecast because positive S3-09 guest material custody and fresh close ownership span distinct existing files. Three S3-09 files were not assigned in the first exact path map. The aggregate forecast remains under the unchanged 16,000-line global ceiling, but integrating under the old owner vector would fail closed.

The first-party OpenBao artifact recipe remains separately blocked and is not part of this integration measurement. Its reserved build workflow is unnecessary for local feasibility and can be released. ADR 0310 remains the accepted recognition-correction scope; no derivative is admitted by this decision.

## Decision

Before integrating application commits, assign the three omitted exact paths:

- lifecycle: `dev/launcher/trusted-controls.ts` and `test/dev-launcher-operations.test.ts`;
- integration: `docs/test-reports/stage-3-s3-09-linux-kvm-exit.md`.

Reallocate only owner ceilings, retaining the exact baseline, global ceiling, all byte/cardinality/Stage2 hard limits, no-deletion credit, whole-file accounting and future v5 absence:

| Owner | Superseding ceiling |
|---|---:|
| route | 1,500 |
| revocation | 3,000 |
| relay | 1,300 |
| lifecycle | 5,200 |
| completion | 1,800 |
| integration | 3,200 |
| **Total** | **16,000** |

This is capacity allocation, not permission to weaken tests or claim measured integrated closure. Exceeding any owner or global bound still stops work.

Remove the unused `.github/workflows/build-openbao-local.yml` reservation. Use that file slot for this accepted ADR. Reserve future replacement-H freeze/control and Q/qualification decisions as ADR 0312 and ADR 0313. No such future record is created now.

The integration lead must cherry-pick and inspect each isolated implementation, resolve shared close/OpenBao/S3 interfaces, run combined accounting, and correct any cross-module failure. In particular, the S3-09 handoff's explicitly missing complete final WAL/completion observation remains a blocker; local available-observer deltas cannot be promoted into literal zero-extra authority. The blocked OpenBao artifact recipe cannot be counted as real-fixture qualification.

## Validation

Before replacement H:

1. all exact owner/global/source/Stage2 limits pass on the combined endpoint;
2. S3-09 obtains a complete final retired WAL/completion fact or narrows its claim without false pass;
3. shared close owners are actual-work records, never bounded public observations;
4. OpenBao root/PKI/storage changes integrate without weakening retirement;
5. pinned Envoy and applicable Linux/KVM behavior are observed on final bytes;
6. independent hostile reviews report no P0–P2 blocker.

## Authority boundary

This decision authorizes local integration, correction, tests, ordinary protected CI and explicitly non-authorizing diagnostics only. It grants no producer, publisher, preflight, qualification, image publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release or Issue #42 closure authority. Work stops before the authoritative chain.
