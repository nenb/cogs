# ADR 0326: Reconcile historical Stage2 retirement policy

- Status: Accepted
- Date: 2026-09-08
- Deciders: Nick Byrne
- Scope: complete current prebuilt/formal-chain retirement enforcement and replacement H; no AWS

## Context

Protected main H `6276eae08e29ee577f3d9b2c739ceadfe467a769`, tree `5277f644eac0fb1af1800d212d7e49c315653173`, passed protected checks. Sole first-created producer `34257525184`, attempt 1, then passed two equal builds and exact readback. Artifact `10069446931` has Actions archive SHA-256 `9b9edb376e59d74f5a9436605dbb473213b9a54da0a5f3a92664a58112eb52be`. Its seven members and canonical rootfs were independently byte-verified.

A second hostile audit found that the closed retirement registry introduced by ADR 0309 preserved only recent tombstones. It omitted complete prebuilt/formal generations expressly retired by ADRs 0286, 0296, 0300, 0301, 0304, and 0306. Existing exact review constants and blocked seals reject those generations today, but that incidental rejection does not implement permanent retirement after the constants are replaced. Tests incorrectly required retired H3/G3/Q3 to remain outside the registry.

The producer itself is correct. This later P2 governance finding nevertheless changes H-owned policy, producer/static workflow bytes, and the static workflow commitment. Therefore its successful source-bound producer custody cannot authorize a corrected descendant.

## Decision

Permanently retire H `6276eae08e29ee577f3d9b2c739ceadfe467a769`, producer `34257525184`, and artifact `10069446931` from authorization use. Preserve their successful historical observations and exact bytes. Do not rerun, relabel, or reuse them.

Reconcile every complete prebuilt/formal generation retired since ADR 0286 into the current typed exact-selection registry. The following additions are controlled by this decision, including associated control/source and custody identities whose original decisions retired the complete generation rather than spelling out every scalar again:

| Decision | Retired revisions |
| --- | --- |
| ADR 0286 | `9f6e79140e4df284588182c96b5044bb52f50ef9`, `5601edf196a1bd4127afed6adf12ad8525fdb5b3` |
| ADR 0296 | `f93748b253c1429cce9149defde623f40c9cc0ab`, `0e5b7012fabae3412ce8e3110bb181af1ffe608b` |
| ADR 0300 | `d2fe08553d25d73fa276794c96b0f311e5406186`, `a108f981dacad6978e2a37d16a143da5c3b51cf4`, `728a77a87328e9cccd57547a930e84764964061f` |
| ADR 0301 | `8e2af4398519ab8d64b7f9e7194f9c116c6f51d9` |
| ADR 0304 | `229ea62bce964086726181974a6fec1c6dfd1f86`, `821149ba4c3dbccef48694efcdb1eb29fa9fd2b9`, `06188f67a9a699924d645ce8aa0e91950b6341c7` |
| ADR 0306 | `8a1b56cfdaf013b27d8ef7a7e2753d3bb2582271`, `69987e08cf9454fecf540a4de097f0877155b043` |
| ADR 0326 | `6276eae08e29ee577f3d9b2c739ceadfe467a769` |

Retire the corresponding selected observations:

- ADR 0286 runs `33626103650`, `33630868892`; artifact `9845676644`.
- ADR 0296 runs `33837299968`, `33850962596`, `33851159217`; artifacts `9924034454`, `9928325265`.
- ADR 0300 runs `33908498241`, `33931002300`, `33931091412`, `33965298642`; artifacts `9951239210`, `9958532006`, `9958574502`.
- ADR 0301 run `33972129993`; artifact `9971564905`.
- ADR 0304 runs `33980034976`, `33987181596`, `33987659305`, `33995592875`, `33995910136`; artifacts `9973726406`, `9975524471`, `9975667979`.
- ADR 0306 runs `34007531193`, `34013328638`, `34013774850`; artifacts `9981717931`, `9983143614`, `9983282050`.
- ADR 0326 run `34257525184`; artifact `10069446931`.

Preserve all existing ADR 0308–0324 tombstones. The canonical policy, closed Python copy, and all 19 current pre-effect workflow mirrors must contain the same complete 21-revision, 24-run, and 17-artifact set. Missing, extra, mistyped, malformed, or decision-drifted policy fails closed. The corrected static workflow digest must be recomputed only after all mirror bytes settle.

This registry covers identities selectable by the current prebuilt producer, publisher, static, rehearsal, mixed-preflight, formal qualification, and production provenance paths. Earlier failed diagnostics and legacy dual-build evidence remain governed by their typed workflow, authority-label, schema, and profile restrictions. ADR 0287's exact diagnostic-only publication remains usable only by its closed no-mint diagnostic lock and is not added here. This does not permit promotion of diagnostic evidence.

Retirement remains an exact typed selection veto, never authorization or an ancestry veto. Historical codecs and cleanup-only settlement remain available. Do not globally retire the content-identical canonical rootfs, manifest, metadata, sentinel, shared workflow content, tree, descriptor content, or OCI layer merely because retired provenance contains it. Authenticated retired revisions/runs/artifacts already make their descriptors and OCI provenance unusable for successor authority.

## Bounded accounting

The correction and remaining G/Q closure exceed the 444-line global and 474-line integration margins. Raise only:

| Bound | ADR 0324 | ADR 0326 |
| --- | ---: | ---: |
| remediation global gross | 21,400 | 21,800 |
| integration owner gross | 4,150 | 4,550 |
| integration planned new files | 36 | 37 |
| total planned new files | 44 | 45 |

Allocate this ADR as the only additional file. Keep the tracked-source high at 1,465, but align the stale executable inventory enforcement from 1,460 to that already authorized high. Keep source bytes, serialized inventory, all other owner highs, correction/post-H highs, hard retained limit, and no-deletion-credit rules unchanged.

ADR 0325 remains absent and reserved for the replacement H control decision. ADR 0322 remains absent and reserved for the later exact Q and qualification decision. With this ADR plus those reservations and Q's thirteen members, the planned endpoint is exactly 1,465 tracked files.

## Required gates

1. Every typed tombstone is rejected by both policy copies and every current mirror before effects; omission and distinct-descendant tests pass.
2. Current production and qualification selectors remain independently blocked until fresh H/G/Q values are established.
3. Static current-tree acceptance and one-byte mutation rejection use the final recomputed workflow commitment.
4. Focused retirement, producer, publisher, static, preflight, qualification, production, accounting, workflow syntax, and source-inventory tests pass.
5. Full local checks and deterministic readiness regeneration pass after source settles.
6. Two independent reviews report no P0–P2; a changed-since-review check covers any later evidence-only change.
7. Protected checks pass and merged-tree equality is verified before freezing replacement H.

Only then may one fresh producer be dispatched, independently audited, and bound by sole-parent G under ADR 0325. Every later publisher, static observation, Q, preflight, and qualification identity must be fresh.

## Consequences

The newly retired producer remains a valid historical deterministic-rootfs observation, not successor authority. No G, publisher, static observation, Q, preflight, or qualification exists for its generation. Model-key revocation after hydration remains unresolved.

This decision grants only the bounded replacement-H correction and subsequent non-AWS chain already authorized by the owner. It grants no AWS, provider, OpenTofu, SSM, inventory, deployment, campaign, production, release, or Stage3/Stage4 exit authority. Stop before AWS.
