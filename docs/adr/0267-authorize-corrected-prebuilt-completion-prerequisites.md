# ADR 0267: Authorize corrected prebuilt completion prerequisites

- Status: Accepted
- Date: 2026-08-31
- Accepted by: Nick Byrne through the explicit instruction to complete the corrected anti-fiasco non-AWS sequence autonomously and stop at AWS effects

## Context

ADR 0266 froze truthful evidence for implementation H `1fc2dea2dcefea2aaf71a80356e0f5ed946e9991`, which built the Stage 2 rootfs twice inside every lifecycle. The required production shape instead consumes one separately qualified, versioned, immutable, hash-pinned rootfs artifact. Independent reviews also established that protected main has only fake campaign ports and synthetic receipts, while the fixed full/readiness cycle routes deliberately lack batch/ordinal effect authority. Consequently ADR 0266's statement that no further local qualification is needed and that only AWS execution remains is no longer a valid readiness conclusion.

The historical run, report, receipts, H/G, and pre-AWS package remain immutable and valid for the exact dual-build path they observed. They cannot authorize a prebuilt consumer or a production seven-cycle controller.

## Decision

Adopt `docs/security-evidence/plans/stage2-prebuilt-completion-prerequisite-map.md` as the binding pre-H acceptance map. Complete discovery and all non-AWS production-shaped implementation before freezing H. In particular:

1. Retain the 16-input dual-build path only as a qualification producer. Publish one canonical uncompressed V2 ustar through an isolated trusted publisher to an immutable digest-addressed durable location, with exact readback and authenticated provenance.
2. Make authenticated G the sole descriptor issuer. H accepts no caller or environment URL, path, tag, digest, version, mirror, or fallback selector.
3. Add one transport-neutral verifier/importer that preflights the exact ustar and materializes once through the existing fd-relative writer, ledger, complete postwalk, retained lease, release, and recovery interfaces. Host tar, `extractall`, images, alternate writers, retries, and build fallback are forbidden.
4. Remove every consumer-time dependency on the 16 producer inputs from immutable preparation, static/runtime closure, admission, lease verification, and recovery. Preserve producer modules for qualification only.
5. Add durable artifact/import lineage, exact failure stages, identity-conservative recovery, and explicit acquisition/import residue domains to new additive evidence contracts.
6. Implement and locally/fake-test the production controller boundary, real full/readiness batch capabilities, typed plan/apply/running/remote/destroy/inventory custody, detailed eighth final inventory receipt, common resolved AMI/artifact binding, actual first-apply-through-final-zero duration, and pass-only report issuance. No cloud effect is authorized.
7. Keep Kata, QMP, SSH, networking, guest workloads, teardown ordering, sticky uncertainty, and cleanup-only recovery unchanged except for a demonstrated narrow type/binding requirement.
8. Use cheap hostile and Linux-root tests, then one no-mint KVM rehearsal of the complete consumer and both real owner routes. Freeze H only after a clean whole-graph review. Exact H then produces the artifact; independently produced G binds it; one mixed static observation and one first-created seven-sample/21-measurement formal qualification may follow.
9. Preserve all historical schemas/evidence. Add a supersession record and additive versions; never relabel the old pass as prebuilt consumption. Keep Issue #42 open until actual AWS acceptance passes.

## Measured capacity

At the clean ADR 0266 head, retained accounting is 52,754 deployment lines, 15,375 retained schema/script lines, 4,496 workflow lines, and 72,625 current lines. No-deletion-credit additions are 14,772 deployment, 4,067 retained, 1,514 workflow, and 20,353 global; conservative total is 75,707. The old global and workflow highs have only 147 and 6 lines remaining and cannot hold even the narrow importer, much less the independently discovered controller/evidence closure.

Raise the no-deletion-credit correction highs to 17,500 deployment, 7,500 retained schema/script, 2,300 workflow, and 26,000 global. Raise the advisory preferred total to 83,000 and hard stop to 86,000. These are maxima, not targets or transferable credit. Deletion, movement, replacement, generation, compression, or omission creates no credit. Readable ownership states, validators, failure stages, and tests remain mandatory. The complete tracked-source cardinality bound rises from 1,233 to at most 1,250 solely for additive contracts, producer/consumer owners, workflows, tests, decisions, and the final supersession package.

## Process controls

The formal qualification cannot be used as a diagnostic. Before it, the producer/upload/download/readback/import seam must pass without KVM, complete hostile and recovery matrices must pass, one authentic no-mint KVM rehearsal must pass, and a clean independent review must map every Issue #42 criterion to producer, observer, evidence, and validator. Any change after review or rehearsal invalidates those gates. A failed, cancelled, stale, retried, artifactless, cleanup-uncertain, or replacement run is non-authorizing.

## Consequences

The immediate prototype that assumed an unauthenticated fixed local bundle is discarded. The existing content pins and lifecycle machinery remain reusable. The correction is larger than a lease optimization because it closes artifact supply chain, consumer authority, recovery, controller reachability, and final evidence together before H/G.

This ADR supersedes only ADR 0266's readiness and “no further qualification” conclusion. It preserves ADR 0266's frozen bytes and prohibition on AWS, provider/OpenTofu effects, SSM, inventory queries, deployment, campaign execution, production release, and Issue closure. After corrected non-AWS evidence is frozen, work stops for fresh AWS authorization.
