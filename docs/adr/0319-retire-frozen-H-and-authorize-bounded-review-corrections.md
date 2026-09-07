# ADR 0319: Retire frozen H and authorize bounded review corrections

- Status: Accepted
- Date: 2026-09-07
- Deciders: Nick Byrne
- Scope: findings 1, 3, and 4 from the post-PR-522 review; no authoritative chain or AWS

## Context

Protected main revision `9b9966afffe0ea8de4d0c99147886a95094470a9`, tree `fa0bae41334be413f6a50750cc3b920a2992c48f`, was frozen as a Stage2-only implementation H after PR 522. No producer, direct-child G, publisher/static observation, Q, mixed preflight, qualification, production, provider, or AWS operation was started from it.

A later independent review confirmed three bounded defects:

1. route-level `response_headers_to_remove` does not remove the injected credential name from HTTP response trailers;
2. model credentials are hydrated into the worker without the integration-route OpenBao revocation watcher;
3. the launch schema admits `tool_timeout_seconds` through 900 while the SFTP file adapter rejects an operation timeout above 60 seconds; and
4. atomic SFTP replacement publishes the temporary inode's `0600` mode instead of preserving an existing ordinary file mode.

Finding 2 remains open and is not converted into a claim of closure. This Stage2 correction may only state that model-key containment requires externally owned worker shutdown/replacement; it cannot claim that OpenBao deletion cancels an active or future model call in an existing worker.

The existing remediation ceiling has only 17 gross lines remaining. Compressing protocol proof, timeout handling, retirement defense, or hostile metadata/late-callback tests would weaken the correction.

## Decision

Permanently retire exact H `9b9966afffe0ea8de4d0c99147886a95094470a9` as `ADR0319`. Preserve every older retired revision, run, and artifact. Add the exact H literal to every current pre-checkout producer, publisher, static, preflight, qualification, diagnostic, and production mirror. Mechanically hard-disable every job in superseded Stage2 candidate/static/preflight/qualification workflows and retain a closed workflow classification test so another selector cannot appear unclassified. Production scripts must repeat the central retirement selector over authenticated embedded H/G/Q provenance before credentials, signing, staging, or provider effects. A corrected descendant remains only eligible for later review; ancestry is not a veto.

Authorize one correction branch and one protected PR for findings 1, 3, and 4 only.

### Response phases

Keep final-response `response_headers_to_remove`. Against pinned Envoy v1.38.3, independently reproduce final headers, HTTP/2 trailers, and informational responses with synthetic values. Use native response-trailer mutation to remove every occurrence of `authorization`, `proxy-authorization`, and each configured credential header name before downstream delivery. Explicitly suppress upstream informational forwarding with a pinned native mechanism. The retained regression must first prove that its synthetic sentinel is observable without the correction and then prove absence with the production correction, including duplicates, benign controls, delayed streamed body bytes, valid lowercase HTTP/2 wire names, and mixed-case removal configuration. No response-body buffering, value inspection, custom Envoy build, or response-DLP claim is authorized. A reset or missing final response remains failed completion evidence, not clean replacement success.

### Timeout compatibility

Preserve the schema's 1–900 second range and accept its exact millisecond maximum in the SFTP file adapter. Keep open, operation, idle, channel-close, and cleanup bounds separately named; this correction does not invent a new startup architecture or claim that timeout proves retirement. Tests must cover 60, 61, and 900 seconds, reject one past the exact option bound, and perform a quick production-composed operation at the schema maximum.

### Existing-file modes

Treat SFTP metadata as hostile input. Derive the source mode from `fstat` on the same opened original handle used for content or existing-target observation. Reject missing, accessor-backed, malformed, non-regular, or special-bit modes before masking. New files remain `0600`. An exclusive temporary sibling must be observed through its own handle as empty, regular, and exactly `0600` before payload; apply and re-observe the selected ordinary mode through that handle before fsync, close, and rename. Preserve final-target symlink rejection.

Confirmed pre-publication failure or confirmed rename rejection may clean the temporary sibling and must not report mutation success. Timeout, malformed callback, unacknowledged mutation, ambiguous rename, or cleanup uncertainty must fail readiness and retain actual-work/channel ownership; it must not speculate, rollback, unlink an uncertain target, or report successful cleanup. Ownership, ACL, xattr, hard-link topology, and concurrent hostile-writer preservation remain outside this correction.

### Bounded accounting

Retain baseline `242bbefeae5444118d9e97b46597130b509ca253`, whole-file ownership, disabled rename/copy/textconv credit, and all source byte/file limits. Supersede only these ceilings:

| Bound | Previous | ADR 0319 |
|---|---:|---:|
| remediation global gross | 18,500 | 20,500 |
| route owner | 1,800 | 2,200 |
| lifecycle owner | 7,000 | 7,200 |
| completion owner | 2,600 | 2,800 |
| integration owner | 3,000 | 3,500 |
| conservative hard retained lines | 95,900 | 97,000 |
| correction global | 40,500 | 42,000 |
| post-H retained/global | 500 / 1,000 | 1,500 / 2,100 |
| post-H workflow | 350 | 500 |
| integration/total new-file high | 31 / 39 | 32 / 40 |

Route, lifecycle, completion, and integration capacity is not transferable. Revocation remains 3,000 and relay remains 1,950. Post-H deploy remains 150. Every other deploy, retained, workflow, source-byte, serialized-inventory, per-file, and mutable-owner limit remains unchanged.

ADR 0319 consumes the former first reserved decision slot. Reserve absent ADR 0320 for a later corrected-H freeze/control decision and absent ADR 0322 for a still later Q/qualification decision; ADR 0321 remains the historical npm correction. The thirteen final-v5 members remain absent and reserved. No new implementation, schema, fixture, or framework file is authorized by this decision.

## Required gates

Before replacement-H freeze:

1. focused hostile tests and pinned Envoy runtime proof pass;
2. full local checks and exact no-deletion accounting pass;
3. independent Envoy, SFTP/lifecycle, retirement/accounting, and holistic reviews report no P0–P2 blocker;
4. readiness/source evidence is regenerated only after source settles and is deterministic;
5. exact-head protected CI, insecure-container, KVM, and every Stage2 lifecycle shard pass; and
6. protected-main tree equality is verified after merge.

Review corrections may require repeated affected tests, evidence, and protected checks. “One cycle” is an optimization, not permission to accept stale evidence.

## Consequences

H `9b9966afffe0ea8de4d0c99147886a95094470a9` and its handoff remain historical and non-authorizing. Finding 2 remains confirmed and deferred. The resulting revision, if all gates pass, is only a replacement Stage2 H. This ADR grants no producer, G, publisher, Q, preflight, qualification, production, release, Stage3/Stage4 exit, provider, OpenTofu, SSM, inventory, deployment, campaign, or AWS authority.

Stop after freezing replacement H. The authoritative chain must not start under this decision.
