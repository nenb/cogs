# ADR 0019: Raise issue #66 telemetry line-budget

## Header

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead on 2026-07-17 under Nick Byrne’s explicit instruction: when a decision is required I let you make it based on what you think best.

## Status

Accepted by delegated project lead on 2026-07-17 under Nick Byrne’s explicit instruction: when a decision is required I let you make it based on what you think best.

## Context

ADR 0018 sets the current issue #66 production TypeScript cap at 11,650 `src/` lines. The accepted baseline before S3-09 WAL-to-OTLP work was 11,395 lines, leaving 255 lines.

The S3-09 lead decision requires one bounded slice containing:

- production OTLP/HTTP JSON logs exporter;
- production runtime-manager wiring;
- WAL-correlated completion sink hook;
- real insecure-container and KVM harness telemetry evidence;
- no new dependency;
- exact `/v1/logs` endpoint validation;
- HTTPS or explicit HTTP loopback evidence mode only;
- exact OTLP JSON logs envelope;
- bounded queue, batching, retry, close, and redacted counters;
- outage must not poison ordinary WAL/authz/completion readiness.

A first uncommitted attempt was intentionally stopped after lead review. After running Biome on changed production files to remove unsafe line compression, the measured production count is 11,738 lines, already 88 lines over ADR 0018 before fixing known correctness blockers.

## Measured blocker summary

The stopped attempt is not acceptable as-is. Known blockers include:

- exporter sends one request per record instead of exact batches up to 16;
- final close can take `capacity * timeout`, and runtime timeout can return while pump work continues;
- no strong abort/join semantics for in-flight work;
- response validation lacks required content-type/content-length handling;
- `partialSuccess` validation is too permissive;
- OTLP JSON `intValue` must use protobuf-JSON string mapping for int64 values;
- config/event exact-shape validation does not reject symbols, non-enumerables, or accessors strongly enough;
- top-level telemetry event is not frozen;
- sink readiness/closing/stub-close semantics need tightening;
- malformed telemetry config is validated after WAL side effects;
- completion hook option shape is not validated;
- no total bounded close guarantee;
- pump has an enqueue/finally lost-wakeup race;
- runtime outage non-poisoning and exact WAL/completion correlation must be preserved.

## Line-budget measurement

| Item | Production `src/` TypeScript lines |
|---|---:|
| ADR 0018 baseline before S3-09 | 11,395 |
| ADR 0018 cap | 11,650 |
| Remaining under ADR 0018 | 255 |
| Current formatted stopped attempt | 11,738 |
| Current overage vs ADR 0018 | 88 |

Readable strict fixes for the blockers above are estimated at 95 additional production lines beyond the formatted stopped attempt. That puts the likely implementation at approximately 11,833 lines before contingency.

Applying at least 15% contingency to the remaining implementation delta from the ADR 0018 baseline:

- measured and estimated delta: `11,833 - 11,395 = 438` lines;
- 15% contingency: `66` lines;
- defensible cap: `11,395 + 438 + 66 = 11,899` lines.

A cap of 11,800 was evaluated but is not defensible: it would leave only 62 lines above the current formatted stopped attempt, less than the measured blocker-fix estimate and with no 15% contingency.

## Decision

This accepted decision amends only the absolute issue #66 production TypeScript cap from 11,650 to **11,900** total `src/` lines. This is not an additive telemetry-only allowance on top of ADR 0018; it is the new overall issue #66 cap.

This cap is intended only to finish the S3-09 telemetry completion slice readably and strictly. It does not authorize any new production-readiness, AWS, or release claim. Stage 3 evidence remains bounded to local functional and authoritative-local KVM evidence unless a later accepted ADR says otherwise.

## Non-expansion constraints

Acceptance of this ADR would not expand scope beyond issue #66 Stage 3 evidence completion:

- no new dependencies;
- no architecture expansion beyond the existing Stage 3 egress runtime, WAL/completion, and OTLP metadata-export path;
- no protocol expansion beyond the already required exact OTLP/HTTP JSON logs `/v1/logs` envelope;
- no OAuth broker work or credential-flow expansion;
- no AWS, EKS, deployment, release, production-profile, or production-readiness claim;
- no weakening of exact OTLP validation, ADR 0008 privacy restrictions, redaction, bounded cleanup, fail-closed credential authorization, or outage non-poisoning semantics;
- no closing issue #66 before final evidence and owner-approved review explicitly allow closure.

## Remaining issue #66 work after S3-09 telemetry

After telemetry implementation is evidenced and reviewed, the expected remaining issue #66 work is mostly test-only and review/evidence work:

- refresh generated insecure-container and KVM Stage 3 evidence artifacts with real OTLP telemetry marked `real`;
- validate exact OTLP records and forbidden-value absence in both profiles;
- update report/sidecar tests and validators as needed without changing production semantics;
- run focused and full required checks;
- obtain lead/owner artifact review before any merge or issue closure decision.

## Consequences

- The implementation can be written readably and reviewed for security semantics rather than compressed to fit ADR 0018.
- The cap remains narrowly scoped to issue #66 S3-09 telemetry completion.
- The uncommitted stopped attempt remains review material; implementation resumed only after this explicit delegated acceptance.
