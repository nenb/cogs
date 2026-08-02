# Draft observability dashboard field reference

This reference defines metadata-only telemetry and audit expectations. It neither configures a collector nor proves a dashboard. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future platform may provide authenticated OTLP, bounded buffers, tenant access, retention, alerts, time sync, and node/runtime metrics. | [Authority: DESIGN observability and audit](../../../DESIGN.md#16-observability-and-audit) |
| Backend costs, Kubernetes dimensions, and SLOs remain environment-specific/unverified. | [Authority: IMPLEMENTATION performance campaign](../../../IMPLEMENTATION.md#353-performance-campaign) |
| Dashboard access grants no raw transcript/export access. | [Authority: DESIGN privacy defaults](../../../DESIGN.md#162-privacy-defaults) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Allowed dimensions are bounded opaque IDs, profile/component/route/model identifiers, categorical results, resource class, and exact digest references; credentials cannot be identifiers. | [Authority: DESIGN OpenTelemetry fields](../../../DESIGN.md#161-opentelemetry) |
| Required spans cover lifecycle, Pi/model, tool/SSH/SFTP, egress, Git/checkpoint, export, and handle-category resolution. | [Authority: DESIGN OpenTelemetry fields](../../../DESIGN.md#161-opentelemetry) |
| Required metrics cover tokens/cost, turn/model, tools, egress, VM resources, startup, checkpoint/export, WAL, and OTLP lag/drop. | [Authority: DESIGN OpenTelemetry fields](../../../DESIGN.md#161-opentelemetry) |
| Central sinks forbid prompts/output/source/complete commands/arbitrary paths/tool output/query/body/credentials/placeholders/raw JSONL/exports. | [Authority: DESIGN privacy defaults](../../../DESIGN.md#162-privacy-defaults) |
| Exact command/path/tool detail stays user-owned; enterprise command audit is disabled by default and outside this guide. | [Authority: DESIGN privacy defaults](../../../DESIGN.md#162-privacy-defaults) |
| Audit append/authorization failure denies credentialed egress; bounded OTLP outage drops with counters while ordinary work continues. | [Authority: DESIGN audit fail-closed behavior](../../../DESIGN.md#114-audit-fail-closed-behavior) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Stage 3 local tests cover metadata-only shape/redaction, audit-before-use, WAL failure denial, and OTLP outage locally. | [Authority: Stage 3 exit evidence](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#automatic-acceptance) |
| Local collector proves no cloud transport, tenant ACL, retention, backend scrubbing, node metrics, cardinality, or load capacity. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Static policy shapes remain pending exact runtime qualification. | [Authority: Stage 4 static policy report](../../test-reports/stage-4-static-policy-contracts.md#remaining-mandatory-qualification) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Establish end-to-end trace propagation and candidate binding across daemon/worker/proxy/platform/OpenBao/WAL/collector/dashboard. | [Planned DESIGN-24.20, .22 / `future-eks-conformance-reference-v1`, `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Inspect telemetry/logs/events/crash artifacts/reports for forbidden content at highest validated real concurrency. | [Planned DESIGN-24.22 and STAGE5-45.08 / `future-load-reference-v1`, `future-independent-review-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Exercise collector loss, WAL full, clock/cardinality pressure, revocation, node loss, and access denial with real dependencies. | [Planned STAGE5-45.07–.08 / `future-eks-conformance-reference-v1`, `future-independent-review-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |

## Dashboard views

**Section authority:** [Authority: DESIGN OpenTelemetry fields](../../../DESIGN.md#161-opentelemetry).

| View | Primary fields | Alert conditions |
|---|---|---|
| Admission/readiness | profile, resource class, dependency state, reason category | dependency loss, fallback signal, sustained unready |
| Session lifecycle | active/idle, age, recycle notice, shutdown result | idle leak, emergency deadline, unknown outcome |
| Sandbox/runtime | startup percentiles, VM CPU/memory/disk/network | KVM/runtime mismatch, disk full, resource pressure |
| Tools/SSH | tool category, latency, timeout, truncation, SSH status | channel saturation, disconnect, cancellation unconfirmed |
| Model usage | provider/model ID, tokens, latency, reported cost | auth failure, latency/error shift, spend bound |
| Egress | integration/route, status class, bytes, latency, deny category | undeclared route, revocation failure, connection not drained |
| Audit WAL | depth, append latency, full/unwritable, export lag | any append failure; depth/age threshold |
| Storage/Git/export | attach/checkpoint/export result and duration | lease conflict, detach uncertainty, backup failure |
| Privacy | forbidden-field scanner result, sink identity | any match; access-policy drift |
| Teardown | phase state, uncertainty category, inventory scope | out-of-order phase, residue, unknown ownership |

## Triage rule

Alerts are leads, not ownership or absence proof. Correlate by exact opaque IDs and immutable candidate binding. If correlation is missing or conflicting, mark unknown, deny the affected capability where safely bounded, preserve metadata, and follow [incident response](incident-response.md). Never copy sensitive transcript content into a central alert to make diagnosis easier.
