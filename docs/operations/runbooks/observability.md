# Draft observability dashboard field reference

This reference defines metadata-only telemetry and audit expectations. It neither configures a collector nor proves a dashboard. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future platform will provide authenticated OTLP ingestion, bounded buffering, tenant-aware access, retention, alert routing, clock synchronization, and node/runtime metrics.
- Backend-derived costs, Kubernetes dimensions, and SLOs remain environment-specific and unverified.
- Dashboard access does not authorize raw transcript/export access.

## Static contract facts

### Allowed dimensions

Use opaque `user_id`, `session_id`, `workspace_id`, request/correlation ID, profile, component, integration/route name, model/provider identifier, result category, status code class, resource class, and exact source/artifact digest reference. Bound cardinality and never use credential values as identifiers.

### Required spans

- session startup/shutdown and readiness transitions;
- Pi turn and model call;
- tool dispatch plus SSH/SFTP operation;
- egress authorization and upstream request;
- Git observation/checkpoint;
- export;
- credential resolution by handle category, never value.

### Required metrics

- input/output/cache tokens and provider-reported cost;
- turn/model latency and active/idle state;
- tool count, latency, errors, timeouts, and output truncation;
- egress count, status, bytes, and latency by integration/route;
- VM CPU, memory, disk, and network from external collectors;
- startup/sandbox-ready latency;
- checkpoint/export failure;
- audit-WAL depth/full state and OTLP export lag/drop count.

### Forbidden central content

Prompts, model output, source, complete shell commands, arbitrary file paths, tool output, HTTP query strings/bodies, credentials, placeholders, raw JSONL, and raw exports are forbidden. Exact command/path/tool detail remains in user-owned Pi state. A separate enterprise command-audit sink is disabled by default and outside this guide.

Audit and telemetry fail differently: inability to authorize or append the local secret-use intent denies credentialed egress; an unavailable OTLP collector buffers within limits, then drops with counters while ordinary operation continues. Do not merge the audit WAL with best-effort telemetry.

## Authoritative-local facts

- Stage 3 local tests assert metadata-only telemetry shapes, redaction, audit-before-secret-use, WAL failure denial, and OTLP outage behavior within the local profile.
- Local collector output does not establish cloud transport security, tenant ACLs, retention, backend scrubbing, node metrics, high-cardinality behavior, or load capacity.

See the [Stage 3 Linux/KVM exit report](../../test-reports/stage-3-s3-09-linux-kvm-exit.md) and [static policy report](../../test-reports/stage-4-static-policy-contracts.md).

## Future cloud evidence

A future exact profile must establish end-to-end trace propagation and source/artifact binding across daemon, worker, proxy, sandbox platform, OpenBao, WAL, collector, and dashboard. Inspect telemetry, worker/proxy logs, Kubernetes events, crash artifacts, and reports for forbidden content at the highest validated real concurrency. Exercise collector loss, WAL full, clock/cardinality pressure, revocation, node loss, and access denial with real dependencies.

## Dashboard views

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
