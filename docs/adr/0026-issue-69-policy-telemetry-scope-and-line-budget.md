# ADR 0026: Issue #69 policy and telemetry scope and line budget

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

Issue #69 is the Stage 3 S3-07 workstream for the static policy and metadata-only telemetry requirements in `IMPLEMENTATION.md` §26 and `DESIGN.md` §§16-17.

The clean `main` baseline for this decision is `685e7a26ca8af34749a722088cce11cb6024259b` with:

```sh
find src -name '*.ts' -print0 | xargs -0 wc -l | tail -1
# 18921 total
```

Existing accepted constraints remain authoritative:

- ADR 0003 keeps real credentials, trusted proxy state, and CA private keys outside the sandbox VM.
- ADR 0008 permits central telemetry only for opaque operational metadata and forbids prompts, model output, source, complete commands, paths, tool output, HTTP query/body, credentials, and placeholders.
- ADR 0015 through ADR 0019 authorized and amended only issue #66 secure-egress integration, including the existing egress completion telemetry path. They did not authorize broader worker policy/observability work.

Current `main` already satisfies the issue #66 egress-completion telemetry subset: WAL-correlated completion events are exported through the existing bounded OTLP JSON logs sink, OTLP outage is nonfatal, and authorization/WAL failure remains fail-closed before credential use. Issue #69 must reuse or safely refactor that path without weakening it.

## Decision

Authorize issue #69 implementation of one static in-process policy function plus metadata-only worker OpenTelemetry under a bounded production line-budget cap.

Until issue #69 is closed, production TypeScript under `src/**/*.ts` may grow up to **22,000** total lines for this issue. This cap is measured from the accepted `18,921`-line baseline and covers only the work described here.

## Authorized policy scope

Issue #69 may add one strict static policy module implementing a versioned action envelope and a versioned decision envelope suitable for future OPA adapter comparison.

Authorized action coverage:

- launch mount/config validation metadata;
- Pi tool enablement and dispatch;
- egress route authorization metadata and secret-use metadata;
- local raw export mode;
- reserved restore request denial.

Required behavior:

- fail closed for unknown actions, unknown resources, unknown fields, malformed envelopes, hostile object shapes, and unsupported surfaces;
- never parse bash text as policy;
- never receive prompt/model text, source text, complete commands, arbitrary paths, tool output, HTTP query/body, secrets, placeholders, account IDs, or raw identifiers;
- expose canonical contract fixtures so a future OPA adapter can prove decision equivalence before replacing the static function.

Policy integration must not replace or weaken existing enforcement:

- ext_authz route matching and capability checks remain authoritative for egress request details;
- synchronous WAL append remains required before any credentialed allow response;
- existing OpenBao, tmpfs, route-policy, Envoy, and completion fail-closed semantics remain intact;
- the existing authenticated local raw export API remains the export surface;
- restore remains reserved and denied; no restore API is authorized.

## Authorized telemetry scope

Issue #69 may add metadata-only worker telemetry for:

- worker lifecycle and dependency state;
- Pi turns/events/model-call metadata;
- tool dispatch metadata;
- SSH/SFTP/bash operation metadata;
- egress authorization/completion metadata;
- WAL depth/status metadata;
- OTLP queue/export lag/drop/failure metadata;
- export metadata;
- shutdown preparation/readiness metadata.

The implementation should reuse or safely refactor the existing bounded OTLP queue/sink code where practical. No new production dependency is authorized by this ADR. If a new dependency appears necessary, implementation must stop for a superseding ADR or explicit accepted amendment.

Telemetry requirements:

- central telemetry is metadata-only and must exclude prompt/model text, source content, complete commands, arbitrary paths, tool output, HTTP query strings/bodies, secrets, placeholders, account IDs, and raw identifiers;
- labels must be bounded enums, booleans, small integers, opaque IDs, or safe buckets;
- hostile telemetry shapes must be rejected or reduced to counters without invoking getters/proxies or leaking content;
- OTLP outage, collector outage, queue overflow, and export failure do not stop ordinary Pi/tool/export work;
- credential authorization and audit WAL failure still deny credential use and remain fail-closed.

## Command-audit hook

Issue #69 may add only an explicit, disabled-by-default enterprise command-audit hook contract.

Constraints:

- no command-audit payload is emitted by default;
- the hook is separate from ordinary OTLP telemetry;
- any supplied sink must be exact-shape validated and separately protected;
- enabling payload-bearing command audit, retention, or access controls beyond a disabled hook contract requires future review.

## Line-budget measurement

Planning estimate from the accepted issue #69 plan:

| Area | Estimated production lines |
|---|---:|
| Static policy core/schema helpers | 390 |
| Policy integration | 460 |
| Shared OTLP worker telemetry sink | 670 |
| Instrumentation | 750 |
| Disabled command-audit hook | 120 |
| **Planned addition** | **2,390** |
| 25% contingency | 598 |
| **Recommended cap from baseline** | **21,909** |

Decision cap: **22,000** production `src/**/*.ts` lines.

This provides at least the required 25% contingency over the 2,390-line planning estimate. Every issue #69 implementation PR must report the measured production line count and stop before exceeding the cap.

## Required tests and evidence

Issue #69 implementation must include tests for:

- exact policy envelope and decision shape;
- unknown actions/fields/resources and hostile object shapes failing closed;
- static decision fixtures for future OPA parity;
- bash command text never entering policy or telemetry;
- file-tool path classification without path emission;
- ext_authz/WAL ordering preserved when policy is added;
- export raw mode allowed and archive/cloud/sanitized/restore denied;
- OTLP outage nonfatal to ordinary work;
- WAL/authz failures still fail closed for credential use;
- forbidden telemetry sentinel absence across lifecycle, Pi, tool, SSH, egress, WAL, OTLP, export, and shutdown events;
- bounded queue/close/abort/drop semantics;
- disabled command-audit default behavior.

Evidence may be local functional-only plus existing CI/insecure-container/Linux-KVM regression evidence. It must not claim production monitoring, compliance certification, release eligibility, AWS, EKS, deployment, cloud telemetry, launcher behavior, or restore support.

## Non-decisions and exclusions

This ADR does not authorize:

- new production dependencies;
- OPA runtime integration;
- cloud, AWS, EKS, deployment, release, production-readiness, or compliance claims;
- restore implementation;
- archive export, cloud export, sanitization/anonymization transforms, or import/restore flows;
- parsing bash text as policy;
- moving secrets, proxy private material, or CA private keys into the guest;
- weakening ADR 0008 telemetry exclusions;
- weakening ext_authz, WAL, OpenBao, tmpfs, or egress fail-closed behavior;
- enabling command-audit payloads by default.

## Stop gates

Implementation must pause for review and, if necessary, a superseding ADR if any of the following occur:

- production code would exceed 22,000 `src/**/*.ts` lines;
- a new production dependency is needed;
- telemetry requires raw commands, paths, prompts, source, query/body, output, secrets, placeholders, account IDs, or raw provider responses;
- policy would parse bash text;
- policy would replace ext_authz route matching or weaken WAL-before-credential ordering;
- restore, archive, cloud export, sanitization, release, deployment, or compliance scope is requested.

## Consequences

Issue #69 can proceed in bounded slices without compressing security-critical policy validation, telemetry redaction, queueing, and cleanup code. The existing issue #66 egress telemetry remains the authoritative egress completion telemetry path unless a later reviewed change safely refactors it without semantic weakening.
