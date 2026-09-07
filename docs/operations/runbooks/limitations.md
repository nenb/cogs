# Draft known limitations and residual risks

These boundaries must accompany every future evaluation. They are not defects silently waived by a successful test. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| Operators/users understand model-directed code is untrusted and allowlists are not information-flow control. | [Authority: DESIGN narrow credential guarantee](../../../DESIGN.md#41-narrow-credential-guarantee) |
| Configured model provider and platform administrators remain trusted. | [Authority: DESIGN trust domains](../../../DESIGN.md#42-trust-domains) |
| Future daemon/identity/storage/cluster/provider implementations may add unrepresented risk. | [Authority: DESIGN logical session resources](../../../DESIGN.md#51-logical-session-resources) |

## Static contract facts

| Static limitation | Specific authority |
|---|---|
| Agent may misuse granted capability; approved write endpoint may receive source; no DLP. | [Authority: DESIGN narrow credential guarantee](../../../DESIGN.md#41-narrow-credential-guarantee) |
| Model provider receives prompt/selected source by design. | [Authority: DESIGN residual risks](../../../DESIGN.md#26-residual-risks-to-state-publicly) |
| Hypervisor/QEMU/Kata/kernel/proxy/worker/OpenBao/CNI/CSI/platform remain trusted-computing-base risks. | [Authority: DESIGN trust domains](../../../DESIGN.md#42-trust-domains) |
| Compromised trusted worker can access session credentials; proxy-bootstrap separation is deferred. | [Authority: DESIGN residual risks](../../../DESIGN.md#26-residual-risks-to-state-publicly) |
| Guest root may copy short-lived proxy capability; source binding/route policy only limit it. | [Authority: DESIGN residual risks](../../../DESIGN.md#26-residual-risks-to-state-publicly) |
| Pinned/custom trust fails closed; unsupported auth/protocol does not become safe by generic config. | [Authority: DESIGN compatibility classes](../../../DESIGN.md#115-supported-compatibility-classes) |
| Git mapping records untrusted observation, not repository attestation. | [Authority: DESIGN mapping record](../../../DESIGN.md#151-mapping-record) |
| Checkpoints/metadata/wrappers are not complete filesystem/syscall audit. | [Authority: DESIGN execution and filesystem audit](../../../DESIGN.md#163-mvp-execution-and-filesystem-audit) |
| Subscription OAuth/refresh handling, daemon/ingress/sanitizer/apps/indexing/restoration/audit and advanced/non-HTTP egress are deferred or unsupported. | [Authority: provisional unsupported capabilities](../stage-5-api-key-release-acceptance-matrix.md#unsupported-capabilities-and-claims) |
| GCP/Azure/Hetzner/other-cloud/generic Kubernetes/AWS EKS profiles are unadvertised. | [Authority: provisional platform profiles and unsupported capabilities](../stage-5-api-key-release-acceptance-matrix.md#platform-profiles) |
| Prompt replay, outside-observation exact Git mapping, and crash-consistent per-turn object backup are unavailable. | [Authority: DESIGN failure behavior and residual risks](../../../DESIGN.md#21-failure-behavior) |
| Subscription OAuth remains disabled/unadvertised; issue #13 is future post-MVP only. | [Authority: provisional OAuth blocker](../stage-5-api-key-release-acceptance-matrix.md#subscription-oauth-blocker) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Linux/KVM authority is local only and establishes no EKS/CNI/provider/cloud-storage/release/production/GA/compliance/general guarantee. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Insecure container and macOS VM are development profiles without authoritative isolation. | [Authority: CI profile schedule](../ci-schedule.md#ci-and-conformance-schedule) |
| Standalone Stage 2 EC2 evidence establishes neither EKS nor current resources. | [Authority: Stage 2 feasibility report scope](../../test-reports/stage-2-aws-feasibility.md#claim-boundary) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Bind NIC capability, EKS image/kernel/KVM/runtime, scheduling, CNI, CSI, OpenBao/revocation, and OTLP. | [Planned DESIGN-24.4–.12, .19–.22 / `future-eks-conformance-reference-v1`, `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind capacity/cost, upgrade, incident, deletion, teardown, and independent review. | [Planned STAGE5-45.02–.12 / `future-independent-review-reference-v1`, `future-operations-reference-v1`, `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Matrix has no accepted evidence or final decision. | [Authority: matrix purpose and non-authority](../stage-5-api-key-release-acceptance-matrix.md#purpose-and-non-authority) |

## Public wording guardrails

**Section authority:** [Authority: provisional matrix support claims](../stage-5-api-key-release-acceptance-matrix.md#machine-generated-support-and-unsupported-claims).

Do not say or imply that Cogs:

- prevents source exfiltration, prompt injection, confused-deputy actions, or all hypervisor escape;
- supports a provider, platform, model provider, concurrency level, auth class, or protocol without exact accepted evidence;
- has a production daemon, scheduler, ingress, deployment, release, GA status, compliance certification, or general security guarantee;
- deletes all copies, provides anonymous exports, captures every filesystem action, or restores every turn;
- makes revocation instant for existing streams or makes explicit-proxy TLS compatible with every client.

Use bounded statements with profile, exact revision/artifact, evidence link, applicability, date, and residual risk.

## Operator stop conditions

**Section authority:** [Authority: DESIGN mandatory invariants](../../../DESIGN.md#44-mandatory-invariants).

Stop and preserve uncertainty on any request to bypass the VM, use a container fallback, expose cloud/Kubernetes/OpenBao credentials, permit direct/wildcard egress, disable audit, share trusted and sandbox mounts, broaden OpenBao paths, persist refresh tokens, centralize sensitive content, infer ownership, perform broad deletion, or advertise beyond evidence. Such a request requires architecture/security review and may be prohibited outright.

## Egress raw-path capability

**Section authority:** [Authority: ADR 0308 route/path remediation](../../adr/0308-retire-paused-chain-and-authorize-external-review-remediation.md#narrow-implementation-choices).

Cogs authorizes the exact raw HTTP origin-form target received by Envoy. It does not URL-decode, Unicode-normalize, merge slashes, remove dot segments, or reinterpret a target before authorization. Envoy does not normalize paths and rejects escaped slashes. Authorization rejects percent encoding, non-ASCII bytes, whitespace/control bytes, backslashes, fragments, semicolons, repeated slashes, and segments made only of dots. Query-bearing routes accept only their sorted exact ASCII `key=value` list.

The supported built-in path capabilities are GitHub smart HTTP fetch for ASCII owner/repository names, unscoped npm metadata and tarballs with ASCII names, and the declared ASCII PyPI index/file targets. Real npm clients encode scoped metadata as `/@scope%2fpackage`; scoped npm is therefore unsupported. Encoded or Unicode Git, npm, and PyPI names are unsupported. Requests outside this capability fail closed.

Route patterns use a closed exact/prefix/segment-glob grammar. A star consumes one or more bytes within one segment. Cogs uses bounded iterative matching and emits separately derived RE2 for Envoy; it never executes configured or rendered route text as a JavaScript regular expression.

## Fixed Envoy resource profile

**Section authority:** [Authority: ADR 0309 bounded Envoy corrections](../../adr/0309-retire-post-review-H-and-authorize-bounded-corrections.md#seven-bounded-closures-not-claims-of-implementation).

The renderer owns immutable `cogs-egress-bounded-v1`: 32 admitted external TCP connections, HTTP/1-only outer CONNECT (one request per connection), eight concurrent inner H2 streams, 64 KiB watermarks/internal pipes, bounded H2 windows/frame queues, and application/authz/tunnel circuit breakers. Application capacity is allocated across expanded routes, not multiplied by a per-route default. Application LOGICAL_DNS keeps one logical host per cluster; it does not balance across all resolved addresses. Destination, SNI, certificate and per-request credential authorization are unchanged.

At 256 routes/authorities the conservative Envoy envelope is 256 inner requests, 288 outer-plus-inner streams, 547 external/application/authz network sockets and 1024 internal virtual endpoints, including the documented host/pool connection-breaker allowance. Resolver, process-owner and worker sockets and kernel backlog are additional. Active and pending requests refer to the same downstream streams, not independent additive populations. This assumes the existing single Envoy worker and one connection pool per cluster.

Headers, ClientHello inspection and TLS establishment each have 5-second deadlines; empty connections idle at 30 seconds, streams at 60 seconds. Application streams expire at 30 minutes and CONNECT at 60 minutes, with a separate 60-second blocked-flush timeout. Connection-duration settings initiate drain, not exact FD retirement. Continuous-high-watermark and delayed-close timers are not a universal wall-clock socket deadline; generation retirement remains the final fence.

Bodies intentionally stream without inspection or a cumulative byte ceiling, including accepted GET bodies and Git POST requests. No whole-body global filter, retry, hedge, preconnect override or response-body collector is installed. Healthy large transfers can exceed the former 30-second whole-response timer, but remain subject to idle/absolute lifetimes and backpressure. Git push, npm publish/scoped encoding and PyPI upload remain unsupported. Rate/bandwidth and rapid-reset CPU/fairness protection are deferred.

Fixed-heap and global downstream-connection monitors shed new work. No cgroup resource monitor is configured: Envoy's fixed mount-root paths do not prove process membership or the intended cgroup's scope. Watermarks and the arithmetic are **not a hard RSS bound**. The externally enforced worker-plus-Envoy 2 GiB shared cgroup and lifecycle admission/retirement are separate requirements, not delivered or verified by this renderer. Pinned-binary validation and sustained resource/client-pressure qualification remain required before a resource-safety claim. Matcher-only real Git/npm/pip tests do not test Envoy; Stage 1's npm CONNECT-auth incompatibility is not erased by them. The optional pinned Linux loopback diagnostic covers only accept/header/TLS-inspection rejection and recovery, not memory shedding, full-duration lifetimes or large-client streaming.

## Injected credential confidentiality

**Section authority:** [Authority: ADR 0308 credential-reflection boundary](../../adr/0308-retire-paused-chain-and-authorize-external-review-remediation.md#narrow-implementation-choices).

Cogs removes the configured credential header from upstream responses and excludes injected credentials from its structured logs, telemetry, route plan, and ordinary errors. This blocks direct same-name response-header reflection by the configured route.

This is **not** response data-loss prevention. A permitted upstream can store a credential, use it, or reflect it in another header or response body. Polling-based deletion detection cannot undo disclosure or an accepted upstream side effect. Integrations must trust the declared upstream and scope credentials to its minimum required authority.
