# ADR 0015: Stage 3 egress integration scope and line budget

- Status: Proposed
- Date: 2026-07-15
- Decision owner: Nick Byrne

## Context

Issue #66 is the Stage 3 gate for integrating the selected Envoy egress path with real Cogs/OpenBao authorization, audit WAL, revocation, completion, and conformance evidence. This is docs-only authorization for a future implementation PR set; it does not add production code.

ADR 0011 selected Envoy 1.38.3 for initial HTTP/HTTPS egress and deliberately kept the architecture static and inspectable. The Stage 1 Envoy candidate proved the proxy mechanism with fixture identity/authz/audit dependencies, but ADR 0011 explicitly requires Stage 3 reruns against real Cogs authorization, durable WAL, completion, OpenBao integration, and telemetry boundaries before any production or release claim.

ADR 0003 keeps the real credentials, trusted proxy, and CA private key outside the sandbox VM. The guest may receive only a public CA, placeholders, and a short-lived per-session proxy capability. ADR 0008 permits only metadata central telemetry and forbids prompts, model output, source, complete commands, paths, HTTP queries/bodies, credentials, placeholders, and tool output in OTLP or other central logs.

ADR 0013 authorized only issue #64 SSH/SFTP/bash work. ADR 0014 authorized only issue #65 API-key model authentication plus the disabled OAuth broker contract. Neither ADR authorizes Envoy integration, egress credential injection, audit WAL, egress telemetry/completion, OpenBao PKI, route groups, revocation/drain, or Stage 1 conformance replacement.

Clean `main` after PR #82 is at **5,695** production TypeScript lines under `src/`:

```sh
find src -name '*.ts' -not -path '*/test/*' -print0 | xargs -0 wc -l | tail -1
# 5695 total
```

The line-count definition remains production TypeScript under `src/`; docs, tests, scripts, schemas, dev fixtures, CI workflows, generated evidence, and local harnesses do not count.

## Decision

Approve a bounded production line-count exception **only for issue #66 secure egress integration**.

Until issue #66 is closed, production TypeScript under `src/` may grow up to **8,500 lines** for the components and behavior listed in this ADR. This permits about **2,805** production `src/` TypeScript lines beyond the current 5,695-line baseline. If completing issue #66 would cross 8,500 production `src/` TypeScript lines, implementation must pause for another scope/architecture ADR before adding more production code.

This is an issue-specific aggregate cap, not a broad Stage 3 reset. It does not widen ADR 0013's issue #64 SSH/SFTP/bash authorization or ADR 0014's issue #65 model-auth authorization. Remaining issue #64 or issue #65 follow-up work must not consume the issue #66 budget. Future changes to model auth, SSH tools, session export, skills, Git checkpoints, AWS/EKS, release, or unsupported protocols need their own authority.

### Required Envoy architecture

Issue #66 implementation must preserve ADR 0011:

- Envoy remains **1.38.3**, pinned to the exact ADR 0011 OCI digest unless a later accepted update decision changes it.
- Cogs generates deterministic immutable static Envoy configuration from validated launch/integration presets.
- No Lua, xDS, SDS, original-destination routing, dynamic-forward-proxy, cluster-header routing, Envoy admin endpoint, config dump endpoint, or direct fallback path may be enabled.
- Explicit proxy `CONNECT` plus host-specific inner TLS termination remains the MVP HTTPS shape.
- Envoy uses native v3 `ext_authz` with `failure_mode_allow: false`.
- Routes enforce exact configured hosts, registered upstream dial targets, ports, methods, canonical path behavior, declared query behavior, SNI/Host/`:authority` consistency as bounded by ADR 0011, and credential header strip/overwrite behavior.
- Proxy capability material is stripped before upstream forwarding and must never become an upstream credential.
- Route, trust, credential, certificate, and OpenBao metadata changes use resource replacement with drain, not mutable in-place expansion.

OpenBao is **not** an Envoy SDS provider for this scope. This ADR does not approve building an xDS/SDS bridge. Static secret-bearing material is rendered only into trusted tmpfs and replaced on rotation/revocation.

### Dependency and binding subgate

Issue #66 must not start the production `ext_authz` authorization-service implementation until a reviewed ADR amendment or dependency decision selects the binding strategy. That subgate must:

- choose generated/pinned Envoy v3 API bindings matching Envoy 1.38.3, or a documented equivalent generated surface;
- count any checked-in generated TypeScript under `src/` against the issue #66 line cap;
- verify license compatibility, source integrity, pinned upstream/proto revision, transitive import closure, and reproducibility of generated artifacts;
- explicitly decide whether the existing `@grpc/grpc-js@1.14.4` dev dependency is promoted for production use;
- decide whether `@grpc/proto-loader@0.8.1` or another loader/codegen component is needed. It is only a candidate, not accepted by this ADR;
- avoid promoting the handwritten Stage 1 protobuf codec into production.

This ADR does not authorize a new production loader/codegen dependency or a vendored Envoy proto closure by itself.

### Authorized production components

Issue #66 may add narrow production modules equivalent to these surfaces:

| Area | Estimated production lines |
|---|---:|
| Validated egress route groups, preset lowering, canonical Envoy static config model/rendering, config validation hooks | 650 |
| Generated/pinned Envoy v3 `ext_authz` binding assets and wrapper, counted if checked in under `src/`, plus minimized request/response mapping | 450 |
| Loopback-only authorization/completion service, capability checks, denial mapping, and lifecycle integration | 320 |
| Synchronous append-only intent audit WAL before credential use, bounded WAL errors/full handling, and replay/correlation helpers | 320 |
| Bounded completion queue and OTLP metadata-only buffering/drop accounting | 180 |
| Callback-scoped OpenBao secret/metadata/PKI access, certificate lifetime checks, and trusted tmpfs materialization/cleanup | 320 |
| Revocation polling, metadata-version detection, deny-new/drain/replacement orchestration | 240 |
| Launch/session wiring and guest proxy environment/capability injection without widening SSH/model-auth APIs | 130 |
| Contingency for fail-closed validation/redaction/error paths without compression | 195 |
| **Estimated addition** | **2,805** |
| **Cap from current 5,695** | **8,500** |

This estimate is intentionally larger than the first draft because the existing Stage 1 Envoy config generator is already 577 test-infrastructure lines before production preset lowering, launch validation, trusted tmpfs, OpenBao, and lifecycle adaptations. The revised cap is still for Cogs-side configuration/authz/WAL/OpenBao integration only. It does not authorize custom Envoy in-process code, Lua, dynamic proxy behavior, or a Cogs proxy implementation, so the line increase alone does not revisit ADR 0011.

If implementation requires substantially more custom security-critical code than this estimate, especially custom HTTP/TLS parsing, handwritten protobuf decoding, dynamic proxy behavior, or in-process proxy code, ADR 0011 must be revisited before proceeding. Hitting the 8,500 cap also requires a new ADR even if the architecture remains unchanged.

## Required behavior

Issue #66 implementation must satisfy these requirements:

- Generate immutable route groups from validated presets/configuration; unsupported hosts, methods, paths, queries, redirects, auth classes, protocols, or clients fail closed.
- Resolve integration credentials only through scoped OpenBao handles using trusted-worker identity. Local OpenBao/PKI token wiring remains functional local evidence only. Kubernetes-auth production wiring is not approved by this ADR. No OpenBao token or real integration credential may enter the sandbox, launch document, events, logs, telemetry, Pi JSONL, exports, or guest-visible files.
- Obtain proxy leaf certificates through OpenBao PKI. The CA private key remains in OpenBao/outside the sandbox. Leaf certificate lifetime must exceed maximum session lifetime plus the configured startup/drain margin or startup fails closed.
- Place secret-bearing Envoy config, credentials, and private keys only in trusted tmpfs. Cleanup must run on normal shutdown and failure paths; remaining tmpfs material after cleanup is a failure.
- Generate a high-entropy per-session proxy capability, expose it only through the guest proxy configuration path needed by supported clients, and strip it before upstream forwarding.
- Restrict guest reachability to the proxy listener port. Envoy is not the isolation boundary; direct internet, direct DNS/DoH, UDP, IPv6 bypass where unsupported, arbitrary TCP/TLS, nested CONNECT, and non-proxy egress must fail closed under the authoritative Linux/KVM profile.
- Append a durable authorization intent to the WAL synchronously before any credentialed request can receive injected credentials. Authorization service outage, WAL unwritable, WAL full, malformed request, route miss, unsupported credential class, missing OpenBao secret, revoked metadata, or capability failure denies the request.
- Record bounded completion metadata correlated to the authorization intent. Completion/OTLP buffering may lag, bound, and drop with counters, but must not stop unrelated agent progress and must not contain forbidden metadata from ADR 0008.
- Poll OpenBao metadata within the configured revocation bound. Missing, revoked, or version-changed secret/PKI/policy metadata denies new requests, drains old resources, invalidates old capabilities, and replaces Envoy resources within the configured bound.
- Rerun the full applicable Stage 1 conformance suite after Cogs integration. All Stage 1 audit/revocation `stubbed` results must be replaced by real Stage 3 results for the Cogs authorization path, WAL, completion, OpenBao metadata, revocation, telemetry, and Linux/KVM bypass rows.
- Preserve the issue #65 model-auth boundary: model provider API keys for Pi are trusted-worker runtime auth, not egress-proxy credentials. Cogs still must not receive, persist, hydrate, refresh, log, export, or write back OAuth refresh tokens.

## Non-decisions and exclusions

This ADR does not approve:

- AWS, EKS, Kubernetes controller work, production deployment, release eligibility, or stronger isolation claims;
- relaxing default-deny networking or adding direct internet fallback;
- Envoy admin, xDS, SDS, Lua, original-destination, dynamic-forward-proxy, cluster-header routing, direct fallback, or dynamic mutable route expansion;
- application gRPC, SigV4/HMAC signing, upstream mTLS, database protocols, SSH egress, WebSockets, arbitrary TCP/TLS, nested CONNECT, UDP, QUIC/HTTP/3, guest DNS/DoH, or native Node/npm support beyond separately measured launcher/proxy-agent decisions;
- subscription OAuth enablement or any worker-visible OAuth refresh-token path;
- session export/history, skills, Git checkpoints, or broader policy/observability work except the minimum egress metadata and completion surfaces needed for issue #66;
- adding production dependencies, generated binding artifacts, loader/codegen dependencies, or vendored Envoy proto closures without the dependency/binding subgate above or a superseding ADR.

## Consequences

Accepted issue #66 implementation can proceed without unsafe compression of route validation, authorization, WAL, OpenBao, tmpfs cleanup, revocation, and conformance code. The cap is measurable in every PR: report current production `src/` TypeScript lines and keep issue #66 additions within the 8,500 aggregate cap.

Security claims remain bounded. Insecure-container/local OpenBao evidence is functional-only unless backed by security-labelled authoritative Linux/KVM CI. No release, AWS, EKS, or production readiness claim follows from this ADR.

## Explicit unresolved decisions

These choices remain unresolved and must be settled by issue-specific PR review, the dependency/binding subgate, or a later ADR before implementation relies on them:

- exact Envoy v3 `ext_authz` generated-binding source, generator, checked-in artifact location, and reproducibility process;
- whether `@grpc/grpc-js@1.14.4` is promoted from dev to production dependency;
- whether `@grpc/proto-loader@0.8.1` or any other loader/codegen dependency is introduced;
- exact local OpenBao PKI mount/role/path conventions for functional fixtures;
- production Kubernetes-auth/OpenBao identity wiring, which is not authorized here;
- exact OTLP exporter dependency/path, if any beyond existing metadata-only test fixtures;
- exact host firewall/guest reachability mechanism for authoritative Linux/KVM enforcement;
- exact tmpfs path, ownership, permissions, capacity, and cleanup verification mechanism;
- exact drain timeout/replacement bound values and scale limits.

None of these unresolved choices may be filled by direct egress fallback, handwritten security parsers, Envoy dynamic configuration, in-process proxy scripting, or worker-visible refresh tokens.

## Rejected alternatives

### Treat ADR 0011 as enough for issue #66 implementation

Rejected. ADR 0011 selected Envoy and required Stage 3 reruns, but it did not authorize the real Cogs/OpenBao/WAL production implementation or a post-PR #82 line budget.

### Copy the Stage 1 handwritten protobuf codec into production

Rejected. The Stage 1 codec is test infrastructure. Production `ext_authz` should use generated, pinned Envoy API bindings or another reviewed generated surface.

### Use OpenBao as Envoy SDS/xDS input

Rejected for this scope. The MVP keeps static immutable Envoy config and trusted tmpfs materialization with resource replacement.

### Fall back to direct egress or another proxy on Envoy/config/authz failure

Rejected. Failures deny egress. Switching proxy or enabling direct traffic requires a new ADR and conformance evidence.

### Expand protocol/client support while integrating egress

Rejected. Unsupported clients/protocols fail closed until each has a reviewed contract and conformance evidence.
