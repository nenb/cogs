# ADR 0014: Issue #65 model-auth scope and line budget

- Status: Accepted
- Date: 2026-07-15
- Decision owner: Nick Byrne
- Accepted by: Nick Byrne on 2026-07-15

## Context

`DESIGN.md` §4.1 defines the credential guarantee narrowly: a sandbox may exercise an approved credentialed capability, but it must not be able to read the real credential value from environment variables, files, Kubernetes, OpenBao, proxy administration interfaces, or its own outbound request headers. It also states that this does not prevent confused-deputy misuse or data exfiltration through an approved capability.

`DESIGN.md` §12 defines model authentication as trusted-worker traffic, not sandbox egress-proxy traffic. Organization/user API keys are stored in OpenBao, resolved by a scoped worker identity, supplied to Pi through runtime auth, and held in memory only. Subscription OAuth belongs to a future external daemon/platform broker; Cogs may receive only short-lived Pi-compatible access material and must not receive, persist, hydrate, refresh, log, or write back refresh tokens. The initial release remains API-key-only.

`IMPLEMENTATION.md` §22 requires scoped OpenBao retrieval for model API keys, runtime-only Pi auth, local development credentials only outside CI, and a small disabled external OAuth broker contract with tests for expiry, concurrency, refresh serialization, outage, and revoked authorization. `IMPLEMENTATION.md` §29 makes API-key model calls and simulated OAuth broker concurrency part of Stage 3 exit criteria. `IMPLEMENTATION.md` §47 requires an ADR for any subscription OAuth path that exposes refresh tokens to workers; this ADR explicitly does not authorize such a path.

ADR 0007 already accepted the API-key-first release and external broker ownership model. ADR 0013 accepted a narrow issue #64 SSH/SFTP/bash line-budget exception only; it explicitly does not authorize model-auth code, egress integration, API expansion, AWS work, release work, or unrelated Stage 3 growth.

Clean `main` after PR #80 is already above the original 5,000-line planning threshold:

```sh
find src -name '*.ts' -not -path '*/test/*' -print0 | xargs -0 wc -l | tail -1
# 5207 total
```

Current production module inventory:

| Production module | Lines |
|---|---:|
| `src/api/server.ts` | 1,126 |
| `src/launch/config.ts` | 96 |
| `src/launch/lifecycle.ts` | 343 |
| `src/pi/session.ts` | 1,037 |
| `src/ssh/bash-tool.ts` | 468 |
| `src/ssh/connection.ts` | 1,581 |
| `src/ssh/file-tools.ts` | 556 |
| **Total** | **5,207** |

The line-count definition remains production TypeScript under `src/`; tests, docs, scripts, deploy harnesses, and dev utilities do not count.

## Decision

Approve a bounded production line-count exception **only for issue #65 model authentication**.

Until issue #65 is closed, production TypeScript under `src/` may grow up to **6,050 lines** for API-key model auth and the disabled external OAuth broker contract. If completing issue #65 would cross 6,050 production `src/` TypeScript lines, implementation must pause for another scope/architecture ADR before adding more production code.

This is an issue-specific cap, not an unbounded Stage 3 exception. It does not pre-authorize egress proxy integration, Envoy, audit WAL, session export/history work, launch lifecycle expansion beyond auth readiness wiring, production broker implementation, AWS/EKS, release, or issue #64 follow-on work. Because ADR 0013 and issue #64 are still open, this aggregate cap must be read narrowly: model-auth additions alone may bring the repository total up to 6,050 production `src/` lines, but this does not reclassify, extend, or widen the separate issue #64 SSH/SFTP/bash authorization.

### Architecture

Add narrow auth ports/adapters rather than embedding provider, OpenBao, or broker logic directly into Pi session code:

- `ModelCredentialResolver` resolves a validated launch/user/provider/model request into short-lived runtime material.
- `OpenBaoModelApiKeyStore` retrieves API keys by scoped handle using OpenBao's HTTP API. It accepts a narrow scoped-token/identity port so later cluster wiring can provide a Kubernetes-derived OpenBao identity without changing the resolver boundary.
- `DevelopmentModelApiKeySource` is an explicitly selected development source, not an automatic fallback. It requires explicit development mode, absence of CI, and a fixed configured environment variable name for the selected provider/model. It must never activate automatically after OpenBao is missing, errors, or is unavailable; it must perform no ambient environment enumeration or credential discovery.
- `OAuthBrokerClient` is a small production type-only port declaring the external contract from ADR 0007 and `IMPLEMENTATION.md` §22.2, because §22 requires the contract. Fake broker state and concurrency simulation live under tests only. Subscription OAuth remains disabled in Cogs unless a later owner-approved decision enables it.
- Pi session construction continues to receive only runtime material and uses `AuthStorage.inMemory().setRuntimeApiKey(...)`; runtime material is cleared on failure/dispose and is never written to Pi JSONL, events, telemetry, errors, or exports.

No new production dependency is approved by this ADR. Use Node 22 built-in `fetch`/HTTP primitives for the OpenBao HTTP API. Any dependency requires a later reviewed amendment to this ADR or a superseding ADR before implementation.

### Expected production line budget

| Area | Estimated production lines |
|---|---:|
| Auth types, opaque handles, validation, redaction helpers | 90 |
| OpenBao API-key store over Node HTTP/fetch, timeout/error handling | 180 |
| Explicit development credential source with CI fail-closed guard | 55 |
| Resolver/orchestration and runtime material lifetime handling | 125 |
| OAuth broker contract and disabled production gate | 130 |
| Pi session/launch integration changes | 110 |
| Auth dependency readiness/docs hooks in existing lifecycle wiring | 60 |
| Contingency for fail-closed edge cases without compression | 93 |
| **Estimated addition** | **843** |
| **Cap from current 5,207** | **6,050** |

The estimate intentionally includes contingency so fail-closed validation, redaction, timeout, outage, and concurrency behavior are not compressed to satisfy the old planning threshold.

## Required behavior

Issue #65 implementation must preserve these boundaries:

- API keys are resolved from scoped OpenBao handles or from an explicitly configured development source only outside CI.
- OpenBao model credential handles are opaque launch/config values bound to this scope: only `users/...` and `organizations/...` handles are accepted. `sessions/...` handles are rejected. A `users/...` handle must match the launch `user_id`. Organization access is enforced by the scoped OpenBao identity/policy. Cogs must not accept arbitrary caller-built OpenBao paths.
- OpenBao HTTP access is bounded and strict: exact origin and mount configuration; HTTPS except explicit loopback development; timeout, abort, response-size, and content-shape bounds; KV-v2 path construction from the validated opaque handle; redirects disabled; generic redacted errors; readiness fails closed. OpenBao tokens remain memory-only and are never accepted from launch documents.
- Runtime model credentials exist only in trusted worker memory and Pi in-memory auth storage.
- No credential value appears in events, SSE, Pi JSONL, errors, telemetry, reports, export payloads, test output, or docs.
- OpenBao outage, broker outage, missing credentials, revoked credentials, malformed handles, unsupported provider/auth classes, and CI development-source attempts fail closed.
- Cogs never receives, persists, hydrates, refreshes, logs, exports, or writes back rotating OAuth refresh tokens.
- Subscription OAuth remains disabled and absent from the advertised support matrix until a future accepted decision, external broker ownership, provider-terms approval, and concurrency/revocation evidence exist.
- Local tests use a least-privilege local development token with a real local OpenBao fixture plus hostile HTTP unit fixtures for protocol/adversarial behavior. No Kubernetes-auth simulator is included in issue #65. Local OpenBao mounts/tokens used in tests are local-only and are destroyed/reset after tests.

## Non-decisions and exclusions

This ADR does not approve:

- enabling subscription OAuth;
- receiving or persisting OAuth refresh tokens in Cogs;
- a production daemon/platform broker implementation inside Cogs;
- egress proxy credential injection or Envoy integration;
- telemetry/export/history implementation beyond credential redaction requirements for issue #65;
- AWS, EKS, production, release, or stronger isolation claims;
- changing the Stage 3 authority boundary or replacing ADR 0007.

## Consequences

Implementation may proceed after owner acceptance of this ADR without unsafe compression of credential-boundary code. The cap is narrow and measurable: issue #65 only, 6,050 production `src/` TypeScript lines, with measured counts reported in affected PRs.

## Rejected alternatives

### Implement model auth under ADR 0013

Rejected. ADR 0013 is explicitly limited to issue #64 SSH/SFTP/bash work and does not authorize model-auth production code.

### Enable OAuth directly in Cogs

Rejected. ADR 0007 and `DESIGN.md` §12 reserve refresh-token ownership, refresh serialization, and provider terms review for an external broker. Any worker-visible refresh-token path crosses `IMPLEMENTATION.md` §47.

### Use Pi ambient auth discovery

Rejected. Cogs must not discover Pi `auth.json`, subscription credentials, or provider refresh state from ambient global/project locations. Runtime auth remains explicit and memory-only.

### Add a large OpenBao/OAuth SDK now

Rejected for this scope. Node's built-in HTTP/fetch surface is required for the small OpenBao API-key retrieval path. Any dependency needs a later reviewed amendment to this ADR or a superseding ADR before implementation.

### Automatically fall back to environment credentials when OpenBao fails

Rejected. Development credentials are an explicitly selected local source only. OpenBao absence, errors, or outage must fail closed and must not trigger ambient environment probing.
