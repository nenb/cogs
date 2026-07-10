# ADR 0007: Ship API keys first and keep OAuth refresh ownership external

- Status: Proposed
- Date: 2026-07-10
- Reviewer and interim broker owner: Nick Byrne

## Context

Concurrent workers must not hydrate, rotate, or overwrite one user's subscription OAuth refresh token. Provider terms for server-hosted multi-session subscription use also require explicit review.

## Decision

The initial release is API-key-only. Subscription OAuth is disabled and absent from the advertised support matrix. Cogs uses explicit request-scoped/in-memory authentication and does not discover Pi `auth.json`, subscription credentials, or provider refresh state from ambient global/project locations.

Keep the Stage 3 broker client contract and fake broker:

```text
GetAccessMaterial(user, provider, model)
InvalidateAccessMaterial(reference)
GetExpiry(reference)
```

Cogs may receive only short-lived Pi-compatible access material and never receives or persists refresh tokens. Epic I is assigned to Nick Byrne until a daemon/platform team exists, then will be reassigned. Its milestone is post-MVP unless explicitly reprioritized.

## Consequences

- API-key release work is independent of subscription readiness.
- Enabling subscription OAuth requires the real external single-owner broker, provider-terms approval, and Stage 5 concurrency/revocation/account-switch tests.
- Any path exposing refresh tokens to workers crosses an ADR boundary and is prohibited by the current decision.
