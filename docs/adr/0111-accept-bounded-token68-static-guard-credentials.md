# ADR 0111: Accept bounded token68-style static-guard credentials

- Status: Accepted under the owner's standing issue-42 non-AWS replacement authority
- Date: 2026-08-22
- Scope: One fail-closed correction generation for the consumed authenticated no-KVM static-control event

## Context

The authenticated replacement static-control event was consumed by run `32560385792`, attempt 1, on exact protected `main` workflow head `7ccb35d14d749a0ef14602889ce2b52934c03d4d`, with reviewed implementation H `67b1ca45f101f98c56b2717549e9252a38a9f2a1`. It completed with conclusion `failure` in the first pre-checkout guard and emitted the safe diagnostic `TOKEN_REJECTED`. GitHub's run-scoped `${{ github.token }}` has a valid visible bearer-token shape broader than the guard's `[A-Za-z0-9_]+` expression.

The guard failure occurred before checkout, immutable acquisition, candidate production, upload, KVM action, or AWS action. The source/effect steps were skipped and the run has zero artifacts. The earlier run `32558263561`, attempt 1, remains separately consumed at workflow head `a201d5688013377069b6fb4a36159360dc307cae` with reviewed H `62bcfbcd58f90d0e329683e3297693c32bb71877`; it also completed with conclusion `failure` before those effects and has zero artifacts. Neither failure creates retry authority by itself.

ADR 0109 and ADR 0110 carry the owner's standing issue-42 authority through bounded non-AWS correction and replacement. Under that authority, this decision replaces only the failed-before-effects token-shape guard generation. It establishes no general retry mechanism.

## Decision

Use `cogs.stage2-static-control-dispatch-guard/v3`, embedded byte-for-byte as the first workflow step. Accept only 20 through 256 ASCII characters matching a bounded token68-style subset: one or more `A-Za-z0-9-._~+/` characters followed by at most one optional terminal `=`. Reject an initial or interior `=`, repeated padding, non-ASCII, spaces, tabs, line endings, NUL/DEL and all other control or header-separator characters. The token remains confined to the first step's `ACTIONS_READ_TOKEN`, is sent only in the Bearer header to the fixed HTTPS Actions-runs endpoint, and is never logged, persisted, placed in a URL, passed to a child, or exposed to another step. Permissions remain exactly `actions: read`; proxy, redirect, ambient credential, OIDC, cloud, and Python-override restrictions remain unchanged.

The complete bounded single-page workflow history is closed world. It must contain both and only these consumed predecessor identities plus the current generation:

1. run `32558263561`, attempt 1, exact repository/head repository/path/branch/event, workflow head `a201d5688013377069b6fb4a36159360dc307cae`, title binding H `62bcfbcd58f90d0e329683e3297693c32bb71877`, status `completed`, conclusion `failure`;
2. run `32560385792`, attempt 1, exact repository/head repository/path/branch/event, workflow head `7ccb35d14d749a0ef14602889ce2b52934c03d4d`, title binding H `67b1ca45f101f98c56b2717549e9252a38a9f2a1`, status `completed`, conclusion `failure`.

A missing, duplicate, or mutated predecessor rejects. Every unknown historical run rejects. The next reviewed-H generation must contain exactly one current run and its ID must be the singular earliest current-generation ID; a second creation rejects the generation. All prior pagination, completeness, API, identity, event and bounded-diagnostic fail-closed behavior remains.

The implementation commit H7 contains v3 behavior, this ADR, and hostile token-shape/predecessor tests. Its direct child G7 changes only the workflow/guard/static-test reviewed-H binding to exact H7 and deterministic readiness bindings. No dispatch is part of either commit.

## Authority boundary

This ADR authorizes local implementation, hostile/static tests, exact H7 then direct-child G7 commits, and deterministic readiness regeneration. It authorizes no workflow dispatch or rerun, artifact claim, KVM action, AWS credential/API/provider/OpenTofu/SSM/inventory/campaign execution, deployment, release, or future replacement. Any terminal outcome remains fail closed and grants no further attempt.
