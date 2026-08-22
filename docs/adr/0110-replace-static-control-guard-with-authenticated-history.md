# ADR 0110: Replace the static-control guard with authenticated history

- Status: Accepted under the owner's standing issue-42 non-AWS correction instruction
- Date: 2026-08-22
- Scope: One fail-closed replacement generation for the consumed no-KVM static-control event

## Context

The first-created static-control event was consumed by run `32558263561`, attempt 1, on exact protected `main` workflow head `a201d5688013377069b6fb4a36159360dc307cae`, with reviewed implementation H `62bcfbcd58f90d0e329683e3297693c32bb71877`. It concluded `failure` in the first pre-checkout guard. No checkout, immutable acquisition, candidate production, upload, artifact, KVM action, or AWS action occurred.

ADR 0108's guard queried the public Actions API without authentication. GitHub-hosted runners share public API rate-limit pressure, and the guard collapsed transport, HTTP, and response failures into an undifferentiated exit. That design is not a reliable way to distinguish a closed admission decision from transient unauthenticated API exhaustion. The consumed run does not create retry authority by itself.

ADR 0109 carries the owner's standing instruction through non-AWS correction, exact-head review, and one no-KVM static-control event. Under that standing authority, this decision replaces only the failed-before-effects guard generation. It does not reinterpret the predecessor as unconsumed and does not establish a general retry mechanism.

## Decision

Use `cogs.stage2-static-control-dispatch-guard/v2`, embedded byte-for-byte as the first workflow step before checkout or any other source effect. Workflow permissions remain exactly `actions: read`. The sole credential is the run-scoped ephemeral `${{ github.token }}`, exposed only to that step under the fixed name `ACTIONS_READ_TOKEN`. The guard requires a bounded ASCII token shape, sends it only as a Bearer `Authorization` header to the fixed HTTPS Actions-runs endpoint, disables proxies, rejects redirects, and never prints, persists, includes in a URL, passes to a child, or exposes the token to another step. Standard GitHub, OIDC, cloud, proxy, and Python override credential environments remain denied. Checkout remains unauthenticated.

The complete single-page history is closed world. Exactly one predecessor is permitted: run `32558263561`, attempt 1, `workflow_dispatch`, exact repository/head repository/path, workflow head `a201d5688013377069b6fb4a36159360dc307cae`, title binding H `62bcfbcd58f90d0e329683e3297693c32bb71877`, completed with conclusion `failure`. Any changed predecessor field, duplicate, absent predecessor, additional predecessor generation, or other historical run rejects.

For the corrected reviewed-H generation, the current event must remain attempt 1 on protected `main`, with the fixed repository, workflow reference, exact input/title, and a workflow head distinct from the consumed predecessor. Its run ID must be the earliest numeric ID in that exact generation, and the generation must contain exactly one run. A second creation therefore rejects both the later run and any still-running earlier run when it re-observes history. Pagination, an over-bound or incomplete count/list, duplicate IDs, malformed JSON or run identity, unknown history, redirect, timeout, API error, HTTP 403/429, or any other uncertainty rejects before effects.

Diagnostics are limited to a fixed allowlist of short v2 classification codes. Exception text, response bodies and headers, URLs containing credentials, run listings, and token material are never emitted. `API_FORBIDDEN_OR_RATE_LIMITED` intentionally does not claim whether a 403 was permissions policy or rate limiting.

The implementation commit H contains the replacement behavior, ADR, and hostile tests. Its direct child G changes only the workflow/guard/static-test reviewed-H binding to exact H and regenerates deterministic readiness evidence. This preserves the directional H/G model: H does not bind itself, and G contains no implementation behavior change.

## Authority boundary

This ADR authorizes the local implementation, hostile/static tests, exact H then direct-child G commits, and deterministic readiness regeneration requested by the owner. It authorizes no workflow dispatch or rerun now. It also grants no artifact claim, KVM action, AWS credential/API/provider/OpenTofu/SSM/inventory/campaign execution, deployment, production use, release, fallback, or generalized future replacement. Any terminal outcome of the corrected generation remains fail closed and grants no further attempt.
