# ADR 0112: Transport the static-guard token without shape assumptions

- Status: Accepted under the owner's explicit issue-42 correction instruction
- Date: 2026-08-22
- Scope: One fail-closed correction generation for the consumed v3 no-KVM static-control event

## Context

Run `32561859288`, attempt 1, consumed the v3 static-control generation on exact protected `main` workflow head `549126bd7ba72d571d53113722e766967aaa0d23`, with reviewed implementation H `5f8c04899422ccf546c0f500b3647a5816b2675c`. It completed with conclusion `failure` in the first pre-checkout guard and emitted only `TOKEN_REJECTED`. Checkout, source materialization, immutable acquisition, candidate production and upload were skipped. The run has zero artifacts and produced no source effect. The always-run cleanup encountered the hosted runner's pre-existing `/dev/kvm` check after removing only the absent owned paths; it does not change those facts.

The same no-effect facts remain true for exact attempt-one predecessor runs `32558263561` and `32560385792`. None of the three failures, separately or together, creates retry authority. The v3 token68-style allowlist still inferred opaque token contents and the `${{ github.token }}` transport did not establish a usable credential before that inference rejected it.

## Decision

Use `cogs.stage2-static-control-dispatch-guard/v4` as the byte-identical first workflow step and transport the run-scoped credential exactly once through that step's `ACTIONS_READ_TOKEN` environment entry using `${{ secrets.GITHUB_TOKEN }}`. Workflow permissions remain exactly `actions: read`. The token is unavailable to every later step and remains absent from URLs, subprocesses, files and diagnostics.

Treat the credential as an opaque HTTP field value rather than a token format. Require a nonempty value of 1 through 1,024 ASCII bytes, each in visible range `0x21` through `0x7e`. This accepts realistic long values and every visible punctuation character without guessing GitHub's current or future token syntax. It rejects space and all other whitespace, CR/LF header injection, NUL, DEL, controls and non-ASCII. Those restrictions are exactly the HTTP header-safety boundary; no narrower opaque-content allowlist is imposed.

Fail with one of three fixed bounded pre-API categories: `TOKEN_MISSING` for an absent or empty transport, `TOKEN_BOUND` for an oversized visible-ASCII value, and `TOKEN_CHAR` for a non-ASCII or non-visible character. Diagnostics contain no token, length, response body or exception text. Once a safe value is transported, an API 401 or 403 maps to the fixed `API_AUTH_REJECTED` category without reading or emitting a body; 429 and all existing redirect, availability, completeness and response failures remain fail closed.

The complete bounded single-page workflow history is closed world. It must contain all three and only these exact consumed predecessors plus the current generation:

1. run `32558263561`, attempt 1, workflow head `a201d5688013377069b6fb4a36159360dc307cae`, title H `62bcfbcd58f90d0e329683e3297693c32bb71877`, completed failure, zero artifacts and no source effect;
2. run `32560385792`, attempt 1, workflow head `7ccb35d14d749a0ef14602889ce2b52934c03d4d`, title H `67b1ca45f101f98c56b2717549e9252a38a9f2a1`, completed failure, zero artifacts and no source effect;
3. run `32561859288`, attempt 1, workflow head `549126bd7ba72d571d53113722e766967aaa0d23`, title H `5f8c04899422ccf546c0f500b3647a5816b2675c`, completed failure, zero artifacts and no source effect.

Repository, head repository, workflow path, branch, event, head, title, attempt, status and conclusion remain exact guard bindings. A missing, duplicate, mutated or unknown run rejects. The current generation must be singular and its run ID must be its earliest ID; any second creation rejects.

The implementation commit H8 is a direct child of current protected `main` and contains v4, this ADR, and hostile transport tests. Its direct child G8 changes only the reviewed-H binding to exact H8 and deterministic readiness bindings. Neither commit dispatches a workflow.

## Authority boundary

This decision authorizes local implementation, hostile/static tests, exact H8 and direct-child G8 commits, and deterministic readiness regeneration. It authorizes no workflow dispatch or rerun, artifact claim, KVM action, AWS credential/API/provider/OpenTofu/SSM/inventory/campaign execution, deployment, release or future replacement. Every terminal outcome remains fail closed and grants no further attempt.
