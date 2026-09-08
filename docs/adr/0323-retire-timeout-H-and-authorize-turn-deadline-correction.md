# ADR 0323: Retire timeout H and authorize turn-deadline correction

- Status: Accepted
- Date: 2026-09-08
- Deciders: Nick Byrne
- Scope: production Pi-turn timeout and malformed successful SFTP handle; no authoritative chain or AWS

## Context

Protected main H `0296252721fad0502dd4f41dacb1674e71b42bd6`, tree `e5c592fa3e9370fdfe0a948169878ad57ce6cc37`, passed the ADR 0319 correction gates. No producer, G, publisher/static observation, Q, mixed preflight, seven-runner qualification, production, provider, or AWS operation was started from it.

Subsequent review confirmed two P2 defects. Production passes schema-valid tool limits through 900 seconds to SSH adapters but leaves Pi's complete prompt operation on a default 60-second deadline. Separately, a successful SFTP `OPEN` callback carrying a malformed handle is rejected as an ordinary settled error even though the peer may have created the exclusive temporary file or allocated a remote handle that Cogs cannot retire.

Model-key revocation remains deferred. OpenBao deletion does not invalidate a key already hydrated into a worker. This correction grants no broader claim that every external P2 is closed.

## Decision

Retire exact H `0296252721fad0502dd4f41dacb1674e71b42bd6` as `ADR0323`. Preserve every prior retired revision, run, and artifact. Add the exact literal to the canonical policy and every current pre-checkout producer, publisher, static, preflight, qualification, diagnostic, and production mirror. Retirement remains exact-selection-only; descendant ancestry is not rejected.

### Authoritative launch turn deadline

Require `limits.turn_timeout_seconds` in every current runnable `cogs.dev/v1alpha1` launch document. Admit integers from 61 through 3600 only and require `turn_timeout_seconds >= tool_timeout_seconds + 60`. The 60 seconds is minimum configured headroom, not reserved time and not a guarantee that a late tool receives its full allowance.

The shared authenticated launch-to-Pi boundary is the sole authority: it derives exact milliseconds from the validated launch and callers cannot provide a competing turn option. Direct Pi construction requires a distinct `turnTimeoutMs`; `operationTimeoutMs` remains a bounded model-runtime operation setting and is not a compatibility alias or fallback for the turn.

Capture one monotonic deadline for the original prompt before Git setup. Steering and follow-up do not reset it. Recheck expiry after every awaited turn phase and immediately before success so delayed timer delivery cannot publish `run_settled` after expiry. Expiry requests bounded abort and suppresses late results; it never proves model, tool, channel, or worker retirement.

The existing tool contract is unchanged. `tool_timeout_seconds` controls the SSH adapter operation deadline. SFTP permit acquisition, channel opening, cancellation, close, cleanup, and actual retirement retain their independently bounded phases.

### Malformed successful SFTP handles

A no-error SFTP `OPEN` callback with a missing, oversized, or hostile handle is terminal uncertainty, for both read and exclusive create. Do not pass the malformed value to `close`, infer non-mutation, or unlink by pathname. Retain the unresolved open owner so the existing outer operation deadline seals manager readiness and retains channel/permit ownership. A duplicate later callback cannot heal the first uncertain observation or trigger speculative cleanup.

Malformed stats received after a valid owned handle remain ordinary hostile metadata rejection with existing confirmed cleanup semantics; they are not reclassified by this decision.

### Bounded accounting

Retain the ADR 0319 baseline and no-deletion-credit rules. Supersede only these ceilings after measured source/test planning:

| Bound | ADR 0319 | ADR 0323 |
|---|---:|---:|
| remediation global gross | 20,500 | 21,000 |
| lifecycle owner | 7,200 | 7,500 |
| completion owner | 2,800 | 3,100 |
| integration owner | 3,500 | 3,750 |
| conservative hard retained lines | 97,000 | 98,000 |
| correction global | 42,000 | 43,000 |
| post-H retained/workflow/global | 1,500 / 500 / 2,100 | 2,000 / 600 / 2,500 |

The integration/total planned new-file highs become 34/42 and the tracked-source ceiling becomes 1,465 for the ADR and isolated long-turn workflow. Every other owner, byte, file, deploy, and mutable-owner limit remains unchanged. No final-v5 control member is authorized.

ADR 0320 remains absent and reserved for a later corrected-H control decision. ADR 0322 remains absent and reserved for a later Q/qualification decision. This ADR does not consume either reservation.

## Required gates

1. Fast launch, authenticated-boundary, monotonic-expiry, Git-edge, SFTP uncertainty, composition, type, schema, and accounting tests pass.
2. One synthetic no-uplink production-composed turn exceeds 60 seconds through the real authenticated Pi and bash adapters, then proves durable native history. Run it once per settled candidate, not in every shard.
3. The full local suite passes before source review.
4. Two parallel reviews cover (a) timeout/SFTP semantics, tests, and retirement and (b) launch compatibility and governance, followed by one changed-since-review check.
5. Deterministic readiness evidence is regenerated twice after source settles; only affected checks are rerun after generated changes.
6. Exact-head protected CI, insecure-container, KVM, every Stage2 lifecycle shard, and one isolated long-turn job pass before protected merge. Candidate and protected-main trees must be equal.

## Consequences

H `0296252721fad0502dd4f41dacb1674e71b42bd6` is historical and non-authorizing. A gated descendant may be frozen only as a replacement Stage2 implementation H. Model-key revocation remains deferred.

This decision grants no producer, G, publisher, Q, mixed preflight, qualification, production, release, Stage3/Stage4 exit, provider, OpenTofu, SSM, inventory, deployment, campaign, or AWS authority. Stop after replacement-H freeze and before the authoritative chain.
