# Stage 4 teardown claimed-evidence order classifier

This Stage 4 slice is a bounded, pure, local classifier. It is deliberately non-authoritative. It cannot remove resources, select targets, render operations, contact a provider, inspect a machine, authenticate an artifact, or establish that a digest describes a truthful observation.

## Boundary

`scripts/stage4-teardown-verifier.ts` accepts one strict, already-decoded metadata object and returns one immutable verdict. The accepted input contains only:

- the fixed plan version;
- source and profile SHA-256 digests; and
- exactly eight fixed rows containing a phase, a claimed producer category, a state, and the digest required by that state.

There are no resource identifiers, deletion targets, provider payloads, callbacks, paths, URLs, credentials, logs, or arbitrary reason strings. The evaluator performs no process, network, environment, filesystem, or provider operation. It catches hostile object-introspection traps and returns `preserve-uncertain` rather than allowing the trap to escape.

## Fixed claimed-evidence order

| Order | Claimed-evidence phase | Claimed producer category |
| ---: | --- | --- |
| 1 | `freeze-reconcilers` | `control-observer` |
| 2 | `close-admission` | `admission-observer` |
| 3 | `revoke-credentials` | `credential-observer` |
| 4 | `revoke-readiness` | `readiness-observer` |
| 5 | `remove-session-workloads` | `workload-mutator` |
| 6 | `verify-kubernetes-zero` | `kubernetes-zero-observer` |
| 7 | `remove-cluster-infrastructure` | `infrastructure-mutator` |
| 8 | `record-external-cloud-inventory-claim` | `claimed-external-inventory-observer` |

Phase names are evidence-order labels, not recommended or executable actions. An `awaiting-evidence` verdict asks only for the next claimed row; it grants no permission to perform that phase.

Every `producer_class` is a caller-claimed fixed category only. A matching category proves no producer identity, credential, signature, provenance, custody, organizational separation, or observation authority. In particular, `claimed-external-inventory-observer` does not prove that an external party or provider inventory was observed.

A row is `pending`, `observed`, or `uncertain`. An observed row requires `evidence_sha256`; an uncertain row requires `uncertainty_artifact_sha256`; a pending row has neither. The uncertainty digest identifies an externally retained artifact but does not make that artifact true or observed evidence. Observed rows must form a contiguous prefix, and artifact digests cannot be replayed within the plan or reused from source/profile fields.

## Semantic bindings and verdicts

For every fully strict decoded plan, the verdict contains:

- `plan_sha256`, a domain-separated SHA-256 digest of deterministic canonical encoding of the normalized semantic plan; and
- `evidence_root_sha256`, a separately domain-separated digest of the ordered row states and their evidence or uncertainty-artifact digests.

Changing any evidence or uncertainty-artifact digest changes both bindings. Object key order does not. These values bind the classified semantic object, **not original JSON bytes, artifact contents, producer provenance, or provider truth**. They may be null when malformed structure prevents strict decoding. `accepted_phase_count` is the validated contiguous observed prefix when row inspection reached that point, and otherwise null.

Verdicts are:

- `awaiting-evidence`: the strict observed prefix is incomplete; `next_phase` is its first pending phase.
- `preserve-uncertain`: input is malformed, evidence is uncertain, out of order, or replayed, or a fixed claimed category is wrong; `next_phase` is null.
- `evidence-order-complete` / `STAGE4_EVIDENCE_ORDER_COMPLETE`: all eight claimed evidence rows are observed in order. This is only terminal ordering completion.

Every verdict fixes `authority: local-teardown-order-classifier`, `cloud_inventory_observed: false`, `cloud_execution_observed: false`, `stage4_exit_satisfied: false`, and `release_eligible: false`. There is no zero-verified verdict. No local classifier result can serve as cloud inventory, cleanup, campaign-exit, or release evidence.

Uncertainty is sticky for an input snapshot: later observed rows cannot resolve an uncertain row. Preserve the artifact identified by `uncertainty_artifact_sha256` under an external custody process and use a separately approved recovery procedure. This module provides no override, recovery, cleanup, execution, or publication path.
