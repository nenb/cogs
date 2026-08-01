# Stage 4 teardown evidence-order verifier

This first Stage 4 slice is a bounded, pure, local evidence-order classifier. It is deliberately non-authoritative. It cannot remove resources, select targets, render operations, contact a provider, inspect a machine, or establish that an evidence digest describes a truthful observation.

## Boundary

`scripts/stage4-teardown-verifier.ts` accepts one already-decoded metadata object and returns one immutable verdict. The accepted input contains only:

- the fixed plan version;
- a source SHA-256 digest;
- a profile SHA-256 digest; and
- exactly eight fixed phase rows containing a phase, its fixed producer class, a state, and an evidence SHA-256 digest only when the state is `observed`.

There are no resource names or identifiers, deletion targets, provider payloads, executable callbacks, paths, URLs, credentials, logs, or arbitrary reason strings. The evaluator performs no I/O. The plan schema defines the structural canonical form; this slice does not parse bytes or claim that an in-memory object had a particular JSON serialization.

## Fixed evidence order

| Order | Evidence phase | Fixed producer class |
| ---: | --- | --- |
| 1 | `freeze-reconcilers` | `control-observer` |
| 2 | `close-admission` | `admission-observer` |
| 3 | `revoke-credentials` | `credential-observer` |
| 4 | `revoke-readiness` | `readiness-observer` |
| 5 | `remove-session-workloads` | `workload-mutator` |
| 6 | `verify-kubernetes-zero` | `kubernetes-zero-observer` |
| 7 | `remove-cluster-infrastructure` | `infrastructure-mutator` |
| 8 | `verify-independent-cloud-zero` | `independent-cloud-zero-observer` |

The phase names describe the evidence sequence, not recommended actions. In particular, an `awaiting-evidence` verdict asks only for the digest associated with its one `next_phase`. It is not permission to perform that phase.

Every row is `pending`, `observed`, or `uncertain`. An observed row must have one lowercase SHA-256 digest. Pending and uncertain rows must not have an evidence field. Observed rows must be a contiguous prefix. Evidence digests cannot be replayed between phase rows or reused from the source/profile fields.

The two mutator-attestation classes are intentionally distinct from observer classes. Final zero is accepted only from the fixed `independent-cloud-zero-observer` class, never from either mutator class. This is class separation only; a digest and class label are not an identity, signature, provenance proof, or provider observation.

## Verdicts

- `awaiting-evidence`: the prefix is certain and incomplete. `next_phase` is exactly the first pending phase.
- `preserve-uncertain`: input is malformed, evidence is out of order or replayed, a producer class is wrong, or any row is uncertain. `next_phase` is always null.
- `zero-verified`: all eight rows are observed in order and the final row has the independent observer class.

Uncertainty is sticky for an input snapshot: later observed rows cannot make a plan containing an uncertain row complete. Recovery requires preserving the external evidence and resolving uncertainty outside this verifier; there is no override state or force path.

`zero-verified` means only that the supplied fixed digests satisfy this local ordering contract. It does **not** prove provider inventory zero, authorize publication as infrastructure evidence, identify anything to remove, or replace an independently reviewed Stage 4 ownership, observation, and execution design.

## Operational separation

Evidence collection and any future execution mechanism remain outside this module and require separate review. Do not feed the verdict to an operation renderer or treat a phase string as an executable instruction. Provider inventory, ownership/incarnation checks, account and cluster binding, expiry and cost controls, and independent artifact custody are explicitly not implemented in this slice.

If the verdict is `preserve-uncertain`, stop. Retain evidence under the applicable external custody process and escalate through a separately approved recovery procedure. This verifier provides no recovery or cleanup procedure.
