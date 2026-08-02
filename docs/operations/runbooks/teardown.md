# Draft teardown and orphan-resource verification guide

This is a non-executable evidence and escalation plan. It contains no provider command, resource target, deletion selector, callback, URL, credential, or cluster operation. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future attempt may bind account/region/attempt/source/artifact/state/manifest/TTL and authenticated operator/observer. | [Authority: offline readiness required identities](../stage-4-offline-readiness.md#stopdestroy-and-identities) |
| A future independent observer may have read-only inventory separated from operator/approver. | [Authority: ownership separation register](../ownership.md#initial-ownership-and-approval-register) |
| Current offline package has none of those bindings/capabilities. | [Authority: offline readiness current blockers](../stage-4-offline-readiness.md#honest-image-nic-and-runtime-blockers) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Every future outcome requires state-bound destruction then independent read-only inventory. | [Authority: offline readiness non-executable stop/destroy paths](../stage-4-offline-readiness.md#stopdestroy-and-identities) |
| Inventory uncertainty blocks success/retry; approval is one attempt and grants no correction/retry. | [Authority: offline readiness one-attempt authority](../stage-4-offline-readiness.md#stopdestroy-and-identities) |
| Storage uncertainty preserves state/resources/attachments/lease; expiry grants no takeover. | [Authority: storage/launch exclusive writer lease](../stage-4-storage-launch-contract.md#exclusive-writer-lease) |
| Local teardown classifier orders claims only; terminal order observes no deletion/inventory/exit/zero. | [Authority: Stage 4 teardown semantic verdicts](../stage-4-teardown.md#semantic-bindings-and-verdicts) |
| No local/static result promotes into cleanup evidence. | [Authority: Stage 4 teardown boundary](../stage-4-teardown.md#boundary) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Local launchers have bounded profile-owned cleanup tests inside exact local runtime roots. | [Authority: Stage 3 exit evidence](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#automatic-acceptance) |
| They prove no provider ownership, cluster teardown, retained-volume handling, independent inventory, or account/region absence. | [Authority: Stage 4 teardown boundary](../stage-4-teardown.md#boundary) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Bind exact approved state to separate inventory scopes for cluster/node groups, instances/templates, volumes/snapshots, network interfaces, load-balancing resources, public addresses, IAM, security groups, logs, TTL controls, and campaign-tagged resources. | [Planned STAGE5-45.11 / `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) and [planned inventory scopes](../stage-4-offline-readiness.md#stopdestroy-and-identities) |
| A zero result binds every approved scope, retained exception, account/region, independent producer, time, pagination/completeness, and immutable evidence. | [Planned STAGE5-45.11 / `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| One query or local classifier cannot establish zero. | [Authority: Stage 4 teardown semantic verdicts](../stage-4-teardown.md#semantic-bindings-and-verdicts) |

## Fixed evidence order

**Section authority:** [Authority: Stage 4 fixed claimed-evidence order](../stage-4-teardown.md#fixed-claimed-evidence-order).

Use the exact eight-phase order from the static contract. Names below are evidence labels, not commands or permission to act:

1. `freeze-reconcilers` — claimed `control-observer` evidence.
2. `close-admission` — claimed `admission-observer` evidence.
3. `revoke-credentials` — claimed `credential-observer` evidence.
4. `revoke-readiness` — claimed `readiness-observer` evidence.
5. `remove-session-workloads` — claimed `workload-mutator` evidence.
6. `verify-kubernetes-zero` — claimed `kubernetes-zero-observer` evidence.
7. `remove-cluster-infrastructure` — claimed `infrastructure-mutator` evidence.
8. `record-external-cloud-inventory-claim` — claimed external-inventory-observer evidence.

Observed rows must form a contiguous prefix. A pending row stops progression. Any uncertain, malformed, out-of-order, replayed, mismatched, or contradictory row yields `preserve-uncertain` and cannot be repaired by later rows.

## Retained data split

Ordinary session teardown must not delete the retained workspace. Trusted session state follows its 30-day policy. Explicit user deletion is a separate authenticated lifecycle described in [retention/deletion](retention-deletion.md). Teardown evidence must distinguish intentionally retained data from orphan infrastructure; neither is a zero-inventory shortcut.

## Exact ownership gate before any future mutation

**Section authority:** [Authority: storage uncertainty preservation](../stage-4-storage-launch-contract.md#exclusive-writer-lease).

For each candidate resource, a separately authorized recovery process must prove **all** applicable fields before mutation:

1. exact account binding and region match the approved attempt;
2. immutable provider resource ID and resource type appear in the attempt's state-bound manifest;
3. attempt ID, source revision, artifact root, owner principal binding, purpose, and expiry match the approved envelope;
4. creation evidence and dependency edges bind the resource to that exact state generation;
5. current identity/generation has not been replaced, reused, adopted, or reconciled by another owner;
6. resource is not an intentionally retained workspace, trusted session state within retention, evidence artifact, legal hold, shared prerequisite, or pre-existing resource;
7. authenticated recovery operator is authorized for that one immutable resource and is distinct where required from approver and zero-inventory observer.

Names, prefixes, labels, tags, timestamps, network attachment, adjacency, apparent idleness, and source revision alone are insufficient. Tags may corroborate but never establish ownership by themselves.

If every applicable check is exact, produce a one-resource recovery proposal containing only its immutable identity, expected generation, dependency order, preservation exceptions, accountable operator/approver, deadline, and evidence plan. Approval of that proposal applies to that resource and generation only. It does not authorize sibling or discovered resources.

If any check is missing, stale, mismatched, conflicting, or unknown: **do not mutate or delete the candidate**. Preserve state and bounded diagnostics, keep admission/readiness/credential use closed where safely scoped, and enter exact orphan escalation.

## Exact orphan escalation

**Section authority:** [Planned STAGE5-45.11 / `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability).

1. Set status to `preserve-uncertain`; record UTC time, exact attempt and candidate immutable references if known, failed ownership checks as categorical codes, and a digest of redacted diagnostics.
2. Stop reconciliation, admission, retry, replacement, lease takeover, and success/zero promotion for the affected scope. Do not stop unrelated resources by discovered prefix or tag.
3. Notify the authenticated campaign operator, campaign approver, security/evidence reviewer, budget approver, resource/service owner, and zero-inventory observer through the private incident channel. If an identity is absent or not distinct as required, record `identity-not-bound` and keep mutation blocked.
4. Transfer the uncertainty artifact and state custody to a **separately approved recovery authority**. The original campaign approval is exhausted and cannot authorize recovery or retry.
5. Require the recovery authority to bind exact account/region, state generation, candidate resource ID/type/generation, principal identities, preservation classes, per-resource mutation proposal, spend/time bound, and independent observation plan.
6. Re-run the complete ownership gate from independently obtained read-only evidence. A repeated unknown remains unknown; nonappearance is not absence.
7. Only an exact per-resource recovery approval may permit the named future mutator to act on that one proven generation. Afterward, the independent observer re-inventories every fixed scope and records residue or uncertainty separately.
8. Close escalation only when each candidate is either independently observed absent, explicitly preserved with owner/lifecycle, or still recorded uncertain under continuing custody. Any uncertain item blocks zero, campaign success, Stage 4 exit, and retry.

## Prohibited cleanup shortcuts

**Section authority:** [Authority: Stage 4 teardown boundary](../stage-4-teardown.md#boundary).

Never use wildcard, recursive, account-wide, region-wide, prefix-wide, tag-only, label-only, namespace-wide, or "delete all" cleanup. Never delete a parent merely to remove unknown children; never force-detach or take over an uncertain retained volume/lease; never convert not-found, timeout, access denial, pagination gap, stale state, or observer failure into absence. Do not run a second attempt to see whether residue disappears.

## Completion record

**Section authority:** [Planned STAGE5-45.11 / `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability).

The future record must preserve exact candidate binding, authenticated producers, ordered phase evidence, per-resource outcomes, retained exceptions, uncertainty custody, cost, and independent inventory. In the current local/static scope, completion is always unavailable: cloud execution observed, cloud inventory observed, Stage 4 exit, and release eligibility remain false.
