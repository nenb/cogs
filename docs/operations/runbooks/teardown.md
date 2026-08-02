# Draft teardown and orphan-resource verification guide

This is a non-executable evidence and escalation plan. It contains no provider command, resource target, deletion selector, callback, URL, credential, or cluster operation. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future approved attempt will have immutable account binding, region, attempt ID, source/artifact revision, state custody, resource manifest, TTL, and authenticated operator/observer bindings.
- A future independent observer will have read-only inventory capability separated from operator and approver.
- None of those bindings or capabilities exists in the current offline package.

## Static contract facts

- Every future outcome—success, apply/bootstrap/test failure, timeout, or interruption—requires state-bound destruction followed by independently produced read-only inventory.
- Inventory uncertainty blocks success and retry. Approval is one attempt only; prior approval never authorizes a correction or retry.
- Storage cleanup uncertainty preserves state, resources, attachments, and workspace lease. Lease expiry never authorizes takeover.
- The local [teardown classifier](../stage-4-teardown.md) orders claimed evidence only. Even `evidence-order-complete` does not observe deletion, cloud inventory, Stage 4 exit, or zero resources.
- No local or static result can be promoted into cleanup evidence.

## Authoritative-local facts

- Local launchers have bounded profile-owned cleanup tests within their exact local runtime roots.
- Those tests do not prove provider resource ownership, cluster teardown, retained-volume handling, independent inventory, or absence in an account/region.

## Future cloud evidence

A future attempt must bind mutation and observation evidence to the exact approved state and cover separately:

- EKS clusters and node groups;
- EC2 instances and launch templates;
- EBS volumes and snapshots;
- network interfaces;
- load balancers and target groups;
- elastic IPs;
- campaign IAM roles and policies;
- security groups;
- logs;
- TTL schedules and functions; and
- all campaign-tagged resources.

A zero result requires all approved scopes, expected retained-data exceptions, exact account/region, independent authenticated producer, timestamps, pagination/completeness semantics, and immutable evidence binding. Absence from one query or the local classifier is not zero evidence.

## Fixed evidence order

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

1. Set status to `preserve-uncertain`; record UTC time, exact attempt and candidate immutable references if known, failed ownership checks as categorical codes, and a digest of redacted diagnostics.
2. Stop reconciliation, admission, retry, replacement, lease takeover, and success/zero promotion for the affected scope. Do not stop unrelated resources by discovered prefix or tag.
3. Notify the authenticated campaign operator, campaign approver, security/evidence reviewer, budget approver, resource/service owner, and zero-inventory observer through the private incident channel. If an identity is absent or not distinct as required, record `identity-not-bound` and keep mutation blocked.
4. Transfer the uncertainty artifact and state custody to a **separately approved recovery authority**. The original campaign approval is exhausted and cannot authorize recovery or retry.
5. Require the recovery authority to bind exact account/region, state generation, candidate resource ID/type/generation, principal identities, preservation classes, per-resource mutation proposal, spend/time bound, and independent observation plan.
6. Re-run the complete ownership gate from independently obtained read-only evidence. A repeated unknown remains unknown; nonappearance is not absence.
7. Only an exact per-resource recovery approval may permit the named future mutator to act on that one proven generation. Afterward, the independent observer re-inventories every fixed scope and records residue or uncertainty separately.
8. Close escalation only when each candidate is either independently observed absent, explicitly preserved with owner/lifecycle, or still recorded uncertain under continuing custody. Any uncertain item blocks zero, campaign success, Stage 4 exit, and retry.

## Prohibited cleanup shortcuts

Never use wildcard, recursive, account-wide, region-wide, prefix-wide, tag-only, label-only, namespace-wide, or "delete all" cleanup. Never delete a parent merely to remove unknown children; never force-detach or take over an uncertain retained volume/lease; never convert not-found, timeout, access denial, pagination gap, stale state, or observer failure into absence. Do not run a second attempt to see whether residue disappears.

## Completion record

The future record must preserve exact candidate binding, authenticated producers, ordered phase evidence, per-resource outcomes, retained exceptions, uncertainty custody, cost, and independent inventory. In the current local/static scope, completion is always unavailable: cloud execution observed, cloud inventory observed, Stage 4 exit, and release eligibility remain false.
