# Stage 4 bounded offline preflight and readiness package

This issue #357 package is **local/static only**. Its canonical instance is [`stage4-offline-readiness-package.json`](../security-evidence/stage4-offline-readiness-package.json), validated by strict schemas and the pure classifier in [`scripts/stage4-offline-readiness.ts`](../../scripts/stage4-offline-readiness.ts). The package has no command, callback, target, credential, account identifier, resource identifier, provider payload, or execution route.

A valid verdict distinguishes two facts that must not be collapsed:

- `local_preparation_complete=true` means the bounded package was structurally assembled, canonicalized, digest-bound, and checked by the recorded local/static validation set;
- `campaign_request_ready=false` and `cloud_authorized=false` mean the package cannot yet be submitted as an executable campaign request and authorizes nothing.

It does not approve a campaign, observe AWS/provider/Kubernetes truth, claim current or zero resources, satisfy Stage 4 exit, or establish release eligibility.

## Exact bounded closure

The package binds exact SHA-256 digests for ten caller-supplied byte artifacts:

1. a bounded exact source-file inventory rooted at integrated predecessor `b673609f7ed7b53d3085afbd83094a9b3c4f9511` and including the issue #357 implementation closure;
2. a complete chart-file inventory for chart `cogs` `0.0.1`;
3. the synthetic enabled NOTES values fixture;
4. one local NOTES source-shape render;
5. a byte-identical repeat render;
6. an image lock;
7. the exact NIC semantic contract;
8. an honest runtime-pin record;
9. the complete Stage 4/5 schema inventory; and
10. the local-validation receipt and exact validator/test source digests.

The classifier accepts only canonical package JSON, one terminal LF, bounded non-empty byte inputs, exact artifact keys, byte-identical renders, exact image references, and a domain-separated semantic binding root. The root binds all artifact digests plus source/pin, proposal, blocker, identity, stop/destroy, one-attempt, and revalidation semantics. Changing one of those fields while retaining the old root fails closed.

The worker and sandbox image references are deliberately `.invalid` synthetic placeholders, not release images. The Envoy digest is an exact static input, not a runtime observation. `containerd` and QEMU remain version requirements without binary artifact digests. No release-candidate source or image set is bound.

## Current blockers preserved exactly

The valid local package remains blocked by all of the following:

- issue #42 is open;
- NIC `v0.11.0` at commit `28221c652c56bb8d48a92538c01503a82f2f9321` and `nebari-dev/eks-cluster/aws` module `0.7.0` at commit `5d4cb31f07fda5c010b5be580258d32f6db75828` cannot carry custom launch-template ID/version or `CpuOptions.NestedVirtualization`;
- the EKS node AMI ID, image release, and kernel release are unresolved;
- the proposed account binding is absent;
- current price and quota have not been discovered or revalidated by this package;
- required separated campaign identities are absent;
- no campaign envelope, attempt ID, or approval exists; and
- this repository slice intentionally exposes no executable provider route.

The NIC capability blocker takes precedence even if an image pin is later supplied. A capable NIC revision requires a new immutable source/module closure, contract, schema, and review rather than mutating the `v0.11.0` assessment.

## Proposal-only envelope

These are ceilings for a future review, not approved or current provider facts:

| Proposal | Exact ceiling |
|---|---|
| Account | absent and blocking |
| Region | `us-east-1` only |
| Sandbox instance | no larger or different than `c8i-flex.large`; CPU-only, On-Demand, non-metal |
| EKS clusters | 1 |
| Sandbox nodes | minimum 0, maximum 1 |
| Trusted nodes | maximum 1 |
| Total nodes | maximum 2 |
| Workspace | one 20 GiB retained CSI-block role |
| Trusted session state | one 5 GiB retained role |
| EKS campaign duration | 5,400 seconds |
| Absolute TTL | 14,400 seconds |
| Spend cap / alert proposals | USD 20 / USD 5, 10, and 20 |
| Access | proposed SSM-only, no public SSH; unexecuted |
| Data | synthetic repositories, identities, credentials, and sessions only |

Budgets and alerts are not a hard kill switch. Current price, quota, capacity, account suitability, EKS support, and resource availability are unknown. NAT Gateway, load balancer, EIP, EFS workspace, public ingress, GPU, bare metal, Spot, a second sandbox node, a larger instance, another region, and production data are prohibited by this proposal.

## Non-executable stop and destroy paths

The package records categorical control flow only; it provides no destroy command or target selection.

| Future condition | Required proposed disposition |
|---|---|
| Apply failure | stop; preserve bounded evidence; require destroy; require independent inventory |
| Bootstrap failure | same; no idle debugging cluster |
| Test failure | same; no correction or retry in place |
| Timeout | same; absolute TTL remains a backstop proposal, not observed control |
| Interruption | same; unknown outcome remains unknown |
| Inventory uncertainty | preserve uncertainty; block success and retry; escalate under a separate recovery authority |

Every future outcome requires state-bound destruction and then independently produced read-only inventory. No failure authorizes interactive retention, widening, replacement resources, or another attempt. A local teardown-order verdict remains non-authoritative and cannot substitute for independent inventory.

Independent inventory must cover these scopes separately: EKS clusters/node groups; EC2 instances/launch templates; EBS volumes/snapshots; ENIs; load balancers/target groups; EIPs; campaign IAM roles/policies; security groups; logs; TTL schedules/functions; and all campaign-tagged resources. The package records all scopes as future and unexecuted and makes no zero claim.

## Required identities and one-attempt authority

The future campaign operator, campaign approver, budget approver, security/evidence reviewer, and zero-inventory observer all require stable authenticated bindings. Every binding is currently null. The package requires operator separation from approver, budget approver, reviewer, and zero-inventory observer; approver and reviewer are also separated from the zero-inventory observer. Role labels and the ownership register do not prove identity or independence.

Any future approval is limited to exactly one named attempt. Prior approval never authorizes a retry, correction run, later Stage 4 issue, or Stage 5 campaign. Failure, interruption, timeout, drift, or uncertainty requires fresh local revalidation and a new approval. This package has no campaign envelope or approval surface that can be promoted into authority.

## Mandatory fresh revalidation

Fresh revalidation is required after #42 closes and after **any** source, pin, current-price, current-quota, or campaign-shape change. It must replace the current absent account/identity/approval fields through a new future authority, re-evaluate NIC and EKS AMI/kernel blockers, regenerate all affected artifacts and roots, rerun local checks on one clean exact revision, and only then permit a separate campaign-request review.

Closure of #42, package validity, ownership, a merge, an issue state, an earlier approval, or possession of matching digests is never cloud authority.

## Pure classifier boundary

The classifier snapshots exact artifact keys and byte arrays, rejects recursive Proxies before traps, rejects getters and non-plain prototypes without invoking them, enforces per-artifact and aggregate byte limits before hashing, and returns only fixed reason codes. Invalid, hostile, stale, replay-mutated, or ambiguous input returns `preserve-uncertain` with every campaign/cloud/release field false. It performs no filesystem, process, environment, network, provider, Kubernetes, Helm, or external-model operation.
