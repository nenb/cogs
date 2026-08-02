# Stage 4 bounded offline preflight and readiness package

Issue #357 is **local/static only**. Its canonical instance is [`stage4-offline-readiness-package.json`](../security-evidence/stage4-offline-readiness-package.json). It has two deliberately different components:

1. [`stage4-offline-render-preparation.ts`](../../scripts/stage4-offline-render-preparation.ts) is a bounded **trusted local preparation executable**. It authenticates the complete chart inventory, exact synthetic values bytes, and an exact Helm executable digest/version; invokes only local `helm version --short` and `helm template`; renders the NOTES payload twice under fixed time/output/environment bounds; compares both fresh outputs with committed bytes; and emits a canonical digest-only receipt. Pinned Helm v4 no longer exposes the historical `template --notes` flag, so the generator adds one fixed, digest-bound local review wrapper to a temporary copy and templates that wrapper. It never installs, upgrades, contacts a cluster, enables DNS, or accepts another rendering command.
2. [`stage4-offline-readiness.ts`](../../scripts/stage4-offline-readiness.ts) is the **pure classifier**. It invokes nothing. It checks canonical package bytes, exact artifact digests, the trusted-preparation receipt digest, byte-identical renders, the closed proposal, and a domain-separated semantic root.

A valid classifier verdict means only:

- `local_preparation_complete=true` with `local_preparation_scope=bounded-package-assembly-and-local-validation-only`; and
- the bounded package was assembled, its local procedures passed, and its committed render has a matching trusted fresh-render receipt.

It simultaneously fixes `exact_image_runtime_closure_satisfied=false`, `campaign_request_ready=false`, `campaign_approved=false`, `cloud_authorized=false`, provider/cloud/Kubernetes/current-resource/zero-resource observations to false, Stage 4 exit to false, and release eligibility to false. “Local preparation complete” is not exact release-artifact closure and is not campaign readiness.

## Exact bound inputs and source closure

The package binds SHA-256 over exact bytes for the complete Stage 4 source inventory, chart inventory, synthetic values, two fresh-equivalent committed renders, trusted render-preparation receipt, image record, NIC contract, runtime record, complete Stage 4/5 schema inventory, and local-validation receipt.

[`stage4-offline-source-inventory.ts`](../../scripts/stage4-offline-source-inventory.ts) generates the complete Stage 4 closure: root governing/build/lock files; Helm and NIC sources; ADR 0012; the AWS feasibility boundary; Stage 4 operations/evidence/report docs; every Stage 4 schema, validator, test, fixture, and generator; and all offline-readiness artifacts that are not cyclic outputs. It includes the later proxied-byte storage validator correction. Exactly three self-referential generated outputs are excluded and recorded in the inventory itself:

- the readiness package, which binds the inventory;
- the source inventory itself; and
- local validation, which binds source/procedure digests and is itself bound by the package.

No other Stage 4 source is excluded. Tests regenerate the inventory from the final worktree and require byte identity.

The semantic root additionally binds the closed resource graph, independent inventory map, blockers, identities, one-attempt rule, stop/destroy behavior, and complete revalidation trigger inventory. Matching digests do not authenticate provider truth.

## Trusted render provenance

The trusted preparation pin is Helm `v4.1.1+g5caf004`, executable SHA-256 `9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4`. The executable must resolve to the exact pinned local regular file. The process uses no shell, a minimal fixed environment, client-only dry run, absent kubeconfig, no DNS, a 20-second bound, and bounded stdout/stderr. It templates two independent temporary chart copies and removes each copy afterward.

The canonical receipt contains only digests, fixed categories, and false cloud/provider/Kubernetes observation fields. It binds exact chart inventory, values, Helm executable, Helm version output, generator source, fixed wrapper source, and both render outputs. The local-validation receipt and package both bind this receipt. Tests freshly execute the pinned renderer and reject forged identical committed renders even if a hostile package copy rewrites both render digest fields.

## Honest image, NIC, and runtime blockers

Worker and sandbox image references remain `.invalid` synthetic placeholders. A placeholder digest is not an artifact identity. The Envoy reference is only an exact static input, not release-runtime evidence. Therefore:

- `release_image_set_present=false`;
- `exact_image_closure_satisfied=false`; and
- `RELEASE_IMAGE_SET_ABSENT` remains a sticky blocker.

NIC `v0.11.0` at `28221c652c56bb8d48a92538c01503a82f2f9321` and module `0.7.0` at `5d4cb31f07fda5c010b5be580258d32f6db75828` still cannot carry custom launch-template ID/version or `CpuOptions.NestedVirtualization`. The EKS AMI, image release, and kernel remain null.

Kata `3.32.0` retains its exact Stage 2 archive digest, but that is not an EKS observation. `containerd` `2.2.1` and QEMU `8.2.2` are version requirements only: both artifact SHA-256 fields remain null and both states are `artifact-identity-unresolved-blocking`. `CONTAINERD_ARTIFACT_IDENTITY_UNRESOLVED` and `QEMU_ARTIFACT_IDENTITY_UNRESOLVED` are sticky blockers. Version strings and placeholder records can never satisfy exact image/runtime closure.

## Closed proposal-only resource graph

Every count below is an exact **hard maximum proposal**, not an observed count, provider guarantee, price estimate, quota result, or approval. The account binding is absent. Region is exactly `us-east-1`; both proposed node classes are capped at one `c8i-flex.large` On-Demand node each. Undeclared resource classes are forbidden.

| Resource class | Max | Exact proposed type / size |
|---|---:|---|
| EKS cluster / managed add-on | 1 / 0 | regional control plane / none |
| VPC / subnet | 1 / 2 | dedicated IPv4-only / public, no inbound |
| Route table / route / IGW | 2 / 4 / 1 | two local plus two IGW routes |
| Network ACL / DHCP association | 1 / 1 | explicit review of VPC defaults |
| NAT gateway / VPC endpoint / EIP | 0 / 0 / 0 | prohibited |
| Load balancer / target group | 0 / 0 | prohibited |
| Security group | 5 | VPC default, cluster, shared-node, trusted, sandbox |
| IAM role / customer policy / attachment / instance profile | 4 / 4 / 8 / 2 | closed campaign roles only |
| Launch template / managed node group / ASG | 2 / 2 / 2 | trusted and sandbox, explicit LT versions |
| Trusted node | 1 | `c8i-flex.large`, 30 GiB encrypted gp3 root |
| Sandbox node | 1 | `c8i-flex.large`, nested KVM, 30 GiB encrypted gp3 root |
| ENI | 10 | hard provider-managed and node ceiling |
| Trusted root / sandbox root EBS | 1 / 1 | encrypted gp3, 30 GiB each, delete on termination |
| Workspace / session-state EBS | 1 / 1 | encrypted gp3 Retain, 20 GiB / 5 GiB |
| EBS snapshot | 0 | prohibited |
| KMS key / alias | 1 / 1 | symmetric campaign-storage key |
| Log group | 2 | EKS control and TTL function, 30-day proposal |
| Budget / notifications | 1 / 3 | USD 20; USD 5/10/20 proposals |
| TTL schedule / function / invoke permission | 1 / 1 / 1 | 14,400 seconds; 128 MiB terminator |

The EKS duration proposal is 5,400 seconds. Data is synthetic only. NAT, endpoints, EIP, load balancing, snapshots, managed add-ons, GPU, bare metal, Spot, public ingress, larger instances, another region, production data, and a second sandbox node remain zero/prohibited. Budgets and TTL are proposals, not observed kill switches.

## Service-specific independent inventory

The package has exactly one inventory row for every resource-graph class in the same order. Each row names the responsible service and an account/region, VPC, cluster, role, attachment, function, or budget-specific enumeration scope. Tags are not accepted as the sole discovery mechanism (`tag_only_inventory_allowed=false` and every row fixes `tag_only=false`).

Inventory includes EKS clusters/add-ons/node groups; EC2 VPCs, subnets, routes/tables, gateways, endpoints, addresses, security groups, launch templates/all versions, instances, ENIs, volumes, snapshots, ACLs and DHCP associations; ELBv2 load balancers/target groups; IAM roles/policies/attachments/profiles; Auto Scaling groups; KMS keys/aliases; Logs groups; Budgets/notifications; Scheduler schedules; and Lambda functions/resource policies. Campaign tags are supplementary binding only. All inventory remains required, future, unexecuted, and non-zero-claiming.

## Stop/destroy and identities

Apply, bootstrap, test, timeout, or interruption failure means stop, preserve bounded evidence, require destroy, then require service-specific independent inventory. Inventory uncertainty preserves uncertainty and blocks success and retry. There is no idle debugging cluster, command, target, or executable provider route.

Campaign operator, approver, budget approver, security/evidence reviewer, and zero-inventory observer bindings are all absent. Required separation remains unproven and blocking. Any future approval is one named attempt only; prior approval never authorizes retry, correction, another issue, or a later stage.

## Mandatory fresh revalidation

Fresh revalidation is required after #42 closure and after any change to source, pins, price, quota, campaign shape, Helm chart, Helm values, renderer, Helm executable identity/version, validation procedure, security advisory or disposition expiry, account binding, principal binding, separation state, campaign approval, campaign envelope, attempt, stop/destroy procedure, or independent inventory scope/procedure.

Closure of #42, package validity, a matching digest, ownership, a merge, or an earlier approval is never cloud authority.
