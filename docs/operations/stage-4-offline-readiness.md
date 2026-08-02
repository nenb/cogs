# Stage 4 bounded offline preflight and readiness package

Issue #357 is **local/static only**. Its canonical instance is [`stage4-offline-readiness-package.json`](../security-evidence/stage4-offline-readiness-package.json). It has two deliberately different components:

1. [`stage4-offline-render-preparation.ts`](../../scripts/stage4-offline-render-preparation.ts) is a bounded **trusted local preparation executable**. It runs only as the exact pinned Node binary with native TypeScript stripping and no loader/tsx arguments; authenticates its source from `import.meta.filename`; authenticates the complete chart inventory, exact synthetic values bytes, and exact Helm executable digest/version; materializes chart, values, and a private mode-0500 Helm executor from already authenticated bytes; invokes that immutable private copy for local `helm version --short`, strict `helm lint`, a client-only zero-manifest template, and two review-wrapper templates; reauthenticates the copy after each invocation; compares both fresh review outputs with committed bytes; and emits a canonical digest-only receipt. Pinned Helm v4 no longer exposes the historical `template --notes` flag, so the generator adds one fixed, digest-bound local review wrapper only after lint and the zero-manifest check. It never reopens the original Helm pathname for execution, installs, upgrades, contacts a cluster, enables DNS, or accepts caller-selected paths or commands.
2. [`stage4-offline-readiness.ts`](../../scripts/stage4-offline-readiness.ts) is the **pure classifier**. It invokes nothing. It checks canonical package bytes, exact artifact digests, the trusted-preparation receipt digest, byte-identical renders, the closed proposal, and a domain-separated semantic root.

## Pure classifier boundary

A valid classifier verdict means only:

- `local_preparation_complete=true` with `local_preparation_scope=bounded-package-assembly-and-local-validation-only`; and
- the bounded package was assembled, the eight exact commands recorded in local validation exited zero with bounded normalized output digests, and its committed render has a matching trusted fresh-render receipt.

Those commands are the readiness-source format check, repository typecheck, bounded Stage 4 unit contracts, Stage 4 schema registry, all-schema validator, trusted Helm local contracts (strict lint, zero submitted manifests, and repeated NOTES rendering), complete source inventory, and package-lock SRI integrity. A current npm-registry audit is explicitly `not-run-not-claimed`: it requires external network access and is outside this offline completion scope. Therefore `local_preparation_complete` does not claim current advisory discovery or audit success.

It simultaneously fixes `exact_image_runtime_closure_satisfied=false`, `campaign_request_ready=false`, `campaign_approved=false`, `cloud_authorized=false`, provider/cloud/Kubernetes/current-resource/zero-resource observations to false, Stage 4 exit to false, and release eligibility to false. “Local preparation complete” is not exact release-artifact closure and is not campaign readiness.

## Exact bound inputs and source closure

The package binds SHA-256 over exact bytes for the complete Stage 4 source inventory, chart inventory, synthetic values, two fresh-equivalent committed renders, trusted render-preparation receipt, image record, NIC contract, runtime record, complete Stage 4/5 schema inventory, and local-validation receipt.

[`stage4-offline-source-inventory.ts`](../../scripts/stage4-offline-source-inventory.ts) generates the complete Stage 4 closure: root governing/build/lock files; Helm and NIC sources; ADR 0012; the AWS feasibility boundary; Stage 4 operations/evidence/report docs; every Stage 4 schema, validator, test, fixture, and generator; the active generic schema executor [`validate-schemas.ts`](../../scripts/validate-schemas.ts); the canonical regeneration procedure; and all offline-readiness artifacts that are not cyclic outputs. It includes the later proxied-byte storage validator correction. Local validation separately binds that active validator, procedure documentation, report, and hostile tests. Exactly three self-referential generated outputs are excluded and recorded in the inventory itself:

- the readiness package, which binds the inventory;
- the source inventory itself; and
- local validation, which binds source/procedure digests and is itself bound by the package.

No other Stage 4 source is excluded. The inventory obtains its bounded path set from the pinned `/usr/bin/git` index (selected untracked source is rejected), records the exact regeneration-base HEAD `dc11c1f6f2e29a66c602b82d805c764a00517bf0` and selected index path-set digest, and permits dirty tracked files because their worktree bytes—not index blobs—are authoritative. Every file is opened with `O_NOFOLLOW`; every path component is opened and retained; lstat/fstat identities are compared before and after a bounded descriptor read; final files must be regular, single-linked, nonempty, and bounded. Symlink components, final symlinks, hard links, path replacement, and identity drift fail closed.

Tests regenerate the inventory from the final worktree and require byte identity. After an integrated-branch source change, `npm run readiness:regenerate` deterministically reruns the trusted renderer and all recorded commands, preserves the schema-enforced strict inventory scopes, rebuilds schema/source/local-validation records, rewrites normalized classifier anchors without a self-hash cycle, reruns the commands against the rewritten source, rejects normalized-result drift, and emits the final canonical package. Formatting and validation must then pass without changing those bytes.

The semantic root additionally binds the closed resource graph, independent inventory map, blockers, identities, one-attempt rule, stop/destroy behavior, and complete revalidation trigger inventory. Matching digests do not authenticate provider truth.

## Trusted render provenance

The trusted preparation pins Node `v22.22.2` (`darwin`/`arm64`) at SHA-256 `5c899797c4eb8f1db5563eea56538342ddb3e9276ee1b04a5a1f0f1023d2b011` and Helm `v4.1.1+g5caf004` at SHA-256 `9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4`. No tsx or other loader is allowed in the trusted invocation. Both executable paths must resolve exactly. Helm is opened without following a final symlink, read and race-checked through one descriptor, copied into a private mode-0700 directory, made mode 0500, re-read and authenticated, and only that copy is executed and reauthenticated. Chart and values temporary files are likewise written from authenticated bytes rather than reopened source paths. The process uses no shell, a minimal fixed environment, client-only dry run, absent kubeconfig, no DNS, a 20-second bound, and bounded stdout/stderr.

The canonical receipt contains only digests, fixed categories, and false cloud/provider/Kubernetes observation fields. It binds the actual Node binary/version/platform/architecture, absence of a TypeScript loader, exact generator bytes from `import.meta.filename`, a digest over that execution layer, exact chart inventory, values, original and copied Helm bytes, Helm version output, normalized lint output, the empty zero-manifest output, fixed wrapper source, and both render outputs. The classifier canonical-parses it and requires its exact anchored digest plus cross-bindings to source, local validation, chart, values, and renders. It likewise canonical-parses and exact-validates anchored source, schema, local-validation, image, and runtime records; package digest/root rewrites cannot replace them. Tests freshly execute the pinned renderer and reject forged identical committed renders or opaque receipts even if a hostile package copy rewrites artifact digests and its semantic root.

## Honest image, NIC, and runtime blockers

Worker and sandbox image references remain `.invalid` synthetic placeholders. A placeholder digest is not an artifact identity. The Envoy reference is only an exact static input, not release-runtime evidence. Therefore:

- `release_image_set_present=false`;
- `exact_image_closure_satisfied=false`; and
- `RELEASE_IMAGE_SET_ABSENT` remains a sticky blocker.

Historical NIC v1 preserves the `v0.11.0` / module `0.7.0` missing-capability result. Active v2 pins accepted personal-fork NIC `53b1a791ed1ff394969e0aeaa6379be955244b62` and module `c3017c0e15b538cd4e04c0786809a861ea82c621`; source-level external launch-template ID/version preservation is satisfied with operator attestation only. Launch-template contents and provider truth remain unobserved. The EKS AMI, image release, and kernel remain null. ADR 0094's separate local static manifest handoff does not change campaign readiness or provider authority.

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

The package has exactly one inventory row for every resource-graph class in the same order. Every row is account-wide or account/region service-wide and identity-independent. APIs that require a parent enumerate every parent from the service-wide result first. IAM profiles and attachments are enumerated account-wide even if a role was deleted; EC2 instances, ENIs, internet gateways, and all EBS volume roles cover every lifecycle/attachment state even if a launch template, node, tag, or attachment identity disappeared. Tags are not accepted as the sole discovery mechanism (`tag_only_inventory_allowed=false` and every row fixes `tag_only=false`).

Inventory includes EKS clusters/add-ons/node groups; EC2 VPCs, subnets, routes/tables, gateways, endpoints, addresses, security groups, launch templates/all versions, instances, ENIs, volumes, snapshots, ACLs and DHCP associations; ELBv2 load balancers/target groups; IAM roles/policies/attachments/profiles; Auto Scaling groups; KMS keys/aliases; Logs groups; Budgets/notifications; Scheduler schedules; and Lambda functions/resource policies. Campaign tags are supplementary binding only. All inventory remains required, future, unexecuted, and non-zero-claiming.

## Stop/destroy and identities

Apply, bootstrap, test, timeout, or interruption failure means stop, preserve bounded evidence, require destroy, then require service-specific independent inventory. Inventory uncertainty preserves uncertainty and blocks success and retry. There is no idle debugging cluster, command, target, or executable provider route.

Campaign operator, approver, budget approver, security/evidence reviewer, and zero-inventory observer bindings are all absent. Required separation remains unproven and blocking. Any future approval is one named attempt only; prior approval never authorizes retry, correction, another issue, or a later stage.

## Mandatory fresh revalidation

Fresh revalidation is required after #42 closure and after any change to source, pins, price, quota, campaign shape, Helm chart, Helm values, renderer, Helm executable identity/version, validation procedure, security advisory or disposition expiry, account binding, principal binding, separation state, campaign approval, campaign envelope, attempt, stop/destroy procedure, or independent inventory scope/procedure.

Closure of #42, package validity, a matching digest, ownership, a merge, or an earlier approval is never cloud authority.
