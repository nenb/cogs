# Stage 4 bounded offline preflight and readiness package

Issue #357 is **local/static only**. Its canonical instance is [`stage4-offline-readiness-package.json`](../security-evidence/stage4-offline-readiness-package.json). It has two deliberately different components:

1. [`stage4-offline-render-preparation.ts`](../../scripts/stage4-offline-render-preparation.ts) is a bounded **trusted local preparation executable**. It runs only as the exact pinned Node binary with native TypeScript stripping and no loader/tsx arguments; authenticates its source from `import.meta.filename`; authenticates the complete chart inventory, exact synthetic values bytes, and exact Helm executable digest/version; materializes chart, values, and a private mode-0500 Helm executor from already authenticated bytes; invokes that immutable private copy for local `helm version --short`, strict `helm lint`, a client-only zero-manifest template, and two review-wrapper templates; reauthenticates the copy after each invocation; compares both fresh review outputs with committed bytes; and emits a canonical digest-only receipt. Pinned Helm v4 no longer exposes the historical `template --notes` flag, so the generator adds one fixed, digest-bound local review wrapper only after lint and the zero-manifest check. It never reopens the original Helm pathname for execution, installs, upgrades, contacts a cluster, enables DNS, or accepts caller-selected paths or commands.
2. [`stage4-offline-readiness.ts`](../../scripts/stage4-offline-readiness.ts) is the **pure classifier**. It invokes nothing. It checks canonical package bytes, exact artifact digests, the trusted-preparation receipt digest, byte-identical renders, the closed proposal, and a domain-separated semantic root.

## Pure classifier boundary

A valid classifier verdict means only:

- `local_preparation_complete=true` with `local_preparation_scope=bounded-package-assembly-and-local-validation-only`; and
- the bounded package was assembled, the nine exact commands recorded in local validation exited zero with bounded normalized output digests, and its committed render has a matching trusted fresh-render receipt.

Those commands are the readiness-source format check, repository typecheck, bounded Stage 4 unit contracts, the production runtime/image/static-route source contracts, Stage 4 schema registry, all-schema validator, trusted Helm local contracts (strict lint, zero submitted manifests, and repeated NOTES rendering), complete source inventory, and package-lock SRI integrity. The production command is local/static: it runs no Docker build, registry publication, provider, Kubernetes, cloud, or external model. Docker image builds and release-image publication are explicitly `not-run-not-claimed` and remain owned by their separate workflows. A current npm-registry audit is likewise `not-run-not-claimed`: it requires external network access and is outside this offline completion scope. Therefore `local_preparation_complete` does not claim image bytes, publication, current advisory discovery, or audit success.

It also records `candidate_artifact_closure_complete=true` and `selected_runtime_artifacts_authenticated=true`. Those fields mean only that the exact public containerd and Kata release bytes selected for a future candidate are authenticated and locally bound. The verdict simultaneously fixes `exact_image_runtime_closure_satisfied=false`, `campaign_request_ready=false`, `campaign_approved=false`, `cloud_authorized=false`, provider/cloud/Kubernetes/current-resource/zero-resource observations to false, Stage 4 exit to false, and release eligibility to false. Candidate artifact closure is neither runtime observation nor campaign readiness.

## Exact bound inputs and source closure

The v2 package binds SHA-256 over exact bytes for the complete Stage 4 source inventory, chart inventory, synthetic values, two fresh-equivalent committed renders, trusted render-preparation receipt, image record, NIC contract, runtime record, authenticated-runtime-artifact evidence, complete Stage 4/5 plus production runtime/image schema inventory, and local-validation receipt. The v1 package/verdict schemas remain unchanged historical contracts; v2 is the first readiness contract that can represent authenticated selected-runtime artifacts.

[`stage4-offline-source-inventory.ts`](../../scripts/stage4-offline-source-inventory.ts) inventories every tracked worktree source, build, test, qualification, workflow, vendored `third_party/`, documentation, and evidence input rather than maintaining a selected-prefix approximation. Local validation separately binds its active validators, procedure documentation, hostile tests, and passing production source-contract command. Exactly three generated evidence outputs are excluded to break explicit recursion:

- the readiness package, which binds the inventory;
- the source inventory itself; and
- local validation, which binds source/procedure digests and is itself bound by the package.

No other tracked file is excluded. Untracked paths are outside this tracked-source closure and cannot enter the release build because that workflow constructs its context with `git archive` from the exact reviewed commit. Every inventory entry records its exact Git mode (`100644` or `100755`), path, and exact worktree-byte SHA-256. Regeneration verifies the parsed Git mode against the worktree executable bits, and the domain-separated worktree Merkle digest covers all three fields. The inventory also records the complete tracked path-set digest. It intentionally records no commit or clean-index claim: the complete tracked-mode/worktree-byte closure is authoritative for this local package and must later be bound separately to any reviewed release candidate. Every file is opened with `O_NOFOLLOW`; every path component is retained; lstat/fstat identities are compared before and after bounded descriptor reads; final files must be regular, single-linked, nonempty, mode-consistent, and bounded. Symlink components/finals, hard links, executable-mode mismatch, oversize files, path replacement, and identity drift fail closed.

Tests regenerate the inventory from the final worktree and require byte identity. After an integrated-branch source change, `npm run readiness:regenerate` deterministically reruns the trusted renderer and all recorded commands, preserves the schema-enforced strict inventory scopes, rebuilds schema/source/local-validation records, rewrites normalized classifier anchors without a self-hash cycle, reruns the commands against the rewritten source, rejects normalized-result drift, and emits the final canonical package. Formatting and validation must then pass without changing those bytes.

The semantic root additionally binds the closed resource graph, independent inventory map, blockers, identities, one-attempt rule, stop/destroy behavior, and complete revalidation trigger inventory. Matching digests do not authenticate provider truth.

## Trusted render provenance

The trusted preparation pins Node `v22.22.2` (`darwin`/`arm64`) at SHA-256 `5c899797c4eb8f1db5563eea56538342ddb3e9276ee1b04a5a1f0f1023d2b011` and Helm `v4.1.1+g5caf004` at SHA-256 `9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4`. No tsx or other loader is allowed in the trusted invocation. Both executable paths must resolve exactly. Helm is opened without following a final symlink, read and race-checked through one descriptor, copied into a private mode-0700 directory, made mode 0500, re-read and authenticated, and only that copy is executed and reauthenticated. Chart and values temporary files are likewise written from authenticated bytes rather than reopened source paths. The process uses no shell, a minimal fixed environment, client-only dry run, absent kubeconfig, no DNS, a 20-second bound, and bounded stdout/stderr.

The canonical receipt contains only digests, fixed categories, and false cloud/provider/Kubernetes observation fields. It binds the actual Node binary/version/platform/architecture, absence of a TypeScript loader, exact generator bytes from `import.meta.filename`, a digest over that execution layer, exact chart inventory, values, original and copied Helm bytes, Helm version output, normalized lint output, the empty zero-manifest output, fixed wrapper source, and both render outputs. The classifier canonical-parses it and requires its exact anchored digest plus cross-bindings to source, local validation, chart, values, and renders. It likewise canonical-parses and exact-validates anchored source, schema, local-validation, image, and runtime records; package digest/root rewrites cannot replace them. Tests freshly execute the pinned renderer and reject forged identical committed renders or opaque receipts even if a hostile package copy rewrites artifact digests and its semantic root.

## Authenticated runtime candidate, frozen static pins, and remaining blockers

[`stage4-runtime-artifact-closure.ts`](../../scripts/stage4-runtime-artifact-closure.ts) builds and purely classifies the strict v1 authenticated-runtime evidence. It performs no filesystem, process, network, provider, Kubernetes, Docker, or external-model operation. The evidence binds:

- containerd `2.2.1` static amd64 archive SHA-256 `af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883`, its checksum record, SLSA v1 attestation, source commit, GitHub Actions workflow identity/issuer/run, and selected `containerd`/`ctr` archive members;
- Kata `3.32.0` archive SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01`, immutable-release attestation and source commit;
- the QEMU executable actually selected by Kata's bundled configuration: `opt/kata/bin/qemu-system-x86_64`, version `11.0.1`, SHA-256 `1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d`; configuration SHA-256 `7ecd072a35da55f5abc76d604a610cf3f2d543c7de0cefc4d1a81028facd2cae`; and guest kernel `vmlinux-6.18.35-197` SHA-256 `43701715ae2885f936bbe5c66a2de7c14dc51de7d19412d04833e4bbcf205bd0`; and
- exact Envoy/OpenBao OCI indexes and amd64 manifests, signed OpenBao identity, unsigned Envoy disposition, empty adopted-skill policy/digests, chart inventory, schema inventory, package lock, and Pi package SRIs.

Historical NIC v1 preserves the `v0.11.0` / module `0.7.0` missing-capability result. Active v2 pins accepted personal-fork NIC `53b1a791ed1ff394969e0aeaa6379be955244b62` and module `c3017c0e15b538cd4e04c0786809a861ea82c621`; source-level external launch-template ID/version preservation is satisfied with operator attestation only. Launch-template contents and provider truth remain unobserved. ADR 0094's separate local static manifest handoff does not change campaign readiness or provider authority.

QEMU `8.2.2` is retained only as the historical Ubuntu host command observation from Stage 2. Its authenticated upstream source tarball is explicitly source-only and is not substituted for the active Kata `11.0.1` executable. Consequently the NIC capability, `CONTAINERD_ARTIFACT_IDENTITY_UNRESOLVED`, and `QEMU_ARTIFACT_IDENTITY_UNRESOLVED` blockers are absent from active readiness v2.

The public node-image candidate is Kubernetes `1.35`, `AL2023_x86_64_STANDARD`, `amazon-eks-node-al2023-x86_64-standard-1.35-v20260728`, release `1.35.6-20260728`, catalog commit `80b4c870f33069dadf27e075f184c06cccfc7999`, and public kernel package `6.12.94-123.192.amzn2023`. Kubernetes `1.35` matches the pinned autoscaler default line and the latest non-abandoned public AMI catalog. The catalog's baked containerd `2.2.5-1.amzn2023.0.1` does not satisfy the selected `2.2.1` pin, so a future authenticated override and runtime observation remain required. Region-specific AMI ID and running kernel remain null because only AWS/provider execution can resolve them.

### Honest image, NIC, and runtime blockers

Worker and sandbox image references remain `.invalid` synthetic placeholders. Envoy is content-pinned but no publisher signature was found for the exact image; OpenBao is signed but neither image has been observed in a release runtime. Thus `release_image_set_present=false`, `exact_image_runtime_closure_satisfied=false`, and `RELEASE_IMAGE_SET_ABSENT` remain. Active NIC v2 resolves source capability only; launch-template contents and provider truth remain unobserved. The readiness blockers retain issue #42, AWS image/kernel, account, current price, current quota, separated identities, campaign approval/envelope, release images, and executable provider route. All cloud, provider, Kubernetes, current-resource, zero-resource, Stage 4 exit, and release claims remain false.

Regenerate the authenticated evidence alone with `npx tsx scripts/stage4-runtime-artifact-closure-regenerate.ts`. The full `npm run readiness:regenerate` procedure regenerates the runbook index, schema inventory, the runtime evidence's deterministic schema-inventory anchor, authenticated evidence, source/local-validation inventories, classifier anchors, and the v2 package. If integration changes a schema or any frozen source byte, rerun the full procedure rather than hand-editing digests.

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
