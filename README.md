# Cogs

Cogs is a secure, minimal, VM-isolated personal assistant built by embedding Pi.

**Status: pre-release; the Stage 3 local vertical slice is complete.** Accepted Linux/KVM evidence covers the authoritative-local profile only. Stage 2 issue #42 remains the hard gate before any Stage 4 cloud campaign, and no Stage 4 EKS/NIC or Stage 5 release-readiness claim exists yet. Cogs is not production-ready and provides no production daemon, scheduler, user ingress, EKS deployment, release, compliance, or general isolation guarantee.

Authoritative project documents, in order:

1. [`COGS.md`](COGS.md) — product needs and scope
2. [`SECRET-INJECTION.md`](SECRET-INJECTION.md) — credential-security requirements
3. [`DESIGN.md`](DESIGN.md) — architecture and security contract
4. [`IMPLEMENTATION.md`](IMPLEMENTATION.md) — staged plan and acceptance gates

Stage 3 exited through closed issue #71 and the accepted [S3-09 Linux/KVM report](docs/test-reports/stage-3-s3-09-linux-kvm-exit.md). The development launcher remains development-only; `insecure-container` is functional-only, and `linux-kvm` is authoritative only for local guest-root evidence. Local/static Stage 4 preparation may proceed, but #42 must close before any Stage 4 cloud action, followed by a separate explicit campaign approval. Issue #356's workload-identity, proxy, network, telemetry, and audit-WAL policy contracts are static expected-policy shapes only and remain pending exact EKS CNI/runtime qualification. Issue #355 adds only a [pure local storage and session-launch object-graph contract](docs/operations/stage-4-storage-launch-contract.md): it launches nothing, observes no RuntimeClass/storage/provider truth, and grants no deployment or cleanup authority.

Implemented local capabilities include Pi session embedding, trusted SSH/SFTP file and bash tools, egress proxy integration, policy/telemetry plumbing, durable session history and export, and launcher smoke workflows. Local Stage 4 preparation now includes a strict [NIC sandbox node-group source contract](docs/operations/stage-4-nic-node-group-contract.md), pinned to NIC `v0.11.0`; that source lacks the required custom launch-template ID/version and nested-virtualization CPU option, while the EKS node-image pin also remains unresolved, so the contract fails closed and grants no cloud authority. Issue #357 assembles a [bounded offline readiness package](docs/operations/stage-4-offline-readiness.md): `local_preparation_complete=true` is narrowly `bounded-package-assembly-and-local-validation-only`. A pinned local Helm preparation executable freshly verifies render provenance, while the separate classifier remains pure. Release worker/sandbox images are absent placeholders, containerd/QEMU artifact identities and the EKS image/kernel are unresolved, and exact image/runtime closure is false. The package fixes `campaign_request_ready=false` and `cloud_authorized=false`, has no account or executable provider route, and requires fresh revalidation after #42 closure or any source, toolchain, validation, advisory, pin, price, quota, account, identity, approval, attempt, destroy, inventory, or campaign-shape change. [Issues #358–#362 offline models](docs/operations/stage-4-campaign-offline-models.md) add only an absent/unapproved one-attempt envelope, digest-bound non-executable campaign ordering models, and an always-false exit-review template. #358–#362 remain open/blocked; these fixtures and templates cannot authorize execution/retry or establish cleanup/inventory truth. A bounded standalone EC2 campaign selected the initial Stage 4 runtime candidate, but #42's completion measurements are deferred and no AWS resources are currently claimed. Standalone EC2 evidence is not EKS, CNI, release, or production evidence.

Issue #365 adds a [local/static synthetic privacy and deletion contract](docs/operations/stage-5-privacy-retention-export-deletion.md) for bounded OTLP/log/report/event/crash/export metadata, raw-export marking and attachment exclusion, retention/version policy, separate legal hold, and deterministic failure/uncertainty-aware deletion modeling. It commits no raw fixture payload and fixes actual EKS/object-store deletion to unexecuted. Issue #366 adds a strict [local/static draft runbook set](docs/operations/runbooks/README.md) for future installation, operations, incidents, upgrades, capacity, and teardown. Neither establishes operational, cloud, release, production, GA, or compliance authority.

## Local checks

Requires Node.js 22.22.2.

```bash
npm ci --ignore-scripts
npm run check
helm lint deploy/helm/cogs
helm template cogs deploy/helm/cogs  # submits zero manifests; enabled shapes exist only in unsafe, unqualified NOTES
```

The local macOS host and development containers cannot provide authoritative guest-root security evidence. See [`docs/operations/ci-schedule.md`](docs/operations/ci-schedule.md).

## License

Apache License 2.0.
