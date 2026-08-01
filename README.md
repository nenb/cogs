# Cogs

Cogs is a secure, minimal, VM-isolated personal assistant built by embedding Pi.

**Status: pre-release; the Stage 3 local vertical slice is complete.** Accepted Linux/KVM evidence covers the authoritative-local profile only. Stage 2 issue #42 remains the hard gate before any Stage 4 cloud campaign, and no Stage 4 EKS/NIC or Stage 5 release-readiness claim exists yet. Cogs is not production-ready and provides no production daemon, scheduler, user ingress, EKS deployment, release, compliance, or general isolation guarantee.

Authoritative project documents, in order:

1. [`COGS.md`](COGS.md) — product needs and scope
2. [`SECRET-INJECTION.md`](SECRET-INJECTION.md) — credential-security requirements
3. [`DESIGN.md`](DESIGN.md) — architecture and security contract
4. [`IMPLEMENTATION.md`](IMPLEMENTATION.md) — staged plan and acceptance gates

Stage 3 exited through closed issue #71 and the accepted [S3-09 Linux/KVM report](docs/test-reports/stage-3-s3-09-linux-kvm-exit.md). The development launcher remains development-only; `insecure-container` is functional-only, and `linux-kvm` is authoritative only for local guest-root evidence. Local/static Stage 4 preparation may proceed, but #42 must close before any Stage 4 cloud action, followed by a separate explicit campaign approval. Issue #356's workload-identity, proxy, network, telemetry, and audit-WAL policy contracts are static expected-policy shapes only and remain pending exact EKS CNI/runtime qualification.

Implemented local capabilities include Pi session embedding, trusted SSH/SFTP file and bash tools, egress proxy integration, policy/telemetry plumbing, durable session history and export, and launcher smoke workflows. Local Stage 4 preparation now includes a strict [NIC sandbox node-group source contract](docs/operations/stage-4-nic-node-group-contract.md), pinned to NIC `v0.11.0`; that source lacks the required custom launch-template ID/version and nested-virtualization CPU option, while the EKS node-image pin also remains unresolved, so the contract fails closed and grants no cloud authority. A bounded standalone EC2 campaign selected the initial Stage 4 runtime candidate, but #42's completion measurements are deferred and no AWS resources are currently claimed. Standalone EC2 evidence is not EKS, CNI, release, or production evidence.

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
