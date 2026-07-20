# Cogs

Cogs is a secure, minimal, VM-isolated personal assistant built by embedding Pi.

**Status: development-only Stage 3 local vertical slice.** Cogs now has local Pi embedding with native JSONL session history, SSH/SFTP-backed tool ports, default-deny egress integration, static policy enforcement, metadata-only telemetry, local session export, and a development launcher with `insecure-container` functional-only and `linux-kvm` authoritative-local profiles. It is not production-ready and provides no production daemon, scheduler, EKS/cloud deployment, release, compliance, or general isolation guarantee.

Authoritative project documents, in order:

1. [`COGS.md`](COGS.md) — product needs and scope
2. [`SECRET-INJECTION.md`](SECRET-INJECTION.md) — credential-security requirements
3. [`DESIGN.md`](DESIGN.md) — architecture and security contract
4. [`IMPLEMENTATION.md`](IMPLEMENTATION.md) — staged plan and acceptance gates

Current Stage 3 work is local-only. The development launcher exercises the local vertical slice and records metadata-only evidence; `insecure-container` is functional-only and cannot support isolation claims, while `linux-kvm` is the authoritative-local path when KVM prerequisites are met. The next exit gate is #71, the authoritative Linux/KVM Stage 3 scenario.

Implemented local capabilities include Pi session embedding, trusted SSH/SFTP file and bash tools, egress proxy integration, policy/telemetry plumbing, durable session history and export, and launcher smoke workflows. AWS feasibility work remains separate and must not be treated as completed or as evidence of current cloud resources.

## Local checks

Requires Node.js 22.22.2.

```bash
npm ci --ignore-scripts
npm run check
helm lint deploy/helm/cogs
helm template cogs deploy/helm/cogs  # intentionally emits no resources
```

The local macOS host and development containers cannot provide authoritative guest-root security evidence. See [`docs/operations/ci-schedule.md`](docs/operations/ci-schedule.md).

## License

Apache License 2.0.
