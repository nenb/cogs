# Cogs

Cogs is a secure, minimal, VM-isolated personal assistant built by embedding Pi.

**Status: Stage 0 feasibility work. Cogs is not production-ready and currently provides no sandbox, credential, deployment, or isolation guarantee.**

Authoritative project documents, in order:

1. [`COGS.md`](COGS.md) — product needs and scope
2. [`SECRET-INJECTION.md`](SECRET-INJECTION.md) — credential-security requirements
3. [`DESIGN.md`](DESIGN.md) — architecture and security contract
4. [`IMPLEMENTATION.md`](IMPLEMENTATION.md) — staged plan and acceptance gates

Stage 0 covers deterministic repository/CI setup, Pi SDK embedding and native JSONL compatibility, hostile extension/package canaries, Linux/KVM runner qualification, evidence conventions, and initial ADRs. It does not implement EKS, the production worker/daemon, secure egress, application deployment, or sanitization.

## Local checks

Requires Node.js 22.22.2.

```bash
npm ci --ignore-scripts
npm run check
helm lint deploy/helm/cogs
helm template cogs deploy/helm/cogs  # intentionally emits no resources in Stage 0
```

The local macOS host and development containers cannot provide authoritative guest-root security evidence. See [`docs/operations/ci-schedule.md`](docs/operations/ci-schedule.md).

## License

Apache License 2.0.
