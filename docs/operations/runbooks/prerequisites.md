# Draft prerequisites guide

This is a requirements checklist, not a discovery script or installation authorization. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future environment may be able to provide dedicated trusted and KVM sandbox nodes, externally enforced networking, CSI block volumes, OpenBao, and an OTLP collector.
- A future organization may bind the required operator, approver, budget approver, security reviewer, and zero-inventory observer to distinct authenticated principals.
- Current price, quota, capacity, account suitability, and service availability are unknown.

Unverified assumptions remain blockers.

## Static contract facts

### Governance and authority

- Issue #42 is open and blocks cloud entry. Closure alone would not authorize a campaign.
- Every campaign is one-attempt-only, exact-revision-bound, time-boxed, spend-capped, and subject to state-bound destroy plus independent inventory.
- The offline package currently records no account, principal bindings, campaign envelope, attempt ID, approval, or executable provider route.

### Runtime and scheduling

- Required sandbox runtime: Kata `3.32.0`, archive SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01`, containerd `2.2.1`, QEMU `8.2.2`, `io.containerd.kata.v2`, and KVM-only acceleration.
- RuntimeClass must be exactly `kata-qemu-cogs`. `runc` and TCG fallback are forbidden.
- Trusted and sandbox placement must remain disjoint. The [NIC contract](../stage-4-nic-node-group-contract.md) fixes exact labels and taint/toleration shape.

### Identity, egress, and secrets

- The sandbox receives no service-account token, cloud credential, OpenBao identity, real model/integration credential, or CA private key.
- Egress is explicit HTTP/HTTPS proxy only, externally default-denied, dual-stack covered or IPv6 disabled, and UDP blocked.
- Credential-use authorization and local audit-WAL append fail closed. Ordinary OTLP delivery failure does not stop uncredentialed work.
- Subscription OAuth is disabled and unadvertised; issue #13 is future post-MVP work only. API keys are the only planned Stage 4/5 model-auth class.

### Storage and data

- Workspace: distinct 20 GiB CSI block-backed `Filesystem`, `ReadWriteOncePod`, `WaitForFirstConsumer`, `Retain`; sandbox only; retained until explicit workspace deletion.
- Trusted Pi state: distinct 5 GiB `Filesystem`, `ReadWriteOncePod`, `WaitForFirstConsumer`, `Retain`; trusted worker only; 30-day default after close.
- One fenced writer is required. Expiry or uncertainty never authorizes takeover.

## Authoritative-local facts

- Linux/KVM is the only authoritative-local profile and only for accepted local guest-root evidence.
- Stage 3 demonstrated the local worker boundary, SSH/SFTP tools, API-key-only model-auth path, integrated proxy controls, metadata-only telemetry, session/Git/export behavior, and cleanup within the report's applicability.
- Local OpenBao smoke is functional-only; it does not prove Kubernetes auth, multi-tenant policy, or cluster revocation behavior.

See the [Stage 3 exit report](../../test-reports/stage-3-s3-09-linux-kvm-exit.md) and [CI schedule](../ci-schedule.md).

## Future cloud evidence

Before any later installation decision, exact evidence must answer every item below:

- capable NIC revision and preserved launch-template ID/version with nested virtualization enabled;
- immutable EKS node image/release/kernel and active KVM modules/device;
- actual RuntimeClass, no trusted sandbox sidecar, no runtime fallback;
- real CNI denial of IPv4, IPv6, UDP/QUIC, metadata, API/admin, cross-session, and direct egress bypass;
- actual CSI attach/detach/reattach, retained deletion behavior, fencing, and forced-loss outcomes;
- scoped OpenBao workload identity, PKI, secret retrieval, revocation/drain, audit WAL, and metadata-only OTLP;
- startup, capacity, failure, privacy/deletion, cost, and independent zero-inventory evidence.

## Admission decision

A prerequisite is `present` only when its designated future authority binds a truthful observation to the exact candidate and principal. `Unknown`, stale, inferred, static-only, functional-only, or mismatched observations are `blocking`. Do not downgrade them to warnings or compensate with broader privileges, fallback runtimes, shared storage, or open networking.
