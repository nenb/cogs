# Draft known limitations and residual risks

These boundaries must accompany every future evaluation. They are not defects silently waived by a successful test. Read the [runbook authority rules](README.md) first.

## Assumptions

- Operators and users will understand that Cogs grants powerful capabilities to untrusted model-directed code and that allowlists are not information-flow control.
- A configured model provider and trusted platform administrators remain trusted parties.
- Future external daemon, identity, storage, cluster, and provider implementations may add risks not represented in this repository.

## Static contract facts

### Security residuals

- An agent can misuse every intentionally granted capability. An approved write-capable endpoint can receive source; there is no DLP.
- Model providers receive prompt content and selected source by design.
- Hypervisor, QEMU, Kata, host kernel, proxy, worker, OpenBao, CNI, CSI, and platform compromise remain trusted-computing-base risks.
- A compromised trusted worker can access that session's model/integration credentials. Separating proxy bootstrap is deferred hardening.
- Guest root can copy its short-lived proxy capability; external source binding and route policy limit, but do not erase, that risk.
- TLS interception fails closed for certificate pinning/custom trust. Unsupported auth/protocol classes do not become safe via generic configuration.
- Git mappings are trusted records of untrusted sandbox observations, not repository integrity attestations.
- Hidden checkpoints, filesystem metadata, and tool wrappers do not provide complete syscall/filesystem auditing.

### Unsupported or deferred capabilities

- subscription OAuth, refresh-token handling, production daemon, user ingress, session sanitizer, apps/approvals, indexing/vector search, restoration, authoritative filesystem audit, general gRPC credential injection, SigV4/HMAC, mTLS, non-HTTP protocols, arbitrary TCP, WebSockets, QUIC/HTTP3, and wildcard egress;
- GCP, Azure, Hetzner, other-cloud, generic Kubernetes, and AWS EKS profile support;
- automatic prompt replay, exact mapping of commits made outside active Cogs observation, and crash-consistent per-turn object backup.

Subscription OAuth remains disabled and unadvertised; issue #13 is future post-MVP only.

## Authoritative-local facts

- Linux/KVM evidence is authoritative-local only and does not establish EKS, CNI, provider identity, cloud storage, release eligibility, production readiness, GA, compliance, or a general isolation guarantee.
- Insecure containers and macOS VMs remain development profiles without authoritative isolation claims.
- Stage 2 standalone EC2 evidence does not establish EKS or current resources.

## Future cloud evidence

The following remain unknown until bound to an exact separately approved profile: NIC capability, EKS node image/kernel, KVM/runtime state, scheduler separation, CNI bypass resistance, CSI retention/fencing, OpenBao workload identity, revocation bounds, OTLP privacy under load, capacity/cost, upgrades, incidents, deletion, teardown, and independent review. The [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md) has no accepted evidence or final decision.

## Public wording guardrails

Do not say or imply that Cogs:

- prevents source exfiltration, prompt injection, confused-deputy actions, or all hypervisor escape;
- supports a provider, platform, model provider, concurrency level, auth class, or protocol without exact accepted evidence;
- has a production daemon, scheduler, ingress, deployment, release, GA status, compliance certification, or general security guarantee;
- deletes all copies, provides anonymous exports, captures every filesystem action, or restores every turn;
- makes revocation instant for existing streams or makes explicit-proxy TLS compatible with every client.

Use bounded statements with profile, exact revision/artifact, evidence link, applicability, date, and residual risk.

## Operator stop conditions

Stop and preserve uncertainty on any request to bypass the VM, use a container fallback, expose cloud/Kubernetes/OpenBao credentials, permit direct/wildcard egress, disable audit, share trusted and sandbox mounts, broaden OpenBao paths, persist refresh tokens, centralize sensitive content, infer ownership, perform broad deletion, or advertise beyond evidence. Such a request requires architecture/security review and may be prohibited outright.
