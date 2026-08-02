# Stage 5 draft operations runbooks

**Status:** issue #366 local/static documentation only. These drafts are not an installation, deployment, campaign approval, operator authorization, release decision, production claim, GA claim, or compliance claim. They contain no provider command, resource target, credential, or cluster operation.

The strict inventory is [`index.json`](index.json), governed by [`stage5-operations-runbook-index-v1.json`](../../../schemas/stage5-operations-runbook-index-v1.json). Schema or link validity establishes documentation consistency only. It does not authenticate an operator or evidence, observe a platform, or satisfy S4-11 or Stage 5.

## Fact classes

Every runbook uses the following headings and the classes must not be merged:

1. **Assumptions** — a proposed operator or environment condition. It is untested and cannot satisfy a gate.
2. **Static contract facts** — requirements fixed by checked source, schemas, classifiers, or plans. They describe expected shape, not installed behavior.
3. **Authoritative-local facts** — accepted Linux/KVM evidence, applicable only to that exact local profile. Development containers and macOS VMs are not authoritative.
4. **Future cloud evidence** — observations still required from a separately approved, exact-revision campaign with real dependencies. A planned evidence link is not evidence.

When classes disagree, use the least-authoritative result and preserve uncertainty. A static pass never promotes a future observation to true.

## Common operating rules

- Stage 2 issue #42 remains the cloud-entry blocker. Its closure would permit only a fresh Stage 4 request, never execution by itself.
- The NIC `v0.11.0` source contract is blocked because it cannot carry the required custom launch-template ID/version and nested-virtualization CPU option. The EKS node image is unresolved.
- Subscription OAuth is disabled and unadvertised. Issue #13 is future post-MVP work only. Workers must not receive or persist subscription refresh tokens.
- Fail closed on missing identity, policy, audit, ownership, storage/lease, runtime, network, or evidence state. Do not fall back to local tools, `runc`, TCG, open egress, or another credential source.
- Never infer ownership from a name, prefix, tag alone, current visibility, or absence from one inventory. Never perform wildcard, recursive, account-wide, region-wide, label-wide, or other broad deletion.
- Do not place credentials, prompts, source, complete commands, arbitrary paths, query strings, bodies, tool output, or raw exports in tickets, central telemetry, or runbook evidence.
- Failure, interruption, timeout, drift, or uncertainty stops the attempt. It does not authorize debugging in place, widening, replacement resources, cleanup by discovery, or retry.

## Inventory

| ID | Draft guide |
|---|---|
| `installation` | [Installation](installation.md) |
| `prerequisites` | [Prerequisites](prerequisites.md) |
| `nic-configuration` | [NIC configuration](nic-configuration.md) |
| `platform-matrix` | [Platform matrix](platform-matrix.md) |
| `upgrade` | [Runtime and proxy upgrade](upgrade.md) |
| `openbao` | [OpenBao policy and revocation](openbao.md) |
| `incident-response` | [Credential incident response](incident-response.md) |
| `cve-response` | [Node and runtime CVE response](cve-response.md) |
| `retention-deletion` | [Backup, retention, export, and deletion](retention-deletion.md) |
| `capacity` | [Capacity and cost planning](capacity.md) |
| `observability` | [Observability field reference](observability.md) |
| `limitations` | [Known limitations and residual risks](limitations.md) |
| `teardown` | [Teardown and orphan escalation](teardown.md) |

## Evidence and authority links

- Governing architecture and gates: [`DESIGN.md`](../../../DESIGN.md), [`IMPLEMENTATION.md`](../../../IMPLEMENTATION.md), and [`SECRET-INJECTION.md`](../../../SECRET-INJECTION.md).
- Current ownership rules: [`ownership.md`](../ownership.md).
- Static Stage 4 contracts: [NIC](../stage-4-nic-node-group-contract.md), [storage/launch](../stage-4-storage-launch-contract.md), [offline readiness](../stage-4-offline-readiness.md), and [teardown order](../stage-4-teardown.md).
- Provisional Stage 5 requirements: [API-key-only acceptance matrix](../stage-5-api-key-release-acceptance-matrix.md).
- Authoritative-local boundary: [Stage 3 Linux/KVM exit report](../../test-reports/stage-3-s3-09-linux-kvm-exit.md).

These drafts must be rebound to an exact future candidate and rerun under the matrix's `future-operations-reference-v1` lane before they can contribute to any later decision.
