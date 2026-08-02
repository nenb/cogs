# Stage 5 draft operations runbooks

**Status:** issue #366 local/static documentation only. These drafts are not an installation, deployment, campaign approval, operator authorization, release decision, production claim, GA claim, or compliance claim. They contain no provider command, resource target, credential, or cluster operation.

The strict inventory is [`index.json`](index.json), governed by [`stage5-operations-runbook-index-v1.json`](../../../schemas/stage5-operations-runbook-index-v1.json). Schema or link validity establishes documentation consistency only. It does not authenticate an operator or evidence, observe a platform, or satisfy S4-11 or Stage 5.

## Fact classes

Every runbook uses the following headings and the classes must not be merged:

1. **Assumptions** — a proposed operator/environment condition; untested and unable to satisfy a gate. [Authority: IMPLEMENTATION evidence format](../../../IMPLEMENTATION.md#75-security-evidence-format)
2. **Static contract facts** — checked source/schema/classifier/plan requirements that describe expected shape, not installed behavior. [Authority: Stage 4 offline readiness boundary](../stage-4-offline-readiness.md#pure-classifier-boundary)
3. **Authoritative-local facts** — accepted Linux/KVM evidence only for its exact local profile; containers/macOS are not authoritative. [Authority: CI profile schedule](../ci-schedule.md#ci-and-conformance-schedule)
4. **Future cloud evidence** — observations requiring a separately approved exact-revision campaign with real dependencies; a planned link is not evidence. [Authority: matrix evidence lanes](../stage-5-api-key-release-acceptance-matrix.md#evidence-lanes-remain-separate)

When classes disagree, use the least-authoritative result and preserve uncertainty. A static pass never promotes a future observation to true.

## Common operating rules

- Stage 2 issue #42 remains the cloud-entry blocker; closure permits only a fresh Stage 4 request. [Authority: offline readiness blockers](../stage-4-offline-readiness.md#current-blockers-preserved-exactly)
- NIC `v0.11.0` cannot carry required launch-template/nested-CPU fields; EKS image is unresolved. [Authority: NIC current blockers](../stage-4-nic-node-group-contract.md#authenticated-public-source-pin-and-current-blockers)
- Subscription OAuth is disabled and unadvertised. Issue #13 is future post-MVP work only; worker refresh tokens are forbidden. [Authority: matrix OAuth blocker](../stage-5-api-key-release-acceptance-matrix.md#subscription-oauth-blocker)
- Missing identity/policy/audit/ownership/storage/runtime/network/evidence fails closed without local-tool, `runc`, TCG, open-egress, or credential fallback. [Authority: DESIGN mandatory invariants](../../../DESIGN.md#44-mandatory-invariants)
- Ownership cannot be inferred from name/prefix/tag/visibility/one inventory; broad deletion is forbidden. [Authority: storage uncertainty contract](../stage-4-storage-launch-contract.md#exclusive-writer-lease)
- Tickets/telemetry/evidence exclude credentials, prompts, source, complete commands, arbitrary paths, query/body, tool output, and raw exports. [Authority: DESIGN privacy defaults](../../../DESIGN.md#162-privacy-defaults)
- Failure/interruption/timeout/drift/uncertainty stops the attempt without in-place widening, discovery cleanup, or retry. [Authority: offline stop/destroy paths](../stage-4-offline-readiness.md#non-executable-stop-and-destroy-paths)

## Inventory

| ID | Exact title | Indexed path |
|---|---|---|
| `installation` | Draft installation guide | [`docs/operations/runbooks/installation.md`](installation.md) |
| `prerequisites` | Draft prerequisites guide | [`docs/operations/runbooks/prerequisites.md`](prerequisites.md) |
| `nic-configuration` | Draft NIC configuration guide | [`docs/operations/runbooks/nic-configuration.md`](nic-configuration.md) |
| `platform-matrix` | Draft NIC and platform matrix | [`docs/operations/runbooks/platform-matrix.md`](platform-matrix.md) |
| `upgrade` | Draft runtime and proxy upgrade runbook | [`docs/operations/runbooks/upgrade.md`](upgrade.md) |
| `openbao` | Draft OpenBao policy and revocation runbook | [`docs/operations/runbooks/openbao.md`](openbao.md) |
| `incident-response` | Draft credential incident-response runbook | [`docs/operations/runbooks/incident-response.md`](incident-response.md) |
| `cve-response` | Draft node and runtime CVE response runbook | [`docs/operations/runbooks/cve-response.md`](cve-response.md) |
| `retention-deletion` | Draft backup, retention, export, and deletion guide | [`docs/operations/runbooks/retention-deletion.md`](retention-deletion.md) |
| `capacity` | Draft capacity and cost planning guide | [`docs/operations/runbooks/capacity.md`](capacity.md) |
| `observability` | Draft observability dashboard field reference | [`docs/operations/runbooks/observability.md`](observability.md) |
| `limitations` | Draft known limitations and residual risks | [`docs/operations/runbooks/limitations.md`](limitations.md) |
| `teardown` | Draft teardown and orphan-resource verification guide | [`docs/operations/runbooks/teardown.md`](teardown.md) |

## Evidence and authority links

- Governing architecture and gates: [`DESIGN.md`](../../../DESIGN.md), [`IMPLEMENTATION.md`](../../../IMPLEMENTATION.md), and [`SECRET-INJECTION.md`](../../../SECRET-INJECTION.md).
- Current ownership rules: [`ownership.md`](../ownership.md).
- Static Stage 4 contracts: [NIC](../stage-4-nic-node-group-contract.md), [storage/launch](../stage-4-storage-launch-contract.md), [offline readiness](../stage-4-offline-readiness.md), and [teardown order](../stage-4-teardown.md).
- Provisional Stage 5 requirements: [API-key-only acceptance matrix](../stage-5-api-key-release-acceptance-matrix.md).
- Authoritative-local boundary: [Stage 3 Linux/KVM exit report](../../test-reports/stage-3-s3-09-linux-kvm-exit.md).

These drafts must be rebound to an exact future candidate and rerun under the matrix's `future-operations-reference-v1` lane before they can contribute to any later decision.
