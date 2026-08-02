# Draft capacity and cost planning guide

All figures are planning inputs unless explicitly labelled authoritative-local. This guide performs no pricing, quota, provider, cluster, or model call. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| Demand, workload, model latency, node/bin-packing/cache/storage/OpenBao/telemetry capacity vary by environment. | [Authority: DESIGN resource lifecycle and scale](../../../DESIGN.md#18-resource-lifecycle-and-scale) |
| Price/quota/capacity/EKS overhead are unknown; USD 20 cap and USD 5/10/20 alerts are proposal-only, not hard kill. | [Authority: offline readiness proposal envelope](../stage-4-offline-readiness.md#proposal-only-envelope) |
| A future autoscaler/admission service may enforce limits; no production daemon exists here. | [Authority: DESIGN non-goals](../../../DESIGN.md#3-non-goals) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Resource classes are Default 2 vCPU/4 GiB, Large 4/8 GiB, Maximum 8/16 GiB. | [Authority: DESIGN resource lifecycle and scale](../../../DESIGN.md#18-resource-lifecycle-and-scale) |
| Defaults include 20 GiB ephemeral disk, 30-minute idle, eight-hour settled-boundary recycle plus emergency deadline, and four sessions/user. | [Authority: DESIGN resource lifecycle and scale](../../../DESIGN.md#18-resource-lifecycle-and-scale) |
| Durable workspace/trusted-state roles are distinct retained 20 GiB/5 GiB allocations. | [Authority: storage/launch durable roles](../stage-4-storage-launch-contract.md#separate-durable-storage-roles) |
| Arithmetic for 250 default sandboxes is 500 vCPU/1 TiB before overhead and is not validated capacity. | [Authority: DESIGN resource lifecycle arithmetic](../../../DESIGN.md#18-resource-lifecycle-and-scale) |
| Planned ramp is 10/25/50/100/250 with prior-step gates; no cloud result exists; advertisement cannot exceed passing real load. | [Authority: IMPLEMENTATION ramp plan](../../../IMPLEMENTATION.md#401-ramp-plan) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Local benchmarks/Stage 3 establish only recorded small local concurrency and environment. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |
| Stage 2 standalone candidate is not EKS density, CNI, EBS, control-plane, or current price evidence. | [Authority: Stage 2 measurement report limitations](../../test-reports/stage-2-aws-measurement.md#limitations-and-non-claims) |
| No authoritative-local result supports a cloud session-count advertisement. | [Authority: provisional matrix platform profiles](../stage-5-api-key-release-acceptance-matrix.md#platform-profiles) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Collect requested/actual worker/proxy/sandbox/VM/system CPU and memory. | [Planned DESIGN-24.20–.22 / `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Collect nodes, allocatable/bin-packing, scheduling/image failures, and cold-start percentiles. | [Planned DESIGN-24.21–.22 / `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Collect first-tool/SSH/storage/Git/build/proxy/recycle latency. | [Planned DESIGN-24.20–.22 / `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Collect proxy/OpenBao/SSH/CSI resources and errors. | [Planned DESIGN-24.20–.22 / `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Collect OTLP lag and WAL depth/full outcomes. | [Planned DESIGN-24.10, .22 / `future-eks-conformance-reference-v1`, `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove admission/per-user/same-workspace/cross-user controls. | [Planned DESIGN-24.19–.22 / `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Separate infrastructure cost/session-hour from model cost. | [Planned STAGE5-45.05, .11 / `future-load-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Measure teardown duration/failures/residue and independent inventory. | [Planned STAGE5-45.11 / `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Use mocked model saturation and separately authorized small API-key samples; this issue invokes neither. | [Authority: IMPLEMENTATION ramp plan](../../../IMPLEMENTATION.md#401-ramp-plan) |

## Planning method

**Section authority:** [Authority: IMPLEMENTATION ramp plan](../../../IMPLEMENTATION.md#401-ramp-plan).

For a proposed class mix, calculate:

- sandbox CPU = sum of class CPU requests;
- sandbox memory = sum of class memory requests;
- durable storage = active workspaces × 20 GiB plus retained session states × 5 GiB, adjusted only by measured backend behavior;
- trusted overhead, VM/runtime overhead, daemon/platform overhead, failure headroom, and rollout headroom as separate measured terms, never hidden in an assumed multiplier;
- max admission as the minimum independently safe bound across compute, memory, storage, IP/network, proxy, OpenBao, SSH, WAL, OTLP, quota, and spend.

If any term is unknown, capacity is unknown and admission remains closed for the proposed step.

## Step gate and stop conditions

**Section authority:** [Planned STAGE5-45.05 / `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability).

Before a future step, require exact candidate binding, approved node/session/spend/time ceiling, synthetic data, prior-step pass, cleanup closure, and independent observer. Stop admissions and end the attempt on scheduling instability, data isolation failure, WAL full, uncontrolled spend, missing metrics, timeout, cleanup uncertainty, or any security failure. Do not scale around a blocker, alter resource classes during a run, or infer 100/250 support from 50.
