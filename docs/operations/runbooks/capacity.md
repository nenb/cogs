# Draft capacity and cost planning guide

All figures are planning inputs unless explicitly labelled authoritative-local. This guide performs no pricing, quota, provider, cluster, or model call. Read the [runbook authority rules](README.md) first.

## Assumptions

- Session demand, repository workload, model latency, node shape, bin-packing, image cache, storage throughput, OpenBao limits, and telemetry backend capacity will differ by environment.
- Current provider price, quota, service capacity, and EKS overhead are unknown. The offline USD 20 cap and USD 5/10/20 alerts are proposal ceilings, not current cost evidence or a hard kill switch.
- A future autoscaler and admission service will enforce limits; neither exists as a production daemon in this repository.

## Static contract facts

### Resource classes

| Class | CPU request | Memory request |
|---|---:|---:|
| Default | 2 vCPU | 4 GiB |
| Large | 4 vCPU | 8 GiB |
| Maximum | 8 vCPU | 16 GiB |

Additional defaults are 20 GiB ephemeral guest disk, 30-minute idle shutdown, eight-hour maximum sandbox lifetime with settled-turn recycle and separate emergency deadline, and four concurrent sessions per user. The workspace role is a distinct retained 20 GiB allocation; trusted session state is a distinct retained 5 GiB allocation.

At 250 default active sessions, requested sandbox capacity alone is 500 vCPU and 1 TiB memory, before workers, proxies, runtime/VM overhead, system reservations, storage, and telemetry. This arithmetic is not a validated capacity claim.

### Future load sequence

The fixed planned ramp is 10, 25, 50, 100, then 250 only after every earlier step meets safety, stability, cost, and cleanup gates. At least 50 real concurrent sandboxes is a later Stage 5 criterion; no such cloud result exists. An advertised maximum may never exceed the highest successful real step.

## Authoritative-local facts

- Local benchmarks and Stage 3 operation establish functional behavior only at their recorded small local concurrency and exact environment.
- The Stage 2 standalone candidate evidence is not EKS density, CNI, EBS, control-plane, or current pricing evidence.
- No authoritative-local result supports advertising a cloud session count.

## Future cloud evidence

At each separately approved ramp step, collect:

- requested/actual worker, proxy, sandbox, VM, and system CPU/memory;
- node count, allocatable capacity, bin-packing, scheduling/image-pull failures, and cold-start p50/p95/p99;
- first-tool, SSH-ready, storage attach, Git/build, proxy, and recycle latency;
- proxy connections/resources, OpenBao request/error rate, SSH channels/errors, CSI latency/throughput;
- OTLP export lag and audit-WAL depth/full events;
- admission denials, per-user concurrency, same-workspace lease denial, cross-user isolation;
- infrastructure cost per active-session hour and model cost separately;
- teardown duration, failures, residue, and independent inventory.

Infrastructure saturation tests use mocked model responses; separately authorized small API-key samples are required for real-model latency/usage evidence. This issue invokes neither.

## Planning method

For a proposed class mix, calculate:

- sandbox CPU = sum of class CPU requests;
- sandbox memory = sum of class memory requests;
- durable storage = active workspaces × 20 GiB plus retained session states × 5 GiB, adjusted only by measured backend behavior;
- trusted overhead, VM/runtime overhead, daemon/platform overhead, failure headroom, and rollout headroom as separate measured terms, never hidden in an assumed multiplier;
- max admission as the minimum independently safe bound across compute, memory, storage, IP/network, proxy, OpenBao, SSH, WAL, OTLP, quota, and spend.

If any term is unknown, capacity is unknown and admission remains closed for the proposed step.

## Step gate and stop conditions

Before a future step, require exact candidate binding, approved node/session/spend/time ceiling, synthetic data, prior-step pass, cleanup closure, and independent observer. Stop admissions and end the attempt on scheduling instability, data isolation failure, WAL full, uncontrolled spend, missing metrics, timeout, cleanup uncertainty, or any security failure. Do not scale around a blocker, alter resource classes during a run, or infer 100/250 support from 50.
