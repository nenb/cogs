# ADR 0012: Use AWS virtual nested KVM as the Stage 4 runtime candidate

- Status: Accepted
- Date: 2026-07-14
- Decision owner: Nick Byrne
- Accepted by: Nick Byrne on 2026-07-14

## Context

`DESIGN.md` selects Kata Containers with QEMU/KVM as the reference runtime but deliberately left AWS virtual nested KVM versus bare metal pending Stage 2 evidence. `IMPLEMENTATION.md` requires a short-lived, one-instance AWS campaign before EKS-specific investment. ADR 0004 preserved Kata as the reference runtime while warning that AWS feasibility remained empirical.

Stage 2 has now produced one successful disposable EC2 campaign at source revision [`2036bb7d0e115bba2fa4b84f875e657559243c80`](https://github.com/nenb/cogs/tree/2036bb7d0e115bba2fa4b84f875e657559243c80). The detailed report is [`stage-2-aws-feasibility.md`](../test-reports/stage-2-aws-feasibility.md).

## Decision

Cogs will use **AWS virtual nested KVM on `c8i-flex.large` in `us-east-1` as the Stage 4 EKS/NIC candidate** for the Kata reference profile.

This decision is limited to candidate selection for the next validation stage. It does not approve production, release, EKS operation, general AWS availability, or a security/isolation claim beyond the measured one-instance evidence.

The Stage 4 candidate must preserve these bounds from Stage 2 unless a new review approves otherwise:

1. CPU-only virtual 8th-generation Intel nested-virtualization family; initial type `c8i-flex.large`.
2. Launch-template `CpuOptions.NestedVirtualization=enabled` must be rendered, applied, and independently verified.
3. No GPU, bare metal, NAT Gateway, load balancer, EIP, EFS workspace default, broad service expansion, or silent instance-size escalation.
4. Dedicated tainted sandbox nodes, no trusted sidecars inside a Kata sandbox VM, and no runc/TCG fallback.
5. SSM-only or equivalent controlled operator access during campaigns; no unmanaged SSH exposure.
6. Explicit budget, TTL, one-command destroy, and independent zero-resource inventory for every AWS campaign.

## Evidence

The successful campaign used the checked OpenTofu flow under `deploy/aws-feasibility/`:

- source revision: `2036bb7d0e115bba2fa4b84f875e657559243c80`;
- saved plan digest: `6e42a6df1ceff65f3b45a9805d91cdce5fbd7a5fb775789fe56c4ebe4a2466be`;
- plan shape: 16 creates, 0 changes, 0 destroys;
- compute: exactly one `c8i-flex.large`, 2 vCPU, 4096 MiB, `x86_64`, non-GPU, non-bare-metal;
- AMI: Canonical Ubuntu 24.04 gp3 `ami-052355af2a014bd2c`;
- access: SSM only, no inbound rules, IMDSv2 required;
- disk: encrypted disposable 30 GiB gp3 root volume;
- cleanup: immediate destroy of 16 resources followed by independent zero-resource inventory total `0`.

Runtime evidence:

- host kernel `6.17.0-1019-aws`;
- guest kernel `6.18.35`, distinct from host;
- guest UID 0/root workload succeeded;
- CPU `vmx`, `/dev/kvm`, QMP `query-kvm present=true`, and `enabled=true` all passed;
- Kata Containers 3.32.0 static archive verified as SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01`;
- containerd shim-v2 path used `io.containerd.kata.v2` with `--runtime-config-path` bound to the checked QEMU config and a read-only fixed rootfs;
- QEMU version was `8.2.2` from Ubuntu packages;
- package setup took 31,143 ms;
- Kata boot took 2,097 ms.

The expected cost envelope from the checked campaign remains below USD 0.25 for normal operation and below USD 0.50 under the four-hour TTL estimate, excluding unrelated existing account costs. A USD 20 EC2 budget with 25/50/100 percent alerts was part of the checked plan.

## Upstream and implementation references

- AWS nested virtualization overview: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html
- AWS CPU options API for `NestedVirtualization`: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CpuOptionsRequest.html
- Kata Containers 3.32.0 shim-v2 architecture: https://github.com/kata-containers/kata-containers/blob/3.32.0/docs/design/architecture/README.md
- Kata Containers 3.32.0 containerd runtime type: https://github.com/kata-containers/kata-containers/blob/3.32.0/docs/Developer-Guide.md
- containerd v2.2.1 `ctr run` runtime-config/rootfs/read-only handling: https://github.com/containerd/containerd/blob/v2.2.1/cmd/ctr/commands/run/run_unix.go
- containerd v2.2.1 runtime-v2 naming: https://github.com/containerd/containerd/blob/v2.2.1/core/runtime/v2/README.md
- PR #47 ignored campaign var-file binding: https://github.com/nenb/cogs/pull/47
- PR #48 valid Scheduler execution-role trust: https://github.com/nenb/cogs/pull/48
- PR #49 retained bounded runtime diagnostics: https://github.com/nenb/cogs/pull/49
- PR #50 bounded Kata stdout/stderr diagnostics: https://github.com/nenb/cogs/pull/50
- PR #51 containerd shim-v2 correction: https://github.com/nenb/cogs/pull/51

## Rejected alternatives for this decision

### Immediate bare metal

Bare metal remains a fallback if EKS virtual nested KVM fails a mandatory gate, but Stage 2 evidence does not justify paying the higher idle-cost and coarser-scaling tax before trying the supported virtual path. Bare metal would require a separate cost and safety decision.

### Plain containers, runc, or QEMU TCG

Rejected. They do not satisfy the Cogs VM-boundary objective. The Stage 2 probe and tests explicitly reject runc, direct `kata-runtime run`, and TCG fallback.

### Larger virtual instance or broader AWS topology now

Rejected for this ADR. Stage 2 did not demonstrate a need for a larger instance, EKS cluster, NAT Gateway, EFS, EIP, load balancer, or broader service. Any expansion belongs to a bounded Stage 4 campaign proposal.

## Consequences

- Stage 4 may plan an EKS/NIC campaign around the validated virtual nested-KVM candidate instead of beginning with bare metal.
- NIC/EKS work must include launch-template preservation and verification for nested virtualization.
- The Stage 2 standalone EC2 evidence becomes a prerequisite input, not a substitute, for EKS evidence.
- Cost and cleanup controls from Stage 2 become mandatory AWS campaign hygiene.
- Runtime probe failures must continue to fail closed and destroy resources before debugging.

## Mandatory Stage 4 reruns and qualifications

Acceptance of this ADR would require the following before any production or release claim:

1. Verify EKS node launch template, node AMI, kernel modules, `/dev/kvm`, active QEMU KVM, and Kata/QEMU/containerd versions in-cluster.
2. Prove the actual Kubernetes `RuntimeClass` runs a root Kata guest with a distinct kernel and no trusted sidecar in the sandbox VM.
3. Rerun Stage 1/3 egress conformance under actual EKS CNI and host controls, including root guest bypass attempts, service-account absence, metadata denial, proxy admin denial, OpenBao denial, and cross-session isolation.
4. Replace remaining Stage 1 stubs with real Cogs authorization, durable WAL, completion telemetry, OpenBao, revocation, and production proxy integration evidence.
5. Measure scheduled-to-SSH-ready, first-tool latency, workspace attach, representative Git/build/package workloads, idle overhead, and cleanup/recycle behavior.
6. Validate StorageClass behavior for active workspaces and trusted session state without relying on EFS as the default Git/build workspace unless benchmarks justify it.
7. Reconfirm budget, TTL, destroy, and zero-resource inventory for every EKS campaign.
8. Record a new Stage 4 report and revisit this ADR if the measured candidate misses cost, performance, cleanup, or security gates.

## Revisit triggers

Revisit before acceptance or after acceptance if:

- AWS documentation/API changes the supported nested-virtualization family list;
- `c8i-flex.large` becomes unavailable or materially insufficient for package install/build workloads;
- EKS or NIC cannot preserve the required launch-template CPU option;
- the selected node AMI lacks required KVM modules;
- Kata cannot boot through the supported containerd shim-v2 path in EKS;
- root guest bypass tests fail under actual CNI/host controls;
- cleanup inventory cannot reliably converge to zero;
- budget/cost behavior exceeds the planned envelope; or
- a security update invalidates the pinned Kata/QEMU/containerd/kernel assumptions.
