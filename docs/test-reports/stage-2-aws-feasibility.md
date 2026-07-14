# Stage 2 AWS nested-virtualization feasibility report

Date: 2026-07-14

Status: review package for Stage 2 decision; **not release evidence for EKS, production, general availability, or isolation beyond the measured one-instance campaign**.

## Claim boundary

This report records one successful disposable EC2 feasibility campaign for the Cogs Stage 2 runtime question. The evidence supports only this narrow claim:

> At source revision `2036bb7d0e115bba2fa4b84f875e657559243c80`, one checked `c8i-flex.large` instance in `us-east-1` booted with AWS nested virtualization enabled, exposed active KVM to the host OS, and ran a root Kata Containers 3.32.0 QEMU guest through containerd shim-v2 with a kernel distinct from the host kernel.

This report does **not** authorize EKS, production use, release readiness, multi-node operation, Kubernetes `RuntimeClass`, CNI/network default-deny, credential isolation, workload isolation beyond the measured VM/KVM facts, general regional availability, capacity claims, or any larger/more expensive AWS resource. Stage 4 must rerun the relevant checks in the actual EKS/NIC topology.

## Source, review, and CI trace

| Item | Reference |
|---|---|
| Successful campaign revision | [`2036bb7d0e115bba2fa4b84f875e657559243c80`](https://github.com/nenb/cogs/tree/2036bb7d0e115bba2fa4b84f875e657559243c80) |
| Bounded diagnostic PR | [PR #50](https://github.com/nenb/cogs/pull/50) |
| Corrected shim-v2 probe PR | [PR #51](https://github.com/nenb/cogs/pull/51) |
| PR #51 quality CI | [GitHub Actions run 29349090382](https://github.com/nenb/cogs/actions/runs/29349090382) |
| PR #51 non-AWS security-labelled jobs | [linux-kvm run 29349090537](https://github.com/nenb/cogs/actions/runs/29349090537) and [insecure-container run 29349090500](https://github.com/nenb/cogs/actions/runs/29349090500) were skipped on that PR and are not the authoritative AWS campaign evidence |
| Stage 2 implementation authority | [`deploy/aws-feasibility/`](../../deploy/aws-feasibility/) |
| Campaign safety plan | [`docs/operations/aws-feasibility-campaign.md`](../operations/aws-feasibility-campaign.md) |

The checked plan and raw runtime evidence remain in ignored local `.state/` files and are intentionally not committed because they can contain account, instance, network, command, email, and state details. This report includes only redacted, non-secret evidence fields needed for review.

## AWS and OpenTofu bounds

| Bound | Evidence |
|---|---|
| AWS profile/region | `nebula`, `us-east-1` only |
| Source revision tag | `2036bb7d0e115bba2fa4b84f875e657559243c80` |
| Saved plan digest | `6e42a6df1ceff65f3b45a9805d91cdce5fbd7a5fb775789fe56c4ebe4a2466be` |
| Plan shape | 16 creates, 0 changes, 0 destroys |
| Compute | exactly one EC2 instance, `c8i-flex.large`, 2 vCPU, 4096 MiB |
| Architecture and AMI | `x86_64`, Canonical Ubuntu 24.04 gp3 AMI `ami-052355af2a014bd2c` |
| Nested virtualization | launch template `CpuOptions.NestedVirtualization=enabled`, `core_count=1`, `threads_per_core=2` |
| Access | SSM-managed only; no SSH key and no inbound security-group rules |
| Network/cost controls | one temporary VPC/subnet/route table/internet gateway and one ephemeral public IPv4 for outbound setup; no NAT Gateway, load balancer, EIP, EFS, EKS, GPU, bare metal, endpoint, RDS, or broader service |
| Storage | encrypted disposable 30 GiB gp3 root volume, delete on termination |
| Metadata | IMDSv2 required, hop limit one |
| Budget and TTL | USD 20 EC2 budget with 25/50/100 percent alerts; independent EventBridge Scheduler terminator; guest-local shutdown fallback |
| Expected cost envelope | normal campaign expected below USD 0.25; four-hour TTL estimate below USD 0.50, excluding existing account-wide costs |

The pre-apply zero-resource inventory and final post-destroy inventory both reported every tracked campaign resource count as zero and total `0`.

## Runtime validation method

The controller sent the local checked validation script from the planned source revision through SSM. The controller does not currently record or verify a separate script digest. The disposable host did not receive repository source, developer AWS credentials, user credentials, model credentials, integration credentials, or user prompts. It had only the campaign-scoped SSM instance profile needed for Systems Manager access.

The script:

1. installed bounded distro tooling for QEMU, containerd, CPU/KVM checks, BusyBox, curl, jq, and zstd;
2. required the host CPU `vmx` flag;
3. loaded KVM modules and required readable/writable `/dev/kvm`;
4. ran `kvm-ok`;
5. launched QEMU with `-machine accel=kvm` and no TCG fallback;
6. required QMP `query-kvm` to return `present=true` and `enabled=true`;
7. downloaded the pinned Kata Containers 3.32.0 static archive and verified SHA-256 `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01`;
8. checked the Kata QEMU configuration file and `kata-runtime check`;
9. bound `containerd-shim-kata-v2` to the checked QEMU config via `ctr --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only`;
10. booted a fixed read-only BusyBox rootfs workload as UID 0; and
11. required the guest kernel to differ from the host kernel.

Upstream interfaces used by the corrected probe:

- Kata Containers 3.32.0 shim-v2 architecture: https://github.com/kata-containers/kata-containers/blob/3.32.0/docs/design/architecture/README.md
- Kata Containers 3.32.0 containerd runtime type `io.containerd.kata.v2`: https://github.com/kata-containers/kata-containers/blob/3.32.0/docs/Developer-Guide.md
- containerd v2.2.1 `ctr run` handling for `--runtime-config-path`, `--rootfs`, and `--read-only`: https://github.com/containerd/containerd/blob/v2.2.1/cmd/ctr/commands/run/run_unix.go
- containerd v2.2.1 runtime-v2 naming: https://github.com/containerd/containerd/blob/v2.2.1/core/runtime/v2/README.md

## Successful runtime evidence

| Field | Value |
|---|---|
| Result | `pass` |
| Instance type | `c8i-flex.large` |
| Architecture | `x86_64` |
| Hypervisor field | `xen` |
| Root device | `ebs` |
| Public IPv4 present | true, ephemeral only; no EIP |
| IMDSv2 | required |
| Bare metal / GPU | `false` / `false` |
| Nested virtualization | `enabled` |
| Host kernel | `6.17.0-1019-aws` |
| Guest kernel | `6.18.35` |
| Guest root | `true` |
| CPU VMX | `true` |
| `/dev/kvm` | `true` |
| QMP KVM present / enabled | `true` / `true` |
| Kata runtime | `kata-runtime 3.32.0` |
| containerd | `containerd github.com/containerd/containerd/v2 2.2.1` |
| QEMU | `QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.17)` |
| Package setup | 31,143 ms |
| Kata boot | 2,097 ms |

The machine evidence was validated by `scripts/validate-aws-feasibility-report.ts` immediately before destroy.

## Fail-closed diagnostic history and fixes

Stage 2 intentionally treated every runtime failure as a stop-and-destroy condition. No failed campaign was debugged interactively on an idle host, and no failed run was claimed as a pass.

| Incident | Evidence and handling | Fix |
|---|---|---|
| Ignored variable file was not passed to plan/destroy | Non-deploying local plan path failed before resource creation; no AWS resources were created. | [PR #47](https://github.com/nenb/cogs/pull/47) explicitly passed the ignored `0600` campaign variable file to plan and destroy and added regression assertions. |
| EventBridge Scheduler trust policy was scoped to a not-yet-created schedule ARN | First authorized apply failed closed before runtime validation; the apply trap destroyed 15 partial resources and final inventory was zero. | [PR #48](https://github.com/nenb/cogs/pull/48) changed the trust to AWS-documented schedule-group `SourceArn` semantics while retaining exact account binding and exact instance/tag-bound termination policy. |
| Runtime validation exited opaquely after package setup | First complete safely terminated runtime campaign reached SSM but returned only exit 1 after package setup; it produced no authoritative evidence, destroyed 16 resources immediately, and final inventory was zero. | [PR #49](https://github.com/nenb/cogs/pull/49) added non-sensitive stage markers and retained bounded local SSM failure diagnostics under ignored state. |
| Kata boot failure was localized but lacked actionable bounded guest output | Follow-up campaign stopped at `kata-boot`; it produced no pass evidence, destroyed 16 resources, and final inventory was zero. | [PR #50](https://github.com/nenb/cogs/pull/50) added bounded diagnostics: at most 2 KiB each from Kata stderr and workload stdout, emitted only for the `kata-boot` stage and sanitized to printable characters. |
| Direct `kata-runtime run` was unsupported in Kata 3.32.0 | One bounded follow-up campaign failed closed with `Invalid command "run"`; all 16 resources were destroyed and final inventory was zero. | [PR #51](https://github.com/nenb/cogs/pull/51) replaced direct runtime invocation with containerd shim-v2, pinned the shim to the checked QEMU config using `--runtime-config-path`, preserved read-only fixed rootfs behavior, and added regression tests. |

These failures are part of the Stage 2 evidence trail: they show fail-closed diagnostics and cleanup behavior, not successful feasibility until revision `2036bb7d0e115bba2fa4b84f875e657559243c80`.

## Cleanup and final zero-resource inventory

After the successful validation, OpenTofu destroy ran immediately. It destroyed 16 resources and then executed an independent tag/name-bound inventory. The final inventory reported total `0` across:

- EC2 instances and volumes;
- VPCs, subnets, internet gateways, route tables, security groups, and launch templates;
- Elastic IPs;
- IAM roles and instance profiles with the campaign prefix;
- EventBridge schedules; and
- campaign budgets.

The inventory command is read-only and does not delete unrelated account resources to make the count pass.

## Limitations and mandatory next-stage obligations

This Stage 2 result is sufficient to propose using virtual AWS nested KVM as the Stage 4 candidate, but only under strict rerun obligations:

1. Recreate the result through NIC/EKS, not a standalone EC2 host.
2. Verify the EKS node-group launch template preserves `CpuOptions.NestedVirtualization=enabled`.
3. Pin and verify the EKS node AMI, KVM modules, Kata, QEMU, containerd, and RuntimeClass configuration.
4. Prove a Kubernetes Kata pod has a distinct guest kernel and no trusted sidecar in the sandbox VM.
5. Rerun guest-root network bypass/default-deny tests with the actual EKS CNI and host controls.
6. Prove sandbox service-account token absence, cloud metadata denial, OpenBao isolation, proxy admin denial, and cross-session isolation.
7. Rerun egress conformance with real Cogs authorization, durable WAL, OpenBao, proxy completion, and telemetry; Stage 1 stubs remain non-release evidence.
8. Measure EKS scheduled-to-SSH-ready and representative workload performance; this report records only package setup and one Kata boot timing on a standalone host.
9. Keep all AWS campaigns manually approved, TTL-tagged, budgeted, destroyed, and followed by independent zero-resource inventory.
10. Do not silently fall back to runc, TCG, plain containers, GPU, bare metal, larger instances, NAT Gateway, EFS, EIP, load balancer, or EKS expansion without separate review.
