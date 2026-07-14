# Disposable AWS nested-virtualization fixture

This directory implements Stage 2's one-instance feasibility campaign. It is not EKS or production infrastructure.

Safety authority: [`docs/operations/aws-feasibility-campaign.md`](../../docs/operations/aws-feasibility-campaign.md).

## Fixed bounds

- designated `nebula` profile and hashed account binding;
- `us-east-1`, `c8i-flex.large`, x86_64, CPU-only;
- exactly one EC2 instance;
- `CpuOptions.NestedVirtualization=enabled` in the launch template;
- SSM only, no inbound rules or SSH key;
- one ephemeral public IPv4; no NAT Gateway, endpoint, Elastic IP, load balancer, EFS, EKS, GPU, or bare metal;
- encrypted disposable 30 GiB gp3 root;
- USD 20 EC2 budget with 25/50/100 percent alerts;
- explicit expiry under five hours, AWS Scheduler termination, and guest-local termination fallback;
- local ignored state outside the instance.

## Non-deploying validation

```bash
./deploy/aws-feasibility/validate.sh
```

The installer downloads OpenTofu 1.12.4 only over HTTPS and verifies a hard-coded platform SHA-256. The AWS provider is locked to 6.54.0.

## Saved plan

Supply the alert email only through the environment. It is written with mode 0600 under ignored `.state/` and marked sensitive in OpenTofu.

```bash
export AWS_PROFILE=nebula
export COGS_AWS_BUDGET_EMAIL='owner@example.com'
./deploy/aws-feasibility/plan.sh
```

Review `.state/campaign.plan.txt`. `check-plan.py` independently rejects anything except the exact create-only resource allowlist and checks CPU, nested virtualization, disk, network, metadata, budget, and termination bounds. Planning creates no resources.

## Manual apply gate

Only after owner review of the saved plan:

```bash
export AWS_PROFILE=nebula
export COGS_AWS_APPLY_APPROVED=apply-one-cpu-instance
./deploy/aws-feasibility/apply.sh
unset COGS_AWS_APPLY_APPROVED
```

Apply failure or SSM-readiness timeout triggers immediate best-effort destroy. Success is not permission to leave the host idle; proceed directly to runtime validation.

## Bounded runtime validation

```bash
export AWS_PROFILE=nebula
./deploy/aws-feasibility/run-runtime-validation.sh
```

The controller sends the local checked validation script from the planned source revision through SSM, with no repository checkout or developer, user, model, or integration credentials on the host. The host has only the campaign-scoped SSM instance profile. It installs distro QEMU/containerd tooling, proves VMX and `/dev/kvm`, starts QEMU with `accel=kvm`, requires QMP `query-kvm` to return `present=true` and `enabled=true`, verifies the SHA-256 of Kata 3.32.0's static x86_64 archive, and boots a fixed read-only BusyBox root workload as root through Kata's supported containerd shim-v2 runtime (`containerd-shim-kata-v2`, selected with `ctr --runtime io.containerd.kata.v2 --runtime-config-path "$config"`). The bound config is the checked Kata QEMU configuration file, so the Kata boot claim is specifically a QEMU/KVM sandbox claim. The probe then proves the guest kernel differs from the host. There is no TCG, runc, direct `kata-runtime run`, or normal-container fallback. The command is bounded to 45 minutes and writes redacted local evidence under ignored `.state/`.

Any failure is a stop-and-destroy condition, not permission to debug on an idle instance.

## Bounded Stage 2 measurements

Issue #42 is intentionally still a one-instance Stage 2 measurement, not EKS or Stage 4 scope. The fail-closed campaign entry point is:

```bash
export AWS_PROFILE=nebula
export COGS_AWS_MEASUREMENT_CAMPAIGN_APPROVED=run-one-stage2-measurement-campaign
./deploy/aws-feasibility/run-measurement-campaign.sh
```

The orchestrator plans, applies one approved host, runs measurement validation, destroys on success/failure/interrupt/report-validation failure, writes an independent final zero-inventory artifact, and only then renders publishable evidence. The lower-level `run-measurement-validation.sh` is for an already-applied campaign only; it refuses to send SSM unless the tree is clean and the checked-out HEAD exactly matches the planned source revision.

The measurement controller sends a local checked script from the planned source revision over SSM and writes redacted machine and human reports under ignored `.state/`: `stage2-measurement-evidence.json` and `stage2-measurement-report.md`. It preserves the same active-KVM, pinned Kata, root guest, distinct-kernel, QEMU config binding, SSM-only access, timeout, and fail-closed cleanup expectations as runtime validation.

The harness records seven samples by default for Kata cold boot, warm CPU workload, warm filesystem workload, a synthetic host Git baseline, and a synthetic host package-build baseline. Warm in-guest workload samples use a persistent Kata task plus `ctr tasks exec`, so they exclude cold boot. The guest rootfs contains BusyBox only and the guest filesystem workload invokes explicit `/bin/busybox` applets. The report also records one apply-to-running and apply-to-SSM-online observation, deterministic idle QEMU RSS, configured guest memory/vCPU allocation, a conservative bounded density estimate, campaign duration through destroy completion, cleanup/zero-inventory status, and a cost estimate capped below the documented four-hour USD 0.50 envelope. It does not claim repeated EC2 launch p50/p95, SSH-ready timing, EKS timing, or representative sandbox Git/build/package workload acceptance. Those remain Stage 4/EKS or separately approved measurements, and issue #42 must stay open unless all acceptance criteria are actually met.

Any measurement failure is a stop-and-destroy condition, not permission to debug on an idle instance.

## Destroy and inventory

```bash
export AWS_PROFILE=nebula
./deploy/aws-feasibility/destroy.sh
```

Destroy retries a tag/name-bound inventory until it proves zero campaign instances, volumes, VPCs, subnets, gateways, route tables, security groups, launch templates, Elastic IPs, IAM roles/profiles, schedules, and budgets. Never delete untagged or unrelated account resources to make inventory pass.
