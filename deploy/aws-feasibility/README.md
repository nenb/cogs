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

The controller sends one digest-pinned validation script through SSM, with no repository checkout or credentials on the host. It installs distro QEMU/containerd tooling, proves VMX and `/dev/kvm`, starts QEMU with `accel=kvm`, requires QMP `query-kvm` to return `present=true` and `enabled=true`, verifies the SHA-256 of Kata 3.32.0's static x86_64 archive, and boots a fixed read-only BusyBox root workload as root through Kata's supported containerd shim-v2 runtime (`containerd-shim-kata-v2`, selected with `ctr --runtime io.containerd.kata.v2 --runtime-config-path "$config"`). The bound config is the checked Kata QEMU configuration file, so the Kata boot claim is specifically a QEMU/KVM sandbox claim. The probe then proves the guest kernel differs from the host. There is no TCG, runc, direct `kata-runtime run`, or normal-container fallback. The command is bounded to 45 minutes and writes redacted local evidence under ignored `.state/`.

Any failure is a stop-and-destroy condition, not permission to debug on an idle instance.

## Destroy and inventory

```bash
export AWS_PROFILE=nebula
./deploy/aws-feasibility/destroy.sh
```

Destroy retries a tag/name-bound inventory until it proves zero campaign instances, volumes, VPCs, subnets, gateways, route tables, security groups, launch templates, Elastic IPs, IAM roles/profiles, schedules, and budgets. Never delete untagged or unrelated account resources to make inventory pass.
