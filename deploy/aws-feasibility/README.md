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

Apply failure or SSM-readiness timeout triggers immediate best-effort destroy. Success is not permission to leave the host idle; proceed directly to the bounded validation script implemented by #41.

## Destroy and inventory

```bash
export AWS_PROFILE=nebula
./deploy/aws-feasibility/destroy.sh
```

Destroy retries a tag/name-bound inventory until it proves zero campaign instances, volumes, VPCs, subnets, gateways, route tables, security groups, launch templates, Elastic IPs, IAM roles/profiles, schedules, and budgets. Never delete untagged or unrelated account resources to make inventory pass.
