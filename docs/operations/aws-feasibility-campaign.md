# Stage 2 AWS feasibility campaign

Status: planned; no billable Stage 2 resources have been created

Date: 2026-07-14
Owner: Nick Byrne (`@nenb`)
Purpose: one-host nested-KVM and Kata feasibility only; no EKS

## Authorization and identity

The locally designated AWS CLI profile is `nebula`, with configured region `us-east-1`. Credentials remain solely in the operator's standard AWS credential store and must never be copied into repository files, OpenTofu state, EC2 user data, reports, or the disposable host.

The verified caller is an IAM user in the designated account. To avoid publishing the account number, the report binds it by SHA-256:

`65eb8fbcacd1a51be6de86ac302df96a98a41c6190a4a161bf720592bf6a2bb7`

Read-only discovery found no pending, running, stopping, or stopped EC2 instances in any enabled region. The account has no default VPC. Existing account budgets are much larger than this campaign and are not acceptable campaign controls.

## Current AWS support evidence

Authoritative AWS documentation:

- nested virtualization overview and current family list: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html
- `CpuOptionsRequest.NestedVirtualization`: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CpuOptionsRequest.html
- regional instance availability: https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-instance-regions.html

The overview currently lists C8i/M8i/R8i and flex variants plus several 7th-generation Intel families. The API reference is stricter and says `NestedVirtualization=enabled` is supported only on 8th-generation Intel C8i, M8i, R8i, and flex variants. The campaign follows the stricter API reference.

Nested virtualization itself has no additional AWS feature charge. KVM and Hyper-V are the currently documented L1 hypervisors; this campaign uses KVM only. Runtime validation must enter Kata through an upstream-supported Kata Containers 3.32.0 interface. The local probe uses containerd's runtime-v2 path (`ctr --runtime io.containerd.kata.v2 --runtime-config-path "$config"` resolving to `containerd-shim-kata-v2`) rather than the unsupported direct `kata-runtime run` form, and binds that shim invocation to the checked Kata QEMU configuration file.

## Candidate and availability

Initial candidate: `c8i-flex.large` in `us-east-1`.

Read-only EC2 evidence:

- non-bare-metal Nitro instance;
- x86_64;
- 2 vCPUs, 4 GiB memory;
- no `GpuInfo` and no GPU use permitted;
- offered in `us-east-1a`, `us-east-1b`, `us-east-1c`, `us-east-1d`, and `us-east-1f` at discovery time;
- current Linux shared-tenancy on-demand price: USD 0.08902/hour;
- account on-demand Standard-family quota: 384 vCPUs, while the plan permits only 2 vCPUs and one instance.

A current Canonical public SSM parameter resolved Ubuntu Server 24.04 amd64 gp3 to `ami-052355af2a014bd2c` (parameter version 74). EC2 reported it as available, HVM, x86_64, EBS-backed, and owned by Canonical account `099720109477`. The OpenTofu plan must resolve and bind the current parameter rather than permanently trusting this discovery-time AMI ID, and must print the selected AMI in the saved plan.

`c8i-flex.xlarge` (4 vCPUs, 8 GiB, USD 0.17804/hour at discovery) is only a documented fallback if the smallest candidate cannot install or boot one Kata sandbox due to memory. Changing instance type requires a new saved plan. Any larger type, bare metal, GPU type, second instance, or different region requires explicit approval.

## Cost envelope

Expected normal campaign duration: at most 90 minutes.
Independent TTL: four hours from apply.
Expected normal infrastructure cost: less than USD 0.25.
Worst-case planned four-hour infrastructure estimate: less than USD 0.50, comprising approximately:

- instance: USD 0.35608;
- ephemeral public IPv4: approximately USD 0.02;
- 30 GiB gp3 root volume: approximately USD 0.013;
- negligible SSM, scheduler/Lambda, log, and API usage at this scale.

Campaign budget ceiling: USD 20. Budget alerts should be configured at USD 5, USD 10, and USD 20 before compute apply. AWS Budgets alerts are not a hard kill switch; the independent four-hour terminator is mandatory. A notification email is required at apply time and is not stored until explicitly supplied by the owner.

Stop and request approval before any change whose plausible incremental cost exceeds USD 5, or before creating any resource omitted from this document.

## Hard resource constraints

The OpenTofu fixture must enforce:

- exactly zero or one EC2 instance; never more than one;
- allowlisted CPU-only `c8i-flex.large`, with `c8i-flex.xlarge` requiring an explicit changed plan;
- launch-template `CpuOptions.NestedVirtualization=enabled` visible in plan and post-launch evidence;
- no GPU, bare-metal, Spot Fleet, Auto Scaling group, EKS, ECS, load balancer, NAT Gateway, VPC endpoint, EFS, RDS, Elastic IP, or dedicated host;
- one temporary VPC, one public subnet, one route table, and one internet gateway because the account has no default VPC;
- no inbound security-group rules;
- SSM Session Manager only; no SSH key pair;
- one ephemeral public IPv4 solely for outbound SSM/package access, avoiding NAT Gateway and paid VPC endpoints;
- one encrypted 30 GiB gp3 root volume with delete-on-termination;
- instance metadata service v2 required and hop limit one;
- no developer AWS credentials, repository source, integration credentials, model credentials, prompts, or user data secrets on the instance; the instance has only the campaign-scoped SSM instance profile;
- one least-privilege instance role for SSM;
- local/trusted OpenTofu state outside the disposable instance and excluded from Git;
- bounded creation and command waits.

All resources must carry:

- `cogs:owner=nenb`
- `cogs:purpose=stage-2-nested-virtualization`
- `cogs:source-revision=<exact revision>`
- `cogs:expires-at=<RFC3339 UTC>`
- `cogs:managed-by=opentofu`

## Independent cleanup

Normal cleanup is a bounded one-command OpenTofu destroy followed by zero-resource inventory.

An independent EventBridge Scheduler invocation must call a narrowly scoped Lambda terminator at the four-hour expiry. It may terminate only an EC2 instance carrying the exact campaign purpose/source/expiry tags. OpenTofu destroy then removes the terminated instance record and all campaign IAM, network, schedule, and Lambda resources.

If setup fails before the independent terminator exists, apply must fail closed and immediately destroy any partial resources. The instance must not remain running while tests or package installation are debugged interactively.

## Manual gates

Read-only AWS discovery is approved. Repository implementation and local validation create no billable resources.

Before apply:

1. install/use a pinned current OpenTofu and AWS provider version;
2. provide a budget notification email out of band;
3. produce and inspect a saved plan;
4. verify the plan has exactly one CPU-only instance and only the allowed supporting resources;
5. verify the current estimated maximum remains below USD 1;
6. record explicit manual apply approval in the Stage 2 issue.

Bare metal is not part of this campaign. If supported virtual nested KVM fails, destroy first and open a separate cost/ADR decision rather than silently escalating.
