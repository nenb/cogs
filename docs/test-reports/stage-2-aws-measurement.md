# Stage 2 AWS accepted bounded measurement report

Status: generated from redacted machine evidence. This report is one-instance Stage 2 measurement evidence only; it is not EKS, production, release, general availability, or isolation evidence beyond the measured campaign.

## Evidence provenance

- Accepted source revision: `5847df8d307884c6543def9eb91cf17351a7ba48`
- Checked plan digest: `f0dc5a1b3b24f5b583eed9935cc717dde5d204adcccc8df58130104ded566773`
- Evidence schema: `cogs.aws-stage2-measurement-evidence/v1alpha1`
- Validation sequence: pre-cleanup machine validation passed, destroy completed, final zero inventory passed, final machine validation passed, and this human report rendered from final evidence.
- Publication boundary: this file is the redacted human report only. Raw ignored `.state` evidence, SSM command identifiers, instance/network identifiers, account identifiers, public IPs, budget email, and Terraform state are not committed.

## Scope

- Source revision: `5847df8d307884c6543def9eb91cf17351a7ba48`
- Region: `us-east-1`
- Expiry: `2026-07-15T05:06:01Z`
- Instance type: `c8i-flex.large`, architecture `x86_64`, vCPU `2`, memory MiB `4096`
- Nested virtualization: `enabled`; bare metal `false`; GPU `false`

## Campaign

- Sample count: 7
- Apply-start to instance-running: 34000 ms
- Apply-start to SSM-online: 46000 ms
- Observed/estimated campaign duration: 246000 ms
- Cleanup observed in evidence: true
- Independent final inventory total: 0
- Estimated cost: USD 0.0066
- Cost basis: observed apply-start through destroy-complete duration multiplied by c8i-flex.large Linux on-demand 0.08902 USD/hour, ephemeral IPv4 0.005 USD/hour, and a small gp3 allowance; excludes unrelated account costs; not SSH-ready timing

## Runtime identity and invariants

- Host kernel: `6.17.0-1019-aws`
- Guest kernel: `6.18.35`
- Kata: `kata-runtime   3.32.0`
- containerd: `containerd github.com/containerd/containerd/v2 2.2.1 `
- QEMU: `QEMU emulator version 8.2.2 (Debian 18.2.2ds-0ubuntu1.17)`
- Active KVM/QMP, guest root, and distinct-kernel invariants passed in machine validation.

## Measurements

- Package setup: 40095 ms
- Measurement script duration: 138958 ms
- Kata cold boot: min 1361 ms; p50 1378 ms; p95 1612 ms; max 1612 ms
- Warm CPU workload host: min 211 ms; p50 213 ms; p95 236 ms; max 236 ms
- Warm CPU workload Kata exec: min 332 ms; p50 353 ms; p95 395 ms; max 395 ms; p50 ratio 1.657
- Warm filesystem workload host: min 110 ms; p50 112 ms; p95 114 ms; max 114 ms
- Warm filesystem workload Kata exec: min 1638 ms; p50 1658 ms; p95 1799 ms; max 1799 ms; p50 ratio 14.804
- Host Git baseline only: min 312 ms; p50 313 ms; p95 314 ms; max 314 ms
- Host package-build baseline only: min 2019 ms; p50 2039 ms; p95 2200 ms; max 2200 ms
- Idle memory: QEMU RSS 260 MiB; configured guest memory 2048 MiB; density memory basis 2048 MiB
- Bounded density estimate: 1 sandbox(es); memory bound 1; CPU bound 2; basis min(memory_bound_after_1024_mib_host_reserve_using_max(qemu_rss,configured_guest_memory), cpu_bound_host_vcpus_per_configured_guest_vcpu)

## Limitations and non-claims

- single EC2 host campaign; EC2 launch p50/p95 requires multiple launches and is not measured by this harness
- SSM readiness has one sample per campaign; SSH-ready is not measured because Stage 2 access is SSM-only
- Git and package-build measurements are host baselines only; representative sandbox Git/build/package workload acceptance remains unmet by this evidence
- density estimate is a conservative bound, not a scheduler or isolation claim
- No credentials, source content, prompts, account identifiers, instance/network identifiers, public IPs, SSM command identifiers, or ignored raw state are included in this report.

