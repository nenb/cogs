import { readFileSync, writeFileSync } from "node:fs";

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) {
  throw new Error("usage: render-aws-stage2-measurement-report.ts INPUT_JSON OUTPUT_MD");
}
const report = JSON.parse(readFileSync(inputPath, "utf8")) as {
  source_revision: string;
  region: string;
  expires_at: string;
  launch: Record<string, unknown>;
  campaign: {
    sample_count: number;
    observed_duration_ms: number;
    apply_to_running_ms: number;
    apply_to_ssm_online_ms: number;
    cleanup_observed: boolean;
    final_zero_inventory_total: number;
    estimated_cost_usd: number;
    cost_basis: string;
  };
  measurement: {
    host_kernel: string;
    guest_kernel: string;
    containerd_version: string;
    qemu_version: string;
    kata_runtime_version: string;
    package_setup_ms: number;
    measurement_duration_ms: number;
    kata_cold_boot: Summary;
    warm_cpu_workload: Paired;
    warm_filesystem_workload: Paired;
    host_git_baseline: Summary;
    host_package_build_baseline: Summary;
    idle_memory: { qemu_rss_mib: number; configured_guest_memory_mib: number; memory_basis_mib: number };
    density_estimate: {
      basis: string;
      host_vcpus: number;
      configured_guest_vcpus: number;
      memory_bound_sandboxes: number;
      cpu_bound_sandboxes: number;
      bounded_estimate_sandboxes: number;
    };
  };
  limitations: string[];
};

type Summary = { min_ms: number; p50_ms: number; p95_ms: number; max_ms: number; samples: number[] };
type Paired = { host: Summary; kata: Summary; kata_to_host_p50_ratio: number };
const summary = (item: Summary) =>
  `min ${item.min_ms} ms; p50 ${item.p50_ms} ms; p95 ${item.p95_ms} ms; max ${item.max_ms} ms`;
const lines = [
  "# Stage 2 AWS bounded measurement report",
  "",
  "Status: generated from redacted machine evidence. This report is one-instance Stage 2 measurement evidence only; it is not EKS, production, release, general availability, or isolation evidence beyond the measured campaign.",
  "",
  "## Scope",
  "",
  `- Source revision: \`${report.source_revision}\``,
  `- Region: \`${report.region}\``,
  `- Expiry: \`${report.expires_at}\``,
  `- Instance type: \`${report.launch.instance_type}\`, architecture \`${report.launch.architecture}\`, vCPU \`${report.launch.vcpu}\`, memory MiB \`${report.launch.memory_mib}\``,
  `- Nested virtualization: \`${report.launch.nested_virtualization}\`; bare metal \`${report.launch.bare_metal}\`; GPU \`${report.launch.gpu}\``,
  "",
  "## Campaign",
  "",
  `- Sample count: ${report.campaign.sample_count}`,
  `- Apply-start to instance-running: ${report.campaign.apply_to_running_ms} ms`,
  `- Apply-start to SSM-online: ${report.campaign.apply_to_ssm_online_ms} ms`,
  `- Observed/estimated campaign duration: ${report.campaign.observed_duration_ms} ms`,
  `- Cleanup observed in evidence: ${report.campaign.cleanup_observed}`,
  `- Independent final inventory total: ${report.campaign.final_zero_inventory_total}`,
  `- Estimated cost: USD ${report.campaign.estimated_cost_usd}`,
  `- Cost basis: ${report.campaign.cost_basis}`,
  "",
  "## Runtime identity and invariants",
  "",
  `- Host kernel: \`${report.measurement.host_kernel}\``,
  `- Guest kernel: \`${report.measurement.guest_kernel}\``,
  `- Kata: \`${report.measurement.kata_runtime_version}\``,
  `- containerd: \`${report.measurement.containerd_version}\``,
  `- QEMU: \`${report.measurement.qemu_version}\``,
  "- Active KVM/QMP, guest root, and distinct-kernel invariants passed in machine validation.",
  "",
  "## Measurements",
  "",
  `- Package setup: ${report.measurement.package_setup_ms} ms`,
  `- Measurement script duration: ${report.measurement.measurement_duration_ms} ms`,
  `- Kata cold boot: ${summary(report.measurement.kata_cold_boot)}`,
  `- Warm CPU workload host: ${summary(report.measurement.warm_cpu_workload.host)}`,
  `- Warm CPU workload Kata exec: ${summary(report.measurement.warm_cpu_workload.kata)}; p50 ratio ${report.measurement.warm_cpu_workload.kata_to_host_p50_ratio}`,
  `- Warm filesystem workload host: ${summary(report.measurement.warm_filesystem_workload.host)}`,
  `- Warm filesystem workload Kata exec: ${summary(report.measurement.warm_filesystem_workload.kata)}; p50 ratio ${report.measurement.warm_filesystem_workload.kata_to_host_p50_ratio}`,
  `- Host Git baseline only: ${summary(report.measurement.host_git_baseline)}`,
  `- Host package-build baseline only: ${summary(report.measurement.host_package_build_baseline)}`,
  `- Idle memory: QEMU RSS ${report.measurement.idle_memory.qemu_rss_mib} MiB; configured guest memory ${report.measurement.idle_memory.configured_guest_memory_mib} MiB; density memory basis ${report.measurement.idle_memory.memory_basis_mib} MiB`,
  `- Bounded density estimate: ${report.measurement.density_estimate.bounded_estimate_sandboxes} sandbox(es); memory bound ${report.measurement.density_estimate.memory_bound_sandboxes}; CPU bound ${report.measurement.density_estimate.cpu_bound_sandboxes}; basis ${report.measurement.density_estimate.basis}`,
  "",
  "## Limitations and non-claims",
  "",
  ...report.limitations.map((item) => `- ${item}`),
  "- No credentials, source, prompts, account identifiers, instance/network identifiers, public IPs, SSM command identifiers, or ignored raw state are included in this report.",
  "",
];
writeFileSync(outputPath, `${lines.join("\n")}\n`);
