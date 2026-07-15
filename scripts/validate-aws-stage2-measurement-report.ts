import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;

const provisional = process.argv[2] === "--provisional";
const path = provisional ? process.argv[3] : process.argv[2];
assert.ok(path, "usage: validate-aws-stage2-measurement-report.ts [--provisional] REPORT");
const root = resolve(import.meta.dirname, "..");
const schema = JSON.parse(readFileSync(resolve(root, "schemas/aws-stage2-measurement-evidence-v1alpha1.json"), "utf8"));
const reportText = readFileSync(resolve(path), "utf8");
assert.ok(reportText.length <= 96 * 1024, "AWS Stage 2 measurement report exceeds its bound");
const report = JSON.parse(reportText) as {
  result?: string;
  source_revision?: string;
  launch?: {
    bare_metal?: boolean;
    gpu?: boolean;
    nested_virtualization?: string;
    instance_type?: string;
    vcpu?: number;
    memory_mib?: number;
  };
  measurement?: {
    result?: string;
    host_kernel?: string;
    guest_kernel?: string;
    kata_cold_boot?: Summary;
    warm_cpu_workload?: Paired;
    warm_filesystem_workload?: Paired;
    host_git_baseline?: Summary;
    host_package_build_baseline?: Summary;
    idle_memory?: { qemu_rss_mib?: number; configured_guest_memory_mib?: number; memory_basis_mib?: number };
    density_estimate?: {
      host_vcpus?: number;
      configured_guest_vcpus?: number;
      memory_bound_sandboxes?: number;
      cpu_bound_sandboxes?: number;
      bounded_estimate_sandboxes?: number;
    };
  };
  campaign?: {
    sample_count?: number;
    observed_duration_ms?: number;
    apply_to_running_ms?: number;
    apply_to_ssm_online_ms?: number;
    cleanup_observed?: boolean;
    final_zero_inventory_total?: number;
    estimated_cost_usd?: number;
  };
  limitations?: string[];
};

type Summary = { samples?: number[]; min_ms?: number; p50_ms?: number; p95_ms?: number; max_ms?: number };
type Paired = { host?: Summary; kata?: Summary; kata_to_host_p50_ratio?: number };

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
if (!validate(report)) {
  const details = (validate.errors ?? [])
    .map((error) => {
      const location = error.instancePath || "/";
      const extra =
        error.keyword === "additionalProperties" && typeof error.params.additionalProperty === "string"
          ? ` (${error.params.additionalProperty})`
          : "";
      return `${location}: ${error.message ?? error.keyword}${extra}`;
    })
    .join("\n");
  assert.fail(details || ajv.errorsText(validate.errors, { separator: "\n" }));
}
assert.equal(report.result, "pass");
assert.equal(report.measurement?.result, "pass");
assert.notEqual(report.measurement?.host_kernel, report.measurement?.guest_kernel);
assert.deepEqual(
  {
    bare_metal: report.launch?.bare_metal,
    gpu: report.launch?.gpu,
    instance_type: report.launch?.instance_type,
    nested_virtualization: report.launch?.nested_virtualization,
  },
  { bare_metal: false, gpu: false, instance_type: "c8i-flex.large", nested_virtualization: "enabled" },
);
if (!provisional) {
  assert.equal(report.campaign?.cleanup_observed, true, "publishable evidence must include observed cleanup");
  assert.equal(
    report.campaign?.final_zero_inventory_total,
    0,
    "publishable evidence must include independent zero inventory",
  );
}
assert.ok(
  (report.campaign?.estimated_cost_usd ?? 99) < 0.5,
  "estimated cost must stay inside the approved four-hour envelope",
);
assert.ok((report.campaign?.apply_to_running_ms ?? 0) <= (report.campaign?.apply_to_ssm_online_ms ?? 0));
assert.ok((report.campaign?.apply_to_ssm_online_ms ?? 0) <= (report.campaign?.observed_duration_ms ?? 0));

function percentile(samples: number[], p: number) {
  const sorted = [...samples].sort((a, b) => a - b);
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
}
function checkSummary(name: string, value: Summary | undefined, sampleCount: number) {
  assert.ok(value, `${name} missing`);
  const samples = value.samples ?? [];
  assert.equal(samples.length, sampleCount, `${name} sample count mismatch`);
  assert.ok(
    samples.every((sample) => Number.isInteger(sample) && sample >= 25),
    `${name} contains zero/too-short samples`,
  );
  assert.equal(value.min_ms, Math.min(...samples), `${name} min mismatch`);
  assert.equal(value.p50_ms, percentile(samples, 50), `${name} p50 mismatch`);
  assert.equal(value.p95_ms, percentile(samples, 95), `${name} p95 mismatch`);
  assert.equal(value.max_ms, Math.max(...samples), `${name} max mismatch`);
}
function checkPaired(name: string, value: Paired | undefined, sampleCount: number) {
  assert.ok(value, `${name} missing`);
  checkSummary(`${name}.host`, value.host, sampleCount);
  checkSummary(`${name}.kata`, value.kata, sampleCount);
  const expected = Number(((value.kata?.p50_ms ?? 0) / (value.host?.p50_ms ?? 1)).toFixed(3));
  assert.equal(value.kata_to_host_p50_ratio, expected, `${name} ratio mismatch`);
}
const sampleCount = report.campaign?.sample_count ?? 0;
assert.ok(sampleCount >= 7 && sampleCount <= 9, "sample count must stay in the approved 7-9 bound");
checkSummary("kata_cold_boot", report.measurement?.kata_cold_boot, sampleCount);
checkPaired("warm_cpu_workload", report.measurement?.warm_cpu_workload, sampleCount);
checkPaired("warm_filesystem_workload", report.measurement?.warm_filesystem_workload, sampleCount);
checkSummary("host_git_baseline", report.measurement?.host_git_baseline, sampleCount);
checkSummary("host_package_build_baseline", report.measurement?.host_package_build_baseline, sampleCount);

const memoryBasis = Math.max(
  report.measurement?.idle_memory?.qemu_rss_mib ?? 0,
  report.measurement?.idle_memory?.configured_guest_memory_mib ?? 0,
);
assert.equal(report.measurement?.idle_memory?.memory_basis_mib, memoryBasis, "memory basis mismatch");
const memoryBound = Math.max(1, Math.floor(((report.launch?.memory_mib ?? 0) - 1024) / memoryBasis));
const cpuBound = Math.max(
  1,
  Math.floor(
    (report.measurement?.density_estimate?.host_vcpus ?? 0) /
      (report.measurement?.density_estimate?.configured_guest_vcpus ?? 1),
  ),
);
assert.equal(
  report.measurement?.density_estimate?.memory_bound_sandboxes,
  memoryBound,
  "memory density bound mismatch",
);
assert.equal(report.measurement?.density_estimate?.cpu_bound_sandboxes, cpuBound, "CPU density bound mismatch");
assert.equal(
  report.measurement?.density_estimate?.bounded_estimate_sandboxes,
  Math.max(1, Math.min(memoryBound, cpuBound)),
  "bounded density mismatch",
);

assert.ok(report.limitations?.some((item) => item.includes("SSM") && item.includes("SSH-ready")));
assert.ok(report.limitations?.some((item) => item.includes("representative sandbox") && item.includes("unmet")));
assert.doesNotMatch(
  reportText,
  /AKIA|ASIA|secret|credential|authorization|account[_-]?id|public[_-]?ip|command[_-]?id|prompt|\b\d{12}\b|\bi-[0-9a-f]{8,}\b|\bvpc-[0-9a-f]{8,}\b|\bsubnet-[0-9a-f]{8,}\b|\bsg-[0-9a-f]{8,}\b|\blt-[0-9a-f]{8,}\b|\b[0-9a-f-]{36}\b|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\b(?:\d{1,3}\.){3}\d{1,3}\b/i,
);
console.log("Validated bounded AWS Stage 2 measurement evidence.");
