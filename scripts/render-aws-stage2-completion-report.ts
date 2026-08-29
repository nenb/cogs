import assert from "node:assert/strict";
import { closeSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import {
  evidenceFromValidated,
  parseAwsStage2CompletionEvidence,
  type Summary,
  type ValidatedCompletionEvidence,
} from "./validate-aws-stage2-completion-evidence.ts";

function formatSummary(value: Summary): string {
  return `min ${value.min_ns} ns; p50 ${value.p50_ns} ns; p95 ${value.p95_ns} ns; max ${value.max_ns} ns`;
}

export function renderAwsStage2CompletionReport(validated: ValidatedCompletionEvidence): string {
  const evidence = evidenceFromValidated(validated);
  const lines = [
    "# AWS Stage 2 completion report",
    "",
    "Status: pass-only rendering of validated, redacted completion evidence.",
    "",
    "## Batch and fixed bindings",
    "",
    `- Source revision: \`${evidence.batch.source_revision}\``,
    `- Batch commitment: \`${evidence.batch.commitment}\``,
    `- Common expiry: \`${evidence.batch.expiry_at}\``,
    `- Normal effect deadline: ${evidence.deadlines.normal_effect_deadline_seconds} seconds`,
    `- Deadline binding: \`${evidence.deadlines.binding_commitment}\``,
    "",
    "## Seven fresh sequential cycles",
    "",
    "| Cycle | Mode | Apply to running | Kata launch to authenticated SSH-ready | Duration | Cost |",
    "| ---: | --- | ---: | ---: | ---: | ---: |",
    ...evidence.cycles.map(
      (cycle) =>
        `| ${cycle.ordinal} | ${cycle.mode} | ${cycle.apply_to_running_ns} ns | ${cycle.kata_launch_to_ssh_ready_ns} ns | ${cycle.duration_ns} ns | ${cycle.cost.total_micro_usd} micro-USD |`,
    ),
    "",
    `- Apply-to-running summary: ${formatSummary(evidence.launch_summary)}`,
    `- Kata-launch-to-SSH-ready summary: ${formatSummary(evidence.ssh_ready_summary)}`,
    "",
    "## Full-cycle synthetic workload",
    "",
    `- Git (7 samples): ${formatSummary(evidence.workload_summary.git)}`,
    `- Package build (7 samples): ${formatSummary(evidence.workload_summary.build)}`,
    `- Package install (7 samples): ${formatSummary(evidence.workload_summary.install)}`,
    "- Workload samples exist only in cycle 1; every sample records immediate deletion.",
    "",
    "## Cleanup and bounded cost",
    "",
    `- State-bound destroy attempts: ${evidence.cleanup.destroy_attempts}`,
    `- Distinct independently observed zero receipts: ${evidence.cleanup.zero_receipt_count}`,
    `- Local teardown phases per cycle: ${evidence.cleanup.teardown_phase_count}`,
    `- Aggregate effect duration: ${evidence.cost.aggregate_duration_ns} ns`,
    `- Aggregate cost: ${evidence.cost.aggregate_cost_micro_usd} micro-USD`,
    `- Expected upper bound: ${evidence.cost.expected_upper_bound_micro_usd} micro-USD (strictly below 250000)`,
    "",
    "## Limitations and non-claims",
    "",
    ...evidence.limitations.map((limitation) => `- ${limitation}`),
    "",
  ];
  return `${lines.join("\n")}\n`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [inputPath, outputPath] = process.argv.slice(2);
  assert.ok(
    inputPath && outputPath && process.argv.length === 4,
    "usage: render-aws-stage2-completion-report.ts INPUT_JSON OUTPUT_MD",
  );
  const validated = parseAwsStage2CompletionEvidence(readFileSync(resolve(inputPath), "utf8"));
  const rendered = Buffer.from(renderAwsStage2CompletionReport(validated), "utf8");
  const descriptor = openSync(resolve(outputPath), "wx", 0o400);
  try {
    assert.equal(writeSync(descriptor, rendered), rendered.length, "short completion report write");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}
