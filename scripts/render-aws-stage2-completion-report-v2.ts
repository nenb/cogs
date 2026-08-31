import assert from "node:assert/strict";
import { closeSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import {
  evidenceFromValidated,
  parseAwsStage2CompletionEvidence,
  type ValidatedCompletionEvidence,
} from "./validate-aws-stage2-completion-evidence-v2.ts";

/** Deterministic human projection; only a validator-issued token is accepted. */
export function renderAwsStage2CompletionReport(validated: ValidatedCompletionEvidence): string {
  const value = evidenceFromValidated(validated);
  const lines = [
    "# AWS Stage 2 completion report",
    "",
    "Status: pass-only rendering of validated, redacted completion evidence.",
    "",
    "## Batch",
    "",
    `- Implementation revision: \`${value.batch.implementation_revision}\``,
    `- Batch commitment: \`${value.batch.commitment}\``,
    "- Cycles: 7 (one full, six readiness)",
    "",
    "## Measurements",
    "",
    "| Cycle | Mode | Apply to running | Kata launch to SSH ready | Cost |",
    "| ---: | --- | ---: | ---: | ---: |",
    ...value.cycles.map(
      (cycle) =>
        `| ${cycle.ordinal} | ${cycle.mode} | ${cycle.remote.apply_to_running_ns} ns | ${cycle.remote.kata_launch_to_ssh_ready_ns} ns | ${cycle.cost.cost_micro_usd} micro-USD |`,
    ),
    "",
    "- Full-cycle workload measurements: 21",
    `- Actual first-apply through final-zero duration: ${value.deadlines.actual_campaign_duration_ns} ns`,
    "",
    "## Cleanup and cost",
    "",
    "- State-bound destroy attempts: 7",
    "- Detailed inventory observations: 8",
    `- Final zero commitment: \`${value.cleanup.final_zero_commitment}\``,
    `- Aggregate cost: ${value.cost.aggregate_cost_micro_usd} micro-USD`,
    "",
    "## Limitations",
    "",
    ...value.limitations.map((item) => `- ${item}`),
  ];
  return `${lines.join("\n")}\n`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [inputPath, outputPath] = process.argv.slice(2);
  assert.ok(
    inputPath && outputPath && process.argv.length === 4,
    "usage: render-aws-stage2-completion-report-v2.ts INPUT_JSON OUTPUT_MD",
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
