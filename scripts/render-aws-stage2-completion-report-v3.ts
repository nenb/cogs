import fs from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  type CompletionEvidenceCliOutput,
  CompletionEvidenceValidationError,
  completionEvidenceCliDiagnostic,
  completionEvidenceCliOutput,
  evidenceFromValidated,
  parseAwsStage2CompletionEvidence,
  readCompletionEvidenceFile,
  type ValidatedCompletionEvidence,
} from "./validate-aws-stage2-completion-evidence-v3.ts";

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

/** Shares the validator's fixed diagnostics, including input and output I/O failures. */
export function runAwsStage2CompletionReportCli(
  args: readonly string[],
  output: CompletionEvidenceCliOutput = completionEvidenceCliOutput,
): 0 | 2 {
  try {
    const [inputPath, outputPath] = args;
    if (!inputPath || !outputPath || args.length !== 2)
      throw new CompletionEvidenceValidationError("invalid arguments", "usage");
    const validated = parseAwsStage2CompletionEvidence(readCompletionEvidenceFile(inputPath));
    const rendered = Buffer.from(renderAwsStage2CompletionReport(validated), "utf8");
    try {
      const requested = resolve(outputPath);
      const requestedParent = dirname(requested);
      const parentPath = fs.realpathSync(requestedParent);
      if (requestedParent !== parentPath) throw new Error("output ancestry is not canonical");
      const currentUid = process.getuid?.();
      if (currentUid === undefined) throw new Error("output owner unavailable");
      let ancestor = "/";
      for (const component of parentPath.split("/").filter(Boolean)) {
        ancestor = join(ancestor, component);
        const identity = fs.lstatSync(ancestor);
        const mode = identity.mode & 0o7777;
        const stickyRoot = identity.uid === 0 && (mode & 0o1000) !== 0;
        if (
          !identity.isDirectory() ||
          (identity.uid !== 0 && identity.uid !== currentUid) ||
          ((mode & 0o022) !== 0 && !stickyRoot)
        )
          throw new Error("output ancestry is not trusted");
      }
      const destination = join(parentPath, basename(requested));
      const parent = fs.openSync(parentPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
      try {
        const parentIdentity = fs.fstatSync(parent);
        const same = (left: fs.Stats, right: fs.Stats) =>
          left.dev === right.dev &&
          left.ino === right.ino &&
          left.mode === right.mode &&
          left.uid === right.uid &&
          left.gid === right.gid;
        const trustedMode = parentIdentity.mode & 0o777;
        if (
          !parentIdentity.isDirectory() ||
          !same(parentIdentity, fs.lstatSync(parentPath)) ||
          parentIdentity.uid !== process.getuid?.() ||
          (trustedMode & 0o077) !== 0
        )
          throw new Error("output directory is not private custody");
        const descriptor = fs.openSync(destination, "wx+", 0o400);
        try {
          const fileIdentity = fs.fstatSync(descriptor);
          if (!fileIdentity.isFile() || fileIdentity.nlink !== 1) throw new Error("output identity invalid");
          if (fs.writeSync(descriptor, rendered) !== rendered.length) throw new Error("short write");
          fs.fsyncSync(descriptor);
          if (
            !same(parentIdentity, fs.fstatSync(parent)) ||
            !same(parentIdentity, fs.lstatSync(parentPath)) ||
            fs.realpathSync(requestedParent) !== parentPath
          )
            throw new Error("output directory changed");
          fs.fsyncSync(parent);
          const fileAfter = fs.fstatSync(descriptor);
          const pathAfter = fs.lstatSync(destination);
          const readback = Buffer.alloc(rendered.length);
          const read = fs.readSync(descriptor, readback, 0, readback.length, 0);
          if (
            read !== rendered.length ||
            !readback.equals(rendered) ||
            fileAfter.size !== rendered.length ||
            fileAfter.nlink !== 1 ||
            pathAfter.nlink !== 1 ||
            !same(fileIdentity, fileAfter) ||
            !same(fileIdentity, pathAfter) ||
            !same(parentIdentity, fs.fstatSync(parent)) ||
            !same(parentIdentity, fs.lstatSync(parentPath)) ||
            fs.realpathSync(requestedParent) !== parentPath
          )
            throw new Error("durable output changed");
        } finally {
          fs.closeSync(descriptor);
        }
      } finally {
        fs.closeSync(parent);
      }
    } catch {
      throw new CompletionEvidenceValidationError("completion report file unavailable", "file");
    }
    return 0;
  } catch (error) {
    try {
      output.stderr(completionEvidenceCliDiagnostic(error));
    } catch {}
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = runAwsStage2CompletionReportCli(process.argv.slice(2));
}
