import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { validateSecurityResultSemantics } from "../../../scripts/security-result-semantics.ts";
import type { SecurityReport } from "./runner.ts";
import { renderHumanReport } from "./runner.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
const schema = require("../../../schemas/security-report-v1alpha1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validate = ajv.compile(schema) as ValidateFunction<SecurityReport>;

export function assertValidSecurityReport(report: SecurityReport): void {
  if (!validate(report))
    throw new Error(`security report schema validation failed: ${ajv.errorsText(validate.errors)}`);
  if (Date.parse(report.completed_at) < Date.parse(report.started_at)) {
    throw new Error("security report completion precedes start");
  }
  if (new Set(report.tests.map((test) => test.id)).size !== report.tests.length) {
    throw new Error("security report contains duplicate test IDs");
  }
  for (const test of report.tests) {
    const errors = validateSecurityResultSemantics(test);
    if (errors.length > 0) throw new Error(`invalid result ${test.id}: ${errors.join("; ")}`);
    if (test.release_eligible && report.authority === "functional-only") {
      throw new Error(`functional profile result ${test.id} cannot be release eligible`);
    }
    if (
      test.result === "skipped-with-approved-reason" &&
      Date.parse(test.skip_approval?.review_at ?? "") <= Date.parse(report.completed_at)
    ) {
      throw new Error(`skip approval for ${test.id} expired before report completion`);
    }
  }
}

export interface ReportPaths {
  machine: string;
  human: string;
}

export async function writeReports(outputDirectory: string, report: SecurityReport): Promise<ReportPaths> {
  assertValidSecurityReport(report);
  await mkdir(outputDirectory, { recursive: true });
  const destination = resolve(outputDirectory, report.report_id);
  const temporary = resolve(outputDirectory, `.${report.report_id}.tmp-${process.pid}-${Date.now()}`);
  const machineTemporary = resolve(temporary, "report.json");
  const humanTemporary = resolve(temporary, "report.md");
  try {
    await mkdir(temporary, { mode: 0o700 });
    await Promise.all([
      writeFile(machineTemporary, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 }),
      writeFile(humanTemporary, renderHumanReport(report), { encoding: "utf8", mode: 0o600 }),
    ]);
    await rename(temporary, destination);
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
  return { machine: resolve(destination, "report.json"), human: resolve(destination, "report.md") };
}
