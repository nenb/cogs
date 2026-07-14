import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
const path = process.argv[2];
assert.ok(path, "usage: validate-aws-feasibility-report.ts REPORT");
const root = resolve(import.meta.dirname, "..");
const schema = JSON.parse(readFileSync(resolve(root, "schemas/aws-feasibility-report-v1alpha1.json"), "utf8"));
const reportText = readFileSync(resolve(path), "utf8");
assert.ok(reportText.length <= 64 * 1024, "AWS feasibility report exceeds its bound");
const report = JSON.parse(reportText) as {
  result?: string;
  launch?: { bare_metal?: boolean; gpu?: boolean; nested_virtualization?: string };
  runtime?: { host_kernel?: string; guest_kernel?: string; result?: string };
};
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
assert.equal(validate(report), true, ajv.errorsText(validate.errors, { separator: "\n" }));
assert.equal(report.result, "pass");
assert.equal(report.runtime?.result, "pass");
assert.notEqual(report.runtime?.host_kernel, report.runtime?.guest_kernel);
assert.deepEqual(
  {
    bare_metal: report.launch?.bare_metal,
    gpu: report.launch?.gpu,
    nested_virtualization: report.launch?.nested_virtualization,
  },
  { bare_metal: false, gpu: false, nested_virtualization: "enabled" },
);
assert.doesNotMatch(reportText, /AKIA|ASIA|secret|credential|authorization|account[_-]?id/i);
console.log("Validated bounded AWS nested-KVM and Kata feasibility evidence.");
