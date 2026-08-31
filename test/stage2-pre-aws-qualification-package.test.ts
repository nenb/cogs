/* biome-ignore-all lint/suspicious/noExplicitAny: exact frozen JSON evidence is checked structurally below */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();
const evidenceRoot = join(root, "docs/security-evidence/stage2-local-kata-qualification-33392217934");
const packagePath = join(evidenceRoot, "pre-aws-package.json");
const reportPath = join(evidenceRoot, "report.json");
const receiptPath = join(evidenceRoot, "upload-receipt.json");
const sha256 = (raw: Buffer): string => createHash("sha256").update(raw).digest("hex");
const parse = (path: string): Record<string, any> => JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;
const stable = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(stable);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, stable(child)]),
    );
  }
  return value;
};
const canonical = (value: unknown): Buffer => Buffer.from(`${JSON.stringify(stable(value))}\n`, "ascii");

function ajv(): AjvCore {
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  const addFormats = require("ajv-formats") as (value: AjvCore) => AjvCore;
  return addFormats(new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true }));
}

test("frozen pre-AWS package and canonical members are exact and schema-valid", () => {
  const packageRaw = readFileSync(packagePath);
  const reportRaw = readFileSync(reportPath);
  const receiptRaw = readFileSync(receiptPath);
  const value = parse(packagePath);
  const report = parse(reportPath);
  const receipt = parse(receiptPath);
  assert.deepEqual(packageRaw, canonical(value));
  assert.deepEqual(reportRaw, canonical(report));
  assert.deepEqual(receiptRaw, canonical(receipt));
  assert.equal(sha256(packageRaw), "78f19b4fc4ac9d64d4f3a9a35d68850fd44122c61e00907eefcb19d6f86c0899");
  const validator = ajv();
  const packageSchema = JSON.parse(
    readFileSync(join(root, "schemas/stage2-pre-aws-qualification-package-v1.json"), "utf8"),
  ) as object;
  const reportSchema = JSON.parse(
    readFileSync(join(root, "schemas/stage2-workload-local-qualification-v3.json"), "utf8"),
  ) as object;
  assert.equal(validator.compile(packageSchema)(value), true);
  assert.equal(validator.compile(reportSchema)(report), true);
  assert.equal(value.claims.aws_authorized, false);
  assert.equal(value.claims.aws_execution_observed, false);
  assert.equal(value.claims.provider_execution_observed, false);
  assert.equal(value.claims.local_kata_qualification_passed, true);
  assert.equal(value.terminal_gate.fresh_aws_authorization_required, true);
});

test("qualification package binds exact H, G, static observation, artifacts, and durable members", () => {
  const value = parse(packagePath);
  const reportRaw = readFileSync(reportPath);
  const receiptRaw = readFileSync(receiptPath);
  const report = parse(reportPath);
  const receipt = parse(receiptPath);
  assert.deepEqual(value.source, {
    implementation_head: "1fc2dea2dcefea2aaf71a80356e0f5ed946e9991",
    manifest_sha256: "509dacc4a83b45a2da1ca7892210de8434a2b9de5b2a478ce4d8197f85967f3a",
  });
  assert.equal(value.control.head, "c72161b4a513b38c5d968e84d7fa440921b730da");
  assert.equal(value.static_observation.run_id, 33348451013);
  assert.equal(value.static_observation.artifact_id, 9742819865);
  assert.equal(value.static_observation.artifact_members, 13);
  assert.equal(value.qualification.run_id, 33392217934);
  assert.equal(value.qualification.job_id, 99488388424);
  assert.equal(value.qualification.run_attempt, 1);
  assert.equal(value.qualification.first_created, true);
  assert.equal(value.qualification.report_artifact.id, 9761867397);
  assert.equal(value.qualification.receipt_artifact.id, 9761868222);
  assert.equal(value.qualification.report.sha256, sha256(reportRaw));
  assert.equal(value.qualification.report.bytes, reportRaw.length);
  assert.equal(value.qualification.upload_receipt.sha256, sha256(receiptRaw));
  assert.equal(value.qualification.upload_receipt.bytes, receiptRaw.length);
  assert.equal(receipt.report.sha256, sha256(reportRaw));
  assert.equal(receipt.report.bytes, reportRaw.length);
  assert.equal(receipt.artifact.id, value.qualification.report_artifact.id);
  assert.equal(receipt.artifact.digest, value.qualification.report_artifact.archive_sha256);
  assert.equal(receipt.run.id, value.qualification.run_id);
  assert.equal(receipt.control.head, value.control.head);
  assert.equal(receipt.source.head, value.source.implementation_head);
  assert.equal(report.bindings.source_head, value.source.implementation_head);
  assert.equal(report.bindings.source_manifest_sha256, value.source.manifest_sha256);
  assert.equal(report.bindings.artifact_sha256, value.package_identity.deb_sha256);
  assert.equal(report.bindings.final_pin_sha256, value.package_identity.final_pin_sha256);
  assert.equal(report.bindings.rootfs_sha256, value.package_identity.rootfs_sha256);
  const historical = value.control.head as string;
  const fromHistorical = (path: string) => execFileSync("git", ["show", `${historical}:${path}`], { cwd: root });
  const workflow = fromHistorical(".github/workflows/stage2-local-kata-qualification.yml");
  const schema = fromHistorical("schemas/stage2-workload-local-qualification-v3.json");
  const control = fromHistorical(
    "deploy/aws-feasibility/remote/stage2-completion-local-control-v2/stage2-local-static-control-v1.json",
  );
  assert.equal(sha256(workflow), value.control.workflow_sha256);
  assert.equal(sha256(schema), value.control.result_schema_sha256);
  assert.equal(sha256(control), value.control.static_control_sha256);
});

test("seven samples, 21 measurements, ordered teardown, and zero residue are frozen", () => {
  const value = parse(packagePath);
  const report = parse(reportPath);
  assert.equal(report.result, "pass");
  assert.equal(report.qualified, true);
  assert.equal(report.failure_code, null);
  assert.deepEqual(report.lifecycle, { attempts: 1, outcome: "pass", ssh_attempts: 1, ssh_outcome: "pass" });
  let measurements = 0;
  for (const kind of ["git", "build", "install"] as const) {
    const rows = report.timings[kind] as Array<Record<string, any>>;
    assert.deepEqual(
      rows.map((row) => row.ordinal),
      [1, 2, 3, 4, 5, 6, 7],
    );
    assert.ok(rows.every((row) => row.outcome === "pass" && row.deletion === "absent" && row.duration_ns > 0));
    const durations = rows.map((row) => row.duration_ns as number);
    assert.deepEqual(report.timing_summaries[kind], {
      count: 7,
      maximum_ns: Math.max(...durations),
      minimum_ns: Math.min(...durations),
      total_ns: durations.reduce((sum, current) => sum + current, 0),
    });
    measurements += rows.length;
  }
  assert.equal(measurements, 21);
  assert.equal(value.qualification.measurements, measurements);
  assert.deepEqual(
    report.teardown.map((row: Record<string, any>) => row.phase),
    [
      "READINESS_REVOKED",
      "TASK_STOPPED",
      "TASK_ABSENT",
      "RUNTIME_PROCESSES_ABSENT",
      "NETWORK_ABSENT",
      "CONTAINER_ABSENT",
      "SHARE_AND_MOUNTS_ABSENT",
      "FIREWALL_ABSENT",
      "CONTAINERD_ABSENT",
      "INPUTS_ABSENT",
      "ROOTFS_ABSENT",
      "FINAL_BASELINES",
      "RETIRED",
    ],
  );
  assert.ok(report.teardown.every((row: Record<string, any>) => row.outcome === "pass"));
  assert.equal(Object.keys(report.zero_residue).length, value.qualification.zero_residue_domains);
  assert.ok(Object.values(report.zero_residue).every((outcome) => outcome === "absent"));
  assert.deepEqual(receiptOutcomes(), ["success"]);
});

function receiptOutcomes(): string[] {
  const receipt = parse(receiptPath);
  return [...new Set(Object.values(receipt.outcomes) as string[])];
}
