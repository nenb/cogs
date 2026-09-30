import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

function record(value: unknown): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), "invalid npm audit result");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} fields changed`);
}

export function validateNpmAuditResult(auditValue: unknown): void {
  const root = record(auditValue);
  exactKeys(root, ["auditReportVersion", "metadata", "vulnerabilities"], "npm audit report");
  assert.equal(root.auditReportVersion, 2, "unexpected npm audit report version");

  const vulnerabilities = record(root.vulnerabilities);
  exactKeys(vulnerabilities, [], "npm audit vulnerabilities");

  const metadata = record(root.metadata);
  exactKeys(metadata, ["dependencies", "vulnerabilities"], "npm audit metadata");
  const vulnerabilityCounts = record(metadata.vulnerabilities);
  exactKeys(vulnerabilityCounts, ["critical", "high", "info", "low", "moderate", "total"], "vulnerability counts");
  assert.deepEqual(vulnerabilityCounts, {
    info: 0,
    low: 0,
    moderate: 0,
    high: 0,
    critical: 0,
    total: 0,
  });

  const dependencies = record(metadata.dependencies);
  exactKeys(dependencies, ["dev", "optional", "peer", "peerOptional", "prod", "total"], "dependency counts");
  for (const [name, value] of Object.entries(dependencies)) {
    assert.ok(Number.isSafeInteger(value) && (value as number) >= 0, `invalid ${name} dependency count`);
  }
}

function main(): void {
  const audit = spawnSync("npm", ["audit", "--json", "--audit-level=low"], {
    cwd: process.cwd(),
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 120_000,
  });
  assert.equal(audit.error, undefined, "npm audit invocation failed");
  assert.equal(audit.signal, null, "npm audit was terminated");
  assert.equal(audit.status, 0, "npm audit reported a vulnerability or failed unexpectedly");
  assert.ok(audit.stdout.length > 0 && audit.stdout.length <= 1024 * 1024, "invalid npm audit output");
  let parsed: unknown;
  try {
    parsed = JSON.parse(audit.stdout);
  } catch {
    throw new Error("invalid npm audit JSON");
  }
  validateNpmAuditResult(parsed);
  console.log("npm audit reported zero findings.");
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
