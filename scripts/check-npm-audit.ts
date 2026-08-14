import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

function record(value: unknown): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), "invalid npm audit result");
  return value as Record<string, unknown>;
}

const audit = spawnSync("npm", ["audit", "--json", "--audit-level=high"], {
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
const root = record(parsed);
assert.equal(root.auditReportVersion, 2, "unexpected npm audit report version");
assert.deepEqual(record(root.vulnerabilities), {}, "npm audit vulnerability set is not empty");
assert.deepEqual(
  record(record(root.metadata).vulnerabilities),
  { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
  "npm audit vulnerability counts are not zero",
);
console.log("Verified zero npm audit findings at every severity.");
