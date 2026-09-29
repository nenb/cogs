import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PI_PATH = "node_modules/@earendil-works/pi-coding-agent";
const UNDICI_PATH = `${PI_PATH}/node_modules/undici`;

function record(value: unknown): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), "invalid npm audit result");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} fields changed`);
}

function fixAvailable(value: unknown): void {
  const fix = record(value);
  exactKeys(fix, ["isSemVerMajor", "name", "version"], "fixAvailable");
  assert.equal(fix.name, "@earendil-works/pi-coding-agent");
  assert.equal(fix.isSemVerMajor, true);
  assert.equal(fix.version, "0.87.1");
}

export function validateNpmAuditDisposition(auditValue: unknown, lockValue: unknown): void {
  const lock = record(lockValue);
  const packages = record(lock.packages);
  const rootPackage = record(packages[""]);
  const piPackage = record(packages[PI_PATH]);
  assert.equal(record(rootPackage.dependencies)["@earendil-works/pi-coding-agent"], "0.84.2");
  assert.equal(piPackage.version, "0.84.2", "disposed Pi version changed");
  assert.equal(record(piPackage.dependencies).undici, "8.9.0", "disposed Pi-to-undici edge changed");
  assert.equal(record(packages[UNDICI_PATH]).version, "8.9.0", "disposed undici version changed");

  const root = record(auditValue);
  exactKeys(root, ["auditReportVersion", "metadata", "vulnerabilities"], "npm audit report");
  assert.equal(root.auditReportVersion, 2, "unexpected npm audit report version");
  const vulnerabilities = record(root.vulnerabilities);
  exactKeys(vulnerabilities, ["@earendil-works/pi-coding-agent", "undici"], "disposed vulnerabilities");

  const pi = record(vulnerabilities["@earendil-works/pi-coding-agent"]);
  exactKeys(
    pi,
    ["effects", "fixAvailable", "isDirect", "name", "nodes", "range", "severity", "via"],
    "Pi meta-finding",
  );
  assert.equal(pi.name, "@earendil-works/pi-coding-agent");
  assert.equal(pi.severity, "moderate");
  assert.equal(pi.isDirect, true);
  assert.deepEqual(pi.via, ["undici"]);
  assert.deepEqual(pi.effects, []);
  assert.equal(pi.range, "0.75.4 - 0.85.1");
  assert.deepEqual(pi.nodes, [PI_PATH]);
  fixAvailable(pi.fixAvailable);

  const undici = record(vulnerabilities.undici);
  exactKeys(
    undici,
    ["effects", "fixAvailable", "isDirect", "name", "nodes", "range", "severity", "via"],
    "undici finding",
  );
  assert.equal(undici.name, "undici");
  assert.equal(undici.severity, "moderate");
  assert.equal(undici.isDirect, false);
  assert.deepEqual(undici.effects, ["@earendil-works/pi-coding-agent"]);
  assert.equal(undici.range, "8.1.0 - 8.10.1");
  assert.deepEqual(undici.nodes, [UNDICI_PATH]);
  fixAvailable(undici.fixAvailable);
  const via = undici.via;
  assert.ok(Array.isArray(via) && via.length === 1);
  assert.deepEqual(via[0], {
    source: 1239932,
    name: "undici",
    dependency: "undici",
    title: "undici vulnerable to Denial of Service via unhandled error in WebSocket permessage-deflate decompression",
    url: "https://github.com/advisories/GHSA-3wwx-pv8p-q78v",
    severity: "moderate",
    cwe: ["CWE-248"],
    cvss: { score: 5.9, vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" },
    range: ">=8.1.0 <8.10.2",
  });

  const metadata = record(root.metadata);
  exactKeys(metadata, ["dependencies", "vulnerabilities"], "npm audit metadata");
  assert.deepEqual(record(metadata.vulnerabilities), {
    info: 0,
    low: 0,
    moderate: 2,
    high: 0,
    critical: 0,
    total: 2,
  });
  assert.deepEqual(record(metadata.dependencies), {
    prod: 257,
    dev: 42,
    optional: 49,
    peer: 0,
    peerOptional: 0,
    total: 312,
  });
}

function main(): void {
  const audit = spawnSync("npm", ["audit", "--json", "--audit-level=high"], {
    cwd: process.cwd(),
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 120_000,
  });
  assert.equal(audit.error, undefined, "npm audit invocation failed");
  assert.equal(audit.signal, null, "npm audit was terminated");
  assert.equal(audit.status, 0, "npm audit reported a high-severity finding or failed unexpectedly");
  assert.ok(audit.stdout.length > 0 && audit.stdout.length <= 1024 * 1024, "invalid npm audit output");
  let parsed: unknown;
  try {
    parsed = JSON.parse(audit.stdout);
  } catch {
    throw new Error("invalid npm audit JSON");
  }
  validateNpmAuditDisposition(parsed, JSON.parse(readFileSync("package-lock.json", "utf8")));
  console.log(
    "Accepted only GHSA-3wwx-pv8p-q78v under the organization-wide Pi 0.84.2 disposition; zero undisposed findings.",
  );
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
