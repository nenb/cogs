import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const created = "2026-07-25T01:40:00Z";
const expiry = "2026-08-08T01:39:59Z";
const expected = {
  "brace-expansion": {
    severity: "high",
    source: 1124334,
    url: "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
    range: "<=5.0.7",
    findingRange: "<=5.0.7",
    node: "node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion",
  },
  protobufjs: {
    severity: "moderate",
    source: 1123964,
    url: "https://github.com/advisories/GHSA-j3f2-48v5-ccww",
    range: ">=7.5.0 <=7.6.4",
    findingRange: "7.5.0 - 7.6.4",
    node: "node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs",
  },
} as const;

function record(value: unknown): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), "invalid npm audit result");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), "unexpected npm audit finding set");
}

const createdAt = Date.parse(created);
const expiresAt = Date.parse(expiry);
assert.ok(Number.isFinite(createdAt) && Number.isFinite(expiresAt), "invalid npm audit disposition dates");
assert.ok(
  expiresAt > createdAt && expiresAt - createdAt <= 14 * 24 * 60 * 60 * 1000,
  "npm audit disposition is too long",
);
assert.ok(Date.now() >= createdAt && Date.now() <= expiresAt, "npm audit disposition is inactive or expired");
const audit = spawnSync("npm", ["audit", "--json", "--audit-level=high"], {
  cwd: process.cwd(),
  encoding: "utf8",
  maxBuffer: 1024 * 1024,
  shell: false,
  timeout: 120_000,
});
assert.equal(audit.error, undefined, "npm audit invocation failed");
assert.equal(audit.signal, null, "npm audit was terminated");
assert.equal(audit.status, 1, "temporary npm audit disposition is stale or audit failed unexpectedly");
assert.ok(audit.stdout.length > 0 && audit.stdout.length <= 1024 * 1024, "invalid npm audit output");

let parsed: unknown;
try {
  parsed = JSON.parse(audit.stdout);
} catch {
  throw new Error("invalid npm audit JSON");
}
const root = record(parsed);
const vulnerabilities = record(root.vulnerabilities);
exactKeys(vulnerabilities, Object.keys(expected));

for (const [name, disposition] of Object.entries(expected)) {
  const finding = record(vulnerabilities[name]);
  assert.equal(finding.name, name, "npm audit package mismatch");
  assert.equal(finding.severity, disposition.severity, "npm audit severity mismatch");
  assert.equal(finding.isDirect, false, "npm audit directness mismatch");
  assert.equal(finding.fixAvailable, true, "npm audit fixability mismatch");
  assert.equal(finding.range, disposition.findingRange, "npm audit affected range changed");
  assert.deepEqual(finding.effects, [], "npm audit effect graph changed");
  assert.deepEqual(finding.nodes, [disposition.node], "npm audit dependency path changed");
  assert.ok(Array.isArray(finding.via) && finding.via.length === 1, "npm audit advisory graph changed");
  const advisory = record(finding.via[0]);
  assert.equal(advisory.source, disposition.source, "npm audit advisory identity changed");
  assert.equal(advisory.name, name, "npm audit advisory package changed");
  assert.equal(advisory.dependency, name, "npm audit advisory dependency changed");
  assert.equal(advisory.url, disposition.url, "npm audit advisory URL changed");
  assert.equal(advisory.severity, disposition.severity, "npm audit advisory severity changed");
  assert.equal(advisory.range, disposition.range, "npm audit advisory range changed");
}

const counts = record(record(root.metadata).vulnerabilities);
assert.deepEqual(
  counts,
  { info: 0, low: 0, moderate: 1, high: 1, critical: 0, total: 2 },
  "npm audit vulnerability counts changed",
);
console.log(`Accepted exactly two temporary npm audit dispositions through ${expiry}.`);
