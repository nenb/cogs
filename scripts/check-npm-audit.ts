import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const created = "2026-08-03T21:58:55Z";
const expiry = "2026-08-16T23:59:59Z";
const expected = {
  "@earendil-works/pi-coding-agent": {
    severity: "moderate",
    isDirect: true,
    findingRange: ">=0.75.4",
    node: "node_modules/@earendil-works/pi-coding-agent",
    effects: [],
    fixAvailable: { name: "@earendil-works/pi-coding-agent", version: "0.75.3", isSemVerMajor: true },
    viaPackages: ["undici"],
  },
  "brace-expansion": {
    severity: "high",
    isDirect: false,
    findingRange: "3.0.0 - 5.0.8",
    node: "node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion",
    effects: [],
    fixAvailable: true,
    advisories: [
      {
        source: 1123898,
        url: "https://github.com/advisories/GHSA-3jxr-9vmj-r5cp",
        severity: "high",
        range: ">=3.0.0 <5.0.7",
      },
      {
        source: 1130591,
        url: "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
        severity: "high",
        range: ">=4.0.0 <5.0.8",
      },
      {
        source: 1130734,
        url: "https://github.com/advisories/GHSA-rgw5-rvv9-x895",
        severity: "high",
        range: ">=4.0.0 <5.0.9",
      },
    ],
  },
  protobufjs: {
    severity: "moderate",
    isDirect: false,
    findingRange: "7.5.0 - 7.6.4",
    node: "node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs",
    effects: [],
    fixAvailable: true,
    advisories: [
      {
        source: 1123964,
        url: "https://github.com/advisories/GHSA-j3f2-48v5-ccww",
        severity: "moderate",
        range: ">=7.5.0 <=7.6.4",
      },
    ],
  },
  undici: {
    severity: "high",
    isDirect: false,
    findingRange: "8.0.0 - 8.8.0",
    node: "node_modules/@earendil-works/pi-coding-agent/node_modules/undici",
    effects: ["@earendil-works/pi-coding-agent"],
    fixAvailable: { name: "@earendil-works/pi-coding-agent", version: "0.75.3", isSemVerMajor: true },
    advisories: [
      {
        source: 1130714,
        url: "https://github.com/advisories/GHSA-8xcm-r25x-g524",
        severity: "moderate",
        range: ">=8.0.0 <8.9.0",
      },
      {
        source: 1130717,
        url: "https://github.com/advisories/GHSA-4cwx-7wf7-3272",
        severity: "high",
        range: ">=8.0.0 <8.9.0",
      },
      {
        source: 1130725,
        url: "https://github.com/advisories/GHSA-m8rv-5g2x-5cg5",
        severity: "moderate",
        range: ">=8.0.0 <8.9.0",
      },
      {
        source: 1130728,
        url: "https://github.com/advisories/GHSA-jr45-8vmc-qm54",
        severity: "moderate",
        range: ">=8.0.0 <8.9.0",
      },
      {
        source: 1130730,
        url: "https://github.com/advisories/GHSA-v3r7-h72x-cjcm",
        severity: "moderate",
        range: ">=8.0.0 <8.9.0",
      },
    ],
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
  assert.equal(finding.isDirect, disposition.isDirect, "npm audit directness mismatch");
  assert.deepEqual(finding.fixAvailable, disposition.fixAvailable, "npm audit fixability changed");
  assert.equal(finding.range, disposition.findingRange, "npm audit affected range changed");
  assert.deepEqual(finding.effects, disposition.effects, "npm audit effect graph changed");
  assert.deepEqual(finding.nodes, [disposition.node], "npm audit dependency path changed");
  if ("viaPackages" in disposition) {
    assert.deepEqual(finding.via, disposition.viaPackages, "npm audit package effect changed");
    continue;
  }
  assert.ok(
    Array.isArray(finding.via) && finding.via.length === disposition.advisories.length,
    "npm audit advisory graph changed",
  );
  for (const [index, expectedAdvisory] of disposition.advisories.entries()) {
    const advisory = record(finding.via[index]);
    assert.equal(advisory.source, expectedAdvisory.source, "npm audit advisory identity changed");
    assert.equal(advisory.name, name, "npm audit advisory package changed");
    assert.equal(advisory.dependency, name, "npm audit advisory dependency changed");
    assert.equal(advisory.url, expectedAdvisory.url, "npm audit advisory URL changed");
    assert.equal(advisory.severity, expectedAdvisory.severity, "npm audit advisory severity changed");
    assert.equal(advisory.range, expectedAdvisory.range, "npm audit advisory range changed");
  }
}

const counts = record(record(root.metadata).vulnerabilities);
assert.deepEqual(
  counts,
  { info: 0, low: 0, moderate: 2, high: 2, critical: 0, total: 4 },
  "npm audit vulnerability counts changed",
);
console.log(`Accepted exactly four package findings covering nine advisories through ${expiry}.`);
