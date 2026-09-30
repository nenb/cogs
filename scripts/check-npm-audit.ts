import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const BRACE_EXPANSION_ACCEPTANCE_NOT_BEFORE = "2026-09-30T12:22:00.000Z";
export const BRACE_EXPANSION_ACCEPTANCE_EXPIRES_AT = "2026-10-14T00:00:00.000Z";

const BRACE_PATH = "node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion";
const MINIMATCH_PATH = "node_modules/@earendil-works/pi-coding-agent/node_modules/minimatch";
const PI_PATH = "node_modules/@earendil-works/pi-coding-agent";
const FAST_URI_PATH = "node_modules/fast-uri";
const PI_INTEGRITY = "sha512-tzLh/10bPQZbA9shvA8TALT4eSNCifJaDq672MPXHldsvZ9t9lQ8J5Z9CD1d7UZVzG4l85XUZWo6ZCCNhBULxw==";
const MINIMATCH_INTEGRITY =
  "sha512-vpLQEs+VLCr1nU0BXS07maYoFwlDAH0gngQuuttxIwutDFEMHq2blX+8vpgxDdK3J1PwjCJiep77OitTZ4Ll1A==";
const BRACE_INTEGRITY =
  "sha512-ScQ4IuvIEF1TMlP7Zt+vjJ//9zlPb2SDcxWxM3bk8s6t6GGdJ7KO1dCcTidOPJKePW30LE/2cT7wCyPho9/Wxg==";
const AJV_INTEGRITY = "sha512-Thbli+OlOj+iMPYFBVBfJ3OmCAnaSyNn4M1vz9T6Gka5Jt9ba/HIR56joy65tY6kx/FCF5VXNB819Y7/GUrBGA==";
const FAST_URI_INTEGRITY =
  "sha512-GZMtZUTNRpOVIECoXwLNZS5xUGE+mVNbTB8h/7Rwh2TFWcBQiPzTgyZi05BF9UMZKkLJv8XBRJTlU7zg8+ZfMg==";

function record(value: unknown, label = "value"): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), `invalid ${label}`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} fields changed`);
}

function expectedBraceFinding(): Record<string, unknown> {
  return {
    name: "brace-expansion",
    severity: "high",
    isDirect: false,
    via: [
      {
        source: 1240103,
        name: "brace-expansion",
        dependency: "brace-expansion",
        title: "brace-expansion: Quadratic-time expansion of the `{a},b}` rewrite causes CPU denial of service",
        url: "https://github.com/advisories/GHSA-q2hr-2g5m-vwhr",
        severity: "moderate",
        cwe: ["CWE-400", "CWE-407"],
        cvss: { score: 5.3, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" },
        range: ">=4.0.0 <5.0.12",
      },
      {
        source: 1240107,
        name: "brace-expansion",
        dependency: "brace-expansion",
        title: "brace-expansion: DoS via uncontrolled recursion on nested brace groups causing stack exhaustion",
        url: "https://github.com/advisories/GHSA-qhr7-859c-m2p7",
        severity: "high",
        cwe: ["CWE-400", "CWE-674"],
        cvss: { score: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
        range: ">=4.0.0 <5.0.11",
      },
      {
        source: 1240111,
        name: "brace-expansion",
        dependency: "brace-expansion",
        title: "brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion",
        url: "https://github.com/advisories/GHSA-6j4f-fj2g-mc7p",
        severity: "high",
        cwe: ["CWE-400", "CWE-674"],
        cvss: { score: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
        range: ">=4.0.0 <5.0.10",
      },
    ],
    effects: [],
    range: "4.0.0 - 5.0.11",
    nodes: [BRACE_PATH],
    fixAvailable: true,
  };
}

export function validateNpmAuditResult(auditValue: unknown, nowMs = Date.now()): void {
  assert.ok(Number.isSafeInteger(nowMs), "invalid audit disposition time");
  assert.ok(
    nowMs >= Date.parse(BRACE_EXPANSION_ACCEPTANCE_NOT_BEFORE),
    "brace-expansion disposition predates acceptance",
  );
  assert.ok(nowMs < Date.parse(BRACE_EXPANSION_ACCEPTANCE_EXPIRES_AT), "brace-expansion disposition expired");

  const root = record(auditValue, "npm audit result");
  exactKeys(root, ["auditReportVersion", "metadata", "vulnerabilities"], "npm audit report");
  assert.equal(root.auditReportVersion, 2, "unexpected npm audit report version");

  const vulnerabilities = record(root.vulnerabilities, "npm audit vulnerabilities");
  exactKeys(vulnerabilities, ["brace-expansion"], "npm audit vulnerabilities");
  assert.deepEqual(vulnerabilities["brace-expansion"], expectedBraceFinding(), "accepted finding bytes changed");

  const metadata = record(root.metadata, "npm audit metadata");
  exactKeys(metadata, ["dependencies", "vulnerabilities"], "npm audit metadata");
  const vulnerabilityCounts = record(metadata.vulnerabilities, "vulnerability counts");
  exactKeys(vulnerabilityCounts, ["critical", "high", "info", "low", "moderate", "total"], "vulnerability counts");
  assert.deepEqual(vulnerabilityCounts, {
    info: 0,
    low: 0,
    moderate: 0,
    high: 1,
    critical: 0,
    total: 1,
  });

  const dependencies = record(metadata.dependencies, "dependency counts");
  exactKeys(dependencies, ["dev", "optional", "peer", "peerOptional", "prod", "total"], "dependency counts");
  assert.deepEqual(dependencies, { prod: 243, dev: 15, optional: 64, peer: 0, peerOptional: 0, total: 312 });
}

export interface AcceptedNpmDependencyClosure {
  readonly packageJson: unknown;
  readonly packageLock: unknown;
  readonly piPackageJson: unknown;
  readonly piShrinkwrap: unknown;
  readonly installedMinimatchPackageJson: unknown;
  readonly installedBracePackageJson: unknown;
  readonly installedFastUriPackageJson: unknown;
}

function dependency(recordValue: Record<string, unknown>, name: string, expected: string, label: string): void {
  const dependencies = record(recordValue.dependencies, `${label} dependencies`);
  assert.equal(dependencies[name], expected, `${label} ${name} edge changed`);
}

function lockEntry(packages: Record<string, unknown>, path: string): Record<string, unknown> {
  return record(packages[path], `lock entry ${path}`);
}

function registryIdentity(
  entry: Record<string, unknown>,
  version: string,
  resolved: string,
  integrity: string,
  label: string,
): void {
  assert.equal(entry.version, version, `${label} version changed`);
  assert.equal(entry.resolved, resolved, `${label} registry URL changed`);
  assert.equal(entry.integrity, integrity, `${label} integrity changed`);
}

const PI_DEPENDENCIES = {
  "@earendil-works/chord": "^0.86.0",
  "@earendil-works/pi-agent-core": "^0.86.0",
  "@earendil-works/pi-ai": "^0.86.0",
  "@earendil-works/pi-tui": "^0.86.0",
  "@silvia-odwyer/photon-node": "0.3.4",
  chalk: "6.0.0",
  "cross-spawn": "7.0.6",
  diff: "8.0.4",
  "grok-mermaid": "0.2.3",
  "highlight.js": "10.7.3",
  "hosted-git-info": "9.0.3",
  ignore: "7.0.8",
  jiti: "2.7.0",
  minimatch: "10.2.6",
  "proper-lockfile": "4.1.2",
  semver: "7.8.5",
  typebox: "1.3.27",
  undici: "8.10.2",
  yaml: "2.9.0",
} as const;

export function validateAcceptedNpmDependencyClosure(input: AcceptedNpmDependencyClosure): void {
  const packageJson = record(input.packageJson, "package.json");
  dependency(packageJson, "@earendil-works/pi-agent-core", "0.86.0", "package.json");
  dependency(packageJson, "@earendil-works/pi-ai", "0.86.0", "package.json");
  dependency(packageJson, "@earendil-works/pi-coding-agent", "0.86.0", "package.json");
  dependency(packageJson, "ajv", "8.20.0", "package.json");

  const packageLock = record(input.packageLock, "package-lock.json");
  assert.equal(packageLock.lockfileVersion, 3, "package lock version changed");
  const packages = record(packageLock.packages, "package lock packages");
  const root = lockEntry(packages, "");
  dependency(root, "@earendil-works/pi-coding-agent", "0.86.0", "root lock");
  dependency(root, "ajv", "8.20.0", "root lock");

  const pi = lockEntry(packages, PI_PATH);
  registryIdentity(
    pi,
    "0.86.0",
    "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-0.86.0.tgz",
    PI_INTEGRITY,
    "Pi coding-agent lock",
  );
  assert.equal(pi.hasShrinkwrap, true, "Pi coding-agent shrinkwrap marker changed");
  assert.deepEqual(record(pi.dependencies, "Pi coding-agent lock dependencies"), PI_DEPENDENCIES);

  const minimatch = lockEntry(packages, MINIMATCH_PATH);
  registryIdentity(
    minimatch,
    "10.2.6",
    "https://registry.npmjs.org/minimatch/-/minimatch-10.2.6.tgz",
    MINIMATCH_INTEGRITY,
    "minimatch lock",
  );
  assert.deepEqual(record(minimatch.dependencies, "minimatch lock dependencies"), { "brace-expansion": "^5.0.8" });

  const brace = lockEntry(packages, BRACE_PATH);
  registryIdentity(
    brace,
    "5.0.9",
    "https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.9.tgz",
    BRACE_INTEGRITY,
    "accepted brace-expansion lock",
  );
  assert.deepEqual(record(brace.dependencies, "brace-expansion lock dependencies"), { "balanced-match": "^4.0.2" });

  const ajv = lockEntry(packages, "node_modules/ajv");
  registryIdentity(ajv, "8.20.0", "https://registry.npmjs.org/ajv/-/ajv-8.20.0.tgz", AJV_INTEGRITY, "Ajv lock");
  assert.deepEqual(record(ajv.dependencies, "Ajv lock dependencies"), {
    "fast-deep-equal": "^3.1.3",
    "fast-uri": "^3.0.1",
    "json-schema-traverse": "^1.0.0",
    "require-from-string": "^2.0.2",
  });
  const fastUri = lockEntry(packages, FAST_URI_PATH);
  registryIdentity(
    fastUri,
    "3.1.8",
    "https://registry.npmjs.org/fast-uri/-/fast-uri-3.1.8.tgz",
    FAST_URI_INTEGRITY,
    "fixed fast-uri lock",
  );

  const piPackage = record(input.piPackageJson, "installed Pi package");
  assert.equal(piPackage.name, "@earendil-works/pi-coding-agent");
  assert.equal(piPackage.version, "0.86.0");
  assert.deepEqual(record(piPackage.dependencies, "installed Pi package dependencies"), PI_DEPENDENCIES);

  const piShrinkwrap = record(input.piShrinkwrap, "installed Pi shrinkwrap");
  assert.equal(piShrinkwrap.lockfileVersion, 3, "installed Pi shrinkwrap version changed");
  const piPackages = record(piShrinkwrap.packages, "installed Pi shrinkwrap packages");
  const shrinkRoot = lockEntry(piPackages, "");
  assert.equal(shrinkRoot.name, "@earendil-works/pi-coding-agent");
  assert.equal(shrinkRoot.version, "0.86.0");
  assert.deepEqual(record(shrinkRoot.dependencies, "installed Pi shrinkwrap dependencies"), PI_DEPENDENCIES);
  const shrinkMinimatch = lockEntry(piPackages, "node_modules/minimatch");
  registryIdentity(
    shrinkMinimatch,
    "10.2.6",
    "https://registry.npmjs.org/minimatch/-/minimatch-10.2.6.tgz",
    MINIMATCH_INTEGRITY,
    "installed Pi shrinkwrap minimatch",
  );
  assert.deepEqual(record(shrinkMinimatch.dependencies, "installed Pi shrinkwrap minimatch dependencies"), {
    "brace-expansion": "^5.0.8",
  });
  const shrinkBrace = lockEntry(piPackages, "node_modules/brace-expansion");
  registryIdentity(
    shrinkBrace,
    "5.0.9",
    "https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.9.tgz",
    BRACE_INTEGRITY,
    "installed Pi shrinkwrap brace-expansion",
  );
  assert.deepEqual(record(shrinkBrace.dependencies, "installed Pi shrinkwrap brace-expansion dependencies"), {
    "balanced-match": "^4.0.2",
  });

  for (const [value, name, version] of [
    [input.installedMinimatchPackageJson, "minimatch", "10.2.6"],
    [input.installedBracePackageJson, "brace-expansion", "5.0.9"],
    [input.installedFastUriPackageJson, "fast-uri", "3.1.8"],
  ] as const) {
    const installed = record(value, `installed ${name}`);
    assert.equal(installed.name, name, `installed ${name} name changed`);
    assert.equal(installed.version, version, `installed ${name} version changed`);
  }
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function main(): void {
  const root = resolve(import.meta.dirname, "..");
  const piRoot = resolve(root, PI_PATH);
  validateAcceptedNpmDependencyClosure({
    packageJson: readJson(resolve(root, "package.json")),
    packageLock: readJson(resolve(root, "package-lock.json")),
    piPackageJson: readJson(resolve(piRoot, "package.json")),
    piShrinkwrap: readJson(resolve(piRoot, "npm-shrinkwrap.json")),
    installedMinimatchPackageJson: readJson(resolve(root, MINIMATCH_PATH, "package.json")),
    installedBracePackageJson: readJson(resolve(root, BRACE_PATH, "package.json")),
    installedFastUriPackageJson: readJson(resolve(root, FAST_URI_PATH, "package.json")),
  });

  const audit = spawnSync("npm", ["audit", "--json", "--audit-level=low"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 120_000,
  });
  assert.equal(audit.error, undefined, "npm audit invocation failed");
  assert.equal(audit.signal, null, "npm audit was terminated");
  assert.equal(audit.status, 1, "accepted npm audit disposition is missing or npm failed unexpectedly");
  assert.ok(audit.stdout.length > 0 && audit.stdout.length <= 1024 * 1024, "invalid npm audit output");
  let parsed: unknown;
  try {
    parsed = JSON.parse(audit.stdout);
  } catch {
    throw new Error("invalid npm audit JSON");
  }
  validateNpmAuditResult(parsed);
  console.log(
    `npm audit matched only the exact temporary brace-expansion 5.0.9 availability-risk disposition; expires ${BRACE_EXPANSION_ACCEPTANCE_EXPIRES_AT}.`,
  );
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
