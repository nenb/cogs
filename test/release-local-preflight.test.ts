import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { RELEASE_IMAGE_SET_PINS, RELEASE_IMAGE_SET_PINS_MANIFEST_PATH } from "../scripts/release-image-set-pins.ts";
import {
  canonicalReleaseLocalBytes,
  createReleaseLocalLedger,
  inspectTrivyDatabaseMetadata,
  RELEASE_LOCAL_TRIVY,
  type ReleaseLocalDatabaseObservation,
  type ReleaseLocalJson,
} from "../scripts/release-local-preflight.ts";

const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const metadataValue = {
  Version: 2,
  UpdatedAt: "2026-08-02T12:00:00Z",
  NextUpdate: "2026-08-03T12:00:00Z",
  DownloadedAt: "2026-08-02T13:00:00Z",
};

function databases(at = "2026-08-03T11:59:59Z"): ReleaseLocalDatabaseObservation {
  return {
    vulnerability: inspectTrivyDatabaseMetadata(bytes(metadataValue), new Date(at)),
    java: inspectTrivyDatabaseMetadata(bytes(metadataValue), new Date(at)),
  };
}

function report(findings = true): Record<string, unknown> {
  const osVulnerabilities = findings
    ? [
        {
          VulnerabilityID: "CVE-2026-0001",
          PkgID: "libexample@1.0",
          PkgName: "libexample",
          InstalledVersion: "1.0",
          Severity: "CRITICAL",
          SeveritySource: "nvd",
          VendorSeverity: { nvd: "CRITICAL", debian: "HIGH" },
          Status: "fix_deferred",
          DataSource: { ID: "debian", Name: "Debian Security Tracker", URL: "https://security-tracker.debian.org" },
          PrimaryURL: "https://avd.aquasec.com/nvd/cve-2026-0001",
        },
        {
          VulnerabilityID: "CVE-2026-0002",
          PkgID: "libexample@1.0",
          PkgName: "libexample",
          InstalledVersion: "1.0",
          FixedVersion: "1.1",
          Severity: "MEDIUM",
          SeveritySource: "debian",
          Status: "fixed",
          DataSource: { ID: "debian" },
        },
      ]
    : [];
  const languageVulnerabilities = findings
    ? [
        {
          VulnerabilityID: "CVE-2026-0003",
          PkgID: "npm-package@2.0",
          PkgName: "npm-package",
          InstalledVersion: "2.0",
          FixedVersion: "2.1",
          Severity: "HIGH",
          SeveritySource: "ghsa",
          Status: "fixed",
          DataSource: { ID: "ghsa", URL: "https://github.com/advisories" },
        },
      ]
    : [];
  return {
    SchemaVersion: 2,
    ArtifactName: `example.invalid/worker@sha256:${"a".repeat(64)}`,
    ArtifactType: "container_image",
    Metadata: {
      RepoDigests: [`example.invalid/worker@sha256:${"a".repeat(64)}`],
      OS: { Family: "debian", Name: "13.6" },
    },
    Results: [
      {
        Target: "example.invalid/worker (debian 13.6)",
        Class: "os-pkgs",
        Type: "debian",
        Packages: [
          {
            ID: "libexample@1.0",
            Name: "libexample",
            Version: "1.0",
            SrcName: "example-source",
            SrcVersion: "1.0+src1",
          },
        ],
        Vulnerabilities: osVulnerabilities,
      },
      {
        Target: "usr/lib/node_modules/package-lock.json",
        Class: "lang-pkgs",
        Type: "npm",
        Packages: [{ ID: "npm-package@2.0", Name: "npm-package", Version: "2.0" }],
        Vulnerabilities: languageVulnerabilities,
      },
    ],
  };
}

function ledger(value = report(), selectedDatabases = databases()) {
  const reference = `example.invalid/worker@sha256:${"a".repeat(64)}`;
  return createReleaseLocalLedger(bytes(value), {
    role: "worker",
    input: { kind: "docker-image", exact_reference: reference },
    expectedArtifactName: reference,
    databases: selectedDatabases,
  });
}

test("database freshness is strict at NextUpdate and rejects inconsistent metadata", () => {
  assert.equal(inspectTrivyDatabaseMetadata(bytes(metadataValue), new Date("2026-08-03T11:59:59Z")).current, true);
  assert.equal(inspectTrivyDatabaseMetadata(bytes(metadataValue), new Date("2026-08-03T12:00:00Z")).current, false);
  assert.throws(() =>
    inspectTrivyDatabaseMetadata(
      bytes({ ...metadataValue, DownloadedAt: "2026-08-01T00:00:00Z" }),
      new Date("2026-08-02T14:00:00Z"),
    ),
  );
});

test("canonical ledger retains every raw finding and source-package category without weakening the gate", () => {
  const value = ledger();
  assert.equal(value.reason_code, "VULNERABILITY_GATE_BLOCKED");
  assert.deepEqual(value.gate, {
    policy: "zero-raw-high-critical-including-unfixed",
    finding_count: 2,
    high: 1,
    critical: 1,
    includes_unfixed: true,
    passed: false,
  });
  const counts = value.counts as Record<string, unknown>;
  assert.equal(counts.raw_findings, 3);
  assert.equal(counts.unique_vulnerability_ids, 3);
  assert.equal(counts.unique_source_advisories, 3);
  const sourcePackages = value.source_packages as Array<Record<string, unknown>>;
  const debianSource = sourcePackages.find(
    (item) => (item.source_package as Record<string, unknown>).name === "example-source",
  );
  assert.ok(debianSource);
  assert.equal(
    (debianSource.source_package as Record<string, unknown>).mapping,
    "scanner-authenticated-source-package",
  );
  assert.equal(debianSource.occurrence_count, 2);
  assert.equal((value.findings as unknown[]).length, 3);
  assert.equal((value.claims as Record<string, unknown>).publication_performed, false);
  assert.equal((value.claims as Record<string, unknown>).vulnerability_truth_established, false);
  const canonical = canonicalReleaseLocalBytes(value);
  assert.deepEqual(
    canonical,
    canonicalReleaseLocalBytes(JSON.parse(Buffer.from(canonical).toString("utf8")) as ReleaseLocalJson),
  );
});

test("zero HIGH/CRITICAL passes only while both exact database observations are current", () => {
  const current = ledger(report(false));
  assert.equal(current.reason_code, "LOCAL_POLICY_GATE_OBSERVED_ZERO");
  assert.equal((current.gate as Record<string, unknown>).passed, true);

  const expired = ledger(report(false), databases("2026-08-03T12:00:00Z"));
  assert.equal(expired.reason_code, "DATABASE_EXPIRED");
  assert.equal((expired.gate as Record<string, unknown>).finding_count, 0);
  assert.equal((expired.gate as Record<string, unknown>).passed, false);
  assert.equal((expired.claims as Record<string, unknown>).database_current_at_evaluation, false);
});

test("Ubuntu and Debian reports use the scanner OS identity without distribution-specific assumptions", () => {
  const ubuntu = report(false);
  const metadata = ubuntu.Metadata as { OS: { Family: string; Name: string } };
  metadata.OS = { Family: "ubuntu", Name: "24.04" };
  const osResult = (ubuntu.Results as Array<Record<string, unknown>>)[0];
  assert.ok(osResult);
  osResult.Target = "example.invalid/worker (ubuntu 24.04)";
  osResult.Type = "ubuntu";

  const value = ledger(ubuntu);
  assert.deepEqual((value.report as Record<string, unknown>).os, { family: "ubuntu", name: "24.04" });
  assert.equal((value.report as Record<string, unknown>).os_package_inventory_count, 1);
  assert.equal((value.report as Record<string, unknown>).package_inventory_count, 2);
  assert.equal((value.gate as Record<string, unknown>).passed, true);
});

test("report parser fails closed on subject, class, package inventory, and vulnerability shape drift", () => {
  const wrongSubject = report();
  wrongSubject.ArtifactName = `example.invalid/other@sha256:${"b".repeat(64)}`;
  assert.throws(() => ledger(wrongSubject), /artifact name/u);

  const wrongDigest = report();
  (wrongDigest.Metadata as Record<string, unknown>).RepoDigests = [`example.invalid/worker@sha256:${"b".repeat(64)}`];
  assert.throws(() => ledger(wrongDigest), /exact local digest/u);

  const emptyOsFamily = report();
  ((emptyOsFamily.Metadata as Record<string, unknown>).OS as Record<string, unknown>).Family = "";
  assert.throws(() => ledger(emptyOsFamily), /OS.Family/u);

  const wrongClass = report();
  const wrongClassResult = (wrongClass.Results as Array<Record<string, unknown>>)[0];
  assert.ok(wrongClassResult);
  wrongClassResult.Class = "secret";
  assert.throws(() => ledger(wrongClass), /result class/u);

  const wrongOsType = report();
  const wrongOsResult = (wrongOsType.Results as Array<Record<string, unknown>>)[0];
  assert.ok(wrongOsResult);
  wrongOsResult.Type = "ubuntu";
  assert.throws(() => ledger(wrongOsType), /OS result type/u);

  const emptyOsInventory = report();
  const emptyOsResult = (emptyOsInventory.Results as Array<Record<string, unknown>>)[0];
  assert.ok(emptyOsResult);
  emptyOsResult.Packages = [];
  assert.throws(() => ledger(emptyOsInventory), /nonempty OS package inventory/u);

  const missingOsInventory = report();
  const missingOsResult = (missingOsInventory.Results as Array<Record<string, unknown>>)[0];
  assert.ok(missingOsResult);
  delete missingOsResult.Packages;
  assert.throws(() => ledger(missingOsInventory), /nonempty OS package inventory/u);

  const wrongSeverity = report();
  const result = (wrongSeverity.Results as Array<Record<string, unknown>>)[0];
  assert.ok(result);
  const wrongSeverityFinding = (result.Vulnerabilities as Array<Record<string, unknown>>)[0];
  assert.ok(wrongSeverityFinding);
  wrongSeverityFinding.Severity = "URGENT";
  assert.throws(() => ledger(wrongSeverity), /severity/u);

  const missingPackageIdentity = report();
  const missingResult = (missingPackageIdentity.Results as Array<Record<string, unknown>>)[0];
  assert.ok(missingResult);
  const missingFinding = (missingResult.Vulnerabilities as Array<Record<string, unknown>>)[0];
  assert.ok(missingFinding);
  delete missingFinding.PkgID;
  assert.throws(() => ledger(missingPackageIdentity), /PkgID/u);

  const scalarVulnerabilities = report();
  const scalarResult = (scalarVulnerabilities.Results as Array<Record<string, unknown>>)[0];
  assert.ok(scalarResult);
  scalarResult.Vulnerabilities = "none";
  assert.throws(() => ledger(scalarVulnerabilities), /Vulnerabilities/u);

  const invalidFixedVersion = report();
  const fixedResult = (invalidFixedVersion.Results as Array<Record<string, unknown>>)[0];
  assert.ok(fixedResult);
  const fixedFinding = (fixedResult.Vulnerabilities as Array<Record<string, unknown>>)[0];
  assert.ok(fixedFinding);
  fixedFinding.FixedVersion = 1;
  assert.throws(() => ledger(invalidFixedVersion), /FixedVersion/u);
});

test("orchestrator rejects tags before Docker effects and leaves a private non-promoting reason record", () => {
  const root = realpathSync(mkdtempSync(resolve(tmpdir(), "cogs-release-preflight-test-")));
  const output = resolve(root, "private-output");
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        resolve(import.meta.dirname, "../scripts/release-local-preflight-cli.ts"),
        "scan",
        "--worker",
        `docker-image:example.invalid/worker:tag@sha256:${"a".repeat(64)}`,
        "--sandbox",
        `docker-image:example.invalid/sandbox@sha256:${"b".repeat(64)}`,
        "--output",
        output,
      ],
      { encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /INPUT_CONTRACT_VIOLATION/u);
    const resultPath = resolve(output, "preflight-result.canonical.json");
    const state = statSync(resultPath);
    assert.equal(state.mode & 0o777, 0o600);
    const record = JSON.parse(readFileSync(resultPath, "utf8")) as Record<string, unknown>;
    assert.equal(record.reason_code, "INPUT_CONTRACT_VIOLATION");
    assert.equal(record.publication_performed, false);
    assert.equal(record.release_eligible, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("local preflight is pinned to release inputs and exposes no publication, signing, dispatch, or suppression route", () => {
  const workflow = readFileSync(resolve(import.meta.dirname, "../.github/workflows/release-images.yml"), "utf8");
  const cli = readFileSync(resolve(import.meta.dirname, "../scripts/release-local-preflight-cli.ts"), "utf8");
  const core = readFileSync(resolve(import.meta.dirname, "../scripts/release-local-preflight.ts"), "utf8");
  const manifest = readFileSync(resolve(import.meta.dirname, `../${RELEASE_IMAGE_SET_PINS_MANIFEST_PATH}`), "utf8");
  assert.deepEqual(RELEASE_LOCAL_TRIVY, {
    image: RELEASE_IMAGE_SET_PINS.tools.trivy_image,
    database: RELEASE_IMAGE_SET_PINS.tools.trivy_database,
    java_database: RELEASE_IMAGE_SET_PINS.tools.trivy_java_database,
    platform: "linux/amd64",
    severities: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
  });
  assert.match(core, /from "\.\/release-image-set-pins\.ts"/u);
  for (const pin of [RELEASE_LOCAL_TRIVY.image, RELEASE_LOCAL_TRIVY.database, RELEASE_LOCAL_TRIVY.java_database]) {
    const exactPin = new RegExp(pin.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u");
    assert.match(workflow, exactPin);
    assert.match(manifest, exactPin);
    assert.equal(core.match(exactPin), null, "preflight must not duplicate a release Trivy pin literal");
  }
  for (const required of [
    '"--skip-db-update"',
    '"--skip-java-db-update"',
    '"--offline-scan"',
    '"--scanners"',
    '"vuln"',
    '"UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"',
    '"--ignore-unfixed=false"',
    '"--exit-code"',
    '"0"',
    '"--format"',
    '"json"',
    '"--list-all-pkgs"',
  ]) {
    assert.ok(cli.includes(required), `missing exact scan argument ${required}`);
  }
  for (const forbidden of ['"push"', '"login"', "cosign", "gh workflow", "--ignore-status", "--vex", "--ignorefile"]) {
    assert.equal(cli.toLowerCase().includes(forbidden), false, `forbidden route present: ${forbidden}`);
  }
  assert.match(cli, /"--pull", "never"/u);
  assert.match(cli, /docker image input must be an exact digest reference/u);
});
