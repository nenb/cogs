import { createHash } from "node:crypto";
import { capturePrivateBytes } from "./private-bytes.ts";
import { RELEASE_IMAGE_SET_PINS } from "./release-image-set-pins.ts";

const MAX_REPORT_BYTES = 256 * 1024 * 1024;
const MAX_RESULTS = 1024;
const MAX_PACKAGES = 500_000;
const MAX_FINDINGS = 250_000;
const MAX_STRING = 16_384;
const SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const SEVERITY_SET = new Set<string>(SEVERITIES);
const CLASSES = new Set(["os-pkgs", "lang-pkgs"]);

export const RELEASE_LOCAL_TRIVY = Object.freeze({
  image: RELEASE_IMAGE_SET_PINS.tools.trivy_image,
  database: RELEASE_IMAGE_SET_PINS.tools.trivy_database,
  java_database: RELEASE_IMAGE_SET_PINS.tools.trivy_java_database,
  platform: "linux/amd64",
  severities: SEVERITIES,
});

export type ReleaseLocalRole = "worker" | "sandbox";
export type ReleaseLocalInputIdentity = Readonly<
  | { kind: "docker-image"; exact_reference: string }
  | {
      kind: "oci-layout";
      exact_reference: null;
      index_sha256: string;
      subject_manifest_digest: string;
    }
>;

type JsonPrimitive = string | number | boolean | null;
export type ReleaseLocalJson = JsonPrimitive | ReleaseLocalJson[] | { [key: string]: ReleaseLocalJson };
type JsonObject = { [key: string]: ReleaseLocalJson };

export type ReleaseTrivyDatabaseType = "vulnerability" | "java";

export const RELEASE_TRIVY_DATABASE_EXPECTATIONS = Object.freeze({
  vulnerability: Object.freeze({
    metadata_schema: "trivy-db-cache-metadata/v1",
    database_version: 2,
    oci_manifest_schema_version: 2,
    oci_artifact_type: "application/vnd.aquasec.trivy.config.v1+json",
    oci_layer_media_type: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
  }),
  java: Object.freeze({
    metadata_schema: "trivy-db-cache-metadata/v1",
    database_version: 1,
    oci_manifest_schema_version: 2,
    oci_artifact_type: "application/vnd.aquasec.trivy.config.v1+json",
    oci_layer_media_type: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
  }),
});

export type ReleaseTrivyDatabaseMetadata = Readonly<{
  schema: "trivy-db-cache-metadata/v1";
  type: ReleaseTrivyDatabaseType;
  version: number;
  updated_at: string;
  next_update: string;
  downloaded_at: string;
  evaluated_at: string;
  current: boolean;
}>;

export type ReleaseLocalDatabaseObservation = Readonly<{
  vulnerability: ReleaseTrivyDatabaseMetadata;
  java: ReleaseTrivyDatabaseMetadata;
}>;

export type ReleaseLocalLedgerContext = Readonly<{
  role: ReleaseLocalRole;
  input: ReleaseLocalInputIdentity;
  expectedArtifactName: string;
  databases: ReleaseLocalDatabaseObservation;
}>;

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJson(value: ReleaseLocalJson): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("non-JSON value");
  return encoded;
}

export function canonicalReleaseLocalBytes(value: ReleaseLocalJson): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}: object required`);
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label}: plain object required`);
  return value as Record<string, unknown>;
}

function boundedString(value: unknown, label: string, allowEmpty = false): string {
  if (
    typeof value !== "string" ||
    value.length > MAX_STRING ||
    (!allowEmpty && value.length === 0) ||
    value.includes("\u0000")
  ) {
    throw new Error(`${label}: invalid string`);
  }
  return value;
}

function nullableString(value: unknown, label: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  return boundedString(value, label);
}

const TRIVY_METADATA_KEYS = new Set(["Version", "NextUpdate", "UpdatedAt", "DownloadedAt"]);
const STRICT_UTC_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u;

function parseTimestamp(value: unknown, label: string): { source: string; nanoseconds: bigint } {
  const source = boundedString(value, label, false);
  const match = STRICT_UTC_TIMESTAMP.exec(source);
  if (match === null) throw new Error(`${label}: invalid UTC timestamp`);
  const [, yearSource, monthSource, daySource, hourSource, minuteSource, secondSource, fractionSource = ""] = match;
  const parts = [yearSource, monthSource, daySource, hourSource, minuteSource, secondSource].map(Number);
  const [year, month, day, hour, minute, second] = parts;
  if (
    parts.some((part) => !Number.isSafeInteger(part)) ||
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new Error(`${label}: invalid UTC timestamp`);
  }
  const epochMilliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(epochMilliseconds);
  if (
    !Number.isFinite(epochMilliseconds) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  ) {
    throw new Error(`${label}: invalid UTC timestamp`);
  }
  const fraction = BigInt(fractionSource.padEnd(9, "0"));
  return { source, nanoseconds: BigInt(epochMilliseconds) * 1_000_000n + fraction };
}

export function inspectTrivyDatabaseMetadata(
  input: unknown,
  evaluatedAt: Date,
  type: ReleaseTrivyDatabaseType,
  minimumValidUntil?: Date,
): ReleaseTrivyDatabaseMetadata {
  const captured = capturePrivateBytes(input, 64 * 1024);
  if (captured.bytes === null) throw new Error("database metadata: bounded private bytes required");
  let parsed: unknown;
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes);
    parsed = JSON.parse(source);
  } catch {
    throw new Error("database metadata: invalid UTF-8 JSON");
  }
  const compact = JSON.stringify(parsed);
  if (source !== compact && source !== `${compact}\n`) throw new Error("database metadata: strict JSON required");
  const value = asObject(parsed, "database metadata");
  const keys = Object.keys(value);
  if (keys.length !== TRIVY_METADATA_KEYS.size || keys.some((key) => !TRIVY_METADATA_KEYS.has(key))) {
    throw new Error("database metadata: exact schema required");
  }
  const expectation = RELEASE_TRIVY_DATABASE_EXPECTATIONS[type];
  if (expectation === undefined) throw new Error("database metadata: unsupported database type");
  if (value.Version !== expectation.database_version) {
    throw new Error(`database metadata: ${type} database version mismatch`);
  }
  const updated = parseTimestamp(value.UpdatedAt, "database metadata.UpdatedAt");
  const next = parseTimestamp(value.NextUpdate, "database metadata.NextUpdate");
  const downloaded = parseTimestamp(value.DownloadedAt, "database metadata.DownloadedAt");
  const evaluatedMilliseconds = evaluatedAt.getTime();
  const minimumMilliseconds = minimumValidUntil?.getTime();
  if (!Number.isFinite(evaluatedMilliseconds)) throw new Error("database metadata: invalid evaluation time");
  if (
    minimumMilliseconds !== undefined &&
    (!Number.isFinite(minimumMilliseconds) || minimumMilliseconds < evaluatedMilliseconds)
  ) {
    throw new Error("database metadata: invalid minimum validity time");
  }
  const evaluatedNanoseconds = BigInt(evaluatedMilliseconds) * 1_000_000n;
  if (updated.nanoseconds > evaluatedNanoseconds) throw new Error("database metadata: UpdatedAt is in the future");
  if (next.nanoseconds <= updated.nanoseconds || downloaded.nanoseconds < updated.nanoseconds) {
    throw new Error("database metadata: inconsistent update interval");
  }
  if (minimumMilliseconds !== undefined && next.nanoseconds <= BigInt(minimumMilliseconds) * 1_000_000n) {
    throw new Error("database metadata: insufficient run validity");
  }
  return Object.freeze({
    schema: expectation.metadata_schema,
    type,
    version: expectation.database_version,
    updated_at: updated.source,
    next_update: next.source,
    downloaded_at: downloaded.source,
    evaluated_at: evaluatedAt.toISOString(),
    current: evaluatedNanoseconds < next.nanoseconds,
  });
}

function parseJsonReport(bytes: Uint8Array): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("Trivy report: invalid UTF-8 JSON");
  }
  return asObject(parsed, "Trivy report");
}

function optionalObject(value: unknown, label: string): Record<string, unknown> | null {
  if (value === undefined || value === null) return null;
  return asObject(value, label);
}

function severity(value: unknown, label: string): (typeof SEVERITIES)[number] {
  const selected = boundedString(value, label);
  if (!SEVERITY_SET.has(selected)) throw new Error(`${label}: unsupported severity`);
  return selected as (typeof SEVERITIES)[number];
}

function packageSecurityIdentity(inventory: Record<string, unknown>): JsonObject {
  return {
    name: boundedString(inventory.Name, "package.Name"),
    version: boundedString(inventory.Version, "package.Version"),
    source_name: nullableString(inventory.SrcName, "package.SrcName"),
    source_version: nullableString(inventory.SrcVersion, "package.SrcVersion"),
  };
}

function sourcePackage(
  resultClass: string,
  vulnerability: Record<string, unknown>,
  packages: Map<string, Record<string, unknown>>,
): JsonObject {
  const packageId = boundedString(vulnerability.PkgID, "vulnerability.PkgID");
  const packageName = boundedString(vulnerability.PkgName, "vulnerability.PkgName");
  const installedVersion = boundedString(vulnerability.InstalledVersion, "vulnerability.InstalledVersion");
  const inventory = packages.get(packageId);
  if (inventory === undefined) {
    return {
      name: packageName,
      version: installedVersion,
      mapping: resultClass === "os-pkgs" ? "binary-package-fallback-unverified" : "language-package-self",
    };
  }
  const identity = packageSecurityIdentity(inventory);
  const inventoryName = identity.name as string;
  const inventoryVersion = identity.version as string;
  const sourceName = identity.source_name as string | null;
  const sourceVersion = identity.source_version as string | null;
  return {
    name: sourceName ?? inventoryName,
    version: sourceVersion ?? inventoryVersion,
    mapping:
      resultClass === "lang-pkgs"
        ? "language-package-self"
        : sourceName === null
          ? "scanner-package-self"
          : "scanner-authenticated-source-package",
  };
}

function vendorSeverity(value: unknown): JsonObject {
  if (value === undefined || value === null) return {};
  const object = asObject(value, "vulnerability.VendorSeverity");
  if (Object.keys(object).length > 64) throw new Error("vulnerability.VendorSeverity: too many sources");
  const result: JsonObject = {};
  for (const [key, item] of Object.entries(object)) {
    boundedString(key, "vulnerability.VendorSeverity key");
    if (!Number.isSafeInteger(item) || (item as number) < 0 || (item as number) >= SEVERITIES.length) {
      throw new Error(`vulnerability.VendorSeverity.${key}: unsupported numeric severity`);
    }
    result[key] = SEVERITIES[item as number] as ReleaseLocalJson;
  }
  return result;
}

function dataSource(value: unknown): JsonObject | null {
  const object = optionalObject(value, "vulnerability.DataSource");
  if (object === null) return null;
  return {
    id: nullableString(object.ID, "vulnerability.DataSource.ID"),
    name: nullableString(object.Name, "vulnerability.DataSource.Name"),
    url: nullableString(object.URL, "vulnerability.DataSource.URL"),
  };
}

function findingIdentity(row: JsonObject): JsonObject {
  return {
    class: row.class as ReleaseLocalJson,
    target: row.target as ReleaseLocalJson,
    type: row.type as ReleaseLocalJson,
    vulnerability_id: row.vulnerability_id as ReleaseLocalJson,
    package_id: row.package_id as ReleaseLocalJson,
    package_name: row.package_name as ReleaseLocalJson,
    installed_version: row.installed_version as ReleaseLocalJson,
    fixed_version: row.fixed_version as ReleaseLocalJson,
    severity: row.severity as ReleaseLocalJson,
    status: row.status as ReleaseLocalJson,
  };
}

function increment(target: Record<string, number>, key: string): void {
  target[key] = (target[key] ?? 0) + 1;
}

function numericPartition(keys: readonly string[]): Record<string, number> {
  return Object.fromEntries(keys.map((key) => [key.toLowerCase(), 0]));
}

export function createReleaseLocalLedger(
  reportInput: unknown,
  context: ReleaseLocalLedgerContext,
): Readonly<JsonObject> {
  const captured = capturePrivateBytes(reportInput, MAX_REPORT_BYTES);
  if (captured.bytes === null) throw new Error("Trivy report: bounded private bytes required");
  const report = parseJsonReport(captured.bytes);
  if (report.SchemaVersion !== 2 || report.ArtifactType !== "container_image") {
    throw new Error("Trivy report: release schema or artifact type mismatch");
  }
  if (report.ArtifactName !== context.expectedArtifactName) {
    throw new Error("Trivy report: exact artifact name mismatch");
  }
  const metadata = asObject(report.Metadata, "Trivy report.Metadata");
  if (context.input.kind === "docker-image") {
    if (!Array.isArray(metadata.RepoDigests) || !metadata.RepoDigests.includes(context.input.exact_reference)) {
      throw new Error("Trivy report: exact local digest absent from RepoDigests");
    }
  }
  const os = asObject(metadata.OS, "Trivy report.Metadata.OS");
  const osFamily = boundedString(os.Family, "Trivy report.Metadata.OS.Family");
  const osName = boundedString(os.Name, "Trivy report.Metadata.OS.Name");
  if (!Array.isArray(report.Results) || report.Results.length < 1 || report.Results.length > MAX_RESULTS) {
    throw new Error("Trivy report: bounded nonempty Results required");
  }

  const rows: JsonObject[] = [];
  let sawOsPackages = false;
  let osPackageCount = 0;
  let packageCount = 0;
  for (const [resultIndex, resultValue] of report.Results.entries()) {
    const result = asObject(resultValue, `Trivy report.Results[${resultIndex}]`);
    const resultClass = boundedString(result.Class, `Results[${resultIndex}].Class`);
    if (!CLASSES.has(resultClass)) throw new Error("Trivy report: unexpected result class");
    const target = boundedString(result.Target, `Results[${resultIndex}].Target`);
    const type = boundedString(result.Type, `Results[${resultIndex}].Type`);
    if (resultClass === "os-pkgs") {
      sawOsPackages = true;
      if (type !== osFamily) throw new Error("Trivy report: OS result type mismatch");
      if (!Array.isArray(result.Packages) || result.Packages.length < 1) {
        throw new Error("Trivy report: nonempty OS package inventory required");
      }
      osPackageCount += result.Packages.length;
    }
    const packages = new Map<string, Record<string, unknown>>();
    if (result.Packages !== undefined && result.Packages !== null) {
      if (!Array.isArray(result.Packages)) throw new Error("Trivy report: Packages must be an array");
      packageCount += result.Packages.length;
      if (packageCount > MAX_PACKAGES) throw new Error("Trivy report: package bound exceeded");
      for (const [packageIndex, packageValue] of result.Packages.entries()) {
        const item = asObject(packageValue, `Results[${resultIndex}].Packages[${packageIndex}]`);
        const id = boundedString(item.ID, "package.ID");
        const identity = packageSecurityIdentity(item);
        const existing = packages.get(id);
        if (existing !== undefined) {
          if (canonicalJson(packageSecurityIdentity(existing)) !== canonicalJson(identity)) {
            throw new Error("Trivy report: conflicting duplicate package inventory ID");
          }
        } else {
          packages.set(id, item);
        }
      }
    }
    if (
      result.Vulnerabilities !== undefined &&
      result.Vulnerabilities !== null &&
      !Array.isArray(result.Vulnerabilities)
    ) {
      throw new Error("Trivy report: Vulnerabilities must be null or an array");
    }
    const vulnerabilities = (result.Vulnerabilities ?? []) as unknown[];
    if (rows.length + vulnerabilities.length > MAX_FINDINGS) throw new Error("Trivy report: finding bound exceeded");
    for (const [findingIndex, findingValue] of vulnerabilities.entries()) {
      const finding = asObject(findingValue, `Results[${resultIndex}].Vulnerabilities[${findingIndex}]`);
      const selectedSeverity = severity(finding.Severity, "vulnerability.Severity");
      const fixedVersion = nullableString(finding.FixedVersion, "vulnerability.FixedVersion");
      const source = sourcePackage(resultClass, finding, packages);
      const row: JsonObject = {
        class: resultClass,
        target,
        type,
        vulnerability_id: boundedString(finding.VulnerabilityID, "vulnerability.VulnerabilityID"),
        package_id: boundedString(finding.PkgID, "vulnerability.PkgID"),
        package_name: boundedString(finding.PkgName, "vulnerability.PkgName"),
        installed_version: boundedString(finding.InstalledVersion, "vulnerability.InstalledVersion"),
        fixed_version: fixedVersion,
        fixedness: fixedVersion === null ? "no-known-fixed-version" : "fixed-version-available",
        severity: selectedSeverity,
        severity_source: nullableString(finding.SeveritySource, "vulnerability.SeveritySource"),
        vendor_severity: vendorSeverity(finding.VendorSeverity),
        status: nullableString(finding.Status, "vulnerability.Status") ?? "unknown",
        data_source: dataSource(finding.DataSource),
        primary_url: nullableString(finding.PrimaryURL, "vulnerability.PrimaryURL"),
        source_package: source,
      };
      row.finding_key_sha256 = createHash("sha256")
        .update(canonicalReleaseLocalBytes(findingIdentity(row)))
        .digest("hex");
      rows.push(row);
    }
  }
  if (!sawOsPackages || osPackageCount < 1) {
    throw new Error("Trivy report: supported nonempty OS package inventory required");
  }

  rows.sort((left, right) =>
    compareCodePoints(
      `${left.finding_key_sha256 as string}\u0000${canonicalJson(left)}`,
      `${right.finding_key_sha256 as string}\u0000${canonicalJson(right)}`,
    ),
  );
  const severityCounts = numericPartition(SEVERITIES);
  const fixednessCounts: Record<string, number> = {
    "fixed-version-available": 0,
    "no-known-fixed-version": 0,
  };
  const classCounts: Record<string, number> = { "lang-pkgs": 0, "os-pkgs": 0 };
  const statusCounts: Record<string, number> = {};
  const categoryMap = new Map<string, JsonObject & { occurrence_count: number }>();
  const sourceMap = new Map<string, JsonObject & { occurrence_count: number; vulnerability_ids: ReleaseLocalJson[] }>();
  const vulnerabilityIds = new Set<string>();
  const sourceAdvisories = new Set<string>();

  for (const row of rows) {
    const selectedSeverity = row.severity as string;
    increment(severityCounts, selectedSeverity.toLowerCase());
    increment(fixednessCounts, row.fixedness as string);
    increment(classCounts, row.class as string);
    increment(statusCounts, row.status as string);
    vulnerabilityIds.add(row.vulnerability_id as string);
    const source = row.source_package as JsonObject;
    const sourceKey = [row.class, row.type, source.name, source.version, source.mapping].join("\u0000");
    sourceAdvisories.add(`${sourceKey}\u0000${row.vulnerability_id as string}`);
    const sourceRow = sourceMap.get(sourceKey) ?? {
      class: row.class as ReleaseLocalJson,
      type: row.type as ReleaseLocalJson,
      source_package: source,
      occurrence_count: 0,
      vulnerability_ids: [],
    };
    sourceRow.occurrence_count += 1;
    (sourceRow.vulnerability_ids as ReleaseLocalJson[]).push(row.vulnerability_id as string);
    sourceMap.set(sourceKey, sourceRow);

    const data = row.data_source as JsonObject | null;
    const categoryKey = [
      row.class,
      row.type,
      row.severity,
      row.status,
      row.fixedness,
      row.severity_source ?? "",
      data?.id ?? "",
      source.name,
      source.version,
      source.mapping,
    ].join("\u0000");
    const category = categoryMap.get(categoryKey) ?? {
      class: row.class as ReleaseLocalJson,
      type: row.type as ReleaseLocalJson,
      severity: row.severity as ReleaseLocalJson,
      status: row.status as ReleaseLocalJson,
      fixedness: row.fixedness as ReleaseLocalJson,
      severity_source: row.severity_source as ReleaseLocalJson,
      data_source_id: (data?.id ?? null) as ReleaseLocalJson,
      source_package: source,
      occurrence_count: 0,
    };
    category.occurrence_count += 1;
    categoryMap.set(categoryKey, category);
  }
  const sortAggregate = <T extends JsonObject>(values: T[]): T[] =>
    values.sort((left, right) => compareCodePoints(canonicalJson(left), canonicalJson(right)));
  const sourcePackages = sortAggregate([...sourceMap.values()]).map((row) => ({
    ...row,
    vulnerability_ids: [...new Set(row.vulnerability_ids as string[])].sort(compareCodePoints),
  }));
  const high = severityCounts.high ?? 0;
  const critical = severityCounts.critical ?? 0;
  const databaseCurrent = context.databases.vulnerability.current && context.databases.java.current;
  const gateCount = high + critical;
  const reasonCode = !databaseCurrent
    ? "DATABASE_EXPIRED"
    : gateCount === 0
      ? "LOCAL_POLICY_GATE_OBSERVED_ZERO"
      : "VULNERABILITY_GATE_BLOCKED";

  return Object.freeze({
    version: "cogs.release-local-vulnerability-ledger/v1",
    authority: "bounded-local-trivy-observation",
    role: context.role,
    input: context.input as unknown as ReleaseLocalJson,
    target: { os: "linux", architecture: "amd64", variant: null },
    tools: {
      trivy_image: RELEASE_LOCAL_TRIVY.image,
      trivy_database: RELEASE_LOCAL_TRIVY.database,
      trivy_java_database: RELEASE_LOCAL_TRIVY.java_database,
    },
    database_observation: context.databases as unknown as ReleaseLocalJson,
    scanner_policy: {
      scanners: ["vuln"],
      severities: [...SEVERITIES],
      package_types: ["os", "library"],
      ignore_unfixed: false,
      ignore_statuses: [],
      ignore_file_loaded: false,
      ignore_policy_loaded: false,
      vex_loaded: false,
      suppressions: false,
      offline_scan: true,
      exit_code: 0,
      diagnostic_list_all_packages: true,
      authoritative_gate_population: "all-raw-package-findings",
    },
    report: {
      sha256: createHash("sha256").update(captured.bytes).digest("hex"),
      size_bytes: captured.bytes.byteLength,
      schema_version: 2,
      artifact_name: context.expectedArtifactName,
      artifact_type: "container_image",
      os: { family: osFamily, name: osName },
      package_inventory_count: packageCount,
      os_package_inventory_count: osPackageCount,
    },
    counts: {
      raw_findings: rows.length,
      severity: severityCounts,
      fixedness: fixednessCounts,
      class: classCounts,
      status: Object.fromEntries(
        Object.entries(statusCounts).sort(([left], [right]) => compareCodePoints(left, right)),
      ),
      unique_vulnerability_ids: vulnerabilityIds.size,
      unique_source_advisories: sourceAdvisories.size,
      source_package_roots: sourcePackages.length,
    },
    categories: sortAggregate([...categoryMap.values()]),
    source_packages: sourcePackages,
    findings: rows,
    gate: {
      policy: "zero-raw-high-critical-including-unfixed",
      finding_count: gateCount,
      high,
      critical,
      includes_unfixed: true,
      passed: databaseCurrent && gateCount === 0,
    },
    claims: {
      local_scan_observed: true,
      database_current_at_evaluation: databaseCurrent,
      publication_performed: false,
      registry_write_performed: false,
      signing_performed: false,
      workflow_dispatched: false,
      vulnerability_truth_established: false,
      publication_truth_established: false,
      readiness_promoted: false,
      production_ready: false,
      release_eligible: false,
    },
    reason_code: reasonCode,
  });
}

export const RELEASE_LOCAL_PREFLIGHT_LIMITS = Object.freeze({
  max_report_bytes: MAX_REPORT_BYTES,
  max_results: MAX_RESULTS,
  max_packages: MAX_PACKAGES,
  max_findings: MAX_FINDINGS,
});
