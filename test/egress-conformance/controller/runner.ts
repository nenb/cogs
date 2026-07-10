import { performance } from "node:perf_hooks";

export const dependencyNames = ["authorization", "audit", "revocation", "identity", "network_enforcement"] as const;

export type DependencyName = (typeof dependencyNames)[number];
export type DependencyMode = "real" | "stubbed" | "not-applicable";
export type ConformanceProfile = "insecure-container" | "macos-vm-dev" | "linux-kvm";
export type ConformanceResult = "pass" | "fail" | "stubbed" | "not-applicable" | "skipped-with-approved-reason";

export interface ConformanceCase {
  id: string;
  group:
    | "identity-route"
    | "http-parsing"
    | "credential-handling"
    | "bypass-resistance"
    | "audit-failure"
    | "revocation"
    | "client-compatibility"
    | "runner-control";
  timeout_ms: number;
  profiles: ConformanceProfile[];
  dependencies: DependencyName[];
}

export interface CaseManifest {
  version: "cogs.egress-cases/v1alpha1";
  cases: ConformanceCase[];
}

export interface SkipApproval {
  owner: string;
  reason: string;
  review_at: string;
}

export interface AdapterResult {
  passed: boolean;
  diagnosticsRedacted?: string;
}

export interface ReportComponent {
  name: string;
  version: string;
  image_digest?: string;
}

export interface RunnerOptions {
  reportId: string;
  sourceRevision: string;
  profile: ConformanceProfile;
  authority: "functional-only" | "authoritative-local";
  environment: {
    os: string;
    architecture: string;
    runner: string;
    runner_image?: string;
    runtime_versions: Record<string, string>;
    metadata?: Record<string, string | number | boolean | null>;
  };
  components: ReportComponent[];
  dependencies: Record<DependencyName, { mode: DependencyMode; implementation: string; version?: string }>;
  knownLimitations: string[];
  skips?: Readonly<Record<string, SkipApproval>>;
  redactValues?: readonly string[];
  execute(test: ConformanceCase, signal: AbortSignal): Promise<AdapterResult>;
  teardown(): Promise<void>;
  now?: () => Date;
}

export interface SecurityTestResult {
  id: string;
  group: string;
  result: ConformanceResult;
  release_eligible: boolean;
  duration_ms: number;
  dependency_modes: Partial<Record<DependencyName, DependencyMode>>;
  diagnostics_redacted?: string;
  skip_approval?: SkipApproval;
}

export interface SecurityReport {
  version: "cogs.security-report/v1alpha1";
  report_id: string;
  source_revision: string;
  profile: ConformanceProfile;
  authority: "functional-only" | "authoritative-local";
  started_at: string;
  completed_at: string;
  duration_ms: number;
  environment: RunnerOptions["environment"];
  components: ReportComponent[];
  dependencies: RunnerOptions["dependencies"];
  tests: SecurityTestResult[];
  known_limitations: string[];
}

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const groups = new Set<ConformanceCase["group"]>([
  "identity-route",
  "http-parsing",
  "credential-handling",
  "bypass-resistance",
  "audit-failure",
  "revocation",
  "client-compatibility",
  "runner-control",
]);
const profiles = new Set<ConformanceProfile>(["insecure-container", "macos-vm-dev", "linux-kvm"]);
const dependencies = new Set<DependencyName>(dependencyNames);
const revisionPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;

export function validateManifest(manifest: CaseManifest): void {
  if (
    manifest.version !== "cogs.egress-cases/v1alpha1" ||
    !Array.isArray(manifest.cases) ||
    manifest.cases.length === 0
  ) {
    throw new Error("invalid or empty egress case manifest");
  }
  const ids = new Set<string>();
  for (const test of manifest.cases) {
    if (!idPattern.test(test.id)) throw new Error(`invalid case id: ${test.id}`);
    if (ids.has(test.id)) throw new Error(`duplicate case id: ${test.id}`);
    ids.add(test.id);
    if (!groups.has(test.group)) throw new Error(`invalid group for ${test.id}`);
    if (!Number.isInteger(test.timeout_ms) || test.timeout_ms < 100 || test.timeout_ms > 300_000) {
      throw new Error(`invalid timeout for ${test.id}`);
    }
    if (
      !Array.isArray(test.profiles) ||
      test.profiles.length === 0 ||
      new Set(test.profiles).size !== test.profiles.length ||
      test.profiles.some((profile) => !profiles.has(profile))
    ) {
      throw new Error(`invalid profiles for ${test.id}`);
    }
    if (
      !Array.isArray(test.dependencies) ||
      test.dependencies.length === 0 ||
      new Set(test.dependencies).size !== test.dependencies.length ||
      test.dependencies.some((dependency) => !dependencies.has(dependency))
    ) {
      throw new Error(`invalid dependencies for ${test.id}`);
    }
  }
}

function validateOptions(options: RunnerOptions): void {
  if (!idPattern.test(options.reportId)) throw new Error("invalid report ID");
  if (!revisionPattern.test(options.sourceRevision)) throw new Error("source revision must be a full Git SHA-1");
  if (options.profile !== "linux-kvm" && options.authority !== "functional-only") {
    throw new Error(`${options.profile} cannot produce authoritative evidence`);
  }
  for (const component of options.components) {
    if (component.image_digest !== undefined && !digestPattern.test(component.image_digest)) {
      throw new Error(`invalid image digest for ${component.name}`);
    }
  }
  for (const name of dependencyNames) {
    if (options.dependencies[name] === undefined) throw new Error(`missing dependency declaration: ${name}`);
  }
}

function redact(value: string, secrets: readonly string[]): string {
  let output = value;
  for (const secret of secrets) {
    if (secret.length > 0) output = output.replaceAll(secret, "[REDACTED]");
  }
  output = output.replace(/[\r\n\t]+/g, " ").trim();
  return output.slice(0, 2_048);
}

function relevantModes(test: ConformanceCase, options: RunnerOptions): Partial<Record<DependencyName, DependencyMode>> {
  return Object.fromEntries(test.dependencies.map((name) => [name, options.dependencies[name].mode]));
}

async function executeWithTimeout(test: ConformanceCase, options: RunnerOptions): Promise<AdapterResult> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error(`case timed out after ${test.timeout_ms}ms`)),
    test.timeout_ms,
  );
  try {
    return await Promise.race([
      options.execute(test, controller.signal),
      new Promise<never>((_resolve, reject) => {
        controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function resultFor(passed: boolean, modes: Partial<Record<DependencyName, DependencyMode>>): ConformanceResult {
  if (!passed) return "fail";
  if (Object.values(modes).includes("stubbed")) return "stubbed";
  return "pass";
}

export async function runConformance(manifest: CaseManifest, options: RunnerOptions): Promise<SecurityReport> {
  validateManifest(manifest);
  validateOptions(options);
  const now = options.now ?? (() => new Date());
  const started = now();
  const startedClock = performance.now();
  const tests: SecurityTestResult[] = [];

  try {
    for (const test of manifest.cases) {
      const caseStarted = performance.now();
      const modes = relevantModes(test, options);
      const skip = options.skips?.[test.id];
      if (skip !== undefined) {
        tests.push({
          id: test.id,
          group: test.group,
          result: "skipped-with-approved-reason",
          release_eligible: false,
          duration_ms: 0,
          dependency_modes: modes,
          skip_approval: skip,
        });
        continue;
      }
      if (!test.profiles.includes(options.profile)) {
        tests.push({
          id: test.id,
          group: test.group,
          result: "not-applicable",
          release_eligible: false,
          duration_ms: 0,
          dependency_modes: modes,
        });
        continue;
      }
      try {
        const adapterResult = await executeWithTimeout(test, options);
        const result = resultFor(adapterResult.passed, modes);
        const diagnostics = adapterResult.diagnosticsRedacted;
        tests.push({
          id: test.id,
          group: test.group,
          result,
          release_eligible:
            result === "pass" &&
            options.authority !== "functional-only" &&
            Object.values(modes).every((mode) => mode === "real"),
          duration_ms: Math.round(performance.now() - caseStarted),
          dependency_modes: modes,
          ...(diagnostics === undefined
            ? {}
            : { diagnostics_redacted: redact(diagnostics, options.redactValues ?? []) }),
        });
      } catch (error) {
        tests.push({
          id: test.id,
          group: test.group,
          result: "fail",
          release_eligible: false,
          duration_ms: Math.round(performance.now() - caseStarted),
          dependency_modes: modes,
          diagnostics_redacted: redact(
            error instanceof Error ? error.message : "unknown adapter failure",
            options.redactValues ?? [],
          ),
        });
      }
    }
  } finally {
    try {
      await options.teardown();
    } catch (error) {
      tests.push({
        id: "runner.teardown",
        group: "runner-control",
        result: "fail",
        release_eligible: false,
        duration_ms: 0,
        dependency_modes: {},
        diagnostics_redacted: redact(
          error instanceof Error ? error.message : "unknown teardown failure",
          options.redactValues ?? [],
        ),
      });
    }
  }

  const completed = now();
  return {
    version: "cogs.security-report/v1alpha1",
    report_id: options.reportId,
    source_revision: options.sourceRevision,
    profile: options.profile,
    authority: options.authority,
    started_at: started.toISOString(),
    completed_at: completed.toISOString(),
    duration_ms: Math.round(performance.now() - startedClock),
    environment: options.environment,
    components: options.components,
    dependencies: options.dependencies,
    tests,
    known_limitations: options.knownLimitations,
  };
}

export function renderHumanReport(report: SecurityReport): string {
  const counts = new Map<ConformanceResult, number>();
  for (const test of report.tests) counts.set(test.result, (counts.get(test.result) ?? 0) + 1);
  const summary = [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([result, count]) => `${result}=${count}`)
    .join(", ");
  const rows = report.tests.map((test) => `| ${test.id} | ${test.group} | ${test.result} | ${test.duration_ms} |`);
  return [
    `# Egress conformance report: ${report.report_id}`,
    "",
    `- Source: \`${report.source_revision}\``,
    `- Profile: \`${report.profile}\` (${report.authority})`,
    `- Results: ${summary}`,
    "",
    "| Case | Group | Result | Duration (ms) |",
    "|---|---|---:|---:|",
    ...rows,
    "",
    "## Known limitations",
    "",
    ...(report.known_limitations.length === 0
      ? ["None recorded."]
      : report.known_limitations.map((item) => `- ${item}`)),
    "",
  ].join("\n");
}
