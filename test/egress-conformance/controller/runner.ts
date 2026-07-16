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
    | "client-compatibility";
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

/**
 * Candidate-specific orchestration implements this boundary. Proxy work must run
 * out of process; adapter methods must never perform blocking candidate work in
 * the controller process. cleanup() forcibly terminates all per-case resources
 * and acknowledges their termination before resolving.
 */
export interface ConformanceAdapter {
  readonly name: string;
  execute(test: Readonly<ConformanceCase>, signal: AbortSignal): Promise<AdapterResult>;
  cleanup(test: Readonly<ConformanceCase>): Promise<void>;
  teardown(): Promise<void>;
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
  releaseEligibility?: "enabled" | "disabled-candidate";
  skips?: Readonly<Record<string, SkipApproval>>;
  redactValues?: readonly string[];
  adapter: ConformanceAdapter;
  cleanupTimeoutMs: number;
  teardownTimeoutMs: number;
  now?: () => Date;
}

export interface SecurityTestResult {
  id: string;
  group: string;
  result: ConformanceResult;
  release_eligible: boolean;
  duration_ms: number;
  dependency_modes: Record<string, DependencyMode>;
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
]);
const profiles = new Set<ConformanceProfile>(["insecure-container", "macos-vm-dev", "linux-kvm"]);
const dependencies = new Set<DependencyName>(dependencyNames);
const revisionPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const utcTimestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

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
    if (!idPattern.test(test.id) || test.id.startsWith("runner.")) throw new Error(`invalid case id: ${test.id}`);
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
  if (!profiles.has(options.profile)) throw new Error("invalid conformance profile");
  if (options.authority !== "functional-only" && options.authority !== "authoritative-local") {
    throw new Error("invalid evidence authority");
  }
  if (options.profile !== "linux-kvm" && options.authority !== "functional-only") {
    throw new Error(`${options.profile} cannot produce authoritative evidence`);
  }
  if (!Array.isArray(options.components) || options.components.length === 0) {
    throw new Error("at least one versioned component is required");
  }
  for (const component of options.components) {
    if (component.name.trim().length === 0 || component.version.trim().length === 0) {
      throw new Error("component names and versions must not be empty");
    }
    if (component.image_digest !== undefined && !digestPattern.test(component.image_digest)) {
      throw new Error(`invalid image digest for ${component.name}`);
    }
  }
  for (const name of dependencyNames) {
    const dependency = options.dependencies[name];
    if (dependency === undefined) throw new Error(`missing dependency declaration: ${name}`);
    if (!new Set<DependencyMode>(["real", "stubbed", "not-applicable"]).has(dependency.mode)) {
      throw new Error(`invalid dependency mode: ${name}`);
    }
    if (dependency.implementation.trim().length === 0) throw new Error(`empty dependency implementation: ${name}`);
  }
  if (
    options.environment.os.trim().length === 0 ||
    options.environment.architecture.trim().length === 0 ||
    options.environment.runner.trim().length === 0
  ) {
    throw new Error("environment identity fields must not be empty");
  }
  if (!Array.isArray(options.knownLimitations) || options.knownLimitations.some((item) => item.trim().length === 0)) {
    throw new Error("known limitations must be non-empty strings");
  }
  if (options.redactValues?.some((value) => value.length === 0)) {
    throw new Error("redaction values must not be empty");
  }
  if (options.adapter.name.trim().length === 0) throw new Error("adapter name must not be empty");
  for (const [name, value] of [
    ["cleanup", options.cleanupTimeoutMs],
    ["teardown", options.teardownTimeoutMs],
  ] as const) {
    if (!Number.isInteger(value) || value < 100 || value > 300_000) {
      throw new Error(`${name} timeout must be an integer from 100 to 300000ms`);
    }
  }
}

function redact(value: string, secrets: readonly string[]): string {
  let output = value;
  for (const secret of [...secrets]
    .filter((item) => item.length > 0)
    .sort((left, right) => right.length - left.length)) {
    output = output.replaceAll(secret, "[REDACTED]");
  }
  output = output.replace(/[\r\n\t]+/g, " ").trim();
  return output.slice(0, 2_048);
}

function relevantModes(test: ConformanceCase, options: RunnerOptions): Partial<Record<DependencyName, DependencyMode>> {
  return Object.fromEntries(test.dependencies.map((name) => [name, options.dependencies[name].mode]));
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function validateAdapterResult(value: unknown): AdapterResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("adapter returned a malformed result");
  }
  const result = value as Record<string, unknown>;
  const keys = Object.keys(result);
  if (
    typeof result.passed !== "boolean" ||
    (result.diagnosticsRedacted !== undefined && typeof result.diagnosticsRedacted !== "string") ||
    keys.some((key) => key !== "passed" && key !== "diagnosticsRedacted")
  ) {
    throw new Error("adapter returned a malformed result");
  }
  return result as unknown as AdapterResult;
}

async function executeWithTimeout(test: Readonly<ConformanceCase>, options: RunnerOptions): Promise<AdapterResult> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error(`case timed out after ${test.timeout_ms}ms`)),
    test.timeout_ms,
  );
  try {
    const result = await Promise.race([
      options.adapter.execute(test, controller.signal),
      new Promise<never>((_resolve, reject) => {
        controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
      }),
    ]);
    return validateAdapterResult(result);
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
  const cases = structuredClone(manifest.cases);
  for (const test of cases) {
    Object.freeze(test.profiles);
    Object.freeze(test.dependencies);
    Object.freeze(test);
  }
  const caseIds = new Set(cases.map((test) => test.id));
  for (const skippedId of Object.keys(options.skips ?? {})) {
    if (!caseIds.has(skippedId)) throw new Error(`skip approval refers to unknown case: ${skippedId}`);
  }

  const now = options.now ?? (() => new Date());
  const started = now();
  if (!Number.isFinite(started.getTime())) throw new Error("runner clock returned an invalid start time");
  const startedClock = performance.now();
  const tests: SecurityTestResult[] = [];
  let adapterUsable = true;
  let lifecycleFailed = false;

  try {
    for (const test of cases) {
      const caseStarted = performance.now();
      const modes = relevantModes(test, options);
      if (!test.profiles.includes(options.profile) || Object.values(modes).includes("not-applicable")) {
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
      const skip = options.skips?.[test.id];
      if (skip !== undefined) {
        const reviewAt = Date.parse(skip.review_at);
        const valid =
          skip.owner.trim().length > 0 &&
          skip.reason.trim().length > 0 &&
          utcTimestampPattern.test(skip.review_at) &&
          Number.isFinite(reviewAt) &&
          reviewAt > now().getTime();
        tests.push({
          id: test.id,
          group: test.group,
          result: valid ? "skipped-with-approved-reason" : "fail",
          release_eligible: false,
          duration_ms: 0,
          dependency_modes: modes,
          ...(valid
            ? { skip_approval: skip }
            : { diagnostics_redacted: "skip approval is incomplete, invalid, or expired" }),
        });
        continue;
      }
      if (!adapterUsable) {
        tests.push({
          id: test.id,
          group: test.group,
          result: "fail",
          release_eligible: false,
          duration_ms: 0,
          dependency_modes: modes,
          diagnostics_redacted: "case not executed after an earlier adapter cleanup failure",
        });
        continue;
      }

      let result: ConformanceResult = "fail";
      let diagnostics: string | undefined;
      try {
        const adapterResult = await executeWithTimeout(test, options);
        result = resultFor(adapterResult.passed, modes);
        diagnostics = adapterResult.diagnosticsRedacted;
      } catch (error) {
        diagnostics = error instanceof Error ? error.message : "unknown adapter failure";
      }

      try {
        await withTimeout(options.adapter.cleanup(test), options.cleanupTimeoutMs, `cleanup for ${test.id}`);
      } catch (error) {
        adapterUsable = false;
        lifecycleFailed = true;
        result = "fail";
        const cleanupDiagnostic = error instanceof Error ? error.message : "unknown adapter cleanup failure";
        diagnostics =
          diagnostics === undefined ? cleanupDiagnostic : `${diagnostics}; cleanup failed: ${cleanupDiagnostic}`;
      }

      tests.push({
        id: test.id,
        group: test.group,
        result,
        release_eligible:
          result === "pass" &&
          options.releaseEligibility !== "disabled-candidate" &&
          options.authority !== "functional-only" &&
          Object.values(modes).every((mode) => mode === "real"),
        duration_ms: Math.round(performance.now() - caseStarted),
        dependency_modes: modes,
        ...(diagnostics === undefined ? {} : { diagnostics_redacted: redact(diagnostics, options.redactValues ?? []) }),
      });
    }
  } finally {
    try {
      await withTimeout(options.adapter.teardown(), options.teardownTimeoutMs, "adapter teardown");
    } catch (error) {
      lifecycleFailed = true;
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
  if (!Number.isFinite(completed.getTime()) || completed < started) {
    throw new Error("runner clock returned an invalid completion time");
  }
  for (const test of tests) {
    if (
      test.result === "skipped-with-approved-reason" &&
      Date.parse(test.skip_approval?.review_at ?? "") <= completed.getTime()
    ) {
      test.result = "fail";
      delete test.skip_approval;
      test.diagnostics_redacted = "skip approval expired before report completion";
    }
    if (lifecycleFailed) test.release_eligible = false;
  }
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
