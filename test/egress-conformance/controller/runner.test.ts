import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { assertValidSecurityReport } from "./report.ts";
import type { AdapterResult, CaseManifest, ConformanceAdapter, RunnerOptions } from "./runner.ts";
import { renderHumanReport, runConformance, validateManifest } from "./runner.ts";

const firstCase: CaseManifest["cases"][number] = {
  id: "route.allowed",
  group: "identity-route",
  timeout_ms: 500,
  profiles: ["insecure-container", "linux-kvm"],
  dependencies: ["identity", "authorization"],
};

const manifest: CaseManifest = {
  version: "cogs.egress-cases/v1alpha1",
  cases: [
    firstCase,
    {
      id: "audit.intent-before-use",
      group: "audit-failure",
      timeout_ms: 500,
      profiles: ["insecure-container", "linux-kvm"],
      dependencies: ["audit", "authorization"],
    },
    {
      id: "bypass.direct-ipv4",
      group: "bypass-resistance",
      timeout_ms: 500,
      profiles: ["linux-kvm"],
      dependencies: ["network_enforcement"],
    },
  ],
};

function adapter(overrides: Partial<ConformanceAdapter> = {}): ConformanceAdapter {
  return {
    name: "test-adapter",
    execute: async () => ({ passed: true }),
    cleanup: async () => undefined,
    teardown: async () => undefined,
    ...overrides,
  };
}

function options(overrides: Partial<RunnerOptions> = {}): RunnerOptions {
  return {
    reportId: "egress-test",
    sourceRevision: "a".repeat(40),
    profile: "insecure-container",
    authority: "functional-only",
    environment: {
      os: "linux",
      architecture: "x86_64",
      runner: "node-test",
      runtime_versions: { node: process.version },
    },
    components: [{ name: "candidate", version: "test", image_digest: `sha256:${"b".repeat(64)}` }],
    dependencies: {
      authorization: { mode: "stubbed", implementation: "fixture-authz" },
      audit: { mode: "stubbed", implementation: "fixture-audit" },
      revocation: { mode: "stubbed", implementation: "fixture-revocation" },
      identity: { mode: "real", implementation: "candidate-capability" },
      network_enforcement: { mode: "not-applicable", implementation: "insecure profile" },
    },
    knownLimitations: ["unit test"],
    adapter: adapter(),
    cleanupTimeoutMs: 500,
    teardownTimeoutMs: 500,
    now: () => new Date("2026-07-10T12:00:00Z"),
    ...overrides,
  };
}

test("runner is deterministic, applicability-aware, stub-aware, redacted, and human-readable", async () => {
  const report = await runConformance(
    manifest,
    options({
      redactValues: ["fixture-secret"],
      adapter: adapter({
        execute: async (conformanceCase) => ({
          passed: true,
          diagnosticsRedacted: `case=${conformanceCase.id} token=fixture-secret\n`,
        }),
      }),
    }),
  );

  assertValidSecurityReport(report);
  assert.deepEqual(
    report.tests.map(({ id, result, release_eligible }) => ({ id, result, release_eligible })),
    [
      { id: "route.allowed", result: "stubbed", release_eligible: false },
      { id: "audit.intent-before-use", result: "stubbed", release_eligible: false },
      { id: "bypass.direct-ipv4", result: "not-applicable", release_eligible: false },
    ],
  );
  assert.equal(JSON.stringify(report).includes("fixture-secret"), false);
  assert.match(report.tests[0]?.diagnostics_redacted ?? "", /\[REDACTED\]/);
  assert.match(renderHumanReport(report), /not-applicable=1, stubbed=2/);
});

test("non-cooperative execution and teardown timeouts become bounded failed evidence", async () => {
  const oneCase: CaseManifest = { version: manifest.version, cases: [firstCase] };
  let cleaned = false;
  const started = performance.now();
  const report = await runConformance(
    oneCase,
    options({
      adapter: adapter({
        execute: async () => await new Promise<never>(() => undefined),
        cleanup: async () => {
          cleaned = true;
        },
        teardown: async () => await new Promise<never>(() => undefined),
      }),
      teardownTimeoutMs: 100,
    }),
  );
  assert.ok(performance.now() - started < 1_000);
  assert.equal(cleaned, true);
  assertValidSecurityReport(report);

  assert.deepEqual(
    report.tests.map(({ id, result }) => ({ id, result })),
    [
      { id: "route.allowed", result: "fail" },
      { id: "runner.teardown", result: "fail" },
    ],
  );
  assert.match(report.tests[0]?.diagnostics_redacted ?? "", /timed out/);
  assert.match(report.tests[1]?.diagnostics_redacted ?? "", /teardown timed out/);
});

test("cleanup failure invalidates its case and prevents later adapter execution", async () => {
  let executions = 0;
  const report = await runConformance(
    { version: manifest.version, cases: manifest.cases.slice(0, 2) },
    options({
      adapter: adapter({
        execute: async () => {
          executions += 1;
          return { passed: true };
        },
        cleanup: async () => await new Promise<never>(() => undefined),
      }),
      cleanupTimeoutMs: 100,
    }),
  );

  assert.equal(executions, 1);
  assertValidSecurityReport(report);
  assert.deepEqual(
    report.tests.map(({ result }) => result),
    ["fail", "fail"],
  );
  assert.match(report.tests[0]?.diagnostics_redacted ?? "", /cleanup.*timed out/);
  assert.match(report.tests[1]?.diagnostics_redacted ?? "", /not executed/);
});

test("approved skips retain owner and review point while expired skips fail closed", async () => {
  const report = await runConformance(
    { version: manifest.version, cases: [firstCase] },
    options({
      skips: {
        "route.allowed": {
          owner: "Nick Byrne",
          reason: "bounded fixture outage",
          review_at: "2026-07-17T00:00:00Z",
        },
      },
    }),
  );
  assertValidSecurityReport(report);
  assert.equal(report.tests[0]?.result, "skipped-with-approved-reason");
  assert.equal(report.tests[0]?.skip_approval?.owner, "Nick Byrne");

  const expired = await runConformance(
    { version: manifest.version, cases: [firstCase] },
    options({
      skips: {
        "route.allowed": {
          owner: "Nick Byrne",
          reason: "expired fixture outage",
          review_at: "2026-07-09T00:00:00Z",
        },
      },
    }),
  );
  assertValidSecurityReport(expired);
  assert.equal(expired.tests[0]?.result, "fail");
  assert.equal(expired.tests[0]?.skip_approval, undefined);
});

test("malformed adapter results fail while genuine real-dependency success passes", async () => {
  const realDependencies = options().dependencies;
  realDependencies.authorization = { mode: "real", implementation: "candidate-policy" };
  const malformed = await runConformance(
    { version: manifest.version, cases: [firstCase] },
    options({
      dependencies: realDependencies,
      adapter: adapter({ execute: async () => ({ passed: "true" }) as unknown as AdapterResult }),
    }),
  );
  assert.equal(malformed.tests[0]?.result, "fail");

  const passing = await runConformance(
    { version: manifest.version, cases: [firstCase] },
    options({ dependencies: realDependencies }),
  );
  assert.equal(passing.tests[0]?.result, "pass");
  assertValidSecurityReport(passing);
});

test("malformed manifests and invalid authority claims fail before execution", async () => {
  assert.throws(() => validateManifest({ ...manifest, cases: [firstCase, firstCase] }), /duplicate case id/);
  assert.throws(() => validateManifest({ ...manifest, cases: [{ ...firstCase, timeout_ms: 1 }] }), /invalid timeout/);
  assert.throws(
    () =>
      validateManifest({
        ...manifest,
        cases: [{ ...firstCase, group: "runner-control" } as unknown as CaseManifest["cases"][number]],
      }),
    /invalid group/,
  );
  await assert.rejects(
    runConformance(manifest, options({ authority: "authoritative-local" })),
    /cannot produce authoritative evidence/,
  );
});
