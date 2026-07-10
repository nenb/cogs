import assert from "node:assert/strict";
import test from "node:test";
import type { CaseManifest, RunnerOptions } from "./runner.ts";
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
    execute: async () => ({ passed: true }),
    teardown: async () => undefined,
    ...overrides,
  };
}

test("runner is deterministic, applicability-aware, stub-aware, redacted, and human-readable", async () => {
  const report = await runConformance(
    manifest,
    options({
      redactValues: ["fixture-secret"],
      execute: async (conformanceCase) => ({
        passed: true,
        diagnosticsRedacted: `case=${conformanceCase.id} token=fixture-secret\n`,
      }),
    }),
  );

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

test("timeouts and teardown failures become explicit failed evidence", async () => {
  const oneCase: CaseManifest = { version: manifest.version, cases: [firstCase] };
  const report = await runConformance(
    oneCase,
    options({
      execute: async (_case, signal) =>
        await new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
      teardown: async () => {
        throw new Error("teardown exposed fixture-secret");
      },
      redactValues: ["fixture-secret"],
    }),
  );

  assert.deepEqual(
    report.tests.map(({ id, result }) => ({ id, result })),
    [
      { id: "route.allowed", result: "fail" },
      { id: "runner.teardown", result: "fail" },
    ],
  );
  assert.match(report.tests[0]?.diagnostics_redacted ?? "", /timed out/);
  assert.equal(JSON.stringify(report).includes("fixture-secret"), false);
});

test("approved skips retain owner and review point", async () => {
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
  assert.equal(report.tests[0]?.result, "skipped-with-approved-reason");
  assert.equal(report.tests[0]?.skip_approval?.owner, "Nick Byrne");
});

test("malformed manifests and invalid authority claims fail before execution", async () => {
  assert.throws(() => validateManifest({ ...manifest, cases: [firstCase, firstCase] }), /duplicate case id/);
  assert.throws(() => validateManifest({ ...manifest, cases: [{ ...firstCase, timeout_ms: 1 }] }), /invalid timeout/);
  await assert.rejects(
    runConformance(manifest, options({ authority: "authoritative-local" })),
    /cannot produce authoritative evidence/,
  );
});
