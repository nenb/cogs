import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assertValidSecurityReport, writeReports } from "./report.ts";
import type { SecurityReport } from "./runner.ts";

function report(): SecurityReport {
  return {
    version: "cogs.security-report/v1alpha1",
    report_id: "egress-unit",
    source_revision: "a".repeat(40),
    profile: "insecure-container",
    authority: "functional-only",
    started_at: "2026-07-10T12:00:00Z",
    completed_at: "2026-07-10T12:00:01Z",
    duration_ms: 1000,
    environment: {
      os: "linux",
      architecture: "x86_64",
      runner: "node-test",
      runtime_versions: { node: process.version },
    },
    components: [{ name: "fixture", version: "1", image_digest: `sha256:${"b".repeat(64)}` }],
    dependencies: {
      authorization: { mode: "stubbed", implementation: "fixture" },
      audit: { mode: "stubbed", implementation: "fixture" },
      revocation: { mode: "stubbed", implementation: "fixture" },
      identity: { mode: "real", implementation: "fixture" },
      network_enforcement: { mode: "not-applicable", implementation: "insecure profile" },
    },
    tests: [
      {
        id: "route.allowed",
        group: "identity-route",
        result: "pass",
        release_eligible: false,
        duration_ms: 10,
        dependency_modes: { identity: "real" },
      },
    ],
    known_limitations: ["unit test only"],
  };
}

test("validated machine and human reports are written together", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cogs-report-"));
  try {
    const paths = await writeReports(directory, report());
    const [machine, human] = await Promise.all([readFile(paths.machine, "utf8"), readFile(paths.human, "utf8")]);
    assert.equal((JSON.parse(machine) as SecurityReport).report_id, "egress-unit");
    assert.match(human, /route\.allowed.*pass/);

    await assert.rejects(writeReports(directory, report()));
    assert.equal(await readFile(paths.machine, "utf8"), machine, "a failed replacement must preserve prior evidence");
    assert.equal(
      (await readdir(directory)).some((name) => name.startsWith(".egress-unit.tmp-")),
      false,
      "temporary report directories must be removed",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("schema and semantic failures are rejected before writing", () => {
  const invalidSchema = { ...report(), source_revision: "short" };
  assert.throws(() => assertValidSecurityReport(invalidSchema), /schema validation failed/);

  const invalidSemantics = report();
  invalidSemantics.tests = [
    {
      id: "route.allowed",
      group: "identity-route",
      result: "pass",
      release_eligible: false,
      duration_ms: 10,
      dependency_modes: { authorization: "stubbed" },
    },
  ];
  assert.throws(() => assertValidSecurityReport(invalidSemantics), /requires result=stubbed/);
});
