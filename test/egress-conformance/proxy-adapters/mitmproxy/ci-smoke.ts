import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { platform, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { writeReports } from "../../controller/report.ts";
import { type CaseManifest, runConformance, type SecurityReport } from "../../controller/runner.ts";
import { startFaultInjector } from "../../fault-injector/server.ts";
import { startUpstreamFixtures } from "../../upstream-fixtures/server.ts";
import { MitmproxyConformanceAdapter } from "./adapter.ts";
import { MITMPROXY_IMAGE, MITMPROXY_IMAGE_DIGEST, MITMPROXY_VERSION } from "./image.ts";
import type { MitmproxyPolicyInput } from "./policy.ts";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../..");
const outputDirectory = resolve(process.argv[2] ?? join(repo, "docs/security-evidence/generated"));
const sourceRevision =
  process.env.COGS_SOURCE_REVISION ?? (await execFileAsync("git", ["-C", repo, "rev-parse", "HEAD"])).stdout.trim();
const reportId = `mitmproxy-candidate-${process.env.GITHUB_RUN_ID ?? "local"}`;
const stateRoot = process.platform === "linux" ? "/dev/shm" : tmpdir();
const realCredential = `Bearer cogs-fixture-${randomBytes(24).toString("hex")}`;
const capability = `cogs-capability-${randomBytes(24).toString("hex")}`;
const wrongCapability = `cogs-wrong-${randomBytes(24).toString("hex")}`;
const placeholder = "Bearer cogs-non-secret-placeholder";
const sessionId = "session-mitmproxy-smoke";

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
  return port;
}

const fixtures = await startUpstreamFixtures({
  expectedCredentials: {
    bearer: realCredential,
    apiKey: "unused-api-key-fixture",
    basic: "Basic dW51c2VkOmZpeHR1cmU=",
  },
  redirectLocation: "https://undeclared.invalid/denied",
});
const faultInjector = await startFaultInjector({ initialCapability: capability });
let report: SecurityReport | undefined;
try {
  const fixtureUrl = new URL(fixtures.tlsOrigin);
  const fixturePort = Number(fixtureUrl.port);
  const proxyPort = await reservePort();
  await execFileAsync("docker", ["pull", MITMPROXY_IMAGE], { timeout: 120_000, maxBuffer: 1024 * 1024 });
  const imageIdentity = (
    await execFileAsync("docker", ["image", "inspect", "--format", "{{json .RepoDigests}}", MITMPROXY_IMAGE], {
      timeout: 30_000,
    })
  ).stdout;
  assert.ok(imageIdentity.includes(MITMPROXY_IMAGE_DIGEST));
  const versionOutput = (
    await execFileAsync("docker", ["run", "--rm", MITMPROXY_IMAGE, "mitmdump", "--version"], { timeout: 30_000 })
  ).stdout;
  assert.ok(versionOutput.includes(MITMPROXY_VERSION));

  const policyFor = (caseId: string): MitmproxyPolicyInput => ({
    caseId,
    sessionId,
    authorizationOrigin: faultInjector.origin,
    routes: [
      {
        id: "route.fixture-bearer",
        protocol: "https",
        host: "localhost",
        port: fixturePort,
        methods: ["GET"],
        pathPrefix: "/protected/header",
        credential: { kind: "bearer", value: realCredential },
      },
    ],
  });

  const adapter = new MitmproxyConformanceAdapter({
    stateRoot,
    listenerPort: proxyPort,
    upstreamCaCertificatePem: fixtures.caCertificatePem,
    sensitiveValues: [realCredential, capability, wrongCapability, placeholder],
    policyFor: (test) => policyFor(test.id),
    commandFor: (test, runtime) => ({
      command: join(here, "case-probe.sh"),
      args: [],
      env: {
        COGS_MITMPROXY_GUEST_PROXY: `http://host.docker.internal:${new URL(runtime.proxyOrigin).port}`,
        COGS_MITMPROXY_TARGET: `https://localhost:${fixturePort}/protected/header`,
        COGS_MITMPROXY_PROXY_CA: runtime.publicCaPath,
        COGS_MITMPROXY_CAPABILITY: test.id === "mitmproxy.capability-wrong" ? wrongCapability : capability,
        COGS_MITMPROXY_EXPECT: test.id === "mitmproxy.capability-wrong" ? "deny" : "allow",
      },
    }),
  });

  const manifest: CaseManifest = {
    version: "cogs.egress-cases/v1alpha1",
    cases: [
      {
        id: "mitmproxy.capability-wrong",
        group: "identity-route",
        timeout_ms: 45_000,
        profiles: ["insecure-container"],
        dependencies: ["identity"],
      },
      {
        id: "mitmproxy.bearer-injection",
        group: "credential-handling",
        timeout_ms: 45_000,
        profiles: ["insecure-container"],
        dependencies: ["identity", "authorization", "audit"],
      },
    ],
  };
  const dockerVersion = (
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"], { timeout: 30_000 })
  ).stdout.trim();
  report = await runConformance(manifest, {
    reportId,
    sourceRevision,
    profile: "insecure-container",
    authority: "functional-only",
    environment: {
      os: platform(),
      architecture: process.arch,
      runner:
        process.env.GITHUB_ACTIONS === "true"
          ? `GitHub Actions ${process.env.RUNNER_NAME ?? "unknown"}`
          : "local Docker host",
      runner_image: process.env.ImageOS ?? "local",
      runtime_versions: { docker: dockerVersion, mitmproxy: MITMPROXY_VERSION },
      metadata: { isolation_claim: false, proxy_admin_enabled: false, immutable_configuration: true },
    },
    components: [{ name: "mitmproxy", version: MITMPROXY_VERSION, image_digest: MITMPROXY_IMAGE_DIGEST }],
    dependencies: {
      authorization: { mode: "stubbed", implementation: "Stage 1 fault injector HTTP ext_authz hook" },
      audit: { mode: "stubbed", implementation: "Stage 1 in-memory intent and completion fixture" },
      revocation: { mode: "stubbed", implementation: "Stage 1 deny-new and process-drain fixture" },
      identity: { mode: "stubbed", implementation: "Stage 1 keyed session capability fixture" },
      network_enforcement: { mode: "not-applicable", implementation: "insecure-container has no default-deny claim" },
    },
    knownLimitations: [
      "This is functional-only insecure-container evidence and cannot support a guest-root isolation claim.",
      "Direct OpenBao polling and production WAL persistence remain mandatory Stage 3 reruns.",
      "The candidate requires a custom 202-line Python addon for policy, capability, injection, and audit hooks.",
      "The latest upstream image still has six unique fixed HIGH finding identifiers; the candidate-only ignore was removed rather than renewed, and this historical adapter cannot support Stage 3 selection or release.",
      "The complete route, parser, HTTP/2, redirect, drain, and client matrix is tracked by Stage 1 issue 22.",
    ],
    redactValues: [realCredential, capability, wrongCapability, placeholder],
    adapter,
    cleanupTimeoutMs: 20_000,
    teardownTimeoutMs: 20_000,
  });

  const bearerResult = report.tests.find((result) => result.id === "mitmproxy.bearer-injection");
  if (bearerResult?.result === "fail") {
    const checks = faultInjector.snapshot().capability_checks;
    bearerResult.diagnostics_redacted = `${bearerResult.diagnostics_redacted ?? "Mitmproxy mechanism failed"}; capability checks total=${checks.total} present=${checks.header_present} matched=${checks.digest_matched} accepted=${checks.accepted}`;
  }

  try {
    assert.equal(report.tests.find((result) => result.id === "mitmproxy.capability-wrong")?.result, "stubbed");
    assert.equal(report.tests.find((result) => result.id === "mitmproxy.bearer-injection")?.result, "stubbed");
    const observations = fixtures.observations().filter((item) => item.kind === "http");
    assert.equal(observations.length, 1);
    assert.equal(observations[0]?.route, "header-protected");
    assert.equal(observations[0]?.credential_matches, true);
    assert.equal(observations[0]?.authority_matches, null);
    const snapshot = faultInjector.snapshot();
    assert.equal(snapshot.intents.length, 1);
    assert.equal(snapshot.intents[0]?.case_id, "mitmproxy.bearer-injection");
    assert.equal(snapshot.intents[0]?.route_id, "route.fixture-bearer");
    const records = adapter.accessRecords();
    assert.equal(records.length, 1);
    const completionRecord = records[0];
    assert.ok(completionRecord);
    assert.equal(completionRecord.intent_id, snapshot.intents[0]?.intent_id);
    assert.equal(completionRecord.route_id, "route.fixture-bearer");
    assert.equal(completionRecord.response_code, 200);
    assert.equal(completionRecord.completion_recorded, true);
    assert.notEqual(faultInjector.snapshot().intents[0]?.completion, null);
    const serialized = JSON.stringify({ report, observations, snapshot: faultInjector.snapshot(), records });
    for (const value of [realCredential, capability, wrongCapability, placeholder])
      assert.equal(serialized.includes(value), false);
  } catch (error) {
    const result = bearerResult ?? report.tests[0];
    if (result !== undefined && result.result !== "fail") {
      result.result = "fail";
      result.release_eligible = false;
      result.diagnostics_redacted =
        error instanceof Error ? error.message.slice(0, 2048) : "Mitmproxy smoke postcondition failed";
    }
  }

  const paths = await writeReports(outputDirectory, report);
  console.log(`Wrote Mitmproxy functional candidate evidence to ${paths.machine} and ${paths.human}`);
  if (report.tests.some((result) => result.result === "fail")) process.exitCode = 1;
} finally {
  await Promise.allSettled([fixtures.stop(), faultInjector.stop()]);
}
