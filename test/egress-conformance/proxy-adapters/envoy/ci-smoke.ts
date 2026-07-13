import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { platform, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { writeReports } from "../../controller/report.ts";
import { type CaseManifest, runConformance, type SecurityReport } from "../../controller/runner.ts";
import { startFaultInjector } from "../../fault-injector/server.ts";
import { startUpstreamFixtures } from "../../upstream-fixtures/server.ts";
import { EnvoyConformanceAdapter } from "./adapter.ts";
import type { EnvoyCandidateConfigInput } from "./config.ts";
import { ENVOY_IMAGE, ENVOY_IMAGE_DIGEST, ENVOY_VERSION } from "./image.ts";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../..");
const outputDirectory = resolve(process.argv[2] ?? join(repo, "docs/security-evidence/generated"));
const sourceRevision =
  process.env.COGS_SOURCE_REVISION ?? (await execFileAsync("git", ["-C", repo, "rev-parse", "HEAD"])).stdout.trim();
const reportId = `envoy-candidate-${process.env.GITHUB_RUN_ID ?? "local"}`;
const stateRoot = process.platform === "linux" ? "/dev/shm" : tmpdir();
const realCredential = `Bearer cogs-fixture-${randomBytes(24).toString("hex")}`;
const capability = `cogs-capability-${randomBytes(24).toString("hex")}`;
const wrongCapability = `cogs-wrong-${randomBytes(24).toString("hex")}`;
const placeholder = "Bearer cogs-non-secret-placeholder";
const sessionId = "session-envoy-smoke";

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

async function generateProxyCertificate(directory: string): Promise<{
  caPath: string;
  certificate: string;
  privateKey: string;
}> {
  const caKey = join(directory, "proxy-ca.key");
  const caPath = join(directory, "proxy-ca.crt");
  const keyPath = join(directory, "proxy-leaf.key");
  const csrPath = join(directory, "proxy-leaf.csr");
  const certPath = join(directory, "proxy-leaf.crt");
  const extensions = join(directory, "proxy-leaf.ext");
  await writeFile(
    extensions,
    [
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      "subjectAltName=DNS:localhost",
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  const options = { cwd: directory, timeout: 10_000, maxBuffer: 64 * 1024 } as const;
  await execFileAsync(
    "openssl",
    ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", caKey],
    options,
  );
  await execFileAsync(
    "openssl",
    [
      "req",
      "-x509",
      "-new",
      "-key",
      caKey,
      "-sha256",
      "-days",
      "2",
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign",
      "-subj",
      "/CN=Cogs Envoy Smoke CA",
      "-out",
      caPath,
    ],
    options,
  );
  await execFileAsync(
    "openssl",
    ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", keyPath],
    options,
  );
  await execFileAsync("openssl", ["req", "-new", "-key", keyPath, "-subj", "/CN=localhost", "-out", csrPath], options);
  await execFileAsync(
    "openssl",
    [
      "x509",
      "-req",
      "-in",
      csrPath,
      "-CA",
      caPath,
      "-CAkey",
      caKey,
      "-CAcreateserial",
      "-days",
      "2",
      "-sha256",
      "-extfile",
      extensions,
      "-out",
      certPath,
    ],
    options,
  );
  const [certificate, privateKey] = await Promise.all([readFile(certPath, "utf8"), readFile(keyPath, "utf8")]);
  await rm(caKey, { force: true });
  return { caPath, certificate, privateKey };
}

async function completeIntent(origin: string, intentId: string, status: number, duration: number): Promise<void> {
  const response = await fetch(`${origin}/v1/complete`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      intent_id: intentId,
      outcome: status >= 200 && status < 400 ? "success" : "failed",
      status_class: Math.floor(status / 100),
      latency_ms: duration,
    }),
  });
  assert.equal(response.status, 200);
}

const material = await mkdtemp(join(stateRoot, "cogs-envoy-smoke-material-"));
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
  const proxyCertificate = await generateProxyCertificate(material);
  const fixtureUrl = new URL(fixtures.tlsOrigin);
  const fixturePort = Number(fixtureUrl.port);
  const proxyPort = await reservePort();
  await execFileAsync("docker", ["pull", ENVOY_IMAGE], { timeout: 120_000, maxBuffer: 1024 * 1024 });
  const imageIdentity = (
    await execFileAsync("docker", ["image", "inspect", "--format", "{{json .RepoDigests}}", ENVOY_IMAGE], {
      timeout: 30_000,
    })
  ).stdout;
  assert.ok(imageIdentity.includes(ENVOY_IMAGE_DIGEST));
  const versionOutput = (await execFileAsync("docker", ["run", "--rm", ENVOY_IMAGE, "--version"], { timeout: 30_000 }))
    .stdout;
  assert.ok(versionOutput.includes(ENVOY_VERSION));

  const configFor = (caseId: string): EnvoyCandidateConfigInput => ({
    caseId,
    sessionId,
    listenerAddress: "0.0.0.0",
    listenerPort: proxyPort,
    authorizationGrpcTarget: faultInjector.grpcTarget,
    proxyCertificatePem: proxyCertificate.certificate,
    proxyPrivateKeyPem: proxyCertificate.privateKey,
    routes: [
      {
        id: "route.fixture-bearer",
        protocol: "https",
        host: "localhost",
        port: fixturePort,
        methods: ["GET"],
        pathPrefix: "/protected/header",
        upstreamAddress: "127.0.0.1",
        upstreamPort: fixturePort,
        upstreamCaCertificatePem: fixtures.caCertificatePem,
        credential: { kind: "bearer", value: realCredential },
      },
    ],
  });

  const adapter = new EnvoyConformanceAdapter({
    stateRoot,
    sensitiveValues: [realCredential, capability, wrongCapability, placeholder],
    configurationFor: (test) => configFor(test.id),
    commandFor: (test, runtime) => ({
      command: join(here, "case-probe.sh"),
      args: [],
      env: {
        COGS_ENVOY_GUEST_PROXY: `http://host.docker.internal:${new URL(runtime.proxyOrigin).port}`,
        COGS_ENVOY_TARGET: `https://localhost:${fixturePort}/protected/header`,
        COGS_ENVOY_PROXY_CA: proxyCertificate.caPath,
        COGS_ENVOY_CAPABILITY: test.id === "envoy.capability-wrong" ? wrongCapability : capability,
        COGS_ENVOY_EXPECT: test.id === "envoy.capability-wrong" ? "deny" : "allow",
      },
    }),
  });

  const manifest: CaseManifest = {
    version: "cogs.egress-cases/v1alpha1",
    cases: [
      {
        id: "envoy.capability-wrong",
        group: "identity-route",
        timeout_ms: 45_000,
        profiles: ["insecure-container"],
        dependencies: ["identity"],
      },
      {
        id: "envoy.bearer-injection",
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
      runtime_versions: { docker: dockerVersion, envoy: ENVOY_VERSION },
      metadata: { isolation_claim: false, proxy_admin_enabled: false, immutable_configuration: true },
    },
    components: [{ name: "envoy", version: ENVOY_VERSION, image_digest: ENVOY_IMAGE_DIGEST }],
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
      "The immutable TLS interception certificate enumerates registered hosts; Envoy does not mint leaves dynamically.",
      "The complete route, parser, HTTP/2, redirect, drain, and client matrix is tracked by Stage 1 issue 22.",
    ],
    redactValues: [realCredential, capability, wrongCapability, placeholder],
    adapter,
    cleanupTimeoutMs: 20_000,
    teardownTimeoutMs: 20_000,
  });

  const bearerResult = report.tests.find((result) => result.id === "envoy.bearer-injection");
  if (bearerResult?.result === "fail") {
    const checks = faultInjector.snapshot().capability_checks;
    bearerResult.diagnostics_redacted = `${bearerResult.diagnostics_redacted ?? "Envoy mechanism failed"}; capability checks total=${checks.total} present=${checks.header_present} matched=${checks.digest_matched} accepted=${checks.accepted}`;
  }

  try {
    assert.equal(report.tests.find((result) => result.id === "envoy.capability-wrong")?.result, "stubbed");
    assert.equal(report.tests.find((result) => result.id === "envoy.bearer-injection")?.result, "stubbed");
    const observations = fixtures.observations().filter((item) => item.kind === "http");
    assert.equal(observations.length, 1);
    assert.equal(observations[0]?.route, "header-protected");
    assert.equal(observations[0]?.credential_matches, true);
    assert.equal(observations[0]?.authority_matches, null);
    const snapshot = faultInjector.snapshot();
    assert.equal(snapshot.intents.length, 1);
    assert.equal(snapshot.intents[0]?.case_id, "envoy.bearer-injection");
    assert.equal(snapshot.intents[0]?.route_id, "route.fixture-bearer");
    const records = adapter.accessRecords();
    assert.equal(records.length, 1);
    const completionRecord = records[0];
    assert.ok(completionRecord);
    assert.equal(completionRecord.intent_id, snapshot.intents[0]?.intent_id);
    assert.equal(completionRecord.route_id, "route.fixture-bearer");
    assert.equal(completionRecord.response_code, 200);
    await completeIntent(
      faultInjector.origin,
      completionRecord.intent_id,
      completionRecord.response_code,
      completionRecord.duration_ms,
    );
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
        error instanceof Error ? error.message.slice(0, 2048) : "Envoy smoke postcondition failed";
    }
  }

  const paths = await writeReports(outputDirectory, report);
  console.log(`Wrote Envoy functional candidate evidence to ${paths.machine} and ${paths.human}`);
  if (report.tests.some((result) => result.result === "fail")) process.exitCode = 1;
} finally {
  await Promise.allSettled([fixtures.stop(), faultInjector.stop()]);
  await rm(material, { recursive: true, force: true });
}
