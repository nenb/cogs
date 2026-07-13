import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { platform, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { STAGE_1_MANIFEST, stage1Case } from "../../cases/stage-1.ts";
import { type PreparedCase, prepareStage1Case } from "../../cases/suite-runtime.ts";
import { writeReports } from "../../controller/report.ts";
import { runConformance, type SecurityReport } from "../../controller/runner.ts";
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
const reportId = `envoy-suite-${process.env.GITHUB_RUN_ID ?? "local"}`;
const stateRoot = process.platform === "linux" ? "/dev/shm" : tmpdir();
const realCredential = `Bearer cogs-fixture-${randomBytes(24).toString("hex")}`;
const capability = `cogs-capability-${randomBytes(24).toString("hex")}`;
const wrongCapability = `cogs-wrong-${randomBytes(24).toString("hex")}`;
const placeholder = "Bearer cogs-non-secret-placeholder";
const sessionId = "session-envoy-suite";
const replacementCapability = `cogs-replacement-${randomBytes(24).toString("hex")}`;

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

  const prepared = new Map<string, PreparedCase>();
  const adapter = new EnvoyConformanceAdapter({
    stateRoot,
    sensitiveValues: [realCredential, capability, replacementCapability, wrongCapability, placeholder],
    configurationFor: (test) => {
      const definition = stage1Case(test.id);
      const state = prepareStage1Case(definition, faultInjector, capability, wrongCapability, replacementCapability);
      prepared.set(test.id, state);
      const scenario = definition.probe.scenario;
      const credential =
        scenario === "telemetry-outage"
          ? undefined
          : scenario === "api-key"
            ? ({ kind: "api-key", header: "x-api-key", value: "unused-api-key-fixture" } as const)
            : scenario === "basic"
              ? ({ kind: "basic", value: "Basic dW51c2VkOmZpeHR1cmU=" } as const)
              : ({ kind: "bearer", value: realCredential } as const);
      const parserPost = new Set(["cl-te-conflict", "invalid-chunk-size", "invalid-chunk-extension"]);
      return {
        caseId: test.id,
        sessionId,
        listenerAddress: "0.0.0.0",
        listenerPort: proxyPort,
        authorizationGrpcTarget: faultInjector.grpcTarget,
        proxyCertificatePem: proxyCertificate.certificate,
        proxyPrivateKeyPem: proxyCertificate.privateKey,
        routes: [
          {
            id: "route.fixture",
            protocol: "https",
            host: state.includeCredentialRoute ? "localhost" : "unused.invalid",
            port: fixturePort,
            methods: parserPost.has(scenario) ? ["GET", "POST"] : ["GET"],
            pathPrefix:
              scenario === "api-key"
                ? "/protected/api-key"
                : scenario === "basic"
                  ? "/protected/basic"
                  : scenario === "redirect-undeclared"
                    ? "/redirect"
                    : "/protected/header",
            upstreamAddress: "127.0.0.1",
            upstreamPort: fixturePort,
            upstreamCaCertificatePem: fixtures.caCertificatePem,
            ...(credential === undefined ? {} : { credential }),
          },
        ],
      } satisfies EnvoyCandidateConfigInput;
    },
    commandFor: (test, runtime) => {
      const definition = stage1Case(test.id);
      const state = prepared.get(test.id);
      if (!state) throw new Error("suite case was not prepared");
      return {
        command: join(repo, "test/egress-conformance/guest-probes/run-black-box-case.sh"),
        args: [],
        env: {
          COGS_SUITE_GUEST_PROXY: `http://host.docker.internal:${new URL(runtime.proxyOrigin).port}`,
          COGS_SUITE_TARGET_PORT: String(fixturePort),
          COGS_SUITE_PUBLIC_CA: proxyCertificate.caPath,
          COGS_SUITE_CAPABILITY: state.capability,
          COGS_SUITE_SCENARIO: definition.probe.scenario,
          COGS_SUITE_KIND: definition.probe.kind,
          COGS_SUITE_EXPECT: state.probeExpected,
        },
      };
    },
  });
  const dockerVersion = (
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"], { timeout: 30_000 })
  ).stdout.trim();
  report = await runConformance(STAGE_1_MANIFEST, {
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
      "Direct OpenBao change detection remains a Stage 1 revocation stub and requires a mandatory Stage 3 rerun.",
    ],
    redactValues: [realCredential, capability, replacementCapability, wrongCapability, placeholder],
    adapter,
    cleanupTimeoutMs: 20_000,
    teardownTimeoutMs: 20_000,
  });

  try {
    const records = adapter.accessRecords();
    const snapshot = faultInjector.snapshot();
    for (const record of records) {
      const intent = snapshot.intents.find((item) => item.intent_id === record.intent_id);
      assert.ok(intent, "completion record has no authorization intent");
      assert.equal(record.route_id, "route.fixture");
      if (intent.completion === null)
        await completeIntent(faultInjector.origin, record.intent_id, record.response_code, record.duration_ms);
    }
    const observations = fixtures.observations().filter((item) => item.kind === "http");
    const serialized = JSON.stringify({ report, observations, snapshot: faultInjector.snapshot(), records });
    for (const value of [realCredential, capability, replacementCapability, wrongCapability, placeholder])
      assert.equal(serialized.includes(value), false);
  } catch (error) {
    const result = report.tests.find((item) => item.result !== "fail") ?? report.tests[0];
    if (result) {
      result.result = "fail";
      result.release_eligible = false;
      result.diagnostics_redacted =
        error instanceof Error ? error.message.slice(0, 2048) : "suite postcondition failed";
    }
  }

  const paths = await writeReports(outputDirectory, report);
  console.log(`Wrote Envoy Stage 1 suite evidence to ${paths.machine} and ${paths.human}`);
  if (report.tests.some((result) => result.result === "fail")) process.exitCode = 1;
} finally {
  await Promise.allSettled([fixtures.stop(), faultInjector.stop()]);
  await rm(material, { recursive: true, force: true });
}
