import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
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
import { emitOtlpMetadata, startOtlpFixture } from "../../telemetry-fixture/server.ts";
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
const profile = process.env.COGS_CONFORMANCE_PROFILE === "linux-kvm" ? "linux-kvm" : "insecure-container";
const authoritative = profile === "linux-kvm";
const reportId = `mitmproxy-suite-${profile}-${process.env.GITHUB_RUN_ID ?? "local"}`;
const stateRoot = process.platform === "linux" ? "/dev/shm" : tmpdir();
const realCredential = `Bearer cogs-fixture-${randomBytes(24).toString("hex")}`;
const apiCredential = `cogs-api-${randomBytes(24).toString("hex")}`;
const basicCredential = `Basic ${Buffer.from(`fixture:${randomBytes(24).toString("hex")}`).toString("base64")}`;
const capability = `cogs-capability-${randomBytes(24).toString("hex")}`;
const wrongCapability = `cogs-wrong-${randomBytes(24).toString("hex")}`;
const placeholder = "Bearer cogs-non-secret-placeholder";
const sessionId = "session-mitmproxy-suite";
const replacementCapability = `cogs-replacement-${randomBytes(24).toString("hex")}`;
const sensitiveValues = [
  realCredential,
  apiCredential,
  basicCredential,
  capability,
  replacementCapability,
  wrongCapability,
  placeholder,
] as const;

let authoritativeGuestKernel: string | undefined;
if (authoritative) {
  const driver = join(repo, "dev/linux-kvm/driver.sh");
  const verification = JSON.parse((await execFileAsync(driver, ["verify"], { timeout: 30_000 })).stdout) as Record<
    string,
    unknown
  >;
  assert.equal(verification.kvm_enabled, true);
  assert.equal(verification.guest_root, true);
  assert.equal(verification.distinct_boot_ids, true);
  assert.equal(typeof verification.guest_kernel, "string");
  authoritativeGuestKernel = verification.guest_kernel as string;
  const hostBootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  const guestBootId = (
    await execFileAsync(driver, ["ssh", "cat /proc/sys/kernel/random/boot_id"], { timeout: 15_000 })
  ).stdout.trim();
  assert.notEqual(guestBootId, hostBootId);
}

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
    apiKey: apiCredential,
    basic: basicCredential,
  },
  redirectLocation: "https://undeclared.invalid/denied",
  delayedResponseMs: 5_000,
});
const faultInjector = await startFaultInjector({ initialCapability: capability });
const telemetry = await startOtlpFixture(sensitiveValues);
let report: SecurityReport | undefined;
try {
  const fixtureUrl = new URL(fixtures.tlsOrigin);
  const fixturePort = Number(fixtureUrl.port);
  const proxyPort = authoritative ? 18080 : await reservePort();
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

  const prepared = new Map<string, PreparedCase>();
  const certificateDigests = new Map<string, string>();
  const adapter = new MitmproxyConformanceAdapter({
    stateRoot,
    listenerPort: proxyPort,
    upstreamCaCertificatePem: fixtures.caCertificatePem,
    sensitiveValues,
    policyFor: (test) => {
      const definition = stage1Case(test.id);
      const state = prepareStage1Case(definition, faultInjector, capability, wrongCapability, replacementCapability);
      prepared.set(test.id, state);
      const scenario = definition.probe.scenario;
      const credential =
        scenario === "telemetry-outage"
          ? undefined
          : scenario === "api-key"
            ? ({ kind: "api-key", header: "x-api-key", value: apiCredential } as const)
            : scenario === "basic"
              ? ({ kind: "basic", value: basicCredential } as const)
              : ({ kind: "bearer", value: realCredential } as const);
      const parserPost = new Set(["cl-te-conflict", "invalid-chunk-size", "invalid-chunk-extension"]);
      return {
        caseId: test.id,
        sessionId,
        authorizationOrigin: faultInjector.origin,
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
                    : scenario === "telemetry-outage"
                      ? "/large"
                      : scenario === "long-lived-drain"
                        ? "/delayed"
                        : "/protected/header",
            ...(credential === undefined ? {} : { credential }),
          },
        ],
      } satisfies MitmproxyPolicyInput;
    },
    commandFor: (test, runtime) => {
      const definition = stage1Case(test.id);
      const state = prepared.get(test.id);
      if (!state) throw new Error("suite case was not prepared");
      certificateDigests.set(test.id, createHash("sha256").update(readFileSync(runtime.publicCaPath)).digest("hex"));
      return {
        command: join(
          repo,
          authoritative
            ? "test/egress-conformance/guest-probes/run-kvm-black-box-case.sh"
            : "test/egress-conformance/guest-probes/run-black-box-case.sh",
        ),
        args: [],
        env: {
          COGS_SUITE_GUEST_PROXY: authoritative
            ? "http://192.0.2.1:18080"
            : `http://host.docker.internal:${new URL(runtime.proxyOrigin).port}`,
          COGS_SUITE_TARGET_PORT: String(fixturePort),
          COGS_SUITE_PUBLIC_CA: runtime.publicCaPath,
          COGS_SUITE_CAPABILITY: state.capability,
          COGS_SUITE_SCENARIO: definition.probe.scenario,
          COGS_SUITE_KIND: definition.probe.kind,
          COGS_SUITE_EXPECT: state.probeExpected,
          COGS_SUITE_DRAIN_CONTAINER: runtime.containerName,
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
    profile,
    authority: authoritative ? "authoritative-local" : "functional-only",
    environment: {
      os: platform(),
      architecture: process.arch,
      runner:
        process.env.GITHUB_ACTIONS === "true"
          ? `GitHub Actions ${process.env.RUNNER_NAME ?? "unknown"}`
          : "local Docker host",
      runner_image: process.env.ImageOS ?? "local",
      runtime_versions: {
        docker: dockerVersion,
        mitmproxy: MITMPROXY_VERSION,
        ...(authoritativeGuestKernel ? { guest_kernel: authoritativeGuestKernel } : {}),
      },
      metadata: {
        isolation_claim: authoritative,
        kvm_present: authoritative,
        kvm_enabled: authoritative,
        guest_root: true,
        distinct_boot_ids: authoritative,
        host_enforced_network: authoritative,
        ...(authoritative
          ? {
              guest_image_sha512:
                "78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667",
            }
          : {}),
        proxy_admin_enabled: false,
        immutable_configuration: true,
      },
    },
    components: [{ name: "mitmproxy", version: MITMPROXY_VERSION, image_digest: MITMPROXY_IMAGE_DIGEST }],
    dependencies: {
      authorization: { mode: "stubbed", implementation: "Stage 1 fault injector HTTP ext_authz hook" },
      audit: { mode: "stubbed", implementation: "Stage 1 in-memory intent and completion fixture" },
      revocation: { mode: "stubbed", implementation: "Stage 1 deny-new and process-drain fixture" },
      identity: { mode: "stubbed", implementation: "Stage 1 keyed session capability fixture" },
      network_enforcement: authoritative
        ? { mode: "real", implementation: "host-owned TAP INPUT/FORWARD policy with no NAT or default route" }
        : { mode: "not-applicable", implementation: "insecure-container has no default-deny claim" },
    },
    releaseEligibility: "disabled-candidate",
    knownLimitations: [
      authoritative
        ? "This is authoritative local KVM evidence; authorization, audit, identity, and revocation dependencies remain Stage 1 stubs."
        : "This is functional-only insecure-container evidence and cannot support a guest-root isolation claim.",
      "Candidate evaluation disables release eligibility until proxy selection and production integration.",
      "Direct OpenBao polling and production WAL persistence remain mandatory Stage 3 reruns.",
      "The candidate requires a custom 182-line Python addon for policy, capability, injection, and audit hooks.",
      "The latest upstream image has six fixed HIGH findings under a narrow owner-and-expiry ignore through 2026-07-27; this evidence cannot support selection or release.",
      "Direct OpenBao change detection remains a Stage 1 revocation stub and requires a mandatory Stage 3 rerun.",
    ],
    redactValues: sensitiveValues,
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
      assert.equal(record.completion_recorded, true);
      assert.deepEqual(intent.completion, {
        outcome: record.response_code >= 200 && record.response_code < 400 ? "success" : "failed",
        status_class: Math.floor(record.response_code / 100),
        latency_ms: record.duration_ms,
      });
      if (intent.case_id !== "audit.telemetry-outage-uncredentialed") {
        await emitOtlpMetadata(telemetry.origin, {
          test_id: intent.case_id,
          outcome: record.response_code < 400 ? "success" : "failed",
          status_class: Math.floor(record.response_code / 100),
          duration_ms: record.duration_ms,
        });
      }
    }
    assert.notEqual(
      certificateDigests.get("credential.bearer-injected"),
      certificateDigests.get("revocation.replacement-capability"),
    );
    const observations = fixtures.observations().filter((item) => item.kind === "http");
    const serialized = JSON.stringify({ report, observations, snapshot, records, telemetry: telemetry.records() });
    for (const value of sensitiveValues) assert.equal(serialized.includes(value), false);
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
  console.log(`Wrote mitmproxy Stage 1 suite evidence to ${paths.machine} and ${paths.human}`);
  if (report.tests.some((result) => result.result === "fail")) process.exitCode = 1;
} finally {
  await Promise.allSettled([fixtures.stop(), faultInjector.stop(), telemetry.stop()]);
}
