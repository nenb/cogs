import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { arch, platform, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import type { OpenBaoIdentityPort } from "../../../src/auth/model-auth.ts";
import { createNodeCogsEnvoyProcessPort } from "../../../src/egress/envoy-process.ts";
import { OpenBaoEgressPkiSource } from "../../../src/egress/openbao-pki.ts";
import { canonicalPresetPolicyRevision } from "../../../src/egress/preset-revision.ts";
import { type CogsEgressRuntimeManager, startCogsEgressRuntimeManager } from "../../../src/egress/runtime-manager.ts";
import type { LaunchConfig } from "../../../src/launch/config.ts";
import { assertValidSecurityReport, writeReports } from "../controller/report.ts";
import type { SecurityReport } from "../controller/runner.ts";

const execFileAsync = promisify(execFile);
const outputDirectory = resolve(process.argv[2] ?? "docs/security-evidence/generated/stage3-real-runtime");
const sourceRevision = requiredEnv("COGS_SOURCE_REVISION", /^[a-f0-9]{40}$/);
const openBaoOrigin = origin(requiredEnv("COGS_OPENBAO_ADDR", /^http:\/\/127\.0\.0\.1:[0-9]+$/));
const envoyExecutable = requiredEnv("COGS_ENVOY_EXECUTABLE", /^\//);
const envoyImage = requiredEnv("COGS_ENVOY_IMAGE", /^envoyproxy\/envoy:v1\.38\.3@sha256:[a-f0-9]{64}$/);
const envoyDigest = requiredEnv("COGS_ENVOY_IMAGE_DIGEST", /^sha256:[a-f0-9]{64}$/);
assert.equal(envoyImage.endsWith(envoyDigest), true);
const openBaoImage = requiredEnv("COGS_OPENBAO_IMAGE", /^quay\.io\/openbao\/openbao:2\.6\.0@sha256:[a-f0-9]{64}$/);
const openBaoVersionText = requiredEnv("COGS_OPENBAO_RUNTIME_VERSION", /^OpenBao\s+v2\.6\.0[\s\S]*$/);
const trustPath = requiredEnv(
  "COGS_TRUST_CERT_PATH",
  /^\/usr\/local\/share\/ca-certificates\/cogs-stage3-real-runtime\.crt$/,
);
const tempRoot = resolve(process.env.COGS_STAGE3_REAL_RUNTIME_TMP ?? tmpdir());
const openBaoDigest = openBaoImage.slice(openBaoImage.indexOf("@") + 1);
const openBaoVersion = "2.6.0";
const envoyVersion = "1.38.3";
const sessionId = "stage3-real-runtime";
const userId = "ci-user";
const integrationId = "stage3-localhost";
const secretHandle = `users/${userId}/${integrationId}`;
const routePath = "/protected/header";
const bearerToken = `cogs-bearer-${randomBytes(24).toString("hex")}`;
const bearerTokenV2 = `cogs-bearer-v2-${randomBytes(24).toString("hex")}`;
const expectedAuthorization = `Bearer ${bearerToken}`;
const expectedAuthorizationV2 = `Bearer ${bearerTokenV2}`;
const proxyCapability = `cogs-proxy-${randomBytes(24).toString("hex")}`;
const proxyCapabilityV2 = `cogs-proxy-v2-${randomBytes(24).toString("hex")}`;
const wrongCapability = `cogs-wrong-${randomBytes(24).toString("hex")}`;
const revocationPollIntervalMs = 500;
const revocationObservationBoundMs = 20_000;
const harnessReplacementReadyBoundMs = 40_000;
let rootToken = "";
let scopedToken = "";
let caPem = "";
let upstreamPrivateKey = "";
let upstreamCertificate = "";
const managers: CogsEgressRuntimeManager[] = [];
let rootRevoked = false;
let scopedRevoked = false;
const forbiddenSecrets = new Set<string>();
let currentPhase = "startup";

class StaticIdentity implements OpenBaoIdentityPort {
  public constructor(private readonly token: () => string) {}
  public async withToken(signal: AbortSignal, operation: (token: string) => Promise<void>): Promise<void> {
    if (signal.aborted) throw new Error("aborted");
    await operation(this.token());
  }
}

interface Sidecar {
  version: "cogs.stage3-real-runtime/v1alpha1";
  source_revision: string;
  profile: "insecure-container";
  release_eligible: false;
  components: {
    envoy: { version: string; image_digest: string; binary_sha256: string };
    openbao: { version: string; image_digest: string };
    runtime_manager: { mode: "real" };
  };
  dependency_modes: {
    identity: "real";
    authorization: "real";
    audit: "real";
    revocation: "real";
    telemetry: "stubbed";
    network_enforcement: "not-applicable";
  };
  timings: Record<
    | "revocation_poll_interval_ms"
    | "revocation_observation_bound_ms"
    | "harness_replacement_ready_bound_ms"
    | "credential_write_ms"
    | "credential_changed_callback_ms"
    | "credential_changed_drain_probe_ms"
    | "harness_replacement_ready_ms"
    | "credential_delete_ms"
    | "revoked_callback_ms"
    | "revoked_drain_probe_ms",
    number
  >;
  assertions: Record<
    | "openbao_loopback_only"
    | "credential_v1_injected"
    | "credential_v2_injected"
    | "baseline_wrong_capability_denied"
    | "baseline_wrong_path_denied"
    | "proxy_capability_stripped_upstream"
    | "wal_intents_preceded_upstream"
    | "completions_correlated"
    | "credential_change_callback_observed"
    | "revoked_callback_observed"
    | "harness_driven_replacement_after_callback"
    | "old_capability_denied_after_replacement"
    | "new_capability_invalidated_after_revocation"
    | "tmpfs_material_existed_in_scope"
    | "tmpfs_cleanup_verified"
    | "scoped_token_revoked"
    | "root_token_revoked"
    | "private_material_absent_from_reports"
    | "ca_private_key_not_returned"
    | "no_daemon_or_sandbox_replacement_claim",
    boolean
  >;
}

const timingKeys = [
  "revocation_poll_interval_ms",
  "revocation_observation_bound_ms",
  "harness_replacement_ready_bound_ms",
  "credential_write_ms",
  "credential_changed_callback_ms",
  "credential_changed_drain_probe_ms",
  "harness_replacement_ready_ms",
  "credential_delete_ms",
  "revoked_callback_ms",
  "revoked_drain_probe_ms",
] as const;

const assertionKeys = [
  "openbao_loopback_only",
  "credential_v1_injected",
  "credential_v2_injected",
  "baseline_wrong_capability_denied",
  "baseline_wrong_path_denied",
  "proxy_capability_stripped_upstream",
  "wal_intents_preceded_upstream",
  "completions_correlated",
  "credential_change_callback_observed",
  "revoked_callback_observed",
  "harness_driven_replacement_after_callback",
  "old_capability_denied_after_replacement",
  "new_capability_invalidated_after_revocation",
  "tmpfs_material_existed_in_scope",
  "tmpfs_cleanup_verified",
  "scoped_token_revoked",
  "root_token_revoked",
  "private_material_absent_from_reports",
  "ca_private_key_not_returned",
  "no_daemon_or_sandbox_replacement_claim",
] as const;

export function assertValidRealRuntimeSidecar(value: unknown): asserts value is Sidecar {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  exactKeys(value, [
    "assertions",
    "components",
    "dependency_modes",
    "profile",
    "release_eligible",
    "source_revision",
    "timings",
    "version",
  ]);
  const sidecar = value as Sidecar;
  assert.equal(sidecar.version, "cogs.stage3-real-runtime/v1alpha1");
  assert.match(sidecar.source_revision, /^[a-f0-9]{40}$/);
  assert.equal(sidecar.profile, "insecure-container");
  assert.equal(sidecar.release_eligible, false);
  exactKeys(sidecar.components, ["envoy", "openbao", "runtime_manager"]);
  exactKeys(sidecar.components.envoy, ["binary_sha256", "image_digest", "version"]);
  exactKeys(sidecar.components.openbao, ["image_digest", "version"]);
  exactKeys(sidecar.components.runtime_manager, ["mode"]);
  assert.equal(sidecar.components.envoy.version, "1.38.3");
  assert.match(sidecar.components.envoy.image_digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(sidecar.components.envoy.binary_sha256, /^sha256:[a-f0-9]{64}$/);
  assert.equal(sidecar.components.openbao.version, "2.6.0");
  assert.match(sidecar.components.openbao.image_digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(sidecar.components.runtime_manager.mode, "real");
  exactKeys(sidecar.dependency_modes, [
    "audit",
    "authorization",
    "identity",
    "network_enforcement",
    "revocation",
    "telemetry",
  ]);
  assert.deepEqual(sidecar.dependency_modes, {
    identity: "real",
    authorization: "real",
    audit: "real",
    revocation: "real",
    telemetry: "stubbed",
    network_enforcement: "not-applicable",
  });
  exactKeys(sidecar.timings, [...timingKeys]);
  for (const key of timingKeys) {
    assert.equal(Number.isSafeInteger(sidecar.timings[key]), true);
    assert.ok(sidecar.timings[key] >= 0);
  }
  assert.equal(sidecar.timings.revocation_poll_interval_ms, revocationPollIntervalMs);
  assert.equal(sidecar.timings.revocation_observation_bound_ms, revocationObservationBoundMs);
  assert.ok(sidecar.timings.credential_changed_callback_ms <= revocationObservationBoundMs);
  assert.ok(sidecar.timings.credential_changed_drain_probe_ms <= revocationObservationBoundMs);
  assert.ok(sidecar.timings.revoked_callback_ms <= revocationObservationBoundMs);
  assert.ok(sidecar.timings.revoked_drain_probe_ms <= revocationObservationBoundMs);
  assert.ok(sidecar.timings.harness_replacement_ready_ms <= sidecar.timings.harness_replacement_ready_bound_ms);
  exactKeys(sidecar.assertions, [...assertionKeys]);
  for (const key of assertionKeys) assert.equal(sidecar.assertions[key], true);
}

async function main(): Promise<void> {
  const started = new Date();
  const startedMs = Date.now();
  const state = await mkdtemp(join(tempRoot, "runtime-state-"));
  const walDirectory = join(state, "wal");
  await mkdir(walDirectory, { mode: 0o700 });
  const walPath = join(walDirectory, "egress.wal");
  const binaryHash = await phase(
    "hash_envoy_binary",
    async () =>
      `sha256:${createHash("sha256")
        .update(await readFile(envoyExecutable))
        .digest("hex")}`,
  );
  const version = await phase("verify_envoy_version", () => run(envoyExecutable, ["--version"], 10_000));
  assert.match(version.stdout, /1\.38\.3/);

  try {
    const pki = await phase("initialize_openbao", () => initializeOpenBao());
    caPem = pki.ca;
    upstreamCertificate = pki.leaf.certificate;
    upstreamPrivateKey = pki.leaf.privateKey;
    await phase("install_public_ca", () => installPublicCa(caPem, state));
    const upstream = await phase("start_upstream", () => startUpstream(upstreamCertificate, upstreamPrivateKey));
    try {
      const launch = launchFor(upstream.port);
      const identity = new StaticIdentity(() => scopedToken);
      const realPkiSource = new OpenBaoEgressPkiSource({
        origin: `${openBaoOrigin}/`,
        mount: "pki",
        role: "cogs-egress",
        identity,
        allowLoopbackHttpDevelopment: true,
        timeoutMs: 5_000,
        minValidityMarginMs: 1_000,
      });
      const pkiSource = Object.freeze({
        withPkiMaterial: <T>(
          request: Parameters<typeof realPkiSource.withPkiMaterial<T>>[0],
          consume: Parameters<typeof realPkiSource.withPkiMaterial<T>>[1],
        ) =>
          phase("issue_proxy_pki", () =>
            realPkiSource.withPkiMaterial(request, async (material) => {
              currentPhase = "runtime_scope_with_pki";
              return consume(material);
            }),
          ),
      });
      const timers = { setTimeout, clearTimeout };
      const replacements: { epoch: "A" | "B"; reason: string; atMs: number }[] = [];
      const startRuntime = async (epoch: "A" | "B", capability: string, wal: string, listenerPort: number) => {
        const controller = new AbortController();
        const manager = await phase(`start_runtime_manager_${epoch}`, () =>
          startCogsEgressRuntimeManager({
            launch,
            walPath: wal,
            listenerPort,
            maxSessionExpiresAtMs: Date.now() + 60 * 60 * 1000,
            completionCapacity: 8,
            revocation: {
              mode: "openbao",
              openbao: {
                origin: `${openBaoOrigin}/`,
                mount: "model",
                identity,
                allowLoopbackHttpDevelopment: true,
                timeoutMs: 5_000,
                maxResponseBytes: 16 * 1024,
              },
            },
            proxyCapability: capability,
            pkiSource,
            envoyProcess: Object.freeze({
              start: (request) =>
                phase(`start_envoy_process_${epoch}`, () =>
                  createNodeCogsEnvoyProcessPort({
                    executablePath: envoyExecutable,
                    startupTimeoutMs: 15_000,
                    closeTimeoutMs: 5_000,
                  }).start(request),
                ),
            }),
            randomSecret: (bytes) => `cogs-${randomBytes(bytes).toString("base64url")}`,
            onReplacementRequired: async (reason) => {
              replacements.push({ epoch, reason, atMs: Date.now() });
            },
            nowMs: Date.now,
            timers,
            signal: controller.signal,
            revocationPollIntervalMs,
            revocationMinPkiRemainingMs: 60_000,
            operationTimeoutMs: 5000,
          }),
        );
        managers.push(manager);
        return { manager, controller, listenerPort, wal };
      };

      const walPathA = walPath;
      const walPathB = join(walDirectory, "egress-b.wal");
      const runtimeA = await startRuntime("A", proxyCapability, walPathA, await reservePort());
      const materialExisted = await exists("/run/cogs/egress/envoy/bootstrap.json");
      assert.equal(runtimeA.manager.ready, true);
      const curlA = await phase("allowed_proxy_probe_v1", () =>
        proxyProbe(runtimeA.listenerPort, proxyCapability, upstream.port, routePath),
      );
      if (!curlA.ok || curlA.stdout !== "ok") throw new Error("proxy probe v1 failed");
      const beforeWrongCapabilityA = upstream.observations.length;
      const wrongCapabilityA = await phase("wrong_capability_denial_probe_a", () =>
        proxyProbe(runtimeA.listenerPort, wrongCapability, upstream.port, routePath, 3),
      );
      const wrongCapabilityADenied = !wrongCapabilityA.ok && upstream.observations.length === beforeWrongCapabilityA;
      if (!wrongCapabilityADenied) throw new Error("wrong capability reached upstream");
      const beforeWrongPathA = upstream.observations.length;
      const wrongPathA = await phase("wrong_path_denial_probe_a", () =>
        proxyProbe(runtimeA.listenerPort, proxyCapability, upstream.port, "/denied", 3),
      );
      const wrongPathADenied = !wrongPathA.ok && upstream.observations.length === beforeWrongPathA;
      if (!wrongPathADenied) throw new Error("wrong path reached upstream");
      const observationAfterA = upstream.observations.length;
      const mutationAStartedMs = Date.now();
      await phase("write_openbao_credential_v2", () => writeCredential(bearerTokenV2));
      const mutationACompletedMs = Date.now();
      const credentialChanged = await phase("wait_credential_changed", () =>
        waitForReplacement(
          runtimeA.manager,
          replacements,
          "A",
          "credential_changed",
          upstream.observations,
          observationAfterA,
          upstream.port,
          proxyCapability,
          runtimeA.listenerPort,
          mutationAStartedMs,
        ),
      );
      await runtimeA.manager.close().catch(() => undefined);
      const completionsA = runtimeA.manager.drainCompletions(8);
      const walRecordsA = await readWal(walPathA);
      runtimeA.controller.abort();

      const runtimeB = await startRuntime("B", proxyCapabilityV2, walPathB, await reservePort());
      const runtimeBReadyMs = Date.now() - mutationAStartedMs;
      if (runtimeBReadyMs > harnessReplacementReadyBoundMs)
        throw new Error("replacement runtime startup exceeded bound");
      assert.equal(runtimeB.manager.ready, true);
      const beforeOldCapability = upstream.observations.length;
      const oldCapabilityProbe = await phase("old_capability_denial_after_harness_replacement", () =>
        proxyProbe(runtimeB.listenerPort, proxyCapability, upstream.port, routePath, 3),
      );
      const oldCapabilityDenied = !oldCapabilityProbe.ok && upstream.observations.length === beforeOldCapability;
      if (!oldCapabilityDenied) throw new Error("old capability reached replacement runtime");
      const curlB = await phase("allowed_proxy_probe_v2", () =>
        proxyProbe(runtimeB.listenerPort, proxyCapabilityV2, upstream.port, routePath),
      );
      if (!curlB.ok || curlB.stdout !== "ok") throw new Error("proxy probe v2 failed");
      const observationAfterB = upstream.observations.length;
      const mutationBStartedMs = Date.now();
      await phase("soft_delete_openbao_credential_v2", () => deleteCredential());
      const mutationBCompletedMs = Date.now();
      const revoked = await phase("wait_revoked", () =>
        waitForReplacement(
          runtimeB.manager,
          replacements,
          "B",
          "revoked",
          upstream.observations,
          observationAfterB,
          upstream.port,
          proxyCapabilityV2,
          runtimeB.listenerPort,
          mutationBStartedMs,
        ),
      );
      await runtimeB.manager.close().catch(() => undefined);
      const completionsB = runtimeB.manager.drainCompletions(8);
      const walRecordsB = await readWal(walPathB);
      runtimeB.controller.abort();

      if (upstream.observations.length !== 2) throw new Error("upstream observation count assertion failed");
      const observedA = upstream.observations[0];
      const observedB = upstream.observations[1];
      if (!observedA || !observedB) throw new Error("upstream observations missing");
      if (observedA.authorization !== expectedAuthorization)
        throw new Error("credential v1 injection assertion failed");
      if (observedB.authorization !== expectedAuthorizationV2)
        throw new Error("credential v2 injection assertion failed");
      if (observedA.proxyAuthorization !== undefined || observedB.proxyAuthorization !== undefined)
        throw new Error("capability stripping assertion failed");
      if (walRecordsA.length !== 1 || walRecordsB.length !== 1) throw new Error("WAL intent count assertion failed");
      if (completionsA.length !== 1 || completionsB.length !== 1) throw new Error("completion count assertion failed");
      assert.ok(walRecordsA[0]);
      assert.ok(walRecordsB[0]);
      assert.ok(walRecordsA[0].timestamp_ms <= observedA.atMs);
      assert.ok(walRecordsB[0].timestamp_ms <= observedB.atMs);
      const completionA = completionsA.some((item) => item.intentId === walRecordsA[0]?.intent_id);
      const completionB = completionsB.some((item) => item.intentId === walRecordsB[0]?.intent_id);
      assert.deepEqual(
        replacements.map((item) => `${item.epoch}:${item.reason}`),
        ["A:credential_changed", "B:revoked"],
      );
      const tmpfsClean = !(await exists("/run/cogs/egress/envoy"));
      await phase("revoke_tokens", async () => {
        await revokeTokens();
        if (!scopedRevoked || !rootRevoked) throw new Error("OpenBao token revocation assertion failed");
      });
      const completed = new Date();
      const sidecar: Sidecar = {
        version: "cogs.stage3-real-runtime/v1alpha1",
        source_revision: sourceRevision,
        profile: "insecure-container",
        release_eligible: false,
        components: {
          envoy: { version: envoyVersion, image_digest: envoyDigest, binary_sha256: binaryHash },
          openbao: { version: openBaoVersion, image_digest: openBaoDigest },
          runtime_manager: { mode: "real" },
        },
        timings: {
          revocation_poll_interval_ms: revocationPollIntervalMs,
          revocation_observation_bound_ms: revocationObservationBoundMs,
          harness_replacement_ready_bound_ms: harnessReplacementReadyBoundMs,
          credential_write_ms: mutationACompletedMs - mutationAStartedMs,
          credential_changed_callback_ms: credentialChanged.callbackMs,
          credential_changed_drain_probe_ms: credentialChanged.drainProbeMs,
          harness_replacement_ready_ms: runtimeBReadyMs,
          credential_delete_ms: mutationBCompletedMs - mutationBStartedMs,
          revoked_callback_ms: revoked.callbackMs,
          revoked_drain_probe_ms: revoked.drainProbeMs,
        },
        dependency_modes: {
          identity: "real",
          authorization: "real",
          audit: "real",
          revocation: "real",
          telemetry: "stubbed",
          network_enforcement: "not-applicable",
        },
        assertions: {
          openbao_loopback_only: openBaoOrigin.startsWith("http://127.0.0.1:"),
          credential_v1_injected: observedA.authorization === expectedAuthorization,
          credential_v2_injected: observedB.authorization === expectedAuthorizationV2,
          baseline_wrong_capability_denied: wrongCapabilityADenied,
          baseline_wrong_path_denied: wrongPathADenied,
          proxy_capability_stripped_upstream:
            observedA.proxyAuthorization === undefined &&
            observedB.proxyAuthorization === undefined &&
            wrongCapabilityADenied &&
            wrongPathADenied,
          wal_intents_preceded_upstream:
            walRecordsA[0].timestamp_ms <= observedA.atMs && walRecordsB[0].timestamp_ms <= observedB.atMs,
          completions_correlated: completionA && completionB,
          credential_change_callback_observed: replacements.some(
            (item) => item.epoch === "A" && item.reason === "credential_changed",
          ),
          revoked_callback_observed: replacements.some((item) => item.epoch === "B" && item.reason === "revoked"),
          harness_driven_replacement_after_callback: true,
          old_capability_denied_after_replacement: oldCapabilityDenied,
          new_capability_invalidated_after_revocation: revoked.drainProbeMs <= revocationObservationBoundMs,
          tmpfs_material_existed_in_scope: materialExisted,
          tmpfs_cleanup_verified: tmpfsClean,
          scoped_token_revoked: scopedRevoked,
          root_token_revoked: rootRevoked,
          private_material_absent_from_reports: true,
          ca_private_key_not_returned: true,
          no_daemon_or_sandbox_replacement_claim: true,
        },
      };
      await phase("validate_sidecar", async () => assertValidRealRuntimeSidecar(sidecar));
      const report: SecurityReport = {
        version: "cogs.security-report/v1alpha1",
        report_id: `stage3-real-runtime-${sourceRevision.slice(0, 12)}`,
        source_revision: sourceRevision,
        profile: "insecure-container",
        authority: "functional-only",
        started_at: started.toISOString(),
        completed_at: completed.toISOString(),
        duration_ms: Date.now() - startedMs,
        environment: {
          os: platform(),
          architecture: arch(),
          runner:
            process.env.GITHUB_ACTIONS === "true" ? `GitHub Actions ${process.env.RUNNER_NAME ?? "unknown"}` : "local",
          runner_image: process.env.ImageOS ?? "local",
          runtime_versions: { node: process.version, envoy: envoyVersion, openbao: openBaoVersionText.trim() },
          metadata: {
            real_runtime_manager: true,
            openbao_loopback_only: true,
            revocation_poll_interval_ms: revocationPollIntervalMs,
            revocation_observation_bound_ms: revocationObservationBoundMs,
            harness_replacement_ready_bound_ms: harnessReplacementReadyBoundMs,
            credential_changed_callback_ms: credentialChanged.callbackMs,
            credential_changed_drain_probe_ms: credentialChanged.drainProbeMs,
            harness_replacement_ready_ms: runtimeBReadyMs,
            credential_write_ms: mutationACompletedMs - mutationAStartedMs,
            credential_delete_ms: mutationBCompletedMs - mutationBStartedMs,
            revoked_callback_ms: revoked.callbackMs,
            revoked_drain_probe_ms: revoked.drainProbeMs,
            credential_changed_callback_observed: true,
            revoked_callback_observed: true,
            harness_driven_replacement_after_production_callback: true,
            daemon_or_sandbox_replacement_proven: false,
            tmpfs_parent_verified: true,
            tmpfs_cleanup_verified: tmpfsClean,
            wal_intent_count: walRecordsA.length + walRecordsB.length,
            completion_count: completionsA.length + completionsB.length,
            proxy_capability_stripped_upstream: true,
            ca_private_key_not_returned: true,
          },
        },
        components: [
          { name: "cogs", version: "0.0.0" },
          { name: "envoy", version: envoyVersion, image_digest: envoyDigest },
          { name: "openbao", version: openBaoVersion, image_digest: openBaoDigest },
        ],
        dependencies: {
          authorization: { mode: "real", implementation: "Cogs ext_authz server and route policy" },
          audit: { mode: "real", implementation: "Cogs append-only WAL and Envoy completion correlation" },
          revocation: { mode: "real", implementation: "OpenBao KV-v2 metadata polling via production runtime binding" },
          identity: { mode: "real", implementation: "OpenBao scoped KV-v2 credential and PKI issue token" },
          network_enforcement: { mode: "not-applicable", implementation: "insecure-container functional profile" },
        },
        tests: [
          {
            id: "stage3.real-runtime.bearer",
            group: "credential-handling",
            result: "stubbed",
            release_eligible: false,
            duration_ms: Date.now() - startedMs,
            dependency_modes: {
              authorization: "real",
              audit: "real",
              identity: "real",
              revocation: "real",
              telemetry: "stubbed",
              network_enforcement: "not-applicable",
            },
            diagnostics_redacted:
              "Real runtime manager, Envoy process, OpenBao KV/PKI, metadata revocation callbacks, WAL, authz, tmpfs, and completion correlation passed in functional insecure-container evidence; telemetry remains stubbed and replacement is harness-driven after production callback.",
          },
        ],
        known_limitations: [
          "Functional insecure-container evidence only; no bypass, default-deny, guest-reachability, or release claim.",
          "WAL-to-OTLP buffering remains pending and telemetry is stubbed.",
          "Harness constructs the second runtime after observing the production replacement callback; no daemon or sandbox replacement automation is proven.",
          "KVM authoritative guest proxy client evidence is intentionally out of scope for this harness slice.",
        ],
      };
      await phase("validate_security_report", async () => assertValidSecurityReport(report));
      await phase("validate_redaction", async () =>
        assertNoSecrets({ report, sidecar }, [
          bearerToken,
          bearerTokenV2,
          expectedAuthorization,
          expectedAuthorizationV2,
          proxyCapability,
          proxyCapabilityV2,
          wrongCapability,
          secretHandle,
          upstreamPrivateKey,
          ...forbiddenSecrets,
        ]),
      );
      const paths = await phase("write_reports", () => writeReports(outputDirectory, report));
      await writeFile(
        resolve(outputDirectory, report.report_id, "stage3-real-runtime-sidecar.json"),
        `${JSON.stringify(sidecar, null, 2)}\n`,
        { mode: 0o600 },
      );
      const serialized = await readFile(paths.machine, "utf8");
      await phase("validate_redaction", async () =>
        assertNoSecrets(serialized, [
          bearerToken,
          bearerTokenV2,
          expectedAuthorization,
          expectedAuthorizationV2,
          proxyCapability,
          proxyCapabilityV2,
          wrongCapability,
          secretHandle,
          upstreamPrivateKey,
          ...forbiddenSecrets,
        ]),
      );
      for (const manager of managers) await manager.close().catch(() => undefined);
    } finally {
      await upstream.stop();
    }
  } finally {
    await Promise.all(managers.map((manager) => manager.close().catch(() => undefined)));
    await revokeTokens().catch(() => undefined);
    upstreamPrivateKey = "";
    upstreamCertificate = "";
    rootToken = "";
    scopedToken = "";
    forbiddenSecrets.clear();
    await rm(state, { recursive: true, force: true });
  }
}

async function initializeOpenBao(): Promise<{ ca: string; leaf: { certificate: string; privateKey: string } }> {
  const init = object(await bao("/v1/sys/init", { method: "POST", body: { secret_shares: 1, secret_threshold: 1 } }));
  rootToken = stringField(init, "root_token");
  forbiddenSecrets.add(rootToken);
  const keys = init.keys_base64;
  assert.ok(Array.isArray(keys));
  const unseal = String(keys[0]);
  forbiddenSecrets.add(unseal);
  await bao("/v1/sys/unseal", { method: "POST", body: { key: unseal } });
  await bao("/v1/sys/mounts/model", {
    method: "POST",
    token: rootToken,
    body: { type: "kv", options: { version: "2" } },
  });
  await bao(`/v1/model/data/${secretHandle}`, {
    method: "POST",
    token: rootToken,
    body: { data: { api_key: bearerToken } },
  });
  await bao("/v1/sys/mounts/pki", {
    method: "POST",
    token: rootToken,
    body: { type: "pki", config: { max_lease_ttl: "24h" } },
  });
  const root = object(
    await bao("/v1/pki/root/generate/internal", {
      method: "POST",
      token: rootToken,
      body: { common_name: "localhost", ttl: "24h" },
    }),
  );
  const data = object(root.data);
  if (Object.hasOwn(data, "private_key")) throw new Error("OpenBao CA response assertion failed");
  const ca = stringField(data, "certificate");
  await bao("/v1/pki/roles/cogs-egress", {
    method: "POST",
    token: rootToken,
    body: {
      allowed_domains: ["localhost"],
      allow_bare_domains: true,
      allow_subdomains: false,
      allow_localhost: false,
      max_ttl: "8h",
      ttl: "2h",
      key_type: "rsa",
      key_bits: 2048,
    },
  });
  const policy = [
    `path "model/data/${secretHandle}" { capabilities = ["read"] }`,
    `path "model/metadata/${secretHandle}" { capabilities = ["read"] }`,
    'path "pki/issue/cogs-egress" { capabilities = ["update"] }',
  ].join("\n");
  await bao("/v1/sys/policies/acl/cogs-stage3-runtime", { method: "PUT", token: rootToken, body: { policy } });
  const token = object(
    await bao("/v1/auth/token/create-orphan", {
      method: "POST",
      token: rootToken,
      body: { policies: ["cogs-stage3-runtime"], ttl: "15m", explicit_max_ttl: "15m", renewable: false },
    }),
  );
  scopedToken = stringField(object(token.auth), "client_token");
  forbiddenSecrets.add(scopedToken);
  const leaf = await issueLeaf(scopedToken);
  return { ca, leaf };
}

async function issueLeaf(token: string): Promise<{ certificate: string; privateKey: string }> {
  const issued = object(
    await bao("/v1/pki/issue/cogs-egress", { method: "POST", token, body: { common_name: "localhost", ttl: "1h" } }),
  );
  const data = object(issued.data);
  return { certificate: stringField(data, "certificate"), privateKey: stringField(data, "private_key") };
}

async function revokeTokens(): Promise<void> {
  if (scopedToken !== "") {
    const token = scopedToken;
    const revoke =
      rootToken === ""
        ? () => bao("/v1/auth/token/revoke-self", { method: "POST", token, body: {} })
        : () => bao("/v1/auth/token/revoke", { method: "POST", token: rootToken, body: { token } });
    await revoke().then(
      () => {
        scopedRevoked = true;
        scopedToken = "";
      },
      () => undefined,
    );
  }
  if (rootToken !== "") {
    const token = rootToken;
    await bao("/v1/auth/token/revoke-self", { method: "POST", token, body: {} }).then(
      () => {
        rootRevoked = true;
        rootToken = "";
      },
      () => undefined,
    );
  }
}

async function writeCredential(apiKey: string): Promise<void> {
  await bao(`/v1/model/data/${secretHandle}`, {
    method: "POST",
    token: rootToken,
    body: { data: { api_key: apiKey } },
  });
}

async function deleteCredential(): Promise<void> {
  await bao(`/v1/model/data/${secretHandle}`, { method: "DELETE", token: rootToken });
}

async function proxyProbe(
  listenerPort: number,
  capability: string,
  upstreamPort: number,
  path: string,
  maxTimeSeconds = 15,
): Promise<{ stdout: string; stderr: string; ok: boolean }> {
  try {
    const { stdout, stderr } = (await execFileAsync(
      "curl",
      [
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        String(maxTimeSeconds),
        "--proxy",
        `http://127.0.0.1:${listenerPort}`,
        "--noproxy",
        "",
        "--proxy-header",
        `Proxy-Authorization: ${capability}`,
        `https://localhost:${upstreamPort}${path}`,
      ],
      { timeout: (maxTimeSeconds + 5) * 1000, maxBuffer: 1024 * 1024, windowsHide: true },
    )) as { stdout: string; stderr: string };
    return { stdout, stderr, ok: true };
  } catch {
    return { stdout: "", stderr: "", ok: false };
  }
}

async function waitForReplacement(
  manager: CogsEgressRuntimeManager,
  replacements: readonly { epoch: "A" | "B"; reason: string; atMs: number }[],
  epoch: "A" | "B",
  reason: "credential_changed" | "revoked",
  observations: readonly unknown[],
  observationBaseline: number,
  upstreamPort: number,
  capability: string,
  listenerPort: number,
  mutationStartedMs: number,
): Promise<{ callbackMs: number; drainProbeMs: number }> {
  const deadline = mutationStartedMs + revocationObservationBoundMs;
  let wrongReason = "";
  while (Date.now() < deadline) {
    await delay(100);
    const epochCallbacks = replacements.filter((entry) => entry.epoch === epoch);
    const item = epochCallbacks.find((entry) => entry.reason === reason);
    const unexpected = epochCallbacks.find((entry) => entry.reason !== reason);
    if (unexpected) wrongReason = unexpected.reason;
    if (item) {
      const callbackMs = item.atMs - mutationStartedMs;
      if (callbackMs < 0 || callbackMs > revocationObservationBoundMs)
        throw new Error(`revocation ${reason} callback bound failed`);
      assert.equal(manager.ready, false);
      assert.equal(manager.replacementRequired, true);
      const probe = await proxyProbe(listenerPort, capability, upstreamPort, routePath, 3);
      const drainProbeMs = Date.now() - mutationStartedMs;
      if (probe.ok) throw new Error(`revocation ${reason} old listener still accepted proxy request`);
      if (observations.length !== observationBaseline)
        throw new Error(`revocation ${reason} old listener reached upstream`);
      if (drainProbeMs < 0 || drainProbeMs > revocationObservationBoundMs)
        throw new Error(`revocation ${reason} drain probe bound failed`);
      return { callbackMs, drainProbeMs };
    }
  }
  if (wrongReason !== "") throw new Error(`revocation ${reason} observed wrong callback reason ${wrongReason}`);
  throw new Error(`revocation ${reason} callback missing within bound`);
}

async function readWal(path: string): Promise<{ intent_id: string; route_id: string; timestamp_ms: number }[]> {
  return (await readFile(path, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { intent_id: string; route_id: string; timestamp_ms: number });
}

async function bao(path: string, init: { method: string; token?: string; body?: unknown }): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  let response: Response | undefined;
  try {
    const headers = new Headers({ accept: "application/json" });
    if (init.token) headers.set("x-vault-token", init.token);
    if (init.body !== undefined) headers.set("content-type", "application/json");
    response = await fetch(`${openBaoOrigin}${path}`, {
      method: init.method,
      headers,
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
      redirect: "error",
      signal: controller.signal,
    });
    const type = response.headers.get("content-type") ?? "";
    const length = response.headers.get("content-length");
    if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > 128 * 1024))
      throw new Error("OpenBao request failed");
    if (!response.ok) throw new Error("OpenBao request failed");
    const text = await boundedText(response, 128 * 1024);
    if (text === "") return {};
    if (!/^application\/json(?:\s*;|$)/i.test(type)) throw new Error("OpenBao request failed");
    try {
      return JSON.parse(text);
    } catch {
      throw new Error("OpenBao request failed");
    }
  } finally {
    clearTimeout(timeout);
    response?.body?.cancel().catch(() => undefined);
  }
}

function launchFor(port: number): LaunchConfig {
  const integration = {
    version: "cogs.integration/v1alpha1",
    id: integrationId,
    preset_revision: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    dns: { mode: "proxy-connect-authority", guest_resolution: false },
    rules: [
      {
        name: "localhost-get",
        host: "localhost",
        port,
        methods: ["GET"],
        path_patterns: [routePath],
        path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
        query_policy: { mode: "deny" },
        redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
        inject_auth: true,
      },
    ],
    auth: {
      type: "bearer_header",
      header: "Authorization",
      prefix: "Bearer ",
      placeholder: "COGS_PLACEHOLDER_STAGE3_BEARER",
      secret_handle: secretHandle,
    },
  };
  integration.preset_revision = canonicalPresetPolicyRevision(integration);
  return Object.freeze({
    version: "cogs.dev/v1alpha1",
    user_id: userId,
    session_id: sessionId,
    workspace_id: "workspace-stage3",
    sandbox: {
      ssh_endpoint: "127.0.0.1:22",
      ssh_host_key: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      client_key_path: "/tmp/key",
      proxy_auth_handle: "users/ci-user/proxy",
    },
    model: { provider: "anthropic", id: "claude-sonnet-4-5", credential_handle: "users/ci-user/model" },
    skills: {
      shared_revision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      shared_path: "/shared/skills",
      user_revision: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      user_path: "/user/skills",
    },
    integrations: [integration],
    limits: { cpu: 1, memory_bytes: 1024 * 1024 * 1024, tool_timeout_seconds: 30, max_tool_output_bytes: 1024 * 1024 },
  } as LaunchConfig);
}

async function startUpstream(
  certificate: string,
  key: string,
): Promise<{
  port: number;
  observations: { authorization?: string; proxyAuthorization?: string; atMs: number }[];
  stop(): Promise<void>;
}> {
  const observations: { authorization?: string; proxyAuthorization?: string; atMs: number }[] = [];
  const handler: Parameters<typeof createHttpsServer>[1] = (request, response) => {
    const authorization = header(request.headers.authorization);
    const proxyAuthorization = header(request.headers["proxy-authorization"]);
    observations.push({
      ...(authorization === undefined ? {} : { authorization }),
      ...(proxyAuthorization === undefined ? {} : { proxyAuthorization }),
      atMs: Date.now(),
    });
    response.writeHead(request.url === routePath ? 200 : 404, { "content-type": "text/plain" });
    response.end(request.url === routePath ? "ok" : "not found");
  };
  const ipv6 = createHttpsServer({ cert: certificate, key }, handler);
  const ipv4 = createHttpsServer({ cert: certificate, key }, handler);
  await new Promise<void>((resolve, reject) => {
    ipv6.once("error", reject);
    ipv6.listen({ port: 0, host: "::1", ipv6Only: true }, resolve);
  });
  const address = ipv6.address();
  assert.ok(address && typeof address !== "string");
  try {
    await new Promise<void>((resolve, reject) => {
      ipv4.once("error", reject);
      ipv4.listen(address.port, "127.0.0.1", resolve);
    });
  } catch (error) {
    await new Promise<void>((resolve) => ipv6.close(() => resolve()));
    throw error;
  }
  return {
    port: address.port,
    observations,
    stop: async () => {
      await Promise.all([closeServer(ipv4), closeServer(ipv6)]);
    },
  };
}

async function closeServer(server: ReturnType<typeof createHttpsServer>): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function reservePort(): Promise<number> {
  const server = createTcpServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

async function installPublicCa(certificate: string, directory: string): Promise<void> {
  const source = join(directory, "public-ca.crt");
  await writeFile(source, certificate, { mode: 0o600 });
  await run("sudo", ["-n", "install", "-m", "0644", "--", source, trustPath], 10_000);
  await run("sudo", ["-n", "update-ca-certificates"], 30_000);
}

async function run(
  command: string,
  args: readonly string[],
  timeout: number,
  allowFailure = false,
): Promise<{ stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = (await execFileAsync(command, [...args], {
      timeout,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    })) as { stdout: string; stderr: string };
    return { stdout, stderr };
  } catch {
    if (allowFailure) return { stdout: "", stderr: "" };
    throw new Error("external command failed");
  }
}
function requiredEnv(name: string, pattern: RegExp): string {
  const value = process.env[name];
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`missing ${name}`);
  return value;
}
function origin(value: string): string {
  const url = new URL(value);
  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "127.0.0.1");
  assert.equal(url.pathname, "/");
  return url.origin;
}
function object(value: unknown): Record<string, unknown> {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as Record<string, unknown>;
}
function exactKeys(value: unknown, keys: readonly string[]): void {
  const ownKeys = Reflect.ownKeys(object(value));
  if (!ownKeys.every((key) => typeof key === "string")) throw new Error("unexpected key");
  const actual = ownKeys.sort();
  assert.deepEqual(actual, [...keys].sort());
}

function stringField(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  assert.equal(typeof field, "string");
  assert.notEqual(field, "");
  return field as string;
}
function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value.join(",") : value;
}
async function exists(path: string): Promise<boolean> {
  return (await import("node:fs/promises")).access(path).then(
    () => true,
    () => false,
  );
}
async function delay(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
async function phase<T>(name: string, operation: () => Promise<T>): Promise<T> {
  currentPhase = name;
  return operation();
}
async function boundedText(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) throw new Error("OpenBao request failed");
      total += value.byteLength;
      if (total > maxBytes) throw new Error("OpenBao request failed");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}
function assertNoSecrets(value: unknown, forbidden: readonly string[]): void {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of forbidden) if (secret !== "") assert.equal(text.includes(secret), false);
  assert.doesNotMatch(text, /-----BEGIN (?:PRIVATE|RSA PRIVATE|EC PRIVATE) KEY-----/);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    void error;
    console.error(`stage3 real runtime phase failed: ${currentPhase}`);
    console.error("stage3 real runtime failed");
    process.exit(1);
  });
}
