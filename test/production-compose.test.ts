import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { ApiServer, ApiServerOptions, JsonValue } from "../src/api/server.ts";
import type { ModelApiKeySource, OpenBaoIdentityPort } from "../src/auth/model-auth.ts";
import type { CogsEgressRuntimeManager, CogsEgressRuntimeManagerOptions } from "../src/egress/runtime-manager.ts";
import type { LaunchConfig } from "../src/launch/config.ts";
import { LaunchLifecycle, type LaunchLifecycleOptions } from "../src/launch/lifecycle.ts";
import { type ProductionMainPort, runProductionMain } from "../src/main.ts";
import type { AuthenticatedCogsPiSessionOptions, CogsPiSessionPorts } from "../src/pi/session.ts";
import { ProductionWorkerError, type ProductionWorkerSeams, startProductionWorker } from "../src/runtime/compose.ts";
import type { RuntimeConfig } from "../src/runtime/config.ts";
import type { CogsPrivateSkillStore } from "../src/skills/local-private-store.ts";
import type { CogsSharedSkillOciResolver } from "../src/skills/oci-layout.ts";
import type { SshConnectionManager, SshConnectionManagerOptions } from "../src/ssh/connection.ts";
import { type CogsWorkerTelemetrySink, createCogsWorkerTelemetrySink } from "../src/telemetry/worker-telemetry.ts";

const secretBearer = "bearer-production-value-000000000000";
const secretProxy = "proxy-production-capability-00000";

function runtime(): RuntimeConfig {
  return {
    version: "cogs.runtime/v1alpha1",
    profile: "api-key-only",
    paths: {
      launch_document: "/etc/cogs/launch.json",
      api_bearer: "/run/cogs/api/bearer",
      openbao_jwt: "/run/cogs/openbao/jwt",
      proxy_capability: "/run/cogs/proxy/capability",
      envoy_executable: "/usr/local/bin/envoy",
      egress_tmpfs: "/run/cogs/egress",
      audit_wal: "/var/lib/cogs/session/egress-audit.wal",
      agent_directory: "/var/lib/cogs/session/agent",
      session_root: "/var/lib/cogs/session/sessions",
      shared_skill_oci: "/var/lib/cogs/skills/shared-oci",
      private_skill_source: "/var/lib/cogs/skills/private-source",
      private_skill_store: "/var/lib/cogs/skills/private-store",
    },
    api: { listen_host: "127.0.0.1", port: 18081 },
    openbao: {
      origin: "https://openbao.internal/",
      kubernetes_auth_mount: "kubernetes",
      kubernetes_auth_role: "worker",
      model_kv_mount: "model",
      egress_kv_mount: "egress",
      pki_mount: "pki",
      pki_role: "egress",
      projected_jwt_ttl_seconds: 600,
      max_client_token_ttl_seconds: 600,
    },
    otlp: {
      protocol: "http/json",
      traces_endpoint: "https://otlp.internal/v1/traces",
      metrics_endpoint: "https://otlp.internal/v1/metrics",
      logs_endpoint: "https://otlp.internal/v1/logs",
    },
    egress: { listener_port: 18080, revocation_poll_seconds: 1, completion_capacity: 8 },
    lifecycle: { maximum_session_seconds: 28800, shutdown_timeout_seconds: 1 },
  };
}

function launch(overrides: Partial<LaunchConfig> = {}): LaunchConfig {
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "alice",
    session_id: "session-1",
    workspace_id: "workspace-1",
    sandbox: {
      ssh_endpoint: "sandbox.internal:22",
      ssh_host_key: `SHA256:${"A".repeat(43)}`,
      client_key_path: "/run/cogs/ssh/session-1",
      proxy_auth_handle: "sessions/session-1/proxy",
    },
    model: { provider: "anthropic", id: "model-1", credential_handle: "users/alice/models/anthropic" },
    skills: {
      shared_revision: `sha256:${"a".repeat(64)}`,
      shared_path: "/shared/skills",
      user_revision: `sha256:${"b".repeat(64)}`,
      user_path: "/user/skills",
    },
    integrations: [
      {
        version: "cogs.integration/v1alpha1",
        id: "github",
        preset_revision: `sha256:${"c".repeat(64)}`,
        dns: { mode: "proxy-connect-authority", guest_resolution: false },
        auth: {
          type: "bearer_header",
          header: "Authorization",
          prefix: "Bearer ",
          placeholder: "COGS_PLACEHOLDER_GITHUB_TOKEN",
          secret_handle: "users/alice/integrations/github",
        },
        rules: [
          {
            name: "api",
            host: "api.github.com",
            port: 443,
            methods: ["GET"],
            path_patterns: ["/user"],
            path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
            query_policy: { mode: "deny" },
            redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
            inject_auth: true,
          },
        ],
      },
    ],
    limits: { cpu: 1, memory_bytes: 536870912, tool_timeout_seconds: 2, max_tool_output_bytes: 4096 },
    ...overrides,
  } as LaunchConfig;
}

function harness() {
  const log: string[] = [];
  let sshLost: (() => void) | undefined;
  let egressReady = true;
  let failAt = "";
  let cleanupFailure = "";
  let piState: "idle" | "running" = "idle";
  let sshOptions: SshConnectionManagerOptions | undefined;
  const maybe = (stage: string) => {
    log.push(stage);
    if (failAt === stage) throw new Error(`${secretBearer}:${secretProxy}`);
  };
  const identity: OpenBaoIdentityPort = Object.freeze({
    withToken: async (_signal: AbortSignal, operation: (token: string) => Promise<void>) => operation("openbao-token"),
  });
  const model: ModelApiKeySource = Object.freeze({
    withApiKey: async (
      _request: Parameters<ModelApiKeySource["withApiKey"]>[0],
      operation: (apiKey: string) => Promise<void>,
    ) => {
      maybe("auth.probe");
      await operation("model-api-key");
    },
  });
  const ssh = {
    get ready() {
      return true;
    },
    start: async () => maybe("ssh.start"),
    shutdown: async () => {
      maybe("ssh.close");
      if (cleanupFailure === "ssh") throw new Error("ssh close secret");
    },
  } as unknown as SshConnectionManager;
  const egress: CogsEgressRuntimeManager = Object.freeze({
    get ready() {
      return egressReady;
    },
    listenerPort: 18080,
    replacementRequired: false,
    drainCompletions: () => Object.freeze([]),
    close: async () => {
      maybe("egress.close");
      if (cleanupFailure === "egress") throw new Error("egress close secret");
    },
  });
  const pi = Object.freeze({
    input: async () => "running" as const,
    abort: async () => ({ aborted: false, runState: "idle" as const }),
    state: async () => {
      maybe("pi.state");
      return { runState: piState };
    },
    entries: async () => ({ entries: Object.freeze([]) }),
    createExport: async () => ({ mode: "raw" }) as JsonValue,
    dispose: async () => {
      maybe("pi.dispose");
      if (cleanupFailure === "pi") throw new Error("pi close secret");
    },
    disposeOwnedRuntime: async () => ({ version: "cogs.pi-owned-runtime-cleanup/v1alpha1", cleaned: true as const }),
    model: {} as CogsPiSessionPorts["model"],
    activeToolNames: () => Object.freeze(["read", "write", "edit", "bash"]),
    sessionFile: () => "/var/lib/cogs/session/sessions/session-1/session.jsonl",
    skillMetadata: () => undefined,
    gitMapRecords: () => Object.freeze([]),
    resolveGitMapping: async () => undefined,
    prepareShutdown: async () => {
      maybe("pi.prepare");
      return { version: "cogs.shutdown-ready/v1alpha1" };
    },
    navigate: async () => ({ cancelled: false }),
  }) as unknown as CogsPiSessionPorts;
  const api: ApiServer = Object.freeze({
    listen: async (port: number | undefined, host: string | undefined) => {
      maybe("api.listen");
      assert.equal(port, 18081);
      assert.equal(host, "127.0.0.1");
      return { port: port ?? 0 };
    },
    close: async () => {
      maybe("api.close");
      if (cleanupFailure === "api") throw new Error("api close secret");
    },
    publish: () => true,
  });
  let telemetry: CogsWorkerTelemetrySink;
  const seams: ProductionWorkerSeams = Object.freeze({
    readRuntime: async () => {
      maybe("runtime");
      return runtime();
    },
    readLaunch: async () => {
      maybe("launch");
      return launch();
    },
    readSecret: async (kind) => {
      maybe(`secret.${kind}`);
      return kind === "api-bearer" ? secretBearer : secretProxy;
    },
    createIdentity: () => {
      maybe("identity");
      return identity;
    },
    createTelemetry: () => {
      maybe("telemetry");
      const base = createCogsWorkerTelemetrySink({ mode: "disabled" });
      telemetry = Object.freeze({
        get ready() {
          return base.ready;
        },
        span: base.span,
        metric: base.metric,
        snapshot: base.snapshot,
        close: async (signal?: AbortSignal) => {
          maybe("telemetry.close");
          await base.close(signal);
        },
      });
      return telemetry;
    },
    prepareStorage: async () => {
      maybe("storage");
      return Object.freeze({
        shared: Object.freeze({ resolve: async () => undefined }) as unknown as CogsSharedSkillOciResolver,
        private: Object.freeze({
          snapshot: async () => undefined,
          resolve: async () => undefined,
        }) as unknown as CogsPrivateSkillStore,
      });
    },
    verifyAuditWal: async () => maybe("audit"),
    createModelStore: () => {
      maybe("model-store");
      return model;
    },
    createSsh: (options: SshConnectionManagerOptions) => {
      maybe("ssh.create");
      sshOptions = options;
      sshLost = () => options.onLost?.("lost");
      return ssh;
    },
    createEgress: async (options: CogsEgressRuntimeManagerOptions) => {
      maybe("egress.start");
      assert.equal(options.proxyCapability, secretProxy);
      assert.equal(options.launch.user_id, "alice");
      assert.equal(options.revocation.mode, "openbao");
      assert.equal(options.telemetry.mode, "otlp");
      return egress;
    },
    createLifecycle: (options: LaunchLifecycleOptions) => {
      maybe("lifecycle");
      return new LaunchLifecycle(options);
    },
    createPi: async (options: AuthenticatedCogsPiSessionOptions) => {
      maybe("pi");
      assert.equal(options.streamFn, undefined);
      assert.equal(options.ownedRuntime, undefined);
      return pi;
    },
    createApi: (options: ApiServerOptions) => {
      maybe("api");
      assert.equal(options.bearerToken, secretBearer);
      assert.equal(options.exporter, pi);
      assert.equal(options.lifecycle.ready, true);
      return api;
    },
    now: Date.now,
    randomSecret: () => "internal-random-secret-value",
  });
  return {
    log,
    seams,
    setFail(stage: string) {
      failAt = stage;
    },
    setCleanupFailure(stage: string) {
      cleanupFailure = stage;
    },
    setPiState(state: "idle" | "running") {
      piState = state;
    },
    sshOptions() {
      return sshOptions;
    },
    loseSsh() {
      sshLost?.();
    },
    loseEgress() {
      egressReady = false;
    },
  };
}

test("production SSH uses the sandbox image's single guest-root identity", async () => {
  const sshdConfig = await readFile(new URL("../images/sandbox/sshd_config", import.meta.url), "utf8");
  const allowedUsers = sshdConfig
    .split("\n")
    .filter((line) => line.startsWith("AllowUsers "))
    .flatMap((line) => line.slice("AllowUsers ".length).trim().split(/\s+/u));
  assert.deepEqual(allowedUsers, ["root"]);

  const h = harness();
  const worker = await startProductionWorker({ seams: h.seams });
  assert.equal(h.sshOptions()?.config.username, allowedUsers[0]);
  await worker.close();
});

test("production composition starts in one exact fail-closed order and closes reverse-owned order", async () => {
  const h = harness();
  const worker = await startProductionWorker({ seams: h.seams }).catch((error) => {
    assert.fail(`startup failed after ${h.log.join(",")}: ${String(error)}`);
  });
  assert.equal(worker.ready, true);
  assert.deepEqual(h.log, [
    "runtime",
    "launch",
    "secret.api-bearer",
    "secret.proxy-capability",
    "identity",
    "telemetry",
    "model-store",
    "lifecycle",
    "storage",
    "ssh.create",
    "ssh.start",
    "auth.probe",
    "audit",
    "egress.start",
    "pi",
    "api",
    "api.listen",
  ]);
  await worker.close();
  await worker.close();
  await worker.closed;
  assert.deepEqual(h.log.slice(-7), [
    "api.close",
    "pi.state",
    "pi.prepare",
    "pi.dispose",
    "egress.close",
    "ssh.close",
    "telemetry.close",
  ]);
});

test("every production startup seam fails generically, redacts secrets, and rolls back only acquired owners", async () => {
  const stages = [
    "runtime",
    "launch",
    "secret.api-bearer",
    "secret.proxy-capability",
    "identity",
    "telemetry",
    "model-store",
    "lifecycle",
    "storage",
    "ssh.create",
    "ssh.start",
    "auth.probe",
    "audit",
    "egress.start",
    "pi",
    "api",
    "api.listen",
  ];
  for (const stage of stages) {
    const h = harness();
    h.setFail(stage);
    await assert.rejects(
      startProductionWorker({ seams: h.seams }),
      (error: unknown) => {
        assert.ok(error instanceof ProductionWorkerError, stage);
        assert.equal(error.message, "production worker unavailable");
        assert.doesNotMatch(
          `${error.name}:${error.message}:${error.stack ?? ""}`,
          /bearer-production|proxy-production/,
        );
        return true;
      },
      stage,
    );
  }
});

test("dependency loss revokes the runtime, and close uncertainty remains a generic failure", async () => {
  const lost = harness();
  const worker = await startProductionWorker({ seams: lost.seams });
  lost.loseSsh();
  await assert.rejects(worker.closed, ProductionWorkerError);
  assert.ok(lost.log.indexOf("api.close") < lost.log.indexOf("egress.close"));

  const egressLost = harness();
  const egressWorker = await startProductionWorker({ seams: egressLost.seams });
  egressLost.loseEgress();
  await new Promise((resolve) => setTimeout(resolve, 150));
  await assert.rejects(egressWorker.closed, ProductionWorkerError);

  const uncertain = harness();
  uncertain.setCleanupFailure("egress");
  const second = await startProductionWorker({ seams: uncertain.seams });
  await assert.rejects(second.close(), ProductionWorkerError);
  await assert.rejects(second.closed, ProductionWorkerError);
});

test("late egress startup remains owned and is closed after startup abort", async () => {
  const h = harness();
  const controller = new AbortController();
  let enter!: () => void;
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  let release!: () => void;
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let closes = 0;
  const manager: CogsEgressRuntimeManager = Object.freeze({
    ready: true,
    listenerPort: 18080,
    replacementRequired: false,
    drainCompletions: () => Object.freeze([]),
    close: async () => {
      closes += 1;
    },
  });
  const seams: ProductionWorkerSeams = Object.freeze({
    ...h.seams,
    createEgress: async () => {
      enter();
      await delayed;
      return manager;
    },
  });
  const start = startProductionWorker({ signal: controller.signal, seams });
  await entered;
  controller.abort();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(closes, 0);
  release();
  await assert.rejects(start, ProductionWorkerError);
  assert.equal(closes, 1);
});

test("caller abort is bounded/idempotent and a running Pi turn is disposed without claiming a settled export", async () => {
  const h = harness();
  h.setPiState("running");
  const controller = new AbortController();
  const worker = await startProductionWorker({ signal: controller.signal, seams: h.seams });
  controller.abort();
  controller.abort();
  await worker.closed;
  assert.equal(h.log.filter((item) => item === "api.close").length, 1);
  assert.equal(h.log.filter((item) => item === "pi.dispose").length, 1);
  assert.equal(h.log.includes("pi.prepare"), false);
});

test("production rejects organization-scoped model and integration API-key handles before reading secrets", async () => {
  const modelHarness = harness();
  const badModel = {
    ...modelHarness.seams,
    readLaunch: async () => launch({ model: { ...launch().model, credential_handle: "organizations/acme/model/key" } }),
  };
  await assert.rejects(startProductionWorker({ seams: badModel }), ProductionWorkerError);
  assert.equal(
    modelHarness.log.some((item) => item.startsWith("secret.")),
    false,
  );

  const integrationHarness = harness();
  const document = launch();
  const integration = document.integrations[0] as Record<string, JsonValue>;
  const badIntegration = {
    ...integrationHarness.seams,
    readLaunch: async () =>
      launch({
        integrations: [
          {
            ...integration,
            auth: {
              ...(integration.auth as Record<string, JsonValue>),
              secret_handle: "organizations/acme/integrations/github",
            },
          },
        ],
      }),
  };
  await assert.rejects(startProductionWorker({ seams: badIntegration }), ProductionWorkerError);
  assert.equal(
    integrationHarness.log.some((item) => item.startsWith("secret.")),
    false,
  );
});

test("main coalesces SIGINT/SIGTERM into one bounded close and removes both handlers", async () => {
  const handlers = new Map<string, () => void>();
  let resolveClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  let closes = 0;
  let cleared = 0;
  let failed = 0;
  let hardDeadlineMs = 0;
  const port: ProductionMainPort = Object.freeze({
    start: async () =>
      Object.freeze({
        ready: true as const,
        apiPort: 18081,
        closed,
        close: async () => {
          closes += 1;
          resolveClosed();
        },
      }),
    on: (signal, listener) => handlers.set(signal, listener),
    off: (signal) => handlers.delete(signal),
    setTimer: (_callback, milliseconds) => {
      hardDeadlineMs = milliseconds;
      return Object.freeze({});
    },
    clearTimer: () => {
      cleared += 1;
    },
    failClosed: () => {
      failed += 1;
    },
    hardStop: () => {
      throw new Error("hard deadline");
    },
  });
  const running = runProductionMain(port);
  await new Promise((resolve) => setImmediate(resolve));
  handlers.get("SIGTERM")?.();
  handlers.get("SIGINT")?.();
  await running;
  assert.equal(closes, 1);
  assert.equal(cleared, 1);
  assert.equal(hardDeadlineMs, 31_000);
  assert.equal(failed, 0);
  assert.equal(handlers.size, 0);
});

test("main arms and preserves the hard deadline after spontaneous runtime loss", async () => {
  let failClosed = 0;
  let timers = 0;
  let cleared = 0;
  let deadline = 0;
  const port: ProductionMainPort = Object.freeze({
    start: async () =>
      Object.freeze({
        ready: true as const,
        apiPort: 18081,
        closed: Promise.reject(new Error(secretBearer)),
        close: async () => undefined,
      }),
    on: () => undefined,
    off: () => undefined,
    setTimer: (_callback, milliseconds) => {
      timers += 1;
      deadline = milliseconds;
      return Object.freeze({});
    },
    clearTimer: () => {
      cleared += 1;
    },
    failClosed: () => {
      failClosed += 1;
    },
    hardStop: () => {
      throw new Error("hard deadline");
    },
  });
  await runProductionMain(port);
  assert.equal(failClosed, 1);
  assert.equal(timers, 1);
  assert.equal(deadline, 31_000);
  assert.equal(cleared, 0);
});

test("main arms and preserves the hard deadline when startup ownership is uncertain", async () => {
  let failed = 0;
  let timers = 0;
  let cleared = 0;
  const port: ProductionMainPort = Object.freeze({
    start: async () => {
      throw new Error(secretBearer);
    },
    on: () => undefined,
    off: () => undefined,
    setTimer: (_callback, milliseconds) => {
      assert.equal(milliseconds, 31_000);
      timers += 1;
      return Object.freeze({});
    },
    clearTimer: () => {
      cleared += 1;
    },
    failClosed: () => {
      failed += 1;
    },
    hardStop: () => {
      throw new Error("hard deadline");
    },
  });
  await runProductionMain(port);
  assert.equal(failed, 1);
  assert.equal(timers, 1);
  assert.equal(cleared, 0);
});

test("production import boundary and foundation docs preserve the implemented-source/non-authority split", async () => {
  const [compose, main, foundation] = await Promise.all([
    readFile(new URL("../src/runtime/compose.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/main.ts", import.meta.url), "utf8"),
    readFile(new URL("../docs/operations/production-runtime-foundation.md", import.meta.url), "utf8"),
  ]);
  const source = `${compose}\n${main}`;
  assert.doesNotMatch(source, /(?:from|import\()\s*["'][^"']*dev\//);
  assert.doesNotMatch(
    source,
    /deterministic|fixture|oauth|process\.env|AWS|terraform|tofu|docker|kubernetes-client|@kubernetes/iu,
  );
  assert.doesNotMatch(source, /child_process|execFile|\bspawn\(/u);
  assert.match(compose, /executablePath:\s*runtime\.paths\.envoy_executable/u);
  assert.match(compose, /exporter:\s*pi/u);
  assert.match(compose, /mode:\s*"otlp"/u);
  assert.match(foundation, /now provide `src\/main\.ts`, fail-closed production composition/u);
  assert.match(foundation, /Helm chart remains NOTES-only with zero submitted manifests/u);
  assert.match(foundation, /readiness v5 removes `RELEASE_IMAGE_SET_ABSENT`/iu);
  assert.match(foundation, /`NO_EXECUTABLE_PROVIDER_ROUTE`; and every false runtime\/provider\/Kubernetes\/cloud/u);
  assert.doesNotMatch(foundation, /following remain unimplemented:[\s\S]*`src\/main\.ts`/u);
});
