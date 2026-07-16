import assert from "node:assert/strict";
import { test } from "node:test";
import npmPreset from "../integrations/presets/npm-v1.json" with { type: "json" };
import type { EgressAuditWal, EgressAuditWalRecord } from "../src/egress/audit-wal.ts";
import type { CogsEgressPkiMaterial, CogsEgressPkiSource } from "../src/egress/egress-material.ts";
import type { CogsEnvoyProcessPort } from "../src/egress/envoy-process.ts";
import type { CogsEnvoyCredentialSource, CogsEnvoyRuntimeConfig } from "../src/egress/envoy-runtime-config.ts";
import type { CogsExtAuthzServer } from "../src/egress/ext-authz-server.ts";
import type { CogsEgressRevocationSnapshot, CogsEgressRevocationTimers } from "../src/egress/revocation-watcher.ts";
import { lowerLaunchEgressRoutePlan } from "../src/egress/route-policy.ts";
import {
  aggregateCogsEgressRoutePlanRevision,
  CogsEgressRuntimeManagerError,
  startCogsEgressRuntimeManager,
} from "../src/egress/runtime-manager.ts";
import type { LaunchConfig } from "../src/launch/config.ts";

const raw = "host.example/path?token=secret users/preset-user/integrations/npm workspace";
const generic = (error: unknown) => {
  assert.ok(error instanceof CogsEgressRuntimeManagerError);
  assert.equal(error.code, "COGS_EGRESS_RUNTIME_MANAGER_FAILED");
  assert.equal(error.message, "egress runtime manager unavailable");
  assert.equal(String(error.stack ?? "").includes(raw), false);
  return true;
};

test("starts with listenerPort-only frozen surface and separates trusted proxy capability from generated authz token", async () => {
  const fixture = fixtureRuntime();
  const manager = await startCogsEgressRuntimeManager(fixture.options());
  assert.equal(manager.ready, true);
  assert.equal(manager.listenerPort, 15001);
  assert.equal("proxyUrl" in manager, false);
  assert.throws(() => ((manager as { listenerPort: number }).listenerPort = 1), TypeError);
  assert.deepEqual(fixture.secretCalls, [32]);
  assert.equal(fixture.authzOptions?.internalAuthzToken, "S".repeat(32));
  assert.equal(fixture.authzOptions?.proxyCapability, "P".repeat(32));
  assert.equal(fixture.openWalOptions?.maxBytes, 1024 * 1024);
  assert.equal(fixture.openWalOptions?.maxRecords, 10_000);
  assert.equal(fixture.openWalOptions?.maxRecordBytes, 4096);
  assert.equal(fixture.processBootstrapPath, "/run/cogs/egress/envoy/bootstrap.json");
  await manager.close();
});

test("aggregate route-plan revision hashes only sorted id and revision and rejects hostile plans", () => {
  const plan = lowerLaunchEgressRoutePlan(launch());
  const revision = aggregateCogsEgressRoutePlanRevision(plan);
  assert.match(revision, /^sha256:[a-f0-9]{64}$/);
  const first = plan.integrations[0] ?? assert.fail("missing integration");
  const duplicate = Object.freeze({
    routeCount: 2,
    integrations: Object.freeze([first, first]),
  });
  assert.throws(() => aggregateCogsEgressRoutePlanRevision(duplicate), generic);
  assert.throws(() => aggregateCogsEgressRoutePlanRevision({ routeCount: 1, integrations: "bad" } as never), generic);
});

test("revocation performs deny authz, process drain final completion, replacement callback, and release", async () => {
  const fixture = fixtureRuntime();
  const manager = await startCogsEgressRuntimeManager(fixture.options());
  fixture.revocation = snap({ revoked: true });
  fixture.timers.tick(50);
  await flush();
  assert.deepEqual(fixture.events, ["authz.close", "process.close", "replacement:revoked"]);
  assert.equal(manager.ready, false);
  assert.equal(manager.replacementRequired, true);
  assert.deepEqual(manager.drainCompletions(4), [
    {
      intentId: "intent",
      sequence: 1,
      routeId: "npm:npm-registry-metadata:GET:0",
      responseCode: 200,
      durationMs: 1,
      completedAtMs: 5000,
    },
  ]);
  assert.deepEqual(manager.drainCompletions(4), []);
});

test("replacement callback failure still releases scope and cleanup attempts all stages", async () => {
  const fixture = fixtureRuntime({ replacementRejects: true });
  const manager = await startCogsEgressRuntimeManager(fixture.options());
  fixture.revocation = snap({ revoked: true });
  fixture.timers.tick(50);
  await flush();
  assert.equal(manager.ready, false);
  await flush();
  await flush();
  assert.equal(fixture.scopeReleased, true);
  assert.ok(fixture.events.includes("authz.close"));
  assert.ok(fixture.events.includes("process.close"));
  assert.ok(fixture.events.includes("wal.close"));
});

test("scope rejection and unexpected normal completion after publication fail closed without unhandled rejection", async () => {
  const rejecting = fixtureRuntime({ scopeRejects: true });
  const manager = await startCogsEgressRuntimeManager(rejecting.options());
  rejecting.rejectScope?.(new Error(raw));
  await flush();
  await flush();
  assert.equal(manager.ready, false);
  assert.ok(rejecting.events.includes("wal.close"));

  const completing = fixtureRuntime({ scopeCompletes: true });
  const second = await startCogsEgressRuntimeManager(completing.options());
  completing.releaseScope?.();
  await flush();
  assert.equal(second.ready, false);
  assert.ok(completing.events.includes("wal.close"));
});

test("sticky dependency readiness loss initiates cleanup and close failure keeps one rejected close promise", async () => {
  const fixture = fixtureRuntime({ authzCloseFailsOnce: true });
  const manager = await startCogsEgressRuntimeManager(fixture.options());
  fixture.processReady = false;
  assert.equal(manager.ready, false);
  await flush();
  const first = manager.close();
  const second = manager.close();
  assert.equal(first, second);
  await assert.rejects(first, generic);
  await assert.rejects(second, generic);
  assert.equal(fixture.authzCloseAttempts, 1);
});

test("hostile ready getter is generic, sticky, and cleans during startup gate", async () => {
  const fixture = fixtureRuntime({ processReadyThrows: true });
  await assert.rejects(startCogsEgressRuntimeManager(fixture.options()), generic);
  assert.ok(fixture.events.includes("wal.close"));
});

test("canonical path and invalid injected port fail before side effects", async () => {
  const fixture = fixtureRuntime();
  await assert.rejects(startCogsEgressRuntimeManager(fixture.options({ walPath: "/tmp/../tmp/wal" })), generic);
  await assert.rejects(
    startCogsEgressRuntimeManager(fixture.options({ ports: { openWal: undefined as never } })),
    generic,
  );
  await assert.rejects(
    startCogsEgressRuntimeManager(fixture.options({ ports: { startAuthz: "bad" as never } })),
    generic,
  );
  assert.equal(fixture.openWalCalls, 0);
});

test("normal close uses one promise, closes in order, and preserves final completions", async () => {
  const fixture = fixtureRuntime();
  const manager = await startCogsEgressRuntimeManager(fixture.options());
  const first = manager.close();
  const second = manager.close();
  assert.equal(first, second);
  await first;
  assert.deepEqual(fixture.events, ["authz.close", "process.close", "wal.close"]);
  assert.equal(fixture.scopeReleased, true);
  assert.deepEqual(
    manager.drainCompletions(1).map((item) => item.intentId),
    ["intent"],
  );
});

test("startup failures clean already-owned resources and stay generic", async () => {
  for (const [flag, expected] of [
    ["openWalFails", []],
    ["authzFails", ["wal.close"]],
    ["pkiFails", ["authz.close", "wal.close"]],
    ["configFails", ["authz.close", "wal.close"]],
    ["tmpfsFails", ["authz.close", "wal.close"]],
    ["processFails", ["authz.close", "wal.close"]],
    ["watcherFails", ["authz.close", "process.close", "wal.close"]],
  ] as const) {
    const fixture = fixtureRuntime({ [flag]: true });
    await assert.rejects(startCogsEgressRuntimeManager(fixture.options()), generic);
    for (const event of expected) assert.ok(fixture.events.includes(event), `${flag}:${event}`);
  }
});

function fixtureRuntime(
  flags: {
    replacementRejects?: boolean;
    scopeRejects?: boolean;
    scopeCompletes?: boolean;
    authzCloseFailsOnce?: boolean;
    openWalFails?: boolean;
    authzFails?: boolean;
    configFails?: boolean;
    tmpfsFails?: boolean;
    processFails?: boolean;
    processReadyThrows?: boolean;
    pkiFails?: boolean;
    watcherFails?: boolean;
  } = {},
) {
  const timers = new ManualTimers();
  const events: string[] = [];
  const secretCalls: number[] = [];
  let authzOptions: { internalAuthzToken: string; proxyCapability: string } | undefined;
  let revocation = snap();
  let processReady = true;
  let openWalCalls = 0;
  let openWalOptions: { maxBytes: number; maxRecords: number; maxRecordBytes: number } | undefined;
  let processBootstrapPath = "";
  let authzCloseAttempts = 0;
  let scopeReleased = false;
  let releaseScope: (() => void) | undefined;
  let rejectScope: ((error: Error) => void) | undefined;
  let records: readonly EgressAuditWalRecord[] = [];
  const wal: EgressAuditWal = {
    get ready() {
      return true;
    },
    get records() {
      return records;
    },
    async append() {
      return Object.freeze({
        version: "cogs.egress-intent/v1alpha1",
        sequence: 1,
        intent_id: "intent",
        timestamp_ms: 1,
        session_id: "session",
        integration_id: "npm",
        route_id: "npm:npm-registry-metadata:GET:0",
        method: "GET",
        credential_required: true,
      });
    },
    async close() {
      events.push("wal.close");
    },
  };
  const credentialSource: CogsEnvoyCredentialSource = {
    async withCredential(_request, consume) {
      await consume(Object.freeze({ type: "bearer", token: "T".repeat(16) }));
    },
  };
  const pkiSource: CogsEgressPkiSource = {
    async withPkiMaterial(_request, consume) {
      if (flags.pkiFails) throw new Error(raw);
      return consume(material());
    },
  };
  const envoyProcess: CogsEnvoyProcessPort = {
    async start(input) {
      processBootstrapPath = input.bootstrapPath;
      return Object.freeze({
        get ready() {
          if (flags.processReadyThrows) throw new Error(raw);
          return processReady;
        },
        async close() {
          events.push("process.close");
          records = [
            await wal.append({
              session_id: "session",
              integration_id: "npm",
              route_id: "npm:npm-registry-metadata:GET:0",
              method: "GET",
              credential_required: true,
            }),
          ];
          await input.onCompletionLine(
            '{"event":"request-complete","intent_id":"intent","route_id":"npm:npm-registry-metadata:GET:0","response_code":"200","duration_ms":"1"}',
          );
        },
      });
    },
  };
  const ports = {
    async openWal(options: { maxBytes: number; maxRecords: number; maxRecordBytes: number }) {
      openWalCalls++;
      openWalOptions = options;
      if (flags.openWalFails) throw new Error(raw);
      return wal;
    },
    async startAuthz(options: { internalAuthzToken: string; proxyCapability: string }) {
      if (flags.authzFails) throw new Error(raw);
      authzOptions = options;
      return Object.freeze({
        target: "127.0.0.1:12345",
        ready: true,
        async close() {
          events.push("authz.close");
          authzCloseAttempts++;
          if (flags.authzCloseFailsOnce && authzCloseAttempts === 1) throw new Error(raw);
        },
      }) as CogsExtAuthzServer;
    },
    async withConfig<T>(
      _options: unknown,
      _source: CogsEnvoyCredentialSource,
      operation: (config: CogsEnvoyRuntimeConfig) => Promise<T>,
    ) {
      if (flags.configFails) throw new Error(raw);
      return operation(config());
    },
    async withTmpfs<T>(
      _config: CogsEnvoyRuntimeConfig,
      _pki: CogsEgressPkiMaterial,
      operation: (paths: CogsEnvoyRuntimeConfig["paths"]) => Promise<T>,
    ) {
      if (flags.tmpfsFails) throw new Error(raw);
      const operationPromise = operation(config().paths);
      if (flags.scopeCompletes) {
        operationPromise.catch(() => undefined);
        scopeReleased = true;
        return undefined as T;
      }
      if (flags.scopeRejects) {
        operationPromise.catch(() => undefined);
        await new Promise<void>((_resolve, reject) => {
          rejectScope = reject;
        }).finally(() => {
          scopeReleased = true;
        });
        return undefined as T;
      }
      try {
        return await operationPromise;
      } finally {
        scopeReleased = true;
      }
    },
  };
  const options = (patch: Partial<Parameters<typeof startCogsEgressRuntimeManager>[0]> = {}) => ({
    launch: launch(),
    walPath: "/tmp/cogs-egress.wal",
    listenerPort: 15001,
    maxSessionExpiresAtMs: 20_000,
    completionCapacity: 8,
    credentialVersion: "cred1",
    proxyCapability: "P".repeat(32),
    credentialSource,
    pkiSource,
    revocationSource: { read: async () => (flags.watcherFails ? snap({ revoked: true }) : revocation) },
    envoyProcess: flags.processFails
      ? {
          start: async () => {
            throw new Error(raw);
          },
        }
      : envoyProcess,
    randomSecret(bytes: number) {
      secretCalls.push(bytes);
      return "S".repeat(bytes);
    },
    async onReplacementRequired(reason: string) {
      events.push(`replacement:${reason}`);
      if (flags.replacementRejects) throw new Error(raw);
    },
    nowMs: () => 5000,
    timers,
    revocationPollIntervalMs: 50,
    revocationMinPkiRemainingMs: 1000,
    operationTimeoutMs: 50,
    ports,
    ...patch,
  });
  return {
    get authzCloseAttempts() {
      return authzCloseAttempts;
    },
    get authzOptions() {
      return authzOptions;
    },
    get openWalCalls() {
      return openWalCalls;
    },
    get openWalOptions() {
      return openWalOptions;
    },
    get processBootstrapPath() {
      return processBootstrapPath;
    },
    get processReady() {
      return processReady;
    },
    set processReady(value: boolean) {
      processReady = value;
    },
    get revocation() {
      return revocation;
    },
    set revocation(value: CogsEgressRevocationSnapshot) {
      revocation = value;
    },
    get scopeReleased() {
      return scopeReleased;
    },
    events,
    options,
    get rejectScope() {
      return rejectScope;
    },
    get releaseScope() {
      return releaseScope;
    },
    secretCalls,
    timers,
  };
}

function launch(): LaunchConfig {
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "preset-user",
    session_id: "session",
    workspace_id: "workspace",
    sandbox: {
      ssh_endpoint: "127.0.0.1:22",
      ssh_host_key: "SHA256:x",
      client_key_path: "/tmp/key",
      proxy_auth_handle: "h",
    },
    model: { provider: "p", id: "m", credential_handle: "users/preset-user/model" },
    skills: { shared_revision: "s", shared_path: "/shared/skills", user_revision: "u", user_path: "/user/skills" },
    integrations: [npmPreset],
    limits: { cpu: 1, memory_bytes: 1, tool_timeout_seconds: 1, max_tool_output_bytes: 1 },
  };
}

function snap(patch: Partial<CogsEgressRevocationSnapshot> = {}): CogsEgressRevocationSnapshot {
  return Object.freeze({
    presetRevision: aggregateCogsEgressRoutePlanRevision(lowerLaunchEgressRoutePlan(launch())),
    credentialVersion: "cred1",
    revoked: false,
    pkiExpiresAtMs: 10_000,
    ...patch,
  });
}

function material(): CogsEgressPkiMaterial {
  return Object.freeze({
    certificateChainPem: "cert",
    privateKeyPem: "key",
    caCertificatePem: "ca",
    expiresAtMs: 10_000,
  });
}

function config(): CogsEnvoyRuntimeConfig {
  return Object.freeze({
    paths: Object.freeze({
      bootstrap: "/run/cogs/egress/envoy/bootstrap.json",
      proxyCertificate: "/run/cogs/egress/envoy/proxy-cert.pem",
      proxyPrivateKey: "/run/cogs/egress/envoy/proxy-key.pem",
      proxyCaCertificate: "/run/cogs/egress/envoy/proxy-ca.pem",
    }),
    bootstrapJson: "{}",
    routeCount: 1,
  });
}

async function flush(): Promise<void> {
  for (let index = 0; index < 20; index++) await Promise.resolve();
}

class ManualTimers implements CogsEgressRevocationTimers {
  private now = 0;
  private id = 0;
  private readonly timers = new Map<number, { at: number; callback: () => void }>();
  public setTimeout(callback: () => void, ms: number): number {
    const id = ++this.id;
    this.timers.set(id, { at: this.now + ms, callback });
    return id;
  }
  public clearTimeout(timer: unknown): void {
    this.timers.delete(Number(timer));
  }
  public tick(ms: number): void {
    this.now += ms;
    for (const [id, timer] of [...this.timers.entries()].sort((a, b) => a[1].at - b[1].at)) {
      if (timer.at <= this.now && this.timers.delete(id)) timer.callback();
    }
  }
}
