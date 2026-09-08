import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import {
  ENVOY_IMAGE,
  type EnvoyEgressSeams,
  observeLauncherClose,
  prepareEnvoyBinary,
  startEnvoyEgress as startUnarmedEnvoyEgress,
} from "../dev/launcher/envoy-egress.ts";
import { KvmRelay } from "../dev/launcher/kvm-relay.ts";
import type { OpenBaoHandle, SecretHolder } from "../dev/launcher/openbao.ts";
import { createState, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";
import { OpenBaoEgressPkiSource } from "../src/egress/openbao-pki.ts";
import { canonicalPresetPolicyRevision } from "../src/egress/preset-revision.ts";
import { lowerLaunchEgressRoutePlan } from "../src/egress/route-policy.ts";
import {
  type CogsEgressRuntimeManagerOptions,
  type CogsEgressRuntimeObservation,
  registerCogsEgressRuntimeObserver,
} from "../src/egress/runtime-manager.ts";
import { createCloseOwner, registerCloseOwner } from "../src/launch/close.ts";

// Hold a pristine trusted baseline until arming, then expose the test window.
async function startEnvoyEgress(
  options: Parameters<typeof startUnarmedEnvoyEgress>[0],
  mutate: (s: CogsEgressRuntimeObservation) => CogsEgressRuntimeObservation = (s) => s,
) {
  let live = false;
  let canArm = false;
  const start = options.seams?.startManager;
  const relay = options.seams?.relay;
  const h = await startUnarmedEnvoyEgress({
    ...options,
    seams: Object.freeze({
      ...options.seams,
      ...(start
        ? {
            startManager: Object.freeze(async (input: Parameters<NonNullable<typeof start>>[0]) => {
              const manager = await start(input);
              canArm = options.profile === "linux-kvm" && manager.auditRecords !== undefined;
              if (!canArm)
                return registerCloseOwner(
                  manager,
                  createCloseOwner(() => manager.close()),
                );
              const generation = Object.freeze({});
              const completions: CogsEgressRuntimeObservation["completions"][number][] = [];
              let pending: typeof completions = [];
              let retired = false;
              const owner = createCloseOwner(async () => {
                await manager.close();
                retired = true;
              });
              const wrapped = registerCloseOwner(
                Object.freeze({
                  ...manager,
                  auditRecords: (limit: number) => (live ? (manager.auditRecords?.(limit) as never) : []),
                  drainCompletions: () => {
                    const out = pending;
                    pending = [];
                    return out;
                  },
                }),
                owner,
              );
              return registerCogsEgressRuntimeObserver(wrapped, () => {
                const records = live ? (manager.auditRecords?.(64) ?? []) : [];
                if (live) {
                  pending = [...manager.drainCompletions(64)];
                  completions.push(...pending);
                }
                return mutate(
                  Object.freeze({
                    generation,
                    sessionId: input.launch.session_id,
                    uncorrelated: 0,
                    retired,
                    records,
                    completions: Object.freeze([...completions]),
                    accounting: {
                      accepted: completions.length,
                      drained: completions.length,
                      dropped: 0,
                      retained: 0,
                      failed: false,
                    },
                  }),
                );
              });
            }),
          }
        : {}),
      ...(relay
        ? {
            relay: Object.freeze(() => {
              const instance = relay();
              let closed = false;
              return Object.freeze({
                ...instance,
                close: async () => {
                  await instance.close();
                  closed = true;
                },
                snapshot: () => {
                  const snap = instance.snapshot();
                  return live
                    ? closed
                      ? { ...snap, closed: true, ready: false, activeTarget: null, registeredTargets: [] }
                      : snap
                    : {
                        ...snap,
                        acceptedConnections: 0,
                        deniedConnections: 0,
                        activeSockets: 0,
                        activeTarget: 18081,
                        registeredTargets: [18081],
                        switchedTargets: 1,
                      };
                },
              }) as never;
            }),
          }
        : {}),
    }),
  });
  if (canArm) h.armS309();
  live = true;
  return h;
}

test("real curl verifies current CA through authenticated relay; unrelated/stale CA and capability fail", async () => {
  const exec = promisify(execFile);
  const dir = await mkdtemp(join(tmpdir(), "cogs-s309-tls-"));
  try {
    for (const generation of ["a", "b"])
      await exec(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:P-256",
          "-nodes",
          "-keyout",
          join(dir, `${generation}.key`),
          "-out",
          join(dir, `${generation}.pem`),
          "-days",
          "1",
          "-subj",
          "/CN=localhost",
          "-addext",
          "subjectAltName=DNS:localhost",
        ],
        { maxBuffer: 4096 },
      );
    for (const generation of ["a", "b"]) {
      let forwarded = 0;
      const capability = generation.repeat(43);
      const server = httpsServer(
        { key: await readFile(join(dir, `${generation}.key`)), cert: await readFile(join(dir, `${generation}.pem`)) },
        (_req, res) => {
          forwarded++;
          res.end("ok");
        },
      );
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const port = (server.address() as { port: number }).port;
      // Synthetic CONNECT endpoint only; no Envoy/OpenBao qualification claim.
      const proxy = httpServer();
      proxy.on("connect", (req, socket, head) => {
        assert.equal(
          req.headers["proxy-authorization"] === `Basic ${Buffer.from(`cogs:${capability}`).toString("base64")}`,
          true,
        );
        const upstream = connect(port, "127.0.0.1", () => {
          socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          if (head.length) upstream.write(head);
          socket.pipe(upstream).pipe(socket);
        });
        socket.on("error", () => upstream.destroy());
        upstream.on("error", () => socket.destroy());
        socket.on("close", () => upstream.destroy());
        upstream.on("close", () => socket.destroy());
      });
      await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
      const relay = KvmRelay.linuxKvmTestLoopback();
      relay.configureProxyCapability(holder(capability));
      try {
        await relay.start();
        const proxyPort = (proxy.address() as { port: number }).port;
        relay.registerTarget(proxyPort);
        await relay.switchTo(proxyPort);
        const attempt = async (ca: string, token: string) => {
          const config = join(dir, "curl.conf");
          await writeFile(config, `proxy-user = "cogs:${token}"\n`, { mode: 0o600 });
          try {
            await exec(
              "curl",
              [
                "-q",
                "--config",
                config,
                "--proxy-basic",
                "--proxy",
                `http://127.0.0.1:${relay.snapshot().bindPort}`,
                "--noproxy",
                "",
                "--cacert",
                join(dir, `${ca}.pem`),
                "--silent",
                "--http1.1",
                "--max-time",
                "3",
                "-o",
                "/dev/null",
                `https://localhost:${port}/credential`,
              ],
              { env: { PATH: process.env.PATH ?? "/usr/bin:/bin" }, maxBuffer: 4096 },
            );
            return 0;
          } catch (error) {
            return (error as { code: number }).code;
          }
        };
        assert.equal(await attempt(generation, capability), 0);
        const before = forwarded;
        // In B, A is the retained public trust anchor of the retired generation.
        assert.equal(await attempt(generation === "a" ? "b" : "a", capability), 60);
        assert.equal(forwarded, before);
        const denied = relay.snapshot().deniedConnections;
        assert.notEqual(await attempt(generation, generation === "b" ? "a".repeat(43) : "wrong".repeat(9)), 0);
        assert.equal(relay.snapshot().deniedConnections, denied + 1);
        assert.equal(forwarded, before);
        assert.equal(await attempt(generation, capability), 0);
        assert.equal(forwarded, before + 1);
      } finally {
        await relay.close();
        await new Promise<void>((resolve) => proxy.close(() => resolve()));
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const sourceRevision = "a".repeat(40);
const fakeBin = Buffer.alloc(1024 * 1024, 1);
const fakeBinHash = `sha256:${createHash("sha256").update(fakeBin).digest("hex")}`;
const envoyVersion = (path: string) => `\n${path}  version: ${"a".repeat(40)}/1.38.3/Clean/RELEASE/BoringSSL\n\n`;
function launch(stateId: string, port = 31337) {
  const integ: Record<string, unknown> = {
    version: "cogs.integration/v1alpha1",
    id: "stage3-localhost",
    preset_revision: "",
    dns: { mode: "proxy-connect-authority", guest_resolution: false },
    auth: {
      type: "bearer_header",
      header: "Authorization",
      prefix: "Bearer ",
      placeholder: "COGS_PLACEHOLDER_TOKEN",
      secret_handle: "users/alice/integrations/stage3-localhost",
    },
    rules: [
      {
        name: "credential",
        host: "localhost",
        port,
        methods: ["GET", "POST"],
        path_patterns: ["/credential"],
        path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
        query_policy: { mode: "deny" },
        redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
        inject_auth: true,
      },
    ],
  };
  integ.preset_revision = canonicalPresetPolicyRevision(integ);
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "alice",
    session_id: `launcher-${stateId}`,
    workspace_id: "launcher",
    sandbox: {
      ssh_endpoint: "127.0.0.1:22",
      ssh_host_key: `SHA256:${"a".repeat(43)}`,
      client_key_path: "/run/cogs/ssh/launcher-key",
      proxy_auth_handle: "sessions/launcher/proxy",
    },
    model: { provider: "anthropic", id: "claude-sonnet-4-5", credential_handle: "users/alice/anthropic" },
    skills: {
      shared_revision: `sha256:${"b".repeat(64)}`,
      shared_path: "/shared/skills",
      user_revision: `sha256:${"c".repeat(64)}`,
      user_path: "/user/skills",
    },
    integrations: [integ],
    limits: {
      cpu: 1,
      memory_bytes: 536870912,
      tool_timeout_seconds: 60,
      turn_timeout_seconds: 120,
      max_tool_output_bytes: 65536,
    },
  };
}
async function launcherState(profile: "insecure-container" | "linux-kvm" = "linux-kvm") {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-envoy-"));
  const root = join(await realpath(dir), "launcher");
  await mkdir(root, { mode: 0o700 });
  const state = await resolveLauncherState({ root, name: "s1", sourceRevision });
  const m = await createState(state, profile);
  await writePhase(state, m, "sandbox-ready");
  return { dir, state };
}
function holder(secret: string): SecretHolder {
  let s = secret;
  return Object.freeze({
    withSecret: (op) => {
      if (!s) throw new Error("empty");
      return op(s);
    },
    dispose: () => {
      s = "";
    },
  });
}
function walRecord(routeId: string, sessionId: string, overrides: Record<string, unknown> = {}) {
  return Object.freeze({
    version: "cogs.egress-intent/v1alpha1",
    sequence: 0,
    intent_id: "intent-1",
    timestamp_ms: 1,
    session_id: sessionId,
    integration_id: "stage3-localhost",
    route_id: routeId,
    method: "GET",
    credential_required: true,
    ...overrides,
  });
}

function relaySeam(accepted: () => number, extra: Record<string, unknown> = {}) {
  return Object.freeze(
    () =>
      Object.freeze({
        snapshot: () =>
          Object.freeze({
            profile: "linux-kvm",
            bindHost: "192.0.2.1",
            bindPort: 18080,
            activeTarget: 18081,
            registeredTargets: Object.freeze([18081]),
            acceptedConnections: accepted(),
            deniedConnections: 0,
            switchedTargets: 1,
            activeSockets: 0,
            maxActiveSockets: 16,
            ready: true,
            poisoned: false,
            closed: false,
            ...extra,
          }),
        configureProxyCapability: () => undefined,
        registerTarget: () => undefined,
        switchTo: async () => undefined,
        clear: async () => undefined,
        start: async () => undefined,
        close: async () => undefined,
      }) as never,
  );
}

function completion(routeId: string, responseCode = 200) {
  return Object.freeze({
    intentId: "intent-1",
    sequence: 0,
    routeId,
    responseCode,
    durationMs: 1,
    completedAtMs: 1,
  });
}

function credentialRouteId(doc: ReturnType<typeof launch>) {
  return lowerLaunchEgressRoutePlan(doc as never).integrations[0]?.routes.find(
    (route) => route.ruleName === "credential" && route.method === "GET",
  )?.routeId as string;
}

function openbao(): OpenBaoHandle {
  return Object.freeze({
    snapshot: () =>
      Object.freeze({
        ready: true,
        name: "bao",
        containerId: "a".repeat(64),
        port: 8200,
        image: "openbao",
        seeded: "model-kv-egress-pki",
        egress: {
          mount: "model",
          pkiMount: "pki",
          pkiRole: "cogs-egress",
          credentialHandle: "users/alice/integrations/stage3-localhost",
        } as const,
      }),
    modelToken: holder("model-token-123456"),
    modelApiKey: holder("model-key-123456"),
    egressToken: holder("egress-token-123456"),
    integrationCredential: holder("integration-credential-123456"),
    close: async () => undefined,
  });
}

test("prepareEnvoyBinary extracts exact pinned image into owned runtime dir and cleans container", async () => {
  const { dir, state } = await launcherState();
  const events: string[] = [];
  const id = "b".repeat(64);
  try {
    const seams: EnvoyEgressSeams = Object.freeze({
      docker: Object.freeze(async (raw: readonly string[]) => {
        events.push(raw.join(" "));
        const args = raw.slice(1);
        if (args[0] === "ps") return { status: 0, stdout: "" };
        if (args[0] === "image")
          return { status: 0, stdout: `${JSON.stringify([ENVOY_IMAGE.replace(":v1.38.3@", "@")])}\n` };
        if (args[0] === "create") return { status: 0, stdout: `${id}\n` };
        if (args[0] === "cp") {
          await writeFile(String(args[2]), Buffer.alloc(1024 * 1024, 1));
          return { status: 0, stdout: "" };
        }
        if (args[0] === "inspect")
          return {
            status: 0,
            stdout: `${JSON.stringify({
              Id: id,
              Name: `/cogs-envoy-extract-${state.stateId}`,
              Config: { Image: ENVOY_IMAGE, Labels: { "cogs.dev.launcher.envoy": state.stateId } },
            })}\n`,
          };
        if (args[0] === "rm") return { status: 0, stdout: "" };
        return { status: 1, stdout: "" };
      }),
      runVersion: Object.freeze(async (path: string) => envoyVersion(path)),
    });
    const d = await prepareEnvoyBinary(state, seams);
    assert.equal(d.image, ENVOY_IMAGE);
    assert.match(d.sha256, /^sha256:[a-f0-9]{64}$/u);
    assert.equal(d.path, join(state.dir, "runtime", "envoy"));
    assert.ok(events.some((e) => e.includes(" create ") && e.includes(ENVOY_IMAGE)));
    assert.ok(events.some((e) => e.includes(" cp ")));
    assert.ok(events.some((e) => e.includes(" rm ")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Permanent form of /tmp/cogs42-holistic-extraction-repro.mts: the Docker
// fixture acquires an object then returns a truncated ID. No Docker is executed.
test("extraction failures retain durable intent/exact custody rather than erasing the surviving object", async () => {
  for (const fault of [
    "truncated",
    "create-failed",
    "create-rejected",
    "inspect-malformed",
    "inspect-failed",
    "foreign-id",
    "foreign-name",
    "foreign-image",
    "foreign-label",
    "rm-failed",
    "rm-rejected",
    "absence-failed",
    "absence-present",
    "cp-failed",
  ]) {
    const { dir, state } = await launcherState();
    const id = "b".repeat(64),
      calls: string[] = [];
    const runtime = join(state.dir, "runtime"),
      custody = join(runtime, ".cogs-envoy-extraction.jsonl");
    let container = false;
    try {
      const docker = Object.freeze(async (raw: readonly string[]) => {
        const args = raw.slice(1),
          command = String(args[0]);
        calls.push(command);
        if (command === "ps") {
          if (!calls.includes("create")) return { status: 0, stdout: "" };
          return {
            status: fault === "absence-failed" ? 1 : 0,
            stdout: fault === "absence-present" || container ? `${id}\n` : "",
          };
        }
        if (command === "image") return { status: 0, stdout: JSON.stringify([ENVOY_IMAGE.replace(":v1.38.3@", "@")]) };
        if (command === "create") {
          // Observe the fsynced intent before the actual acquisition boundary.
          const intent = JSON.parse((await readFile(custody, "utf8")).trim());
          assert.deepEqual(
            {
              phase: intent.phase,
              name: intent.name,
              label: intent.label,
              image: intent.image,
              stateId: intent.stateId,
            },
            {
              phase: "create-intent",
              name: `cogs-envoy-extract-${state.stateId}`,
              label: `cogs.dev.launcher.envoy=${state.stateId}`,
              image: ENVOY_IMAGE,
              stateId: state.stateId,
            },
          );
          assert.equal((await lstat(custody)).mode & 0o777, 0o600);
          container = true;
          if (fault === "create-rejected") throw new Error("lost response");
          return {
            status: fault === "create-failed" ? 1 : 0,
            stdout: fault === "truncated" ? "truncated-container-id\n" : `${id}\n`,
          };
        }
        if (command === "inspect") {
          assert.equal(args[1], id);
          if (fault === "inspect-failed" && calls.filter((call) => call === "inspect").length === 1)
            return { status: 1, stdout: "" };
          return {
            status: 0,
            stdout:
              fault === "inspect-malformed"
                ? "{"
                : JSON.stringify({
                    Id: fault === "foreign-id" ? "f".repeat(64) : id,
                    Name: fault === "foreign-name" ? "/foreign" : `/cogs-envoy-extract-${state.stateId}`,
                    Config: {
                      Image: fault === "foreign-image" ? "foreign" : ENVOY_IMAGE,
                      Labels: { "cogs.dev.launcher.envoy": fault === "foreign-label" ? "foreign" : state.stateId },
                    },
                  }),
          };
        }
        if (command === "cp") {
          await writeFile(String(args[2]), fakeBin);
          return { status: fault === "cp-failed" ? 1 : 0, stdout: "" };
        }
        if (command === "rm") {
          assert.equal(args[1], id);
          const records = (await readFile(custody, "utf8"))
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
          assert.deepEqual(records.at(-1), { phase: "remove-intent", id });
          if (fault === "rm-rejected") throw new Error("lost removal");
          if (fault === "rm-failed") return { status: 1, stdout: "" };
          container = false;
          return { status: 0, stdout: "" };
        }
        throw new Error("unexpected fake command");
      });
      await assert.rejects(
        () =>
          prepareEnvoyBinary(
            state,
            Object.freeze({ docker, runVersion: Object.freeze(async (path: string) => envoyVersion(path)) }),
          ),
        /launcher egress failed/,
        fault,
      );
      assert.equal(await readFile(join(runtime, ".cogs-envoy-owner"), "utf8"), `${state.stateId}\n`, fault);
      const records = (await readFile(custody, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      assert.equal(records[0].phase, "create-intent");
      if (!["truncated", "create-rejected"].includes(fault)) assert.equal(records[1].id, id);
      assert.equal(container, !fault.startsWith("absence-"), fault);
      if (fault.startsWith("create-") || fault === "truncated") assert.deepEqual(calls, ["ps", "image", "create"]);
      if (fault.startsWith("foreign-") || fault.startsWith("inspect-")) {
        assert.ok(!calls.includes("rm"));
        assert.equal(
          calls.filter((call) => call === "inspect").length,
          1,
          "never replace a failed observation with a retry",
        );
      }
      assert.ok(calls.filter((call) => call === "rm").length <= 1);
      const before = calls.length;
      await assert.rejects(() => prepareEnvoyBinary(state, Object.freeze({ docker })), /launcher egress failed/);
      assert.equal(calls.length, before, "retained custody blocks reuse before Docker");
      await lstat(custody);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("cancelled extraction joins late create/inspect/removal work and never releases custody early", async () => {
  for (const observation of ["create", "inspect", "rm", "create-failed", "inspect-failed", "rm-failed"]) {
    const late = observation.split("-")[0];
    const failLate = observation.endsWith("-failed");
    const { dir, state } = await launcherState();
    const controller = new AbortController(),
      id = "c".repeat(64),
      calls: string[] = [];
    const arrived = Promise.withResolvers<void>(),
      release = Promise.withResolvers<void>();
    let container = false,
      delayed = false,
      settled = false;
    const custody = join(state.dir, "runtime", ".cogs-envoy-extraction.jsonl");
    try {
      const docker = Object.freeze(async (raw: readonly string[]) => {
        const args = raw.slice(1),
          command = String(args[0]);
        calls.push(command);
        // The external effect occurs before its response is observable.
        if (command === "create") container = true;
        if (command === "rm") container = false;
        if (command === late && !delayed) {
          delayed = true;
          arrived.resolve();
          await release.promise;
          await lstat(custody);
          if (failLate) throw new Error("late observation failed");
        }
        if (command === "ps") return { status: 0, stdout: container ? `${id}\n` : "" };
        if (command === "image") return { status: 0, stdout: JSON.stringify([ENVOY_IMAGE.replace(":v1.38.3@", "@")]) };
        if (command === "create") {
          container = true;
          return { status: 0, stdout: `${id}\n` };
        }
        if (command === "inspect") {
          assert.equal(args[1], id);
          return {
            status: 0,
            stdout: JSON.stringify({
              Id: id,
              Name: `/cogs-envoy-extract-${state.stateId}`,
              Config: { Image: ENVOY_IMAGE, Labels: { "cogs.dev.launcher.envoy": state.stateId } },
            }),
          };
        }
        if (command === "cp") {
          await writeFile(String(args[2]), fakeBin);
          return { status: 0, stdout: "" };
        }
        if (command === "rm") {
          assert.equal(args[1], id);
          container = false;
          return { status: 0, stdout: "" };
        }
        throw new Error("unexpected command");
      });
      const result = prepareEnvoyBinary(state, {
        signal: controller.signal,
        seams: Object.freeze({ docker, runVersion: Object.freeze(async (path: string) => envoyVersion(path)) }),
      })
        .then(
          () => "resolved",
          () => "rejected",
        )
        .finally(() => {
          settled = true;
        });
      await arrived.promise;
      controller.abort();
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(settled, false, "cancellation is not actual producer retirement");
      await lstat(custody);
      await lstat(join(state.dir, "runtime", ".cogs-envoy-owner"));
      release.resolve();
      assert.equal(await result, "rejected");
      assert.equal(calls.filter((call) => call === "create").length, 1);
      if (failLate) {
        assert.equal(container, late !== "rm");
        await lstat(custody);
        await lstat(join(state.dir, "runtime", ".cogs-envoy-owner"));
      } else {
        assert.equal(container, false);
        assert.equal(calls.filter((call) => call === "rm").length, 1);
        await assert.rejects(() => lstat(join(state.dir, "runtime")), { code: "ENOENT" });
      }
    } finally {
      release.resolve();
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("envoy egress adapter wires production manager options and insecure loopback listener without relay", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const binHash = fakeBinHash;
    let captured: CogsEgressRuntimeManagerOptions | undefined;
    const h = await startEnvoyEgress({
      state,
      profile: "insecure-container",
      openbao: openbao(),
      fixturePort: 31337,
      launchDocument: launch(state.stateId),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: binHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        startManager: Object.freeze(async (o: CogsEgressRuntimeManagerOptions) => {
          captured = o;
          return Object.freeze({
            ready: true,
            listenerPort: o.listenerPort,
            replacementRequired: false,
            drainCompletions: () => Object.freeze([]),
            close: async () => undefined,
          });
        }),
      }),
    });
    const snap = h.snapshot();
    assert.equal(snap.authority.user, "alice");
    assert.equal(snap.authority.egressHandle, "users/alice/integrations/stage3-localhost");
    assert.ok(captured);
    assert.equal(captured.launch.user_id, "alice");
    assert.equal(captured.launch.model.credential_handle, "users/alice/anthropic");
    const integration = captured.launch.integrations[0] as {
      auth: { secret_handle: string };
      rules: [{ port: number }];
    };
    assert.equal(integration.auth.secret_handle, "users/alice/integrations/stage3-localhost");
    assert.equal(integration.rules[0].port, 31337);
    assert.equal(captured.revocation.mode, "openbao");
    if (captured.revocation.mode !== "openbao") throw new Error("bad revocation");
    assert.equal(captured.revocation.openbao.mount, "model");
    assert.equal(captured.telemetry.mode, "otlp");
    if (captured.telemetry.mode !== "otlp") throw new Error("bad telemetry");
    assert.equal(captured.telemetry.endpoint, "http://127.0.0.1:4318/v1/logs");
    assert.equal(typeof captured.pkiSource.withPkiMaterial, "function");
    assert.equal(JSON.stringify(snap).includes("token"), false);
    await h.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("public guest material is only the active issuance CA and existing capability; lexical exit and close seal it", async (t) => {
  const { dir, state } = await launcherState();
  const material = Object.freeze({
    caCertificatePem: "synthetic-issued-public-root",
    certificateChainPem: "synthetic-leaf",
    privateKeyPem: "PRIVATE_CANARY",
    expiresAtMs: Date.now() + 60000,
  });
  let release!: () => void;
  const retired = new Promise<void>((resolve) => {
    release = resolve;
  });
  let issued = 0;
  t.mock.method(
    OpenBaoEgressPkiSource.prototype,
    "withPkiMaterial",
    async (_request: unknown, consume: (value: typeof material) => Promise<void>) => {
      issued++;
      return consume(material);
    },
  );
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    const h = await startUnarmedEnvoyEgress({
      state,
      profile: "linux-kvm",
      openbao: openbao(),
      fixturePort: 31337,
      launchDocument: launch(state.stateId),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        relay: relaySeam(() => 0),
        startManager: Object.freeze(async (options: CogsEgressRuntimeManagerOptions) => {
          const task = options.pkiSource.withPkiMaterial(
            {
              sessionId: `launcher-${state.stateId}`,
              hosts: ["localhost"],
              maxSessionExpiresAtMs: material.expiresAtMs,
            },
            async (actual) => {
              assert.equal(actual, material);
              await retired;
            },
          );
          await new Promise((resolve) => setImmediate(resolve));
          const close = async () => {
            release();
            await task;
          };
          return registerCloseOwner(
            {
              ready: true,
              replacementRequired: false,
              listenerPort: 18081,
              drainCompletions: () => [],
              close,
            },
            createCloseOwner(close),
          );
        }),
      }),
    });
    let caBuffer!: Buffer;
    let configBuffer!: Buffer;
    let assertCurrent!: () => void;
    await h.withGuestProxyMaterial(new AbortController().signal, async (guest) => {
      caBuffer = guest.ca;
      configBuffer = guest.config;
      assertCurrent = guest.assertCurrent;
      assert.equal(guest.ca.toString() === material.caCertificatePem, true);
      assert.equal(
        h.proxyCapability.withSecret((secret) => guest.config.toString() === `proxy-user = "cogs:${secret}"\n`),
        true,
      );
      assert.equal(JSON.stringify(Object.keys(guest)).includes("private"), false);
      assert.equal(guest.config.includes("PRIVATE_CANARY"), false);
    });
    assert.equal(
      caBuffer.every((byte) => byte === 0),
      true,
    );
    assert.equal(
      configBuffer.every((byte) => byte === 0),
      true,
    );
    assert.equal(issued, 1);
    assertCurrent();
    release();
    await new Promise((resolve) => setImmediate(resolve));
    assert.throws(assertCurrent);
    await assert.rejects(h.withGuestProxyMaterial(new AbortController().signal, async () => undefined));
    await h.close();
    await assert.rejects(h.withGuestProxyMaterial(new AbortController().signal, async () => undefined));
  } finally {
    release();
    await rm(dir, { recursive: true, force: true });
  }
});

test("local close observers have independent deadlines/abort and never repeat actual work", async () => {
  let release!: () => void;
  let calls = 0;
  const work = Promise.resolve().then(async () => {
    calls++;
    await new Promise<void>((resolve) => {
      release = resolve;
    });
  });
  const controller = new AbortController();
  const a = observeLauncherClose(work, { signal: controller.signal, deadlineAt: Date.now() + 1000 });
  const b = observeLauncherClose(work, { deadlineAt: Date.now() + 1000 });
  const short = observeLauncherClose(work, { deadlineAt: Date.now() + 5 });
  controller.abort();
  await assert.rejects(a);
  await assert.rejects(short);
  release();
  await b;
  await observeLauncherClose(work);
  await assert.rejects(observeLauncherClose(work, { signal: controller.signal }));
  await assert.rejects(observeLauncherClose(work, { deadlineAt: Date.now() - 1 }));
  assert.equal(calls, 1);
});

test("envoy egress S3 completion proof is bounded, cached, and fail closed", async () => {
  const { dir, state } = await launcherState();
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const doc = launch(state.stateId);
    const routeId = credentialRouteId(doc);
    const drained = [Object.freeze([]), Object.freeze([completion(routeId)]), Object.freeze([completion("wrong")])];
    let observations = 0;
    const h = await startEnvoyEgress({
      state,
      profile: "linux-kvm",
      openbao: openbao(),
      fixturePort: 31337,
      launchDocument: doc,
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        relay: relaySeam(() => (observations === 0 ? 0 : 2)),
        startManager: Object.freeze(async () =>
          Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            auditRecords: (limit: number) => {
              assert.equal(limit, 64);
              observations += 1;
              return Object.freeze(observations === 1 ? [] : [walRecord(routeId, doc.session_id)]);
            },
            drainCompletions: (limit: number) => {
              assert.equal(limit, 64);
              return drained.shift() ?? Object.freeze([]);
            },
            close: async () => undefined,
          }),
        ),
      }),
    });
    assert.deepEqual(h.s309CompletionProof(), {
      version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
      outcome: "pending",
      reason: "relay-zero-wal-zero",
    });
    assert.deepEqual(h.s309CompletionProof(), {
      version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
      outcome: "pass",
      runtime_observers_consistent: true,
      completion_observer_consistent: true,
    });
    assert.deepEqual(h.s309CompletionProof(), {
      version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
      outcome: "fail",
      reason: "total-count",
    });
    await assert.rejects(h.close());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress S3 completion proof keeps draining after pass and remains pass on empty", async () => {
  const { dir, state } = await launcherState();
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const doc = launch(state.stateId);
    const routeId = credentialRouteId(doc);
    let drains = 0;
    const h = await startEnvoyEgress({
      state,
      profile: "linux-kvm",
      openbao: openbao(),
      fixturePort: 31337,
      launchDocument: doc,
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        relay: relaySeam(() => 2),
        startManager: Object.freeze(async () =>
          Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            auditRecords: () => Object.freeze([walRecord(routeId, doc.session_id)]),
            drainCompletions: () => Object.freeze(++drains === 1 ? [completion(routeId)] : []),
            close: async () => undefined,
          }),
        ),
      }),
    });
    assert.equal(h.s309CompletionProof().outcome, "pass");
    assert.equal(h.s309CompletionProof().outcome, "pass");
    assert.equal(drains, 2);
    await h.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("final S3 proof rejects missing/drop/extra/late/malformed/generation/unretired facts and timed-out attempts", async () => {
  for (const mode of [
    "success",
    "missing",
    "dropped",
    "extra",
    "late-wal",
    "malformed",
    "generation",
    "unretired",
    "uncorrelated",
    "failed",
    "timeout",
  ]) {
    const { dir, state } = await launcherState();
    try {
      const runtime = join(state.dir, "runtime");
      await mkdir(runtime, { mode: 0o700 });
      await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
      const bin = join(runtime, "envoy");
      await writeFile(bin, fakeBin, { mode: 0o500 });
      const doc = launch(state.stateId),
        route = credentialRouteId(doc);
      const held = Promise.withResolvers<void>();
      let drains = 0,
        closes = 0;
      const h = await startEnvoyEgress(
        {
          state,
          profile: "linux-kvm",
          openbao: openbao(),
          fixturePort: 31337,
          launchDocument: doc,
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
          seams: Object.freeze({
            validateTmpfs: Object.freeze(async () => undefined),
            proveClosed: Object.freeze(async () => undefined),
            relay: relaySeam(() => 2),
            startManager: Object.freeze(async () =>
              Object.freeze({
                ready: true,
                listenerPort: 18081,
                replacementRequired: false,
                auditRecords: () => [walRecord(route, doc.session_id)],
                drainCompletions: () => (++drains === 1 ? [completion(route)] : []),
                close: async () => {
                  closes++;
                  await held.promise;
                },
              }),
            ),
          }),
        },
        (s) =>
          !s.retired
            ? s
            : {
                ...s,
                ...(mode === "missing"
                  ? { completions: [], accounting: { ...s.accounting, accepted: 0, drained: 0 } }
                  : {}),
                ...(mode === "dropped" ? { accounting: { ...s.accounting, drained: 0, dropped: 1 } } : {}),
                ...(mode === "extra"
                  ? {
                      completions: [...s.completions, completion(route)],
                      accounting: { ...s.accounting, accepted: 2, drained: 2 },
                    }
                  : {}),
                ...(mode === "late-wal"
                  ? { records: [...s.records, walRecord(route, doc.session_id, { sequence: 1 })] }
                  : {}),
                ...(mode === "malformed" ? { completions: [{ ...completion(route), durationMs: 86_400_001 }] } : {}),
                ...(mode === "generation" ? { generation: {} } : {}),
                ...(mode === "unretired" ? { retired: false } : {}),
                ...(mode === "uncorrelated" ? { uncorrelated: 1 } : {}),
                ...(mode === "failed" ? { accounting: { ...s.accounting, failed: true } } : {}),
              },
      );
      assert.equal(h.s309CompletionProof().outcome, "pass", mode);
      const closing = h.close(mode === "timeout" ? { deadlineAt: Date.now() - 1 } : {});
      const result = mode === "success" ? closing : assert.rejects(closing);
      if (mode === "timeout") await result;
      assert.equal(h.s309CompletionProof().outcome, "fail", "no final proof while actual close is held");
      held.resolve();
      await result;
      if (mode !== "success") await assert.rejects(h.close());
      else await h.close();
      assert.equal(h.s309CompletionProof().outcome, mode === "success" ? "pass" : "fail", mode);
      assert.equal(closes, 1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("envoy egress S3 proof rejects relay and WAL anomalies", async () => {
  const cases = [
    ["relay-zero-wal-pass", { relay: { acceptedConnections: 0 }, wal: {} }],
    ["relay-one", { relay: { acceptedConnections: 1 }, wal: {} }],
    ["relay-denied", { relay: { deniedConnections: 1 }, wal: {} }],
    ["relay-target", { relay: { activeTarget: 12345 }, wal: {} }],
    ["relay-one-wal-zero", { relay: { acceptedConnections: 1 }, wal: { empty: true } }],
    ["wal-zero", { relay: {}, wal: { empty: true } }],
    ["wal-extra", { relay: {}, wal: { extra: true } }],
    ["wal-route", { relay: {}, wal: { route_id: "wrong" } }],
    ["wal-method", { relay: {}, wal: { method: "POST" } }],
    ["wal-credential", { relay: {}, wal: { credential_required: false } }],
    ["wal-session", { relay: {}, wal: { session_id: "other" } }],
    ["wal-sequence", { relay: {}, wal: { sequence: 1 } }],
    ["wal-intent", { relay: {}, wal: { intent_id: "" } }],
    ["wal-time", { relay: {}, wal: { timestamp_ms: -1 } }],
    ["relay-switch", { relay: { switchedTargets: 2 }, wal: {} }],
    ["relay-extra", { relay: { acceptedConnections: 3 }, wal: {} }],
  ] as const;
  for (const [name, value] of cases) {
    const { dir, state } = await launcherState();
    try {
      const runtime = join(state.dir, "runtime");
      await mkdir(runtime, { mode: 0o700 });
      await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
      const bin = join(runtime, "envoy");
      await writeFile(bin, fakeBin, { mode: 0o500 });
      await chmod(bin, 0o500);
      const doc = launch(state.stateId);
      const routeId = credentialRouteId(doc);
      const h = await startEnvoyEgress({
        state,
        profile: "linux-kvm",
        openbao: openbao(),
        fixturePort: 31337,
        launchDocument: doc,
        listenerPort: 18081,
        otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
        binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
        seams: Object.freeze({
          validateTmpfs: Object.freeze(async () => undefined),
          proveClosed: Object.freeze(async () => undefined),
          relay: relaySeam(() => 2, value.relay),
          startManager: Object.freeze(async () =>
            Object.freeze({
              ready: true,
              listenerPort: 18081,
              replacementRequired: false,
              auditRecords: () =>
                Object.freeze(
                  "empty" in value.wal
                    ? []
                    : "extra" in value.wal
                      ? [walRecord(routeId, doc.session_id), walRecord(routeId, doc.session_id, { sequence: 2 })]
                      : [walRecord(routeId, doc.session_id, value.wal)],
                ),
              drainCompletions: () => Object.freeze([]),
              close: async () => undefined,
            }),
          ),
        }),
      });
      assert.deepEqual(
        h.s309CompletionProof(),
        name === "relay-one" || name === "relay-zero-wal-pass" || name === "relay-one-wal-zero" || name === "wal-zero"
          ? {
              version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
              outcome: "pending",
              reason:
                name === "wal-zero"
                  ? "wal"
                  : name === "relay-one-wal-zero"
                    ? "relay-one-wal-zero"
                    : name === "relay-one"
                      ? "relay-one-wal-pass"
                      : "relay-zero-wal-pass",
            }
          : {
              version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
              outcome: "fail",
              reason: name === "relay-switch" ? "generation" : "total-count",
            },
        name,
      );
      await assert.rejects(h.close());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("envoy egress S3 completion proof rejects wrong duplicate status and hostile records", async () => {
  const cases = [
    ["missing", (_routeId: string) => []],
    ["wrong", (routeId: string) => [completion(`x-${routeId}`)]],
    ["duplicate", (routeId: string) => [completion(routeId), completion(routeId)]],
    ["status", (routeId: string) => [completion(routeId, 500)]],
    ["code-zero", (routeId: string) => [completion(routeId, 0)]],
    ["wrong-intent", (routeId: string) => [{ ...completion(routeId), intentId: "other" }]],
    ["wrong-sequence", (routeId: string) => [{ ...completion(routeId), sequence: 99 }]],
    ["hostile", () => [Object.freeze(Object.create(null, { routeId: { get: () => "x", enumerable: true } }))]],
  ] as const;
  for (const [name, records] of cases) {
    const { dir, state } = await launcherState();
    try {
      const runtime = join(state.dir, "runtime");
      await mkdir(runtime, { mode: 0o700 });
      await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
      const bin = join(runtime, "envoy");
      await writeFile(bin, fakeBin, { mode: 0o500 });
      await chmod(bin, 0o500);
      const doc = launch(state.stateId);
      const routeId = credentialRouteId(doc);
      const h = await startEnvoyEgress({
        state,
        profile: "linux-kvm",
        openbao: openbao(),
        fixturePort: 31337,
        launchDocument: doc,
        listenerPort: 18081,
        otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
        binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
        seams: Object.freeze({
          validateTmpfs: Object.freeze(async () => undefined),
          proveClosed: Object.freeze(async () => undefined),
          relay: relaySeam(() => 2),
          startManager: Object.freeze(async () => {
            return Object.freeze({
              ready: true,
              listenerPort: 18081,
              replacementRequired: false,
              auditRecords: () => [walRecord(routeId, doc.session_id)] as never,
              drainCompletions: () => Object.freeze(records(routeId)) as never,
              close: async () => undefined,
            });
          }),
        }),
      });
      assert.deepEqual(
        h.s309CompletionProof(),
        {
          version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
          outcome: name === "missing" ? "pending" : "fail",
          reason: name === "missing" ? "wal" : "total-count",
        },
        name,
      );
      await assert.rejects(h.close());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("envoy egress fails closed on unsafe tmpfs, handle mismatch, and macos profile", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "macos-vm",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: launch(state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          seams: Object.freeze({ validateTmpfs: Object.freeze(async () => undefined) }),
        }),
      /launcher egress failed/,
    );
    const bad = openbao();
    const badBao = Object.freeze({
      ...bad,
      snapshot: () =>
        Object.freeze({
          ...bad.snapshot(),
          egress: { ...bad.snapshot().egress, credentialHandle: "users/bob/x" as never },
        }),
    });
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "insecure-container",
          openbao: badBao,
          fixturePort: 1,
          launchDocument: launch(state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          seams: Object.freeze({ validateTmpfs: Object.freeze(async () => undefined) }),
        }),
      /launcher egress failed/,
    );
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "insecure-container",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: launch(state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
        }),
      /launcher egress failed/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress rejects supplied hash mismatch and unknown runtime entries", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "insecure-container",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: launch(state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          binary: { path: bin, sha256: `sha256:${"e".repeat(64)}`, image: ENVOY_IMAGE, cleanup: "owned" },
          seams: Object.freeze({ validateTmpfs: Object.freeze(async () => undefined) }),
        }),
      /launcher egress failed/,
    );
    await writeFile(join(runtime, "extra"), "x");
    await assert.rejects(
      () =>
        prepareEnvoyBinary(state, Object.freeze({ docker: Object.freeze(async () => ({ status: 1, stdout: "" })) })),
      /launcher egress failed/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress preserves binary on manager close failure and clears capability", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const binHash = fakeBinHash;
    const calls: string[] = [];
    const h = await startEnvoyEgress({
      state,
      profile: "insecure-container",
      openbao: openbao(),
      fixturePort: 1,
      launchDocument: launch(state.stateId, 1),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: binHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        startManager: Object.freeze(async () =>
          Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            drainCompletions: () => {
              calls.push("drain");
              return Object.freeze([{} as never]);
            },
            close: async () => {
              calls.push("close");
              throw new Error("boom");
            },
          }),
        ),
      }),
    });
    let cap = "";
    h.proxyCapability.withSecret((s) => (cap = s));
    assert.ok(cap.length >= 16);
    assert.equal(JSON.stringify(h.snapshot()).includes(cap), false);
    await assert.rejects(() => h.close(), /launcher egress failed/);
    assert.deepEqual(calls, ["close"]);
    await lstat(bin);
    assert.throws(() => h.proxyCapability.withSecret(() => undefined));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("linux-kvm profile switches relay after manager ready without fallback", async () => {
  const { dir, state } = await launcherState("linux-kvm");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const binHash = fakeBinHash;
    const calls: string[] = [];
    const relay = Object.freeze({
      configureProxyCapability: (holder: { withSecret<T>(op: (secret: string) => T): T }) => {
        holder.withSecret((secret) => {
          assert.match(secret, /^[A-Za-z0-9_-]{32,128}$/u);
        });
        calls.push("relay.capability");
      },
      start: async () => {
        calls.push("relay.start");
      },
      registerTarget: (p: number) => {
        calls.push(`relay.register:${p}`);
      },
      switchTo: async (p: number) => {
        calls.push(`relay.switch:${p}`);
      },
      clear: async () => {
        calls.push("relay.clear");
      },
      close: async () => {
        calls.push("relay.close");
      },
      snapshot: () => Object.freeze({ bindPort: 18080 }),
    }) as never;
    const h = await startEnvoyEgress({
      state,
      profile: "linux-kvm",
      openbao: openbao(),
      fixturePort: 1,
      launchDocument: launch(state.stateId, 1),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: binHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        relay: Object.freeze(() => relay),
        startManager: Object.freeze(async () => {
          calls.push("manager.start");
          return Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            drainCompletions: () => Object.freeze([]),
            close: async () => {
              calls.push("manager.close");
            },
          });
        }),
      }),
    });
    assert.deepEqual(calls.slice(0, 5), [
      "manager.start",
      "relay.capability",
      "relay.start",
      "relay.register:18081",
      "relay.switch:18081",
    ]);
    await h.close();
    assert.deepEqual(calls.slice(-3), ["relay.clear", "manager.close", "relay.close"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress rejects manager readiness or listener mismatch before relay", async () => {
  const { dir, state } = await launcherState("linux-kvm");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const calls: string[] = [];
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "linux-kvm",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: launch(state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
          seams: Object.freeze({
            validateTmpfs: Object.freeze(async () => undefined),
            proveClosed: Object.freeze(async () => undefined),
            relay: Object.freeze(() => {
              calls.push("relay");
              throw new Error("no");
            }),
            startManager: Object.freeze(async () =>
              Object.freeze({
                ready: true,
                listenerPort: 18082,
                replacementRequired: false,
                drainCompletions: () => Object.freeze([]),
                close: async () => {
                  calls.push("close");
                },
              }),
            ),
          }),
        }),
      /launcher egress failed/,
    );
    assert.equal(calls.includes("relay"), false);
    assert.equal(
      calls.every((c) => c === "close"),
      true,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress preserves binary when post-close tmpfs proof is uncertain", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    let tmpfsChecks = 0;
    const h = await startEnvoyEgress({
      state,
      profile: "insecure-container",
      openbao: openbao(),
      fixturePort: 1,
      launchDocument: launch(state.stateId, 1),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => {
          if (++tmpfsChecks > 1) throw new Error("dirty");
        }),
        proveClosed: Object.freeze(async () => undefined),
        startManager: Object.freeze(async () =>
          Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            drainCompletions: () => Object.freeze([]),
            close: async () => undefined,
          }),
        ),
      }),
    });
    await assert.rejects(() => h.close(), /launcher egress failed/);
    await lstat(bin);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress cooperative abort after manager closes owned manager and preserves caller binary", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const events: string[] = [];
    const controller = new AbortController();
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "insecure-container",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: launch(state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
          signal: controller.signal,
          seams: Object.freeze({
            validateTmpfs: Object.freeze(async () => undefined),
            proveClosed: Object.freeze(async () => undefined),
            startManager: Object.freeze(async () => {
              events.push("manager.start");
              queueMicrotask(() => controller.abort());
              return Object.freeze({
                ready: true,
                listenerPort: 18081,
                replacementRequired: false,
                drainCompletions: () => Object.freeze([]),
                close: async () => {
                  events.push("manager.close");
                },
              });
            }),
          }),
        }),
      /launcher egress failed/,
    );
    assert.deepEqual(events, ["manager.start", "manager.close"]);
    await lstat(bin);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("prepare envoy cooperative deadline after extraction cleans owned runtime", async () => {
  const { dir, state } = await launcherState();
  const id = "c".repeat(64);
  const events: string[] = [];
  try {
    const seams: EnvoyEgressSeams = Object.freeze({
      docker: Object.freeze(async (raw: readonly string[], options?: { deadlineAt?: number }) => {
        events.push(`${raw.join(" ")}:${options?.deadlineAt ? "deadline" : "nodeadline"}`);
        const args = raw.slice(1);
        if (args[0] === "ps") return { status: 0, stdout: "" };
        if (args[0] === "image")
          return { status: 0, stdout: `${JSON.stringify([ENVOY_IMAGE.replace(":v1.38.3@", "@")])}\n` };
        if (args[0] === "create") return { status: 0, stdout: `${id}\n` };
        if (args[0] === "cp") {
          await writeFile(String(args[2]), fakeBin);
          return { status: 0, stdout: "" };
        }
        if (args[0] === "inspect")
          return {
            status: 0,
            stdout: `${JSON.stringify({ Id: id, Name: `/cogs-envoy-extract-${state.stateId}`, Config: { Image: ENVOY_IMAGE, Labels: { "cogs.dev.launcher.envoy": state.stateId } } })}\n`,
          };
        if (args[0] === "rm") return { status: 0, stdout: "" };
        return { status: 1, stdout: "" };
      }),
      runVersion: Object.freeze(async (_path: string, options?: { deadlineAt?: number }) => {
        const wait = Math.max(1, (options?.deadlineAt ?? Date.now()) - Date.now() + 1);
        await new Promise((resolve) => setTimeout(resolve, wait));
        return envoyVersion(join(state.dir, "runtime", "envoy"));
      }),
    });
    await assert.rejects(
      () => prepareEnvoyBinary(state, { deadlineAt: Date.now() + 100, seams }),
      /launcher egress failed/,
    );
    await assert.rejects(() => lstat(join(state.dir, "runtime")));
    assert.ok(events.some((event) => event.endsWith(":deadline")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy close continues manager after relay failure and stays generic without secret leakage", async () => {
  const { dir, state } = await launcherState("linux-kvm");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const events: string[] = [];
    const relay = Object.freeze({
      configureProxyCapability: () => undefined,
      start: async () => undefined,
      registerTarget: () => undefined,
      switchTo: async () => undefined,
      clear: async () => {
        events.push("relay.clear");
        throw new Error("SECRET_TOKEN_SHOULD_NOT_LEAK");
      },
      close: async () => {
        events.push("relay.close");
      },
      snapshot: () => Object.freeze({ bindPort: 18080 }),
    }) as never;
    const h = await startEnvoyEgress({
      state,
      profile: "linux-kvm",
      openbao: openbao(),
      fixturePort: 1,
      launchDocument: launch(state.stateId, 1),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        relay: Object.freeze(() => relay),
        startManager: Object.freeze(async () =>
          Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            drainCompletions: () => Object.freeze([]),
            close: async () => {
              events.push("manager.close");
            },
          }),
        ),
      }),
    });
    const first = h.close({ deadlineAt: Date.now() + 5000 });
    assert.equal(h.snapshot().ready, false);
    const second = h.close();
    assert.notEqual(second, first);
    void second.catch(() => undefined);
    await assert.rejects(
      first,
      (error) => String(error).includes("launcher egress failed") && !JSON.stringify(error).includes("SECRET_TOKEN"),
    );
    assert.ok(events.includes("manager.close"));
    assert.ok(events.includes("relay.close"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("prepare envoy failure preserves pre-existing owned and hostile runtime roots", async () => {
  for (const hostile of [false, true]) {
    const { dir, state } = await launcherState();
    try {
      const runtime = join(state.dir, "runtime");
      await mkdir(runtime, { mode: 0o700 });
      await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
      const bin = join(runtime, "envoy");
      await writeFile(bin, fakeBin, { mode: 0o500 });
      await chmod(bin, 0o500);
      if (hostile) await writeFile(join(runtime, "extra"), "preserve");
      await assert.rejects(
        () =>
          prepareEnvoyBinary(state, Object.freeze({ docker: Object.freeze(async () => ({ status: 1, stdout: "" })) })),
        /launcher egress failed/,
      );
      await lstat(bin);
      if (hostile) await lstat(join(runtime, "extra"));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("envoy start abort before handoff and hostile manager getter close exact acquired manager", async () => {
  for (const mode of ["abort", "getter"] as const) {
    const { dir, state } = await launcherState("insecure-container");
    try {
      const runtime = join(state.dir, "runtime");
      await mkdir(runtime, { mode: 0o700 });
      await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
      const bin = join(runtime, "envoy");
      await writeFile(bin, fakeBin, { mode: 0o500 });
      await chmod(bin, 0o500);
      const events: string[] = [];
      const controller = new AbortController();
      await assert.rejects(
        () =>
          startEnvoyEgress({
            state,
            profile: "insecure-container",
            openbao: openbao(),
            fixturePort: 1,
            launchDocument: launch(state.stateId, 1),
            listenerPort: 18081,
            otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
            binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
            ...(mode === "abort" ? { signal: controller.signal } : {}),
            seams: Object.freeze({
              validateTmpfs: Object.freeze(async () => undefined),
              proveClosed: Object.freeze(async () => undefined),
              startManager: Object.freeze(async () => {
                if (mode === "abort") queueMicrotask(() => controller.abort());
                return Object.freeze({
                  get ready() {
                    if (mode === "getter") throw new Error("hostile");
                    return true;
                  },
                  listenerPort: 18081,
                  replacementRequired: false,
                  drainCompletions: () => Object.freeze([]),
                  close: async () => {
                    events.push("manager.close");
                  },
                });
              }),
            }),
          }),
        /launcher egress failed/,
      );
      assert.deepEqual(events, ["manager.close"]);
      await lstat(bin);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("envoy runVersion and relay startup receive cooperative cancellation", async () => {
  const first = await launcherState();
  try {
    const controller = new AbortController();
    let observed = false;
    await assert.rejects(
      () =>
        prepareEnvoyBinary(first.state, {
          signal: controller.signal,
          seams: Object.freeze({
            docker: Object.freeze(async (raw: readonly string[]) => {
              const args = raw.slice(1);
              if (args[0] === "ps") return { status: 0, stdout: "" };
              if (args[0] === "image")
                return { status: 0, stdout: `${JSON.stringify([ENVOY_IMAGE.replace(":v1.38.3@", "@")])}\n` };
              if (args[0] === "create") return { status: 0, stdout: `${"d".repeat(64)}\n` };
              if (args[0] === "cp") {
                await writeFile(String(args[2]), fakeBin);
                return { status: 0, stdout: "" };
              }
              if (args[0] === "inspect")
                return {
                  status: 0,
                  stdout: `${JSON.stringify({ Id: "d".repeat(64), Name: `/cogs-envoy-extract-${first.state.stateId}`, Config: { Image: ENVOY_IMAGE, Labels: { "cogs.dev.launcher.envoy": first.state.stateId } } })}\n`,
                };
              if (args[0] === "rm") return { status: 0, stdout: "" };
              return { status: 1, stdout: "" };
            }),
            runVersion: Object.freeze((_path: string, options?: { signal?: AbortSignal }) => {
              queueMicrotask(() => controller.abort());
              return new Promise<string>((_resolve, reject) =>
                options?.signal?.addEventListener("abort", () => {
                  observed = true;
                  reject(new Error("aborted"));
                }),
              );
            }),
          }),
        }),
      /launcher egress failed/,
    );
    assert.equal(observed, true);
    await lstat(join(first.state.dir, "runtime", ".cogs-envoy-extraction.jsonl"));
    await lstat(join(first.state.dir, "runtime", ".cogs-envoy-owner"));
  } finally {
    await rm(first.dir, { recursive: true, force: true });
  }

  const second = await launcherState("linux-kvm");
  try {
    const runtime = join(second.state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${second.state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const controller = new AbortController();
    const events: string[] = [];
    const relay = Object.freeze({
      configureProxyCapability: () => undefined,
      start: (options?: { signal?: AbortSignal; deadlineAt?: number }) => {
        assert(Object.isFrozen(options));
        assert(options?.signal instanceof AbortSignal);
        return new Promise<void>((_resolve, reject) => {
          options?.signal?.addEventListener("abort", () => {
            events.push("relay.abort");
            reject(new Error("aborted"));
          });
          queueMicrotask(() => controller.abort());
        });
      },
      registerTarget: () => undefined,
      switchTo: async () => undefined,
      clear: async () => undefined,
      close: async () => {
        events.push("relay.close");
      },
      snapshot: () => Object.freeze({ bindPort: 18080 }),
    }) as never;
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state: second.state,
          profile: "linux-kvm",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: launch(second.state.stateId, 1),
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
          signal: controller.signal,
          seams: Object.freeze({
            validateTmpfs: Object.freeze(async () => undefined),
            proveClosed: Object.freeze(async () => undefined),
            relay: Object.freeze(() => relay),
            startManager: Object.freeze(async () =>
              Object.freeze({
                ready: true,
                listenerPort: 18081,
                replacementRequired: false,
                drainCompletions: () => Object.freeze([]),
                close: async () => {
                  events.push("manager.close");
                },
              }),
            ),
          }),
        }),
      /launcher egress failed/,
    );
    assert.deepEqual(events, ["relay.abort", "relay.close", "manager.close"]);
  } finally {
    await rm(second.dir, { recursive: true, force: true });
  }
});

test("envoy close rejects hostile cooperative option bags before getters", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const runtime = join(state.dir, "runtime");
    await mkdir(runtime, { mode: 0o700 });
    await writeFile(join(runtime, ".cogs-envoy-owner"), `${state.stateId}\n`, { mode: 0o600 });
    const bin = join(runtime, "envoy");
    await writeFile(bin, fakeBin, { mode: 0o500 });
    await chmod(bin, 0o500);
    const h = await startEnvoyEgress({
      state,
      profile: "insecure-container",
      openbao: openbao(),
      fixturePort: 1,
      launchDocument: launch(state.stateId, 1),
      listenerPort: 18081,
      otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
      binary: { path: bin, sha256: fakeBinHash, image: ENVOY_IMAGE, cleanup: "owned" },
      seams: Object.freeze({
        validateTmpfs: Object.freeze(async () => undefined),
        proveClosed: Object.freeze(async () => undefined),
        startManager: Object.freeze(async () =>
          Object.freeze({
            ready: true,
            listenerPort: 18081,
            replacementRequired: false,
            drainCompletions: () => Object.freeze([]),
            close: async () => undefined,
          }),
        ),
      }),
    });
    assert.throws(() => h.close({ extra: true } as never), /launcher egress failed/);
    assert.throws(() =>
      h.close(Object.defineProperty({}, "deadlineAt", { enumerable: true, get: () => Date.now() }) as never),
    );
    await h.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("envoy egress rejects non-exact model and integration semantics", async () => {
  const { dir, state } = await launcherState("insecure-container");
  try {
    const base = launch(state.stateId, 1) as Record<string, unknown>;
    const badModel = structuredClone(base) as { model: { provider: string } };
    badModel.model.provider = "other";
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "insecure-container",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: badModel,
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          seams: Object.freeze({ validateTmpfs: Object.freeze(async () => undefined) }),
        }),
      /launcher egress failed/,
    );
    const badIntegration = structuredClone(base) as {
      integrations: [{ auth: { placeholder: string }; rules: [{ name: string }] }];
    };
    badIntegration.integrations[0].auth.placeholder = "COGS_PLACEHOLDER_OTHER";
    badIntegration.integrations[0].rules[0].name = "other";
    await assert.rejects(
      () =>
        startEnvoyEgress({
          state,
          profile: "insecure-container",
          openbao: openbao(),
          fixturePort: 1,
          launchDocument: badIntegration,
          listenerPort: 18081,
          otlpLogsEndpoint: "http://127.0.0.1:4318/v1/logs",
          seams: Object.freeze({ validateTmpfs: Object.freeze(async () => undefined) }),
        }),
      /launcher egress failed/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
