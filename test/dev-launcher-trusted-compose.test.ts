import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, realpath, rm, rmdir, symlink, unlink, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  createDeterministicLauncherStream,
  LAUNCHER_DETERMINISTIC_NORMAL_PROMPT,
} from "../dev/launcher/deterministic-stream.ts";
import type { LauncherState } from "../dev/launcher/state.ts";
import {
  createRawExportOpeningVerifier,
  createS309ProofEmitter,
  createTrustedWorkerRuntime,
  type TrustedCompositionSeams,
} from "../dev/launcher/trusted-compose.ts";
import type { WorkerProvisionalRuntime } from "../dev/launcher/worker-process.ts";
import { type CogsToolPorts, createCogsPiSession } from "../src/pi/session.ts";
import { createCogsJsonlHistoryStore } from "../src/session/jsonl-history.ts";
import { createCogsLocalExporter } from "../src/session/local-export.ts";
import type { CogsPreparedSkillMetadata } from "../src/skills/session-preparer.ts";

const sourceRevision = "a".repeat(40);
const stateId = "b".repeat(64);
const emptyBundle = "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c";
const emptyManifest = "sha256:726176e9bdb7524fbe935a0235fcbe5d509bf44592b9571421fc9fd8551ff1c1";

test("trusted composition factory starts in exact order, proves ready, and closes in reverse", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const captured: Record<string, unknown> = {};
    let runtime: WorkerProvisionalRuntime;
    try {
      runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, seams(calls, captured));
    } catch (error) {
      assert.fail(`${(error as Error).message}: ${calls.join(" > ")}`);
    }
    assert.equal(runtime.apiPort, 40123);
    assert.equal(Object.getPrototypeOf(runtime), Object.prototype);
    assert.equal(Object.isFrozen(runtime), true);
    assert.deepEqual(Object.keys(runtime).sort(), ["apiPort", "close"]);
    const apiPortDescriptor = Object.getOwnPropertyDescriptor(runtime, "apiPort");
    const closeDescriptor = Object.getOwnPropertyDescriptor(runtime, "close");
    assert.equal(apiPortDescriptor?.enumerable, true);
    assert.equal(apiPortDescriptor?.writable, false);
    assert.equal(apiPortDescriptor?.configurable, false);
    assert.equal(closeDescriptor?.enumerable, true);
    assert.equal(closeDescriptor?.writable, false);
    assert.equal(closeDescriptor?.configurable, false);
    assert.equal(Object.isFrozen(runtime.close), true);
    assert.throws(() => Object.defineProperty(runtime, "close", { value: () => undefined }));
    assert.equal(Reflect.deleteProperty(runtime, "close"), false);
    assert.deepEqual(Object.keys(runtime).sort(), ["apiPort", "close"]);
    assert.deepEqual(calls.slice(0, 18), [
      "manifest",
      "descriptor",
      "preflight-egress",
      "manifest",
      "descriptor",
      "ssh-controls",
      "manifest",
      "descriptor",
      "skills",
      `mkdir:trusted-compose-${stateId}`,
      "mkdir:agent",
      "mkdir:sessions",
      "manifest",
      "descriptor",
      "api-token",
      "manifest",
      "descriptor",
      "openbao",
    ]);
    assert.equal(calls.includes("pi"), true);
    assert.equal(calls.includes("api-listen"), true);
    assert.equal(calls.includes("fetch-ready"), true);
    assert.equal(captured.eventReplayCapacity, 32);
    const launch = captured.launch as {
      user_id: string;
      session_id: string;
      integrations: readonly Record<string, unknown>[];
      sandbox: Record<string, string>;
    };
    assert.equal(launch.user_id, "alice");
    assert.equal(launch.session_id, `launcher-${stateId}`);
    assert.equal(launch.sandbox.client_key_path, `/run/cogs/ssh/launcher-${stateId}`);
    assert.equal(launch.integrations[0]?.id, "stage3-localhost");
    assert.equal(JSON.stringify(launch).includes("SECRET"), false);
    calls.length = 0;
    const close1 = runtime.close();
    const close2 = runtime.close();
    assert.equal(close1, close2);
    await close1;
    assert.deepEqual(calls, [
      "api-close",
      "pi-dispose",
      "lifecycle-shutdown",
      "egress-close",
      "ssh-shutdown",
      "telemetry-close",
      "fixture-close",
      "otlp-reset",
      "otlp-close",
      "openbao-close",
      "api-token-dispose",
      "skills-close",
      "ssh-key-close",
    ]);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition attempts all registered cleanup despite close failures", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      createTelemetry: (...args: Parameters<NonNullable<typeof base.createTelemetry>>) => {
        const telemetry = (base.createTelemetry as NonNullable<typeof base.createTelemetry>)(...args);
        return Object.freeze({
          ...telemetry,
          close: async () => {
            calls.push("bad-telemetry-close");
            throw new Error("close failed");
          },
        }) as never;
      },
      createApi: (...args: Parameters<NonNullable<typeof base.createApi>>) => {
        const api = (base.createApi as NonNullable<typeof base.createApi>)(...args);
        return Object.freeze({
          ...api,
          close: async () => {
            calls.push("bad-api-close");
            throw new Error("close failed");
          },
        }) as never;
      },
    });
    const runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped);
    calls.length = 0;
    await assert.rejects(runtime.close(), /launcher trusted composition failed/);
    assert.deepEqual(calls, [
      "bad-api-close",
      "pi-dispose",
      "lifecycle-shutdown",
      "egress-close",
      "ssh-shutdown",
      "bad-telemetry-close",
      "fixture-close",
      "otlp-reset",
      "otlp-close",
      "openbao-close",
      "api-token-dispose",
      "skills-close",
      "ssh-key-close",
    ]);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition fails closed before OpenBao when preflight fails", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const bad = seams(calls, {});
    const wrapped = Object.freeze({
      ...bad,
      preflightEgressRoot: async () => {
        calls.push("preflight-egress");
        throw new Error("boom SECRET path");
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("openbao"), false);
    assert.equal(calls.includes("fixture"), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition releases real port reservation before egress bind", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      reserveLoopbackPort: async () => {
        const server = createServer();
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject);
          server.listen(0, "127.0.0.1", () => resolve());
        });
        const address = server.address();
        const port = typeof address === "object" && address !== null ? address.port : 0;
        return Object.freeze({
          port,
          close: () => new Promise<void>((resolve) => server.close(() => resolve())),
        });
      },
      startEnvoyEgress: async (options: Parameters<NonNullable<typeof base.startEnvoyEgress>>[0]) => {
        const probe = createServer();
        await new Promise<void>((resolve, reject) => {
          probe.once("error", reject);
          probe.listen(options.listenerPort, "127.0.0.1", () => resolve());
        });
        await new Promise<void>((resolve) => probe.close(() => resolve()));
        return (base.startEnvoyEgress as NonNullable<typeof base.startEnvoyEgress>)(options);
      },
    });
    const runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped);
    await runtime.close();
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition default reservation closes pending abort and allows rebind", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const controller = new AbortController();
    const base = seams(calls, {});
    const { reserveLoopbackPort: _omittedReservation, ...withoutReservation } = base;
    let selected = 0;
    const wrapped = Object.freeze({
      ...withoutReservation,
      createNetServer: () => {
        const server = createServer();
        const listen = server.listen.bind(server);
        server.listen = ((...args: Parameters<typeof server.listen>) => {
          calls.push("reservation-listen-pending");
          server.once("listening", () => {
            const address = server.address();
            selected = typeof address === "object" && address !== null ? address.port : 0;
          });
          setImmediate(() => listen(...args));
          controller.abort();
          return server;
        }) as typeof server.listen;
        return server;
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(
        fixture.state,
        controller.signal,
        wrapped as unknown as Partial<TrustedCompositionSeams>,
      ),
      /launcher trusted composition failed/,
    );
    assert.notEqual(selected, 0);
    const probe = createServer();
    await new Promise<void>((resolve, reject) => {
      probe.once("error", reject);
      probe.listen(selected, "127.0.0.1", () => resolve());
    });
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    assert.equal(calls.includes("egress-start"), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects descriptor replacement after admission", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    let reads = 0;
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      readWorkerDescriptor: async (state: LauncherState) => {
        reads += 1;
        const descriptor = await (base.readWorkerDescriptor as NonNullable<typeof base.readWorkerDescriptor>)(state);
        return reads > 2 ? Object.freeze({ ...descriptor, startupDigest: `sha256:${"f".repeat(64)}` }) : descriptor;
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("openbao"), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects malformed ready proof and closes partial resources", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      fetch: async () =>
        new Response(`{"ready":true,"closed":false,"extra":"${"x".repeat(200)}"}`, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("api-close"), true);
    assert.equal(calls.includes("fixture-close"), true);
    assert.equal(calls.includes("otlp-close"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects wrong egress proof and disposes rollback", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      startEnvoyEgress: async (options: Parameters<NonNullable<typeof base.startEnvoyEgress>>[0]) => {
        const handle = await (base.startEnvoyEgress as NonNullable<typeof base.startEnvoyEgress>)(options);
        return Object.freeze({
          ...handle,
          snapshot: () => Object.freeze({ ...handle.snapshot(), listenerPort: 39001 }),
        });
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("egress-close"), true);
    assert.equal(calls.includes("reserve-close"), true);
    assert.equal(calls.includes("ssh-shutdown"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition requires contained session file and exact empty skill metadata", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
        const pi = await (base.createPi as NonNullable<typeof base.createPi>)(options);
        return Object.freeze({ ...pi, sessionFile: () => undefined });
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("api-listen"), false);
    assert.equal(calls.includes("pi-dispose"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition observes pre-aborted admission before hidden work", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, controller.signal, seams(calls, {})),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("preflight-egress"), false);
    assert.equal(calls.includes("openbao"), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects unfrozen or hostile seam bags generically", async () => {
  const fixture = await makeFixture();
  try {
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, {}),
      /launcher trusted composition failed/,
    );
    const hostile = {} as Partial<TrustedCompositionSeams>;
    Object.defineProperty(hostile, "startOpenBao", {
      get: () => {
        throw new Error("SECRET");
      },
      enumerable: true,
    });
    Object.freeze(hostile);
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, hostile),
      /launcher trusted composition failed/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects auth mismatch without self-compare or secret serialization", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      startOpenBao: async (state: LauncherState, options?: { signal?: AbortSignal; deadlineAt?: number }) => {
        const openbao = await (base.startOpenBao as NonNullable<typeof base.startOpenBao>)(state, options);
        return Object.freeze({
          ...openbao,
          modelApiKey: Object.freeze({
            withSecret: <T>(op: (secret: string) => T) => op("DIFFERENT_MODEL_KEY_123"),
            dispose: () => undefined,
          }),
        });
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      (error) =>
        String(error).includes("launcher trusted composition failed") && !JSON.stringify(error).includes("MODEL_KEY"),
    );
    assert.equal(calls.includes("egress-start"), false);
    assert.equal(calls.includes("openbao-close"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition ledgers telemetry and API before validation", async () => {
  for (const mode of ["telemetry", "api"] as const) {
    const fixture = await makeFixture();
    try {
      const calls: string[] = [];
      const base = seams(calls, {});
      const wrapped = Object.freeze({
        ...base,
        ...(mode === "telemetry"
          ? {
              createTelemetry: () =>
                Object.freeze({
                  snapshot: () => Object.freeze({ ready: true }),
                  close: async () => calls.push("bad-telemetry-close"),
                }) as never,
            }
          : {
              createApi: () =>
                Object.freeze({
                  close: async () => calls.push("bad-api-close"),
                  publish: () => true,
                }) as never,
            }),
      });
      await assert.rejects(
        createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
        /launcher trusted composition failed/,
      );
      assert.equal(calls.includes(mode === "telemetry" ? "bad-telemetry-close" : "bad-api-close"), true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("trusted composition rolls back partial startup roots exactly", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      mkdir: (async (path: unknown, options: unknown) => {
        if (String(path).endsWith("sessions")) throw new Error("mkdir failed");
        return (base.mkdir as NonNullable<typeof base.mkdir>)(path as never, options as never);
      }) as never,
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    await assert.rejects(realpath(join(fixture.state.sandboxDir, `trusted-compose-${stateId}`)));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition uses Pi-owned cleanup success and rejects cleanup failure", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
        const pi = await (base.createPi as NonNullable<typeof base.createPi>)(options);
        return Object.freeze({
          ...pi,
          disposeOwnedRuntime: async () => {
            calls.push("pi-owned-fail");
            throw new Error("SECRET pi path");
          },
        });
      },
    });
    const runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped);
    await assert.rejects(runtime.close(), /launcher trusted composition failed/);
    assert.equal(calls.includes("pi-owned-fail"), true);
    assert.equal(calls.includes("egress-close"), true);
    assert.equal(JSON.stringify(calls).includes("SECRET"), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects lying Pi cleanup that leaves runtime roots", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    let agentDir = "";
    let sessionRoot = "";
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
        const pi = await (base.createPi as NonNullable<typeof base.createPi>)(options);
        agentDir = (options as { agentDir: string }).agentDir;
        sessionRoot = (options as { sessionRoot: string }).sessionRoot;
        return Object.freeze({
          ...pi,
          disposeOwnedRuntime: async () => {
            calls.push("pi-lying-cleanup");
            return Object.freeze({
              version: "cogs.pi-owned-runtime-cleanup/v1alpha1" as const,
              cleaned: true as const,
            });
          },
        });
      },
    });
    const runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped);
    await assert.rejects(runtime.close(), /launcher trusted composition failed/);
    await assert.doesNotReject(realpath(agentDir));
    await assert.doesNotReject(realpath(sessionRoot));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition preserves unknown launcher root content after Pi cleanup", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    let unknown = "";
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
        const pi = await (base.createPi as NonNullable<typeof base.createPi>)(options);
        unknown = join((options as { agentDir: string }).agentDir, "..", "unknown");
        return Object.freeze({
          ...pi,
          disposeOwnedRuntime: async () => {
            const result = await pi.disposeOwnedRuntime();
            await writeFile(unknown, "preserve", { flag: "wx" });
            return result;
          },
        });
      },
    });
    const runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped);
    await assert.rejects(runtime.close(), /launcher trusted composition failed/);
    await assert.doesNotReject(realpath(unknown));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition pending OpenBao observes cooperative abort without live handle", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const controller = new AbortController();
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      startOpenBao: (_state: LauncherState, options?: { signal?: AbortSignal }) =>
        new Promise<Awaited<ReturnType<NonNullable<TrustedCompositionSeams["startOpenBao"]>>>>((_resolve, reject) => {
          calls.push("openbao-pending");
          options?.signal?.addEventListener(
            "abort",
            () => {
              calls.push("openbao-abort");
              reject(new Error("aborted"));
            },
            { once: true },
          );
        }),
    });
    const pending = createTrustedWorkerRuntime(fixture.state, controller.signal, wrapped);
    await eventually(() => calls.includes("openbao-pending"));
    controller.abort();
    await assert.rejects(pending, /launcher trusted composition failed/);
    assert.equal(calls.includes("openbao-abort"), true);
    assert.equal(calls.includes("openbao-close"), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects frozen accessor handles without invoking secret getters", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    let invoked = false;
    const handle = {};
    Object.defineProperty(handle, "snapshot", {
      enumerable: true,
      get: () => {
        invoked = true;
        throw new Error("SECRET getter");
      },
    });
    Object.defineProperty(handle, "close", { enumerable: true, value: async () => calls.push("openbao-close") });
    Object.freeze(handle);
    const wrapped = Object.freeze({ ...base, startOpenBao: async () => handle as never });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(invoked, false);
    assert.equal(calls.includes("openbao-close"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects ready hangs through abort and does not leak bearer", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const controller = new AbortController();
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      fetch: async (_url: string | URL | Request, init?: RequestInit) => {
        calls.push(`fetch-auth:${String(init?.headers).includes("TESTTOKEN")}`);
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        });
      },
    });
    const pending = createTrustedWorkerRuntime(fixture.state, controller.signal, wrapped);
    await eventually(() => calls.some((call) => call.startsWith("fetch-auth:")));
    controller.abort();
    await assert.rejects(pending, /launcher trusted composition failed/);
    assert.equal(JSON.stringify(calls).includes("TESTTOKEN"), false);
    assert.equal(calls.includes("api-close"), true);
    assert.equal(calls.includes("pi-dispose"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition defers triggered cleanup until startup quiesces", async () => {
  for (const mode of ["ssh-loss", "lifecycle-stopped", "pi-fatal"] as const) {
    const fixture = await makeFixture();
    try {
      const calls: string[] = [];
      const base = seams(calls, {});
      let release: (() => void) | undefined;
      let onLost: (() => void) | undefined;
      let onEvent: ((event: unknown) => void) | undefined;
      let onFatal: (() => void) | undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const wrapped = Object.freeze({
        ...base,
        ...(mode === "ssh-loss"
          ? {
              createSshManager: (options: Parameters<NonNullable<typeof base.createSshManager>>[0]) => {
                onLost = options.onLost as () => void;
                const ssh = (base.createSshManager as NonNullable<typeof base.createSshManager>)(options);
                return {
                  get ready() {
                    return ssh.ready;
                  },
                  start: (signal: AbortSignal) => ssh.start(signal),
                  shutdown: () => ssh.shutdown(),
                } as never;
              },
              prepareEnvoyBinary: async () => {
                calls.push("prepare-envoy");
                onLost?.();
                await gate;
                return Object.freeze({
                  path: "/redacted/envoy",
                  sha256: `sha256:${"3".repeat(64)}`,
                  image:
                    "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb",
                  cleanup: "owned" as const,
                });
              },
              cleanupEnvoyBinary: async () => calls.push("envoy-binary-cleanup"),
            }
          : {}),
        ...(mode === "lifecycle-stopped"
          ? {
              createLifecycle: (options: Parameters<TrustedCompositionSeams["createLifecycle"]>[0]) => {
                onEvent = options.onEvent as never;
                return fakeLifecycle(options, calls) as never;
              },
              createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
                calls.push("pi-pending");
                onEvent?.({ state: "stopped" });
                await gate;
                return (base.createPi as NonNullable<typeof base.createPi>)(options);
              },
            }
          : {}),
        ...(mode === "pi-fatal"
          ? {
              createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
                onFatal = options.onFatal as () => void;
                return (base.createPi as NonNullable<typeof base.createPi>)(options);
              },
              createApi: () =>
                Object.freeze({
                  listen: async () => {
                    calls.push("api-listen");
                    onFatal?.();
                    await gate;
                    return { port: 40123 };
                  },
                  close: async () => calls.push("api-close"),
                  publish: () => true,
                }) as never,
            }
          : {}),
      });
      const pending = createTrustedWorkerRuntime(
        fixture.state,
        new AbortController().signal,
        wrapped as unknown as Partial<TrustedCompositionSeams>,
      );
      await eventually(() => calls.some((call) => ["prepare-envoy", "pi-pending", "api-listen"].includes(call)));
      release?.();
      await assert.rejects(pending, /launcher trusted composition failed/);
      assert.equal(
        mode === "ssh-loss"
          ? calls.includes("envoy-binary-cleanup")
          : calls.includes(mode === "lifecycle-stopped" ? "pi-dispose" : "api-close"),
        true,
      );
      assert.equal(calls.includes("ssh-key-close"), true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("trusted composition rejects lifecycle stop during final verification without returning runtime", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    let event: ((event: unknown) => void) | undefined;
    const base = seams(calls, {});
    let fired = false;
    const wrapped = Object.freeze({
      ...base,
      createLifecycle: (options: Parameters<TrustedCompositionSeams["createLifecycle"]>[0]) => {
        event = options.onEvent as never;
        return fakeLifecycle(options, calls) as never;
      },
      readManifest: async (state: LauncherState) => {
        if (calls.includes("fetch-ready") && !fired) {
          fired = true;
          event?.({ state: "stopped" });
        }
        return (base.readManifest as NonNullable<typeof base.readManifest>)(state);
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(calls.includes("api-close"), true);
    assert.equal(calls.includes("pi-dispose"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition preserves runtime replacements during cleanup", async () => {
  for (const target of ["agent", "sessions", ".cogs-trusted-compose-owner", "root"] as const) {
    const fixture = await makeFixture();
    try {
      const calls: string[] = [];
      const base = seams(calls, {});
      let replaced = "";
      const wrapped = Object.freeze({
        ...base,
        readApiToken: async () => {
          throw new Error("force cleanup");
        },
        beforeRemoveRuntimePath: async (path: string) => {
          if (replaced !== "") return;
          const name = path.split("/").at(-1);
          if ((target === "root" && name?.startsWith("trusted-compose-")) || name === target) {
            replaced = path;
            await rm(path, { recursive: true, force: true });
            if (target === ".cogs-trusted-compose-owner") await writeFile(path, "attacker", { mode: 0o600 });
            else await mkdir(path, { mode: 0o700 });
          }
        },
      });
      await assert.rejects(
        createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
        /launcher trusted composition failed/,
      );
      assert.notEqual(replaced, "");
      await assert.doesNotReject(realpath(replaced));
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("trusted composition rejects same-inode sentinel overwrite before unlink", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    let sentinel = "";
    const wrapped = Object.freeze({
      ...base,
      readApiToken: async () => {
        throw new Error("force cleanup");
      },
      beforeRemoveRuntimePath: async (path: string) => {
        if (sentinel === "" && path.endsWith("/.cogs-trusted-compose-owner")) {
          sentinel = path;
          await writeFile(path, "x".repeat(stateId.length + 1), { flag: "r+" });
        }
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.notEqual(sentinel, "");
    await assert.doesNotReject(realpath(sentinel));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition rejects reservation close callback errors and releases port", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const controller = new AbortController();
    const base = seams(calls, {});
    const { reserveLoopbackPort: _omittedReservation, ...withoutReservation } = base;
    let selected = 0;
    const wrapped = Object.freeze({
      ...withoutReservation,
      createNetServer: () => {
        const server = createServer();
        const listen = server.listen.bind(server);
        const close = server.close.bind(server);
        server.listen = ((...args: Parameters<typeof server.listen>) => {
          server.once("listening", () => {
            const address = server.address();
            selected = typeof address === "object" && address !== null ? address.port : 0;
          });
          return listen(...args);
        }) as typeof server.listen;
        server.close = ((callback?: (error?: Error & { code?: string }) => void) =>
          close(() =>
            callback?.(Object.assign(new Error("synthetic close failure"), { code: "SYNTHETIC" })),
          )) as typeof server.close;
        return server;
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(
        fixture.state,
        controller.signal,
        wrapped as unknown as Partial<TrustedCompositionSeams>,
      ),
      /launcher trusted composition failed/,
    );
    assert.notEqual(selected, 0);
    const probe = createServer();
    await new Promise<void>((resolve, reject) => {
      probe.once("error", reject);
      probe.listen(selected, "127.0.0.1", () => resolve());
    });
    await new Promise<void>((resolve) => probe.close(() => resolve()));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition lifecycle stopped after return enters same cleanup", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    let event: ((event: unknown) => void) | undefined;
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      createLifecycle: (options: Parameters<TrustedCompositionSeams["createLifecycle"]>[0]) => {
        event = options.onEvent as never;
        return fakeLifecycle(options, calls) as never;
      },
    });
    const runtime = await createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped);
    event?.({ state: "stopped" });
    await new Promise((resolve) => setImmediate(resolve));
    await runtime.close();
    assert.equal(calls.includes("api-close"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition continues all later cleanup after individual cleanup failures", async () => {
  for (const failing of [
    "api",
    "pi",
    "egress",
    "ssh",
    "telemetry",
    "fixture",
    "otlp",
    "openbao",
    "token",
    "skills",
    "ssh-key",
  ] as const) {
    const fixture = await makeFixture();
    try {
      const calls: string[] = [];
      const base = seams(calls, {});
      const wrapped = Object.freeze({
        ...base,
        materializeSshControls: async (state: LauncherState) => {
          const v = await (base.materializeSshControls as NonNullable<typeof base.materializeSshControls>)(
            state,
            "linux-kvm",
            "authoritative-local",
            new AbortController().signal,
          );
          return hiddenSshControls({
            endpoint: v.endpoint,
            username: v.username,
            hostKeySha256: v.hostKeySha256,
            clientKeyPath: v.clientKeyPath,
            close: async () => {
              await v.close();
              if (failing === "ssh-key") throw new Error("x");
            },
          }) as never;
        },
        createSkillInputs: async (state: LauncherState, signal?: AbortSignal) => {
          const v = await (base.createSkillInputs as NonNullable<typeof base.createSkillInputs>)(state, signal);
          return Object.freeze({
            ...v,
            close: async () => {
              await v.close();
              if (failing === "skills") throw new Error("x");
            },
          });
        },
        readApiToken: async (state: LauncherState) => {
          const v = await (base.readApiToken as NonNullable<typeof base.readApiToken>)(state);
          return Object.freeze({
            ...v,
            dispose: () => {
              v.dispose();
              if (failing === "token") throw new Error("x");
            },
          });
        },
        startOpenBao: async (state: LauncherState, options?: { signal?: AbortSignal; deadlineAt?: number }) => {
          const v = await (base.startOpenBao as NonNullable<typeof base.startOpenBao>)(state, options);
          return Object.freeze({
            ...v,
            close: async () => {
              await v.close();
              if (failing === "openbao") throw new Error("x");
            },
          });
        },
        startLocalFixtures: async (options: never) => {
          const v = await (base.startLocalFixtures as NonNullable<typeof base.startLocalFixtures>)(options);
          return Object.freeze({
            ...v,
            close: async () => {
              await v.close();
              if (failing === "fixture") throw new Error("x");
            },
          });
        },
        startOtlpFixture: async (options: never) => {
          const v = await (base.startOtlpFixture as NonNullable<typeof base.startOtlpFixture>)(options);
          return Object.freeze({
            ...v,
            close: async () => {
              await v.close();
              if (failing === "otlp") throw new Error("x");
            },
          });
        },
        createTelemetry: (options: never) => {
          const v = (base.createTelemetry as NonNullable<typeof base.createTelemetry>)(options);
          return Object.freeze({
            ...v,
            close: async () => {
              await v.close();
              if (failing === "telemetry") throw new Error("x");
            },
          }) as never;
        },
        startEnvoyEgress: async (options: Parameters<NonNullable<typeof base.startEnvoyEgress>>[0]) => {
          const v = await (base.startEnvoyEgress as NonNullable<typeof base.startEnvoyEgress>)(options);
          return Object.freeze({
            ...v,
            close: async () => {
              await v.close();
              if (failing === "egress") throw new Error("x");
            },
          });
        },
        createSshManager: (options: Parameters<NonNullable<typeof base.createSshManager>>[0]) => {
          const ssh = (base.createSshManager as NonNullable<typeof base.createSshManager>)(options);
          return {
            get ready() {
              return ssh.ready;
            },
            start: (signal: AbortSignal) => ssh.start(signal),
            shutdown: async () => {
              await ssh.shutdown();
              if (failing === "ssh") throw new Error("x");
            },
          } as never;
        },
        createPi: async (options: Parameters<NonNullable<typeof base.createPi>>[0]) => {
          const pi = await (base.createPi as NonNullable<typeof base.createPi>)(options);
          return Object.freeze({
            ...pi,
            disposeOwnedRuntime: async () => {
              const result = await pi.disposeOwnedRuntime();
              if (failing === "pi") throw new Error("x");
              return result;
            },
          });
        },
        createApi: (options: never) => {
          const api = (base.createApi as NonNullable<typeof base.createApi>)(options);
          return Object.freeze({
            ...api,
            close: async () => {
              await api.close();
              if (failing === "api") throw new Error("x");
            },
          }) as never;
        },
      });
      const runtime = await createTrustedWorkerRuntime(
        fixture.state,
        new AbortController().signal,
        wrapped as unknown as Partial<TrustedCompositionSeams>,
      );
      await assert.rejects(runtime.close(), /launcher trusted composition failed/);
      assert.equal(calls.includes("ssh-key-close"), true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("trusted composition rejects ready proof status headers utf8 and oversize", async () => {
  const cases = [
    () =>
      new Response('{"ready":true,"closed":false}', { status: 503, headers: { "content-type": "application/json" } }),
    () => new Response('{"ready":true,"closed":false}', { status: 200, headers: { "content-type": "text/plain" } }),
    () => new Response(new Uint8Array([0xff]), { status: 200, headers: { "content-type": "application/json" } }),
    () =>
      new Response(`{"ready":true,"closed":false,"pad":"${"x".repeat(200)}"}`, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  ];
  for (const makeResponse of cases) {
    const fixture = await makeFixture();
    try {
      const calls: string[] = [];
      const base = seams(calls, {});
      const wrapped = Object.freeze({ ...base, fetch: async () => makeResponse() });
      await assert.rejects(
        createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
        /launcher trusted composition failed/,
      );
      assert.equal(calls.includes("api-close"), true);
      assert.equal(calls.includes("ssh-key-close"), true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("trusted composition rejects accessor proxy capability without invoking getter", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    let invoked = false;
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      startEnvoyEgress: async (options: Parameters<NonNullable<typeof base.startEnvoyEgress>>[0]) => {
        const handle = await (base.startEnvoyEgress as NonNullable<typeof base.startEnvoyEgress>)(options);
        const bad = { snapshot: handle.snapshot, close: handle.close };
        Object.defineProperty(bad, "proxyCapability", {
          enumerable: true,
          get: () => {
            invoked = true;
            return handle.proxyCapability;
          },
        });
        return Object.freeze(bad) as never;
      },
    });
    await assert.rejects(
      createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped),
      /launcher trusted composition failed/,
    );
    assert.equal(invoked, false);
    assert.equal(calls.includes("egress-close"), true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("trusted composition error serialization excludes seeded secret and path sentinels", async () => {
  const fixture = await makeFixture();
  try {
    const calls: string[] = [];
    const base = seams(calls, {});
    const wrapped = Object.freeze({
      ...base,
      fetch: async () => {
        throw new Error("TESTTOKEN MODEL_KEY_VALUE_123 INTEGRATION_SECRET PROXY_CAPABILITY_123 /redacted/envoy");
      },
    });
    await assert.rejects(createTrustedWorkerRuntime(fixture.state, new AbortController().signal, wrapped), (error) => {
      const text = JSON.stringify(error);
      return [
        "TESTTOKEN",
        "MODEL_KEY_VALUE_123",
        "INTEGRATION_SECRET",
        "PROXY_CAPABILITY_123",
        "/redacted/envoy",
      ].every((secret) => !text.includes(secret));
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function makeFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "cogs-trusted-compose-")));
  const sandboxDir = join(root, "sandbox");
  await import("node:fs/promises").then(async (fs) => {
    await fs.mkdir(sandboxDir, { mode: 0o700 });
    await fs.mkdir(join(root, "state"), { mode: 0o700 });
    await fs.mkdir(join(root, "state", "control"), { mode: 0o700 });
  });
  const state: LauncherState = Object.freeze({
    root,
    name: "s1",
    dir: join(root, "state"),
    controlDir: join(root, "state", "control"),
    sandboxDir,
    driverStateName: "driver",
    driverStateDir: join(root, "driver"),
    driverCacheDir: join(root, "cache"),
    lockDir: join(root, "lock"),
    manifestPath: join(root, "state", "manifest.json"),
    sentinelPath: join(root, "state", ".cogs-launcher-owner"),
    recoveryPath: join(root, "state", ".cogs-launcher-recovery"),
    stateId,
    sourceRevision,
  });
  return { root, state };
}

async function eventually(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for test condition");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

function hiddenSshControls(value: Record<string, unknown>) {
  const output: Record<string, unknown> = {};
  for (const key of ["endpoint", "username", "hostKeySha256", "clientKeyPath", "close"])
    Object.defineProperty(output, key, { value: value[key], enumerable: false, writable: false, configurable: false });
  return Object.freeze(output);
}

function seams(calls: string[], captured: Record<string, unknown>): Partial<TrustedCompositionSeams> {
  const fake: Partial<TrustedCompositionSeams> = {
    readManifest: async (state) => {
      calls.push("manifest");
      return Object.freeze({
        version: "cogs.dev-launcher-manifest/v1alpha1",
        stateId: state.stateId,
        stateName: state.name,
        sourceRevision: state.sourceRevision,
        profile: "linux-kvm",
        phase: "sandbox-ready",
        owned: { sandboxState: state.driverStateName, controlDir: "control", lockName: `.${state.stateId}.lock` },
        ports: [],
      }) as never;
    },
    readWorkerDescriptor: async (state) => {
      calls.push("descriptor");
      return Object.freeze({
        version: "cogs.dev-launcher-worker/v1alpha1",
        stateId: state.stateId,
        sourceRevision: state.sourceRevision,
        profile: "linux-kvm",
        authority: "authoritative-local",
        readiness: "starting",
        stage: "child-bound",
        startupDigest: `sha256:${"c".repeat(64)}`,
        parentPid: 10,
        parentPidIdentity: `sha256:${"d".repeat(64)}`,
        childPid: 11,
        childPidIdentity: `sha256:${"e".repeat(64)}`,
      }) as never;
    },
    preflightEgressRoot: async () => {
      calls.push("preflight-egress");
    },
    materializeSshControls: async (state) => {
      calls.push("ssh-controls");
      return hiddenSshControls({
        endpoint: "192.0.2.2:22",
        username: "root" as const,
        hostKeySha256: `SHA256:${"A".repeat(43)}`,
        clientKeyPath: `/run/cogs/ssh/launcher-${state.stateId}`,
        close: async () => {
          calls.push("ssh-key-close");
        },
      }) as never;
    },
    createSkillInputs: async () => {
      calls.push("skills");
      return Object.freeze({
        sharedRevision: emptyManifest,
        userRevision: emptyBundle,
        createPreparer: () =>
          Object.freeze({
            prepare: async () =>
              Object.freeze({
                piSkills: [],
                eagerTrustedSkillPrompt: "",
                agentsFiles: [],
                metadata: Object.freeze({ shared: [], user: [] }),
                dispose: async () => undefined,
              }),
          }),
        close: async () => {
          calls.push("skills-close");
        },
      }) as never;
    },
    readApiToken: async () => {
      calls.push("api-token");
      let token = "TESTTOKEN";
      return Object.freeze({
        read: () => token,
        withToken: (op: (token: string) => unknown) => {
          captured.apiTokenActive = true;
          try {
            return op(token);
          } finally {
            captured.apiTokenActive = false;
          }
        },
        dispose: () => {
          token = "";
          calls.push("api-token-dispose");
        },
      }) as never;
    },
    startOpenBao: async () => {
      calls.push("openbao");
      const modelSecret = "MODEL_KEY_VALUE_123";
      const server = createHttpServer((request, response) => {
        if (request.url?.startsWith("/v1/model/data/users/alice/anthropic") === true) {
          response.writeHead(200, { "content-type": "application/json" });
          response.end(
            JSON.stringify({
              data: {
                data: { api_key: modelSecret },
                metadata: {
                  created_time: "2026-01-01T00:00:00Z",
                  deletion_time: "",
                  destroyed: false,
                  version: 1,
                  custom_metadata: null,
                },
              },
            }),
          );
          return;
        }
        response.writeHead(404, { "content-type": "application/json" });
        response.end("{}");
      });
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => resolve());
      });
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      let closePromise: Promise<void> | undefined;
      const closeServer = () => {
        closePromise ??= new Promise<void>((resolve) => server.close(() => resolve()));
        server.closeAllConnections();
        return closePromise;
      };
      const holder = (secret: string) =>
        Object.freeze({ withSecret: (op: (secret: string) => unknown) => op(secret), dispose: () => undefined });
      return Object.freeze({
        snapshot: () =>
          Object.freeze({
            ready: true,
            name: "n",
            containerId: "c".repeat(64),
            port,
            image: "i",
            seeded: "model-kv-egress-pki",
            egress: {
              mount: "model",
              pkiMount: "pki",
              pkiRole: "cogs-egress",
              credentialHandle: "users/alice/integrations/stage3-localhost",
            },
          }),
        modelToken: holder("T".repeat(32)),
        modelApiKey: holder(modelSecret),
        egressToken: holder("E".repeat(32)),
        integrationCredential: holder("INTEGRATION_SECRET"),
        close: async () => {
          calls.push("openbao-close");
          await closeServer();
        },
      }) as never;
    },
    startLocalFixtures: async () => {
      calls.push("fixture");
      return Object.freeze({
        endpoint: () => "http://127.0.0.1:3000",
        snapshot: () => Object.freeze({ ready: true, port: 3000, generation: 0, inflight: 0, total: 0, counts: {} }),
        reset: () => undefined,
        close: async () => {
          calls.push("fixture-close");
        },
      });
    },
    startOtlpFixture: async () => {
      calls.push("otlp");
      return Object.freeze({
        endpoint: (signal: string) => `http://127.0.0.1:4318/v1/${signal}`,
        snapshot: () =>
          Object.freeze({
            ready: true,
            port: 4318,
            generation: 0,
            inflight: 0,
            logs: 0,
            traces: 0,
            metrics: 0,
            names: [],
          }),
        reset: () => calls.push("otlp-reset"),
        close: async () => {
          calls.push("otlp-close");
        },
      }) as never;
    },
    createTelemetry: () => {
      calls.push("telemetry");
      return Object.freeze({
        get ready() {
          return true;
        },
        span: () => true,
        metric: () => true,
        snapshot: () => Object.freeze({ ready: true, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 }),
        close: async () => {
          calls.push("telemetry-close");
        },
      }) as never;
    },
    prepareEnvoyBinary: async () => {
      calls.push("prepare-envoy");
      return Object.freeze({
        path: "/redacted/envoy",
        sha256: `sha256:${"3".repeat(64)}`,
        image: "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb",
        cleanup: "owned" as const,
      });
    },
    startEnvoyEgress: async (options) => {
      calls.push("egress-start");
      captured.launch = options.launchDocument;
      return Object.freeze({
        snapshot: () =>
          Object.freeze({
            ready: true,
            profile: "linux-kvm",
            listenerPort: 18080,
            replacementRequired: false,
            replacementEvents: 0,
            authority: {
              user: "alice",
              modelHandle: "users/alice/anthropic",
              egressHandle: "users/alice/integrations/stage3-localhost",
              pkiMount: "pki",
              pkiRole: "cogs-egress",
            },
            envoy: { image: "x", binarySha256: `sha256:${"3".repeat(64)}` },
            completions: { drained: 0, classification: "none" },
          }),
        s309CompletionProof: () =>
          Object.freeze({
            version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
            outcome: "pending",
          }),
        proxyCapability: Object.freeze({
          withSecret: (op: (secret: string) => unknown) => op("PROXY_CAPABILITY_123"),
          dispose: () => undefined,
        }),
        close: async () => {
          calls.push("egress-close");
        },
      }) as never;
    },
    createSshManager: () => {
      let ready = false;
      return {
        get ready() {
          return ready;
        },
        start: async () => {
          calls.push("ssh-start");
          ready = true;
        },
        shutdown: async () => {
          calls.push("ssh-shutdown");
          ready = false;
        },
      } as never;
    },
    createLifecycle: (options) => fakeLifecycle(options, calls) as never,
    createPi: async (options) => {
      calls.push("pi");
      captured.launch = options.launchDocument;
      await writeFile(join((options as { agentDir: string }).agentDir, "agent-state.json"), "{}", { flag: "wx" });
      await writeFile(join((options as { sessionRoot: string }).sessionRoot, "launcher.jsonl"), "", { flag: "wx" });
      return Object.freeze({
        state: async () => ({ runState: "idle" as const }),
        activeToolNames: () => ["read", "write", "edit", "bash"],
        sessionFile: () => join((options as { sessionRoot: string }).sessionRoot, "launcher.jsonl"),
        skillMetadata: () =>
          Object.freeze({
            shared: Object.freeze({
              scope: "shared",
              revision: emptyManifest,
              bundleDigest: emptyBundle,
              guestRoot: "/shared/skills",
              guestSubtree: "/shared/skills/empty",
              fileCount: 0,
              byteCount: 0,
              readOnlyEnforced: false,
            }),
            user: Object.freeze({
              scope: "user",
              revision: emptyBundle,
              bundleDigest: emptyBundle,
              guestRoot: "/user/skills",
              guestSubtree: "/user/skills/empty",
              fileCount: 0,
              byteCount: 0,
              readOnlyEnforced: false,
            }),
            agentsStatus: "missing",
            skillCount: 0,
          }),
        dispose: async () => {
          calls.push("pi-dispose");
        },
        disposeOwnedRuntime: async () => {
          calls.push("pi-dispose");
          await unlink(join((options as { agentDir: string }).agentDir, "agent-state.json")).catch(() => undefined);
          await unlink(join((options as { sessionRoot: string }).sessionRoot, "launcher.jsonl")).catch(() => undefined);
          await rmdir((options as { agentDir: string }).agentDir).catch(() => undefined);
          await rmdir((options as { sessionRoot: string }).sessionRoot).catch(() => undefined);
          return Object.freeze({ version: "cogs.pi-owned-runtime-cleanup/v1alpha1" as const, cleaned: true as const });
        },
        input: async () => "running" as const,
        abort: async () => ({ aborted: true, runState: "idle" as const }),
        entries: async () => ({ entries: [] }),
        createExport: async () => ({}),
        prepareShutdown: async () => ({}),
        navigate: async () => ({ cancelled: false }),
        model: {} as never,
        gitMapRecords: () => [],
        resolveGitMapping: async () => undefined,
      }) as never;
    },
    createApi: (options) => {
      assert.equal(captured.apiTokenActive, true);
      captured.eventReplayCapacity = (options as { eventReplayCapacity?: unknown }).eventReplayCapacity;
      return Object.freeze({
        listen: async () => {
          calls.push("api-listen");
          return { port: 40123 };
        },
        close: async () => {
          calls.push("api-close");
        },
        publish: () => true,
      }) as never;
    },
    fetch: async () => {
      calls.push("fetch-ready");
      return new Response('{"ready":true,"closed":false}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    reserveLoopbackPort: async () => {
      calls.push("reserve-port");
      return Object.freeze({
        port: 39000,
        close: async () => {
          calls.push("reserve-close");
        },
      });
    },
    mkdir: (async (path: unknown, options: unknown) => {
      calls.push(`mkdir:${String(path).split("/").at(-1)}`);
      await mkdir(String(path), options as never);
      return undefined;
    }) as never,
  };
  return Object.freeze(fake);
}
function fakeLifecycle(options: Parameters<TrustedCompositionSeams["createLifecycle"]>[0], calls: string[]) {
  let ready = false;
  return Object.freeze({
    get ready() {
      return ready;
    },
    get state() {
      return ready ? "ready" : "created";
    },
    start: async () => {
      for (const dep of options.dependencies) {
        if (dep.name === "auth") calls.push("auth-start");
        else await dep.start(new AbortController().signal);
      }
      ready = true;
      calls.push("lifecycle-ready");
    },
    requestShutdown: async () => {
      calls.push("lifecycle-shutdown");
      for (const dep of [...options.dependencies].reverse()) await dep.shutdown(new AbortController().signal);
      ready = false;
    },
  });
}

function s309EgressProof(...outcomes: readonly ("pending" | "pass" | "generation" | "total-count")[]) {
  let calls = 0;
  return Object.freeze({
    s309CompletionProof: () => {
      const outcome = outcomes[Math.min(calls++, outcomes.length - 1)] ?? "pass";
      return Object.freeze({
        version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
        ...(outcome === "pass"
          ? {
              outcome: "pass",
              trusted_authorization_credential: true,
              trusted_relay_exact: true,
              completion_observer_consistent: true,
            }
          : outcome === "pending"
            ? { outcome: "pending" }
            : { outcome: "fail", reason: outcome }),
      });
    },
  }) as never;
}

test("s3-09 trusted proof channel captures baseline and binds to serialized settled deltas", () => {
  let resetCalls = 0;
  let total = 5;
  let counts: Readonly<Record<string, number>> = Object.freeze({ "GET /credential 200": 4, "GET /health 200": 1 });
  const fixture = {
    snapshot: () => Object.freeze({ ready: true, port: 1234, generation: 0, inflight: 0, total, counts }),
    reset: () => {
      resetCalls += 1;
    },
  } as never;
  const emit = createS309ProofEmitter(fixture, s309EgressProof("pending", "pass"), "linux-kvm");
  const event = (correlation_id: string) =>
    Object.freeze({ kind: "run_settled", correlation_id, payload: Object.freeze({}) }) as never;
  assert.equal((emit(event("setup")).payload.s3_09_proof as { reason: string }).reason, "credential-count");
  counts = Object.freeze({ "GET /credential 200": 5, "GET /health 200": 1 });
  total = 6;
  const settled = emit(event("scenario"));
  assert.deepEqual(settled.payload.s3_09_proof, {
    version: "cogs.launcher.s3-09-proof/v1alpha1",
    scenario: "s3-09",
    profile: "linux-kvm",
    outcome: "pass",
    trusted_authorization_credential: true,
    trusted_relay_exact: true,
    completion_observer_consistent: true,
    fixture_denied_route_absent: true,
    fixture_observer_consistent: true,
    fixture_ready: true,
    fixture_baseline_captured: true,
  });
  assert.equal(resetCalls, 0);
  assert.equal(JSON.stringify(settled).includes("1234"), false);
  assert.equal(JSON.stringify(settled).includes("credential"), true);
});

test("s3-09 trusted proof channel emits fixed failure reasons without metadata leakage", () => {
  const make = (baseline: Record<string, unknown>, snapshot: Record<string, unknown> = baseline) => {
    let current = baseline;
    return {
      fixture: { snapshot: () => Object.freeze(current), reset: () => assert.fail("reset called") } as never,
      advance: () => (current = snapshot),
    };
  };
  const settled = Object.freeze({
    kind: "run_settled",
    correlation_id: "scenario",
    payload: Object.freeze({}),
  }) as never;
  for (const [baseline, snapshot, reason] of [
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: false, generation: 1, inflight: 0, total: 1, counts: Object.freeze({ "GET /credential 200": 1 }) },
      "fixture-not-ready",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: true, generation: 2, inflight: 0, total: 1, counts: Object.freeze({ "GET /credential 200": 1 }) },
      "generation",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: true, generation: 1, inflight: 1, total: 1, counts: Object.freeze({ "GET /credential 200": 1 }) },
      "inflight",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 1, counts: Object.freeze({ "GET /credential 200": 1 }) },
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      "total-count",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      "credential-count",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: true, generation: 1, inflight: 0, total: 1, counts: Object.freeze({ "GET /credential 401": 1 }) },
      "total-count",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: true, generation: 1, inflight: 0, total: 2, counts: Object.freeze({ "GET /credential 200": 2 }) },
      "total-count",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      {
        ready: true,
        generation: 1,
        inflight: 0,
        total: 2,
        counts: Object.freeze({ "GET /credential 200": 1, "GET /allowed 200": 1 }),
      },
      "denied-forwarded",
    ],
    [
      { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
      { ready: true, generation: 1, inflight: 0, total: 2, counts: Object.freeze({ "GET /credential 200": 1 }) },
      "total-count",
    ],
  ] as const) {
    const { fixture, advance } = make(baseline, snapshot);
    const emit = createS309ProofEmitter(
      fixture,
      s309EgressProof(reason === "credential-count" ? "pending" : "pass"),
      "linux-kvm",
    );
    advance();
    assert.deepEqual(emit(settled).payload.s3_09_proof, {
      version: "cogs.launcher.s3-09-proof/v1alpha1",
      scenario: "s3-09",
      profile: "linux-kvm",
      outcome: "fail",
      reason,
    });
  }
  const zeroCredential = make({ ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) });
  const lateExtra = createS309ProofEmitter(zeroCredential.fixture, s309EgressProof("pass", "total-count"), "linux-kvm");
  assert.equal((lateExtra(settled).payload.s3_09_proof as { outcome: string }).outcome, "pass");
  assert.equal((lateExtra(settled).payload.s3_09_proof as { reason: string }).reason, "total-count");
  assert.equal(
    (
      createS309ProofEmitter(zeroCredential.fixture, s309EgressProof("pending"), "linux-kvm")(settled).payload
        .s3_09_proof as { reason: string }
    ).reason,
    "credential-count",
  );
  assert.deepEqual(
    createS309ProofEmitter(zeroCredential.fixture, s309EgressProof("pass"), "linux-kvm")(settled).payload.s3_09_proof,
    {
      version: "cogs.launcher.s3-09-proof/v1alpha1",
      scenario: "s3-09",
      profile: "linux-kvm",
      outcome: "pass",
      trusted_authorization_credential: true,
      trusted_relay_exact: true,
      completion_observer_consistent: true,
      fixture_denied_route_absent: true,
      fixture_observer_consistent: true,
      fixture_ready: true,
      fixture_baseline_captured: true,
    },
  );
  assert.equal(
    (
      createS309ProofEmitter(zeroCredential.fixture, s309EgressProof("generation"), "linux-kvm")(settled).payload
        .s3_09_proof as { reason: string }
    ).reason,
    "generation",
  );
  const otherTraffic = make(
    { ready: true, generation: 1, inflight: 0, total: 0, counts: Object.freeze({}) },
    { ready: true, generation: 1, inflight: 0, total: 1, counts: Object.freeze({}) },
  );
  const otherEmit = createS309ProofEmitter(otherTraffic.fixture, s309EgressProof("pass"), "linux-kvm");
  otherTraffic.advance();
  assert.equal((otherEmit(settled).payload.s3_09_proof as { reason: string }).reason, "total-count");
  const wrongProfile = make({
    ready: true,
    generation: 0,
    inflight: 0,
    total: 1,
    counts: Object.freeze({ "GET /credential 200": 1 }),
  });
  assert.equal(
    "s3_09_proof" in
      createS309ProofEmitter(wrongProfile.fixture, s309EgressProof("pass"), "insecure-container")(settled).payload,
    false,
  );
});

test("raw export opening verifier accepts real local exporter bundle", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-real-raw-open-"));
  try {
    const realRoot = await realpath(root);
    const sessionRoot = join(realRoot, "sessions");
    const sessionDir = join(sessionRoot, "session-1");
    await mkdir(sessionDir, { recursive: true, mode: 0o700 });
    await chmod(sessionRoot, 0o700);
    await chmod(sessionDir, 0o700);
    const sessionFile = join(sessionDir, "session.jsonl");
    await writeFile(sessionFile, sessionJsonl("native-pi-session"), { mode: 0o600 });
    await chmod(sessionFile, 0o600);
    const history = createCogsJsonlHistoryStore({ sessionFile, sessionDir });
    await history.initialize();
    const local = createCogsLocalExporter({
      sessionDir,
      sessionId: "session-1",
      history,
      skillMetadata: realExportSkillMetadata,
      model: { provider: "test", id: "model" },
    });
    const verifier = createRawExportOpeningVerifier(
      Object.freeze({
        createExport: async (input: { signal?: AbortSignal }) =>
          local.createExport(input.signal === undefined ? {} : { signal: input.signal }),
        sessionFile: () => sessionFile,
      }) as never,
      sessionRoot,
      "session-1",
    );
    const result = await verifier.createExport({ requestId: "req", correlationId: "corr" });
    assert.equal(
      (result as { raw_export_opening: { current_session: boolean } }).raw_export_opening.current_session,
      true,
    );
    assert.equal((result as { file_count: number }).file_count, 6);
    await local.dispose();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("raw export opening verifier accepts real hardened Pi session export", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-real-pi-raw-open-"));
  try {
    const realRoot = await realpath(root);
    const cwd = join(realRoot, "workspace");
    const agentDir = join(realRoot, "agent");
    const sessionRoot = join(realRoot, "sessions");
    const sessionId = "cogs-session-1";
    await mkdir(cwd, { recursive: true, mode: 0o700 });
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    const pi = await createCogsPiSession({
      cwd,
      agentDir,
      sessionRoot,
      sessionId,
      userId: "user-1",
      model: { provider: "anthropic", id: "claude-sonnet-4-5" },
      apiKey: "aaaaaaaa",
      toolPorts: rawVerifierToolPorts,
      streamFn: createDeterministicLauncherStream(Object.freeze({ now: () => 1780000000000 })),
      preparedResources: realPreparedResources(),
      emit: () => true,
      onFatal: () => undefined,
    });
    try {
      await pi.input({
        requestId: "run",
        correlationId: "corr",
        kind: "prompt",
        content: LAUNCHER_DETERMINISTIC_NORMAL_PROMPT,
      });
      for (let i = 0; i < 500 && (await pi.state()).runState !== "settled"; i += 1)
        await new Promise((resolveTimer) => setTimeout(resolveTimer, 10));
      assert.equal((await pi.state()).runState, "settled");
      const live = pi.sessionFile();
      assert.ok(live);
      assert.equal((await lstat(live)).mode & 0o777, 0o600);
      const result = await createRawExportOpeningVerifier(pi, sessionRoot, sessionId).createExport({
        requestId: "req",
        correlationId: "corr",
      });
      assert.equal(
        (result as { raw_export_opening: { current_session: boolean } }).raw_export_opening.current_session,
        true,
      );
    } finally {
      await pi.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("raw export opening verifier uses pinned Pi and emits only fixed metadata", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-raw-open-"));
  try {
    const realRoot = await realpath(root);
    await makeRawBundle(realRoot, "session-1", undefined, "native-pi-session");
    const verifier = createRawExportOpeningVerifier(exporter(realRoot, "session-1"), realRoot, "session-1");
    const result = await verifier.createExport({ requestId: "req", correlationId: "corr" });
    assert.deepEqual((result as { raw_export_opening: unknown }).raw_export_opening, {
      version: "cogs.launcher.raw-export-opening/v1alpha1",
      opened_with: "pinned-pi-session-manager",
      session_jsonl_openable: true,
      current_session: true,
      content_redacted: true,
    });
    const serialized = JSON.stringify(result);
    for (const forbidden of [root, "session.jsonl", "secret", "tool-output"])
      assert.equal(serialized.includes(forbidden), false, forbidden);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("raw export opening verifier accepts bounded large session JSONL", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-raw-open-large-"));
  try {
    const realRoot = await realpath(root);
    await makeRawBundle(realRoot, "session-1", 2 * 1024 * 1024 - 4096);
    const verifier = createRawExportOpeningVerifier(exporter(realRoot, "session-1"), realRoot, "session-1");
    const result = await verifier.createExport({ requestId: "req", correlationId: "corr" });
    assert.equal(
      (result as { raw_export_opening: { session_jsonl_openable: boolean } }).raw_export_opening.session_jsonl_openable,
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("raw export opening verifier fails closed on hostile bundle shapes", async () => {
  for (const kind of [
    "wrong-session",
    "wrong-live-session",
    "missing-live",
    "live-outside",
    "live-export-alias",
    "live-symlink",
    "live-hardlink",
    "live-mode",
    "live-oversize",
    "malformed-jsonl",
    "symlink",
    "hardlink",
    "oversize",
    "getter",
    "extra",
    "missing",
    "bad-digest",
    "bad-date",
    "bad-count",
    "bad-total",
    "wrong-root",
  ] as const) {
    const root = await mkdtemp(join(tmpdir(), `cogs-raw-open-${kind}-`));
    try {
      const realRoot = await realpath(root);
      await makeRawBundle(realRoot, "session-1");
      let descriptor = descriptorFor("session-1") as Record<string, unknown>;
      let liveOverride: string | undefined | null;
      if (kind === "wrong-session") {
        await writeFile(
          join(root, "session-1", "exports", "cogs-session-session-1", "session.jsonl"),
          sessionJsonl("native-session-2"),
          {
            mode: 0o600,
          },
        );
      }
      if (kind === "wrong-live-session")
        await writeFile(liveFileFor(root, "session-1"), sessionJsonl("native-session-2"), { mode: 0o600 });
      if (kind === "missing-live") liveOverride = null;
      if (kind === "live-outside") {
        liveOverride = join(root, "outside.jsonl");
        await writeFile(liveOverride, sessionJsonl("native-session-1"), { mode: 0o600 });
        await chmod(liveOverride, 0o600);
      }
      if (kind === "live-export-alias")
        liveOverride = join(root, "session-1", "exports", "cogs-session-session-1", "session.jsonl");
      if (kind === "live-symlink") {
        const live = liveFileFor(root, "session-1");
        await unlink(live);
        await symlink(join(root, "target"), live);
      }
      if (kind === "live-hardlink") await link(liveFileFor(root, "session-1"), join(root, "session-1", "other.jsonl"));
      if (kind === "live-mode") await chmod(liveFileFor(root, "session-1"), 0o644);
      if (kind === "live-oversize")
        await writeFile(
          liveFileFor(root, "session-1"),
          `${sessionJsonl("native-session-1")}${"x".repeat(2 * 1024 * 1024)}\n`,
          {
            mode: 0o600,
          },
        );
      if (kind === "malformed-jsonl")
        await writeFile(join(root, "session-1", "exports", "cogs-session-session-1", "session.jsonl"), "not-json\n", {
          mode: 0o600,
        });
      if (kind === "symlink") {
        const file = join(root, "session-1", "exports", "cogs-session-session-1", "session.jsonl");
        await unlink(file);
        await symlink(join(root, "target"), file);
      }
      if (kind === "hardlink")
        await link(
          join(root, "session-1", "exports", "cogs-session-session-1", "session.jsonl"),
          join(root, "session-1", "exports", "cogs-session-session-1", "other.jsonl"),
        );
      if (kind === "oversize")
        await writeFile(
          join(root, "session-1", "exports", "cogs-session-session-1", "session.jsonl"),
          `${sessionJsonl("session-1")}${"x".repeat(2 * 1024 * 1024)}\n`,
          { mode: 0o600 },
        );
      if (kind === "getter")
        descriptor = Object.freeze(
          Object.defineProperty({}, "version", {
            enumerable: true,
            get() {
              throw new Error("SECRET");
            },
          }),
        ) as never;
      if (kind === "extra") descriptor = { ...descriptor, extra: true };
      if (kind === "missing") {
        descriptor = { ...descriptor };
        delete descriptor.total_bytes;
      }
      if (kind === "bad-digest") descriptor = { ...descriptor, manifest_sha256: "sha256:bad" };
      if (kind === "bad-date") descriptor = { ...descriptor, created_at: "not-date" };
      if (kind === "bad-count") descriptor = { ...descriptor, file_count: 5 };
      if (kind === "bad-total") descriptor = { ...descriptor, total_bytes: 72 * 1024 * 1024 + 1 };
      const verifier = createRawExportOpeningVerifier(
        exporter(realRoot, "session-1", descriptor, liveOverride),
        kind === "wrong-root" ? join(realRoot, "missing") : realRoot,
        "session-1",
      );
      await assert.rejects(
        () => verifier.createExport({ requestId: "req", correlationId: "corr" }),
        /launcher trusted composition failed/,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

async function makeRawBundle(
  root: string,
  sessionId: string,
  contentBytes?: number,
  nativeSessionId = "native-session-1",
): Promise<void> {
  const sessionDir = join(root, sessionId);
  const bundle = join(sessionDir, "exports", `cogs-session-${sessionId}`);
  await mkdir(bundle, { recursive: true, mode: 0o700 });
  await chmod(sessionDir, 0o700);
  await chmod(join(sessionDir, "exports"), 0o700);
  await chmod(bundle, 0o700);
  await writeFile(liveFileFor(root, sessionId), sessionJsonl(nativeSessionId), { mode: 0o600 });
  await chmod(liveFileFor(root, sessionId), 0o600);
  await writeFile(join(bundle, "session.jsonl"), sessionJsonl(nativeSessionId, contentBytes), { mode: 0o600 });
  await chmod(join(bundle, "session.jsonl"), 0o600);
}

function liveFileFor(root: string, sessionId: string): string {
  return join(root, sessionId, "live-session.jsonl");
}

function sessionJsonl(sessionId: string, contentBytes?: number): string {
  const content = contentBytes === undefined ? "secret" : "x".repeat(contentBytes);
  return `${JSON.stringify({ type: "session", version: 3, id: sessionId, timestamp: "2026-01-01T00:00:00.000Z", cwd: "/workspace" })}\n${JSON.stringify({ type: "message", id: "aaaaaaaa", parentId: null, timestamp: "2026-01-01T00:00:01.000Z", message: { role: "user", content } })}\n`;
}

function descriptorFor(sessionId: string): Record<string, unknown> {
  return {
    version: "cogs.export-descriptor/v1alpha1",
    bundle: `cogs-session-${sessionId}`,
    manifest_sha256: "a".repeat(64),
    created_at: "2026-01-01T00:00:00.000Z",
    mode: "raw",
    attachments_included: false,
    file_count: 6,
    total_bytes: 200,
    sensitive: true,
    sanitized: false,
    anonymized: false,
  };
}

function exporter(
  root: string,
  sessionId: string,
  descriptor: unknown = descriptorFor(sessionId),
  liveSessionFile: string | undefined | null = liveFileFor(root, sessionId),
) {
  return Object.freeze({
    createExport: async () => descriptor,
    sessionFile: () => (liveSessionFile === null ? undefined : liveSessionFile),
  }) as never;
}

const rawVerifierToolPorts: CogsToolPorts = Object.freeze({
  read: async (input: Parameters<CogsToolPorts["read"]>[0]) => ({ path: input.path, content: "" }),
  write: async (input: Parameters<CogsToolPorts["write"]>[0]) => ({ bytes: input.content.length }),
  edit: async () => ({ ok: true }),
  bash: async () => ({ exit_code: 0, stdout: "cogs-launcher-deterministic" }),
});

function realPreparedResources() {
  return Object.freeze({
    piSkills: Object.freeze([]),
    eagerTrustedSkillPrompt: "",
    agentsFiles: Object.freeze([]),
    metadata: realExportSkillMetadata(),
    dispose: async () => undefined,
  });
}

function realExportSkillMetadata(): CogsPreparedSkillMetadata {
  const digest = (seed: string) => `sha256:${createHash("sha256").update(seed).digest("hex")}` as const;
  return Object.freeze({
    shared: Object.freeze({
      scope: "shared",
      revision: digest("shared"),
      bundleDigest: digest("shared-bundle"),
      guestRoot: "/shared/skills",
      guestSubtree: `/shared/skills/${digest("shared-bundle").slice(7)}`,
      fileCount: 1,
      byteCount: 1,
      readOnlyEnforced: false,
    }),
    user: Object.freeze({
      scope: "user",
      revision: digest("user-bundle"),
      bundleDigest: digest("user-bundle"),
      guestRoot: "/user/skills",
      guestSubtree: `/user/skills/${digest("user-bundle").slice(7)}`,
      fileCount: 1,
      byteCount: 1,
      readOnlyEnforced: false,
    }),
    agentsStatus: "missing",
    skillCount: 0,
  });
}
