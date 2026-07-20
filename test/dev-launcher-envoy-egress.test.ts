import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  ENVOY_IMAGE,
  type EnvoyEgressSeams,
  prepareEnvoyBinary,
  startEnvoyEgress,
} from "../dev/launcher/envoy-egress.ts";
import type { OpenBaoHandle, SecretHolder } from "../dev/launcher/openbao.ts";
import { createState, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";
import { canonicalPresetPolicyRevision } from "../src/egress/preset-revision.ts";
import type { CogsEgressRuntimeManagerOptions } from "../src/egress/runtime-manager.ts";

const sourceRevision = "a".repeat(40);
const fakeBin = Buffer.alloc(1024 * 1024, 1);
const fakeBinHash = `sha256:${createHash("sha256").update(fakeBin).digest("hex")}`;
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
    limits: { cpu: 1, memory_bytes: 536870912, tool_timeout_seconds: 60, max_tool_output_bytes: 65536 },
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
      runVersion: Object.freeze(async () => "Envoy version: 1.38.3/clean"),
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
    assert.equal(captured.pkiSource.constructor.name, "OpenBaoEgressPkiSource");
    assert.equal(JSON.stringify(snap).includes("token"), false);
    await h.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
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
    assert.deepEqual(calls.slice(0, 4), ["manager.start", "relay.start", "relay.register:18081", "relay.switch:18081"]);
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
      runVersion: Object.freeze(async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        await new Promise((resolve) => setTimeout(resolve, 80));
        return "Envoy version: 1.38.3/clean";
      }),
    });
    await assert.rejects(
      () => prepareEnvoyBinary(state, { deadlineAt: Date.now() + 50, seams }),
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
    assert.equal(h.close(), first);
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
      start: (options?: { signal?: AbortSignal }) => {
        queueMicrotask(() => controller.abort());
        return new Promise<void>((_resolve, reject) =>
          options?.signal?.addEventListener("abort", () => {
            events.push("relay.abort");
            reject(new Error("aborted"));
          }),
        );
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
