import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import test from "node:test";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { AssistantMessage } from "@earendil-works/pi-ai/compat";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import type { Ajv as AjvCore } from "ajv";
import { createFakeModelStream } from "../spikes/pi-embedding.ts";
import { createApiServer } from "../src/api/server.ts";
import type { ModelApiKeySource } from "../src/auth/model-auth.ts";
import { type LaunchDependency, LaunchLifecycle } from "../src/launch/lifecycle.ts";
import {
  COGS_PI_TOOL_NAMES,
  type CogsPiSessionOptions,
  type CogsToolPorts,
  createAuthenticatedCogsPiSession,
  createCogsPiSession,
} from "../src/pi/session.ts";

const require = createRequire(import.meta.url);
const Ajv = require("ajv/dist/2020") as new (options?: Record<string, unknown>) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
const hostileFixtures = resolve(import.meta.dirname, "fixtures/hostile-discovery");

async function installHostileCanaries(cwd: string, agentDir: string, marker: string): Promise<void> {
  const projectExtension = resolve(cwd, ".pi/extensions/canary.js");
  const globalExtension = resolve(agentDir, "extensions/canary.js");
  const projectPackage = resolve(cwd, "hostile-project-package");
  const globalPackage = resolve(agentDir, "hostile-global-package");
  await mkdir(dirname(projectExtension), { recursive: true });
  await mkdir(dirname(globalExtension), { recursive: true });
  await cp(resolve(hostileFixtures, "project-extension/canary.js"), projectExtension);
  await cp(resolve(hostileFixtures, "global-extension/canary.js"), globalExtension);
  await cp(resolve(hostileFixtures, "project-package"), projectPackage, { recursive: true });
  await cp(resolve(hostileFixtures, "global-package"), globalPackage, { recursive: true });
  await writeFile(
    resolve(cwd, ".pi/settings.json"),
    JSON.stringify({ extensions: [projectExtension], packages: [projectPackage] }),
  );
  await writeFile(
    resolve(agentDir, "settings.json"),
    JSON.stringify({ extensions: [globalExtension], packages: [globalPackage] }),
  );
  process.env.COGS_CANARY_MARKER = marker;
}

async function assertMissing(path: string): Promise<void> {
  await assert.rejects(readFile(path, "utf8"), { code: "ENOENT" });
}

async function eventually(assertion: () => void | Promise<void>): Promise<void> {
  const deadline = Date.now() + 5000;
  let last: unknown;
  while (Date.now() < deadline) {
    try {
      await assertion();
      return;
    } catch (error) {
      last = error;
      await new Promise((resolveTimer) => setTimeout(resolveTimer, 20));
    }
  }
  throw last;
}

function withDefaults(
  options: Omit<CogsPiSessionOptions, "emit" | "onFatal"> & Partial<Pick<CogsPiSessionOptions, "emit" | "onFatal">>,
): CogsPiSessionOptions {
  return { emit: () => true, onFatal: () => undefined, ...options };
}

function validLaunch(sessionId: string): unknown {
  const digest = `sha256:${"a".repeat(64)}`;
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "user-1",
    session_id: sessionId,
    workspace_id: "workspace-1",
    sandbox: {
      ssh_endpoint: "sandbox.local:2222",
      ssh_host_key: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      client_key_path: `/run/cogs/ssh/${sessionId}`,
      proxy_auth_handle: `sessions/${sessionId}/proxy`,
    },
    model: { provider: "anthropic", id: "claude-sonnet-4-5", credential_handle: "users/user-1/model" },
    skills: {
      shared_revision: digest,
      shared_path: "/shared/skills",
      user_revision: digest,
      user_path: "/user/skills",
    },
    integrations: [],
    limits: { cpu: 1, memory_bytes: 268435456, tool_timeout_seconds: 30, max_tool_output_bytes: 4096 },
  };
}

function dependencies(shutdowns: string[]): LaunchDependency[] {
  return (["sessionStorage", "ssh", "proxy", "auth", "auditWal"] as const).map((name) => ({
    name,
    start: async () => undefined,
    shutdown: async () => {
      shutdowns.push(name);
    },
  }));
}

function fakePorts(calls: string[], result: unknown = { ok: true }): CogsToolPorts {
  return {
    read: async (input) => {
      calls.push(`read:${input.path}`);
      return { ...asRecord(result), path: input.path, content: "hello" };
    },
    write: async (input) => {
      calls.push(`write:${input.path}`);
      return { ...asRecord(result), bytes: input.content.length };
    },
    edit: async (input) => {
      calls.push(`edit:${input.path}`);
      return { ...asRecord(result), old: input.oldText, new: input.newText };
    },
    bash: async (input) => {
      calls.push(`bash:${input.command}`);
      await input.onUpdate?.({
        content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: asRecord(result).leaked ?? "ok" }) }],
        details: { cogsTool: "bash", stream: "stdout" },
      });
      await input.onUpdate?.({
        content: [{ type: "text", text: JSON.stringify({ terminal: true, exitCode: 0, signal: null }) }],
        details: { cogsTool: "bash", terminal: true },
      });
      return { ...asRecord(result), exit_code: 0, stdout: "" };
    },
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function hangingStream(aborted: { count: number }): StreamFn {
  return (_model, _context, options) => {
    const stream = createAssistantMessageEventStream();
    options?.signal?.addEventListener("abort", () => {
      aborted.count += 1;
      stream.end();
    });
    return stream;
  };
}

function oneToolStream(name: string, args: Record<string, unknown>): StreamFn {
  let calls = 0;
  return (model) => {
    calls += 1;
    const stream = createAssistantMessageEventStream();
    const content =
      calls === 1
        ? [{ type: "toolCall" as const, id: "tool-1", name, arguments: args }]
        : [{ type: "text" as const, text: "done" }];
    const message: AssistantMessage = {
      role: "assistant",
      content,
      api: "anthropic-messages",
      provider: "anthropic",
      model: model.id,
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: calls === 1 ? "toolUse" : "stop",
      timestamp: Date.now(),
    };
    queueMicrotask(() => {
      stream.push({ type: "start", partial: message });
      if (calls === 1) {
        const toolCall = message.content[0];
        if (toolCall?.type !== "toolCall") throw new Error("bad tool call");
        stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
        stream.push({ type: "toolcall_end", contentIndex: 0, toolCall, partial: message });
      }
      stream.push({ type: "done", reason: message.stopReason === "toolUse" ? "toolUse" : "stop", message });
      stream.end();
    });
    return stream;
  };
}

function allToolsStream(): StreamFn {
  const tools = [
    { name: "read", arguments: { path: "/workspace/README.md" } },
    { name: "write", arguments: { path: "/workspace/out.txt", content: "payload" } },
    { name: "edit", arguments: { path: "/workspace/out.txt", oldText: "old", newText: "new" } },
    { name: "bash", arguments: { command: "printf ok" } },
  ];
  let calls = 0;
  return (model) => {
    calls += 1;
    const stream = createAssistantMessageEventStream();
    const tool = tools[calls - 1];
    const content = tool
      ? [{ type: "toolCall" as const, id: `tool-${calls}`, name: tool.name, arguments: tool.arguments }]
      : [{ type: "text" as const, text: "all tools complete tokenization unaffected" }];
    const message: AssistantMessage = {
      role: "assistant",
      content,
      api: "anthropic-messages",
      provider: "anthropic",
      model: model.id,
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: tool ? "toolUse" : "stop",
      timestamp: Date.now(),
    };
    queueMicrotask(() => {
      stream.push({ type: "start", partial: message });
      if (tool) {
        const toolCall = message.content[0];
        if (toolCall?.type !== "toolCall") throw new Error("bad tool call");
        stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
        stream.push({ type: "toolcall_end", contentIndex: 0, toolCall, partial: message });
      } else {
        stream.push({ type: "text_start", contentIndex: 0, partial: message });
        stream.push({ type: "text_delta", contentIndex: 0, delta: "all tools complete", partial: message });
        stream.push({ type: "text_end", contentIndex: 0, content: "all tools complete", partial: message });
      }
      stream.push({ type: "done", reason: tool ? "toolUse" : "stop", message });
      stream.end();
    });
    return stream;
  };
}

function nonCooperativeStream(): StreamFn {
  return () => createAssistantMessageEventStream();
}

function internalSession(adapter: Awaited<ReturnType<typeof createCogsPiSession>>): {
  abort: () => Promise<void>;
  dispose: () => void;
  _emit: (event: { type: string; [key: string]: unknown }) => void;
} {
  return (
    adapter as unknown as {
      session: {
        abort: () => Promise<void>;
        dispose: () => void;
        _emit: (event: { type: string; [key: string]: unknown }) => void;
      };
    }
  ).session;
}

function oneTextStream(text: string): StreamFn {
  return (model) => {
    const stream = createAssistantMessageEventStream();
    const message: AssistantMessage = {
      role: "assistant",
      content: [{ type: "text", text }],
      api: "anthropic-messages",
      provider: "anthropic",
      model: model.id,
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: Date.now(),
    };
    queueMicrotask(() => {
      stream.push({ type: "start", partial: message });
      stream.push({ type: "text_start", contentIndex: 0, partial: message });
      stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: message });
      stream.push({ type: "text_end", contentIndex: 0, content: text, partial: message });
      stream.push({ type: "done", reason: "stop", message });
      stream.end();
    });
    return stream;
  };
}

test("Pi session adapter constructs locked runtime-only SDK components, only Cogs tools, and native JSONL", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-session-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const secret = "COGS_RUNTIME_ONLY_TEST_KEY";
  const calls: string[] = [];
  const events: Array<{ kind: string; correlation_id: string; request_id?: string; text: string }> = [];
  const fakeModelState = { calls: 0, observedApiKeys: [] as Array<string | undefined> };
  const marker = resolve(temporaryRoot, "CANARY_EXECUTED");
  const priorMarker = process.env.COGS_CANARY_MARKER;

  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await installHostileCanaries(cwd, agentDir, marker);

    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: sessionDir,
        sessionId: "session-test",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: fakePorts(calls),
        streamFn: createFakeModelStream(fakeModelState),
        emit: (event) => {
          events.push({
            kind: event.kind,
            correlation_id: event.correlation_id,
            ...(event.request_id === undefined ? {} : { request_id: event.request_id }),
            text: JSON.stringify(event),
          });
          return true;
        },
        operationTimeoutMs: 10_000,
      }),
    );

    try {
      assert.equal("authStorage" in adapter, false);
      assert.equal("modelRegistry" in adapter, false);
      assert.deepEqual([...adapter.activeToolNames()].sort(), [...COGS_PI_TOOL_NAMES].sort());
      assert.equal(
        await adapter.input({ requestId: "req1", correlationId: "corr1", kind: "prompt", content: "use read" }),
        "running",
      );
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      await assertMissing(marker);
      assert.deepEqual(calls, ["read:/workspace/README.md"]);
      assert.deepEqual(fakeModelState.observedApiKeys, [secret, secret]);
      assert.equal(events.filter((event) => event.kind === "run_settled").length, 1);
      assert.equal(
        events.some((event) => event.text.includes(secret)),
        false,
        "events must not contain API keys",
      );

      const sessionFile = adapter.sessionFile();
      assert.ok(sessionFile);
      const jsonl = await readFile(sessionFile, "utf8");
      assert.equal(jsonl.includes(secret), false, "runtime API keys must not be persisted in Pi JSONL");
      const reopened = SessionManager.open(sessionFile, dirname(sessionFile));
      assert.equal(reopened.getHeader()?.version, 3);
      const firstUser = reopened
        .getEntries()
        .find((entry) => entry.type === "message" && entry.message.role === "user");
      assert.ok(firstUser);

      await adapter.navigate(firstUser.id);
      await assert.rejects(
        adapter.input({ requestId: "req2", correlationId: "corr2", kind: "follow_up", content: "not running" }),
        /not running/,
      );
    } finally {
      await adapter.dispose();
    }

    await assert.rejects(readFile(resolve(agentDir, "auth.json"), "utf8"), { code: "ENOENT" });
  } finally {
    if (priorMarker === undefined) delete process.env.COGS_CANARY_MARKER;
    else process.env.COGS_CANARY_MARKER = priorMarker;
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session invokes exactly the four Cogs tool ports and redacts tool-result secrets", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-tools-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const secret = "COGS_RUNTIME_ONLY_TEST_KEY";
  const calls: string[] = [];
  const events: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: sessionDir,
        sessionId: "tool-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: fakePorts(calls, { leaked: secret, innocentPrefix: secret.slice(0, 16), normal: "tokenization" }),
        streamFn: allToolsStream(),
        emit: (event) => {
          events.push(JSON.stringify(event));
          return true;
        },
        maxToolResultBytes: 4096,
      }),
    );
    try {
      assert.deepEqual([...adapter.activeToolNames()].sort(), [...COGS_PI_TOOL_NAMES].sort());
      await adapter.input({ requestId: "tools", correlationId: "tools-corr", kind: "prompt", content: "all" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.deepEqual(calls, [
        "read:/workspace/README.md",
        "write:/workspace/out.txt",
        "edit:/workspace/out.txt",
        "bash:printf ok",
      ]);
      const eventText = events.join("\n");
      assert.equal(eventText.includes(secret), false);
      assert.equal(eventText.includes(secret.slice(0, 16)), true, "innocent shared prefixes must not be redacted");
      assert.equal(eventText.includes("tokenization"), true, "innocent normal text must not be redacted");
      const bashUpdateEvent = events.find(
        (event) => event.includes('"cogsTool":"bash"') && event.includes('"stream":"stdout"'),
      );
      assert.ok(bashUpdateEvent, "bash update content/details must be forwarded as a full tool update result");
      assert.equal(bashUpdateEvent.includes(secret), false);
      assert.ok(Buffer.byteLength(bashUpdateEvent, "utf8") <= 4096);
      const sessionFile = adapter.sessionFile();
      assert.ok(sessionFile);
      assert.equal((await readFile(sessionFile, "utf8")).includes(secret), false);
      await assert.rejects(adapter.entries({ after: "missing", limit: 1 }), /unknown history cursor/);
      await assert.rejects(adapter.entries({ after: undefined, limit: 0 }), /invalid history limit/);
      await assert.rejects(adapter.entries({ after: undefined, limit: 101 }), /invalid history limit/);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session rejects malformed tool args and malformed tool results without key leakage", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-tool-errors-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const secret = "COGS_RUNTIME_ONLY_TEST_KEY";
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const malformedCalls: string[] = [];
    const malformed = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "malformed-args"),
        sessionId: "tool-malformed-args",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: fakePorts(malformedCalls),
        streamFn: oneToolStream("read", { offset: -1 }),
      }),
    );
    await malformed.input({ requestId: "badargs", correlationId: "badargs-corr", kind: "prompt", content: "bad" });
    await eventually(async () => assert.equal((await malformed.state()).runState, "settled"));
    assert.deepEqual(malformedCalls, [], "schema-invalid tool arguments must not reach injected ports");
    await malformed.dispose();

    for (const [name, result] of [
      [
        "cycle",
        (() => {
          const value: Record<string, unknown> = {};
          value.self = value;
          return value;
        })(),
      ],
      ["bigint", { value: 1n }],
      ["accessor", Object.defineProperty({}, "secret", { get: () => secret, enumerable: true })],
      ["oversize", { value: "x".repeat(4096) }],
    ] as const) {
      const calls: string[] = [];
      const events: string[] = [];
      const adapter = await createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, `bad-result-${name}`),
          sessionId: `bad-result-${name}`,
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: secret,
          toolPorts: fakePorts(calls, result),
          streamFn: oneToolStream("read", { path: "/workspace/README.md" }),
          maxToolResultBytes: 512,
          emit: (event) => {
            events.push(JSON.stringify(event));
            return true;
          },
        }),
      );
      await adapter.input({
        requestId: `bad-${name}`,
        correlationId: `bad-${name}-corr`,
        kind: "prompt",
        content: "bad",
      });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.deepEqual(calls, ["read:/workspace/README.md"]);
      const sessionFile = adapter.sessionFile();
      assert.ok(sessionFile);
      assert.equal((await readFile(sessionFile, "utf8")).includes(secret), false);
      assert.equal(events.join("\n").includes(secret), false);
      await adapter.dispose();
    }

    const rejectingEvents: string[] = [];
    const rejecting = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "rejecting-port"),
        sessionId: "rejecting-port",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: {
          ...fakePorts([]),
          read: async () => {
            throw new Error(secret);
          },
        },
        streamFn: oneToolStream("read", { path: "/workspace/README.md" }),
        emit: (event) => {
          rejectingEvents.push(JSON.stringify(event));
          return true;
        },
      }),
    );
    await rejecting.input({ requestId: "rejecting", correlationId: "rejecting-corr", kind: "prompt", content: "bad" });
    await eventually(async () => assert.equal((await rejecting.state()).runState, "settled"));
    const rejectingFile = rejecting.sessionFile();
    assert.ok(rejectingFile);
    const rejectingJsonl = await readFile(rejectingFile, "utf8");
    assert.equal(rejectingJsonl.includes(secret), false);
    assert.equal(rejectingEvents.join("\n").includes(secret), false);
    await rejecting.dispose();

    const straddleEvents: string[] = [];
    const straddle = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "straddle-secret"),
        sessionId: "straddle-secret",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: fakePorts([], { prefix: `${"x".repeat(4090)}${secret}suffix` }),
        streamFn: oneToolStream("read", { path: "/workspace/README.md" }),
        emit: (event) => {
          straddleEvents.push(JSON.stringify(event));
          return true;
        },
      }),
    );
    await straddle.input({ requestId: "straddle", correlationId: "straddle-corr", kind: "prompt", content: "bad" });
    await eventually(async () => assert.equal((await straddle.state()).runState, "settled"));
    const straddleText = straddleEvents.join("\n");
    assert.equal(straddleText.includes(secret), false);
    assert.equal(straddleText.includes(secret.slice(0, 16)), false);
    await straddle.dispose();

    const largeEvents: string[] = [];
    const innocentPrefix = secret.slice(0, 16);
    const large = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "large-redaction"),
        sessionId: "large-redaction",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("unused"),
        emit: (event) => {
          largeEvents.push(JSON.stringify(event));
          return true;
        },
      }),
    );
    (large as unknown as { forwardEvent: (event: { type: string; [key: string]: unknown }) => void }).forwardEvent({
      type: "hostile_large_event",
      text: `${"x".repeat(4090)}${secret}${"y".repeat(2_000_000)}`,
    });
    const largeText = largeEvents.join("\n");
    assert.equal(largeText.includes(secret), false);
    assert.equal(largeText.includes("[redacted]"), true);
    assert.equal(largeText.includes("[truncated]"), true);
    assert.equal(largeText.includes(innocentPrefix), false);
    assert.ok(largeEvents.every((event) => Buffer.byteLength(event, "utf8") < 24 * 1024));
    await large.dispose();
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session queue, abort, timeout, publication failure, and containment fail closed", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-session-race-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const calls: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });

    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: sessionDir,
          sessionId: "session-test",
          model: { provider: "anthropic", id: "missing-model" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /unknown model/,
    );
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: sessionDir,
          sessionId: "session-test",
          model: { provider: "missing-provider", id: "missing-model" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /unknown model/,
    );
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: sessionDir,
          sessionId: "session-test",
          model: { provider: "anthropic", id: "valid launch schema chars before registry lookup" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /unknown model/,
    );
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: sessionDir,
          sessionId: "session-test",
          model: { provider: "anthropic", id: "x".repeat(257) },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /invalid model id/,
    );
    await assertMissing(resolve(sessionDir, "session-test"));
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: sessionDir,
          sessionId: "session-test",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
          maxToolResultBytes: Number.NaN,
        }),
      ),
      /invalid maxToolResultBytes/,
    );

    const aborted = { count: 0 };
    const events: string[] = [];
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: sessionDir,
        sessionId: "session-test",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: hangingStream(aborted),
        emit: (event) => {
          events.push(`${event.kind}:${event.correlation_id}:${event.request_id ?? "none"}`);
          return true;
        },
        operationTimeoutMs: 75,
        abortTimeoutMs: 500,
      }),
    );
    try {
      const session = internalSession(adapter);
      let releaseAbort: (() => void) | undefined;
      session.abort = async () => {
        await new Promise<void>((resolveAbort) => {
          releaseAbort = resolveAbort;
        });
      };
      await adapter.input({ requestId: "root", correlationId: "root-corr", kind: "prompt", content: "hang" });
      await assert.rejects(adapter.navigate("entry-while-running"), /cannot navigate while running/);
      const abortPromise = adapter.abort({ requestId: "abort1", correlationId: "abort-corr" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "aborting"));
      releaseAbort?.();
      await abortPromise;
      assert.deepEqual(
        events.filter((event) => event.startsWith("run_aborted")),
        ["run_aborted:abort-corr:abort1"],
      );
    } finally {
      await adapter.dispose();
    }

    const queueEvents: string[] = [];
    const queueAdapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions-queue"),
        sessionId: "session-queue",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: hangingStream(aborted),
        emit: (event) => {
          queueEvents.push(`${event.kind}:${event.correlation_id}:${event.request_id ?? "none"}`);
          return true;
        },
        operationTimeoutMs: 75,
        abortTimeoutMs: 500,
      }),
    );
    await queueAdapter.input({ requestId: "root2", correlationId: "root-corr2", kind: "prompt", content: "hang" });
    await assert.rejects(
      queueAdapter.input({
        requestId: "badkind",
        correlationId: "badkind-corr",
        kind: "unknown" as never,
        content: "queued",
      }),
      /invalid input kind/,
    );
    await assert.rejects(
      queueAdapter.input({
        requestId: "toolong",
        correlationId: "toolong-corr",
        kind: "steer",
        content: "x".repeat(8193),
      }),
      /invalid input content/,
    );
    await assert.rejects(
      queueAdapter.input({
        requestId: "toobig",
        correlationId: "toobig-corr",
        kind: "steer",
        content: "💣".repeat(4097),
      }),
      /invalid input content/,
    );
    await queueAdapter.input({ requestId: "steer1", correlationId: "steer-corr", kind: "steer", content: "queued" });
    await queueAdapter.input({
      requestId: "follow1",
      correlationId: "follow-corr",
      kind: "follow_up",
      content: "queued",
    });
    await eventually(() => assert.ok(queueEvents.includes("pi_event:steer-corr:steer1")));
    await eventually(() => assert.ok(queueEvents.includes("pi_event:follow-corr:follow1")));
    await eventually(async () => assert.notEqual((await queueAdapter.state()).runState, "running"));
    assert.ok(aborted.count >= 1, "deadline must abort the Pi stream");
    assert.equal(queueEvents.filter((event) => event.startsWith("error:root-corr2:root2")).length, 1);
    assert.equal(
      queueEvents.some((event) => event.startsWith("run_settled:root-corr2:root2")),
      false,
    );
    await queueAdapter.dispose();

    const nonCooperative = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions-noncoop"),
        sessionId: "session-noncoop",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: nonCooperativeStream(),
        emit: () => true,
        operationTimeoutMs: 25,
        abortTimeoutMs: 25,
      }),
    );
    await nonCooperative.input({ requestId: "noncoop", correlationId: "noncoop-corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await nonCooperative.state()).runState, "shutdown"));
    await assert.rejects(
      nonCooperative.input({ requestId: "after-noncoop", correlationId: "corr", kind: "prompt", content: "x" }),
    );
    await nonCooperative.dispose();

    const failing = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions2"),
        sessionId: "session-test-2",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: oneTextStream("ok"),
        emit: () => false,
      }),
    );
    await failing.input({ requestId: "fail", correlationId: "corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await failing.state()).runState, "shutdown"));
    await assert.rejects(failing.input({ requestId: "after", correlationId: "corr", kind: "prompt", content: "x" }));
    await failing.dispose();

    const throwing = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions-throw"),
        sessionId: "session-throw",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: oneTextStream("ok"),
        emit: () => {
          throw new Error("observer failed");
        },
      }),
    );
    await throwing.input({ requestId: "throw", correlationId: "corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await throwing.state()).runState, "shutdown"));
    await throwing.dispose();

    const outside = resolve(temporaryRoot, "outside.jsonl");
    await writeFile(outside, "");
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, "contained"),
          resumeFile: `..${sepForTest()}${basename(outside)}`,
          sessionId: "session-test-3",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /escapes|ENOENT|invalid/,
    );

    const validSource = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "valid-resume"),
        sessionId: "session-resume-source",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: oneTextStream("resume ok"),
      }),
    );
    await validSource.input({
      requestId: "resume-source",
      correlationId: "resume-corr",
      kind: "prompt",
      content: "persist",
    });
    await eventually(async () => assert.equal((await validSource.state()).runState, "settled"));
    const validFile = validSource.sessionFile();
    assert.ok(validFile);
    await validSource.dispose();
    const resumedContexts: string[] = [];
    const resumed = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "valid-resume"),
        resumeFile: basename(validFile),
        sessionId: "session-resume-source",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: (model, context, streamOptions) => {
          resumedContexts.push(JSON.stringify(context));
          return oneTextStream("resumed")(model, context, streamOptions);
        },
      }),
    );
    const resumedEntries = await resumed.entries({ after: undefined, limit: 100 });
    assert.ok(resumedEntries.entries.length > 0);
    await resumed.input({
      requestId: "resume-next",
      correlationId: "resume-next-corr",
      kind: "prompt",
      content: "next",
    });
    await eventually(async () => assert.equal((await resumed.state()).runState, "settled"));
    assert.match(resumedContexts.join("\n"), /persist/);
    const firstEntry = resumedEntries.entries.find((entry) => {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return false;
      return (entry as Record<string, unknown>).type === "message";
    });
    assert.ok(firstEntry && typeof firstEntry === "object" && !Array.isArray(firstEntry));
    const firstEntryId = (firstEntry as Record<string, unknown>).id;
    if (typeof firstEntryId !== "string") throw new Error("missing first entry id");
    await resumed.navigate(firstEntryId);
    const branchContexts: string[] = [];
    const branchFile = resumed.sessionFile();
    assert.ok(branchFile);
    await resumed.dispose();
    const branched = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "valid-resume"),
        resumeFile: basename(branchFile),
        sessionId: "session-resume-source",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: (model, context, streamOptions) => {
          branchContexts.push(JSON.stringify(context));
          return oneTextStream("branched")(model, context, streamOptions);
        },
      }),
    );
    await branched.navigate(firstEntryId);
    await branched.input({
      requestId: "branch-next",
      correlationId: "branch-corr",
      kind: "prompt",
      content: "branch-prompt",
    });
    await eventually(async () => assert.equal((await branched.state()).runState, "settled"));
    assert.match(branchContexts.join("\n"), /branch-prompt/);
    assert.doesNotMatch(branchContexts.join("\n"), /next/);
    await branched.dispose();
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, "valid-resume"),
          resumeFile: basename(validFile),
          sessionId: "session-resume-target",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /ENOENT|invalid/,
    );
    const linkFile = resolve(temporaryRoot, "valid-resume", "session-resume-source", "link.jsonl");
    await symlink(validFile, linkFile);
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, "valid-resume"),
          resumeFile: "link.jsonl",
          sessionId: "session-resume-source",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /invalid resume file/,
    );

    const linkDir = resolve(temporaryRoot, "linkdir");
    await mkdir(resolve(temporaryRoot, "target"), { recursive: true });
    await symlink(resolve(temporaryRoot, "target"), linkDir);
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: linkDir,
          sessionId: "session-test-4",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
        }),
      ),
      /invalid session directory/,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi adapter fatal callback requests lifecycle shutdown and readiness closes", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-fatal-api-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const calls: string[] = [];
  const shutdowns: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let adapter: Awaited<ReturnType<typeof createCogsPiSession>> | undefined;
    const lifecycle = new LaunchLifecycle({
      launchDocument: validLaunch("fatal-session"),
      dependencies: dependencies(shutdowns),
      shutdownTimeoutMs: 1000,
    });
    await lifecycle.start();
    assert.equal(lifecycle.ready, true);
    const api = createApiServer({
      lifecycle,
      bearerToken: "worker-secret-0123456789abcdefghi",
      sessionId: "fatal-session",
      session: {
        input: (input) => adapter?.input(input) ?? Promise.reject(new Error("missing adapter")),
        abort: (input) => adapter?.abort(input) ?? Promise.reject(new Error("missing adapter")),
        state: (input) => adapter?.state(input) ?? Promise.reject(new Error("missing adapter")),
      },
      history: { entries: (input) => adapter?.entries(input) ?? Promise.reject(new Error("missing adapter")) },
      exporter: { createExport: async () => ({ files: [] }) },
    });
    adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "fatal-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: oneTextStream("fatal"),
        emit: () => false,
        onFatal: () => {
          void lifecycle.requestShutdown("pi-fatal");
        },
      }),
    );
    const { port } = await api.listen();
    const base = `http://127.0.0.1:${port}`;
    const accepted = await fetch(`${base}/v1/input`, {
      method: "POST",
      headers: {
        authorization: "Bearer worker-secret-0123456789abcdefghi",
        "content-type": "application/json",
      },
      body: JSON.stringify({ request_id: "fatal", type: "prompt", content: "x" }),
    });
    assert.equal(accepted.status, 202);
    await eventually(async () =>
      assert.equal(
        (
          await fetch(`${base}/health/ready`, {
            headers: { authorization: "Bearer worker-secret-0123456789abcdefghi" },
          })
        ).status,
        503,
      ),
    );
    await adapter.dispose();
    await api.close();
    assert.equal(lifecycle.ready, false);
    assert.deepEqual(shutdowns.sort(), ["auditWal", "auth", "proxy", "sessionStorage", "ssh"].sort());
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi adapter events publish through the actual SSE server schema envelope", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-sse-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const calls: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let adapter: Awaited<ReturnType<typeof createCogsPiSession>> | undefined;
    const lifecycle = { ready: true, state: "ready", requestShutdown: async () => undefined };
    const api = createApiServer({
      lifecycle: lifecycle as never,
      bearerToken: "worker-secret-0123456789abcdefghi",
      sessionId: "session-test",
      session: {
        input: (input) => {
          if (adapter === undefined) throw new Error("missing adapter");
          return adapter.input(input);
        },
        abort: (input) => {
          if (adapter === undefined) throw new Error("missing adapter");
          return adapter.abort(input);
        },
        state: (input) => {
          if (adapter === undefined) throw new Error("missing adapter");
          return adapter.state(input);
        },
      },
      history: {
        entries: (input) => {
          if (adapter === undefined) throw new Error("missing adapter");
          return adapter.entries(input);
        },
      },
      exporter: { createExport: async () => ({ files: [] }) },
    });
    adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: sessionDir,
        sessionId: "session-test",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: createFakeModelStream({ calls: 0, observedApiKeys: [] }),
        emit: api.publish,
      }),
    );
    const { port } = await api.listen();
    try {
      const base = `http://127.0.0.1:${port}`;
      const input = await fetch(`${base}/v1/input`, {
        method: "POST",
        headers: {
          authorization: "Bearer worker-secret-0123456789abcdefghi",
          "content-type": "application/json",
          "x-cogs-correlation-id": "corr-sse",
        },
        body: JSON.stringify({ request_id: "req-sse", type: "prompt", content: "use read" }),
      });
      assert.equal(input.status, 202);
      await eventually(() => assert.ok(calls.length > 0));
      const stream = await fetch(`${base}/v1/events?after=0`, {
        headers: { authorization: "Bearer worker-secret-0123456789abcdefghi" },
      });
      assert.equal(stream.status, 200);
      const reader = stream.body?.getReader();
      assert.ok(reader);
      const chunks: string[] = [];
      let envelopes: Array<Record<string, unknown>> = [];
      for (;;) {
        const read = await reader.read();
        if (read.done) break;
        chunks.push(Buffer.from(read.value).toString("utf8"));
        envelopes = chunks
          .join("")
          .split("\n")
          .filter((candidate) => candidate.startsWith("data: "))
          .map((line) => JSON.parse(line.slice("data: ".length)) as Record<string, unknown>);
        if (envelopes.some((envelope) => envelope.kind === "run_settled")) break;
      }
      await reader.cancel();
      assert.ok(envelopes.length > 0);
      const schema = JSON.parse(
        await readFile(resolve(import.meta.dirname, "../schemas/events-v1alpha1.json"), "utf8"),
      );
      const ajv = new Ajv({ strict: true, allErrors: true });
      addFormats(ajv);
      const validate = ajv.compile(schema);
      let previousSeq = 0;
      for (const envelope of envelopes) {
        assert.equal(validate(envelope), true, JSON.stringify(validate.errors));
        assert.equal(envelope.correlation_id, "corr-sse");
        assert.equal(envelope.request_id, "req-sse");
        assert.equal("type" in envelope, false);
        assert.equal(typeof envelope.seq, "number");
        assert.ok((envelope.seq as number) > previousSeq);
        previousSeq = envelope.seq as number;
        assert.equal(JSON.stringify(envelope).includes("COGS_RUNTIME_ONLY_TEST_KEY"), false);
      }
    } finally {
      await api.close();
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

function sepForTest(): string {
  return process.platform === "win32" ? "\\" : "/";
}

function bashUpdateChunks(events: string[]): {
  stdout: string;
  stderr: string;
  streamCount: number;
  terminalCount: number;
  terminalAfterStreams: boolean;
} {
  const out = { stdout: "", stderr: "", streamCount: 0, terminalCount: 0, terminalAfterStreams: false };
  let sawTerminal = false;
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (typeof value !== "object" || value === null) return;
    const maybe = value as { details?: unknown; content?: unknown };
    if (typeof maybe.details === "object" && maybe.details !== null && Array.isArray(maybe.content)) {
      const details = maybe.details as { cogsTool?: unknown; stream?: unknown; terminal?: unknown };
      const first = maybe.content[0] as { text?: unknown } | undefined;
      if (
        details.cogsTool === "bash" &&
        (details.stream === "stdout" || details.stream === "stderr") &&
        typeof first?.text === "string"
      ) {
        const payload = JSON.parse(first.text) as { stream?: unknown; chunk?: unknown };
        if (payload.stream === details.stream && typeof payload.chunk === "string") {
          assert.equal(sawTerminal, false);
          out[details.stream] += payload.chunk;
          out.streamCount += 1;
        }
      }
      if (details.cogsTool === "bash" && details.terminal === true && typeof first?.text === "string") {
        const payload = JSON.parse(first.text) as { terminal?: unknown };
        if (payload.terminal === true) {
          out.terminalAfterStreams ||= out.streamCount > 0;
          sawTerminal = true;
          out.terminalCount += 1;
        }
      }
    }
    for (const item of Object.values(value)) visit(item);
  };
  for (const event of events) visit(JSON.parse(event));
  return out;
}

test("Pi bash update redaction spans every boundary and rejects malformed updates", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-bash-redact-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const secret = "SPLIT_SECRET_KEY";
  const events: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: sessionDir,
        sessionId: "bash-redact-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        streamFn: oneToolStream("bash", { command: "printf split" }),
        emit: (event) => {
          events.push(JSON.stringify(event));
          return true;
        },
        toolPorts: {
          ...fakePorts([]),
          bash: async (input) => {
            for (let cut = 0; cut <= secret.length; cut++) {
              await input.onUpdate?.({
                content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: secret.slice(0, cut) }) }],
                details: { cogsTool: "bash", stream: "stdout" },
              });
              await input.onUpdate?.({
                content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: secret.slice(cut) }) }],
                details: { cogsTool: "bash", stream: "stdout" },
              });
            }
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stderr", chunk: secret.slice(0, 3) }) }],
              details: { cogsTool: "bash", stream: "stderr" },
            });
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stderr", chunk: `${secret.slice(3)}-err` }) }],
              details: { cogsTool: "bash", stream: "stderr" },
            });
            await input.onUpdate?.({
              content: [
                { type: "text", text: JSON.stringify({ stream: "stdout", chunk: "\u0000".repeat(1024) + secret }) },
              ],
              details: { cogsTool: "bash", stream: "stdout" },
            });
            await input.onUpdate?.({
              content: [
                { type: "text", text: JSON.stringify({ stream: "stdout", chunk: `${secret.slice(0, 5)}innocent` }) },
              ],
              details: { cogsTool: "bash", stream: "stdout" },
            });
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ terminal: true, exitCode: 0, signal: null }) }],
              details: { cogsTool: "bash", terminal: true },
            });
            return { ok: true, stdout: "", stderr: "", exitCode: 0 };
          },
        },
        maxToolResultBytes: 8192,
      }),
    );
    try {
      await adapter.input({ requestId: "split", correlationId: "split-corr", kind: "prompt", content: "split" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const eventText = events.join("\n");
      assert.equal(eventText.includes(secret), false);
      const chunks = bashUpdateChunks(events);
      assert.equal(chunks.stdout.includes(secret), false);
      assert.equal(chunks.stderr.includes(secret), false);
      assert.match(chunks.stdout, /\[REDACTED\]/);
      assert.match(chunks.stderr, /\[REDACTED\]-err/);
      assert.equal(chunks.stdout.includes(`${secret.slice(0, 5)}innocent`), true);
      assert.ok(chunks.streamCount > 0);
      assert.equal(chunks.terminalCount, 1);
      assert.equal(chunks.terminalAfterStreams, true);
      assert.ok(events.every((event) => Buffer.byteLength(event, "utf8") <= 8192));
      assert.equal((await readFile(adapter.sessionFile() ?? "", "utf8")).includes(secret), false);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }

  const badRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-bash-badupdate-"));
  try {
    const badCwd = resolve(badRoot, "workspace");
    const badAgent = resolve(badRoot, "agent");
    await mkdir(badCwd, { recursive: true });
    await mkdir(badAgent, { recursive: true });
    const bad = await createCogsPiSession(
      withDefaults({
        cwd: badCwd,
        agentDir: badAgent,
        sessionRoot: resolve(badRoot, "sessions"),
        sessionId: "bad-update",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        streamFn: oneToolStream("bash", { command: "bad" }),
        toolPorts: {
          ...fakePorts([]),
          bash: async (input) => {
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: "abc" }) }],
              details: { cogsTool: "bash", stream: "stdout" },
            });
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: "oops" }) }],
              details: { cogsTool: "not-bash", stream: "stdout" },
            });
            return { ok: true };
          },
        },
      }),
    );
    try {
      await bad.input({ requestId: "bad", correlationId: "bad-corr", kind: "prompt", content: "bad" });
      await eventually(async () => assert.equal((await bad.state()).runState, "settled"));
      const entries = await bad.entries({ after: undefined, limit: 10 });
      assert.ok(JSON.stringify(entries).includes("tool failed"));
    } finally {
      await bad.dispose();
    }
  } finally {
    await rm(badRoot, { recursive: true, force: true });
  }
});

test("Pi bash update redaction flushes max-length held tail in bounded pieces", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-bash-maxkey-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const secret = "K".repeat(8192);
  const events: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: sessionDir,
        sessionId: "bash-maxkey-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        streamFn: oneToolStream("bash", { command: "printf max" }),
        emit: (event) => {
          events.push(JSON.stringify(event));
          return true;
        },
        toolPorts: {
          ...fakePorts([]),
          bash: async (input) => {
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: secret.slice(0, 4096) }) }],
              details: { cogsTool: "bash", stream: "stdout" },
            });
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: secret.slice(4096, 8191) }) }],
              details: { cogsTool: "bash", stream: "stdout" },
            });
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ terminal: true, exitCode: 0, signal: null }) }],
              details: { cogsTool: "bash", terminal: true },
            });
            return { ok: true, stdout: "", stderr: "", exitCode: 0 };
          },
        },
        maxToolResultBytes: 4096,
      }),
    );
    try {
      await adapter.input({ requestId: "maxkey", correlationId: "maxkey-corr", kind: "prompt", content: "max" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const chunks = bashUpdateChunks(events);
      assert.equal(chunks.stdout, secret.slice(0, 8191));
      assert.equal(chunks.streamCount > 1, true);
      assert.equal(chunks.terminalCount, 1);
      assert.equal(chunks.terminalAfterStreams, true);
      assert.ok(
        events.every((event) => {
          assert.ok(Buffer.byteLength(event, "utf8") <= 4096);
          JSON.stringify(JSON.parse(event));
          return true;
        }),
      );
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi bash terminal updates reject malformed terminal unions and emitted update floods", async () => {
  const malformedTerminals = [
    { terminal: true, exitCode: 0, signal: "SIGTERM" },
    { terminal: true, exitCode: null, signal: null },
    { terminal: true, exitCode: null, signal: "SIGWAT" },
    { terminal: true, exitCode: 256, signal: null },
    { terminal: true, exitCode: 1.5, signal: null },
    { terminal: true, exitCode: 0, signal: null, description: "extra" },
    { terminal: false, exitCode: 0, signal: null },
  ];
  for (const [index, terminal] of malformedTerminals.entries()) {
    const root = await mkdtemp(resolve(tmpdir(), `cogs-pi-bash-badterminal-${index}-`));
    try {
      const cwd = resolve(root, "workspace");
      const agentDir = resolve(root, "agent");
      await mkdir(cwd, { recursive: true });
      await mkdir(agentDir, { recursive: true });
      const adapter = await createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(root, "sessions"),
          sessionId: `bad-terminal-${index}`,
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "BAD_TERMINAL_SECRET",
          streamFn: oneToolStream("bash", { command: "bad-terminal" }),
          toolPorts: {
            ...fakePorts([]),
            bash: async (input) => {
              await input.onUpdate?.({
                content: [{ type: "text", text: JSON.stringify(terminal) }],
                details: { cogsTool: "bash", terminal: true },
              });
              return { ok: true };
            },
          },
        }),
      );
      try {
        await adapter.input({
          requestId: `bad-terminal-${index}`,
          correlationId: `bad-terminal-${index}`,
          kind: "prompt",
          content: "bad",
        });
        await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
        assert.ok(JSON.stringify(await adapter.entries({ after: undefined, limit: 10 })).includes("tool failed"));
      } finally {
        await adapter.dispose();
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-bash-update-flood-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(root, "sessions"),
        sessionId: "update-flood",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "ZZZZZZZZ",
        streamFn: oneToolStream("bash", { command: "flood" }),
        toolPorts: {
          ...fakePorts([]),
          bash: async (input) => {
            for (let index = 0; index < 2049; index++) {
              await input.onUpdate?.({
                content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: "aaaaaaaa" }) }],
                details: { cogsTool: "bash", stream: "stdout" },
              });
            }
            return { ok: true };
          },
        },
      }),
    );
    try {
      await adapter.input({ requestId: "flood", correlationId: "flood", kind: "prompt", content: "flood" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.ok(JSON.stringify(await adapter.entries({ after: undefined, limit: 10 })).includes("tool failed"));
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi bash low-budget astral stream is preserved or rejected, never silently omitted", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-bash-emoji-low-budget-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const events: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "emoji-low-budget",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "EMOJIKEY",
        streamFn: oneToolStream("bash", { command: "emoji" }),
        emit: (event) => {
          events.push(JSON.stringify(event));
          return true;
        },
        toolPorts: {
          ...fakePorts([]),
          bash: async (input) => {
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ stream: "stdout", chunk: "😀" }) }],
              details: { cogsTool: "bash", stream: "stdout" },
            });
            await input.onUpdate?.({
              content: [{ type: "text", text: JSON.stringify({ terminal: true, exitCode: 0, signal: null }) }],
              details: { cogsTool: "bash", terminal: true },
            });
            return { ok: true, stdout: "", stderr: "", exitCode: 0 };
          },
        },
        maxToolResultBytes: 128,
      }),
    );
    try {
      await adapter.input({ requestId: "emoji", correlationId: "emoji-corr", kind: "prompt", content: "emoji" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const failed = JSON.stringify(await adapter.entries({ after: undefined, limit: 10 })).includes("tool failed");
      const chunks = bashUpdateChunks(events);
      if (failed) {
        assert.equal(chunks.stdout, "");
      } else {
        assert.equal(chunks.stdout, "😀");
        assert.equal(chunks.terminalCount, 1);
        assert.equal(chunks.terminalAfterStreams, true);
      }
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

class TestModelApiKeySource implements ModelApiKeySource {
  public calls = 0;
  public observedReturn: unknown = "unset";
  public lastRequest: unknown;
  public constructor(
    private readonly apiKey: string,
    private readonly options: {
      throwBefore?: boolean;
      duplicate?: boolean;
      missing?: boolean;
      expectHandle?: string;
    } = {},
  ) {}
  public async withApiKey(
    request: Parameters<ModelApiKeySource["withApiKey"]>[0],
    operation: (apiKey: string) => Promise<void>,
  ): Promise<void> {
    this.calls += 1;
    this.lastRequest = request;
    if (request.signal?.aborted) throw new Error(`${this.apiKey} aborted`);
    if (this.options.throwBefore) throw new Error(`${this.apiKey} source failed`);
    if (this.options.expectHandle !== undefined && request.credentialHandle !== this.options.expectHandle) {
      throw new Error(`${this.apiKey} bad handle`);
    }
    if (this.options.missing) return;
    this.observedReturn = await operation(this.apiKey);
    if (this.options.duplicate) await operation(this.apiKey);
  }
}

function authOptions(
  root: string,
  source: ModelApiKeySource,
  overrides: Partial<Parameters<typeof createAuthenticatedCogsPiSession>[0]> = {},
) {
  const cwd = resolve(root, "workspace");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  return {
    cwd,
    agentDir,
    sessionRoot,
    launchDocument: validLaunch("auth-session"),
    toolPorts: fakePorts([]),
    modelApiKeys: source,
    emit: () => true,
    onFatal: () => undefined,
    ...overrides,
  };
}

test("authenticated Pi session derives model auth from launch and performs runtime model call", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-auth-success-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const secret = "aaaaaaaa";
    const source = new TestModelApiKeySource(secret);
    const events: string[] = [];
    let seenApiKey = "";
    const delegate = oneToolStream("read", { path: "/workspace/README.md" });
    const adapter = await createAuthenticatedCogsPiSession(
      authOptions(root, source, {
        emit: (event) => {
          events.push(JSON.stringify(event));
          return true;
        },
        streamFn: (model, context, options) => {
          assert.ok(options?.apiKey);
          seenApiKey = options.apiKey;
          return delegate(model, context, options);
        },
      }),
    );
    try {
      await adapter.input({ requestId: "auth", correlationId: "auth-corr", kind: "prompt", content: "auth" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.equal(seenApiKey, secret);
      assert.equal(source.calls, 1);
      assert.deepEqual(source.lastRequest, {
        userId: "user-1",
        provider: "anthropic",
        model: "claude-sonnet-4-5",
        credentialHandle: "users/user-1/model",
      });
      assert.equal(source.observedReturn, undefined);
      const sessionFile = adapter.sessionFile() ?? "";
      const sessionText = await readFile(sessionFile, "utf8");
      assert.equal(sessionText.includes(secret), false);
      assert.equal(events.join("\n").includes(secret), false);
      const historyText = JSON.stringify(await adapter.entries({ after: undefined, limit: 20 }));
      assert.equal(historyText.includes(secret), false);
      await adapter.dispose();
      assert.equal((await readFile(sessionFile, "utf8")).includes(secret), false);
      assert.equal(events.join("\n").includes(secret), false);
      assert.equal(historyText.includes(secret), false);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("authenticated Pi session auth failures create no session and leak no key", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-auth-fail-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const secret = "aaaaaaaa";
    for (const source of [
      new TestModelApiKeySource(secret, { throwBefore: true }),
      new TestModelApiKeySource(secret, { duplicate: true }),
      new TestModelApiKeySource(secret, { missing: true }),
      new TestModelApiKeySource(secret, { expectHandle: "users/user-1/other" }),
      new TestModelApiKeySource("bad\nkey"),
    ]) {
      let modelCalls = 0;
      await assert.rejects(
        createAuthenticatedCogsPiSession(
          authOptions(root, source, {
            streamFn: () => {
              modelCalls += 1;
              return createAssistantMessageEventStream();
            },
          }),
        ),
        (error) => {
          const text = String(error);
          assert.equal(text.includes(secret), false);
          assert.equal(text.includes("bad\nkey"), false);
          assert.equal(
            (error as { code?: unknown }).code === "COGS_MODEL_AUTH_FAILED" || text.includes("invalid"),
            true,
          );
          return true;
        },
      );
      assert.equal(modelCalls, 0);
    }
    await assert.rejects(
      createAuthenticatedCogsPiSession(
        authOptions(root, new TestModelApiKeySource(secret), { launchDocument: { bad: true } }),
      ),
    );
    await assertMissing(resolve(root, "sessions/auth-session.jsonl"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("authenticated Pi session respects abort before resolution and unknown models create no session", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-auth-abort-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const controller = new AbortController();
    controller.abort();
    const source = new TestModelApiKeySource("aaaaaaaa");
    await assert.rejects(createAuthenticatedCogsPiSession(authOptions(root, source, { signal: controller.signal })));
    assert.equal(source.calls, 1);

    const unknownModelLaunch = validLaunch("unknown-model-session") as Record<string, unknown>;
    unknownModelLaunch.model = { provider: "anthropic", id: "unknown-model", credential_handle: "users/user-1/model" };
    await assert.rejects(
      createAuthenticatedCogsPiSession(
        authOptions(root, new TestModelApiKeySource("aaaaaaaa"), { launchDocument: unknownModelLaunch }),
      ),
    );
    await assertMissing(resolve(root, "sessions/unknown-model-session.jsonl"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
