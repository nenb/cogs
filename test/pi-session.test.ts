import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  chmod,
  cp,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { AssistantMessage } from "@earendil-works/pi-ai/compat";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import type { Ajv as AjvCore } from "ajv";
import { createFakeModelStream } from "../spikes/pi-embedding.ts";
import { createApiServer } from "../src/api/server.ts";
import type { ModelApiKeySource } from "../src/auth/model-auth.ts";
import { type LaunchDependency, LaunchLifecycle } from "../src/launch/lifecycle.ts";
import { createCogsPiOwnedRuntimeTracker, type InternalCogsPiOwnedMarker } from "../src/pi/owned-runtime.ts";
import {
  COGS_PI_TOOL_NAMES,
  type CogsPiSessionOptions,
  type CogsToolPorts,
  createAuthenticatedCogsPiSession,
  createCogsPiSession,
} from "../src/pi/session.ts";
import type { CogsGitCheckpointer } from "../src/session/git-checkpoint.ts";
import type { CogsGitMapRecord } from "../src/session/git-map.ts";
import type { CogsGitObservation, CogsGitObserver } from "../src/session/git-observer.ts";
import type { CogsPreparedSkills, CogsSkillPreparerPort } from "../src/skills/session-preparer.ts";

const execFileAsync = promisify(execFile);
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
  options: Omit<CogsPiSessionOptions, "userId" | "emit" | "onFatal"> &
    Partial<Pick<CogsPiSessionOptions, "userId" | "emit" | "onFatal">>,
): CogsPiSessionOptions {
  return { userId: "user-1", emit: () => true, onFatal: () => undefined, ...options };
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
  return (["sessionStorage", "ssh", "proxy", "auth", "auditWal", "egressRuntime"] as const).map((name) => ({
    name,
    start: async () => undefined,
    shutdown: async () => {
      shutdowns.push(name);
    },
  }));
}

function pausedObserver(state: { started: boolean; aborted: boolean; calls?: number }): CogsGitObserver {
  return Object.freeze({
    observeHead: async (input: { readonly signal?: AbortSignal } = {}): Promise<CogsGitObservation> => {
      state.calls = (state.calls ?? 0) + 1;
      if (state.calls <= 2)
        return Object.freeze({
          kind: "observed" as const,
          repo: "workspace-1",
          commit: "a".repeat(40),
          observed_at: "2026-07-17T00:00:00.000Z",
        });
      state.started = true;
      return new Promise((_resolve, reject) => {
        const abort = () => {
          state.aborted = true;
          reject(new Error("aborted"));
        };
        if (input.signal?.aborted) return abort();
        input.signal?.addEventListener("abort", abort, { once: true });
      });
    },
    nearestAncestor: async () => null,
    appendNote: async () => true,
    dispose: async () => undefined,
  });
}

function fakeObserver(commits: readonly string[], notes: CogsGitMapRecord[] = []): CogsGitObserver {
  let index = 0;
  return Object.freeze({
    observeHead: async (): Promise<CogsGitObservation> => {
      const commit = commits[Math.min(index, commits.length - 1)];
      index += 1;
      return commit === undefined
        ? Object.freeze({ kind: "unavailable" as const })
        : Object.freeze({
            kind: "observed" as const,
            repo: "workspace-1",
            commit,
            observed_at: "2026-07-17T00:00:00.000Z",
          });
    },
    nearestAncestor: async (input: { readonly candidates: readonly string[] }) => input.candidates[0] ?? null,
    appendNote: async (record: CogsGitMapRecord) => {
      notes.push(record);
      return true;
    },
    dispose: async () => undefined,
  });
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

function textStream(text = "done"): StreamFn {
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
      assert.equal((await lstat(sessionFile)).mode & 0o777, 0o600);
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

test("Pi session secures owned native resume JSONL before opening", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-secure-resume-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    const sessionId = "secure-resume-session";
    const sessionDir = resolve(sessionRoot, sessionId);
    const resumeFile = "resume.jsonl";
    const sessionFile = resolve(sessionDir, resumeFile);
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await mkdir(sessionDir, { recursive: true });
    await writeFile(
      sessionFile,
      `${JSON.stringify({ type: "session", version: 3, id: "native-resume", timestamp: new Date(0).toISOString(), cwd })}\n`,
      { mode: 0o644 },
    );
    await chmod(sessionFile, 0o644);
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId,
        resumeFile,
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "aaaaaaaa",
        toolPorts: fakePorts([]),
        streamFn: textStream(),
      }),
    );
    try {
      assert.equal(adapter.sessionFile(), await realpath(sessionFile));
      assert.equal((await lstat(sessionFile)).mode & 0o777, 0o600);
      assert.equal(SessionManager.open(sessionFile, sessionDir, cwd).getHeader()?.id, "native-resume");
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session rejects linked native resume JSONL before opening", async () => {
  for (const kind of ["symlink", "hardlink"] as const) {
    const root = await mkdtemp(resolve(tmpdir(), `cogs-pi-linked-resume-${kind}-`));
    try {
      const cwd = resolve(root, "workspace");
      const agentDir = resolve(root, "agent");
      const sessionRoot = resolve(root, "sessions");
      const sessionId = "linked-resume-session";
      const sessionDir = resolve(sessionRoot, sessionId);
      const resumeFile = "resume.jsonl";
      const sessionFile = resolve(sessionDir, resumeFile);
      await mkdir(cwd, { recursive: true });
      await mkdir(agentDir, { recursive: true });
      await mkdir(sessionDir, { recursive: true });
      await writeFile(
        sessionFile,
        `${JSON.stringify({ type: "session", version: 3, id: "native-resume", timestamp: new Date(0).toISOString(), cwd })}\n`,
        { mode: 0o600 },
      );
      if (kind === "symlink") {
        await unlink(sessionFile);
        await symlink(resolve(root, "outside.jsonl"), sessionFile);
      } else {
        await link(sessionFile, resolve(sessionDir, "other.jsonl"));
      }
      await assert.rejects(
        createCogsPiSession(
          withDefaults({
            cwd,
            agentDir,
            sessionRoot,
            sessionId,
            resumeFile,
            model: { provider: "anthropic", id: "claude-sonnet-4-5" },
            apiKey: "aaaaaaaa",
            toolPorts: fakePorts([]),
            streamFn: textStream(),
          }),
        ),
        /invalid session file/,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
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
  const policyInputs: unknown[] = [];
  const policyAuthorizer = Object.freeze((input: unknown) => {
    policyInputs.push(input);
    return Object.freeze({
      version: "cogs.policy-decision/v1alpha1" as const,
      decision_id: `sha256:${"a".repeat(64)}` as const,
      allow: true,
      reason: "allowed" as const,
    });
  });
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
        policyAuthorizer,
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
      assert.equal(JSON.stringify(policyInputs).includes("/workspace/README.md"), false);
      assert.equal(JSON.stringify(policyInputs).includes("printf ok"), false);
      assert.deepEqual(
        policyInputs.filter((input) => (input as { action?: unknown }).action === "tool.dispatch"),
        [
          {
            version: "cogs.policy/v1alpha1",
            action: "tool.dispatch",
            user: "user-1",
            session: "tool-session",
            resource: "read",
            attributes: { tool: "read", path_class: "workspace" },
          },
          {
            version: "cogs.policy/v1alpha1",
            action: "tool.dispatch",
            user: "user-1",
            session: "tool-session",
            resource: "write",
            attributes: { tool: "write", path_class: "workspace" },
          },
          {
            version: "cogs.policy/v1alpha1",
            action: "tool.dispatch",
            user: "user-1",
            session: "tool-session",
            resource: "edit",
            attributes: { tool: "edit", path_class: "workspace" },
          },
          {
            version: "cogs.policy/v1alpha1",
            action: "tool.dispatch",
            user: "user-1",
            session: "tool-session",
            resource: "bash",
            attributes: { tool: "bash" },
          },
        ],
      );
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

test("Pi session Git observer maps user, tool, and settle boundaries only after durable sidecar append", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-git-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const calls: string[] = [];
  const events: Array<{ kind: string; payload: Record<string, unknown> }> = [];
  const commits = ["a".repeat(40), "b".repeat(40), "c".repeat(40)] as const;
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "git-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts(calls),
        streamFn: oneToolStream("read", { path: "/workspace/README.md" }),
        git: { repositoryId: "workspace-1", observer: fakeObserver(commits), enableNotes: true },
        emit: (event) => {
          events.push({ kind: event.kind, payload: event.payload as Record<string, unknown> });
          return true;
        },
      }),
    );
    try {
      await adapter.input({ requestId: "git", correlationId: "git-corr", kind: "prompt", content: "git" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const mappings = adapter.gitMapRecords();
      assert.equal(mappings.length, 3);
      assert.deepEqual(
        mappings.map((record) => record.commit),
        commits,
      );
      assert.deepEqual(
        events.filter((event) => event.kind === "git_mapping").map((event) => event.payload.boundary),
        ["user", "tool", "settle"],
      );
      const gitEvents = events.filter((event) => event.kind === "git_mapping" || event.kind === "warning");
      assert.equal(
        gitEvents.some((event) => JSON.stringify(event).includes("/workspace")),
        false,
      );
      assert.equal(
        gitEvents.some((event) => JSON.stringify(event).includes("README")),
        false,
      );
      assert.equal(
        events.findIndex((event) => event.kind === "git_mapping") <
          events.findIndex((event) => event.kind === "run_settled"),
        true,
      );
      assert.equal((await adapter.resolveGitMapping({ repo: "workspace-1", commit: commits[1] }))?.kind, "mapped");
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session Git observer captures failed tool operation once", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-git-tool-error-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "git-tool-error",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: {
          ...fakePorts([]),
          read: async () => {
            throw new Error("raw read failure");
          },
        },
        streamFn: oneToolStream("read", { path: "/workspace/README.md" }),
        git: { repositoryId: "workspace-1", observer: fakeObserver(["a".repeat(40), "b".repeat(40), "c".repeat(40)]) },
      }),
    );
    try {
      await adapter.input({ requestId: "git-tool", correlationId: "git-tool", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.equal(adapter.gitMapRecords().filter((record) => record.commit === "b".repeat(40)).length, 1);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session policy path denial blocks ports and still records failed tool boundary once", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-policy-path-deny-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const calls: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    for (const [tool, args] of [
      ["read", { path: "../secret" }],
      ["write", { path: "/shared/skills/file", content: "x" }],
      ["edit", { path: "/user/skills/file", oldText: "x", newText: "y" }],
    ] as const) {
      calls.length = 0;
      const adapter = await createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, `sessions-${tool}`),
          sessionId: `policy-path-${tool}`,
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts(calls),
          streamFn: oneToolStream(tool, args),
          git: {
            repositoryId: "workspace-1",
            observer: fakeObserver(["a".repeat(40), "b".repeat(40), "c".repeat(40)]),
          },
        }),
      );
      try {
        await adapter.input({
          requestId: `path-${tool}`,
          correlationId: `path-${tool}`,
          kind: "prompt",
          content: "go",
        });
        await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
        assert.deepEqual(calls, []);
        assert.equal(adapter.gitMapRecords().filter((record) => record.commit === "b".repeat(40)).length, 1);
      } finally {
        await adapter.dispose();
      }
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session Git observer failures are warnings and note failures are nonfatal", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-git-hostile-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const events: Array<{ kind: string; payload: Record<string, unknown> }> = [];
  let noteAttempts = 0;
  const observer: CogsGitObserver = Object.freeze({
    observeHead: async () =>
      Object.freeze({
        kind: "observed" as const,
        repo: "workspace-1",
        commit: "d".repeat(40),
        observed_at: "2026-07-17T00:00:00.000Z",
      }),
    nearestAncestor: async () => null,
    appendNote: async () => {
      noteAttempts += 1;
      throw new Error("raw note failure");
    },
    dispose: async () => undefined,
  });
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "git-hostile-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: { repositoryId: "workspace-1", observer },
        emit: (event) => {
          events.push({ kind: event.kind, payload: event.payload as Record<string, unknown> });
          return true;
        },
      }),
    );
    try {
      await adapter.input({ requestId: "git-note", correlationId: "git-note", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.ok(noteAttempts > 0, "notes are attempted by default");
      assert.ok(events.some((event) => event.kind === "warning" && event.payload.code === "git-note-unavailable"));
      assert.ok(events.some((event) => event.kind === "run_settled"));
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session enabled checkpoint publishes only after exact map and durable sidecar", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-checkpoint-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const notes: CogsGitMapRecord[] = [];
  const events: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const checkpointer = Object.freeze({
      checkpoint: async (input: Parameters<CogsGitCheckpointer["checkpoint"]>[0]) =>
        Object.freeze({
          repo: input.repo,
          session: input.session,
          entry: input.entry,
          turn: input.turn,
          commit: "9".repeat(40),
          checkpoint_ref: `refs/cogs/sessions/${input.session}/${input.turn}`,
          observed_at: input.observed_at,
          file_count: 1,
          total_bytes: 4,
          duration_ms: 3,
        }),
      dispose: async () => undefined,
    });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "checkpoint-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: {
          repositoryId: "workspace-1",
          observer: fakeObserver(["1".repeat(40), "2".repeat(40)], notes),
          checkpointer,
        },
        emit: (event) => {
          if (event.kind === "git_mapping" || event.kind === "checkpoint") events.push(event.kind);
          return true;
        },
      }),
    );
    try {
      await adapter.input({ requestId: "checkpoint", correlationId: "checkpoint", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.deepEqual(events, ["git_mapping", "git_mapping", "checkpoint"]);
      assert.equal(adapter.gitMapRecords().at(-1)?.confidence, "checkpoint");
      assert.equal(notes.at(-1)?.confidence, "checkpoint");
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session disabled or failed checkpoint is nonfatal and never fabricates checkpoint events", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-checkpoint-fail-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let checkpointCalls = 0;
    const disabled = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "disabled"),
        sessionId: "disabled-checkpoint",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: { repositoryId: "workspace-1", observer: fakeObserver(["3".repeat(40), "4".repeat(40)]) },
        emit: (event) => event.kind !== "checkpoint",
      }),
    );
    await disabled.input({ requestId: "disabled", correlationId: "disabled", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await disabled.state()).runState, "settled"));
    assert.equal(
      disabled.gitMapRecords().some((record) => record.confidence === "checkpoint"),
      false,
    );
    await disabled.dispose();

    const failedEvents: string[] = [];
    const failing = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "failed"),
        sessionId: "failed-checkpoint",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: {
          repositoryId: "workspace-1",
          observer: fakeObserver(["5".repeat(40), "6".repeat(40)]),
          checkpointer: Object.freeze({
            checkpoint: async () => {
              checkpointCalls += 1;
              throw new Error("raw checkpoint failure");
            },
            dispose: async () => undefined,
          }),
        },
        emit: (event) => {
          failedEvents.push(event.kind);
          return true;
        },
      }),
    );
    await failing.input({ requestId: "failed", correlationId: "failed", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await failing.state()).runState, "settled"));
    assert.equal(checkpointCalls, 1);
    assert.equal(
      failing.gitMapRecords().some((record) => record.confidence === "checkpoint"),
      false,
    );
    assert.ok(failedEvents.includes("warning"));
    assert.equal(failedEvents.includes("checkpoint"), false);
    await failing.dispose();
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session hanging or forged checkpoint warns without checkpoint claim", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-checkpoint-hostile-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    for (const checkpointer of [
      Object.freeze({ checkpoint: () => new Promise(() => undefined), dispose: async () => undefined }),
      Object.freeze({
        checkpoint: async () =>
          Object.freeze({
            repo: "other",
            session: "bad",
            entry: "00000000",
            turn: 999,
            commit: "b".repeat(40),
            checkpoint_ref: "refs/cogs/sessions/bad/999",
            observed_at: "2026-07-17T00:00:00.000Z",
            file_count: 1,
            total_bytes: 1,
            duration_ms: 1,
          }),
        dispose: async () => undefined,
      }),
    ] as CogsGitCheckpointer[]) {
      const events: string[] = [];
      const adapter = await createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, `sessions-${events.length}-${Date.now()}`),
          sessionId: `hostile-checkpoint-${events.length}-${Date.now()}`,
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts([]),
          streamFn: oneTextStream("done"),
          git: { repositoryId: "workspace-1", observer: fakeObserver(["b".repeat(40), "c".repeat(40)]), checkpointer },
          emit: (event) => {
            events.push(event.kind);
            return true;
          },
        }),
      );
      await adapter.input({ requestId: "hostile", correlationId: "hostile", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.ok(events.includes("warning"));
      assert.equal(events.includes("checkpoint"), false);
      assert.equal(
        adapter.gitMapRecords().some((record) => record.confidence === "checkpoint"),
        false,
      );
      await adapter.dispose();
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session checkpoint event publication failure shuts down", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-checkpoint-emit-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "sessions"),
        sessionId: "checkpoint-emit",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: {
          repositoryId: "workspace-1",
          observer: fakeObserver(["7".repeat(40), "8".repeat(40)]),
          checkpointer: Object.freeze({
            checkpoint: async (input: Parameters<CogsGitCheckpointer["checkpoint"]>[0]) =>
              Object.freeze({
                repo: input.repo,
                session: input.session,
                entry: input.entry,
                turn: input.turn,
                commit: "a".repeat(40),
                checkpoint_ref: `refs/cogs/sessions/${input.session}/${input.turn}`,
                observed_at: input.observed_at,
                file_count: 1,
                total_bytes: 1,
                duration_ms: 1,
              }),
            dispose: async () => undefined,
          }),
        },
        emit: (event) => event.kind !== "checkpoint",
      }),
    );
    await adapter.input({ requestId: "emit", correlationId: "emit", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "shutdown"));
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("Pi session bounds hanging Git notes and resolver ancestor lookups", async () => {
  const noteRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-git-hanging-note-"));
  try {
    const cwd = resolve(noteRoot, "workspace");
    const agentDir = resolve(noteRoot, "agent");
    const events: Array<{ kind: string; payload: Record<string, unknown> }> = [];
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let noteAttempts = 0;
    const observer: CogsGitObserver = Object.freeze({
      observeHead: async () =>
        Object.freeze({
          kind: "observed" as const,
          repo: "workspace-1",
          commit: "f".repeat(40),
          observed_at: "2026-07-17T00:00:00.000Z",
        }),
      nearestAncestor: async () => null,
      appendNote: () => {
        noteAttempts += 1;
        return noteAttempts === 1 ? new Promise<boolean>(() => undefined) : Promise.resolve(false);
      },
      dispose: async () => undefined,
    });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(noteRoot, "sessions"),
        sessionId: "git-hanging-note",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: { repositoryId: "workspace-1", observer },
        emit: (event) => {
          events.push({ kind: event.kind, payload: event.payload as Record<string, unknown> });
          return true;
        },
      }),
    );
    try {
      await adapter.input({ requestId: "hanging-note", correlationId: "hanging-note", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.ok(events.some((event) => event.kind === "warning" && event.payload.code === "git-note-unavailable"));
      assert.ok(events.some((event) => event.kind === "run_settled"));
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(noteRoot, { recursive: true, force: true });
  }

  const resolveRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-git-hanging-resolve-"));
  try {
    const cwd = resolve(resolveRoot, "workspace");
    const agentDir = resolve(resolveRoot, "agent");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(resolveRoot, "sessions"),
        sessionId: "git-hanging-resolve",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: {
          repositoryId: "workspace-1",
          observer: Object.freeze({
            ...fakeObserver(["1".repeat(40)]),
            nearestAncestor: () => new Promise<string | null>(() => undefined),
          }),
        },
      }),
    );
    try {
      await adapter.input({
        requestId: "hanging-resolve",
        correlationId: "hanging-resolve",
        kind: "prompt",
        content: "go",
      });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const started = Date.now();
      const resolved = await adapter.resolveGitMapping({ repo: "workspace-1", commit: "2".repeat(40) });
      assert.equal(resolved?.kind, "unavailable");
      assert.ok(Date.now() - started < 3500);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(resolveRoot, { recursive: true, force: true });
  }
});

test("Pi session rejects malformed Git options before sidecar and git event publication failure shuts down", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-git-options-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const cyclic = new Proxy(
      { repositoryId: "workspace-1", manager: {} },
      { getPrototypeOf: (target) => target },
    ) as NonNullable<CogsPiSessionOptions["git"]>;
    await assert.rejects(() =>
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(temporaryRoot, "bad"),
          sessionId: "bad-git",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts([]),
          git: cyclic,
        }),
      ),
    );
    await assert.rejects(readFile(resolve(temporaryRoot, "bad/bad-git/git-map.jsonl"), "utf8"), { code: "ENOENT" });

    const observer = fakeObserver(["e".repeat(40)]);
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot: resolve(temporaryRoot, "publish"),
        sessionId: "publish-git",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("done"),
        git: { repositoryId: "workspace-1", observer },
        emit: (event) => event.kind !== "git_mapping",
      }),
    );
    await adapter.input({ requestId: "pub", correlationId: "pub", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "shutdown"));
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
          events.push(
            `${event.kind}:${event.correlation_id}:${event.request_id ?? "none"}:${event.payload.abort_correlation_id ?? "none"}:${event.payload.abort_request_id ?? "none"}`,
          );
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
        ["run_aborted:root-corr:root:abort-corr:abort1"],
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
      /invalid/,
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
    assert.deepEqual(shutdowns.sort(), ["auditWal", "auth", "egressRuntime", "proxy", "sessionStorage", "ssh"].sort());
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

function emptySkillPreparer(): CogsSkillPreparerPort {
  return Object.freeze({
    prepare: async () =>
      Object.freeze({
        piSkills: Object.freeze([]),
        eagerTrustedSkillPrompt: "",
        agentsFiles: Object.freeze([]),
        metadata: Object.freeze({
          shared: Object.freeze({
            scope: "shared",
            revision: `sha256:${"a".repeat(64)}`,
            bundleDigest: `sha256:${"a".repeat(64)}`,
            guestRoot: "/shared/skills",
            guestSubtree: `/shared/skills/${"a".repeat(64)}`,
            fileCount: 0,
            byteCount: 0,
            readOnlyEnforced: false,
          }),
          user: Object.freeze({
            scope: "user",
            revision: `sha256:${"a".repeat(64)}`,
            bundleDigest: `sha256:${"a".repeat(64)}`,
            guestRoot: "/user/skills",
            guestSubtree: `/user/skills/${"a".repeat(64)}`,
            fileCount: 0,
            byteCount: 0,
            readOnlyEnforced: false,
          }),
          agentsStatus: "missing",
          skillCount: 0,
        }),
        dispose: async () => undefined,
      }),
  });
}

function hostilePrepared(overrides: Record<string, unknown> = {}): CogsPreparedSkills {
  const sharedHex = "a".repeat(64);
  const userHex = "b".repeat(64);
  return Object.freeze({
    piSkills: Object.freeze([
      Object.freeze({
        name: "safe-skill",
        description: "safe description",
        filePath: `/shared/skills/${sharedHex}/SKILL.md`,
        baseDir: `/shared/skills/${sharedHex}`,
        sourceInfo: {},
        disableModelInvocation: false,
      }),
    ]),
    eagerTrustedSkillPrompt: "",
    agentsFiles: Object.freeze([]),
    metadata: Object.freeze({
      shared: Object.freeze({
        scope: "shared",
        revision: `sha256:${"c".repeat(64)}`,
        bundleDigest: `sha256:${sharedHex}`,
        guestRoot: "/shared/skills",
        guestSubtree: `/shared/skills/${sharedHex}`,
        fileCount: 1,
        byteCount: 1,
        readOnlyEnforced: false,
      }),
      user: Object.freeze({
        scope: "user",
        revision: `sha256:${userHex}`,
        bundleDigest: `sha256:${userHex}`,
        guestRoot: "/user/skills",
        guestSubtree: `/user/skills/${userHex}`,
        fileCount: 0,
        byteCount: 0,
        readOnlyEnforced: false,
      }),
      agentsStatus: "missing",
      skillCount: 1,
    }),
    dispose: async () => undefined,
    ...overrides,
  }) as unknown as CogsPreparedSkills;
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
    skillPreparer: emptySkillPreparer(),
    emit: () => true,
    onFatal: () => undefined,
    ...overrides,
  };
}

test("Pi session rejects hostile policy authorizer seam generically before side effects", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-policy-seam-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const hostileAuthorizer = new Proxy(
      Object.freeze(() => assert.fail("authorizer should not run")),
      {
        isExtensible() {
          throw new Error("SECRET_POLICY_AUTHORIZE_TRAP");
        },
      },
    );
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot: resolve(root, "sessions"),
          sessionId: "policy-seam-deny",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "aaaaaaaa",
          toolPorts: fakePorts([]),
          policyAuthorizer: hostileAuthorizer,
        }),
      ),
      /invalid policy authorizer/,
    );
    await assertMissing(resolve(root, "sessions"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session model policy denial cleans prepared resources before session side effects", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-policy-model-deny-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let disposed = 0;
    const authorizer = Object.freeze(() =>
      Object.freeze({
        version: "cogs.policy-decision/v1alpha1" as const,
        decision_id: `sha256:${"b".repeat(64)}` as const,
        allow: false,
        reason: "unsupported_surface" as const,
      }),
    );
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot,
          sessionId: "policy-model-deny",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "aaaaaaaa",
          toolPorts: fakePorts([]),
          preparedResources: hostilePrepared({
            dispose: async () => {
              disposed += 1;
            },
          }),
          policyAuthorizer: authorizer,
        }),
      ),
    );
    assert.equal(disposed, 1);
    await assertMissing(resolve(sessionRoot, "policy-model-deny"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session tool enable policy denial cleans owned exporter Git and prepared resources", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-policy-enable-deny-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let disposed = 0;
    let observerDisposed = 0;
    let checkpointerDisposed = 0;
    let policyCalls = 0;
    const observer = fakeObserver(["a".repeat(40)]);
    const trackedObserver: CogsGitObserver = Object.freeze({
      ...observer,
      dispose: async () => {
        observerDisposed += 1;
        await observer.dispose();
      },
    });
    const checkpointer: CogsGitCheckpointer = Object.freeze({
      checkpoint: async () => ({
        repo: "workspace-1",
        session: "policy-enable-deny",
        entry: "00000000",
        turn: 1,
        commit: "b".repeat(40),
        checkpoint_ref: "refs/cogs/checkpoints/session/1",
        observed_at: new Date(0).toISOString(),
        file_count: 0,
        total_bytes: 0,
        duration_ms: 0,
      }),
      dispose: async () => {
        checkpointerDisposed += 1;
      },
    });
    const authorizer = Object.freeze((input: unknown) => {
      policyCalls += 1;
      const action = (input as { action?: unknown }).action;
      return Object.freeze({
        version: "cogs.policy-decision/v1alpha1" as const,
        decision_id: `sha256:${"a".repeat(64)}` as const,
        allow: action !== "tool.enable",
        reason: action === "tool.enable" ? ("unsupported_surface" as const) : ("allowed" as const),
      });
    });
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot,
          sessionId: "policy-enable-deny",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "aaaaaaaa",
          toolPorts: fakePorts([]),
          preparedResources: hostilePrepared({
            dispose: async () => {
              disposed += 1;
              throw new Error("prepared cleanup failed");
            },
          }),
          git: { repositoryId: "workspace-1", observer: trackedObserver, checkpointer },
          policyAuthorizer: authorizer,
        }),
      ),
    );
    assert.equal(disposed, 1);
    assert.equal(observerDisposed, 1);
    assert.equal(checkpointerDisposed, 1);
    assert.ok(policyCalls >= 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session fails closed instead of settling when durable JSONL flush rejects", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-jsonl-flush-fail-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    const sessionId = "jsonl-flush-fail-session";
    const sessionDir = resolve(sessionRoot, sessionId);
    const resumeFile = "resume.jsonl";
    const sessionFile = resolve(sessionDir, resumeFile);
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await mkdir(sessionDir, { recursive: true });
    await writeFile(
      sessionFile,
      `${JSON.stringify({ type: "session", version: 3, id: sessionId, timestamp: new Date(0).toISOString(), cwd })}\n`,
    );
    let fatal = "";
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId,
        resumeFile,
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "aaaaaaaa",
        toolPorts: fakePorts([]),
        streamFn: oneToolStream("read", { path: "/workspace/README.md" }),
        onFatal: (reason) => {
          fatal = reason;
        },
      }),
    );
    await unlink(sessionFile);
    await symlink(resolve(root, "outside.jsonl"), sessionFile);
    await writeFile(resolve(root, "outside.jsonl"), "not pi jsonl\n");
    await adapter.input({ requestId: "flush", correlationId: "flush-corr", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "shutdown"));
    assert.equal(fatal, "history-flush-failed");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("authenticated Pi session disposes malformed prepared resources before model key source", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-bad-prepared-cleanup-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const source = new TestModelApiKeySource("aaaaaaaa");
    let disposed = 0;
    await assert.rejects(
      createAuthenticatedCogsPiSession(
        authOptions(root, source, {
          skillPreparer: Object.freeze({
            prepare: async () =>
              Object.freeze({
                piSkills: Object.freeze([
                  Object.freeze({
                    name: "bad",
                    description: "bad",
                    filePath: "/tmp/host/SKILL.md",
                    baseDir: "/tmp/host",
                    sourceInfo: {},
                    disableModelInvocation: false,
                  }),
                ]),
                eagerTrustedSkillPrompt: "bad",
                agentsFiles: Object.freeze([]),
                metadata: Object.freeze({}),
                dispose: async () => {
                  disposed += 1;
                },
              } as never),
          }),
        }),
      ),
    );
    assert.equal(disposed, 1);
    assert.equal(source.calls, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("authenticated Pi session rejects hostile prepared paths and metadata before model key source", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-hostile-prepared-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const source = new TestModelApiKeySource("aaaaaaaa");
    const sharedHex = "a".repeat(64);
    const userHex = "b".repeat(64);
    const cases: Array<{ name: string; prepared: CogsPreparedSkills }> = [
      {
        name: "terminal-dotdot",
        prepared: hostilePrepared({
          piSkills: Object.freeze([
            Object.freeze({
              name: "safe-skill",
              description: "safe description",
              filePath: `/shared/skills/${sharedHex}/..`,
              baseDir: `/shared/skills/${sharedHex}`,
              sourceInfo: {},
              disableModelInvocation: false,
            }),
          ]),
        }),
      },
      {
        name: "control-char",
        prepared: hostilePrepared({
          piSkills: Object.freeze([
            Object.freeze({
              name: "safe-skill",
              description: "safe description",
              filePath: `/shared/skills/${sharedHex}/bad\u0001.md`,
              baseDir: `/shared/skills/${sharedHex}`,
              sourceInfo: {},
              disableModelInvocation: false,
            }),
          ]),
        }),
      },
      {
        name: "empty-description",
        prepared: hostilePrepared({
          piSkills: Object.freeze([
            Object.freeze({
              name: "safe-skill",
              description: "",
              filePath: `/shared/skills/${sharedHex}/SKILL.md`,
              baseDir: `/shared/skills/${sharedHex}`,
              sourceInfo: {},
              disableModelInvocation: false,
            }),
          ]),
        }),
      },
      {
        name: "bad-name",
        prepared: hostilePrepared({
          piSkills: Object.freeze([
            Object.freeze({
              name: "-bad",
              description: "safe description",
              filePath: `/shared/skills/${sharedHex}/SKILL.md`,
              baseDir: `/shared/skills/${sharedHex}`,
              sourceInfo: {},
              disableModelInvocation: false,
            }),
          ]),
        }),
      },
      {
        name: "guest-subtree-digest-mismatch",
        prepared: hostilePrepared({
          metadata: Object.freeze({
            ...hostilePrepared().metadata,
            shared: Object.freeze({
              ...hostilePrepared().metadata.shared,
              guestSubtree: `/shared/skills/${"c".repeat(64)}`,
            }),
          }),
        }),
      },
      {
        name: "user-revision-mismatch",
        prepared: hostilePrepared({
          metadata: Object.freeze({
            ...hostilePrepared().metadata,
            user: Object.freeze({ ...hostilePrepared().metadata.user, revision: `sha256:${"c".repeat(64)}` }),
          }),
        }),
      },
      {
        name: "file-count-cap",
        prepared: hostilePrepared({
          metadata: Object.freeze({
            ...hostilePrepared().metadata,
            shared: Object.freeze({ ...hostilePrepared().metadata.shared, fileCount: 129 }),
          }),
        }),
      },
      {
        name: "byte-count-cap",
        prepared: hostilePrepared({
          metadata: Object.freeze({
            ...hostilePrepared().metadata,
            shared: Object.freeze({ ...hostilePrepared().metadata.shared, byteCount: 768 * 1024 + 1 }),
          }),
        }),
      },
      {
        name: "skill-count-cap",
        prepared: hostilePrepared({ metadata: Object.freeze({ ...hostilePrepared().metadata, skillCount: 33 }) }),
      },
    ];
    for (const one of cases) {
      await assert.rejects(
        createAuthenticatedCogsPiSession(
          authOptions(root, source, { skillPreparer: Object.freeze({ prepare: async () => one.prepared }) }),
        ),
        /skill preparation failed/,
        one.name,
      );
      assert.equal(source.calls, 0, one.name);
    }
    assert.equal(userHex.length, 64);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("authenticated Pi session fails preparation before model key source", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-prep-before-auth-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const source = new TestModelApiKeySource("aaaaaaaa");
    await assert.rejects(
      createAuthenticatedCogsPiSession(
        authOptions(root, source, {
          skillPreparer: Object.freeze({
            prepare: async () => {
              throw new Error("prep failed with secret-ish host /tmp/private");
            },
          }),
        }),
      ),
    );
    assert.equal(source.calls, 0);
    await assertMissing(resolve(root, "sessions/auth-session.jsonl"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session exposes canonical prepared metadata and direct-root skill paths", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-skill-metadata-"));
  try {
    await mkdir(resolve(root, "workspace"), { recursive: true });
    await mkdir(resolve(root, "agent"), { recursive: true });
    const sharedHex = "a".repeat(64);
    const prepared = hostilePrepared({
      piSkills: Object.freeze([
        Object.freeze({
          name: "root-skill",
          description: "root description",
          filePath: `/shared/skills/${sharedHex}/root.md`,
          baseDir: `/shared/skills/${sharedHex}`,
          sourceInfo: {},
          disableModelInvocation: false,
        }),
      ]),
    });
    const source = new TestModelApiKeySource("aaaaaaaa");
    const adapter = await createAuthenticatedCogsPiSession(
      authOptions(root, source, { skillPreparer: Object.freeze({ prepare: async () => prepared }) }),
    );
    try {
      assert.equal(adapter.skillMetadata()?.shared.guestSubtree, `/shared/skills/${sharedHex}`);
      const metadata = adapter.skillMetadata();
      assert.ok(Object.isFrozen(metadata));
      assert.equal(source.calls, 1);
      assert.equal(adapter.activeToolNames().length, COGS_PI_TOOL_NAMES.length);
    } finally {
      await adapter.dispose();
    }

    const unprepared = await createCogsPiSession(
      withDefaults({
        cwd: resolve(root, "workspace"),
        agentDir: resolve(root, "agent"),
        sessionRoot: resolve(root, "sessions2"),
        sessionId: "no-skill-metadata-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "aaaaaaaa",
        toolPorts: fakePorts([]),
      }),
    );
    try {
      assert.equal(unprepared.skillMetadata(), undefined);
    } finally {
      await unprepared.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session creates authenticated local export descriptor without adding a model tool", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-local-export-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await mkdir(sessionRoot, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionId: "export-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-ant-api03-local-export",
        sessionRoot,
        toolPorts: fakePorts([]),
        streamFn: textStream("export ready"),
        preparedResources: hostilePrepared(),
      }),
    );
    try {
      assert.deepEqual(adapter.activeToolNames(), COGS_PI_TOOL_NAMES);
      await adapter.input({ requestId: "export-run", correlationId: "export-corr", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const descriptor = await adapter.createExport({ requestId: "export", correlationId: "export-corr" });
      assert.equal((descriptor as { sensitive?: unknown }).sensitive, true);
      assert.equal((descriptor as { bundle?: unknown }).bundle, "cogs-session-export-session");
      assert.equal(typeof (descriptor as { manifest_sha256?: unknown }).manifest_sha256, "string");
      const manifest = JSON.parse(
        await readFile(
          resolve(sessionRoot, "export-session", "exports", "cogs-session-export-session", "manifest.json"),
          "utf8",
        ),
      );
      assert.equal(manifest.mode, "raw");
      assert.equal(manifest.attachments_included, false);
      const lifecycle = { ready: true, state: "ready", requestShutdown: async () => undefined };
      const api = createApiServer({
        lifecycle: lifecycle as never,
        bearerToken: "worker-secret-0123456789abcdefghi",
        sessionId: "export-session",
        session: adapter,
        history: adapter,
        exporter: adapter,
      });
      const { port } = await api.listen();
      try {
        const base = `http://127.0.0.1:${port}`;
        assert.equal(
          (
            await fetch(`${base}/v1/export`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ request_id: "api-export" }),
            })
          ).status,
          401,
        );
        const response = await fetch(`${base}/v1/export`, {
          method: "POST",
          headers: {
            authorization: "Bearer worker-secret-0123456789abcdefghi",
            "content-type": "application/json",
          },
          body: JSON.stringify({ request_id: "api-export" }),
        });
        assert.equal(response.status, 200);
        const body = (await response.json()) as { sensitive?: unknown; bundle?: Record<string, unknown> };
        assert.equal(body.sensitive, true);
        assert.equal(body.bundle?.bundle, "cogs-session-export-session");
        assert.equal(String(body.bundle?.bundle).startsWith("/"), false);
        assert.equal(JSON.stringify(body).includes("export ready"), false);
      } finally {
        await api.close();
      }
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session prepareShutdown maps shutdown boundary before final export and ready event", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-shutdown-export-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await mkdir(sessionRoot, { recursive: true });
    const events: string[] = [];
    const notes: CogsGitMapRecord[] = [];
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "shutdown-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-ant-api03-shutdown-export",
        toolPorts: fakePorts([]),
        streamFn: textStream("shutdown ready"),
        preparedResources: hostilePrepared(),
        git: {
          repositoryId: "workspace-1",
          observer: fakeObserver(["a".repeat(40), "b".repeat(40), "c".repeat(40)], notes),
        },
        emit: (event) => {
          events.push(`${event.kind}:${(event.payload as { boundary?: unknown }).boundary ?? ""}`);
          return true;
        },
      }),
    );
    try {
      assert.deepEqual(adapter.activeToolNames(), COGS_PI_TOOL_NAMES);
      await adapter.input({ requestId: "run", correlationId: "corr", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const [first, second] = await Promise.all([
        adapter.prepareShutdown({ requestId: "shutdown", correlationId: "corr" }),
        adapter.prepareShutdown({ requestId: "shutdown", correlationId: "corr" }),
      ]);
      assert.deepEqual(second, first);
      assert.equal((await adapter.state()).runState, "shutdown");
      assert.equal(events.filter((event) => event === "git_mapping:shutdown").length, 1, JSON.stringify(events));
      assert.equal(events.filter((event) => event === "shutdown_ready:").length, 1, JSON.stringify(events));
      assert.ok(events.indexOf("git_mapping:shutdown") >= 0, JSON.stringify(events));
      assert.ok(events.indexOf("shutdown_ready:") > events.indexOf("git_mapping:shutdown"));
      assert.equal(notes.at(-1)?.commit, "c".repeat(40));
      await assert.rejects(adapter.createExport({ requestId: "late", correlationId: "corr" }), /closed/);
      const gitMap = JSON.parse(
        await readFile(
          resolve(sessionRoot, "shutdown-session", "exports", "cogs-session-shutdown-session", "git-map.json"),
          "utf8",
        ),
      );
      assert.equal(gitMap.records.at(-1).commit, "c".repeat(40));
      assert.equal(JSON.stringify(first).includes("sk-ant-api03"), false);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session dispose aborts and joins draining shutdown without late ready", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-shutdown-dispose-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const events: string[] = [];
    const observerState = { started: false, aborted: false };
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "shutdown-dispose-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-ant-api03-shutdown-dispose",
        toolPorts: fakePorts([]),
        streamFn: textStream("ready"),
        preparedResources: hostilePrepared(),
        git: { repositoryId: "workspace-1", observer: pausedObserver(observerState) },
        emit: (event) => {
          events.push(event.kind);
          return true;
        },
      }),
    );
    await adapter.input({ requestId: "run", correlationId: "corr", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const preparing = adapter.prepareShutdown({ requestId: "shutdown", correlationId: "corr" });
    await eventually(() => assert.equal(observerState.started, true));
    await adapter.dispose();
    await assert.rejects(preparing, /shutdown preparation failed/);
    assert.equal(observerState.aborted, true);
    assert.equal(events.includes("shutdown_ready"), false);
    assert.equal((await adapter.state()).runState, "shutdown");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session shutdown rejection cases preserve active turn and fail closed on ready publication", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-shutdown-reject-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const active = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "shutdown-active-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-ant-api03-shutdown-active",
        toolPorts: fakePorts([]),
        streamFn: hangingStream({ count: 0 }),
      }),
    );
    try {
      await active.input({ requestId: "run", correlationId: "corr", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await active.state()).runState, "running"));
      await assert.rejects(active.prepareShutdown({ requestId: "shutdown", correlationId: "corr" }), /not idle/);
      assert.equal((await active.state()).runState, "running");
    } finally {
      await active.dispose().catch(() => undefined);
    }

    let readyAttempts = 0;
    const failReady = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "shutdown-ready-fail-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-ant-api03-shutdown-ready-fail",
        toolPorts: fakePorts([]),
        streamFn: textStream("ready"),
        preparedResources: hostilePrepared(),
        emit: (event) => {
          if (event.kind === "shutdown_ready") {
            readyAttempts += 1;
            return false;
          }
          return true;
        },
      }),
    );
    await failReady.input({ requestId: "run", correlationId: "corr", kind: "prompt", content: "go" });
    await eventually(async () => assert.equal((await failReady.state()).runState, "settled"));
    await assert.rejects(failReady.prepareShutdown({ requestId: "shutdown", correlationId: "corr" }), /failed/);
    assert.equal(readyAttempts, 1);
    assert.equal((await failReady.state()).runState, "shutdown");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session shutdown without Git still emits one ready", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-shutdown-nongit-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const events: string[] = [];
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "shutdown-nongit-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-ant-api03-shutdown-nongit",
        toolPorts: fakePorts([]),
        streamFn: textStream("ready"),
        preparedResources: hostilePrepared(),
        emit: (event) => {
          events.push(event.kind);
          return true;
        },
      }),
    );
    try {
      await adapter.input({ requestId: "run", correlationId: "corr", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const [first, second] = await Promise.all([
        adapter.prepareShutdown({ requestId: "shutdown", correlationId: "corr" }),
        adapter.prepareShutdown({ requestId: "shutdown", correlationId: "corr" }),
      ]);
      assert.deepEqual(second, first);
      assert.equal(events.filter((event) => event === "shutdown_ready").length, 1);
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session uses prepared eager skill prompt with guest paths before first model call", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-prepared-prompt-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const hostPath = resolve(root, "trusted-host-temp");
    const trusted = "# Trusted skill body\nUse the verified skill content.";
    let observed = "";
    const delegate = oneToolStream("read", { path: "/workspace/README.md" });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "prepared-prompt-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "aaaaaaaa",
        toolPorts: fakePorts([]),
        preparedResources: Object.freeze({
          piSkills: Object.freeze([]),
          eagerTrustedSkillPrompt: JSON.stringify({ path: "/shared/skills/abc/SKILL.md", markdown: trusted }),
          agentsFiles: Object.freeze([]),
          metadata: Object.freeze({
            shared: Object.freeze({
              scope: "shared",
              revision: `sha256:${"a".repeat(64)}`,
              bundleDigest: `sha256:${"a".repeat(64)}`,
              guestRoot: "/shared/skills",
              guestSubtree: `/shared/skills/${"a".repeat(64)}`,
              fileCount: 1,
              byteCount: trusted.length,
              readOnlyEnforced: false,
            }),
            user: Object.freeze({
              scope: "user",
              revision: `sha256:${"b".repeat(64)}`,
              bundleDigest: `sha256:${"b".repeat(64)}`,
              guestRoot: "/user/skills",
              guestSubtree: `/user/skills/${"b".repeat(64)}`,
              fileCount: 0,
              byteCount: 0,
              readOnlyEnforced: false,
            }),
            agentsStatus: "missing",
            skillCount: 0,
          }),
          dispose: async () => undefined,
        }),
        streamFn: (model, context, options) => {
          observed = JSON.stringify(context);
          return delegate(model, context, options);
        },
      }),
    );
    try {
      await adapter.input({ requestId: "prepared", correlationId: "prepared-corr", kind: "prompt", content: "go" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      assert.match(observed, /Trusted skill body/);
      assert.match(observed, /\/shared\/skills\/abc\/SKILL\.md/);
      assert.equal(observed.includes(hostPath), false);
      assert.deepEqual([...adapter.activeToolNames()].sort(), [...COGS_PI_TOOL_NAMES].sort());
    } finally {
      await adapter.dispose();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

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

function recordingTelemetry() {
  const spans: unknown[] = [];
  const metrics: unknown[] = [];
  const sink = Object.freeze({
    get ready() {
      return true;
    },
    span: (input: unknown) => {
      spans.push(input);
      return true;
    },
    metric: (input: unknown) => {
      metrics.push(input);
      return true;
    },
    snapshot: () => Object.freeze({ ready: true, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 }),
    close: async () => undefined,
  });
  return { sink, spans, metrics };
}

function telemetryByName(items: unknown[], name: string): Array<{ attributes?: Record<string, unknown> }> {
  return items.filter(
    (item): item is { attributes?: Record<string, unknown> } =>
      typeof item === "object" && item !== null && (item as { name?: unknown }).name === name,
  );
}

function metricValues(metrics: unknown[], name: string): number[] {
  return telemetryByName(metrics, name)
    .map((item) => item.attributes?.value)
    .filter((value): value is number => typeof value === "number");
}

function throwingTelemetry() {
  return Object.freeze({
    get ready() {
      return true;
    },
    span: () => {
      throw new Error("SECRET_TELEMETRY");
    },
    metric: () => {
      throw new Error("SECRET_TELEMETRY");
    },
    snapshot: () => Object.freeze({ ready: true, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 }),
    close: async () => undefined,
  });
}

test("Pi telemetry instruments real tool dispatches and excludes sentinels", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-telemetry-"));
  const cwd = resolve(root, "cwd");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  const telemetry = recordingTelemetry();
  const secret = "sk-test-telemetry-secret";
  const calls: string[] = [];
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-tools",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: secret,
        toolPorts: fakePorts(calls, { ok: true, truncated: true, timedOut: true, stdoutTruncated: true }),
        streamFn: allToolsStream(),
        telemetry: telemetry.sink,
      }),
    );
    await adapter.input({
      requestId: "request-secret",
      correlationId: "correlation-secret",
      kind: "prompt",
      content:
        "PROMPT_SECRET COMMAND_SECRET PATH_SECRET OUTPUT_SECRET QUERY_SECRET ACCOUNT_SECRET MODEL_SECRET PROVIDER_SECRET",
    });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const text = JSON.stringify([...telemetry.spans, ...telemetry.metrics]);
    const enableTools = telemetryByName(telemetry.spans, "tool.enable").map((span) => span.attributes?.tool);
    assert.deepEqual(enableTools, ["read", "write", "edit", "bash"]);
    const dispatchTools = telemetryByName(telemetry.spans, "tool.dispatch").map((span) => [
      span.attributes?.tool,
      span.attributes?.outcome,
    ]);
    assert.deepEqual(dispatchTools, [
      ["read", "ok"],
      ["write", "ok"],
      ["edit", "ok"],
      ["bash", "timeout"],
    ]);
    assert.equal(metricValues(telemetry.metrics, "tool.count").length, 4);
    assert.equal(metricValues(telemetry.metrics, "tool.timeouts").length, 1);
    assert.equal(metricValues(telemetry.metrics, "tool.truncated").length, 4);
    assert.equal(
      /PROMPT_SECRET|COMMAND_SECRET|PATH_SECRET|OUTPUT_SECRET|QUERY_SECRET|ACCOUNT_SECRET|MODEL_SECRET|PROVIDER_SECRET|\/workspace|request-secret|correlation-secret|claude-sonnet|sk-test/.test(
        text,
      ),
      false,
    );
    await adapter.dispose();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi telemetry handles policy denial, throwing sink, model events and usage deltas", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-telemetry-deny-"));
  const cwd = resolve(root, "cwd");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  const telemetry = recordingTelemetry();
  const beforeStats = { tokens: { input: 0, output: 0, cache: 5, cacheRead: 99, cacheWrite: 99 }, cost: { total: 0 } };
  const afterStats = {
    tokens: { input: 10, output: 4, cache: 7, cacheRead: 1000, cacheWrite: 1000 },
    cost: { total: 0.000123 },
  };
  const secondStats = {
    tokens: { input: 13, output: 9, cacheRead: 2, cacheWrite: 8 },
    cost: { total: 0.0002 },
  };
  const resetStats = { tokens: { input: 1, output: Number.NaN, cache: 0 }, cost: { total: Number.NaN } };
  const hugeStats = { tokens: { input: 1_000, output: 1_000, cache: 1_000 }, cost: { total: 0.01 } };
  const hugeDeltaStats = { tokens: { input: 86_401_001, output: 1_001, cache: 1_001 }, cost: { total: 0.010001 } };
  let turnCalls = 0;
  let currentBefore = beforeStats as unknown;
  let currentAfter = afterStats as unknown;
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-usage",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-usage-secret",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("ok"),
        telemetry: telemetry.sink,
      }),
    );
    (adapter as unknown as { session: { getSessionStats: () => unknown } }).session.getSessionStats = () =>
      turnCalls++ === 0 ? currentBefore : currentAfter;
    const session = internalSession(adapter);
    for (const reason of ["toolUse", "stop", "length"] as const) {
      session._emit({ type: "message_start", message: { role: "assistant", content: "SECRET_SOURCE" } });
      session._emit({
        type: "message_end",
        message: { role: "assistant", stopReason: reason, content: "SECRET_OUTPUT" },
      });
    }
    session._emit({ type: "message_start", message: { role: "assistant" } });
    session._emit({ type: "message_end", message: { role: "assistant", stopReason: "aborted" } });
    session._emit({ type: "message_start", message: { role: "assistant" } });
    session._emit({ type: "message_end", message: { role: "assistant", stopReason: "error" } });
    session._emit({ type: "message_start", message: { role: "assistant" } });
    session._emit({ type: "message_end", message: { role: "assistant" } });
    let getterInvoked = false;
    let contentGetterInvoked = false;
    const hostileContentMessage = Object.freeze(
      Object.defineProperty({ role: "assistant", stopReason: "stop" }, "content", {
        enumerable: true,
        get: () => {
          contentGetterInvoked = true;
          return "SECRET_CONTENT";
        },
      }),
    );
    session._emit({ type: "message_start", message: hostileContentMessage });
    session._emit({ type: "message_end", message: hostileContentMessage });
    session._emit({
      type: "message_start",
      message: Object.defineProperty({}, "role", {
        enumerable: true,
        get: () => {
          getterInvoked = true;
          return "assistant";
        },
      }),
    });
    session._emit({
      type: "message_end",
      message: new Proxy(
        { role: "assistant" },
        {
          getOwnPropertyDescriptor: () => {
            throw new Error("trap");
          },
        },
      ),
    });
    turnCalls = 0;
    currentBefore = beforeStats;
    currentAfter = afterStats;
    await adapter.input({ requestId: "usage", correlationId: "usage-corr", kind: "prompt", content: "hello" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    turnCalls = 0;
    currentBefore = afterStats;
    currentAfter = secondStats;
    await adapter.input({ requestId: "usage2", correlationId: "usage-corr2", kind: "prompt", content: "hello again" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    turnCalls = 0;
    currentBefore = secondStats;
    currentAfter = resetStats;
    await adapter.input({ requestId: "usage3", correlationId: "usage-corr3", kind: "prompt", content: "reset" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    turnCalls = 0;
    currentBefore = resetStats;
    currentAfter = hugeStats;
    await adapter.input({ requestId: "usage4", correlationId: "usage-corr4", kind: "prompt", content: "baseline" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    turnCalls = 0;
    currentBefore = hugeStats;
    currentAfter = hugeDeltaStats;
    await adapter.input({ requestId: "usage5", correlationId: "usage-corr5", kind: "prompt", content: "delta" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const text = JSON.stringify([...telemetry.spans, ...telemetry.metrics]);
    assert.deepEqual(
      telemetryByName(telemetry.spans, "pi.model_call")
        .map((span) => span.attributes?.outcome)
        .slice(0, 5),
      ["ok", "ok", "ok", "cancelled", "error"],
    );
    assert.equal(telemetryByName(telemetry.spans, "pi.model_call").map((span) => span.attributes?.outcome)[5], "error");
    assert.equal(getterInvoked, false);
    assert.equal(contentGetterInvoked, false);
    assert.deepEqual(metricValues(telemetry.metrics, "token.input"), [10, 3, 86_400_001]);
    assert.deepEqual(metricValues(telemetry.metrics, "token.output"), [4, 5, 1]);
    assert.deepEqual(metricValues(telemetry.metrics, "token.cache"), [2, 3, 1]);
    assert.deepEqual(metricValues(telemetry.metrics, "cost.microunits"), [123, 77, 1]);
    assert.equal(text.includes("SECRET_SOURCE"), false);
    assert.equal(text.includes("SECRET_OUTPUT"), false);
    await adapter.dispose();
    session._emit({ type: "message_start", message: { role: "assistant" } });
    session._emit({ type: "message_end", message: { role: "assistant", stopReason: "stop" } });
    assert.equal(telemetryByName(telemetry.spans, "pi.model_call").length, 12);

    const throwing = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-throwing",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-throwing-secret",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("ok"),
        telemetry: throwingTelemetry(),
      }),
    );
    await throwing.input({ requestId: "throw", correlationId: "throw-corr", kind: "prompt", content: "ok" });
    await eventually(async () => assert.equal((await throwing.state()).runState, "settled"));
    await throwing.dispose();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi telemetry covers real tool policy denial, malformed paths, failed ports, aborts, and metadata accessors", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-telemetry-negative-"));
  const cwd = resolve(root, "cwd");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });

    const traversalTelemetry = recordingTelemetry();
    const traversalCalls: string[] = [];
    const traversal = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-traversal",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-negative-secret",
        toolPorts: fakePorts(traversalCalls),
        streamFn: oneToolStream("read", { path: "/workspace/../SECRET_PATH" }),
        telemetry: traversalTelemetry.sink,
      }),
    );
    await traversal.input({ requestId: "trav", correlationId: "trav-corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await traversal.state()).runState, "settled"));
    assert.deepEqual(traversalCalls, []);
    assert.equal(telemetryByName(traversalTelemetry.spans, "tool.dispatch").at(0)?.attributes?.outcome, "error");
    assert.equal(JSON.stringify(traversalTelemetry.spans).includes("SECRET_PATH"), false);
    await traversal.dispose();

    const denialTelemetry = recordingTelemetry();
    const denialCalls: string[] = [];
    const denyDispatch = Object.freeze((input: unknown) => {
      const allow = (input as { action?: unknown }).action !== "tool.dispatch";
      return Object.freeze({
        version: "cogs.policy-decision/v1alpha1" as const,
        decision_id: `sha256:${"b".repeat(64)}` as const,
        allow,
        reason: allow ? ("allowed" as const) : ("unsupported_surface" as const),
      });
    });
    const denied = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-denied-dispatch",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-negative-secret",
        toolPorts: fakePorts(denialCalls),
        streamFn: oneToolStream("read", { path: "/workspace/file.txt" }),
        policyAuthorizer: denyDispatch,
        telemetry: denialTelemetry.sink,
      }),
    );
    await denied.input({ requestId: "deny", correlationId: "deny-corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await denied.state()).runState, "settled"));
    assert.deepEqual(denialCalls, []);
    assert.equal(telemetryByName(denialTelemetry.spans, "tool.dispatch").at(0)?.attributes?.outcome, "denied");
    await denied.dispose();

    const enableTelemetry = recordingTelemetry();
    const denyEnable = Object.freeze((input: unknown) => {
      const allow =
        (input as { action?: unknown; resource?: unknown }).action !== "tool.enable" ||
        (input as { resource?: unknown }).resource !== "edit";
      return Object.freeze({
        version: "cogs.policy-decision/v1alpha1" as const,
        decision_id: `sha256:${"c".repeat(64)}` as const,
        allow,
        reason: allow ? ("allowed" as const) : ("unsupported_surface" as const),
      });
    });
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot,
          sessionId: "telemetry-denied-enable",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "sk-test-negative-secret",
          toolPorts: fakePorts([]),
          policyAuthorizer: denyEnable,
          telemetry: enableTelemetry.sink,
        }),
      ),
    );
    assert.deepEqual(
      telemetryByName(enableTelemetry.spans, "tool.enable").map((span) => [
        span.attributes?.tool,
        span.attributes?.outcome,
      ]),
      [
        ["read", "ok"],
        ["write", "ok"],
        ["edit", "denied"],
      ],
    );

    let metadataGetter = false;
    const result = Object.defineProperty({ ok: true }, "truncated", {
      enumerable: false,
      get: () => {
        metadataGetter = true;
        return true;
      },
    });
    const accessorTelemetry = recordingTelemetry();
    const accessor = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-accessor-metadata",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-negative-secret",
        toolPorts: fakePorts([], result),
        streamFn: oneToolStream("read", { path: "/workspace/file.txt" }),
        telemetry: accessorTelemetry.sink,
      }),
    );
    await accessor.input({ requestId: "accessor", correlationId: "accessor-corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await accessor.state()).runState, "settled"));
    assert.equal(metadataGetter, false);
    assert.equal(JSON.stringify(accessorTelemetry.metrics).includes("tool.truncated"), false);
    await accessor.dispose();

    const failedTelemetry = recordingTelemetry();
    const failed = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-failed-port",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-negative-secret",
        toolPorts: {
          ...fakePorts([]),
          read: async () => {
            throw new Error("SECRET_PORT_FAILURE");
          },
        },
        streamFn: oneToolStream("read", { path: "/workspace/file.txt" }),
        telemetry: failedTelemetry.sink,
      }),
    );
    await failed.input({ requestId: "failed", correlationId: "failed-corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.equal((await failed.state()).runState, "settled"));
    assert.equal(telemetryByName(failedTelemetry.spans, "tool.dispatch").at(0)?.attributes?.outcome, "error");
    assert.equal(JSON.stringify(failedTelemetry.spans).includes("SECRET_PORT_FAILURE"), false);
    await failed.dispose();

    const cancelledTelemetry = recordingTelemetry();
    const cancelled = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "telemetry-cancelled-port",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-negative-secret",
        toolPorts: {
          ...fakePorts([]),
          read: async (input) => {
            await new Promise((_resolve, reject) =>
              input.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true }),
            );
            return { ok: true };
          },
        },
        streamFn: oneToolStream("read", { path: "/workspace/file.txt" }),
        telemetry: cancelledTelemetry.sink,
        operationTimeoutMs: 10,
      }),
    );
    await cancelled.input({ requestId: "cancel", correlationId: "cancel-corr", kind: "prompt", content: "x" });
    await eventually(async () => assert.notEqual((await cancelled.state()).runState, "running"));
    assert.equal(telemetryByName(cancelledTelemetry.spans, "tool.dispatch").at(0)?.attributes?.outcome, "cancelled");
    await cancelled.dispose().catch(() => undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi command audit disabled seam is inert for real bash dispatch", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-command-audit-"));
  const cwd = resolve(root, "cwd");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    const omittedCalls: string[] = [];
    const omitted = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "audit-omitted",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-command-audit",
        toolPorts: fakePorts(omittedCalls),
        streamFn: oneToolStream("bash", { command: "printf SECRET_COMMAND" }),
      }),
    );
    await omitted.input({ requestId: "omitted", correlationId: "omitted-corr", kind: "prompt", content: "run" });
    await eventually(async () => assert.equal((await omitted.state()).runState, "settled"));
    await omitted.dispose();

    let auditCalls = 0;
    const explicitAudit = Object.freeze({
      mode: "disabled" as const,
      enabled: false as const,
      record: () => {
        auditCalls += 1;
        throw new Error("SECRET_COMMAND audit callback must not run");
      },
    });
    const explicitCalls: string[] = [];
    const explicit = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "audit-explicit",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "sk-test-command-audit",
        toolPorts: fakePorts(explicitCalls),
        streamFn: oneToolStream("bash", { command: "printf SECRET_COMMAND" }),
        commandAudit: explicitAudit,
      }),
    );
    await explicit.input({ requestId: "explicit", correlationId: "explicit-corr", kind: "prompt", content: "run" });
    await eventually(async () => assert.equal((await explicit.state()).runState, "settled"));
    await explicit.dispose();

    assert.deepEqual(omittedCalls, ["bash:printf SECRET_COMMAND"]);
    assert.deepEqual(explicitCalls, omittedCalls);
    assert.equal(auditCalls, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi command audit rejects malformed hooks before session side effects", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-pi-command-audit-invalid-"));
  const cwd = resolve(root, "cwd");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    let disposed = 0;
    const resources = hostilePrepared({
      dispose: async () => {
        disposed += 1;
      },
    });
    const invalidHooks: unknown[] = [
      Object.freeze({ mode: "enabled", enabled: true, record: () => false }),
      Object.freeze({ mode: "disabled", enabled: false, record: () => false, extra: "SECRET" }),
      Object.freeze(
        Object.defineProperty({ enabled: false, record: () => false }, "mode", {
          enumerable: true,
          get: () => "disabled",
        }),
      ),
      Object.freeze({ mode: "disabled", enabled: false, record: () => false, [Symbol.for("SECRET")]: true }),
      new Proxy(Object.freeze({ mode: "disabled", enabled: false, record: () => false }), {
        getOwnPropertyDescriptor: () => {
          throw new Error("SECRET proxy trap");
        },
      }),
    ];
    for (const [index, commandAudit] of invalidHooks.entries()) {
      await assert.rejects(
        createCogsPiSession(
          withDefaults({
            cwd,
            agentDir,
            sessionRoot,
            sessionId: `audit-invalid-${index}`,
            model: { provider: "anthropic", id: "claude-sonnet-4-5" },
            apiKey: "sk-test-command-audit",
            toolPorts: fakePorts([]),
            preparedResources: resources,
            commandAudit: commandAudit as never,
          }),
        ),
        /^Error: invalid command audit hook$/,
      );
      await assertMissing(resolve(sessionRoot, `audit-invalid-${index}`));
    }
    assert.equal(disposed, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function makeOwnedSession(root: string, overrides: Partial<CogsPiSessionOptions> = {}) {
  const cwd = resolve(root, "workspace");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  await mkdir(cwd, { recursive: true });
  await mkdir(agentDir, { recursive: true, mode: 0o700 });
  await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
  await chmod(agentDir, 0o700);
  await chmod(sessionRoot, 0o700);
  return createCogsPiSession(
    withDefaults({
      cwd,
      agentDir,
      sessionRoot,
      sessionId: "owned-session",
      model: { provider: "anthropic", id: "claude-sonnet-4-5" },
      apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
      toolPorts: fakePorts([]),
      streamFn: oneTextStream("owned ok"),
      ownedRuntime: { enabled: true, requireEmptyRoots: true },
      ...overrides,
    }),
  );
}

async function assertGone(path: string): Promise<void> {
  await assert.rejects(lstat(path), { code: "ENOENT" });
}

async function ownedMarkerForTest(path: string, kind: "file" | "dir"): Promise<InternalCogsPiOwnedMarker> {
  const stat = await lstat(path, { bigint: true });
  return Object.freeze({
    path,
    dev: stat.dev,
    ino: stat.ino,
    mode: Number(stat.mode) & 0o777,
    nlink: BigInt(stat.nlink),
    size: BigInt(stat.size),
    mtimeNs: statNsForTest(stat, "mtime"),
    ctimeNs: statNsForTest(stat, "ctime"),
    kind,
  });
}

function statNsForTest(stat: Awaited<ReturnType<typeof lstat>>, prefix: "mtime" | "ctime"): bigint {
  const keyed = stat as unknown as Record<string, unknown>;
  const ns = keyed[`${prefix}Ns`];
  if (typeof ns === "bigint") return ns;
  const ms = prefix === "mtime" ? stat.mtimeMs : stat.ctimeMs;
  if (typeof ms === "bigint") return ms * 1_000_000n;
  return BigInt(Math.trunc(Number(ms) * 1_000_000));
}

async function makeTrackedOwnedRuntime(
  root: string,
  hook?: { readonly after: (stage: string) => void | Promise<void> },
) {
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  const sessionDir = resolve(sessionRoot, "owned-session");
  await mkdir(agentDir, { recursive: true, mode: 0o700 });
  await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
  const tracker = createCogsPiOwnedRuntimeTracker({
    agentDir,
    sessionRoot,
    sessionId: "owned-session",
    options: { enabled: true, requireEmptyRoots: true, cleanupDeadlineMs: 120 },
    ...(hook === undefined ? {} : { testHook: hook }),
  });
  await tracker.begin();
  await mkdir(sessionDir, { mode: 0o700 });
  await tracker.adoptSessionDir(sessionDir);
  const file = resolve(sessionDir, "owned.jsonl");
  await writeFile(file, '{"type":"session"}\n', { mode: 0o600, flag: "wx" });
  await tracker.recordSessionFile(await ownedMarkerForTest(file, "file"));
  return { agentDir, sessionRoot, sessionDir, file, tracker };
}

test("Pi owned runtime final cleanup removes exact empty roots and is idempotent", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-empty-"));
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  try {
    const adapter = await makeOwnedSession(root);
    const first = adapter.disposeOwnedRuntime();
    assert.equal(first, adapter.disposeOwnedRuntime());
    assert.deepEqual(await first, { version: "cogs.pi-owned-runtime-cleanup/v1alpha1", cleaned: true });
    await assertGone(agentDir);
    await assertGone(sessionRoot);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime retains history/export until final cleanup then removes exact artifacts", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-artifacts-"));
  const sessionRoot = resolve(root, "sessions");
  try {
    const adapter = await makeOwnedSession(root, { preparedResources: hostilePrepared() });
    await adapter.input({ requestId: "owned-run", correlationId: "owned-corr", kind: "prompt", content: "persist" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const sessionFile = adapter.sessionFile();
    assert.ok(sessionFile);
    assert.ok((await adapter.entries({ after: undefined, limit: 10 })).entries.length > 0);
    const descriptor = await adapter.createExport({ requestId: "owned-export", correlationId: "owned-export-corr" });
    assert.equal((descriptor as Record<string, unknown>).sensitive, true);
    await lstat(sessionFile);
    await lstat(resolve(sessionRoot, "owned-session", "exports"));
    await adapter.disposeOwnedRuntime();
    await assertGone(resolve(root, "agent"));
    await assertGone(sessionRoot);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime preserves unknown entries and rejects generically without broad deletion", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-unknown-"));
  const sentinel = resolve(root, "sessions", "owned-session", "unknown.txt");
  try {
    const adapter = await makeOwnedSession(root);
    await writeFile(sentinel, "preserve", { flag: "wx" });
    await assert.rejects(adapter.disposeOwnedRuntime(), /owned runtime cleanup failed/i);
    assert.equal(await readFile(sentinel, "utf8"), "preserve");
    assert.deepEqual((await readdir(resolve(root, "agent"))).sort(), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime requires explicit empty roots option and rejects nonempty roots", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-roots-"));
  try {
    await assert.rejects(
      makeOwnedSession(root, { ownedRuntime: { enabled: true } as never }),
      /owned runtime cleanup failed/i,
    );
    await mkdir(resolve(root, "agent"), { recursive: true, mode: 0o700 });
    await mkdir(resolve(root, "sessions"), { recursive: true, mode: 0o700 });
    await writeFile(resolve(root, "agent", "unknown.txt"), "x");
    await assert.rejects(makeOwnedSession(root), /owned runtime cleanup failed/i);
    assert.equal(await readFile(resolve(root, "agent", "unknown.txt"), "utf8"), "x");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime accepts controlled JSONL and Git growth across repeated turns", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-growth-"));
  try {
    const notes: CogsGitMapRecord[] = [];
    const adapter = await makeOwnedSession(root, {
      git: {
        repositoryId: "workspace-1",
        observer: fakeObserver(["a".repeat(40), "b".repeat(40), "c".repeat(40), "d".repeat(40)], notes),
      },
    });
    await adapter.input({ requestId: "owned-run-1", correlationId: "owned-corr-1", kind: "prompt", content: "one" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    await adapter.input({ requestId: "owned-run-2", correlationId: "owned-corr-2", kind: "prompt", content: "two" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    assert.ok(notes.length >= 2);
    await adapter.disposeOwnedRuntime();
    await assertGone(resolve(root, "agent"));
    await assertGone(resolve(root, "sessions"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime supports repeated exports after settled backup removal", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-two-export-"));
  try {
    const adapter = await makeOwnedSession(root, { preparedResources: hostilePrepared() });
    await adapter.input({ requestId: "owned-run", correlationId: "owned-corr", kind: "prompt", content: "persist" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const first = await adapter.createExport({ requestId: "owned-export-1", correlationId: "owned-export-corr-1" });
    const second = await adapter.createExport({ requestId: "owned-export-2", correlationId: "owned-export-corr-2" });
    assert.equal((first as { bundle: string }).bundle, (second as { bundle: string }).bundle);
    await adapter.disposeOwnedRuntime();
    await assertGone(resolve(root, "agent"));
    await assertGone(resolve(root, "sessions"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects schema-valid replaced export between repeated exports", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-export-transition-"));
  try {
    const adapter = await makeOwnedSession(root, { preparedResources: hostilePrepared() });
    await adapter.input({ requestId: "owned-run", correlationId: "owned-corr", kind: "prompt", content: "persist" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const first = await adapter.createExport({ requestId: "owned-export-1", correlationId: "owned-export-corr-1" });
    const bundle = resolve(root, "sessions", "owned-session", "exports", (first as { bundle: string }).bundle);
    for (const name of await readdir(bundle)) {
      const path = resolve(bundle, name);
      const bytes = await readFile(path);
      await unlink(path);
      await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
    }
    await assert.rejects(
      adapter.createExport({ requestId: "owned-export-2", correlationId: "owned-export-corr-2" }),
      /local export unavailable/,
    );
    assert.ok((await readdir(bundle)).includes("manifest.json"));
    await assert.rejects(adapter.disposeOwnedRuntime(), /owned runtime cleanup failed/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi session ports never expose owned runtime marker APIs", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-surface-"));
  try {
    const adapter = await makeOwnedSession(root);
    const keys = new Set(Reflect.ownKeys(Object.getPrototypeOf(adapter)).map(String));
    assert.equal(keys.has("recordSessionFile"), false);
    assert.equal(keys.has("recordGitMapFile"), false);
    assert.equal(keys.has("recordExportBundle"), false);
    assert.deepEqual(await adapter.disposeOwnedRuntime(), {
      version: "cogs.pi-owned-runtime-cleanup/v1alpha1",
      cleaned: true,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime failure hook rejects before broad deletion and after joined deletion", async () => {
  const makeArmed = async (name: string, failAt: string) => {
    const root = await mkdtemp(resolve(await realpath(tmpdir()), `cogs-pi-owned-hook-${name}-`));
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    const sessionDir = resolve(sessionRoot, "owned-session");
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    const seen: string[] = [];
    const tracker = createCogsPiOwnedRuntimeTracker({
      agentDir,
      sessionRoot,
      sessionId: "owned-session",
      options: { enabled: true, requireEmptyRoots: true, cleanupDeadlineMs: 100 },
      testHook: Object.freeze({
        after: Object.freeze((stage: string) => {
          seen.push(stage);
          if (stage === failAt) throw new Error("fail");
        }),
      }),
    });
    await tracker.begin();
    await mkdir(sessionDir, { mode: 0o700 });
    await tracker.adoptSessionDir(sessionDir);
    const file = resolve(sessionDir, "owned.jsonl");
    await writeFile(file, '{"type":"session"}\n', { mode: 0o600, flag: "wx" });
    await tracker.recordSessionFile(await ownedMarkerForTest(file, "file"));
    return { root, sessionRoot, sessionDir, file, tracker, seen };
  };

  const preflight = await makeArmed("preflight", "preflight:done");
  try {
    await assert.rejects(
      preflight.tracker.cleanup(async () => undefined),
      /owned runtime cleanup failed/i,
    );
    assert.equal(await readFile(preflight.file, "utf8"), '{"type":"session"}\n');
  } finally {
    await rm(preflight.root, { recursive: true, force: true });
  }

  const afterUnlink = await makeArmed("unlink", "unlink:after");
  try {
    await assert.rejects(
      afterUnlink.tracker.cleanup(async () => undefined),
      /owned runtime cleanup failed/i,
    );
    await assertGone(afterUnlink.file);
    assert.ok(afterUnlink.seen.includes("unlink:after"));
    assert.ok(await lstat(afterUnlink.sessionDir));
  } finally {
    await rm(afterUnlink.root, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects strict test hook anomalies before touching roots", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-hook-shape-"));
  try {
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    let getterInvoked = false;
    const hostile = Object.freeze(
      Object.defineProperty({}, "after", {
        enumerable: true,
        get: () => {
          getterInvoked = true;
          return Object.freeze(() => undefined);
        },
      }),
    ) as { readonly after: (stage: string) => void };
    assert.throws(
      () =>
        createCogsPiOwnedRuntimeTracker({
          agentDir,
          sessionRoot,
          sessionId: "owned-session",
          options: { enabled: true, requireEmptyRoots: true },
          testHook: hostile,
        }),
      /owned runtime cleanup failed/i,
    );
    assert.equal(getterInvoked, false);
    const thenable = () => undefined;
    Object.defineProperty(thenable, `th${"en"}`, { value: Object.freeze(() => undefined) });
    Object.freeze(thenable);
    assert.throws(
      () =>
        createCogsPiOwnedRuntimeTracker({
          agentDir,
          sessionRoot,
          sessionId: "owned-session",
          options: { enabled: true, requireEmptyRoots: true },
          testHook: Object.freeze({ after: thenable }),
        }),
      /owned runtime cleanup failed/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects directory replacement at cleanup preflight without unlink", async () => {
  const cases = ["agent", "root", "session", "export-root", "export-bundle"] as const;
  for (const target of cases) {
    const root = await mkdtemp(resolve(await realpath(tmpdir()), `cogs-pi-owned-dir-race-${target}-`));
    let armed = true;
    try {
      const hook = Object.freeze({
        after: Object.freeze(async (stage: string) => {
          if (!armed || stage !== "preflight:start") return;
          armed = false;
          const sessionDir = resolve(root, "sessions", "owned-session");
          const exports = resolve(sessionDir, "exports");
          const bundle = resolve(exports, "cogs-session-owned-session");
          const replace =
            target === "agent"
              ? resolve(root, "agent")
              : target === "root"
                ? resolve(root, "sessions")
                : target === "session"
                  ? sessionDir
                  : target === "export-root"
                    ? exports
                    : bundle;
          await rm(replace, { recursive: true, force: true });
          await mkdir(replace, { recursive: true, mode: 0o700 });
          await writeFile(resolve(replace, "sentinel.txt"), "preserve", { flag: "wx" });
        }),
      });
      const owned = await makeTrackedOwnedRuntime(root, hook);
      const exports = resolve(owned.sessionDir, "exports");
      const bundle = resolve(exports, "cogs-session-owned-session");
      await mkdir(bundle, { recursive: true, mode: 0o700 });
      const files = [
        "git-map.json",
        "manifest.json",
        "session.jsonl",
        "skills.json",
        "transform-report.json",
        "warnings.json",
      ];
      for (const file of files) await writeFile(resolve(bundle, file), "{}", { mode: 0o600, flag: "wx" });
      await owned.tracker.recordExportBundle({
        root: await ownedMarkerForTest(exports, "dir"),
        bundleDir: await ownedMarkerForTest(bundle, "dir"),
        files: await Promise.all(files.map((file) => ownedMarkerForTest(resolve(bundle, file), "file"))),
      });
      await assert.rejects(
        owned.tracker.cleanup(async () => undefined),
        /owned runtime cleanup failed/i,
      );
      const replace =
        target === "agent"
          ? resolve(root, "agent")
          : target === "root"
            ? resolve(root, "sessions")
            : target === "session"
              ? resolve(root, "sessions", "owned-session")
              : target === "export-root"
                ? resolve(root, "sessions", "owned-session", "exports")
                : resolve(root, "sessions", "owned-session", "exports", "cogs-session-owned-session");
      assert.equal(await readFile(resolve(replace, "sentinel.txt"), "utf8"), "preserve");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Pi owned runtime stage failures cover close fsync rmdir and expired delayed stages", async () => {
  const cases = ["close:after", "fsync:after", "rmdir:before", "unlink:before-expire"] as const;
  for (const failure of cases) {
    const root = await mkdtemp(
      resolve(await realpath(tmpdir()), `cogs-pi-owned-stage-${failure.replace(/[^a-z]/g, "-")}-`),
    );
    const seen: string[] = [];
    try {
      const hook = Object.freeze({
        after: Object.freeze(async (stage: string) => {
          seen.push(stage);
          if (failure === "unlink:before-expire" && stage === "preflight:done")
            await new Promise((resolveTimer) => setTimeout(resolveTimer, 150));
          if (stage === failure) throw new Error("stage failure");
        }),
      });
      const owned = await makeTrackedOwnedRuntime(root, hook);
      await assert.rejects(
        owned.tracker.cleanup(async () => undefined),
        /owned runtime cleanup failed/i,
      );
      if (failure === "fsync:after") await assertGone(owned.file);
      else if (failure === "rmdir:before") assert.ok(await lstat(owned.sessionDir));
      else assert.equal(await readFile(owned.file, "utf8"), '{"type":"session"}\n');
      assert.ok(seen.length > 0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Pi owned runtime explicitly adopts contained resumed JSONL and cleans it after append", async () => {
  const sourceRoot = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-resume-source-"));
  const ownedRoot = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-resume-adopt-"));
  try {
    const sourceCwd = resolve(sourceRoot, "workspace");
    const sourceAgent = resolve(sourceRoot, "agent");
    const sourceSessionRoot = resolve(sourceRoot, "sessions");
    await mkdir(sourceCwd, { recursive: true });
    await mkdir(sourceAgent, { recursive: true, mode: 0o700 });
    await mkdir(sourceSessionRoot, { recursive: true, mode: 0o700 });
    const source = await createCogsPiSession(
      withDefaults({
        cwd: sourceCwd,
        agentDir: sourceAgent,
        sessionRoot: sourceSessionRoot,
        sessionId: "owned-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("resume source ok"),
      }),
    );
    await source.input({
      requestId: "resume-source",
      correlationId: "resume-source-corr",
      kind: "prompt",
      content: "persist",
    });
    await eventually(async () => assert.equal((await source.state()).runState, "settled"));
    const sourceFile = source.sessionFile();
    assert.ok(sourceFile);
    const sourceEntries = (await source.entries({ after: undefined, limit: 20 })).entries.length;
    await source.dispose();

    const ownedAgent = resolve(ownedRoot, "agent");
    const ownedSessionRoot = resolve(ownedRoot, "sessions");
    const ownedSessionDir = resolve(ownedSessionRoot, "owned-session");
    await mkdir(ownedAgent, { recursive: true, mode: 0o700 });
    await mkdir(ownedSessionDir, { recursive: true, mode: 0o700 });
    await chmod(ownedAgent, 0o700);
    await chmod(ownedSessionRoot, 0o700);
    await chmod(ownedSessionDir, 0o700);
    const resumeName = basename(sourceFile);
    const ownedResume = resolve(ownedSessionDir, resumeName);
    await cp(sourceFile, ownedResume);
    await chmod(ownedResume, 0o644);
    const preSecureIdentity = await ownedMarkerForTest(ownedResume, "file");

    const ownedCwd = resolve(ownedRoot, "workspace");
    await mkdir(ownedCwd, { recursive: true });
    const resumed = await createCogsPiSession(
      withDefaults({
        cwd: ownedCwd,
        agentDir: ownedAgent,
        sessionRoot: ownedSessionRoot,
        sessionId: "owned-session",
        resumeFile: resumeName,
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
        streamFn: oneTextStream("resume append ok"),
        ownedRuntime: { enabled: true, requireEmptyRoots: true },
      }),
    );
    assert.equal(resumed.sessionFile(), ownedResume);
    const securedIdentity = await ownedMarkerForTest(ownedResume, "file");
    assert.equal(securedIdentity.dev, preSecureIdentity.dev);
    assert.equal(securedIdentity.ino, preSecureIdentity.ino);
    assert.equal(securedIdentity.mode, 0o600);
    assert.ok((await resumed.entries({ after: undefined, limit: 30 })).entries.length >= sourceEntries);
    await resumed.input({
      requestId: "resume-owned",
      correlationId: "resume-owned-corr",
      kind: "prompt",
      content: "append",
    });
    await eventually(async () => assert.equal((await resumed.state()).runState, "settled"));
    assert.ok((await resumed.entries({ after: undefined, limit: 40 })).entries.length > sourceEntries);
    await resumed.disposeOwnedRuntime();
    await assertGone(ownedAgent);
    await assertGone(ownedSessionRoot);
    assert.ok(await lstat(sourceFile));
  } finally {
    await rm(sourceRoot, { recursive: true, force: true });
    await rm(ownedRoot, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects hostile explicit resumed JSONL adoption before mutation", async () => {
  const cases = [
    "extra-agent",
    "extra-session-root",
    "extra-session-file",
    "symlink",
    "hardlink",
    "wrong-mode",
    "replace",
  ] as const;
  for (const hazard of cases) {
    const root = await mkdtemp(resolve(await realpath(tmpdir()), `cogs-pi-owned-resume-${hazard}-`));
    try {
      const agentDir = resolve(root, "agent");
      const sessionRoot = resolve(root, "sessions");
      const sessionDir = resolve(sessionRoot, "owned-session");
      const resumeName = "resume.jsonl";
      const resumePath = resolve(sessionDir, resumeName);
      await mkdir(agentDir, { recursive: true, mode: 0o700 });
      await mkdir(sessionDir, { recursive: true, mode: 0o700 });
      await writeFile(
        resumePath,
        '{"type":"session","version":3,"id":"owned-session","timestamp":"2026-07-17T00:00:00.000Z","cwd":"/workspace"}\n',
        { mode: 0o644, flag: "wx" },
      );
      const sentinel = resolve(root, "sentinel.txt");
      await writeFile(sentinel, "preserve", { flag: "wx" });
      if (hazard === "extra-agent") await writeFile(resolve(agentDir, "extra.txt"), "x", { flag: "wx" });
      else if (hazard === "extra-session-root") await mkdir(resolve(sessionRoot, "other-session"), { mode: 0o700 });
      else if (hazard === "extra-session-file")
        await writeFile(resolve(sessionDir, "other.jsonl"), "{}\n", { flag: "wx" });
      else if (hazard === "symlink") {
        await unlink(resumePath);
        await symlink(sentinel, resumePath);
      } else if (hazard === "hardlink") await link(resumePath, resolve(sessionDir, "linked.jsonl"));
      else if (hazard === "wrong-mode") await chmod(resumePath, 0o666);

      if (hazard === "replace") {
        await chmod(resumePath, 0o600);
        const tracker = createCogsPiOwnedRuntimeTracker({
          agentDir,
          sessionRoot,
          sessionId: "owned-session",
          resumeFile: resumeName,
          options: { enabled: true, requireEmptyRoots: true },
        });
        await tracker.begin();
        await unlink(resumePath);
        await writeFile(resumePath, '{"type":"session"}\n', { mode: 0o600, flag: "wx" });
        await assert.rejects(
          tracker.recordSessionFile(await ownedMarkerForTest(resumePath, "file")),
          /owned runtime cleanup failed/i,
        );
      } else {
        const cwd = resolve(root, "workspace");
        await mkdir(cwd, { recursive: true });
        await assert.rejects(
          createCogsPiSession(
            withDefaults({
              cwd,
              agentDir,
              sessionRoot,
              sessionId: "owned-session",
              resumeFile: resumeName,
              model: { provider: "anthropic", id: "claude-sonnet-4-5" },
              apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
              toolPorts: fakePorts([]),
              streamFn: oneTextStream("resume hostile"),
              ownedRuntime: { enabled: true, requireEmptyRoots: true },
            }),
          ),
          /owned runtime cleanup failed|invalid session/i,
        );
      }
      assert.equal(await readFile(sentinel, "utf8"), "preserve");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Pi owned runtime rejects owner-marker callback path replacements", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-marker-race-"));
  try {
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    const sessionDir = resolve(sessionRoot, "owned-session");
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    const tracker = createCogsPiOwnedRuntimeTracker({
      agentDir,
      sessionRoot,
      sessionId: "owned-session",
      options: { enabled: true, requireEmptyRoots: true },
    });
    await tracker.begin();
    await mkdir(sessionDir, { mode: 0o700 });
    await tracker.adoptSessionDir(sessionDir);
    const gitMap = resolve(sessionDir, "git-map.jsonl");
    await writeFile(gitMap, "{}\n", { mode: 0o600, flag: "wx" });
    const gitOwner = await ownedMarkerForTest(gitMap, "file");
    await unlink(gitMap);
    await writeFile(gitMap, "{}\n", { mode: 0o600, flag: "wx" });
    await assert.rejects(tracker.recordGitMapFile(gitOwner), /owned runtime cleanup failed/i);
    const replacementOwner = await ownedMarkerForTest(gitMap, "file");
    await assert.rejects(
      tracker.recordGitMapFile(
        Object.freeze({
          ...replacementOwner,
          mtimeNs: gitOwner.mtimeNs,
          ctimeNs: gitOwner.ctimeNs,
        }),
      ),
      /owned runtime cleanup failed/i,
    );

    const exports = resolve(sessionDir, "exports");
    const bundle = resolve(exports, "cogs-session-owned-session");
    await mkdir(bundle, { recursive: true, mode: 0o700 });
    const files = [
      "git-map.json",
      "manifest.json",
      "session.jsonl",
      "skills.json",
      "transform-report.json",
      "warnings.json",
    ];
    for (const file of files) await writeFile(resolve(bundle, file), "{}", { mode: 0o600, flag: "wx" });
    const ledger = {
      root: await ownedMarkerForTest(exports, "dir"),
      bundleDir: await ownedMarkerForTest(bundle, "dir"),
      files: await Promise.all(files.map((file) => ownedMarkerForTest(resolve(bundle, file), "file"))),
    };
    await unlink(resolve(bundle, "warnings.json"));
    await writeFile(resolve(bundle, "warnings.json"), "{}", { mode: 0o600, flag: "wx" });
    await assert.rejects(tracker.recordExportBundle(ledger), /owned runtime cleanup failed/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects replacements and preserves matching attacker export names", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-replace-"));
  try {
    const adapter = await makeOwnedSession(root, { preparedResources: hostilePrepared() });
    await adapter.input({ requestId: "owned-run", correlationId: "owned-corr", kind: "prompt", content: "persist" });
    await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
    const descriptor = await adapter.createExport({ requestId: "owned-export", correlationId: "owned-export-corr" });
    const sessionFile = adapter.sessionFile();
    assert.ok(sessionFile);
    const bundle = resolve(root, "sessions", "owned-session", "exports", (descriptor as { bundle: string }).bundle);
    const attacker = resolve(bundle, "warnings.json");
    await unlink(attacker);
    await writeFile(attacker, "attacker replacement", { flag: "wx" });
    await assert.rejects(adapter.disposeOwnedRuntime(), /owned runtime cleanup failed/i);
    assert.equal(await readFile(attacker, "utf8"), "attacker replacement");
    assert.ok((await readdir(bundle)).includes("manifest.json"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects JSONL, Git map, file type, hardlink, and unknown-level hazards", async () => {
  const cases = [
    "jsonl-replace",
    "jsonl-shrink",
    "gitmap-replace",
    "symlink",
    "fifo",
    "hardlink",
    "wrong-mode",
    "unknown-root",
    "unknown-export",
  ] as const;
  for (const hazard of cases) {
    const root = await mkdtemp(resolve(await realpath(tmpdir()), `cogs-pi-owned-${hazard}-`));
    try {
      const notes: CogsGitMapRecord[] = [];
      const adapter = await makeOwnedSession(root, {
        ...(hazard === "gitmap-replace"
          ? { git: { repositoryId: "workspace-1", observer: fakeObserver(["a".repeat(40), "b".repeat(40)], notes) } }
          : {}),
        ...(hazard === "unknown-export" ? { preparedResources: hostilePrepared() } : {}),
      });
      await adapter.input({ requestId: "owned-run", correlationId: "owned-corr", kind: "prompt", content: "persist" });
      await eventually(async () => assert.equal((await adapter.state()).runState, "settled"));
      const descriptor =
        hazard === "unknown-export"
          ? await adapter.createExport({ requestId: "owned-export", correlationId: "owned-export-corr" })
          : undefined;
      const sessionDir = resolve(root, "sessions", "owned-session");
      const sessionFile = adapter.sessionFile();
      assert.ok(sessionFile);
      const bundle =
        descriptor === undefined
          ? undefined
          : resolve(sessionDir, "exports", (descriptor as { bundle: string }).bundle);
      if (hazard === "jsonl-replace") {
        await unlink(sessionFile);
        await writeFile(sessionFile, "{}\n", { flag: "wx" });
      } else if (hazard === "jsonl-shrink") {
        await writeFile(sessionFile, "", { flag: "w" });
      } else if (hazard === "gitmap-replace") {
        await unlink(resolve(sessionDir, "git-map.jsonl"));
        await writeFile(resolve(sessionDir, "git-map.jsonl"), "attacker\n", { flag: "wx" });
      } else if (hazard === "symlink") {
        await symlink(sessionFile, resolve(sessionDir, "unknown-link"));
      } else if (hazard === "fifo") {
        await execFileAsync("mkfifo", [resolve(sessionDir, "unknown-fifo")]);
      } else if (hazard === "hardlink") {
        await link(sessionFile, resolve(sessionDir, "unknown-hardlink"));
      } else if (hazard === "wrong-mode") {
        await chmod(sessionFile, 0o666);
      } else if (hazard === "unknown-root") {
        await writeFile(resolve(root, "sessions", "unknown.txt"), "preserve", { flag: "wx" });
      } else {
        assert.ok(bundle);
        await writeFile(resolve(bundle, "unknown.txt"), "preserve", { flag: "wx" });
      }
      await assert.rejects(adapter.disposeOwnedRuntime(), /owned runtime cleanup failed/i);
      assert.equal(
        JSON.stringify(await adapter.disposeOwnedRuntime().catch((error: unknown) => error)).includes(sessionDir),
        false,
      );
      assert.ok(await lstat(sessionDir));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Pi owned runtime rollback is exact and final cleanup is same-promise during dispose", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-rollback-"));
  const denyEnable = Object.freeze((input: unknown) => {
    const allow = (input as { action?: unknown }).action !== "tool.enable";
    return Object.freeze({
      version: "cogs.policy-decision/v1alpha1" as const,
      decision_id: `sha256:${"c".repeat(64)}` as const,
      allow,
      reason: allow ? ("allowed" as const) : ("unsupported_surface" as const),
    });
  });
  try {
    await assert.rejects(
      makeOwnedSession(root, { policyAuthorizer: denyEnable }),
      /Pi session cleanup failed|policy denied|unsupported/i,
    );
    await assertGone(resolve(root, "agent"));
    await assertGone(resolve(root, "sessions"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }

  const concurrentRoot = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-concurrent-"));
  try {
    const adapter = await makeOwnedSession(concurrentRoot);
    const normalDispose = adapter.dispose();
    const owned = adapter.disposeOwnedRuntime();
    assert.equal(owned, adapter.disposeOwnedRuntime());
    await normalDispose;
    assert.deepEqual(await owned, { version: "cogs.pi-owned-runtime-cleanup/v1alpha1", cleaned: true });
    await assertGone(resolve(concurrentRoot, "agent"));
    await assertGone(resolve(concurrentRoot, "sessions"));
  } finally {
    await rm(concurrentRoot, { recursive: true, force: true });
  }
});

test("non-owned Pi session dispose retains host runtime directories", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-non-owned-retain-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    const adapter = await createCogsPiSession(
      withDefaults({
        cwd,
        agentDir,
        sessionRoot,
        sessionId: "non-owned-session",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
        toolPorts: fakePorts([]),
      }),
    );
    await adapter.dispose();
    assert.ok(await lstat(agentDir));
    assert.ok(await lstat(sessionRoot));
    await assert.rejects(adapter.disposeOwnedRuntime(), /Pi owned runtime cleanup failed/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi owned runtime rejects hostile option shapes before creating roots", async () => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), "cogs-pi-owned-hostile-"));
  try {
    const cwd = resolve(root, "workspace");
    const agentDir = resolve(root, "agent");
    const sessionRoot = resolve(root, "sessions");
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    await chmod(agentDir, 0o700);
    await chmod(sessionRoot, 0o700);
    const hostile = Object.create(null, {
      enabled: {
        enumerable: true,
        get() {
          throw new Error("SECRET_HOSTILE_OWNED_RUNTIME");
        },
      },
    });
    await assert.rejects(
      createCogsPiSession(
        withDefaults({
          cwd,
          agentDir,
          sessionRoot,
          sessionId: "owned-session",
          model: { provider: "anthropic", id: "claude-sonnet-4-5" },
          apiKey: "COGS_RUNTIME_ONLY_TEST_KEY",
          toolPorts: fakePorts([]),
          ownedRuntime: hostile as CogsPiSessionOptions["ownedRuntime"] & {},
        }),
      ),
      (error: unknown) => {
        assert.equal(String(error).includes("SECRET_HOSTILE_OWNED_RUNTIME"), false);
        return true;
      },
    );
    assert.deepEqual(await readdir(agentDir), []);
    assert.deepEqual(await readdir(sessionRoot), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
