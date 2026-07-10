import type { StreamFn } from "@earendil-works/pi-agent-core";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import { type AssistantMessage, getModel } from "@earendil-works/pi-ai/compat";
import {
  AuthStorage,
  createAgentSession,
  createExtensionRuntime,
  defineTool,
  ModelRegistry,
  type ResourceLoader,
  type SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

export const SPIKE_API_KEY = "COGS_NON_SECRET_RUNTIME_KEY";
export const SPIKE_TOOL_NAMES = ["read", "write", "edit", "bash"] as const;

export interface FakeModelState {
  calls: number;
  observedApiKeys: Array<string | undefined>;
}

export interface SpikeSessionResult {
  session: Awaited<ReturnType<typeof createAgentSession>>["session"];
  authStorage: AuthStorage;
  fakeModelState: FakeModelState;
  executedTools: string[];
}

function assistantMessage(modelId: string, content: AssistantMessage["content"], stopReason: "stop" | "toolUse") {
  return {
    role: "assistant",
    content,
    api: "anthropic-messages",
    provider: "anthropic",
    model: modelId,
    usage: {
      input: 1,
      output: 1,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 2,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason,
    timestamp: Date.now(),
  } satisfies AssistantMessage;
}

export function createFakeModelStream(state: FakeModelState): StreamFn {
  return (model, _context, options) => {
    state.calls += 1;
    state.observedApiKeys.push(options?.apiKey);
    const stream = createAssistantMessageEventStream();
    const message =
      state.calls === 1
        ? assistantMessage(
            model.id,
            [{ type: "toolCall", id: "fake-call-1", name: "read", arguments: { path: "/workspace/README.md" } }],
            "toolUse",
          )
        : assistantMessage(
            model.id,
            [{ type: "text", text: "Fake model completed after the stub tool result." }],
            "stop",
          );

    queueMicrotask(() => {
      stream.push({ type: "start", partial: message });
      if (state.calls === 1) {
        const toolCall = message.content[0];
        if (toolCall?.type !== "toolCall") throw new Error("fake tool call was not constructed");
        stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
        stream.push({ type: "toolcall_end", contentIndex: 0, toolCall, partial: message });
      } else {
        const text = message.content[0];
        if (text?.type !== "text") throw new Error("fake text response was not constructed");
        stream.push({ type: "text_start", contentIndex: 0, partial: message });
        stream.push({ type: "text_delta", contentIndex: 0, delta: text.text, partial: message });
        stream.push({ type: "text_end", contentIndex: 0, content: text.text, partial: message });
      }
      stream.push({ type: "done", reason: message.stopReason, message });
      stream.end();
    });
    return stream;
  };
}

export function createLockedResourceLoader(): ResourceLoader {
  const extensionRuntime = createExtensionRuntime();
  return {
    getExtensions: () => ({ extensions: [], errors: [], runtime: extensionRuntime }),
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () => "You are a deterministic Stage 0 test agent. Use only the explicitly supplied stub tools.",
    getAppendSystemPrompt: () => [],
    extendResources: () => {},
    reload: async () => {},
  };
}

function createStubTools(executedTools: string[]) {
  const result = (name: string) => {
    executedTools.push(name);
    return { content: [{ type: "text" as const, text: `harmless ${name} stub executed` }], details: { stub: true } };
  };

  return [
    defineTool({
      name: "read",
      label: "Read stub",
      description: "Harmless Stage 0 read stub",
      parameters: Type.Object({ path: Type.String() }, { additionalProperties: false }),
      execute: async () => result("read"),
    }),
    defineTool({
      name: "write",
      label: "Write stub",
      description: "Harmless Stage 0 write stub",
      parameters: Type.Object({ path: Type.String(), content: Type.String() }, { additionalProperties: false }),
      execute: async () => result("write"),
    }),
    defineTool({
      name: "edit",
      label: "Edit stub",
      description: "Harmless Stage 0 edit stub",
      parameters: Type.Object(
        { path: Type.String(), oldText: Type.String(), newText: Type.String() },
        { additionalProperties: false },
      ),
      execute: async () => result("edit"),
    }),
    defineTool({
      name: "bash",
      label: "Bash stub",
      description: "Harmless Stage 0 bash stub",
      parameters: Type.Object({ command: Type.String() }, { additionalProperties: false }),
      execute: async () => result("bash"),
    }),
  ];
}

export async function createSpikeSession(
  sessionManager: SessionManager,
  cwd: string,
  agentDir: string,
): Promise<SpikeSessionResult> {
  const authStorage = AuthStorage.inMemory();
  authStorage.setRuntimeApiKey("anthropic", SPIKE_API_KEY);
  const modelRegistry = ModelRegistry.inMemory(authStorage);
  const model = getModel("anthropic", "claude-sonnet-4-5");
  if (!model) throw new Error("Pinned Pi catalog does not contain the spike model");

  const executedTools: string[] = [];
  const fakeModelState: FakeModelState = { calls: 0, observedApiKeys: [] };
  const { session } = await createAgentSession({
    cwd,
    agentDir,
    model,
    thinkingLevel: "off",
    authStorage,
    modelRegistry,
    resourceLoader: createLockedResourceLoader(),
    customTools: createStubTools(executedTools),
    tools: [...SPIKE_TOOL_NAMES],
    noTools: "builtin",
    sessionManager,
    settingsManager: SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false } }),
  });

  const fakeStream = createFakeModelStream(fakeModelState);
  session.agent.streamFn = async (activeModel, context, options) => {
    const apiKey = await authStorage.getApiKey(activeModel.provider);
    if (!apiKey) throw new Error("fake stream did not receive the runtime API key");
    return fakeStream(activeModel, context, { ...options, apiKey });
  };
  return { session, authStorage, fakeModelState, executedTools };
}
