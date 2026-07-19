import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import test from "node:test";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import type { AssistantMessageEvent, Context, Model } from "@earendil-works/pi-ai";
import {
  createDeterministicLauncherStream,
  LAUNCHER_DETERMINISTIC_ABORT_PROMPT,
  LAUNCHER_DETERMINISTIC_API,
  LAUNCHER_DETERMINISTIC_FINAL_TEXT,
  LAUNCHER_DETERMINISTIC_MODEL_ID,
  LAUNCHER_DETERMINISTIC_NORMAL_PROMPT,
  LAUNCHER_DETERMINISTIC_PROVIDER,
  LAUNCHER_DETERMINISTIC_TOOL_ARGUMENTS,
  LAUNCHER_DETERMINISTIC_TOOL_ID,
  LAUNCHER_DETERMINISTIC_TOOL_NAME,
  LAUNCHER_DETERMINISTIC_UNKNOWN_TEXT,
} from "../dev/launcher/deterministic-stream.ts";

const TIMESTAMP = 1_800_000_000_000;

function model(overrides: Partial<Model<"anthropic-messages">> = {}): Model<"anthropic-messages"> {
  return {
    id: LAUNCHER_DETERMINISTIC_MODEL_ID,
    name: "Claude Sonnet 4.5",
    api: LAUNCHER_DETERMINISTIC_API,
    provider: LAUNCHER_DETERMINISTIC_PROVIDER,
    baseUrl: "https://example.invalid",
    reasoning: true,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 1,
    maxTokens: 1,
    ...overrides,
  };
}

function options(controller = new AbortController(), apiKey = "test-key") {
  return { apiKey, signal: controller.signal };
}

function normalContext(): Context {
  return { messages: [{ role: "user", content: LAUNCHER_DETERMINISTIC_NORMAL_PROMPT, timestamp: TIMESTAMP }] };
}

function unknownContext(prompt = "unrecognized bounded prompt"): Context {
  return { messages: [{ role: "user", content: prompt, timestamp: TIMESTAMP }] };
}

function abortContext(): Context {
  return { messages: [{ role: "user", content: LAUNCHER_DETERMINISTIC_ABORT_PROMPT, timestamp: TIMESTAMP }] };
}

function matchingFinalContext(): Context {
  return {
    messages: [
      { role: "user", content: LAUNCHER_DETERMINISTIC_NORMAL_PROMPT, timestamp: TIMESTAMP },
      {
        role: "assistant",
        api: LAUNCHER_DETERMINISTIC_API,
        provider: LAUNCHER_DETERMINISTIC_PROVIDER,
        model: LAUNCHER_DETERMINISTIC_MODEL_ID,
        content: [
          {
            type: "toolCall",
            id: LAUNCHER_DETERMINISTIC_TOOL_ID,
            name: LAUNCHER_DETERMINISTIC_TOOL_NAME,
            arguments: { command: "ignored-by-validator" },
          },
        ],
        usage: zeroUsage(),
        stopReason: "toolUse",
        timestamp: TIMESTAMP,
      },
      {
        role: "toolResult",
        toolCallId: LAUNCHER_DETERMINISTIC_TOOL_ID,
        toolName: LAUNCHER_DETERMINISTIC_TOOL_NAME,
        content: [{ type: "text", text: "tool output is not reflected" }],
        isError: false,
        timestamp: TIMESTAMP,
      },
    ],
  };
}

function zeroUsage() {
  return {
    input: 0,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
}

async function collect(stream: Awaited<ReturnType<StreamFn>>): Promise<AssistantMessageEvent[]> {
  const events: AssistantMessageEvent[] = [];
  for await (const event of stream) events.push(event);
  return events;
}

async function collectWithTimeout(
  stream: Awaited<ReturnType<StreamFn>>,
  timeoutMs = 25,
): Promise<AssistantMessageEvent[] | "timeout"> {
  return Promise.race([
    collect(stream),
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), timeoutMs)),
  ]);
}

async function resultWithTimeout(
  stream: Awaited<ReturnType<StreamFn>>,
  timeoutMs = 100,
): Promise<Awaited<ReturnType<typeof stream.result>> | "timeout"> {
  return Promise.race([
    stream.result(),
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), timeoutMs)),
  ]);
}

function stream(clock = () => TIMESTAMP): StreamFn {
  return createDeterministicLauncherStream(Object.freeze({ now: clock }));
}

async function eventsFor(context: Context, initOptions = options()) {
  return collect(await stream()(model(), context, initOptions));
}

function assertGenericError(events: AssistantMessageEvent[]): void {
  assert.equal(events.length, 1);
  assert.equal(events[0]?.type, "error");
  if (events[0]?.type !== "error") throw new Error("expected error");
  assert.equal(events[0].reason, "error");
  assert.equal(events[0].error.errorMessage, "launcher deterministic stream failed");
  assert.equal(events[0].error.model, LAUNCHER_DETERMINISTIC_MODEL_ID);
}

test("deterministic stream emits exact first-turn tool event order and values", async () => {
  const events = await eventsFor(normalContext());
  assert.deepEqual(
    events.map((event) => event.type),
    ["start", "toolcall_start", "toolcall_end", "done"],
  );
  const done = events[3];
  assert.equal(done?.type, "done");
  if (done?.type !== "done") throw new Error("expected done");
  assert.equal(done.reason, "toolUse");
  assert.equal(done.message.api, LAUNCHER_DETERMINISTIC_API);
  assert.equal(done.message.provider, LAUNCHER_DETERMINISTIC_PROVIDER);
  assert.equal(done.message.model, LAUNCHER_DETERMINISTIC_MODEL_ID);
  assert.equal(done.message.timestamp, TIMESTAMP);
  assert.deepEqual(done.message.usage, zeroUsage());
  assert.equal(done.message.stopReason, "toolUse");
  assert.deepEqual(done.message.content, [
    {
      type: "toolCall",
      id: LAUNCHER_DETERMINISTIC_TOOL_ID,
      name: LAUNCHER_DETERMINISTIC_TOOL_NAME,
      arguments: LAUNCHER_DETERMINISTIC_TOOL_ARGUMENTS,
    },
  ]);
  assert.equal(Object.isFrozen(done.message), true);
  assert.equal(Object.isFrozen(done.message.content), true);
  assert.equal(Object.isFrozen(done.message.content[0]), true);
  assert.equal(Object.isFrozen(done.message.usage), true);
  assert.equal(Object.isFrozen(done.message.usage.cost), true);
  const emittedToolCall = done.message.content[0];
  assert.equal(emittedToolCall?.type, "toolCall");
  if (emittedToolCall?.type === "toolCall") {
    assert.equal(Object.isFrozen(emittedToolCall.arguments), true);
    assert.throws(() => {
      (emittedToolCall.arguments as { command: string }).command = "mutated";
    }, TypeError);
  }
  const toolEnd = events[2];
  assert.equal(toolEnd?.type, "toolcall_end");
  if (toolEnd?.type === "toolcall_end") assert.deepEqual(toolEnd.toolCall, done.message.content[0]);
});

test("deterministic stream emits exact matching second-turn text event order", async () => {
  const events = await eventsFor(matchingFinalContext());
  assert.deepEqual(
    events.map((event) => event.type),
    ["start", "text_start", "text_delta", "text_end", "done"],
  );
  assert.equal(events[2]?.type, "text_delta");
  if (events[2]?.type === "text_delta") assert.equal(events[2].delta, LAUNCHER_DETERMINISTIC_FINAL_TEXT);
  assert.equal(events[3]?.type, "text_end");
  if (events[3]?.type === "text_end") assert.equal(events[3].content, LAUNCHER_DETERMINISTIC_FINAL_TEXT);
  const done = events[4];
  assert.equal(done?.type, "done");
  if (done?.type !== "done") throw new Error("expected done");
  assert.equal(done.reason, "stop");
  assert.equal(done.message.stopReason, "stop");
  assert.deepEqual(done.message.content, [{ type: "text", text: LAUNCHER_DETERMINISTIC_FINAL_TEXT }]);
});

test("deterministic stream returns metadata-safe fixed unknown prompt response", async () => {
  const secretPrompt = "unknown prompt with api-key-like secret api-key-sensitive and path /secret";
  const events = await eventsFor(unknownContext(secretPrompt));
  assert.deepEqual(
    events.map((event) => event.type),
    ["start", "text_start", "text_delta", "text_end", "done"],
  );
  const serialized = JSON.stringify(events);
  assert.match(serialized, new RegExp(LAUNCHER_DETERMINISTIC_UNKNOWN_TEXT));
  assert.doesNotMatch(serialized, /api-key-sensitive|\/secret|unknown prompt with/);
});

test("deterministic abort mode waits for later abort and removes its listener", async () => {
  const controller = new AbortController();
  let added = 0;
  let removed = 0;
  const originalAdd = controller.signal.addEventListener.bind(controller.signal);
  const originalRemove = controller.signal.removeEventListener.bind(controller.signal);
  Object.defineProperty(controller.signal, "addEventListener", {
    value: (...args: Parameters<AbortSignal["addEventListener"]>) => {
      if (args[0] === "abort") added += 1;
      return originalAdd(...args);
    },
  });
  Object.defineProperty(controller.signal, "removeEventListener", {
    value: (...args: Parameters<AbortSignal["removeEventListener"]>) => {
      if (args[0] === "abort") removed += 1;
      return originalRemove(...args);
    },
  });
  const pending = await stream()(model(), abortContext(), options(controller));
  assert.equal(await collectWithTimeout(pending), "timeout");
  assert.equal(await resultWithTimeout(pending, 25), "timeout");
  assert.equal(added, 0);
  assert.equal(getEventListeners(controller.signal, "abort").length, 1);
  controller.abort();
  assert.deepEqual(await collectWithTimeout(pending, 100), []);
  const result = await resultWithTimeout(pending);
  assert.notEqual(result, "timeout");
  if (result === "timeout") throw new Error("expected result");
  assert.equal(result.stopReason, "aborted");
  assert.equal(result.api, LAUNCHER_DETERMINISTIC_API);
  assert.equal(result.provider, LAUNCHER_DETERMINISTIC_PROVIDER);
  assert.equal(result.model, LAUNCHER_DETERMINISTIC_MODEL_ID);
  assert.equal(result.errorMessage, "launcher deterministic stream failed");
  assert.equal(removed, 0);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("deterministic abort mode pre-aborted signal terminates immediately without listener", async () => {
  const controller = new AbortController();
  controller.abort();
  let added = 0;
  Object.defineProperty(controller.signal, "addEventListener", {
    value: (..._args: Parameters<AbortSignal["addEventListener"]>) => {
      added += 1;
    },
  });
  const pending = await stream()(model(), abortContext(), options(controller));
  assert.deepEqual(await collectWithTimeout(pending, 100), []);
  const result = await resultWithTimeout(pending);
  assert.notEqual(result, "timeout");
  if (result === "timeout") throw new Error("expected result");
  assert.equal(result.stopReason, "aborted");
  assert.equal(result.errorMessage, "launcher deterministic stream failed");
  assert.equal(added, 0);
});

test("deterministic stream accepts realistic config-spread options without reading unrelated values", async () => {
  let callbackCalled = false;
  const controller = new AbortController();
  const configSpreadOptions = {
    apiKey: "test-key",
    signal: controller.signal,
    reasoning: "low",
    sessionId: "session-1",
    transport: "auto",
    cacheRetention: "short",
    temperature: 0,
    maxTokens: 16,
    headers: { "x-test": "metadata-only" },
    env: { COGS_TEST: "1" },
    metadata: { user_id: "launcher-test" },
    timeoutMs: 1000,
    maxRetries: 0,
    maxRetryDelayMs: 1,
    thinkingBudgets: { low: 1 },
    onPayload: () => {
      callbackCalled = true;
    },
    onResponse: () => {
      callbackCalled = true;
    },
    toolExecutionMode: "sequential",
    convertToLlm: () => {
      callbackCalled = true;
      return [];
    },
  };
  const events = await collect(await stream()(model(), normalContext(), configSpreadOptions as never));
  assert.equal(events.at(-1)?.type, "done");
  assert.equal(callbackCalled, false);
  assert.doesNotMatch(JSON.stringify(events), /metadata-only|launcher-test|session-1|COGS_TEST/);
});

test("deterministic stream validates model and API key contract generically", async () => {
  for (const badModel of [
    model({ provider: "openai" }),
    model({ api: "openai-responses" as "anthropic-messages" }),
    model({ id: "claude-other" }),
  ]) {
    assertGenericError(await collect(await stream()(badModel, normalContext(), options())));
  }
  for (const badOptions of [
    undefined,
    {},
    { apiKey: "", signal: new AbortController().signal },
    { apiKey: "x".repeat(4097), signal: new AbortController().signal },
  ]) {
    assertGenericError(await collect(await stream()(model(), normalContext(), badOptions as never)));
  }
});

test("deterministic stream rejects malformed context, bounds, duplicate and wrong tool cases", async () => {
  const tooManyMessages = { messages: Array.from({ length: 5 }, () => normalContext().messages[0]) };
  const wrongToolId = matchingFinalContext();
  (wrongToolId.messages[2] as { toolCallId: string }).toolCallId = "wrong";
  const wrongToolName = matchingFinalContext();
  (wrongToolName.messages[2] as { toolName: string }).toolName = "read";
  const duplicateResult = matchingFinalContext();
  duplicateResult.messages.push({
    role: "toolResult",
    toolCallId: LAUNCHER_DETERMINISTIC_TOOL_ID,
    toolName: LAUNCHER_DETERMINISTIC_TOOL_NAME,
    content: [],
    isError: false,
    timestamp: TIMESTAMP,
  });
  const duplicateToolCall = matchingFinalContext();
  const assistant = duplicateToolCall.messages[1];
  if (assistant?.role === "assistant") {
    assistant.content.push({
      type: "toolCall",
      id: LAUNCHER_DETERMINISTIC_TOOL_ID,
      name: LAUNCHER_DETERMINISTIC_TOOL_NAME,
      arguments: {},
    });
  }
  for (const badContext of [
    { messages: [] },
    tooManyMessages,
    { messages: [{ role: "system", content: "bad", timestamp: TIMESTAMP }] },
    { messages: [{ role: "user", content: "x".repeat(1025), timestamp: TIMESTAMP }] },
    { messages: [{ role: "user", content: [{ type: "text", text: "bad" }], timestamp: TIMESTAMP }] },
    {
      messages: [
        normalContext().messages[0],
        matchingFinalContext().messages[1],
        {
          role: "toolResult",
          toolCallId: LAUNCHER_DETERMINISTIC_TOOL_ID,
          toolName: LAUNCHER_DETERMINISTIC_TOOL_NAME,
          isError: false,
          timestamp: TIMESTAMP,
        },
      ],
    },
    {
      messages: [
        normalContext().messages[0],
        {
          role: "toolResult",
          toolCallId: LAUNCHER_DETERMINISTIC_TOOL_ID,
          toolName: LAUNCHER_DETERMINISTIC_TOOL_NAME,
          content: [],
          isError: false,
          timestamp: TIMESTAMP,
        },
      ],
    },
    wrongToolId,
    wrongToolName,
    duplicateResult,
    duplicateToolCall,
  ]) {
    assertGenericError(await collect(await stream()(model(), badContext as never, options())));
  }
});

test("deterministic stream rejects final-turn reorder, extra content, metadata mismatch, and errored results", async () => {
  const reordered = matchingFinalContext();
  const [firstMessage, secondMessage, thirdMessage] = reordered.messages;
  assert.ok(firstMessage !== undefined && secondMessage !== undefined && thirdMessage !== undefined);
  reordered.messages = [thirdMessage, firstMessage, secondMessage];
  const extraText = matchingFinalContext();
  const assistantWithExtra = extraText.messages[1];
  if (assistantWithExtra?.role === "assistant") assistantWithExtra.content.push({ type: "text", text: "extra" });
  const wrongApi = matchingFinalContext();
  (wrongApi.messages[1] as { api: string }).api = "openai-responses";
  const wrongProvider = matchingFinalContext();
  (wrongProvider.messages[1] as { provider: string }).provider = "openai";
  const wrongModel = matchingFinalContext();
  (wrongModel.messages[1] as { model: string }).model = "other";
  const wrongStopReason = matchingFinalContext();
  (wrongStopReason.messages[1] as { stopReason: string }).stopReason = "stop";
  const erroredResult = matchingFinalContext();
  (erroredResult.messages[2] as { isError: boolean }).isError = true;
  for (const badContext of [
    reordered,
    extraText,
    wrongApi,
    wrongProvider,
    wrongModel,
    wrongStopReason,
    erroredResult,
  ]) {
    assertGenericError(await collect(await stream()(model(), badContext, options())));
  }
});

test("deterministic stream rejects oversized record key inventories before descriptor snapshots", async () => {
  const manyKeys = Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`key${index}`, index]));
  assertGenericError(await collect(await stream()(manyKeys as never, normalContext(), options())));
  assertGenericError(
    await collect(
      await stream()(model(), normalContext(), {
        ...manyKeys,
        apiKey: "test-key",
        signal: new AbortController().signal,
      } as never),
    ),
  );
  assertGenericError(
    await collect(
      await stream()(
        model(),
        { messages: [{ ...manyKeys, role: "user", content: "prompt", timestamp: TIMESTAMP }] } as never,
        options(),
      ),
    ),
  );
});

test("deterministic stream rejects hostile arrays without invoking getters or iterators", async () => {
  let invoked = false;
  const sparseMessages = new Array(1);
  const accessorMessages = [normalContext().messages[0]];
  Object.defineProperty(accessorMessages, "0", {
    get() {
      invoked = true;
      return normalContext().messages[0];
    },
  });
  const symbolMessages = [normalContext().messages[0]] as unknown[] & { [key: symbol]: string };
  symbolMessages[Symbol("hidden")] = "hidden";
  const extraMessages = [normalContext().messages[0]] as unknown[] & { extra: string };
  extraMessages.extra = "bad";
  const protoMessages = [normalContext().messages[0]];
  Object.setPrototypeOf(protoMessages, {
    [Symbol.iterator]: () => {
      invoked = true;
      return [][Symbol.iterator]();
    },
  });
  const iteratorMessages = [normalContext().messages[0]];
  Object.defineProperty(iteratorMessages, Symbol.iterator, {
    value: () => {
      invoked = true;
      return [][Symbol.iterator]();
    },
  });
  const contentAccessor = matchingFinalContext();
  const assistant = contentAccessor.messages[1];
  if (assistant?.role === "assistant") {
    Object.defineProperty(assistant.content, "0", {
      get() {
        invoked = true;
        return { type: "toolCall", id: LAUNCHER_DETERMINISTIC_TOOL_ID, name: LAUNCHER_DETERMINISTIC_TOOL_NAME };
      },
    });
  }
  const toolResultExtraContent = matchingFinalContext();
  const result = toolResultExtraContent.messages[2];
  if (result?.role === "toolResult") (result.content as unknown[] & { extra: string }).extra = "bad";
  for (const badContext of [
    { messages: sparseMessages },
    { messages: accessorMessages },
    { messages: symbolMessages },
    { messages: extraMessages },
    { messages: protoMessages },
    { messages: iteratorMessages },
    contentAccessor,
    toolResultExtraContent,
    { messages: normalContext().messages, tools: iteratorMessages },
  ]) {
    assertGenericError(await collect(await stream()(model(), badContext as never, options())));
  }
  assert.equal(invoked, false);
});

test("deterministic abort mode uses native AbortSignal accessors despite hostile own properties", async () => {
  const controller = new AbortController();
  let invoked = false;
  Object.defineProperty(controller.signal, "aborted", {
    get() {
      invoked = true;
      return false;
    },
  });
  Object.defineProperty(controller.signal, "addEventListener", {
    value: () => {
      invoked = true;
    },
  });
  Object.defineProperty(controller.signal, "removeEventListener", {
    value: () => {
      invoked = true;
    },
  });
  const pending = await stream()(model(), abortContext(), options(controller));
  assert.equal(await collectWithTimeout(pending), "timeout");
  assert.equal(getEventListeners(controller.signal, "abort").length, 1);
  controller.abort();
  assert.deepEqual(await collectWithTimeout(pending, 100), []);
  const result = await resultWithTimeout(pending);
  assert.notEqual(result, "timeout");
  if (result === "timeout") throw new Error("expected result");
  assert.equal(result.stopReason, "aborted");
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  assert.equal(invoked, false);
});

test("deterministic stream rejects clock faults and aborted non-abort requests generically", async () => {
  for (const badClock of [
    () => -1,
    () => 1.5,
    () => Number.MAX_SAFE_INTEGER + 1,
    () => 4_102_444_800_001,
    () => {
      throw new Error("clock secret");
    },
  ]) {
    assertGenericError(await collect(await stream(badClock)(model(), normalContext(), options())));
  }
  const controller = new AbortController();
  controller.abort();
  assertGenericError(await collect(await stream()(model(), normalContext(), options(controller))));
});

test("deterministic stream rejects hostile accessors, prototypes, symbols, and thenables without invoking them", async () => {
  let getterInvoked = false;
  const accessorContext = {};
  Object.defineProperty(accessorContext, "messages", {
    get() {
      getterInvoked = true;
      return [];
    },
  });
  const symbolContext = normalContext() as Context & { [key: symbol]: string };
  symbolContext[Symbol("secret")] = "hidden";
  const protoContext = Object.create({ inherited: true }) as Context;
  Object.assign(protoContext, normalContext());
  const thenableContext = { ...normalContext() };
  Object.defineProperty(thenableContext, ["th", "en"].join(""), { value: () => undefined, enumerable: true });
  const protoPayload = {};
  Object.defineProperty(protoPayload, "content", {
    get() {
      getterInvoked = true;
      return LAUNCHER_DETERMINISTIC_NORMAL_PROMPT;
    },
  });
  const magicProtoMessage = { role: "user" };
  Object.defineProperty(magicProtoMessage, "__proto__", { value: protoPayload, enumerable: true });
  const magicProtoContext = { messages: [magicProtoMessage] };
  for (const badContext of [accessorContext, symbolContext, protoContext, thenableContext, magicProtoContext]) {
    assertGenericError(await collect(await stream()(model(), badContext as never, options())));
  }
  const hostileOptions = {};
  Object.defineProperty(hostileOptions, "apiKey", {
    get() {
      getterInvoked = true;
      return "test-key";
    },
  });
  Object.defineProperty(hostileOptions, "signal", { value: new AbortController().signal });
  const hostileSignal = {
    get aborted() {
      getterInvoked = true;
      return false;
    },
  };
  assertGenericError(await collect(await stream()(model(), normalContext(), hostileOptions as never)));
  assertGenericError(
    await collect(await stream()(model(), normalContext(), { apiKey: "test-key", signal: hostileSignal } as never)),
  );
  assert.equal(getterInvoked, false);
});

test("deterministic stream does not reflect or retain API keys, prompts, commands, or provider seams", async () => {
  const secretKey = "api-key-sensitive-token";
  const context = unknownContext("secret prompt text that must not be returned");
  const events = await collect(await stream()(model(), context, options(new AbortController(), secretKey)));
  const serialized = JSON.stringify(events);
  assert.doesNotMatch(serialized, /api-key-sensitive-token|secret prompt text/);
  assert.doesNotMatch(serialized, /provider-called/);

  const finalEvents = await eventsFor(matchingFinalContext());
  const finalSerialized = JSON.stringify(finalEvents);
  assert.doesNotMatch(finalSerialized, /ignored-by-validator|tool output is not reflected/);
});

test("deterministic stream factory validates and freezes its seam", () => {
  const deterministic = createDeterministicLauncherStream(Object.freeze({ now: () => TIMESTAMP }));
  assert.equal(Object.isFrozen(deterministic), true);
  assert.throws(
    () => createDeterministicLauncherStream({ now: () => TIMESTAMP }),
    /launcher deterministic stream failed/,
  );
  assert.throws(
    () =>
      createDeterministicLauncherStream(
        Object.freeze({
          get now() {
            throw new Error("secret getter");
          },
        }) as never,
      ),
    /launcher deterministic stream failed/,
  );
  assert.throws(
    () => createDeterministicLauncherStream(Object.freeze(Object.create(null)) as never),
    /launcher deterministic stream failed/,
  );
});
