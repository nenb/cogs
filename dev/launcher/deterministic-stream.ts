import type { StreamFn } from "@earendil-works/pi-agent-core";
import type {
  Api,
  AssistantMessage,
  Context,
  Model,
  SimpleStreamOptions,
  ToolCall,
  Usage,
} from "@earendil-works/pi-ai";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";

export const LAUNCHER_DETERMINISTIC_PROVIDER = "anthropic" as const;
export const LAUNCHER_DETERMINISTIC_MODEL_ID = "claude-sonnet-4-5" as const;
export const LAUNCHER_DETERMINISTIC_API = "anthropic-messages" as const;
export const LAUNCHER_DETERMINISTIC_NORMAL_PROMPT = "cogs launcher deterministic smoke" as const;
export const LAUNCHER_DETERMINISTIC_ABORT_PROMPT = "cogs launcher deterministic abort" as const;
export const LAUNCHER_DETERMINISTIC_TOOL_ID = "launcher-tool-1" as const;
export const LAUNCHER_DETERMINISTIC_TOOL_NAME = "bash" as const;
export const LAUNCHER_DETERMINISTIC_TOOL_ARGUMENTS = Object.freeze({
  command: "printf cogs-launcher-deterministic",
});
export const LAUNCHER_DETERMINISTIC_FINAL_TEXT = "cogs launcher deterministic run complete" as const;
export const LAUNCHER_DETERMINISTIC_S309_SETUP_PROMPT = "cogs launcher s3-09 setup" as const;
export const LAUNCHER_DETERMINISTIC_S309_PROMPT = "cogs launcher s3-09 integrated" as const;
export const LAUNCHER_DETERMINISTIC_S309_FINAL_TEXT = "cogs launcher s3-09 complete" as const;
export const LAUNCHER_DETERMINISTIC_S309_UPDATE_COUNT = 300 as const;
export const LAUNCHER_DETERMINISTIC_S309_UPDATE_DELAY = "0.02" as const;
export const LAUNCHER_DETERMINISTIC_S309_UPDATE_LINE = "u\n" as const;
export const LAUNCHER_DETERMINISTIC_S309_BASH_MARKER = "allowed=200 denied=403 committed updates=300" as const;
export const LAUNCHER_DETERMINISTIC_S309_BASH_STDOUT =
  `${LAUNCHER_DETERMINISTIC_S309_UPDATE_LINE.repeat(LAUNCHER_DETERMINISTIC_S309_UPDATE_COUNT)}${LAUNCHER_DETERMINISTIC_S309_BASH_MARKER}` as const;
export const LAUNCHER_DETERMINISTIC_UNKNOWN_TEXT = "cogs launcher deterministic fallback response" as const;

const GENERIC_ERROR = "launcher deterministic stream failed";
const MAX_API_KEY_LENGTH = 4096;
const MAX_PROMPT_LENGTH = 1024;
const MAX_MESSAGES = 9;
const MAX_CONTENT_BLOCKS = 8;
const MAX_RECORD_KEYS = 32;
const DEFAULT_SEAMS = Object.freeze({});
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const EVENT_TARGET_ADD = EventTarget.prototype.addEventListener;
const EVENT_TARGET_REMOVE = EventTarget.prototype.removeEventListener;
const MIN_TIMESTAMP = 0;
const MAX_TIMESTAMP = 4_102_444_800_000; // 2100-01-01T00:00:00.000Z
const S309_SETUP_TOOL = Object.freeze({
  id: "launcher-s309-setup-1",
  name: "bash",
  arguments: Object.freeze({
    command:
      "set -eu\nmkdir -p /workspace/s3-09\nprintf 'alpha\\n' > /workspace/s3-09/proof.txt\ncd /workspace\ngit init -q\ngit config user.email cogs@example.invalid\ngit config user.name 'Cogs Launcher'\ngit add s3-09/proof.txt\ngit commit -q -m s3-09-baseline\nprintf s3-09-setup",
  }),
});
const S309_READ_TOOL = Object.freeze({
  id: "launcher-s309-read-1",
  name: "read",
  arguments: Object.freeze({ path: "/workspace/s3-09/proof.txt", offset: 0, limit: 10 }),
});
const S309_EDIT_TOOL = Object.freeze({
  id: "launcher-s309-edit-1",
  name: "edit",
  arguments: Object.freeze({ path: "/workspace/s3-09/proof.txt", oldText: "alpha\n", newText: "alpha\nbeta\n" }),
});
function s309BashTool(port: number | undefined) {
  if (port === undefined) throw new Error(GENERIC_ERROR);
  return Object.freeze({
    id: "launcher-s309-bash-1",
    name: "bash",
    arguments: Object.freeze({
      command: `set -eu\ntest "$(cat /workspace/s3-09/proof.txt)" = "alpha\nbeta"\nallowed=$(curl -sS --proxy http://192.0.2.1:18080 --noproxy '' --insecure -o /dev/null -w '%{http_code}' https://localhost:${port}/credential)\ndenied=$(curl -sS --proxy http://192.0.2.1:18080 --noproxy '' --insecure -o /dev/null -w '%{http_code}' https://localhost:${port}/allowed || true)\ntest "$allowed" = 200\ntest "$denied" = 403\ncd /workspace\ngit add s3-09/proof.txt\ngit commit -q -m s3-09-integrated\ni=0; while [ "$i" -lt ${LAUNCHER_DETERMINISTIC_S309_UPDATE_COUNT} ]; do printf '${LAUNCHER_DETERMINISTIC_S309_UPDATE_LINE}'; sleep ${LAUNCHER_DETERMINISTIC_S309_UPDATE_DELAY}; i=$((i+1)); done\nprintf '${LAUNCHER_DETERMINISTIC_S309_BASH_MARKER}'`,
    }),
  });
}

export interface DeterministicLauncherStreamSeams {
  readonly now?: () => number;
  readonly s309FixturePort?: number;
}

interface SnapshotOptions {
  readonly apiKeyPresent: true;
  readonly signal: AbortSignal;
}

interface UserSnapshot {
  readonly role: "user";
  readonly content: string;
}

interface AssistantSnapshot {
  readonly role: "assistant";
  readonly api: string;
  readonly provider: string;
  readonly model: string;
  readonly stopReason: string;
  readonly toolCall?: {
    readonly id: string;
    readonly name: string;
  };
  readonly text?: string;
}

interface ToolResultSnapshot {
  readonly role: "toolResult";
  readonly toolCallId: string;
  readonly toolName: string;
  readonly text: string;
}

type MessageSnapshot = UserSnapshot | AssistantSnapshot | ToolResultSnapshot;

interface ContextSnapshot {
  readonly messages: readonly MessageSnapshot[];
}

interface RequestSnapshot {
  readonly modelId: string;
  readonly mode:
    | "tool"
    | "final"
    | "s309-setup-tool"
    | "s309-setup-final"
    | "s309-read"
    | "s309-edit"
    | "s309-bash"
    | "s309-final"
    | "unknown"
    | "abort";
  readonly signal: AbortSignal;
}

export function createDeterministicLauncherStream(seams: DeterministicLauncherStreamSeams = DEFAULT_SEAMS): StreamFn {
  const clock = snapshotClock(seams);
  const s309FixturePort = snapshotS309FixturePort(seams);
  const streamFn: StreamFn = (model, context, options) => {
    try {
      const request = snapshotRequest(model, context, options);
      if (request.mode === "abort") {
        return createPendingAbortStream(request.modelId, request.signal, safeTimestamp(clock));
      }
      if (nativeAborted(request.signal)) {
        return createErrorStream(request.modelId, safeTimestamp(clock));
      }
      const timestamp = safeTimestamp(clock);
      if (nativeAborted(request.signal)) {
        return createErrorStream(request.modelId, timestamp);
      }
      if (request.mode === "tool") return createToolStream(request.modelId, timestamp);
      if (request.mode === "s309-setup-tool") return createToolStream(request.modelId, timestamp, S309_SETUP_TOOL);
      if (request.mode === "s309-read") return createToolStream(request.modelId, timestamp, S309_READ_TOOL);
      if (request.mode === "s309-edit") return createToolStream(request.modelId, timestamp, S309_EDIT_TOOL);
      if (request.mode === "s309-bash")
        return createToolStream(request.modelId, timestamp, s309BashTool(s309FixturePort));
      if (request.mode === "s309-final") {
        return createChunkedTextStream(request.modelId, timestamp, LAUNCHER_DETERMINISTIC_S309_FINAL_TEXT);
      }
      const text =
        request.mode === "final"
          ? LAUNCHER_DETERMINISTIC_FINAL_TEXT
          : request.mode === "s309-setup-final"
            ? LAUNCHER_DETERMINISTIC_S309_FINAL_TEXT
            : LAUNCHER_DETERMINISTIC_UNKNOWN_TEXT;
      return createTextStream(request.modelId, timestamp, text);
    } catch {
      return createErrorStream(LAUNCHER_DETERMINISTIC_MODEL_ID, fallbackTimestamp());
    }
  };
  return Object.freeze(streamFn);
}

function snapshotClock(seams: DeterministicLauncherStreamSeams): () => number {
  if (!Object.isFrozen(seams)) throw new Error(GENERIC_ERROR);
  const record = snapshotPlainRecord(seams, ["now", "s309FixturePort"]);
  const value = record.now;
  if (value === undefined) return Date.now;
  if (typeof value !== "function") throw new Error(GENERIC_ERROR);
  return value as () => number;
}

function snapshotS309FixturePort(seams: DeterministicLauncherStreamSeams): number | undefined {
  if (!Object.isFrozen(seams)) throw new Error(GENERIC_ERROR);
  const record = snapshotPlainRecord(seams, ["now", "s309FixturePort"]);
  const value = record.s309FixturePort;
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 65535)
    throw new Error(GENERIC_ERROR);
  return value as number;
}

function snapshotRequest(model: Model<Api>, context: Context, options?: SimpleStreamOptions): RequestSnapshot {
  const modelSnapshot = snapshotModel(model);
  const optionSnapshot = snapshotOptions(options);
  if (
    modelSnapshot.provider !== LAUNCHER_DETERMINISTIC_PROVIDER ||
    modelSnapshot.api !== LAUNCHER_DETERMINISTIC_API ||
    modelSnapshot.id !== LAUNCHER_DETERMINISTIC_MODEL_ID
  ) {
    throw new Error(GENERIC_ERROR);
  }
  const contextSnapshot = snapshotContext(context);
  const mode = selectMode(contextSnapshot);
  if (mode !== "abort" && nativeAborted(optionSnapshot.signal)) throw new Error(GENERIC_ERROR);
  return { modelId: modelSnapshot.id, mode, signal: optionSnapshot.signal };
}

function snapshotModel(model: Model<Api>): { readonly id: string; readonly api: Api; readonly provider: string } {
  const record = snapshotPlainRecord(model, []);
  const id = boundedString(record.id, 1, 256);
  const api = boundedString(record.api, 1, 128) as Api;
  const provider = boundedString(record.provider, 1, 128);
  return { id, api, provider };
}

function snapshotOptions(options: SimpleStreamOptions | undefined): SnapshotOptions {
  if (options === undefined) throw new Error(GENERIC_ERROR);
  const record = snapshotPlainRecord(options, []);
  const apiKey = boundedString(record.apiKey, 1, MAX_API_KEY_LENGTH);
  if (apiKey.length === 0) throw new Error(GENERIC_ERROR);
  const signal = record.signal;
  if (!isAbortSignal(signal)) throw new Error(GENERIC_ERROR);
  return { apiKeyPresent: true, signal };
}

function snapshotContext(context: Context): ContextSnapshot {
  const record = snapshotPlainRecord(context, ["systemPrompt", "messages", "tools"]);
  if (record.systemPrompt !== undefined) boundedString(record.systemPrompt, 0, MAX_PROMPT_LENGTH);
  if (record.tools !== undefined) snapshotDenseArray(record.tools, MAX_CONTENT_BLOCKS);
  const rawMessages = snapshotDenseArray(record.messages, MAX_MESSAGES);
  const messages = rawMessages.map((message) => snapshotMessage(message));
  return { messages: Object.freeze(messages) };
}

function snapshotMessage(message: unknown): MessageSnapshot {
  const record = snapshotPlainRecord(message, []);
  const role = record.role;
  if (role === "user") {
    return Object.freeze({ role, content: snapshotUserText(record.content) });
  }
  if (role === "assistant") {
    return snapshotAssistant(record);
  }
  if (role === "toolResult") {
    return snapshotToolResult(record);
  }
  throw new Error(GENERIC_ERROR);
}

function snapshotUserText(content: unknown): string {
  const blocks = snapshotDenseArray(content, 1);
  if (blocks.length !== 1) throw new Error(GENERIC_ERROR);
  const textBlock = snapshotPlainRecord(blocks[0], ["type", "text"]);
  if (Object.keys(textBlock).sort().join(",") !== "text,type" || textBlock.type !== "text") {
    throw new Error(GENERIC_ERROR);
  }
  return boundedUserText(textBlock.text);
}

function snapshotAssistant(record: Record<string, unknown>): AssistantSnapshot {
  const blocks = snapshotDenseArray(record.content, MAX_CONTENT_BLOCKS);
  let toolCall: AssistantSnapshot["toolCall"];
  let text: string | undefined;
  for (const block of blocks) {
    const content = snapshotPlainRecord(block, []);
    const type = content.type;
    if (type === "toolCall") {
      if (toolCall !== undefined || text !== undefined) throw new Error(GENERIC_ERROR);
      toolCall = Object.freeze({
        id: boundedString(content.id, 1, 128),
        name: boundedString(content.name, 1, 128),
      });
      continue;
    }
    if (type === "text") {
      if (text !== undefined || toolCall !== undefined) throw new Error(GENERIC_ERROR);
      text = boundedString(content.text, 0, MAX_PROMPT_LENGTH);
      continue;
    }
    throw new Error(GENERIC_ERROR);
  }
  const metadata = Object.freeze({
    role: "assistant" as const,
    api: boundedString(record.api, 1, 128),
    provider: boundedString(record.provider, 1, 128),
    model: boundedString(record.model, 1, 256),
    stopReason: boundedString(record.stopReason, 1, 32),
  });
  return Object.freeze({
    ...metadata,
    ...(toolCall === undefined ? {} : { toolCall }),
    ...(text === undefined ? {} : { text }),
  });
}

function snapshotToolResult(record: Record<string, unknown>): ToolResultSnapshot {
  const blocks = snapshotDenseArray(record.content, MAX_CONTENT_BLOCKS);
  if (blocks.length !== 1) throw new Error(GENERIC_ERROR);
  const content = snapshotPlainRecord(blocks[0], []);
  if (content.type !== "text") throw new Error(GENERIC_ERROR);
  const text = boundedString(content.text, 0, MAX_PROMPT_LENGTH);
  if (record.isError !== false) throw new Error(GENERIC_ERROR);
  return Object.freeze({
    role: "toolResult",
    toolCallId: boundedString(record.toolCallId, 1, 128),
    toolName: boundedString(record.toolName, 1, 128),
    text,
  });
}

function selectMode(context: ContextSnapshot): RequestSnapshot["mode"] {
  if (isFreshAbort(context.messages) || isCompletedNormalThenAbort(context.messages)) return "abort";
  const userMessages = context.messages.filter((message): message is UserSnapshot => message.role === "user");
  if (userMessages.length !== 1) throw new Error(GENERIC_ERROR);
  const prompt = userMessages[0]?.content;
  if (prompt === LAUNCHER_DETERMINISTIC_NORMAL_PROMPT) {
    if (context.messages.length === 1) return "tool";
    if (context.messages.length !== 3) throw new Error(GENERIC_ERROR);
    const result = requireToolPair(
      context.messages,
      1,
      LAUNCHER_DETERMINISTIC_TOOL_ID,
      LAUNCHER_DETERMINISTIC_TOOL_NAME,
    );
    if (!isExactSuccessfulBashResult(result.text)) throw new Error(GENERIC_ERROR);
    return "final";
  }
  if (prompt === LAUNCHER_DETERMINISTIC_S309_SETUP_PROMPT) {
    if (context.messages.length === 1) return "s309-setup-tool";
    if (context.messages.length !== 3) throw new Error(GENERIC_ERROR);
    const result = requireToolPair(context.messages, 1, S309_SETUP_TOOL.id, S309_SETUP_TOOL.name);
    if (!isSuccessfulBashWithStdout(result.text, "s3-09-setup")) throw new Error(GENERIC_ERROR);
    return "s309-setup-final";
  }
  if (prompt === LAUNCHER_DETERMINISTIC_S309_PROMPT) {
    if (context.messages.length === 1) return "s309-read";
    if (context.messages.length === 3) {
      const result = requireToolPair(context.messages, 1, S309_READ_TOOL.id, S309_READ_TOOL.name);
      if (!isReadAlpha(result.text)) throw new Error(GENERIC_ERROR);
      return "s309-edit";
    }
    if (context.messages.length === 5) {
      const read = requireToolPair(context.messages, 1, S309_READ_TOOL.id, S309_READ_TOOL.name);
      const result = requireToolPair(context.messages, 3, S309_EDIT_TOOL.id, S309_EDIT_TOOL.name);
      if (!isReadAlpha(read.text) || !isEditOk(result.text)) throw new Error(GENERIC_ERROR);
      return "s309-bash";
    }
    if (context.messages.length === 7) {
      const read = requireToolPair(context.messages, 1, S309_READ_TOOL.id, S309_READ_TOOL.name);
      const edit = requireToolPair(context.messages, 3, S309_EDIT_TOOL.id, S309_EDIT_TOOL.name);
      const result = requireToolPair(context.messages, 5, "launcher-s309-bash-1", "bash");
      if (!isReadAlpha(read.text) || !isEditOk(edit.text)) throw new Error(GENERIC_ERROR);
      if (!isSuccessfulBashWithStdout(result.text, LAUNCHER_DETERMINISTIC_S309_BASH_STDOUT))
        throw new Error(GENERIC_ERROR);
      return "s309-final";
    }
    throw new Error(GENERIC_ERROR);
  }
  if (context.messages.length !== 1) throw new Error(GENERIC_ERROR);
  boundedString(prompt, 0, MAX_PROMPT_LENGTH);
  return "unknown";
}

function requireToolPair(
  messages: readonly MessageSnapshot[],
  assistantIndex: number,
  id: string,
  name: string,
): ToolResultSnapshot {
  const assistant = messages[assistantIndex];
  const result = messages[assistantIndex + 1];
  if (assistant?.role !== "assistant" || result?.role !== "toolResult") throw new Error(GENERIC_ERROR);
  const call = assistant.toolCall;
  if (
    assistant.api !== LAUNCHER_DETERMINISTIC_API ||
    assistant.provider !== LAUNCHER_DETERMINISTIC_PROVIDER ||
    assistant.model !== LAUNCHER_DETERMINISTIC_MODEL_ID ||
    assistant.stopReason !== "toolUse" ||
    call?.id !== id ||
    call.name !== name ||
    result.toolCallId !== id ||
    result.toolName !== name
  )
    throw new Error(GENERIC_ERROR);
  return result;
}

function isFreshAbort(messages: readonly MessageSnapshot[]): boolean {
  const only = messages[0];
  return messages.length === 1 && only?.role === "user" && only.content === LAUNCHER_DETERMINISTIC_ABORT_PROMPT;
}

function isCompletedNormalThenAbort(messages: readonly MessageSnapshot[]): boolean {
  if (messages.length !== 5) return false;
  const [prompt, toolUse, result, final, abort] = messages;
  return (
    prompt?.role === "user" &&
    prompt.content === LAUNCHER_DETERMINISTIC_NORMAL_PROMPT &&
    toolUse?.role === "assistant" &&
    toolUse.api === LAUNCHER_DETERMINISTIC_API &&
    toolUse.provider === LAUNCHER_DETERMINISTIC_PROVIDER &&
    toolUse.model === LAUNCHER_DETERMINISTIC_MODEL_ID &&
    toolUse.stopReason === "toolUse" &&
    toolUse.text === undefined &&
    toolUse.toolCall?.id === LAUNCHER_DETERMINISTIC_TOOL_ID &&
    toolUse.toolCall.name === LAUNCHER_DETERMINISTIC_TOOL_NAME &&
    result?.role === "toolResult" &&
    result.toolCallId === LAUNCHER_DETERMINISTIC_TOOL_ID &&
    result.toolName === LAUNCHER_DETERMINISTIC_TOOL_NAME &&
    isExactSuccessfulBashResult(result.text) &&
    final?.role === "assistant" &&
    final.api === LAUNCHER_DETERMINISTIC_API &&
    final.provider === LAUNCHER_DETERMINISTIC_PROVIDER &&
    final.model === LAUNCHER_DETERMINISTIC_MODEL_ID &&
    final.stopReason === "stop" &&
    final.toolCall === undefined &&
    final.text === LAUNCHER_DETERMINISTIC_FINAL_TEXT &&
    abort?.role === "user" &&
    abort.content === LAUNCHER_DETERMINISTIC_ABORT_PROMPT
  );
}

function isExactSuccessfulBashResult(text: string): boolean {
  try {
    const value = JSON.parse(text) as unknown;
    if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) return false;
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort().join(",");
    if (
      keys !==
      "cancelled,elapsedMs,exitCode,idleTimedOut,ok,signal,stderr,stderrBytes,stderrDroppedBytes,stderrLossyUtf8,stderrResultOmittedUtf8Bytes,stderrTruncated,stdout,stdoutBytes,stdoutDroppedBytes,stdoutLossyUtf8,stdoutResultOmittedUtf8Bytes,stdoutTruncated,timedOut,updateDropped"
    )
      return false;
    return (
      record.ok === true &&
      record.stdout === "cogs-launcher-deterministic" &&
      record.stderr === "" &&
      record.exitCode === 0 &&
      record.signal === null &&
      Number.isSafeInteger(record.elapsedMs) &&
      (record.elapsedMs as number) >= 0 &&
      record.timedOut === false &&
      record.idleTimedOut === false &&
      record.cancelled === false &&
      record.stdoutBytes === 27 &&
      record.stderrBytes === 0 &&
      record.stdoutDroppedBytes === 0 &&
      record.stderrDroppedBytes === 0 &&
      record.stdoutResultOmittedUtf8Bytes === 0 &&
      record.stderrResultOmittedUtf8Bytes === 0 &&
      record.stdoutTruncated === false &&
      record.stderrTruncated === false &&
      record.stdoutLossyUtf8 === false &&
      record.stderrLossyUtf8 === false &&
      record.updateDropped === 0
    );
  } catch {
    return false;
  }
}

function isSuccessfulBashWithStdout(text: string, stdout: string): boolean {
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    return value.ok === true && value.exitCode === 0 && value.signal === null && value.stdout === stdout;
  } catch {
    return false;
  }
}

function isReadAlpha(text: string): boolean {
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    return value.path === "/workspace/s3-09/proof.txt" && value.content === "alpha\n" && value.eof === true;
  } catch {
    return false;
  }
}

function isEditOk(text: string): boolean {
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    return value.ok === true && value.path === "/workspace/s3-09/proof.txt" && value.occurrences === 1;
  } catch {
    return false;
  }
}

function createToolStream(
  modelId: string,
  timestamp: number,
  tool: {
    readonly id: string;
    readonly name: string;
    readonly arguments: Readonly<Record<string, unknown>>;
  } = Object.freeze({
    id: LAUNCHER_DETERMINISTIC_TOOL_ID,
    name: LAUNCHER_DETERMINISTIC_TOOL_NAME,
    arguments: LAUNCHER_DETERMINISTIC_TOOL_ARGUMENTS,
  }),
) {
  const stream = createAssistantMessageEventStream();
  const toolCall = deepFreeze({
    type: "toolCall" as const,
    id: tool.id,
    name: tool.name,
    arguments: { ...tool.arguments },
  }) satisfies ToolCall;
  const message = assistantMessage(modelId, [toolCall], "toolUse", timestamp);
  stream.push({ type: "start", partial: message });
  stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
  stream.push({ type: "toolcall_end", contentIndex: 0, toolCall, partial: message });
  stream.push({ type: "done", reason: "toolUse", message });
  stream.end();
  return stream;
}

function createTextStream(modelId: string, timestamp: number, text: string) {
  const stream = createAssistantMessageEventStream();
  const message = assistantMessage(modelId, [{ type: "text", text }], "stop", timestamp);
  stream.push({ type: "start", partial: message });
  stream.push({ type: "text_start", contentIndex: 0, partial: message });
  stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: message });
  stream.push({ type: "text_end", contentIndex: 0, content: text, partial: message });
  stream.push({ type: "done", reason: "stop", message });
  stream.end();
  return stream;
}

function createChunkedTextStream(modelId: string, timestamp: number, text: string) {
  const stream = createAssistantMessageEventStream();
  const message = assistantMessage(modelId, [{ type: "text", text }], "stop", timestamp);
  stream.push({ type: "start", partial: message });
  stream.push({ type: "text_start", contentIndex: 0, partial: message });
  for (const delta of Array.from(text)) stream.push({ type: "text_delta", contentIndex: 0, delta, partial: message });
  stream.push({ type: "text_end", contentIndex: 0, content: text, partial: message });
  stream.push({ type: "done", reason: "stop", message });
  stream.end();
  return stream;
}

function createPendingAbortStream(modelId: string, signal: AbortSignal, timestamp: number) {
  const stream = createAssistantMessageEventStream();
  const message = assistantMessage(modelId, [{ type: "text", text: "" }], "aborted", timestamp, GENERIC_ERROR);
  let settled = false;
  const settle = () => {
    if (settled) return;
    settled = true;
    EVENT_TARGET_REMOVE.call(signal, "abort", settle);
    stream.end(message);
  };
  if (nativeAborted(signal)) {
    settle();
    return stream;
  }
  EVENT_TARGET_ADD.call(signal, "abort", settle, { once: true });
  if (nativeAborted(signal)) settle();
  return stream;
}

function createErrorStream(modelId: string, timestamp: number) {
  const stream = createAssistantMessageEventStream();
  const message = assistantMessage(modelId, [{ type: "text", text: "" }], "error", timestamp, GENERIC_ERROR);
  stream.push({ type: "error", reason: "error", error: message });
  stream.end();
  return stream;
}

function assistantMessage(
  modelId: string,
  content: AssistantMessage["content"],
  stopReason: AssistantMessage["stopReason"],
  timestamp: number,
  errorMessage?: string,
): AssistantMessage {
  return deepFreeze({
    role: "assistant" as const,
    content: content.map((block) => deepFreeze(block)),
    api: LAUNCHER_DETERMINISTIC_API,
    provider: LAUNCHER_DETERMINISTIC_PROVIDER,
    model: modelId,
    usage: zeroUsage(),
    stopReason,
    ...(errorMessage === undefined ? {} : { errorMessage }),
    timestamp,
  });
}

function zeroUsage(): Usage {
  return deepFreeze({
    input: 0,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  });
}

function safeTimestamp(clock: () => number): number {
  const timestamp = clock();
  if (!Number.isSafeInteger(timestamp) || timestamp < MIN_TIMESTAMP || timestamp > MAX_TIMESTAMP) {
    throw new Error(GENERIC_ERROR);
  }
  return timestamp;
}

function fallbackTimestamp(): number {
  return 0;
}

function boundedString(value: unknown, minLength: number, maxLength: number): string {
  if (typeof value !== "string" || value.length < minLength || value.length > maxLength) throw new Error(GENERIC_ERROR);
  return value;
}

function boundedUserText(value: unknown): string {
  const text = boundedString(value, 1, MAX_PROMPT_LENGTH);
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) throw new Error(GENERIC_ERROR);
  }
  return text;
}

function snapshotPlainRecord(value: unknown, allowedKeys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(GENERIC_ERROR);
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error(GENERIC_ERROR);
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_RECORD_KEYS) throw new Error(GENERIC_ERROR);
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw new Error(GENERIC_ERROR);
    if (key === "then") throw new Error(GENERIC_ERROR);
    if (allowedKeys.length > 0 && !allowedKeys.includes(key)) throw new Error(GENERIC_ERROR);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new Error(GENERIC_ERROR);
    }
    Object.defineProperty(result, key, {
      value: descriptor.value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return result;
}

function snapshotDenseArray(value: unknown, maxLength: number): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new Error(GENERIC_ERROR);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value)
  ) {
    throw new Error(GENERIC_ERROR);
  }
  const length = lengthDescriptor.value as number;
  if (length < 0 || length > maxLength) throw new Error(GENERIC_ERROR);
  const keys = Reflect.ownKeys(value);
  if (keys.length > length + 1) throw new Error(GENERIC_ERROR);
  const allowedKeys = new Set<PropertyKey>(["length"]);
  for (let index = 0; index < length; index += 1) allowedKeys.add(String(index));
  for (const key of keys) {
    if (typeof key !== "string" || !allowedKeys.has(key)) throw new Error(GENERIC_ERROR);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new Error(GENERIC_ERROR);
    }
  }
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) throw new Error(GENERIC_ERROR);
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  for (const nested of Object.values(value as object)) deepFreeze(nested);
  return Object.freeze(value);
}

function nativeAborted(signal: AbortSignal): boolean {
  if (ABORTED_GETTER === undefined) throw new Error(GENERIC_ERROR);
  return ABORTED_GETTER.call(signal);
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return value instanceof AbortSignal;
}
