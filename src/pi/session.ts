import { constants } from "node:fs";
import { access, lstat, mkdir, realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import type { Api, Model } from "@earendil-works/pi-ai/compat";
import {
  AuthStorage,
  createAgentSession,
  createExtensionRuntime,
  defineTool,
  ModelRegistry,
  type ResourceLoader,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import type { ApiEvent, HistoryPort, InputKind, JsonValue, RunState, SessionPort } from "../api/server.ts";

export const COGS_PI_TOOL_NAMES = ["read", "write", "edit", "bash"] as const;
export type CogsPiToolName = (typeof COGS_PI_TOOL_NAMES)[number];

export interface CogsToolPorts {
  readonly read: (input: { path: string; offset?: number; limit?: number; signal?: AbortSignal }) => Promise<JsonValue>;
  readonly write: (input: { path: string; content: string; signal?: AbortSignal }) => Promise<JsonValue>;
  readonly edit: (input: {
    path: string;
    oldText: string;
    newText: string;
    signal?: AbortSignal;
  }) => Promise<JsonValue>;
  readonly bash: (input: {
    command: string;
    signal?: AbortSignal;
    onUpdate?: (update: { content: [{ type: "text"; text: string }]; details: JsonValue }) => void | Promise<void>;
  }) => Promise<JsonValue>;
}

export interface CogsPiSessionOptions {
  readonly cwd: string;
  readonly agentDir: string;
  readonly sessionId: string;
  readonly model: { provider: string; id: string };
  readonly apiKey: string;
  readonly sessionRoot: string;
  readonly resumeFile?: string;
  readonly toolPorts: CogsToolPorts;
  readonly streamFn?: StreamFn;
  readonly emit: (event: ApiEvent) => boolean | undefined;
  readonly onFatal: (reason: string) => void | Promise<void>;
  readonly operationTimeoutMs?: number;
  readonly abortTimeoutMs?: number;
  readonly maxToolResultBytes?: number;
}

export interface CogsPiSessionPorts extends SessionPort, HistoryPort {
  readonly dispose: () => Promise<void>;
  readonly model: Model<Api>;
  readonly activeToolNames: () => readonly string[];
  readonly sessionFile: () => string | undefined;
  readonly navigate: (
    entryId: string,
    input?: { signal?: AbortSignal },
  ) => Promise<{ cancelled: boolean; editorText?: string }>;
}

type PiSession = Awaited<ReturnType<typeof createAgentSession>>["session"];

type SecretHolder = { value: string };

type ActiveRun = {
  readonly requestId: string;
  readonly correlationId: string;
  abortRequestId?: string;
  abortCorrelationId?: string;
  terminal: boolean;
  suppressLate: boolean;
  deadline: NodeJS.Timeout | undefined;
  promise: Promise<void>;
};

const SENSITIVE_FIELD = /^(api[-_]?key|authorization|credential|secret|token|refresh[-_]?token|access[-_]?token)$/i;

function validateOptions(options: CogsPiSessionOptions): void {
  validateOptionalInteger(options.operationTimeoutMs, "operationTimeoutMs", 1, 3_600_000);
  validateOptionalInteger(options.abortTimeoutMs, "abortTimeoutMs", 1, 60_000);
  validateOptionalInteger(options.maxToolResultBytes, "maxToolResultBytes", 128, 1024 * 1024);
}

function validateOptionalInteger(value: number | undefined, label: string, minimum: number, maximum: number): void {
  if (value === undefined) return;
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`invalid ${label}`);
}

export function createLockedResourceLoader(systemPrompt?: string): ResourceLoader {
  const runtime = createExtensionRuntime();
  return {
    getExtensions: () => ({ extensions: [], errors: [], runtime }),
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () =>
      systemPrompt ?? "You are Cogs. Use only the explicitly supplied read, write, edit, and bash tools.",
    getAppendSystemPrompt: () => [],
    extendResources: () => {},
    reload: async () => {},
  };
}

export async function createCogsPiSession(options: CogsPiSessionOptions): Promise<CogsPiSessionPorts> {
  validateOptions(options);
  const cwd = options.cwd;
  const agentDir = options.agentDir;
  const sessionId = options.sessionId;
  const modelProvider = options.model.provider;
  const modelId = options.model.id;
  const sessionRoot = options.sessionRoot;
  const resumeFile = options.resumeFile;
  const streamFn = options.streamFn;
  const emit = options.emit;
  const onFatal = options.onFatal;
  const toolPorts = options.toolPorts;
  const operationTimeoutMs = options.operationTimeoutMs;
  const abortTimeoutMs = options.abortTimeoutMs;
  const maxToolResultBytes = options.maxToolResultBytes ?? 16 * 1024;
  const apiKey = options.apiKey;

  assertRuntimeSecret(apiKey, "model API key");
  assertOpaqueId(sessionId, "session id");
  assertProviderId(modelProvider, "provider id");
  assertModelId(modelId, "model id");

  const secret: SecretHolder = { value: apiKey };
  const authStorage = AuthStorage.inMemory();
  authStorage.setRuntimeApiKey(modelProvider, secret.value);
  try {
    const modelRegistry = ModelRegistry.inMemory(authStorage);
    const model = modelRegistry.find(modelProvider, modelId);
    if (!model) throw new Error("unknown model");
    if (modelRegistry.isUsingOAuth(model)) throw new Error("oauth model authentication is disabled");

    const sessionManager = await createContainedSessionManager(cwd, sessionRoot, sessionId, resumeFile);

    const sessionResult = await createAgentSession({
      cwd,
      agentDir,
      model,
      thinkingLevel: "off",
      authStorage,
      modelRegistry,
      resourceLoader: createLockedResourceLoader(),
      customTools: createCogsTools(toolPorts, maxToolResultBytes, secret),
      tools: [...COGS_PI_TOOL_NAMES],
      noTools: "builtin",
      sessionManager,
      settingsManager: SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false } }),
    });
    const session = sessionResult.session;

    if (streamFn !== undefined) {
      session.agent.streamFn = async (activeModel, context, streamOptions) => {
        const apiKey = await authStorage.getApiKey(activeModel.provider, { includeFallback: false });
        if (!apiKey) throw new Error("missing runtime model API key");
        return streamFn(activeModel, context, { ...streamOptions, apiKey });
      };
    }

    return new PiSessionAdapter(session, authStorage, model, sessionManager, {
      emit,
      onFatal,
      provider: modelProvider,
      secret,
      operationTimeoutMs,
      abortTimeoutMs,
    });
  } catch (error) {
    authStorage.removeRuntimeApiKey(modelProvider);
    secret.value = "";
    throw error;
  }
}

type AdapterPhase = "open" | "running" | "aborting" | "failed" | "disposed";

class PiSessionAdapter implements CogsPiSessionPorts {
  readonly #authStorage: AuthStorage;
  private active: ActiveRun | undefined;
  private phase: AdapterPhase = "open";
  private cleanupPromise: Promise<void> | undefined;
  private fatalEmitted = false;
  private readonly timeoutMs: number;
  private readonly abortTimeoutMs: number;
  private readonly unsubscribe: () => void;

  public constructor(
    private readonly session: PiSession,
    authStorage: AuthStorage,
    public readonly model: Model<Api>,
    private readonly sessionManager: SessionManager,
    private readonly runtime: {
      readonly emit: (event: ApiEvent) => boolean | undefined;
      readonly onFatal: (reason: string) => void | Promise<void>;
      readonly provider: string;
      readonly secret: SecretHolder;
      readonly operationTimeoutMs: number | undefined;
      readonly abortTimeoutMs: number | undefined;
    },
  ) {
    this.#authStorage = authStorage;
    this.timeoutMs = runtime.operationTimeoutMs ?? 60_000;
    this.abortTimeoutMs = runtime.abortTimeoutMs ?? 5_000;
    this.unsubscribe = session.subscribe((event) => this.forwardEvent(event));
  }

  public activeToolNames(): readonly string[] {
    return this.session.agent.state.tools.map((tool) => tool.name);
  }

  public sessionFile(): string | undefined {
    return this.sessionManager.getSessionFile();
  }

  public async navigate(
    entryId: string,
    input: { signal?: AbortSignal } = {},
  ): Promise<{ cancelled: boolean; editorText?: string }> {
    this.assertLive();
    assertOpaqueId(entryId, "entry id");
    if (this.active !== undefined || this.session.isStreaming) throw new Error("cannot navigate while running");
    await throwIfAborted(input.signal);
    return this.session.navigateTree(entryId, { summarize: false });
  }

  public async input(input: {
    requestId: string;
    correlationId: string;
    kind: InputKind;
    content: string;
    signal?: AbortSignal;
  }): Promise<RunState> {
    this.assertLive();
    await throwIfAborted(input.signal);
    assertOpaqueId(input.requestId, "request id");
    assertOpaqueId(input.correlationId, "correlation id");
    assertInputKind(input.kind);
    if (input.content.length < 1 || input.content.length > 8192 || Buffer.byteLength(input.content, "utf8") > 16 * 1024)
      throw new Error("invalid input content");

    if (input.kind !== "prompt") {
      const active = this.active;
      if (active === undefined || active.terminal) throw new Error("Pi session is not running");
      if (this.phase !== "running") throw new Error("Pi session is not running");
      if (input.kind === "steer") await this.session.steer(input.content);
      else if (input.kind === "follow_up") await this.session.followUp(input.content);
      this.emitOrFail("pi_event", input.correlationId, input.requestId, {
        event: { type: "queued_input", kind: input.kind, request_id: input.requestId },
      });
      return this.stateSync();
    }

    if (this.active !== undefined || this.session.isStreaming) throw new Error("Pi session is already running");
    const active: ActiveRun = {
      requestId: input.requestId,
      correlationId: input.correlationId,
      terminal: false,
      suppressLate: false,
      deadline: undefined,
      promise: Promise.resolve(),
    };
    this.active = active;
    this.phase = "running";
    active.promise = this.runPrompt(active, input.content);
    active.promise.catch(() => undefined);
    return "running";
  }

  public async abort(input: { requestId: string; correlationId: string; signal?: AbortSignal }): Promise<{
    aborted: boolean;
    runState: RunState;
  }> {
    this.assertLive();
    await throwIfAborted(input.signal);
    assertOpaqueId(input.requestId, "request id");
    assertOpaqueId(input.correlationId, "correlation id");
    const active = this.active;
    if (active === undefined || active.terminal) return { aborted: false, runState: this.stateSync() };
    await this.abortActive(active, "requested", input.requestId, input.correlationId);
    return { aborted: true, runState: this.stateSync() };
  }

  public async state(input: { signal?: AbortSignal } = {}): Promise<{ runState: RunState; usage?: JsonValue }> {
    await throwIfAborted(input.signal);
    const runState = this.stateSync();
    if (runState === "shutdown") return { runState };
    return { runState, usage: this.usage() };
  }

  public async entries(input: { after: string | undefined; limit: number; signal?: AbortSignal }): Promise<{
    entries: readonly JsonValue[];
    nextAfter?: string;
  }> {
    this.assertLive();
    await throwIfAborted(input.signal);
    if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100)
      throw new Error("invalid history limit");
    const entries = this.sessionManager.getEntries();
    const cursorIndex = input.after === undefined ? -1 : entries.findIndex((entry) => entry.id === input.after);
    if (input.after !== undefined && cursorIndex < 0) throw new Error("unknown history cursor");
    const start = cursorIndex + 1;
    const page = entries.slice(start, start + input.limit);
    const last = page.at(-1);
    return {
      entries: sanitizeJson(page, { secrets: [this.runtime.secret.value] }) as JsonValue[],
      ...(start + input.limit < entries.length && last !== undefined ? { nextAfter: last.id } : {}),
    };
  }

  public async dispose(): Promise<void> {
    if (this.phase === "disposed") return;
    if (this.cleanupPromise !== undefined) {
      await this.cleanupPromise;
      this.phase = "disposed";
      return;
    }
    const active = this.active;
    if (active !== undefined && !active.terminal) {
      await this.failClosed("disposed", active);
      this.phase = "disposed";
      return;
    }
    this.unsubscribe();
    this.session.dispose();
    this.#authStorage.removeRuntimeApiKey(this.runtime.provider);
    this.runtime.secret.value = "";
    this.phase = "disposed";
  }

  private async runPrompt(active: ActiveRun, content: string): Promise<void> {
    active.deadline = setTimeout(() => {
      void this.timeoutActive(active);
    }, this.timeoutMs);
    try {
      await this.session.prompt(content, { expandPromptTemplates: false });
      if (active.suppressLate || this.phase === "aborting") return;
      this.terminal(active, "run_settled", { state: "settled" });
    } catch (error) {
      if (active.terminal || active.suppressLate || this.phase === "aborting") return;
      if (isAbortLike(error)) {
        this.terminal(active, "run_aborted", { reason: "cancelled" });
        return;
      }
      this.terminal(active, "error", { message: "pi operation failed" });
    }
  }

  private async timeoutActive(active: ActiveRun): Promise<void> {
    if (active.terminal || this.active !== active) return;
    active.suppressLate = true;
    active.terminal = true;
    this.phase = "aborting";
    if (active.deadline !== undefined) clearTimeout(active.deadline);
    if (!this.publishEvent("error", active.correlationId, active.requestId, { message: "pi operation timed out" })) {
      await this.failClosed("publish-failed", active);
      return;
    }
    try {
      await this.abortWithBound("timeout");
      if (this.active === active) this.active = undefined;
      if (this.phase === "aborting") this.phase = "open";
    } catch {
      await this.failClosed("timeout-abort-failed", active);
    }
  }

  private async abortActive(
    active: ActiveRun,
    reason: string,
    abortRequestId = active.requestId,
    abortCorrelationId = active.correlationId,
  ): Promise<void> {
    if (active.terminal) return;
    active.abortRequestId = abortRequestId;
    active.abortCorrelationId = abortCorrelationId;
    active.suppressLate = true;
    this.phase = "aborting";
    try {
      await this.abortWithBound(reason);
      this.terminal(active, "run_aborted", {
        reason,
        run_request_id: active.requestId,
        run_correlation_id: active.correlationId,
      });
    } catch (error) {
      await this.failClosed("abort-failed", active);
      throw error;
    }
  }

  private async abortWithBound(reason: string): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const abortPromise = this.session.abort();
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Pi abort timed out after ${reason}`)), this.abortTimeoutMs);
    });
    try {
      await Promise.race([abortPromise, timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private terminal(
    active: ActiveRun,
    kind: "run_settled" | "run_aborted" | "error",
    payload: Record<string, JsonValue>,
  ): void {
    if (active.terminal) return;
    active.terminal = true;
    active.suppressLate = true;
    if (active.deadline !== undefined) clearTimeout(active.deadline);
    const terminalRequestId = kind === "run_aborted" ? (active.abortRequestId ?? active.requestId) : active.requestId;
    const terminalCorrelationId =
      kind === "run_aborted" ? (active.abortCorrelationId ?? active.correlationId) : active.correlationId;
    this.emitOrFail(kind, terminalCorrelationId, terminalRequestId, payload);
    if (this.active === active) this.active = undefined;
    if (this.phase === "running" || this.phase === "aborting") this.phase = "open";
  }

  private stateSync(): RunState {
    if (this.phase === "disposed" || this.phase === "failed") return "shutdown";
    if (this.phase === "aborting") return "aborting";
    const active = this.active;
    if (active !== undefined && !active.terminal) return "running";
    return this.sessionManager.getEntries().some((entry) => entry.type === "message") ? "settled" : "idle";
  }

  private usage(): JsonValue {
    const stats = this.session.getSessionStats();
    return sanitizeJson(
      {
        model: `${this.model.provider}/${this.model.id}`,
        tokens: stats.tokens,
        cost: stats.cost,
        entries: this.sessionManager.getEntries().length,
      },
      { secrets: [this.runtime.secret.value] },
    );
  }

  private forwardEvent(event: { type: string; [key: string]: unknown }): void {
    const active = this.active;
    if (
      this.phase === "disposed" ||
      this.phase === "failed" ||
      this.phase === "aborting" ||
      active?.suppressLate === true
    )
      return;
    const correlation = active?.correlationId ?? "system";
    const request = active?.requestId;
    if (event.type === "agent_settled") return;
    if (event.type === "tool_execution_start") {
      this.publishOrClose("tool_start", correlation, request, { event: this.redactEvent(event) });
    } else if (event.type === "tool_execution_update") {
      this.publishOrClose("tool_update", correlation, request, { event: this.redactEvent(event) });
    } else if (event.type === "tool_execution_end") {
      this.publishOrClose("tool_end", correlation, request, { event: this.redactEvent(event) });
    } else if (event.type === "turn_end") {
      this.publishOrClose("usage", correlation, request, this.usageObject());
    } else {
      this.publishOrClose("pi_event", correlation, request, { event: this.redactEvent(event) });
    }
  }

  private usageObject(): Record<string, JsonValue> {
    const usage = this.usage();
    return typeof usage === "object" && usage !== null && !Array.isArray(usage)
      ? (usage as Record<string, JsonValue>)
      : {};
  }

  private redactEvent(event: { type: string; [key: string]: unknown }): Record<string, JsonValue> {
    return sanitizeJson(event, { secrets: [this.runtime.secret.value] }) as Record<string, JsonValue>;
  }

  private emitOrFail(
    kind: ApiEvent["kind"],
    correlationId: string,
    requestId: string | undefined,
    payload: Record<string, JsonValue>,
  ): void {
    if (!this.publishEvent(kind, correlationId, requestId, payload)) {
      const active = this.active;
      void this.failClosed("publish-failed", active).catch(() => undefined);
      throw new Error("Pi event publication failed");
    }
  }

  private publishOrClose(
    kind: ApiEvent["kind"],
    correlationId: string,
    requestId: string | undefined,
    payload: Record<string, JsonValue>,
  ): void {
    if (!this.publishEvent(kind, correlationId, requestId, payload)) {
      void this.failClosed("publish-failed", this.active).catch(() => undefined);
    }
  }

  private publishEvent(
    kind: ApiEvent["kind"],
    correlationId: string,
    requestId: string | undefined,
    payload: Record<string, JsonValue>,
  ): boolean {
    if (this.phase === "failed" || this.phase === "disposed") return false;
    const event = {
      kind,
      correlation_id: opaqueOrSystem(correlationId),
      ...(requestId === undefined ? {} : { request_id: requestId }),
      payload: sanitizeJson(payload, { secrets: [this.runtime.secret.value] }) as Record<string, JsonValue>,
    } satisfies ApiEvent;
    try {
      return this.runtime.emit(event) !== false;
    } catch {
      return false;
    }
  }

  private async failClosed(_reason: string, active: ActiveRun | undefined): Promise<void> {
    if (this.cleanupPromise !== undefined) return this.cleanupPromise;
    if (this.phase === "failed" || this.phase === "disposed") return;
    this.phase = "aborting";
    if (active !== undefined) {
      active.suppressLate = true;
      if (active.deadline !== undefined) clearTimeout(active.deadline);
    }
    this.cleanupPromise = (async () => {
      try {
        await this.abortWithBound("fail-closed");
      } catch {
        // Non-cooperative abort is represented by the failed-closed phase.
      } finally {
        this.unsubscribe();
        this.session.dispose();
        this.#authStorage.removeRuntimeApiKey(this.runtime.provider);
        this.runtime.secret.value = "";
        this.active = undefined;
        this.phase = "failed";
        this.invokeFatal(_reason);
      }
    })();
    await this.cleanupPromise;
  }

  private invokeFatal(reason: string): void {
    if (this.fatalEmitted) return;
    this.fatalEmitted = true;
    queueMicrotask(() => {
      Promise.resolve(this.runtime.onFatal(reason)).catch(() => undefined);
    });
  }

  private assertLive(): void {
    if (this.phase !== "open" && this.phase !== "running") throw new Error("Pi session is closed");
  }
}

async function createContainedSessionManager(
  cwd: string,
  sessionRoot: string,
  sessionId: string,
  resumeFile: string | undefined,
): Promise<SessionManager> {
  const realSessionRoot = await ensureRealDirectory(sessionRoot);
  const realSessionDir = await ensureRealDirectory(resolve(realSessionRoot, sessionId));
  if (!contained(realSessionRoot, realSessionDir)) throw new Error("session directory escapes root");
  if (resumeFile === undefined) return SessionManager.create(cwd, realSessionDir);
  if (resumeFile !== basenameOnly(resumeFile)) throw new Error("invalid resume file");
  const candidate = resolve(realSessionDir, resumeFile);
  const rawStat = await lstat(candidate);
  if (!rawStat.isFile() || rawStat.isSymbolicLink()) throw new Error("invalid resume file");
  const realCandidate = await realpath(candidate);
  if (!contained(realSessionDir, realCandidate)) throw new Error("resume file escapes session directory");
  await access(realCandidate, constants.R_OK);
  return SessionManager.open(realCandidate, realSessionDir, cwd);
}

async function ensureRealDirectory(path: string): Promise<string> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const original = await lstat(path);
  if (!original.isDirectory() || original.isSymbolicLink()) throw new Error("invalid session directory");
  const real = await realpath(path);
  const stat = await lstat(real);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("invalid session directory");
  return real;
}

function contained(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(`${root}${sep}`);
}

function basenameOnly(path: string): string {
  const normalized = path.replaceAll("\\", "/");
  const parts = normalized.split("/");
  return parts.at(-1) ?? path;
}

function createCogsTools(ports: CogsToolPorts, maxResultBytes: number, secret: SecretHolder) {
  const result = async (name: CogsPiToolName, operation: () => Promise<JsonValue>) => {
    try {
      const value = normalizeToolResult(await operation(), maxResultBytes, secret.value);
      return { content: [{ type: "text" as const, text: JSON.stringify(value) }], details: { cogsTool: name } };
    } catch {
      throw new Error(`${name} tool failed`);
    }
  };
  return [
    defineTool({
      name: "read",
      label: "Read",
      description: "Read a file from the Cogs sandbox through the injected read port.",
      parameters: Type.Object(
        {
          path: Type.String({ minLength: 1, maxLength: 4096 }),
          offset: Type.Optional(Type.Integer({ minimum: 0, maximum: 1_000_000 })),
          limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 10_000 })),
        },
        { additionalProperties: false },
      ),
      execute: async (_id, params, signal) => result("read", () => ports.read(withSignal(params, signal))),
    }),
    defineTool({
      name: "write",
      label: "Write",
      description: "Write a file in the Cogs sandbox through the injected write port.",
      parameters: Type.Object(
        { path: Type.String({ minLength: 1, maxLength: 4096 }), content: Type.String({ maxLength: 1_000_000 }) },
        { additionalProperties: false },
      ),
      execute: async (_id, params, signal) => result("write", () => ports.write(withSignal(params, signal))),
    }),
    defineTool({
      name: "edit",
      label: "Edit",
      description: "Edit a file in the Cogs sandbox through the injected edit port.",
      parameters: Type.Object(
        {
          path: Type.String({ minLength: 1, maxLength: 4096 }),
          oldText: Type.String({ minLength: 1, maxLength: 1_000_000 }),
          newText: Type.String({ maxLength: 1_000_000 }),
        },
        { additionalProperties: false },
      ),
      execute: async (_id, params, signal) => result("edit", () => ports.edit(withSignal(params, signal))),
    }),
    defineTool({
      name: "bash",
      label: "Bash",
      description: "Run a shell command in the Cogs sandbox through the injected bash port.",
      parameters: Type.Object(
        { command: Type.String({ minLength: 1, maxLength: 100_000 }) },
        { additionalProperties: false },
      ),
      execute: async (_id, params, signal, onUpdate) =>
        result("bash", () => {
          const update = toolUpdate(
            onUpdate as ((update: unknown) => void | Promise<void>) | undefined,
            maxResultBytes,
            secret.value,
          );
          return ports.bash(
            update === undefined ? withSignal(params, signal) : { ...withSignal(params, signal), onUpdate: update },
          );
        }),
    }),
  ];
}

function withSignal<T extends object>(params: T, signal: AbortSignal | undefined): T & { signal?: AbortSignal } {
  return signal === undefined ? params : { ...params, signal };
}

function toolUpdate(
  onUpdate: ((update: unknown) => void | Promise<void>) | undefined,
  maxBytes: number,
  apiKey: string,
) {
  if (onUpdate === undefined) return undefined;
  if (apiKey.length > 8192) throw new Error("api key too large for streaming redaction");
  let emittedUpdates = 0;
  const tails = new Map<string, string>();
  const templates = new Map<string, { content: [{ type: "text"; text: string }]; details: JsonValue }>();
  const safeEmit = async (update: { content: [{ type: "text"; text: string }]; details: JsonValue }) => {
    emittedUpdates += 1;
    if (emittedUpdates > BASH_TOOL_UPDATE_EMIT_LIMIT) throw new Error("bash update limit exceeded");
    const normalized = normalizeToolResult(update, maxBytes, apiKey);
    if (!isToolUpdateResult(normalized)) throw new Error("invalid tool update");
    await onUpdate(normalized);
  };
  const safeEmitChunkPieces = async (
    template: { content: [{ type: "text"; text: string }]; details: JsonValue },
    stream: string,
    chunk: string,
  ) => {
    for (const piece of splitScalarPieces(chunk, streamUpdatePieceLimit(maxBytes))) {
      const rebuilt = rebuildBashChunkUpdate(template, stream, piece);
      JSON.parse(rebuilt.content[0].text);
      if (Buffer.byteLength(rebuilt.content[0].text, "utf8") > 4096) throw new Error("bash update chunk too large");
      if (Buffer.byteLength(JSON.stringify(rebuilt), "utf8") > maxBytes) throw new Error("bash update too large");
      await safeEmit(rebuilt);
    }
  };
  const flushStream = async (stream: string) => {
    const tail = tails.get(stream) ?? "";
    if (tail.length === 0) return;
    const template = templates.get(stream);
    if (template === undefined) throw new Error("missing bash update template");
    const processed = redactStreamingPrefix(tail, apiKey, tail.length);
    tails.set(stream, processed.tail);
    if (processed.emit.length > 0) await safeEmitChunkPieces(template, stream, processed.emit);
  };
  return async (update: { content: [{ type: "text"; text: string }]; details: JsonValue }) => {
    assertToolJson(update, 64 * 1024);
    const parsed = parseBashChunkUpdate(update);
    if (parsed === undefined) {
      if (!isBashTerminalUpdate(update)) throw new Error("invalid bash update");
      for (const stream of [...tails.keys()]) await flushStream(stream);
      await safeEmit(update);
      return;
    }
    const template = normalizeToolResult(rebuildBashChunkUpdate(update, parsed.stream, ""), maxBytes, apiKey);
    if (!isToolUpdateResult(template)) throw new Error("invalid tool update");
    templates.set(parsed.stream, template);
    const prior = tails.get(parsed.stream) ?? "";
    const joined = prior + parsed.chunk;
    const cut = scalarPrefixLength(joined, Math.max(0, joined.length - Math.max(0, apiKey.length - 1)));
    const processed = redactStreamingPrefix(joined, apiKey, cut);
    tails.set(parsed.stream, processed.tail);
    if (processed.emit.length > 0) await safeEmitChunkPieces(template, parsed.stream, processed.emit);
  };
}

function redactStreamingPrefix(joined: string, secret: string, cut: number): { emit: string; tail: string } {
  if (secret.length === 0) return { emit: joined.slice(0, cut), tail: joined.slice(cut) };
  let processed = 0;
  let emit = "";
  while (true) {
    const index = joined.indexOf(secret, processed);
    if (index < 0 || index >= cut) break;
    emit += `${joined.slice(processed, index)}[REDACTED]`;
    processed = index + secret.length;
  }
  const safeCut = Math.max(processed, cut);
  emit += joined.slice(processed, safeCut);
  return { emit, tail: joined.slice(safeCut) };
}

function scalarPrefixLength(value: string, requested: number): number {
  if (requested <= 0) return 0;
  let end = Math.min(value.length, requested);
  const last = value.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return end;
}

function streamUpdatePieceLimit(maxBytes: number): number {
  const usable = Math.max(1, Math.min(maxBytes, 4096) - 512);
  return Math.max(1, Math.min(512, Math.floor(usable / 12)));
}

function splitScalarPieces(value: string, maxCodeUnits: number): string[] {
  const pieces: string[] = [];
  for (let offset = 0; offset < value.length; ) {
    let end = offset + scalarPrefixLength(value.slice(offset), maxCodeUnits);
    if (end <= offset) {
      const first = value.charCodeAt(offset);
      const second = value.charCodeAt(offset + 1);
      end = first >= 0xd800 && first <= 0xdbff && second >= 0xdc00 && second <= 0xdfff ? offset + 2 : offset + 1;
    }
    pieces.push(value.slice(offset, end));
    offset = end;
  }
  return pieces;
}

const BASH_TOOL_UPDATE_EMIT_LIMIT = 2048;

const BASH_TERMINAL_SIGNAL_NAMES = new Set([
  "SIGABRT",
  "SIGALRM",
  "SIGHUP",
  "SIGFPE",
  "SIGILL",
  "SIGINT",
  "SIGKILL",
  "SIGPIPE",
  "SIGQUIT",
  "SIGSEGV",
  "SIGTERM",
  "SIGUSR1",
  "SIGUSR2",
]);

function isBashTerminalUpdate(value: { content: [{ type: "text"; text: string }]; details: JsonValue }): boolean {
  if (typeof value.details !== "object" || value.details === null) return false;
  if (!hasExactKeys(value.details, ["cogsTool", "terminal"])) return false;
  const details = value.details as { cogsTool?: unknown; terminal?: unknown };
  if (details.cogsTool !== "bash" || details.terminal !== true) return false;
  try {
    const parsed = JSON.parse(value.content[0].text) as unknown;
    if (typeof parsed !== "object" || parsed === null) return false;
    if (!hasExactKeys(parsed, ["terminal", "exitCode", "signal"])) return false;
    const entry = parsed as { terminal?: unknown; exitCode?: unknown; signal?: unknown };
    if (entry.terminal !== true) return false;
    if (Number.isInteger(entry.exitCode) && (entry.exitCode as number) >= 0 && (entry.exitCode as number) <= 255) {
      return entry.signal === null;
    }
    return entry.exitCode === null && typeof entry.signal === "string" && BASH_TERMINAL_SIGNAL_NAMES.has(entry.signal);
  } catch {
    return false;
  }
}

function hasExactKeys(value: object, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && expected.every((key, index) => actual[index] === key);
}

function parseBashChunkUpdate(value: {
  content: [{ type: "text"; text: string }];
  details: JsonValue;
}): { stream: string; chunk: string } | undefined {
  if (typeof value.details !== "object" || value.details === null) return undefined;
  const details = value.details as { cogsTool?: unknown; stream?: unknown };
  if (details.cogsTool !== "bash" || (details.stream !== "stdout" && details.stream !== "stderr")) return undefined;
  try {
    const parsed = JSON.parse(value.content[0].text) as unknown;
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const entry = parsed as { stream?: unknown; chunk?: unknown };
    return entry.stream === details.stream && typeof entry.chunk === "string"
      ? { stream: details.stream, chunk: entry.chunk }
      : undefined;
  } catch {
    return undefined;
  }
}

function rebuildBashChunkUpdate(
  template: { content: [{ type: "text"; text: string }]; details: JsonValue },
  stream: string,
  chunk: string,
): { content: [{ type: "text"; text: string }]; details: JsonValue } {
  return { ...template, content: [{ type: "text", text: JSON.stringify({ stream, chunk }) }] };
}

function isToolUpdateResult(
  value: JsonValue,
): value is { content: [{ type: "text"; text: string }]; details: JsonValue } {
  return (
    typeof value === "object" &&
    value !== null &&
    Array.isArray((value as { content?: unknown }).content) &&
    (value as { content: unknown[] }).content.length === 1 &&
    typeof (value as { content: [{ type?: unknown; text?: unknown }] }).content[0]?.text === "string" &&
    (value as { content: [{ type?: unknown }] }).content[0]?.type === "text" &&
    "details" in value
  );
}

function normalizeToolResult(value: unknown, maxBytes: number, apiKey: string): JsonValue {
  assertToolJson(value, maxBytes);
  const normalized = sanitizeJson(value, { secrets: [apiKey] });
  if (Buffer.byteLength(JSON.stringify(normalized), "utf8") > maxBytes) throw new Error("tool result too large");
  return normalized;
}

function assertToolJson(value: unknown, maxBytes: number): void {
  const seen = new WeakSet<object>();
  let bytes = 0;
  let nodes = 0;
  const visit = (entry: unknown): void => {
    nodes += 1;
    if (nodes > 2048) throw new Error("tool result too complex");
    if (entry === null || typeof entry === "boolean") return;
    if (typeof entry === "number") {
      if (!Number.isFinite(entry)) throw new Error("tool result contains non-finite number");
      return;
    }
    if (typeof entry === "string") {
      bytes += Buffer.byteLength(entry, "utf8");
      if (bytes > maxBytes) throw new Error("tool result too large");
      return;
    }
    if (Array.isArray(entry)) {
      if (seen.has(entry)) throw new Error("tool result contains cycle");
      seen.add(entry);
      for (const item of entry) visit(item);
      return;
    }
    if (typeof entry === "object") {
      if (seen.has(entry)) throw new Error("tool result contains cycle");
      if (Object.getPrototypeOf(entry) !== Object.prototype) throw new Error("tool result has unsupported prototype");
      seen.add(entry);
      for (const key of Object.keys(entry)) {
        const descriptor = Object.getOwnPropertyDescriptor(entry, key);
        if (descriptor === undefined || !("value" in descriptor)) throw new Error("tool result contains accessor");
        visit(descriptor.value);
      }
      return;
    }
    throw new Error("tool result is not JSON");
  };
  visit(value);
}

function sanitizeJson(value: unknown, options: { secrets: readonly string[] }): JsonValue {
  const seen = new WeakSet<object>();
  let nodes = 0;
  let bytes = 0;
  const visit = (entry: unknown, depth: number, key?: string): JsonValue => {
    nodes += 1;
    if (nodes > 2048 || depth > 16) return "[truncated]";
    if (key !== undefined && SENSITIVE_FIELD.test(key)) return "[redacted]";
    if (entry === null || typeof entry === "boolean") return entry;
    if (typeof entry === "number") return Number.isFinite(entry) ? entry : null;
    if (typeof entry === "string") {
      const bounded = redactStringBounded(entry, options.secrets, 4096);
      bytes += Buffer.byteLength(bounded, "utf8");
      if (bytes > 64 * 1024) return "[truncated]";
      return bounded;
    }
    if (Array.isArray(entry)) return entry.slice(0, 128).map((item) => visit(item, depth + 1));
    if (typeof entry === "object") {
      if (seen.has(entry)) return "[cycle]";
      seen.add(entry);
      const output: Record<string, JsonValue> = {};
      for (const keyName of Object.keys(entry).slice(0, 128)) {
        const descriptor = Object.getOwnPropertyDescriptor(entry, keyName);
        if (descriptor === undefined || !("value" in descriptor)) {
          output[keyName] = "[unreadable]";
        } else {
          output[keyName] = visit(descriptor.value, depth + 1, keyName);
        }
      }
      return output;
    }
    return null;
  };
  return visit(value, 0);
}

function redactStringBounded(value: string, secrets: readonly string[], maximum: number): string {
  const truncated = value.length > maximum;
  const truncationMarker = truncated ? "[truncated]" : "";
  const contentBudget = Math.max(0, maximum - truncationMarker.length);
  const scanLimit = Math.min(value.length, maximum);
  let output = "";
  let chunkStart = 0;
  let index = 0;
  while (index < scanLimit) {
    const match = findSecretAt(value, index, secrets);
    if (match === undefined) {
      index += 1;
      continue;
    }
    output = appendBounded(output, value.slice(chunkStart, index), contentBudget);
    output = appendMarker(output, "[redacted]", contentBudget);
    index += match.length;
    chunkStart = index;
  }
  if (chunkStart < scanLimit) output = appendBounded(output, value.slice(chunkStart, scanLimit), contentBudget);
  return `${output}${truncationMarker}`;
}

function appendBounded(output: string, chunk: string, budget: number): string {
  const remaining = budget - output.length;
  if (remaining <= 0) return output;
  return `${output}${chunk.slice(0, remaining)}`;
}

function appendMarker(output: string, marker: string, budget: number): string {
  if (marker.length > budget) return marker.slice(0, budget);
  if (output.length + marker.length <= budget) return `${output}${marker}`;
  return `${output.slice(0, budget - marker.length)}${marker}`;
}

function findSecretAt(value: string, index: number, secrets: readonly string[]): string | undefined {
  let longest: string | undefined;
  for (const secret of secrets) {
    if (secret.length === 0) continue;
    if (value.startsWith(secret, index) && (longest === undefined || secret.length > longest.length)) longest = secret;
  }
  return longest;
}

function assertRuntimeSecret(value: string, label: string): void {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < 8 || bytes > 8192 || hasControl(value)) throw new Error(`invalid ${label}`);
}

function assertProviderId(value: string, label: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/+.-]{0,127}$/.test(value)) throw new Error(`invalid ${label}`);
}

function assertModelId(value: string, label: string): void {
  if (value.length < 1 || value.length > 256 || hasControl(value)) throw new Error(`invalid ${label}`);
}

function hasControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code !== undefined && (code < 0x20 || code === 0x7f)) return true;
  }
  return false;
}

function assertInputKind(value: string): asserts value is InputKind {
  if (value !== "prompt" && value !== "steer" && value !== "follow_up") throw new Error("invalid input kind");
}

function assertOpaqueId(value: string, label: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) throw new Error(`invalid ${label}`);
}

function opaqueOrSystem(value: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value) ? value : "system";
}

async function throwIfAborted(signal: AbortSignal | undefined): Promise<void> {
  if (signal?.aborted) throw new Error("operation aborted");
}

function isAbortLike(error: unknown): boolean {
  return error instanceof Error && /aborted|abort|cancel/i.test(error.message);
}
