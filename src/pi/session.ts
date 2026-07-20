import { constants } from "node:fs";
import { access, lstat, mkdir, realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import type { Api, Model } from "@earendil-works/pi-ai/compat";
import {
  AuthStorage,
  createAgentSession,
  createExtensionRuntime,
  createSyntheticSourceInfo,
  defineTool,
  ModelRegistry,
  type ResourceLoader,
  SessionManager,
  SettingsManager,
  type Skill,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import type { ApiEvent, ExportPort, HistoryPort, InputKind, JsonValue, RunState, SessionPort } from "../api/server.ts";
import { type CogsCommandAuditHook, captureCogsCommandAuditHook } from "../audit/command-audit.ts";
import { type ModelApiKeySource, ModelCredentialResolver, validateModelApiKey } from "../auth/model-auth.ts";
import { validateLaunchConfig } from "../launch/config.ts";
import { type CogsPolicyAuthorizer, CogsPolicyDeniedError, requireCogsPolicyAllow } from "../policy/require-policy.ts";
import {
  type CogsGitCheckpointConfig,
  type CogsGitCheckpointer,
  type CogsGitCheckpointResult,
  checkpointEvent,
  checkpointRecord,
  createSshGitCheckpointer,
} from "../session/git-checkpoint.ts";
import {
  type CogsGitMapRecord,
  type CogsGitMapResolveResult,
  type CogsGitMapStore,
  createCogsGitMapStore,
} from "../session/git-map.ts";
import {
  type CogsGitObservation,
  type CogsGitObserver,
  createSshGitObserver,
  gitObservationEvent,
} from "../session/git-observer.ts";
import {
  CogsJsonlHistoryCursorError,
  type CogsJsonlHistoryStore,
  createCogsJsonlHistoryStore,
} from "../session/jsonl-history.ts";
import { type CogsLocalExporter, createCogsLocalExporter } from "../session/local-export.ts";
import type {
  CogsAgentsFile,
  CogsPreparedSkillMetadata,
  CogsPreparedSkills,
  CogsSkillPreparerPort,
} from "../skills/session-preparer.ts";
import type { SshConnectionManager } from "../ssh/connection.ts";
import {
  byteBucket,
  type CogsTelemetry,
  captureTelemetry,
  emitMetric,
  emitSpan,
  emitTelemetryHealth,
  TelemetryHealthCursor,
  telemetryDuration,
  telemetryStart,
} from "../telemetry/instrumentation.ts";
import {
  type CogsPiOwnedRuntimeCleanupResult,
  type CogsPiOwnedRuntimeOptions,
  type CogsPiOwnedRuntimeTracker,
  createCogsPiOwnedRuntimeTracker,
  snapshotCogsPiOwnedRuntimeOptions,
} from "./owned-runtime.ts";

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
  readonly userId: string;
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
  readonly preparedResources?: CogsPreparedSkills;
  readonly git?: CogsPiGitOptions;
  readonly policyAuthorizer?: CogsPolicyAuthorizer;
  readonly telemetry?: CogsTelemetry;
  readonly commandAudit?: CogsCommandAuditHook;
  readonly ownedRuntime?: CogsPiOwnedRuntimeOptions;
}

export interface CogsPiGitOptions {
  readonly repositoryId: string;
  readonly manager?: SshConnectionManager;
  readonly observer?: CogsGitObserver;
  readonly enableNotes?: boolean;
  readonly checkpoint?: CogsGitCheckpointConfig;
  readonly checkpointer?: CogsGitCheckpointer;
}

export interface AuthenticatedCogsPiSessionOptions
  extends Omit<CogsPiSessionOptions, "userId" | "sessionId" | "model" | "apiKey"> {
  readonly launchDocument: unknown;
  readonly modelApiKeys: ModelApiKeySource;
  readonly skillPreparer: CogsSkillPreparerPort;
  readonly signal?: AbortSignal;
}

export interface CogsPiSessionPorts extends SessionPort, HistoryPort, ExportPort {
  readonly dispose: () => Promise<void>;
  readonly disposeOwnedRuntime: () => Promise<CogsPiOwnedRuntimeCleanupResult>;
  readonly model: Model<Api>;
  readonly activeToolNames: () => readonly string[];
  readonly sessionFile: () => string | undefined;
  readonly skillMetadata: () => CogsPreparedSkillMetadata | undefined;
  readonly gitMapRecords: () => readonly CogsGitMapRecord[];
  readonly resolveGitMapping: (input: {
    repo: string;
    commit: string;
    signal?: AbortSignal;
  }) => Promise<CogsGitMapResolveResult | undefined>;
  readonly prepareShutdown: (input: {
    requestId: string;
    correlationId: string;
    signal?: AbortSignal;
  }) => Promise<JsonValue>;
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
  if (options.policyAuthorizer !== undefined) validatePolicyAuthorizer(options.policyAuthorizer);
  captureTelemetry(options.telemetry);
  captureCogsCommandAuditHook(options.commandAudit);
  validateOptionalInteger(options.abortTimeoutMs, "abortTimeoutMs", 1, 60_000);
  validateOptionalInteger(options.maxToolResultBytes, "maxToolResultBytes", 128, 1024 * 1024);
  snapshotCogsPiOwnedRuntimeOptions(options.ownedRuntime);
}

function validatePolicyAuthorizer(value: unknown): asserts value is CogsPolicyAuthorizer {
  try {
    if (typeof value !== "function" || !Object.isFrozen(value)) throw new Error("invalid policy authorizer");
  } catch {
    throw new Error("invalid policy authorizer");
  }
}

function validateOptionalInteger(value: number | undefined, label: string, minimum: number, maximum: number): void {
  if (value === undefined) return;
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`invalid ${label}`);
}

function validateGitOptions(value: CogsPiGitOptions | undefined): CogsPiGitOptions | undefined {
  try {
    if (value === undefined) return undefined;
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid git options");
    if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error("invalid git options");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const allowed = ["repositoryId", "manager", "observer", "enableNotes", "checkpoint", "checkpointer"];
    if (!keys.every((key) => typeof key === "string" && allowed.includes(key))) throw new Error("invalid git options");
    if (
      !descriptors.repositoryId ||
      !("value" in descriptors.repositoryId) ||
      descriptors.repositoryId.enumerable !== true
    )
      throw new Error("invalid git options");
    const repositoryId = descriptors.repositoryId.value;
    const manager = dataValue(descriptors, "manager");
    const observer = dataValue(descriptors, "observer");
    const enableNotes = dataValue(descriptors, "enableNotes");
    const checkpoint = dataValue(descriptors, "checkpoint");
    const checkpointer = dataValue(descriptors, "checkpointer");
    if (typeof repositoryId !== "string") throw new Error("invalid git options");
    assertOpaqueId(repositoryId, "repository id");
    if ((manager === undefined) === (observer === undefined)) throw new Error("invalid git options");
    if (observer !== undefined) validateObserverShape(observer);
    if (manager !== undefined) validateManagerShape(manager);
    if (enableNotes !== undefined && typeof enableNotes !== "boolean") throw new Error("invalid git options");
    const normalizedCheckpoint = validateCheckpointOptions(checkpoint);
    if (checkpointer !== undefined) validateCheckpointerShape(checkpointer);
    if (normalizedCheckpoint?.enabled === true && manager === undefined && checkpointer === undefined)
      throw new Error("invalid git options");
    if (checkpointer !== undefined && normalizedCheckpoint !== undefined) throw new Error("invalid git options");
    return Object.freeze({
      repositoryId,
      ...(manager === undefined ? {} : { manager: manager as SshConnectionManager }),
      ...(observer === undefined ? {} : { observer: observer as CogsGitObserver }),
      ...(enableNotes === undefined ? {} : { enableNotes }),
      ...(normalizedCheckpoint === undefined ? {} : { checkpoint: normalizedCheckpoint }),
      ...(checkpointer === undefined ? {} : { checkpointer: checkpointer as CogsGitCheckpointer }),
    }) as CogsPiGitOptions;
  } catch {
    throw new Error("invalid git options");
  }
}

function dataValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor) || descriptor.enumerable !== true) throw new Error("invalid git options");
  return descriptor.value;
}

function validateCheckpointOptions(value: unknown): CogsGitCheckpointConfig | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid git options");
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error("invalid git options");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const allowed = [
    "enabled",
    "exclusions",
    "maxChangedFiles",
    "maxFileBytes",
    "maxTotalBytes",
    "maxOutputBytes",
    "timeoutMs",
  ];
  if (!keys.every((key) => typeof key === "string" && allowed.includes(key))) throw new Error("invalid git options");
  const enabled = dataValue(descriptors, "enabled");
  if (typeof enabled !== "boolean") throw new Error("invalid git options");
  const exclusions = dataValue(descriptors, "exclusions");
  const config: CogsGitCheckpointConfig = { enabled };
  if (exclusions !== undefined) {
    if (!Array.isArray(exclusions) || Object.getPrototypeOf(exclusions) !== Array.prototype)
      throw new Error("invalid git options");
    const arrayDescriptors = Object.getOwnPropertyDescriptors(exclusions);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(exclusions, "length");
    const length =
      lengthDescriptor === undefined || !("value" in lengthDescriptor) ? undefined : lengthDescriptor.value;
    if (!Number.isInteger(length) || length < 0 || length > 64) throw new Error("invalid git options");
    const copied: string[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = arrayDescriptors[String(index)];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
        throw new Error("invalid git options");
      if (typeof descriptor.value !== "string") throw new Error("invalid git options");
      copied.push(descriptor.value);
    }
    const allowedArrayKeys = new Set(["length", ...copied.map((_, index) => String(index))]);
    if (!Reflect.ownKeys(arrayDescriptors).every((key) => typeof key === "string" && allowedArrayKeys.has(key)))
      throw new Error("invalid git options");
    Object.assign(config, { exclusions: Object.freeze(copied) });
  }
  for (const key of ["maxChangedFiles", "maxFileBytes", "maxTotalBytes", "maxOutputBytes", "timeoutMs"] as const) {
    const item = dataValue(descriptors, key);
    if (item !== undefined) {
      if (!Number.isInteger(item)) throw new Error("invalid git options");
      const bounds = checkpointBounds(key);
      if ((item as number) < bounds[0] || (item as number) > bounds[1]) throw new Error("invalid git options");
      Object.assign(config, { [key]: item });
    }
  }
  return Object.freeze(config);
}

function checkpointBounds(key: string): readonly [number, number] {
  switch (key) {
    case "maxChangedFiles":
      return [1, 4096];
    case "maxFileBytes":
      return [0, 32 * 1024 * 1024];
    case "maxTotalBytes":
      return [0, 128 * 1024 * 1024];
    case "maxOutputBytes":
      return [1024, 4 * 1024 * 1024];
    default:
      return [1, 60_000];
  }
}

function validateObserverShape(value: unknown): void {
  if (value === null || typeof value !== "object" || !Object.isFrozen(value)) throw new Error("invalid git options");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors).sort();
  if (keys.join("\0") !== ["appendNote", "dispose", "nearestAncestor", "observeHead"].join("\0"))
    throw new Error("invalid git options");
  for (const key of keys) {
    if (typeof key !== "string") throw new Error("invalid git options");
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid git options");
    if (typeof descriptor.value !== "function") throw new Error("invalid git options");
  }
}

function validateCheckpointerShape(value: unknown): void {
  if (value === null || typeof value !== "object" || !Object.isFrozen(value)) throw new Error("invalid git options");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors).sort();
  if (keys.join("\0") !== ["checkpoint", "dispose"].join("\0")) throw new Error("invalid git options");
  for (const key of keys) {
    if (typeof key !== "string") throw new Error("invalid git options");
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid git options");
    if (typeof descriptor.value !== "function") throw new Error("invalid git options");
  }
}

function validateManagerShape(value: unknown): void {
  if (value === null || typeof value !== "object") throw new Error("invalid git options");
  let current: object | null = value;
  const seen = new Set<object>();
  for (let depth = 0; current !== null && depth < 8; depth += 1) {
    if (seen.has(current)) throw new Error("invalid git options");
    seen.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, "withBashExec");
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") throw new Error("invalid git options");
      return;
    }
    current = Object.getPrototypeOf(current);
  }
  throw new Error("invalid git options");
}

export function createLockedResourceLoader(
  input: {
    readonly systemPrompt?: string;
    readonly skills?: readonly Skill[];
    readonly agentsFiles?: readonly { readonly path: string; readonly content: string }[];
    readonly appendSystemPrompt?: readonly string[];
  } = {},
): ResourceLoader {
  const runtime = createExtensionRuntime();
  const skills = Object.freeze([...(input.skills ?? [])]);
  const agentsFiles = Object.freeze([...(input.agentsFiles ?? [])]);
  const appendSystemPrompt = Object.freeze([...(input.appendSystemPrompt ?? [])]);
  return {
    getExtensions: () => ({ extensions: [], errors: [], runtime }),
    getSkills: () => ({ skills: [...skills], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [...agentsFiles] }),
    getSystemPrompt: () =>
      input.systemPrompt ?? "You are Cogs. Use only the explicitly supplied read, write, edit, and bash tools.",
    getAppendSystemPrompt: () => [...appendSystemPrompt],
    extendResources: () => {},
    reload: async () => {},
  };
}

function debugPiStage(stage: string): void {
  if (process.env.COGS_LAUNCHER_DEBUG_STAGE === "1") process.stderr.write(`launcher-debug-stage:${stage}\n`);
}

export async function createAuthenticatedCogsPiSession({
  launchDocument,
  modelApiKeys,
  skillPreparer,
  signal,
  git,
  ...sessionOptions
}: AuthenticatedCogsPiSessionOptions): Promise<CogsPiSessionPorts> {
  const launch = validateLaunchConfig(launchDocument);
  debugPiStage("pi-launch-validated");
  const authenticatedGit = validateGitOptions(git);
  const prepareSkills = validateSkillPreparer(skillPreparer);
  debugPiStage("pi-skill-preparer-validated");
  let preparedResources: CogsPreparedSkills;
  try {
    const rawPrepared = await prepareSkills({ launch, ...(signal === undefined ? {} : { signal }) });
    try {
      preparedResources = validatePreparedResources(rawPrepared);
      debugPiStage("pi-skills-prepared");
    } catch (error) {
      await disposeMalformedPrepared(rawPrepared);
      throw error;
    }
  } catch {
    throw new Error("skill preparation failed");
  }
  const resolver = new ModelCredentialResolver(modelApiKeys);
  try {
    return await resolver.withApiKey(
      {
        userId: launch.user_id,
        provider: launch.model.provider,
        model: launch.model.id,
        credentialHandle: launch.model.credential_handle,
        ...(signal === undefined ? {} : { signal }),
      },
      async (apiKey) => {
        debugPiStage("pi-credential-resolved");
        const session = await createCogsPiSession({
          ...sessionOptions,
          userId: launch.user_id,
          sessionId: launch.session_id,
          model: { provider: launch.model.provider, id: launch.model.id },
          apiKey,
          preparedResources,
          ...(authenticatedGit === undefined
            ? {}
            : {
                git: Object.freeze({
                  repositoryId: launch.workspace_id,
                  ...(authenticatedGit.manager === undefined ? {} : { manager: authenticatedGit.manager }),
                  ...(authenticatedGit.observer === undefined ? {} : { observer: authenticatedGit.observer }),
                  ...(authenticatedGit.enableNotes === undefined ? {} : { enableNotes: authenticatedGit.enableNotes }),
                }),
              }),
        });
        debugPiStage("pi-create-cogs-pi-return");
        return session;
      },
    );
  } catch (error) {
    let cleanupError: unknown;
    try {
      await preparedResources.dispose();
    } catch (disposeError) {
      cleanupError = disposeError;
    }
    if (cleanupError !== undefined) throw new Error("Pi session cleanup failed");
    throw error;
  }
}

export async function createCogsPiSession(options: CogsPiSessionOptions): Promise<CogsPiSessionPorts> {
  validateOptions(options);
  debugPiStage("pi-options");
  const cwd = options.cwd;
  const agentDir = options.agentDir;
  const userId = options.userId;
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
  const policyAuthorizer = options.policyAuthorizer;
  const rawPreparedResources = options.preparedResources;
  const telemetry = captureTelemetry(options.telemetry);
  captureCogsCommandAuditHook(options.commandAudit);
  const ownedRuntimeOptions = snapshotCogsPiOwnedRuntimeOptions(options.ownedRuntime);

  validateModelApiKey(apiKey);
  const gitOptions = validateGitOptions(options.git);
  assertOpaqueId(userId, "user id");
  assertOpaqueId(sessionId, "session id");
  assertProviderId(modelProvider, "provider id");
  assertModelId(modelId, "model id");

  const secret: SecretHolder = { value: apiKey };
  let preparedResources: CogsPreparedSkills | undefined;
  let startupGitBinding: CogsGitBoundary | undefined;
  let startupLocalExporter: CogsLocalExporter | undefined;
  const ownedRuntime =
    ownedRuntimeOptions === undefined
      ? undefined
      : createCogsPiOwnedRuntimeTracker({
          agentDir,
          sessionRoot,
          sessionId,
          options: ownedRuntimeOptions,
          ...(resumeFile === undefined ? {} : { resumeFile }),
        });
  const authStorage = AuthStorage.inMemory();
  let ownershipStarted = false;
  try {
    await ownedRuntime?.begin();
    ownershipStarted = ownedRuntime !== undefined;
    preparedResources =
      rawPreparedResources === undefined ? undefined : validatePreparedResources(rawPreparedResources);
    requireCogsPolicyAllow(
      {
        version: "cogs.policy/v1alpha1",
        action: "secret.use",
        user: userId,
        session: sessionId,
        resource: "model_api_key_runtime",
        attributes: { secret_class: "model_api_key_runtime" },
      },
      policyAuthorizer,
    );
    authStorage.setRuntimeApiKey(modelProvider, secret.value);
    const modelRegistry = ModelRegistry.inMemory(authStorage);
    const model = modelRegistry.find(modelProvider, modelId);
    debugPiStage("pi-model-found");
    if (!model) throw new Error("unknown model");
    if (modelRegistry.isUsingOAuth(model)) throw new Error("oauth model authentication is disabled");

    const sessionManager = await createContainedSessionManager(cwd, sessionRoot, sessionId, resumeFile);
    debugPiStage("pi-session-manager");
    const sessionDir = sessionManager.getSessionDir();
    await ownedRuntime?.adoptSessionDir(sessionDir);
    const historyStore = createCogsJsonlHistoryStore({
      sessionFile: sessionManager.getSessionFile(),
      sessionDir,
      ...(ownedRuntime === undefined ? {} : { onOwnedHistoryMarker: ownedRuntime.recordSessionFile }),
    });
    await historyStore.initialize();
    debugPiStage("pi-history");
    const gitMapStore =
      gitOptions === undefined
        ? undefined
        : await createCogsGitMapStore({
            sessionDir,
            ...(ownedRuntime === undefined ? {} : { onOwnedSidecar: ownedRuntime.recordGitMapFile }),
          });
    const gitObserver =
      gitOptions?.observer ??
      (gitOptions?.manager === undefined
        ? undefined
        : createSshGitObserver({ manager: gitOptions.manager, repositoryId: gitOptions.repositoryId }));
    const gitCheckpointer =
      gitOptions?.checkpointer ??
      (gitOptions?.manager === undefined || gitOptions.checkpoint?.enabled !== true
        ? undefined
        : createSshGitCheckpointer({ manager: gitOptions.manager, config: gitOptions.checkpoint }));
    const localExporter = createCogsLocalExporter({
      sessionDir,
      sessionId,
      history: historyStore,
      ...(gitMapStore === undefined ? {} : { gitMap: gitMapStore }),
      skillMetadata: () => preparedResources?.metadata,
      model: { provider: modelProvider, id: modelId },
      ...(ownedRuntime === undefined
        ? {}
        : {
            onOwnedExportTransition: ownedRuntime.verifyExportTransition,
            onOwnedExportBundle: ownedRuntime.recordExportBundle,
          }),
    });
    startupLocalExporter = localExporter;
    debugPiStage("pi-export");
    const adapterRef: { current?: PiSessionAdapter } = {};
    debugPiStage("pi-git");
    const gitBinding =
      gitOptions === undefined || gitMapStore === undefined || gitObserver === undefined
        ? undefined
        : new CogsGitBoundary({
            sessionId,
            repositoryId: gitOptions.repositoryId,
            store: gitMapStore,
            observer: gitObserver,
            checkpointer: gitCheckpointer,
            checkpointTimeoutMs: gitOptions.checkpoint?.timeoutMs ?? 2500,
            telemetry,
            emit: (kind, correlationId, requestId, payload) =>
              adapterRef.current?.publishGit(kind, correlationId, requestId, payload),
            notes: gitOptions.enableNotes !== false,
          });
    startupGitBinding = gitBinding;
    const toolHooks = gitBinding?.toolHooks();
    for (const tool of COGS_PI_TOOL_NAMES) {
      try {
        requireCogsPolicyAllow(
          {
            version: "cogs.policy/v1alpha1",
            action: "tool.enable",
            user: userId,
            session: sessionId,
            resource: tool,
            attributes: { tool },
          },
          policyAuthorizer,
        );
        emitSpan(telemetry, "tool.enable", { tool, outcome: "ok" });
      } catch (error) {
        emitSpan(telemetry, "tool.enable", { tool, outcome: "denied" });
        throw error;
      }
    }

    const sessionResult = await createAgentSession({
      cwd,
      agentDir,
      model,
      thinkingLevel: "off",
      authStorage,
      modelRegistry,
      resourceLoader: createLockedResourceLoader(
        preparedResources === undefined
          ? {}
          : {
              skills: preparedResources.piSkills,
              agentsFiles: preparedResources.agentsFiles,
              appendSystemPrompt: [preparedResources.eagerTrustedSkillPrompt],
            },
      ),
      customTools: createCogsTools(toolPorts, maxToolResultBytes, secret, toolHooks, {
        userId,
        sessionId,
        telemetry,
        ...(policyAuthorizer === undefined ? {} : { authorizer: policyAuthorizer }),
      }),
      tools: [...COGS_PI_TOOL_NAMES],
      noTools: "builtin",
      sessionManager,
      settingsManager: SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false } }),
    });
    debugPiStage("pi-session-created");
    const session = sessionResult.session;

    if (streamFn !== undefined) {
      session.agent.streamFn = async (activeModel, context, streamOptions) => {
        const apiKey = await authStorage.getApiKey(activeModel.provider, { includeFallback: false });
        if (!apiKey) throw new Error("missing runtime model API key");
        return streamFn(activeModel, context, { ...streamOptions, apiKey });
      };
    }

    const adapter = new PiSessionAdapter(session, authStorage, model, sessionManager, {
      emit,
      onFatal,
      provider: modelProvider,
      userId,
      sessionId,
      secret,
      operationTimeoutMs,
      abortTimeoutMs,
      preparedResources,
      historyStore,
      gitMapStore,
      gitBinding,
      localExporter,
      policyAuthorizer,
      telemetry,
      ownedRuntime,
    });
    adapterRef.current = adapter;
    debugPiStage("pi-ports-return");
    return adapter;
  } catch (error) {
    let cleanupError: unknown;
    for (const cleanup of [
      () => startupLocalExporter?.dispose() ?? Promise.resolve(),
      () => startupGitBinding?.dispose() ?? Promise.resolve(),
      () => preparedResources?.dispose() ?? Promise.resolve(),
    ]) {
      try {
        await cleanup();
      } catch (disposeError) {
        cleanupError = disposeError;
      }
    }
    authStorage.removeRuntimeApiKey(modelProvider);
    secret.value = "";
    if (ownershipStarted) {
      try {
        await ownedRuntime?.cleanup(async () => undefined);
      } catch {
        cleanupError = new Error("Pi owned runtime cleanup failed");
      }
    }
    if (cleanupError !== undefined) throw new Error("Pi session cleanup failed");
    throw error;
  }
}

function validateSkillPreparer(value: CogsSkillPreparerPort): CogsSkillPreparerPort["prepare"] {
  try {
    if (value === null || typeof value !== "object" || !Object.isFrozen(value)) throw new Error("bad preparer");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== 1 || keys[0] !== "prepare") throw new Error("bad preparer");
    const prepare = descriptors.prepare;
    if (prepare === undefined || !("value" in prepare) || typeof prepare.value !== "function")
      throw new Error("bad preparer");
    return prepare.value as CogsSkillPreparerPort["prepare"];
  } catch {
    throw new Error("invalid skill preparer");
  }
}

function validatePreparedResources(value: CogsPreparedSkills): CogsPreparedSkills {
  try {
    const snapshot = exactValues(value, ["piSkills", "eagerTrustedSkillPrompt", "agentsFiles", "metadata", "dispose"]);
    const piSkills = snapshotFrozenArray(snapshot.piSkills, 32).map(canonicalPreparedSkill);
    const prompt = snapshot.eagerTrustedSkillPrompt;
    if (typeof prompt !== "string" || Buffer.byteLength(prompt, "utf8") > 384 * 1024) throw new Error("bad resources");
    const agentsFiles = snapshotFrozenArray(snapshot.agentsFiles, 1).map(canonicalPreparedAgentsFile);
    const metadata = canonicalPreparedMetadata(snapshot.metadata);
    if (typeof snapshot.dispose !== "function") throw new Error("bad resources");
    return Object.freeze({
      piSkills: Object.freeze(piSkills),
      eagerTrustedSkillPrompt: prompt,
      agentsFiles: Object.freeze(agentsFiles),
      metadata,
      dispose: onceAsync(snapshot.dispose as () => Promise<void>),
    });
  } catch {
    throw new Error("invalid prepared skill resources");
  }
}

async function disposeMalformedPrepared(value: unknown): Promise<void> {
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value as object);
    const dispose = descriptors.dispose;
    if (dispose !== undefined && "value" in dispose && typeof dispose.value === "function") await dispose.value();
  } catch {
    // Preparation failure remains generic; best-effort cleanup cannot expose raw errors.
  }
}

function canonicalPreparedSkill(value: unknown): Skill {
  const data = exactValues(value, [
    "name",
    "description",
    "filePath",
    "baseDir",
    "sourceInfo",
    "disableModelInvocation",
  ]);
  if (typeof data.name !== "string" || !isStandardSkillName(data.name)) throw new Error("bad resources");
  if (
    typeof data.description !== "string" ||
    Buffer.byteLength(data.description, "utf8") < 1 ||
    Buffer.byteLength(data.description, "utf8") > 1024
  )
    throw new Error("bad resources");
  if (typeof data.filePath !== "string" || !strictGuestPath(data.filePath)) throw new Error("bad resources");
  if (typeof data.baseDir !== "string" || !strictGuestBaseDir(data.baseDir, data.filePath))
    throw new Error("bad resources");
  if (typeof data.disableModelInvocation !== "boolean") throw new Error("bad resources");
  return Object.freeze({
    name: data.name,
    description: data.description,
    filePath: data.filePath,
    baseDir: data.baseDir,
    sourceInfo: createSyntheticSourceInfo(data.filePath, {
      source: "cogs",
      scope: "project",
      origin: "top-level",
      baseDir: data.baseDir,
    }),
    disableModelInvocation: data.disableModelInvocation,
  });
}

function canonicalPreparedAgentsFile(value: unknown): CogsAgentsFile {
  const data = exactValues(value, ["path", "content"]);
  if (data.path !== "/workspace/AGENTS.md") throw new Error("bad resources");
  if (typeof data.content !== "string" || Buffer.byteLength(data.content, "utf8") > 32 * 1024)
    throw new Error("bad resources");
  return Object.freeze({ path: "/workspace/AGENTS.md" as const, content: data.content });
}

function canonicalPreparedMetadata(value: unknown): CogsPreparedSkills["metadata"] {
  const data = exactValues(value, ["shared", "user", "agentsStatus", "skillCount"]);
  const agentsStatus = data.agentsStatus;
  if (
    agentsStatus !== "loaded" &&
    agentsStatus !== "missing" &&
    agentsStatus !== "permission_denied" &&
    agentsStatus !== "oversize" &&
    agentsStatus !== "invalid" &&
    agentsStatus !== "read_error"
  )
    throw new Error("bad resources");
  if (!Number.isSafeInteger(data.skillCount) || (data.skillCount as number) < 0 || (data.skillCount as number) > 32)
    throw new Error("bad resources");
  return Object.freeze({
    shared: canonicalPreparedSet(data.shared, "shared"),
    user: canonicalPreparedSet(data.user, "user"),
    agentsStatus,
    skillCount: data.skillCount as number,
  });
}

function canonicalPreparedSet(value: unknown, scope: "shared" | "user") {
  const data = exactValues(value, [
    "scope",
    "revision",
    "bundleDigest",
    "guestRoot",
    "guestSubtree",
    "fileCount",
    "byteCount",
    "readOnlyEnforced",
  ]);
  if (data.scope !== scope) throw new Error("bad resources");
  if (typeof data.revision !== "string" || !/^sha256:[a-f0-9]{64}$/.test(data.revision))
    throw new Error("bad resources");
  if (typeof data.bundleDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(data.bundleDigest))
    throw new Error("bad resources");
  const expectedRoot = scope === "shared" ? "/shared/skills" : "/user/skills";
  if (data.guestRoot !== expectedRoot) throw new Error("bad resources");
  const bundleHex = data.bundleDigest.slice("sha256:".length);
  if (data.guestSubtree !== `${expectedRoot}/${bundleHex}`) throw new Error("bad resources");
  if (scope === "user" && data.revision !== data.bundleDigest) throw new Error("bad resources");
  if (!Number.isSafeInteger(data.fileCount) || (data.fileCount as number) < 0 || (data.fileCount as number) > 128)
    throw new Error("bad resources");
  if (
    !Number.isSafeInteger(data.byteCount) ||
    (data.byteCount as number) < 0 ||
    (data.byteCount as number) > 768 * 1024
  )
    throw new Error("bad resources");
  if (data.readOnlyEnforced !== false) throw new Error("bad resources");
  return Object.freeze({
    scope,
    revision: data.revision as `sha256:${string}`,
    bundleDigest: data.bundleDigest as `sha256:${string}`,
    guestRoot: expectedRoot,
    guestSubtree: data.guestSubtree,
    fileCount: data.fileCount as number,
    byteCount: data.byteCount as number,
    readOnlyEnforced: false as const,
  });
}

function exactValues(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || !Object.isFrozen(value)) throw new Error("bad resources");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (names.length !== keys.length || !names.every((name) => typeof name === "string" && keys.includes(name)))
    throw new Error("bad resources");
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor)) throw new Error("bad resources");
    result[key] = descriptor.value;
  }
  return result;
}

function snapshotFrozenArray(value: unknown, maxLength: number): unknown[] {
  if (!Array.isArray(value) || !Object.isFrozen(value)) throw new Error("bad resources");
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>;
  const lengthDescriptor = descriptors.length;
  if (lengthDescriptor === undefined || !("value" in lengthDescriptor) || !Number.isSafeInteger(lengthDescriptor.value))
    throw new Error("bad resources");
  const length = lengthDescriptor.value as number;
  if (length < 0 || length > maxLength) throw new Error("bad resources");
  const out: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[`${index}`];
    if (descriptor === undefined || !("value" in descriptor)) throw new Error("bad resources");
    out.push(descriptor.value);
  }
  return out;
}

function onceAsync<T>(fn: () => Promise<T>): () => Promise<T> {
  let promise: Promise<T> | undefined;
  return () => (promise ??= fn());
}

function isStandardSkillName(value: string): boolean {
  return /^[a-z0-9](?:[a-z0-9]|-(?!-)){0,62}[a-z0-9]$|^[a-z0-9]$/.test(value);
}

function strictGuestPath(value: string): boolean {
  if (value.normalize("NFC") !== value || Buffer.from(value, "utf8").toString("utf8") !== value) return false;
  const segments = value.split("/");
  if (segments.length < 5 || segments[0] !== "" || (segments[1] !== "shared" && segments[1] !== "user")) return false;
  const digest = segments[3];
  if (segments[2] !== "skills" || digest === undefined || !/^[a-f0-9]{64}$/.test(digest)) return false;
  return segments.slice(4).every(isSafeGuestSegment);
}
function isSafeGuestSegment(segment: string): boolean {
  return (
    segment.length > 0 &&
    segment !== "." &&
    segment !== ".." &&
    !segment.includes("\\") &&
    hasNoControlChars(segment) &&
    segment.normalize("NFC") === segment &&
    Buffer.from(segment, "utf8").toString("utf8") === segment
  );
}
function hasNoControlChars(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0);
    if (code === undefined || code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}
function strictGuestBaseDir(baseDir: string, filePath: string): boolean {
  if (!strictGuestPath(`${baseDir}/x`) || !strictGuestPath(filePath) || !filePath.startsWith(`${baseDir}/`))
    return false;
  const base = baseDir.split("/");
  const file = filePath.split("/");
  return base[1] === file[1] && base[2] === "skills" && base[3] === file[3];
}

type AdapterPhase = "open" | "running" | "aborting" | "draining" | "shutdown" | "failed" | "disposed";
type CogsToolGitHooks = { readonly afterTool: (toolCallId: string, signal?: AbortSignal) => Promise<void> };
type CogsGitBoundaryKind = "user" | "tool" | "settle" | "shutdown";
type PendingCapture = {
  readonly observation: CogsGitObservation;
  readonly boundary: CogsGitBoundaryKind;
  readonly turn: number;
};
type GitEmit = (
  kind: ApiEvent["kind"],
  correlationId: string,
  requestId: string | undefined,
  payload: Record<string, JsonValue>,
) => void;

const MAX_GIT_PENDING = 128;
const MAX_GIT_TOOLS = 64;

class CogsGitBoundary {
  private turn = 0;
  private preTurn: PendingCapture | undefined;
  private readonly toolCaptures = new Map<string, PendingCapture>();
  private readonly messageWaiters = new Map<
    string,
    { sessionManager: SessionManager; correlationId: string; requestId: string | undefined }
  >();
  private readonly queued: Array<() => Promise<void>> = [];
  private readonly pendingPersist = new Set<Promise<void>>();
  private drainChain: Promise<void> = Promise.resolve();
  private disposed = false;
  private overflow = false;
  private incomplete = false;

  public constructor(
    private readonly options: {
      readonly sessionId: string;
      readonly repositoryId: string;
      readonly store: CogsGitMapStore;
      readonly observer: CogsGitObserver;
      readonly checkpointer: CogsGitCheckpointer | undefined;
      readonly checkpointTimeoutMs: number;
      readonly telemetry: CogsTelemetry;
      readonly emit: GitEmit;
      readonly notes: boolean;
    },
  ) {
    this.turn = maxTurn(options.store.records());
  }

  public toolHooks(): CogsToolGitHooks {
    return Object.freeze({
      afterTool: async (toolCallId: string, signal?: AbortSignal) => {
        if (!strictToolCallId(toolCallId) || this.disposed) return;
        if (this.toolCaptures.size + this.messageWaiters.size + this.queued.length >= MAX_GIT_PENDING) {
          this.overflow = true;
          return;
        }
        const observation = await this.safeObserve(signal);
        if (this.disposed) return;
        this.toolCaptures.set(toolCallId, Object.freeze({ observation, boundary: "tool", turn: this.turn }));
        const waiter = this.messageWaiters.get(toolCallId);
        if (waiter !== undefined) this.bindToolLater(toolCallId, waiter);
      },
    });
  }

  public async beginTurn(correlationId: string, requestId: string): Promise<void> {
    if (this.disposed) return;
    this.turn += 1;
    const observation = await this.safeObserve();
    if (this.disposed) return;
    if (observation.kind === "unavailable") {
      this.warn(correlationId, requestId, "git-head-unavailable", "user");
      this.preTurn = undefined;
      return;
    }
    this.preTurn = Object.freeze({ observation, boundary: "user", turn: this.turn });
  }

  public messageEnd(
    event: { type: string; [key: string]: unknown },
    sessionManager: SessionManager,
    correlationId: string,
    requestId: string | undefined,
  ): void {
    const message = (event as { message?: unknown }).message;
    if (!plainObject(message)) return;
    const role = (message as { role?: unknown }).role;
    if (role === "user" && this.preTurn !== undefined) {
      const capture = this.preTurn;
      this.preTurn = undefined;
      void this.bindAfterPersist(sessionManager, capture, { role: "user" }, correlationId, requestId).catch(
        () => undefined,
      );
      return;
    }
    if (role !== "toolResult") return;
    const toolCallId = (message as { toolCallId?: unknown }).toolCallId;
    if (typeof toolCallId !== "string" || !strictToolCallId(toolCallId)) return;
    const waiter = { sessionManager, correlationId, requestId };
    if (this.messageWaiters.size >= MAX_GIT_TOOLS) {
      this.overflow = true;
      this.warn(correlationId, requestId, "git-binding-overflow", "tool");
      return;
    }
    this.messageWaiters.set(toolCallId, waiter);
    if (this.toolCaptures.has(toolCallId)) this.bindToolLater(toolCallId, waiter);
  }

  public async settleTurn(
    sessionManager: SessionManager,
    correlationId: string,
    requestId: string | undefined,
  ): Promise<void> {
    await this.drain();
    if (this.disposed) return;
    this.reportIncomplete(correlationId, requestId);
    this.clearPending();
    const observation = await this.safeObserve();
    if (observation.kind === "unavailable") {
      this.warn(correlationId, requestId, "git-head-unavailable", "settle");
      this.clearPending();
      return;
    }
    const capture = Object.freeze({ observation, boundary: "settle" as const, turn: this.turn });
    const leaf = latestEntry(sessionManager);
    await this.bindLeaf(sessionManager, capture, correlationId, requestId);
    await this.drain();
    await this.checkpointLeaf(leaf, capture, correlationId, requestId);
    this.reportIncomplete(correlationId, requestId);
    this.clearPending();
  }

  public async shutdown(
    sessionManager: SessionManager,
    correlationId: string,
    requestId: string | undefined,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.drain();
    if (this.disposed) return;
    this.reportIncomplete(correlationId, requestId);
    this.clearPending();
    const observation = await this.safeObserve(signal);
    if (observation.kind === "unavailable") {
      this.warn(correlationId, requestId, "git-head-unavailable", "shutdown");
      return;
    }
    await this.bindLeaf(
      sessionManager,
      Object.freeze({ observation, boundary: "shutdown" as const, turn: this.turn }),
      correlationId,
      requestId,
      undefined,
      signal,
    );
    await this.drain();
  }

  public resolve(input: { repo: string; commit: string; signal?: AbortSignal }): Promise<CogsGitMapResolveResult> {
    return this.options.store.resolve({
      repo: input.repo,
      session: this.options.sessionId,
      commit: input.commit,
      nearestAncestor: (ancestorInput) =>
        observerDeadline(
          Promise.resolve().then(() => this.options.observer.nearestAncestor(ancestorInput)),
          2500,
        ),
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
  }

  public async dispose(): Promise<void> {
    this.disposed = true;
    this.preTurn = undefined;
    this.toolCaptures.clear();
    this.messageWaiters.clear();
    this.queued.length = 0;
    await this.drain().catch(() => undefined);
    await observerDeadline(this.options.observer.dispose(), 2500).catch(() => undefined);
    await observerDeadline(this.options.checkpointer?.dispose() ?? Promise.resolve(), 2500).catch(() => undefined);
    this.clearPending();
  }

  private bindToolLater(
    toolCallId: string,
    waiter: { sessionManager: SessionManager; correlationId: string; requestId: string | undefined },
  ): void {
    const capture = this.toolCaptures.get(toolCallId);
    if (capture === undefined) return;
    this.toolCaptures.delete(toolCallId);
    this.messageWaiters.delete(toolCallId);
    void this.bindAfterPersist(
      waiter.sessionManager,
      capture,
      { role: "toolResult", toolCallId },
      waiter.correlationId,
      waiter.requestId,
    ).catch(() => undefined);
  }

  private async bindAfterPersist(
    sessionManager: SessionManager,
    capture: PendingCapture,
    expected: { role: "user" } | { role: "toolResult"; toolCallId: string },
    correlationId: string,
    requestId: string | undefined,
  ): Promise<void> {
    const promise = new Promise<void>((resolve) =>
      queueMicrotask(() => {
        const leaf = latestEntry(sessionManager);
        if (!this.disposed && this.queued.length < MAX_GIT_PENDING)
          this.queued.push(() => this.bindEntry(leaf, capture, correlationId, requestId, expected));
        else this.overflow = true;
        resolve();
      }),
    );
    this.pendingPersist.add(promise);
    await promise.finally(() => this.pendingPersist.delete(promise));
  }

  private async bindLeaf(
    sessionManager: SessionManager,
    capture: PendingCapture,
    correlationId: string,
    requestId: string | undefined,
    expected?: { role: "user" } | { role: "toolResult"; toolCallId: string },
    signal?: AbortSignal,
  ): Promise<void> {
    if (this.disposed) return;
    if (capture.observation.kind === "unavailable") {
      this.warn(correlationId, requestId, "git-head-unavailable", capture.boundary);
      return;
    }
    await this.bindEntry(latestEntry(sessionManager), capture, correlationId, requestId, expected, signal);
  }

  private async bindEntry(
    leaf: { id?: unknown; message?: unknown; type?: unknown } | undefined,
    capture: PendingCapture,
    correlationId: string,
    requestId: string | undefined,
    expected?: { role: "user" } | { role: "toolResult"; toolCallId: string },
    signal?: AbortSignal,
  ): Promise<void> {
    if (capture.observation.kind === "unavailable") {
      this.warn(correlationId, requestId, "git-head-unavailable", capture.boundary);
      return;
    }
    if (capture.observation.repo !== this.options.repositoryId) {
      this.warn(correlationId, requestId, "git-repo-mismatch", capture.boundary);
      return;
    }
    if (leaf === undefined || typeof leaf.id !== "string" || !ENTRY_ID.test(leaf.id)) {
      this.warn(correlationId, requestId, "git-entry-unavailable", capture.boundary);
      return;
    }
    if (expected !== undefined && !matchesLeaf(leaf, expected)) {
      this.warn(correlationId, requestId, "git-boundary-mismatch", capture.boundary);
      return;
    }
    const record = {
      version: "cogs.git-mapping/v1alpha1" as const,
      repo: this.options.repositoryId,
      commit: capture.observation.commit,
      session: this.options.sessionId,
      entry: leaf.id,
      turn: capture.turn,
      observed_at: capture.observation.observed_at,
      confidence: "exact" as const,
    };
    let appended: CogsGitMapRecord;
    try {
      appended = await this.options.store.append(record, signal === undefined ? {} : { signal });
    } catch {
      this.warn(correlationId, requestId, "git-map-unavailable", capture.boundary);
      return;
    }
    this.options.emit("git_mapping", correlationId, requestId, gitObservationEvent(appended, capture.boundary));
    if (this.options.notes) {
      let ok = false;
      try {
        ok = await observerDeadline(
          Promise.resolve().then(() =>
            this.options.observer.appendNote(appended, signal === undefined ? {} : { signal }),
          ),
          2500,
        );
      } catch {
        ok = false;
      }
      if (!ok) this.warn(correlationId, requestId, "git-note-unavailable", capture.boundary);
    }
  }

  private async checkpointLeaf(
    leaf: { id?: unknown; message?: unknown; type?: unknown } | undefined,
    capture: PendingCapture,
    correlationId: string,
    requestId: string | undefined,
  ): Promise<void> {
    if (this.options.checkpointer === undefined || this.disposed) return;
    if (capture.observation.kind === "unavailable") {
      this.warn(correlationId, requestId, "git-checkpoint-unavailable", "settle");
      return;
    }
    if (leaf === undefined || typeof leaf.id !== "string" || !ENTRY_ID.test(leaf.id)) {
      this.warn(correlationId, requestId, "git-checkpoint-unavailable", "settle");
      return;
    }
    const input = {
      repo: this.options.repositoryId,
      session: this.options.sessionId,
      entry: leaf.id,
      turn: capture.turn,
      head: capture.observation.commit,
      observed_at: capture.observation.observed_at,
    };
    let checkpoint: CogsGitCheckpointResult | null;
    const controller = new AbortController();
    const start = telemetryStart();
    try {
      checkpoint = await observerDeadline(
        Promise.resolve().then(
          () => this.options.checkpointer?.checkpoint({ ...input, signal: controller.signal }) ?? null,
        ),
        this.options.checkpointTimeoutMs,
        () => controller.abort(),
      );
      if (checkpoint !== null) checkpoint = snapshotCheckpointResult(checkpoint, input);
    } catch {
      controller.abort();
      emitSpan(this.options.telemetry, "checkpoint.failure", { operation: "checkpoint", outcome: "error" });
      emitMetric(this.options.telemetry, "checkpoint.failures", 1);
      this.warn(correlationId, requestId, "git-checkpoint-unavailable", "settle");
      return;
    }
    if (checkpoint === null) return;
    const record = checkpointRecord(checkpoint);
    try {
      await this.options.store.append(record);
    } catch {
      this.warn(correlationId, requestId, "git-checkpoint-map-unavailable", "settle");
      return;
    }
    emitSpan(this.options.telemetry, "checkpoint.create", {
      operation: "checkpoint",
      outcome: "ok",
      duration_ms: telemetryDuration(undefined, start),
    });
    emitMetric(this.options.telemetry, "checkpoint.count", 1);
    this.options.emit("checkpoint", correlationId, requestId, checkpointEvent(checkpoint));
    if (this.options.notes) {
      let ok = false;
      try {
        ok = await observerDeadline(
          Promise.resolve().then(() => this.options.observer.appendNote(record)),
          2500,
        );
      } catch {
        ok = false;
      }
      if (!ok) this.warn(correlationId, requestId, "git-note-unavailable", "settle");
    }
  }

  private drain(): Promise<void> {
    this.drainChain = this.drainChain.then(async () => {
      if (this.pendingPersist.size > 0) await Promise.allSettled([...this.pendingPersist]);
      while (this.queued.length > 0) {
        const operation = this.queued.shift();
        if (operation !== undefined) await operation().catch(() => undefined);
      }
    });
    return this.drainChain;
  }

  private reportIncomplete(correlationId: string, requestId: string | undefined): void {
    if (this.toolCaptures.size > 0 || this.messageWaiters.size > 0 || this.queued.length > 0) this.incomplete = true;
    if (this.incomplete) this.warn(correlationId, requestId, "git-binding-incomplete", "settle");
    if (this.overflow) this.warn(correlationId, requestId, "git-binding-overflow", "settle");
    this.incomplete = false;
    this.overflow = false;
  }

  private clearPending(): void {
    this.preTurn = undefined;
    this.toolCaptures.clear();
    this.messageWaiters.clear();
    this.queued.length = 0;
  }

  private async safeObserve(signal?: AbortSignal): Promise<CogsGitObservation> {
    const start = telemetryStart();
    try {
      const observation = await observerDeadline(
        this.options.observer.observeHead(signal === undefined ? {} : { signal }),
        2500,
      );
      const ok = observation.kind === "observed" && observation.repo === this.options.repositoryId;
      emitSpan(this.options.telemetry, "git.observe", {
        operation: "observe",
        outcome: ok ? "ok" : "error",
        duration_ms: telemetryDuration(undefined, start),
      });
      return ok ? observation : Object.freeze({ kind: "unavailable" as const });
    } catch {
      emitSpan(this.options.telemetry, "git.observe", {
        operation: "observe",
        outcome: "error",
        duration_ms: telemetryDuration(undefined, start),
      });
      return Object.freeze({ kind: "unavailable" as const });
    }
  }

  private warn(
    correlationId: string,
    requestId: string | undefined,
    reason: string,
    boundary: CogsGitBoundaryKind,
  ): void {
    this.options.emit("warning", correlationId, requestId, {
      code: reason,
      boundary,
      trust: "trusted Cogs record of untrusted Git observation",
    });
  }
}

const ENTRY_ID = /^[a-f0-9]{8}$/;
const TOOL_CALL_ID = /^[A-Za-z0-9._:-]{1,128}$/;

function strictToolCallId(value: string): boolean {
  return TOOL_CALL_ID.test(value);
}

function maxTurn(records: readonly CogsGitMapRecord[]): number {
  let turn = 0;
  for (const record of records) if (record.turn > turn) turn = record.turn;
  return turn;
}

function observerDeadline<T>(promise: Promise<T> | PromiseLike<T>, ms: number, onTimeout?: () => void): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        onTimeout?.();
        reject(new Error("git observer unavailable"));
      }, ms);
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function snapshotExportDescriptor(value: unknown, sessionId: string): Record<string, JsonValue> {
  try {
    const snapshot = exactValues(value, [
      "anonymized",
      "attachments_included",
      "bundle",
      "created_at",
      "file_count",
      "manifest_sha256",
      "mode",
      "sanitized",
      "sensitive",
      "total_bytes",
      "version",
    ]);
    if (
      snapshot.version !== "cogs.export-descriptor/v1alpha1" ||
      snapshot.bundle !== `cogs-session-${sessionId}` ||
      typeof snapshot.manifest_sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(snapshot.manifest_sha256) ||
      typeof snapshot.created_at !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(snapshot.created_at) ||
      new Date(snapshot.created_at).toISOString() !== snapshot.created_at ||
      snapshot.mode !== "raw" ||
      snapshot.attachments_included !== false ||
      snapshot.sensitive !== true ||
      snapshot.sanitized !== false ||
      snapshot.anonymized !== false ||
      typeof snapshot.file_count !== "number" ||
      !Number.isSafeInteger(snapshot.file_count) ||
      snapshot.file_count !== 6 ||
      typeof snapshot.total_bytes !== "number" ||
      !Number.isSafeInteger(snapshot.total_bytes) ||
      snapshot.total_bytes < 1 ||
      snapshot.total_bytes > 72 * 1024 * 1024
    )
      throw new Error("bad descriptor");
    return {
      version: snapshot.version,
      bundle: snapshot.bundle,
      manifest_sha256: snapshot.manifest_sha256,
      created_at: snapshot.created_at,
      mode: snapshot.mode,
      attachments_included: false,
      file_count: snapshot.file_count,
      total_bytes: snapshot.total_bytes,
      sensitive: true,
      sanitized: false,
      anonymized: false,
    };
  } catch {
    throw new Error("invalid export descriptor");
  }
}

function optionalExactValues(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("bad input");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  const allowed = new Set(keys);
  if (!actual.every((key) => typeof key === "string" && allowed.has(key))) throw new Error("bad input");
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined) continue;
    if (!descriptor.enumerable || !("value" in descriptor)) throw new Error("bad input");
    out[key] = descriptor.value;
  }
  return out;
}

function snapshotShutdownInput(input: unknown): { requestId: string; correlationId: string; signal?: AbortSignal } {
  try {
    const snapshot = optionalExactValues(input, ["correlationId", "requestId", "signal"]);
    if (typeof snapshot.requestId !== "string" || typeof snapshot.correlationId !== "string")
      throw new Error("bad shutdown request");
    assertOpaqueId(snapshot.requestId, "request id");
    assertOpaqueId(snapshot.correlationId, "correlation id");
    if (snapshot.signal !== undefined && !(snapshot.signal instanceof AbortSignal)) throw new Error("bad signal");
    return Object.freeze({
      requestId: snapshot.requestId,
      correlationId: snapshot.correlationId,
      ...(snapshot.signal === undefined ? {} : { signal: snapshot.signal }),
    });
  } catch {
    throw new Error("invalid shutdown request");
  }
}

function snapshotCheckpointResult(
  value: unknown,
  input: { repo: string; session: string; entry: string; turn: number; head: string; observed_at: string },
): CogsGitCheckpointResult {
  if (value === null || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("git checkpoint unavailable");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors).sort();
  const expected = [
    "checkpoint_ref",
    "commit",
    "duration_ms",
    "entry",
    "file_count",
    "observed_at",
    "repo",
    "session",
    "total_bytes",
    "turn",
  ];
  if (keys.join("\0") !== expected.join("\0")) throw new Error("git checkpoint unavailable");
  const record = Object.fromEntries(expected.map((key) => [key, ownCheckpointData(descriptors, key)]));
  if (
    record.repo !== input.repo ||
    record.session !== input.session ||
    record.entry !== input.entry ||
    record.turn !== input.turn ||
    record.observed_at !== input.observed_at ||
    record.checkpoint_ref !== `refs/cogs/sessions/${input.session}/${input.turn}` ||
    typeof record.commit !== "string" ||
    !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(record.commit) ||
    record.commit.length !== input.head.length ||
    !safeInteger(record.file_count, 0, 4096) ||
    !safeInteger(record.total_bytes, 0, 128 * 1024 * 1024) ||
    !safeInteger(record.duration_ms, 0, 60_000)
  )
    throw new Error("git checkpoint unavailable");
  return Object.freeze(record as unknown as CogsGitCheckpointResult);
}

function ownCheckpointData(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
    throw new Error("git checkpoint unavailable");
  return descriptor.value;
}

function safeInteger(value: unknown, min: number, max: number): boolean {
  return Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max;
}

function statInt(value: unknown): number | undefined {
  if (value === undefined) return 0;
  return Number.isSafeInteger(value) && (value as number) >= 0 ? (value as number) : undefined;
}

function statCache(tokens: Record<string, unknown> | undefined): number | undefined {
  if (tokens === undefined) return 0;
  if (tokens.cache !== undefined) return validStat(tokens.cache) ? (tokens.cache as number) : undefined;
  if (tokens.cached !== undefined) return validStat(tokens.cached) ? (tokens.cached as number) : undefined;
  const read = statInt(tokens.cacheRead);
  const write = statInt(tokens.cacheWrite);
  if (read === undefined || write === undefined || Number.MAX_SAFE_INTEGER - read < write) return undefined;
  return read + write;
}

function validStat(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function statCostMicros(value: unknown): number | undefined {
  const total = value !== null && typeof value === "object" ? (value as { total?: unknown }).total : value;
  if (total === undefined) return 0;
  if (typeof total === "number" && Number.isFinite(total) && total >= 0) {
    const micros = total * 1_000_000;
    if (!Number.isSafeInteger(Math.trunc(micros)) || micros > Number.MAX_SAFE_INTEGER) return undefined;
    return Math.trunc(micros);
  }
  return undefined;
}

function emitDelta(sink: CogsTelemetry, name: string, after: number, before: number): void {
  if (!Number.isSafeInteger(after) || !Number.isSafeInteger(before) || after < before) return;
  const value = after - before;
  if (value > 0) emitMetric(sink, name, value);
}

function latestEntry(sessionManager: SessionManager): { id?: unknown; message?: unknown; type?: unknown } | undefined {
  const entries = sessionManager.getEntries() as unknown[];
  return entries.at(-1) as { id?: unknown; message?: unknown; type?: unknown } | undefined;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assistantMessage(value: unknown): boolean {
  return snapshotAssistantMessage(value) !== undefined;
}

function modelOutcome(value: unknown): "ok" | "error" | "cancelled" {
  const message = snapshotAssistantMessage(value);
  if (message === undefined) return "error";
  const reason = message.stopReason ?? message.stop_reason;
  if (
    reason === "stop" ||
    reason === "end_turn" ||
    reason === "toolUse" ||
    reason === "tool_use" ||
    reason === "length"
  )
    return "ok";
  if (reason === "aborted") return "cancelled";
  return "error";
}

function snapshotAssistantMessage(
  value: unknown,
): { role: unknown; stopReason?: unknown; stop_reason?: unknown } | undefined {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
    if (Object.getPrototypeOf(value) !== Object.prototype) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const data = (key: "role" | "stopReason" | "stop_reason"): unknown => {
      const descriptor = descriptors[key];
      if (descriptor === undefined) return undefined;
      if (!("value" in descriptor) || descriptor.enumerable !== true) throw new Error("bad message");
      return descriptor.value;
    };
    const role = data("role");
    if (role !== "assistant") return undefined;
    return Object.freeze({ role, stopReason: data("stopReason"), stop_reason: data("stop_reason") });
  } catch {
    return undefined;
  }
}

function matchesLeaf(
  leaf: { id?: unknown; message?: unknown; type?: unknown },
  expected: { role: "user" } | { role: "toolResult"; toolCallId: string },
): boolean {
  if (leaf.type !== "message" || !plainObject(leaf.message)) return false;
  const message = leaf.message as { role?: unknown; toolCallId?: unknown };
  if (message.role !== expected.role) return false;
  return expected.role === "user" || message.toolCallId === expected.toolCallId;
}

class PiSessionAdapter implements CogsPiSessionPorts {
  readonly #authStorage: AuthStorage;
  private active: ActiveRun | undefined;
  private phase: AdapterPhase = "open";
  private cleanupPromise: Promise<void> | undefined;
  private shutdownPreparePromise: Promise<JsonValue> | undefined;
  private shutdownPrepareAbort: { abort: () => void } | undefined;
  private fatalEmitted = false;
  private usageBase: { input: number; output: number; cache: number; cost: number } | undefined;
  private modelCallStartedAt: number | undefined;
  private readonly telemetryHealth = new TelemetryHealthCursor();
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
      readonly userId: string;
      readonly sessionId: string;
      readonly secret: SecretHolder;
      readonly operationTimeoutMs: number | undefined;
      readonly abortTimeoutMs: number | undefined;
      readonly preparedResources: CogsPreparedSkills | undefined;
      readonly historyStore: CogsJsonlHistoryStore;
      readonly gitMapStore: CogsGitMapStore | undefined;
      readonly gitBinding: CogsGitBoundary | undefined;
      readonly localExporter: CogsLocalExporter;
      readonly policyAuthorizer: CogsPolicyAuthorizer | undefined;
      readonly telemetry: CogsTelemetry;
      readonly ownedRuntime: CogsPiOwnedRuntimeTracker | undefined;
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

  public skillMetadata(): CogsPreparedSkillMetadata | undefined {
    return this.runtime.preparedResources?.metadata;
  }

  public gitMapRecords(): readonly CogsGitMapRecord[] {
    return this.runtime.gitMapStore?.records() ?? Object.freeze([]);
  }

  public resolveGitMapping(input: {
    repo: string;
    commit: string;
    signal?: AbortSignal;
  }): Promise<CogsGitMapResolveResult | undefined> {
    const binding = this.runtime.gitBinding;
    if (binding === undefined) return Promise.resolve(undefined);
    return binding.resolve(input);
  }

  public publishGit(
    kind: ApiEvent["kind"],
    correlationId: string,
    requestId: string | undefined,
    payload: Record<string, JsonValue>,
  ): void {
    this.publishOrClose(kind, correlationId, requestId, payload);
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
    try {
      const page = await this.runtime.historyStore.entries(input);
      return {
        entries: sanitizeJson(page.entries, { secrets: [this.runtime.secret.value] }) as JsonValue[],
        ...(page.nextAfter === undefined ? {} : { nextAfter: page.nextAfter }),
      };
    } catch (error) {
      if (error instanceof CogsJsonlHistoryCursorError) throw new Error("unknown history cursor");
      throw new Error("invalid session history");
    }
  }

  public async prepareShutdown(input: {
    requestId: string;
    correlationId: string;
    signal?: AbortSignal;
  }): Promise<JsonValue> {
    const request = snapshotShutdownInput(input);
    if (this.shutdownPreparePromise !== undefined) return this.shutdownPreparePromise;
    await throwIfAborted(request.signal);
    if (this.shutdownPreparePromise !== undefined) return this.shutdownPreparePromise;
    if (this.phase === "shutdown") return { version: "cogs.shutdown-ready/v1alpha1", already_ready: true };
    if (this.phase !== "open" || this.active !== undefined || this.session.isStreaming)
      throw new Error("Pi session is not idle");
    this.phase = "draining";
    const controller = linkedAbortSignal(request.signal);
    this.shutdownPrepareAbort = controller;
    this.shutdownPreparePromise = this.prepareShutdownOnce({
      requestId: request.requestId,
      correlationId: request.correlationId,
      signal: controller.signal,
    })
      .catch(async (error) => {
        await this.failClosed("shutdown-prepare-failed", this.active).catch(() => undefined);
        throw error instanceof Error ? error : new Error("shutdown preparation failed");
      })
      .finally(() => {
        controller.dispose();
        if (this.shutdownPrepareAbort === controller) this.shutdownPrepareAbort = undefined;
      });
    return this.shutdownPreparePromise;
  }

  public async createExport(input: {
    requestId: string;
    correlationId: string;
    signal?: AbortSignal;
  }): Promise<JsonValue> {
    this.assertLive();
    await throwIfAborted(input.signal);
    assertOpaqueId(input.requestId, "request id");
    assertOpaqueId(input.correlationId, "correlation id");
    const start = telemetryStart();
    try {
      requireRawExportPolicy(this.runtime.userId, this.runtime.sessionId, this.runtime.policyAuthorizer);
      const descriptor = snapshotExportDescriptor(
        await this.runtime.localExporter.createExport(input.signal === undefined ? {} : { signal: input.signal }),
        this.runtime.sessionId,
      );
      const bytes = statInt(descriptor.total_bytes) ?? 0;
      emitSpan(this.runtime.telemetry, "export.create", {
        operation: "export",
        outcome: "ok",
        duration_ms: telemetryDuration(undefined, start),
        bytes_bucket: byteBucket(bytes),
      });
      emitMetric(this.runtime.telemetry, "export.bytes", bytes, { bytes_bucket: byteBucket(bytes) });
      return descriptor as unknown as JsonValue;
    } catch (error) {
      emitSpan(this.runtime.telemetry, "export.failure", { operation: "export", outcome: "error" });
      emitMetric(this.runtime.telemetry, "export.failures", 1);
      throw error;
    }
  }

  public disposeOwnedRuntime(): Promise<CogsPiOwnedRuntimeCleanupResult> {
    const owner = this.runtime.ownedRuntime;
    if (owner === undefined) return Promise.reject(new Error("Pi owned runtime cleanup failed"));
    return owner.cleanup((deadlineExpiresAt) => this.dispose({ ownedDeadlineExpiresAt: deadlineExpiresAt }));
  }

  public async dispose(input: { readonly ownedDeadlineExpiresAt?: number } = {}): Promise<void> {
    if (this.phase === "disposed") return;
    if (this.phase === "draining" && this.shutdownPreparePromise !== undefined) {
      this.shutdownPrepareAbort?.abort();
      try {
        await observerDeadline(
          this.shutdownPreparePromise.then(
            () => undefined,
            () => undefined,
          ),
          this.abortTimeoutMs,
        );
      } catch {
        throw new Error("Pi session cleanup failed");
      }
    }
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
    let cleanupError: unknown;
    try {
      this.session.dispose();
    } catch (error) {
      cleanupError = error;
    }
    for (const cleanup of [
      () => this.runtime.localExporter.dispose(input.ownedDeadlineExpiresAt),
      () => this.runtime.gitBinding?.dispose() ?? Promise.resolve(),
      () => this.runtime.preparedResources?.dispose() ?? Promise.resolve(),
    ]) {
      try {
        await cleanup();
      } catch (error) {
        cleanupError = error;
      }
    }
    this.#authStorage.removeRuntimeApiKey(this.runtime.provider);
    this.runtime.secret.value = "";
    this.phase = "disposed";
    if (cleanupError !== undefined) throw new Error("Pi session cleanup failed");
  }

  private async prepareShutdownOnce(input: {
    requestId: string;
    correlationId: string;
    signal?: AbortSignal;
  }): Promise<JsonValue> {
    const start = telemetryStart();
    let exportStarted = false;
    emitSpan(this.runtime.telemetry, "shutdown.prepare", { operation: "prepare", state: "shutdown" });
    try {
      await throwIfAborted(input.signal);
      const flushStart = telemetryStart();
      await this.runtime.historyStore.flushSettled(input.signal === undefined ? {} : { signal: input.signal });
      emitSpan(this.runtime.telemetry, "pi.history.flush", {
        operation: "flush",
        outcome: "ok",
        duration_ms: telemetryDuration(undefined, flushStart),
      });
      await this.runtime.gitBinding?.shutdown(this.sessionManager, input.correlationId, input.requestId, input.signal);
      await throwIfAborted(input.signal);
      requireRawExportPolicy(this.runtime.userId, this.runtime.sessionId, this.runtime.policyAuthorizer);
      exportStarted = true;
      const descriptor = snapshotExportDescriptor(
        await this.runtime.localExporter.createExport(input.signal === undefined ? {} : { signal: input.signal }),
        this.runtime.sessionId,
      );
      const payload = sanitizeJson(
        {
          version: "cogs.shutdown-ready/v1alpha1",
          bundle: descriptor.bundle,
          manifest_sha256: descriptor.manifest_sha256,
          created_at: descriptor.created_at,
          mode: descriptor.mode,
          attachments_included: descriptor.attachments_included,
          file_count: descriptor.file_count,
          total_bytes: descriptor.total_bytes,
          sensitive: true,
          sanitized: false,
          anonymized: false,
        },
        { secrets: [this.runtime.secret.value] },
      ) as Record<string, JsonValue>;
      emitSpan(this.runtime.telemetry, "shutdown.ready", {
        operation: "prepare",
        outcome: "ok",
        duration_ms: telemetryDuration(undefined, start),
      });
      emitTelemetryHealth(this.runtime.telemetry, this.telemetryHealth);
      this.emitOrFail("shutdown_ready", input.correlationId, input.requestId, payload);
      this.phase = "shutdown";
      return Object.freeze(payload);
    } catch {
      emitSpan(this.runtime.telemetry, "shutdown.ready", { operation: "prepare", outcome: "error" });
      if (exportStarted) {
        emitSpan(this.runtime.telemetry, "export.failure", { operation: "export", outcome: "error" });
        emitMetric(this.runtime.telemetry, "export.failures", 1);
      }
      throw new Error("shutdown preparation failed");
    }
  }

  private async runPrompt(active: ActiveRun, content: string): Promise<void> {
    const runStart = telemetryStart();
    this.usageBase = this.safeUsageBase();
    active.deadline = setTimeout(() => {
      void this.timeoutActive(active);
    }, this.timeoutMs);
    try {
      await this.runtime.gitBinding?.beginTurn(active.correlationId, active.requestId);
      await this.session.prompt(content, { expandPromptTemplates: false });
      if (active.suppressLate || this.phase === "aborting") return;
      try {
        const flushStart = telemetryStart();
        await this.runtime.historyStore.flushSettled();
        emitSpan(this.runtime.telemetry, "pi.history.flush", {
          operation: "flush",
          outcome: "ok",
          duration_ms: telemetryDuration(undefined, flushStart),
        });
      } catch {
        emitSpan(this.runtime.telemetry, "pi.history.flush", { operation: "flush", outcome: "error" });
        await this.failClosed("history-flush-failed", active);
        return;
      }
      if (active.suppressLate) return;
      await this.runtime.gitBinding?.settleTurn(this.sessionManager, active.correlationId, active.requestId);
      if (active.suppressLate) return;
      this.emitUsageDeltas();
      emitTelemetryHealth(this.runtime.telemetry, this.telemetryHealth);
      emitSpan(this.runtime.telemetry, "pi.run", {
        operation: "run",
        outcome: "ok",
        duration_ms: telemetryDuration(undefined, runStart),
      });
      emitSpan(this.runtime.telemetry, "pi.turn", {
        state: "settled",
        outcome: "ok",
        duration_ms: telemetryDuration(undefined, runStart),
      });
      this.terminal(active, "run_settled", { state: "settled" });
    } catch (error) {
      if (active.terminal || active.suppressLate || this.phase === "aborting") return;
      if (isAbortLike(error)) {
        emitSpan(this.runtime.telemetry, "pi.run", {
          outcome: "cancelled",
          duration_ms: telemetryDuration(undefined, runStart),
        });
        this.terminal(active, "run_aborted", { reason: "cancelled" });
        return;
      }
      emitSpan(this.runtime.telemetry, "pi.run", {
        outcome: "error",
        duration_ms: telemetryDuration(undefined, runStart),
      });
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
    if (this.phase === "disposed" || this.phase === "failed" || this.phase === "shutdown" || this.phase === "draining")
      return "shutdown";
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
    this.observeModelEvent(event);
    emitSpan(this.runtime.telemetry, "pi.event", { outcome: "ok" });
    if (event.type === "message_end")
      this.runtime.gitBinding?.messageEnd(event, this.sessionManager, correlation, request);
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

  private observeModelEvent(event: { type: string; [key: string]: unknown }): void {
    if (this.phase === "disposed" || this.phase === "failed" || this.active?.suppressLate === true) return;
    if (event.type === "message_start" && assistantMessage(event.message)) {
      this.modelCallStartedAt = telemetryStart();
      return;
    }
    if (event.type !== "message_end" || !assistantMessage(event.message)) return;
    const started = this.modelCallStartedAt;
    this.modelCallStartedAt = undefined;
    if (started === undefined) return;
    emitSpan(this.runtime.telemetry, "pi.model_call", {
      operation: "run",
      outcome: modelOutcome(event.message),
      duration_ms: telemetryDuration(undefined, started),
    });
  }

  private safeUsageBase(): { input: number; output: number; cache: number; cost: number } | undefined {
    try {
      const stats = this.session.getSessionStats() as { tokens?: unknown; cost?: unknown };
      const tokens = stats.tokens as Record<string, unknown> | undefined;
      const input = statInt(tokens?.input ?? tokens?.inputTokens);
      const output = statInt(tokens?.output ?? tokens?.outputTokens);
      const cache = statCache(tokens);
      const cost = statCostMicros(stats.cost);
      if (input === undefined || output === undefined || cache === undefined || cost === undefined) return undefined;
      return { input, output, cache, cost };
    } catch {
      return undefined;
    }
  }

  private emitUsageDeltas(): void {
    const before = this.usageBase;
    const after = this.safeUsageBase();
    this.usageBase = after;
    if (before === undefined || after === undefined) return;
    emitDelta(this.runtime.telemetry, "token.input", after.input, before.input);
    emitDelta(this.runtime.telemetry, "token.output", after.output, before.output);
    emitDelta(this.runtime.telemetry, "token.cache", after.cache, before.cache);
    emitDelta(this.runtime.telemetry, "cost.microunits", after.cost, before.cost);
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
    this.shutdownPrepareAbort?.abort();
    if (active !== undefined) {
      active.suppressLate = true;
      if (active.deadline !== undefined) clearTimeout(active.deadline);
    }
    this.cleanupPromise = (async () => {
      let cleanupError: unknown;
      try {
        await this.abortWithBound("fail-closed");
      } catch {
        // Non-cooperative abort is represented by the failed-closed phase.
      } finally {
        this.unsubscribe();
        try {
          this.session.dispose();
        } catch (error) {
          cleanupError = error;
        }
        for (const cleanup of [
          () => this.runtime.localExporter.dispose(),
          () => this.runtime.gitBinding?.dispose() ?? Promise.resolve(),
          () => this.runtime.preparedResources?.dispose() ?? Promise.resolve(),
        ]) {
          try {
            await cleanup();
          } catch (error) {
            cleanupError = error;
          }
        }
        this.#authStorage.removeRuntimeApiKey(this.runtime.provider);
        this.runtime.secret.value = "";
        this.active = undefined;
        this.phase = "failed";
        this.invokeFatal(_reason);
      }
      if (cleanupError !== undefined) throw new Error("Pi session cleanup failed");
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

function createCogsTools(
  ports: CogsToolPorts,
  maxResultBytes: number,
  secret: SecretHolder,
  hooks: CogsToolGitHooks | undefined,
  policy: {
    readonly userId: string;
    readonly sessionId: string;
    readonly authorizer?: CogsPolicyAuthorizer;
    readonly telemetry: CogsTelemetry;
  },
) {
  const result = async (
    name: CogsPiToolName,
    toolCallId: string,
    signal: AbortSignal | undefined,
    operation: () => Promise<JsonValue>,
    pathClass?: "workspace" | "shared_skill" | "user_skill",
  ) => {
    const start = telemetryStart();
    const attrs =
      pathClass === undefined
        ? { tool: name, operation: "dispatch" as const }
        : { tool: name, path_class: pathClass, operation: "dispatch" as const };
    emitMetric(policy.telemetry, "tool.count", 1, { tool: name });
    try {
      let value: JsonValue;
      try {
        value = await operation();
      } catch (error) {
        await hooks?.afterTool(toolCallId, signal).catch(() => undefined);
        throw error;
      }
      await hooks?.afterTool(toolCallId, signal).catch(() => undefined);
      const meta = toolResultMetadata(name, value);
      const normalized = normalizeToolResult(value, maxResultBytes, secret.value);
      const outcome = meta.timed_out ? "timeout" : meta.cancelled ? "cancelled" : meta.ok === false ? "error" : "ok";
      const extra = { timed_out: meta.timed_out, cancelled: meta.cancelled, truncated: meta.truncated };
      emitSpan(policy.telemetry, name === "bash" ? "bash.operation" : "sftp.operation", {
        operation: name === "bash" ? "run" : name,
        outcome,
        duration_ms: telemetryDuration(undefined, start),
        ...extra,
      });
      emitSpan(policy.telemetry, "tool.dispatch", {
        ...attrs,
        outcome,
        duration_ms: telemetryDuration(undefined, start),
        ...extra,
      });
      if (meta.timed_out) emitMetric(policy.telemetry, "tool.timeouts", 1, { tool: name });
      if (meta.truncated) emitMetric(policy.telemetry, "tool.truncated", 1, { tool: name });
      if (outcome === "error") emitMetric(policy.telemetry, "tool.errors", 1, { tool: name });
      return { content: [{ type: "text" as const, text: JSON.stringify(normalized) }], details: { cogsTool: name } };
    } catch (error) {
      const outcome =
        error instanceof CogsPolicyDeniedError ? "denied" : signal?.aborted === true ? "cancelled" : "error";
      emitSpan(policy.telemetry, name === "bash" ? "bash.operation" : "sftp.operation", {
        operation: name === "bash" ? "run" : name,
        outcome,
        duration_ms: telemetryDuration(undefined, start),
      });
      emitSpan(policy.telemetry, "tool.dispatch", {
        ...attrs,
        outcome,
        duration_ms: telemetryDuration(undefined, start),
      });
      if (outcome === "error") emitMetric(policy.telemetry, "tool.errors", 1, { tool: name });
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
      execute: async (id, params, signal) =>
        (() => {
          const pathClass = safeReadPathClass(params.path);
          return result(
            "read",
            id,
            signal,
            () => {
              if (pathClass === undefined) throw new Error("read tool failed");
              requireToolDispatchPolicy(policy, "read", pathClass);
              return ports.read(withSignal(params, signal));
            },
            pathClass,
          );
        })(),
    }),
    defineTool({
      name: "write",
      label: "Write",
      description: "Write a file in the Cogs sandbox through the injected write port.",
      parameters: Type.Object(
        { path: Type.String({ minLength: 1, maxLength: 4096 }), content: Type.String({ maxLength: 1_000_000 }) },
        { additionalProperties: false },
      ),
      execute: async (id, params, signal) =>
        (() => {
          const pathClass = safeWorkspacePathClass(params.path);
          return result(
            "write",
            id,
            signal,
            () => {
              if (pathClass === undefined) throw new Error("write tool failed");
              requireToolDispatchPolicy(policy, "write", pathClass);
              return ports.write(withSignal(params, signal));
            },
            pathClass,
          );
        })(),
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
      execute: async (id, params, signal) =>
        (() => {
          const pathClass = safeWorkspacePathClass(params.path);
          return result(
            "edit",
            id,
            signal,
            () => {
              if (pathClass === undefined) throw new Error("write tool failed");
              requireToolDispatchPolicy(policy, "edit", pathClass);
              return ports.edit(withSignal(params, signal));
            },
            pathClass,
          );
        })(),
    }),
    defineTool({
      name: "bash",
      label: "Bash",
      description: "Run a shell command in the Cogs sandbox through the injected bash port.",
      parameters: Type.Object(
        { command: Type.String({ minLength: 1, maxLength: 100_000 }) },
        { additionalProperties: false },
      ),
      execute: async (id, params, signal, onUpdate) =>
        result("bash", id, signal, () => {
          requireToolDispatchPolicy(policy, "bash");
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

function toolResultMetadata(
  tool: CogsPiToolName,
  value: unknown,
): {
  readonly ok: boolean | undefined;
  readonly timed_out: boolean;
  readonly cancelled: boolean;
  readonly truncated: boolean;
} {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return Object.freeze({ ok: undefined, timed_out: false, cancelled: false, truncated: false });
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const data = (key: string): unknown => {
      const descriptor = descriptors[key];
      return descriptor !== undefined && descriptor.enumerable === true && "value" in descriptor
        ? descriptor.value
        : undefined;
    };
    const ok = typeof data("ok") === "boolean" ? (data("ok") as boolean) : undefined;
    if (tool === "bash") {
      const timedOut = data("timedOut") === true;
      const cancelled = data("cancelled") === true;
      const truncated = data("stdoutTruncated") === true || data("stderrTruncated") === true;
      return Object.freeze({ ok, timed_out: timedOut, cancelled, truncated });
    }
    return Object.freeze({ ok, timed_out: false, cancelled: false, truncated: data("truncated") === true });
  } catch {
    return Object.freeze({ ok: undefined, timed_out: false, cancelled: false, truncated: false });
  }
}

function requireRawExportPolicy(userId: string, sessionId: string, authorizer: CogsPolicyAuthorizer | undefined): void {
  requireCogsPolicyAllow(
    {
      version: "cogs.policy/v1alpha1",
      action: "export.create",
      user: userId,
      session: sessionId,
      resource: "local_bundle",
      attributes: {
        mode: "raw",
        sensitive: true,
        sanitized: false,
        anonymized: false,
        attachments_included: false,
      },
    },
    authorizer,
  );
}

function requireToolDispatchPolicy(
  policy: { readonly userId: string; readonly sessionId: string; readonly authorizer?: CogsPolicyAuthorizer },
  tool: CogsPiToolName,
  pathClass?: "workspace" | "shared_skill" | "user_skill",
): void {
  requireCogsPolicyAllow(
    {
      version: "cogs.policy/v1alpha1",
      action: "tool.dispatch",
      user: policy.userId,
      session: policy.sessionId,
      resource: tool,
      attributes: tool === "bash" ? { tool } : { tool, path_class: pathClass },
    },
    policy.authorizer,
  );
}

function classifyReadPath(path: string): "workspace" | "shared_skill" | "user_skill" {
  if (isGuestPathClass(path, "/workspace")) return "workspace";
  if (isGuestPathClass(path, "/shared/skills")) return "shared_skill";
  if (isGuestPathClass(path, "/user/skills")) return "user_skill";
  throw new Error("read tool failed");
}

function safeReadPathClass(path: string): "workspace" | "shared_skill" | "user_skill" | undefined {
  try {
    return classifyReadPath(path);
  } catch {
    return undefined;
  }
}

function classifyWorkspaceWritePath(path: string): "workspace" {
  if (isGuestPathClass(path, "/workspace")) return "workspace";
  throw new Error("write tool failed");
}

function safeWorkspacePathClass(path: string): "workspace" | undefined {
  try {
    return classifyWorkspaceWritePath(path);
  } catch {
    return undefined;
  }
}

function isGuestPathClass(path: string, root: string): boolean {
  if (!path.startsWith("/")) return false;
  if (path.includes("\0") || path.includes("\\")) return false;
  const segments = path.split("/");
  if (segments.some((segment) => segment === "." || segment === "..")) return false;
  return path === root || path.startsWith(`${root}/`);
}

function linkedAbortSignal(parent: AbortSignal | undefined): {
  signal: AbortSignal;
  abort: () => void;
  dispose: () => void;
} {
  const controller = new AbortController();
  if (parent?.aborted) controller.abort();
  const abort = () => controller.abort();
  parent?.addEventListener("abort", abort, { once: true });
  return {
    signal: controller.signal,
    abort: () => controller.abort(),
    dispose: () => parent?.removeEventListener("abort", abort),
  };
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
      let keys: string[];
      try {
        keys = Object.keys(entry).slice(0, 128);
      } catch {
        return "[unreadable]";
      }
      for (const keyName of keys) {
        let descriptor: PropertyDescriptor | undefined;
        try {
          descriptor = Object.getOwnPropertyDescriptor(entry, keyName);
        } catch {
          descriptor = undefined;
        }
        const sanitizedValue =
          descriptor === undefined || !("value" in descriptor)
            ? "[unreadable]"
            : visit(descriptor.value, depth + 1, keyName);
        Object.defineProperty(output, keyName, {
          value: sanitizedValue,
          enumerable: true,
          writable: true,
          configurable: true,
        });
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
