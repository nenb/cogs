import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { URL } from "node:url";
import type { LaunchLifecycle } from "../launch/lifecycle.ts";

export type InputKind = "prompt" | "steer" | "follow_up";
export type RunState = "idle" | "running" | "settled" | "aborting" | "shutdown";
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue | undefined };

export interface AcceptedResult {
  readonly version: "cogs.input-acceptance/v1alpha1";
  readonly request_id: string;
  readonly correlation_id: string;
  readonly accepted: boolean;
  readonly duplicate: boolean;
  readonly run_state: RunState;
}

export interface SessionPort {
  readonly input: (input: {
    requestId: string;
    correlationId: string;
    kind: InputKind;
    content: string;
    signal?: AbortSignal;
  }) => Promise<RunState>;
  readonly abort: (input: {
    requestId: string;
    correlationId: string;
    signal?: AbortSignal;
  }) => Promise<{ aborted: boolean; runState: RunState }>;
  readonly state: (input?: { signal?: AbortSignal }) => Promise<{ runState: RunState; usage?: JsonValue }>;
}

export interface HistoryPort {
  readonly entries: (input: { after: string | undefined; limit: number; signal?: AbortSignal }) => Promise<{
    entries: readonly JsonValue[];
    nextAfter?: string;
  }>;
}

export interface ExportPort {
  readonly createExport: (input: {
    requestId: string;
    correlationId: string;
    signal?: AbortSignal;
  }) => Promise<JsonValue>;
}

export interface ApiEvent {
  readonly type: string;
  readonly correlation_id?: string;
  readonly payload?: JsonValue;
}

export interface ApiServerOptions {
  readonly lifecycle: Pick<LaunchLifecycle, "ready" | "state" | "requestShutdown">;
  readonly session: SessionPort;
  readonly history: HistoryPort;
  readonly exporter: ExportPort;
  readonly bearerToken: string;
  readonly sessionId: string;
  readonly maxRequestBytes?: number;
  readonly maxResponseBytes?: number;
  readonly duplicateCapacity?: number;
  readonly eventReplayCapacity?: number;
  readonly requestTimeoutMs?: number;
  readonly portTimeoutMs?: number;
  readonly maxEventBytes?: number;
}

export interface ApiServer {
  readonly listen: (port?: number, host?: string) => Promise<{ port: number }>;
  readonly close: () => Promise<void>;
  readonly publish: (event: ApiEvent) => boolean;
}

type DuplicateEntry = {
  readonly requestId: string;
  readonly fingerprint: string;
  readonly result: Promise<AcceptedResult>;
  settled: boolean;
  lastUsed: number;
};
type Client = { readonly response: ServerResponse; readonly close: () => void };

const forbiddenResponse = Object.freeze({ version: "cogs.error/v1alpha1", error: "forbidden" });

export function createApiServer(options: ApiServerOptions): ApiServer {
  validateConfig(options);
  const maxRequestBytes = optionInteger(options.maxRequestBytes, 16 * 1024, "maxRequestBytes", 128, 1024 * 1024);
  const maxResponseBytes = optionInteger(options.maxResponseBytes, 128 * 1024, "maxResponseBytes", 128, 1024 * 1024);
  const duplicateCapacity = optionInteger(options.duplicateCapacity, 128, "duplicateCapacity", 1, 4096);
  const eventReplayCapacity = optionInteger(options.eventReplayCapacity, 256, "eventReplayCapacity", 1, 4096);
  const requestTimeoutMs = optionInteger(options.requestTimeoutMs, 5_000, "requestTimeoutMs", 1, 60_000);
  const portTimeoutMs = optionInteger(options.portTimeoutMs, requestTimeoutMs, "portTimeoutMs", 1, 60_000);
  const maxEventBytes = optionInteger(options.maxEventBytes, 32 * 1024, "maxEventBytes", 128, 1024 * 1024);
  const duplicates: DuplicateEntry[] = [];
  const replay: { seq: number; event: ApiEvent; serialized: string }[] = [];
  const clients = new Set<Client>();
  let sequence = 0;
  let inputQueue: Promise<void> = Promise.resolve();
  let abortPromise: Promise<{ aborted: boolean; runState: RunState }> | undefined;
  let shutdownPromise: Promise<void> | undefined;
  let closed = false;
  let poisoned = false;
  let duplicateClock = 0;
  const tokenDigest = digest(options.bearerToken);
  const cursorSecret = createHmac("sha256", options.bearerToken).update(`cursor:${options.sessionId}`).digest();

  const server = createServer((request, response) => {
    void route(request, response).catch(() => {
      safeWriteJson(response, 500, { version: "cogs.error/v1alpha1", error: "internal" }, maxResponseBytes, "internal");
    });
  });

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const rawTarget = request.url ?? "/";
    const correlationId = correlationFrom(request);
    let url: URL;
    try {
      if (
        !validRequestTarget(rawTarget) ||
        duplicateHeader(request, "authorization") ||
        duplicateHeader(request, "x-cogs-correlation-id")
      )
        throw new Error("bad target");
      url = new URL(rawTarget, "http://127.0.0.1");
    } catch {
      drainRequest(request);
      return safeWriteJson(
        response,
        400,
        { version: "cogs.error/v1alpha1", error: "bad_request_target" },
        maxResponseBytes,
        correlationId,
        true,
      );
    }
    response.setHeader("x-cogs-correlation-id", correlationId);
    if (url.pathname === "/health/live") {
      return method(request, response, url, maxResponseBytes, "GET", [], false, () =>
        safeWriteJson(response, 200, { live: true }, maxResponseBytes, correlationId),
      );
    }
    if (!authorized(request, tokenDigest)) {
      drainRequest(request);
      return safeWriteJson(response, 401, forbiddenResponse, maxResponseBytes, correlationId, true);
    }
    switch (url.pathname) {
      case "/health/ready":
        return method(request, response, url, maxResponseBytes, "GET", [], false, () =>
          safeWriteJson(
            response,
            !poisoned && options.lifecycle.ready ? 200 : 503,
            { ready: !poisoned && options.lifecycle.ready },
            maxResponseBytes,
            correlationId,
          ),
        );
      case "/v1/state":
        return method(request, response, url, maxResponseBytes, "GET", [], false, async () =>
          safeWriteJson(response, 200, await stateBody(), maxResponseBytes, correlationId),
        );
      case "/v1/input":
        return method(request, response, url, maxResponseBytes, "POST", [], true, async () =>
          handleInput(request, response, correlationId),
        );
      case "/v1/abort":
        return method(request, response, url, maxResponseBytes, "POST", [], true, async () =>
          handleAbort(request, response, correlationId),
        );
      case "/v1/export":
        return method(request, response, url, maxResponseBytes, "POST", [], true, async () =>
          handleExport(request, response, correlationId),
        );
      case "/v1/shutdown":
        return method(request, response, url, maxResponseBytes, "POST", [], true, async () =>
          handleShutdown(request, response, correlationId),
        );
      case "/v1/entries":
        return method(request, response, url, maxResponseBytes, "GET", ["after", "limit"], false, async () =>
          handleEntries(url, response, correlationId),
        );
      case "/v1/events":
        return method(request, response, url, maxResponseBytes, "GET", ["after"], false, () =>
          handleEvents(url, request, response),
        );
      default:
        drainRequest(request);
        return safeWriteJson(
          response,
          404,
          { version: "cogs.error/v1alpha1", error: "not_found" },
          maxResponseBytes,
          correlationId,
        );
    }
  }

  function requireReady(): void {
    if (poisoned || !options.lifecycle.ready) throw new HttpError(503, "not_ready");
  }

  function poisonFromPortTimeout(): void {
    if (poisoned) return;
    poisoned = true;
    if (shutdownPromise === undefined) {
      try {
        shutdownPromise = options.lifecycle.requestShutdown("api-port-timeout");
      } catch (error) {
        shutdownPromise = Promise.reject(error);
      }
      shutdownPromise.catch(() => undefined);
    }
  }

  async function callPort<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    requireReady();
    try {
      return await withPortTimeout(operation, portTimeoutMs);
    } catch (error) {
      if (error instanceof HttpError && error.code === "port_timeout") poisonFromPortTimeout();
      throw error;
    }
  }

  async function handleInput(request: IncomingMessage, response: ServerResponse, correlationId: string): Promise<void> {
    requireReady();
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    const parsed = parseInput(body);
    const fingerprint = inputFingerprint(parsed.type, parsed.content);
    const duplicate = duplicates.find((entry) => entry.requestId === parsed.request_id);
    if (duplicate !== undefined) {
      if (duplicate.fingerprint !== fingerprint) throw new HttpError(409, "duplicate_mismatch");
      duplicate.lastUsed = ++duplicateClock;
      const result = await duplicate.result;
      return safeWriteJson(response, 202, { ...result, duplicate: true }, maxResponseBytes, correlationId);
    }
    if (duplicates.length >= duplicateCapacity && duplicates.every((entry) => !entry.settled))
      throw new HttpError(429, "duplicate_cache_pending");
    while (duplicates.length >= duplicateCapacity) {
      let index = -1;
      let oldest = Number.POSITIVE_INFINITY;
      for (let i = 0; i < duplicates.length; i += 1) {
        const entry = duplicates[i];
        if (entry?.settled === true && entry.lastUsed < oldest) {
          oldest = entry.lastUsed;
          index = i;
        }
      }
      if (index < 0) throw new HttpError(429, "duplicate_cache_pending");
      duplicates.splice(index, 1);
    }
    const accepted = enqueueInput(async (): Promise<AcceptedResult> => {
      requireReady();
      const state = validateRunState((await callPort((signal) => options.session.state({ signal }))).runState);
      if (!legalInput(parsed.type, state)) throw new HttpError(409, "illegal_state");
      const runState = validateRunState(
        await callPort((signal) =>
          options.session.input({
            requestId: parsed.request_id,
            correlationId,
            kind: parsed.type,
            content: parsed.content,
            signal,
          }),
        ),
      );
      return {
        version: "cogs.input-acceptance/v1alpha1",
        request_id: parsed.request_id,
        correlation_id: correlationId,
        accepted: true,
        duplicate: false,
        run_state: runState,
      };
    });
    const entry: DuplicateEntry = {
      requestId: parsed.request_id,
      fingerprint,
      result: accepted,
      settled: false,
      lastUsed: ++duplicateClock,
    };
    duplicates.push(entry);
    accepted
      .finally(() => {
        entry.settled = true;
      })
      .catch(() => undefined);
    try {
      const result = await accepted;
      return safeWriteJson(response, 202, { ...result }, maxResponseBytes, correlationId);
    } catch (error) {
      forgetDuplicate(parsed.request_id);
      throw error;
    }
  }

  async function handleAbort(request: IncomingMessage, response: ServerResponse, correlationId: string): Promise<void> {
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    if (!plainObject(body)) throw new HttpError(400, "malformed_json");
    assertNoUnknown(body, ["request_id"]);
    const requestId = requiredId(body, "request_id");
    const state = validateRunState((await callPort((signal) => options.session.state({ signal }))).runState);
    if (state !== "running") {
      return safeWriteJson(
        response,
        202,
        { version: "cogs.abort/v1alpha1", request_id: requestId, aborted: state === "aborting", run_state: state },
        maxResponseBytes,
        correlationId,
      );
    }
    abortPromise ??= callPort((signal) => options.session.abort({ requestId, correlationId, signal })).finally(() => {
      abortPromise = undefined;
    });
    const result = validateAbortResult(await abortPromise);
    return safeWriteJson(
      response,
      202,
      { version: "cogs.abort/v1alpha1", request_id: requestId, aborted: result.aborted, run_state: result.runState },
      maxResponseBytes,
      correlationId,
    );
  }

  async function handleExport(
    request: IncomingMessage,
    response: ServerResponse,
    correlationId: string,
  ): Promise<void> {
    requireReady();
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    if (!plainObject(body)) throw new HttpError(400, "malformed_json");
    assertNoUnknown(body, ["request_id"]);
    const requestId = requiredId(body, "request_id");
    const bundle = validateJsonValue(
      await callPort((signal) => options.exporter.createExport({ requestId, correlationId, signal })),
    );
    return safeWriteJson(
      response,
      200,
      { version: "cogs.export-response/v1alpha1", sensitive: true, bundle },
      maxResponseBytes,
      correlationId,
    );
  }

  async function handleShutdown(
    request: IncomingMessage,
    response: ServerResponse,
    correlationId: string,
  ): Promise<void> {
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    if (!plainObject(body)) throw new HttpError(400, "malformed_json");
    assertNoUnknown(body, []);
    shutdownPromise ??= options.lifecycle.requestShutdown("api-shutdown");
    await shutdownPromise;
    return safeWriteJson(
      response,
      202,
      { version: "cogs.shutdown/v1alpha1", accepted: true },
      maxResponseBytes,
      correlationId,
    );
  }

  async function handleEntries(url: URL, response: ServerResponse, correlationId: string): Promise<void> {
    requireReady();
    const limitText = url.searchParams.get("limit") ?? "50";
    if (!/^\d+$/.test(limitText)) throw new HttpError(400, "bad_limit");
    const limit = Number(limitText);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new HttpError(400, "bad_limit");
    const after = decodeCursor(url.searchParams.get("after"));
    const page = validateEntriesPage(await callPort((signal) => options.history.entries({ after, limit, signal })));
    return safeWriteJson(
      response,
      200,
      {
        version: "cogs.entries/v1alpha1",
        entries: page.entries,
        next: page.nextAfter === undefined ? undefined : encodeCursor(page.nextAfter),
      },
      maxResponseBytes,
      correlationId,
    );
  }

  function handleEvents(url: URL, request: IncomingMessage, response: ServerResponse): void {
    requireReady();
    const afterText = url.searchParams.get("after") ?? "0";
    if (!/^\d+$/.test(afterText)) throw new HttpError(400, "bad_after");
    const after = Number(afterText);
    if (!Number.isSafeInteger(after)) throw new HttpError(400, "bad_after");
    if (after > sequence) throw new HttpError(409, "replay_future");
    const oldest = replay[0]?.seq ?? sequence + 1;
    if (replay.length > 0 && after < oldest - 1) throw new HttpError(409, "replay_gap");
    response.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    for (const item of replay) {
      if (item.seq > after && !writeSerializedSse(response, item.seq, item.serialized)) {
        response.destroy();
        return;
      }
    }
    const onClose = () => clients.delete(client);
    const client = { response, close: () => request.off("close", onClose) };
    clients.add(client);
    request.on("close", onClose);
  }

  async function stateBody(): Promise<JsonValue> {
    const state = await callPort((signal) => options.session.state({ signal }));
    return {
      version: "cogs.state/v1alpha1",
      lifecycle: options.lifecycle.state,
      ready: !poisoned && options.lifecycle.ready,
      run_state: validateRunState(state.runState),
      usage: state.usage === undefined ? null : validateJsonValue(state.usage),
    };
  }

  function enqueueInput<T>(operation: () => Promise<T>): Promise<T> {
    const run = inputQueue.then(operation, operation);
    inputQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  function forgetDuplicate(requestId: string): void {
    const index = duplicates.findIndex((entry) => entry.requestId === requestId);
    if (index >= 0) duplicates.splice(index, 1);
  }

  function publish(event: ApiEvent): boolean {
    if (poisoned || sequence >= Number.MAX_SAFE_INTEGER) return false;
    const nextSeq = sequence + 1;
    let clean: ApiEvent;
    let serialized: string;
    try {
      clean = validateEvent(event);
      serialized = serializeSse(nextSeq, clean);
    } catch {
      return false;
    }
    if (Buffer.byteLength(serialized) > maxEventBytes) return false;
    sequence = nextSeq;
    replay.push({ seq: sequence, event: clean, serialized });
    while (replay.length > eventReplayCapacity) replay.shift();
    for (const client of [...clients]) {
      if (!writeSerializedSse(client.response, sequence, serialized)) {
        clients.delete(client);
        client.close();
      }
    }
    return true;
  }

  function encodeCursor(after: string): string {
    const payload = Buffer.from(JSON.stringify({ session: options.sessionId, after }), "utf8").toString("base64url");
    const sig = createHmac("sha256", cursorSecret).update(payload).digest("base64url");
    return `${payload}.${sig}`;
  }

  function decodeCursor(cursor: string | null): string | undefined {
    if (cursor === null || cursor === "") return undefined;
    try {
      const [payload, sig, extra] = cursor.split(".");
      if (payload === undefined || sig === undefined || extra !== undefined) throw new Error("bad cursor");
      const expected = createHmac("sha256", cursorSecret).update(payload).digest("base64url");
      if (!safeEqual(sig, expected)) throw new Error("bad cursor");
      const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
        session?: unknown;
        after?: unknown;
      };
      if (
        decoded.session !== options.sessionId ||
        typeof decoded.after !== "string" ||
        Object.keys(decoded).some((key) => key !== "session" && key !== "after")
      )
        throw new Error("bad cursor");
      return decoded.after;
    } catch {
      throw new HttpError(400, "bad_cursor");
    }
  }

  return {
    listen: (port = 0, host = "127.0.0.1") =>
      new Promise((resolve, reject) => {
        if (!loopbackHost(host)) {
          reject(new Error("listen host must be loopback"));
          return;
        }
        const onError = (error: Error) => {
          server.off("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.off("error", onError);
          resolve({ port: (server.address() as { port: number }).port });
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(port, host);
      }),
    close: () =>
      new Promise((resolve, reject) => {
        closed = true;
        for (const client of clients) {
          client.close();
          client.response.destroy();
        }
        clients.clear();
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      }),
    publish,
  };

  function safeWriteJson(
    response: ServerResponse,
    status: number,
    body: JsonValue,
    maxBytes: number,
    correlationId: string,
    closeAfter = false,
  ): void {
    if (closed || response.destroyed || response.writableEnded) return;
    writeJson(response, status, body, maxBytes, correlationId, closeAfter);
  }
}

class HttpError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
  }
}

async function method(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
  maxResponseBytes: number,
  expected: string,
  allowedQuery: readonly string[],
  allowBody: boolean,
  handler: () => void | Promise<void>,
): Promise<void> {
  try {
    validateQuery(url, allowedQuery);
    if (!allowBody) rejectGetBody(request);
  } catch (error) {
    if (error instanceof HttpError) {
      drainRequest(request);
      return writeJson(
        response,
        error.status,
        { version: "cogs.error/v1alpha1", error: error.code },
        maxResponseBytes,
        correlationFrom(request),
        true,
      );
    }
    throw error;
  }
  if (request.method !== expected) {
    drainRequest(request);
    return writeJson(
      response,
      405,
      { version: "cogs.error/v1alpha1", error: "method_not_allowed" },
      maxResponseBytes,
      correlationFrom(request),
      true,
    );
  }
  try {
    await handler();
  } catch (error) {
    if (error instanceof HttpError) {
      drainRequest(request);
      return writeJson(
        response,
        error.status,
        { version: "cogs.error/v1alpha1", error: error.code },
        maxResponseBytes,
        correlationFrom(request),
        true,
      );
    }
    throw error;
  }
}

function validateQuery(url: URL, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  const seen = new Set<string>();
  for (const key of url.searchParams.keys()) {
    if (!allowedSet.has(key)) throw new HttpError(400, "unknown_query");
    if (seen.has(key)) throw new HttpError(400, "repeated_query");
    seen.add(key);
  }
}

function rejectGetBody(request: IncomingMessage): void {
  if (request.headers["content-length"] !== undefined && request.headers["content-length"] !== "0")
    throw new HttpError(400, "get_body_not_allowed");
  if (request.headers["transfer-encoding"] !== undefined) throw new HttpError(400, "get_body_not_allowed");
}

function authorized(request: IncomingMessage, tokenDigest: Buffer): boolean {
  const authorization = request.headers.authorization;
  const match = typeof authorization === "string" ? authorization.match(/^Bearer (.+)$/) : null;
  const candidate = digest(match?.[1] ?? "");
  return timingSafeEqual(candidate, tokenDigest);
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function safeEqual(left: string, right: string): boolean {
  return timingSafeEqual(digest(left), digest(right));
}

async function readJson(request: IncomingMessage, maxBytes: number, timeoutMs: number): Promise<unknown> {
  const contentType = request.headers["content-type"];
  if (request.headers["content-encoding"] !== undefined) {
    drainRequest(request);
    throw new HttpError(415, "content_encoding_not_allowed");
  }
  if (typeof contentType !== "string" || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType)) {
    drainRequest(request);
    throw new HttpError(415, "unsupported_media_type");
  }
  const contentLength = request.headers["content-length"];
  if (typeof contentLength === "string" && /^\d+$/.test(contentLength) && Number(contentLength) > maxBytes) {
    drainRequest(request);
    throw new HttpError(413, "request_too_large");
  }
  let bytes = 0;
  const chunks: Buffer[] = [];
  let settled = false;
  let timeout: NodeJS.Timeout | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      const onData = (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          drainRequest(request);
          finish(new HttpError(413, "request_too_large"));
          return;
        }
        chunks.push(chunk);
      };
      const onEnd = () => finish();
      const onError = (error: Error) => finish(error);
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        request.off("data", onData);
        request.off("end", onEnd);
        request.off("error", onError);
        if (error !== undefined) reject(error);
        else resolve();
      };
      timeout = setTimeout(() => {
        drainRequest(request);
        finish(new HttpError(408, "request_timeout"));
      }, timeoutMs);
      request.on("data", onData);
      request.on("end", onEnd);
      request.on("error", onError);
    });
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "malformed_json");
  }
}

function parseInput(body: unknown): { request_id: string; type: InputKind; content: string } {
  if (!plainObject(body)) throw new HttpError(400, "malformed_input");
  assertNoUnknown(body, ["request_id", "type", "content"]);
  const request_id = requiredId(body, "request_id");
  const type = body.type;
  const content = body.content;
  if (type !== "prompt" && type !== "steer" && type !== "follow_up") throw new HttpError(400, "bad_input_type");
  if (typeof content !== "string" || content.length < 1 || content.length > 8192)
    throw new HttpError(400, "bad_content");
  return { request_id, type, content };
}

function requiredId(body: unknown, key: string): string {
  if (!plainObject(body)) throw new HttpError(400, "malformed_json");
  const value = body[key];
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value))
    throw new HttpError(400, `bad_${key}`);
  return value;
}

function assertNoUnknown(body: Record<string, unknown>, keys: readonly string[]): void {
  const allowed = new Set(keys);
  if (Object.keys(body).some((key) => !allowed.has(key))) throw new HttpError(400, "unknown_field");
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function legalInput(kind: InputKind, state: RunState): boolean {
  if (kind === "steer") return state === "running";
  if (kind === "follow_up") return state === "settled" || state === "idle";
  return state === "idle" || state === "settled";
}

function validateRunState(value: unknown): RunState {
  if (value === "idle" || value === "running" || value === "settled" || value === "aborting" || value === "shutdown")
    return value;
  throw new HttpError(500, "malformed_port_result");
}

function validateAbortResult(value: unknown): { aborted: boolean; runState: RunState } {
  if (!plainObject(value)) throw new HttpError(500, "malformed_port_result");
  if (Object.keys(value).some((key) => key !== "aborted" && key !== "runState"))
    throw new HttpError(500, "malformed_port_result");
  if (typeof value.aborted !== "boolean") throw new HttpError(500, "malformed_port_result");
  return { aborted: value.aborted, runState: validateRunState(value.runState) };
}

function validateEntriesPage(value: unknown): { entries: readonly JsonValue[]; nextAfter?: string } {
  if (!plainObject(value)) throw new HttpError(500, "malformed_port_result");
  if (Object.keys(value).some((key) => key !== "entries" && key !== "nextAfter"))
    throw new HttpError(500, "malformed_port_result");
  if (!Array.isArray(value.entries)) throw new HttpError(500, "malformed_port_result");
  const entries = validateJsonValue(value.entries);
  if (!Array.isArray(entries)) throw new HttpError(500, "malformed_port_result");
  if (value.nextAfter !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(String(value.nextAfter)))
    throw new HttpError(500, "malformed_port_result");
  return value.nextAfter === undefined ? { entries } : { entries, nextAfter: String(value.nextAfter) };
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: JsonValue,
  maxResponseBytes: number,
  correlationId: string,
  closeAfter = false,
): void {
  if (response.destroyed || response.writableEnded) return;
  const limit = Number.isSafeInteger(maxResponseBytes) && maxResponseBytes >= 128 ? maxResponseBytes : 128;
  let payload: Buffer;
  try {
    payload = Buffer.from(JSON.stringify(body));
  } catch {
    if (response.headersSent) {
      response.destroy();
      return;
    }
    status = 500;
    closeAfter = true;
    payload = Buffer.from(JSON.stringify({ version: "cogs.error/v1alpha1", error: "internal" }));
  }
  if (payload.length > limit) {
    const overflow = Buffer.from(JSON.stringify({ version: "cogs.error/v1alpha1", error: "response_too_large" }));
    if (overflow.length > limit) {
      response.destroy();
      return;
    }
    if (!response.headersSent)
      response.writeHead(500, {
        "content-type": "application/json; charset=utf-8",
        "content-length": overflow.length,
        "x-cogs-correlation-id": correlationId,
        "cache-control": "no-store",
        ...(closeAfter ? { connection: "close" } : {}),
      });
    endResponse(response, overflow, closeAfter);
    return;
  }
  if (!response.headersSent)
    response.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "content-length": payload.length,
      "x-cogs-correlation-id": correlationId,
      "cache-control": "no-store",
      ...(closeAfter ? { connection: "close" } : {}),
    });
  endResponse(response, payload, closeAfter);
}

function endResponse(response: ServerResponse, payload: Buffer, closeAfter: boolean): void {
  response.end(payload, () => {
    if (closeAfter) response.destroy();
  });
}

function validateEvent(event: ApiEvent): ApiEvent {
  if (!strictPlainObject(event)) throw new Error("malformed event");
  const keys = Object.keys(event);
  if (keys.some((key) => key !== "type" && key !== "correlation_id" && key !== "payload"))
    throw new Error("malformed event");
  const type = dataProperty(event, "type");
  const correlation = dataProperty(event, "correlation_id");
  const payload = dataProperty(event, "payload");
  if (typeof type !== "string" || !/^[a-z][a-z0-9._:-]{0,63}$/.test(type)) throw new Error("malformed event");
  if (
    correlation !== undefined &&
    (typeof correlation !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(correlation))
  )
    throw new Error("malformed event");
  const clean: { type: string; correlation_id?: string; payload?: JsonValue } = { type };
  if (correlation !== undefined) clean.correlation_id = correlation;
  if (payload !== undefined) clean.payload = validateJsonValue(payload);
  return clean;
}

function serializeSse(seq: number, event: ApiEvent): string {
  return `id: ${seq}\nevent: cogs\ndata: ${JSON.stringify({ ...event, version: "cogs.event/v1alpha1", seq })}\n\n`;
}

function dataProperty(object: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor)) throw new Error("malformed event");
  return descriptor.value;
}

function strictPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateJsonValue(value: unknown, seen = new Set<object>(), depth = 0, count = { value: 0 }): JsonValue {
  count.value += 1;
  if (depth > 32 || count.value > 4096) throw new Error("malformed event");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("malformed event");
    return value;
  }
  if (typeof value !== "object") throw new Error("malformed event");
  if (seen.has(value)) throw new Error("malformed event");
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => validateJsonValue(item, seen, depth + 1, count));
    if (!strictPlainObject(value)) throw new Error("malformed event");
    const output: Record<string, JsonValue> = {};
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) throw new Error("malformed event");
      if (descriptor.value !== undefined) output[key] = validateJsonValue(descriptor.value, seen, depth + 1, count);
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

function writeSerializedSse(response: ServerResponse, _seq: number, serialized: string): boolean {
  if (response.destroyed || response.writableEnded) return false;
  if (!response.write(serialized)) {
    response.destroy();
    return false;
  }
  return true;
}

function correlationFrom(request: IncomingMessage): string {
  const header = request.headers["x-cogs-correlation-id"];
  if (typeof header === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(header)) return header;
  return `worker-${randomUUID()}`;
}

function drainRequest(request: IncomingMessage): void {
  request.resume();
}

function validateConfig(options: ApiServerOptions): void {
  const bearerBytes = Buffer.byteLength(options.bearerToken, "utf8");
  if (bearerBytes < 32 || bearerBytes > 4096 || hasControlCharacter(options.bearerToken))
    throw new Error("invalid bearer token configuration");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(options.sessionId))
    throw new Error("invalid session id configuration");
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code !== undefined && (code < 0x20 || code === 0x7f)) return true;
  }
  return false;
}

function optionInteger(value: number | undefined, fallback: number, name: string, min: number, max: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) throw new Error(`invalid ${name}`);
  return resolved;
}

function loopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "::1";
}

function validRequestTarget(target: string): boolean {
  if (!target.startsWith("/") || target.startsWith("//")) return false;
  for (const character of target) {
    const code = character.codePointAt(0);
    if (code !== undefined && (code < 0x20 || code === 0x7f)) return false;
  }
  return !target.includes("\\") && !target.includes("#");
}

function duplicateHeader(request: IncomingMessage, name: string): boolean {
  let count = 0;
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i]?.toLowerCase() === name) count += 1;
  }
  return count > 1;
}

async function withPortTimeout<T>(operation: (signal: AbortSignal) => Promise<T>, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  let timeout: NodeJS.Timeout | undefined;
  try {
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new HttpError(504, "port_timeout"));
      }, timeoutMs);
    });
    return await Promise.race([operation(controller.signal), timeoutPromise]);
  } finally {
    controller.abort();
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function inputFingerprint(kind: InputKind, content: string): string {
  return createHash("sha256").update(kind).update("\0").update(content).digest("base64url");
}
