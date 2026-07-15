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
};
type Client = { readonly response: ServerResponse; readonly after: number };

const forbiddenResponse = Object.freeze({ version: "cogs.error/v1alpha1", error: "forbidden" });

export function createApiServer(options: ApiServerOptions): ApiServer {
  if (options.bearerToken.length < 16 || options.bearerToken.length > 4096) {
    throw new Error("invalid bearer token configuration");
  }
  const maxRequestBytes = options.maxRequestBytes ?? 16 * 1024;
  const maxResponseBytes = options.maxResponseBytes ?? 128 * 1024;
  const duplicateCapacity = options.duplicateCapacity ?? 128;
  const eventReplayCapacity = options.eventReplayCapacity ?? 256;
  const requestTimeoutMs = options.requestTimeoutMs ?? 5_000;
  const portTimeoutMs = options.portTimeoutMs ?? requestTimeoutMs;
  const maxEventBytes = options.maxEventBytes ?? 32 * 1024;
  const duplicates: DuplicateEntry[] = [];
  const replay: { seq: number; event: ApiEvent; serialized: string }[] = [];
  const clients = new Set<Client>();
  let sequence = 0;
  let inputQueue: Promise<void> = Promise.resolve();
  let abortPromise: Promise<{ aborted: boolean; runState: RunState }> | undefined;
  let shutdownPromise: Promise<void> | undefined;
  let closed = false;
  const tokenDigest = digest(options.bearerToken);
  const cursorSecret = createHmac("sha256", options.bearerToken).update(`cursor:${options.sessionId}`).digest();

  const server = createServer((request, response) => {
    void route(request, response).catch(() => {
      safeWriteJson(response, 500, { version: "cogs.error/v1alpha1", error: "internal" }, maxResponseBytes, "internal");
    });
  });

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const correlationId = correlationFrom(request);
    response.setHeader("x-cogs-correlation-id", correlationId);
    if (url.pathname === "/health/live") {
      return method(request, response, url, "GET", [], false, () =>
        safeWriteJson(response, 200, { live: true }, maxResponseBytes, correlationId),
      );
    }
    if (!authorized(request, tokenDigest)) {
      drainRequest(request);
      return safeWriteJson(response, 401, forbiddenResponse, maxResponseBytes, correlationId);
    }
    switch (url.pathname) {
      case "/health/ready":
        return method(request, response, url, "GET", [], false, () =>
          safeWriteJson(
            response,
            options.lifecycle.ready ? 200 : 503,
            { ready: options.lifecycle.ready },
            maxResponseBytes,
            correlationId,
          ),
        );
      case "/v1/state":
        return method(request, response, url, "GET", [], false, async () =>
          safeWriteJson(response, 200, await stateBody(), maxResponseBytes, correlationId),
        );
      case "/v1/input":
        return method(request, response, url, "POST", [], true, async () =>
          handleInput(request, response, correlationId),
        );
      case "/v1/abort":
        return method(request, response, url, "POST", [], true, async () =>
          handleAbort(request, response, correlationId),
        );
      case "/v1/export":
        return method(request, response, url, "POST", [], true, async () =>
          handleExport(request, response, correlationId),
        );
      case "/v1/shutdown":
        return method(request, response, url, "POST", [], true, async () =>
          handleShutdown(request, response, correlationId),
        );
      case "/v1/entries":
        return method(request, response, url, "GET", ["after", "limit"], false, async () =>
          handleEntries(url, response, correlationId),
        );
      case "/v1/events":
        return method(request, response, url, "GET", ["after"], false, () => handleEvents(url, request, response));
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
    if (!options.lifecycle.ready) throw new HttpError(503, "not_ready");
  }

  async function handleInput(request: IncomingMessage, response: ServerResponse, correlationId: string): Promise<void> {
    requireReady();
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    const parsed = parseInput(body);
    const fingerprint = inputFingerprint(parsed.type, parsed.content);
    const duplicate = duplicates.find((entry) => entry.requestId === parsed.request_id);
    if (duplicate !== undefined) {
      if (duplicate.fingerprint !== fingerprint) throw new HttpError(409, "duplicate_mismatch");
      const result = await duplicate.result;
      return safeWriteJson(response, 202, { ...result, duplicate: true }, maxResponseBytes, correlationId);
    }
    if (duplicates.length >= duplicateCapacity && duplicates.every((entry) => !entry.settled))
      throw new HttpError(429, "duplicate_cache_pending");
    while (duplicates.length >= duplicateCapacity) {
      const index = duplicates.findIndex((entry) => entry.settled);
      if (index < 0) throw new HttpError(429, "duplicate_cache_pending");
      duplicates.splice(index, 1);
    }
    const accepted = enqueueInput(async (): Promise<AcceptedResult> => {
      requireReady();
      const state = (await withPortTimeout((signal) => options.session.state({ signal }), portTimeoutMs)).runState;
      if (!legalInput(parsed.type, state)) throw new HttpError(409, "illegal_state");
      const runState = await withPortTimeout(
        (signal) =>
          options.session.input({
            requestId: parsed.request_id,
            correlationId,
            kind: parsed.type,
            content: parsed.content,
            signal,
          }),
        portTimeoutMs,
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
    const entry: DuplicateEntry = { requestId: parsed.request_id, fingerprint, result: accepted, settled: false };
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
    const state = (await withPortTimeout((signal) => options.session.state({ signal }), portTimeoutMs)).runState;
    if (state !== "running" && state !== "aborting") {
      return safeWriteJson(
        response,
        202,
        { version: "cogs.abort/v1alpha1", request_id: requestId, aborted: false, run_state: state },
        maxResponseBytes,
        correlationId,
      );
    }
    abortPromise ??= withPortTimeout(
      (signal) => options.session.abort({ requestId, correlationId, signal }),
      portTimeoutMs,
    ).finally(() => {
      abortPromise = undefined;
    });
    const result = await abortPromise;
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
    const bundle = await withPortTimeout(
      (signal) => options.exporter.createExport({ requestId, correlationId, signal }),
      portTimeoutMs,
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
    const page = await withPortTimeout((signal) => options.history.entries({ after, limit, signal }), portTimeoutMs);
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
    const oldest = replay[0]?.seq ?? sequence + 1;
    if (replay.length > 0 && after < oldest - 1) throw new HttpError(409, "replay_gap");
    response.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    for (const item of replay) if (item.seq > after && !writeSerializedSse(response, item.seq, item.serialized)) return;
    const client = { response, after };
    clients.add(client);
    request.on("close", () => clients.delete(client));
  }

  async function stateBody(): Promise<JsonValue> {
    const state = await withPortTimeout((signal) => options.session.state({ signal }), portTimeoutMs);
    return {
      version: "cogs.state/v1alpha1",
      lifecycle: options.lifecycle.state,
      ready: options.lifecycle.ready,
      run_state: state.runState,
      usage: state.usage ?? null,
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
    const clean = validateEvent(event);
    const nextSeq = sequence + 1;
    const serialized = serializeSse(nextSeq, clean);
    if (Buffer.byteLength(serialized) > maxEventBytes) return false;
    sequence = nextSeq;
    replay.push({ seq: sequence, event: clean, serialized });
    while (replay.length > eventReplayCapacity) replay.shift();
    for (const client of [...clients]) {
      if (!writeSerializedSse(client.response, sequence, serialized)) clients.delete(client);
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
      new Promise((resolve) =>
        server.listen(port, host, () => resolve({ port: (server.address() as { port: number }).port })),
      ),
    close: () =>
      new Promise((resolve, reject) => {
        closed = true;
        for (const client of clients) client.response.destroy();
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
  ): void {
    if (closed || response.destroyed || response.writableEnded) return;
    writeJson(response, status, body, maxBytes, correlationId);
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
        4096,
        correlationFrom(request),
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
      4096,
      correlationFrom(request),
    );
  }
  try {
    await handler();
  } catch (error) {
    if (error instanceof HttpError)
      return writeJson(
        response,
        error.status,
        { version: "cogs.error/v1alpha1", error: error.code },
        4096,
        correlationFrom(request),
      );
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
  if (request.headers["content-encoding"] !== undefined) throw new HttpError(415, "content_encoding_not_allowed");
  if (typeof contentType !== "string" || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType))
    throw new HttpError(415, "unsupported_media_type");
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
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        request.removeAllListeners("data");
        request.removeAllListeners("end");
        request.removeAllListeners("error");
        if (error !== undefined) reject(error);
        else resolve();
      };
      timeout = setTimeout(() => {
        drainRequest(request);
        finish(new HttpError(408, "request_timeout"));
      }, timeoutMs);
      request.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          drainRequest(request);
          finish(new HttpError(413, "request_too_large"));
          return;
        }
        chunks.push(chunk);
      });
      request.on("end", () => finish());
      request.on("error", finish);
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

function writeJson(
  response: ServerResponse,
  status: number,
  body: JsonValue,
  maxResponseBytes: number,
  correlationId: string,
): void {
  if (response.destroyed || response.writableEnded) return;
  const payload = Buffer.from(JSON.stringify(body));
  if (payload.length > maxResponseBytes) {
    const overflow = Buffer.from(JSON.stringify({ version: "cogs.error/v1alpha1", error: "response_too_large" }));
    if (!response.headersSent)
      response.writeHead(500, {
        "content-type": "application/json; charset=utf-8",
        "content-length": overflow.length,
        "x-cogs-correlation-id": correlationId,
        "cache-control": "no-store",
      });
    response.end(overflow);
    return;
  }
  if (!response.headersSent)
    response.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "content-length": payload.length,
      "x-cogs-correlation-id": correlationId,
      "cache-control": "no-store",
    });
  response.end(payload);
}

function validateEvent(event: ApiEvent): ApiEvent {
  if (!plainObject(event)) throw new Error("malformed event");
  const keys = Object.keys(event);
  if (keys.some((key) => key !== "type" && key !== "correlation_id" && key !== "payload"))
    throw new Error("malformed event");
  if (typeof event.type !== "string" || !/^[a-z][a-z0-9._:-]{0,63}$/.test(event.type))
    throw new Error("malformed event");
  if (
    event.correlation_id !== undefined &&
    (typeof event.correlation_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(event.correlation_id))
  )
    throw new Error("malformed event");
  const clean: { type: string; correlation_id?: string; payload?: JsonValue } = { type: event.type };
  if (event.correlation_id !== undefined) clean.correlation_id = event.correlation_id;
  if (event.payload !== undefined) clean.payload = event.payload;
  return clean;
}

function serializeSse(seq: number, event: ApiEvent): string {
  return `id: ${seq}\nevent: cogs\ndata: ${JSON.stringify({ ...event, version: "cogs.event/v1alpha1", seq })}\n\n`;
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
