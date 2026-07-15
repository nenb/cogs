import { createHmac, timingSafeEqual } from "node:crypto";
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
  }) => Promise<RunState>;
  readonly abort: (input: {
    requestId: string;
    correlationId: string;
  }) => Promise<{ aborted: boolean; runState: RunState }>;
  readonly state: () => Promise<{ runState: RunState; usage?: JsonValue }>;
}

export interface HistoryPort {
  readonly entries: (input: { after: string | undefined; limit: number }) => Promise<{
    entries: readonly JsonValue[];
    nextAfter?: string;
  }>;
}

export interface ExportPort {
  readonly createExport: (input: { requestId: string; correlationId: string }) => Promise<JsonValue>;
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
}

export interface ApiServer {
  readonly listen: (port?: number, host?: string) => Promise<{ port: number }>;
  readonly close: () => Promise<void>;
  readonly publish: (event: ApiEvent) => void;
}

type DuplicateEntry = { readonly requestId: string; readonly result: Promise<AcceptedResult> };
type Client = { readonly response: ServerResponse; readonly after: number };

const forbiddenResponse = Object.freeze({ version: "cogs.error/v1alpha1", error: "forbidden" });

export function createApiServer(options: ApiServerOptions): ApiServer {
  const maxRequestBytes = options.maxRequestBytes ?? 16 * 1024;
  const maxResponseBytes = options.maxResponseBytes ?? 128 * 1024;
  const duplicateCapacity = options.duplicateCapacity ?? 128;
  const eventReplayCapacity = options.eventReplayCapacity ?? 256;
  const requestTimeoutMs = options.requestTimeoutMs ?? 5_000;
  const duplicates: DuplicateEntry[] = [];
  const replay: { seq: number; event: ApiEvent }[] = [];
  const clients = new Set<Client>();
  let sequence = 0;
  const cursorSecret = createHmac("sha256", options.bearerToken).update(`cursor:${options.sessionId}`).digest();

  const server = createServer((request, response) => {
    void route(request, response).catch(() => {
      writeJson(response, 500, { version: "cogs.error/v1alpha1", error: "internal" }, maxResponseBytes, "internal");
    });
  });

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const correlationId = correlationFrom(request);
    response.setHeader("x-cogs-correlation-id", correlationId);
    if (url.pathname === "/health/live")
      return method(request, response, "GET", () =>
        writeJson(response, 200, { live: true }, maxResponseBytes, correlationId),
      );
    if (!authorized(request, options.bearerToken))
      return writeJson(response, 401, forbiddenResponse, maxResponseBytes, correlationId);
    switch (url.pathname) {
      case "/health/ready":
        return method(request, response, "GET", () =>
          writeJson(
            response,
            options.lifecycle.ready ? 200 : 503,
            { ready: options.lifecycle.ready },
            maxResponseBytes,
            correlationId,
          ),
        );
      case "/v1/state":
        return method(request, response, "GET", async () =>
          writeJson(response, 200, await stateBody(), maxResponseBytes, correlationId),
        );
      case "/v1/input":
        return method(request, response, "POST", async () => handleInput(request, response, correlationId));
      case "/v1/abort":
        return method(request, response, "POST", async () => handleAbort(request, response, correlationId));
      case "/v1/export":
        return method(request, response, "POST", async () => handleExport(request, response, correlationId));
      case "/v1/shutdown":
        return method(request, response, "POST", async () => {
          await options.lifecycle.requestShutdown("api-shutdown");
          return writeJson(
            response,
            202,
            { version: "cogs.shutdown/v1alpha1", accepted: true },
            maxResponseBytes,
            correlationId,
          );
        });
      case "/v1/entries":
        return method(request, response, "GET", async () => handleEntries(url, response, correlationId));
      case "/v1/events":
        return method(request, response, "GET", () => handleEvents(url, request, response));
      default:
        return writeJson(
          response,
          404,
          { version: "cogs.error/v1alpha1", error: "not_found" },
          maxResponseBytes,
          correlationId,
        );
    }
  }

  async function handleInput(request: IncomingMessage, response: ServerResponse, correlationId: string): Promise<void> {
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    const parsed = parseInput(body);
    const duplicate = duplicates.find((entry) => entry.requestId === parsed.request_id);
    if (duplicate !== undefined) {
      const result = await duplicate.result;
      return writeJson(response, 202, { ...result, duplicate: true }, maxResponseBytes, correlationId);
    }
    const accepted = (async (): Promise<AcceptedResult> => {
      const state = (await options.session.state()).runState;
      if (!legalInput(parsed.type, state)) throw new HttpError(409, "illegal_state");
      const runState = await options.session.input({
        requestId: parsed.request_id,
        correlationId,
        kind: parsed.type,
        content: parsed.content,
      });
      return {
        version: "cogs.input-acceptance/v1alpha1",
        request_id: parsed.request_id,
        correlation_id: correlationId,
        accepted: true,
        duplicate: false,
        run_state: runState,
      };
    })();
    rememberDuplicate(parsed.request_id, accepted);
    try {
      const result = await accepted;
      return writeJson(response, 202, { ...result }, maxResponseBytes, correlationId);
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
    const state = (await options.session.state()).runState;
    if (state !== "running" && state !== "aborting")
      return writeJson(
        response,
        202,
        { version: "cogs.abort/v1alpha1", request_id: requestId, aborted: false, run_state: state },
        maxResponseBytes,
        correlationId,
      );
    const result = await options.session.abort({ requestId, correlationId });
    return writeJson(
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
    const body = await readJson(request, maxRequestBytes, requestTimeoutMs);
    if (!plainObject(body)) throw new HttpError(400, "malformed_json");
    assertNoUnknown(body, ["request_id"]);
    const requestId = requiredId(body, "request_id");
    const bundle = await options.exporter.createExport({ requestId, correlationId });
    return writeJson(
      response,
      200,
      { version: "cogs.export-response/v1alpha1", sensitive: true, bundle },
      maxResponseBytes,
      correlationId,
    );
  }

  async function handleEntries(url: URL, response: ServerResponse, correlationId: string): Promise<void> {
    const limitText = url.searchParams.get("limit") ?? "50";
    if (!/^\d+$/.test(limitText))
      return writeJson(
        response,
        400,
        { version: "cogs.error/v1alpha1", error: "bad_limit" },
        maxResponseBytes,
        correlationId,
      );
    const limit = Number(limitText);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      return writeJson(
        response,
        400,
        { version: "cogs.error/v1alpha1", error: "bad_limit" },
        maxResponseBytes,
        correlationId,
      );
    const after = decodeCursor(url.searchParams.get("after"));
    const page = await options.history.entries({ after, limit });
    return writeJson(
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
    const afterText = url.searchParams.get("after") ?? "0";
    if (!/^\d+$/.test(afterText)) {
      writeJson(
        response,
        400,
        { version: "cogs.error/v1alpha1", error: "bad_after" },
        maxResponseBytes,
        correlationFrom(request),
      );
      return;
    }
    const after = Number(afterText);
    const oldest = replay[0]?.seq ?? sequence + 1;
    if (replay.length > 0 && after < oldest - 1) {
      writeJson(
        response,
        409,
        { version: "cogs.error/v1alpha1", error: "replay_gap", oldest },
        maxResponseBytes,
        correlationFrom(request),
      );
      return;
    }
    response.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    for (const item of replay) if (item.seq > after) writeSse(response, item.seq, item.event);
    const client = { response, after };
    clients.add(client);
    request.on("close", () => clients.delete(client));
  }

  async function stateBody(): Promise<JsonValue> {
    const state = await options.session.state();
    return {
      version: "cogs.state/v1alpha1",
      lifecycle: options.lifecycle.state,
      ready: options.lifecycle.ready,
      run_state: state.runState,
      usage: state.usage ?? null,
    };
  }

  function rememberDuplicate(requestId: string, result: Promise<AcceptedResult>): void {
    duplicates.push({ requestId, result });
    while (duplicates.length > duplicateCapacity) duplicates.shift();
  }

  function forgetDuplicate(requestId: string): void {
    const index = duplicates.findIndex((entry) => entry.requestId === requestId);
    if (index >= 0) duplicates.splice(index, 1);
  }

  function publish(event: ApiEvent): void {
    sequence += 1;
    replay.push({ seq: sequence, event });
    while (replay.length > eventReplayCapacity) replay.shift();
    for (const client of clients) writeSse(client.response, sequence, event);
  }

  function encodeCursor(after: string): string {
    const payload = Buffer.from(JSON.stringify({ session: options.sessionId, after }), "utf8").toString("base64url");
    const sig = createHmac("sha256", cursorSecret).update(payload).digest("base64url");
    return `${payload}.${sig}`;
  }

  function decodeCursor(cursor: string | null): string | undefined {
    if (cursor === null || cursor === "") return undefined;
    const [payload, sig, extra] = cursor.split(".");
    if (payload === undefined || sig === undefined || extra !== undefined) throw new HttpError(400, "bad_cursor");
    const expected = createHmac("sha256", cursorSecret).update(payload).digest("base64url");
    if (!safeEqual(sig, expected)) throw new HttpError(400, "bad_cursor");
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
      session?: unknown;
      after?: unknown;
    };
    if (decoded.session !== options.sessionId || typeof decoded.after !== "string")
      throw new HttpError(400, "bad_cursor");
    return decoded.after;
  }

  return {
    listen: (port = 0, host = "127.0.0.1") =>
      new Promise((resolve) =>
        server.listen(port, host, () => resolve({ port: (server.address() as { port: number }).port })),
      ),
    close: () =>
      new Promise((resolve, reject) => {
        for (const client of clients) client.response.destroy();
        clients.clear();
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      }),
    publish,
  };
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
  expected: string,
  handler: () => void | Promise<void>,
): Promise<void> {
  if (request.method !== expected)
    return writeJson(
      response,
      405,
      { version: "cogs.error/v1alpha1", error: "method_not_allowed" },
      4096,
      correlationFrom(request),
    );
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

function authorized(request: IncomingMessage, bearerToken: string): boolean {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string") return false;
  const match = authorization.match(/^Bearer (.+)$/);
  if (match === null) return false;
  return safeEqual(match[1] ?? "", bearerToken);
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) timingSafeEqual(leftBuffer, leftBuffer);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

async function readJson(request: IncomingMessage, maxBytes: number, timeoutMs: number): Promise<unknown> {
  const contentType = request.headers["content-type"];
  if (typeof contentType !== "string" || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType))
    throw new HttpError(415, "unsupported_media_type");
  let bytes = 0;
  const chunks: Buffer[] = [];
  let timeout: NodeJS.Timeout | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      timeout = setTimeout(() => reject(new HttpError(408, "request_timeout")), timeoutMs);
      request.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          reject(new HttpError(413, "request_too_large"));
          return;
        }
        chunks.push(chunk);
      });
      request.on("end", resolve);
      request.on("error", reject);
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
  const payload = Buffer.from(JSON.stringify(body));
  if (payload.length > maxResponseBytes) {
    const overflow = Buffer.from(JSON.stringify({ version: "cogs.error/v1alpha1", error: "response_too_large" }));
    response.writeHead(500, {
      "content-type": "application/json; charset=utf-8",
      "content-length": overflow.length,
      "x-cogs-correlation-id": correlationId,
    });
    response.end(overflow);
    return;
  }
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": payload.length,
    "x-cogs-correlation-id": correlationId,
  });
  response.end(payload);
}

function writeSse(response: ServerResponse, seq: number, event: ApiEvent): void {
  response.write(`id: ${seq}\n`);
  response.write("event: cogs\n");
  response.write(`data: ${JSON.stringify({ version: "cogs.event/v1alpha1", seq, ...event })}\n\n`);
}

function correlationFrom(request: IncomingMessage): string {
  const header = request.headers["x-cogs-correlation-id"];
  if (typeof header === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(header)) return header;
  return `worker-${Date.now().toString(36)}`;
}
