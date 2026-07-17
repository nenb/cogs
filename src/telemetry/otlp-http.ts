import { TextDecoder } from "node:util";

export type OtlpSignalKind = "logs" | "traces" | "metrics";
export type OtlpFetch = (url: string, init: RequestInit) => Promise<Response>;

export type OtlpPostConfig = Readonly<{
  url: string;
  kind: OtlpSignalKind;
  body: unknown;
  timeoutMs: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  fetch?: OtlpFetch;
  parent?: AbortSignal;
}>;

export function exactPlainObject(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
): asserts value is Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("bad object");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key === "symbol")) throw new Error("bad keys");
  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error("bad descriptor");
    if (!required.includes(key) && !optional.includes(key)) throw new Error("bad key");
  }
  for (const key of required) if (!Object.hasOwn(descriptors, key)) throw new Error("missing key");
}

export function safeInteger(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max)
    throw new Error("bad int");
  return value;
}

export function frozenFetch(value: unknown): OtlpFetch {
  if (typeof value !== "function" || !Object.isFrozen(value)) throw new Error("bad fetch");
  return value as OtlpFetch;
}

export function otlpEndpoint(value: unknown, kind: OtlpSignalKind, allowLoopbackHttp: boolean): string {
  if (typeof value !== "string") throw new Error("bad url");
  const path = kind === "logs" ? "/v1/logs" : kind === "traces" ? "/v1/traces" : "/v1/metrics";
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== path || url.port === "0")
    throw new Error("bad url");
  if (url.href !== value) throw new Error("noncanonical url");
  if (url.protocol === "https:") return url.href;
  if (url.protocol === "http:" && allowLoopbackHttp && (url.hostname === "127.0.0.1" || url.hostname === "[::1]"))
    return url.href;
  throw new Error("bad url");
}

export function jsonContentType(value: string | null): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

export async function postOtlpJson(input: OtlpPostConfig): Promise<void> {
  exactPlainObject(
    input,
    ["body", "kind", "maxRequestBytes", "maxResponseBytes", "timeoutMs", "url"],
    ["fetch", "parent"],
  );
  if (input.kind !== "logs" && input.kind !== "traces" && input.kind !== "metrics") throw new Error("bad kind");
  const timeoutMs = safeInteger(input.timeoutMs, 1, 10_000);
  const maxRequestBytes = safeInteger(input.maxRequestBytes, 1, 262_144);
  const maxResponseBytes = safeInteger(input.maxResponseBytes, 0, 65_536);
  const fetchFn = Object.hasOwn(input, "fetch") ? frozenFetch(input.fetch) : fetch;
  if (input.parent !== undefined && (!(input.parent instanceof AbortSignal) || input.parent.aborted))
    throw new Error("aborted");
  const body = JSON.stringify(input.body);
  if (Buffer.byteLength(body) > maxRequestBytes) throw new Error("too large");
  const controller = new AbortController();
  const abort = () => controller.abort();
  let removeParent: (() => void) | undefined;
  try {
    input.parent?.addEventListener("abort", abort, { once: true });
    removeParent = () => input.parent?.removeEventListener("abort", abort);
    const init = Object.freeze({
      method: "POST",
      redirect: "error" as const,
      headers: Object.freeze({
        "content-type": "application/json",
        accept: "application/json",
        "content-length": String(Buffer.byteLength(body)),
      }),
      body,
      signal: controller.signal,
    });
    await raceTimeout(
      postAttempt(input.url, input.kind, init, fetchFn, maxResponseBytes, timeoutMs, controller),
      timeoutMs,
      abort,
      input.parent,
    );
  } finally {
    removeParent?.();
    controller.abort();
  }
}

async function postAttempt(
  url: string,
  kind: OtlpSignalKind,
  init: RequestInit,
  fetchFn: OtlpFetch,
  maxResponseBytes: number,
  timeoutMs: number,
  controller: AbortController,
): Promise<void> {
  const fetched = fetchFn(url, init);
  if (!fetched || typeof (fetched as Promise<Response>).then !== "function") throw new Error("bad fetch");
  const response = await fetched;
  if (!response || typeof response !== "object") throw new Error("bad response");
  const status = response.status;
  if (!Number.isInteger(status)) throw new Error("bad response");
  const headers = response.headers;
  if (!headers || typeof headers.get !== "function") throw new Error("bad response");
  const length = headers.get("content-length");
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > maxResponseBytes)) {
    safeCancel(response);
    throw new Error("bad response");
  }
  if (status !== 200 || !jsonContentType(headers.get("content-type"))) {
    safeCancel(response);
    throw new Error("bad response");
  }
  validateOtlpResponse(
    kind,
    await raceTimeout(boundedText(response, maxResponseBytes, timeoutMs), Math.max(1, timeoutMs - 1), () => {
      controller.abort();
      safeCancel(response);
    }),
  );
}

export function validateOtlpResponse(kind: OtlpSignalKind, text: string): void {
  if (kind !== "logs" && kind !== "traces" && kind !== "metrics") throw new Error("bad kind");
  const value = text === "" ? {} : JSON.parse(text);
  exactPlainObject(value, [], ["partialSuccess"]);
  if (!Object.hasOwn(value, "partialSuccess")) return;
  const partial = value.partialSuccess;
  const countKey = kind === "logs" ? "rejectedLogRecords" : kind === "traces" ? "rejectedSpans" : "rejectedDataPoints";
  exactPlainObject(partial, [], ["errorMessage", countKey]);
  if (Object.hasOwn(partial, countKey) && partial[countKey] !== 0 && partial[countKey] !== "0")
    throw new Error("partial success");
  if (Object.hasOwn(partial, "errorMessage") && partial.errorMessage !== "") throw new Error("partial success");
}

async function boundedText(response: Response, max: number, timeoutMs: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  let total = 0;
  const chunks: Uint8Array[] = [];
  let done = false;
  let cancelled = false;
  try {
    for (;;) {
      const part = await raceTimeout(reader.read(), Math.max(1, timeoutMs - 1), () => {
        void safeReaderCancel(reader).catch(() => undefined);
      });
      if (part.done) {
        done = true;
        break;
      }
      total += part.value.byteLength;
      if (total > max) {
        await safeReaderCancel(reader);
        cancelled = true;
        throw new Error("too large");
      }
      chunks.push(part.value);
    }
  } finally {
    if (!done && !cancelled) await safeReaderCancel(reader);
    else releaseReader(reader);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}

export function safeCancel(response: Response): void {
  void Promise.resolve()
    .then(() => response.body?.cancel())
    .catch(() => undefined);
}

async function safeReaderCancel(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  await raceTimeout(
    Promise.resolve()
      .then(() => reader.cancel())
      .catch(() => undefined),
    50,
    () => undefined,
  ).catch(() => undefined);
  releaseReader(reader);
}

function releaseReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.releaseLock();
  } catch {
    // best effort
  }
}

export async function raceTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout: () => void,
  parent?: AbortSignal,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  let abort: (() => void) | undefined;
  promise.catch(() => undefined);
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          try {
            onTimeout();
          } catch {
            // best effort
          }
          reject(new Error("otlp timeout"));
        }, timeoutMs);
        abort = () => reject(new Error("otlp aborted"));
        parent?.addEventListener("abort", abort, { once: true });
        if (parent?.aborted) abort();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (abort !== undefined) parent?.removeEventListener("abort", abort);
  }
}
