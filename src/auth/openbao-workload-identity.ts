import { types } from "node:util";
import { type TrustedFileCaptureOptions, withTrustedFileBytes } from "../runtime/trusted-files.ts";
import type { OpenBaoIdentityPort } from "./model-auth.ts";

const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset\s*=\s*utf-8\s*)?$/iu;
const MOUNT = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;
const ROLE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const JWT = /^[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,8192}$/u;
const ROOT_KEYS = new Set([
  "request_id",
  "lease_id",
  "renewable",
  "lease_duration",
  "data",
  "wrap_info",
  "warnings",
  "auth",
  "mount_type",
]);
const AUTH_KEYS = new Set([
  "client_token",
  "accessor",
  "policies",
  "token_policies",
  "identity_policies",
  "metadata",
  "lease_duration",
  "renewable",
  "entity_id",
  "token_type",
  "orphan",
  "mfa_requirement",
  "num_uses",
]);

export type OpenBaoKubernetesWorkloadIdentityOptions = Readonly<{
  origin: string;
  authMount: string;
  role: string;
  jwtFile: TrustedFileCaptureOptions;
  maxTokenTtlSeconds?: number;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}>;

export class OpenBaoWorkloadIdentityError extends Error {
  public readonly code = "COGS_OPENBAO_WORKLOAD_IDENTITY_FAILED";
  public constructor() {
    super("OpenBao workload identity unavailable");
    this.name = "OpenBaoWorkloadIdentityError";
    this.stack = `${this.name}: ${this.message}`;
  }
}

type CapturedOptions = Readonly<{
  loginUrl: string;
  role: string;
  jwtFile: TrustedFileCaptureOptions;
  maxTokenTtlSeconds: number;
  timeoutMs: number;
  maxResponseBytes: number;
  fetchImpl: typeof fetch;
}>;

export class OpenBaoKubernetesWorkloadIdentity implements OpenBaoIdentityPort {
  readonly #options: CapturedOptions;

  public constructor(options: OpenBaoKubernetesWorkloadIdentityOptions) {
    try {
      this.#options = captureOptions(options);
    } catch {
      throw new OpenBaoWorkloadIdentityError();
    }
  }

  public async withToken(signal: AbortSignal, operation: (token: string) => Promise<void>): Promise<void> {
    try {
      if (!(signal instanceof AbortSignal) || signal.aborted || typeof operation !== "function")
        throw new Error("invalid request");
      let token = "";
      try {
        token = await withTrustedFileBytes(this.#options.jwtFile, async (bytes) => {
          const jwt = decodeJwt(bytes);
          return await this.login(jwt, signal);
        });
        if (signal.aborted) throw new Error("aborted");
        await operation(token);
        if (signal.aborted) throw new Error("aborted");
      } finally {
        token = "";
      }
    } catch {
      throw new OpenBaoWorkloadIdentityError();
    }
  }

  private async login(jwtValue: string, parent: AbortSignal): Promise<string> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timer = setTimeout(abort, this.#options.timeoutMs);
    let jwt = jwtValue;
    let body = "";
    try {
      parent.addEventListener("abort", abort, { once: true });
      if (parent.aborted) controller.abort();
      body = JSON.stringify({ role: this.#options.role, jwt });
      const response = await withAbort(
        Promise.resolve().then(() =>
          this.#options.fetchImpl(this.#options.loginUrl, {
            method: "POST",
            headers: {
              accept: "application/json",
              "content-type": "application/json",
              "content-length": String(Buffer.byteLength(body)),
            },
            body,
            redirect: "error",
            signal: controller.signal,
          }),
        ),
        controller.signal,
      );
      if (controller.signal.aborted) throw new Error("aborted");
      const text = await boundedResponse(response, this.#options.maxResponseBytes, controller.signal);
      if (controller.signal.aborted) throw new Error("aborted");
      return parseLogin(text, this.#options.maxTokenTtlSeconds);
    } finally {
      jwt = "";
      body = "";
      clearTimeout(timer);
      parent.removeEventListener("abort", abort);
      controller.abort();
    }
  }
}

function captureOptions(options: OpenBaoKubernetesWorkloadIdentityOptions): CapturedOptions {
  exactOptions(options);
  const origin = httpsOrigin(options.origin);
  const authMount = named(options.authMount, MOUNT);
  const role = named(options.role, ROLE);
  const maxTokenTtlSeconds = integer(options.maxTokenTtlSeconds ?? 600, 1, 3600);
  const timeoutMs = integer(options.timeoutMs ?? 5000, 1, 60_000);
  const maxResponseBytes = integer(options.maxResponseBytes ?? 16 * 1024, 512, 1024 * 1024);
  if (
    typeof options.fetchImpl !== "undefined" &&
    (typeof options.fetchImpl !== "function" || types.isProxy(options.fetchImpl))
  )
    throw new Error("invalid fetch");
  return Object.freeze({
    loginUrl: `${origin}/v1/auth/${encodeURIComponent(authMount)}/login`,
    role,
    jwtFile: captureJwtFile(options.jwtFile),
    maxTokenTtlSeconds,
    timeoutMs,
    maxResponseBytes,
    fetchImpl: options.fetchImpl ?? fetch,
  });
}

function exactOptions(options: OpenBaoKubernetesWorkloadIdentityOptions): void {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options) ||
    types.isProxy(options) ||
    Object.getPrototypeOf(options) !== Object.prototype
  )
    throw new Error("invalid options");
  const required = new Set(["origin", "authMount", "role", "jwtFile"]);
  const optional = new Set(["maxTokenTtlSeconds", "timeoutMs", "maxResponseBytes", "fetchImpl"]);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string" || (!required.has(key) && !optional.has(key))) throw new Error("invalid options");
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("invalid options");
  }
  for (const key of required) if (!Object.hasOwn(descriptors, key)) throw new Error("invalid options");
}

function captureJwtFile(value: TrustedFileCaptureOptions): TrustedFileCaptureOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("invalid JWT file");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = ["allowedGids", "allowedModes", "allowedUids", "maximumBytes", "minimumBytes", "path"];
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string") ||
    Object.keys(descriptors).sort().join() !== keys.join()
  )
    throw new Error("invalid JWT file");
  const read = (key: string): unknown => {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("invalid JWT file");
    return descriptor.value;
  };
  return Object.freeze({
    path: read("path") as string,
    minimumBytes: read("minimumBytes") as number,
    maximumBytes: read("maximumBytes") as number,
    allowedModes: copyNumberArray(read("allowedModes")),
    allowedUids: copyNumberArray(read("allowedUids")),
    allowedGids: copyNumberArray(read("allowedGids")),
  });
}

function copyNumberArray(value: unknown): readonly number[] {
  if (
    types.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < 1 ||
    value.length > 8
  )
    throw new Error("invalid array");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== value.length + 1) throw new Error("invalid array");
  const result: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor?.enumerable || !("value" in descriptor) || typeof descriptor.value !== "number")
      throw new Error("invalid array");
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

function decodeJwt(bytes: Buffer): string {
  const jwt = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (jwt.length < 26 || jwt.length > 16 * 1024 || !JWT.test(jwt)) throw new Error("invalid JWT");
  return jwt;
}

async function boundedResponse(response: Response, maximum: number, signal: AbortSignal): Promise<string> {
  if (!(response instanceof Response)) throw new Error("invalid response");
  const type = response.headers.get("content-type") ?? "";
  const length = response.headers.get("content-length");
  if (
    response.status !== 200 ||
    response.redirected ||
    !JSON_CONTENT_TYPE.test(type) ||
    (length !== null && (!/^[0-9]+$/u.test(length) || Number(length) > maximum))
  ) {
    cancelBody(response.body);
    throw new Error("invalid response");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("missing response");
  const chunks: Uint8Array[] = [];
  let total = 0;
  const cancel = () => cancelReader(reader);
  signal.addEventListener("abort", cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new Error("aborted");
      const next = await withAbort(reader.read(), signal);
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximum) throw new Error("response too large");
      chunks.push(next.value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
  } catch (error) {
    cancelReader(reader);
    throw error;
  } finally {
    signal.removeEventListener("abort", cancel);
    try {
      reader.releaseLock();
    } catch {
      // The caller still receives the generic fail-closed identity error.
    }
  }
}

function withAbort<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = () => {
      settled = true;
      signal.removeEventListener("abort", abort);
    };
    const abort = () => {
      if (settled) return;
      finish();
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    void pending.then(
      (value) => {
        if (settled) {
          if (value instanceof Response) cancelBody(value.body);
          return;
        }
        finish();
        resolve(value);
      },
      () => {
        if (settled) return;
        finish();
        reject(new Error("operation failed"));
      },
    );
  });
}

function cancelBody(body: ReadableStream<Uint8Array> | null): void {
  try {
    void body?.cancel().catch(() => undefined);
  } catch {
    // Cancellation is best effort after the request has already failed closed.
  }
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    void reader.cancel().catch(() => undefined);
  } catch {
    // Cancellation is best effort after the request has already failed closed.
  }
}

function parseLogin(text: string, maxTokenTtlSeconds: number): string {
  rejectDuplicateKeys(text);
  const root = plainJson(JSON.parse(text));
  onlyKnown(root, ROOT_KEYS);
  optionalString(root.request_id, 256);
  optionalString(root.lease_id, 1024);
  optionalBoolean(root.renewable);
  optionalNonnegative(root.lease_duration);
  if (root.data !== undefined && root.data !== null) throw new Error("invalid data");
  if (root.wrap_info !== undefined && root.wrap_info !== null) throw new Error("invalid wrap");
  optionalWarnings(root.warnings);
  if (root.mount_type !== undefined && root.mount_type !== "kubernetes") throw new Error("invalid mount");
  const auth = plainJson(root.auth);
  onlyKnown(auth, AUTH_KEYS);
  const token = visibleSecret(auth.client_token);
  positiveInteger(auth.lease_duration, maxTokenTtlSeconds);
  if (typeof auth.renewable !== "boolean") throw new Error("invalid renewable");
  if (auth.token_type !== "service" && auth.token_type !== "batch") throw new Error("invalid token type");
  optionalString(auth.accessor, 8192);
  optionalString(auth.entity_id, 256);
  optionalBoolean(auth.orphan);
  optionalNonnegative(auth.num_uses);
  optionalStringArray(auth.policies);
  optionalStringArray(auth.token_policies);
  optionalStringArray(auth.identity_policies);
  optionalMetadata(auth.metadata);
  if (auth.mfa_requirement !== undefined && auth.mfa_requirement !== null) throw new Error("invalid MFA");
  return token;
}

function rejectDuplicateKeys(text: string): void {
  const scopes: Array<{ object: boolean; keys: Set<string>; expectsKey: boolean }> = [];
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === "{") scopes.push({ object: true, keys: new Set(), expectsKey: true });
    else if (character === "[") scopes.push({ object: false, keys: new Set(), expectsKey: false });
    else if (character === "}" || character === "]") scopes.pop();
    else if (character === ",") {
      const scope = scopes.at(-1);
      if (scope?.object) scope.expectsKey = true;
    } else if (character === '"') {
      let end = index + 1;
      let escaped = false;
      for (; end < text.length; end += 1) {
        if (escaped) escaped = false;
        else if (text[end] === "\\") escaped = true;
        else if (text[end] === '"') break;
      }
      if (end >= text.length) throw new Error("invalid JSON string");
      const scope = scopes.at(-1);
      if (scope?.object && scope.expectsKey) {
        let colon = end + 1;
        while (colon < text.length && /[\t\n\r ]/u.test(text[colon] ?? "")) colon += 1;
        if (text[colon] !== ":") throw new Error("invalid object key");
        const key = JSON.parse(text.slice(index, end + 1)) as unknown;
        if (typeof key !== "string" || scope.keys.has(key)) throw new Error("duplicate object key");
        scope.keys.add(key);
        scope.expectsKey = false;
      }
      index = end;
    }
  }
}

function plainJson(value: unknown): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("invalid object");
  if (
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.getOwnPropertyNames(value).length !== Object.keys(value).length
  )
    throw new Error("invalid object");
  return value as Record<string, unknown>;
}

function onlyKnown(value: Record<string, unknown>, known: ReadonlySet<string>): void {
  if (Object.keys(value).some((key) => !known.has(key))) throw new Error("unknown field");
}

function optionalMetadata(value: unknown): void {
  if (value === undefined || value === null) return;
  const metadata = plainJson(value);
  const keys = Object.keys(metadata);
  if (keys.length > 32) throw new Error("invalid metadata");
  for (const key of keys) {
    named(key, ROLE);
    if (typeof metadata[key] !== "string" || Buffer.byteLength(metadata[key], "utf8") > 1024)
      throw new Error("invalid metadata");
  }
}

function optionalStringArray(value: unknown): void {
  if (value === undefined || value === null) return;
  if (
    !Array.isArray(value) ||
    value.length > 64 ||
    !value.every((item) => typeof item === "string" && item.length <= 256)
  )
    throw new Error("invalid array");
}

function optionalWarnings(value: unknown): void {
  if (value === undefined || value === null) return;
  if (
    !Array.isArray(value) ||
    value.length > 16 ||
    !value.every((item) => typeof item === "string" && item.length <= 1024)
  )
    throw new Error("invalid warnings");
}

function optionalString(value: unknown, maximum: number): void {
  if (value !== undefined && (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maximum))
    throw new Error("invalid string");
}

function optionalBoolean(value: unknown): void {
  if (value !== undefined && typeof value !== "boolean") throw new Error("invalid boolean");
}

function optionalNonnegative(value: unknown): void {
  if (value !== undefined && (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0))
    throw new Error("invalid integer");
}

function visibleSecret(value: unknown): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 8 || Buffer.byteLength(value, "utf8") > 8192)
    throw new Error("invalid token");
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x21 || code > 0x7e) throw new Error("invalid token");
  }
  return value;
}

function httpsOrigin(value: string): string {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.port === "0" ||
    url.href !== value
  )
    throw new Error("invalid origin");
  return url.origin;
}

function named(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error("invalid name");
  return value;
}

function positiveInteger(value: unknown, maximum: number): number {
  return integer(value, 1, maximum);
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error("invalid integer");
  return value;
}
