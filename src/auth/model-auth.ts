export interface ModelAuthRequest {
  readonly userId: string;
  readonly provider: string;
  readonly model: string;
  readonly credentialHandle: string;
  readonly signal?: AbortSignal;
}

export interface ModelApiKeySource {
  readonly withApiKey: (request: ModelAuthRequest, operation: (apiKey: string) => Promise<void>) => Promise<void>;
}

export interface OpenBaoIdentityPort {
  readonly withToken: (signal: AbortSignal, operation: (token: string) => Promise<void>) => Promise<void>;
}

export interface OAuthAccessMaterial {
  readonly reference: string;
  readonly provider: string;
  readonly model: string;
  readonly accessToken: string;
  readonly expiresAt: string;
}

export interface OAuthBrokerClient {
  readonly getAccessMaterial: (input: {
    userId: string;
    provider: string;
    model: string;
    signal?: AbortSignal;
  }) => Promise<OAuthAccessMaterial>;
  readonly invalidateAccessMaterial: (reference: string, input?: { signal?: AbortSignal }) => Promise<void>;
  readonly getExpiry: (reference: string, input?: { signal?: AbortSignal }) => Promise<string>;
}

export class ModelAuthError extends Error {
  public readonly code = "COGS_MODEL_AUTH_FAILED";
  public constructor() {
    super("model authentication failed");
    this.name = "ModelAuthError";
  }
}

export class DisabledOAuthBrokerClient implements OAuthBrokerClient {
  public async getAccessMaterial(_input: {
    userId: string;
    provider: string;
    model: string;
    signal?: AbortSignal;
  }): Promise<OAuthAccessMaterial> {
    throw new ModelAuthError();
  }
  public async invalidateAccessMaterial(_reference: string, _input?: { signal?: AbortSignal }): Promise<void> {
    throw new ModelAuthError();
  }
  public async getExpiry(_reference: string, _input?: { signal?: AbortSignal }): Promise<string> {
    throw new ModelAuthError();
  }
}

export class ModelCredentialResolver {
  public constructor(private readonly source: ModelApiKeySource) {}
  public async withApiKey<T>(request: ModelAuthRequest, operation: (apiKey: string) => Promise<T>): Promise<T> {
    return generic(async () => {
      let active = true;
      let called = false;
      let callbackPromise: Promise<void> | undefined;
      let captured = "";
      try {
        await this.source.withApiKey(request, (sourceKey) => {
          if (!active || called) return Promise.reject(new Error("invalid source callback"));
          called = true;
          callbackPromise = (async () => {
            captured = validateModelApiKey(sourceKey);
          })();
          return callbackPromise;
        });
        if (!called || callbackPromise === undefined) throw new Error("missing source callback");
        await callbackPromise;
      } finally {
        active = false;
      }
      try {
        return await operation(captured);
      } finally {
        captured = "";
      }
    });
  }
}

export interface OpenBaoModelApiKeyStoreOptions {
  readonly origin: string;
  readonly mount: string;
  readonly identity: OpenBaoIdentityPort;
  readonly allowLoopbackHttpDevelopment?: boolean;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly fetchImpl?: typeof fetch;
}

export class OpenBaoModelApiKeyStore implements ModelApiKeySource {
  readonly #origin: string;
  readonly #mount: string;
  readonly #identity: OpenBaoIdentityPort;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;

  public constructor(options: OpenBaoModelApiKeyStoreOptions) {
    this.#origin = validateOpenBaoOrigin(options.origin, options.allowLoopbackHttpDevelopment === true);
    this.#mount = validateMount(options.mount);
    this.#identity = options.identity;
    this.#timeoutMs = validateInteger(options.timeoutMs ?? 5_000, 1, 60_000);
    this.#maxResponseBytes = validateInteger(options.maxResponseBytes ?? 16 * 1024, 512, 1024 * 1024);
    this.#fetch = options.fetchImpl ?? fetch;
  }

  public async withApiKey(request: ModelAuthRequest, operation: (apiKey: string) => Promise<void>): Promise<void> {
    return generic(async () => {
      const provider = validateOpaqueId(request.provider, "provider");
      const model = validateModelId(request.model);
      void provider;
      void model;
      const path = credentialPath(request.credentialHandle, request.userId);
      const controller = new AbortController();
      if (request.signal?.aborted) throw new Error("aborted");
      const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
      const onAbort = () => controller.abort();
      request.signal?.addEventListener("abort", onAbort, { once: true });
      let apiKey = "";
      try {
        apiKey = await withTokenOnce(this.#identity, controller.signal, async (rawToken) => {
          if (controller.signal.aborted) throw new Error("aborted");
          let token = "";
          try {
            token = validateModelApiKey(rawToken);
            const response = await this.#fetch(`${this.#origin}/v1/${encodeURIComponent(this.#mount)}/data/${path}`, {
              method: "GET",
              headers: { "x-vault-token": token, accept: "application/json" },
              redirect: "error",
              signal: controller.signal,
            });
            const type = response.headers.get("content-type") ?? "";
            const length = response.headers.get("content-length");
            if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > this.#maxResponseBytes)) {
              cancelBody(response);
              throw new Error("too large");
            }
            if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(type)) {
              cancelBody(response);
              throw new Error("bad response");
            }
            return parseKv2ApiKey(await boundedText(response, this.#maxResponseBytes, controller.signal));
          } finally {
            token = "";
          }
        });
      } finally {
        clearTimeout(timeout);
        request.signal?.removeEventListener("abort", onAbort);
      }
      try {
        if (request.signal?.aborted) throw new Error("aborted");
        await operation(apiKey);
      } finally {
        apiKey = "";
      }
    });
  }
}

export interface DevelopmentModelApiKeySourceOptions {
  readonly developmentMode: boolean;
  readonly envName: string;
  readonly userId: string;
  readonly provider: string;
  readonly model: string;
  readonly credentialHandle: string;
  readonly env?: Record<string, string | undefined>;
}

export class DevelopmentModelApiKeySource implements ModelApiKeySource {
  readonly #envName: string;
  readonly #env: Record<string, string | undefined>;
  readonly #userId: string;
  readonly #provider: string;
  readonly #model: string;
  readonly #credentialHandle: string;
  public constructor(options: DevelopmentModelApiKeySourceOptions) {
    try {
      const env = options.env ?? process.env;
      if (!options.developmentMode || (process.env.CI ?? "") !== "" || (env.CI ?? "") !== "")
        throw new ModelAuthError();
      this.#envName = validateEnvName(options.envName);
      this.#env = env;
    } catch {
      throw new ModelAuthError();
    }
    this.#userId = validateOpaqueId(options.userId, "user");
    this.#provider = validateOpaqueId(options.provider, "provider");
    this.#model = validateModelId(options.model);
    this.#credentialHandle = options.credentialHandle;
    credentialPath(options.credentialHandle, options.userId);
  }
  public async withApiKey(request: ModelAuthRequest, operation: (apiKey: string) => Promise<void>): Promise<void> {
    return generic(async () => {
      if (
        validateOpaqueId(request.userId, "user") !== this.#userId ||
        validateOpaqueId(request.provider, "provider") !== this.#provider ||
        validateModelId(request.model) !== this.#model ||
        request.credentialHandle !== this.#credentialHandle
      )
        throw new Error("wrong request");
      if (request.signal?.aborted) throw new Error("aborted");
      let apiKey = "";
      try {
        const value = this.#env[this.#envName];
        if (value === undefined) throw new Error("missing");
        apiKey = validateModelApiKey(value);
        await operation(apiKey);
      } finally {
        apiKey = "";
      }
    });
  }
}

function validateOpenBaoOrigin(input: string, allowLoopbackHttp: boolean): string {
  try {
    const url = new URL(input);
    if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || url.pathname !== "/")
      throw new Error("bad");
    if (url.protocol === "https:") return url.origin;
    if (url.protocol === "http:" && allowLoopbackHttp && isLoopback(url.hostname)) return url.origin;
  } catch {
    throw new ModelAuthError();
  }
  throw new ModelAuthError();
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

function credentialPath(handle: string, userId: string): string {
  if (
    handle.length < 1 ||
    handle.length > 512 ||
    handle.normalize("NFC") !== handle ||
    handle.includes("%") ||
    handle.includes("\\") ||
    handle.includes("//") ||
    hasControl(handle)
  )
    throw new ModelAuthError();
  const user = validateOpaqueId(userId, "user");
  const parts = handle.split("/");
  if (parts.length < 3 || parts.length > 8) throw new ModelAuthError();
  const validated = parts.map((part) => validateOpaqueId(part, "handle"));
  if (validated.some((part) => part === "." || part === "..")) throw new ModelAuthError();
  if (validated[0] === "sessions") throw new ModelAuthError();
  if (validated[0] === "users") {
    if (validated[1] !== user) throw new ModelAuthError();
  } else if (validated[0] !== "organizations") throw new ModelAuthError();
  return validated.map((part) => encodeURIComponent(part)).join("/");
}

function validateMount(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value)) throw new ModelAuthError();
  return value;
}

function validateOpaqueId(value: string, _label: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) throw new ModelAuthError();
  return value;
}

function validateModelId(value: string): string {
  if (
    value.length < 1 ||
    value.length > 256 ||
    hasControl(value) ||
    value.normalize("NFC") !== value ||
    !/^[A-Za-z0-9]/.test(value)
  )
    throw new ModelAuthError();
  return value;
}

function validateEnvName(value: string): string {
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(value)) throw new ModelAuthError();
  return value;
}

export function validateModelApiKey(value: string): string {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < 8 || bytes > 8192 || hasControl(value)) throw new ModelAuthError();
  return value;
}

function hasControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function validateInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new ModelAuthError();
  return value;
}

function cancelBody(response: Response): void {
  response.body?.cancel().catch(() => undefined);
}

async function boundedText(response: Response, maximum: number, signal: AbortSignal): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("missing body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error("aborted");
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximum) throw new Error("too large");
      chunks.push(next.value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch (error) {
    reader.cancel().catch(() => undefined);
    throw error;
  }
}

async function withTokenOnce<T>(
  identity: OpenBaoIdentityPort,
  signal: AbortSignal,
  operation: (token: string) => Promise<T>,
): Promise<T> {
  let active = true;
  let called = false;
  let callbackPromise: Promise<void> | undefined;
  let result: { value: T } | undefined;
  try {
    await identity.withToken(signal, (token) => {
      if (!active || called) return Promise.reject(new Error("invalid identity callback"));
      called = true;
      callbackPromise = (async () => {
        result = { value: await operation(token) };
      })();
      return callbackPromise;
    });
    if (!called || callbackPromise === undefined) throw new Error("missing identity callback");
    await callbackPromise;
    if (result === undefined) throw new Error("missing identity result");
    return result.value;
  } finally {
    active = false;
  }
}

function parseKv2ApiKey(text: string): string {
  const parsed = JSON.parse(text) as unknown;
  const allowedRoot = [
    "request_id",
    "lease_id",
    "renewable",
    "lease_duration",
    "data",
    "wrap_info",
    "warnings",
    "auth",
    "mount_type",
  ];
  if (!isPlainObject(parsed) || !hasOnlyKeys(parsed, allowedRoot, true)) throw new Error("bad json");
  validateOpenBaoEnvelope(parsed);
  const root = parsed as { data?: unknown };
  if (!isPlainObject(root.data) || !hasOnlyKeys(root.data, ["data", "metadata"])) throw new Error("bad data");
  const data = root.data as { data: unknown; metadata: unknown };
  validateKv2Metadata(data.metadata);
  if (!isPlainObject(data.data) || !hasOnlyKeys(data.data, ["api_key"])) throw new Error("bad secret data");
  const secret = data.data as { api_key: unknown };
  if (typeof secret.api_key !== "string") throw new Error("missing api key");
  return validateModelApiKey(secret.api_key);
}

function validateOpenBaoEnvelope(value: Record<string, unknown>): void {
  if (value.request_id !== undefined && typeof value.request_id !== "string") throw new Error("bad request_id");
  if (value.lease_id !== undefined && typeof value.lease_id !== "string") throw new Error("bad lease_id");
  if (value.renewable !== undefined && typeof value.renewable !== "boolean") throw new Error("bad renewable");
  if (value.lease_duration !== undefined) {
    const leaseDuration = value.lease_duration;
    if (typeof leaseDuration !== "number" || !Number.isSafeInteger(leaseDuration) || leaseDuration < 0)
      throw new Error("bad lease_duration");
  }
  if (value.mount_type !== undefined && value.mount_type !== "kv") throw new Error("bad mount_type");
  if (value.auth !== undefined && value.auth !== null) throw new Error("bad auth");
  if (value.wrap_info !== undefined && value.wrap_info !== null) throw new Error("bad wrap_info");
  if (
    value.warnings !== undefined &&
    value.warnings !== null &&
    (!Array.isArray(value.warnings) || !value.warnings.every((item) => typeof item === "string"))
  )
    throw new Error("bad warnings");
}

function validateKv2Metadata(value: unknown): void {
  if (
    !isPlainObject(value) ||
    !hasOnlyKeys(value, ["created_time", "deletion_time", "destroyed", "version", "custom_metadata"])
  )
    throw new Error("bad metadata");
  const metadata = value as {
    created_time: unknown;
    deletion_time: unknown;
    destroyed: unknown;
    version: unknown;
    custom_metadata: unknown;
  };
  if (typeof metadata.created_time !== "string" || typeof metadata.deletion_time !== "string")
    throw new Error("bad metadata time");
  const version = metadata.version;
  if (
    typeof metadata.destroyed !== "boolean" ||
    typeof version !== "number" ||
    !Number.isSafeInteger(version) ||
    version < 1
  )
    throw new Error("bad metadata state");
  if (metadata.custom_metadata !== null) throw new Error("bad custom metadata");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function hasOnlyKeys(value: Record<string, unknown>, keys: string[], allowSubset = false): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.every((key) => expected.includes(key)) && (allowSubset || actual.length === expected.length);
}

async function generic<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch {
    throw new ModelAuthError();
  }
}
