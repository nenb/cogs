import type { OpenBaoIdentityPort } from "../auth/model-auth.ts";
import type { CogsEgressRevocationSnapshot, CogsEgressRevocationSource } from "./revocation-watcher.ts";

const jsonType = /^application\/json(?:\s*;|$)/i;
const name = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** Source-only adapter options; later composition must supply the watcher baseline credentialVersion consistently. */
export type OpenBaoEgressRevocationSourceOptions = Readonly<{
  origin: string;
  mount: string;
  identity: OpenBaoIdentityPort;
  userId: string;
  credentialHandle: string;
  presetRevision: string;
  pkiExpiresAtMs: number;
  allowLoopbackHttpDevelopment?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}>;

export class CogsEgressOpenBaoRevocationError extends Error {
  public readonly code = "COGS_EGRESS_OPENBAO_REVOCATION_FAILED";
  public constructor() {
    super("egress revocation metadata unavailable");
    this.name = "CogsEgressOpenBaoRevocationError";
  }
}

export class OpenBaoEgressRevocationSource implements CogsEgressRevocationSource {
  readonly #origin: string;
  readonly #mount: string;
  readonly #identity: OpenBaoIdentityPort;
  readonly #path: string;
  readonly #presetRevision: string;
  readonly #pkiExpiresAtMs: number;
  readonly #timeoutMs: number;
  readonly #maxBytes: number;
  readonly #fetch: typeof fetch;

  public constructor(options: OpenBaoEgressRevocationSourceOptions) {
    try {
      this.#origin = origin(options.origin, options.allowLoopbackHttpDevelopment === true);
      this.#mount = named(options.mount);
      this.#identity = options.identity;
      this.#path = credentialPath(options.credentialHandle, validOpaque(options.userId));
      this.#presetRevision = validOpaque(options.presetRevision);
      this.#pkiExpiresAtMs = integer(options.pkiExpiresAtMs, 1, Number.MAX_SAFE_INTEGER);
      this.#timeoutMs = integer(options.timeoutMs ?? 5000, 1, 60_000);
      this.#maxBytes = integer(options.maxResponseBytes ?? 16 * 1024, 512, 1024 * 1024);
      this.#fetch = options.fetchImpl ?? fetch;
    } catch {
      throw new CogsEgressOpenBaoRevocationError();
    }
  }

  public async read(signal: AbortSignal): Promise<CogsEgressRevocationSnapshot> {
    try {
      if (signal.aborted) throw new Error("aborted");
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
      const relay = () => controller.abort();
      signal.addEventListener("abort", relay, { once: true });
      try {
        if (signal.aborted) controller.abort();
        const result = await withTokenOnce(this.#identity, controller.signal, async (rawToken) => {
          const response = await this.#fetch(
            `${this.#origin}/v1/${encodeURIComponent(this.#mount)}/metadata/${this.#path}`,
            {
              method: "GET",
              headers: { "x-vault-token": secret(rawToken), accept: "application/json" },
              redirect: "error",
              signal: controller.signal,
            },
          );
          if (response.status === 404) {
            await cancelBody(response);
            return { version: "missing", revoked: true };
          }
          const data = parseMetadata(await bounded(response, this.#maxBytes, controller.signal), response);
          return { version: String(data.current), revoked: data.revoked };
        });
        return Object.freeze({
          presetRevision: this.#presetRevision,
          credentialVersion: result.version,
          revoked: result.revoked,
          pkiExpiresAtMs: this.#pkiExpiresAtMs,
        });
      } finally {
        controller.abort();
        clearTimeout(timeout);
        signal.removeEventListener("abort", relay);
      }
    } catch {
      throw new CogsEgressOpenBaoRevocationError();
    }
  }
}

function parseMetadata(text: string, response: Response): { current: number; revoked: boolean } {
  const length = response.headers.get("content-length");
  const type = response.headers.get("content-type") ?? "";
  if (response.status !== 200 || !jsonType.test(type) || (length !== null && !/^[0-9]+$/.test(length)))
    throw new Error("bad response");
  const root = JSON.parse(text) as unknown;
  onlyKnownPlain(root, [
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
  const envelope = root as Record<string, unknown>;
  if (envelope.request_id !== undefined && typeof envelope.request_id !== "string") throw new Error("bad envelope");
  if (envelope.lease_id !== undefined && typeof envelope.lease_id !== "string") throw new Error("bad envelope");
  if (envelope.renewable !== undefined && typeof envelope.renewable !== "boolean") throw new Error("bad envelope");
  if (envelope.lease_duration !== undefined && !safeNonnegative(envelope.lease_duration))
    throw new Error("bad envelope");
  if (envelope.mount_type !== undefined && envelope.mount_type !== "kv") throw new Error("bad envelope");
  if (envelope.auth !== undefined && envelope.auth !== null) throw new Error("bad envelope");
  if (envelope.wrap_info !== undefined && envelope.wrap_info !== null) throw new Error("bad envelope");
  if (envelope.warnings !== undefined && envelope.warnings !== null) {
    if (!Array.isArray(envelope.warnings) || !envelope.warnings.every((item) => typeof item === "string"))
      throw new Error("bad envelope");
  }
  onlyPlain(envelope.data, [
    "cas_required",
    "created_time",
    "current_metadata_version",
    "current_version",
    "custom_metadata",
    "delete_version_after",
    "max_versions",
    "metadata_cas_required",
    "oldest_version",
    "updated_time",
    "versions",
  ]);
  const data = envelope.data as Record<string, unknown>;
  const current = positive(data.current_version);
  if (data.current_metadata_version !== undefined && !safeNonnegative(data.current_metadata_version))
    throw new Error("bad metadata");
  if (data.custom_metadata !== null) throw new Error("bad metadata");
  if (!nonemptyString(data.created_time) || !nonemptyString(data.updated_time)) throw new Error("bad metadata");
  if (data.cas_required !== undefined && typeof data.cas_required !== "boolean") throw new Error("bad metadata");
  if (data.delete_version_after !== undefined && !duration(data.delete_version_after)) throw new Error("bad metadata");
  if (data.max_versions !== undefined && !safeNonnegative(data.max_versions)) throw new Error("bad metadata");
  if (data.metadata_cas_required !== undefined && typeof data.metadata_cas_required !== "boolean")
    throw new Error("bad metadata");
  if (data.oldest_version !== undefined && !safeNonnegative(data.oldest_version)) throw new Error("bad metadata");
  onlyVersions(data.versions);
  const versions = data.versions as Record<string, unknown>;
  const entry = versions[String(current)];
  const currentEntry = versionEntry(entry);
  return { current, revoked: currentEntry.destroyed || currentEntry.deletion_time !== "" };
}

async function bounded(response: Response, maximum: number, signal: AbortSignal): Promise<string> {
  const type = response.headers.get("content-type") ?? "";
  const length = response.headers.get("content-length");
  if (
    response.status !== 200 ||
    !jsonType.test(type) ||
    (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > maximum))
  ) {
    await cancelBody(response);
    throw new Error("bad response");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("missing body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  let failed = true;
  const abortRead = () => {
    reader.cancel().catch(() => undefined);
  };
  signal.addEventListener("abort", abortRead, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new Error("aborted");
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximum) throw new Error("too large");
      chunks.push(next.value);
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
    failed = false;
    return text;
  } finally {
    signal.removeEventListener("abort", abortRead);
    try {
      if (failed) await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}

async function cancelBody(response: Response): Promise<void> {
  if (response.body) await response.body.cancel();
}

async function withTokenOnce<T>(
  identity: OpenBaoIdentityPort,
  signal: AbortSignal,
  operation: (token: string) => Promise<T>,
): Promise<T> {
  let called = false;
  let active = true;
  let result: Promise<T> | undefined;
  try {
    await identity.withToken(signal, (token) => {
      if (!active || called) return Promise.reject(new Error("bad token callback"));
      called = true;
      result = operation(token);
      return result.then(() => undefined);
    });
  } finally {
    active = false;
  }
  if (!called || result === undefined) throw new Error("missing token callback");
  return result;
}

function versionEntry(value: unknown): { created_time: string; deletion_time: string; destroyed: boolean } {
  onlyPlain(value, ["created_time", "deletion_time", "destroyed"]);
  const entry = value as Record<string, unknown>;
  if (!nonemptyString(entry.created_time) || typeof entry.deletion_time !== "string") throw new Error("bad version");
  if (entry.deletion_time !== "" && !strictPrintable(entry.deletion_time)) throw new Error("bad version");
  if (typeof entry.destroyed !== "boolean") throw new Error("bad version");
  return entry as { created_time: string; deletion_time: string; destroyed: boolean };
}

function onlyVersions(value: unknown): void {
  onlyPlain(value, undefined);
  const keys = Object.keys(value as Record<string, unknown>);
  if (keys.length < 1 || keys.length > 1024) throw new Error("bad versions");
  const seen = new Set<number>();
  const versions = value as Record<string, unknown>;
  for (const key of keys) {
    if (!/^[1-9][0-9]{0,15}$/.test(key)) throw new Error("bad versions");
    const version = Number(key);
    if (!Number.isSafeInteger(version) || seen.has(version)) throw new Error("bad versions");
    versionEntry(versions[key]);
    seen.add(version);
  }
}

function onlyKnownPlain(value: unknown, keys: readonly string[]): void {
  onlyPlain(value);
  if (Object.keys(value as Record<string, unknown>).some((key) => !keys.includes(key))) throw new Error("bad object");
}

function onlyPlain(value: unknown, keys?: readonly string[]): void {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("bad object");
  if (Object.getOwnPropertySymbols(value).length > 0) throw new Error("bad object");
  const actual = Object.keys(value as Record<string, unknown>);
  if (Object.getOwnPropertyNames(value).length !== actual.length) throw new Error("bad object");
  if (keys && (actual.length !== keys.length || actual.some((key) => !keys.includes(key))))
    throw new Error("bad object");
}

function origin(input: string, allowLoopbackHttp: boolean): string {
  const url = new URL(input);
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("bad origin");
  if (url.protocol === "https:" || (url.protocol === "http:" && allowLoopbackHttp && loopback(url.hostname)))
    return url.origin;
  throw new Error("bad origin");
}
function loopback(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}
function credentialPath(handle: string, userId: string): string {
  if (
    handle.length < 1 ||
    handle.length > 512 ||
    handle.normalize("NFC") !== handle ||
    handle.includes("%") ||
    handle.includes("\\") ||
    hasControl(handle) ||
    handle.includes("//")
  )
    throw new Error("bad handle");
  const parts = handle.split("/").map(validOpaque);
  if (
    parts.length < 3 ||
    parts.length > 8 ||
    parts[0] === "sessions" ||
    parts.some((part) => part === "." || part === "..")
  )
    throw new Error("bad handle");
  if (parts[0] === "users" ? parts[1] !== userId : parts[0] !== "organizations") throw new Error("bad handle");
  return parts.map(encodeURIComponent).join("/");
}
function named(value: string): string {
  if (!name.test(value)) throw new Error("bad name");
  return value;
}
function validOpaque(value: string): string {
  if (!opaque.test(value)) throw new Error("bad opaque");
  return value;
}
function secret(value: string): string {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < 8 || bytes > 8192 || !strictPrintable(value)) throw new Error("bad secret");
  return value;
}
function duration(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && strictPrintable(value);
}
function nonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && strictPrintable(value);
}
function strictPrintable(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}
function hasControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}
function integer(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error("bad integer");
  return value;
}
function positive(value: unknown): number {
  if (typeof value !== "number") throw new Error("bad version");
  return integer(value, 1, Number.MAX_SAFE_INTEGER);
}
function safeNonnegative(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
