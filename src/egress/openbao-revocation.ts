import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  ModelCredentialResolver,
  type OpenBaoIdentityPort,
  OpenBaoModelApiKeyStore,
  parseOpenBaoJson,
  validateOpenBaoTimestamp,
} from "../auth/model-auth.ts";
import { ModelBackedEgressCredentialSource } from "./egress-material.ts";
import type { CogsEnvoyCredentialSource } from "./envoy-runtime-config.ts";
import type { CogsEgressRevocationSnapshot, CogsEgressRevocationSource } from "./revocation-watcher.ts";
import type { CogsEgressRoutePlan } from "./route-policy.ts";

const jsonType = /^application\/json(?:\s*;|$)/i;
const name = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

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

export type OpenBaoEgressRevocationBindingOptions = Omit<
  OpenBaoEgressRevocationSourceOptions,
  "userId" | "credentialHandle" | "presetRevision" | "pkiExpiresAtMs"
>;

export function normalizeOpenBaoEgressRevocationAuthorityOptions(
  input: OpenBaoEgressRevocationBindingOptions,
): OpenBaoEgressRevocationBindingOptions {
  try {
    exactPlain(
      input,
      ["identity", "mount", "origin"],
      ["allowLoopbackHttpDevelopment", "fetchImpl", "maxResponseBytes", "timeoutMs"],
    );
    const normalized = Object.freeze({
      origin: origin(input.origin, input.allowLoopbackHttpDevelopment === true),
      mount: named(input.mount),
      identity: identity(input.identity),
      ...(input.allowLoopbackHttpDevelopment === undefined
        ? {}
        : { allowLoopbackHttpDevelopment: boolean(input.allowLoopbackHttpDevelopment) }),
      ...(input.timeoutMs === undefined ? {} : { timeoutMs: integer(input.timeoutMs, 1, 60_000) }),
      ...(input.maxResponseBytes === undefined
        ? {}
        : { maxResponseBytes: integer(input.maxResponseBytes, 512, 1024 * 1024) }),
      ...(input.fetchImpl === undefined ? {} : { fetchImpl: fetchFunction(input.fetchImpl) }),
    });
    return normalized;
  } catch {
    throw new CogsEgressOpenBaoRevocationError();
  }
}

export type OpenBaoEgressRevocationBindingRequest = Readonly<
  OpenBaoEgressRevocationBindingOptions & {
    routePlan: CogsEgressRoutePlan;
    userId: string;
    presetRevision: string;
    pkiExpiresAtMs: number;
    signal?: AbortSignal;
  }
>;

/** Trusted in-memory only: never put raw tuples/handles in logs, status or durable storage.
 * Authority is the canonical configured endpoint, under a stable backend binding (ADR 0308).
 * No namespace, replica fallback or backend substitution is supported.
 */
export type OpenBaoHydratedIdentity = readonly [
  schema: "openbao-kv2-generation-v1",
  authority: string,
  mount: string,
  handle: string,
  currentVersion: number,
  keyCreatedTime: string,
  versionCreatedTime: string,
];
export type OpenBaoHydratedManifest = Readonly<{
  schema: "openbao-hydrated-manifest-v1";
  identities: readonly OpenBaoHydratedIdentity[];
  baseline: CogsEgressRevocationSnapshot;
}>;
export type OpenBaoEgressRevocationBinding = Readonly<{
  source: CogsEgressRevocationSource;
  credentialSource: CogsEnvoyCredentialSource;
  credentialVersion: string;
}>;
export type OpenBaoHydratedMaterial = Readonly<{ manifest: OpenBaoHydratedManifest; release: () => void }>;
const hydratedMaterials = new WeakMap<OpenBaoEgressRevocationBinding, OpenBaoHydratedMaterial>();

/** Requires the original binding object, not a reconstructed or legacy numeric baseline. */
export function getOpenBaoHydratedMaterial(binding: OpenBaoEgressRevocationBinding): OpenBaoHydratedMaterial {
  const material = hydratedMaterials.get(binding);
  if (!material) throw new CogsEgressOpenBaoRevocationError();
  return material;
}

/** Lifecycle seam: hydrate before rendering; start watcher with manifest.baseline and validate
 * the whole source against it immediately before admission. Never establish another baseline.
 * On invalidation close the terminal admission gate synchronously, including after WAL awaits.
 * Retain this binding and secret material until all users/late starters actually retire, then
 * call release(). Timeout is not retirement. Abort prevents further credential callbacks.
 *
 * Conditional detection <= P + 2R + J: P is post-poll wait, R one entire aggregate read,
 * J total scheduler/gate allowance. Retirement adds independently enforced/proven D;
 * replacement-ready requires an external provisioner bound. This module proves neither J nor D.
 * Requires non-repeating full creation identities, trusted clock/storage and consistent reads
 * from the same authoritative endpoint. Identical restore, rollback, backend substitution,
 * malicious metadata, and delete/undelete wholly between samples are excluded. No immediate
 * revocation, issuer revocation, erasure/zeroization, or transactional multi-key snapshot claim.
 */

export async function createOpenBaoEgressRevocationBinding(
  request: OpenBaoEgressRevocationBindingRequest,
): Promise<OpenBaoEgressRevocationBinding> {
  try {
    const authority = normalizeOpenBaoEgressRevocationAuthorityOptions(authorityOptions(request));
    const source = new AggregateOpenBaoEgressRevocationSource({ ...request, ...authority });
    const userId = validOpaque(request.userId);
    const handles = routeCredentialHandles(request.routePlan, userId);
    const values = new Map<string, string>();
    const identities: OpenBaoHydratedIdentity[] = [];
    let released = false;
    const release = () => {
      released = true;
      values.clear();
    };
    const signal = request.signal ?? new AbortController().signal;
    const store = new OpenBaoModelApiKeyStore(authority);
    try {
      await ownedOpenBaoDeadline(signal, authority.timeoutMs ?? 5000, async (captureSignal) => {
        for (const handle of handles) {
          const reader = new OpenBaoEgressRevocationSource({
            ...request,
            ...authority,
            credentialHandle: handle,
          });
          const m0 = await reader.readIdentity(captureSignal);
          if (m0.revoked || m0.identity === null) throw new Error("revoked");
          const expected = m0.identity;
          let captured = "";
          try {
            await store.withPinnedApiKey(
              {
                userId,
                provider: "egress",
                model: "egress-hydration",
                credentialHandle: handle,
                signal: captureSignal,
              },
              { version: expected[4], createdTime: expected[6] },
              async (key) => {
                captured = key;
              },
            );
            const m1 = await reader.readIdentity(captureSignal);
            if (captureSignal.aborted || m1.revoked || JSON.stringify(m1.identity) !== JSON.stringify(expected))
              throw new Error("identity mismatch");
            values.set(handle, captured);
            identities.push(expected);
          } finally {
            captured = "";
          }
        }
      });
      if (signal.aborted) throw new Error("aborted");
      const baseline = aggregateSnapshot(
        request.presetRevision,
        identities.map((entry) => [handleDigest(entry[3]), identityVersion(entry)]),
        false,
        request.pkiExpiresAtMs,
      );
      const manifest: OpenBaoHydratedManifest = Object.freeze({
        schema: "openbao-hydrated-manifest-v1",
        identities: Object.freeze(identities),
        baseline,
      });
      const credentialSource = new ModelBackedEgressCredentialSource({
        userId,
        resolver: new ModelCredentialResolver({
          async withApiKey(input, consume) {
            if (released || signal.aborted || input.signal?.aborted) throw new Error("closed");
            const value = values.get(input.credentialHandle);
            if (value === undefined) throw new Error("unbound handle");
            await consume(value);
          },
        }),
        signal,
      });
      const binding = Object.freeze({ source, credentialSource, credentialVersion: baseline.credentialVersion });
      hydratedMaterials.set(binding, Object.freeze({ manifest, release }));
      return binding;
    } catch {
      release();
      throw new Error("capture failed");
    }
  } catch {
    throw new CogsEgressOpenBaoRevocationError();
  }
}

export class OpenBaoEgressRevocationSource implements CogsEgressRevocationSource {
  readonly #origin: string;
  readonly #mount: string;
  readonly #identity: OpenBaoIdentityPort;
  readonly #path: string;
  readonly #handle: string;
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
      this.#handle = options.credentialHandle;
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
    const result = await this.readIdentity(signal);
    return Object.freeze({
      presetRevision: this.#presetRevision,
      credentialVersion: result.identity === null ? "missing" : identityVersion(result.identity),
      revoked: result.revoked,
      pkiExpiresAtMs: this.#pkiExpiresAtMs,
    });
  }

  public async readIdentity(
    parent: AbortSignal,
  ): Promise<Readonly<{ identity: OpenBaoHydratedIdentity | null; revoked: boolean }>> {
    try {
      return await ownedOpenBaoDeadline(parent, this.#timeoutMs, async (signal) =>
        withTokenOnce(this.#identity, signal, async (rawToken) => {
          if (signal.aborted) throw new Error("aborted");
          const response = await this.#fetch(
            `${this.#origin}/v1/${encodeURIComponent(this.#mount)}/metadata/${this.#path}`,
            {
              method: "GET",
              headers: { "x-vault-token": secret(rawToken), accept: "application/json" },
              redirect: "error",
              signal,
            },
          );
          const text = await bounded(response, this.#maxBytes, signal);
          if (text === null) return Object.freeze({ identity: null, revoked: true });
          const data = parseMetadata(text, response);
          const tuple: OpenBaoHydratedIdentity = Object.freeze([
            "openbao-kv2-generation-v1",
            this.#origin,
            this.#mount,
            this.#handle,
            data.current,
            data.keyCreatedTime,
            data.versionCreatedTime,
          ]);
          return Object.freeze({ identity: tuple, revoked: data.revoked });
        }),
      );
    } catch {
      throw new CogsEgressOpenBaoRevocationError();
    }
  }
}

class AggregateOpenBaoEgressRevocationSource implements CogsEgressRevocationSource {
  readonly #options: OpenBaoEgressRevocationBindingOptions;
  readonly #handles: readonly string[];
  readonly #userId: string;
  readonly #presetRevision: string;
  readonly #pkiExpiresAtMs: number;
  readonly #timeoutMs: number;

  public constructor(request: OpenBaoEgressRevocationBindingRequest) {
    this.#options = normalizeOpenBaoEgressRevocationAuthorityOptions(authorityOptions(request));
    this.#userId = validOpaque(request.userId);
    this.#handles = routeCredentialHandles(request.routePlan, this.#userId);
    this.#presetRevision = validOpaque(request.presetRevision);
    this.#pkiExpiresAtMs = integer(request.pkiExpiresAtMs, 1, Number.MAX_SAFE_INTEGER);
    this.#timeoutMs = integer(request.timeoutMs ?? 5000, 1, 60_000);
  }

  public async read(signal: AbortSignal): Promise<CogsEgressRevocationSnapshot> {
    if (signal.aborted) throw new CogsEgressOpenBaoRevocationError();
    try {
      return await ownedOpenBaoDeadline(signal, this.#timeoutMs, (boundedSignal) => this.readInner(boundedSignal));
    } catch {
      throw new CogsEgressOpenBaoRevocationError();
    }
  }

  private async readInner(signal: AbortSignal): Promise<CogsEgressRevocationSnapshot> {
    const pairs: [string, string][] = [];
    let revoked = false;
    for (const handle of this.#handles) {
      if (signal.aborted) throw new Error("aborted");
      const snapshot = await new OpenBaoEgressRevocationSource({
        ...this.#options,
        userId: this.#userId,
        credentialHandle: handle,
        presetRevision: this.#presetRevision,
        pkiExpiresAtMs: this.#pkiExpiresAtMs,
      }).read(signal);
      pairs.push([handleDigest(handle), snapshot.credentialVersion]);
      revoked ||= snapshot.revoked;
    }
    return aggregateSnapshot(this.#presetRevision, pairs, revoked, this.#pkiExpiresAtMs);
  }
}
function authorityOptions(request: OpenBaoEgressRevocationBindingRequest): OpenBaoEgressRevocationBindingOptions {
  return Object.freeze({
    origin: request.origin,
    mount: request.mount,
    identity: request.identity,
    ...(request.allowLoopbackHttpDevelopment === undefined
      ? {}
      : { allowLoopbackHttpDevelopment: request.allowLoopbackHttpDevelopment }),
    ...(request.timeoutMs === undefined ? {} : { timeoutMs: request.timeoutMs }),
    ...(request.maxResponseBytes === undefined ? {} : { maxResponseBytes: request.maxResponseBytes }),
    ...(request.fetchImpl === undefined ? {} : { fetchImpl: request.fetchImpl }),
  });
}
function aggregateSnapshot(
  presetRevision: string,
  pairs: readonly (readonly [string, string])[],
  revoked: boolean,
  pkiExpiresAtMs: number,
): CogsEgressRevocationSnapshot {
  return Object.freeze({ presetRevision, credentialVersion: aggregateVersion(pairs), revoked, pkiExpiresAtMs });
}
function routeCredentialHandles(routePlan: CogsEgressRoutePlan, userId: string): readonly string[] {
  if (!routePlan || typeof routePlan !== "object" || Array.isArray(routePlan) || !Object.isFrozen(routePlan))
    throw new Error("bad route plan");
  const handles = new Set<string>();
  for (const integration of routePlan.integrations) {
    if (!Object.isFrozen(integration) || !Object.isFrozen(integration.routes)) throw new Error("bad route plan");
    if (integration.routes.some((route) => route.credentialRequired === true)) {
      credentialPath(integration.auth.secretHandle, userId);
      handles.add(integration.auth.secretHandle);
    }
  }
  if (handles.size > 128) throw new Error("too many handles");
  return Object.freeze([...handles].sort());
}
function handleDigest(handle: string): string {
  return `sha256:${createHash("sha256").update(handle).digest("hex")}`;
}

function aggregateVersion(pairs: readonly (readonly [string, string])[]): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(pairs)).digest("hex")}`;
}

async function ownedOpenBaoDeadline<T>(
  parent: AbortSignal,
  timeoutMs: number,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const deadlineAt = performance.now() + timeoutMs;
  let expired = false;
  const abort = () => controller.abort();
  if (parent.aborted) abort();
  else parent.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => {
    expired = true;
    controller.abort();
  }, timeoutMs);
  try {
    const value = await operation(controller.signal);
    if (expired || performance.now() >= deadlineAt || parent.aborted || controller.signal.aborted)
      throw new Error("openbao deadline");
    return value;
  } finally {
    clearTimeout(timer);
    parent.removeEventListener("abort", abort);
    controller.abort();
  }
}

function identityVersion(identity: OpenBaoHydratedIdentity): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(identity)).digest("hex")}`;
}

function parseMetadata(
  text: string,
  response: Response,
): { current: number; revoked: boolean; keyCreatedTime: string; versionCreatedTime: string } {
  const length = response.headers.get("content-length");
  const type = response.headers.get("content-type") ?? "";
  if (response.status !== 200 || !jsonType.test(type) || (length !== null && !/^[0-9]+$/.test(length)))
    throw new Error("bad response");
  const root = parseOpenBaoJson(text);
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
  const keyCreatedTime = validateOpenBaoTimestamp(data.created_time);
  validateOpenBaoTimestamp(data.updated_time);
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
  return {
    current,
    keyCreatedTime,
    versionCreatedTime: currentEntry.created_time,
    revoked: currentEntry.destroyed || currentEntry.deletion_time !== "",
  };
}

async function bounded(response: Response, maximum: number, signal: AbortSignal): Promise<string | null> {
  // Capture the original body before hostile headers/reader acquisition.
  const body = response.body;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const chunks: Uint8Array[] = [];
  let total = 0;
  let cancellation: Promise<void> | undefined;
  const abortRead = () => {
    // Publish before cancellation can invoke injected stream code/reenter.
    cancellation ??= Promise.resolve().then(() => (reader ? reader.cancel() : body?.cancel()));
    void cancellation.catch(() => undefined);
  };
  try {
    if (signal.aborted) throw new Error("aborted");
    if (response.status === 404) return null;
    const type = response.headers.get("content-type") ?? "";
    const length = response.headers.get("content-length");
    if (
      response.status !== 200 ||
      !jsonType.test(type) ||
      (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > maximum))
    )
      throw new Error("bad response");
    reader = body?.getReader();
    if (!reader) throw new Error("missing body");
    signal.addEventListener("abort", abortRead, { once: true });
    for (;;) {
      if (signal.aborted) throw new Error("aborted");
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximum) throw new Error("too large");
      chunks.push(next.value);
    }
    if (signal.aborted) throw new Error("aborted");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
    return text;
  } finally {
    abortRead();
    try {
      await cancellation;
    } finally {
      signal.removeEventListener("abort", abortRead);
      reader?.releaseLock();
    }
  }
}

async function withTokenOnce<T>(
  identity: OpenBaoIdentityPort,
  signal: AbortSignal,
  operation: (token: string) => Promise<T>,
): Promise<T> {
  let active = true;
  let invalid = false;
  let callback: Promise<void> | undefined;
  let result: { value: T } | undefined;
  try {
    try {
      await identity.withToken(signal, (token) => {
        if (!active || callback || signal.aborted) {
          invalid = true;
          const rejected = Promise.reject(new Error("bad token callback"));
          void rejected.catch(() => undefined);
          return rejected;
        }
        callback = Promise.resolve().then(async () => {
          if (signal.aborted) throw new Error("aborted");
          result = { value: await operation(token) };
        });
        void callback.catch(() => undefined);
        return callback;
      });
    } finally {
      active = false;
      // Wrapper failure/early return cannot detach acquired callback work.
      await callback?.catch(() => undefined);
    }
    if (invalid || !callback || !result || signal.aborted) throw new Error("bad token callback");
    await callback;
    return result.value;
  } finally {
    result = undefined;
  }
}

function versionEntry(value: unknown): { created_time: string; deletion_time: string; destroyed: boolean } {
  onlyPlain(value, ["created_time", "deletion_time", "destroyed"]);
  const entry = value as Record<string, unknown>;
  validateOpenBaoTimestamp(entry.created_time);
  if (entry.deletion_time !== "") validateOpenBaoTimestamp(entry.deletion_time);
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
  if (typeof value !== "string" || !name.test(value)) throw new Error("bad name");
  return value;
}
function identity(value: OpenBaoIdentityPort): OpenBaoIdentityPort {
  if (!value || typeof value !== "object" || typeof value.withToken !== "function") throw new Error("bad identity");
  return value;
}
function boolean(value: boolean): boolean {
  if (typeof value !== "boolean") throw new Error("bad boolean");
  return value;
}
function fetchFunction(value: typeof fetch): typeof fetch {
  if (typeof value !== "function") throw new Error("bad fetch");
  return value;
}
function exactPlain(
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
  if (keys.some((key) => typeof key === "symbol")) throw new Error("bad object");
  const names = keys as string[];
  if (required.some((key) => !names.includes(key))) throw new Error("bad object");
  if (names.some((key) => !required.includes(key) && !optional.includes(key))) throw new Error("bad object");
  for (const key of names) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error("bad object");
  }
}
function validOpaque(value: string): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
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
