import { createRequire } from "node:module";
import { types } from "node:util";
import type { Ajv as AjvCore, ErrorObject, Options } from "ajv";
import runtimeSchema from "../../schemas/runtime-v1alpha1.json" with { type: "json" };
import { deepFreeze } from "../launch/config.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const MAX_NODES = 256;
const MAX_DEPTH = 12;
const MAX_STRING_BYTES = 4096;
const MAX_DOCUMENT_BYTES = 32 * 1024;

export interface RuntimeConfig {
  readonly version: "cogs.runtime/v1alpha1";
  readonly profile: "api-key-only";
  readonly paths: {
    readonly launch_document: "/etc/cogs/launch.json";
    readonly api_bearer: "/run/cogs/api/bearer";
    readonly openbao_jwt: "/run/cogs/openbao/jwt";
    readonly proxy_capability: "/run/cogs/proxy/capability";
    readonly envoy_executable: "/usr/local/bin/envoy";
    readonly egress_tmpfs: "/run/cogs/egress";
    readonly audit_wal: "/var/lib/cogs/session/egress-audit.wal";
    readonly agent_directory: "/var/lib/cogs/session/agent";
    readonly session_root: "/var/lib/cogs/session/sessions";
    readonly shared_skill_oci: "/var/lib/cogs/skills/shared-oci";
    readonly private_skill_source: "/var/lib/cogs/skills/private-source";
    readonly private_skill_store: "/var/lib/cogs/skills/private-store";
  };
  readonly api: { readonly listen_host: "127.0.0.1" | "0.0.0.0"; readonly port: number };
  readonly openbao: {
    readonly origin: string;
    readonly kubernetes_auth_mount: string;
    readonly kubernetes_auth_role: string;
    readonly model_kv_mount: string;
    readonly egress_kv_mount: string;
    readonly pki_mount: string;
    readonly pki_role: string;
    readonly projected_jwt_ttl_seconds: 600;
    readonly max_client_token_ttl_seconds: 600;
  };
  readonly otlp: {
    readonly protocol: "http/json";
    readonly traces_endpoint: string;
    readonly metrics_endpoint: string;
    readonly logs_endpoint: string;
  };
  readonly egress: {
    readonly listener_port: number;
    readonly revocation_poll_seconds: number;
    readonly completion_capacity: number;
  };
  readonly lifecycle: { readonly maximum_session_seconds: 28800; readonly shutdown_timeout_seconds: number };
}

export class RuntimeConfigError extends Error {
  public readonly code = "COGS_RUNTIME_CONFIG_INVALID";
  public readonly issues: readonly { readonly instancePath: string; readonly keyword: string }[];

  public constructor(issues: readonly { readonly instancePath: string; readonly keyword: string }[] = []) {
    super("invalid production runtime configuration");
    this.name = "RuntimeConfigError";
    this.issues = Object.freeze(issues.map((issue) => Object.freeze({ ...issue })));
  }
}

const ajv = new Ajv2020({
  allErrors: true,
  coerceTypes: false,
  removeAdditional: false,
  useDefaults: false,
  strict: true,
  strictRequired: false,
  validateFormats: false,
  ownProperties: true,
});
const validateSchema = ajv.compile<RuntimeConfig>(runtimeSchema);

export function validateRuntimeConfig(input: unknown): RuntimeConfig {
  try {
    const candidate = snapshot(input, { nodes: 0 }, 0);
    if (!validateSchema(candidate)) throw schemaError(validateSchema.errors ?? []);
    const runtime = candidate as RuntimeConfig;
    requireHttpsOrigin(runtime.openbao.origin);
    requireOtlpEndpoint(runtime.otlp.traces_endpoint, "/v1/traces");
    requireOtlpEndpoint(runtime.otlp.metrics_endpoint, "/v1/metrics");
    requireOtlpEndpoint(runtime.otlp.logs_endpoint, "/v1/logs");
    if (runtime.api.port === runtime.egress.listener_port) throw new RuntimeConfigError();
    return deepFreeze(runtime);
  } catch (error) {
    if (error instanceof RuntimeConfigError) throw error;
    throw new RuntimeConfigError();
  }
}

export function parseRuntimeConfigBytes(bytes: Uint8Array): RuntimeConfig {
  try {
    if (!(bytes instanceof Uint8Array) || types.isProxy(bytes)) throw new Error("invalid bytes");
    if (bytes.byteLength < 2 || bytes.byteLength > MAX_DOCUMENT_BYTES) throw new Error("invalid size");
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error("invalid encoding");
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.codePointAt(0) === 0xfeff || !text.endsWith("\n")) throw new Error("invalid encoding");
    const parsed = JSON.parse(text.slice(0, -1)) as unknown;
    const runtime = validateRuntimeConfig(parsed);
    if (text !== `${canonicalJson(runtime)}\n`) throw new Error("noncanonical document");
    return runtime;
  } catch (error) {
    if (error instanceof RuntimeConfigError) throw error;
    throw new RuntimeConfigError();
  }
}

export function canonicalRuntimeConfig(config: RuntimeConfig): string {
  return `${canonicalJson(validateRuntimeConfig(config))}\n`;
}

function snapshot(value: unknown, count: { nodes: number }, depth: number): unknown {
  count.nodes += 1;
  if (count.nodes > MAX_NODES || depth > MAX_DEPTH || types.isProxy(value)) throw new RuntimeConfigError();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new RuntimeConfigError();
    return value;
  }
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES || hasControl(value)) throw new RuntimeConfigError();
    return value;
  }
  if (typeof value !== "object") throw new RuntimeConfigError();
  const prototype = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype) throw new RuntimeConfigError();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    const length = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : undefined;
    if (
      typeof length !== "number" ||
      !Number.isSafeInteger(length) ||
      length < 0 ||
      Reflect.ownKeys(descriptors).length !== length + 1
    )
      throw new RuntimeConfigError();
    const result: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor?.enumerable || !("value" in descriptor)) throw new RuntimeConfigError();
      result.push(snapshot(descriptor.value, count, depth + 1));
    }
    return result;
  }
  if (prototype !== Object.prototype && prototype !== null) throw new RuntimeConfigError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key === "symbol")) throw new RuntimeConfigError();
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !("value" in descriptor)) throw new RuntimeConfigError();
    Object.defineProperty(result, key, {
      value: snapshot(descriptor.value, count, depth + 1),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return result;
}

function schemaError(errors: readonly ErrorObject[]): RuntimeConfigError {
  return new RuntimeConfigError(
    errors.map((error) => ({ instancePath: boundedIssue(error.instancePath), keyword: boundedIssue(error.keyword) })),
  );
}

function boundedIssue(value: string): string {
  return value.length <= 256 && !hasControl(value) ? value : "invalid";
}

function requireHttpsOrigin(value: string): void {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.port === "0" ||
    url.href !== value
  )
    throw new RuntimeConfigError();
}

function requireOtlpEndpoint(value: string, path: string): void {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== path ||
    url.search !== "" ||
    url.hash !== "" ||
    url.port === "0" ||
    url.href !== value
  )
    throw new RuntimeConfigError();
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function hasControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}
