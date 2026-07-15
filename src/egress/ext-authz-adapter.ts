const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const methodToken = /^[A-Z][A-Z0-9!#$&'*+.^_`|~-]{0,31}$/;
const hostValue = /^[A-Za-z0-9._:-]{1,253}$/;
const schemeValue = /^(?:http|https)$/;
const knownContextKeys = new Set([
  "cogs.mode",
  "cogs.case_id",
  "cogs.session_id",
  "cogs.route_id",
  "cogs.require_capability",
  "cogs.credential_required",
]);

export interface CogsExtAuthzCheck {
  readonly mode: "capability" | "authorize";
  readonly caseId: string;
  readonly sessionId: string;
  readonly routeId?: string;
  readonly requireCapability: boolean;
  readonly credentialRequired: boolean;
  readonly proxyAuthorization?: string;
  readonly method?: string;
  readonly host?: string;
  readonly pathAndQuery?: string;
  readonly scheme?: string;
}

export type CogsExtAuthzDecision =
  | { readonly outcome: "allow"; readonly intentId: string }
  | { readonly outcome: "deny"; readonly status: 403 | 407 };

export class ExtAuthzAdapterError extends Error {
  public readonly code = "COGS_EXT_AUTHZ_ADAPTER_FAILED";
  public constructor() {
    super("ext_authz request rejected");
    this.name = "ExtAuthzAdapterError";
  }
}

export function parseExtAuthzCheck(input: unknown): CogsExtAuthzCheck {
  try {
    const request = ownObject(input);
    const attributes = ownObject(request.attributes);
    const context = contextMap(attributes.context_extensions);
    const mode = required(context, "cogs.mode");
    if (mode !== "capability" && mode !== "authorize") throw new Error("bad mode");
    const caseId = validateOpaque(required(context, "cogs.case_id"));
    const sessionId = validateOpaque(required(context, "cogs.session_id"));
    const route = optional(context, "cogs.route_id");
    const requireCapability = parseBoolean(optional(context, "cogs.require_capability") ?? "false");
    const credentialRequired = parseBoolean(optional(context, "cogs.credential_required") ?? "false");
    const http = optionalHttp(attributes);
    const headers = http === undefined ? new Map<string, string>() : headerMap(http.headers);
    const proxyAuthorization = optional(headers, "proxy-authorization");
    return Object.freeze({
      mode,
      caseId,
      sessionId,
      ...(route === undefined ? {} : { routeId: validateOpaque(route) }),
      requireCapability,
      credentialRequired,
      ...(proxyAuthorization === undefined ? {} : { proxyAuthorization }),
      ...optionalStringFields(http),
    });
  } catch {
    throw new ExtAuthzAdapterError();
  }
}

export function buildExtAuthzResponse(decision: CogsExtAuthzDecision): unknown {
  return buildExtAuthzResponseFromUnknown(decision);
}

function buildExtAuthzResponseFromUnknown(decision: unknown): unknown {
  try {
    const value = ownObject(decision);
    if (value.outcome === "allow") {
      return deepFreeze({
        status: { code: 0, message: "", details: [] },
        ok_response: {},
        dynamic_metadata: {
          fields: [{ key: "x-cogs-intent-id", value: { string_value: validateOpaque(value.intentId) } }],
        },
      });
    }
    if (value.outcome === "deny" && (value.status === 403 || value.status === 407)) {
      return deepFreeze({
        status: { code: 7, message: "denied", details: [] },
        denied_response: {
          status: { code: value.status },
          headers:
            value.status === 407
              ? [
                  {
                    header: { key: "proxy-authenticate", value: 'Basic realm="cogs-session"' },
                    append: { value: false },
                  },
                ]
              : [],
          body: "",
        },
      });
    }
    throw new Error("bad decision");
  } catch {
    throw new ExtAuthzAdapterError();
  }
}

function optionalHttp(attributes: Record<string, unknown>): Record<string, unknown> | undefined {
  const request = attributes.request;
  if (request === undefined) return undefined;
  return ownObject(ownObject(request).http);
}

function optionalStringFields(http: Record<string, unknown> | undefined): Partial<CogsExtAuthzCheck> {
  if (http === undefined) return {};
  return {
    ...methodField(http),
    ...hostField(http),
    ...pathAndQueryField(http),
    ...schemeField(http),
  };
}

function methodField(source: Record<string, unknown>): Partial<CogsExtAuthzCheck> {
  const value = source.method;
  if (value === undefined) return {};
  const method = validateText(value, "method", 32);
  if (!methodToken.test(method)) throw new Error("bad method");
  return { method };
}

function hostField(source: Record<string, unknown>): Partial<CogsExtAuthzCheck> {
  const value = source.host;
  if (value === undefined) return {};
  const host = validateText(value, "host", 253);
  if (!hostValue.test(host)) throw new Error("bad host");
  return { host };
}

function pathAndQueryField(source: Record<string, unknown>): Partial<CogsExtAuthzCheck> {
  const value = source.path;
  if (value === undefined) return {};
  const pathAndQuery = validateText(value, "path", 2048);
  if (!pathAndQuery.startsWith("/")) throw new Error("bad path");
  return { pathAndQuery };
}

function schemeField(source: Record<string, unknown>): Partial<CogsExtAuthzCheck> {
  const value = source.scheme;
  if (value === undefined) return {};
  const scheme = validateText(value, "scheme", 5);
  if (!schemeValue.test(scheme)) throw new Error("bad scheme");
  return { scheme };
}

function contextMap(value: unknown): Map<string, string> {
  const map = entryMap(value, { maximum: 6, keyMaximum: 32, valueMaximum: 128, normalizeKey: false });
  if ([...map.keys()].some((key) => !knownContextKeys.has(key))) throw new Error("unknown context");
  return map;
}

function headerMap(value: unknown): Map<string, string> {
  const map = entryMap(value, { maximum: 1, keyMaximum: 64, valueMaximum: 8192, normalizeKey: true });
  if ([...map.keys()].some((key) => key !== "proxy-authorization")) throw new Error("unknown header");
  return map;
}

function entryMap(
  value: unknown,
  options: { maximum: number; keyMaximum: number; valueMaximum: number; normalizeKey: boolean },
): Map<string, string> {
  if (value === undefined) return new Map();
  if (!Array.isArray(value) || value.length > options.maximum) throw new Error("bad entries");
  const output = new Map<string, string>();
  for (const raw of value) {
    const entry = ownObject(raw);
    if (!Object.hasOwn(entry, "key") || !Object.hasOwn(entry, "value")) throw new Error("bad entry");
    const rawKey = validateText(entry.key, "entry key", options.keyMaximum);
    const key = options.normalizeKey ? rawKey.toLowerCase() : rawKey;
    const val = validateText(entry.value, "entry value", options.valueMaximum);
    if (output.has(key)) throw new Error("duplicate key");
    output.set(key, val);
  }
  return output;
}

function required(map: Map<string, string>, key: string): string {
  const value = optional(map, key);
  if (value === undefined) throw new Error("missing");
  return value;
}

function optional(map: Map<string, string>, key: string): string | undefined {
  return map.get(key);
}

function parseBoolean(value: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error("bad boolean");
}

function validateOpaque(value: unknown): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
  return value;
}

function validateText(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || hasControl(value)) {
    throw new Error(`bad ${label}`);
  }
  return value;
}

function hasControl(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function ownObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("bad object");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("bad prototype");
  return value as Record<string, unknown>;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
