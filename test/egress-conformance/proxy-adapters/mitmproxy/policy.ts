import type { CredentialConfig } from "../envoy/config.ts";

export interface MitmproxyRouteConfig {
  id: string;
  protocol: "https";
  host: string;
  port: number;
  methods: readonly string[];
  pathPrefix: string;
  query?: string;
  credential?: CredentialConfig;
}

export interface MitmproxyPolicyInput {
  caseId: string;
  sessionId: string;
  authorizationOrigin: string;
  routes: readonly MitmproxyRouteConfig[];
}

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const hostPattern = /^(?:localhost|[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)$/;
const methodPattern = /^[A-Z]{1,16}$/;
const headerPattern = /^[a-z][a-z0-9-]{0,63}$/;

function safeText(value: string, label: string, max: number): void {
  if (value.length === 0 || value.length > max || /[\0\r\n]/.test(value)) throw new Error(`${label} is invalid`);
}

function validateCredential(value: CredentialConfig): void {
  safeText(value.value, "credential value", 8192);
  if (value.kind === "bearer" && !/^Bearer [^\s]+$/.test(value.value)) throw new Error("bearer credential is invalid");
  if (value.kind === "basic" && !/^Basic [A-Za-z0-9+/]+={0,2}$/.test(value.value))
    throw new Error("basic credential is invalid");
  if (value.kind === "api-key") {
    if (
      value.header !== value.header.toLowerCase() ||
      !headerPattern.test(value.header) ||
      new Set([
        "authorization",
        "proxy-authorization",
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
      ]).has(value.header)
    )
      throw new Error("API-key header is unsafe");
  }
}

function validateQuery(value: string): void {
  safeText(value, "route query", 1024);
  const parts = value.split("&");
  if (
    parts.some((part) => !/^[A-Za-z0-9._~-]+=[A-Za-z0-9._~-]+$/.test(part)) ||
    new Set(parts.map((part) => part.split("=", 1)[0])).size !== parts.length ||
    [...parts].sort().join("&") !== value
  )
    throw new Error("route query must be exact, canonical, uniquely keyed, and key-sorted");
}

function validatePath(value: string): void {
  if (
    !value.startsWith("/") ||
    value.length > 2048 ||
    /[?#\\%\0\r\n]/.test(value) ||
    value.includes("//") ||
    value.split("/").some((part) => part === "." || part === "..")
  )
    throw new Error("route path prefix is non-canonical");
}

export function renderMitmproxyPolicy(input: MitmproxyPolicyInput): string {
  if (!idPattern.test(input.caseId) || !idPattern.test(input.sessionId))
    throw new Error("policy identifiers are invalid");
  const origin = new URL(input.authorizationOrigin);
  if (
    origin.protocol !== "http:" ||
    origin.username !== "" ||
    origin.password !== "" ||
    origin.hostname !== "127.0.0.1" ||
    origin.port === "" ||
    origin.pathname !== "/" ||
    origin.search !== "" ||
    origin.hash !== ""
  )
    throw new Error("authorization origin must be uncredentialed loopback HTTP with an explicit port");
  if (input.routes.length === 0 || input.routes.length > 128) throw new Error("policy route count is invalid");

  const routeIds = new Set<string>();
  const tuples = new Set<string>();
  const routes = input.routes.map((route) => {
    if (!idPattern.test(route.id) || routeIds.has(route.id))
      throw new Error("route identifier is invalid or duplicated");
    routeIds.add(route.id);
    if (!hostPattern.test(route.host) || route.host !== route.host.toLowerCase())
      throw new Error("route host is invalid");
    if (!Number.isInteger(route.port) || route.port < 1 || route.port > 65535) throw new Error("route port is invalid");
    validatePath(route.pathPrefix);
    if (route.query !== undefined) validateQuery(route.query);
    if (route.credential !== undefined) validateCredential(route.credential);
    if (route.methods.length === 0 || route.methods.some((method) => !methodPattern.test(method)))
      throw new Error("route methods are invalid");
    const methods = [...new Set(route.methods)].sort();
    if (methods.length !== route.methods.length) throw new Error("route methods are duplicated");
    const tuple = `${route.host}|${route.port}|${methods.join(",")}|${route.pathPrefix}|${route.query ?? ""}`;
    if (tuples.has(tuple)) throw new Error("route policy is ambiguous");
    tuples.add(tuple);
    return { ...route, methods };
  });
  routes.sort(
    (left, right) =>
      left.host.localeCompare(right.host) ||
      left.port - right.port ||
      right.pathPrefix.length - left.pathPrefix.length ||
      left.id.localeCompare(right.id),
  );
  return `${JSON.stringify({ version: "cogs.mitmproxy-policy/v1alpha1", case_id: input.caseId, session_id: input.sessionId, authorization_origin: origin.origin, routes })}\n`;
}
