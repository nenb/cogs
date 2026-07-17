import { createHash } from "node:crypto";
import type { LaunchConfig } from "../launch/config.ts";
import { requireCogsPolicyAllow } from "../policy/require-policy.ts";
import { canonicalPresetPolicyRevision } from "./preset-revision.ts";

const maxIntegrations = 16;
const maxExpandedRoutes = 256;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const hostName = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const safeQueryPart = /^[A-Za-z0-9._~-]+=[A-Za-z0-9._~-]+$/;
const placeholder = /^COGS_PLACEHOLDER_[A-Z0-9_]+$/;
const headerName = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const forbiddenAuthHeaders = new Set([
  "authorization",
  "proxy-authorization",
  "host",
  "cookie",
  "connection",
  "content-length",
  "transfer-encoding",
]);
const maxRegexLength = 4096;
const methodOrder = new Map(["GET", "POST"].map((method, index) => [method, index]));

export class EgressRoutePolicyError extends Error {
  public readonly code = "COGS_EGRESS_ROUTE_POLICY_INVALID";
  public constructor() {
    super("egress route policy invalid");
    this.name = "EgressRoutePolicyError";
  }
}

export interface CogsEgressRoutePlan {
  readonly integrations: readonly CogsEgressIntegrationPlan[];
  readonly routeCount: number;
}

export interface CogsEgressIntegrationPlan {
  readonly id: string;
  readonly presetRevision: string;
  readonly auth: CogsEgressAuthRef;
  readonly routes: readonly CogsEgressRoute[];
}

export type CogsEgressAuthRef =
  | {
      readonly type: "bearer_header" | "api_key_header";
      readonly header: string;
      readonly prefix: string;
      readonly placeholder: string;
      readonly secretHandle: string;
    }
  | {
      readonly type: "basic_header";
      readonly header: "Authorization";
      readonly placeholder: string;
      readonly secretHandle: string;
    };

export interface CogsEgressRoute {
  readonly integrationId: string;
  readonly ruleName: string;
  readonly routeId: string;
  readonly host: string;
  readonly port: number;
  readonly method: string;
  readonly pathPattern: string;
  readonly pathStrategy: "exact" | "prefix" | "segment-glob";
  readonly queryPolicy:
    | { readonly mode: "deny" }
    | { readonly mode: "exact"; readonly values: readonly string[]; readonly canonical: string };
  readonly pathMatch: { readonly kind: "safe_regex"; readonly value: string };
  readonly injectAuth: boolean;
  readonly credentialRequired: boolean;
}

export function lowerLaunchEgressRoutePlan(launch: LaunchConfig): CogsEgressRoutePlan {
  try {
    const launchObject = object(launch);
    const userId = text(launchObject.user_id, "user id", 128);
    if (!opaque.test(userId)) throw new Error("bad user id");
    const integrations = array(launchObject.integrations, maxIntegrations);
    const ids = new Set<string>();
    const budget = { remaining: maxExpandedRoutes };
    const lowered = integrations
      .map((integration) => lowerIntegration(integration, ids, userId, budget))
      .sort((left, right) => left.id.localeCompare(right.id));
    const routeCount = maxExpandedRoutes - budget.remaining;
    rejectDuplicateRoutes(lowered);
    const plan = deepFreeze({ integrations: lowered, routeCount });
    requireCogsPolicyAllow({
      version: "cogs.policy/v1alpha1",
      action: "config.validate",
      user: launch.user_id,
      session: launch.session_id,
      resource: "egress_route_plan",
      attributes: {
        route_count: routeCount,
        credential_route_count: lowered.reduce(
          (count, integration) => count + integration.routes.filter((route) => route.credentialRequired).length,
          0,
        ),
      },
    });
    return plan;
  } catch {
    throw new EgressRoutePolicyError();
  }
}

function lowerIntegration(
  input: unknown,
  ids: Set<string>,
  userId: string,
  budget: { remaining: number },
): CogsEgressIntegrationPlan {
  const integration = object(input);
  exactKeys(integration, ["auth", "dns", "id", "preset_revision", "rules", "version"]);
  const id = text(integration.id, "id", 128);
  if (!opaque.test(id) || ids.has(id)) throw new Error("bad integration id");
  ids.add(id);
  if (integration.version !== "cogs.integration/v1alpha1") throw new Error("bad integration version");
  if (!digest(text(integration.preset_revision, "preset revision", 71))) throw new Error("bad revision");
  const dns = object(integration.dns);
  exactKeys(dns, ["guest_resolution", "mode"]);
  if (dns.mode !== "proxy-connect-authority" || dns.guest_resolution !== false) throw new Error("bad dns");
  const auth = authRef(integration.auth, userId);
  const rules = array(integration.rules, 64);
  const ruleNames = new Set<string>();
  const routes = rules.flatMap((rule) => lowerRule(id, rule, ruleNames, budget)).sort(routeCompare);
  assertCanonicalRevision(integration);
  if (routes.length === 0) throw new Error("empty routes");
  return { id, presetRevision: text(integration.preset_revision, "preset revision", 71), auth, routes };
}

function lowerRule(
  integrationId: string,
  input: unknown,
  names: Set<string>,
  budget: { remaining: number },
): CogsEgressRoute[] {
  const rule = object(input);
  exactKeys(rule, [
    "host",
    "inject_auth",
    "methods",
    "name",
    "path_patterns",
    "path_policy",
    "port",
    "query_policy",
    "redirects",
  ]);
  const ruleName = text(rule.name, "rule name", 128);
  if (!opaque.test(ruleName) || names.has(ruleName)) throw new Error("bad rule name");
  names.add(ruleName);
  const host = text(rule.host, "host", 253);
  if (host !== host.toLowerCase() || !hostName.test(host)) throw new Error("bad host");
  const port = integer(rule.port, 1, 65_535);
  const methods = array(rule.methods, 7).map((method) => text(method, "method", 7));
  if (new Set(methods).size !== methods.length || methods.some((method) => method !== "GET" && method !== "POST")) {
    throw new Error("bad methods");
  }
  const patterns = array(rule.path_patterns, 128).map((pattern) => text(pattern, "path", 2048));
  if (new Set(patterns).size !== patterns.length) throw new Error("bad patterns");
  const pathPolicy = object(rule.path_policy);
  exactKeys(pathPolicy, ["normalization", "strategy"]);
  const strategy = pathPolicy.strategy;
  if (
    (strategy !== "exact" && strategy !== "prefix" && strategy !== "segment-glob") ||
    pathPolicy.normalization !== "reject-ambiguous"
  ) {
    throw new Error("bad path policy");
  }
  const queryPolicy = parseQueryPolicy(rule.query_policy);
  const redirects = object(rule.redirects);
  exactKeys(redirects, ["allowed_hosts", "max_hops", "mode"]);
  if (redirects.mode !== "deny" || redirects.max_hops !== 0 || array(redirects.allowed_hosts, 0).length !== 0) {
    throw new Error("redirects unsupported");
  }
  const expanded = methods.length * patterns.length;
  if (expanded > budget.remaining) throw new Error("too many routes");
  budget.remaining -= expanded;
  const injectAuth = boolean(rule.inject_auth);
  return methods.flatMap((method) =>
    patterns.map((pattern) => {
      const pathMatch = compilePathMatch(pattern, strategy, queryPolicy);
      return {
        integrationId,
        ruleName,
        routeId: `route-${createHash("sha256")
          .update(`${integrationId}\0${ruleName}\0${host}\0${port}\0${method}\0${pattern}\0${queryKey(queryPolicy)}`)
          .digest("hex")
          .slice(0, 32)}`,
        host,
        port,
        method,
        pathPattern: pattern,
        pathStrategy: strategy,
        queryPolicy,
        pathMatch,
        injectAuth,
        credentialRequired: injectAuth,
      };
    }),
  );
}

function compilePathMatch(
  pattern: string,
  strategy: "exact" | "prefix" | "segment-glob",
  query: CogsEgressRoute["queryPolicy"],
): CogsEgressRoute["pathMatch"] {
  validatePathPattern(pattern);
  if (strategy === "exact") {
    if (pattern.includes("*")) throw new Error("wildcard exact");
    return query.mode === "exact"
      ? boundedRegex(`^${regexEscape(pattern)}\\?${regexEscape(query.canonical)}$`)
      : boundedRegex(`^${regexEscape(pattern)}$`);
  }
  if (strategy === "prefix") {
    if (pattern.includes("*") || (pattern !== "/" && pattern.endsWith("/"))) throw new Error("bad prefix");
    const body = pattern === "/" ? "/[^?#]*" : `${regexEscape(pattern)}(?:/[^?#]*)?`;
    return boundedRegex(`^${body}${query.mode === "exact" ? `\\?${regexEscape(query.canonical)}` : ""}$`);
  }
  const body = pattern
    .split("/")
    .map((segment, index) => (index === 0 ? "" : globSegment(segment)))
    .join("/");
  return boundedRegex(`^${body}${query.mode === "exact" ? `\\?${regexEscape(query.canonical)}` : ""}$`);
}

function validatePathPattern(pattern: string): void {
  if (
    !pattern.startsWith("/") ||
    pattern.includes("**") ||
    pattern.includes("%") ||
    pattern.includes("\\") ||
    pattern.includes("?") ||
    pattern.includes("#") ||
    pattern.includes("//") ||
    hasControl(pattern) ||
    pattern.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    throw new Error("bad path");
  }
}

function globSegment(segment: string): string {
  return segment.length === 0 ? "" : segment.split("*").map(regexEscape).join("[^/?#]+");
}

function parseQueryPolicy(input: unknown): CogsEgressRoute["queryPolicy"] {
  const query = object(input);
  if (query.mode === "deny") {
    exactKeys(query, ["mode"]);
    return { mode: "deny" };
  }
  if (query.mode === "exact") {
    exactKeys(query, ["mode", "values"]);
    const values = array(query.values, 16).map((value) => text(value, "query", 256));
    if (values.length === 0 || values.some((value) => !safeQueryPart.test(value))) throw new Error("bad query");
    const keys = values.map((value) => value.split("=", 1)[0] ?? "");
    if (new Set(keys).size !== keys.length || [...values].sort().join("&") !== values.join("&"))
      throw new Error("bad query order");
    return { mode: "exact", values, canonical: values.join("&") };
  }
  throw new Error("bad query mode");
}

function authRef(input: unknown, userId: string): CogsEgressAuthRef {
  const auth = object(input);
  const type = auth.type;
  if (type === "bearer_header") {
    exactKeys(auth, ["header", "placeholder", "prefix", "secret_handle", "type"]);
    if (auth.header !== "Authorization" || auth.prefix !== "Bearer ") throw new Error("bad bearer auth");
    return {
      type,
      header: "Authorization",
      prefix: "Bearer ",
      placeholder: checkedPlaceholder(auth.placeholder),
      secretHandle: secretHandle(auth.secret_handle, userId),
    };
  }
  if (type === "api_key_header") {
    exactKeys(auth, ["header", "placeholder", "prefix", "secret_handle", "type"]);
    const header = text(auth.header, "auth header", 64).toLowerCase();
    if (!headerName.test(header) || forbiddenAuthHeaders.has(header)) throw new Error("bad api key header");
    return {
      type,
      header,
      prefix: text(auth.prefix, "auth prefix", 128, true),
      placeholder: checkedPlaceholder(auth.placeholder),
      secretHandle: secretHandle(auth.secret_handle, userId),
    };
  }
  if (type === "basic_header") {
    exactKeys(auth, ["header", "placeholder", "secret_handle", "type"]);
    if (auth.header !== "Authorization") throw new Error("bad basic header");
    return {
      type,
      header: "Authorization",
      placeholder: checkedPlaceholder(auth.placeholder),
      secretHandle: secretHandle(auth.secret_handle, userId),
    };
  }
  throw new Error("bad auth");
}

function rejectDuplicateRoutes(integrations: readonly CogsEgressIntegrationPlan[]): void {
  const keys = new Set<string>();
  const routeIds = new Set<string>();
  const routes: CogsEgressRoute[] = [];
  for (const integration of integrations) {
    for (const route of integration.routes) {
      if (routeIds.has(route.routeId) || route.routeId.length > 128 || !opaque.test(route.routeId)) {
        throw new Error("duplicate route id");
      }
      routeIds.add(route.routeId);
      const key = `${route.host}|${route.port}|${route.method}|${route.pathMatch.kind}|${route.pathMatch.value}|${queryKey(route.queryPolicy)}`;
      if (keys.has(key)) throw new Error("duplicate route");
      keys.add(key);
      for (const existing of routes) {
        if (routesMayOverlap(existing, route)) throw new Error("overlapping route");
      }
      routes.push(route);
    }
  }
}

function routesMayOverlap(left: CogsEgressRoute, right: CogsEgressRoute): boolean {
  return (
    left.host === right.host &&
    left.port === right.port &&
    left.method === right.method &&
    queryPoliciesOverlap(left.queryPolicy, right.queryPolicy) &&
    pathPoliciesOverlap(left, right)
  );
}

function queryPoliciesOverlap(left: CogsEgressRoute["queryPolicy"], right: CogsEgressRoute["queryPolicy"]): boolean {
  if (left.mode !== right.mode) return false;
  return left.mode === "deny" || left.canonical === (right as { readonly canonical: string }).canonical;
}

function pathPoliciesOverlap(left: CogsEgressRoute, right: CogsEgressRoute): boolean {
  if (left.pathStrategy === "exact" && right.pathStrategy === "exact") return left.pathPattern === right.pathPattern;
  if (left.pathStrategy === "prefix" && right.pathStrategy === "prefix") {
    return prefixContains(left.pathPattern, right.pathPattern) || prefixContains(right.pathPattern, left.pathPattern);
  }
  if (left.pathStrategy === "exact" && right.pathStrategy === "prefix")
    return prefixContains(right.pathPattern, left.pathPattern);
  if (left.pathStrategy === "prefix" && right.pathStrategy === "exact")
    return prefixContains(left.pathPattern, right.pathPattern);
  if (left.pathStrategy === "exact" && right.pathStrategy === "segment-glob")
    return globMatchesPath(right.pathPattern, left.pathPattern);
  if (left.pathStrategy === "segment-glob" && right.pathStrategy === "exact")
    return globMatchesPath(left.pathPattern, right.pathPattern);
  if (left.pathStrategy === "prefix" && right.pathStrategy === "segment-glob")
    return prefixMayOverlapGlob(left.pathPattern, right.pathPattern);
  if (left.pathStrategy === "segment-glob" && right.pathStrategy === "prefix")
    return prefixMayOverlapGlob(right.pathPattern, left.pathPattern);
  return globsMayOverlap(left.pathPattern, right.pathPattern);
}

function prefixContains(prefix: string, path: string): boolean {
  return prefix === "/" || path === prefix || path.startsWith(`${prefix}/`);
}

function globMatchesPath(glob: string, path: string): boolean {
  const globSegments = glob.split("/");
  const pathSegments = path.split("/");
  return (
    globSegments.length === pathSegments.length &&
    globSegments.every((segment, index) => globSegmentMatches(segment, pathSegments[index] ?? ""))
  );
}

function prefixMayOverlapGlob(prefix: string, glob: string): boolean {
  if (prefix === "/") return true;
  const prefixSegments = prefix.split("/");
  const globSegments = glob.split("/");
  if (globSegments.length < prefixSegments.length) return false;
  return prefixSegments.every((segment, index) => globSegmentMatches(globSegments[index] ?? "", segment));
}

function globsMayOverlap(left: string, right: string): boolean {
  const leftSegments = left.split("/");
  const rightSegments = right.split("/");
  return (
    leftSegments.length === rightSegments.length &&
    leftSegments.every((segment, index) => globSegmentsMayOverlap(segment, rightSegments[index] ?? ""))
  );
}

function globSegmentMatches(glob: string, value: string): boolean {
  if (!glob.includes("*")) return glob === value;
  if (value.length === 0 || value.includes("/") || value.includes("?") || value.includes("#")) return false;
  return new RegExp(`^${globSegment(glob)}$`).test(value);
}

function globSegmentsMayOverlap(left: string, right: string): boolean {
  if (!left.includes("*") && !right.includes("*")) return left === right;
  if (left.length === 0 || right.length === 0) return left.length === right.length;
  const leftParts = left.split("*").filter((part) => part.length > 0);
  const rightParts = right.split("*").filter((part) => part.length > 0);
  return (
    leftParts.every((part) => right.includes(part) || right.includes("*")) &&
    rightParts.every((part) => left.includes(part) || left.includes("*"))
  );
}

function assertCanonicalRevision(integration: Record<string, unknown>): void {
  const expected = canonicalPresetPolicyRevision(integration);
  if (integration.preset_revision !== expected) throw new Error("bad revision");
}

function routeCompare(left: CogsEgressRoute, right: CogsEgressRoute): number {
  return (
    left.integrationId.localeCompare(right.integrationId) ||
    left.host.localeCompare(right.host) ||
    left.port - right.port ||
    specificity(right) - specificity(left) ||
    (methodOrder.get(left.method) ?? 99) - (methodOrder.get(right.method) ?? 99) ||
    left.routeId.localeCompare(right.routeId)
  );
}

function specificity(route: CogsEgressRoute): number {
  const base = route.pathStrategy === "exact" ? 30_000 : route.pathStrategy === "segment-glob" ? 20_000 : 10_000;
  return base + route.pathPattern.replaceAll("*", "").length;
}

function queryKey(query: CogsEgressRoute["queryPolicy"]): string {
  return query.mode === "deny" ? "deny" : `exact:${query.canonical}`;
}

function boundedRegex(value: string): CogsEgressRoute["pathMatch"] {
  if (value.length > maxRegexLength) throw new Error("regex too long");
  return { kind: "safe_regex", value };
}

function checkedPlaceholder(value: unknown): string {
  const textValue = text(value, "placeholder", 128);
  if (!placeholder.test(textValue)) throw new Error("bad placeholder");
  return textValue;
}

function secretHandle(value: unknown, userId: string): string {
  const textValue = text(value, "secret handle", 512);
  if (!/^(users|organizations)(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)+$/.test(textValue))
    throw new Error("bad secret handle");
  if (textValue.startsWith("users/") && !textValue.startsWith(`users/${userId}/`)) throw new Error("wrong user handle");
  return textValue;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("bad object");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("bad prototype");
  return value as Record<string, unknown>;
}

function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error("bad array");
  return value;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index]))
    throw new Error("bad keys");
}

function text(value: unknown, label: string, maximum: number, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0) || value.length > maximum || hasControl(value)) {
    throw new Error(`bad ${label}`);
  }
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum)
    throw new Error("bad integer");
  return value as number;
}

function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("bad boolean");
  return value;
}

function digest(value: string): boolean {
  return /^sha256:[a-f0-9]{64}$/.test(value);
}

function hasControl(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function regexEscape(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
