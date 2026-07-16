import type {
  CogsEgressAuthRef,
  CogsEgressIntegrationPlan,
  CogsEgressRoute,
  CogsEgressRoutePlan,
} from "./route-policy.ts";

const envoyType = "type.googleapis.com";
const maxBootstrapBytes = 1024 * 1024;
const maxCredentialBytes = 8192;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const authzTarget = /^(127\.0\.0\.1):([0-9]{1,5})$/;
const basicPayload = /^[A-Za-z0-9+/]+={0,2}$/;
const visibleAscii = /^[\x21-\x7e]+$/;
const dnsName = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const secretHandle = /^(?:users|organizations)\/[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/;
const apiKeyHeader = /^[a-z][a-z0-9-]{0,63}$/;
const forbiddenHeaders = new Set([
  "authorization",
  "proxy-authorization",
  "host",
  "cookie",
  "connection",
  "content-length",
  "transfer-encoding",
]);
const paths = Object.freeze({
  bootstrap: "/run/cogs/egress/envoy/bootstrap.json",
  proxyCertificate: "/run/cogs/egress/envoy/proxy-cert.pem",
  proxyPrivateKey: "/run/cogs/egress/envoy/proxy-key.pem",
  proxyCaCertificate: "/run/cogs/egress/envoy/proxy-ca.pem",
} as const);

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

type Header = Readonly<{ name: string; value: string }>;

export interface CogsEnvoyRuntimeConfigOptions {
  readonly sessionId: string;
  readonly listenerPort: number;
  readonly routePlan: CogsEgressRoutePlan;
  readonly authzTarget: string;
  readonly internalAuthzToken: string;
}

export interface CogsEnvoyCredentialRequest {
  readonly integrationId: string;
  readonly secretHandle: string;
  readonly authType: "bearer_header" | "api_key_header" | "basic_header";
}

export type CogsEnvoyCredentialValue =
  | { readonly type: "bearer"; readonly token: string }
  | { readonly type: "api_key"; readonly value: string }
  | { readonly type: "basic"; readonly base64: string };

export interface CogsEnvoyCredentialSource {
  withCredential(
    request: CogsEnvoyCredentialRequest,
    consume: (credential: CogsEnvoyCredentialValue) => Promise<void>,
  ): Promise<void>;
}

export interface CogsEnvoyRuntimeConfig {
  readonly paths: typeof paths;
  readonly bootstrapJson: string;
  readonly routeCount: number;
}

export class CogsEnvoyRuntimeConfigError extends Error {
  public readonly code = "COGS_ENVOY_RUNTIME_CONFIG_FAILED";
  public constructor() {
    super("egress runtime config unavailable");
    this.name = "CogsEnvoyRuntimeConfigError";
  }
}

interface CopiedIntegration {
  readonly id: string;
  readonly auth: CopiedAuth;
  readonly routes: readonly CopiedRoute[];
  readonly needsCredential: boolean;
}
type CopiedAuth =
  | {
      readonly type: "bearer_header";
      readonly header: "Authorization";
      readonly prefix: "Bearer ";
      readonly secretHandle: string;
    }
  | { readonly type: "api_key_header"; readonly header: string; readonly prefix: string; readonly secretHandle: string }
  | { readonly type: "basic_header"; readonly header: "Authorization"; readonly secretHandle: string };
interface CopiedRoute {
  readonly integrationId: string;
  readonly routeId: string;
  readonly host: string;
  readonly port: number;
  readonly method: "GET" | "POST";
  readonly pathRegex: string;
  readonly credentialRequired: boolean;
}

export async function withCogsEnvoyRuntimeConfig<T>(
  options: CogsEnvoyRuntimeConfigOptions,
  credentialSource: CogsEnvoyCredentialSource,
  operation: (config: CogsEnvoyRuntimeConfig) => Promise<T>,
): Promise<T> {
  try {
    const captured = Object.freeze({ ...options });
    const sessionId = validOpaque(captured.sessionId);
    const listenerPort = port(captured.listenerPort);
    const authorization = parseAuthzTarget(captured.authzTarget);
    const internalToken = visibleSecret(captured.internalAuthzToken, 16, 256);
    const integrations = copyPlan(captured.routePlan);
    const credentialed = integrations.filter((integration) => integration.needsCredential);
    const credentials = new Map<string, Header>();
    let result: T | undefined;
    let operationCalled = false;
    try {
      await withCredentials(
        0,
        credentialed,
        credentialSource,
        credentials,
        () => true,
        async () => {
          operationCalled = true;
          result = await operation(
            render(sessionId, listenerPort, authorization, internalToken, integrations, credentials),
          );
        },
      );
      if (!operationCalled) throw new Error("operation not called");
      return result as T;
    } finally {
      credentials.clear();
    }
  } catch {
    throw new CogsEnvoyRuntimeConfigError();
  }
}

async function withCredentials(
  index: number,
  integrations: readonly CopiedIntegration[],
  source: CogsEnvoyCredentialSource,
  credentials: Map<string, Header>,
  parentActive: () => boolean,
  next: () => Promise<void>,
): Promise<void> {
  const integration = integrations[index];
  if (integration === undefined) {
    if (!parentActive()) throw new Error("inactive credential scope");
    return next();
  }
  let called = false;
  let active = true;
  let violated = false;
  let callbackSettled = false;
  let callbackPromise: Promise<void> | undefined;
  const request = Object.freeze({
    integrationId: integration.id,
    secretHandle: integration.auth.secretHandle,
    authType: integration.auth.type,
  });
  const consume = async (credential: CogsEnvoyCredentialValue): Promise<void> => {
    if (!active || called) {
      violated = true;
      throw new CogsEnvoyRuntimeConfigError();
    }
    called = true;
    callbackPromise = (async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (!active || violated || !parentActive()) throw new Error("inactive credential scope");
      credentials.set(integration.id, credentialHeader(integration.auth, credential));
      await withCredentials(index + 1, integrations, source, credentials, () => active && parentActive(), next);
    })().finally(() => {
      callbackSettled = true;
    });
    return callbackPromise;
  };
  try {
    await source.withCredential(request, consume);
    active = false;
    if (!called || callbackPromise === undefined) throw new Error("missing credential callback");
    if (!callbackSettled) throw new Error("credential source did not await callback");
    await callbackPromise;
    if (violated) throw new Error("bad credential callback");
  } catch (error) {
    active = false;
    if (callbackPromise !== undefined) await callbackPromise.catch(() => undefined);
    throw error;
  }
}

function render(
  sessionId: string,
  listenerPort: number,
  authorization: { address: string; port: number },
  internalToken: string,
  integrations: readonly CopiedIntegration[],
  credentials: ReadonlyMap<string, Header>,
): CogsEnvoyRuntimeConfig {
  const allRoutes = integrations.flatMap((integration) => integration.routes);
  const groups = Map.groupBy(allRoutes, (route) => `${route.host}:${route.port}`);
  const clusters: Json[] = [authzCluster(authorization)];
  const listeners: Json[] = [outerListener(listenerPort, sessionId, groups, internalToken)];
  for (const route of allRoutes) clusters.push(upstreamCluster(route));
  for (const [authority, routes] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const first = routes[0];
    if (first === undefined) continue;
    listeners.push(innerListener(authority, sessionId, routes, credentials, internalToken));
    clusters.push(tunnelCluster(first));
  }
  const bootstrap = deepFreeze({
    bootstrap_extensions: [
      {
        name: "envoy.bootstrap.internal_listener",
        typed_config: { "@type": `${envoyType}/envoy.extensions.bootstrap.internal_listener.v3.InternalListener` },
      },
    ],
    static_resources: { listeners, clusters },
  });
  const bootstrapJson = `${JSON.stringify(bootstrap, null, 2)}\n`;
  if (Buffer.byteLength(bootstrapJson) > maxBootstrapBytes) throw new Error("bootstrap too large");
  return deepFreeze({ paths, bootstrapJson, routeCount: allRoutes.length });
}

function outerListener(portValue: number, sessionId: string, groups: Map<string, CopiedRoute[]>, token: string): Json {
  const routes = [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([authority, routes]) => {
      const first = routes[0];
      if (first === undefined) throw new Error("empty group");
      return {
        name: `connect.${authority}`,
        match: { connect_matcher: {}, headers: [{ name: ":authority", string_match: { exact: authority } }] },
        route: {
          cluster: `tunnel_${first.routeId}`,
          timeout: "0s",
          upgrade_configs: [{ upgrade_type: "CONNECT", connect_config: {} }],
        },
        request_headers_to_remove: ["proxy-authorization", "authorization"],
        typed_per_filter_config: perRoute(context("capability", sessionId, "proxy-capability", undefined, true, false)),
      };
    });
  return listener(
    "forward_proxy",
    { socket_address: { protocol: "TCP", address: "0.0.0.0", port_value: portValue } },
    hcm(
      "forward_proxy",
      [{ name: "explicit_proxy", domains: ["*"], routes }],
      [extAuthz(true, token), router()],
      false,
    ),
  );
}

function innerListener(
  authority: string,
  sessionId: string,
  routes: readonly CopiedRoute[],
  credentials: ReadonlyMap<string, Header>,
  token: string,
): Json {
  const first = routes[0];
  if (first === undefined) throw new Error("empty group");
  return {
    name: `mitm_${first.routeId}`,
    internal_listener: {},
    listener_filters: [
      {
        name: "envoy.filters.listener.tls_inspector",
        typed_config: { "@type": `${envoyType}/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector` },
      },
    ],
    filter_chains: [
      {
        filter_chain_match: { server_names: [first.host], transport_protocol: "tls" },
        transport_socket: {
          name: "envoy.transport_sockets.tls",
          typed_config: {
            "@type": `${envoyType}/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext`,
            common_tls_context: {
              alpn_protocols: ["h2", "http/1.1"],
              tls_certificates: [
                {
                  certificate_chain: { filename: paths.proxyCertificate },
                  private_key: { filename: paths.proxyPrivateKey },
                },
              ],
            },
          },
        },
        filters: [
          {
            name: "envoy.filters.network.http_connection_manager",
            typed_config: hcm(
              `mitm_${first.routeId}`,
              [
                {
                  name: `mitm_${authority}`,
                  domains: [first.host, `${first.host}:${first.port}`],
                  routes: routes.map((route) => envoyRoute(route, sessionId, credentials)),
                },
              ],
              [extAuthz(false, token), router()],
              true,
            ),
          },
        ],
      },
    ],
  };
}

function envoyRoute(route: CopiedRoute, sessionId: string, credentials: ReadonlyMap<string, Header>): Json {
  const credential = route.credentialRequired ? credentials.get(route.integrationId) : undefined;
  if (route.credentialRequired && credential === undefined) throw new Error("missing credential");
  return {
    name: route.routeId,
    match: {
      prefix: "/",
      headers: [
        { name: ":method", string_match: { exact: route.method } },
        { name: ":authority", string_match: { safe_regex: { regex: authorityRegex(route) } } },
        { name: ":path", string_match: { safe_regex: { regex: route.pathRegex } } },
      ],
    },
    route: { cluster: `upstream_${route.routeId}`, timeout: "30s" },
    request_headers_to_remove: removeHeaders(credential),
    ...(credential === undefined
      ? {}
      : {
          request_headers_to_add: [
            { header: { key: credential.name, value: credential.value }, append_action: "OVERWRITE_IF_EXISTS_OR_ADD" },
          ],
        }),
    typed_per_filter_config: perRoute(
      context("authorize", sessionId, route.routeId, route.routeId, false, route.credentialRequired),
    ),
  };
}

function removeHeaders(credential: Header | undefined): string[] {
  return [...new Set(["authorization", "proxy-authorization", ...(credential === undefined ? [] : [credential.name])])];
}
function extAuthz(capability: boolean, token: string): Json {
  return {
    name: "envoy.filters.http.ext_authz",
    typed_config: {
      "@type": `${envoyType}/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz`,
      grpc_service: {
        envoy_grpc: { cluster_name: "cogs_authz" },
        timeout: "1s",
        initial_metadata: [{ key: "x-cogs-authz-token", value: token }],
      },
      transport_api_version: "V3",
      failure_mode_allow: false,
      validate_mutations: true,
      ...(capability ? { allowed_headers: matcher("proxy-authorization") } : {}),
      disallowed_headers: {
        patterns: [
          { exact: "authorization" },
          { exact: "cookie" },
          ...(capability ? [] : [{ exact: "proxy-authorization" }]),
        ],
      },
    },
  };
}
function hcm(name: string, virtualHosts: Json[], filters: Json[], completion: boolean): Json {
  return {
    "@type": `${envoyType}/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager`,
    stat_prefix: name,
    codec_type: "AUTO",
    normalize_path: true,
    merge_slashes: false,
    path_with_escaped_slashes_action: "REJECT_REQUEST",
    stream_error_on_invalid_http_message: true,
    max_request_headers_kb: 32,
    common_http_protocol_options: { max_headers_count: 100, headers_with_underscores_action: "REJECT_REQUEST" },
    route_config: { name: `${name}_routes`, virtual_hosts: virtualHosts },
    ...(completion
      ? {
          access_log: [
            {
              name: "envoy.access_loggers.stdout",
              typed_config: {
                "@type": `${envoyType}/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog`,
                log_format: {
                  json_format: {
                    event: "request-complete",
                    intent_id: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:x-cogs-intent-id)%",
                    route_id: "%ROUTE_NAME%",
                    response_code: "%RESPONSE_CODE%",
                    duration_ms: "%DURATION%",
                  },
                },
              },
            },
          ],
        }
      : {}),
    http_filters: filters,
  };
}
function authzCluster(target: { address: string; port: number }): Json {
  return {
    name: "cogs_authz",
    type: "STATIC",
    connect_timeout: "1s",
    typed_extension_protocol_options: {
      "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
        "@type": `${envoyType}/envoy.extensions.upstreams.http.v3.HttpProtocolOptions`,
        explicit_http_config: { http2_protocol_options: {} },
      },
    },
    load_assignment: {
      cluster_name: "cogs_authz",
      endpoints: [
        {
          lb_endpoints: [
            { endpoint: { address: { socket_address: { address: target.address, port_value: target.port } } } },
          ],
        },
      ],
    },
  };
}
function upstreamCluster(route: CopiedRoute): Json {
  return {
    name: `upstream_${route.routeId}`,
    type: "STRICT_DNS",
    connect_timeout: "2s",
    load_assignment: {
      cluster_name: `upstream_${route.routeId}`,
      endpoints: [
        {
          lb_endpoints: [
            { endpoint: { address: { socket_address: { address: route.host, port_value: route.port } } } },
          ],
        },
      ],
    },
    typed_extension_protocol_options: {
      "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
        "@type": `${envoyType}/envoy.extensions.upstreams.http.v3.HttpProtocolOptions`,
        auto_config: { http_protocol_options: {}, http2_protocol_options: {} },
      },
    },
    transport_socket: {
      name: "envoy.transport_sockets.tls",
      typed_config: {
        "@type": `${envoyType}/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext`,
        sni: route.host,
        common_tls_context: {
          alpn_protocols: ["h2", "http/1.1"],
          validation_context: {
            trusted_ca: { filename: "/etc/ssl/certs/ca-certificates.crt" },
            match_typed_subject_alt_names: [{ san_type: "DNS", matcher: { exact: route.host } }],
          },
        },
      },
    },
  };
}
function tunnelCluster(route: CopiedRoute): Json {
  return {
    name: `tunnel_${route.routeId}`,
    type: "STATIC",
    connect_timeout: "2s",
    load_assignment: {
      cluster_name: `tunnel_${route.routeId}`,
      endpoints: [
        {
          lb_endpoints: [
            { endpoint: { address: { envoy_internal_address: { server_listener_name: `mitm_${route.routeId}` } } } },
          ],
        },
      ],
    },
  };
}
function listener(name: string, address: Json, hcmConfig: Json): Json {
  return {
    name,
    address,
    filter_chains: [{ filters: [{ name: "envoy.filters.network.http_connection_manager", typed_config: hcmConfig }] }],
  };
}
function context(
  mode: "capability" | "authorize",
  sessionId: string,
  caseId: string,
  routeId: string | undefined,
  requireCapability: boolean,
  credentialRequired: boolean,
): Record<string, string> {
  return {
    "cogs.mode": mode,
    "cogs.case_id": caseId,
    "cogs.session_id": sessionId,
    ...(routeId === undefined ? {} : { "cogs.route_id": routeId }),
    "cogs.require_capability": String(requireCapability),
    "cogs.credential_required": String(credentialRequired),
  };
}
function perRoute(ctx: Record<string, string>): Json {
  return {
    "envoy.filters.http.ext_authz": {
      "@type": `${envoyType}/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute`,
      check_settings: { context_extensions: ctx },
    },
  };
}
function router(): Json {
  return {
    name: "envoy.filters.http.router",
    typed_config: { "@type": `${envoyType}/envoy.extensions.filters.http.router.v3.Router` },
  };
}
function matcher(value: string): Json {
  return { patterns: [{ exact: value }] };
}

function copyPlan(plan: CogsEgressRoutePlan): readonly CopiedIntegration[] {
  if (
    !Object.isFrozen(plan) ||
    !Object.isFrozen(plan.integrations) ||
    !Array.isArray(plan.integrations) ||
    plan.integrations.length > 16
  )
    throw new Error("bad plan");
  let count = 0;
  const integrationIds = new Set<string>();
  const routeIds = new Set<string>();
  const output = plan.integrations.map((integration) =>
    copyIntegration(integration, integrationIds, routeIds, () => {
      if (++count > 256) throw new Error("too many routes");
    }),
  );
  if (count !== plan.routeCount || count === 0) throw new Error("bad route count");
  return deepFreeze(output.sort((a, b) => a.id.localeCompare(b.id)));
}
function copyIntegration(
  integration: CogsEgressIntegrationPlan,
  integrationIds: Set<string>,
  routeIds: Set<string>,
  tick: () => void,
): CopiedIntegration {
  const id = validOpaque(integration.id);
  if (integrationIds.has(id)) throw new Error("duplicate integration");
  integrationIds.add(id);
  if (!Object.isFrozen(integration) || !Object.isFrozen(integration.routes) || !Array.isArray(integration.routes))
    throw new Error("bad integration");
  const auth = validateAuth(integration.auth);
  const routes = integration.routes
    .map((route) => {
      tick();
      return copyRoute(route, id, routeIds);
    })
    .sort(routeCompare);
  return { id, auth, routes, needsCredential: routes.some((route) => route.credentialRequired) };
}
function copyRoute(route: CogsEgressRoute, integrationId: string, routeIds: Set<string>): CopiedRoute {
  if (!Object.isFrozen(route) || !Object.isFrozen(route.pathMatch)) throw new Error("bad route");
  if (route.integrationId !== integrationId || route.injectAuth !== route.credentialRequired)
    throw new Error("bad route integration");
  const method = route.method === "GET" || route.method === "POST" ? route.method : undefined;
  if (
    method === undefined ||
    route.pathMatch.kind !== "safe_regex" ||
    route.pathMatch.value.length > 4096 ||
    !route.pathMatch.value.startsWith("^") ||
    !route.pathMatch.value.endsWith("$")
  )
    throw new Error("bad route match");
  const routeId = validOpaque(route.routeId);
  if (routeIds.has(routeId)) throw new Error("duplicate route");
  routeIds.add(routeId);
  const host = validDnsHost(route.host);
  return {
    integrationId,
    routeId,
    host,
    port: port(route.port),
    method,
    pathRegex: route.pathMatch.value,
    credentialRequired: route.credentialRequired,
  };
}
function validateAuth(auth: CogsEgressAuthRef): CopiedAuth {
  if (!Object.isFrozen(auth)) throw new Error("bad auth");
  const handle = validSecretHandle(auth.secretHandle);
  if (auth.type === "basic_header") {
    if (auth.header !== "Authorization") throw new Error("bad basic auth");
    return Object.freeze({ type: auth.type, header: "Authorization", secretHandle: handle });
  }
  if (auth.type === "bearer_header") {
    if (auth.header !== "Authorization" || auth.prefix !== "Bearer ") throw new Error("bad bearer auth");
    return Object.freeze({ type: auth.type, header: "Authorization", prefix: "Bearer ", secretHandle: handle });
  }
  const header = boundedText(auth.header, 1, 64);
  if (header !== header.toLowerCase() || !apiKeyHeader.test(header) || forbiddenHeaders.has(header)) {
    throw new Error("bad api key auth");
  }
  if (auth.type !== "api_key_header") throw new Error("bad auth type");
  return Object.freeze({ type: auth.type, header, prefix: boundedText(auth.prefix, 0, 128), secretHandle: handle });
}
function credentialHeader(auth: CopiedAuth, credential: CogsEnvoyCredentialValue): Header {
  if (auth.type === "bearer_header" && credential.type === "bearer")
    return Object.freeze({ name: auth.header.toLowerCase(), value: `${auth.prefix}${secret(credential.token)}` });
  if (auth.type === "api_key_header" && credential.type === "api_key")
    return Object.freeze({ name: auth.header.toLowerCase(), value: `${auth.prefix}${secret(credential.value)}` });
  if (auth.type === "basic_header" && credential.type === "basic")
    return Object.freeze({ name: "authorization", value: `Basic ${basicSecret(credential.base64)}` });
  throw new Error("wrong credential");
}
function parseAuthzTarget(value: string): { address: string; port: number } {
  const match = value.match(authzTarget);
  if (match === null) throw new Error("bad authz target");
  return { address: "127.0.0.1", port: port(Number(match[2])) };
}
function authorityRegex(route: CopiedRoute): string {
  const host = regexEscape(route.host);
  return route.port === 443 ? `^${host}(?::443)?$` : `^${host}:${route.port}$`;
}
function routeCompare(left: CopiedRoute, right: CopiedRoute): number {
  return (
    left.host.localeCompare(right.host) ||
    left.port - right.port ||
    left.routeId.localeCompare(right.routeId) ||
    left.method.localeCompare(right.method) ||
    left.pathRegex.localeCompare(right.pathRegex)
  );
}
function regexEscape(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}
function validOpaque(value: string): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
  return value;
}
function boundedText(value: string, min: number, max: number): string {
  if (typeof value !== "string" || value.length < min || value.length > max || hasControl(value))
    throw new Error("bad text");
  return value;
}
function validDnsHost(value: string): string {
  const host = boundedText(value, 1, 253);
  if (host !== host.toLowerCase() || !dnsName.test(host)) throw new Error("bad host");
  return host;
}
function validSecretHandle(value: string): string {
  const handle = boundedText(value, 1, 512);
  if (!secretHandle.test(handle)) throw new Error("bad secret handle");
  return handle;
}
function secret(value: string): string {
  return visibleSecret(value, 1, maxCredentialBytes);
}
function visibleSecret(value: string, min: number, max: number): string {
  const text = boundedText(value, min, max);
  if (!visibleAscii.test(text)) throw new Error("bad secret");
  return text;
}
function basicSecret(value: string): string {
  const text = secret(value);
  if (!basicPayload.test(text)) throw new Error("bad basic credential");
  const decoded = Buffer.from(text, "base64");
  try {
    if (decoded.length === 0 || decoded.toString("base64") !== text || decoded.indexOf(0x3a) <= 0) {
      throw new Error("bad basic credential");
    }
    return text;
  } finally {
    decoded.fill(0);
  }
}
function port(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new Error("bad port");
  return value;
}
function hasControl(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 32 || code === 127) return true;
  }
  return false;
}
function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
