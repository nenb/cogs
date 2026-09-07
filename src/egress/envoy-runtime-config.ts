import { type CogsPolicyAuthorizer, requireCogsPolicyAllow } from "../policy/require-policy.ts";
import {
  type CogsEgressAuthRef,
  type CogsEgressIntegrationPlan,
  type CogsEgressRoute,
  type CogsEgressRoutePlan,
  validatedRoutePathMatch,
} from "./route-policy.ts";

const envoyType = "type.googleapis.com";
const maxBootstrapBytes = 1024 * 1024;
const maxCredentialBytes = 8192;
const maxDownstreamConnections = 32;
const maxInnerStreams = 8;
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

/** Renderer-owned v1, not a tuning API. Watermarks are not hard RSS/body-byte limits.
 * Requires one Envoy worker and an externally enforced shared worker/child 2 GiB cgroup.
 * Fixed-heap pressure only sheds; it neither bounds RSS nor establishes/checks the cgroup.
 * No cgroup monitor: v1.38.3 reads fixed mount-root paths, not process membership.
 */
export const cogsEnvoyBoundedV1 = deepFreeze({
  name: "cogs-egress-bounded-v1",
  downstreamConnections: maxDownstreamConnections,
  aggregateClusterBudget: 256,
  network: { per_connection_buffer_limit_bytes: 65536, per_connection_buffer_high_watermark_timeout: "60s" },
  internalPipe: { buffer_size_kb: 64 },
  inspector: { max_client_hello_size: 16384, close_connection_on_client_hello_parsing_errors: true },
  http1: { accept_http_10: false, allow_chunked_length: false },
  http2: {
    max_concurrent_streams: maxInnerStreams,
    initial_stream_window_size: 65536,
    initial_connection_window_size: 262144,
    hpack_table_size: 4096,
    // Omit the optional single-field override (PGV minimum 64 KiB). The codec
    // derives its field/list bound from the 32 KiB aggregate supplied by HCM/upstream.
    max_outbound_frames: 256,
    max_outbound_control_frames: 32,
    max_consecutive_inbound_frames_with_empty_payload: 1,
    max_inbound_priority_frames_per_stream: 100,
    max_inbound_window_update_frames_per_data_frame_sent: 10,
    allow_connect: false,
    allow_metadata: false,
  },
  commonHttp: {
    idle_timeout: "30s",
    max_connection_duration: "3600s", // Drain, NOT an absolute socket retirement deadline.
    max_stream_duration: "1800s",
    max_requests_per_connection: 1024,
    max_headers_count: 100,
    headers_with_underscores_action: "REJECT_REQUEST", // Downstream only; no response-header control in clusters.
  },
  earlyHeaders: [
    {
      name: "envoy.http.early_header_mutation.header_mutation",
      typed_config: {
        "@type": `${envoyType}/envoy.extensions.http.early_header_mutation.header_mutation.v3.HeaderMutation`,
        mutations: [{ remove_on_match: { key_matcher: { prefix: "x-envoy-" } } }, { remove: "grpc-timeout" }],
      },
    },
  ],
  overload: {
    refresh_interval: "0.1s",
    resource_monitors: [
      {
        name: "envoy.resource_monitors.global_downstream_max_connections",
        typed_config: {
          "@type": `${envoyType}/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig`,
          max_active_downstream_connections: String(maxDownstreamConnections),
        },
      },
      {
        name: "envoy.resource_monitors.fixed_heap",
        typed_config: {
          "@type": `${envoyType}/envoy.extensions.resource_monitors.fixed_heap.v3.FixedHeapConfig`,
          max_heap_size_bytes: "536870912",
        },
      },
    ],
    actions: [
      { name: "envoy.overload_actions.disable_http_keepalive", triggers: pressureTriggers(0.75) },
      { name: "envoy.overload_actions.stop_accepting_requests", triggers: pressureTriggers(0.85) },
    ],
    loadshed_points: [{ name: "envoy.load_shed_points.tcp_listener_accept", triggers: pressureTriggers(0.85) }],
  },
});
function pressureTriggers(heap: number) {
  return [{ name: "envoy.resource_monitors.fixed_heap", threshold: { value: heap } }];
}

/** Positive cold-connect pending capacity; budgets sum <=256, not 256 per route.
 * LOGICAL_DNS gives one host, one pool: conservatively allow c+1 connections per
 * cluster (Envoy's host/pool breaker exception). Internal endpoints aren't FDs.
 */
export function cogsEnvoyResourceAllocation(routes: number, authorities: number) {
  if (
    !Number.isInteger(routes) ||
    routes < 1 ||
    routes > 256 ||
    !Number.isInteger(authorities) ||
    authorities < 1 ||
    authorities > routes
  )
    throw new Error("bad resource graph");
  const b = Math.floor(cogsEnvoyBoundedV1.aggregateClusterBudget / routes);
  const connections = Math.min(8, b),
    requests = Math.min(16, b),
    pending = Math.min(4, b);
  const d = cogsEnvoyBoundedV1.downstreamConnections;
  const streams = d * cogsEnvoyBoundedV1.http2.max_concurrent_streams;
  const tunnels = Math.min(d, Math.floor(cogsEnvoyBoundedV1.aggregateClusterBudget / authorities));
  return deepFreeze({
    application: circuitBreakers(connections, requests, pending),
    authz: circuitBreakers(2, 32, 8),
    tunnel: circuitBreakers(tunnels, d, tunnels),
    envelope: {
      innerStreams: streams,
      outerAndInnerStreams: d + streams,
      applicationActive: routes * requests,
      applicationPending: routes * pending,
      applicationConnections: routes * (connections + 1),
      // Pool/downstream endpoints only: excludes listener, DNS, worker-side authz,
      // telemetry and other worker FDs. Not a shared-worker socket/RSS inventory.
      poolAndDownstreamSockets: d + routes * (connections + 1) + 3,
      internalEndpoints: 2 * authorities * (tunnels + 1),
    },
  });
}
function circuitBreakers(connections: number, requests: number, pending: number) {
  return {
    thresholds: [
      {
        priority: "DEFAULT",
        max_connections: connections,
        max_requests: requests,
        max_pending_requests: pending,
        max_retries: 0,
        max_connection_pools: 1,
        track_remaining: true,
      },
      {
        priority: "HIGH",
        max_connections: 0,
        max_requests: 0,
        max_pending_requests: 0,
        max_retries: 0,
        max_connection_pools: 0,
        track_remaining: true,
      },
    ],
  };
}
export function cogsEnvoyHcmBounds(inner: boolean) {
  return deepFreeze({
    codec_type: inner ? "AUTO" : "HTTP1",
    proxy_100_continue: false,
    use_remote_address: true,
    xff_num_trusted_hops: 0,
    early_header_mutation_extensions: cogsEnvoyBoundedV1.earlyHeaders,
    http_protocol_options: cogsEnvoyBoundedV1.http1,
    ...(inner ? { http2_protocol_options: cogsEnvoyBoundedV1.http2 } : {}),
    common_http_protocol_options: {
      ...cogsEnvoyBoundedV1.commonHttp,
      max_stream_duration: inner ? "1800s" : "3600s",
      max_requests_per_connection: inner ? 1024 : 1,
    },
    request_headers_timeout: "5s",
    stream_idle_timeout: "60s",
    stream_flush_timeout: "60s",
    drain_timeout: "1s",
    delayed_close_timeout: "1s",
    request_timeout: "0s",
  });
}

export interface CogsEnvoyRuntimeConfigOptions {
  readonly userId: string;
  readonly sessionId: string;
  readonly listenerPort: number;
  readonly routePlan: CogsEgressRoutePlan;
  readonly authzTarget: string;
  readonly internalAuthzToken: string;
  readonly policyAuthorizer?: CogsPolicyAuthorizer;
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

const runtimeConfigFailureCauses = new WeakMap<CogsEnvoyRuntimeConfigError, unknown>();

/** Internal composition seam; public errors remain generic and cause-free. */
export function envoyRuntimeConfigFailureCause(error: unknown): unknown {
  return error instanceof CogsEnvoyRuntimeConfigError ? runtimeConfigFailureCauses.get(error) : undefined;
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
    const userId = validOpaque(captured.userId);
    const sessionId = validOpaque(captured.sessionId);
    const listenerPort = port(captured.listenerPort);
    const authorization = parseAuthzTarget(captured.authzTarget);
    const internalToken = visibleSecret(captured.internalAuthzToken, 16, 256);
    // gRPC initial metadata is not the route-header formatter seam; deny ambiguity.
    if (internalToken.includes("%")) throw new Error("bad internal token");
    try {
      if (
        captured.policyAuthorizer !== undefined &&
        (typeof captured.policyAuthorizer !== "function" || !Object.isFrozen(captured.policyAuthorizer))
      )
        throw new Error("bad policy authorizer");
    } catch {
      throw new Error("bad policy authorizer");
    }
    const integrations = copyPlan(captured.routePlan);
    const credentialed = integrations.filter((integration) => integration.needsCredential);
    const credentials = new Map<string, Header>();
    let result: T | undefined;
    let operationCalled = false;
    try {
      await withCredentials(
        0,
        credentialed,
        userId,
        sessionId,
        captured.policyAuthorizer,
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
  } catch (error) {
    const failure = new CogsEnvoyRuntimeConfigError();
    runtimeConfigFailureCauses.set(failure, error);
    throw failure;
  }
}

async function withCredentials(
  index: number,
  integrations: readonly CopiedIntegration[],
  userId: string,
  sessionId: string,
  authorizer: CogsPolicyAuthorizer | undefined,
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
  requireCogsPolicyAllow(
    {
      version: "cogs.policy/v1alpha1",
      action: "secret.use",
      user: userId,
      session: sessionId,
      resource: "egress_integration_credential",
      attributes: { secret_class: "egress_integration_credential", integration_id: integration.id },
    },
    authorizer,
  );
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
      await withCredentials(
        index + 1,
        integrations,
        userId,
        sessionId,
        authorizer,
        source,
        credentials,
        () => active && parentActive(),
        next,
      );
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
  const allocation = cogsEnvoyResourceAllocation(allRoutes.length, groups.size);
  for (const route of allRoutes) clusters.push(upstreamCluster(route, allocation.application));
  for (const [authority, routes] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const first = routes[0];
    if (first === undefined) continue;
    listeners.push(innerListener(authority, sessionId, routes, credentials, internalToken));
    clusters.push(tunnelCluster(first, allocation.tunnel));
  }
  const bootstrap = deepFreeze({
    layered_runtime: cogsEnvoyLiteralHeaderRuntime,
    overload_manager: cogsEnvoyBoundedV1.overload,
    bootstrap_extensions: [
      {
        name: "envoy.bootstrap.internal_listener",
        typed_config: {
          "@type": `${envoyType}/envoy.extensions.bootstrap.internal_listener.v3.InternalListener`,
          ...cogsEnvoyBoundedV1.internalPipe,
        },
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
    ...cogsEnvoyBoundedV1.network,
    listener_filters_timeout: "5s",
    continue_on_listener_filters_timeout: false,
    listener_filters: [
      {
        name: "envoy.filters.listener.tls_inspector",
        typed_config: {
          "@type": `${envoyType}/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector`,
          ...cogsEnvoyBoundedV1.inspector,
        },
      },
    ],
    filter_chains: [
      {
        filter_chain_match: { server_names: [first.host], transport_protocol: "tls" },
        transport_socket_connect_timeout: "5s",
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
              [extAuthz(false, token), responseTrailerMutation(credentials), router()],
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
    // Stream GET bodies and Git POST/pack bytes; no cumulative body ceiling or replay.
    // Independent HCM idle/absolute/flush timers replace the whole-response timer.
    route: { cluster: `upstream_${route.routeId}`, timeout: "0s" },
    request_headers_to_remove: removeHeaders(credential),
    // Block direct named-header reflection, not arbitrary headers/bodies or upstream storage.
    response_headers_to_remove: removeHeaders(credential),
    ...(credential === undefined
      ? {}
      : {
          request_headers_to_add: [
            {
              header: { key: credential.name, value: cogsEnvoyLiteralHeaderValue(credential.value) },
              append_action: "OVERWRITE_IF_EXISTS_OR_ADD",
            },
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
function responseTrailerMutation(credentials: ReadonlyMap<string, Header>): Json {
  const names = new Set(removeHeaders(undefined));
  for (const credential of credentials.values()) for (const name of removeHeaders(credential)) names.add(name);
  return {
    name: "envoy.filters.http.header_mutation",
    typed_config: {
      "@type": `${envoyType}/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation`,
      mutations: { response_trailers_mutations: [...names].sort().map((remove) => ({ remove })) },
    },
  };
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
      allowed_headers: matcher("proxy-authorization"),
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
    ...cogsEnvoyHcmBounds(completion),
    // Preserve original bytes for reject-ambiguous authz; never erase traversal evidence.
    normalize_path: false,
    merge_slashes: false,
    path_with_escaped_slashes_action: "REJECT_REQUEST",
    stream_error_on_invalid_http_message: true,
    max_request_headers_kb: 32,
    route_config: { name: `${name}_routes`, virtual_hosts: virtualHosts },
    ...(completion
      ? {
          access_log: [
            {
              name: "envoy.access_loggers.stdout",
              filter: {
                metadata_filter: {
                  matcher: {
                    filter: "envoy.filters.http.ext_authz",
                    path: [{ key: "x-cogs-intent-id" }],
                    value: { present_match: true },
                  },
                  match_if_key_not_found: false,
                },
              },
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
    ...cogsEnvoyBoundedV1.network,
    circuit_breakers: circuitBreakers(2, 32, 8),
    typed_extension_protocol_options: {
      "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
        "@type": `${envoyType}/envoy.extensions.upstreams.http.v3.HttpProtocolOptions`,
        common_http_protocol_options: {
          ...cogsEnvoyBoundedV1.commonHttp,
          max_stream_duration: "1s",
          max_response_headers_kb: 32,
        },
        explicit_http_config: { http2_protocol_options: { ...cogsEnvoyBoundedV1.http2, max_concurrent_streams: 32 } },
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
function upstreamCluster(route: CopiedRoute, breakers: ReturnType<typeof circuitBreakers>): Json {
  const endpointHost = route.host === "localhost" ? "127.0.0.1" : route.host;
  return {
    name: `upstream_${route.routeId}`,
    type: "LOGICAL_DNS",
    dns_lookup_family: "AUTO",
    connect_timeout: "2s",
    ...cogsEnvoyBoundedV1.network,
    circuit_breakers: breakers,
    load_assignment: {
      cluster_name: `upstream_${route.routeId}`,
      endpoints: [
        {
          lb_endpoints: [
            { endpoint: { address: { socket_address: { address: endpointHost, port_value: route.port } } } },
          ],
        },
      ],
    },
    typed_extension_protocol_options: {
      "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
        "@type": `${envoyType}/envoy.extensions.upstreams.http.v3.HttpProtocolOptions`,
        common_http_protocol_options: { ...cogsEnvoyBoundedV1.commonHttp, max_response_headers_kb: 32 },
        auto_config: {
          http_protocol_options: cogsEnvoyBoundedV1.http1,
          http2_protocol_options: cogsEnvoyBoundedV1.http2,
        },
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
function tunnelCluster(route: CopiedRoute, breakers: ReturnType<typeof circuitBreakers>): Json {
  // Raw TCP pools also use max_pending_requests as a connection limit; max_requests
  // does not count CONNECTs. Outer H1's single request supplies the live tunnel cap.
  return {
    ...cogsEnvoyBoundedV1.network,
    circuit_breakers: breakers,
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
    ...cogsEnvoyBoundedV1.network,
    ignore_global_conn_limit: false,
    bypass_overload_manager: false,
    tcp_backlog_size: maxDownstreamConnections,
    max_connections_to_accept_per_socket_event: 1,
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
      check_settings: { context_extensions: ctx, disable_request_body_buffering: true },
    },
  };
}
function router(): Json {
  return {
    name: "envoy.filters.http.router",
    typed_config: {
      "@type": `${envoyType}/envoy.extensions.filters.http.router.v3.Router`,
      respect_expected_rq_timeout: false,
    },
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
    pathRegex: validatedRoutePathMatch(route).value,
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
// v1.38.3 defaults this guard OFF. Legacy metadata translation runs before %%
// decoding and would rewrite even escaped DYNAMIC_METADATA/PER_REQUEST_STATE text.
export const cogsEnvoyLiteralHeaderRuntime = deepFreeze({
  layers: [
    {
      name: "cogs-literal-header-format",
      static_layer: { "envoy.reloadable_features.remove_legacy_route_formatter": true },
    },
  ],
});
/** v1.38.3 (0ebfcfe5): HeaderParser consumes value(), not raw_value().
 * SubstitutionFormatParser::parse consumes %% as one literal %, before commands.
 * Encode the complete prefix+value exactly once; never interpolate secret bytes.
 */
export function cogsEnvoyLiteralHeaderValue(value: string): string {
  if (!/^[\x20-\x7e]+$/.test(value)) throw new Error("bad header bytes");
  const encoded = value.replaceAll("%", "%%");
  if (encoded.length > 16384) throw new Error("header formatter too large");
  return encoded;
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
