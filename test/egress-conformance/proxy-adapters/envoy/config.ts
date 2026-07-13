import { isIP } from "node:net";

const opaqueId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const dnsName = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const methodToken = /^[A-Z][A-Z0-9!#$&'*+.^_`|~-]{0,31}$/;
const headerName = /^[a-z][a-z0-9-]{0,63}$/;
const pemLimit = 1024 * 1024;
const envoyType = "type.googleapis.com";

export type CredentialConfig =
  | { kind: "bearer"; value: string }
  | { kind: "basic"; value: string }
  | { kind: "api-key"; header: string; value: string };

export interface EnvoyRouteConfig {
  id: string;
  protocol: "http" | "https";
  host: string;
  port: number;
  methods: readonly string[];
  pathPrefix: string;
  upstreamAddress: string;
  upstreamPort: number;
  upstreamCaCertificatePem?: string;
  credential: CredentialConfig;
}

export interface EnvoyCandidateConfigInput {
  caseId: string;
  sessionId: string;
  listenerAddress: "127.0.0.1" | "0.0.0.0";
  listenerPort: number;
  authorizationGrpcTarget: string;
  proxyCertificatePem: string;
  proxyPrivateKeyPem: string;
  routes: readonly EnvoyRouteConfig[];
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function hasControlCharacters(value: string, allowNewlines: boolean): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if ((code < 32 && !(allowNewlines && (code === 10 || code === 13))) || code === 127) return true;
  }
  return false;
}

function assertSafeText(value: string, label: string, maximum = 4096): void {
  if (value.length === 0 || value.length > maximum || hasControlCharacters(value, false)) {
    throw new Error(`${label} is empty, oversized, or contains control characters`);
  }
}

function validatePem(value: string, kind: "certificate" | "private-key", label: string): void {
  if (value.length === 0 || value.length > pemLimit || hasControlCharacters(value, true)) {
    throw new Error(`${label} is empty, oversized, or contains invalid control characters`);
  }
  const certificate = value.includes("-----BEGIN CERTIFICATE-----") && value.includes("-----END CERTIFICATE-----");
  const privateKey = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(value);
  if (kind === "certificate" ? !certificate || privateKey : !privateKey || certificate) {
    throw new Error(`${label} is not isolated ${kind} PEM material`);
  }
}

function validatePort(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(`${label} must be a valid TCP port`);
}

function validateHost(value: string): void {
  if (value !== value.toLowerCase() || !dnsName.test(value) || isIP(value) !== 0 || value.endsWith(".")) {
    throw new Error("route host must be one exact, lowercase DNS name");
  }
}

function validatePathPrefix(value: string): void {
  assertSafeText(value, "route path prefix", 2048);
  if (
    !value.startsWith("/") ||
    value.includes("?") ||
    value.includes("#") ||
    value.includes("\\") ||
    value.includes("%") ||
    value.includes("//") ||
    value.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    throw new Error(
      "route path prefix must be canonical and contain no encoded, query, fragment, slash, or dot ambiguity",
    );
  }
}

function credentialHeader(credential: CredentialConfig): { name: string; value: string } {
  assertSafeText(credential.value, "credential value", 8192);
  if (credential.kind === "bearer") {
    if (!/^Bearer [^\s]+$/.test(credential.value)) throw new Error("bearer credential must use the Bearer scheme");
    return { name: "authorization", value: credential.value };
  }
  if (credential.kind === "basic") {
    if (!/^Basic [A-Za-z0-9+/]+={0,2}$/.test(credential.value)) {
      throw new Error("basic credential must use a canonical Basic value");
    }
    return { name: "authorization", value: credential.value };
  }
  const name = credential.header.toLowerCase();
  if (
    credential.header !== name ||
    !headerName.test(name) ||
    new Set(["authorization", "proxy-authorization", "host", "connection", "content-length", "transfer-encoding"]).has(
      name,
    )
  ) {
    throw new Error("API-key header is invalid or security-sensitive");
  }
  return { name, value: credential.value };
}

function parseAuthorizationGrpcTarget(value: string): { address: string; port: number } {
  const match = value.match(/^(127\.0\.0\.1):([0-9]{1,5})$/);
  const port = Number(match?.[2]);
  if (match === null || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("authorization gRPC target must be an uncredentialed loopback host and explicit port");
  }
  return { address: match[1] ?? "127.0.0.1", port };
}

function validateInput(input: EnvoyCandidateConfigInput): EnvoyRouteConfig[] {
  if (!opaqueId.test(input.caseId) || !opaqueId.test(input.sessionId))
    throw new Error("case and session IDs must be opaque IDs");
  validatePort(input.listenerPort, "listener port");
  validatePem(input.proxyCertificatePem, "certificate", "proxy certificate");
  validatePem(input.proxyPrivateKeyPem, "private-key", "proxy private key");
  if (!Array.isArray(input.routes) || input.routes.length === 0 || input.routes.length > 128) {
    throw new Error("one to 128 routes are required");
  }
  const routes = structuredClone(input.routes).sort((left, right) => left.id.localeCompare(right.id));
  const ids = new Set<string>();
  const policyKeys = new Set<string>();
  for (const route of routes) {
    if (!opaqueId.test(route.id) || ids.has(route.id)) throw new Error("route IDs must be unique opaque IDs");
    ids.add(route.id);
    validateHost(route.host);
    validatePort(route.port, "route port");
    validatePort(route.upstreamPort, "upstream port");
    if (isIP(route.upstreamAddress) === 0 && !dnsName.test(route.upstreamAddress)) {
      throw new Error("trusted upstream address must be a literal IP or exact DNS name");
    }
    if (
      !Array.isArray(route.methods) ||
      route.methods.length === 0 ||
      new Set(route.methods).size !== route.methods.length
    ) {
      throw new Error("route methods must be a non-empty unique list");
    }
    for (const method of route.methods) {
      if (!methodToken.test(method) || method === "CONNECT")
        throw new Error("route methods must be canonical non-CONNECT tokens");
    }
    validatePathPrefix(route.pathPrefix);
    credentialHeader(route.credential);
    if (route.protocol === "https") {
      if (route.upstreamCaCertificatePem === undefined)
        throw new Error("HTTPS routes require an upstream CA certificate");
      validatePem(route.upstreamCaCertificatePem, "certificate", "upstream CA certificate");
    } else if (route.upstreamCaCertificatePem !== undefined) {
      throw new Error("HTTP routes must not configure TLS trust material");
    }
    const policyKey = `${route.protocol}|${route.host}|${route.port}|${[...route.methods].sort().join(",")}|${route.pathPrefix}`;
    if (policyKeys.has(policyKey)) throw new Error("duplicate route policy is not allowed");
    policyKeys.add(policyKey);
  }
  return routes;
}

function matcherExact(value: string): Json {
  return { patterns: [{ exact: value }] };
}

function authContext(
  mode: "capability" | "authorize",
  input: EnvoyCandidateConfigInput,
  routeId?: string,
  requireCapability?: boolean,
): Record<string, string> {
  return {
    "cogs.mode": mode,
    "cogs.case_id": input.caseId,
    "cogs.session_id": input.sessionId,
    ...(routeId === undefined ? {} : { "cogs.route_id": routeId }),
    ...(requireCapability === undefined
      ? {}
      : {
          "cogs.require_capability": requireCapability ? "true" : "false",
          "cogs.credential_required": "true",
        }),
  };
}

function extAuthzFilter(capability: boolean): Json {
  return {
    name: "envoy.filters.http.ext_authz",
    typed_config: {
      "@type": `${envoyType}/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz`,
      grpc_service: { envoy_grpc: { cluster_name: "cogs_authz" }, timeout: "1s" },
      transport_api_version: "V3",
      failure_mode_allow: false,
      validate_mutations: true,
      ...(capability ? { allowed_headers: matcherExact("proxy-authorization") } : {}),
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

function routeAuthOverride(context: Record<string, string>): Json {
  return {
    "envoy.filters.http.ext_authz": {
      "@type": `${envoyType}/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute`,
      check_settings: { context_extensions: context },
    },
  };
}

function hardenedHcm(
  name: string,
  virtualHosts: Json[],
  filters: Json[],
  accessLog: false | "proxy" | "completion",
): Json {
  return {
    "@type": `${envoyType}/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager`,
    stat_prefix: name,
    codec_type: "AUTO",
    normalize_path: true,
    merge_slashes: false,
    path_with_escaped_slashes_action: "REJECT_REQUEST",
    stream_error_on_invalid_http_message: true,
    max_request_headers_kb: 32,
    common_http_protocol_options: {
      max_headers_count: 100,
      headers_with_underscores_action: "REJECT_REQUEST",
    },
    route_config: { name: `${name}_routes`, virtual_hosts: virtualHosts },
    ...(accessLog
      ? {
          access_log: [
            {
              name: "envoy.access_loggers.stdout",
              typed_config: {
                "@type": `${envoyType}/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog`,
                log_format: {
                  json_format:
                    accessLog === "completion"
                      ? {
                          event: "request-complete",
                          intent_id: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:x-cogs-intent-id)%",
                          route_id: "%ROUTE_NAME%",
                          response_code: "%RESPONSE_CODE%",
                          duration_ms: "%DURATION%",
                        }
                      : {
                          event: "proxy-request",
                          route_id: "%ROUTE_NAME%",
                          response_code: "%RESPONSE_CODE%",
                          response_flags: "%RESPONSE_FLAGS%",
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

function envoyRoute(route: EnvoyRouteConfig, input: EnvoyCandidateConfigInput, inner: boolean): Json[] {
  const credential = credentialHeader(route.credential);
  const escapedHost = route.host.replaceAll(".", "\\.");
  return route.methods.map((method) => ({
    name: route.id,
    match: {
      prefix: route.pathPrefix,
      headers: [
        { name: ":method", string_match: { exact: method } },
        { name: ":authority", string_match: { safe_regex: { regex: `^${escapedHost}(?::${route.port})?$` } } },
      ],
    },
    route: {
      cluster: `upstream_${route.id}`,
      timeout: "30s",
    },
    request_headers_to_remove: ["authorization", "proxy-authorization", credential.name],
    request_headers_to_add: [
      { header: { key: credential.name, value: credential.value }, append_action: "OVERWRITE_IF_EXISTS_OR_ADD" },
    ],
    typed_per_filter_config: routeAuthOverride(authContext("authorize", input, route.id, !inner)),
  }));
}

function upstreamCluster(route: EnvoyRouteConfig): Json {
  return {
    name: `upstream_${route.id}`,
    type: "STATIC",
    connect_timeout: "2s",
    load_assignment: {
      cluster_name: `upstream_${route.id}`,
      endpoints: [
        {
          lb_endpoints: [
            {
              endpoint: {
                address: { socket_address: { address: route.upstreamAddress, port_value: route.upstreamPort } },
              },
            },
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
    ...(route.protocol === "https"
      ? {
          transport_socket: {
            name: "envoy.transport_sockets.tls",
            typed_config: {
              "@type": `${envoyType}/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext`,
              sni: route.host,
              common_tls_context: {
                alpn_protocols: ["h2", "http/1.1"],
                validation_context: {
                  trusted_ca: { inline_string: route.upstreamCaCertificatePem ?? "" },
                  match_typed_subject_alt_names: [{ san_type: "DNS", matcher: { exact: route.host } }],
                },
              },
            },
          },
        }
      : {}),
  };
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

export function generateEnvoyConfig(input: EnvoyCandidateConfigInput): Readonly<Json> {
  const routes = validateInput(input);
  const authorization = parseAuthorizationGrpcTarget(input.authorizationGrpcTarget);
  const physicalRoutes = routes.filter((route) => route.protocol === "http");
  const secureGroups = Map.groupBy(
    routes.filter((route) => route.protocol === "https"),
    (route) => `${route.host}:${route.port}`,
  );
  const routerFilter: Json = {
    name: "envoy.filters.http.router",
    typed_config: { "@type": `${envoyType}/envoy.extensions.filters.http.router.v3.Router` },
  };

  const outerRoutes: Json[] = physicalRoutes.flatMap((route) => envoyRoute(route, input, false));
  for (const [authority, grouped] of [...secureGroups.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const first = grouped[0];
    if (first === undefined) continue;
    outerRoutes.push({
      name: `connect.${first.host}.${first.port}`,
      match: {
        connect_matcher: {},
        headers: [{ name: ":authority", string_match: { exact: authority } }],
      },
      route: {
        cluster: `tunnel_${first.id}`,
        timeout: "0s",
        upgrade_configs: [{ upgrade_type: "CONNECT", connect_config: {} }],
      },
      request_headers_to_remove: ["proxy-authorization", "authorization"],
      typed_per_filter_config: routeAuthOverride(authContext("capability", input)),
    });
  }

  const listeners: Json[] = [
    {
      name: "forward_proxy",
      address: { socket_address: { protocol: "TCP", address: input.listenerAddress, port_value: input.listenerPort } },
      filter_chains: [
        {
          filters: [
            {
              name: "envoy.filters.network.http_connection_manager",
              typed_config: hardenedHcm(
                "forward_proxy",
                [{ name: "explicit_proxy", domains: ["*"], routes: outerRoutes }],
                [extAuthzFilter(true), routerFilter],
                "proxy",
              ),
            },
          ],
        },
      ],
    },
  ];

  const clusters: Json[] = [
    {
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
              {
                endpoint: {
                  address: { socket_address: { address: authorization.address, port_value: authorization.port } },
                },
              },
            ],
          },
        ],
      },
    },
    ...routes.map(upstreamCluster),
  ];

  for (const [, grouped] of [...secureGroups.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const first = grouped[0];
    if (first === undefined) continue;
    const internalName = `mitm_${first.id}`;
    listeners.push({
      name: internalName,
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
                    certificate_chain: { inline_string: input.proxyCertificatePem },
                    private_key: { inline_string: input.proxyPrivateKeyPem },
                  },
                ],
              },
            },
          },
          filters: [
            {
              name: "envoy.filters.network.http_connection_manager",
              typed_config: hardenedHcm(
                `mitm_${first.id}`,
                [
                  {
                    name: `mitm_${first.host}_${first.port}`,
                    domains: [first.host, `${first.host}:${first.port}`],
                    routes: grouped.flatMap((route) => envoyRoute(route, input, true)),
                  },
                ],
                [extAuthzFilter(false), routerFilter],
                "completion",
              ),
            },
          ],
        },
      ],
    });
    clusters.push({
      name: `tunnel_${first.id}`,
      type: "STATIC",
      connect_timeout: "2s",
      load_assignment: {
        cluster_name: `tunnel_${first.id}`,
        endpoints: [
          {
            lb_endpoints: [
              {
                endpoint: {
                  address: { envoy_internal_address: { server_listener_name: internalName } },
                },
              },
            ],
          },
        ],
      },
    });
  }

  return deepFreeze({
    bootstrap_extensions: [
      {
        name: "envoy.bootstrap.internal_listener",
        typed_config: { "@type": `${envoyType}/envoy.extensions.bootstrap.internal_listener.v3.InternalListener` },
      },
    ],
    static_resources: { listeners, clusters },
  });
}

export function renderEnvoyConfig(input: EnvoyCandidateConfigInput): string {
  return `${JSON.stringify(generateEnvoyConfig(input), null, 2)}\n`;
}
