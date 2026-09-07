import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as httpsServer } from "node:https";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { connect as tlsConnect } from "node:tls";
import { promisify } from "node:util";
import { openEgressAuditWal } from "../src/egress/audit-wal.ts";
import { createNodeCogsEnvoyProcessPort, nodeEnvoyProcessPorts } from "../src/egress/envoy-process.ts";
import {
  type CogsEnvoyCredentialSource,
  type CogsEnvoyCredentialValue,
  CogsEnvoyRuntimeConfigError,
  type CogsEnvoyRuntimeConfigOptions,
  cogsEnvoyBoundedV1,
  cogsEnvoyHcmBounds,
  cogsEnvoyResourceAllocation,
  envoyRuntimeConfigFailureCause,
  withCogsEnvoyRuntimeConfig,
} from "../src/egress/envoy-runtime-config.ts";
import { startCogsExtAuthzServer } from "../src/egress/ext-authz-server.ts";
import { encodeProxyAuthorizationBasic } from "../src/egress/proxy-capability.ts";
import type { CogsEgressAuthRef, CogsEgressRoutePlan } from "../src/egress/route-policy.ts";

const token = "internal-authz-token";
const baseOptions = (): CogsEnvoyRuntimeConfigOptions => ({
  userId: "user-1",
  sessionId: "session-1",
  listenerPort: 15001,
  authzTarget: "127.0.0.1:18080",
  internalAuthzToken: token,
  routePlan: plan(),
});

function plan(extra?: { auth?: CogsEgressAuthRef; route?: Partial<Route>; id?: string }): CogsEgressRoutePlan {
  const id = extra?.id ?? "github";
  return deepFreeze({
    routeCount: 2,
    integrations: [
      {
        id,
        presetRevision: `sha256:${"a".repeat(64)}`,
        auth: extra?.auth ?? {
          type: "bearer_header",
          header: "Authorization",
          prefix: "Bearer ",
          placeholder: "COGS_PLACEHOLDER_TOKEN",
          secretHandle: "users/session/github-token",
        },
        routes: [
          route({
            integrationId: id,
            routeId: "route-b",
            method: "POST",
            pathPattern: "/owner/repo.git/git-upload-pack",
            queryPolicy: { mode: "deny" },
            pathMatch: { kind: "safe_regex", value: "^/owner/repo\\.git/git-upload-pack$" },
            ...extra?.route,
          }),
          route({
            integrationId: id,
            routeId: "route-a",
            method: "GET",
            pathMatch: { kind: "safe_regex", value: "^/owner/repo\\.git/info/refs\\?service=git-upload-pack$" },
            ...extra?.route,
          }),
        ],
      },
    ],
  });
}

function multiIntegrationPlan(): CogsEgressRoutePlan {
  return deepFreeze({
    routeCount: 4,
    integrations: [
      plan().integrations[0] as NonNullable<ReturnType<typeof plan>["integrations"][0]>,
      {
        id: "npm",
        presetRevision: `sha256:${"b".repeat(64)}`,
        auth: {
          type: "api_key_header",
          header: "x-api-key",
          prefix: "Token ",
          placeholder: "COGS_PLACEHOLDER_NPM",
          secretHandle: "organizations/acme/npm-token",
        },
        routes: [
          route({
            integrationId: "npm",
            routeId: "route-npm",
            host: "registry.npmjs.org",
            port: 443,
            method: "GET",
            pathPattern: "/left-pad",
            queryPolicy: { mode: "deny" },
            pathMatch: { kind: "safe_regex", value: "^/left-pad$" },
          }),
        ],
      },
      {
        id: "pypi",
        presetRevision: `sha256:${"c".repeat(64)}`,
        auth: {
          type: "bearer_header",
          header: "Authorization",
          prefix: "Bearer ",
          placeholder: "COGS_PLACEHOLDER_UNUSED",
          secretHandle: "organizations/acme/unused",
        },
        routes: [
          route({
            integrationId: "pypi",
            routeId: "route-pypi",
            host: "pypi.org",
            port: 443,
            method: "GET",
            pathPattern: "/simple/pkg/",
            queryPolicy: { mode: "deny" },
            pathMatch: { kind: "safe_regex", value: "^/simple/pkg/$" },
            injectAuth: false,
            credentialRequired: false,
          }),
        ],
      },
    ],
  });
}

type Route = ReturnType<typeof route>;
function route(extra: Record<string, unknown>) {
  return deepFreeze({
    integrationId: "github",
    ruleName: "fetch",
    routeId: "route-a",
    host: "github.com",
    port: 443,
    method: "GET",
    pathPattern: "/owner/repo.git/info/refs",
    pathStrategy: "exact",
    queryPolicy: { mode: "exact", values: ["service=git-upload-pack"], canonical: "service=git-upload-pack" },
    pathMatch: { kind: "safe_regex", value: "^/owner/repo\\.git/info/refs\\?service=git-upload-pack$" },
    injectAuth: true,
    credentialRequired: true,
    ...extra,
  } as const);
}

function source(
  value: CogsEnvoyCredentialValue = { type: "bearer", token: "secret-token" },
  seen: string[] = [],
): CogsEnvoyCredentialSource {
  return {
    withCredential: async (request, consume) => {
      seen.push(`${request.integrationId}:${request.authType}:${request.secretHandle}`);
      await consume(value);
    },
  };
}

async function render(options = baseOptions(), credentialSource = source()) {
  let active = false;
  let rendered: unknown;
  const result = await withCogsEnvoyRuntimeConfig(options, credentialSource, async (config) => {
    active = true;
    rendered = config;
    assert.equal(Object.isFrozen(config), true);
    assert.deepEqual(config.paths, {
      bootstrap: "/run/cogs/egress/envoy/bootstrap.json",
      proxyCertificate: "/run/cogs/egress/envoy/proxy-cert.pem",
      proxyPrivateKey: "/run/cogs/egress/envoy/proxy-key.pem",
      proxyCaCertificate: "/run/cogs/egress/envoy/proxy-ca.pem",
    });
    return "ok";
  });
  assert.equal(result, "ok");
  assert.equal(active, true);
  return rendered as { bootstrapJson: string; routeCount: number };
}

test("renders deterministic contained Envoy bootstrap JSON with loopback authz metadata", async () => {
  const seen: string[] = [];
  const config = await render(baseOptions(), source({ type: "bearer", token: "secret-token" }, seen));
  const same = await render(baseOptions(), source({ type: "bearer", token: "secret-token" }));
  assert.equal(config.bootstrapJson, same.bootstrapJson);
  assert.deepEqual(seen, ["github:bearer_header:users/session/github-token"]);
  assert.equal(config.routeCount, 2);
  const boot = JSON.parse(config.bootstrapJson);
  assert.equal(boot.static_resources.listeners.length, 2);
  assert.equal(boot.static_resources.clusters.length, 4);
  assert.equal(JSON.stringify(boot).includes("dynamic_forward_proxy"), false);
  assert.equal(JSON.stringify(boot).includes("ORIGINAL_DST"), false);
  assert.equal(JSON.stringify(boot).includes("direct_response"), false);
  const outer = boot.static_resources.listeners[0];
  assert.equal(outer.address.socket_address.address, "0.0.0.0");
  assert.equal(outer.address.socket_address.port_value, 15001);
  assert.equal(JSON.stringify(boot).includes("/run/cogs/egress/envoy/proxy-cert.pem"), true);
  assert.equal(JSON.stringify(boot).includes("-----BEGIN"), false);
  assert.equal(JSON.stringify(boot).includes("x-cogs-authz-token"), true);
  assert.equal(JSON.stringify(boot).includes(token), true);
  assert.equal(JSON.stringify(boot).includes("proxy-capability"), true);
  assert.equal(JSON.stringify(boot).includes("/etc/ssl/certs/ca-certificates.crt"), true);
  assert.equal(JSON.stringify(boot).includes("secret-token"), true);
  assert.equal(JSON.stringify(boot).includes("x-cogs-intent-id"), true);
  assert.equal(JSON.stringify(boot).includes("COGS_PLACEHOLDER"), false);
  assert.equal(JSON.stringify(boot).includes("users/session/github-token"), false);
  const outerHcm = outer.filter_chains[0].filters[0].typed_config;
  const outerFilter = outerHcm.http_filters[0].typed_config;
  assert.equal(outerFilter.failure_mode_allow, false);
  assert.deepEqual(outerFilter.grpc_service.initial_metadata, [{ key: "x-cogs-authz-token", value: token }]);
  assert.deepEqual(outerFilter.allowed_headers, { patterns: [{ exact: "proxy-authorization" }] });
  const connectRoute = outerHcm.route_config.virtual_hosts[0].routes[0];
  assert.deepEqual(connectRoute.match, {
    connect_matcher: {},
    headers: [{ name: ":authority", string_match: { exact: "github.com:443" } }],
  });
  assert.deepEqual(connectRoute.request_headers_to_remove, ["proxy-authorization", "authorization"]);
  assert.deepEqual(
    connectRoute.typed_per_filter_config["envoy.filters.http.ext_authz"].check_settings.context_extensions,
    {
      "cogs.mode": "capability",
      "cogs.case_id": "proxy-capability",
      "cogs.session_id": "session-1",
      "cogs.require_capability": "true",
      "cogs.credential_required": "false",
    },
  );
  const inner = boot.static_resources.listeners[1];
  const innerHcm = inner.filter_chains[0].filters[0].typed_config;
  assert.equal(innerHcm.normalize_path, false);
  assert.equal(innerHcm.merge_slashes, false);
  assert.equal(innerHcm.path_with_escaped_slashes_action, "REJECT_REQUEST");
  const innerFilter = innerHcm.http_filters[0].typed_config;
  assert.deepEqual(innerFilter.allowed_headers, { patterns: [{ exact: "proxy-authorization" }] });
  assert.deepEqual(innerFilter.disallowed_headers.patterns, [
    { exact: "authorization" },
    { exact: "cookie" },
    { exact: "proxy-authorization" },
  ]);
  const completionAccessLog = innerHcm.access_log[0];
  assert.deepEqual(completionAccessLog.filter, {
    metadata_filter: {
      matcher: {
        filter: "envoy.filters.http.ext_authz",
        path: [{ key: "x-cogs-intent-id" }],
        value: { present_match: true },
      },
      match_if_key_not_found: false,
    },
  });
  assert.deepEqual(Object.keys(completionAccessLog.typed_config.log_format.json_format).sort(), [
    "duration_ms",
    "event",
    "intent_id",
    "response_code",
    "route_id",
  ]);
  const innerRoute = innerHcm.route_config.virtual_hosts[0].routes.find(
    (item: { name: string }) => item.name === "route-a",
  );
  assert.deepEqual(innerRoute.match.headers, [
    { name: ":method", string_match: { exact: "GET" } },
    { name: ":authority", string_match: { safe_regex: { regex: "^github\\.com(?::443)?$" } } },
    {
      name: ":path",
      string_match: { safe_regex: { regex: "^/owner/repo\\.git/info/refs\\?service=git-upload-pack$" } },
    },
  ]);
  assert.deepEqual(innerRoute.request_headers_to_remove, ["authorization", "proxy-authorization"]);
  assert.deepEqual(innerRoute.response_headers_to_remove, ["authorization", "proxy-authorization"]);
  assert.deepEqual(innerRoute.request_headers_to_add, [
    { header: { key: "authorization", value: "Bearer secret-token" }, append_action: "OVERWRITE_IF_EXISTS_OR_ADD" },
  ]);
  assert.deepEqual(
    innerRoute.typed_per_filter_config["envoy.filters.http.ext_authz"].check_settings.context_extensions,
    {
      "cogs.mode": "authorize",
      "cogs.case_id": "route-a",
      "cogs.session_id": "session-1",
      "cogs.route_id": "route-a",
      "cogs.require_capability": "false",
      "cogs.credential_required": "true",
    },
  );
  const upstream = boot.static_resources.clusters.find(
    (cluster: { name: string }) => cluster.name === "upstream_route-a",
  );
  assert.equal(upstream.type, "LOGICAL_DNS");
  assert.equal(
    upstream.load_assignment.endpoints[0].lb_endpoints[0].endpoint.address.socket_address.address,
    "github.com",
  );
  assert.equal(upstream.transport_socket.typed_config.sni, "github.com");
  assert.deepEqual(
    upstream.transport_socket.typed_config.common_tls_context.validation_context.match_typed_subject_alt_names,
    [{ san_type: "DNS", matcher: { exact: "github.com" } }],
  );
});

test("pins exact localhost upstream socket to IPv4 while preserving authority and SNI", async () => {
  const localhost = JSON.parse(
    (
      await render({
        ...baseOptions(),
        routePlan: plan({ route: { host: "localhost" as never, port: 3210 as never } }),
      })
    ).bootstrapJson,
  );
  const localRoute =
    localhost.static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0]
      .routes[0];
  const localCluster = localhost.static_resources.clusters.find(
    (cluster: { name: string }) => cluster.name === "upstream_route-a",
  );
  assert.deepEqual(localRoute.match.headers, [{ name: ":authority", string_match: { exact: "localhost:3210" } }]);
  assert.equal(
    localCluster.load_assignment.endpoints[0].lb_endpoints[0].endpoint.address.socket_address.address,
    "127.0.0.1",
  );
  assert.equal(localCluster.transport_socket.typed_config.sni, "localhost");
  assert.deepEqual(
    localCluster.transport_socket.typed_config.common_tls_context.validation_context.match_typed_subject_alt_names,
    [{ san_type: "DNS", matcher: { exact: "localhost" } }],
  );

  const lookalike = JSON.parse(
    (
      await render({
        ...baseOptions(),
        routePlan: plan({ route: { host: "localhost.example" as never, port: 443 } }),
      })
    ).bootstrapJson,
  );
  const lookalikeCluster = lookalike.static_resources.clusters.find(
    (cluster: { name: string }) => cluster.name === "upstream_route-a",
  );
  assert.equal(
    lookalikeCluster.load_assignment.endpoints[0].lb_endpoints[0].endpoint.address.socket_address.address,
    "localhost.example",
  );
});

test("supports basic and api-key credentials from integration-scoped callback", async () => {
  const basic = await render(
    {
      ...baseOptions(),
      routePlan: plan({
        auth: {
          type: "basic_header",
          header: "Authorization",
          placeholder: "COGS_PLACEHOLDER_BASIC",
          secretHandle: "users/session/basic",
        },
      }),
    },
    source({ type: "basic", base64: "dXNlcjpwYXNz" }),
  );
  assert.equal(JSON.stringify(JSON.parse(basic.bootstrapJson)).includes("Basic dXNlcjpwYXNz"), true);

  const api = await render(
    {
      ...baseOptions(),
      routePlan: plan({
        auth: {
          type: "api_key_header",
          header: "x-api-key",
          prefix: "Token ",
          placeholder: "COGS_PLACEHOLDER_API",
          secretHandle: "users/session/api",
        },
      }),
    },
    source({ type: "api_key", value: "abc123" }),
  );
  const text = JSON.stringify(JSON.parse(api.bootstrapJson));
  assert.equal(text.includes("x-api-key"), true);
  assert.equal(text.includes("Token abc123"), true);
});

// Independent literal-only interpretation of v1.38.3 SubstitutionFormatParser::parse:
// every percent must be paired; anything else would invoke command parsing.
function literalHeaderBytes(format: string): string {
  let bytes = "";
  for (let i = 0; i < format.length; i++) {
    if (format[i] === "%") assert.equal(format[++i], "%", "unescaped formatter command");
    bytes += format[i];
  }
  return bytes;
}

test("credential values and prefixes are literal pinned-formatter bytes, including malformed commands", async () => {
  const corpus = [
    "%",
    "%%",
    "%REQ(x-guest)%",
    '%DYNAMIC_METADATA(["a","b"])%',
    "%PER_REQUEST_STATE(key)%",
    "%NOT_A_COMMAND%",
    "%REQ(",
    "end%",
  ];
  for (const value of corpus) {
    const boot = JSON.parse((await render(baseOptions(), source({ type: "bearer", token: value }))).bootstrapJson);
    const hcm = boot.static_resources.listeners[1].filter_chains[0].filters[0].typed_config;
    for (const route of hcm.route_config.virtual_hosts[0].routes)
      assert.equal(literalHeaderBytes(route.request_headers_to_add[0].header.value), `Bearer ${value}`);
    const prefix = `${value} `;
    const config = await render(
      {
        ...baseOptions(),
        routePlan: plan({
          auth: {
            type: "api_key_header",
            header: "x-api-key",
            prefix,
            placeholder: "COGS_PLACEHOLDER_KEY",
            secretHandle: "users/session/key",
          },
        }),
      },
      source({ type: "api_key", value }),
    );
    const apiHcm = JSON.parse(config.bootstrapJson).static_resources.listeners[1].filter_chains[0].filters[0]
      .typed_config;
    assert.equal(
      literalHeaderBytes(apiHcm.route_config.virtual_hosts[0].routes[0].request_headers_to_add[0].header.value),
      prefix + value,
    );
  }
  for (const prefix of ["bad\r\n", "é", "\ud800", "%".repeat(128)])
    await assert.rejects(
      () =>
        render(
          {
            ...baseOptions(),
            routePlan: plan({
              auth: {
                type: "api_key_header",
                header: "x-api-key",
                prefix,
                placeholder: "COGS_PLACEHOLDER_KEY",
                secretHandle: "users/session/key",
              },
            }),
          },
          source({ type: "api_key", value: "%".repeat(8192) }),
        ),
      CogsEnvoyRuntimeConfigError,
    );
  await assert.rejects(
    () => render({ ...baseOptions(), internalAuthzToken: "%REQ(x-guest-token)%" }),
    CogsEnvoyRuntimeConfigError,
  );
});

test("resolves credentialed integrations once in deterministic order and skips uncredentialed integrations", async () => {
  const seen: string[] = [];
  const credentialSource: CogsEnvoyCredentialSource = {
    withCredential: async (request, consume) => {
      seen.push(request.integrationId);
      await consume(
        request.authType === "api_key_header"
          ? { type: "api_key", value: `${request.integrationId}-secret` }
          : { type: "bearer", token: `${request.integrationId}-secret` },
      );
    },
  };
  const config = await render({ ...baseOptions(), routePlan: multiIntegrationPlan() }, credentialSource);
  assert.deepEqual(seen, ["github", "npm"]);
  assert.equal(config.routeCount, 4);
  const text = JSON.stringify(JSON.parse(config.bootstrapJson));
  assert.equal(text.includes("github-secret"), true);
  assert.equal(text.includes("npm-secret"), true);
  assert.equal(text.includes("pypi-secret"), false);
});

test("policy secret deny prevents credential source callback", async () => {
  let called = false;
  const authorizer = Object.freeze(() =>
    Object.freeze({
      version: "cogs.policy-decision/v1alpha1" as const,
      decision_id: `sha256:${"b".repeat(64)}` as const,
      allow: false,
      reason: "unsupported_surface" as const,
    }),
  );
  await assert.rejects(
    () =>
      render(
        { ...baseOptions(), policyAuthorizer: authorizer },
        {
          withCredential: async () => {
            called = true;
          },
        },
      ),
    CogsEnvoyRuntimeConfigError,
  );
  assert.equal(called, false);
});

test("credential callback is exactly scoped to caller operation", async () => {
  let operationRan = false;
  let lateConsume: ((value: CogsEnvoyCredentialValue) => Promise<void>) | undefined;
  const scoped: CogsEnvoyCredentialSource = {
    withCredential: async (_request, consume) => {
      lateConsume = consume;
      await consume({ type: "bearer", token: "scoped-token" });
      assert.equal(operationRan, true);
    },
  };
  await withCogsEnvoyRuntimeConfig(baseOptions(), scoped, async () => {
    operationRan = true;
    return undefined;
  });
  await assert.rejects(
    () => lateConsume?.({ type: "bearer", token: "late" }) ?? Promise.resolve(),
    CogsEnvoyRuntimeConfigError,
  );

  await assert.rejects(
    () => withCogsEnvoyRuntimeConfig(baseOptions(), { withCredential: async () => undefined }, async () => undefined),
    CogsEnvoyRuntimeConfigError,
  );
  const nonAwaitedRequests: string[] = [];
  await assert.rejects(
    () =>
      withCogsEnvoyRuntimeConfig(
        baseOptions(),
        {
          withCredential: async (request, consume) => {
            nonAwaitedRequests.push(request.integrationId);
            void consume({ type: "bearer", token: "not-awaited" }).catch(() => undefined);
          },
        },
        async () => undefined,
      ),
    CogsEnvoyRuntimeConfigError,
  );
  assert.deepEqual(nonAwaitedRequests, ["github"]);
  await assert.rejects(
    () =>
      withCogsEnvoyRuntimeConfig(
        baseOptions(),
        {
          withCredential: async (_request, consume) => {
            await consume({ type: "bearer", token: "one" });
            await consume({ type: "bearer", token: "two" }).catch(() => undefined);
          },
        },
        async () => undefined,
      ),
    CogsEnvoyRuntimeConfigError,
  );
});

test("generic config failure privately preserves lexical cleanup ownership", async () => {
  const owner = new Error("synthetic lexical owner");
  const failure = await withCogsEnvoyRuntimeConfig(baseOptions(), source(), async () => {
    throw owner;
  }).catch((error: unknown) => error);
  assert.ok(failure instanceof CogsEnvoyRuntimeConfigError);
  assert.equal(envoyRuntimeConfigFailureCause(failure), owner);
  assert.equal(JSON.stringify(failure).includes("synthetic lexical owner"), false);
});

test("rejects hostile plans, targets, credentials, and direct fallback shapes generically", async () => {
  await assert.rejects(() => render({ ...baseOptions(), authzTarget: "0.0.0.0:1" }), CogsEnvoyRuntimeConfigError);
  await assert.rejects(() => render({ ...baseOptions(), internalAuthzToken: "short" }), CogsEnvoyRuntimeConfigError);
  await assert.rejects(
    () => render({ ...baseOptions(), internalAuthzToken: "internal-authz-token-é" }),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(() => render({ ...baseOptions(), listenerPort: 0 }), CogsEnvoyRuntimeConfigError);
  await assert.rejects(
    () => render(baseOptions(), source({ type: "basic", base64: "not canonical!" })),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(
    () => render(baseOptions(), source({ type: "api_key", value: "wrong" })),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(
    () => render(baseOptions(), source({ type: "basic", base64: "AAAA====" })),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(
    () => render(baseOptions(), source({ type: "basic", base64: "OnBhc3M=" })),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(
    () => render(baseOptions(), source({ type: "bearer", token: "unicode-é" })),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(
    () =>
      render(
        {
          ...baseOptions(),
          routePlan: plan({
            auth: {
              type: "api_key_header",
              header: "x-api-key",
              prefix: "",
              placeholder: "COGS_PLACEHOLDER_API",
              secretHandle: "users/session/api",
            },
          }),
        },
        source({ type: "api_key", value: "unicode-é" }),
      ),
    CogsEnvoyRuntimeConfigError,
  );
  await assert.rejects(
    () => render({ ...baseOptions(), routePlan: plan({ route: { host: "githubXcom" } as unknown as Partial<Route> }) }),
    CogsEnvoyRuntimeConfigError,
  );

  const badOriginal = plan();
  const bad = {
    ...badOriginal,
    integrations: badOriginal.integrations.map((integration) => ({
      ...integration,
      routes: integration.routes.map((item) => ({ ...item, pathMatch: { ...item.pathMatch }, injectAuth: false })),
    })),
  };
  deepFreeze(bad);
  await assert.rejects(
    () => render({ ...baseOptions(), routePlan: bad as CogsEgressRoutePlan }),
    CogsEnvoyRuntimeConfigError,
  );
});

// Structural/mutation evidence, not measurements of Envoy allocation or timeout enforcement.
function assertBounds(boot: ReturnType<typeof JSON.parse>, count: number, authorities: number) {
  const profile = cogsEnvoyBoundedV1;
  const allocation = cogsEnvoyResourceAllocation(count, authorities);
  assert.deepEqual(boot.overload_manager, profile.overload);
  assert.equal(boot.bootstrap_extensions[0].typed_config.buffer_size_kb, 64);
  assert.equal(boot.static_resources.listeners.length, authorities + 1);
  assert.equal(boot.static_resources.clusters.length, count + authorities + 1);
  for (const listener of boot.static_resources.listeners) {
    for (const [key, value] of Object.entries(profile.network)) assert.equal(listener[key], value);
    const inner = listener.name !== "forward_proxy";
    if (inner) {
      assert.equal(listener.listener_filters_timeout, "5s");
      assert.equal(listener.continue_on_listener_filters_timeout, false);
      const inspector = listener.listener_filters.find((f: { name: string }) => f.name.endsWith(".tls_inspector"));
      for (const [key, value] of Object.entries(profile.inspector)) assert.equal(inspector.typed_config[key], value);
    } else {
      assert.equal(listener.ignore_global_conn_limit, false);
      assert.equal(listener.bypass_overload_manager, false);
      assert.equal(listener.tcp_backlog_size, 32);
      assert.equal(listener.max_connections_to_accept_per_socket_event, 1);
    }
    for (const chain of listener.filter_chains) {
      if (inner) assert.equal(chain.transport_socket_connect_timeout, "5s");
      const hcm = chain.filters.find((f: { name: string }) => f.name.endsWith(".http_connection_manager")).typed_config;
      for (const [key, value] of Object.entries(cogsEnvoyHcmBounds(inner))) assert.deepEqual(hcm[key], value);
      assert.equal(hcm.max_request_headers_kb, 32);
      assert.deepEqual(
        hcm.http_filters.map((f: { name: string }) => f.name),
        ["envoy.filters.http.ext_authz", "envoy.filters.http.router"],
      );
      assert.equal(hcm.http_filters[0].typed_config.failure_mode_allow, false);
      assert.equal(hcm.http_filters[1].typed_config.respect_expected_rq_timeout, false);
      for (const host of hcm.route_config.virtual_hosts)
        for (const route of host.routes) {
          assert.equal(route.route.timeout, "0s");
          assert.equal(route.route.priority, undefined);
          assert.equal(route.route.idle_timeout, undefined);
          assert.equal(route.route.max_stream_duration, undefined); // Inherit the pre-auth HCM deadline.
          assert.equal(
            route.typed_per_filter_config["envoy.filters.http.ext_authz"].check_settings.disable_request_body_buffering,
            true,
          );
          if (inner) assert.equal(route.route.upgrade_configs, undefined);
        }
    }
  }
  for (const cluster of boot.static_resources.clusters) {
    for (const [key, value] of Object.entries(profile.network)) assert.equal(cluster[key], value);
    const app = cluster.name.startsWith("upstream_");
    const authz = cluster.name === "cogs_authz";
    assert.deepEqual(
      cluster.circuit_breakers,
      app ? allocation.application : authz ? allocation.authz : allocation.tunnel,
    );
    if (app) assert.equal(cluster.type, "LOGICAL_DNS");
    if (!app && !authz) continue;
    const http = cluster.typed_extension_protocol_options["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"];
    assert.deepEqual(http.common_http_protocol_options, {
      ...profile.commonHttp,
      max_stream_duration: authz ? "1s" : "1800s",
      max_response_headers_kb: 32,
    });
    assert.deepEqual(
      authz ? http.explicit_http_config.http2_protocol_options : http.auto_config.http2_protocol_options,
      { ...profile.http2, max_concurrent_streams: authz ? 32 : 8 },
    );
  }
  const walk = (value: unknown): void => {
    if (typeof value !== "object" || value === null) return;
    for (const [key, child] of Object.entries(value)) {
      assert.ok(
        !/^(retry_policy|retry_budget|hedge_policy|request_mirror_policies|preconnect_policy|with_request_body|http3_protocol_options|quic_options|original_ip_detection_extensions)$/.test(
          key,
        ),
        key,
      );
      if (key === "priority") assert.ok(child === "DEFAULT" || child === "HIGH");
      walk(child);
    }
  };
  walk(boot);
}

function sizedPlan(count: number, authorities: number): CogsEgressRoutePlan {
  const original = plan().integrations[0];
  assert.ok(original);
  return deepFreeze({
    routeCount: count,
    integrations: [
      {
        ...original,
        routes: Array.from({ length: count }, (_, i) => route({ routeId: `r${i}`, host: `h${i % authorities}.test` })),
      },
    ],
  });
}

// Exact Envoy v1.38.3, commit 0ebfcfe5b0484b89ca85b761da9e05ce75dbda8d:
// api/envoy/config/core/v3/protocol.proto (Http2ProtocolOptions, field 21):
// max_header_field_size_kb has PGV gte 64/lte 256. HCM config.cc and upstream
// http/config.cc reject an explicit field bound above their aggregate. Omitting it
// keeps codec_impl.cc Http2Options' oghttp2 max_header_list_bytes/field_size at
// max_headers_kb*1024; saveHeader independently checks aggregate size/count.
// This is a selected exact-API structural regression, NOT full protobuf validation.
function assertPinnedHeaderApi(boot: ReturnType<typeof JSON.parse>) {
  assert.deepEqual(boot.layered_runtime, {
    layers: [
      {
        name: "cogs-literal-header-format",
        static_layer: { "envoy.reloadable_features.remove_legacy_route_formatter": true },
      },
    ],
  });
  const h2 = (options: Record<string, unknown>, aggregate: number) => {
    const field = options.max_header_field_size_kb;
    if (field !== undefined) {
      assert.ok(typeof field === "number" && field >= 64 && field <= 256);
      assert.ok(field <= aggregate);
    }
    assert.equal(aggregate, 32, "never enlarge the aggregate to admit a field override");
    assert.equal(field, undefined);
  };
  for (const listener of boot.static_resources.listeners) {
    const hcm = listener.filter_chains[0].filters[0].typed_config;
    assert.equal(hcm.max_request_headers_kb, 32);
    assert.equal(hcm.common_http_protocol_options.max_response_headers_kb, undefined);
    if (hcm.http2_protocol_options) h2(hcm.http2_protocol_options, hcm.max_request_headers_kb);
  }
  for (const cluster of boot.static_resources.clusters) {
    const http = cluster.typed_extension_protocol_options?.["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"];
    if (http)
      h2(
        (http.auto_config ?? http.explicit_http_config).http2_protocol_options,
        http.common_http_protocol_options.max_response_headers_kb,
      );
  }
  assert.deepEqual(
    boot.overload_manager.resource_monitors.map((r: { name: string }) => r.name),
    ["envoy.resource_monitors.global_downstream_max_connections", "envoy.resource_monitors.fixed_heap"],
  );
  assert.equal(boot.overload_manager.resource_monitors[1].typed_config.max_heap_size_bytes, "536870912");
  assert.deepEqual(
    [...boot.overload_manager.actions, ...boot.overload_manager.loadshed_points].map(
      (a: { triggers: unknown }) => a.triggers,
    ),
    [0.75, 0.85, 0.85].map((value) => [{ name: "envoy.resource_monitors.fixed_heap", threshold: { value } }]),
  );
  assert.ok(!JSON.stringify(boot).includes("cgroup_memory"));
}

test("exact pinned API rejects both invalid32 and explicit64 with aggregate32; no mount-root monitor", async () => {
  const boot = JSON.parse((await render()).bootstrapJson);
  assertPinnedHeaderApi(boot);
  const legacy = structuredClone(boot);
  legacy.layered_runtime.layers[0].static_layer["envoy.reloadable_features.remove_legacy_route_formatter"] = false;
  assert.throws(() => assertPinnedHeaderApi(legacy), "legacy pre-translation corrupts escaped metadata literals");
  for (const field of [32, 64])
    for (const site of ["downstream", "authz", "upstream"]) {
      const changed = structuredClone(boot);
      const hcm = changed.static_resources.listeners[1].filter_chains[0].filters[0].typed_config;
      const clusters = changed.static_resources.clusters;
      const http =
        clusters[site === "authz" ? 0 : 1].typed_extension_protocol_options[
          "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
        ];
      (site === "downstream"
        ? hcm.http2_protocol_options
        : (http.explicit_http_config ?? http.auto_config).http2_protocol_options).max_header_field_size_kb = field;
      assert.throws(() => assertPinnedHeaderApi(changed));
    }
});

test("fixed profile is deeply immutable and graph arithmetic includes host/pool exceptions", () => {
  assert.equal(cogsEnvoyBoundedV1.name, "cogs-egress-bounded-v1");
  assert.deepEqual(cogsEnvoyBoundedV1.http2, {
    max_concurrent_streams: 8,
    initial_stream_window_size: 65536,
    initial_connection_window_size: 262144,
    hpack_table_size: 4096,
    max_outbound_frames: 256,
    max_outbound_control_frames: 32,
    max_consecutive_inbound_frames_with_empty_payload: 1,
    max_inbound_priority_frames_per_stream: 100,
    max_inbound_window_update_frames_per_data_frame_sent: 10,
    allow_connect: false,
    allow_metadata: false,
  });
  for (const inner of [false, true]) {
    const hcm = cogsEnvoyHcmBounds(inner);
    assert.deepEqual(
      [
        hcm.request_headers_timeout,
        hcm.stream_idle_timeout,
        hcm.stream_flush_timeout,
        hcm.drain_timeout,
        hcm.delayed_close_timeout,
        hcm.request_timeout,
      ],
      ["5s", "60s", "60s", "1s", "1s", "0s"],
    );
    assert.deepEqual(hcm.common_http_protocol_options, {
      idle_timeout: "30s",
      max_connection_duration: "3600s",
      max_stream_duration: inner ? "1800s" : "3600s",
      max_requests_per_connection: inner ? 1024 : 1,
      max_headers_count: 100,
      headers_with_underscores_action: "REJECT_REQUEST",
    });
  }
  assert.throws(() => {
    cogsEnvoyBoundedV1.http2.max_concurrent_streams = 999;
  }, TypeError);
  assert.throws(() => {
    cogsEnvoyBoundedV1.overload.resource_monitors.pop();
  }, TypeError);
  assert.deepEqual(cogsEnvoyResourceAllocation(7, 4).envelope, {
    innerStreams: 256,
    outerAndInnerStreams: 288,
    applicationActive: 112,
    applicationPending: 28,
    applicationConnections: 63,
    poolAndDownstreamSockets: 98,
    internalEndpoints: 264,
  });
  assert.deepEqual(cogsEnvoyResourceAllocation(256, 256).envelope, {
    innerStreams: 256,
    outerAndInnerStreams: 288,
    applicationActive: 256,
    applicationPending: 256,
    applicationConnections: 512,
    poolAndDownstreamSockets: 547,
    internalEndpoints: 1024,
  });
  for (let r = 1; r <= 256; r++)
    for (const a of [1, r]) {
      const allocation = cogsEnvoyResourceAllocation(r, a);
      assert.ok(allocation.envelope.applicationActive <= 256 && allocation.envelope.applicationPending <= 256);
      assert.ok(allocation.envelope.poolAndDownstreamSockets <= 547 && allocation.envelope.internalEndpoints <= 1024);
      assert.ok((allocation.application.thresholds[0]?.max_pending_requests ?? 0) > 0);
      assert.ok((allocation.tunnel.thresholds[0]?.max_connections ?? 0) * a <= 256);
    }
  for (const [r, a] of [
    [0, 0],
    [257, 1],
    [1, 2],
    [NaN, 1],
    [2.5, 1],
  ]) {
    assert.throws(() => cogsEnvoyResourceAllocation(r as number, a as number));
  }
});

test("every rendered graph member is bounded; unchanged 1 MiB ceiling rejects large graphs", async (t) => {
  for (const count of [1, 7, 32, 64, 128, 256])
    for (const authorities of [1, count]) {
      const options = { ...baseOptions(), routePlan: sizedPlan(count, authorities) };
      try {
        const config = await render(options);
        assert.ok(Buffer.byteLength(config.bootstrapJson) <= 1024 * 1024);
        t.diagnostic(`static R=${count} A=${authorities}: ${Buffer.byteLength(config.bootstrapJson)} bootstrap bytes`);
        assertBounds(JSON.parse(config.bootstrapJson), count, authorities);
        assert.equal(config.bootstrapJson, (await render(options)).bootstrapJson);
      } catch (error) {
        assert.ok(error instanceof CogsEnvoyRuntimeConfigError);
        assert.equal((envoyRuntimeConfigFailureCause(error) as Error).message, "bootstrap too large");
        assert.ok(count >= 64, "small graphs must remain usable");
        t.diagnostic(`static R=${count} A=${authorities}: rejected by unchanged bootstrap-byte ceiling`);
      }
    }
  const seen: string[] = [];
  await assert.rejects(
    () => render({ ...baseOptions(), routePlan: sizedPlan(257, 1) }, source(undefined, seen)),
    CogsEnvoyRuntimeConfigError,
  );
  assert.deepEqual(seen, [], "route overflow fails before credential acquisition");
});

test("structural guard rejects removed bounds, retry/body collectors and timeout/header mutations", async () => {
  const boot = JSON.parse((await render()).bootstrapJson);
  assertBounds(boot, 2, 1);
  const mutations = [
    (b: typeof boot) => {
      delete b.overload_manager;
    },
    (b: typeof boot) => {
      b.overload_manager.resource_monitors[0].typed_config.max_active_downstream_connections = "32000";
    },
    (b: typeof boot) => {
      delete b.static_resources.clusters[1].circuit_breakers;
    },
    (b: typeof boot) => {
      delete b.static_resources.listeners[1].filter_chains[0].transport_socket_connect_timeout;
    },
    ...[
      "early_header_mutation_extensions",
      "stream_flush_timeout",
      "request_headers_timeout",
      "common_http_protocol_options",
      "http2_protocol_options",
    ].map((key) => (b: typeof boot) => {
      delete b.static_resources.listeners[1].filter_chains[0].filters[0].typed_config[key];
    }),
    (b: typeof boot) => {
      b.static_resources.clusters[1].retry_budget = {};
    },
    (b: typeof boot) => {
      b.static_resources.listeners[0].filter_chains[0].filters[0].typed_config.codec_type = "AUTO";
    },
    (b: typeof boot) => {
      b.static_resources.listeners[1].filter_chains[0].filters[0].typed_config.http_filters[0].typed_config.with_request_body =
        { max_request_bytes: 1048576 };
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(boot);
    mutate(changed);
    assert.throws(() => assertBounds(changed, 2, 1));
  }
});

// Opt-in LOCAL Linux diagnostic. No image pull, namespace/firewall changes, or production effect.
// Exact pinned binary + production renderer/authz/WAL/process owner; only paths and loopback binding relocated.
// This tests admission/establishment/recovery, NOT heap/cgroup shedding or full client/stream pressure.
test("pinned Envoy validates and bounds silent accept pressure without WAL/credential forwarding", {
  timeout: 45_000,
}, async (t) => {
  const executable = process.env.COGS_ENVOY_BOUNDED_TEST_BINARY;
  if (!executable || process.platform !== "linux")
    return t.skip("requires local Linux pinned binary via COGS_ENVOY_BOUNDED_TEST_BINARY");
  assert.equal(
    createHash("sha256")
      .update(await readFile(executable))
      .digest("hex"),
    "affffb8d08a14fdc375b1f7dd8d0f3004eacdf51ce07f5636d7e168a01c6b373",
  );
  const exec = promisify(execFile);
  const root = await mkdtemp(join(tmpdir(), "cogs-envoy-bounds-"));
  const cleanup: Array<() => unknown> = [() => rm(root, { recursive: true, force: true })];
  t.after(async () => {
    for (const close of cleanup.reverse()) await close();
  });
  const cert = join(root, "cert.pem"),
    key = join(root, "key.pem"),
    configPath = join(root, "bootstrap.json");
  await exec(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost",
      "-keyout",
      key,
      "-out",
      cert,
    ],
    { timeout: 10_000, maxBuffer: 65536 },
  );
  const prefix = '%DYNAMIC_METADATA(["a","b"])% %PER_REQUEST_STATE(key)% ';
  const credential = "% %% %REQ(x-guest)% %REQ(".replaceAll(" ", "_");
  let forwarded = 0;
  const origin = httpsServer({ key: await readFile(key), cert: await readFile(cert) }, (req, res) => {
    forwarded++;
    assert.equal(req.headers["x-api-key"], prefix + credential);
    res.end("control");
  });
  origin.on("tlsClientError", () => {});
  await new Promise<void>((r) => origin.listen(0, "127.0.0.1", r));
  cleanup.push(
    () =>
      new Promise<void>((r) => {
        origin.closeAllConnections();
        origin.close(() => r());
      }),
  );
  const address = origin.address();
  assert.ok(address && typeof address !== "string");
  const routePlan = plan({
    route: { host: "localhost", port: address.port } as unknown as Partial<Route>,
    auth: {
      type: "api_key_header",
      header: "x-api-key",
      prefix,
      placeholder: "COGS_PLACEHOLDER_KEY",
      secretHandle: "users/session/key",
    },
  });
  const wal = await openEgressAuditWal({
    path: join(root, "audit.wal"),
    maxBytes: 8192,
    maxRecords: 8,
    maxRecordBytes: 1024,
  });
  cleanup.push(() => wal.close());
  const capability = "capability-token-0123456789abcdef";
  const authz = await startCogsExtAuthzServer({ ...baseOptions(), routePlan, wal, proxyCapability: capability });
  cleanup.push(() => authz.close());
  const reservation = createServer();
  await new Promise<void>((r) => reservation.listen(0, "127.0.0.1", r));
  const reserved = reservation.address();
  assert.ok(reserved && typeof reserved !== "string");
  const port = reserved.port;
  await new Promise<void>((r) => reservation.close(() => r()));
  const seen: string[] = [];
  const rendered = await render(
    { ...baseOptions(), routePlan, listenerPort: port, authzTarget: authz.target },
    source({ type: "api_key", value: credential }, seen),
  );
  const boot = JSON.parse(rendered.bootstrapJson);
  boot.static_resources.listeners[0].address.socket_address.address = "127.0.0.1";
  const relocated = JSON.stringify(boot)
    .replaceAll("/run/cogs/egress/envoy/proxy-cert.pem", cert)
    .replaceAll("/run/cogs/egress/envoy/proxy-key.pem", key)
    .replaceAll("/etc/ssl/certs/ca-certificates.crt", cert);
  await writeFile(configPath, relocated, { mode: 0o600 });
  await exec(
    executable,
    ["--mode", "validate", "--config-path", configPath, "--concurrency", "1", "--disable-hot-restart"],
    { timeout: 10_000, maxBuffer: 65536 },
  );
  const owner = createNodeCogsEnvoyProcessPort({
    executablePath: resolve(executable),
    startupTimeoutMs: 5000,
    closeTimeoutMs: 5000,
    ports: Object.freeze({
      ...nodeEnvoyProcessPorts,
      spawn: (request: Parameters<typeof nodeEnvoyProcessPorts.spawn>[0]) =>
        nodeEnvoyProcessPorts.spawn({
          ...request,
          argv: request.argv.map((arg) => (arg === "/run/cogs/egress/envoy/bootstrap.json" ? configPath : arg)),
        }),
    }),
  });
  const child = await owner.start({
    bootstrapPath: "/run/cogs/egress/envoy/bootstrap.json",
    listenerPort: port,
    onCompletionLine: async () => {},
  });
  cleanup.push(() => child.close());
  const sockets = new Set<Socket>();
  cleanup.push(() => {
    for (const socket of sockets) socket.destroy();
  });
  const open = async () => {
    const socket = createConnection({ host: "127.0.0.1", port });
    sockets.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => sockets.delete(socket));
    await new Promise<void>((r, reject) => {
      socket.once("connect", r);
      socket.once("error", reject);
    });
    return socket;
  };
  const pause = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
  const closed = async (socket: Socket, ms: number) => {
    if (socket.destroyed) return;
    await new Promise<void>((r, reject) => {
      const timer = setTimeout(() => reject(new Error("connection deadline exceeded")), ms);
      socket.once("close", () => {
        clearTimeout(timer);
        r();
      });
    });
  };
  for (let i = 0; i < 32; i++) await open();
  await pause(100);
  assert.equal(sockets.size, 32);
  const excess = await open();
  excess.resume();
  await closed(excess, 1000);
  assert.equal(sockets.size, 32);
  assert.equal(wal.records.length, 0);
  assert.equal(forwarded, 0);
  assert.equal(seen.length, 1);
  for (const socket of sockets) socket.destroy();
  await pause(100);
  // Header establishment is absolute, independent of byte dribble (5s + scheduler/close allowance).
  const slow = await open();
  slow.write("CONNECT localhost:");
  slow.resume();
  const dribble = setInterval(() => slow.write("1"), 100);
  try {
    await closed(slow, 6500);
  } finally {
    clearInterval(dribble);
  }
  const connect = async () => {
    const socket = await open();
    socket.write(
      `CONNECT localhost:${address.port} HTTP/1.1\r\nHost: localhost:${address.port}\r\nProxy-Authorization: ${encodeProxyAuthorizationBasic(capability)}\r\n\r\n`,
    );
    await new Promise<void>((r, reject) => {
      let headers = "";
      const timer = setTimeout(() => reject(new Error("CONNECT failed")), 2000);
      const data = (chunk: Buffer) => {
        headers += chunk;
        if (!headers.includes("\r\n\r\n")) return;
        clearTimeout(timer);
        socket.off("data", data);
        try {
          assert.match(headers, /^HTTP\/1.1 200/);
          r();
        } catch (e) {
          reject(e);
        }
      };
      socket.on("data", data);
    });
    return socket;
  };
  const noHello = await connect();
  noHello.resume();
  await closed(noHello, 6500);
  assert.equal(wal.records.length, 0);
  assert.equal(forwarded, 0);
  // A newly admitted authenticated control request succeeds after the slots/deadlines clear.
  const tunnel = await connect();
  const tls = tlsConnect({
    socket: tunnel,
    servername: "localhost",
    ca: await readFile(cert),
    ALPNProtocols: ["http/1.1"],
  });
  cleanup.push(() => tls.destroy());
  await new Promise<void>((r, reject) => {
    tls.once("secureConnect", r);
    tls.once("error", reject);
  });
  const response = await new Promise<string>((r, reject) => {
    let text = "";
    tls.setTimeout(3000, () => tls.destroy(new Error("control deadline")));
    tls.on("error", reject);
    tls.setEncoding("utf8");
    tls.on("data", (data) => {
      text += data;
      if (text.length > 8192) tls.destroy(new Error("oversized control"));
    });
    tls.once("end", () => r(text));
    tls.write(
      `GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: localhost:${address.port}\r\nConnection: close\r\n\r\n`,
    );
  });
  assert.match(response, /^HTTP\/1.1 200/);
  assert.ok(response.endsWith("control"));
  assert.equal(forwarded, 1);
  assert.equal(wal.records.length, 1);
  assert.equal(child.ready, true);
  assert.equal(authz.ready, true);
});

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
