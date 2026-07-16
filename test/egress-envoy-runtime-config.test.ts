import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type CogsEnvoyCredentialSource,
  type CogsEnvoyCredentialValue,
  CogsEnvoyRuntimeConfigError,
  withCogsEnvoyRuntimeConfig,
} from "../src/egress/envoy-runtime-config.ts";
import type { CogsEgressAuthRef, CogsEgressRoutePlan } from "../src/egress/route-policy.ts";

const token = "internal-authz-token";
const baseOptions = () => ({
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
  assert.equal(upstream.type, "STRICT_DNS");
  assert.equal(upstream.transport_socket.typed_config.sni, "github.com");
  assert.deepEqual(
    upstream.transport_socket.typed_config.common_tls_context.validation_context.match_typed_subject_alt_names,
    [{ san_type: "DNS", matcher: { exact: "github.com" } }],
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

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
