import assert from "node:assert/strict";
import test from "node:test";
import { type EnvoyCandidateConfigInput, generateEnvoyConfig, renderEnvoyConfig } from "./config.ts";

const certificate = "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n";
const privateKey = "-----BEGIN PRIVATE KEY-----\na2V5\n-----END PRIVATE KEY-----\n";

function input(): EnvoyCandidateConfigInput {
  return {
    caseId: "envoy.config-test",
    sessionId: "session-test",
    listenerAddress: "127.0.0.1",
    listenerPort: 18080,
    authorizationGrpcTarget: "127.0.0.1:19090",
    proxyCertificatePem: certificate,
    proxyPrivateKeyPem: privateKey,
    routes: [
      {
        id: "route.bearer",
        protocol: "https",
        host: "api.example.test",
        port: 443,
        methods: ["GET", "POST"],
        pathPrefix: "/v1/allowed/",
        query: "a=1&b=2",
        upstreamAddress: "127.0.0.1",
        upstreamPort: 19443,
        upstreamCaCertificatePem: certificate,
        credential: { kind: "bearer", value: "Bearer fixture-real-value" },
      },
      {
        id: "route.basic",
        protocol: "https",
        host: "basic.example.test",
        port: 8443,
        methods: ["GET"],
        pathPrefix: "/basic/",
        upstreamAddress: "upstream.internal",
        upstreamPort: 18443,
        upstreamCaCertificatePem: certificate,
        credential: { kind: "basic", value: "Basic Zml4dHVyZTpwYXNzd29yZA==" },
      },
      {
        id: "route.api-key",
        protocol: "http",
        host: "registry.example.test",
        port: 80,
        methods: ["GET"],
        pathPrefix: "/packages/",
        upstreamAddress: "127.0.0.1",
        upstreamPort: 18000,
        credential: { kind: "api-key", header: "x-api-key", value: "fixture-api-key" },
      },
    ],
  };
}

function walk(value: unknown, visit: (key: string, value: unknown) => void): void {
  if (Array.isArray(value)) {
    for (const item of value) walk(item, visit);
    return;
  }
  if (typeof value !== "object" || value === null) return;
  for (const [key, nested] of Object.entries(value)) {
    visit(key, nested);
    walk(nested, visit);
  }
}

test("generator emits deterministic immutable static Envoy policy with no administration or discovery surface", () => {
  const firstInput = input();
  const reversed = { ...input(), routes: [...input().routes].reverse() };
  const rendered = renderEnvoyConfig(firstInput);
  assert.equal(rendered, renderEnvoyConfig(reversed));
  assert.equal(firstInput.routes[0]?.id, "route.bearer");

  const config = generateEnvoyConfig(firstInput);
  assert.ok(Object.isFrozen(config));
  assert.doesNotMatch(rendered, /"admin"|dynamic_resources|ads_config|sds_config|cluster_header|original_dst/i);
  assert.match(rendered, /envoy\.bootstrap\.internal_listener/);
  assert.match(rendered, /envoy\.filters\.http\.ext_authz/);
  assert.match(rendered, /"grpc_service"/);
  assert.match(rendered, /"transport_api_version": "V3"/);
  assert.doesNotMatch(rendered, /envoy\.filters\.http\.lua|x-cogs-envoy-connect/);
  assert.match(rendered, /"failure_mode_allow": false/);
  assert.match(rendered, /"path_with_escaped_slashes_action": "REJECT_REQUEST"/);
  assert.match(rendered, /"stream_error_on_invalid_http_message": true/);
  assert.match(rendered, /"name": "forward_proxy"/);
  assert.match(rendered, /"internal_listener": \{\}/);
  assert.match(rendered, /"connect_matcher": \{\}/);
  assert.match(rendered, /"exact": "\/v1\/allowed\/\?a=1&b=2"/);
  assert.match(rendered, /"regex": "\^\/basic\/\[\^\?\]\*\$"/);
  assert.match(rendered, /"authorization"/);
  assert.match(rendered, /Bearer fixture-real-value/);
  assert.match(rendered, /Basic Zml4dHVyZTpwYXNzd29yZA==/);
  assert.match(rendered, /"x-api-key"/);
  assert.match(rendered, /"request-complete"/);
  assert.doesNotMatch(rendered, /%REQ\(:PATH\)%|%REQ\(AUTHORIZATION\)%|%REQ\(PROXY-AUTHORIZATION\)%/i);

  const socketListeners: unknown[] = [];
  walk(config, (key, value) => {
    if (key === "socket_address") socketListeners.push(value);
  });
  assert.ok(socketListeners.length >= 5, "one listener plus trusted upstream/authz sockets are expected");
  const parsed = JSON.parse(rendered) as { static_resources: { listeners: Array<Record<string, unknown>> } };
  const exposed = parsed.static_resources.listeners.filter((listener) => "address" in listener);
  assert.equal(exposed.length, 1);
  assert.equal(exposed[0]?.name, "forward_proxy");
});

test("fixture adapter shares bounded settings, not production-policy or pressure qualification", () => {
  const boot = JSON.parse(renderEnvoyConfig(input()));
  assert.equal(boot.overload_manager.resource_monitors[0].typed_config.max_active_downstream_connections, "32");
  assert.equal(boot.bootstrap_extensions[0].typed_config.buffer_size_kb, 64);
  for (const listener of boot.static_resources.listeners) {
    const hcm = listener.filter_chains[0].filters[0].typed_config;
    assert.equal(listener.per_connection_buffer_limit_bytes, 65536);
    assert.equal(hcm.codec_type, listener.name === "forward_proxy" ? "HTTP1" : "AUTO");
    assert.equal(hcm.stream_flush_timeout, "60s");
    assert.equal(
      hcm.early_header_mutation_extensions[0].typed_config.mutations[0].remove_on_match.key_matcher.prefix,
      "x-envoy-",
    );
  }
  for (const cluster of boot.static_resources.clusters) {
    assert.equal(cluster.per_connection_buffer_limit_bytes, 65536);
    assert.equal(cluster.circuit_breakers.thresholds[0].max_retries, 0);
    assert.equal(cluster.circuit_breakers.thresholds[1].max_connections, 0);
  }
  assert.doesNotMatch(JSON.stringify(boot), /retry_policy|hedge_policy|with_request_body|preconnect_policy/);
});

test("conformance credentials share literal percent encoding and disable legacy pre-translation", () => {
  const value = input();
  const literal = 'prefix% %% %REQ(x-guest)% %DYNAMIC_METADATA(["a","b"])% %PER_REQUEST_STATE(key)% %REQ(';
  const apiRoute = value.routes[2];
  assert.ok(apiRoute);
  apiRoute.credential = { kind: "api-key", header: "x-api-key", value: literal };
  const boot = generateEnvoyConfig(value);
  const added: Array<{ header: { key: string; value: string } }> = [];
  walk(boot, (key, nested) => {
    if (key === "request_headers_to_add") added.push(...(nested as typeof added));
  });
  assert.equal(added.find((entry) => entry.header.key === "x-api-key")?.header.value, literal.replaceAll("%", "%%"));
  const rendered = renderEnvoyConfig(value);
  assert.match(rendered, /"envoy.reloadable_features.remove_legacy_route_formatter": true/);
  assert.doesNotMatch(rendered, /max_header_field_size_kb|cgroup_memory/);
});

test("generator rejects ambiguous routes, credential-bearing control origins, and dangerous header choices", () => {
  const mutate = (update: (value: EnvoyCandidateConfigInput) => void, expected: RegExp) => {
    const value = input();
    update(value);
    assert.throws(() => generateEnvoyConfig(value), expected);
  };
  const route = (value: EnvoyCandidateConfigInput, index: number) => {
    const selected = value.routes[index];
    assert.ok(selected);
    return selected;
  };

  mutate((value) => {
    route(value, 0).host = "127.0.0.1";
  }, /exact, lowercase DNS/);
  mutate((value) => {
    route(value, 0).host = "API.example.test";
  }, /exact, lowercase DNS/);
  mutate((value) => {
    route(value, 0).pathPrefix = "/v1/%2e%2e/private";
  }, /canonical/);
  mutate((value) => {
    route(value, 0).pathPrefix = "/v1//private";
  }, /canonical/);
  mutate((value) => {
    route(value, 0).methods = ["CONNECT"];
  }, /non-CONNECT/);
  mutate((value) => {
    route(value, 0).query = "b=2&a=1";
  }, /exact, canonical/);
  mutate((value) => {
    route(value, 0).query = "a=1&a=2";
  }, /uniquely keyed/);
  mutate((value) => {
    route(value, 0).query = "a=%31";
  }, /exact, canonical/);
  mutate((value) => {
    value.authorizationGrpcTarget = "user:secret@127.0.0.1:19090";
  }, /uncredentialed loopback/);
  mutate((value) => {
    route(value, 2).credential = { kind: "api-key", header: "authorization", value: "forbidden" };
  }, /security-sensitive/);
  mutate((value) => {
    route(value, 0).upstreamCaCertificatePem = `${certificate}${privateKey}`;
  }, /isolated certificate/);
});
