import assert from "node:assert/strict";
import test from "node:test";
import { types } from "node:util";
import {
  canonicalRuntimeConfig,
  parseRuntimeConfigBytes,
  type RuntimeConfig,
  RuntimeConfigError,
  validateRuntimeConfig,
} from "../src/runtime/config.ts";

function validRuntime(): RuntimeConfig {
  return {
    version: "cogs.runtime/v1alpha1",
    profile: "api-key-only",
    paths: {
      launch_document: "/etc/cogs/launch.json",
      api_bearer: "/run/cogs/api/bearer",
      openbao_jwt: "/run/cogs/openbao/jwt",
      proxy_capability: "/run/cogs/proxy/capability",
      envoy_executable: "/usr/local/bin/envoy",
      egress_tmpfs: "/run/cogs/egress",
      audit_wal: "/var/lib/cogs/session/egress-audit.wal",
      agent_directory: "/var/lib/cogs/session/agent",
      session_root: "/var/lib/cogs/session/sessions",
      shared_skill_oci: "/var/lib/cogs/skills/shared-oci",
      private_skill_source: "/var/lib/cogs/skills/private-source",
      private_skill_store: "/var/lib/cogs/skills/private-store",
    },
    api: { listen_host: "127.0.0.1", port: 8080 },
    openbao: {
      origin: "https://openbao.internal:8200/",
      kubernetes_auth_mount: "kubernetes-cogs",
      kubernetes_auth_role: "cogs-worker",
      model_kv_mount: "model",
      egress_kv_mount: "egress",
      pki_mount: "pki",
      pki_role: "cogs-egress",
      projected_jwt_ttl_seconds: 600,
      max_client_token_ttl_seconds: 600,
    },
    otlp: {
      protocol: "http/json",
      traces_endpoint: "https://otel.internal:4318/v1/traces",
      metrics_endpoint: "https://otel.internal:4318/v1/metrics",
      logs_endpoint: "https://otel.internal:4318/v1/logs",
    },
    egress: { listener_port: 15001, revocation_poll_seconds: 30, completion_capacity: 64 },
    lifecycle: { maximum_session_seconds: 28800, shutdown_timeout_seconds: 20 },
  };
}

// biome-ignore lint/suspicious/noExplicitAny: hostile mutations intentionally cross the strict runtime type
function mutation(change: (runtime: Record<string, any>) => void): unknown {
  // biome-ignore lint/suspicious/noExplicitAny: hostile mutations intentionally cross the strict runtime type
  const value = structuredClone(validRuntime()) as unknown as Record<string, any>;
  change(value);
  return value;
}

function rejects(value: unknown): void {
  assert.throws(
    () => validateRuntimeConfig(value),
    (error) => {
      assert.ok(error instanceof RuntimeConfigError);
      assert.equal(error.message, "invalid production runtime configuration");
      return true;
    },
  );
}

test("runtime contract validates, snapshots, freezes, and canonicalizes the fixed API-key-only profile", () => {
  const input = validRuntime();
  const runtime = validateRuntimeConfig(input);
  assert.notEqual(runtime, input);
  assert.equal(Object.isFrozen(runtime), true);
  assert.equal(Object.isFrozen(runtime.paths), true);
  assert.equal(Object.isFrozen(runtime.openbao), true);
  assert.equal(runtime.profile, "api-key-only");
  const canonical = canonicalRuntimeConfig(runtime);
  assert.equal(canonical.endsWith("\n"), true);
  assert.deepEqual(parseRuntimeConfigBytes(Buffer.from(canonical)), runtime);
});

test("runtime contract rejects every mutable path, profile, protocol, bound, and unknown field", () => {
  // biome-ignore lint/suspicious/noExplicitAny: hostile mutations intentionally cross the strict runtime type
  const cases: Array<(runtime: Record<string, any>) => void> = [
    (value) => (value.version = "cogs.runtime/v2"),
    (value) => (value.profile = "oauth"),
    (value) => (value.paths.launch_document = "/tmp/launch.json"),
    (value) => (value.paths.api_bearer = "/run/cogs/other"),
    (value) => (value.paths.openbao_jwt = "/run/cogs/openbao/token"),
    (value) => (value.paths.envoy_executable = "/tmp/envoy"),
    (value) => (value.api.listen_host = "::"),
    (value) => (value.api.port = 80),
    (value) => (value.api.port = value.egress.listener_port),
    (value) => (value.openbao.projected_jwt_ttl_seconds = 601),
    (value) => (value.openbao.max_client_token_ttl_seconds = 3600),
    (value) => (value.openbao.kubernetes_auth_mount = "bad/mount"),
    (value) => (value.otlp.protocol = "grpc"),
    (value) => (value.otlp.protocol = "http/protobuf"),
    (value) => (value.egress.revocation_poll_seconds = 61),
    (value) => (value.lifecycle.maximum_session_seconds = 28801),
    (value) => (value.unexpected = true),
    (value) => (value.openbao.unexpected = true),
  ];
  for (const change of cases) rejects(mutation(change));
});

test("runtime contract accepts only canonical HTTPS origins and exact OTLP signal paths", () => {
  for (const origin of [
    "http://openbao.internal:8200/",
    "https://user@openbao.internal/",
    "https://openbao.internal/base",
    "https://openbao.internal/?query=1",
    "https://openbao.internal/#fragment",
    "https://openbao.internal:0/",
    "https://OPENBAO.internal/",
    "https://openbao.internal",
  ])
    rejects(mutation((value) => (value.openbao.origin = origin)));
  for (const endpoint of [
    "http://otel.internal:4318/v1/traces",
    "https://user@otel.internal/v1/traces",
    "https://otel.internal/v1/logs",
    "https://otel.internal/v1/traces?x=1",
    "https://OTEL.internal/v1/traces",
  ])
    rejects(mutation((value) => (value.otlp.traces_endpoint = endpoint)));
});

test("runtime byte parser rejects noncanonical JSON, duplicate keys, BOM, malformed UTF-8, and bounds", () => {
  const canonical = canonicalRuntimeConfig(validRuntime());
  const variants = [
    canonical.slice(0, -1),
    ` ${canonical}`,
    canonical.replace(":", ": "),
    canonical.replace('"version":', '"version":"cogs.runtime/v1alpha1","version":'),
    `\ufeff${canonical}`,
    `${canonical}\n`,
  ];
  for (const value of variants) assert.throws(() => parseRuntimeConfigBytes(Buffer.from(value)), RuntimeConfigError);
  assert.throws(() => parseRuntimeConfigBytes(Buffer.from([0xc3, 0x28, 0x0a])), RuntimeConfigError);
  assert.throws(() => parseRuntimeConfigBytes(Buffer.alloc(32 * 1024 + 1, 0x61)), RuntimeConfigError);
  assert.throws(() => parseRuntimeConfigBytes(new Proxy(new Uint8Array([1, 2]), {})), RuntimeConfigError);
});

test("runtime snapshot rejects getters and Proxies before executing traps", () => {
  let getterCalls = 0;
  const getter = validRuntime() as unknown as Record<string, unknown>;
  Object.defineProperty(getter, "profile", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "api-key-only";
    },
  });
  rejects(getter);
  assert.equal(getterCalls, 0);

  let trapCalls = 0;
  const proxy = new Proxy(validRuntime(), {
    getPrototypeOf() {
      trapCalls += 1;
      return Object.prototype;
    },
    ownKeys() {
      trapCalls += 1;
      return [];
    },
  });
  assert.equal(types.isProxy(proxy), true);
  rejects(proxy);
  assert.equal(trapCalls, 0);

  const nested = validRuntime();
  (nested as unknown as { openbao: RuntimeConfig["openbao"] }).openbao = new Proxy(nested.openbao, {
    ownKeys() {
      trapCalls += 1;
      return [];
    },
  });
  rejects(nested);
  assert.equal(trapCalls, 0);

  const prototypeKey = validRuntime() as unknown as Record<string, unknown>;
  Object.defineProperty(prototypeKey, "__proto__", { value: {}, enumerable: true });
  rejects(prototypeKey);
});
