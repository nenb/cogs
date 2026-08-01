import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import {
  evaluateStage4PolicyProbe,
  STAGE4_POLICY_REASON_CODES,
  STAGE4_POLICY_TRANSITIONS,
  validateStage4PolicyContract,
  validateStage4PolicyProbeSuite,
} from "../scripts/stage4-policy-contract.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const contractPath = resolve(root, "test/fixtures/stage4-policy/valid-contract-v1.json");
const probesPath = resolve(root, "test/fixtures/stage4-policy/hostile-probes-v1.json");
const contractSchema = JSON.parse(readFileSync(resolve(root, "schemas/stage4-policy-contract-v1.json"), "utf8"));
const probeSchema = JSON.parse(readFileSync(resolve(root, "schemas/stage4-policy-probe-suite-v1.json"), "utf8"));

type Json = Record<string, unknown>;
type ProbeSuite = Json & { probes: Array<Json & { id: string; expected: { allow: boolean; reason: string } }> };

function contract(): Json {
  return JSON.parse(readFileSync(contractPath, "utf8")) as Json;
}

function probes(): ProbeSuite {
  return JSON.parse(readFileSync(probesPath, "utf8")) as ProbeSuite;
}

function nested(value: Json, ...path: string[]): Json {
  let current = value;
  for (const key of path) current = current[key] as Json;
  return current;
}

function assertStaticOnly(result: Record<string, unknown>): void {
  assert.equal(result.authority, "static-only-stage4-policy");
  assert.equal(result.qualification, "pending-exact-eks-cni-runtime");
  assert.equal(result.cloud_execution_observed, false);
  assert.equal(result.cni_runtime_qualified, false);
  assert.equal(result.stage4_exit_satisfied, false);
  assert.equal(result.release_eligible, false);
}

test("strict schemas accept the bounded contract and broad hostile probe inventory", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  const validateContract = ajv.compile(contractSchema);
  const validateProbes = ajv.compile(probeSchema);
  assert.equal(validateContract(contract()), true, ajv.errorsText(validateContract.errors));
  assert.equal(validateProbes(probes()), true, ajv.errorsText(validateProbes.errors));
  assert.equal(validateStage4PolicyProbeSuite(probes()), true);

  const unknownContract = contract();
  unknownContract.cloud = { enabled: true };
  assert.equal(validateContract(unknownContract), false);
  const unknownProbe = probes();
  const firstUnknownProbe = unknownProbe.probes[0];
  assert.ok(firstUnknownProbe);
  firstUnknownProbe.command = "forbidden";
  assert.equal(validateProbes(unknownProbe), false);
});

test("valid contract produces only a deterministic static binding and readable fail-closed transitions", () => {
  const first = validateStage4PolicyContract(contract());
  const reordered = {
    telemetry: contract().telemetry,
    network: contract().network,
    proxy: contract().proxy,
    openbao: contract().openbao,
    identity: contract().identity,
    session: contract().session,
    qualification: contract().qualification,
    authority: contract().authority,
    version: contract().version,
    audit_wal: contract().audit_wal,
  };
  const second = validateStage4PolicyContract(reordered);
  assert.equal(first.valid, true);
  assert.deepEqual(first.reason_codes, ["STAGE4_POLICY_VALID"]);
  assert.match(first.contract_sha256 ?? "", /^[0-9a-f]{64}$/u);
  assert.equal(second.contract_sha256, first.contract_sha256);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.transitions.proxyCapability), true);
  assertStaticOnly(first as unknown as Record<string, unknown>);
  assert.deepEqual(STAGE4_POLICY_TRANSITIONS.proxyCapability, [
    "absent",
    "trusted-worker-generated",
    "immutable-session-source-bound",
    "active",
    "deny-new",
    "drain-connections",
    "request-replacement",
    "old-capability-invalid",
  ]);
  assert.deepEqual(STAGE4_POLICY_TRANSITIONS.credentialedEgressFailure, [
    "authorization-or-wal-failure",
    "deny",
    "recycle-required",
    "no-direct-fallback",
  ]);
});

test("trusted-worker identity is exact while sandbox identity and broad OpenBao authority fail closed", () => {
  const identity = contract();
  nested(identity, "openbao").bound_service_account = "cogs-sandbox-inert";
  assert.deepEqual(validateStage4PolicyContract(identity).reason_codes, ["STAGE4_POLICY_IDENTITY_BINDING_INVALID"]);

  const crossUser = contract();
  const handles = nested(crossUser, "openbao").exact_handles as Array<Json>;
  const firstHandle = handles[0];
  assert.ok(firstHandle);
  firstHandle.handle = "users/other-user/models/anthropic";
  assert.deepEqual(validateStage4PolicyContract(crossUser).reason_codes, ["STAGE4_POLICY_HANDLE_SCOPE_INVALID"]);

  const wrongClass = contract();
  const wrongHandles = nested(wrongClass, "openbao").exact_handles as Array<Json>;
  const secondHandle = wrongHandles[1];
  assert.ok(secondHandle);
  secondHandle.handle = "users/user-static-1/models/github";
  assert.deepEqual(validateStage4PolicyContract(wrongClass).reason_codes, ["STAGE4_POLICY_HANDLE_SCOPE_INVALID"]);

  for (const mutate of [
    (value: Json) => (nested(value, "identity", "sandbox").automount_service_account_token = true),
    (value: Json) => (nested(value, "identity", "sandbox").kubernetes_workload_identity = true),
    (value: Json) => (nested(value, "identity", "sandbox").openbao_identity = true),
    (value: Json) => (nested(value, "identity", "sandbox").cloud_identity = true),
    (value: Json) => (nested(value, "openbao").list_capability = true),
    (value: Json) => (nested(value, "openbao").broad_path_grants = true),
  ]) {
    const hostile = contract();
    mutate(hostile);
    assert.deepEqual(validateStage4PolicyContract(hostile).reason_codes, ["STAGE4_POLICY_SCHEMA_INVALID"]);
  }
});

test("selector and immutable capability session/source confusion are rejected", () => {
  const selector = contract();
  nested(selector, "identity", "sandbox", "pod_selector")["dev.cogs/proxy"] = "true";
  assert.deepEqual(validateStage4PolicyContract(selector).reason_codes, ["STAGE4_POLICY_SELECTOR_CONFUSION"]);

  const session = contract();
  nested(session, "proxy", "capability").session_id = "session-static-2";
  assert.deepEqual(validateStage4PolicyContract(session).reason_codes, ["STAGE4_POLICY_CAPABILITY_BINDING_INVALID"]);

  const source = contract();
  nested(source, "proxy", "capability", "source_binding").sandbox_selector = nested(
    source,
    "identity",
    "trusted_worker",
    "pod_selector",
  );
  assert.deepEqual(validateStage4PolicyContract(source).reason_codes, ["STAGE4_POLICY_CAPABILITY_BINDING_INVALID"]);

  const confusedAudience = contract();
  nested(confusedAudience, "proxy", "capability").audience = nested(
    confusedAudience,
    "identity",
    "trusted_worker",
    "openbao_projected_token",
  ).audience;
  assert.deepEqual(validateStage4PolicyContract(confusedAudience).reason_codes, [
    "STAGE4_POLICY_CAPABILITY_BINDING_INVALID",
  ]);

  for (const mutate of [
    (value: Json) => (nested(value, "proxy", "capability").source = "sandbox"),
    (value: Json) => (nested(value, "proxy", "capability").direct_egress_fallback = true),
    (value: Json) => (nested(value, "proxy", "route_policy").immutable = false),
    (value: Json) => (nested(value, "proxy", "revocation").old_capability_after_replacement = "valid"),
    (value: Json) => (nested(value, "network").direct_egress_fallback = true),
  ]) {
    const hostile = contract();
    mutate(hostile);
    assert.deepEqual(validateStage4PolicyContract(hostile).reason_codes, ["STAGE4_POLICY_SCHEMA_INVALID"]);
  }
});

test("metadata-only OTLP remains non-authorizing while bounded WAL failures deny credential use", () => {
  const telemetry = contract();
  nested(telemetry, "telemetry").batch_size = 129;
  nested(telemetry, "telemetry").queue_capacity = 128;
  assert.deepEqual(validateStage4PolicyContract(telemetry).reason_codes, ["STAGE4_POLICY_SCHEMA_INVALID"]);

  const semanticTelemetry = contract();
  nested(semanticTelemetry, "telemetry").batch_size = 64;
  nested(semanticTelemetry, "telemetry").queue_capacity = 32;
  assert.deepEqual(validateStage4PolicyContract(semanticTelemetry).reason_codes, [
    "STAGE4_POLICY_TELEMETRY_BOUNDS_INVALID",
  ]);

  const wal = contract();
  nested(wal, "audit_wal").max_bytes = 1024;
  nested(wal, "audit_wal").max_record_bytes = 4096;
  assert.deepEqual(validateStage4PolicyContract(wal).reason_codes, ["STAGE4_POLICY_AUDIT_WAL_BOUNDS_INVALID"]);

  for (const mutate of [
    (value: Json) => (nested(value, "telemetry").payload = "prompts-and-source"),
    (value: Json) => (nested(value, "telemetry").credential_authorization_dependency = true),
    (value: Json) => (nested(value, "audit_wal").on_failure = "forward-without-credential"),
    (value: Json) => (nested(value, "audit_wal").in_session_recovery = true),
  ]) {
    const hostile = contract();
    mutate(hostile);
    assert.deepEqual(validateStage4PolicyContract(hostile).reason_codes, ["STAGE4_POLICY_SCHEMA_INVALID"]);
  }
});

test("hostile probes cover selector confusion, dual stack, UDP/QUIC, DNS, protected surfaces, and sessions", () => {
  const suite = probes();
  assert.equal(new Set(suite.probes.map((probe) => probe.id)).size, suite.probes.length);
  const inventory = suite.probes.map((probe) => probe.id).join("\n");
  for (const pattern of [
    /selector/u,
    /ipv4/u,
    /ipv6/u,
    /udp/u,
    /quic/u,
    /dns/u,
    /metadata/u,
    /kubernetes-api/u,
    /worker-api/u,
    /proxy-admin/u,
    /openbao/u,
    /cross-session/u,
    /broad-policy/u,
  ]) {
    assert.match(inventory, pattern);
  }
  for (const probe of suite.probes) {
    const decision = evaluateStage4PolicyProbe(contract(), probe);
    assert.equal(decision.probe_id, probe.id);
    assert.equal(decision.allow, probe.expected.allow, probe.id);
    assert.equal(decision.reason, probe.expected.reason, probe.id);
    assertStaticOnly(decision as unknown as Record<string, unknown>);
  }
});

test("probe decisions permit only the assigned session proxy and never a direct-egress fallback", () => {
  const suite = probes();
  const allowed = suite.probes.filter((probe) => evaluateStage4PolicyProbe(contract(), probe).allow);
  assert.deepEqual(
    allowed.map((probe) => probe.id),
    ["allow.assigned-proxy.ipv4", "allow.assigned-proxy.ipv6"],
  );
  assert.ok(suite.probes.filter((probe) => probe.expected.allow === false).length >= 20);

  const firstProbe = suite.probes[0];
  assert.ok(firstProbe);
  const revoked = structuredClone(firstProbe);
  revoked.capability = { state: "revoked", session_id: "session-static-1" };
  assert.equal(evaluateStage4PolicyProbe(contract(), revoked).reason, "capability-revoked");

  const invalidContract = contract();
  nested(invalidContract, "network").default_deny = false;
  const invalidDecision = evaluateStage4PolicyProbe(invalidContract, suite.probes[0]);
  assert.equal(invalidDecision.reason, "contract-invalid");
  assert.equal(invalidDecision.allow, false);
  assertStaticOnly(invalidDecision as unknown as Record<string, unknown>);
});

test("hostile object introspection is bounded, generic, and non-throwing", () => {
  const getter = contract();
  let invoked = false;
  Object.defineProperty(getter, "secret", {
    enumerable: true,
    get() {
      invoked = true;
      throw new Error("must not escape");
    },
  });
  assert.doesNotThrow(() => validateStage4PolicyContract(getter));
  assert.deepEqual(validateStage4PolicyContract(getter).reason_codes, ["STAGE4_POLICY_INVALID_SHAPE"]);
  assert.equal(invoked, false);

  const proxy = new Proxy(contract(), {
    ownKeys() {
      throw new Error("must not escape");
    },
  });
  assert.deepEqual(validateStage4PolicyContract(proxy).reason_codes, ["STAGE4_POLICY_INVALID_SHAPE"]);
  assert.deepEqual(STAGE4_POLICY_REASON_CODES, [
    "STAGE4_POLICY_VALID",
    "STAGE4_POLICY_INVALID_SHAPE",
    "STAGE4_POLICY_SCHEMA_INVALID",
    "STAGE4_POLICY_IDENTITY_BINDING_INVALID",
    "STAGE4_POLICY_HANDLE_SCOPE_INVALID",
    "STAGE4_POLICY_SELECTOR_CONFUSION",
    "STAGE4_POLICY_CAPABILITY_BINDING_INVALID",
    "STAGE4_POLICY_TELEMETRY_BOUNDS_INVALID",
    "STAGE4_POLICY_AUDIT_WAL_BOUNDS_INVALID",
  ]);
});

test("validator source is local, static, pure, and provider-free", () => {
  const source = readFileSync(resolve(root, "scripts/stage4-policy-contract.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /from\s+["']node:(?:child_process|fs|http|https|http2|net|tls|dns|dgram|os|worker_threads)["']|@aws|@kubernetes|aws-sdk|kubernetes-client/iu,
  );
  assert.doesNotMatch(source, /\bprocess(?:\.|\[)|\bfetch\s*\(|\b(?:helm|kubectl|opentofu|terraform)\b/iu);
  assert.doesNotMatch(source, /authoritative-production-profile|release_eligible:\s*true/iu);
});
