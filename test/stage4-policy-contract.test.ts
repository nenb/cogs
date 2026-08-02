import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import {
  buildStage4AuditWalRecord,
  buildStage4PolicyProbeSuite,
  evaluateStage4PolicyProbe,
  REQUIRED_STAGE4_POLICY_PROBE_IDS,
  STAGE4_POLICY_REASON_CODES,
  STAGE4_POLICY_TRANSITIONS,
  validateStage4PolicyContract,
  validateStage4PolicyPayload,
  validateStage4PolicyProbeSuite,
} from "../scripts/stage4-policy-contract.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const contractPath = resolve(root, "test/fixtures/stage4-policy/valid-contract-v1.json");
const probesPath = resolve(root, "test/fixtures/stage4-policy/hostile-probes-v1.json");
const contractSchema = JSON.parse(readFileSync(resolve(root, "schemas/stage4-policy-contract-v1.json"), "utf8"));
const probeSchema = JSON.parse(readFileSync(resolve(root, "schemas/stage4-policy-probe-suite-v1.json"), "utf8"));
const payloadSchema = JSON.parse(readFileSync(resolve(root, "schemas/stage4-policy-payload-v1.json"), "utf8"));
const auditRecordPath = resolve(root, "test/fixtures/stage4-policy/valid-audit-wal-record-v1.json");
const otlpRecordPath = resolve(root, "test/fixtures/stage4-policy/valid-otlp-record-v1.json");

type Json = Record<string, unknown>;
type ProbeSuite = Json & {
  contract_sha256: string;
  probes: Array<Json & { id: string; expected: { allow: boolean; reason: string } }>;
};

function contract(): Json {
  return JSON.parse(readFileSync(contractPath, "utf8")) as Json;
}

function probes(): ProbeSuite {
  return JSON.parse(readFileSync(probesPath, "utf8")) as ProbeSuite;
}

function collisionBoundContract(): Json {
  const value = contract();
  const session = nested(value, "session");
  session.session_id = "session-other";
  session.instance_id = "cogs-other";
  for (const selector of [
    nested(value, "identity", "trusted_worker", "pod_selector"),
    nested(value, "identity", "sandbox", "pod_selector"),
    nested(value, "proxy", "selector"),
    nested(value, "proxy", "capability", "source_binding", "sandbox_selector"),
  ]) {
    selector["dev.cogs/session"] = session.session_id;
    selector["app.kubernetes.io/instance"] = session.instance_id;
  }
  const capability = nested(value, "proxy", "capability");
  capability.session_id = session.session_id;
  capability.instance_id = session.instance_id;
  capability.capability_id = "capability-forged";
  capability.generation = 1_000_000;
  const binding = nested(value, "proxy", "capability", "source_binding");
  binding.session_id = session.session_id;
  binding.instance_id = session.instance_id;
  binding.sandbox_pod_id = "sandbox-pod-other";
  nested(value, "proxy").service_name = "cogs-proxy-other";
  const replacement = nested(value, "proxy", "revocation", "replacement_identity");
  replacement.replacement_capability_id = capability.capability_id;
  replacement.replacement_generation = capability.generation;
  return value;
}

function auditRecord(): Json {
  return JSON.parse(readFileSync(auditRecordPath, "utf8")) as Json;
}

function otlpRecord(): Json {
  return JSON.parse(readFileSync(otlpRecordPath, "utf8")) as Json;
}

function probeAt(suite: ProbeSuite, index: number): ProbeSuite["probes"][number] {
  const probe = suite.probes[index];
  assert.ok(probe);
  return probe;
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
  const validatePayload = ajv.compile(payloadSchema);
  assert.equal(validateContract(contract()), true, ajv.errorsText(validateContract.errors));
  assert.equal(validateProbes(probes()), true, ajv.errorsText(validateProbes.errors));
  assert.equal(validatePayload(auditRecord()), true, ajv.errorsText(validatePayload.errors));
  assert.equal(validatePayload(otlpRecord()), true, ajv.errorsText(validatePayload.errors));
  assert.equal(validateStage4PolicyProbeSuite(contract(), probes()), true);

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

  const equalAccounts = contract();
  nested(equalAccounts, "identity", "trusted_worker").service_account = "cogs-sandbox-inert";
  nested(equalAccounts, "openbao").bound_service_account = "cogs-sandbox-inert";
  assert.deepEqual(validateStage4PolicyContract(equalAccounts).reason_codes, [
    "STAGE4_POLICY_IDENTITY_BINDING_INVALID",
  ]);

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

  const organization = contract();
  const organizationHandles = nested(organization, "openbao").exact_handles as Array<Json>;
  const organizationHandle = organizationHandles[0];
  assert.ok(organizationHandle);
  organizationHandle.handle = "organizations/org-static/models/anthropic";
  assert.deepEqual(validateStage4PolicyContract(organization).reason_codes, ["STAGE4_POLICY_SCHEMA_INVALID"]);

  for (const mutate of [
    (value: Json) => (nested(value, "identity", "sandbox").service_account = "another-account"),
    (value: Json) => (nested(value, "identity", "sandbox").automount_service_account_token = true),
    (value: Json) => (nested(value, "identity", "sandbox").kubernetes_workload_identity = false),
    (value: Json) => (nested(value, "identity", "sandbox").openbao_identity = true),
    (value: Json) => (nested(value, "identity", "sandbox").cloud_identity = false),
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

  const instance = contract();
  nested(instance, "proxy", "capability").instance_id = "cogs-other";
  assert.deepEqual(validateStage4PolicyContract(instance).reason_codes, ["STAGE4_POLICY_CAPABILITY_BINDING_INVALID"]);

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
    (value: Json) => (nested(value, "proxy", "capability").expires_at_ms = 1000),
    (value: Json) => (nested(value, "proxy", "capability").expires_at_ms = 1500),
    (value: Json) => (nested(value, "proxy", "capability").generation = 1),
    (value: Json) =>
      (nested(value, "proxy", "capability").worker_pod_id = nested(value, "proxy", "capability", "source_binding")
        .sandbox_pod_id as string),
    (value: Json) =>
      (nested(value, "proxy", "revocation", "replacement_identity").previous_capability_id = nested(
        value,
        "proxy",
        "capability",
      ).capability_id as string),
    (value: Json) => (nested(value, "proxy", "capability").source = "sandbox"),
    (value: Json) => (nested(value, "proxy", "capability").direct_egress_fallback = true),
    (value: Json) => (nested(value, "proxy", "route_policy").immutable = false),
    (value: Json) => (nested(value, "proxy", "revocation").old_capability_after_replacement = "valid"),
    (value: Json) => (nested(value, "network").direct_egress_fallback = true),
  ]) {
    const hostile = contract();
    mutate(hostile);
    const result = validateStage4PolicyContract(hostile);
    assert.equal(result.valid, false);
    assert.ok(
      result.reason_codes.includes("STAGE4_POLICY_SCHEMA_INVALID") ||
        result.reason_codes.includes("STAGE4_POLICY_CAPABILITY_BINDING_INVALID"),
    );
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

test("closed audit-WAL and OTLP payload validators reject every sensitive class and bound", () => {
  assert.deepEqual(
    buildStage4AuditWalRecord(contract(), {
      sequence: 0,
      timestamp_ms: 2000,
      method: "GET",
      credential_required: true,
    }),
    auditRecord(),
  );
  assert.equal(
    new Set([
      auditRecord().session_ref_sha256,
      auditRecord().intent_ref_sha256,
      auditRecord().policy_ref_sha256,
      auditRecord().capability_ref_sha256,
    ]).size,
    4,
  );
  for (const [record, kind] of [
    [auditRecord(), "audit-wal"],
    [otlpRecord(), "otlp"],
  ] as const) {
    const decision = validateStage4PolicyPayload(contract(), record);
    assert.equal(decision.valid, true);
    assert.equal(decision.record_kind, kind);
    assert.equal(decision.reason, "payload-valid");
    assertStaticOnly(decision as unknown as Record<string, unknown>);
  }

  const sensitiveFields = [
    "query",
    "body",
    "credential",
    "placeholder",
    "secret_handle",
    "source",
    "prompt",
    "command",
    "path",
    "user_id",
    "session_id",
    "cloud_identity",
    "kubernetes_identity",
    "openbao_identity",
    "openbao_role",
    "openbao_audience",
    "openbao_pki_role",
  ];
  for (const field of sensitiveFields) {
    const wal = auditRecord();
    wal[field] = "forbidden";
    assert.equal(validateStage4PolicyPayload(contract(), wal).reason, "payload-invalid", `wal ${field}`);

    const otlp = otlpRecord();
    nested(otlp, "attributes")[field] = "forbidden";
    assert.equal(validateStage4PolicyPayload(contract(), otlp).reason, "payload-invalid", `otlp ${field}`);
  }

  const rawSession = auditRecord();
  delete rawSession.session_ref_sha256;
  rawSession.session_id = "session-static-1";
  assert.equal(validateStage4PolicyPayload(contract(), rawSession).reason, "payload-invalid");
  for (const freeString of [
    "user-static-1",
    "session-static-1",
    "cogs-static-1",
    "cogs-trusted-session-static-1",
    "cogs-sandbox-inert",
    "worker-pod-static-2",
    "sandbox-pod-static-1",
    "cogs-session-static-1",
    "openbao.cogs.static",
    "cogs-egress-session-static-1",
    "sk-secret-shaped-value",
  ]) {
    const disguised = auditRecord();
    disguised.intent_id = freeString;
    assert.equal(validateStage4PolicyPayload(contract(), disguised).reason, "payload-invalid", freeString);
  }
  for (const sensitiveString of [
    "cogs-session-static-1",
    "openbao.cogs.static",
    "cogs-egress-session-static-1",
    "users/user-static-1/pki/issue/cogs-client",
    "sk-secret-shaped-value",
  ]) {
    const embedded = auditRecord();
    embedded.session_ref_sha256 = sensitiveString;
    assert.equal(validateStage4PolicyPayload(contract(), embedded).reason, "payload-invalid", sensitiveString);
  }
  for (const reference of ["session_ref_sha256", "intent_ref_sha256", "policy_ref_sha256", "capability_ref_sha256"]) {
    const forged = auditRecord();
    const replacement = forged[reference] === "a".repeat(64) ? "b".repeat(64) : "a".repeat(64);
    forged[reference] = replacement;
    assert.equal(validateStage4PolicyPayload(contract(), forged).reason, "payload-invalid", reference);
  }
  const reboundContract = collisionBoundContract();
  assert.equal(validateStage4PolicyPayload(reboundContract, auditRecord()).reason, "payload-invalid");
  const reboundRecord = buildStage4AuditWalRecord(reboundContract, {
    sequence: 0,
    timestamp_ms: 2000,
    method: "GET",
    credential_required: true,
  });
  assert.ok(reboundRecord);
  assert.notEqual(reboundRecord.session_ref_sha256, auditRecord().session_ref_sha256);
  assert.equal(validateStage4PolicyPayload(reboundContract, reboundRecord).reason, "payload-valid");

  const tinyContract = contract();
  nested(tinyContract, "audit_wal").max_record_bytes = 256;
  const rebuiltLargeWal = buildStage4AuditWalRecord(tinyContract, {
    sequence: 0,
    timestamp_ms: 2000,
    method: "GET",
    credential_required: true,
  });
  assert.ok(rebuiltLargeWal);
  assert.equal(validateStage4PolicyPayload(tinyContract, rebuiltLargeWal).reason, "payload-too-large");

  const oversizedDepth = otlpRecord();
  nested(oversizedDepth, "attributes").queue_depth = 1025;
  assert.equal(validateStage4PolicyPayload(contract(), oversizedDepth).reason, "payload-invalid");

  let getterInvoked = false;
  const accessor = auditRecord();
  Object.defineProperty(accessor, "query", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not escape");
    },
  });
  assert.equal(validateStage4PolicyPayload(contract(), accessor).reason, "payload-invalid");
  assert.equal(getterInvoked, false);
});

test("probe suite is the exact unique ordered semantic inventory and every expected decision is honest", () => {
  const suite = probes();
  assert.deepEqual(
    suite.probes.map((probe) => probe.id),
    REQUIRED_STAGE4_POLICY_PROBE_IDS,
  );
  assert.equal(new Set(suite.probes.map((probe) => probe.id)).size, REQUIRED_STAGE4_POLICY_PROBE_IDS.length);
  assert.deepEqual(buildStage4PolicyProbeSuite(contract()), suite);
  assert.equal(validateStage4PolicyProbeSuite(contract(), suite), true);
  for (const [id, transport, destinationClass] of [
    ["deny.quic.udp443.ipv6", "quic", "direct-host"],
    ["deny.dns.arbitrary.ipv6", "dns", "resolver"],
    ["deny.dns.over-https.ipv6", "doh", "direct-host"],
    ["deny.kubernetes-api.ipv6", "tcp", "kubernetes-api"],
    ["deny.worker-api.ipv6", "tcp", "worker-api"],
    ["deny.proxy-admin.ipv6", "tcp", "proxy-admin"],
    ["deny.openbao.ipv6", "tcp", "openbao"],
  ]) {
    const probe = suite.probes.find((candidate) => candidate.id === id);
    assert.ok(probe);
    assert.equal(probe.address_family, "IPv6");
    assert.equal(probe.transport, transport);
    assert.equal(nested(probe, "destination").class, destinationClass);
    assert.equal(probe.expected.allow, false);
  }
  for (const probe of suite.probes) {
    const decision = evaluateStage4PolicyProbe(contract(), probe);
    assert.equal(decision.probe_id, probe.id);
    assert.equal(decision.allow, probe.expected.allow, probe.id);
    assert.equal(decision.reason, probe.expected.reason, probe.id);
    assertStaticOnly(decision as unknown as Record<string, unknown>);
  }

  const dishonestSuites: ProbeSuite[] = [];
  const duplicate = probes();
  duplicate.probes[1] = structuredClone(probeAt(duplicate, 0));
  dishonestSuites.push(duplicate);
  const omitted = probes();
  omitted.probes.pop();
  dishonestSuites.push(omitted);
  const reordered = probes();
  [reordered.probes[0], reordered.probes[1]] = [probeAt(reordered, 1), probeAt(reordered, 0)];
  dishonestSuites.push(reordered);
  const substituted = probes();
  probeAt(substituted, 5).id = "deny.broad-policy-peer";
  dishonestSuites.push(substituted);
  const dishonestExpected = probes();
  probeAt(dishonestExpected, 10).expected = { allow: true, reason: "assigned-proxy-only" };
  dishonestSuites.push(dishonestExpected);
  const vacuous = probes();
  vacuous.probes = vacuous.probes.map((probe) => ({
    ...probe,
    expected: { allow: false, reason: "broad-policy-denied" },
  }));
  dishonestSuites.push(vacuous);
  const semanticSubstitution = probes();
  probeAt(semanticSubstitution, 23).destination = {
    class: "assigned-proxy",
    session_id: "session-static-1",
    service_name: "cogs-proxy-session-static-1",
    port: 15001,
  };
  dishonestSuites.push(semanticSubstitution);
  for (const hostile of dishonestSuites) assert.equal(validateStage4PolicyProbeSuite(contract(), hostile), false);

  let getterInvoked = false;
  const accessorSuite = probes();
  Object.defineProperty(accessorSuite, "extra", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not escape");
    },
  });
  assert.equal(validateStage4PolicyProbeSuite(contract(), accessorSuite), false);
  assert.equal(getterInvoked, false);
});

test("required probes derive bounded non-colliding alternates at string and listener boundaries", () => {
  const collisionContract = collisionBoundContract();
  assert.equal(validateStage4PolicyContract(collisionContract).valid, true);
  const collisionSuite = buildStage4PolicyProbeSuite(collisionContract);
  assert.ok(collisionSuite);
  assert.equal(validateStage4PolicyProbeSuite(collisionContract, collisionSuite), true);
  const byId = (id: string) => {
    const probe = collisionSuite.probes.find((candidate) => candidate.id === id);
    assert.ok(probe);
    return probe;
  };
  assert.notEqual(byId("deny.source.cross-session").source_session_id, "session-other");
  assert.notEqual(byId("deny.source.instance-confusion").source_instance_id, "cogs-other");
  assert.notEqual(byId("deny.source.pod-confusion").source_pod_id, "sandbox-pod-other");
  assert.notEqual(byId("deny.assigned-proxy.service-confusion").destination.service_name, "cogs-proxy-other");
  assert.notEqual(byId("deny.capability.id-confusion").capability.capability_id, "capability-forged");
  assert.notEqual(byId("deny.capability.generation-confusion").capability.generation, 1_000_000);

  const boundedContract = collisionBoundContract();
  const boundedSession = "s".repeat(63);
  const boundedInstance = "i".repeat(63);
  const boundedPod = "p".repeat(128);
  const boundedCapability = "c".repeat(128);
  const boundedService = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
  nested(boundedContract, "session").session_id = boundedSession;
  nested(boundedContract, "session").instance_id = boundedInstance;
  for (const selector of [
    nested(boundedContract, "identity", "trusted_worker", "pod_selector"),
    nested(boundedContract, "identity", "sandbox", "pod_selector"),
    nested(boundedContract, "proxy", "selector"),
    nested(boundedContract, "proxy", "capability", "source_binding", "sandbox_selector"),
  ]) {
    selector["dev.cogs/session"] = boundedSession;
    selector["app.kubernetes.io/instance"] = boundedInstance;
  }
  const boundedCapabilityContract = nested(boundedContract, "proxy", "capability");
  boundedCapabilityContract.session_id = boundedSession;
  boundedCapabilityContract.instance_id = boundedInstance;
  boundedCapabilityContract.capability_id = boundedCapability;
  const boundedBinding = nested(boundedContract, "proxy", "capability", "source_binding");
  boundedBinding.session_id = boundedSession;
  boundedBinding.instance_id = boundedInstance;
  boundedBinding.sandbox_pod_id = boundedPod;
  nested(boundedContract, "proxy").service_name = boundedService;
  nested(boundedContract, "proxy", "revocation", "replacement_identity").replacement_capability_id = boundedCapability;
  const boundedSuite = buildStage4PolicyProbeSuite(boundedContract);
  assert.ok(boundedSuite);
  assert.equal(validateStage4PolicyProbeSuite(boundedContract, boundedSuite), true);
  for (const [id, current, alternate] of [
    [
      "deny.source.cross-session",
      boundedSession,
      boundedSuite.probes.find((probe) => probe.id === "deny.source.cross-session")?.source_session_id,
    ],
    [
      "deny.source.instance-confusion",
      boundedInstance,
      boundedSuite.probes.find((probe) => probe.id === "deny.source.instance-confusion")?.source_instance_id,
    ],
    [
      "deny.source.pod-confusion",
      boundedPod,
      boundedSuite.probes.find((probe) => probe.id === "deny.source.pod-confusion")?.source_pod_id,
    ],
    [
      "deny.assigned-proxy.service-confusion",
      boundedService,
      boundedSuite.probes.find((probe) => probe.id === "deny.assigned-proxy.service-confusion")?.destination
        .service_name,
    ],
    [
      "deny.capability.id-confusion",
      boundedCapability,
      boundedSuite.probes.find((probe) => probe.id === "deny.capability.id-confusion")?.capability.capability_id,
    ],
  ] as const) {
    assert.ok(typeof alternate === "string", id);
    assert.notEqual(alternate, current, id);
    assert.ok(alternate.length <= current.length, id);
  }

  for (const [listenerPort, expectedAlternate] of [
    [65_535, 65_534],
    [65_534, 65_535],
  ] as const) {
    const boundaryContract = contract();
    nested(boundaryContract, "proxy").listener_port = listenerPort;
    const suite = buildStage4PolicyProbeSuite(boundaryContract);
    assert.ok(suite);
    assert.equal(validateStage4PolicyProbeSuite(boundaryContract, suite), true);
    assert.equal(
      suite.probes.find((probe) => probe.id === "deny.alternate-proxy-port")?.destination.port,
      expectedAlternate,
    );
  }

  const issuanceBoundary = contract();
  const capability = nested(issuanceBoundary, "proxy", "capability");
  capability.issued_at_ms = 1;
  capability.expires_at_ms = 28_800_001;
  const issuanceSuite = buildStage4PolicyProbeSuite(issuanceBoundary);
  assert.ok(issuanceSuite);
  assert.equal(validateStage4PolicyProbeSuite(issuanceBoundary, issuanceSuite), true);
  assert.equal(issuanceSuite.probes.find((probe) => probe.id === "deny.capability.before-issued")?.observed_at_ms, 0);
  const zeroIssuance = structuredClone(issuanceBoundary);
  nested(zeroIssuance, "proxy", "capability").issued_at_ms = 0;
  assert.deepEqual(validateStage4PolicyContract(zeroIssuance).reason_codes, ["STAGE4_POLICY_SCHEMA_INVALID"]);
});

test("probe decisions cover no-fallback networking and real capability replacement/expiry identity", () => {
  const suite = probes();
  const allowed = suite.probes.filter((probe) => evaluateStage4PolicyProbe(contract(), probe).allow);
  assert.deepEqual(
    allowed.map((probe) => probe.id),
    ["allow.assigned-proxy.ipv4", "allow.assigned-proxy.ipv6"],
  );
  for (const [id, reason] of [
    ["deny.capability.missing", "capability-missing"],
    ["deny.capability.revoked", "capability-revoked"],
    ["deny.capability.replaced", "capability-replaced"],
    ["deny.capability.before-issued", "capability-not-yet-valid"],
    ["deny.capability.expired", "capability-expired"],
    ["deny.direct-host.ipv4", "direct-egress-denied"],
    ["deny.direct-host.ipv6", "direct-egress-denied"],
  ]) {
    const probe = suite.probes.find((candidate) => candidate.id === id);
    assert.ok(probe);
    assert.equal(evaluateStage4PolicyProbe(contract(), probe).reason, reason);
  }

  const replacementProbe = suite.probes.find((probe) => probe.id === "deny.capability.replaced");
  assert.ok(replacementProbe);
  const replaced = structuredClone(replacementProbe);
  nested(replaced, "capability").replacement_capability_id = "forged-replacement";
  assert.equal(evaluateStage4PolicyProbe(contract(), replaced).reason, "probe-invalid");

  const inconsistentProbe = structuredClone(suite.probes[0]);
  assert.ok(inconsistentProbe);
  const expires = nested(inconsistentProbe, "capability").expires_at_ms;
  assert.equal(typeof expires, "number");
  nested(inconsistentProbe, "capability").expires_at_ms = (expires as number) - 1;
  assert.equal(evaluateStage4PolicyProbe(contract(), inconsistentProbe).reason, "probe-invalid");

  const invalidContract = contract();
  nested(invalidContract, "network").default_deny = false;
  const first = suite.probes[0];
  assert.ok(first);
  const invalidDecision = evaluateStage4PolicyProbe(invalidContract, first);
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
