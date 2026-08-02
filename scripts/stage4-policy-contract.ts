import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const contractSchema = require("../schemas/stage4-policy-contract-v1.json") as object;
const probeSchema = require("../schemas/stage4-policy-probe-suite-v1.json") as object;
const payloadSchema = require("../schemas/stage4-policy-payload-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateContractSchema = ajv.compile(contractSchema) as ValidateFunction<Stage4PolicyContract>;
const validateProbeSuiteSchema = ajv.compile(probeSchema) as ValidateFunction<Stage4PolicyProbeSuite>;
const validateProbeSchema = ajv.compile({
  $ref: "https://cogs.dev/schemas/stage4-policy-probe-suite-v1.json#/$defs/probe",
}) as ValidateFunction<Stage4PolicyProbe>;
const validatePayloadSchema = ajv.compile(payloadSchema) as ValidateFunction<Stage4PolicyPayload>;

const CONTRACT_DOMAIN = "cogs.stage4/static-policy-contract-semantic-binding/v1";
const AUDIT_SESSION_REF_DOMAIN = "cogs.stage4/audit-session-reference/v1";
const AUDIT_POLICY_REF_DOMAIN = "cogs.stage4/audit-policy-reference/v1";
const AUDIT_CAPABILITY_REF_DOMAIN = "cogs.stage4/audit-capability-reference/v1";
const AUDIT_INTENT_REF_DOMAIN = "cogs.stage4/audit-intent-reference/v1";
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const MAX_SNAPSHOT_NODES = 4096;
const MAX_SNAPSHOT_DEPTH = 16;

export const REQUIRED_STAGE4_POLICY_PROBE_IDS = Object.freeze([
  "allow.assigned-proxy.ipv4",
  "allow.assigned-proxy.ipv6",
  "deny.selector.empty",
  "deny.selector.trusted-role",
  "deny.selector.proxy-role-confusion",
  "deny.assigned-proxy.service-confusion",
  "deny.source.cross-session",
  "deny.source.instance-confusion",
  "deny.source.pod-confusion",
  "deny.capability.missing",
  "deny.capability.revoked",
  "deny.capability.replaced",
  "deny.capability.before-issued",
  "deny.capability.expired",
  "deny.capability.id-confusion",
  "deny.capability.generation-confusion",
  "deny.capability.cross-session",
  "deny.destination.cross-session-proxy",
  "deny.destination.cross-session-workload",
  "deny.udp.ipv4",
  "deny.udp.ipv6",
  "deny.quic.udp443.ipv4",
  "deny.dns.arbitrary.ipv4",
  "deny.dns.over-https.ipv4",
  "deny.quic.udp443.ipv6",
  "deny.dns.arbitrary.ipv6",
  "deny.dns.over-https.ipv6",
  "deny.direct-host.ipv4",
  "deny.direct-host.ipv6",
  "deny.direct-ip.ipv4",
  "deny.direct-ip.ipv6",
  "deny.alternate-proxy-port",
  "deny.metadata.ipv4",
  "deny.metadata.ipv6",
  "deny.kubernetes-api.ipv4",
  "deny.worker-api.ipv4",
  "deny.proxy-admin.ipv4",
  "deny.openbao.ipv4",
  "deny.kubernetes-api.ipv6",
  "deny.worker-api.ipv6",
  "deny.proxy-admin.ipv6",
  "deny.openbao.ipv6",
  "deny.broad-policy-peer",
] as const);

export const STAGE4_POLICY_TRANSITIONS = deepFreeze({
  identity: [
    "admission",
    "trusted-worker-token-projected",
    "openbao-login",
    "exact-handle-use",
    "revoke-or-expire-to-unready",
  ],
  sandboxIdentity: ["admission", "no-kubernetes-openbao-or-cloud-credential"],
  proxyCapability: [
    "absent",
    "trusted-worker-generated",
    "immutable-session-source-bound",
    "active",
    "deny-new",
    "drain-connections",
    "request-replacement",
    "old-capability-invalid",
  ],
  credentialedEgress: [
    "route-and-session-authorized",
    "wal-append",
    "wal-sync",
    "credential-use",
    "completion-export-async",
  ],
  credentialedEgressFailure: ["authorization-or-wal-failure", "deny", "recycle-required", "no-direct-fallback"],
  telemetry: ["metadata-enqueued", "bounded-export-or-drop", "ordinary-work-continues"],
} as const);

export const STAGE4_POLICY_REASON_CODES = Object.freeze([
  "STAGE4_POLICY_VALID",
  "STAGE4_POLICY_INVALID_SHAPE",
  "STAGE4_POLICY_SCHEMA_INVALID",
  "STAGE4_POLICY_IDENTITY_BINDING_INVALID",
  "STAGE4_POLICY_HANDLE_SCOPE_INVALID",
  "STAGE4_POLICY_SELECTOR_CONFUSION",
  "STAGE4_POLICY_CAPABILITY_BINDING_INVALID",
  "STAGE4_POLICY_TELEMETRY_BOUNDS_INVALID",
  "STAGE4_POLICY_AUDIT_WAL_BOUNDS_INVALID",
] as const);

export type Stage4PolicyReasonCode = (typeof STAGE4_POLICY_REASON_CODES)[number];
export type Stage4PolicyProbeReason =
  | "assigned-proxy-only"
  | "source-session-mismatch"
  | "source-instance-mismatch"
  | "source-pod-mismatch"
  | "selector-confusion"
  | "capability-missing"
  | "capability-revoked"
  | "capability-replaced"
  | "capability-not-yet-valid"
  | "capability-expired"
  | "capability-id-mismatch"
  | "capability-generation-mismatch"
  | "capability-session-mismatch"
  | "udp-quic-denied"
  | "dns-resolver-denied"
  | "direct-egress-denied"
  | "protected-surface-denied"
  | "cross-session-denied"
  | "broad-policy-denied"
  | "alternate-port-denied"
  | "proxy-service-mismatch"
  | "contract-invalid"
  | "probe-invalid";

type Selector = Readonly<Record<string, string>>;
type ExactHandle = Readonly<{ purpose: "model-api-key" | "integration-credential"; handle: string }>;

export type Stage4PolicyContract = Readonly<{
  version: "cogs.stage4-policy-contract/v1";
  authority: "static-only-stage4-policy";
  qualification: "pending-exact-eks-cni-runtime";
  session: Readonly<{ user_id: string; session_id: string; instance_id: string }>;
  identity: Readonly<{
    trusted_worker: Readonly<{
      namespace: string;
      service_account: string;
      pod_selector: Selector;
      openbao_projected_token: Readonly<{ audience: string; expiration_seconds: number; path: string }>;
    }>;
    sandbox: Readonly<{ service_account: string; pod_selector: Selector }>;
  }>;
  openbao: Readonly<{
    bound_namespace: string;
    bound_service_account: string;
    bound_audiences: readonly string[];
    exact_handles: readonly ExactHandle[];
  }>;
  proxy: Readonly<{
    service_name: string;
    listener_port: number;
    selector: Selector;
    capability: Readonly<{
      audience: string;
      session_id: string;
      instance_id: string;
      worker_pod_id: string;
      capability_id: string;
      generation: number;
      issued_at_ms: number;
      expires_at_ms: number;
      lifetime_seconds: number;
      source_binding: Readonly<{
        session_id: string;
        instance_id: string;
        sandbox_pod_id: string;
        sandbox_selector: Selector;
      }>;
    }>;
    route_policy: Readonly<{ source: string; sha256: string; immutable: true }>;
    revocation: Readonly<{
      replacement_identity: Readonly<{
        previous_capability_id: string;
        replacement_capability_id: string;
        replacement_generation: number;
        replacement_worker_pod_id: string;
      }>;
    }>;
  }>;
  network: Readonly<{ address_families: readonly ["IPv4", "IPv6"] }>;
  telemetry: Readonly<{ queue_capacity: number; batch_size: number }>;
  audit_wal: Readonly<{ max_bytes: number; max_records: number; max_record_bytes: number }>;
}>;

export type Stage4PolicyContractVerdict = Readonly<{
  version: "cogs.stage4-policy-verdict/v1";
  authority: "static-only-stage4-policy";
  qualification: "pending-exact-eks-cni-runtime";
  valid: boolean;
  contract_sha256: string | null;
  reason_codes: readonly Stage4PolicyReasonCode[];
  cloud_execution_observed: false;
  cni_runtime_qualified: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  transitions: typeof STAGE4_POLICY_TRANSITIONS;
}>;

type ProbeDestinationClass =
  | "assigned-proxy"
  | "direct-host"
  | "direct-ip"
  | "resolver"
  | "cloud-metadata"
  | "kubernetes-api"
  | "worker-api"
  | "proxy-admin"
  | "openbao"
  | "other-session-proxy"
  | "other-session-workload"
  | "broad-policy-peer";

export type Stage4PolicyProbe = Readonly<{
  id: string;
  observed_at_ms: number;
  source_session_id: string;
  source_instance_id: string;
  source_pod_id: string;
  source_selector: Selector;
  transport: "tcp" | "udp" | "quic" | "dns" | "doh";
  address_family: "IPv4" | "IPv6";
  destination: Readonly<{
    class: ProbeDestinationClass;
    session_id: string | null;
    service_name: string | null;
    port: number;
  }>;
  capability: Readonly<{
    state: "active" | "revoked" | "missing" | "replaced" | "expired";
    session_id: string | null;
    capability_id: string | null;
    generation: number | null;
    expires_at_ms: number | null;
    replacement_capability_id: string | null;
  }>;
  expected: Readonly<{ allow: boolean; reason: Stage4PolicyProbeReason }>;
}>;

export type Stage4PolicyProbeSuite = Readonly<{
  version: "cogs.stage4-policy-probe-suite/v1";
  authority: "static-only-stage4-policy";
  qualification: "pending-exact-eks-cni-runtime";
  contract_sha256: string;
  probes: readonly Stage4PolicyProbe[];
}>;

export type Stage4PolicyPayload = Readonly<Record<string, unknown>>;

export type Stage4AuditWalRecord = Readonly<{
  version: "cogs.stage4-audit-wal-record/v1";
  sequence: number;
  timestamp_ms: number;
  session_ref_sha256: string;
  intent_ref_sha256: string;
  policy_ref_sha256: string;
  capability_ref_sha256: string;
  method: "GET" | "POST";
  credential_required: boolean;
}>;

export type Stage4PolicyPayloadDecision = Readonly<{
  version: "cogs.stage4-policy-payload-decision/v1";
  authority: "static-only-stage4-policy";
  qualification: "pending-exact-eks-cni-runtime";
  valid: boolean;
  record_kind: "audit-wal" | "otlp" | null;
  reason: "payload-valid" | "payload-invalid" | "payload-too-large" | "contract-invalid";
  cloud_execution_observed: false;
  cni_runtime_qualified: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
}>;

export type Stage4PolicyProbeDecision = Readonly<{
  version: "cogs.stage4-policy-probe-decision/v1";
  authority: "static-only-stage4-policy";
  qualification: "pending-exact-eks-cni-runtime";
  probe_id: string | null;
  allow: boolean;
  reason: Stage4PolicyProbeReason;
  cloud_execution_observed: false;
  cni_runtime_qualified: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
}>;

/**
 * Validates one already-decoded, metadata-only contract. It performs no I/O,
 * discovery, rendering, deployment, provider call, or authority promotion.
 */
export function validateStage4PolicyContract(input: unknown): Stage4PolicyContractVerdict {
  const snapshot = snapshotJson(input);
  if (snapshot === null) return contractVerdict(null, ["STAGE4_POLICY_INVALID_SHAPE"]);
  if (!validateContractSchema(snapshot)) return contractVerdict(null, ["STAGE4_POLICY_SCHEMA_INVALID"]);

  const reasons: Stage4PolicyReasonCode[] = [];
  const session = snapshot.session;
  const trusted = snapshot.identity.trusted_worker;
  const sandbox = snapshot.identity.sandbox;
  const proxy = snapshot.proxy;
  const expectedTrusted = coreSelector(session, "trusted");
  const expectedSandbox = coreSelector(session, "sandbox");
  const expectedProxy = { ...expectedTrusted, "dev.cogs/proxy": "true" };

  if (
    trusted.namespace !== snapshot.openbao.bound_namespace ||
    trusted.service_account !== snapshot.openbao.bound_service_account ||
    snapshot.openbao.bound_audiences.length !== 1 ||
    snapshot.openbao.bound_audiences[0] !== trusted.openbao_projected_token.audience ||
    sandbox.service_account !== "cogs-sandbox-inert" ||
    sandbox.service_account === trusted.service_account
  ) {
    reasons.push("STAGE4_POLICY_IDENTITY_BINDING_INVALID");
  }

  if (
    !selectorEqual(trusted.pod_selector, expectedTrusted) ||
    !selectorEqual(sandbox.pod_selector, expectedSandbox) ||
    !selectorEqual(proxy.selector, expectedProxy) ||
    selectorsOverlapAsExactIdentity(trusted.pod_selector, sandbox.pod_selector)
  ) {
    reasons.push("STAGE4_POLICY_SELECTOR_CONFUSION");
  }

  if (!validExactHandles(snapshot.openbao.exact_handles, session.user_id)) {
    reasons.push("STAGE4_POLICY_HANDLE_SCOPE_INVALID");
  }

  if (
    proxy.capability.session_id !== session.session_id ||
    proxy.capability.instance_id !== session.instance_id ||
    proxy.capability.source_binding.session_id !== session.session_id ||
    proxy.capability.source_binding.instance_id !== session.instance_id ||
    !selectorEqual(proxy.capability.source_binding.sandbox_selector, expectedSandbox) ||
    proxy.capability.audience === trusted.openbao_projected_token.audience ||
    proxy.capability.expires_at_ms <= proxy.capability.issued_at_ms ||
    proxy.capability.expires_at_ms - proxy.capability.issued_at_ms !== proxy.capability.lifetime_seconds * 1000 ||
    proxy.revocation.replacement_identity.replacement_capability_id !== proxy.capability.capability_id ||
    proxy.revocation.replacement_identity.replacement_generation !== proxy.capability.generation ||
    proxy.revocation.replacement_identity.replacement_worker_pod_id !== proxy.capability.worker_pod_id ||
    proxy.capability.worker_pod_id === proxy.capability.source_binding.sandbox_pod_id ||
    proxy.revocation.replacement_identity.previous_capability_id === proxy.capability.capability_id ||
    proxy.capability.generation < 2
  ) {
    reasons.push("STAGE4_POLICY_CAPABILITY_BINDING_INVALID");
  }

  if (snapshot.telemetry.batch_size > snapshot.telemetry.queue_capacity) {
    reasons.push("STAGE4_POLICY_TELEMETRY_BOUNDS_INVALID");
  }
  if (snapshot.audit_wal.max_record_bytes > snapshot.audit_wal.max_bytes) {
    reasons.push("STAGE4_POLICY_AUDIT_WAL_BOUNDS_INVALID");
  }

  const digest = semanticDigest(snapshot);
  return contractVerdict(digest, reasons.length === 0 ? ["STAGE4_POLICY_VALID"] : reasons);
}

/** Evaluates only the expected static sandbox-to-proxy policy graph. */
export function evaluateStage4PolicyProbe(contractInput: unknown, probeInput: unknown): Stage4PolicyProbeDecision {
  const contractVerdictValue = validateStage4PolicyContract(contractInput);
  if (!contractVerdictValue.valid) return probeDecision(null, false, "contract-invalid");
  const contract = snapshotJson(contractInput);
  const probe = snapshotJson(probeInput);
  if (contract === null || probe === null || !validateContractSchema(contract) || !validateProbeSchema(probe)) {
    return probeDecision(null, false, "probe-invalid");
  }

  const id = probe.id;
  const sessionId = contract.session.session_id;
  const capability = contract.proxy.capability;
  const replacement = contract.proxy.revocation.replacement_identity;
  if (!validProbeCapabilityCombination(probe)) return probeDecision(id, false, "probe-invalid");
  if (probe.source_session_id !== sessionId) return probeDecision(id, false, "source-session-mismatch");
  if (probe.source_instance_id !== contract.session.instance_id) {
    return probeDecision(id, false, "source-instance-mismatch");
  }
  if (probe.source_pod_id !== capability.source_binding.sandbox_pod_id) {
    return probeDecision(id, false, "source-pod-mismatch");
  }
  if (!selectorEqual(probe.source_selector, contract.identity.sandbox.pod_selector)) {
    return probeDecision(id, false, "selector-confusion");
  }
  if (probe.capability.state !== "missing" && probe.capability.expires_at_ms !== capability.expires_at_ms) {
    return probeDecision(id, false, "probe-invalid");
  }
  if (probe.observed_at_ms < capability.issued_at_ms) {
    return probeDecision(id, false, "capability-not-yet-valid");
  }
  if (probe.capability.state === "missing") return probeDecision(id, false, "capability-missing");
  if (probe.capability.state === "revoked") return probeDecision(id, false, "capability-revoked");
  if (probe.capability.state === "replaced") {
    if (
      probe.capability.capability_id !== replacement.previous_capability_id ||
      probe.capability.replacement_capability_id !== replacement.replacement_capability_id ||
      probe.capability.generation !== replacement.replacement_generation - 1
    ) {
      return probeDecision(id, false, "probe-invalid");
    }
    return probeDecision(id, false, "capability-replaced");
  }
  if (probe.capability.state === "expired" || probe.observed_at_ms >= (probe.capability.expires_at_ms ?? 0)) {
    return probeDecision(id, false, "capability-expired");
  }
  if (probe.capability.session_id !== sessionId) return probeDecision(id, false, "capability-session-mismatch");
  if (probe.capability.capability_id !== capability.capability_id) {
    return probeDecision(id, false, "capability-id-mismatch");
  }
  if (probe.capability.generation !== capability.generation) {
    return probeDecision(id, false, "capability-generation-mismatch");
  }
  if (
    probe.destination.class === "other-session-proxy" ||
    probe.destination.class === "other-session-workload" ||
    (probe.destination.session_id !== null && probe.destination.session_id !== sessionId)
  ) {
    return probeDecision(id, false, "cross-session-denied");
  }
  if (probe.transport === "udp" || probe.transport === "quic") {
    return probeDecision(id, false, "udp-quic-denied");
  }
  if (probe.transport === "dns" || probe.transport === "doh" || probe.destination.class === "resolver") {
    return probeDecision(id, false, "dns-resolver-denied");
  }
  if (probe.destination.class === "assigned-proxy") {
    if (probe.destination.service_name !== contract.proxy.service_name) {
      return probeDecision(id, false, "proxy-service-mismatch");
    }
    return probe.destination.port === contract.proxy.listener_port
      ? probeDecision(id, true, "assigned-proxy-only")
      : probeDecision(id, false, "alternate-port-denied");
  }
  if (probe.destination.class === "direct-host" || probe.destination.class === "direct-ip") {
    return probeDecision(id, false, "direct-egress-denied");
  }
  if (probe.destination.class === "broad-policy-peer") return probeDecision(id, false, "broad-policy-denied");
  return probeDecision(id, false, "protected-surface-denied");
}

export function buildStage4PolicyProbeSuite(contractInput: unknown): Stage4PolicyProbeSuite | null {
  const contract = snapshotJson(contractInput);
  if (contract === null || !validateContractSchema(contract) || !validateStage4PolicyContract(contract).valid)
    return null;
  return deepFreeze({
    version: "cogs.stage4-policy-probe-suite/v1",
    authority: "static-only-stage4-policy",
    qualification: "pending-exact-eks-cni-runtime",
    contract_sha256: semanticDigest(contract),
    probes: requiredProbeSpecs(contract),
  });
}

export function validateStage4PolicyProbeSuite(
  contractInput: unknown,
  input: unknown,
): input is Stage4PolicyProbeSuite {
  const contract = snapshotJson(contractInput);
  const snapshot = snapshotJson(input);
  if (contract === null || snapshot === null) return false;
  const expected = buildStage4PolicyProbeSuite(contract);
  if (expected === null || !validateProbeSuiteSchema(snapshot)) return false;
  if (snapshot.contract_sha256 !== expected.contract_sha256) return false;
  for (const [index, probe] of snapshot.probes.entries()) {
    const required = expected.probes[index];
    if (required === undefined || canonicalJson(withoutExpected(probe)) !== canonicalJson(withoutExpected(required))) {
      return false;
    }
    const decision = evaluateStage4PolicyProbe(contract, probe);
    if (
      decision.probe_id !== probe.id ||
      decision.allow !== probe.expected.allow ||
      decision.reason !== probe.expected.reason
    ) {
      return false;
    }
  }
  return true;
}

function withoutExpected(probe: Stage4PolicyProbe): Omit<Stage4PolicyProbe, "expected"> {
  const { expected: _expected, ...semanticFields } = probe;
  return semanticFields;
}

type DeepMutable<T> = { -readonly [Key in keyof T]: T[Key] extends object ? DeepMutable<T[Key]> : T[Key] };

function requiredProbeSpecs(contract: Stage4PolicyContract): readonly Stage4PolicyProbe[] {
  const capability = contract.proxy.capability;
  const replacement = contract.proxy.revocation.replacement_identity;
  const base: DeepMutable<Stage4PolicyProbe> = {
    id: "allow.assigned-proxy.ipv4",
    observed_at_ms: capability.issued_at_ms + 1,
    source_session_id: contract.session.session_id,
    source_instance_id: contract.session.instance_id,
    source_pod_id: capability.source_binding.sandbox_pod_id,
    source_selector: { ...contract.identity.sandbox.pod_selector },
    transport: "tcp",
    address_family: "IPv4",
    destination: {
      class: "assigned-proxy",
      session_id: contract.session.session_id,
      service_name: contract.proxy.service_name,
      port: contract.proxy.listener_port,
    },
    capability: {
      state: "active",
      session_id: contract.session.session_id,
      capability_id: capability.capability_id,
      generation: capability.generation,
      expires_at_ms: capability.expires_at_ms,
      replacement_capability_id: null,
    },
    expected: { allow: true, reason: "assigned-proxy-only" },
  };
  const probes: Stage4PolicyProbe[] = [];
  const add = (
    id: (typeof REQUIRED_STAGE4_POLICY_PROBE_IDS)[number],
    update: (probe: DeepMutable<Stage4PolicyProbe>) => void,
    allow: boolean,
    reason: Stage4PolicyProbeReason,
  ): void => {
    const probe = structuredClone(base);
    probe.id = id;
    update(probe);
    probe.expected = { allow, reason };
    probes.push(deepFreeze(probe));
  };
  const none = (): void => undefined;
  const destination =
    (kind: ProbeDestinationClass, port: number, sessionId: string | null = null, serviceName: string | null = null) =>
    (probe: DeepMutable<Stage4PolicyProbe>): void => {
      probe.destination = { class: kind, session_id: sessionId, service_name: serviceName, port };
    };
  const alternateSessionId = alternateOpaque(contract.session.session_id);
  const alternateInstanceId = alternateLabel(contract.session.instance_id);
  const alternateSandboxPodId = alternateOpaque(capability.source_binding.sandbox_pod_id);
  const alternateServiceName = alternateDnsName(contract.proxy.service_name);
  const alternateCapabilityId = alternateOpaque(capability.capability_id);
  const alternateGeneration = alternateBoundedInteger(capability.generation, 1, 1_000_000);

  add("allow.assigned-proxy.ipv4", none, true, "assigned-proxy-only");
  add("allow.assigned-proxy.ipv6", (probe) => (probe.address_family = "IPv6"), true, "assigned-proxy-only");
  add("deny.selector.empty", (probe) => (probe.source_selector = {}), false, "selector-confusion");
  add(
    "deny.selector.trusted-role",
    (probe) => (probe.source_selector["dev.cogs/role"] = "trusted"),
    false,
    "selector-confusion",
  );
  add(
    "deny.selector.proxy-role-confusion",
    (probe) => (probe.source_selector["dev.cogs/proxy"] = "true"),
    false,
    "selector-confusion",
  );
  add(
    "deny.assigned-proxy.service-confusion",
    (probe) => (probe.destination.service_name = alternateServiceName),
    false,
    "proxy-service-mismatch",
  );
  add(
    "deny.source.cross-session",
    (probe) => (probe.source_session_id = alternateSessionId),
    false,
    "source-session-mismatch",
  );
  add(
    "deny.source.instance-confusion",
    (probe) => (probe.source_instance_id = alternateInstanceId),
    false,
    "source-instance-mismatch",
  );
  add(
    "deny.source.pod-confusion",
    (probe) => (probe.source_pod_id = alternateSandboxPodId),
    false,
    "source-pod-mismatch",
  );
  add(
    "deny.capability.missing",
    (probe) => (probe.capability = missingCapability("missing")),
    false,
    "capability-missing",
  );
  add("deny.capability.revoked", (probe) => (probe.capability.state = "revoked"), false, "capability-revoked");
  add(
    "deny.capability.replaced",
    (probe) => {
      probe.capability = {
        state: "replaced",
        session_id: contract.session.session_id,
        capability_id: replacement.previous_capability_id,
        generation: replacement.replacement_generation - 1,
        expires_at_ms: capability.expires_at_ms,
        replacement_capability_id: replacement.replacement_capability_id,
      };
    },
    false,
    "capability-replaced",
  );
  add(
    "deny.capability.before-issued",
    (probe) => {
      probe.observed_at_ms = capability.issued_at_ms - 1;
    },
    false,
    "capability-not-yet-valid",
  );
  add(
    "deny.capability.expired",
    (probe) => {
      probe.observed_at_ms = capability.expires_at_ms;
      probe.capability.state = "expired";
    },
    false,
    "capability-expired",
  );
  add(
    "deny.capability.id-confusion",
    (probe) => (probe.capability.capability_id = alternateCapabilityId),
    false,
    "capability-id-mismatch",
  );
  add(
    "deny.capability.generation-confusion",
    (probe) => (probe.capability.generation = alternateGeneration),
    false,
    "capability-generation-mismatch",
  );
  add(
    "deny.capability.cross-session",
    (probe) => (probe.capability.session_id = alternateSessionId),
    false,
    "capability-session-mismatch",
  );
  add(
    "deny.destination.cross-session-proxy",
    destination("other-session-proxy", contract.proxy.listener_port, alternateSessionId, alternateServiceName),
    false,
    "cross-session-denied",
  );
  add(
    "deny.destination.cross-session-workload",
    destination("other-session-workload", 22, alternateSessionId),
    false,
    "cross-session-denied",
  );
  add(
    "deny.udp.ipv4",
    (probe) => {
      probe.transport = "udp";
      destination("direct-host", 9999)(probe);
    },
    false,
    "udp-quic-denied",
  );
  add(
    "deny.udp.ipv6",
    (probe) => {
      probe.transport = "udp";
      probe.address_family = "IPv6";
      destination("direct-host", 9999)(probe);
    },
    false,
    "udp-quic-denied",
  );
  for (const family of ["IPv4", "IPv6"] as const) {
    const suffix = family.toLowerCase() as "ipv4" | "ipv6";
    add(
      `deny.quic.udp443.${suffix}`,
      (probe) => {
        probe.transport = "quic";
        probe.address_family = family;
        destination("direct-host", 443)(probe);
      },
      false,
      "udp-quic-denied",
    );
    add(
      `deny.dns.arbitrary.${suffix}`,
      (probe) => {
        probe.transport = "dns";
        probe.address_family = family;
        destination("resolver", 53)(probe);
      },
      false,
      "dns-resolver-denied",
    );
    add(
      `deny.dns.over-https.${suffix}`,
      (probe) => {
        probe.transport = "doh";
        probe.address_family = family;
        destination("direct-host", 443)(probe);
      },
      false,
      "dns-resolver-denied",
    );
  }
  add("deny.direct-host.ipv4", destination("direct-host", 443), false, "direct-egress-denied");
  add(
    "deny.direct-host.ipv6",
    (probe) => {
      probe.address_family = "IPv6";
      destination("direct-host", 443)(probe);
    },
    false,
    "direct-egress-denied",
  );
  add("deny.direct-ip.ipv4", destination("direct-ip", 443), false, "direct-egress-denied");
  add(
    "deny.direct-ip.ipv6",
    (probe) => {
      probe.address_family = "IPv6";
      destination("direct-ip", 443)(probe);
    },
    false,
    "direct-egress-denied",
  );
  add(
    "deny.alternate-proxy-port",
    (probe) => (probe.destination.port = alternateListenerPort(contract.proxy.listener_port)),
    false,
    "alternate-port-denied",
  );
  add("deny.metadata.ipv4", destination("cloud-metadata", 80), false, "protected-surface-denied");
  add(
    "deny.metadata.ipv6",
    (probe) => {
      probe.address_family = "IPv6";
      destination("cloud-metadata", 80)(probe);
    },
    false,
    "protected-surface-denied",
  );
  for (const family of ["IPv4", "IPv6"] as const) {
    const suffix = family.toLowerCase() as "ipv4" | "ipv6";
    const protectedProbe = (
      id: `deny.${"kubernetes-api" | "worker-api" | "proxy-admin" | "openbao"}.${"ipv4" | "ipv6"}`,
      kind: ProbeDestinationClass,
      port: number,
      sessionId: string | null = null,
    ): void => {
      add(
        id,
        (probe) => {
          probe.address_family = family;
          destination(kind, port, sessionId)(probe);
        },
        false,
        "protected-surface-denied",
      );
    };
    protectedProbe(`deny.kubernetes-api.${suffix}`, "kubernetes-api", 443);
    protectedProbe(`deny.worker-api.${suffix}`, "worker-api", 8080, contract.session.session_id);
    protectedProbe(`deny.proxy-admin.${suffix}`, "proxy-admin", 9901, contract.session.session_id);
    protectedProbe(`deny.openbao.${suffix}`, "openbao", 8200);
  }
  add("deny.broad-policy-peer", destination("broad-policy-peer", 443), false, "broad-policy-denied");
  return Object.freeze(probes);
}

function alternateOpaque(value: string): string {
  return `${value.startsWith("a") ? "b" : "a"}${value.slice(1)}`;
}

function alternateLabel(value: string): string {
  return alternateOpaque(value);
}

function alternateDnsName(value: string): string {
  return alternateOpaque(value);
}

function alternateBoundedInteger(value: number, minimum: number, maximum: number): number {
  if (value < minimum || value > maximum || minimum >= maximum) throw new Error("invalid alternate bound");
  return value === maximum ? value - 1 : value + 1;
}

function alternateListenerPort(value: number): number {
  if (value < 1 || value > 65_535) throw new Error("invalid listener port");
  return value === 65_535 ? 65_534 : 65_535;
}

function missingCapability(state: "missing"): DeepMutable<Stage4PolicyProbe["capability"]> {
  return {
    state,
    session_id: null,
    capability_id: null,
    generation: null,
    expires_at_ms: null,
    replacement_capability_id: null,
  };
}

function validProbeCapabilityCombination(probe: Stage4PolicyProbe): boolean {
  const value = probe.capability;
  if (value.state === "missing") {
    return (
      value.session_id === null &&
      value.capability_id === null &&
      value.generation === null &&
      value.expires_at_ms === null &&
      value.replacement_capability_id === null
    );
  }
  if (value.state === "replaced") {
    return (
      value.session_id !== null &&
      value.capability_id !== null &&
      value.generation !== null &&
      value.expires_at_ms !== null &&
      value.replacement_capability_id !== null
    );
  }
  return (
    value.session_id !== null &&
    value.capability_id !== null &&
    value.generation !== null &&
    value.expires_at_ms !== null &&
    value.replacement_capability_id === null
  );
}

export function buildStage4AuditWalRecord(
  contractInput: unknown,
  input: Readonly<{
    sequence: number;
    timestamp_ms: number;
    method: "GET" | "POST";
    credential_required: boolean;
  }>,
): Stage4AuditWalRecord | null {
  const contract = snapshotJson(contractInput);
  if (contract === null || !validateContractSchema(contract) || !validateStage4PolicyContract(contract).valid)
    return null;
  if (
    !Number.isSafeInteger(input.sequence) ||
    input.sequence < 0 ||
    !Number.isSafeInteger(input.timestamp_ms) ||
    input.timestamp_ms < 0 ||
    (input.method !== "GET" && input.method !== "POST") ||
    typeof input.credential_required !== "boolean"
  ) {
    return null;
  }
  const references = auditReferences(contract);
  const base = {
    version: "cogs.stage4-audit-wal-record/v1" as const,
    sequence: input.sequence,
    timestamp_ms: input.timestamp_ms,
    session_ref_sha256: references.session,
    policy_ref_sha256: references.policy,
    capability_ref_sha256: references.capability,
    method: input.method,
    credential_required: input.credential_required,
  };
  return Object.freeze({
    version: base.version,
    sequence: base.sequence,
    timestamp_ms: base.timestamp_ms,
    session_ref_sha256: base.session_ref_sha256,
    intent_ref_sha256: referenceDigest(AUDIT_INTENT_REF_DOMAIN, base),
    policy_ref_sha256: base.policy_ref_sha256,
    capability_ref_sha256: base.capability_ref_sha256,
    method: base.method,
    credential_required: base.credential_required,
  });
}

export function validateStage4PolicyPayload(
  contractInput: unknown,
  payloadInput: unknown,
): Stage4PolicyPayloadDecision {
  if (!validateStage4PolicyContract(contractInput).valid) return payloadDecision(false, null, "contract-invalid");
  const contract = snapshotJson(contractInput);
  const payload = snapshotJson(payloadInput);
  if (contract === null || payload === null || !validateContractSchema(contract) || !validatePayloadSchema(payload)) {
    return payloadDecision(false, null, "payload-invalid");
  }
  if (containsRawIdentity(contract, payload)) return payloadDecision(false, null, "payload-invalid");
  if (payload.version === "cogs.stage4-audit-wal-record/v1") {
    const record = payload as Stage4AuditWalRecord;
    const expected = buildStage4AuditWalRecord(contract, {
      sequence: record.sequence,
      timestamp_ms: record.timestamp_ms,
      method: record.method,
      credential_required: record.credential_required,
    });
    if (expected === null || canonicalJson(record) !== canonicalJson(expected)) {
      return payloadDecision(false, "audit-wal", "payload-invalid");
    }
    const bytes = new TextEncoder().encode(`${canonicalJson(payload)}\n`).byteLength;
    if (bytes > contract.audit_wal.max_record_bytes) return payloadDecision(false, "audit-wal", "payload-too-large");
    return payloadDecision(true, "audit-wal", "payload-valid");
  }
  if (payload.version === "cogs.stage4-otlp-record/v1") return payloadDecision(true, "otlp", "payload-valid");
  return payloadDecision(false, null, "payload-invalid");
}

function containsRawIdentity(contract: Stage4PolicyContract, payload: Stage4PolicyPayload): boolean {
  const forbidden = new Set<string>([
    contract.session.user_id,
    contract.session.session_id,
    contract.session.instance_id,
    contract.identity.trusted_worker.service_account,
    contract.identity.sandbox.service_account,
    contract.proxy.capability.worker_pod_id,
    contract.proxy.capability.source_binding.sandbox_pod_id,
    contract.proxy.capability.capability_id,
    contract.proxy.revocation.replacement_identity.previous_capability_id,
  ]);
  const pending: unknown[] = [payload];
  while (pending.length > 0) {
    const value = pending.pop();
    if (typeof value === "string" && forbidden.has(value)) return true;
    if (value !== null && typeof value === "object") pending.push(...Object.values(value));
  }
  return false;
}

function payloadDecision(
  valid: boolean,
  recordKind: "audit-wal" | "otlp" | null,
  reason: Stage4PolicyPayloadDecision["reason"],
): Stage4PolicyPayloadDecision {
  return Object.freeze({
    version: "cogs.stage4-policy-payload-decision/v1",
    authority: "static-only-stage4-policy",
    qualification: "pending-exact-eks-cni-runtime",
    valid,
    record_kind: recordKind,
    reason,
    cloud_execution_observed: false,
    cni_runtime_qualified: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
  });
}

function contractVerdict(
  digest: string | null,
  reasons: readonly Stage4PolicyReasonCode[],
): Stage4PolicyContractVerdict {
  return deepFreeze({
    version: "cogs.stage4-policy-verdict/v1",
    authority: "static-only-stage4-policy",
    qualification: "pending-exact-eks-cni-runtime",
    valid: reasons.length === 1 && reasons[0] === "STAGE4_POLICY_VALID",
    contract_sha256: digest,
    reason_codes: [...reasons],
    cloud_execution_observed: false,
    cni_runtime_qualified: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    transitions: STAGE4_POLICY_TRANSITIONS,
  });
}

function probeDecision(
  probeId: string | null,
  allow: boolean,
  reason: Stage4PolicyProbeReason,
): Stage4PolicyProbeDecision {
  return Object.freeze({
    version: "cogs.stage4-policy-probe-decision/v1",
    authority: "static-only-stage4-policy",
    qualification: "pending-exact-eks-cni-runtime",
    probe_id: probeId,
    allow,
    reason,
    cloud_execution_observed: false,
    cni_runtime_qualified: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
  });
}

function coreSelector(session: Stage4PolicyContract["session"], role: "trusted" | "sandbox"): Selector {
  return {
    "app.kubernetes.io/instance": session.instance_id,
    "dev.cogs/session": session.session_id,
    "dev.cogs/role": role,
  };
}

function validExactHandles(handles: readonly ExactHandle[], userId: string): boolean {
  const seen = new Set<string>();
  for (const row of handles) {
    if (seen.has(row.handle) || row.handle.includes("*") || row.handle.includes("//")) return false;
    seen.add(row.handle);
    const parts = row.handle.split("/");
    if (parts.some((part) => !OPAQUE.test(part) || part === "." || part === "..")) return false;
    if (parts[0] !== "users" || parts[1] !== userId) return false;
    const expectedClass = row.purpose === "model-api-key" ? "models" : "integrations";
    if (parts[2] !== expectedClass) return false;
  }
  return true;
}

function selectorEqual(left: Selector, right: Selector): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && left[key] === right[key])
  );
}

function selectorsOverlapAsExactIdentity(left: Selector, right: Selector): boolean {
  return (
    Object.entries(left).every(([key, value]) => right[key] === undefined || right[key] === value) ||
    Object.entries(right).every(([key, value]) => left[key] === undefined || left[key] === value)
  );
}

function auditReferences(contract: Stage4PolicyContract): Readonly<{
  session: string;
  policy: string;
  capability: string;
}> {
  return Object.freeze({
    session: referenceDigest(AUDIT_SESSION_REF_DOMAIN, contract.session),
    policy: referenceDigest(AUDIT_POLICY_REF_DOMAIN, contract.proxy.route_policy),
    capability: referenceDigest(AUDIT_CAPABILITY_REF_DOMAIN, {
      capability: contract.proxy.capability,
      replacement_identity: contract.proxy.revocation.replacement_identity,
    }),
  });
}

function semanticDigest(value: unknown): string {
  return referenceDigest(CONTRACT_DOMAIN, value);
}

function referenceDigest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort(compareCodePoints)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("not canonical JSON");
  return encoded;
}

function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const b = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function snapshotJson(input: unknown): Record<string, unknown> | null {
  let nodes = 0;
  const visit = (value: unknown, depth: number): unknown => {
    nodes += 1;
    if (nodes > MAX_SNAPSHOT_NODES || depth > MAX_SNAPSHOT_DEPTH) throw new Error("snapshot bound");
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "string") {
      if (value.length > 2048) throw new Error("string bound");
      return value;
    }
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new Error("number bound");
      return value;
    }
    if (typeof value !== "object") throw new Error("not JSON");
    const prototype = Object.getPrototypeOf(value);
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype || value.length > 128) throw new Error("array bound");
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const names = Reflect.ownKeys(descriptors);
      const expected = [...Array.from({ length: value.length }, (_, index) => String(index)), "length"];
      if (names.some((name) => typeof name !== "string") || names.length !== expected.length)
        throw new Error("array shape");
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("array descriptor");
        output.push(visit(descriptor.value, depth + 1));
      }
      return output;
    }
    if (prototype !== Object.prototype && prototype !== null) throw new Error("object prototype");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Reflect.ownKeys(descriptors);
    if (names.some((name) => typeof name !== "string") || names.length > 64) throw new Error("object bound");
    const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const name of names as string[]) {
      const descriptor = descriptors[name];
      if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("object descriptor");
      output[name] = visit(descriptor.value, depth + 1);
    }
    return output;
  };
  try {
    const result = visit(input, 0);
    return result !== null && typeof result === "object" && !Array.isArray(result)
      ? (result as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
