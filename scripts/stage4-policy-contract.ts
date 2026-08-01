import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const contractSchema = require("../schemas/stage4-policy-contract-v1.json") as object;
const probeSchema = require("../schemas/stage4-policy-probe-suite-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateContractSchema = ajv.compile(contractSchema) as ValidateFunction<Stage4PolicyContract>;
const validateProbeSuiteSchema = ajv.compile(probeSchema) as ValidateFunction<Stage4PolicyProbeSuite>;

const CONTRACT_DOMAIN = "cogs.stage4/static-policy-contract-semantic-binding/v1";
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const MAX_SNAPSHOT_NODES = 4096;
const MAX_SNAPSHOT_DEPTH = 16;

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
  | "selector-confusion"
  | "capability-missing"
  | "capability-revoked"
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
      source_binding: Readonly<{ session_id: string; sandbox_selector: Selector }>;
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
  source_session_id: string;
  source_selector: Selector;
  transport: "tcp" | "udp" | "quic" | "dns" | "doh";
  address_family: "IPv4" | "IPv6";
  destination: Readonly<{
    class: ProbeDestinationClass;
    session_id: string | null;
    service_name: string | null;
    port: number;
  }>;
  capability: Readonly<{ state: "active" | "revoked" | "missing"; session_id: string | null }>;
  expected: Readonly<{ allow: boolean; reason: string }>;
}>;

export type Stage4PolicyProbeSuite = Readonly<{
  version: "cogs.stage4-policy-probe-suite/v1";
  authority: "static-only-stage4-policy";
  qualification: "pending-exact-eks-cni-runtime";
  probes: readonly Stage4PolicyProbe[];
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
    snapshot.openbao.bound_audiences[0] !== trusted.openbao_projected_token.audience
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
    proxy.capability.source_binding.session_id !== session.session_id ||
    !selectorEqual(proxy.capability.source_binding.sandbox_selector, expectedSandbox) ||
    proxy.capability.audience === trusted.openbao_projected_token.audience
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
  if (contract === null || probe === null || !validateContractSchema(contract) || !validateProbe(probe)) {
    return probeDecision(null, false, "probe-invalid");
  }

  const id = probe.id;
  const sessionId = contract.session.session_id;
  if (probe.source_session_id !== sessionId) return probeDecision(id, false, "source-session-mismatch");
  if (!selectorEqual(probe.source_selector, contract.identity.sandbox.pod_selector)) {
    return probeDecision(id, false, "selector-confusion");
  }
  if (probe.capability.state === "missing") return probeDecision(id, false, "capability-missing");
  if (probe.capability.state === "revoked") return probeDecision(id, false, "capability-revoked");
  if (probe.capability.session_id !== sessionId) return probeDecision(id, false, "capability-session-mismatch");
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

export function validateStage4PolicyProbeSuite(input: unknown): input is Stage4PolicyProbeSuite {
  const snapshot = snapshotJson(input);
  return snapshot !== null && validateProbeSuiteSchema(snapshot);
}

function validateProbe(input: unknown): input is Stage4PolicyProbe {
  const suite = {
    version: "cogs.stage4-policy-probe-suite/v1",
    authority: "static-only-stage4-policy",
    qualification: "pending-exact-eks-cni-runtime",
    probes: [input],
  };
  // The suite schema intentionally requires the committed broad inventory. Use
  // the compiled item validator through a bounded synthetic inventory.
  const repeated = Array.from({ length: 20 }, (_, index) => ({
    ...(input as Record<string, unknown>),
    id: `probe-${index}`,
  }));
  return validateProbeSuiteSchema({ ...suite, probes: repeated });
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
    if (parts[0] === "users" && parts[1] !== userId) return false;
    if (parts[0] !== "users" && parts[0] !== "organizations") return false;
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

function semanticDigest(value: unknown): string {
  return createHash("sha256")
    .update(CONTRACT_DOMAIN, "utf8")
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
