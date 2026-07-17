import { createHash } from "node:crypto";

const POLICY_VERSION = "cogs.policy/v1alpha1";
const DECISION_VERSION = "cogs.policy-decision/v1alpha1";
const DENY_DECISION_SENTINELS: Readonly<Record<Exclude<CogsPolicyDecisionReason, "allowed">, string>> = Object.freeze({
  invalid_envelope: "cogs.policy.deny.invalid_envelope.v1alpha1",
  unknown_action: "cogs.policy.deny.unknown_action.v1alpha1",
  unsupported_surface: "cogs.policy.deny.unsupported_surface.v1alpha1",
  mode_denied: "cogs.policy.deny.mode_denied.v1alpha1",
  restore_reserved: "cogs.policy.deny.restore_reserved.v1alpha1",
});

const TOP_LEVEL_KEYS = ["version", "action", "user", "session", "resource", "attributes"] as const;
const DECISION_KEYS = ["version", "decision_id", "allow", "reason"] as const;
const OPAQUE_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const MOUNT_CLASSES = new Set(["workspace", "shared_skill", "user_skill", "proxy_public"]);
const TOOLS = new Set(["read", "write", "edit", "bash"]);
const PATH_CLASSES = new Set(["workspace", "shared_skill", "user_skill"]);
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"]);
const SECRET_CLASSES = new Set([
  "egress_integration_credential",
  "model_api_key_runtime",
  "proxy_capability",
  "proxy_leaf_key",
]);

export type CogsPolicyDecisionReason =
  | "allowed"
  | "unknown_action"
  | "invalid_envelope"
  | "unsupported_surface"
  | "restore_reserved"
  | "mode_denied";

export type CogsPolicyDecision = Readonly<{
  version: "cogs.policy-decision/v1alpha1";
  decision_id: `sha256:${string}`;
  allow: boolean;
  reason: CogsPolicyDecisionReason;
}>;

type PlainRecord = Record<string, unknown>;

type SnapshotResult = { ok: true; value: PlainRecord } | { ok: false; reason: "invalid_envelope" | "unknown_action" };

export function authorizeCogsPolicyAction(input: unknown): CogsPolicyDecision {
  const snapshot = snapshotEnvelope(input);
  if (!snapshot.ok) return freezeDecision(denyDecision(snapshot.reason));

  const envelope = snapshot.value;
  const action = envelope.action as string;
  const resource = envelope.resource as string;
  const attributes = envelope.attributes as PlainRecord;

  const reason = evaluateKnownAction(action, resource, attributes);
  if (reason !== "allowed") return freezeDecision(denyDecision(reason));
  return freezeDecision(decisionFor(canonicalJson(envelope), true, "allowed"));
}

function evaluateKnownAction(action: string, resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  switch (action) {
    case "mount.validate":
      return mountDecision(resource, attributes);
    case "config.validate":
      return configDecision(resource, attributes);
    case "tool.enable":
      return toolEnableDecision(resource, attributes);
    case "tool.dispatch":
      return toolDispatchDecision(resource, attributes);
    case "egress.authorize":
      return egressDecision(resource, attributes);
    case "secret.use":
      return secretDecision(resource, attributes);
    case "export.create":
      return exportDecision(resource, attributes);
    case "restore.request":
      return restoreDecision(resource, attributes);
    default:
      return "unknown_action";
  }
}

function snapshotEnvelope(input: unknown): SnapshotResult {
  const top = snapshotRecord(input, TOP_LEVEL_KEYS, new Set(["attributes"]));
  if (!top.ok) return { ok: false, reason: "invalid_envelope" };
  const envelope = top.value;
  if (envelope.version !== POLICY_VERSION) return { ok: false, reason: "invalid_envelope" };
  if (typeof envelope.action !== "string") return { ok: false, reason: "invalid_envelope" };
  if (!isKnownAction(envelope.action)) return { ok: false, reason: "unknown_action" };
  if (!isOpaqueId(envelope.user) || !isOpaqueId(envelope.session)) return { ok: false, reason: "invalid_envelope" };
  if (!isBoundedString(envelope.resource, 1, 256)) return { ok: false, reason: "invalid_envelope" };
  const attributes = snapshotRecord(envelope.attributes, undefined);
  if (!attributes.ok) return { ok: false, reason: "invalid_envelope" };
  return { ok: true, value: { ...envelope, attributes: attributes.value } };
}

function snapshotRecord(
  input: unknown,
  expectedKeys: readonly string[] | undefined,
  objectValueKeys = new Set<string>(),
): { ok: true; value: PlainRecord } | { ok: false } {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return { ok: false };
  try {
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) return { ok: false };
    const symbols = Object.getOwnPropertySymbols(input);
    if (symbols.length > 0) return { ok: false };
    const names = Object.getOwnPropertyNames(input);
    if (expectedKeys) {
      if (names.length !== expectedKeys.length) return { ok: false };
      for (const key of expectedKeys) if (!names.includes(key)) return { ok: false };
    }
    const output: PlainRecord = {};
    for (const key of names) {
      if (expectedKeys === undefined && !isBoundedString(key, 1, 64)) return { ok: false };
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) return { ok: false };
      const value = descriptor.value;
      if (objectValueKeys.has(key)) {
        if (value === null || typeof value !== "object" || Array.isArray(value)) return { ok: false };
        output[key] = value;
        continue;
      }
      const safeValue = snapshotSafePolicyValue(value);
      if (!safeValue.ok) return { ok: false };
      output[key] = safeValue.value;
    }
    return { ok: true, value: output };
  } catch {
    return { ok: false };
  }
}

function snapshotSafePolicyValue(value: unknown): { ok: true; value: unknown } | { ok: false } {
  if (value === null) return { ok: false };
  if (typeof value === "string") return isBoundedString(value, 0, 256) ? { ok: true, value } : { ok: false };
  if (typeof value === "boolean") return { ok: true, value };
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 && value <= 10_000 ? { ok: true, value } : { ok: false };
  }
  if (Array.isArray(value)) return snapshotStringArray(value);
  return { ok: false };
}

function snapshotStringArray(value: unknown[]): { ok: true; value: readonly string[] } | { ok: false } {
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype) return { ok: false };
    if (Object.getOwnPropertySymbols(value).length > 0) return { ok: false };
    const names = Object.getOwnPropertyNames(value);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || !("value" in lengthDescriptor)) return { ok: false };
    const length = lengthDescriptor.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > 8) return { ok: false };
    if (names.length !== length + 1 || !names.includes("length")) return { ok: false };
    const output: string[] = [];
    for (let index = 0; index < length; index += 1) {
      const key = String(index);
      if (!names.includes(key)) return { ok: false };
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) return { ok: false };
      if (typeof descriptor.value !== "string" || !isBoundedString(descriptor.value, 1, 64)) return { ok: false };
      output.push(descriptor.value);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch {
    return { ok: false };
  }
}

function mountDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (!hasExactKeys(attributes, ["mount_class"])) return "invalid_envelope";
  if (!MOUNT_CLASSES.has(resource) || attributes.mount_class !== resource) return "unsupported_surface";
  return "allowed";
}

function configDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (resource === "launch") {
    if (!hasExactKeys(attributes, ["integration_count", "mount_classes"])) return "invalid_envelope";
    if (!isCount(attributes.integration_count) || !isMountClassArray(attributes.mount_classes))
      return "unsupported_surface";
    return "allowed";
  }
  if (resource === "egress_route_plan") {
    if (!hasExactKeys(attributes, ["route_count", "credential_route_count"])) return "invalid_envelope";
    if (!isCount(attributes.route_count) || !isCount(attributes.credential_route_count)) return "unsupported_surface";
    if ((attributes.credential_route_count as number) > (attributes.route_count as number))
      return "unsupported_surface";
    return "allowed";
  }
  return "unsupported_surface";
}

function toolEnableDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (!hasExactKeys(attributes, ["tool"])) return "invalid_envelope";
  if (!TOOLS.has(resource) || attributes.tool !== resource) return "unsupported_surface";
  return "allowed";
}

function toolDispatchDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (!TOOLS.has(resource)) return "unsupported_surface";
  if (resource === "bash") {
    if (!hasExactKeys(attributes, ["tool"])) return "invalid_envelope";
    return attributes.tool === "bash" ? "allowed" : "unsupported_surface";
  }
  if (resource === "read") {
    if (!hasExactKeys(attributes, ["tool", "path_class"])) return "invalid_envelope";
    if (attributes.tool !== "read" || !PATH_CLASSES.has(String(attributes.path_class))) return "unsupported_surface";
    return "allowed";
  }
  if (!hasExactKeys(attributes, ["tool", "path_class"])) return "invalid_envelope";
  if (attributes.tool !== resource || attributes.path_class !== "workspace") return "unsupported_surface";
  return "allowed";
}

function egressDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (!isOpaqueId(resource)) return "unsupported_surface";
  if (!hasExactKeys(attributes, ["integration_id", "route_id", "method", "credential_required"]))
    return "invalid_envelope";
  if (!isOpaqueId(attributes.integration_id) || attributes.route_id !== resource) return "unsupported_surface";
  if (!METHODS.has(String(attributes.method)) || typeof attributes.credential_required !== "boolean")
    return "unsupported_surface";
  return "allowed";
}

function secretDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (!SECRET_CLASSES.has(resource)) return "unsupported_surface";
  if (resource === "egress_integration_credential") {
    if (!hasExactKeys(attributes, ["secret_class", "integration_id"])) return "invalid_envelope";
    if (attributes.secret_class !== resource || !isOpaqueId(attributes.integration_id)) return "unsupported_surface";
    return "allowed";
  }
  if (!hasExactKeys(attributes, ["secret_class"])) return "invalid_envelope";
  if (attributes.secret_class !== resource) return "unsupported_surface";
  return "allowed";
}

function exportDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (resource !== "local_bundle") return "unsupported_surface";
  if (!hasExactKeys(attributes, ["mode", "sensitive", "sanitized", "anonymized", "attachments_included"])) {
    return "invalid_envelope";
  }
  if (attributes.mode !== "raw") return "mode_denied";
  if (
    attributes.sensitive !== true ||
    attributes.sanitized !== false ||
    attributes.anonymized !== false ||
    attributes.attachments_included !== false
  ) {
    return "mode_denied";
  }
  return "allowed";
}

function restoreDecision(resource: string, attributes: PlainRecord): CogsPolicyDecisionReason {
  if (resource !== "restore") return "unsupported_surface";
  if (!hasExactKeys(attributes, [])) return "invalid_envelope";
  return "restore_reserved";
}

function isKnownAction(value: string): boolean {
  return [
    "mount.validate",
    "config.validate",
    "tool.enable",
    "tool.dispatch",
    "egress.authorize",
    "secret.use",
    "export.create",
    "restore.request",
  ].includes(value);
}

function hasExactKeys(record: PlainRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isMountClassArray(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= 4 &&
    new Set(value).size === value.length &&
    value.every((item) => typeof item === "string" && MOUNT_CLASSES.has(item))
  );
}

function isCount(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 10_000;
}

function isOpaqueId(value: unknown): value is string {
  return typeof value === "string" && OPAQUE_RE.test(value);
}

function isBoundedString(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.length >= min && value.length <= max;
}

function denyDecision(reason: Exclude<CogsPolicyDecisionReason, "allowed">): CogsPolicyDecision {
  return decisionFor(DENY_DECISION_SENTINELS[reason], false, reason);
}

function decisionFor(canonicalInput: string, allow: boolean, reason: CogsPolicyDecisionReason): CogsPolicyDecision {
  return {
    version: DECISION_VERSION,
    decision_id: `sha256:${createHash("sha256").update(canonicalInput).digest("hex")}`,
    allow,
    reason,
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value as PlainRecord)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as PlainRecord)[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function freezeDecision(decision: CogsPolicyDecision): CogsPolicyDecision {
  const keys = Object.keys(decision);
  if (keys.length !== DECISION_KEYS.length || !DECISION_KEYS.every((key, index) => keys[index] === key)) {
    throw new Error("internal policy decision shape violation");
  }
  return Object.freeze(decision);
}
