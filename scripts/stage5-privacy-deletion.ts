import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { TextDecoder, types as utilTypes } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { capturePrivateBytes, intrinsicByteLength } from "./private-bytes.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const suiteSchema = require("../schemas/stage5-privacy-deletion-suite-v1.json") as object;
const validateSuite = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  ownProperties: true,
}).compile(suiteSchema) as ValidateFunction<Stage5Suite>;

export const STAGE5_PRIVACY_SURFACES = Object.freeze(["otlp", "log", "report", "event", "crash", "export"] as const);
export const STAGE5_PROHIBITED_CATEGORIES = Object.freeze([
  "prompt-or-model-content",
  "source-command-or-tool-content",
  "credential-or-placeholder",
  "private-identifier",
  "arbitrary-path",
  "network-query-or-body",
  "raw-export-content",
  "attachment-content",
] as const);
export const STAGE5_DELETION_TRANSITIONS = Object.freeze([
  "request-accepted",
  "active-state-absence-asserted",
  "current-object-absence-asserted",
  "version-inventory-complete-asserted",
  "all-versions-absence-asserted",
  "all-delete-markers-absence-asserted",
  "attachments-absence-asserted",
  "final-absence-asserted",
] as const);
export const STAGE5_PRIVACY_LIMITS = Object.freeze({
  maxInputBytes: 65_536,
  maxCanonicalBytes: 65_536,
  maxNodes: 512,
  maxDepth: 12,
  maxStringBytes: 512,
  maxKeyBytes: 96,
  maxProperties: 48,
  maxArrayLength: 32,
  maxCanaries: STAGE5_PROHIBITED_CATEGORIES.length,
  maxCanaryBytes: 192,
  maxCanaryInputBytes: 4096,
});

export type Stage5PrivacySurface = (typeof STAGE5_PRIVACY_SURFACES)[number];
export type Stage5ProhibitedCategory = (typeof STAGE5_PROHIBITED_CATEGORIES)[number];
export type Stage5SyntheticCanary = Readonly<{ category: Stage5ProhibitedCategory; value: string }>;
export type Stage5PrivacyDeletionReport = Readonly<{
  version: "cogs.stage5-privacy-deletion-report/v1";
  authority: "local-static-synthetic-privacy-classifier";
  issue: 365;
  scope: "local-static-synthetic-only";
  qualified: false;
  campaign_authorized: false;
  cloud_execution_observed: false;
  kubernetes_execution_observed: false;
  provider_execution_observed: false;
  external_model_invoked: false;
  release_eligible: false;
  suite_sha256: string | null;
  status:
    | "local-contract-pass"
    | "blocked-prohibited-content"
    | "blocked-legal-hold"
    | "failed-stop"
    | "preserve-uncertain"
    | "invalid-contract";
  privacy: Readonly<{
    result: "clear" | "prohibited-content" | "uncertain" | "invalid-contract";
    reason_code:
      | "STAGE5_PRIVACY_CLEAR"
      | "STAGE5_PRIVACY_PROHIBITED_CONTENT"
      | "STAGE5_PRIVACY_RAW_EXPORT_BOUNDARY_INVALID"
      | "STAGE5_PRIVACY_ATTACHMENT_BOUNDARY_INVALID"
      | "STAGE5_PRIVACY_SENSITIVE_MARKING_MISSING"
      | "STAGE5_PRIVACY_INVALID_SHAPE"
      | "STAGE5_PRIVACY_BOUNDED_INPUT";
    surfaces_scanned: number;
    affected_surfaces: readonly (Stage5PrivacySurface | "contract")[];
    categories: readonly Stage5ProhibitedCategory[];
    finding_count: number;
    finding_root_sha256: string | null;
    attachments_excluded: boolean;
    raw_export_boundary: "explicit-sensitive-authenticated-non-model-no-payload" | "invalid" | "not-evaluated";
    sensitive_marking: "present" | "missing" | "not-evaluated";
  }>;
  deletion: Readonly<{
    result:
      | "synthetic-sequence-complete"
      | "held-separate"
      | "failed-stop"
      | "uncertain-stop"
      | "invalid-contract"
      | "not-evaluated";
    reason_code:
      | "STAGE5_DELETION_SEQUENCE_COMPLETE"
      | "STAGE5_DELETION_LEGAL_HOLD_SEPARATE"
      | "STAGE5_DELETION_OPERATION_FAILED"
      | "STAGE5_DELETION_OBSERVATION_UNCERTAIN"
      | "STAGE5_DELETION_INVALID_SEQUENCE"
      | "STAGE5_DELETION_INVALID_CONTRACT"
      | "STAGE5_DELETION_NOT_EVALUATED";
    initial_state: "retained" | null;
    terminal_state: "deleted-verified" | "held-separate" | "failed-stop" | "uncertain-stop" | null;
    accepted_transition_count: number;
    retention_seconds: 2592000 | null;
    version_deletion: "all-versions-and-delete-markers" | "not-evaluated";
    legal_hold: "none-separate" | "active-separate" | "not-evaluated";
    failure_contract: "stop-no-success-no-retry";
    uncertainty_contract: "sticky-preserve-unconfirmed-no-unknown-to-absent";
    actual_eks_deletion: "unexecuted";
    actual_object_store_deletion: "unexecuted";
  }>;
}>;

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };
type Stage5Suite = JsonRecord & {
  version: string;
  surfaces: Array<JsonRecord & { surface: Stage5PrivacySurface; boundary: JsonRecord | null }>;
  retention: JsonRecord;
  legal_hold: JsonRecord;
  deletion: JsonRecord & { transitions: string[]; version_inventory: JsonRecord };
  external_execution: JsonRecord;
};
type Snapshot = Readonly<{ value: JsonRecord | null; bounded: boolean }>;
type ByteSnapshot = Readonly<{ value: JsonRecord | null; bounded: boolean }>;
type Finding = Readonly<{ surface: Stage5PrivacySurface | "contract"; category: Stage5ProhibitedCategory }>;
type FragmentSet = Readonly<{ exact: readonly string[]; folded: readonly string[] }>;
type BoundaryResult = Readonly<{
  reason:
    | "STAGE5_PRIVACY_CLEAR"
    | "STAGE5_PRIVACY_RAW_EXPORT_BOUNDARY_INVALID"
    | "STAGE5_PRIVACY_ATTACHMENT_BOUNDARY_INVALID"
    | "STAGE5_PRIVACY_SENSITIVE_MARKING_MISSING";
  attachmentsExcluded: boolean;
  boundary: "explicit-sensitive-authenticated-non-model-no-payload" | "invalid";
  sensitive: "present" | "missing" | "not-evaluated";
}>;
type DeletionEvaluation = Pick<Stage5PrivacyDeletionReport, "deletion" | "status">;

const REPORT_DOMAIN = "cogs.stage5/privacy-deletion-suite/v1";
const FINDING_DOMAIN = "cogs.stage5/privacy-finding-summary/v1";
const SURFACE_METADATA_DOMAIN = "cogs.stage5/privacy-surface-metadata/v1";
const VERSION_INVENTORY_DOMAIN = "cogs.stage5/privacy-version-inventory/v1";
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const CATEGORY_ORDER = new Map(STAGE5_PROHIBITED_CATEGORIES.map((category, index) => [category, index]));
const SURFACE_ORDER = new Map(
  (["contract", ...STAGE5_PRIVACY_SURFACES] as const).map((surface, index) => [surface, index]),
);
const SAFE_BOUNDARY_KEYS = new Set(["attachments_included", "raw_payload_present"]);
const KEY_CATEGORIES: ReadonlyArray<readonly [Stage5ProhibitedCategory, ReadonlySet<string>]> = [
  [
    "prompt-or-model-content",
    new Set(["prompt", "prompt_text", "instruction", "message", "model_output", "completion", "response_text"]),
  ],
  [
    "source-command-or-tool-content",
    new Set(["source", "source_text", "source_code", "command", "shell_command", "tool_output", "stdout", "stderr"]),
  ],
  [
    "credential-or-placeholder",
    new Set([
      "credential",
      "credentials",
      "secret",
      "api_key",
      "authorization",
      "cookie",
      "placeholder",
      "private_key",
      "access_token",
      "refresh_token",
    ]),
  ],
  [
    "private-identifier",
    new Set([
      "user_id",
      "session_id",
      "workspace_id",
      "account_id",
      "request_id",
      "correlation_id",
      "repository_id",
      "private_id",
    ]),
  ],
  ["arbitrary-path", new Set(["path", "file_path", "filename", "cwd", "working_directory", "host_path"])],
  ["network-query-or-body", new Set(["url", "uri", "query", "query_string", "request_body", "response_body"])],
  ["raw-export-content", new Set(["raw_export", "export_bytes", "session_jsonl", "transcript", "bundle_content"])],
  ["attachment-content", new Set(["attachment", "attachments", "attachment_bytes", "attachment_content"])],
];

function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const b = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function semanticDigest(domain: string, value: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function snapshotJson(input: unknown): Snapshot {
  let nodes = 0;
  let aggregateBytes = 1;
  let bounded = false;
  const seen = new Set<object>();
  const consume = (bytes: number): void => {
    aggregateBytes += bytes;
    if (aggregateBytes > STAGE5_PRIVACY_LIMITS.maxCanonicalBytes) {
      bounded = true;
      throw new TypeError("aggregate bound");
    }
  };
  const visit = (candidate: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > STAGE5_PRIVACY_LIMITS.maxNodes || depth > STAGE5_PRIVACY_LIMITS.maxDepth) {
      bounded = true;
      throw new TypeError("graph bound");
    }
    const candidateType = typeof candidate;
    if (
      ((candidateType === "object" && candidate !== null) || candidateType === "function") &&
      utilTypes.isProxy(candidate)
    ) {
      throw new TypeError("proxy");
    }
    if (candidate === null) {
      consume(4);
      return null;
    }
    if (typeof candidate === "boolean") {
      consume(candidate ? 4 : 5);
      return candidate;
    }
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) throw new TypeError("number");
      consume(Buffer.byteLength(JSON.stringify(candidate)));
      return candidate;
    }
    if (typeof candidate === "string") {
      if (Buffer.byteLength(candidate) > STAGE5_PRIVACY_LIMITS.maxStringBytes) {
        bounded = true;
        throw new TypeError("string bound");
      }
      consume(Buffer.byteLength(JSON.stringify(candidate)));
      return candidate;
    }
    if (typeof candidate !== "object" || candidate === null) throw new TypeError("non-json");
    if (seen.has(candidate)) throw new TypeError("cycle");
    seen.add(candidate);
    try {
      const prototype = Object.getPrototypeOf(candidate);
      const keys = Reflect.ownKeys(candidate);
      if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
      for (const key of keys as string[]) {
        if (Buffer.byteLength(key) > STAGE5_PRIVACY_LIMITS.maxKeyBytes) {
          bounded = true;
          throw new TypeError("key bound");
        }
      }
      const descriptors = Object.getOwnPropertyDescriptors(candidate) as Record<string, PropertyDescriptor | undefined>;
      if (Array.isArray(candidate)) {
        if (prototype !== Array.prototype) throw new TypeError("array prototype");
        const lengthDescriptor = descriptors.length;
        if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) throw new TypeError("array length");
        const length = lengthDescriptor.value;
        if (!Number.isSafeInteger(length) || length < 0 || length > STAGE5_PRIVACY_LIMITS.maxArrayLength) {
          bounded = true;
          throw new TypeError("array bound");
        }
        const expectedKeys = [...Array.from({ length }, (_, index) => String(index)), "length"];
        if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) {
          throw new TypeError("sparse array");
        }
        consume(2 + Math.max(0, length - 1));
        return Array.from({ length }, (_, index) => {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
            throw new TypeError("array accessor");
          }
          return visit(descriptor.value, depth + 1);
        });
      }
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError("object prototype");
      if (keys.length > STAGE5_PRIVACY_LIMITS.maxProperties) {
        bounded = true;
        throw new TypeError("property bound");
      }
      consume(2 + Math.max(0, keys.length - 1));
      const output = Object.create(null) as JsonRecord;
      for (const key of keys as string[]) {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
          throw new TypeError("object accessor");
        }
        consume(Buffer.byteLength(JSON.stringify(key)) + 1);
        output[key] = visit(descriptor.value, depth + 1);
      }
      return output;
    } finally {
      seen.delete(candidate);
    }
  };
  try {
    const value = visit(input, 0);
    const encodedBytes = Buffer.byteLength(canonicalJson(value));
    if (encodedBytes === 0 || encodedBytes > STAGE5_PRIVACY_LIMITS.maxInputBytes) {
      bounded = true;
      return { value: null, bounded };
    }
    return { value: isRecord(value) ? value : null, bounded: false };
  } catch {
    return { value: null, bounded };
  }
}

function isRecord(value: JsonValue | undefined): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function snapshotCanonicalBytes(input: unknown, maximum: number): ByteSnapshot {
  const captured = capturePrivateBytes(input, maximum);
  if (captured.bytes === null) return { value: null, bounded: captured.bounded };
  const bytes = captured.bytes;
  if (intrinsicByteLength(bytes) >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { value: null, bounded: false };
  }
  try {
    const text = decoder.decode(bytes);
    const parsed = JSON.parse(text) as unknown;
    const snapshot = snapshotJson(parsed);
    if (snapshot.value === null) return snapshot;
    if (`${canonicalJson(snapshot.value)}\n` !== text) return { value: null, bounded: false };
    return snapshot;
  } catch {
    return { value: null, bounded: false };
  }
}

function snapshotCanaries(input: unknown): readonly Stage5SyntheticCanary[] | null {
  if (input === undefined) return Object.freeze([]);
  const snapshot = snapshotCanonicalBytes(input, STAGE5_PRIVACY_LIMITS.maxCanaryInputBytes);
  if (snapshot.value === null) return null;
  if (Object.keys(snapshot.value).sort().join("\0") !== "canaries\0version") return null;
  if (snapshot.value.version !== "cogs.stage5-privacy-canaries/v1") return null;
  const values = snapshot.value.canaries;
  if (!Array.isArray(values) || values.length > STAGE5_PRIVACY_LIMITS.maxCanaries) return null;
  const seen = new Set<Stage5ProhibitedCategory>();
  const canaries: Stage5SyntheticCanary[] = [];
  for (const value of values) {
    if (!isRecord(value) || Object.keys(value).sort().join("\0") !== "category\0value") return null;
    if (
      typeof value.category !== "string" ||
      !(STAGE5_PROHIBITED_CATEGORIES as readonly string[]).includes(value.category) ||
      seen.has(value.category as Stage5ProhibitedCategory) ||
      typeof value.value !== "string" ||
      Buffer.byteLength(value.value) < 12 ||
      Buffer.byteLength(value.value) > STAGE5_PRIVACY_LIMITS.maxCanaryBytes
    ) {
      return null;
    }
    const category = value.category as Stage5ProhibitedCategory;
    seen.add(category);
    canaries.push(Object.freeze({ category, value: value.value }));
  }
  return Object.freeze(canaries);
}

function folded(value: string): string {
  return value.normalize("NFKC").toUpperCase().toLowerCase();
}

function keyCategory(key: string): Stage5ProhibitedCategory | null {
  const normalized = folded(key);
  if (SAFE_BOUNDARY_KEYS.has(normalized)) return null;
  for (const [category, keys] of KEY_CATEGORIES) if (keys.has(normalized)) return category;
  return null;
}

function heuristicCategory(value: string): Stage5ProhibitedCategory | null {
  const normalized = value.normalize("NFKC");
  if (/^(?:\/|[A-Za-z]:\\|\\\\)/u.test(normalized)) return "arbitrary-path";
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/=-]+|\bsk-[A-Za-z0-9_-]{8,}/iu.test(normalized)) {
    return "credential-or-placeholder";
  }
  if (/(?:\?|&)[A-Za-z0-9_.~-]+=[^\s&]*/u.test(normalized)) return "network-query-or-body";
  return null;
}

function surfaceFor(value: JsonValue): Stage5PrivacySurface | "contract" {
  if (!isRecord(value) || typeof value.surface !== "string") return "contract";
  return (STAGE5_PRIVACY_SURFACES as readonly string[]).includes(value.surface)
    ? (value.surface as Stage5PrivacySurface)
    : "contract";
}

function addFragment(
  fragments: Map<Stage5PrivacySurface | "contract", { exact: string[]; folded: string[] }>,
  surface: Stage5PrivacySurface | "contract",
  value: string,
): void {
  const target = fragments.get(surface);
  if (target === undefined) return;
  const normalized = value.normalize("NFKC");
  target.exact.push(normalized, normalized.replace(/[\t\n\r ]+/gu, ""));
  target.folded.push(folded(value), folded(value).replace(/[\t\n\r :]+/gu, ""));
  if (surface !== "contract") {
    const global = fragments.get("contract");
    global?.exact.push(normalized, normalized.replace(/[\t\n\r ]+/gu, ""));
    global?.folded.push(folded(value), folded(value).replace(/[\t\n\r :]+/gu, ""));
  }
}

function collectPrivacyFragments(
  value: JsonValue,
  surface: Stage5PrivacySurface | "contract",
  findings: Finding[],
  fragments: Map<Stage5PrivacySurface | "contract", { exact: string[]; folded: string[] }>,
): void {
  if (typeof value === "string") {
    addFragment(fragments, surface, value);
    const heuristic = heuristicCategory(value);
    if (heuristic !== null) findings.push({ surface, category: heuristic });
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) {
      const itemSurface = surfaceFor(item);
      collectPrivacyFragments(item, itemSurface === "contract" ? surface : itemSurface, findings, fragments);
    }
    return;
  }
  const detectedSurface = surfaceFor(value);
  const ownSurface = detectedSurface === "contract" ? surface : detectedSurface;
  for (const [key, item] of Object.entries(value)) {
    const category = keyCategory(key);
    if (category !== null) findings.push({ surface: ownSurface, category });
    addFragment(fragments, ownSurface, key);
    collectPrivacyFragments(item, ownSurface, findings, fragments);
  }
}

function canaryForms(value: string): readonly string[] {
  return Object.freeze(
    [
      ...new Set([
        value,
        value.toLowerCase(),
        value.toUpperCase(),
        value.normalize("NFC"),
        value.normalize("NFD"),
        value.normalize("NFKC"),
        value.normalize("NFKD"),
      ]),
    ].filter((item) => item.length > 0),
  );
}

function canarySignatures(
  canary: Stage5SyntheticCanary,
): Readonly<{ exact: readonly string[]; folded: readonly string[] }> {
  const exact = new Set<string>();
  const normalized = new Set<string>();
  for (const form of canaryForms(canary.value)) {
    normalized.add(folded(form));
    const bytes = Buffer.from(form, "utf8");
    exact.add(bytes.toString("base64"));
    exact.add(bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, ""));
    normalized.add(bytes.toString("hex"));
  }
  return Object.freeze({ exact: Object.freeze([...exact]), folded: Object.freeze([...normalized]) });
}

function signatureComposed(signature: string, fragments: readonly string[]): boolean {
  if (signature.length === 0) return false;
  if (fragments.some((fragment) => fragment.includes(signature))) return true;
  const reachable = new Uint8Array(signature.length + 1);
  reachable[0] = 1;
  for (let offset = 0; offset < signature.length; offset += 1) {
    if (reachable[offset] !== 1) continue;
    for (const fragment of fragments) {
      if (fragment.length === 0) continue;
      if (offset === 0) {
        for (let end = 1; end < signature.length; end += 1) {
          if (fragment.endsWith(signature.slice(0, end))) reachable[end] = 1;
        }
      }
      if (signature.startsWith(fragment, offset)) {
        reachable[Math.min(signature.length, offset + fragment.length)] = 1;
      }
      if (fragment.startsWith(signature.slice(offset))) reachable[signature.length] = 1;
    }
  }
  return reachable[signature.length] === 1;
}

function containsCanary(signatures: ReturnType<typeof canarySignatures>, fragments: FragmentSet): boolean {
  return (
    signatures.exact.some((signature) => signatureComposed(signature, fragments.exact)) ||
    signatures.folded.some((signature) => signatureComposed(signature, fragments.folded))
  );
}

function scanPrivacy(value: JsonRecord, canaries: readonly Stage5SyntheticCanary[]): Finding[] {
  const findings: Finding[] = [];
  const fragments = new Map<Stage5PrivacySurface | "contract", { exact: string[]; folded: string[] }>();
  for (const surface of ["contract", ...STAGE5_PRIVACY_SURFACES] as const) {
    fragments.set(surface, { exact: [], folded: [] });
  }
  collectPrivacyFragments(value, "contract", findings, fragments);
  for (const canary of canaries) {
    const signatures = canarySignatures(canary);
    let surfaceMatch = false;
    for (const surface of STAGE5_PRIVACY_SURFACES) {
      const values = fragments.get(surface);
      if (values !== undefined && containsCanary(signatures, values)) {
        findings.push({ surface, category: canary.category });
        surfaceMatch = true;
      }
    }
    const global = fragments.get("contract");
    if (!surfaceMatch && global !== undefined && containsCanary(signatures, global)) {
      findings.push({ surface: "contract", category: canary.category });
    }
  }
  const unique = new Map<string, Finding>();
  for (const finding of findings) unique.set(`${finding.surface}\0${finding.category}`, finding);
  return [...unique.values()];
}

function findingSummary(findings: readonly Finding[]): {
  affectedSurfaces: readonly (Stage5PrivacySurface | "contract")[];
  categories: readonly Stage5ProhibitedCategory[];
  root: string | null;
} {
  if (findings.length === 0) return { affectedSurfaces: Object.freeze([]), categories: Object.freeze([]), root: null };
  const surfaceSet = new Set(findings.map((finding) => finding.surface));
  const categorySet = new Set(findings.map((finding) => finding.category));
  const affectedSurfaces = [...surfaceSet].sort(
    (left, right) => (SURFACE_ORDER.get(left) ?? 99) - (SURFACE_ORDER.get(right) ?? 99),
  );
  const categories = [...categorySet].sort(
    (left, right) => (CATEGORY_ORDER.get(left) ?? 99) - (CATEGORY_ORDER.get(right) ?? 99),
  );
  const grouped = affectedSurfaces.flatMap((surface) =>
    categories
      .map((category) => ({
        surface,
        category,
        count: findings.filter((finding) => finding.surface === surface && finding.category === category).length,
      }))
      .filter((row) => row.count > 0),
  ) as unknown as JsonValue;
  return {
    affectedSurfaces: Object.freeze(affectedSurfaces),
    categories: Object.freeze(categories),
    root: semanticDigest(FINDING_DOMAIN, grouped),
  };
}

function exportBoundary(value: JsonRecord): BoundaryResult {
  const surfaces = value.surfaces;
  if (!Array.isArray(surfaces)) {
    return {
      reason: "STAGE5_PRIVACY_RAW_EXPORT_BOUNDARY_INVALID",
      attachmentsExcluded: false,
      boundary: "invalid",
      sensitive: "not-evaluated",
    };
  }
  const exportSurface = surfaces.find((surface) => isRecord(surface) && surface.surface === "export");
  if (!isRecord(exportSurface) || !isRecord(exportSurface.boundary)) {
    return {
      reason: "STAGE5_PRIVACY_RAW_EXPORT_BOUNDARY_INVALID",
      attachmentsExcluded: false,
      boundary: "invalid",
      sensitive: "missing",
    };
  }
  const boundary = exportSurface.boundary;
  if (boundary.attachments_included !== false) {
    return {
      reason: "STAGE5_PRIVACY_ATTACHMENT_BOUNDARY_INVALID",
      attachmentsExcluded: false,
      boundary: "invalid",
      sensitive: boundary.sensitive === true ? "present" : "missing",
    };
  }
  if (boundary.sensitive !== true) {
    return {
      reason: "STAGE5_PRIVACY_SENSITIVE_MARKING_MISSING",
      attachmentsExcluded: true,
      boundary: "invalid",
      sensitive: "missing",
    };
  }
  if (
    boundary.explicit_user_action !== true ||
    boundary.authenticated_api !== true ||
    boundary.model_callable !== false ||
    boundary.mode !== "raw" ||
    boundary.sanitized !== false ||
    boundary.anonymized !== false ||
    boundary.raw_payload_present !== false ||
    exportSurface.content_present !== false
  ) {
    return {
      reason: "STAGE5_PRIVACY_RAW_EXPORT_BOUNDARY_INVALID",
      attachmentsExcluded: true,
      boundary: "invalid",
      sensitive: "present",
    };
  }
  return {
    reason: "STAGE5_PRIVACY_CLEAR",
    attachmentsExcluded: true,
    boundary: "explicit-sensitive-authenticated-non-model-no-payload",
    sensitive: "present",
  };
}

function metadataProvenanceValid(suite: Stage5Suite): boolean {
  for (const surface of suite.surfaces) {
    const digestInput: JsonRecord = {
      surface: surface.surface,
      record_kind: surface.record_kind as JsonValue,
      classification: surface.classification as JsonValue,
      outcome: surface.outcome as JsonValue,
      content_present: surface.content_present as JsonValue,
      attachment_content_present: surface.attachment_content_present as JsonValue,
      field_count: surface.field_count as JsonValue,
      boundary: surface.boundary,
    };
    if (surface.metadata_sha256 !== semanticDigest(SURFACE_METADATA_DOMAIN, digestInput)) return false;
  }
  const inventory = suite.deletion.version_inventory;
  const inventoryInput: JsonRecord = {
    version_policy: suite.deletion.version_policy as JsonValue,
    versions_expected: inventory.versions_expected as JsonValue,
    delete_markers_expected: inventory.delete_markers_expected as JsonValue,
  };
  return inventory.inventory_sha256 === semanticDigest(VERSION_INVENTORY_DOMAIN, inventoryInput);
}

function deletionNotEvaluated(): Stage5PrivacyDeletionReport["deletion"] {
  return {
    result: "not-evaluated",
    reason_code: "STAGE5_DELETION_NOT_EVALUATED",
    initial_state: null,
    terminal_state: null,
    accepted_transition_count: 0,
    retention_seconds: null,
    version_deletion: "not-evaluated",
    legal_hold: "not-evaluated",
    failure_contract: "stop-no-success-no-retry",
    uncertainty_contract: "sticky-preserve-unconfirmed-no-unknown-to-absent",
    actual_eks_deletion: "unexecuted",
    actual_object_store_deletion: "unexecuted",
  };
}

function evaluateDeletion(suite: Stage5Suite): DeletionEvaluation {
  const base = {
    initial_state: "retained" as const,
    retention_seconds: 2592000 as const,
    version_deletion: "all-versions-and-delete-markers" as const,
    failure_contract: "stop-no-success-no-retry" as const,
    uncertainty_contract: "sticky-preserve-unconfirmed-no-unknown-to-absent" as const,
    actual_eks_deletion: "unexecuted" as const,
    actual_object_store_deletion: "unexecuted" as const,
  };
  if (suite.legal_hold.mode === "active") {
    if (suite.deletion.transitions.length !== 0) {
      return {
        status: "preserve-uncertain",
        deletion: {
          ...base,
          result: "uncertain-stop",
          reason_code: "STAGE5_DELETION_INVALID_SEQUENCE",
          terminal_state: "uncertain-stop",
          accepted_transition_count: 0,
          legal_hold: "active-separate",
        },
      };
    }
    return {
      status: "blocked-legal-hold",
      deletion: {
        ...base,
        result: "held-separate",
        reason_code: "STAGE5_DELETION_LEGAL_HOLD_SEPARATE",
        terminal_state: "held-separate",
        accepted_transition_count: 0,
        legal_hold: "active-separate",
      },
    };
  }

  let accepted = 0;
  for (const transition of suite.deletion.transitions) {
    if (transition === "operation-failed") {
      return {
        status: "failed-stop",
        deletion: {
          ...base,
          result: "failed-stop",
          reason_code: "STAGE5_DELETION_OPERATION_FAILED",
          terminal_state: "failed-stop",
          accepted_transition_count: accepted,
          legal_hold: "none-separate",
        },
      };
    }
    if (transition === "observation-uncertain") {
      return {
        status: "preserve-uncertain",
        deletion: {
          ...base,
          result: "uncertain-stop",
          reason_code: "STAGE5_DELETION_OBSERVATION_UNCERTAIN",
          terminal_state: "uncertain-stop",
          accepted_transition_count: accepted,
          legal_hold: "none-separate",
        },
      };
    }
    if (transition !== STAGE5_DELETION_TRANSITIONS[accepted]) {
      return {
        status: "preserve-uncertain",
        deletion: {
          ...base,
          result: "uncertain-stop",
          reason_code: "STAGE5_DELETION_INVALID_SEQUENCE",
          terminal_state: "uncertain-stop",
          accepted_transition_count: accepted,
          legal_hold: "none-separate",
        },
      };
    }
    accepted += 1;
  }
  if (accepted !== STAGE5_DELETION_TRANSITIONS.length) {
    return {
      status: "preserve-uncertain",
      deletion: {
        ...base,
        result: "uncertain-stop",
        reason_code: "STAGE5_DELETION_INVALID_SEQUENCE",
        terminal_state: "uncertain-stop",
        accepted_transition_count: accepted,
        legal_hold: "none-separate",
      },
    };
  }
  return {
    status: "local-contract-pass",
    deletion: {
      ...base,
      result: "synthetic-sequence-complete",
      reason_code: "STAGE5_DELETION_SEQUENCE_COMPLETE",
      terminal_state: "deleted-verified",
      accepted_transition_count: accepted,
      legal_hold: "none-separate",
    },
  };
}

function makeReport(
  digest: string | null,
  status: Stage5PrivacyDeletionReport["status"],
  privacy: Stage5PrivacyDeletionReport["privacy"],
  deletion: Stage5PrivacyDeletionReport["deletion"],
): Stage5PrivacyDeletionReport {
  return deepFreeze({
    version: "cogs.stage5-privacy-deletion-report/v1",
    authority: "local-static-synthetic-privacy-classifier",
    issue: 365,
    scope: "local-static-synthetic-only",
    qualified: false,
    campaign_authorized: false,
    cloud_execution_observed: false,
    kubernetes_execution_observed: false,
    provider_execution_observed: false,
    external_model_invoked: false,
    release_eligible: false,
    suite_sha256: digest,
    status,
    privacy,
    deletion,
  });
}

/**
 * Scans bounded canonical JSON bytes for one synthetic metadata suite and
 * evaluates its pure deletion model. The byte bound is enforced before JSON
 * parsing or object reflection. It performs no filesystem, process, network,
 * provider, cluster, object-store, deployment, or model operation.
 */
export function evaluateStage5PrivacyDeletion(
  input: unknown,
  syntheticCanaries?: unknown,
): Stage5PrivacyDeletionReport {
  const canaries = snapshotCanaries(syntheticCanaries);
  if (canaries === null) {
    return makeReport(
      null,
      "preserve-uncertain",
      {
        result: "uncertain",
        reason_code: "STAGE5_PRIVACY_INVALID_SHAPE",
        surfaces_scanned: 0,
        affected_surfaces: Object.freeze([]),
        categories: Object.freeze([]),
        finding_count: 0,
        finding_root_sha256: null,
        attachments_excluded: false,
        raw_export_boundary: "not-evaluated",
        sensitive_marking: "not-evaluated",
      },
      deletionNotEvaluated(),
    );
  }
  const snapshot = snapshotCanonicalBytes(input, STAGE5_PRIVACY_LIMITS.maxInputBytes);
  if (snapshot.value === null) {
    return makeReport(
      null,
      "preserve-uncertain",
      {
        result: "uncertain",
        reason_code: snapshot.bounded ? "STAGE5_PRIVACY_BOUNDED_INPUT" : "STAGE5_PRIVACY_INVALID_SHAPE",
        surfaces_scanned: 0,
        affected_surfaces: Object.freeze([]),
        categories: Object.freeze([]),
        finding_count: 0,
        finding_root_sha256: null,
        attachments_excluded: false,
        raw_export_boundary: "not-evaluated",
        sensitive_marking: "not-evaluated",
      },
      deletionNotEvaluated(),
    );
  }
  const digest = semanticDigest(REPORT_DOMAIN, snapshot.value);
  const findings = scanPrivacy(snapshot.value, canaries);
  const summary = findingSummary(findings);
  const recognizedSurfaces = Array.isArray(snapshot.value.surfaces)
    ? new Set(snapshot.value.surfaces.map(surfaceFor).filter((surface) => surface !== "contract")).size
    : 0;
  if (findings.length > 0) {
    return makeReport(
      digest,
      "blocked-prohibited-content",
      {
        result: "prohibited-content",
        reason_code: "STAGE5_PRIVACY_PROHIBITED_CONTENT",
        surfaces_scanned: recognizedSurfaces,
        affected_surfaces: summary.affectedSurfaces,
        categories: summary.categories,
        finding_count: findings.length,
        finding_root_sha256: summary.root,
        attachments_excluded: false,
        raw_export_boundary: "not-evaluated",
        sensitive_marking: "not-evaluated",
      },
      deletionNotEvaluated(),
    );
  }

  const boundary = exportBoundary(snapshot.value);
  if (boundary.reason !== "STAGE5_PRIVACY_CLEAR") {
    return makeReport(
      digest,
      "invalid-contract",
      {
        result: "invalid-contract",
        reason_code: boundary.reason,
        surfaces_scanned: recognizedSurfaces,
        affected_surfaces: Object.freeze(["export"]),
        categories: Object.freeze([]),
        finding_count: 0,
        finding_root_sha256: null,
        attachments_excluded: boundary.attachmentsExcluded,
        raw_export_boundary: boundary.boundary,
        sensitive_marking: boundary.sensitive,
      },
      deletionNotEvaluated(),
    );
  }
  if (!validateSuite(snapshot.value)) {
    return makeReport(
      digest,
      "invalid-contract",
      {
        result: "invalid-contract",
        reason_code: "STAGE5_PRIVACY_INVALID_SHAPE",
        surfaces_scanned: recognizedSurfaces,
        affected_surfaces: Object.freeze([]),
        categories: Object.freeze([]),
        finding_count: 0,
        finding_root_sha256: null,
        attachments_excluded: true,
        raw_export_boundary: boundary.boundary,
        sensitive_marking: boundary.sensitive,
      },
      {
        ...deletionNotEvaluated(),
        result: "invalid-contract",
        reason_code: "STAGE5_DELETION_INVALID_CONTRACT",
      },
    );
  }
  if (!metadataProvenanceValid(snapshot.value)) {
    return makeReport(
      digest,
      "invalid-contract",
      {
        result: "invalid-contract",
        reason_code: "STAGE5_PRIVACY_INVALID_SHAPE",
        surfaces_scanned: recognizedSurfaces,
        affected_surfaces: Object.freeze([]),
        categories: Object.freeze([]),
        finding_count: 0,
        finding_root_sha256: null,
        attachments_excluded: true,
        raw_export_boundary: boundary.boundary,
        sensitive_marking: boundary.sensitive,
      },
      {
        ...deletionNotEvaluated(),
        result: "invalid-contract",
        reason_code: "STAGE5_DELETION_INVALID_CONTRACT",
      },
    );
  }
  const deletion = evaluateDeletion(snapshot.value);
  return makeReport(
    digest,
    deletion.status,
    {
      result: "clear",
      reason_code: "STAGE5_PRIVACY_CLEAR",
      surfaces_scanned: STAGE5_PRIVACY_SURFACES.length,
      affected_surfaces: Object.freeze([]),
      categories: Object.freeze([]),
      finding_count: 0,
      finding_root_sha256: null,
      attachments_excluded: true,
      raw_export_boundary: boundary.boundary,
      sensitive_marking: boundary.sensitive,
    },
    deletion.deletion,
  );
}

export function canonicalStage5PrivacyDeletionReport(report: Stage5PrivacyDeletionReport): string {
  const snapshot = snapshotJson(report);
  if (snapshot.value === null) throw new TypeError("report is not bounded canonical JSON");
  return `${canonicalJson(snapshot.value)}\n`;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
