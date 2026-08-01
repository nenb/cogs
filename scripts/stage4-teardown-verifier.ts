import { createHash } from "node:crypto";

export const STAGE4_TEARDOWN_PHASES = Object.freeze([
  "freeze-reconcilers",
  "close-admission",
  "revoke-credentials",
  "revoke-readiness",
  "remove-session-workloads",
  "verify-kubernetes-zero",
  "remove-cluster-infrastructure",
  "record-external-cloud-inventory-claim",
] as const);

export const STAGE4_TEARDOWN_PRODUCER_CLASSES = Object.freeze([
  "control-observer",
  "admission-observer",
  "credential-observer",
  "readiness-observer",
  "workload-mutator",
  "kubernetes-zero-observer",
  "infrastructure-mutator",
  "claimed-external-inventory-observer",
] as const);

export const STAGE4_TEARDOWN_REASON_CODES = Object.freeze([
  "STAGE4_AWAITING_EVIDENCE",
  "STAGE4_UNCERTAIN_EVIDENCE",
  "STAGE4_EVIDENCE_ORDER_COMPLETE",
  "STAGE4_INVALID_VERSION",
  "STAGE4_INVALID_SHAPE",
  "STAGE4_INVALID_PHASE_ORDER",
  "STAGE4_INVALID_PRODUCER_CLASS",
  "STAGE4_INVALID_EVIDENCE",
  "STAGE4_EVIDENCE_REPLAY",
  "STAGE4_EVIDENCE_OUT_OF_ORDER",
] as const);

export type Stage4TeardownPhase = (typeof STAGE4_TEARDOWN_PHASES)[number];
export type Stage4TeardownProducerClass = (typeof STAGE4_TEARDOWN_PRODUCER_CLASSES)[number];
export type Stage4TeardownReasonCode = (typeof STAGE4_TEARDOWN_REASON_CODES)[number];
export type Stage4TeardownStatus = "awaiting-evidence" | "preserve-uncertain" | "evidence-order-complete";
export type Stage4TeardownPhaseState = "pending" | "observed" | "uncertain";

export type Stage4TeardownPhaseRow = Readonly<{
  phase: Stage4TeardownPhase;
  producer_class: Stage4TeardownProducerClass;
  state: Stage4TeardownPhaseState;
  evidence_sha256?: string;
  uncertainty_artifact_sha256?: string;
}>;

export type Stage4TeardownPlan = Readonly<{
  version: "cogs.stage4-teardown-plan/v1";
  source_sha256: string;
  profile_sha256: string;
  phases: readonly Stage4TeardownPhaseRow[];
}>;

export type Stage4TeardownVerdict = Readonly<{
  version: "cogs.stage4-teardown-verdict/v1";
  authority: "local-teardown-order-classifier";
  cloud_inventory_observed: false;
  cloud_execution_observed: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  source_sha256: string | null;
  profile_sha256: string | null;
  plan_sha256: string | null;
  evidence_root_sha256: string | null;
  status: Stage4TeardownStatus;
  next_phase: Stage4TeardownPhase | null;
  accepted_phase_count: number | null;
  reason_code: Stage4TeardownReasonCode;
}>;

const EXPECTED_PRODUCER_CLASSES: readonly Stage4TeardownProducerClass[] = STAGE4_TEARDOWN_PRODUCER_CLASSES;
const DIGEST = /^[0-9a-f]{64}$/u;
const PLAN_KEYS = ["phases", "profile_sha256", "source_sha256", "version"] as const;
const PENDING_ROW_KEYS = ["phase", "producer_class", "state"] as const;
const OBSERVED_ROW_KEYS = ["evidence_sha256", "phase", "producer_class", "state"] as const;
const UNCERTAIN_ROW_KEYS = ["phase", "producer_class", "state", "uncertainty_artifact_sha256"] as const;
const PLAN_BINDING_DOMAIN = "cogs.stage4/teardown-plan-semantic-binding/v1";
const EVIDENCE_ROOT_DOMAIN = "cogs.stage4/teardown-evidence-root/v1";

type DataRecord = Record<string, unknown>;
type ParsedRow = Readonly<{
  phase: Stage4TeardownPhase;
  producerClass: Stage4TeardownProducerClass;
  state: Stage4TeardownPhaseState;
  artifactSha256: string | null;
}>;
type Bindings = Readonly<{ planSha256: string; evidenceRootSha256: string }>;

function verdict(
  status: Stage4TeardownStatus,
  reasonCode: Stage4TeardownReasonCode,
  sourceSha256: string | null,
  profileSha256: string | null,
  acceptedPhaseCount: number | null,
  nextPhase: Stage4TeardownPhase | null,
  bindings: Bindings | null,
): Stage4TeardownVerdict {
  return Object.freeze({
    version: "cogs.stage4-teardown-verdict/v1",
    authority: "local-teardown-order-classifier",
    cloud_inventory_observed: false,
    cloud_execution_observed: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    source_sha256: sourceSha256,
    profile_sha256: profileSha256,
    plan_sha256: bindings?.planSha256 ?? null,
    evidence_root_sha256: bindings?.evidenceRootSha256 ?? null,
    status,
    next_phase: nextPhase,
    accepted_phase_count: acceptedPhaseCount,
    reason_code: reasonCode,
  });
}

function preserve(
  reasonCode: Exclude<Stage4TeardownReasonCode, "STAGE4_AWAITING_EVIDENCE" | "STAGE4_EVIDENCE_ORDER_COMPLETE">,
  sourceSha256: string | null,
  profileSha256: string | null,
  acceptedPhaseCount: number | null,
  bindings: Bindings | null = null,
): Stage4TeardownVerdict {
  return verdict("preserve-uncertain", reasonCode, sourceSha256, profileSha256, acceptedPhaseCount, null, bindings);
}

function dataRecord(value: unknown): DataRecord | null {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const snapshot: DataRecord = Object.create(null) as DataRecord;
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) return null;
      snapshot[key] = descriptor.value;
    }
    return snapshot;
  } catch {
    return null;
  }
}

function dataArray(value: unknown): readonly unknown[] | null {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor | undefined>;
    const lengthDescriptor = descriptors.length;
    if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) return null;
    const length = lengthDescriptor.value;
    if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) return null;
    const expectedKeys = [...Array.from({ length }, (_, index) => String(index)), "length"];
    if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) return null;
    const snapshot: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) return null;
      snapshot.push(descriptor.value);
    }
    return snapshot;
  } catch {
    return null;
  }
}

function hasExactKeys(record: DataRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST.test(value);
}

function isProducerClass(value: unknown): value is Stage4TeardownProducerClass {
  return typeof value === "string" && (STAGE4_TEARDOWN_PRODUCER_CLASSES as readonly string[]).includes(value);
}

function isState(value: unknown): value is Stage4TeardownPhaseState {
  return value === "pending" || value === "observed" || value === "uncertain";
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const properties = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => compareCodePoints(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`);
    return `{${properties.join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("value is not representable as canonical JSON");
  return encoded;
}

function semanticDigest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function semanticBindings(plan: Stage4TeardownPlan, rows: readonly ParsedRow[]): Bindings {
  const evidenceRows = rows.map((row) => {
    const base = { phase: row.phase, state: row.state };
    if (row.state === "observed") return { ...base, evidence_sha256: row.artifactSha256 };
    if (row.state === "uncertain") return { ...base, uncertainty_artifact_sha256: row.artifactSha256 };
    return base;
  });
  return {
    planSha256: semanticDigest(PLAN_BINDING_DOMAIN, plan),
    evidenceRootSha256: semanticDigest(EVIDENCE_ROOT_DOMAIN, evidenceRows),
  };
}

/**
 * Classifies a strict, already-decoded, metadata-only Stage 4 plan. Producer
 * classes and artifact digests are caller claims, not identity or provider truth.
 * The function performs no I/O and grants no execution or release authority.
 */
export function verifyStage4Teardown(input: unknown): Stage4TeardownVerdict {
  const root = dataRecord(input);
  if (root === null) return preserve("STAGE4_INVALID_SHAPE", null, null, null);

  const sourceSha256 = isDigest(root.source_sha256) ? root.source_sha256 : null;
  const profileSha256 = isDigest(root.profile_sha256) ? root.profile_sha256 : null;
  if (!hasExactKeys(root, PLAN_KEYS)) return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256, null);
  if (root.version !== "cogs.stage4-teardown-plan/v1") {
    return preserve("STAGE4_INVALID_VERSION", sourceSha256, profileSha256, null);
  }

  const phaseValues = dataArray(root.phases);
  if (sourceSha256 === null || profileSha256 === null || phaseValues === null) {
    return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256, null);
  }
  if (phaseValues.length !== STAGE4_TEARDOWN_PHASES.length) {
    return preserve("STAGE4_INVALID_PHASE_ORDER", sourceSha256, profileSha256, null);
  }

  const rows: ParsedRow[] = [];
  let acceptedPhaseCount = 0;
  let prefixOpen = true;
  for (const [index, value] of phaseValues.entries()) {
    const row = dataRecord(value);
    if (row === null) {
      return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256, acceptedPhaseCount);
    }

    const expectedPhase = STAGE4_TEARDOWN_PHASES[index];
    const expectedProducerClass = EXPECTED_PRODUCER_CLASSES[index];
    if (expectedPhase === undefined || expectedProducerClass === undefined || row.phase !== expectedPhase) {
      return preserve("STAGE4_INVALID_PHASE_ORDER", sourceSha256, profileSha256, acceptedPhaseCount);
    }
    if (!isState(row.state)) {
      return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256, acceptedPhaseCount);
    }
    const expectedKeys =
      row.state === "observed" ? OBSERVED_ROW_KEYS : row.state === "uncertain" ? UNCERTAIN_ROW_KEYS : PENDING_ROW_KEYS;
    if (!hasExactKeys(row, expectedKeys)) {
      return preserve("STAGE4_INVALID_EVIDENCE", sourceSha256, profileSha256, acceptedPhaseCount);
    }
    if (!isProducerClass(row.producer_class) || row.producer_class !== expectedProducerClass) {
      return preserve("STAGE4_INVALID_PRODUCER_CLASS", sourceSha256, profileSha256, acceptedPhaseCount);
    }

    let artifactSha256: string | null = null;
    if (row.state === "observed") {
      if (!isDigest(row.evidence_sha256)) {
        return preserve("STAGE4_INVALID_EVIDENCE", sourceSha256, profileSha256, acceptedPhaseCount);
      }
      artifactSha256 = row.evidence_sha256;
    } else if (row.state === "uncertain") {
      if (!isDigest(row.uncertainty_artifact_sha256)) {
        return preserve("STAGE4_INVALID_EVIDENCE", sourceSha256, profileSha256, acceptedPhaseCount);
      }
      artifactSha256 = row.uncertainty_artifact_sha256;
    }

    rows.push({
      phase: expectedPhase,
      producerClass: expectedProducerClass,
      state: row.state,
      artifactSha256,
    });
    if (prefixOpen && row.state === "observed") acceptedPhaseCount += 1;
    else prefixOpen = false;
  }

  const normalizedPlan: Stage4TeardownPlan = {
    version: "cogs.stage4-teardown-plan/v1",
    source_sha256: sourceSha256,
    profile_sha256: profileSha256,
    phases: rows.map<Stage4TeardownPhaseRow>((row) => {
      const base = { phase: row.phase, producer_class: row.producerClass, state: row.state };
      if (row.state === "observed" && row.artifactSha256 !== null) {
        return { ...base, evidence_sha256: row.artifactSha256 };
      }
      if (row.state === "uncertain" && row.artifactSha256 !== null) {
        return { ...base, uncertainty_artifact_sha256: row.artifactSha256 };
      }
      return base;
    }),
  };
  const bindings = semanticBindings(normalizedPlan, rows);

  if (rows.some((row) => row.state === "uncertain")) {
    return preserve("STAGE4_UNCERTAIN_EVIDENCE", sourceSha256, profileSha256, acceptedPhaseCount, bindings);
  }

  const artifactDigests = new Set<string>([sourceSha256, profileSha256]);
  for (const row of rows) {
    if (row.artifactSha256 === null) continue;
    if (artifactDigests.has(row.artifactSha256)) {
      return preserve("STAGE4_EVIDENCE_REPLAY", sourceSha256, profileSha256, acceptedPhaseCount, bindings);
    }
    artifactDigests.add(row.artifactSha256);
  }

  if (rows.slice(acceptedPhaseCount).some((row) => row.state === "observed")) {
    return preserve("STAGE4_EVIDENCE_OUT_OF_ORDER", sourceSha256, profileSha256, acceptedPhaseCount, bindings);
  }
  if (acceptedPhaseCount < STAGE4_TEARDOWN_PHASES.length) {
    return verdict(
      "awaiting-evidence",
      "STAGE4_AWAITING_EVIDENCE",
      sourceSha256,
      profileSha256,
      acceptedPhaseCount,
      STAGE4_TEARDOWN_PHASES[acceptedPhaseCount] ?? null,
      bindings,
    );
  }
  return verdict(
    "evidence-order-complete",
    "STAGE4_EVIDENCE_ORDER_COMPLETE",
    sourceSha256,
    profileSha256,
    acceptedPhaseCount,
    null,
    bindings,
  );
}
