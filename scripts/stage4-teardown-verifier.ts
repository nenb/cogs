export const STAGE4_TEARDOWN_PHASES = Object.freeze([
  "freeze-reconcilers",
  "close-admission",
  "revoke-credentials",
  "revoke-readiness",
  "remove-session-workloads",
  "verify-kubernetes-zero",
  "remove-cluster-infrastructure",
  "verify-independent-cloud-zero",
] as const);

export const STAGE4_TEARDOWN_PRODUCER_CLASSES = Object.freeze([
  "control-observer",
  "admission-observer",
  "credential-observer",
  "readiness-observer",
  "workload-mutator",
  "kubernetes-zero-observer",
  "infrastructure-mutator",
  "independent-cloud-zero-observer",
] as const);

export const STAGE4_TEARDOWN_REASON_CODES = Object.freeze([
  "STAGE4_AWAITING_EVIDENCE",
  "STAGE4_UNCERTAIN_EVIDENCE",
  "STAGE4_ZERO_VERIFIED",
  "STAGE4_INVALID_VERSION",
  "STAGE4_INVALID_SHAPE",
  "STAGE4_INVALID_PHASE_ORDER",
  "STAGE4_INVALID_PRODUCER_CLASS",
  "STAGE4_INVALID_EVIDENCE",
  "STAGE4_EVIDENCE_REPLAY",
  "STAGE4_EVIDENCE_OUT_OF_ORDER",
  "STAGE4_FINAL_OBSERVER_NOT_INDEPENDENT",
] as const);

export type Stage4TeardownPhase = (typeof STAGE4_TEARDOWN_PHASES)[number];
export type Stage4TeardownProducerClass = (typeof STAGE4_TEARDOWN_PRODUCER_CLASSES)[number];
export type Stage4TeardownReasonCode = (typeof STAGE4_TEARDOWN_REASON_CODES)[number];
export type Stage4TeardownStatus = "awaiting-evidence" | "preserve-uncertain" | "zero-verified";
export type Stage4TeardownPhaseState = "pending" | "observed" | "uncertain";

export type Stage4TeardownPhaseRow = Readonly<{
  phase: Stage4TeardownPhase;
  producer_class: Stage4TeardownProducerClass;
  state: Stage4TeardownPhaseState;
  evidence_sha256?: string;
}>;

export type Stage4TeardownPlan = Readonly<{
  version: "cogs.stage4-teardown-plan/v1";
  source_sha256: string;
  profile_sha256: string;
  phases: readonly Stage4TeardownPhaseRow[];
}>;

export type Stage4TeardownVerdict = Readonly<{
  version: "cogs.stage4-teardown-verdict/v1";
  source_sha256: string | null;
  profile_sha256: string | null;
  status: Stage4TeardownStatus;
  next_phase: Stage4TeardownPhase | null;
  accepted_phase_count: number;
  reason_code: Stage4TeardownReasonCode;
}>;

const EXPECTED_PRODUCER_CLASSES: readonly Stage4TeardownProducerClass[] = STAGE4_TEARDOWN_PRODUCER_CLASSES;
const MUTATOR_CLASSES: readonly Stage4TeardownProducerClass[] = ["workload-mutator", "infrastructure-mutator"];
const DIGEST = /^[0-9a-f]{64}$/u;
const PLAN_KEYS = ["phases", "profile_sha256", "source_sha256", "version"] as const;
const BASE_ROW_KEYS = ["phase", "producer_class", "state"] as const;
const OBSERVED_ROW_KEYS = ["evidence_sha256", "phase", "producer_class", "state"] as const;

type DataRecord = Record<string, unknown>;
type ParsedRow = Readonly<{
  phase: Stage4TeardownPhase;
  state: Stage4TeardownPhaseState;
  evidenceSha256: string | null;
}>;

function verdict(
  status: Stage4TeardownStatus,
  reasonCode: Stage4TeardownReasonCode,
  sourceSha256: string | null,
  profileSha256: string | null,
  acceptedPhaseCount: number,
  nextPhase: Stage4TeardownPhase | null,
): Stage4TeardownVerdict {
  return Object.freeze({
    version: "cogs.stage4-teardown-verdict/v1",
    source_sha256: sourceSha256,
    profile_sha256: profileSha256,
    status,
    next_phase: nextPhase,
    accepted_phase_count: acceptedPhaseCount,
    reason_code: reasonCode,
  });
}

function preserve(
  reasonCode: Exclude<Stage4TeardownReasonCode, "STAGE4_AWAITING_EVIDENCE" | "STAGE4_ZERO_VERIFIED">,
  sourceSha256: string | null,
  profileSha256: string | null,
  acceptedPhaseCount = 0,
): Stage4TeardownVerdict {
  return verdict("preserve-uncertain", reasonCode, sourceSha256, profileSha256, acceptedPhaseCount, null);
}

function dataRecord(value: unknown): DataRecord | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const descriptor of Object.values(descriptors)) {
    if (!("value" in descriptor) || descriptor.enumerable !== true) return null;
  }
  return value as DataRecord;
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

/**
 * Classifies already-decoded, metadata-only Stage 4 evidence. This function has
 * no I/O and its result asks only for the next evidence phase.
 */
export function verifyStage4Teardown(input: unknown): Stage4TeardownVerdict {
  const root = dataRecord(input);
  if (root === null) return preserve("STAGE4_INVALID_SHAPE", null, null);

  const sourceSha256 = isDigest(root.source_sha256) ? root.source_sha256 : null;
  const profileSha256 = isDigest(root.profile_sha256) ? root.profile_sha256 : null;

  if (!hasExactKeys(root, PLAN_KEYS)) return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256);
  if (root.version !== "cogs.stage4-teardown-plan/v1") {
    return preserve("STAGE4_INVALID_VERSION", sourceSha256, profileSha256);
  }
  if (sourceSha256 === null || profileSha256 === null || !Array.isArray(root.phases)) {
    return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256);
  }
  if (root.phases.length !== STAGE4_TEARDOWN_PHASES.length) {
    return preserve("STAGE4_INVALID_PHASE_ORDER", sourceSha256, profileSha256);
  }

  const rows: ParsedRow[] = [];
  for (const [index, value] of root.phases.entries()) {
    const row = dataRecord(value);
    if (row === null) return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256);

    const expectedPhase = STAGE4_TEARDOWN_PHASES[index];
    const expectedProducerClass = EXPECTED_PRODUCER_CLASSES[index];
    if (expectedPhase === undefined || expectedProducerClass === undefined || row.phase !== expectedPhase) {
      return preserve("STAGE4_INVALID_PHASE_ORDER", sourceSha256, profileSha256);
    }
    if (!isState(row.state)) return preserve("STAGE4_INVALID_SHAPE", sourceSha256, profileSha256);
    const expectedKeys = row.state === "observed" ? OBSERVED_ROW_KEYS : BASE_ROW_KEYS;
    if (!hasExactKeys(row, expectedKeys)) {
      return preserve("STAGE4_INVALID_EVIDENCE", sourceSha256, profileSha256);
    }
    if (!isProducerClass(row.producer_class)) {
      return preserve("STAGE4_INVALID_PRODUCER_CLASS", sourceSha256, profileSha256);
    }
    if (
      index === STAGE4_TEARDOWN_PHASES.length - 1 &&
      row.state === "observed" &&
      MUTATOR_CLASSES.includes(row.producer_class)
    ) {
      return preserve("STAGE4_FINAL_OBSERVER_NOT_INDEPENDENT", sourceSha256, profileSha256, index);
    }
    if (row.producer_class !== expectedProducerClass) {
      return preserve("STAGE4_INVALID_PRODUCER_CLASS", sourceSha256, profileSha256);
    }
    const evidenceSha256 = row.state === "observed" && isDigest(row.evidence_sha256) ? row.evidence_sha256 : null;
    if (row.state === "observed" && evidenceSha256 === null) {
      return preserve("STAGE4_INVALID_EVIDENCE", sourceSha256, profileSha256);
    }
    rows.push({
      phase: expectedPhase,
      state: row.state,
      evidenceSha256,
    });
  }

  let acceptedPhaseCount = 0;
  for (const row of rows) {
    if (row.state === "observed") acceptedPhaseCount += 1;
    else break;
  }

  if (rows.some((row) => row.state === "uncertain")) {
    return preserve("STAGE4_UNCERTAIN_EVIDENCE", sourceSha256, profileSha256, acceptedPhaseCount);
  }

  const evidenceDigests = new Set<string>([sourceSha256, profileSha256]);
  for (const row of rows) {
    if (row.evidenceSha256 === null) continue;
    if (evidenceDigests.has(row.evidenceSha256)) {
      return preserve("STAGE4_EVIDENCE_REPLAY", sourceSha256, profileSha256, acceptedPhaseCount);
    }
    evidenceDigests.add(row.evidenceSha256);
  }

  if (rows.slice(acceptedPhaseCount).some((row) => row.state === "observed")) {
    return preserve("STAGE4_EVIDENCE_OUT_OF_ORDER", sourceSha256, profileSha256, acceptedPhaseCount);
  }

  if (acceptedPhaseCount < STAGE4_TEARDOWN_PHASES.length) {
    return verdict(
      "awaiting-evidence",
      "STAGE4_AWAITING_EVIDENCE",
      sourceSha256,
      profileSha256,
      acceptedPhaseCount,
      STAGE4_TEARDOWN_PHASES[acceptedPhaseCount] ?? null,
    );
  }

  return verdict("zero-verified", "STAGE4_ZERO_VERIFIED", sourceSha256, profileSha256, acceptedPhaseCount, null);
}
