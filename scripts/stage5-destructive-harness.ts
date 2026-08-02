import { createHash } from "node:crypto";
import { TextDecoder, types as utilTypes } from "node:util";

export const STAGE5_DESTRUCTIVE_LIMITS = Object.freeze({
  maxFixtureBytes: 131_072,
  maxSourceBytes: 262_144,
  maxAggregateSourceBytes: 1_048_576,
  maxSnapshotNodes: 2048,
  maxDepth: 16,
  maxStringBytes: 2048,
  maxPropertyKeyBytes: 256,
  maxPropertiesPerObject: 64,
  maxAggregateCanonicalBytes: 262_144,
});

export const STAGE5_DESTRUCTIVE_FAULTS = Object.freeze([
  "process",
  "proxy",
  "openbao",
  "otlp",
  "wal",
  "disk",
  "sse",
  "jsonl",
  "git",
  "skill",
  "hostile-output",
] as const);

export type Stage5DestructiveFault = (typeof STAGE5_DESTRUCTIVE_FAULTS)[number];
type Profile = "insecure-container" | "linux-kvm";
type Applicability = "functional-insecure" | "authoritative-local-linux-kvm";
type PromptState = "none" | "settled" | "in-flight";
type Actor = "parent" | "fault";

export const STAGE5_DESTRUCTIVE_SOURCE_PATHS = Object.freeze([
  "DESIGN.md",
  "IMPLEMENTATION.md",
  "docs/operations/stage-3-internal-api.md",
  "docs/operations/stage-3-launch-lifecycle.md",
  "docs/operations/stage-3-model-auth.md",
  "docs/operations/stage-3-pi-session.md",
  "docs/operations/stage-3-ssh-connection.md",
  "docs/operations/stage-5-api-key-release-acceptance-matrix.md",
  "docs/security-evidence/stage5-api-key-release-matrix.draft.json",
  "schemas/launch-v1alpha1.json",
  "schemas/events-v1alpha1.json",
  "schemas/security-report-v1alpha1.json",
  "schemas/stage5-api-key-release-matrix-draft-v1.json",
  "scripts/stage5-destructive-harness.ts",
  "schemas/stage5-destructive-fixture-suite-v1.json",
  "schemas/stage5-destructive-report-v1.json",
  "test/fixtures/stage5-destructive/suite-v1.canonical-json",
] as const);

export const STAGE5_DESTRUCTIVE_ROUTES = deepFreeze({
  cloud: false,
  provider: false,
  cluster: false,
  deployment: false,
  external_model: false,
  scheduler: false,
  controller: false,
  retry: false,
} as const);

const PROFILE_SPECS = Object.freeze([
  Object.freeze({ profile: "insecure-container", applicability: "functional-insecure" }),
  Object.freeze({ profile: "linux-kvm", applicability: "authoritative-local-linux-kvm" }),
] as const);

const FAULT_SPECS: Readonly<
  Record<
    Stage5DestructiveFault,
    Readonly<{
      resources: readonly string[];
      prompt: PromptState;
      responses: readonly string[];
      reason: Stage5DestructiveCaseReason;
      admission: "revoked" | "bounded-continue";
      credentialEgress: "denied" | "not-exercised";
      ordinaryWork: "stopped" | "continued";
    }>
  >
> = deepFreeze({
  process: {
    resources: ["worker-process", "model-stream"],
    prompt: "in-flight",
    responses: ["revoke-admission", "mark-prompt-unknown", "forbid-unknown-prompt-replay"],
    reason: "PROCESS_UNKNOWN_REPORTED_NO_REPLAY",
    admission: "revoked",
    credentialEgress: "not-exercised",
    ordinaryWork: "stopped",
  },
  proxy: {
    resources: ["proxy-process", "proxy-connection"],
    prompt: "settled",
    responses: ["revoke-admission", "deny-credentialed-egress", "drain-connection"],
    reason: "PROXY_EGRESS_DENIED_AND_DRAINED",
    admission: "revoked",
    credentialEgress: "denied",
    ordinaryWork: "stopped",
  },
  openbao: {
    resources: ["openbao-fixture", "credential-lease"],
    prompt: "settled",
    responses: ["revoke-admission", "deny-credentialed-egress", "drain-connection"],
    reason: "OPENBAO_LOSS_OR_STALE_METADATA_DENIED",
    admission: "revoked",
    credentialEgress: "denied",
    ordinaryWork: "stopped",
  },
  otlp: {
    resources: ["otlp-fixture", "telemetry-queue"],
    prompt: "settled",
    responses: ["bound-telemetry-queue", "drop-telemetry-with-counter", "continue-ordinary-work"],
    reason: "OTLP_BOUNDED_DROP_ORDINARY_WORK_CONTINUED",
    admission: "bounded-continue",
    credentialEgress: "not-exercised",
    ordinaryWork: "continued",
  },
  wal: {
    resources: ["audit-wal-fixture"],
    prompt: "settled",
    responses: ["deny-credentialed-egress", "revoke-admission"],
    reason: "WAL_FULL_CREDENTIAL_USE_DENIED",
    admission: "revoked",
    credentialEgress: "denied",
    ordinaryWork: "stopped",
  },
  disk: {
    resources: ["workspace-disk-fixture", "temporary-write"],
    prompt: "settled",
    responses: ["reject-uncommitted-write", "preserve-prior-bytes", "report-explicit-failure"],
    reason: "DISK_WRITE_FAILED_WITHOUT_PARTIAL_PUBLICATION",
    admission: "bounded-continue",
    credentialEgress: "not-exercised",
    ordinaryWork: "continued",
  },
  sse: {
    resources: ["sse-client", "replay-buffer"],
    prompt: "settled",
    responses: ["reject-replay-gap", "require-paged-history", "forbid-unknown-prompt-replay"],
    reason: "SSE_GAP_REQUIRES_HISTORY_NOT_PROMPT_REPLAY",
    admission: "bounded-continue",
    credentialEgress: "not-exercised",
    ordinaryWork: "continued",
  },
  jsonl: {
    resources: ["session-jsonl-fixture", "durable-marker"],
    prompt: "in-flight",
    responses: ["revoke-admission", "reject-malformed-history", "mark-prompt-unknown", "forbid-unknown-prompt-replay"],
    reason: "JSONL_TAIL_REJECTED_UNKNOWN_NOT_REPLAYED",
    admission: "revoked",
    credentialEgress: "not-exercised",
    ordinaryWork: "stopped",
  },
  git: {
    resources: ["git-repository-fixture"],
    prompt: "settled",
    responses: ["warn-mapping-unavailable", "preserve-settled-turn", "forbid-unknown-prompt-replay"],
    reason: "GIT_CORRUPTION_WARNED_TURN_PRESERVED",
    admission: "bounded-continue",
    credentialEgress: "not-exercised",
    ordinaryWork: "continued",
  },
  skill: {
    resources: ["skill-artifact-fixture", "skill-staging-copy"],
    prompt: "none",
    responses: ["reject-artifact-before-prompt", "revoke-admission"],
    reason: "OVERSIZE_SKILL_REJECTED_BEFORE_PROMPT",
    admission: "revoked",
    credentialEgress: "not-exercised",
    ordinaryWork: "stopped",
  },
  "hostile-output": {
    resources: ["tool-process", "output-buffer"],
    prompt: "settled",
    responses: ["truncate-inert-output", "preserve-metadata-only", "forbid-unknown-prompt-replay"],
    reason: "HOSTILE_OUTPUT_BOUNDED_INERT_AND_OMITTED",
    admission: "bounded-continue",
    credentialEgress: "not-exercised",
    ordinaryWork: "continued",
  },
});

export type Stage5DestructiveCaseReason =
  | "PROCESS_UNKNOWN_REPORTED_NO_REPLAY"
  | "PROXY_EGRESS_DENIED_AND_DRAINED"
  | "OPENBAO_LOSS_OR_STALE_METADATA_DENIED"
  | "OTLP_BOUNDED_DROP_ORDINARY_WORK_CONTINUED"
  | "WAL_FULL_CREDENTIAL_USE_DENIED"
  | "DISK_WRITE_FAILED_WITHOUT_PARTIAL_PUBLICATION"
  | "SSE_GAP_REQUIRES_HISTORY_NOT_PROMPT_REPLAY"
  | "JSONL_TAIL_REJECTED_UNKNOWN_NOT_REPLAYED"
  | "GIT_CORRUPTION_WARNED_TURN_PRESERVED"
  | "OVERSIZE_SKILL_REJECTED_BEFORE_PROMPT"
  | "HOSTILE_OUTPUT_BOUNDED_INERT_AND_OMITTED";

export type Stage5DestructiveReasonCode =
  | "STAGE5_DESTRUCTIVE_SUITE_VALID"
  | "STAGE5_DESTRUCTIVE_INVALID_BYTES"
  | "STAGE5_DESTRUCTIVE_INVALID_SHAPE"
  | "STAGE5_DESTRUCTIVE_NONCANONICAL_BYTES"
  | "STAGE5_DESTRUCTIVE_BOUNDED_IO_VIOLATION"
  | "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID"
  | "STAGE5_DESTRUCTIVE_TRANSITION_INVALID"
  | "STAGE5_DESTRUCTIVE_SOURCE_BINDING_INVALID"
  | "STAGE5_DESTRUCTIVE_REPORT_INVALID"
  | "STAGE5_DESTRUCTIVE_REPORT_BINDING_INVALID";

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };

type FixtureAction = Readonly<{ seq: number; actor: Actor; action: string; resource: string | null }>;
type FixtureCase = Readonly<{
  id: string;
  fault: Stage5DestructiveFault;
  profile: Profile;
  applicability: Applicability;
  prompt_state: PromptState;
  owned_resources: readonly string[];
  actions: readonly FixtureAction[];
}>;
type FixtureSuite = Readonly<{
  version: "cogs.stage5-destructive-fixture-suite/v1";
  authority: "local-static-synthetic-fixtures-only";
  execution: "pure-state-machine-no-external-effects";
  routes: typeof STAGE5_DESTRUCTIVE_ROUTES;
  cases: readonly FixtureCase[];
}>;

export type Stage5DestructiveSuiteVerdict = Readonly<{
  valid: boolean;
  reason_code: Stage5DestructiveReasonCode;
  suite_sha256: string | null;
}>;

export type Stage5DestructiveCaseResult = Readonly<{
  id: string;
  fault: Stage5DestructiveFault;
  profile: Profile;
  applicability: Applicability;
  result: "pass";
  reason_code: Stage5DestructiveCaseReason;
  fixture_sha256: string;
  source_set_sha256: string;
  evidence_eligible: false;
  admission: "revoked" | "bounded-continue";
  credentialed_egress: "denied" | "not-exercised";
  ordinary_work: "stopped" | "continued";
  prompt_outcome: "none" | "settled" | "unknown-reported";
  unknown_prompt_replay_count: 0;
  cleanup: Readonly<{
    owner: "fixture-parent";
    acquired: number;
    attempted: number;
    completed: number;
    duplicate_attempts: 0;
    foreign_mutations: 0;
    orphaned_owned_resources: 0;
    exact_reverse_order: true;
  }>;
}>;

export type Stage5DestructiveReport = Readonly<{
  version: "cogs.stage5-destructive-report/v1";
  authority: "local-static-synthetic-destructive-harness";
  issue: 364;
  scope: "offline-static-only";
  qualified: false;
  campaign_authorized: false;
  cloud_execution_observed: false;
  provider_execution_observed: false;
  cluster_execution_observed: false;
  external_model_execution_observed: false;
  release_evidence: false;
  release_eligible: false;
  routes: typeof STAGE5_DESTRUCTIVE_ROUTES;
  source_binding: Readonly<{
    algorithm: "sha256-domain-separated-canonical-source-metadata-and-exact-file-bytes";
    source_set_sha256: string;
    sources: readonly Readonly<{ path: string; bytes: number; sha256: string }>[];
  }>;
  fixture_binding: Readonly<{
    exact_bytes_sha256: string;
    semantic_sha256: string;
    case_count: 22;
  }>;
  applicability: readonly [
    Readonly<{
      profile: "insecure-container";
      class: "functional-insecure";
      case_count: 11;
      environment_observed: false;
      authority_claimed: false;
    }>,
    Readonly<{
      profile: "linux-kvm";
      class: "authoritative-local-linux-kvm";
      case_count: 11;
      environment_observed: false;
      authority_claimed: false;
    }>,
  ];
  summary: Readonly<{
    result: "pass";
    passed: 22;
    failed: 0;
    unknown_prompt_outcomes: 4;
    unknown_prompt_replays: 0;
    cleanup_failures: 0;
    authoritative_runtime_cases: 0;
  }>;
  cases: readonly Stage5DestructiveCaseResult[];
  limitations: readonly [
    "synthetic-fixtures-only",
    "no-runtime-isolation-observed",
    "no-linux-kvm-environment-observed",
    "not-stage5-gate-or-release-evidence",
  ];
}>;

export type Stage5DestructiveSource = Readonly<{ path: string; bytes: Uint8Array }>;
export type Stage5DestructiveReportVerdict = Readonly<{
  valid: boolean;
  reason_code: Stage5DestructiveReasonCode;
}>;
export type Stage5DestructiveRunResult =
  | Readonly<{ ok: true; report: Stage5DestructiveReport }>
  | Readonly<{ ok: false; reason_code: Stage5DestructiveReasonCode }>;

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayByteLength = requiredGetter(typedArrayPrototype, "byteLength");
const typedArrayBuffer = requiredGetter(typedArrayPrototype, "buffer");
const arrayBufferByteLength = requiredGetter(ArrayBuffer.prototype, "byteLength");
const arrayBufferResizable = optionalGetter(ArrayBuffer.prototype, "resizable");
const sharedArrayBufferByteLength =
  typeof SharedArrayBuffer === "undefined" ? undefined : requiredGetter(SharedArrayBuffer.prototype, "byteLength");
const typedArraySet = Uint8Array.prototype.set;
const SUITE_DOMAIN = "cogs.stage5/destructive-fixture-suite-semantic/v1";
const CASE_DOMAIN = "cogs.stage5/destructive-fixture-case-semantic/v1";
const SOURCE_DOMAIN = "cogs.stage5/destructive-source-set/v1";

/** Builds the one reviewed deterministic fixture suite. It has no I/O or ambient inputs. */
export function buildStage5DestructiveFixtureSuite(): FixtureSuite {
  const cases: FixtureCase[] = [];
  for (const fault of STAGE5_DESTRUCTIVE_FAULTS) {
    for (const profile of PROFILE_SPECS) cases.push(buildCase(fault, profile.profile, profile.applicability));
  }
  return deepFreeze({
    version: "cogs.stage5-destructive-fixture-suite/v1",
    authority: "local-static-synthetic-fixtures-only",
    execution: "pure-state-machine-no-external-effects",
    routes: STAGE5_DESTRUCTIVE_ROUTES,
    cases,
  });
}

type InspectedFixture = Readonly<{
  bytes: Uint8Array | null;
  root: JsonRecord | null;
  verdict: Stage5DestructiveSuiteVerdict;
}>;

/** Validates exact canonical fixture bytes and all state-machine transitions. */
export function validateStage5DestructiveFixtureBytes(input: Uint8Array): Stage5DestructiveSuiteVerdict {
  return inspectFixtureBytes(input).verdict;
}

function inspectFixtureBytes(input: Uint8Array): InspectedFixture {
  const captured = capturePrivateBytes(input, STAGE5_DESTRUCTIVE_LIMITS.maxFixtureBytes);
  if (captured.bytes === null) {
    return {
      bytes: null,
      root: null,
      verdict: suiteVerdict(
        false,
        captured.bounded ? "STAGE5_DESTRUCTIVE_BOUNDED_IO_VIOLATION" : "STAGE5_DESTRUCTIVE_INVALID_BYTES",
        null,
      ),
    };
  }
  const bytes = captured.bytes;
  if (hasUtf8Bom(bytes)) {
    return { bytes, root: null, verdict: suiteVerdict(false, "STAGE5_DESTRUCTIVE_INVALID_BYTES", null) };
  }
  try {
    const parsed = JSON.parse(decoder.decode(bytes)) as unknown;
    const snapshot = snapshotJson(parsed);
    if (snapshot.value === null) {
      return {
        bytes,
        root: null,
        verdict: suiteVerdict(
          false,
          snapshot.bounded ? "STAGE5_DESTRUCTIVE_BOUNDED_IO_VIOLATION" : "STAGE5_DESTRUCTIVE_INVALID_SHAPE",
          null,
        ),
      };
    }
    const digest = semanticDigest(SUITE_DOMAIN, snapshot.value);
    const canonical = encodeCanonical(snapshot.value);
    if (!bytesEqual(bytes, canonical)) {
      return {
        bytes,
        root: snapshot.value,
        verdict: suiteVerdict(false, "STAGE5_DESTRUCTIVE_NONCANONICAL_BYTES", digest),
      };
    }
    const reason = validateSuite(snapshot.value);
    return {
      bytes,
      root: snapshot.value,
      verdict:
        reason === null
          ? suiteVerdict(true, "STAGE5_DESTRUCTIVE_SUITE_VALID", digest)
          : suiteVerdict(false, reason, digest),
    };
  } catch {
    return { bytes, root: null, verdict: suiteVerdict(false, "STAGE5_DESTRUCTIVE_INVALID_BYTES", null) };
  }
}

/** Canonicalizes only a bounded plain JSON object graph. */
export function canonicalStage5DestructiveBytes(input: unknown): Uint8Array {
  const snapshot = snapshotJson(input);
  if (snapshot.value === null) {
    throw new TypeError(snapshot.bounded ? "input exceeds a bound" : "input is not a plain JSON object");
  }
  const bytes = encodeCanonical(snapshot.value);
  if (intrinsicByteLength(bytes) > STAGE5_DESTRUCTIVE_LIMITS.maxFixtureBytes) {
    throw new TypeError("fixture exceeds byte bound");
  }
  return bytes;
}

/**
 * Runs and aggregates synthetic fixtures over caller-supplied bytes. It performs
 * no file/environment/process/network/provider/model operation and has no retry path.
 */
export function runStage5DestructiveHarness(
  fixtureBytes: Uint8Array,
  sources: readonly Stage5DestructiveSource[],
): Stage5DestructiveRunResult {
  const inspected = inspectFixtureBytes(fixtureBytes);
  const verdict = inspected.verdict;
  if (!verdict.valid || verdict.suite_sha256 === null || inspected.bytes === null || inspected.root === null) {
    return Object.freeze({ ok: false, reason_code: verdict.reason_code });
  }
  const boundSources = bindSources(sources);
  if (boundSources === null || !bytesEqual(inspected.bytes, boundSources.fixtureBytes)) {
    return Object.freeze({ ok: false, reason_code: "STAGE5_DESTRUCTIVE_SOURCE_BINDING_INVALID" });
  }
  const sourceBinding = boundSources.binding;
  const suite = inspected.root as unknown as FixtureSuite;
  const cases = suite.cases.map((fixture) => caseResult(fixture, sourceBinding.source_set_sha256));
  const report: Stage5DestructiveReport = {
    version: "cogs.stage5-destructive-report/v1",
    authority: "local-static-synthetic-destructive-harness",
    issue: 364,
    scope: "offline-static-only",
    qualified: false,
    campaign_authorized: false,
    cloud_execution_observed: false,
    provider_execution_observed: false,
    cluster_execution_observed: false,
    external_model_execution_observed: false,
    release_evidence: false,
    release_eligible: false,
    routes: STAGE5_DESTRUCTIVE_ROUTES,
    source_binding: sourceBinding,
    fixture_binding: {
      exact_bytes_sha256: sha256(inspected.bytes),
      semantic_sha256: verdict.suite_sha256,
      case_count: 22,
    },
    applicability: [
      {
        profile: "insecure-container",
        class: "functional-insecure",
        case_count: 11,
        environment_observed: false,
        authority_claimed: false,
      },
      {
        profile: "linux-kvm",
        class: "authoritative-local-linux-kvm",
        case_count: 11,
        environment_observed: false,
        authority_claimed: false,
      },
    ],
    summary: {
      result: "pass",
      passed: 22,
      failed: 0,
      unknown_prompt_outcomes: 4,
      unknown_prompt_replays: 0,
      cleanup_failures: 0,
      authoritative_runtime_cases: 0,
    },
    cases,
    limitations: [
      "synthetic-fixtures-only",
      "no-runtime-isolation-observed",
      "no-linux-kvm-environment-observed",
      "not-stage5-gate-or-release-evidence",
    ],
  };
  return Object.freeze({ ok: true, report: deepFreeze(report) });
}

/**
 * Re-aggregates from exact inputs and accepts only the byte-identical canonical
 * metadata report. This is the sole report-ingestion path.
 */
export function validateStage5DestructiveReportBytes(
  reportBytes: Uint8Array,
  fixtureBytes: Uint8Array,
  sources: readonly Stage5DestructiveSource[],
): Stage5DestructiveReportVerdict {
  const captured = capturePrivateBytes(reportBytes, STAGE5_DESTRUCTIVE_LIMITS.maxFixtureBytes);
  if (captured.bytes === null || hasUtf8Bom(captured.bytes)) {
    return reportVerdict(false, "STAGE5_DESTRUCTIVE_REPORT_INVALID");
  }
  const generated = runStage5DestructiveHarness(fixtureBytes, sources);
  if (!generated.ok) return reportVerdict(false, generated.reason_code);
  try {
    const parsed = JSON.parse(decoder.decode(captured.bytes)) as unknown;
    const snapshot = snapshotJson(parsed);
    if (snapshot.value === null || !bytesEqual(captured.bytes, encodeCanonical(snapshot.value))) {
      return reportVerdict(false, "STAGE5_DESTRUCTIVE_REPORT_INVALID");
    }
    const expected = canonicalStage5DestructiveBytes(generated.report);
    return bytesEqual(captured.bytes, expected)
      ? reportVerdict(true, "STAGE5_DESTRUCTIVE_SUITE_VALID")
      : reportVerdict(false, "STAGE5_DESTRUCTIVE_REPORT_BINDING_INVALID");
  } catch {
    return reportVerdict(false, "STAGE5_DESTRUCTIVE_REPORT_INVALID");
  }
}

function buildCase(fault: Stage5DestructiveFault, profile: Profile, applicability: Applicability): FixtureCase {
  const spec = FAULT_SPECS[fault];
  const actions: FixtureAction[] = [];
  const push = (actor: Actor, action: string, resource: string | null = null): void => {
    actions.push({ seq: actions.length, actor, action, resource });
  };
  for (const resource of spec.resources) push("parent", "acquire-owned-resource", resource);
  push("parent", "admit-operation");
  push("fault", `inject-${fault}`);
  for (const response of spec.responses) push("parent", response);
  for (const resource of [...spec.resources].reverse()) push("parent", "cleanup-owned-resource", resource);
  push("parent", "close-fixture");
  return deepFreeze({
    id: `${fault}.${profile === "insecure-container" ? "functional-insecure" : "authoritative-local-linux-kvm"}`,
    fault,
    profile,
    applicability,
    prompt_state: spec.prompt,
    owned_resources: [...spec.resources],
    actions,
  });
}

function validateSuite(root: JsonRecord): Stage5DestructiveReasonCode | null {
  if (!exactKeys(root, ["version", "authority", "execution", "routes", "cases"])) {
    return "STAGE5_DESTRUCTIVE_INVALID_SHAPE";
  }
  if (
    root.version !== "cogs.stage5-destructive-fixture-suite/v1" ||
    root.authority !== "local-static-synthetic-fixtures-only" ||
    root.execution !== "pure-state-machine-no-external-effects" ||
    !same(root.routes, STAGE5_DESTRUCTIVE_ROUTES as unknown as JsonValue) ||
    !Array.isArray(root.cases) ||
    root.cases.length !== 22
  ) {
    return "STAGE5_DESTRUCTIVE_INVALID_SHAPE";
  }
  const expected = buildStage5DestructiveFixtureSuite();
  const seen = new Set<string>();
  for (let index = 0; index < root.cases.length; index += 1) {
    const candidate = root.cases[index];
    const expectedCase = expected.cases[index];
    if (candidate === undefined || !isRecord(candidate) || expectedCase === undefined) {
      return "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID";
    }
    const id = candidate.id;
    if (typeof id !== "string" || seen.has(id)) return "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID";
    seen.add(id);
    if (!caseShape(candidate, expectedCase)) return "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID";
    if (!same(candidate.actions, expectedCase.actions as unknown as JsonValue)) {
      return "STAGE5_DESTRUCTIVE_TRANSITION_INVALID";
    }
  }
  return null;
}

function caseShape(candidate: JsonRecord, expected: FixtureCase): boolean {
  if (
    !exactKeys(candidate, ["id", "fault", "profile", "applicability", "prompt_state", "owned_resources", "actions"])
  ) {
    return false;
  }
  return (
    candidate.id === expected.id &&
    candidate.fault === expected.fault &&
    candidate.profile === expected.profile &&
    candidate.applicability === expected.applicability &&
    candidate.prompt_state === expected.prompt_state &&
    same(candidate.owned_resources, expected.owned_resources as unknown as JsonValue) &&
    Array.isArray(candidate.actions)
  );
}

function caseResult(fixture: FixtureCase, sourceSetSha256: string): Stage5DestructiveCaseResult {
  const spec = FAULT_SPECS[fixture.fault];
  const acquired = fixture.owned_resources.length;
  return deepFreeze({
    id: fixture.id,
    fault: fixture.fault,
    profile: fixture.profile,
    applicability: fixture.applicability,
    result: "pass",
    reason_code: spec.reason,
    fixture_sha256: semanticDigest(CASE_DOMAIN, fixture as unknown as JsonValue),
    source_set_sha256: sourceSetSha256,
    evidence_eligible: false,
    admission: spec.admission,
    credentialed_egress: spec.credentialEgress,
    ordinary_work: spec.ordinaryWork,
    prompt_outcome:
      fixture.prompt_state === "in-flight"
        ? "unknown-reported"
        : fixture.prompt_state === "settled"
          ? "settled"
          : "none",
    unknown_prompt_replay_count: 0,
    cleanup: {
      owner: "fixture-parent",
      acquired,
      attempted: acquired,
      completed: acquired,
      duplicate_attempts: 0,
      foreign_mutations: 0,
      orphaned_owned_resources: 0,
      exact_reverse_order: true,
    },
  });
}

type BoundSources = Readonly<{
  binding: Stage5DestructiveReport["source_binding"];
  fixtureBytes: Uint8Array;
}>;

function bindSources(sources: readonly Stage5DestructiveSource[]): BoundSources | null {
  if (utilTypes.isProxy(sources) || !Array.isArray(sources) || Object.getPrototypeOf(sources) !== Array.prototype) {
    return null;
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(sources, "length");
  const length = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : undefined;
  if (length !== STAGE5_DESTRUCTIVE_SOURCE_PATHS.length) return null;
  const arrayKeys = boundedEnumerableDataKeys(sources, STAGE5_DESTRUCTIVE_SOURCE_PATHS.length);
  if (
    arrayKeys === null ||
    arrayKeys.length !== STAGE5_DESTRUCTIVE_SOURCE_PATHS.length ||
    arrayKeys.some((key, index) => key !== String(index))
  ) {
    return null;
  }

  const records: Array<{ path: string; bytes: number; sha256: string }> = [];
  let aggregate = 0;
  let fixtureSourceBytes: Uint8Array | undefined;
  for (let index = 0; index < STAGE5_DESTRUCTIVE_SOURCE_PATHS.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(sources, String(index));
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) return null;
    const source = descriptor.value as unknown;
    if (utilTypes.isProxy(source) || source === null || typeof source !== "object") return null;
    const sourcePrototype = Object.getPrototypeOf(source);
    if (sourcePrototype !== Object.prototype && sourcePrototype !== null) return null;
    const sourceKeys = boundedEnumerableDataKeys(source, 2);
    if (
      sourceKeys === null ||
      sourceKeys.length !== 2 ||
      !sourceKeys.includes("path") ||
      !sourceKeys.includes("bytes")
    ) {
      return null;
    }
    const pathDescriptor = Object.getOwnPropertyDescriptor(source, "path");
    const bytesDescriptor = Object.getOwnPropertyDescriptor(source, "bytes");
    if (
      pathDescriptor === undefined ||
      !("value" in pathDescriptor) ||
      pathDescriptor.enumerable !== true ||
      bytesDescriptor === undefined ||
      !("value" in bytesDescriptor) ||
      bytesDescriptor.enumerable !== true
    ) {
      return null;
    }
    const expectedPath = STAGE5_DESTRUCTIVE_SOURCE_PATHS[index];
    if (pathDescriptor.value !== expectedPath || expectedPath === undefined) return null;
    const captured = capturePrivateBytes(bytesDescriptor.value, STAGE5_DESTRUCTIVE_LIMITS.maxSourceBytes);
    if (captured.bytes === null) return null;
    const sourceBytes = captured.bytes;
    const size = intrinsicByteLength(sourceBytes);
    aggregate += size;
    if (aggregate > STAGE5_DESTRUCTIVE_LIMITS.maxAggregateSourceBytes) return null;
    records.push({ path: expectedPath, bytes: size, sha256: sha256(sourceBytes) });
    if (expectedPath === "test/fixtures/stage5-destructive/suite-v1.canonical-json") {
      fixtureSourceBytes = sourceBytes;
    }
  }
  if (fixtureSourceBytes === undefined) return null;
  const sourceSetSha256 = createHash("sha256")
    .update(SOURCE_DOMAIN, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(records as unknown as JsonValue), "utf8")
    .digest("hex");
  return {
    binding: deepFreeze({
      algorithm: "sha256-domain-separated-canonical-source-metadata-and-exact-file-bytes",
      source_set_sha256: sourceSetSha256,
      sources: records,
    }),
    fixtureBytes: fixtureSourceBytes,
  };
}

function snapshotJson(input: unknown): { value: JsonRecord | null; bounded: boolean } {
  let nodes = 0;
  let aggregateBytes = 1;
  let bounded = false;
  const consume = (bytes: number): void => {
    aggregateBytes += bytes;
    if (aggregateBytes > STAGE5_DESTRUCTIVE_LIMITS.maxAggregateCanonicalBytes) {
      bounded = true;
      throw new TypeError("aggregate bound");
    }
  };
  const visit = (candidate: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > STAGE5_DESTRUCTIVE_LIMITS.maxSnapshotNodes || depth > STAGE5_DESTRUCTIVE_LIMITS.maxDepth) {
      bounded = true;
      throw new TypeError("graph bound");
    }
    if (
      ((typeof candidate === "object" && candidate !== null) || typeof candidate === "function") &&
      utilTypes.isProxy(candidate)
    ) {
      throw new TypeError("proxy");
    }
    if (candidate === null) {
      consume(4);
      return candidate;
    }
    if (typeof candidate === "boolean") {
      consume(candidate ? 4 : 5);
      return candidate;
    }
    if (typeof candidate === "string") {
      if (Buffer.byteLength(candidate, "utf8") > STAGE5_DESTRUCTIVE_LIMITS.maxStringBytes) {
        bounded = true;
        throw new TypeError("string bound");
      }
      consume(Buffer.byteLength(JSON.stringify(candidate), "utf8"));
      return candidate;
    }
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) throw new TypeError("number");
      consume(Buffer.byteLength(JSON.stringify(candidate), "utf8"));
      return candidate;
    }
    if (typeof candidate !== "object") throw new TypeError("non-json");
    const prototype = Object.getPrototypeOf(candidate);
    if (Array.isArray(candidate)) {
      if (prototype !== Array.prototype) throw new TypeError("array prototype");
      const lengthDescriptor = Object.getOwnPropertyDescriptor(candidate, "length");
      const length = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : undefined;
      if (!Number.isSafeInteger(length) || (length as number) < 0) throw new TypeError("array length");
      if ((length as number) > STAGE5_DESTRUCTIVE_LIMITS.maxSnapshotNodes) {
        bounded = true;
        throw new TypeError("array bound");
      }
      const scanned = scanEnumerableDataKeys(candidate, STAGE5_DESTRUCTIVE_LIMITS.maxPropertiesPerObject);
      if (scanned === null) throw new TypeError("array accessor");
      if (scanned.overflow) {
        bounded = true;
        throw new TypeError("property bound");
      }
      const keys = scanned.keys;
      if (keys.length !== length || keys.some((key, index) => key !== String(index))) {
        throw new TypeError("sparse or extended array");
      }
      consume(2 + Math.max(0, (length as number) - 1));
      return Array.from({ length: length as number }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(candidate, String(index));
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
          throw new TypeError("array accessor");
        }
        return visit(descriptor.value, depth + 1);
      });
    }
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("object prototype");
    const scanned = scanEnumerableDataKeys(candidate, STAGE5_DESTRUCTIVE_LIMITS.maxPropertiesPerObject);
    if (scanned === null) throw new TypeError("object accessor");
    if (scanned.overflow) {
      bounded = true;
      throw new TypeError("property bound");
    }
    const keys = scanned.keys;
    consume(2 + Math.max(0, keys.length - 1));
    const output: JsonRecord = Object.create(null) as JsonRecord;
    for (const key of keys) {
      if (Buffer.byteLength(key, "utf8") > STAGE5_DESTRUCTIVE_LIMITS.maxPropertyKeyBytes) {
        bounded = true;
        throw new TypeError("key bound");
      }
      const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
        throw new TypeError("object accessor");
      }
      consume(Buffer.byteLength(JSON.stringify(key), "utf8") + 1);
      output[key] = visit(descriptor.value, depth + 1);
    }
    return output;
  };
  try {
    const value = visit(input, 0);
    return { value: isRecord(value) ? value : null, bounded: false };
  } catch {
    return { value: null, bounded };
  }
}

function exactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function boundedEnumerableDataKeys(value: object, limit: number): string[] | null {
  const scanned = scanEnumerableDataKeys(value, limit);
  return scanned === null || scanned.overflow ? null : scanned.keys;
}

function scanEnumerableDataKeys(value: object, limit: number): Readonly<{ keys: string[]; overflow: boolean }> | null {
  const keys: string[] = [];
  try {
    for (const key in value) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) return null;
      keys.push(key);
      if (keys.length > limit) return { keys, overflow: true };
    }
    return { keys, overflow: false };
  } catch {
    return null;
  }
}

function isRecord(value: JsonValue): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function same(left: JsonValue | undefined, right: JsonValue): boolean {
  return left !== undefined && canonicalJson(left) === canonicalJson(right);
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

type IntrinsicGetter = (this: unknown) => unknown;
type ByteCapture = Readonly<{ bytes: Uint8Array | null; bounded: boolean }>;

function requiredGetter(prototype: object, key: string): IntrinsicGetter {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (getter === undefined) throw new TypeError(`missing intrinsic getter: ${key}`);
  return getter;
}

function optionalGetter(prototype: object, key: string): IntrinsicGetter | undefined {
  return Object.getOwnPropertyDescriptor(prototype, key)?.get;
}

function capturePrivateBytes(input: unknown, maximum: number): ByteCapture {
  if (
    input === null ||
    typeof input !== "object" ||
    utilTypes.isProxy(input) ||
    Object.getPrototypeOf(input) !== Uint8Array.prototype
  ) {
    return { bytes: null, bounded: false };
  }
  try {
    const length = typedArrayByteLength.call(input);
    const buffer = typedArrayBuffer.call(input);
    if (!Number.isSafeInteger(length) || (length as number) < 1) return { bytes: null, bounded: true };
    if ((length as number) > maximum) return { bytes: null, bounded: true };
    if (buffer === null || typeof buffer !== "object") return { bytes: null, bounded: false };

    if (sharedArrayBufferByteLength !== undefined) {
      try {
        sharedArrayBufferByteLength.call(buffer);
        return { bytes: null, bounded: false };
      } catch {
        // A private ArrayBuffer is expected to reject the SharedArrayBuffer intrinsic.
      }
    }
    const backingLength = arrayBufferByteLength.call(buffer);
    if (!Number.isSafeInteger(backingLength) || (backingLength as number) < (length as number)) {
      return { bytes: null, bounded: false };
    }
    if (arrayBufferResizable !== undefined && arrayBufferResizable.call(buffer) === true) {
      return { bytes: null, bounded: false };
    }

    const copy = new Uint8Array(length as number);
    typedArraySet.call(copy, input as Uint8Array);
    if (intrinsicByteLength(copy) !== length) return { bytes: null, bounded: false };
    return { bytes: copy, bounded: false };
  } catch {
    return { bytes: null, bounded: false };
  }
}

function intrinsicByteLength(bytes: Uint8Array): number {
  const length = typedArrayByteLength.call(bytes);
  if (!Number.isSafeInteger(length) || (length as number) < 0) throw new TypeError("invalid byte length");
  return length as number;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  const leftLength = intrinsicByteLength(left);
  if (leftLength !== intrinsicByteLength(right)) return false;
  for (let index = 0; index < leftLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function hasUtf8Bom(bytes: Uint8Array): boolean {
  return intrinsicByteLength(bytes) >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
}

function encodeCanonical(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

function semanticDigest(domain: string, value: JsonValue): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function suiteVerdict(
  valid: boolean,
  reasonCode: Stage5DestructiveReasonCode,
  suiteSha256: string | null,
): Stage5DestructiveSuiteVerdict {
  return Object.freeze({ valid, reason_code: reasonCode, suite_sha256: suiteSha256 });
}

function reportVerdict(valid: boolean, reasonCode: Stage5DestructiveReasonCode): Stage5DestructiveReportVerdict {
  return Object.freeze({ valid, reason_code: reasonCode });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
