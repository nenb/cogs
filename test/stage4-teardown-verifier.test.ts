import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import * as verifierModule from "../scripts/stage4-teardown-verifier.ts";
import {
  STAGE4_TEARDOWN_PHASES,
  STAGE4_TEARDOWN_PRODUCER_CLASSES,
  STAGE4_TEARDOWN_REASON_CODES,
  type Stage4TeardownPhaseRow,
  type Stage4TeardownPlan,
  verifyStage4Teardown,
} from "../scripts/stage4-teardown-verifier.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const sha = (digit: string): string => digit.repeat(64);

function plan(observedPhases = 0): Stage4TeardownPlan {
  return {
    version: "cogs.stage4-teardown-plan/v1",
    source_sha256: sha("0"),
    profile_sha256: sha("1"),
    phases: STAGE4_TEARDOWN_PHASES.map((phase, index): Stage4TeardownPhaseRow => {
      const base = {
        phase,
        producer_class: STAGE4_TEARDOWN_PRODUCER_CLASSES[index] ?? "control-observer",
      };
      return index < observedPhases
        ? { ...base, state: "observed", evidence_sha256: sha((index + 2).toString(16)) }
        : { ...base, state: "pending" };
    }),
  };
}

function mutablePlan(observedPhases = 0): Record<string, unknown> & { phases: Array<Record<string, unknown>> } {
  return structuredClone(plan(observedPhases)) as unknown as Record<string, unknown> & {
    phases: Array<Record<string, unknown>>;
  };
}

function assertPreserved(input: unknown, reasonCode: string): void {
  const verdict = verifyStage4Teardown(input);
  assert.equal(verdict.status, "preserve-uncertain");
  assert.equal(verdict.reason_code, reasonCode);
  assert.equal(verdict.next_phase, null);
}

test("the canonical phase graph and producer classes are exact and bounded", () => {
  assert.deepEqual(STAGE4_TEARDOWN_PHASES, [
    "freeze-reconcilers",
    "close-admission",
    "revoke-credentials",
    "revoke-readiness",
    "remove-session-workloads",
    "verify-kubernetes-zero",
    "remove-cluster-infrastructure",
    "verify-independent-cloud-zero",
  ]);
  assert.deepEqual(STAGE4_TEARDOWN_PRODUCER_CLASSES, [
    "control-observer",
    "admission-observer",
    "credential-observer",
    "readiness-observer",
    "workload-mutator",
    "kubernetes-zero-observer",
    "infrastructure-mutator",
    "independent-cloud-zero-observer",
  ]);
  assert.equal(new Set(STAGE4_TEARDOWN_PHASES).size, 8);
  assert.equal(new Set(STAGE4_TEARDOWN_PRODUCER_CLASSES).size, 8);
  assert.equal(Object.isFrozen(STAGE4_TEARDOWN_PHASES), true);
  assert.equal(Object.isFrozen(STAGE4_TEARDOWN_PRODUCER_CLASSES), true);
});

test("every legal prefix has one deterministic next evidence phase", () => {
  for (let observed = 0; observed < STAGE4_TEARDOWN_PHASES.length; observed += 1) {
    const input = plan(observed);
    const before = structuredClone(input);
    const first = verifyStage4Teardown(input);
    const second = verifyStage4Teardown(input);
    assert.deepEqual(first, second);
    assert.deepEqual(input, before, "evaluation must not mutate input");
    assert.deepEqual(first, {
      version: "cogs.stage4-teardown-verdict/v1",
      source_sha256: sha("0"),
      profile_sha256: sha("1"),
      status: "awaiting-evidence",
      next_phase: STAGE4_TEARDOWN_PHASES[observed],
      accepted_phase_count: observed,
      reason_code: "STAGE4_AWAITING_EVIDENCE",
    });
    assert.equal(Object.isFrozen(first), true);
  }
});

test("zero is verified only for the complete ordered prefix", () => {
  assert.deepEqual(verifyStage4Teardown(plan(8)), {
    version: "cogs.stage4-teardown-verdict/v1",
    source_sha256: sha("0"),
    profile_sha256: sha("1"),
    status: "zero-verified",
    next_phase: null,
    accepted_phase_count: 8,
    reason_code: "STAGE4_ZERO_VERIFIED",
  });
});

test("strict shape rejects unknown fields, missing rows, malformed digests, and evidence on non-observed rows", () => {
  const cases: Array<[unknown, string]> = [];

  const unknown = mutablePlan();
  unknown.extra = true;
  cases.push([unknown, "STAGE4_INVALID_SHAPE"]);

  const short = mutablePlan();
  short.phases.pop();
  cases.push([short, "STAGE4_INVALID_PHASE_ORDER"]);

  const long = mutablePlan();
  long.phases.push({ ...long.phases[0] });
  cases.push([long, "STAGE4_INVALID_PHASE_ORDER"]);

  const badSource = mutablePlan();
  badSource.source_sha256 = sha("A");
  cases.push([badSource, "STAGE4_INVALID_SHAPE"]);

  const wrongVersion = mutablePlan();
  wrongVersion.version = "cogs.stage4-teardown-plan/v2";
  cases.push([wrongVersion, "STAGE4_INVALID_VERSION"]);

  const pendingEvidence = mutablePlan();
  const pendingFirst = pendingEvidence.phases[0];
  assert.ok(pendingFirst);
  pendingFirst.evidence_sha256 = sha("2");
  cases.push([pendingEvidence, "STAGE4_INVALID_EVIDENCE"]);

  const observedWithoutEvidence = mutablePlan(1);
  const observedFirst = observedWithoutEvidence.phases[0];
  assert.ok(observedFirst);
  delete observedFirst.evidence_sha256;
  cases.push([observedWithoutEvidence, "STAGE4_INVALID_EVIDENCE"]);

  const rowUnknown = mutablePlan();
  const first = rowUnknown.phases[0];
  assert.ok(first);
  first.note = "not canonical metadata";
  cases.push([rowUnknown, "STAGE4_INVALID_EVIDENCE"]);

  cases.push([null, "STAGE4_INVALID_SHAPE"], [[], "STAGE4_INVALID_SHAPE"]);

  const accessor = mutablePlan();
  Object.defineProperty(accessor, "source_sha256", { enumerable: true, get: () => sha("0") });
  cases.push([accessor, "STAGE4_INVALID_SHAPE"]);

  for (const [input, reason] of cases) assertPreserved(input, reason);
});

test("phase order and observation order fail closed", () => {
  const swapped = mutablePlan();
  const first = swapped.phases[0];
  const second = swapped.phases[1];
  assert.ok(first);
  assert.ok(second);
  [swapped.phases[0], swapped.phases[1]] = [second, first];
  assertPreserved(swapped, "STAGE4_INVALID_PHASE_ORDER");

  const gap = mutablePlan(1);
  const third = gap.phases[2];
  assert.ok(third);
  third.state = "observed";
  third.evidence_sha256 = sha("4");
  assertPreserved(gap, "STAGE4_EVIDENCE_OUT_OF_ORDER");

  const duplicatePhase = mutablePlan();
  const duplicateSecond = duplicatePhase.phases[1];
  assert.ok(duplicateSecond);
  duplicateSecond.phase = "freeze-reconcilers";
  assertPreserved(duplicatePhase, "STAGE4_INVALID_PHASE_ORDER");
});

test("evidence replay cannot reach zero", () => {
  for (const replacement of [sha("0"), sha("1"), sha("2")]) {
    const replay = mutablePlan(8);
    const final = replay.phases[7];
    assert.ok(final);
    final.evidence_sha256 = replacement;
    assertPreserved(replay, "STAGE4_EVIDENCE_REPLAY");
  }
});

test("uncertainty is sticky even when every later row is observed", () => {
  for (let uncertainIndex = 0; uncertainIndex < 8; uncertainIndex += 1) {
    const uncertain = mutablePlan(8);
    const row = uncertain.phases[uncertainIndex];
    assert.ok(row);
    row.state = "uncertain";
    delete row.evidence_sha256;
    const verdict = verifyStage4Teardown(uncertain);
    assert.equal(verdict.status, "preserve-uncertain");
    assert.equal(verdict.reason_code, "STAGE4_UNCERTAIN_EVIDENCE");
    assert.equal(verdict.next_phase, null);
    assert.equal(verdict.accepted_phase_count, uncertainIndex);
  }
});

test("producer classes are fixed and the final observer is independent of both mutator classes", () => {
  const wrongEarlier = mutablePlan(8);
  const first = wrongEarlier.phases[0];
  assert.ok(first);
  first.producer_class = "admission-observer";
  assertPreserved(wrongEarlier, "STAGE4_INVALID_PRODUCER_CLASS");

  for (const mutator of ["workload-mutator", "infrastructure-mutator"]) {
    const overlap = mutablePlan(8);
    const final = overlap.phases[7];
    assert.ok(final);
    final.producer_class = mutator;
    const verdict = verifyStage4Teardown(overlap);
    assert.equal(verdict.accepted_phase_count, 7);
    assertPreserved(overlap, "STAGE4_FINAL_OBSERVER_NOT_INDEPENDENT");
  }

  const unknown = mutablePlan(8);
  const final = unknown.phases[7];
  assert.ok(final);
  final.producer_class = "provider";
  assertPreserved(unknown, "STAGE4_INVALID_PRODUCER_CLASS");
});

test("only fixed reason codes can be emitted", () => {
  assert.deepEqual(STAGE4_TEARDOWN_REASON_CODES, [
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
  ]);
  const emitted = [verifyStage4Teardown(plan()), verifyStage4Teardown(plan(8)), verifyStage4Teardown(null)];
  for (const verdict of emitted) assert.ok(STAGE4_TEARDOWN_REASON_CODES.includes(verdict.reason_code));
});

test("plan and verdict schemas enforce shape and status coupling", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  const planSchema = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../schemas/stage4-teardown-plan-v1.json"), "utf8"),
  );
  const verdictSchema = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../schemas/stage4-teardown-verdict-v1.json"), "utf8"),
  );
  const validatePlan = ajv.compile(planSchema);
  const validateVerdict = ajv.compile(verdictSchema);

  for (let observed = 0; observed <= 8; observed += 1) {
    const input = plan(observed);
    const verdict = verifyStage4Teardown(input);
    assert.equal(validatePlan(input), true, ajv.errorsText(validatePlan.errors));
    assert.equal(validateVerdict(verdict), true, ajv.errorsText(validateVerdict.errors));
  }

  const unknownPlan = mutablePlan();
  unknownPlan.authority = "external";
  assert.equal(validatePlan(unknownPlan), false);

  const invalidStateEvidence = mutablePlan();
  const first = invalidStateEvidence.phases[0];
  assert.ok(first);
  first.evidence_sha256 = sha("2");
  assert.equal(validatePlan(invalidStateEvidence), false);

  const hostileVerdict = { ...verifyStage4Teardown(plan()), status: "zero-verified" };
  assert.equal(validateVerdict(hostileVerdict), false);
  assert.equal(validateVerdict({ ...verifyStage4Teardown(plan()), target: "anything" }), false);
});

test("production module has no authority surface or external effects", () => {
  const source = readFileSync(resolve(import.meta.dirname, "../scripts/stage4-teardown-verifier.ts"), "utf8");
  assert.deepEqual(Object.keys(verifierModule).sort(), [
    "STAGE4_TEARDOWN_PHASES",
    "STAGE4_TEARDOWN_PRODUCER_CLASSES",
    "STAGE4_TEARDOWN_REASON_CODES",
    "verifyStage4Teardown",
  ]);
  assert.doesNotMatch(
    source,
    /(?:from\s*|import\s*\()["'](?:node:(?:child_process|fs|http|https|http2|net|tls|dns|dgram)|@aws|@kubernetes|aws-sdk|kubernetes|opentofu)/u,
  );
  assert.doesNotMatch(source, /\b(?:fetch|eval)\s*\(/u);
  assert.doesNotMatch(source, /\bprocess(?:\.|\[)/u);
  assert.doesNotMatch(source, /\b(?:command|argv|endpoint|resource_id|resource_name|target)\s*:/u);
  assert.doesNotMatch(source, /\b(?:writeFile|appendFile|spawn|exec|fork)\b/u);
  assert.doesNotMatch(source, /\b(?:AWS_ACCESS_KEY_ID|KUBECONFIG|TF_VAR_)\b/u);
});
