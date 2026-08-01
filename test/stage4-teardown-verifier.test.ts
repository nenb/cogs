import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import * as verifierModule from "../scripts/stage4-teardown-verifier.ts";
import {
  STAGE4_TEARDOWN_PHASES,
  STAGE4_TEARDOWN_PRODUCER_CLASSES,
  STAGE4_TEARDOWN_REASON_CODES,
  type Stage4TeardownPhaseRow,
  type Stage4TeardownPlan,
  type Stage4TeardownVerdict,
  verifyStage4Teardown,
} from "../scripts/stage4-teardown-verifier.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const sha = (digit: string): string => digit.repeat(64);
const DIGEST = /^[0-9a-f]{64}$/u;

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

type MutablePlan = Record<string, unknown> & { phases: Array<Record<string, unknown>> };
function mutablePlan(observedPhases = 0): MutablePlan {
  return structuredClone(plan(observedPhases)) as unknown as MutablePlan;
}

function assertNonAuthority(verdict: Stage4TeardownVerdict): void {
  assert.equal(verdict.authority, "local-teardown-order-classifier");
  assert.equal(verdict.cloud_inventory_observed, false);
  assert.equal(verdict.cloud_execution_observed, false);
  assert.equal(verdict.stage4_exit_satisfied, false);
  assert.equal(verdict.release_eligible, false);
}

function assertPreserved(
  input: unknown,
  reasonCode: string,
  acceptedPhaseCount?: number | null,
): Stage4TeardownVerdict {
  const verdict = verifyStage4Teardown(input);
  assert.equal(verdict.status, "preserve-uncertain");
  assert.equal(verdict.reason_code, reasonCode);
  assert.equal(verdict.next_phase, null);
  if (acceptedPhaseCount !== undefined) assert.equal(verdict.accepted_phase_count, acceptedPhaseCount);
  assertNonAuthority(verdict);
  return verdict;
}

function schemas(): {
  validatePlan: ValidateFunction;
  validateVerdict: ValidateFunction;
  validateStatic: ValidateFunction;
  validateSecurity: ValidateFunction;
} {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  const addFormats = require("ajv-formats") as (instance: AjvCore) => AjvCore;
  addFormats(ajv);
  const load = (name: string): object =>
    JSON.parse(readFileSync(resolve(import.meta.dirname, `../schemas/${name}`), "utf8")) as object;
  return {
    validatePlan: ajv.compile(load("stage4-teardown-plan-v1.json")),
    validateVerdict: ajv.compile(load("stage4-teardown-verdict-v1.json")),
    validateStatic: ajv.compile(load("stage4-static-preparation-evidence-v1.json")),
    validateSecurity: ajv.compile(load("security-report-v1alpha1.json")),
  };
}

test("the claimed phase/category graph is exact and bounded", () => {
  assert.deepEqual(STAGE4_TEARDOWN_PHASES, [
    "freeze-reconcilers",
    "close-admission",
    "revoke-credentials",
    "revoke-readiness",
    "remove-session-workloads",
    "verify-kubernetes-zero",
    "remove-cluster-infrastructure",
    "record-external-cloud-inventory-claim",
  ]);
  assert.deepEqual(STAGE4_TEARDOWN_PRODUCER_CLASSES, [
    "control-observer",
    "admission-observer",
    "credential-observer",
    "readiness-observer",
    "workload-mutator",
    "kubernetes-zero-observer",
    "infrastructure-mutator",
    "claimed-external-inventory-observer",
  ]);
  assert.equal(new Set(STAGE4_TEARDOWN_PHASES).size, 8);
  assert.equal(new Set(STAGE4_TEARDOWN_PRODUCER_CLASSES).size, 8);
  assert.equal(Object.isFrozen(STAGE4_TEARDOWN_PHASES), true);
  assert.equal(Object.isFrozen(STAGE4_TEARDOWN_PRODUCER_CLASSES), true);
});

test("every legal prefix has deterministic semantic bindings and one next claimed-evidence phase", () => {
  for (let observed = 0; observed < STAGE4_TEARDOWN_PHASES.length; observed += 1) {
    const input = plan(observed);
    const before = structuredClone(input);
    const first = verifyStage4Teardown(input);
    const second = verifyStage4Teardown(input);
    assert.deepEqual(first, second);
    assert.deepEqual(input, before, "evaluation must not mutate input");
    assert.equal(first.status, "awaiting-evidence");
    assert.equal(first.reason_code, "STAGE4_AWAITING_EVIDENCE");
    assert.equal(first.next_phase, STAGE4_TEARDOWN_PHASES[observed]);
    assert.equal(first.accepted_phase_count, observed);
    assert.match(first.plan_sha256 ?? "", DIGEST);
    assert.match(first.evidence_root_sha256 ?? "", DIGEST);
    assert.equal(Object.isFrozen(first), true);
    assertNonAuthority(first);
  }
});

test("terminal verdict is only local evidence-order-complete and never zero verified", () => {
  const verdict = verifyStage4Teardown(plan(8));
  assert.equal(verdict.status, "evidence-order-complete");
  assert.equal(verdict.reason_code, "STAGE4_EVIDENCE_ORDER_COMPLETE");
  assert.equal(verdict.next_phase, null);
  assert.equal(verdict.accepted_phase_count, 8);
  assert.match(verdict.plan_sha256 ?? "", DIGEST);
  assert.match(verdict.evidence_root_sha256 ?? "", DIGEST);
  assertNonAuthority(verdict);
});

test("semantic plan and evidence-root bindings change with every claimed evidence digest", () => {
  const original = plan(8);
  const baseline = verifyStage4Teardown(original);
  for (let index = 0; index < 8; index += 1) {
    const changed = mutablePlan(8);
    const row = changed.phases[index];
    assert.ok(row);
    row.evidence_sha256 = sha(String.fromCharCode("a".charCodeAt(0) + index));
    const verdict = verifyStage4Teardown(changed);
    assert.notEqual(verdict.plan_sha256, baseline.plan_sha256, `plan binding ${index}`);
    assert.notEqual(verdict.evidence_root_sha256, baseline.evidence_root_sha256, `evidence root ${index}`);
  }

  const reorderedKeys = {
    phases: original.phases.map((row) => ({
      state: row.state,
      producer_class: row.producer_class,
      phase: row.phase,
      ...(row.evidence_sha256 === undefined ? {} : { evidence_sha256: row.evidence_sha256 }),
    })),
    version: original.version,
    profile_sha256: original.profile_sha256,
    source_sha256: original.source_sha256,
  };
  const reorderedVerdict = verifyStage4Teardown(reorderedKeys);
  assert.equal(
    reorderedVerdict.plan_sha256,
    baseline.plan_sha256,
    "binding is over the semantic object, not key order",
  );
  assert.equal(reorderedVerdict.evidence_root_sha256, baseline.evidence_root_sha256);
});

test("uncertainty requires a custody artifact and binds it into both semantic digests", () => {
  for (let uncertainIndex = 0; uncertainIndex < 8; uncertainIndex += 1) {
    const uncertain = mutablePlan(8);
    const row = uncertain.phases[uncertainIndex];
    assert.ok(row);
    row.state = "uncertain";
    delete row.evidence_sha256;
    row.uncertainty_artifact_sha256 = sha("f");
    const verdict = assertPreserved(uncertain, "STAGE4_UNCERTAIN_EVIDENCE", uncertainIndex);
    assert.match(verdict.plan_sha256 ?? "", DIGEST);
    assert.match(verdict.evidence_root_sha256 ?? "", DIGEST);

    const changed = structuredClone(uncertain) as MutablePlan;
    const changedRow = changed.phases[uncertainIndex];
    assert.ok(changedRow);
    changedRow.uncertainty_artifact_sha256 = sha("e");
    const changedVerdict = verifyStage4Teardown(changed);
    assert.notEqual(changedVerdict.plan_sha256, verdict.plan_sha256);
    assert.notEqual(changedVerdict.evidence_root_sha256, verdict.evidence_root_sha256);

    const missing = structuredClone(uncertain) as MutablePlan;
    const missingRow = missing.phases[uncertainIndex];
    assert.ok(missingRow);
    delete missingRow.uncertainty_artifact_sha256;
    assertPreserved(missing, "STAGE4_INVALID_EVIDENCE", uncertainIndex);
  }
});

test("malformed rows preserve the same validated observed prefix for every failure position", () => {
  for (let index = 0; index < 8; index += 1) {
    const unknown = mutablePlan(8);
    const unknownRow = unknown.phases[index];
    assert.ok(unknownRow);
    unknownRow.note = "forbidden";
    assertPreserved(unknown, "STAGE4_INVALID_EVIDENCE", index);

    const wrongPhase = mutablePlan(8);
    const wrongPhaseRow = wrongPhase.phases[index];
    assert.ok(wrongPhaseRow);
    wrongPhaseRow.phase = "not-a-phase";
    assertPreserved(wrongPhase, "STAGE4_INVALID_PHASE_ORDER", index);

    const wrongCategory = mutablePlan(8);
    const wrongCategoryRow = wrongCategory.phases[index];
    assert.ok(wrongCategoryRow);
    wrongCategoryRow.producer_class = "provider";
    assertPreserved(wrongCategory, "STAGE4_INVALID_PRODUCER_CLASS", index);

    const badDigest = mutablePlan(8);
    const badDigestRow = badDigest.phases[index];
    assert.ok(badDigestRow);
    badDigestRow.evidence_sha256 = sha("A");
    assertPreserved(badDigest, "STAGE4_INVALID_EVIDENCE", index);
  }

  assertPreserved(null, "STAGE4_INVALID_SHAPE", null);
  const badRoot = mutablePlan();
  badRoot.extra = true;
  assertPreserved(badRoot, "STAGE4_INVALID_SHAPE", null);
});

test("phase order, claimed evidence order, and digest replay fail closed", () => {
  const swapped = mutablePlan(8);
  const first = swapped.phases[0];
  const second = swapped.phases[1];
  assert.ok(first);
  assert.ok(second);
  [swapped.phases[0], swapped.phases[1]] = [second, first];
  assertPreserved(swapped, "STAGE4_INVALID_PHASE_ORDER", 0);

  const gap = mutablePlan(1);
  const third = gap.phases[2];
  assert.ok(third);
  third.state = "observed";
  third.evidence_sha256 = sha("4");
  assertPreserved(gap, "STAGE4_EVIDENCE_OUT_OF_ORDER", 1);

  for (const replacement of [sha("0"), sha("1"), sha("2")]) {
    const replay = mutablePlan(8);
    const final = replay.phases[7];
    assert.ok(final);
    final.evidence_sha256 = replacement;
    assertPreserved(replay, "STAGE4_EVIDENCE_REPLAY", 8);
  }
});

test("throwing proxy and introspection traps preserve uncertainty instead of escaping", () => {
  const traps: unknown[] = [
    new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error("getPrototypeOf trap");
        },
      },
    ),
    new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error("ownKeys trap");
        },
      },
    ),
    new Proxy(
      { version: "cogs.stage4-teardown-plan/v1" },
      {
        getOwnPropertyDescriptor: () => {
          throw new Error("getOwnPropertyDescriptor trap");
        },
      },
    ),
  ];
  const trappedArray = mutablePlan();
  trappedArray.phases = new Proxy(trappedArray.phases, {
    ownKeys: () => {
      throw new Error("array ownKeys trap");
    },
  });
  traps.push(trappedArray);

  for (const hostile of traps) {
    assert.doesNotThrow(() => verifyStage4Teardown(hostile));
    assertPreserved(hostile, "STAGE4_INVALID_SHAPE", null);
  }
});

test("dedicated schema tests compile teardown contracts, reject unknowns, and keep authority domains disjoint", () => {
  const { validatePlan, validateVerdict, validateStatic, validateSecurity } = schemas();
  for (let observed = 0; observed <= 8; observed += 1) {
    const input = plan(observed);
    const verdict = verifyStage4Teardown(input);
    assert.equal(validatePlan(input), true);
    assert.equal(validateVerdict(verdict), true);
  }

  const uncertain = mutablePlan(8);
  const uncertainRow = uncertain.phases[3];
  assert.ok(uncertainRow);
  uncertainRow.state = "uncertain";
  delete uncertainRow.evidence_sha256;
  uncertainRow.uncertainty_artifact_sha256 = sha("f");
  assert.equal(validatePlan(uncertain), true);
  assert.equal(validateVerdict(verifyStage4Teardown(uncertain)), true);
  const malformedOutputs = [
    verifyStage4Teardown(null),
    verifyStage4Teardown({}),
    (() => {
      const replay = mutablePlan(8);
      const final = replay.phases[7];
      assert.ok(final);
      final.evidence_sha256 = sha("2");
      return verifyStage4Teardown(replay);
    })(),
  ];
  for (const malformedOutput of malformedOutputs) assert.equal(validateVerdict(malformedOutput), true);

  const unknownPlan = mutablePlan();
  unknownPlan.unexpected_security_field = true;
  assert.equal(validatePlan(unknownPlan), false);
  const unknownRow = mutablePlan();
  const row = unknownRow.phases[0];
  assert.ok(row);
  row.unexpected_security_field = true;
  assert.equal(validatePlan(unknownRow), false);
  assert.equal(validateVerdict({ ...verifyStage4Teardown(plan()), unexpected_security_field: true }), false);

  const staticReport = {
    version: "cogs.stage4-static-preparation-evidence/v1",
    authority: "static-only-stage4-preparation",
  };
  const teardownPlan = plan();
  const teardownVerdict = verifyStage4Teardown(teardownPlan);
  assert.equal(validatePlan(teardownVerdict), false);
  assert.equal(validateVerdict(teardownPlan), false);
  assert.equal(validatePlan(staticReport), false);
  assert.equal(validateVerdict(staticReport), false);
  assert.equal(validateStatic(teardownPlan), false);
  assert.equal(validateStatic(teardownVerdict), false);
  assert.equal(validateSecurity(teardownPlan), false);
  assert.equal(validateSecurity(teardownVerdict), false);

  for (const field of [
    "cloud_inventory_observed",
    "cloud_execution_observed",
    "stage4_exit_satisfied",
    "release_eligible",
  ] as const) {
    assert.equal(validateVerdict({ ...teardownVerdict, [field]: true }), false, field);
  }
  assert.equal(validateVerdict({ ...teardownVerdict, authority: "authoritative-production-profile" }), false);
  assert.equal(validateVerdict({ ...teardownVerdict, status: "zero-verified" }), false);
});

test("only fixed non-authoritative reason codes can be emitted", () => {
  assert.deepEqual(STAGE4_TEARDOWN_REASON_CODES, [
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
  ]);
  const emitted = [verifyStage4Teardown(plan()), verifyStage4Teardown(plan(8)), verifyStage4Teardown(null)];
  for (const verdict of emitted) assert.ok(STAGE4_TEARDOWN_REASON_CODES.includes(verdict.reason_code));
});

test("production module has no execution, environment, network, or provider surface", () => {
  const source = readFileSync(resolve(import.meta.dirname, "../scripts/stage4-teardown-verifier.ts"), "utf8");
  assert.deepEqual(Object.keys(verifierModule).sort(), [
    "STAGE4_TEARDOWN_PHASES",
    "STAGE4_TEARDOWN_PRODUCER_CLASSES",
    "STAGE4_TEARDOWN_REASON_CODES",
    "verifyStage4Teardown",
  ]);
  assert.doesNotMatch(source, /zero-verified|ZERO_VERIFIED/u);
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
