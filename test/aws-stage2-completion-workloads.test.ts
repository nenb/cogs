import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const root = process.cwd();
const portable = join(root, "test/aws-stage2-completion-workloads.py");
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

for (const optimized of [false, true]) {
  test(`ADR 0099 host workload contracts fail closed${optimized ? " under python -O" : ""}`, () => {
    const result = spawnSync("python3", [...(optimized ? ["-O"] : []), "-B", portable], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /completion workload contract tests passed/u);
  });
}

const identity = {
  deb_sha256: "a".repeat(64),
  deb_bytes: 1234,
  installed_tree_sha256: "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
  installed_entries: 259,
  installed_bytes: 1048576,
  package: "cogs-stage2-fixture",
  version: "1.0",
  architecture: "all",
};
const contractSha = "b8660b92d778e9f5dc89586df4f68a2e2b12cdce818ff4fe12adf0a8e951fdf3";
const executionBinding = {
  fixture_implementation_sha256: "c877bdbbce0f1c7920294f5a240aa8b83c81dd96ce3c4daab650a9fbadc7f9f4",
  workload_implementation_sha256: "451ddb9e65998c3599c534188eb5bbb6270cd0c899cc9dbd2a43106010661797",
  orchestrator_implementation_sha256: "75abc89837833084c2dec1b5d7be1f546261997475a7e73a14a6bede8511dc77",
  tool_observations: [
    { name: "git", sha256: "1".repeat(64), bytes: 1, version: "git version 2.47.3" },
    { name: "dpkg-deb", sha256: "2".repeat(64), bytes: 2, version: "dpkg-deb 1.22.22" },
    { name: "dpkg", sha256: "3".repeat(64), bytes: 3, version: "dpkg 1.22.22" },
  ],
  contract_validator: "unbound-self-referential-host-validator",
  source_checkout: "unbound-current-checkout",
  linux_dynamic_tool_closure: "unbound-kernel-libc-loader-libraries-config-helpers",
  rootfs_execution: "not-used-by-host-candidate-or-reproduction",
};
const reproductions = [
  { id: "A", deleted: true },
  { id: "B", deleted: true },
];

function compile(name: string): ValidateFunction {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  return ajv.compile(JSON.parse(readFileSync(join(root, "schemas", name), "utf8")) as object);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

test("candidate, final, and post-pin schemas make A=B structural", () => {
  const validateCandidate = compile("stage2-workload-candidate-v1.json");
  const candidate = {
    version: "cogs.stage2-workload-candidate/v1",
    result: "pass",
    authority: "non-authoritative-host-candidate-only",
    candidate_contract_sha256: contractSha,
    final_pin_sha256: null,
    package_identity: identity,
    reproductions,
    a_equals_b: true,
    lifecycle_deleted: true,
    promotion: "external-manual-review-required",
    execution_binding: executionBinding,
  };
  assert.equal(validateCandidate(candidate), true, JSON.stringify(validateCandidate.errors));
  for (const hostile of [
    { ...candidate, authority: "authoritative" },
    { ...candidate, final_pin_sha256: "f".repeat(64) },
    { ...candidate, a_equals_b: false },
    { ...candidate, reproductions: [...reproductions].reverse() },
    { ...candidate, candidate_b: { ...identity, deb_sha256: "b".repeat(64) } },
  ]) {
    assert.equal(validateCandidate(hostile), false);
  }

  const validateFinal = compile("stage2-workload-final-pin-v1.json");
  const finalPin = {
    version: "cogs.stage2-workload-final-pin/v1",
    candidate_contract_sha256: contractSha,
    package_identity: identity,
    reproductions: ["A", "B"],
    promotion: "manual-reviewed-a-equals-b",
  };
  assert.equal(validateFinal(finalPin), true, JSON.stringify(validateFinal.errors));
  assert.equal(validateFinal({ ...finalPin, reproductions: ["B", "A"] }), false);
  assert.equal(validateFinal({ ...finalPin, candidate_b: { ...identity, deb_sha256: "b".repeat(64) } }), false);

  const validatePostPin = compile("stage2-workload-post-pin-v1.json");
  const postPin = {
    version: "cogs.stage2-workload-post-pin/v1",
    result: "pass",
    authority: "non-authoritative-host-reproduction-only",
    candidate_contract_sha256: contractSha,
    final_pin_sha256: "f".repeat(64),
    package_identity: identity,
    reproductions,
    matches_final_pin: true,
    lifecycle_deleted: true,
    execution_binding: executionBinding,
  };
  assert.equal(validatePostPin(postPin), true, JSON.stringify(validatePostPin.errors));
  for (const [field, value] of [
    ["authority", "authoritative"],
    ["final_pin_sha256", null],
    ["matches_final_pin", false],
    ["lifecycle_deleted", false],
  ] as const) {
    const hostile = clone(postPin) as Record<string, unknown>;
    hostile[field] = value;
    assert.equal(validatePostPin(hostile), false, `${field} mismatch passed schema`);
  }
});

test("removed host qualification surfaces and protected files stay untouched", () => {
  assert.throws(() => readFileSync(join(root, "deploy/aws-feasibility/remote/completion_local_full.py")));
  assert.throws(() => readFileSync(join(root, "schemas/stage2-workload-local-qualification-v1.json")));

  const protectedDiff = spawnSync(
    "git",
    [
      "diff",
      "--name-only",
      "69eccf1..HEAD",
      "--",
      ".github/workflows",
      "deploy/aws-feasibility/remote/completion_kata_*.py",
      "deploy/aws-feasibility/*.sh",
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(protectedDiff.status, 0, protectedDiff.stderr);
  assert.equal(protectedDiff.stdout, "");
});

test("Darwin CLI is categorical and cannot create a final pin", { skip: process.platform !== "darwin" }, () => {
  const result = spawnSync("python3", ["-B", "deploy/aws-feasibility/remote/completion_package_candidate.py"], {
    cwd: root,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /^completion host candidate failed: [a-z-]+\n$/u);
  assert.doesNotMatch(result.stderr, /\/|git|dpkg|Traceback|Kata|qualification/u);
  assert.throws(() => readFileSync(join(root, "deploy/aws-feasibility/remote/stage2-completion-runtime-v1.json")));
});
