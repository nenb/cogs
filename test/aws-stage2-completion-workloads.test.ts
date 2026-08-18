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
      timeout: process.platform === "linux" ? 600_000 : 60_000,
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
  workload_implementation_sha256: "c856bb997e1d799c712cf08b48c2fb3de314b8e0efe8985908a5b58d08b3c850",
  owner_implementation_sha256: "498407f393924ab472d3f014a3c2e54257e0b38f6b0783f24fcf35e820b31796",
  orchestrator_implementation_sha256: "edb057827c213e35d00f9088abba238bf1ab687b963212eaa311acdc9f0f18f8",
  candidate_recovery_implementation_sha256: "1408a9b51b9e5a241a731ac2f453ee28ff1f44f8e92d4111cd9a4100010522e5",
  post_pin_recovery_implementation_sha256: "1bae8dbde70ea7c0465dbb808a9d85205d88cdf03302f389128a25884ec2c060",
  tool_observations: [
    { name: "git", sha256: "1".repeat(64), bytes: 1, version: "git version 2.47.3" },
    { name: "dpkg-deb", sha256: "2".repeat(64), bytes: 2, version: "dpkg-deb 1.22.22" },
    { name: "dpkg", sha256: "3".repeat(64), bytes: 3, version: "dpkg 1.22.22" },
  ],
  contract_validator: "unbound-self-referential-host-validator",
  source_checkout: "unbound-current-checkout",
  linux_dynamic_tool_closure: "unbound-kernel-libc-loader-libraries-config-helpers",
  process_containment: "linux-subreaper-pidfd-or-start-time-no-cgroup-v2",
  process_containment_limitation: "no-cgroup-proof-honest-supervisor-crash-only-not-hostile-process-closure",
  operation_parent_isolation: "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp",
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

test("rejected v1 is absent from protected main and host foundations remain non-authoritative", () => {
  const rejectedV1 = spawnSync(
    "git",
    ["cat-file", "-e", "69eccf1:schemas/stage2-workload-local-qualification-v1.json"],
    { cwd: root, encoding: "utf8" },
  );
  assert.notEqual(rejectedV1.status, 0);

  const workflow = readFileSync(join(root, ".github/workflows/stage2-workload-linux-foundations.yml"), "utf8");
  assert.match(workflow, /name: Stage 2 workload Linux foundations/u);
  assert.match(workflow, /COGS_REQUIRE_STAGE2_WORKLOAD_LINUX_FOUNDATIONS=1/u);
  const portableSource = readFileSync(portable, "utf8");
  assert.match(portableSource, /check\(linux_destructive_cases_ran,/u);
  assert.match(portableSource, /check\(linux_containment_recovery_cases_ran,/u);
  assert.match(portableSource, /check\(linux_foundation_cases_ran == required_foundations,/u);
});

test("fixed candidate and recovery entries redact every invocation failure", () => {
  for (const entry of [
    "deploy/aws-feasibility/remote/completion_package_candidate.py",
    "deploy/aws-feasibility/remote/completion_package_candidate_recovery.py",
    "deploy/aws-feasibility/remote/completion_package_post_pin_recovery.py",
  ]) {
    const result = spawnSync("python3", ["-B", entry, "forbidden-selector"], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^completion host (candidate|recovery) failed: invocation\n$/u);
    assert.doesNotMatch(result.stderr, /\/|git|dpkg|Traceback|Kata|qualification|forbidden/u);
  }
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
  for (const entry of [
    "deploy/aws-feasibility/remote/completion_package_candidate_recovery.py",
    "deploy/aws-feasibility/remote/completion_package_post_pin_recovery.py",
  ]) {
    const recovery = spawnSync("python3", ["-B", entry], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(recovery.status, 1);
    assert.equal(recovery.stdout, "");
    assert.equal(recovery.stderr, "completion host recovery failed: invariant\n");
    assert.doesNotMatch(recovery.stderr, /\/|Traceback|Kata|qualification/u);
  }
});
