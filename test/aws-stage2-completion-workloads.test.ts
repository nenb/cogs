import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();
const portable = join(root, "test/aws-stage2-completion-workloads.py");
const remote = join(root, "deploy/aws-feasibility/remote");
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

for (const optimized of [false, true]) {
  test(`ADR 0099 workload contracts fail closed${optimized ? " under python -O" : ""}`, () => {
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

test("strict workload schemas reject extra and out-of-order metadata", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  const compile = (name: string) =>
    ajv.compile(JSON.parse(readFileSync(join(root, "schemas", name), "utf8")) as object);
  const validateCandidate = compile("stage2-workload-candidate-v1.json");
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
  const candidate = {
    version: "cogs.stage2-workload-candidate/v1",
    result: "pass",
    candidate_contract_sha256: "b8660b92d778e9f5dc89586df4f68a2e2b12cdce818ff4fe12adf0a8e951fdf3",
    candidates: [
      { id: "A", package_identity: identity, deleted: true },
      { id: "B", package_identity: identity, deleted: true },
    ],
    a_equals_b: true,
    lifecycle_deleted: true,
    promotion: "manual-only",
  };
  assert.equal(validateCandidate(candidate), true, JSON.stringify(validateCandidate.errors));
  assert.equal(validateCandidate({ ...candidate, path: "/hostile" }), false);
  assert.equal(validateCandidate({ ...candidate, candidates: [...candidate.candidates].reverse() }), false);

  const validateQualification = compile("stage2-workload-local-qualification-v1.json");
  const sample = (number: number) => ({
    sample: number,
    operations: ["git", "package-build", "package-install"],
    git_ms: 1,
    package_build_ms: 2,
    package_install_ms: 3,
    package_identity: identity,
    deleted: true,
  });
  const qualification = {
    version: "cogs.stage2-workload-local-qualification/v1",
    result: "pass",
    candidate_contract_sha256: candidate.candidate_contract_sha256,
    lifecycle_count: 1,
    samples: Array.from({ length: 7 }, (_unused, index) => sample(index + 1)),
    all_match_final_pin: true,
    lifecycle_deleted: true,
    authority: "local-standalone-kata-only-stopped-before-step-5",
  };
  assert.equal(validateQualification(qualification), true, JSON.stringify(validateQualification.errors));
  assert.equal(
    validateQualification({ ...qualification, samples: [sample(2), sample(1), ...qualification.samples.slice(2)] }),
    false,
  );
  assert.equal(validateQualification({ ...qualification, samples: qualification.samples.slice(0, 6) }), false);
});

test("workload production surface is fixed, local-only, and does not modify Kata owners", async () => {
  const files = [
    "completion_runtime_contract.py",
    "completion_guest_workloads.py",
    "completion_package_candidate.py",
    "completion_local_full.py",
  ];
  const sources = await Promise.all(files.map((name) => readFile(join(remote, name), "utf8")));
  const source = sources.join("\n");
  assert.match(source, /for sample in range\(1, 8\)/u);
  assert.match(source, /candidate-a/u);
  assert.match(source, /candidate-b/u);
  assert.match(source, /manual-reviewed-a-equals-b/u);
  assert.match(source, /--root-owner-group/u);
  assert.match(source, /--threads-max=1/u);
  assert.doesNotMatch(source, /boto|AWS_|requests|urllib|socket|Terraform|OpenTofu|retry|fallback/u);

  const diff = spawnSync("git", ["diff", "--name-only", "--", "deploy/aws-feasibility/remote/completion_kata_*.py"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(diff.status, 0, diff.stderr);
  assert.equal(diff.stdout, "");
});
