import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
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
const exactTools = [
  {
    name: "git",
    sha256: "356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60",
    bytes: 4082768,
    version: "git version 2.47.3",
  },
  {
    name: "dpkg-deb",
    sha256: "5346e5fdfdc81d58bbc9d2a3de20ff3738dc479cdb04cc52b91503cbb13440eb",
    bytes: 182816,
    version: "Debian 'dpkg-deb' package archive backend version 1.22.22 (amd64).",
  },
  {
    name: "dpkg",
    sha256: "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
    bytes: 326704,
    version: "Debian 'dpkg' package management program version 1.22.22 (amd64).",
  },
];
const runtimeClosure = {
  version: "cogs.stage2-runtime-tool-closure/v1",
  manifest_sha256: "4c11dee4e0cba15c7a4bf7ef76937796abbdebf7a93b395ef47b14659a50b850",
  object_count: 35,
  tools: exactTools,
};
const executionBinding = {
  fixture_implementation_sha256: "c877bdbbce0f1c7920294f5a240aa8b83c81dd96ce3c4daab650a9fbadc7f9f4",
  workload_implementation_sha256: "c856bb997e1d799c712cf08b48c2fb3de314b8e0efe8985908a5b58d08b3c850",
  owner_implementation_sha256: "498407f393924ab472d3f014a3c2e54257e0b38f6b0783f24fcf35e820b31796",
  orchestrator_implementation_sha256: "8341389e56e16e82bb6c477a9181c57d90af59e97e7e03b0cbd9c9a0e4774ce1",
  candidate_recovery_implementation_sha256: "1408a9b51b9e5a241a731ac2f453ee28ff1f44f8e92d4111cd9a4100010522e5",
  post_pin_recovery_implementation_sha256: "1bae8dbde70ea7c0465dbb808a9d85205d88cdf03302f389128a25884ec2c060",
  tool_observations: exactTools,
  runtime_closure: runtimeClosure,
  contract_validator: "unbound-self-referential-host-validator",
  source_checkout: "unbound-current-checkout",
  linux_dynamic_tool_closure: "exact-static-elf-closure-runtime-mapping-attestation-required",
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
    {
      ...candidate,
      execution_binding: {
        ...executionBinding,
        tool_observations: [{ ...exactTools[0], sha256: "f".repeat(64) }, ...exactTools.slice(1)],
      },
    },
    {
      ...candidate,
      execution_binding: {
        ...executionBinding,
        runtime_closure: { ...runtimeClosure, manifest_sha256: "f".repeat(64) },
      },
    },
  ]) {
    assert.equal(validateCandidate(hostile), false);
  }

  const validateFinal = compile("stage2-workload-final-pin-v1.json");
  const finalPin = {
    version: "cogs.stage2-workload-final-pin/v1",
    candidate_contract_sha256: contractSha,
    candidate_result_sha256: "c".repeat(64),
    runtime_closure: runtimeClosure,
    package_identity: identity,
    reproductions: ["A", "B"],
    promotion: "manual-reviewed-a-equals-b",
  };
  assert.equal(validateFinal(finalPin), true, JSON.stringify(validateFinal.errors));
  assert.equal(validateFinal({ ...finalPin, reproductions: ["B", "A"] }), false);
  assert.equal(validateFinal({ ...finalPin, candidate_result_sha256: "C".repeat(64) }), false);
  assert.equal(validateFinal({ ...finalPin, runtime_closure: { ...runtimeClosure, object_count: 34 } }), false);
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

test("retained-rootfs V2 is truthful without reinterpreting historical V1", () => {
  const validateV1 = compile("stage2-workload-candidate-v1.json");
  const schemaPath = join(root, "schemas/stage2-workload-candidate-v2.json");
  const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as Record<string, unknown>;
  assert.match(String(schema.$comment), /exact V2 codec requires explicit expected source revision and manifest/u);
  const validateV2 = compile("stage2-workload-candidate-v2.json");
  const nativeBinding = {
    fixture_implementation_sha256: executionBinding.fixture_implementation_sha256,
    workload_implementation_sha256: executionBinding.workload_implementation_sha256,
    owner_implementation_sha256: executionBinding.owner_implementation_sha256,
    native_producer_implementation_sha256: "fd43735b028e2ea41c6b7cc74109eefcb050603d2861353a4dee9dc04aa4827b",
    runtime_codec_implementation_sha256: "2548e636d496592c325357d6f08c96510e52c127bf0d501486d20925db8595cd",
    launcher_implementation_sha256: "9e0fec1d8735f2f3ce83bc550f282c2477450b25dcd406c9d8e54bdf5b3e8882",
    source_revision: "1".repeat(40),
    source_manifest_sha256: "2".repeat(64),
    tool_observations: exactTools,
    runtime_closure: runtimeClosure,
    contract_validator: "exact-fixed-source-native-v2-codec",
    source_checkout: "manifest-verified-reviewed-revision-loaded-before-chroot",
    linux_dynamic_tool_closure: "exact-static-elf-closure-executed-from-retained-rootfs",
    process_containment: "parent-gated-fork-helper-newns-newpid-newnet-fork-pid1-dual-pidfd-v1",
    process_containment_limitation: "trusted-initial-user-namespace-root-no-hostile-root-security-boundary",
    operation_parent_isolation: "root-owned-mode-0700-parent-workload-uid-gid-65534-zero-capabilities-nnp",
    rootfs_execution: "detached-recursive-read-only-retained-stage2-rootfs-fresh-proc-dev-tmp",
    retained_root_lifecycle: "output-after-pid1-and-helper-settlement-and-retained-root-removal",
  };
  const native = {
    version: "cogs.stage2-workload-candidate/v2",
    result: "pass",
    authority: "non-authoritative-retained-rootfs-candidate-only",
    candidate_contract_sha256: contractSha,
    final_pin_sha256: null,
    package_identity: identity,
    reproductions,
    a_equals_b: true,
    lifecycle_deleted: true,
    promotion: "external-manual-review-required",
    execution_binding: nativeBinding,
  };
  assert.equal(validateV2(native), true, JSON.stringify(validateV2.errors));
  assert.equal(validateV1(native), false);
  assert.equal(validateV2({ ...native, version: "cogs.stage2-workload-candidate/v1" }), false);
  assert.equal(validateV2({ ...native, execution_binding: executionBinding }), false);
  for (const field of [
    "native_producer_implementation_sha256",
    "runtime_codec_implementation_sha256",
    "launcher_implementation_sha256",
  ] as const) {
    assert.equal(
      validateV2({ ...native, execution_binding: { ...nativeBinding, [field]: "d".repeat(64) } }),
      false,
      `${field} accepted arbitrary hex`,
    );
  }
  assert.equal(
    validateV2({
      ...native,
      execution_binding: { ...nativeBinding, orchestrator_implementation_sha256: "d".repeat(64) },
    }),
    false,
  );
  assert.equal(executionBinding.rootfs_execution, "not-used-by-host-candidate-or-reproduction");
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

test("fixed candidate authenticates exact acquired tool bytes before build A", () => {
  const source = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_package_candidate.py"), "utf8");
  const observation = source.indexOf("exact_tool_observations(tools.observations())");
  const firstBuild = source.indexOf('_run_package_sample(root, "candidate-a"');
  assert.ok(observation > 0 && firstBuild > observation);
  assert.match(source, /runtime_closure = exact_runtime_closure\(\)/u);
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

test("production final-pin bytes and authority remain absent", () => {
  assert.equal(existsSync(join(root, "deploy/aws-feasibility/remote/stage2-completion-runtime-v1.json")), false);
  const contractSource = readFileSync(
    join(root, "deploy/aws-feasibility/remote/completion_runtime_contract.py"),
    "utf8",
  );
  assert.match(contractSource, /^REVIEWED_FINAL_PIN_SHA256 = None$/mu);
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
