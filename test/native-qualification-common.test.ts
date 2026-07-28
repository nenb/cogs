/* biome-ignore-all lint/suspicious/noExplicitAny: concise hostile report mutations */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const predecessor = "bec0a19b0b984f88ab9c2effc5059f3737915caa";
const workflowPath = ".github/workflows/ci.yml";
const schemaPath = "schemas/native-qualification-report-v1alpha1.json";
const jobs = [
  ["A", "native-qualification-a", "job-a-runtime-mappings", 300],
  ["B", "native-qualification-b", "job-b-compression", 350],
  ["C", "native-qualification-c", "job-c-descriptors", 250],
  ["D", "native-qualification-d", "job-d-process-lifecycle", 350],
  ["E", "native-qualification-e", "job-e-sandbox", 450],
  ["integration", "native-closure-integration", "thin-integration", 350],
] as const;
const ids = {
  A: `elf_real python_closure_exact map_files_trusted mapped_closure_equal
      mapping_stable helper_reaped cleanup_restored`,
  B: `gzip_source_exact gzip_sealed_exec zstd_source_exact zstd_sealed_exec
      decompression_deterministic network_denied children_exact cleanup_restored`,
  C: `nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact
      cloexec_exact inheritance_exact limit_restored cleanup_restored`,
  D: `pdeathsig_armed parent_handshake_exact before_release_death after_release_death
      starttime_revalidated session_owned process_group_owned term_kill_bounded all_reaped cleanup_restored`,
  E: `mount_view_exact checkout_read_only user_namespace_exact pid_namespace_exact mount_namespace_exact
      network_namespace_exact pid_one capabilities_zero noroot_locked nnp_set seccomp_socket_denied
      seccomp_io_uring_denied no_acquisition_route checkout_unchanged all_reaped mounts_restored cleanup_restored`,
  integration: `closure_prepared handoff_exact gzip_deterministic zstd_deterministic
      marker_exact no_linked_evidence cleanup_restored`,
} as const;
const cleanupKeys = "descriptors children paths mounts namespaces limits checkout".split(" ");
const workflow = readFileSync(workflowPath, "utf8");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validate = ajv.compile(schema);

function block(id: string) {
  const start = workflow.indexOf(`  ${id}:`);
  assert.notEqual(start, -1, id);
  const tail = workflow.slice(start + id.length + 3);
  const next = /\n {2}[a-z0-9-]+:\n/u.exec(tail);
  return workflow.slice(start, next ? start + id.length + 3 + (next.index ?? 0) : undefined);
}

function metadata(job: keyof typeof ids) {
  const digest = "a".repeat(64);
  if (job === "A") return [
    { kind: "object", id: "python", role: "executable", sha256: digest, size_bytes: 1,
      soname: null, needed: ["ld.so"] },
    { kind: "object", id: "loader", role: "loader", sha256: "b".repeat(64), size_bytes: 2,
      soname: "ld.so", needed: [] },
    { kind: "summary", closure_sha256: "c".repeat(64), mapping_sha256: "d".repeat(64) },
  ];
  if (job === "B") return ["gzip", "zstd"].map((id) => ({
    id, source_sha256: digest, source_size_bytes: 1, sealed_sha256: digest, sealed_size_bytes: 1,
    seal_mask: 15, execution_mapping_sha256: digest, output_sha256: digest,
  }));
  if (job === "E") return [{ id: "sandbox-policy", role: "policy", sha256: digest, size_bytes: 0 }];
  if (job === "integration") return ["closure", "gzip_output", "source_set", "zstd_output"].map((id) => (
    { id, role: "digest", sha256: digest, size_bytes: 0 }
  ));
  return [];
}

function report(job: keyof typeof ids, result: "pass" | "fail"): any {
  const jobId = jobs.find(([name]) => name === job)?.[1];
  assert.ok(jobId);
  const pass = result === "pass";
  const digest = "a".repeat(64);
  const checks = ids[job].trim().split(/\s+/u).map((id) => ({ id, outcome: "pass" }));
  const cleanup = Object.fromEntries(cleanupKeys.map((key) => [key, true]));
  if (!pass) { const first = checks[0]; assert.ok(first); first.outcome = "fail"; cleanup.descriptors = false; }
  return {
    version: "cogs.native-qualification/v1alpha1", job,
    source: { head_sha: "1".repeat(40), checkout_sha: "1".repeat(40),
      driver_blob_sha256: digest, common_blob_sha256: digest },
    envelope: { repository: "owner/repo", head_repository: "owner/repo", event_name: "pull_request",
      github_sha: "2".repeat(40), event_merge_sha: "2".repeat(40), base_sha: "3".repeat(40),
      run_id: 1, run_attempt: 1, pull_request_number: 1 },
    workflow: { path: workflowPath, blob_sha256: digest, workflow_sha: "1".repeat(40), job_id: jobId },
    runner: { image: "ubuntu-24.04", image_version: "20260720.1",
      kernel_release: "6.8.0-100-generic", architecture: "x86_64" },
    authority: "exact-run-native-qualification", result, checks, metadata: pass ? metadata(job) : [],
    failure_phase: pass ? null : "portable-test", diagnostics_sha256: pass ? null : "d".repeat(64), cleanup,
  };
}

test("workflow uses one exact ABI and an explicit failing eligibility/final result", () => {
  const eligibility = block("native-qualification-eligibility");
  for (const token of ["pull_request", "RUN_ATTEMPT", "HEAD_REPOSITORY", "BASE_SHA", "MERGE_SHA"]) {
    assert.ok(eligibility.includes(token));
  }
  for (const [job, id, driver] of jobs) {
    const declaration = block(id);
    const source = readFileSync(`scripts/native-qualification/${driver}.py`, "utf8");
    assert.ok(declaration.includes(`NQ_DRIVER: scripts/native-qualification/${driver}.py`));
    assert.match(declaration, /["']\$NQ_DRIVER["']\s+--workflow-bound/u);
    assert.ok(declaration.includes("NQ_EVENT_NAME") && declaration.includes("NQ_HEAD_REPOSITORY"));
    assert.doesNotMatch(declaration, /if:\s*github\.run_attempt/u);
    assert.match(declaration, /Upload validated fixed report[\s\S]*actions\/upload-artifact/u);
    const upload = declaration.split("Restore fixed report-path baseline")[0] ?? "";
    assert.doesNotMatch(upload.split("Upload validated fixed report")[1] ?? "", /^\s*if:\s*\$\{\{\s*always/mu);
    assert.ok(declaration.includes(`/tmp/cogs-native-qualification-${job}/report.json`));
    assert.ok(declaration.includes(`common.py --cleanup ${job}`));
    assert.match(source, /["']--workflow-bound["']/u);
    assert.doesNotMatch(source, /["']--(?:native|native-fixed)["']/u);
    assert.match(source, new RegExp(`WorkflowContext\\.from_environ\\(["']${job}["'], __file__\\)`, "u"));
    assert.match(source, /finalize_report\(/u);
  }
  const final = block("native-qualification-required");
  assert.match(final, /if:\s*\$\{\{\s*always\(\)\s*\}\}/u);
  for (const id of ["quality", "native-qualification-eligibility", ...jobs.map((row) => row[1])]) {
    assert.ok(final.includes(id));
  }
  assert.ok(final.includes("success success success success success success success success"));
});

test("schema closes every job, metadata, result, check, and cleanup branch", () => {
  for (const [job] of jobs) {
    const passing = report(job, "pass");
    const failing = report(job, "fail");
    assert.equal(validate(passing), true, `${job}/pass: ${ajv.errorsText(validate.errors)}`);
    assert.equal(validate(failing), true, `${job}/fail: ${ajv.errorsText(validate.errors)}`);
    for (const mutate of [
      (value: any) => value.checks.reverse(),
      (value: any) => { value.checks[0].id = value.checks[1].id; },
      (value: any) => { value.checks[0].outcome = "fail"; },
      (value: any) => { value.cleanup.paths = false; },
      (value: any) => { value.failure_phase = "contradiction"; },
    ]) {
      const hostile = structuredClone(passing); mutate(hostile);
      assert.equal(validate(hostile), false, job);
    }
    const falseFailure = structuredClone(failing);
    falseFailure.checks.forEach((row: any) => { row.outcome = "pass"; });
    cleanupKeys.forEach((key) => { falseFailure.cleanup[key] = true; });
    assert.equal(validate(falseFailure), false, `${job}: all-success failure`);
  }
  const loader = report("A", "pass");
  assert.equal(validate(loader), true, "A loader role accepted");
  loader.metadata[1].role = "interpreter";
  assert.equal(validate(loader), false, "substituted A role");
  const seal = report("B", "pass");
  seal.metadata[0].seal_mask = 7;
  assert.equal(validate(seal), false, "seal mask");
});

test("common publishes and removes one independently validated generation",
  { skip: process.platform !== "linux" }, () => {
  const script = `import hashlib,os,sys
sys.path.insert(0,'scripts/native-qualification');import common
h=lambda p:hashlib.sha256(open(p,'rb').read()).hexdigest()
c=common.WorkflowContext(
 'C','owner/repo','owner/repo','1'*40,'2'*40,'1'*40,'2'*40,'3'*40,common.JOB_IDS['C'],1,1,1,
 'image','6.8.0-100-generic','x86_64',h(common.WORKFLOW),h(common.COMMON.parent/common.DRIVERS['C']),h(common.COMMON))
checks=dict.fromkeys(common.CHECK_IDS['C'],'pass');clean=dict.fromkeys(common.CLEANUP_KEYS,True)
p=common.finalize_report(c,'pass',checks,[],clean);assert p.is_file()
common.cleanup_report('C');assert not p.parent.exists()`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const common = readFileSync("scripts/native-qualification/common.py", "utf8");
  const transactionTokens = ["O_EXCL", "O_NOFOLLOW", "os.fsync", "_validate_schema", "_validate_semantics",
    "renameat2", "_generation", "_remove_owned"];
  for (const token of transactionTokens) assert.ok(common.includes(token), token);
});

test("native surfaces remain within ADR 0090 readable highs", () => {
  const highs = new Map<string, number>([
    [workflowPath, 300], [schemaPath, 300], ["scripts/native-qualification/common.py", 400],
    ...jobs.map(([, , driver, high]) => [`scripts/native-qualification/${driver}.py`, high] as const),
    ["test/native-qualification-common.test.ts", 200], ["test/native-qualification-a.test.ts", 120],
    ["test/native-qualification-b.test.ts", 120], ["test/native-qualification-c.test.ts", 120],
    ["test/native-qualification-d.test.ts", 150], ["test/native-qualification-e.test.ts", 180],
    ["test/native-qualification-integration.test.ts", 150],
  ]);
  const diff = spawnSync("git", ["diff", "--numstat", predecessor, "--", ...highs.keys()],
    { encoding: "utf8" });
  assert.equal(diff.status, 0, diff.stderr);
  const additions = new Map(diff.stdout.trim().split("\n").filter(Boolean).map((row) => {
    const [added, , path] = row.split("\t"); return [path, Number(added)] as const;
  }));
  let subtotal = 0;
  for (const [path, high] of highs) {
    const added = additions.get(path) ?? 0;
    subtotal += added;
    assert.ok(added <= high, `${path}: ${added}/${high}`);
    const width = path === workflowPath || path === schemaPath ? 200 : path.endsWith("common.py") ? 160 : 220;
    assert.ok(readFileSync(path, "utf8").split("\n").every((line) => line.length <= width), `${path}: readable width`);
  }
  assert.ok(subtotal <= 4_000, `native subtotal: ${subtotal}/4000`);
});
