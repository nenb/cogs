import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();
const workflowPath = join(root, ".github/workflows/stage2-phase-a-candidate.yml");
const runnerPath = join(root, "scripts/run-stage2-phase-a-candidate.py");
const budgetPath = join(root, "scripts/stage2-phase-a-budget.py");
const schemaV1Path = join(root, "schemas/stage2-phase-a-candidate-v1.json");
const schemaV2Path = join(root, "schemas/stage2-phase-a-candidate-v2.json");
const phaseGraphFixturePath = join(root, "test/fixtures/stage2-phase-a-v2-phase-graphs.json");
const pythonTest = join(root, "test/stage2-phase-a-candidate.py");

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

test("Phase A pure downloader, KVM ioctl, and non-authority policies", () => {
  const result = spawnSync("python3", [pythonTest], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 20_000,
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /stage2 phase-a candidate portable tests passed/u);
});

test("Phase A workflow is exact-head, same-repository, PR-only, and package-mutation-free", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /^on:\n {2}pull_request:/mu);
  assert.match(workflow, /contains\(github\.event\.pull_request\.labels\.\*\.name, 'security'\)/u);
  assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /timeout-minutes: 90/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.ok(
    workflow.indexOf("Establish scheduling-only monotonic budget anchor") <
      workflow.indexOf("Check out exact pull request head"),
  );
  assert.match(workflow, /stage2-phase-a-budget\.py timeout source[\s\S]*stage2-phase-a-budget\.py check source/u);
  assert.match(workflow, /stage2-phase-a-budget\.py timeout observe[\s\S]*stage2-phase-a-budget\.py check observe/u);
  assert.match(workflow, /stage2-phase-a-budget\.py timeout cleanup[\s\S]*stage2-phase-a-budget\.py check cleanup/u);
  for (const boundary of ["residue", "render", "validate", "export", "export-cleanup", "post-export-residue"]) {
    assert.match(workflow, new RegExp(`stage2-phase-a-budget\\.py timeout ${boundary}`, "u"));
  }
  assert.match(workflow, /stage2-phase-a-budget\.py check upload/u);
  assert.match(workflow, /stage2-phase-a-budget\.py check post-export-residue-start/u);
  assert.match(workflow, /timeout-minutes: 1[\s\S]*actions\/upload-artifact@/u);
  assert.match(workflow, /stage2-phase-a-budget\.py check final/u);
  assert.match(workflow, /--kill-after=5s/u);
  assert.match(workflow, /permissions:\n {2}contents: read/u);
  assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u);
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /prepare-stage2-fixed-source\.py[\s\S]*result\["revision"\]!=sys\.argv\[1\]/u);
  assert.match(workflow, /EXACT_PR_HEAD: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u);
  assert.match(workflow, /prepare-stage2-fixed-source\.py[\s\S]*run-stage2-phase-a-candidate\.py observe/u);
  assert.match(workflow, /if: always\(\)[\s\S]*run-stage2-phase-a-candidate\.py cleanup/u);
  assert.match(workflow, /run-stage2-phase-a-candidate\.py residue/u);
  assert.match(workflow, /actions\/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0/u);
  assert.match(workflow, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/u);
  assert.match(workflow, /steps\.validate\.outcome == 'success' && steps\.export\.outcome == 'success'/u);
  assert.match(workflow, /path: \/var\/tmp\/cogs-stage2-phase-a-candidate-v2\/candidate\.json/u);
  assert.match(workflow, /run-stage2-phase-a-candidate\.py cleanup-export/u);
  assert.match(workflow, /run-stage2-phase-a-candidate\.py post-export-residue/u);
  assert.ok(
    workflow.indexOf("Upload validated staged candidate JSON only") <
      workflow.indexOf("Exact-identity cleanup of exported report") &&
      workflow.indexOf("Exact-identity cleanup of exported report") <
        workflow.indexOf("Independent read-only post-export-cleanup residue observation") &&
      workflow.indexOf("Independent read-only post-export-cleanup residue observation") <
        workflow.indexOf("Enforce observation"),
  );
  assert.match(workflow, /POST_EXPORT_RESIDUE_OUTCOME[\s\S]*test "\$POST_EXPORT_RESIDUE_OUTCOME" = success/u);
  assert.doesNotMatch(workflow, /path: \/var\/lib\/cogs\/stage2-completion-v1\/source/u);
  assert.doesNotMatch(workflow, /workflow_dispatch|schedule:|\bpush:|setup-node|npm|node_modules/u);
  assert.doesNotMatch(workflow, /apt(?:-get)?|dnf|yum|apk|brew|snap|dpkg|systemctl/u);
  assert.doesNotMatch(workflow, /configure-aws-credentials|opentofu|terraform|tofu|workflow_call/u);
  assert.doesNotMatch(workflow, /cancel-in-progress: true/u);
});

test("historical Phase A v1 schema remains immutable and validates v1 reports only", async () => {
  const v1Raw = await readFile(schemaV1Path, "utf8");
  const committed = spawnSync("git", ["show", "HEAD:schemas/stage2-phase-a-candidate-v1.json"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(committed.status, 0, committed.stderr);
  assert.equal(v1Raw, committed.stdout);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validateV1 = ajv.compile(JSON.parse(v1Raw));
  const v1 = {
    version: "cogs.stage2-phase-a-candidate/v1",
    authority: "candidate",
    qualified: false,
    source_revision: null,
    source_manifest_sha256: null,
    duration_ms: 0,
    blockers: ["observe-uncertainty"],
    checks: {
      platform: "fail",
      root: "fail",
      source: "fail",
      kvm: "unknown",
      artifact_cache: "unknown",
      rootfs_candidates: "unknown",
      runtime_assets: "unknown",
      host_tools: "unknown",
      cleanup: "unknown",
      residue: "unknown",
    },
    rootfs: null,
    rootfs_builds: {
      first: { outcome: "blocked", work_outcome: "blocked", total_elapsed_ms: 0 },
      second: { outcome: "blocked", work_outcome: "blocked", total_elapsed_ms: 0 },
    },
    recovery_attempts: [],
    runtime_assets: [],
    host_tools: [],
    kvm: { device_present: false, device_accessible: false, api_version: null },
    claims: { runtime: false, network: false, ssh: false, coordinator_invoked: false },
    diagnostic_codes: [],
  };
  assert.equal(validateV1(v1), true, ajv.errorsText(validateV1.errors));
});

test("candidate output schema enforces metadata-only non-authority", async () => {
  const schema = JSON.parse(await readFile(schemaV2Path, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  const report = {
    version: "cogs.stage2-phase-a-candidate/v2",
    authority: "candidate",
    qualified: false,
    source_revision: "a".repeat(40),
    source_manifest_sha256: "b".repeat(64),
    duration_ms: 1,
    blockers: ["runtime-extraction-unsafe-or-unknown"],
    checks: {
      platform: "pass",
      root: "pass",
      source: "pass",
      kvm: "pass",
      artifact_cache: "pass",
      rootfs_candidates: "pass",
      runtime_assets: "pass",
      host_tools: "blocked",
      cleanup: "pass",
      residue: "pass",
    },
    rootfs: {
      candidate_count: 2,
      cache_count: 16,
      entry_count: 4353,
      manifest_size: 1049443,
      manifest_sha256: "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691",
      ustar_size: 136905728,
      ustar_sha256: "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3",
      equal: true,
      pins_match: true,
    },
    rootfs_phases: [
      "first-build-work",
      "first-inline-cleanup",
      "second-build-work",
      "second-inline-cleanup",
      "recovery-attempt-1",
      "equality",
      "pin",
      "post-verification",
      "settlement",
    ].map((phase) => ({
      phase,
      status: "success",
      outcome: "success",
      elapsed_ms: 1,
      structural_counters: {
        record_reference_copies: 0,
        byte_names_returned: 1,
        parent_snapshots: 2,
        complete_legal_record_folds: 3,
        complete_filesystem_walks: 4,
        incrementally_advanced_ledger_records: 5,
      },
    })),
    runtime_assets: [],
    host_tools: [],
    kvm: { device_present: true, device_accessible: true, api_version: 12 },
    claims: { runtime: false, network: false, ssh: false, coordinator_invoked: false },
    diagnostic_codes: [],
  };
  assert.equal(validate(report), true, ajv.errorsText(validate.errors));
  const fixture = JSON.parse(await readFile(phaseGraphFixturePath, "utf8")) as {
    version: string;
    valid: Array<{ statuses: string[]; rootfs: boolean }>;
  };
  assert.equal(fixture.version, "cogs.stage2-phase-a-phase-graph-fixtures/v1");
  const validGraphs = new Set(fixture.valid.map((item) => JSON.stringify([item.statuses, item.rootfs])));
  const counters = report.rootfs_phases[0]?.structural_counters;
  assert.ok(counters);
  const allowedOutcomes: Record<string, ReadonlySet<string>> = {
    success: new Set(["success"]),
    failure: new Set(["failed", "cancelled", "deadline", "not-started", "postwork", "over-bound"]),
    blocked: new Set(["prerequisite-failed"]),
    "not-reached": new Set(["observer-ended"]),
  };
  const allOutcomes = new Set(Object.values(allowedOutcomes).flatMap((values) => [...values]));
  const outcomes = Object.fromEntries(
    Object.entries(allowedOutcomes).map(([status, values]) => [status, [...values][0]]),
  ) as Record<string, string>;
  const graphReport = (statuses: string[], hasRootfs: boolean) => ({
    ...report,
    rootfs: hasRootfs ? report.rootfs : null,
    rootfs_phases: report.rootfs_phases.map((row, index) => ({
      ...row,
      status: statuses[index],
      outcome: outcomes[statuses[index] ?? ""] ?? "invalid",
      elapsed_ms: statuses[index] === "success" || statuses[index] === "failure" ? 1 : 0,
      structural_counters: statuses[index] === "success" || statuses[index] === "failure" ? counters : null,
    })),
  });
  for (const item of fixture.valid) {
    assert.equal(validate(graphReport(item.statuses, item.rootfs)), true, ajv.errorsText(validate.errors));
    for (const [index, current] of item.statuses.entries()) {
      for (const replacement of ["success", "failure", "blocked", "not-reached"]) {
        if (replacement === current) continue;
        const changed = item.statuses.with(index, replacement);
        const expected = validGraphs.has(JSON.stringify([changed, item.rootfs]));
        assert.equal(validate(graphReport(changed, item.rootfs)), expected, `${changed.join(",")}/${item.rootfs}`);
      }
    }
    assert.equal(validate(graphReport(item.statuses, !item.rootfs)), false);
    for (const [index, status] of item.statuses.entries()) {
      for (const outcome of allOutcomes) {
        const candidate = graphReport(item.statuses, item.rootfs);
        const row = candidate.rootfs_phases[index];
        assert.ok(row);
        candidate.rootfs_phases[index] = { ...row, outcome };
        assert.equal(
          validate(candidate),
          allowedOutcomes[status]?.has(outcome) === true,
          `${status}/${outcome}/${item.statuses.join(",")}`,
        );
      }
    }
  }
  assert.equal(validate({ ...report, qualified: true }), false);
  assert.equal(validate({ ...report, claims: { ...report.claims, runtime: true } }), false);
  const hostilePhases = [
    report.rootfs_phases.slice(0, 8),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, phase: "second-build-work" } : row)),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, status: "failure", outcome: "success" } : row)),
    report.rootfs_phases.map((row, index) =>
      index === 1 ? { ...row, status: "blocked", outcome: "prerequisite-failed", elapsed_ms: 1 } : row,
    ),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, status: "failure", outcome: "deadline" } : row)),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, structural_counters: null } : row)),
    report.rootfs_phases.map((row, index) =>
      index === 1 ? { ...row, status: "blocked", outcome: "prerequisite-failed", elapsed_ms: 0 } : row,
    ),
    report.rootfs_phases.map((row, index) =>
      index === 2
        ? {
            ...row,
            structural_counters: {
              record_reference_copies: 0,
              byte_names_returned: true,
              parent_snapshots: 0,
              complete_legal_record_folds: 0,
              complete_filesystem_walks: 0,
              incrementally_advanced_ledger_records: 0,
            },
          }
        : row,
    ),
  ];
  for (const rootfs_phases of hostilePhases) assert.equal(validate({ ...report, rootfs_phases }), false);
  assert.equal(validate({ ...report, archive_bytes: "forbidden" }), false);

  const [runner, budget] = await Promise.all([readFile(runnerPath, "utf8"), readFile(budgetPath, "utf8")]);
  assert.doesNotMatch(runner, /\b(?:apt-get|apt|dnf|yum|apk|brew|systemctl)\b/u);
  assert.doesNotMatch(runner, /completion_kata_coordinator|extractall|\.extract\(/u);
  assert.doesNotMatch(runner, /subprocess\.run\([^)]*PIPE/su);
  assert.match(
    runner,
    /first_token = secrets\.token_hex\(32\)[\s\S]*second_token = secrets\.token_hex\(32\)[\s\S]*first_token != second_token[\s\S]*first = _candidate_build\(build, approval, control, "first", first_token, phases\)[\s\S]*second = _candidate_build\(build, approval, control, "second", second_token, phases\)/u,
  );
  assert.doesNotMatch(runner, /build\._two_build_outputs/u);
  assert.match(runner, /build\._require_equal_builds\(first, second\)/u);
  assert.match(runner, /type\(token\) is str and HEX\.fullmatch\(token\) is not None/u);
  assert.doesNotMatch(runner, /elapsed_ms >= build\.BUILD_SECONDS \* 1000|time\.monotonic\(\)/u);
  assert.match(runner, /total_elapsed_ns - cleanup_span_ns/u);
  const candidateBuild = runner.slice(
    runner.indexOf("def _candidate_build"),
    runner.indexOf("def _timed_rootfs_phase"),
  );
  const timedCleanup = candidateBuild.slice(candidateBuild.indexOf("def timed_cleanup"));
  assert.match(
    timedCleanup,
    /span_started = time\.monotonic_ns\(\)[\s\S]*ticket = _counter_start\(build, cleanup_name\)[\s\S]*callback\(\*args\)[\s\S]*_counter_read\(ticket\)[\s\S]*span_elapsed = _elapsed_ns\(span_started\)/u,
  );
  assert.match(candidateBuild, /work_counters = _subtract_counters\(work_total, cleanup_counters\)/u);
  assert.match(runner, /all\(subtrahend\[name\] <= minuend\[name\] for name in STRUCTURAL_COUNTERS\)/u);
  assert.doesNotMatch(
    candidateBuild.slice(0, candidateBuild.indexOf("def timed_cleanup")),
    /_counter_start\(build, cleanup_name\)/u,
  );
  assert.match(runner, /ROOTFS_PHASES = \([\s\S]*"settlement"/u);
  assert.match(runner, /_start_phase_structural_counters/u);
  assert.match(runner, /_read_phase_structural_counters/u);
  assert.match(runner, /type\(provider\) is type\(sys\)/u);
  assert.match(runner, /type\(item\) is int and 0 <= item <= 1_000_000_000/u);
  const finalResidue = runner.slice(
    runner.indexOf("def _post_export_residue"),
    runner.indexOf("def main", runner.indexOf("def _post_export_residue")),
  );
  for (const path of ["ROOTFS_STATE", "ARTIFACT_ROOT", "ASSETS", "STATE", "ANCHOR", "EXPORT_ROOT"]) {
    assert.match(finalResidue, new RegExp(`\\(${path},`, "u"));
  }
  assert.doesNotMatch(
    finalResidue,
    /os\.(?:unlink|rmdir|mkdir|write)|_cleanup|_write|lexists|_fixed_preflight|_source_approval|_verify_fixed_source/u,
  );
  assert.match(finalResidue, /_held_path_absent/u);
  assert.match(runner, /remaining_ns \/\/ NS_PER_SECOND/u);
  assert.doesNotMatch(runner, /outer_deadline_ns \/ 1_000_000_000/u);
  assert.match(runner, /OBSERVE_SECONDS = 3300/u);
  assert.match(runner, /ROOTFS_RECOVERY_ATTEMPTS = 1/u);
  assert.match(runner, /rootfs-recovery-exhausted/u);
  assert.match(runner, /rootfs-foundation-uncertainty/u);
  assert.match(runner, /asset-cleanup-uncertainty/u);
  assert.match(runner, /cache-cleanup-uncertainty/u);
  assert.match(runner, /import completion_rootfs_publish\n/u);
  assert.doesNotMatch(runner, /import completion_rootfs_publication/u);
  assert.match(runner, /ownership\.jsonl/u);
  assert.match(runner, /\.cogs-stage2-phase-a-anchor-v2\.json/u);
  assert.match(runner, /include_size=False, include_nlink=False/u);
  assert.match(runner, /_same_rootfs_lifecycle\(_snapshot_rootfs_lifecycle\(\), rootfs_owned\)/u);
  assert.match(runner, /_same_directory_authority\(os\.fstat\(root\), lifecycle\["root"\]\)/u);
  assert.match(runner, /_verify_fixed_source\(anchor\["source_revision"\], anchor\["source_manifest_sha256"\]\)/u);
  assert.match(runner, /VERSION = "cogs\.stage2-phase-a-candidate\/v2"/u);
  assert.doesNotMatch(runner, /cogs\.stage2-phase-a-candidate\/v1|phase-a-candidate-v1/u);
  assert.match(runner, /authority": "candidate"/u);
  assert.match(runner, /"qualified": False/u);
  assert.doesNotMatch(runner, /COGS_STAGE2_PHASE_A_BUDGET_ANCHOR_NS/u);
  assert.match(
    budget,
    /"cleanup": 5100,[\s\S]*"residue": 5160,[\s\S]*"upload": 5290,[\s\S]*"export-cleanup": 5380,[\s\S]*"post-export-residue-start": 5380,[\s\S]*"post-export-residue": 5400,[\s\S]*"final": 5400/u,
  );
  assert.match(budget, /Scheduling-only monotonic guards/u);
});
