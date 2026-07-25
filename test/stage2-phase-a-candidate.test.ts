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
const schemaPath = join(root, "schemas/stage2-phase-a-candidate-v1.json");
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
  assert.match(workflow, /path: \/var\/tmp\/cogs-stage2-phase-a-candidate-v1\/candidate\.json/u);
  assert.match(workflow, /run-stage2-phase-a-candidate\.py cleanup-export/u);
  assert.doesNotMatch(workflow, /path: \/var\/lib\/cogs\/stage2-completion-v1\/source/u);
  assert.doesNotMatch(workflow, /workflow_dispatch|schedule:|\bpush:|setup-node|npm|node_modules/u);
  assert.doesNotMatch(workflow, /apt(?:-get)?|dnf|yum|apk|brew|snap|dpkg|systemctl/u);
  assert.doesNotMatch(workflow, /configure-aws-credentials|opentofu|terraform|tofu|workflow_call/u);
  assert.doesNotMatch(workflow, /cancel-in-progress: true/u);
});

test("candidate output schema enforces metadata-only non-authority", async () => {
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  const report = {
    version: "cogs.stage2-phase-a-candidate/v1",
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
    runtime_assets: [],
    host_tools: [],
    kvm: { device_present: true, device_accessible: true, api_version: 12 },
    claims: { runtime: false, network: false, ssh: false, coordinator_invoked: false },
    diagnostic_codes: [],
  };
  assert.equal(validate(report), true, ajv.errorsText(validate.errors));
  assert.equal(validate({ ...report, qualified: true }), false);
  assert.equal(validate({ ...report, claims: { ...report.claims, runtime: true } }), false);
  assert.equal(validate({ ...report, archive_bytes: "forbidden" }), false);

  const runner = await readFile(runnerPath, "utf8");
  assert.doesNotMatch(runner, /\b(?:apt-get|apt|dnf|yum|apk|brew|systemctl)\b/u);
  assert.doesNotMatch(runner, /completion_kata_coordinator|extractall|\.extract\(/u);
  assert.doesNotMatch(runner, /subprocess\.run\([^)]*PIPE/su);
  assert.match(
    runner,
    /first_token = secrets\.token_hex\(32\)[\s\S]*second_token = secrets\.token_hex\(32\)[\s\S]*first_token != second_token[\s\S]*first = _candidate_build\(build, approval, control, "first", first_token\)[\s\S]*second = _candidate_build\(build, approval, control, "second", second_token\)/u,
  );
  assert.doesNotMatch(runner, /build\._two_build_outputs/u);
  assert.match(runner, /build\._require_equal_builds\(first, second\)/u);
  assert.match(runner, /type\(token\) is str and HEX\.fullmatch\(token\) is not None/u);
  assert.match(runner, /elapsed >= build\.BUILD_SECONDS/u);
  assert.match(runner, /ROOTFS_RECOVERY_ATTEMPTS = 3/u);
  assert.match(runner, /rootfs-recovery-exhausted/u);
  assert.match(runner, /rootfs-foundation-uncertainty/u);
  assert.match(runner, /asset-cleanup-uncertainty/u);
  assert.match(runner, /cache-cleanup-uncertainty/u);
  assert.match(runner, /import completion_rootfs_publish\n/u);
  assert.doesNotMatch(runner, /import completion_rootfs_publication/u);
  assert.match(runner, /ownership\.jsonl/u);
  assert.match(runner, /\.cogs-stage2-phase-a-anchor-v1\.json/u);
  assert.match(runner, /include_size=False, include_nlink=False/u);
  assert.match(runner, /_same_rootfs_lifecycle\(_snapshot_rootfs_lifecycle\(\), rootfs_owned\)/u);
  assert.match(runner, /_same_directory_authority\(os\.fstat\(root\), lifecycle\["root"\]\)/u);
  assert.match(runner, /_verify_fixed_source\(anchor\["source_revision"\], anchor\["source_manifest_sha256"\]\)/u);
  assert.match(runner, /authority": "candidate"/u);
  assert.match(runner, /"qualified": False/u);
});
