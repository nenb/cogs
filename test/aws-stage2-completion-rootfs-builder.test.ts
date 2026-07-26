import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_builder.py");
const testPath = join(root, "test/aws-stage2-completion-rootfs-builder.py");
const nativeInvokerPath = join(root, "test/aws-stage2-completion-rootfs-builder-native.py");
const workflowRelativePath = ".github/workflows/ci.yml";
const workflowPath = join(root, workflowRelativePath);

test("D-R2.2c exposes only fixed recover-owned and keeps bootstrap private", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs builder portable tests passed/u);

  const source = await readFile(modulePath, "utf8");
  assert.match(source, /argv != \["recover-owned"\]/u);
  assert.match(source, /RECOVER_SECONDS = 600/u);
  assert.match(source, /LOCK_EX \| fcntl\.LOCK_NB/u);
  assert.doesNotMatch(source, /rmtree|os\.walk|glob|subprocess|socket|os\.environ|os\.getenv|argparse/u);
  assert.doesNotMatch(source, /boto3?|terraform|requests|urllib/u);

  const trackedWorkflow = spawnSync("git", ["ls-files", "--error-unmatch", workflowRelativePath], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(trackedWorkflow.status, 0, trackedWorkflow.stderr);
  const workflow = await readFile(workflowPath, "utf8");
  const qualityStart = workflow.indexOf("  quality:\n");
  const qualityEnd = workflow.indexOf("  secret-scan:\n");
  assert.ok(qualityStart >= 0 && qualityEnd > qualityStart);
  const quality = workflow.slice(qualityStart, qualityEnd);
  assert.match(quality, /^ {2}quality:\n[\s\S]*?^ {4}runs-on: ubuntu-24\.04$/mu);
  assert.equal(quality.match(/^ {4}runs-on:/gmu)?.length, 1);
  assert.match(quality, /^ {8}uses: actions\/checkout@[0-9a-f]{40}(?: # .+)?$/mu);
  assert.match(quality, /^ {10}persist-credentials: false$/mu);
  assert.match(
    quality,
    /^ {10}ref: \$\{\{ github\.event_name == 'pull_request' && github\.event\.pull_request\.head\.repo\.full_name == github\.repository && github\.event\.pull_request\.head\.sha \|\| '' \}\}$/mu,
  );
  const sameRepositoryCondition =
    "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository";
  assert.equal(quality.split(sameRepositoryCondition).length - 1, 3);
  const verification = quality.indexOf("- name: Verify exact same-repository pull request head");
  const setup = quality.indexOf("- name: Set up Node.js");
  const tests = quality.indexOf("run: npm test");
  const upload = quality.indexOf("- name: Upload validated guest probe");
  const c1 = quality.indexOf("- name: Observe workflow-bound native C1 gate");
  assert.ok(verification > quality.indexOf("uses: actions/checkout@"));
  assert.ok(setup > verification && tests > setup && c1 > tests && c1 > upload);
  assert.match(quality, /test "\$EXPECTED_HEAD_REPOSITORY" = "\$EXPECTED_REPOSITORY"/u);
  assert.match(quality, /\[\[ "\$EXPECTED_HEAD_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/u);
  assert.match(quality, /test "\$\(\/usr\/bin\/git rev-parse --verify HEAD\)" = "\$EXPECTED_HEAD_SHA"/u);
  assert.match(
    quality,
    /^ {8}run: \/usr\/bin\/python3 -I test\/aws-stage2-completion-rootfs-builder-native\.py --workflow-bound$/mu,
  );
  assert.match(quality, /COGS_C1_EXPECTED_ENVELOPE_SHA: \$\{\{ github\.sha \}\}/u);
  assert.match(quality, /COGS_C1_EXPECTED_EVENT_MERGE_SHA: \$\{\{ github\.event\.pull_request\.merge_commit_sha \}\}/u);
  assert.match(quality, /COGS_C1_EXPECTED_HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u);
  assert.match(quality, /COGS_C1_EXPECTED_WORKFLOW_SHA: \$\{\{ github\.workflow_sha \}\}/u);
  assert.match(
    quality,
    /COGS_C1_EXPECTED_WORKFLOW_BLOB_DIGEST: \$\{\{ hashFiles\('\.github\/workflows\/ci\.yml'\) \}\}/u,
  );
  assert.doesNotMatch(quality.slice(c1), /sudo|docker|container|unshare|nsenter/u);
  assert.doesNotMatch(quality, /^ {4}(?:container|services|strategy):|uses: docker:\/\//mu);

  const nativeInvoker = await readFile(nativeInvokerPath, "utf8");
  assert.match(nativeInvoker, /os\.geteuid\(\) != 0/u);
  assert.match(nativeInvoker, /\/usr\/bin\/sudo/u);
  assert.match(nativeInvoker, /NAMESPACES = \("pid", "mnt", "user", "cgroup"\)/u);
  assert.match(nativeInvoker, /validate_revision_domains/u);
  assert.match(nativeInvoker, /validate_synthetic_context/u);
  assert.match(nativeInvoker, /"classification": "observation-only"/u);
  assert.match(nativeInvoker, /"envelope_sha": expected\["envelope_sha"\]/u);
  assert.match(nativeInvoker, /"event_merge_sha": expected\["event_merge_sha"\]/u);
  assert.match(nativeInvoker, /envelope_sha == github_sha/u);
  assert.match(nativeInvoker, /event_merge_sha == event_payload_merge_sha/u);
  assert.doesNotMatch(nativeInvoker, /envelope_sha == event_merge_sha/u);
  assert.match(nativeInvoker, /"workflow_blob_digest"/u);
  assert.doesNotMatch(nativeInvoker, /native-host|native-qualified|external_authority/u);
  assert.doesNotMatch(nativeInvokerPath, /\.test\.ts$/u);

  const portable = spawnSync("python3", [nativeInvokerPath, "--portable-tests"], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(portable.status, 0, portable.stderr);
  assert.match(portable.stdout, /envelope\/source domain portable tests passed/u);

  const local = spawnSync("python3", [nativeInvokerPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(local.status, 0, local.stderr);
  assert.deepEqual(JSON.parse(local.stdout), {
    classification: "observation-only",
    context: "local-manual",
    local_values: { classification: "observation-only", status: "not-collected" },
    workflow_authority: "unavailable",
  });
});
