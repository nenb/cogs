import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const workflowPath = join(process.cwd(), ".github/workflows/outcome-two-runner-capability.yml");

async function workflowSource(): Promise<string> {
  return readFile(workflowPath, "utf8");
}

test("runner capability workflow is an exact three-step, attempt-one observation", async () => {
  const workflow = await workflowSource();

  assert.match(workflow, /^on:\n {2}pull_request:\n {4}types: \[labeled\]$/mu);
  assert.match(workflow, /^permissions:\n {2}contents: read$/mu);
  assert.match(workflow, /^ {2}runner-capability-probe:$/mu);
  assert.equal(workflow.match(/^ {2}[a-z][a-z0-9-]+:\n/gmu)?.length, 1);
  assert.match(workflow, /github\.run_attempt == 1/u);
  assert.match(workflow, /github\.repository == 'nenb\/cogs'/u);
  assert.match(workflow, /github\.event\.label\.name == 'outcome-two-runner-capability'/u);
  assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /timeout-minutes: 3/u);
  assert.match(workflow, /^concurrency:\n[\s\S]*pull_request\.number[\s\S]*cancel-in-progress: false$/mu);

  assert.equal(workflow.match(/^ {6}- name:/gmu)?.length, 3, "the gate must have exactly three steps");
  const checkout = workflow.indexOf("uses: actions/checkout@");
  const gate = workflow.indexOf("git cat-file blob");
  const driver = workflow.indexOf("--workflow-bound");
  assert.ok(checkout >= 0 && checkout < gate && gate < driver, "checkout, fixed gate, and driver order changed");
  assert.equal(workflow.match(/^\s+uses:/gmu)?.length, 1);
  assert.match(workflow, /actions\/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7\.0\.0/u);
  assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u);
  assert.match(workflow, /persist-credentials: false/u);
});

test("fixed shell gate proves head, clean checkout, credentials, and three blob digests", async () => {
  const workflow = await workflowSource();

  assert.match(workflow, /git rev-parse (?:--verify )?HEAD/u);
  assert.match(workflow, /\^\[0-9a-f\]\{40\}\$/u);
  assert.match(workflow, /git status --porcelain(?:=v1)? --untracked-files=all/u);
  assert.match(workflow, /git config[^\n]+credential/u);
  assert.match(workflow, /extraheader/iu);
  assert.match(workflow, /git remote get-url --all origin/u);
  assert.match(workflow, /git cat-file blob/u);
  assert.match(workflow, /\/usr\/bin\/sha256sum/u);
  for (const path of [
    "scripts/runner-capability-probe.py",
    "schemas/runner-capability-probe-v1alpha1.json",
    ".github/workflows/outcome-two-runner-capability.yml",
  ]) {
    assert.ok(workflow.split(path).length >= 2, `${path} is not checked against its source-head blob`);
  }
  for (const digest of ["DRIVER_SHA256", "SCHEMA_SHA256", "SOURCE_HEAD_WORKFLOW_BLOB_SHA256"]) {
    assert.match(workflow, new RegExp(digest, "u"));
  }
});

test("driver receives only workflow-bound public controls and no report artifact", async () => {
  const workflow = await workflowSource();

  assert.match(
    workflow,
    /\/usr\/bin\/env -i[\s\S]*\/usr\/bin\/python3 -I -B scripts\/runner-capability-probe\.py --workflow-bound/u,
  );
  assert.equal(workflow.match(/\/usr\/bin\/python3/gmu)?.length, 1);
  const controlKeys =
    "REPOSITORY WORKFLOW JOB EVENT ACTION RUN_ID RUN_ATTEMPT PULL_REQUEST_NUMBER PR_HEAD_REPOSITORY PR_HEAD_SHA CHECKOUT_SHA BASE_SHA GITHUB_SHA GITHUB_WORKFLOW_SHA EVENT_MERGE_SHA IMAGE_OS IMAGE_VERSION RUNNER_ARCH RUNNER_ENVIRONMENT DRIVER_SHA256 SCHEMA_SHA256 SOURCE_HEAD_WORKFLOW_BLOB_SHA256".split(
      " ",
    );
  assert.deepEqual(
    [...workflow.matchAll(/\b(COGS_CAP_[A-Z0-9_]+)=/gu)].map((match) => match[1]),
    controlKeys.map((key) => `COGS_CAP_${key}`),
  );
  for (const control of [
    "github.repository",
    "github.event.action",
    "github.run_id",
    "github.run_attempt",
    "github.event.pull_request.number",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.base.sha",
    "github.sha",
    "github.workflow_sha",
    "github.event.pull_request.merge_commit_sha",
    "ImageOS",
    "ImageVersion",
    "RUNNER_ARCH",
    "RUNNER_ENVIRONMENT",
  ]) {
    assert.match(workflow, new RegExp(control.replaceAll(".", "\\."), "u"), `${control} is not bound`);
  }
  assert.doesNotMatch(
    workflow,
    /workflow_dispatch|workflow_call|schedule:|\bpush:|secrets\.|github\.token|GITHUB_TOKEN/u,
  );
  assert.doesNotMatch(workflow, /^\s*(?:services|container):|^\s+needs:|continue-on-error:|always\(\)/mu);
  assert.doesNotMatch(workflow, /setup-|\bcache:|npm\s|npx\s|pip\s|apt(?:-get)?\s|curl\s|wget\s|docker\s|podman\s/u);
  assert.doesNotMatch(workflow, /upload|download|artifact|step-summary|\bvalidate\b|--version|\/bin\/cat/u);
  assert.doesNotMatch(workflow, /python3[^\n]*(?:\s-c\b|<<)|GITHUB_WORKSPACE|RUNNER_TEMP|PATH=|HOME=/u);
});
