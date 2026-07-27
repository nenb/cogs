import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const workflowPath = join(process.cwd(), ".github/workflows/outcome-two-runner-capability.yml");

async function workflowSource(): Promise<string> {
  return readFile(workflowPath, "utf8");
}

function occurrences(source: string, value: string): number {
  return source.split(value).length - 1;
}

function assertWorkflow(workflow: string): void {
  assert.match(workflow, /^on:\n {2}pull_request:\n {4}types: \[labeled\]$/mu);
  assert.match(workflow, /^permissions:\n {2}contents: read$/mu);
  const jobs = workflow.slice(workflow.indexOf("jobs:\n") + "jobs:\n".length);
  assert.deepEqual(jobs.match(/^ {2}[a-z0-9_-]+:\n/gmu), ["  runner-capability-probe:\n"]);
  assert.match(workflow, /github\.run_attempt == 1/u);
  assert.match(workflow, /github\.repository == 'nenb\/cogs'/u);
  assert.match(workflow, /github\.event\.label\.name == 'outcome-two-runner-capability'/u);
  assert.match(workflow, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /timeout-minutes: 3/u);
  assert.match(workflow, /^concurrency:\n[\s\S]*pull_request\.number[\s\S]*cancel-in-progress: false$/mu);

  const actualSteps = workflow.match(/^ {6}-(?:\s|$)/gmu) ?? [];
  assert.equal(actualSteps.length, 3, "workflow must contain exactly three actual step entries");
  assert.equal(workflow.match(/^ {6}- name:/gmu)?.length, 3, "all three fixed steps must remain named");
  const checkout = workflow.indexOf("uses: actions/checkout@");
  const gate = workflow.indexOf("git cat-file blob");
  const driver = workflow.indexOf("--workflow-bound");
  assert.ok(checkout >= 0 && checkout < gate && gate < driver, "checkout, gate, and driver order changed");
  assert.equal(workflow.match(/^\s+uses:/gmu)?.length, 1);
  assert.match(workflow, /actions\/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7\.0\.0/u);
  assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u);
  assert.match(workflow, /persist-credentials: false/u);

  assert.match(workflow, /git rev-parse (?:--verify )?HEAD/u);
  assert.match(workflow, /\^\[0-9a-f\]\{40\}\$/u);
  assert.match(workflow, /git status --porcelain(?:=v1)? --untracked-files=all/u);
  assert.equal(occurrences(workflow, "/usr/bin/git remote get-url --all origin 2>/dev/null"), 1);
  assert.equal(occurrences(workflow, "/usr/bin/git remote get-url --push --all origin 2>/dev/null"), 1);
  for (const kind of ["fetch", "push"]) {
    assert.match(workflow, new RegExp(`case "\\$${kind}_url" in \\*:\\/\\/\\*@\\*\\) exit 1`, "u"));
    assert.match(workflow, new RegExp(`test "\\$${kind}_url" = "\\$expected_url"`, "u"));
  }
  assert.match(workflow, /git config --name-only --get-regexp "\$1" >\/dev\/null 2>&1/u);
  assert.match(workflow, /reject_git_config '\^credential\(\\\.\.\*\)\?\\\.helper\$'/u);
  assert.match(workflow, /reject_git_config '\^http\(\\\.\.\*\)\?\\\.extraheader\$'/u);
  assert.doesNotMatch(workflow, /(?:echo|printf)[^\n]*(?:\$(?:fetch|push)_url|expected_url)/u);
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

  assert.match(
    workflow,
    /\/usr\/bin\/env -i[\s\S]*\/usr\/bin\/python3 -I -B scripts\/runner-capability-probe\.py --workflow-bound/u,
  );
  assert.equal(occurrences(workflow, "/usr/bin/env -i"), 1);
  assert.equal(occurrences(workflow, "/usr/bin/python3"), 1);
  assert.equal(occurrences(workflow, "scripts/runner-capability-probe.py --workflow-bound"), 1);
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
}

function rejectMutation(workflow: string, from: string, to: string): void {
  assert.ok(workflow.includes(from), `mutation source is absent: ${from}`);
  assert.throws(() => assertWorkflow(workflow.replace(from, to)));
}

test("runner capability workflow preserves its complete static contract", async () => {
  assertWorkflow(await workflowSource());
});

test("hostile static mutations cannot bypass steps, URL, credential, or output gates", async () => {
  const workflow = await workflowSource();
  rejectMutation(workflow, "      - name: Emit", "      - run: /bin/true\n\n      - name: Emit");
  rejectMutation(
    workflow,
    "/usr/bin/git remote get-url --push --all origin 2>/dev/null",
    "/usr/bin/git remote get-url --all origin 2>/dev/null",
  );
  rejectMutation(workflow, 'case "$fetch_url" in *://*@*) exit 1', 'case "$fetch_url" in never) exit 1');
  rejectMutation(workflow, "^credential(\\..*)?\\.helper$", "^credential\\.helper$");
  rejectMutation(workflow, "^http(\\..*)?\\.extraheader$", "^http\\..*\\.extraheader$");
  rejectMutation(
    workflow,
    'test "$push_url" = "$expected_url"',
    'echo "$push_url"\n          test "$push_url" = "$expected_url"',
  );
  rejectMutation(workflow, "/usr/bin/env -i", "/usr/bin/env");
  rejectMutation(
    workflow,
    "</dev/null",
    "</dev/null\n      - uses: actions/upload-artifact@0000000000000000000000000000000000000000",
  );
});
