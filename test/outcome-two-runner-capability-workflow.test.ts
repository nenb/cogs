import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const workflowPath = join(process.cwd(), ".github/workflows/outcome-two-runner-capability.yml");

test("runner capability workflow is a bounded same-repository exact-head observation", async () => {
  const workflow = await readFile(workflowPath, "utf8");

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

  assert.match(
    workflow,
    /uses: actions\/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7\.0\.0/u,
  );
  assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u);
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /test "\$\(\/usr\/bin\/git rev-parse HEAD\)" = "\$EXPECTED_HEAD_SHA"/u);
  assert.equal(workflow.match(/^\s+uses:/gmu)?.length, 1);
});

test("runner capability workflow emits exactly one validated authority-none report", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  const probe = '"$GITHUB_WORKSPACE/scripts/runner-capability-probe.py"';

  assert.equal(workflow.split(probe).length - 1, 2);
  assert.match(workflow, /env -i \/usr\/bin\/timeout --signal=TERM --kill-after=5s 120s/u);
  assert.match(workflow, /\/usr\/bin\/python3 -I [^\n]+runner-capability-probe\.py" run/u);
  assert.match(workflow, /--workflow \.github\/workflows\/outcome-two-runner-capability\.yml/u);
  assert.match(workflow, /--image-os "\$\{ImageOS-\}"/u);
  assert.match(workflow, /--image-version "\$\{ImageVersion-\}"/u);
  assert.match(workflow, /--runner-arch "\$\{RUNNER_ARCH-\}"/u);
  assert.match(workflow, /--runner-environment "\$\{RUNNER_ENVIRONMENT-\}"/u);
  assert.match(workflow, /<\/dev\/null >"\$report"/u);
  assert.match(workflow, /runner-capability-probe\.py" validate[\s\S]*--report "\$report"/u);
  assert.match(workflow, /--expected-authority none/u);
  assert.match(workflow, /--expected-qualified false/u);
  assert.match(workflow, />\/dev\/null\n {10}\/bin\/cat -- "\$report"/u);
  assert.equal(workflow.match(/\/bin\/cat -- "\$report"/gu)?.length, 1);
  assert.doesNotMatch(workflow, /python3[^\n]*(?:\s-c\b|<<)/u);
});

test("runner capability workflow has no acquisition, credentials, runtime, or authority expansion", async () => {
  const workflow = await readFile(workflowPath, "utf8");

  assert.doesNotMatch(workflow, /workflow_dispatch|workflow_call|schedule:|\bpush:/u);
  assert.doesNotMatch(workflow, /secrets\.|github\.token|GITHUB_TOKEN/u);
  assert.doesNotMatch(workflow, /^\s*(?:services|container):/mu);
  assert.doesNotMatch(workflow, /setup-node|\bcache:|npm\s|npx\s|pip\s|apt(?:-get)?\s|dnf\s|yum\s|apk\s|brew\s/u);
  assert.doesNotMatch(workflow, /curl\s|wget\s|gh\s|glab\s|docker\s|podman\s|qemu\s|kata\s|containerd\s/u);
  assert.doesNotMatch(workflow, /configure-aws-credentials|\baws\s|opentofu|terraform|\btofu\s|gcloud|\baz\s/u);
  assert.doesNotMatch(workflow, /actions\/upload-artifact@|actions\/download-artifact@/u);
  assert.doesNotMatch(workflow, /^\s+needs:|continue-on-error:/mu);
  assert.doesNotMatch(workflow, /authority (?:candidate|qualification|authoritative)|expected-qualified true/u);
});
