import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const path = ".github/workflows/stage2-local-static-control-prebuilt-candidate.yml";
const workflow = readFileSync(path, "utf8");

test("prebuilt static control is additive, first-created, no-KVM, and exact publisher-bound", () => {
  assert.match(workflow, /^name: Stage 2 prebuilt no-KVM static control candidate$/mu);
  assert.match(workflow, /stage2-local-static-control-prebuilt-candidate\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /\.path == "\.github\/workflows\/stage2-prebuilt-rootfs-publisher\.yml"/u);
  assert.match(workflow, /\.status == "completed" and \.conclusion == "success"/u);
  assert.match(workflow, /\.name == \$name/u);
  assert.match(workflow, /artifact-ids: \$\{\{ inputs\.rootfs_control_artifact_id \}\}/u);
  assert.match(workflow, /test "\$\(find "\$RUNNER_TEMP\/rootfs-control" -type f \| wc -l\)" = 6/u);
  assert.match(workflow, /COGS_STAGE2_CONTROL_REVISION="\$GITHUB_SHA"/u);
  assert.match(workflow, /stage2-prebuilt-static-control-runtime-boundary\.py/u);
  assert.match(workflow, /completion_kata_immutable_preparation\.py/u);
  const descriptor = workflow.indexOf("Stage only the descriptor for immutable acquisition");
  const immutable = workflow.indexOf("Acquire verify and install immutable fixtures without runtime launch");
  const adjuncts = workflow.indexOf("Stage authenticated publication adjuncts after immutable acquisition");
  const control = workflow.indexOf("Produce deterministic non-authoritative control candidate");
  assert.ok(descriptor > 0 && descriptor < immutable && immutable < adjuncts && adjuncts < control);
  assert.match(workflow, /descriptor-v1 -type f \| wc -l\)" = 1/u);
  assert.match(workflow, /descriptor-v1 -type f \| wc -l\)" = 6/u);
  assert.match(workflow, /stage2-local-static-control-v2\.json/u);
  const stepMinutes = [...workflow.matchAll(/^ {8}timeout-minutes: (\d+)$/gmu)].reduce(
    (total, match) => total + Number(match[1]),
    0,
  );
  assert.equal(stepMinutes, 49);
  assert.match(workflow, /^ {4}timeout-minutes: 55$/mu);
  assert.doesNotMatch(workflow, /\/dev\/kvm|containerd|\bctr\b|qmp|run-stage2-completion-(?:full|readiness)/u);
});

test("prebuilt static artifact actions are immutable and no AWS permission exists", () => {
  assert.doesNotMatch(workflow, /actions\/(?:download|upload)-artifact@v[0-9]/u);
  assert.doesNotMatch(workflow, /id-token:\s*write|packages:\s*write|AWS_ACCESS_KEY_ID|aws-actions/u);
});
