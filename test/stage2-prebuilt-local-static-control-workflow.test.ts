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
  assert.match(workflow, /completion_kata_immutable_preparation\.py/u);
  assert.match(workflow, /stage2-local-static-control-v2\.json/u);
  assert.doesNotMatch(workflow, /\/dev\/kvm|containerd|\bctr\b|qmp|run-stage2-completion-(?:full|readiness)/u);
});

test("prebuilt static artifact actions are immutable and no AWS permission exists", () => {
  assert.doesNotMatch(workflow, /actions\/(?:download|upload)-artifact@v[0-9]/u);
  assert.doesNotMatch(workflow, /id-token:\s*write|packages:\s*write|AWS_ACCESS_KEY_ID|aws-actions/u);
});
