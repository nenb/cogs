import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
const workflow = readFileSync(join(root, ".github/workflows/stage2-prebuilt-rootfs-producer.yml"), "utf8");
const producer = readFileSync(join(root, "scripts/stage2-prebuilt-rootfs-producer.py"), "utf8");

test("prebuilt producer is an attempt-one exact-H non-AWS candidate with no publisher credential", () => {
  assert.match(workflow, /test "\$GITHUB_REF" = refs\/heads\/main/u);
  assert.match(workflow, /test "\$GITHUB_REF_PROTECTED" = true/u);
  assert.match(workflow, /test "\$GITHUB_RUN_ATTEMPT" = 1/u);
  assert.match(workflow, /test "\$EXACT_H" = "\$GITHUB_SHA"/u);
  assert.doesNotMatch(workflow, /packages:\s*write|id-token:\s*write|docker login|cosign sign|oras push/u);
  assert.match(producer, /build\._pinned_publication/u);
  assert.doesNotMatch(producer, /boto|AWS_|terraform|opentofu|ssm|subprocess|Popen/u);
  assert.match(producer, /"independent_builds": 2, "equal": True, "pins_matched": True/u);
  assert.match(producer, /"remote_published": False/u);
});

test("producer uploads and freshly reads back exactly seven members without compression", () => {
  assert.match(workflow, /compression-level: 0/u);
  assert.match(workflow, /include-hidden-files: true/u);
  assert.match(workflow, /run-id: \$\{\{ github\.run_id \}\}/u);
  assert.match(workflow, /test "\$\(find "\$root" -type f \| wc -l\)" = 7/u);
  assert.ok(
    workflow.includes(
      "96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0  $root/accepted/.cogs-rootfs-publication-v1",
    ),
  );
  for (const digest of [
    "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397",
    "59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1",
    "8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506",
  ]) {
    assert.match(workflow, new RegExp(digest, "u"));
  }
});
