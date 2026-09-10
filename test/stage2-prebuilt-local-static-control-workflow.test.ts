import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const path = ".github/workflows/stage2-local-static-control-prebuilt-candidate.yml";
const workflow = readFileSync(path, "utf8");

test("prebuilt static control is additive, first-created, no-KVM, and exact publisher-bound", () => {
  assert.match(workflow, /^name: Stage 2 prebuilt no-KVM static control candidate$/mu);
  assert.match(workflow, /stage2-local-static-control-prebuilt-candidate\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(
    workflow,
    /select\(\.head_sha == \$g and\s*\.path == "\.github\/workflows\/stage2-local-static-control-prebuilt-candidate\.yml"\)/u,
  );
  assert.doesNotMatch(workflow, /\.head_sha == \$g and \.display_title/u);
  assert.doesNotMatch(
    workflow,
    /stage2-local-static-control-prebuilt-candidate\.yml\/runs\?event=workflow_dispatch&branch=/u,
  );
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
  const retirement = workflow.indexOf("# ADR0326 complete retirement mirror; selection only, never ancestors.");
  const image = workflow.indexOf('if test "${ImageOS-}" != ubuntu24 || test "${ImageVersion-}" != 20260907.300.1');
  const release = workflow.indexOf("repos/actions/runner-images/releases/tags/ubuntu24%2F20260907.300");
  const singleton = workflow.indexOf("gh api --paginate");
  assert.ok(retirement >= 0 && retirement < image && image < release && release < singleton);
  assert.match(workflow, /"id": 384601141[\s\S]*"prerelease": False/u);
  assert.match(workflow, /"target_commitish": "fc63e1b4dbfacf7e2449bf0706226f9f6eea583e"/u);
  assert.match(workflow, /object_pairs_hook=pairs/u);
  assert.match(workflow, /\/usr\/bin\/head -c 1048577[\s\S]*-le 1048576/u);
  assert.equal(workflow.match(/stage2\.runner-image\.rejected/gu)?.length, 1);
  assert.match(workflow, /if: always\(\) && steps\.boundary\.outcome != 'skipped'/u);
  assert.match(workflow, /if test "\$IMMUTABLE_INTENT" = true; then[\s\S]*cogs-stage2-immutable-preparation\.json/u);
  assert.match(
    workflow,
    /id: candidate_production[\s\S]*printf 'intent=true\\n' >>"\$GITHUB_OUTPUT"[\s\S]*cogs-stage2-static-candidate\.json[\s\S]*printf 'acquired=true\\n'/u,
  );
  assert.match(workflow, /if test "\$CANDIDATE_INTENT" = true; then[\s\S]*cogs-stage2-static-candidate\.json/u);
  assert.ok(workflow.indexOf("stage2-revision-retirement.py custody") < workflow.indexOf("sudo -n install -d"));
  assert.match(workflow, /descriptor-v1 -type f \| wc -l\)" = 1/u);
  assert.match(workflow, /descriptor-v1 -type f \| wc -l\)" = 6/u);
  assert.match(workflow, /stage2-local-static-control-v2\.json/u);
  const stepMinutes = [...workflow.matchAll(/^ {8}timeout-minutes: (\d+)$/gmu)].reduce(
    (total, match) => total + Number(match[1]),
    0,
  );
  assert.equal(stepMinutes, 53);
  assert.match(workflow, /^ {4}timeout-minutes: 60$/mu);
  assert.doesNotMatch(workflow, /\/dev\/kvm|containerd|\bctr\b|qmp|run-stage2-completion-(?:full|readiness)/u);
});

test("prebuilt static release completion gate rejects malformed or non-final evidence before effects", () => {
  const opening = `          /usr/bin/python3 -I -B - "$RUNNER_TEMP/runner-image-release.json" <<'PY'\n`;
  const start = workflow.indexOf(opening);
  const end = workflow.indexOf("\n          PY\n", start);
  assert.ok(start > 0 && end > start);
  const program = workflow
    .slice(start + opening.length, end)
    .split("\n")
    .map((line) => line.replace(/^ {10}/u, ""))
    .join("\n");
  const directory = mkdtempSync(join(tmpdir(), "cogs-release-gate-"));
  const evidence = join(directory, "release.json");
  const execute = (raw: string) => {
    writeFileSync(evidence, raw, { mode: 0o600 });
    return spawnSync(
      "bash",
      [
        "-c",
        `set -euo pipefail\n/usr/bin/python3 -I -B - "$1" <<'PY'\n${program}\nPY\nprintf EFFECT`,
        "release-gate",
        evidence,
      ],
      { encoding: "utf8", timeout: 5000 },
    );
  };
  const final = {
    id: 384601141,
    node_id: "RE_kwDOC1mGT84W7Iw1",
    tag_name: "ubuntu24/20260907.300",
    target_commitish: "fc63e1b4dbfacf7e2449bf0706226f9f6eea583e",
    name: "Ubuntu 24.04 (20260907) Image Update",
    draft: false,
    prerelease: false,
    created_at: "2026-09-08T08:41:19Z",
    published_at: "2026-09-08T09:34:53Z",
  };
  try {
    const accepted = execute(JSON.stringify(final));
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(accepted.stdout, /"prerelease":false/u);
    assert.match(accepted.stdout, /\nEFFECT$/u);
    for (const rejected of [
      { ...final, prerelease: true },
      { ...final, draft: true },
      { ...final, id: 384601142 },
      { ...final, target_commitish: "f".repeat(40) },
      { ...final, published_at: "not-a-time" },
    ]) {
      const result = execute(JSON.stringify(rejected));
      assert.notEqual(result.status, 0);
      assert.doesNotMatch(result.stdout, /EFFECT/u);
    }
    for (const malformed of [
      "",
      "{}{}",
      "{",
      JSON.stringify(final).replace('"prerelease":false', '"prerelease":true,"prerelease":false'),
      `${JSON.stringify(final)}${JSON.stringify({ ...final, prerelease: true })}`,
    ]) {
      const result = execute(malformed);
      assert.notEqual(result.status, 0);
      assert.doesNotMatch(result.stdout, /EFFECT/u);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("prebuilt static artifact actions are immutable and no AWS permission exists", () => {
  assert.doesNotMatch(workflow, /actions\/(?:download|upload)-artifact@v[0-9]/u);
  assert.doesNotMatch(workflow, /id-token:\s*write|packages:\s*write|AWS_ACCESS_KEY_ID|aws-actions/u);
});
