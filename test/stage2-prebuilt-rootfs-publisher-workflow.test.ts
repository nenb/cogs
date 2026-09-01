/* biome-ignore-all lint/suspicious/noExplicitAny: closed descriptor fixture */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
const workflow = readFileSync(join(root, ".github/workflows/stage2-prebuilt-rootfs-publisher.yml"), "utf8");
const script = join(root, "scripts/stage2-prebuilt-rootfs-publisher.py");

test("trusted publisher is directional, numeric-artifact-bound, signed, and byte-read-back", () => {
  assert.match(workflow, /test "\$\(git rev-parse HEAD\^\)" = "\$EXACT_H"/u);
  assert.match(workflow, /fetch-depth: 2/u);
  assert.match(workflow, /artifact-ids: \$\{\{ inputs\.producer_artifact_id \}\}/u);
  assert.match(workflow, /\.digest == \$digest and \.workflow_run\.id == \$run/u);
  assert.match(workflow, /packages: write/u);
  assert.match(workflow, /id-token: write/u);
  assert.match(workflow, /cosign sign --yes --new-bundle-format=true "\$SUBJECT"/u);
  assert.match(workflow, /cosign verify --new-bundle-format=true/u);
  assert.match(
    workflow,
    /for name in accepted\/rootfs\.tar accepted\/rootfs\.manifest\.json accepted\/rootfs\.metadata\.json rootfs\.package\.json rootfs\.provenance\.json/u,
  );
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /\.path == "\.github\/workflows\/stage2-prebuilt-rootfs-producer\.yml"/u);
  assert.doesNotMatch(workflow, /latest|continue-on-error:\s*true/u);
});

test("trusted descriptor issuer emits the closed fixed descriptor", () => {
  const digest = "1".repeat(64);
  const result = spawnSync("python3", ["-I", "-B", script, "issue-descriptor"], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      COGS_PREBUILT_H: "2".repeat(40),
      COGS_PREBUILT_SOURCE_MANIFEST_SHA256: digest,
      COGS_PREBUILT_PACKAGE_MANIFEST_SHA256: "3".repeat(64),
      COGS_PREBUILT_PROVENANCE_SHA256: "4".repeat(64),
      COGS_PREBUILT_QUALIFICATION_RECEIPT_SHA256: "5".repeat(64),
      COGS_PREBUILT_PUBLICATION_RECEIPT_SHA256: "6".repeat(64),
      COGS_PREBUILT_OCI_MANIFEST_DIGEST: "7".repeat(64),
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const value = JSON.parse(result.stdout) as Record<string, any>;
  assert.equal(value.authority, "authenticated-static-control-only");
  assert.equal(value.registry.manifest_digest, "7".repeat(64));
  assert.equal(value.registry.layer_digest, "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397");
  assert.equal(value.producer.publication_receipt_sha256, "6".repeat(64));
});
