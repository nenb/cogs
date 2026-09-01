import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
const probe = join(root, "test/aws-stage2-completion-rootfs-prebuilt-acquisition.py");

test("fixed prebuilt rootfs GHCR acquisition passes hostile fake-wire checks", () => {
  for (const optimize of ["", "1", "2"]) {
    const result = spawnSync("python3", ["-I", probe], {
      cwd: root,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONOPTIMIZE: optimize },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "stage2 prebuilt rootfs acquisition fake-wire checks passed\n");
  }
});

test("production acquisition has one fixed public registry route and no ambient selector", () => {
  const source = readFileSync(
    join(root, "deploy/aws-feasibility/remote/completion_rootfs_prebuilt_acquisition.py"),
    "utf8",
  );
  assert.doesNotMatch(source, /completion_artifact_acquisition|AWS_|GITHUB_TOKEN|GH_TOKEN|NETRC/u);
  assert.doesNotMatch(source, /getenv|environ|sys\.argv|subprocess|curl|wget|latest|mirror|fallback/u);
  assert.match(source, /def acquire_fixed\(descriptor_raw\):/u);
  assert.match(source, /return _acquire\(descriptor_raw, HttpsTransport\(\), ROOT, True, \(0, 0\)\)/u);
});
