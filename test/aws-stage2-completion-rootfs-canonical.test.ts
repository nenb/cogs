import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const testPath = join(root, "test/aws-stage2-completion-rootfs-canonical.py");

test("rootfs candidate canonical manifest and ustar are fixed and internal", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs canonical portable tests passed/u);
  const canonical = await readFile(join(root, "deploy/aws-feasibility/remote/completion_rootfs_canonical.py"), "utf8");
  const build = await readFile(join(root, "deploy/aws-feasibility/remote/completion_rootfs_build.py"), "utf8");
  assert.match(canonical, /ustar\\0/u);
  assert.match(canonical, /BLOCK \* 2/u);
  assert.match(build, /_two_build_candidate/u);
  assert.doesNotMatch(`${canonical}\n${build}`, /if __name__|sys\.argv|argparse|tarfile|subprocess|socket/u);
});
