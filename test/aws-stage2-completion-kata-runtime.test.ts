import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_kata_runtime.py");
const testPath = join(root, "test/aws-stage2-completion-kata-runtime.py");

test("F3 canonical Kata OCI mounts are immutable, exact, and fail closed", async () => {
  const pythonEnv: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete pythonEnv.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: pythonEnv,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion Kata runtime mount contract tests passed/u);

  const optimized = spawnSync("python3", ["-O", testPath], {
    cwd: root,
    env: pythonEnv,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.notEqual(optimized.status, 0, "optimized contract test unexpectedly succeeded");
  assert.doesNotMatch(
    `${optimized.stdout}\n${optimized.stderr}`,
    /completion Kata runtime mount contract tests passed/u,
  );

  const source = await readFile(modulePath, "utf8");
  const physicalLines = source.split("\n").length - 1;
  assert.ok(physicalLines >= 80 && physicalLines <= 140, `unexpected production line count: ${physicalLines}`);
  assert.match(source, /mounts = \(/u);
  assert.match(source, /def validate_stored_spec\(stored_spec\):/u);
  assert.match(source, /def custom_mount_argv\(\):/u);
  assert.match(source, /mounts\[7:\]/u);
  assert.match(source, /hashlib\.sha256\(canonical_mount_json\(\)\)\.hexdigest\(\)/u);
  assert.doesNotMatch(
    source,
    /subprocess|socket|requests|urllib|boto|AWS|terraform|tofu|argparse|sys\.argv|os\.|environ|pathlib|\bopen\(|if __name__|ctr run --config/u,
  );
  assert.doesNotMatch(source, /def custom_mount_argv\([^)]{1,}\)/u);
});
