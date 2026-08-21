import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_kata_runtime.py");
const testPath = join(root, "test/aws-stage2-completion-kata-runtime.py");

test("S4 Kata runtime/spec/process/share owner is closed and hostile-tested offline", async () => {
  const pythonEnv: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete pythonEnv.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: pythonEnv,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion Kata runtime S4 hostile offline matrix passed/u);

  const optimized = spawnSync("python3", ["-O", testPath], {
    cwd: root,
    env: pythonEnv,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.notEqual(optimized.status, 0, "optimized contract test unexpectedly succeeded");
  assert.doesNotMatch(
    `${optimized.stdout}\n${optimized.stderr}`,
    /completion Kata runtime S4 hostile offline matrix passed/u,
  );

  const source = await readFile(modulePath, "utf8");
  const physicalLines = source.split("\n").length - 1;
  assert.ok(
    physicalLines >= 650 && physicalLines <= 1_600,
    `unexpected integrated production line count: ${physicalLines}`,
  );
  assert.match(source, /mounts = \(/u);
  assert.match(source, /def validate_stored_spec\(stored_spec\):/u);
  assert.match(source, /def custom_mount_argv\(\):/u);
  assert.match(source, /mounts\[7:\]/u);
  assert.match(source, /hashlib\.sha256\(canonical_mount_json\(\)\)\.hexdigest\(\)/u);
  assert.match(source, /UNQUALIFIED_OFFLINE_FAKE_CONTAINERD_KATA_S4_V1/u);
  assert.match(source, /MAX_SHARE_PER_DIRECTORY = 64/u);
  assert.match(source, /MAX_SHARE_DEPTH = 4/u);
  assert.match(source, /MAX_SHARE_TOTAL = 256/u);
  assert.match(source, /def next_teardown_action\(snapshot\):/u);
  assert.match(source, /def _open_production_owner\(\):/u);
  assert.match(source, /def fixed_command_specs_v2\(\):/u);
  assert.match(source, /def _stage_containerd_archive\(/u);
  assert.match(source, /CONTAINERD_ARCHIVE_SHA256/u);
  assert.match(source, /def shutdown_daemon\(daemon\):/u);
  assert.match(source, /successful released TERM[\s\S]*CTR_TASK_KILL/u);
  assert.match(source, /def cleanup\(owner\):/u);
  assert.match(source, /def _proc_snapshot\(attested, netns\):/u);
  assert.match(source, /def _qmp_kvm\(processes\):/u);
  assert.match(source, /def _share_fact\(\):/u);
  assert.doesNotMatch(
    source,
    /subprocess|requests|urllib|boto|AWS|terraform|tofu|argparse|sys\.argv|pathlib|if __name__|ctr run --config|callable\(/u,
  );
  assert.match(source, /os\.environ\.get\("COGS_KATA_SYNTHETIC_RUNTIME_V1"\) == "1"/u);
  assert.doesNotMatch(source, /_VERIFIED_INPUTS|_VERIFIED_NETNS|_FIXED_ATTESTATIONS|_PRIVATE_DAEMONS/u);
  assert.doesNotMatch(source, /def custom_mount_argv\([^)]{1,}\)/u);
});
