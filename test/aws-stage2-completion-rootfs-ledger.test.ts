import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_ledger.py");
const testPath = join(root, "test/aws-stage2-completion-rootfs-ledger.py");

test("D-R2.2b ledger codec, reconciliation, writer, and hardlink models fail closed", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs ledger tests passed/u);

  const source = await readFile(modulePath, "utf8");
  assert.match(source, /previous_offset/u);
  assert.match(source, /next_offset/u);
  assert.match(source, /genesis-abort/u);
  assert.match(source, /operation-abort/u);
  assert.match(source, /hardlink-create-settled/u);
  assert.doesNotMatch(
    source,
    /os\.(?:mkdir|makedirs|open|unlink|remove|rmdir|rename|replace|link|symlink|chmod|chown)\s*\(/u,
  );
  assert.doesNotMatch(source, /O_CREAT|O_EXCL|rmtree|os\.walk|glob|subprocess|socket|argparse|sys\.argv|if __name__/u);
});
