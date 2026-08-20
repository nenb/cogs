import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const fixture = join(root, "test/aws-stage2-completion-kata-nft-owner.py");

test("host-global NFT owner is persistent, OFD-retained, and fail-closed", () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [fixture], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /persistent NFT owner hostile-cut matrix passed/u);
});
