import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("real Linux no-KVM preparation bridge retains and faults actual descriptors", {
  skip: process.platform !== "linux",
}, () => {
  const result = spawnSync("python3", ["-B", "test/aws-stage2-completion-kata-preparation-bridge-linux.py"], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 60_000,
    env: { PATH: "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /real Linux no-KVM V2 preparation bridge descriptor\/fault matrix passed/u);
});
