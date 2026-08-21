import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

for (const optimized of [false, true]) {
  test(`typed local evidence and receipt are transactional${optimized ? " under python -O" : ""}`, () => {
    const result = spawnSync(
      "python3",
      [...(optimized ? ["-O"] : []), "-B", "test/aws-stage2-completion-local-receipt.py"],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
        timeout: 30_000,
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /completion local typed evidence and receipt tests passed/u);
  });
}
