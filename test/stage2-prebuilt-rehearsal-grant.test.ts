import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("no-mint rehearsal grants use the production commitment codec", () => {
  const result = spawnSync("python3", ["-I", "-B", "test/stage2-prebuilt-rehearsal-grant.py"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "stage2 prebuilt rehearsal grant checks passed\n");
});
