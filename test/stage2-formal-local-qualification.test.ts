import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("formal local aggregation rejects production-shaped hostile batches", () => {
  const result = spawnSync("python3", ["-I", "-B", "test/stage2-formal-local-qualification.py"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /hostile checks passed/u);
});
