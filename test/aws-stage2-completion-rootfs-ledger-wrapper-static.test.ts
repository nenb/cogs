import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const wrapperPath = join(process.cwd(), "test/aws-stage2-completion-rootfs-ledger.test.ts");

test("ADR0050 C4 ledger wrapper is one exact fail-closed 60-second invocation", async () => {
  const source = await readFile(wrapperPath, "utf8");
  assert.equal(source.match(/\bspawnSync\s*\(/gu)?.length, 1);
  assert.deepEqual(
    [...source.matchAll(/\btimeout:\s*([\d_]+)/gu)].map((match) => match[1]),
    ["60_000"],
  );
  assert.equal(source.match(/assert\.equal\(result\.status,\s*0,/gu)?.length, 1);
  assert.doesNotMatch(source, /result\.status\s*(?:\?\?|\|\|)|result\.signal\s*===?\s*null/u);

  const requireSuccess = (status: number | null) => assert.equal(status, 0);
  for (const outcome of [
    { name: "timeout", status: null, signal: "SIGTERM", error: "ETIMEDOUT" },
    { name: "signal", status: null, signal: "SIGKILL", error: undefined },
    { name: "null-status", status: null, signal: null, error: undefined },
    { name: "nonzero", status: 1, signal: null, error: undefined },
  ]) {
    assert.throws(() => requireSuccess(outcome.status), outcome.name);
  }
  assert.doesNotThrow(() => requireSuccess(0));
});
