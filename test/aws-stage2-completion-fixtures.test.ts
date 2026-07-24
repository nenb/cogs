import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_fixtures.py");
const testPath = join(root, "test/aws-stage2-completion-fixtures.py");

test("F1 fixed Git and package fixture models are byte-deterministic", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion fixture model tests passed/u);

  const source = await readFile(modulePath, "utf8");
  assert.match(source, /def fixed_fixtures\(\):/u);
  assert.match(source, /for index in range\(512\):/u);
  assert.match(source, /for index in range\(256\):/u);
  assert.match(source, /SOURCE_EPOCH = 1782172800/u);
  assert.doesNotMatch(
    source,
    /subprocess|socket|urllib|requests|boto|argparse|sys\.argv|tarfile|extractall|chroot|unshare|namespace|\.deb|PRIVATE KEY|if __name__/u,
  );
});
