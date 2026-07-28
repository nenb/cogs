import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_runtime_closure.py");
const testPath = join(root, "test/aws-stage2-completion-runtime-closure.py");

test("F2 portable ELF parser and resolver reject hostile synthetic inputs", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /synthetic tests passed \(functional-only; exact cache not checked\)/u);

  const harness = await readFile(testPath, "utf8");
  assert.match(harness, /argv != \["--real"\]/u);
  assert.match(harness, /real exact-cache test failed/u);
  assert.doesNotMatch(harness, /skip|SKIP/u);

  const source = await readFile(modulePath, "utf8");
  assert.match(source, /def fixed_runtime_closure\(authority: RootfsBuildInputs\) -> ClosureResult:/u);
  assert.match(source, /revalidate_build_inputs\(authority\)/u);
  assert.match(source, /len\(result_records\) == 35/u);
  assert.match(source, /"usr\/lib\/x86_64-linux-gnu\/libnss_files\.so\.2"/u);
  assert.doesNotMatch(
    source,
    /subprocess|\bldd\b|readelf|objdump|ld\.so\.cache|pathlib|\bopen\(|os\.|sys\.|socket|requests|urllib|boto|AWS|cloud|Docker|extract|tarfile|callback|fallback|argparse|sys\.argv|if __name__/u,
  );
  assert.doesNotMatch(source, /def fixed_runtime_closure\([^)]*,/u);
});
