import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/thin-integration.py";
const source = readFileSync(path, "utf8");

function adapter(sourceText: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", sourceText], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

test("thin integration portable adapter requires every closed fact and digest", () => {
  const result = adapter(`
import runpy
module = runpy.run_path(${JSON.stringify(path)}, run_name="native_integration_adapter")
digests = {name: "a" * 64 for name in ("closure_sha256", "gzip_output_sha256", "source_set_sha256", "zstd_output_sha256")}
class Good:
 def observe(self): return ({name: True for name in module["CHECK_IDS"]}, digests)
value = module["qualify"](Good())
assert tuple(value["checks"]) == module["CHECK_IDS"]
class Extra:
 def observe(self):
  checks = {name: True for name in module["CHECK_IDS"]}
  checks["artifact"] = True
  return checks, digests
try: module["qualify"](Extra())
except RuntimeError: pass
else: raise SystemExit("linked input accepted")
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("thin integration enters admitted production closure and launcher once", () => {
  assert.match(source, /cogs\.runtime-source-admission\/v1/u);
  assert.match(source, /completion_trusted_runtime_closure\.py/u);
  assert.match(source, /completion_trusted_runtime_launcher\.py/u);
  assert.match(source, /os\.execve\("\/usr\/bin\/python3"/u);
  assert.match(source, /result\.get\("gzip_output_sha256"\) == _OUTPUT_SHA/u);
  assert.match(source, /result\.get\("zstd_output_sha256"\) == _OUTPUT_SHA/u);
  assert.match(source, /"evidence" not in result/u);
  assert.doesNotMatch(source, /sudo|download-artifact|upload-artifact|needs\./u);
});

test("thin integration is fixed, metadata-only, and within its high", () => {
  assert.match(source, /sys\.argv != \[sys\.argv\[0\], "--workflow-bound"\]/u);
  assert.doesNotMatch(source, /argparse|requests|urllib|socket\.|boto|KVM|AWS/u);
  assert.doesNotMatch(source, /raw maps|map_files/u);
  assert.ok(source.split("\n").length - 1 <= 170);
});
