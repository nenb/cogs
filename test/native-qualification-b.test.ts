import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const driverPath = join(root, "scripts/native-qualification/job-b-compression.py");
const launcherPath = join(root, "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py");
const driver = readFileSync(driverPath, "utf8");
const launcher = readFileSync(launcherPath, "utf8");
const closure = readFileSync(join(root, "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py"), "utf8");
function position(source: string, text: string) {
  const value = source.indexOf(text);
  assert.notEqual(value, -1, `missing production barrier: ${text}`);
  return value;
}
test("native B remains a bounded standard-library production composition", () => {
  assert.ok(driver.trimEnd().split("\n").length <= 180);
  assert.match(driver, /completion_trusted_runtime_launcher\.py/u);
  assert.match(driver, /"\/usr\/bin\/python3", "-I", "-B"/u);
  assert.match(driver, /all\(0 < len\(value\) <= 65536/u);
  assert.doesNotMatch(driver, /\b(?:requests|urllib|boto3|docker|kata|kvm|pip)\b|https?:\/\//iu);
  assert.match(closure, /def _seal_object\(/u);
  assert.match(launcher, /gzip_output, gzip_observed = _run_tool_with_ops/u);
  assert.match(launcher, /zstd_output, zstd_observed = _run_tool_with_ops/u);
  assert.match(launcher, /socket:41 connect:42/u);
  const barriers = [
    '_recv_status(parent_status, time.monotonic() + _SETUP_SECONDS, "exec-ready", 4)',
    "post_maps = _final_mapping_check",
    "final_fds = _descriptor_snapshot",
    "final_maps = _final_mapping_check",
    "payload = _FIXED_INPUT[role]",
  ].map((value) => position(launcher, value));
  assert.ok(barriers.every((value, index) => index === 0 || barriers[index - 1] < value));
});
test("ordinary native B qualification is scripted and performs no native effects", () => {
  const harness = `
import runpy
ns = runpy.run_path(${JSON.stringify(driverPath)})
revision = "0" * 40
facts = {name: True for name in ns["PREINPUT_FACTS"] + ns["NETWORK_FACTS"] + ns["CLEANUP_FACTS"]}
facts.update(version="cogs.runtime-qualification/v1", marker="cogs-runtime-qualification-v1",
             source_revision=revision, gzip_output_sha256=ns["FIXED_OUTPUT_SHA256"],
             zstd_output_sha256=ns["FIXED_OUTPUT_SHA256"], closure_sha256="1" * 64)
class Scripted:
    def __init__(self, mutation=None): self.mutation = mutation; self.events = []
    def launch(self, requested):
        self.events.append(("launch", requested))
        result = dict(facts)
        if self.mutation: result[self.mutation] = False
        return {"result": result, "child_exact": True, "fd_restored": True,
                "children_restored": True}
adapter = Scripted()
assert len(ns["qualify"](adapter, revision)) == 5
assert adapter.events == [("launch", revision)]
for mutation in ("mapped_generations_exact", "seccomp_denials_exact", "descriptors_restored"):
    try: ns["qualify"](Scripted(mutation), revision)
    except ns["QualificationError"]: pass
    else: raise AssertionError(mutation)
`;
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-"], {
    input: harness,
    env: { PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});
