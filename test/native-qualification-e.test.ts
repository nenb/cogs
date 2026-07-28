import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-e-sandbox.py";
const source = readFileSync(path, "utf8");

function adapter(sourceText: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", sourceText], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

test("Job E portable adapter validates only the closed observation", () => {
  const result = adapter(`
import runpy
module = runpy.run_path(${JSON.stringify(path)}, run_name="native_e_adapter")
class Good:
 def observe(self): return {name: True for name in module["CHECK_IDS"]}
value = module["qualify"](Good())
assert tuple(value["checks"]) == module["CHECK_IDS"]
assert len(value["metadata"]["policy_sha256"]) == 64
class Bad:
 def observe(self):
  value = {name: True for name in module["CHECK_IDS"]}
  value["pid_one"] = False
  return value
try: module["qualify"](Bad())
except RuntimeError: pass
else: raise SystemExit("false sandbox fact accepted")
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("Job E remains the sole fixed sudo/root sandbox entry", () => {
  assert.match(source, /"\/usr\/bin\/sudo", "-n", "--close-from=3", "\/usr\/bin\/env", "-i"/u);
  assert.match(source, /module\._SystemOps, module\._enter_boundary/u);
  assert.match(source, /sys\.argv == \[sys\.argv\[0\], "--root-setup"\]/u);
  assert.match(source, /os\.geteuid\(\) != 0 or os\.environ/u);
  assert.match(source, /_MS_RDONLY \| _MS_NOSUID \| _MS_NODEV \| _MS_NOEXEC/u);
  assert.match(source, /os\.getpid\(\) == 1/u);
  assert.match(source, /facts\["securebits"\] == 0x0F/u);
  assert.match(source, /facts\["no_new_privs"\] == 1/u);
});

test("Job E does not duplicate A-D or acquisition machinery", () => {
  for (const forbidden of [
    "map_files",
    "parse_elf",
    "gzip",
    "zstd",
    "RLIMIT_NOFILE",
    "close_range",
    "PDEATHSIG",
    "KVM",
    "boto",
    "pip install",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
  assert.ok(source.split("\n").length - 1 <= 240);
});
