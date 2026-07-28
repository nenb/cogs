import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-c-descriptors.py";
const source = readFileSync(path, "utf8");
const harness = String.raw`
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_c",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class Scripted:
 def __init__(self,fail=False,clean=True): self.events=[]; self.fail=fail; self.clean=clean
 def measure_and_normalize(self): self.events.append("limit:8193"); return True
 def make_exact_descriptors(self): self.events.append("fds:198,4096"); return True,True,True
 def prove_inheritance(self): self.events.append("inheritance"); return not self.fail
 def prove_close_range(self): self.events.append("close_range:0"); return True
 def restore(self): self.events.append("restore"); return self.clean
for fail,clean in ((False,True),(True,True),(False,False)):
 ops=Scripted(fail,clean); print(json.dumps({"events":ops.events,"report":m.qualify(ops)}))
`;

test("Job C scripted mode proves ordered facts without selecting native mode", () => {
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout.trim().split("\n").map((row) => JSON.parse(row));
  assert.equal(rows[0].report.job, "C");
  assert.equal(rows[0].report.result, "pass");
  assert.deepEqual(rows[0].events, ["limit:8193", "fds:198,4096", "inheritance", "close_range:0", "restore"]);
  assert.equal(rows[1].report.result, "fail");
  assert.deepEqual(rows[1].report.cleanup, { descriptors: true, limits: true });
  assert.equal(rows[2].report.result, "fail");
  assert.deepEqual(rows[2].report.cleanup, { descriptors: false, limits: false });
});

test("Job C keeps real Linux primitives and exact restoration in tracked Python", () => {
  for (const token of ["RLIMIT_NOFILE", "8193", "F_DUPFD_CLOEXEC", "4096", "_SYS_CLOSE_RANGE", "_SYS_DUP3", "FD_CLOEXEC", "resource.setrlimit", "--native"]) {
    assert.ok(source.includes(token), token);
  }
  assert.match(source, /finally|restore/u);
  assert.doesNotMatch(source, /requests|boto|subprocess|socket|\/dev\/kvm/u);
  assert.ok(source.split("\n").length - 1 <= 140);
});
