import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-d-process-lifecycle.py";
const source = readFileSync(path, "utf8");
const harness = String.raw`
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_d",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class Scripted:
 def __init__(self,fail=False,clean=True): self.events=[]; self.fail=fail; self.clean=clean
 def pdeath_case(self,after): self.events.append("pdeath:after" if after else "pdeath:before")
 def terminate_tree(self):
  self.events.append("term-kill-tree")
  if self.fail: raise RuntimeError("scripted fault")
 def restore(self): self.events.append("restore"); return self.clean
for fail,clean in ((False,True),(True,True),(False,False)):
 ops=Scripted(fail,clean); report=m.qualify(ops)
 print(json.dumps({"events":ops.events,"report":report}))
`;

test("Job D scripted mode keeps before/after and tree reports separate", () => {
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row));
  assert.deepEqual(rows[0].events, ["pdeath:before", "pdeath:after", "term-kill-tree", "restore"]);
  assert.equal(rows[0].report.job, "D");
  assert.equal(rows[0].report.result, "pass");
  assert.equal(rows[1].report.result, "fail");
  assert.deepEqual(rows[1].report.cleanup, { children: true, descriptors: true });
  assert.equal(rows[2].report.result, "fail");
  assert.deepEqual(rows[2].report.cleanup, { children: false, descriptors: false });
});

test("Job D retains real identity-bound bounded lifecycle primitives", () => {
  for (const token of [
    "PR_SET_PDEATHSIG",
    "pidfd_open",
    "pidfd_send_signal",
    "/proc/{pid}/stat",
    "os.setsid",
    "os.getppid",
    "SIGTERM",
    "SIGKILL",
    "waitid",
    "WEXITED",
    "--native",
  ]) {
    assert.ok(source.includes(token), token);
  }
  for (const check of [
    "before_release_death",
    "after_release_death",
    "starttime_revalidated",
    "process_group_owned",
    "all_reaped",
  ]) {
    assert.ok(source.includes(check), check);
  }
  assert.doesNotMatch(source, /requests|boto|subprocess|socket|\/dev\/kvm|killpg|pkill/u);
  assert.ok(source.split("\n").length - 1 <= 180);
});
