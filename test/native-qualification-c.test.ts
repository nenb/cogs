import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-c-descriptors.py";
const source = readFileSync(path, "utf8");
const cleanup = {
  descriptors: true,
  children: true,
  paths: true,
  mounts: true,
  namespaces: true,
  limits: true,
  checkout: true,
};
const harness = `
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_c",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
CLEAN=json.loads(${JSON.stringify(JSON.stringify(cleanup))})
class Scripted:
 def __init__(self,cut=None,clean=True): self.events=[]; self.cut=cut; self.clean=clean
 def step(self,name,value):
  self.events.append(name)
  if self.cut==name: raise OSError("cut:"+name)
  return value
 def measure_and_normalize(self): return self.step("limits",(True,True))
 def make_exact_descriptors(self): return self.step("descriptors",(True,True,True))
 def prove_inheritance(self): return self.step("inheritance",True)
 def prove_close_range(self): return self.step("close-range",True)
 def restore(self):
  self.events.append("restore")
  value=dict(CLEAN)
  if not self.clean: value["descriptors"]=False
  return value
for cut,clean in ((None,True),("inheritance",True),(None,False)):
 ops=Scripted(cut,clean); checks,restored=m.qualify(ops)
 print(json.dumps({"events":ops.events,"checks":checks,"cleanup":restored}))
`;

test("Job C fault cuts always restore and preserve exact cleanup observations", () => {
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row));
  assert.deepEqual(rows[0].events, ["limits", "descriptors", "inheritance", "close-range", "restore"]);
  assert.ok(Object.values(rows[0].checks).every((value) => value === "pass"));
  assert.equal(rows[1].checks.inheritance_exact, "fail");
  assert.equal(rows[1].checks.close_range_exact, "fail");
  assert.deepEqual(rows[1].cleanup, cleanup);
  assert.equal(rows[2].checks.limit_restored, "pass");
  assert.equal(rows[2].checks.cleanup_restored, "fail");
  assert.equal(rows[2].cleanup.descriptors, false);
});

test("Job C preregisters a blocked child and proves exact outcomes", () => {
  for (const token of [
    "--workflow-bound",
    'WorkflowContext.from_environ("C", __file__)',
    "common.finalize_report",
    'self.child = {"pid": pid, "pidfd": None',
    "os.pidfd_open(pid, 0)",
    'os.write(gate_writer, b"G")',
    "os.waitid(os.P_PIDFD",
    "os.CLD_EXITED",
    "os.WNOWAIT",
    "SYS_CLOSE_RANGE",
    "F_DUPFD_CLOEXEC",
    "HIGH_FD = 8193, 198, 4096",
  ]) {
    assert.ok(source.includes(token), token);
  }
  const pidfdOpen = source.indexOf("os.pidfd_open(pid, 0)");
  const pidfdRegister = source.indexOf('self.child["pidfd"] = pidfd');
  assert.ok(source.indexOf('self.child = {"pid": pid') < pidfdOpen);
  assert.ok(pidfdOpen < pidfdRegister && pidfdRegister < source.indexOf("identity = _identity(pid)"));
  assert.ok(pidfdRegister < source.indexOf('os.write(gate_writer, b"G")'));
  assert.match(source, /os\.open\("\/proc\/self\/fd"[\s\S]*descriptor != directory[\s\S]*os\.fstat\(descriptor\)/u);
  assert.doesNotMatch(source, /--native|unobserved|dict\.fromkeys\(CHECKS, "pass"\)/u);
});

test("Job C stays within ADR 0090's readable high", () => {
  assert.ok(source.split("\n").length - 1 <= 250);
  assert.doesNotMatch(source, /requests|boto|socket|\/dev\/kvm/u);
});
