import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-d-process-lifecycle.py";
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
spec=importlib.util.spec_from_file_location("job_d",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
CLEAN=json.loads(${JSON.stringify(JSON.stringify(cleanup))})
class Scripted:
 def __init__(self,cut=None,clean=True): self.events=[]; self.cut=cut; self.clean=clean; self.processes={}
 def pdeath_case(self,after):
  name="pdeath-after" if after else "pdeath-before"; self.events.append(name)
  if self.cut==name: raise OSError("cut:"+name)
  return {"armed":True,"released":True,"ownership":True,"parent_normal":True,
          "child_killed":True,"revalidated":True,"adopted":True}
 def terminate_tree(self):
  self.events.append("term-kill-tree")
  if self.cut=="term-kill-tree": raise RuntimeError("cut:tree")
  return {"ownership":True,"ready":True,"survived_term":True,"killed":True,
          "adopted":True,"revalidated":True}
 def restore(self):
  self.events.append("restore"); value=dict(CLEAN)
  if not self.clean: value["children"]=False
  return value
for cut,clean in ((None,True),("pdeath-after",True),("term-kill-tree",True),(None,False)):
 ops=Scripted(cut,clean); checks,restored=m.qualify(ops)
 print(json.dumps({"events":ops.events,"checks":checks,"cleanup":restored}))
`;

test("Job D keeps mechanism outcomes separate at every scripted fault cut", () => {
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row));
  assert.deepEqual(rows[0].events, ["pdeath-before", "pdeath-after", "term-kill-tree", "restore"]);
  assert.ok(Object.values(rows[0].checks).every((value) => value === "pass"));
  assert.equal(rows[1].checks.before_release_death, "pass");
  assert.equal(rows[1].checks.after_release_death, "fail");
  assert.equal(rows[1].checks.pdeathsig_armed, "fail");
  assert.equal(rows[2].checks.before_release_death, "pass");
  assert.equal(rows[2].checks.after_release_death, "pass");
  assert.equal(rows[2].checks.term_kill_bounded, "fail");
  assert.deepEqual(rows[2].cleanup, cleanup);
  assert.equal(rows[3].checks.all_reaped, "pass");
  assert.equal(rows[3].checks.cleanup_restored, "fail");
});

test("Job D registers every leader and descendant before case release", () => {
  for (const token of [
    "--workflow-bound",
    'WorkflowContext.from_environ("D", __file__)',
    "common.finalize_report",
    'self.processes[pid] = {"pidfd": None',
    "os.pidfd_open(pid, 0)",
    'self._write(start_w, b"P")',
    'self._write(child_w, b"P")',
    "PR_SET_PDEATHSIG",
    "PR_SET_CHILD_SUBREAPER",
  ]) {
    assert.ok(source.includes(token), token);
  }
  const pidfdOpen = source.indexOf("pidfd = os.pidfd_open(pid, 0)");
  const pidfdRegister = source.indexOf('self.processes[pid]["pidfd"] = pidfd');
  assert.ok(pidfdOpen < pidfdRegister && pidfdRegister < source.indexOf("identity = _identity(pid)"));
  const registerParent = source.indexOf("parent_identity = self._register(parent");
  const releaseParent = source.indexOf('self._write(start_w, b"P")', registerParent);
  const registerChild = source.indexOf("child_identity = self._register(child", releaseParent);
  const releaseChild = source.indexOf('self._write(child_w, b"P")', registerChild);
  assert.ok(registerParent < releaseParent && releaseParent < registerChild && registerChild < releaseChild);
  const registerLeader = source.indexOf("leader_identity = self._register(leader");
  const registerDescendant = source.indexOf("descendant_identity = self._register(descendant", registerLeader);
  const releaseDescendant = source.indexOf('self._write(child_w, b"P")', registerDescendant);
  assert.ok(registerLeader < registerDescendant && registerDescendant < releaseDescendant);
});

test("Job D requires genuine signal, siginfo, adoption, and restoration proof", () => {
  for (const token of [
    "os.waitid(os.P_PIDFD",
    "os.WNOWAIT",
    "info.si_code == code",
    "info.si_status == status",
    "os.CLD_KILLED",
    "signal.SIGKILL",
    "parent_normal",
    "child_killed",
    "descendant in _children()",
    'cleanup["children"] &= self.process_certain',
  ]) {
    assert.ok(source.includes(token), token);
  }
  assert.match(source, /os\.open\("\/proc\/self\/fd"[\s\S]*descriptor != directory[\s\S]*os\.fstat\(descriptor\)/u);
  assert.doesNotMatch(source, /--native|unobserved|dict\.fromkeys\(CHECKS, "pass"\)|killpg|pkill/u);
  assert.ok(source.split("\n").length - 1 <= 350);
});
