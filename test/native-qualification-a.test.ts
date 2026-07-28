import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-a-runtime-mappings.py";
const source = readFileSync(path, "utf8");

function python(body: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", body], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

test("Job A is a readable failure-only client of one real common receipt boundary", () => {
  const harness = `
import runpy,sys,types
module=runpy.run_path(${JSON.stringify(path)},run_name='job_a_test')
events=[]
class Bomb:
 def __getattribute__(self,name): raise AssertionError('operation result read: '+name)
class Evidence:
 def __init__(self,value): self.value=value;self.reads=0
 @property
 def restored(self):
  self.reads+=1
  if self.reads!=1: raise AssertionError('cleanup evidence reread')
  return self.value
class Candidate:
 def __init__(self,**values):
  assert set(values)=={'failure_phase','diagnostics','primary_error'}
  self.__dict__.update(values)
class Session:
 def __init__(self,restored=True): self.evidence=Evidence(restored)
 def run_fixed_operation(self,operation):
  events.append(('operation',operation));return Bomb()
 def settle_native_phase(self):
  events.append(('settle',));return self.evidence
 def publish(self,candidate):
  events.append(('publish',candidate.failure_phase,candidate.diagnostics,candidate.primary_error))
session=Session()
class NativeSession:
 @staticmethod
 def begin(job,driver):
  assert (job,driver)==('A',${JSON.stringify(path)});return session
common=types.SimpleNamespace(NativeSession=NativeSession,ReportCandidate=Candidate)
assert module['_run'](common)==0
assert events==[('operation','A'),('settle',),('publish',None,None,None)]
assert session.evidence.reads==1

sys.path.insert(0,'scripts/native-qualification');import common as real_common
baseline={key:('baseline',key) for key in real_common.CLEANUP_KEYS};baseline['paths']=(None,None)
class Ops:
 def __init__(self): self.fds=real_common.FdRegistry();self.source_set_sha256='2'*64;self.events=[]
 def observe(self,context): return baseline
 def run_fixed_operation(self,context,operation):
  self.events.append((context.job,operation));raise RuntimeError('safe native boundary')
class Cust:
 def abort(self,error): self.error=error
ops=Ops();real_session=real_common.NativeSession._begin_with_ops(types.SimpleNamespace(job='A'),ops,Cust())
try: module['_operation'](real_session)
except RuntimeError as error: assert str(error)=='safe native boundary'
else: raise AssertionError('completed operation substituted')
assert ops.events==[('A','A')]

dispatched=[]
assert module['_dispatch'](['--workflow-bound'],lambda common:dispatched.append(common) or 7,lambda:'common')==7
for arguments in ([],['--native'],['--fixture']):
 try: module['_dispatch'](arguments,lambda common:dispatched.append('effect'),lambda:'wrong')
 except module['QualificationError']: pass
 else: raise AssertionError(arguments)
assert dispatched==['common']

session=Session();events.clear()
sys.modules['common']=types.SimpleNamespace(NativeSession=NativeSession,ReportCandidate=Candidate)
sys.argv=[${JSON.stringify(path)},'--workflow-bound']
try: runpy.run_path(${JSON.stringify(path)},run_name='__main__')
except SystemExit as error: assert error.code==0
else: raise AssertionError('CLI did not exit')
`;
  const run = python(harness);
  assert.equal(run.status, 0, run.stderr);
  assert.equal((source.match(/run_fixed_operation\(/gu) ?? []).length, 1);
  assert.doesNotMatch(source, /production_checks|metadata|source_set_sha256|context\.head_sha/u);
  assert.doesNotMatch(source, /fork\(|pidfd|waitid|unshare|mount\(|\/proc\//u);
  assert.ok(source.split("\n").every((line) => line.length <= 120));
});
