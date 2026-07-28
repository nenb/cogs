import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/thin-integration.py";
const source = readFileSync(path, "utf8");

test("integration leaves exact digest summaries to one immutable common receipt", () => {
  const harness = `
import runpy,sys,types
module=runpy.run_path(${JSON.stringify(path)},run_name='integration_test')
module['os'].geteuid=lambda:1000
events=[]
class Bomb:
 def __getattribute__(self,name): raise AssertionError('operation result read: '+name)
class Evidence:
 def __init__(self): self.reads=0
 @property
 def restored(self):
  self.reads+=1
  if self.reads!=1: raise AssertionError('cleanup evidence reread')
  return True
class Candidate:
 def __init__(self,**values):
  assert set(values)=={'failure_phase','diagnostics','primary_error'}
  self.__dict__.update(values)
class Session:
 def __init__(self): self.evidence=Evidence()
 def run_fixed_operation(self,operation): events.append(('operation',operation));return Bomb()
 def settle_native_phase(self): events.append(('settle',));return self.evidence
 def publish(self,candidate): events.append(('publish',candidate.failure_phase,candidate.diagnostics,candidate.primary_error))
session=Session()
class NativeSession:
 @staticmethod
 def begin(job,driver): assert (job,driver)==('integration',${JSON.stringify(path)});return session
common=types.SimpleNamespace(NativeSession=NativeSession,ReportCandidate=Candidate)
assert module['_run'](common)==0
assert events==[('operation','integration'),('settle',),('publish',None,None,None)]
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
ops=Ops();context=types.SimpleNamespace(job='integration')
real_session=real_common.NativeSession._begin_with_ops(context,ops,Cust())
try: module['_operation'](real_session)
except RuntimeError as error: assert str(error)=='safe native boundary'
else: raise AssertionError('completed operation substituted')
assert ops.events==[('integration','integration')]

selected=[]
assert module['_dispatch'](['--workflow-bound'],lambda common:selected.append(common) or 4,lambda:'common')==4
for arguments in ([],['--native'],['--fixture']):
 try: module['_dispatch'](arguments,lambda common:selected.append('effect'),lambda:'wrong')
 except module['QualificationError']: pass
 else: raise AssertionError(arguments)
assert selected==['common']
module['os'].geteuid=lambda:0
try: module['_dispatch'](['--workflow-bound'],lambda common:selected.append('root-effect'),lambda:'wrong')
except module['QualificationError']: pass
else: raise AssertionError('root entry accepted')
assert selected==['common']

module['os'].geteuid=lambda:1000
session=Session();events.clear()
sys.modules['common']=types.SimpleNamespace(NativeSession=NativeSession,ReportCandidate=Candidate)
sys.argv=[${JSON.stringify(path)},'--workflow-bound']
try: runpy.run_path(${JSON.stringify(path)},run_name='__main__')
except SystemExit as error: assert error.code==0
else: raise AssertionError('CLI did not exit')
`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal((source.match(/run_fixed_operation\(/gu) ?? []).length, 1);
  assert.doesNotMatch(source, /production_checks|metadata|closure_sha256|output_sha256|source_set_sha256/u);
  assert.doesNotMatch(source, /sudo|subprocess|ctypes|fork\(|pidfd|unshare|mount\(|\/proc\//u);
  assert.ok(source.split("\n").every((line) => line.length <= 120));
});
