import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-e-sandbox.py";
const source = readFileSync(path, "utf8");

test("sandbox root capsule settles an early reader close before rejecting", () => {
  const harness = `
import errno,importlib.util,sys,types
path='deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py'
spec=importlib.util.spec_from_file_location('sandbox_launcher_pipe_test',path)
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
events=[]
class Ops:
 def __init__(self): self.closed=set()
 def close(self,fd): self.closed.add(fd);events.append(('close',fd))
 def read(self,fd,size):
  events.append(('read',fd))
  return b'S' if fd==106 else b''
 def write(self,fd,data):
  if fd==101:
   events.append(('epipe',fd));raise BrokenPipeError(errno.EPIPE,'root bootstrap rejected')
  events.append(('write',fd));return len(data)
class Owner:
 instance=None
 def __init__(self,ops): Owner.instance=self;self.process=None;self.primary=None
 def spawn(self): self.process=types.SimpleNamespace(reaped=False);return 41,self.process,None
 def plan_setsid(self,process): events.append(('plan',41))
 def release(self,process): events.append(('release',41))
 def confirm_setsid(self,process): events.append(('confirm',41))
 def stop(self,process): raise AssertionError('failed process bypassed cleanup')
 def cleanup(self,primary):
  assert self.process.reaped and isinstance(primary,launcher.RuntimeLauncherError)
  assert primary.code.startswith('sudo-early-0-');self.primary=primary;events.append(('cleanup','sudo-early'))
ops=Ops();next_fd=iter(range(100,110))
def pipe2(flags): return next(next_fd),next(next_fd)
def select_(read,write,error,timeout=None): return list(read),[],[]
def wait(process,deadline): process.reaped=True;events.append(('wait',41));return 0
had_pipe2=hasattr(launcher.os,'pipe2');saved_pipe2=getattr(launcher.os,'pipe2',None)
saved=(launcher._ProcessOwner,launcher.select.select,launcher._wait_bounded)
launcher._ProcessOwner=Owner;launcher.os.pipe2=pipe2;launcher.select.select=select_;launcher._wait_bounded=wait
try:
 try: launcher._run_root_capsule_with_ops(ops,b'capsule')
 except launcher.RuntimeLauncherError as error: assert error.code.startswith('sudo-early-0-')
 else: raise AssertionError('early root rejection accepted')
finally:
 launcher._ProcessOwner,launcher.select.select,launcher._wait_bounded=saved
 if had_pipe2: launcher.os.pipe2=saved_pipe2
 else: delattr(launcher.os,'pipe2')
assert ops.closed==set(range(100,110)),ops.closed
ordered=[events.index(item) for item in (('epipe',101),('close',101),('read',102),('read',104),('wait',41),('cleanup','sudo-early'))]
assert ordered==sorted(ordered),events
`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(run.status, 0, run.stderr);
});

test("Job E is an unprivileged failure-only client of one common sandbox receipt", () => {
  const harness = `
import runpy,sys,types
module=runpy.run_path(${JSON.stringify(path)},run_name='job_e_test')
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
 def begin(job,driver): assert (job,driver)==('E',${JSON.stringify(path)});return session
common=types.SimpleNamespace(NativeSession=NativeSession,ReportCandidate=Candidate)
assert module['_run'](common)==0
assert events==[('operation','E'),('settle',),('publish',None,None,None)]
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
ops=Ops();real_session=real_common.NativeSession._begin_with_ops(types.SimpleNamespace(job='E'),ops,Cust())
try: module['_operation'](real_session)
except RuntimeError as error: assert str(error)=='safe native boundary'
else: raise AssertionError('completed operation substituted')
assert ops.events==[('E','E')]

selected=[]
assert module['_dispatch'](['--workflow-bound'],lambda common:selected.append(common) or 8,lambda:'common')==8
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
  assert.doesNotMatch(source, /production_checks|metadata|seccomp_program|POLICY_SHA|source_set_sha256/u);
  assert.doesNotMatch(source, /sudo|subprocess|ctypes|fork\(|pidfd|unshare|mount\(|\/proc\//u);
  assert.ok(source.split("\n").every((line) => line.length <= 120));
});
