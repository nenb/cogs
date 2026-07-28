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
assert launcher._root_capsule_failure_code(True,256,b'root-launcher-process-transfer-0123456789abcdef\\n')=='root-process-transfer'
assert launcher._root_capsule_failure_code(True,256,b'opaque').startswith('sudo-complete-256-')
`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(run.status, 0, run.stderr);
});

test("Job E provisions one independently derived root pin and removes only its exact files", () => {
  const harness = `
import json,os,runpy,stat,tempfile
from pathlib import Path
from types import SimpleNamespace
module=runpy.run_path(${JSON.stringify(path)},run_name='job_e_root_test')
with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary);bootstrap_parent=root/'usr/local/libexec';authority_parent=root/'etc/cogs'
 (root/'usr/local').mkdir(parents=True);(root/'etc').mkdir()
 module['ROOT_BOOTSTRAP_PATH']=bootstrap_parent/'cogs-native-root-bootstrap-v1.py'
 module['ROOT_AUTHORITY_PATH']=authority_parent/'native-root-authority-v1.json'
 module['ROOT_STATE_PATH']=authority_parent/'.native-root-authority-install-v1.json'
 bootstrap=b'fixed reviewed bootstrap';authority=b'{"fixed":"reviewed"}';revision='a'*40
 module['_root_material']=lambda value:(bootstrap,authority) if value==revision else (_ for _ in ()).throw(AssertionError(value))
 module['_provision_root_authority'].__globals__.update(module)
 module['_cleanup_root_authority'].__globals__.update(module)
 identity=dict(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5,st_mode=0o100400,st_uid=0,st_gid=0,st_nlink=1)
 before=SimpleNamespace(**identity,st_atime_ns=6);after=SimpleNamespace(**identity,st_atime_ns=7)
 assert module['_root_file_identity'](before)==module['_root_file_identity'](after)
 after.st_ctime_ns=8
 assert module['_root_file_identity'](before)!=module['_root_file_identity'](after)
 module['_provision_root_authority'](revision)
 assert module['ROOT_BOOTSTRAP_PATH'].read_bytes()==bootstrap
 assert module['ROOT_AUTHORITY_PATH'].read_bytes()==authority
 state=json.loads(module['ROOT_STATE_PATH'].read_bytes())
 assert state=={'bootstrap_parent_created':True,'revision':revision}
 assert stat.S_IMODE(module['ROOT_BOOTSTRAP_PATH'].stat().st_mode)==0o444
 os.chmod(module['ROOT_AUTHORITY_PATH'],0o644);module['ROOT_AUTHORITY_PATH'].write_bytes(b'foreign')
 try: module['_cleanup_root_authority'](revision)
 except module['QualificationError']: pass
 else: raise AssertionError('foreign root authority deleted')
 assert module['ROOT_BOOTSTRAP_PATH'].exists() and module['ROOT_STATE_PATH'].exists()
 module['ROOT_AUTHORITY_PATH'].write_bytes(authority);os.chmod(module['ROOT_AUTHORITY_PATH'],0o444)
 module['_cleanup_root_authority'](revision)
 assert not bootstrap_parent.exists() and not authority_parent.exists()

calls=[]
module['_provision_root_authority']=lambda revision:calls.append(('provision',revision))
module['_cleanup_root_authority']=lambda revision:calls.append(('cleanup',revision))
module['_root_authority_action'].__globals__.update(module)
module['os'].geteuid=lambda:0
saved=dict(os.environ);os.environ.clear();os.environ['NQ_ROOT_AUTHORITY_SHA']='b'*40
try:
 assert module['_root_authority_action'](['--provision-root-authority'])==0 and not os.environ
 os.environ.update({'NQ_ROOT_AUTHORITY_SHA':'b'*40,'LC_CTYPE':'C.UTF-8'})
 assert module['_root_authority_action'](['--cleanup-root-authority'])==0 and not os.environ
 os.environ.update({'NQ_ROOT_AUTHORITY_SHA':'b'*40,'EXTRA':'caller'})
 try: module['_root_authority_action'](['--provision-root-authority'])
 except module['QualificationError']: pass
 else: raise AssertionError('ambient root authority accepted')
finally: os.environ.clear();os.environ.update(saved)
assert calls==[('provision','b'*40),('cleanup','b'*40)]
assert module['_entry_diagnostic'](['--cleanup-root-authority'],module['QualificationError']('root authority file changed'))==b'native-e-cleanup-root-authority-file-changed\\n'
`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(run.status, 0, run.stderr);
  assert.match(source, /rev-parse.*revision.*commit/su);
  assert.match(source, /Path\(__file__\)\.read_bytes\(\) == _reviewed_blob/su);
  assert.match(source, /root_bootstrap_sha256/su);
  const cleanupSource = source.slice(source.indexOf("def _cleanup_root_authority("), source.indexOf("def _root_authority_action("));
  assert.doesNotMatch(cleanupSource, /missing_ok/u);
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
  const operationSource = source.slice(source.indexOf("def _operation("), source.indexOf("def _combine("));
  assert.doesNotMatch(operationSource, /production_checks|metadata|seccomp_program|POLICY_SHA|source_set_sha256/u);
  assert.doesNotMatch(operationSource, /sudo|subprocess|ctypes|fork\(|pidfd|unshare|mount\(|\/proc\//u);
  assert.ok(source.split("\n").every((line) => line.length <= 120));
});
