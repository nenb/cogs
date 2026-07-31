import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-b-compression.py";
const source = readFileSync(path, "utf8");
const launcherSource = readFileSync("deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", "utf8");

function python(body: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", body], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

test("Job B leaves exact compression summaries to one immutable common receipt", () => {
  const harness = `
import runpy,sys,types
module=runpy.run_path(${JSON.stringify(path)},run_name='job_b_test')
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
 def __init__(self): self.evidence=Evidence(True)
 def run_fixed_operation(self,operation): events.append(('operation',operation));return Bomb()
 def settle_native_phase(self): events.append(('settle',));return self.evidence
 def publish(self,candidate): events.append(('publish',candidate.failure_phase,candidate.diagnostics,candidate.primary_error))
session=Session()
class NativeSession:
 @staticmethod
 def begin(job,driver):
  assert (job,driver)==('B',${JSON.stringify(path)});return session
common=types.SimpleNamespace(NativeSession=NativeSession,ReportCandidate=Candidate)
assert module['_run'](common)==0
assert events==[('operation','B'),('settle',),('publish',None,None,None)]
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
ops=Ops();real_session=real_common.NativeSession._begin_with_ops(types.SimpleNamespace(job='B'),ops,Cust())
try: module['_operation'](real_session)
except RuntimeError as error: assert str(error)=='safe native boundary'
else: raise AssertionError('completed operation substituted')
assert ops.events==[('B','B')]

selected=[]
assert module['_dispatch'](['--workflow-bound'],lambda common:selected.append(common) or 9,lambda:'common')==9
for arguments in ([],['--native'],['--command']):
 try: module['_dispatch'](arguments,lambda common:selected.append('effect'),lambda:'wrong')
 except module['QualificationError']: pass
 else: raise AssertionError(arguments)
assert selected==['common']

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
  assert.doesNotMatch(source, /production_checks|metadata|parser|seal_mask|closure_sha256|output_sha256/u);
  assert.doesNotMatch(source, /fork\(|pidfd|waitid|unshare|mount\(|\/proc\//u);
  assert.ok(source.split("\n").every((line) => line.length <= 120));
});

test("Job B wrapper capabilities terminate at the zero-capability child boundary", () => {
  const start = launcherSource.indexOf("def _enter_boundary(");
  const end = launcherSource.indexOf("\ndef _child_fd_install(", start);
  assert.ok(start >= 0 && end > start);
  const boundary = launcherSource.slice(start, end);
  const ordered = [
    "ops.drop_bounding()",
    "ops.capset_zero()",
    'capabilities_zero = not any(capabilities[name] for name in scalar_names)',
    'capabilities_zero = capabilities_zero and not any(capabilities["bounding"]) and not any(capabilities["ambient"])',
    '_require(capabilities_zero and groups_empty',
  ];
  const positions = ordered.map((token) => boundary.indexOf(token));
  assert.ok(positions.every((position) => position >= 0));
  assert.deepEqual(positions, positions.toSorted((left, right) => left - right));
  assert.doesNotMatch(launcherSource, /sys_admin|sys_ptrace/iu);
});

test("launcher ENOENT metadata identifies only the fixed open object class", () => {
  const harness = `
import errno,importlib.util,sys
path='deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py'
spec=importlib.util.spec_from_file_location('job_b_open_classifier',path)
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
ops=module._SystemOps();root=f'{module._ROOT_PARENT}/{module._ROOT_LEAF}'
cases=(
 ('/proc/4815162342/exe','oe-pe'),
 ('/proc/4815162342/map_files/secret-range','oe-pm'),
 ('/proc/4815162342/fd','oe-pf'),
 ('/proc/self/fdinfo/77','oe-pi'),
 ('/proc/4815162342/status','oe-ps'),
 ('/proc/4815162342/maps','oe-pa'),
 ('/proc/4815162342/stat','oe-pt'),
 ('/proc/4815162342/limits','oe-pl'),
 ('/proc/4815162342/ns/user','oe-pn'),
 ('/proc/4815162342/task/9918273/children','oe-pc'),
 ('/proc/thread-self/children','oe-pc'),
 (module._ROOT_PARENT,'oe-r'),
 (root,'oe-r'),
 (root+'/bin/zstd-never-disclose','oe-s'),
 (root+'-impostor/never-disclose','oe-o'),
 ('/proc/4815162342/mountinfo','oe-o'),
)
assert len({code for _,code in cases})==13
original=module.os.open
def missing(path,flags,mode=0o600):
 raise FileNotFoundError(errno.ENOENT,'dynamic-open-detail-never-disclose',path)
module.os.open=missing
try:
 for requested,expected in cases:
  try: ops.open(requested,0)
  except module.RuntimeLauncherError as error:
   assert type(error) is module.RuntimeLauncherError and error.code==expected
   metadata='|'.join((str(error),repr(error),repr(error.args),repr(error.__dict__)))
   assert requested not in metadata and '4815162342' not in metadata
   assert '9918273' not in metadata and 'never-disclose' not in metadata
   assert error.__cause__ is None and error.__context__ is None
  else: raise AssertionError(('accepted missing open',requested))
 denied=PermissionError(errno.EACCES,'preserved-other-errno','/dynamic/denied')
 def inaccessible(path,flags,mode=0o600): raise denied
 module.os.open=inaccessible
 try: ops.open('/dynamic/denied',0)
 except PermissionError as error: assert error is denied
 else: raise AssertionError('non-ENOENT changed')
finally: module.os.open=original
`;
  const run = python(harness);
  assert.equal(run.status, 0, run.stderr);
});
