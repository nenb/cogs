import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "scripts/native-qualification/job-b-compression.py");
const launcher = join(root, "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py");
const source = readFileSync(script, "utf8");

function portable(program: string) {
  const harness = `
import runpy, sys
path = sys.argv[1]
def audit(event, args):
 if event in {'os.fork','os.posix_spawn','subprocess.Popen'}: raise RuntimeError(event)
 if event == 'open' and str(args[0]).startswith('/proc/'): raise RuntimeError(args[0])
sys.addaudithook(audit)
ns = runpy.run_path(path)
${program}
`;
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness, script], {
    cwd: root,
    env: { PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 5_000,
  });
}

test("Job B publishes exact source, sealed, execution, seal, and marker facts", () => {
  const result = portable(`
import copy, hashlib, json
revision='1'*40
source_digest='2'*64
canonical=lambda item: json.dumps(item,allow_nan=False,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def tool(name, executable, size):
 objects=[
  {'role':'executable','sha256':executable,'size_bytes':size,'soname':None,'needed':['libc.so.6']},
  {'role':'loader','sha256':'4'*64,'size_bytes':11,'soname':'ld.so.2','needed':[]},
  {'role':'library','sha256':'5'*64,'size_bytes':12,'soname':'libc.so.6','needed':[]},
 ]
 normalized=[{'needed':row['needed'],'role':row['role'],'sha256':row['sha256'],'size':row['size_bytes'],'soname':row['soname']} for row in objects]
 mapping=hashlib.sha256(canonical([[row['role'],row['sha256']] for row in normalized])).hexdigest()
 return {'id':name,'objects':objects,'closure_sha256':hashlib.sha256(canonical(normalized)).hexdigest(),
  'mapping_sha256':mapping,'source_sha256':executable,'source_size_bytes':size,
  'sealed_sha256':executable,'sealed_size_bytes':size,'seal_mask':63,
  'execution_mapping_sha256':mapping,'output_sha256':ns['MARKER_SHA256']}
tool_rows=[tool('gzip','6'*64,10),tool('zstd','7'*64,13)]
parser_objects=[
 {'role':'executable','sha256':'8'*64,'size_bytes':14,'soname':None,'needed':['libc.so.6']},
 {'role':'loader','sha256':'4'*64,'size_bytes':11,'soname':'ld.so.2','needed':[]},
 {'role':'library','sha256':'5'*64,'size_bytes':12,'soname':'libc.so.6','needed':[]},
]
def view(objects):
 return [{'needed':row['needed'],'role':row['role'],'sha256':row['sha256'],'size':row['size_bytes'],'soname':row['soname']} for row in objects]
parser={'closure_sha256':hashlib.sha256(canonical(view(parser_objects))).hexdigest(),'objects':parser_objects}
def aggregate_tool(row):
 return {'closure_sha256':row['closure_sha256'],'objects':view(row['objects']),
  'seal_profile':'linux-memfd-exec-seals-v1','sealed_executable':True,'tool':row['id']}
aggregate=[{'closure_sha256':parser['closure_sha256'],'objects':view(parser_objects),
 'seal_profile':None,'sealed_executable':False,'tool':'python3-parser'},
 aggregate_tool(tool_rows[1]),aggregate_tool(tool_rows[0])]
top_closure=hashlib.sha256(canonical(aggregate)).hexdigest()
runtime={name:True for name in ns['FACTS']}
runtime.update(version='cogs.runtime-qualification/v1',marker=ns['MARKER'],source_revision=revision,
 source_set_sha256=source_digest,closure_sha256=top_closure,
 gzip_output_sha256=ns['MARKER_SHA256'],zstd_output_sha256=ns['MARKER_SHA256'])
value={'version':ns['RESULT_VERSION'],'source_revision':revision,'source_set_sha256':source_digest,
 'closure_sha256':top_closure,'parser':parser,'tools':tool_rows,'runtime':runtime}
rows=ns['qualify'](value,revision,source_digest)
assert [row['id'] for row in rows] == ['gzip','zstd','trusted-closure']
assert rows[-1] == {'kind':'summary','id':'trusted-closure','closure_sha256':top_closure,'parser':parser}
assert all(row['seal_mask']==63 for row in rows[:2])
for mutation in ('mask15','equal-wrong','source-sealed','size','mapping','object','tool-substitution','parser','aggregate','revision','false-fact'):
 bad=copy.deepcopy(value)
 if mutation=='mask15': bad['tools'][0]['seal_mask']=15
 if mutation=='equal-wrong':
  bad['runtime']['gzip_output_sha256']=bad['runtime']['zstd_output_sha256']='8'*64
  for row in bad['tools']: row['output_sha256']='8'*64
 if mutation=='source-sealed': bad['tools'][0]['sealed_sha256']='8'*64
 if mutation=='size': bad['tools'][0]['source_size_bytes']=134217729
 if mutation=='mapping': bad['tools'][0]['execution_mapping_sha256']='8'*64
 if mutation=='object': bad['tools'][0]['objects'][2]['soname']='other.so'
 if mutation=='tool-substitution': bad['tools'].reverse()
 if mutation=='parser': bad['parser']['closure_sha256']='9'*64
 if mutation=='aggregate':
  bad['closure_sha256']='9'*64
  bad['runtime']['closure_sha256']='9'*64
 if mutation=='revision': bad['source_revision']='0'*40
 if mutation=='false-fact': bad['runtime']['children_reaped']=False
 try: ns['qualify'](bad,revision,source_digest)
 except ns['QualificationError']: pass
 else: raise AssertionError(mutation)
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("Job B safe adapter reaches the real common operation boundary", () => {
  const result = portable(`
import types
sys.path.insert(0,'scripts/native-qualification')
import common
base={key:('baseline',key) for key in common.CLEANUP_KEYS}
base['paths']=(None,None)
class Ops:
 def __init__(self):
  self.fds=common.FdRegistry(); self.source_set_sha256='2'*64; self.events=[]
 def observe(self,context): return base
 def run_fixed_operation(self,context,operation):
  self.events.append((context.job,operation))
  raise RuntimeError('safe native boundary')
class Cust:
 def abort(self,error): self.error=error
ops=Ops()
context=types.SimpleNamespace(job='B')
session=common.NativeSession._begin_with_ops(context,ops,Cust())
try: ns['_production_operation'](session)
except RuntimeError as error: assert str(error)=='safe native boundary'
else: raise AssertionError('completed result substituted')
assert ops.events == [('B','B')]
`);
  assert.equal(result.status, 0, result.stderr);
});

test("Job B real __main__ preserves a successful exit", () => {
  const result = portable(`
import hashlib, json, runpy, types
revision='1'*40; source_digest='2'*64
canonical=lambda value: json.dumps(value,allow_nan=False,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def tool(name,digest):
 objects=[{'role':'executable','sha256':digest,'size_bytes':10,'soname':None,'needed':['ld.so']},
  {'role':'loader','sha256':'4'*64,'size_bytes':11,'soname':'ld.so','needed':[]}]
 normalized=[{'needed':row['needed'],'role':row['role'],'sha256':row['sha256'],'size':row['size_bytes'],'soname':row['soname']} for row in objects]
 mapping=hashlib.sha256(canonical([[row['role'],row['sha256']] for row in normalized])).hexdigest()
 return {'id':name,'objects':objects,'closure_sha256':hashlib.sha256(canonical(normalized)).hexdigest(),
  'mapping_sha256':mapping,'source_sha256':digest,'source_size_bytes':10,'sealed_sha256':digest,
  'sealed_size_bytes':10,'seal_mask':63,'execution_mapping_sha256':mapping,'output_sha256':ns['MARKER_SHA256']}
tool_rows=[tool('gzip','6'*64),tool('zstd','7'*64)]
parser_objects=[{'role':'executable','sha256':'8'*64,'size_bytes':12,'soname':None,'needed':['ld.so']},
 {'role':'loader','sha256':'4'*64,'size_bytes':11,'soname':'ld.so','needed':[]}]
def view(objects):
 return [{'needed':row['needed'],'role':row['role'],'sha256':row['sha256'],'size':row['size_bytes'],'soname':row['soname']} for row in objects]
parser={'closure_sha256':hashlib.sha256(canonical(view(parser_objects))).hexdigest(),'objects':parser_objects}
def aggregate_tool(row):
 return {'closure_sha256':row['closure_sha256'],'objects':view(row['objects']),
  'seal_profile':'linux-memfd-exec-seals-v1','sealed_executable':True,'tool':row['id']}
aggregate=[{'closure_sha256':parser['closure_sha256'],'objects':view(parser_objects),
 'seal_profile':None,'sealed_executable':False,'tool':'python3-parser'},
 aggregate_tool(tool_rows[1]),aggregate_tool(tool_rows[0])]
top_closure=hashlib.sha256(canonical(aggregate)).hexdigest()
runtime={name:True for name in ns['FACTS']}
runtime.update(version='cogs.runtime-qualification/v1',marker=ns['MARKER'],source_revision=revision,
 source_set_sha256=source_digest,closure_sha256=top_closure,
 gzip_output_sha256=ns['MARKER_SHA256'],zstd_output_sha256=ns['MARKER_SHA256'])
value={'version':ns['RESULT_VERSION'],'source_revision':revision,'source_set_sha256':source_digest,
 'closure_sha256':top_closure,'parser':parser,'tools':tool_rows,'runtime':runtime}
class Evidence: restored=True
class Session:
 context=types.SimpleNamespace(head_sha=revision)
 source_set_sha256=source_digest
 def run_fixed_operation(self,operation): assert operation=='B'; return value
 def settle_native_phase(self): return Evidence()
 def publish(self,candidate): assert candidate.primary_error is None
class NativeSession:
 @classmethod
 def begin(cls,job,path): assert job=='B'; return Session()
class Candidate:
 def __init__(self,**values): self.__dict__.update(values)
common=types.ModuleType('common'); common.NativeSession=NativeSession
common.ReportCandidate=Candidate; common.REPORT_LIMIT=32768; sys.modules['common']=common
sys.argv=[path,'--workflow-bound']
try: runpy.run_path(path,run_name='__main__')
except SystemExit as error: assert error.code==0
else: raise AssertionError('main did not exit')
`);
  assert.equal(result.status, 0, result.stderr);
});

test("Job B composes only the held-byte compression owner", () => {
  const launcherSource = readFileSync(launcher, "utf8");
  assert.match(launcherSource, /RuntimeCompressionQualificationResult/u);
  assert.match(launcherSource, /def _launch_admitted_fixed_compression_qualification\(/u);
  assert.match(launcherSource, /cogs\.runtime-source-admission\/compression-v1/u);
  assert.match(launcherSource, /_runtime_metadata[\s\S]*RuntimeCompressionToolObservation/u);
  assert.match(source, /NativeSession\.begin\("B", __file__\)/u);
  assert.match(source, /session\.run_fixed_operation\(OPERATION\)/u);
  assert.doesNotMatch(source, /row\["seal_mask"\]\s*=|seal_mask.*15/u);
  assert.doesNotMatch(source, /os\.(?:pipe|fork|pidfd_open|execve|waitpid)|unshare|mount\(|\/proc\/|Snapshot|finalize_report/u);
  assert.doesNotMatch(source, /cleanup\s*=|CLEANUP_KEYS|source_admission|bootstrap_sha256/u);
});

test("Job B selector has a no-effects dispatch seam", () => {
  const result = portable(`
events=[]
assert ns['_dispatch'](['--workflow-bound'],lambda: events.append('run') or 9)==9
for args in ([],['--native'],['--fixture'],['--command']):
 try: ns['_dispatch'](args,lambda: events.append('effect'))
 except ns['QualificationError']: pass
 else: raise AssertionError(args)
assert events == ['run']
`);
  assert.equal(result.status, 0, result.stderr);
});
