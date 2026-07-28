import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "scripts/native-qualification/job-a-runtime-mappings.py");
const closure = join(root, "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py");
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

test("Job A recomputes exact closure and mapped-sequence summaries", () => {
  const result = portable(`
import hashlib, json
revision='1'*40
source_digest='2'*64
objects=[
 {'role':'executable','sha256':'3'*64,'size_bytes':10,'soname':None,'needed':['libc.so.6']},
 {'role':'loader','sha256':'4'*64,'size_bytes':11,'soname':'ld.so.2','needed':[]},
 {'role':'library','sha256':'5'*64,'size_bytes':12,'soname':'libc.so.6','needed':[]},
]
normalized=[{'needed':row['needed'],'role':row['role'],'sha256':row['sha256'],'size':row['size_bytes'],'soname':row['soname']} for row in objects]
mapped=[{'role':row['role'],'sha256':row['sha256']} for row in normalized]
digest_sequence=[[row['role'],row['sha256']] for row in normalized]
canonical=lambda value: json.dumps(value,allow_nan=False,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
value={
 'version':ns['RESULT_VERSION'],'source_revision':revision,'source_set_sha256':source_digest,
 'closure_sha256':hashlib.sha256(canonical(normalized)).hexdigest(),
 'mapping_sha256':hashlib.sha256(canonical(digest_sequence)).hexdigest(),
 'objects':objects,'mapped':mapped,
 'mapped_generations_exact':True,'mapping_stable':True,'helper_reaped':True,
 'descriptors_restored':True,'children_reaped':True,
}
rows=ns['qualify'](value,revision,source_digest)
assert [row['role'] for row in rows[:-1]] == ['executable','loader','library']
assert rows[-1]['mapped_sequence'] == mapped
for mutation in ('role','oversize','needed-duplicate','provider','extra-library','mapped','closure','mapping'):
 bad={**value,'objects':[dict(row) for row in objects],'mapped':[dict(row) for row in mapped]}
 if mutation=='role': bad['objects'][0]['role']='loader'
 if mutation=='oversize': bad['objects'][2]['size_bytes']=134217729
 if mutation=='needed-duplicate': bad['objects'][0]['needed']=['libc.so.6','libc.so.6']
 if mutation=='provider': bad['objects'][2]['soname']='other.so'
 if mutation=='extra-library': bad['objects'].append({'role':'library','sha256':'6'*64,'size_bytes':1,'soname':'unused.so','needed':[]})
 if mutation=='mapped': bad['mapped'][0]['sha256']='6'*64
 if mutation=='closure': bad['closure_sha256']='6'*64
 if mutation=='mapping': bad['mapping_sha256']='6'*64
 try: ns['qualify'](bad,revision,source_digest)
 except ns['QualificationError']: pass
 else: raise AssertionError(mutation)
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("Job A safe adapter reaches only the fixed common operation", () => {
  const result = portable(`
events=[]
class Evidence: restored=False
class Session:
 context=type('Context',(),{'head_sha':'1'*40})()
 source_set_sha256='2'*64
 def run_fixed_operation(self,operation): events.append(('operation',operation)); raise RuntimeError('stopped-before-owner')
 def settle_native_phase(self): events.append(('settle',)); return Evidence()
 def publish(self,candidate): events.append(('publish',candidate.primary_error.args[0]))
session=Session()
class NativeSession:
 @classmethod
 def begin(cls,job,path): events.append(('begin',job)); return session
class Candidate:
 def __init__(self,**values): self.__dict__.update(values)
common=type('Common',(),{'NativeSession':NativeSession,'ReportCandidate':Candidate,'REPORT_LIMIT':32768})
assert ns['_workflow_bound'](common)==1
assert events == [('begin','A'),('operation','A'),('settle',),('publish','stopped-before-owner')]
`);
  assert.equal(result.status, 0, result.stderr);
});

test("Job A composes the admitted production closure owner", () => {
  const closureSource = readFileSync(closure, "utf8");
  const launcherSource = readFileSync(launcher, "utf8");
  assert.match(closureSource, /def _qualify_admitted_fixed_python_mapping\(/u);
  assert.match(closureSource, /def _qualify_fixed_python_mapping_with_ops\([\s\S]*PreparedRuntimeClosure\._for_fixed_mapping/u);
  assert.match(launcherSource, /cogs\.runtime-source-admission\/mapping-v1/u);
  assert.match(launcherSource, /_qualify_admitted_fixed_python_mapping/u);
  assert.doesNotMatch(launcherSource, /_coordinate_admitted_mapping_only|_MappingAuthority/u);
  assert.match(source, /NativeSession\.begin\("A", __file__\)/u);
  assert.match(source, /session\.run_fixed_operation\(OPERATION\)/u);
  assert.doesNotMatch(source, /os\.(?:pipe|fork|pidfd_open|execve|waitpid)|unshare|mount\(|\/proc\/|Snapshot|finalize_report/u);
  assert.doesNotMatch(source, /cleanup\s*=|CLEANUP_KEYS|source_admission|bootstrap_sha256/u);
});

test("Job A selector has a no-effects dispatch seam", () => {
  const result = portable(`
events=[]
assert ns['_dispatch'](['--workflow-bound'],lambda: events.append('run') or 7)==7
for args in ([],['--native'],['--fixture'],['--self-test']):
 try: ns['_dispatch'](args,lambda: events.append('effect'))
 except ns['QualificationError']: pass
 else: raise AssertionError(args)
assert events == ['run']
`);
  assert.equal(result.status, 0, result.stderr);
});
