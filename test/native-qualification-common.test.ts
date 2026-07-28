import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const commonPath = "scripts/native-qualification/common.py";
const clients = [
  "job-a-runtime-mappings.py",
  "job-b-compression.py",
  "job-c-descriptors.py",
  "job-d-process-lifecycle.py",
  "job-e-sandbox.py",
  "thin-integration.py",
].map((name) => `scripts/native-qualification/${name}`);

test("common alone derives exact B/integration reports from immutable receipts", () => {
  const harness = `
import copy,hashlib,json,sys
sys.path.insert(0,'scripts/native-qualification');import common

def digest_file(path):
 with open(path,'rb') as source: return hashlib.sha256(source.read()).hexdigest()

def context(job):
 return common.WorkflowContext(
  job=job,
  repository='owner/repo',
  head_repository='owner/repo',
  head_sha='a'*40,
  envelope_sha='b'*40,
  workflow_sha='a'*40,
  merge_sha='b'*40,
  base_sha='c'*40,
  job_id=common.JOB_IDS[job],
  run_id=1,
  run_attempt=1,
  pull_request_number=1,
  runner_version='20260720.1',
  kernel_release='6.8.0-100-generic',
  architecture='x86_64',
  workflow_blob_sha256=digest_file(common.WORKFLOW),
  driver_blob_sha256=digest_file(common.COMMON.parent/common.DRIVERS[job]),
  common_blob_sha256=digest_file(common.COMMON),
 )

baseline={name:('baseline',name) for name in common.CLEANUP_KEYS}
baseline['paths']=(None,None)
class Ops:
 def __init__(self,result):
  self.fds=common.FdRegistry()
  self.source_set_sha256=result['source_set_sha256']
  self.result=result
  self.operation_calls=0
  self.observation_calls=0
 def observe(self,workflow_context):
  self.observation_calls+=1
  return dict(baseline)
 def run_fixed_operation(self,workflow_context,operation):
  self.operation_calls+=1
  assert operation==workflow_context.job
  return self.result
class Custodian:
 def publish(self,raw): self.raw=raw

def publish(job,result,mutate):
 ops=Ops(result)
 custodian=Custodian()
 session=common.NativeSession._begin_with_ops(context(job),ops,custodian)
 session.run_fixed_operation(job)
 mutate(result)
 evidence=session.settle_native_phase()
 assert evidence.restored is True
 try:
  evidence.values['checkout']=False
  raise AssertionError('mutable cleanup evidence')
 except TypeError:
  pass
 try:
  common.ReportCandidate(production_checks={},metadata=[])
  raise AssertionError('caller report authority accepted')
 except TypeError:
  pass
 session.publish(common.ReportCandidate())
 assert ops.operation_calls==1
 assert ops.observation_calls==2
 return json.loads(custodian.raw)

def objects(executable):
 return [
  {'role':'executable','sha256':executable,'size_bytes':11,'soname':None,'needed':['ld.so']},
  {'role':'loader','sha256':'2'*64,'size_bytes':12,'soname':'ld.so','needed':[]},
 ]
def normalized(rows):
 return [
  {'needed':row['needed'],'role':row['role'],'sha256':row['sha256'],
   'size':row['size_bytes'],'soname':row['soname']}
  for row in rows
 ]
def digest(value): return hashlib.sha256(common._canonical(value)).hexdigest()
def tool(name,executable):
 rows=objects(executable)
 view=normalized(rows)
 mapping=digest([[row['role'],row['sha256']] for row in view])
 return {
  'id':name,
  'objects':rows,
  'closure_sha256':digest(view),
  'mapping_sha256':mapping,
  'source_sha256':executable,
  'source_size_bytes':11,
  'sealed_sha256':executable,
  'sealed_size_bytes':11,
  'seal_mask':63,
  'execution_mapping_sha256':mapping,
  'output_sha256':common.MARKER_SHA256,
 }
gzip=tool('gzip','3'*64)
zstd=tool('zstd','4'*64)
parser_objects=objects('5'*64)
parser_view=normalized(parser_objects)
parser={'closure_sha256':digest(parser_view),'objects':parser_objects}
def closure_tool(row):
 return {
  'closure_sha256':row['closure_sha256'],
  'objects':normalized(row['objects']),
  'seal_profile':'linux-memfd-exec-seals-v1',
  'sealed_executable':True,
  'tool':row['id'],
 }
closure_view=[
 {'closure_sha256':parser['closure_sha256'],'objects':parser_view,
  'seal_profile':None,'sealed_executable':False,'tool':'python3-parser'},
 closure_tool(zstd),
 closure_tool(gzip),
]
top_closure=digest(closure_view)
b_facts='''
mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact
network_namespace_exact namespace_ownership_exact namespace_handles_exact pid_one
supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero
inheritable_capabilities_zero bounding_capabilities_zero ambient_capabilities_zero
capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route
root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent limits_exact
descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
namespaces_released namespace_handles_released
'''.split()
runtime={name:True for name in b_facts}
runtime.update({
 'version':'cogs.runtime-qualification/v1',
 'marker':'cogs-runtime-qualification-v1',
 'source_revision':'a'*40,
 'source_set_sha256':'6'*64,
 'closure_sha256':top_closure,
 'gzip_output_sha256':common.MARKER_SHA256,
 'zstd_output_sha256':common.MARKER_SHA256,
})
b_result={
 'version':'cogs.runtime-compression-qualification/v1',
 'source_revision':'a'*40,
 'source_set_sha256':'6'*64,
 'closure_sha256':top_closure,
 'parser':parser,
 'tools':[gzip,zstd],
 'runtime':runtime,
}
b_original=copy.deepcopy(b_result)
def mutate_b(value):
 value['tools'][0]['source_sha256']='f'*64
 value['runtime']['pid_one']=False
b_report=publish('B',b_result,mutate_b)
expected_b=[
 b_original['tools'][0],
 b_original['tools'][1],
 {'kind':'summary','id':'trusted-closure','closure_sha256':top_closure,'parser':b_original['parser']},
]
assert b_report['metadata']==expected_b
assert [row['id'] for row in b_report['checks']]==list(common.CHECK_IDS['B'])
assert all(row['outcome']=='pass' for row in b_report['checks'])

ordinary_bools='''
mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact
network_namespace_exact namespace_ownership_exact namespace_handles_exact pid_one
supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero
inheritable_capabilities_zero bounding_capabilities_zero ambient_capabilities_zero
capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route
root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent limits_exact
descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
namespaces_released namespace_handles_released
'''.split()
integration_result={name:True for name in ordinary_bools}
integration_result.update({
 'version':'cogs.runtime-qualification/v1',
 'marker':'cogs-runtime-qualification-v1',
 'source_revision':'a'*40,
 'source_set_sha256':'7'*64,
 'closure_sha256':'8'*64,
 'gzip_output_sha256':common.MARKER_SHA256,
 'zstd_output_sha256':common.MARKER_SHA256,
})
def mutate_integration(value):
 value['closure_sha256']='f'*64
 value['gzip_output_sha256']='e'*64
 value['pid_one']=False
integration_report=publish('integration',integration_result,mutate_integration)
assert integration_report['metadata']==[
 {'id':'closure','role':'digest','sha256':'8'*64,'size_bytes':0},
 {'id':'gzip_output','role':'digest','sha256':common.MARKER_SHA256,'size_bytes':0},
 {'id':'source_set','role':'digest','sha256':'7'*64,'size_bytes':0},
 {'id':'zstd_output','role':'digest','sha256':common.MARKER_SHA256,'size_bytes':0},
]
assert [row['id'] for row in integration_report['checks']]==list(common.CHECK_IDS['integration'])
assert all(row['outcome']=='pass' for row in integration_report['checks'])
`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(run.status, 0, run.stderr);

  for (const path of clients) {
    const source = readFileSync(path, "utf8");
    assert.equal((source.match(/run_fixed_operation\(/gu) ?? []).length, 1, path);
    assert.doesNotMatch(source, /production_checks|metadata|source_set_sha256|context\.head_sha/u);
    assert.doesNotMatch(source, /;\s*\S/u);
    assert.ok(source.split("\n").every((line) => line.length <= 120), path);
  }
  assert.ok(readFileSync(commonPath, "utf8").includes("OperationReceipt"));
});
