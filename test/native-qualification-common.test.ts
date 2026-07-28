/* biome-ignore-all lint/suspicious/noExplicitAny: hostile mutations intentionally use dynamic JSON */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const workflowPath = ".github/workflows/ci.yml";
const commonPath = "scripts/native-qualification/common.py";
const schemaPath = "schemas/native-qualification-report-v1alpha1.json";
const predecessor = "bec0a19b0b984f88ab9c2effc5059f3737915caa";
const jobs = [
  ["A", "native-qualification-a", "job-a-runtime-mappings.py"],
  ["B", "native-qualification-b", "job-b-compression.py"],
  ["C", "native-qualification-c", "job-c-descriptors.py"],
  ["D", "native-qualification-d", "job-d-process-lifecycle.py"],
  ["E", "native-qualification-e", "job-e-sandbox.py"],
  ["integration", "native-closure-integration", "thin-integration.py"],
] as const;
const checkText = {
  A: "elf_real python_closure_exact map_files_trusted mapped_closure_equal mapping_stable helper_reaped cleanup_restored",
  B: "gzip_source_exact gzip_sealed_exec zstd_source_exact zstd_sealed_exec decompression_deterministic network_denied children_exact cleanup_restored",
  C: "nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact inheritance_exact limit_restored cleanup_restored",
  D: "pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated session_owned process_group_owned term_kill_bounded all_reaped cleanup_restored",
  E: "mount_view_exact checkout_read_only user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact pid_one capabilities_zero noroot_locked nnp_set seccomp_socket_denied seccomp_io_uring_denied no_acquisition_route checkout_unchanged all_reaped mounts_restored cleanup_restored",
  integration: "closure_prepared handoff_exact gzip_deterministic zstd_deterministic marker_exact no_linked_evidence cleanup_restored",
} as const;
const markerHash = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8";
const cleanupKeys = "descriptors children paths mounts namespaces limits checkout".split(" ");
const workflow = readFileSync(workflowPath, "utf8");
const common = readFileSync(commonPath, "utf8");
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8")));

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
const digestValue = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const digestFile = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

function objects(seed = 1) {
  return [
    { role: "executable", sha256: `${seed}`.repeat(64), size_bytes: 11, soname: null, needed: ["ld.so"] },
    { role: "loader", sha256: `${seed + 1}`.repeat(64), size_bytes: 12, soname: "ld.so", needed: [] },
  ];
}
function normalized(rows: ReturnType<typeof objects>) {
  return rows.map(({ size_bytes, ...row }) => ({ needed: row.needed, role: row.role, sha256: row.sha256,
    size: size_bytes, soname: row.soname }));
}
function metadata(job: keyof typeof checkText): unknown[] {
  const rows = objects();
  const mapped = rows.map(({ role, sha256 }) => ({ role, sha256 }));
  if (job === "A") return [
    ...rows.map((row, index) => ({ kind: "object", id: `python-object-${index}`, ...row })),
    { kind: "summary", closure_sha256: digestValue(normalized(rows)),
      mapping_sha256: digestValue(mapped.map(({ role, sha256 }) => [role, sha256])), mapped_sequence: mapped },
  ];
  if (job === "B") {
    const tools = [objects(3), objects(5)].map((toolRows, index) => {
      const view = normalized(toolRows);
      const mapping = digestValue(view.map(({ role, sha256 }) => [role, sha256]));
      const executable = toolRows[0]; assert.ok(executable);
      return { id: index === 0 ? "gzip" : "zstd", objects: toolRows, closure_sha256: digestValue(view),
        mapping_sha256: mapping, source_sha256: executable.sha256, source_size_bytes: 11,
        sealed_sha256: executable.sha256, sealed_size_bytes: 11, seal_mask: 63,
        execution_mapping_sha256: mapping, output_sha256: markerHash };
    });
    const parserObjects = objects(1); const parserView = normalized(parserObjects);
    const closureView = (row: typeof tools[number]) => ({ closure_sha256: row.closure_sha256,
      objects: normalized(row.objects), seal_profile: "linux-memfd-exec-seals-v1",
      sealed_executable: true, tool: row.id });
    const gzip = tools[0]; const zstd = tools[1]; assert.ok(gzip); assert.ok(zstd);
    const top = digestValue([{ closure_sha256: digestValue(parserView), objects: parserView,
      seal_profile: null, sealed_executable: false, tool: "python3-parser" },
      closureView(zstd), closureView(gzip)]);
    return [...tools, { kind: "summary", id: "trusted-closure", closure_sha256: top,
      parser: { closure_sha256: digestValue(parserView), objects: parserObjects } }];
  }
  if (job === "E") return [{ id: "sandbox-policy", role: "policy",
    sha256: "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2", size_bytes: 0 }];
  if (job === "integration") return [
    { id: "closure", role: "digest", sha256: "8".repeat(64), size_bytes: 0 },
    { id: "gzip_output", role: "digest", sha256: markerHash, size_bytes: 0 },
    { id: "source_set", role: "digest", sha256: "9".repeat(64), size_bytes: 0 },
    { id: "zstd_output", role: "digest", sha256: markerHash, size_bytes: 0 },
  ];
  return [];
}
const runtimeObservations = ("mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact " +
  "network_namespace_exact namespace_ownership_exact namespace_handles_exact pid_one supplementary_groups_empty " +
  "effective_capabilities_zero permitted_capabilities_zero inheritable_capabilities_zero bounding_capabilities_zero " +
  "ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact " +
  "seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route root_readonly_noexec " +
  "root_has_no_proc host_paths_absent checkout_absent limits_exact descriptors_restored children_reaped " +
  "descendants_reaped mounts_restored paths_restored namespaces_released namespace_handles_released").split(" ");
const descriptorObservations = "nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact inheritance_exact limit_restored descriptors_restored children_reaped".split(" ");
const lifecycleObservations = "pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated session_owned process_group_owned credentialed_pidfd_transfer stable_descendant_census adoption_exact term_kill_bounded siginfo_exact all_reaped subreaper_restored descriptors_restored".split(" ");
const sandboxObservations = "user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact pid_one capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact seccomp_program_exact seccomp_denials_exact no_acquisition_route root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored namespaces_released namespace_handles_released".split(" ");
function operationResult(job: keyof typeof checkText): Record<string, unknown> {
  const identity = { source_revision: "a".repeat(40), source_set_sha256: "9".repeat(64) };
  if (job === "A") {
    const rows = metadata("A") as any[]; const summary = rows.pop();
    return { version: "cogs.runtime-mapping-qualification/v1", ...identity,
      closure_sha256: summary.closure_sha256, mapping_sha256: summary.mapping_sha256,
      objects: rows.map(({ kind, id, ...row }) => row), mapped: summary.mapped_sequence,
      mapped_generations_exact: true, mapping_stable: true, helper_reaped: true,
      descriptors_restored: true, children_reaped: true };
  }
  if (job === "B") {
    const rows = metadata("B") as any[]; const summary = rows[2];
    const runtime = { version: "cogs.runtime-qualification/v1", marker: "cogs-runtime-qualification-v1", ...identity,
      closure_sha256: summary.closure_sha256, gzip_output_sha256: markerHash, zstd_output_sha256: markerHash,
      ...Object.fromEntries(runtimeObservations.map((name) => [name, true])) };
    return { version: "cogs.runtime-compression-qualification/v1", ...identity,
      closure_sha256: summary.closure_sha256, parser: summary.parser, tools: rows.slice(0, 2), runtime };
  }
  if (job === "C") return { version: "cogs.runtime-descriptor-qualification/v1", ...identity,
    ...Object.fromEntries(descriptorObservations.map((name) => [name, true])) };
  if (job === "D") return { version: "cogs.runtime-lifecycle-qualification/v1", ...identity,
    ...Object.fromEntries(lifecycleObservations.map((name) => [name, true])) };
  if (job === "E") return { version: "cogs.sandbox-qualification/v1", ...identity,
    seccomp_program_sha256: "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2",
    ...Object.fromEntries(sandboxObservations.map((name) => [name, true])) };
  return { version: "cogs.runtime-qualification/v1", marker: "cogs-runtime-qualification-v1", ...identity,
    closure_sha256: "8".repeat(64), gzip_output_sha256: markerHash, zstd_output_sha256: markerHash,
    ...Object.fromEntries(runtimeObservations.map((name) => [name, true])) };
}
function report(job: keyof typeof checkText, pass = true): any {
  const found = jobs.find(([name]) => name === job);
  assert.ok(found);
  const checks = checkText[job].split(" ").map((id) => ({ id, outcome: "pass" }));
  const cleanup = Object.fromEntries(cleanupKeys.map((key) => [key, true]));
  if (!pass) { const first = checks[0]; assert.ok(first); first.outcome = "fail"; cleanup.paths = false; }
  return { version: "cogs.native-qualification/v1alpha1", job,
    source: { head_sha: "a".repeat(40), checkout_sha: "a".repeat(40),
      driver_blob_sha256: digestFile(`scripts/native-qualification/${found[2]}`), common_blob_sha256: digestFile(commonPath) },
    envelope: { repository: "owner/repo", head_repository: "owner/repo", event_name: "workflow_dispatch",
      github_sha: "b".repeat(40), ref: "refs/heads/main", default_branch: "main", ref_protected: true,
      run_id: 1, run_attempt: 1 },
    workflow: { path: workflowPath, blob_sha256: digestFile(workflowPath), workflow_sha: "b".repeat(40), job_id: found[1] },
    runner: { image: "ubuntu-24.04", image_version: "20260720.1",
      kernel_release: "6.8.0-100-generic", architecture: "x86_64" },
    authority: "exact-run-native-qualification", result: pass ? "pass" : "fail", checks,
    metadata: pass ? metadata(job) : [],
    operation: { result_sha256: "7".repeat(64), source_set_sha256: job === "integration" ? "9".repeat(64) : "8".repeat(64) },
    failure_phase: pass ? null : "portable-test",
    diagnostics_sha256: pass ? null : "d".repeat(64), cleanup };
}
function pythonValidate(values: Array<{ value: unknown; accept: boolean }>) {
  const script = `import json,sys\nsys.path.insert(0,'scripts/native-qualification')\nimport common\nfor row in json.load(sys.stdin):\n ok=True\n try: common._validate(row['value'])\n except BaseException: ok=False\n assert ok is row['accept'], (row['value'].get('job'),ok,row['accept'])`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { input: JSON.stringify(values), encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
}
type WorkflowStep = { id?: string; uses?: string; with?: Record<string, unknown>; if?: string; env?: Record<string, string>; run?: string };
type WorkflowJob = {
  needs?: string | string[];
  if?: string;
  outputs?: Record<string, string>;
  steps: WorkflowStep[];
};
type WorkflowTrigger = {
  workflow_dispatch: { inputs: { reviewed_sha: { required: boolean; type: string } } };
};
const parsedWorkflow = parseYaml(workflow) as { on: WorkflowTrigger; jobs: Record<string, WorkflowJob> };
const workflowJobs = parsedWorkflow.jobs;
const parsedJob = (id: string): WorkflowJob => {
  const value = workflowJobs[id];
  assert.ok(value, `parsed workflow job ${id}`);
  return value;
};
const needs = (job: WorkflowJob): string[] => job.needs === undefined ? [] :
  typeof job.needs === "string" ? [job.needs] : job.needs;
const stepById = (job: WorkflowJob, id: string): WorkflowStep => {
  const value = job.steps.find((step) => step.id === id);
  assert.ok(value, `parsed workflow step ${id}`);
  return value;
};
const checkout = (job: WorkflowJob): WorkflowStep => {
  const value = job.steps.find((step) => step.uses?.startsWith("actions/checkout@"));
  assert.ok(value, "parsed checkout step");
  return value;
};

test("six strict goldens and isolated structural/semantic mutants", () => {
  const semanticRows: Array<{ value: unknown; accept: boolean }> = [];
  for (const [job] of jobs) {
    for (const pass of [true, false]) {
      const value = report(job, pass);
      assert.equal(validate(value), true, `${job}/${pass}: ${ajv.errorsText(validate.errors)}`);
      semanticRows.push({ value, accept: true });
    }
    for (const mutate of [
      (value: any) => value.checks.reverse(),
      (value: any) => { value.workflow.job_id = "wrong-job"; },
      (value: any) => { value.cleanup.paths = false; },
      (value: any) => { value.failure_phase = "contradiction"; },
      (value: any) => { value.unexpected = true; },
    ]) {
      const hostile = structuredClone(report(job)); mutate(hostile);
      assert.equal(validate(hostile), false, `${job} structural mutant`);
    }
  }
  const aOrder = report("A"); [aOrder.metadata[0], aOrder.metadata[1]] = [aOrder.metadata[1], aOrder.metadata[0]];
  const aProvider = report("A"); aProvider.metadata[0].needed = ["missing.so"];
  const aSummary = report("A"); aSummary.metadata.at(-1).mapping_sha256 = "f".repeat(64);
  const aRoleAlias = report("A"); aRoleAlias.metadata[1].sha256 = aRoleAlias.metadata[0].sha256;
  aRoleAlias.metadata.at(-1).mapped_sequence[1].sha256 = aRoleAlias.metadata[0].sha256;
  aRoleAlias.metadata.at(-1).closure_sha256 = digestValue(normalized(aRoleAlias.metadata.slice(0, -1)));
  aRoleAlias.metadata.at(-1).mapping_sha256 = digestValue(aRoleAlias.metadata.at(-1).mapped_sequence
    .map(({ role, sha256 }: any) => [role, sha256]));
  const bWrong = report("B"); bWrong.metadata.slice(0, 2).forEach((row: any) => { row.output_sha256 = "e".repeat(64); });
  const bMapping = report("B"); bMapping.metadata[1].execution_mapping_sha256 = bMapping.metadata[0].execution_mapping_sha256;
  const bParser = report("B"); bParser.metadata[2].parser.closure_sha256 = "e".repeat(64);
  const bTop = report("B"); bTop.metadata[2].closure_sha256 = "e".repeat(64);
  const ePolicy = report("E"); ePolicy.metadata[0].sha256 = "e".repeat(64);
  const iOutput = report("integration"); iOutput.metadata[1].sha256 = "e".repeat(64);
  for (const value of [aOrder, aProvider, aSummary, aRoleAlias, bWrong, bMapping, bParser, bTop]) {
    assert.equal(validate(value), true, "relation remains structural");
    semanticRows.push({ value, accept: false });
  }
  assert.equal(validate(ePolicy), false, "E policy is structurally fixed");
  assert.equal(validate(iOutput), false, "integration output is structurally fixed");
  const mask = report("B"); mask.metadata[0].seal_mask = 15;
  assert.equal(validate(mask), false, "historical four-bit mask");
  const oversize = report("A"); oversize.metadata[0].size_bytes = 134_217_729;
  assert.equal(validate(oversize), false, "A exact object bound");
  pythonValidate(semanticRows);
});

test("private operation receipts solely derive all six reports and exact baselines", () => {
  const values = Object.fromEntries(jobs.map(([job]) => [job, operationResult(job)]));
  const script = `import ast,dataclasses,hashlib,json,struct,subprocess,sys\nfrom unittest.mock import patch\nsys.path.insert(0,'scripts/native-qualification');import common
values=json.load(sys.stdin);h=lambda p:hashlib.sha256(open(p,'rb').read()).hexdigest()
launcher=open(common.LAUNCHER_PATH,'rb').read();tree=subprocess.check_output(['git','ls-tree','HEAD','--',common.LAUNCHER_PATH]).decode().split()
assert common.SystemCommonOps._blob_matches(launcher,tree[2]) and not common.SystemCommonOps._blob_matches(launcher+b'x',tree[2])
base={k:('value',k) for k in common.CLEANUP_KEYS};base['paths']=(None,None,None)
class Ops:
 def __init__(self,value):self.fds=common.FdRegistry();self.source_set_sha256='9'*64;self.value=value;self.calls=0
 def observe(self,c):self.calls+=1;return dict(base)
 def run_fixed_operation(self,c,o):return self.value
class Cust:
 def publish(self,raw):self.raw=raw
 def abort(self,error):raise error
for job,value in values.items():
 c=common.WorkflowContext(job,'owner/repo','owner/repo','a'*40,'b'*40,'b'*40,'refs/heads/main','main',common.JOB_IDS[job],1,1,True,'image','6.8.0-100-generic','x86_64',h(common.WORKFLOW),h(common.COMMON.parent/common.DRIVERS[job]),h(common.COMMON),h(common.SCHEMA),open(common.SCHEMA,'rb').read())
 assert c.schema_blob_sha256==h(common.SCHEMA)
 cust=Cust();s=common.NativeSession._begin_with_ops(c,Ops(value),cust);returned=s.run_fixed_operation(job)
 for name,item in returned.items():
  if type(item) is bool:returned[name]=False;break
 returned['caller_metadata']=['forged']
 evidence=s.settle_native_phase();assert evidence.restored
 receipt=s._NativeSession__receipt
 if job=='B':
  assert isinstance(receipt._metadata[0],common.Mapping) and type(receipt._metadata[0]['objects']) is tuple
  try:receipt._metadata[0]['objects'][0]['needed']+=('forged',);raise AssertionError('nested metadata mutable')
  except TypeError:pass
 forged=dataclasses.replace(receipt,_seal=object());s._NativeSession__receipt=forged
 try:s._receipt_claims();raise AssertionError('fabricated private receipt accepted')
 except common.QualificationError:pass
 s._NativeSession__receipt=receipt;s.publish(common.ReportCandidate())
 report=json.loads(cust.raw);assert report['result']=='pass' and all(row['outcome']=='pass' for row in report['checks'])
 assert report['operation']['source_set_sha256']=='9'*64 and 'caller_metadata' not in json.dumps(report)
 hostile=json.loads(json.dumps(value))
 target=hostile['runtime'] if job=='B' else hostile
 candidates=[name for name,item in target.items() if type(item) is bool]
 assert candidates;target[candidates[0]]=False
 broken=common.NativeSession._begin_with_ops(c,Ops(hostile),Cust())
 try:broken.run_fixed_operation(job);raise AssertionError(('false receipt accepted',job))
 except common.QualificationError:pass
assert [field.name for field in dataclasses.fields(common.ReportCandidate)]==['failure_phase','diagnostics','primary_error']
class Group(Exception):
 def __init__(self,items):self.exceptions=items
nested=Group([Group([common.QualificationError('fixed stage')]),OSError(5,'secret')])
assert common._error_label(nested)=='fixed-stage--OSError-5'
assert len(common._error_label(Group([OSError(i,'x') for i in range(20)])))<=480
production_environment={name:'' for name in common.ENV_KEYS}
with patch.object(common.os,'environ',production_environment):
 try:common.NativeSession._begin_with_ops(None,None,None);raise AssertionError('production seam accepted')
 except common.QualificationError:pass
reg=common.FdRegistry(lambda n:(_ for _ in ()).throw(OSError('uncertain')));lease=reg.adopt(9,'test')
try:lease.close()
except OSError:pass
try:reg.adopt(9,'reuse');raise AssertionError('reuse')
except common.QualificationError:pass
def dent(name):
 raw=name.encode()+b'\\0';size=((19+len(raw)+7)//8)*8;return struct.pack('QqHB',1,0,size,0)+raw+b'\\0'*(size-19-len(raw))
assert common._parse_dirents(dent('.')+dent('7')+dent('19'),True)==['7','19']
source=ast.parse(open(common.COMMON).read())
descriptor=next(node for node in ast.walk(source) if isinstance(node,ast.FunctionDef) and node.name=='_descriptor_snapshot_once')
text=ast.unparse(descriptor);assert '_generation(after)' in text and 'descriptor_flags' in text and 'status_flags' in text
assert 'F_DUPFD_CLOEXEC' in text and 'anchor_generation' in text and '_descriptor_anchors' in text
assert 'libc.syscall(312' not in text
issuer=next(node for node in ast.walk(source) if isinstance(node,ast.FunctionDef) and node.name=='_issue_cli')
issuer_text=ast.unparse(issuer);assert "os.execve('/usr/bin/python3', ('/usr/bin/python3', '-I', '-B', '-')" in issuer_text
assert 'os.pidfd_open' in issuer_text and 'os.dup2(admission.number, 3' not in issuer_text
assert 'invoke_fixed_admitted_operation' not in open(common.COMMON).read()
children=next(node for node in ast.walk(source) if isinstance(node,ast.FunctionDef) and node.name=='_children')
assert '_stable' in ast.unparse(children)
worker=ast.unparse(next(node for node in ast.walk(source) if isinstance(node,ast.FunctionDef) and node.name=='_custodian_worker'))
assert worker.index("control.recv(7) == b'RELEASE'") < worker.index("control.send(b'READY')") < worker.index('control.recv(REPORT_LIMIT + 1)')`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], {
    input: JSON.stringify(values), encoding: "utf8",
  });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(common, /os\.listdir|os\.scandir|fdopendir|production_checks/u);
  for (const token of ["getdents64", "CLOSE_UNCERTAIN", "report-custodian", "uploaded report bytes",
    "retained cleanup capability", "fixed-admission", "sealed-capsule", "operation receipt required"]) {
    assert.ok(common.includes(token), token);
  }
});

test("real workflow context admits dispatch and rejects PR and failed-upload cleanup before effects", () => {
  const script = `import os,sys\nfrom unittest.mock import patch\nsys.path.insert(0,'scripts/native-qualification');import common
common.platform.release=lambda:'6.8.0-100-generic';common.platform.machine=lambda:'x86_64'
if not hasattr(common.socket,'SOCK_CLOEXEC'):common.socket.SOCK_CLOEXEC=0
base={'LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','NQ_EVENT_NAME':'workflow_dispatch',
 'NQ_REPOSITORY':'owner/repo','NQ_HEAD_REPOSITORY':'owner/repo','NQ_HEAD_SHA':'a'*40,'NQ_ENVELOPE_SHA':'b'*40,
 'NQ_WORKFLOW_SHA':'b'*40,'NQ_REF':'refs/heads/main','NQ_DEFAULT_BRANCH':'main','NQ_REF_PROTECTED':'true',
 'NQ_RUN_ID':'17','NQ_RUN_ATTEMPT':'1','NQ_RUNNER_VERSION':'20260728.1'}
for job,driver in common.DRIVERS.items():
 environment={**base,'NQ_JOB_ID':common.JOB_IDS[job]}
 with patch.dict(os.environ,environment,clear=True):
  context=common.WorkflowContext.from_environ(job,common.COMMON.parent/driver)
  value=common._context_value(context);envelope=value['envelope']
  assert envelope=={'default_branch':'main','event_name':'workflow_dispatch','github_sha':'b'*40,
   'head_repository':'owner/repo','ref':'refs/heads/main','ref_protected':True,'repository':'owner/repo',
   'run_attempt':1,'run_id':17}
class NativeSentinel(Exception):pass
hits=[]
def native_sentinel(*_args):hits.append('native');raise NativeSentinel()
common._start_custodian=native_sentinel
pr={**base,'NQ_EVENT_NAME':'pull_request','NQ_JOB_ID':common.JOB_IDS['A']}
with patch.dict(os.environ,pr,clear=True):
 try:common.NativeSession.begin('A',common.COMMON.parent/common.DRIVERS['A']);raise AssertionError('PR admitted')
 except common.QualificationError:pass
assert hits==[]
with patch.dict(os.environ,{**base,'NQ_JOB_ID':common.JOB_IDS['A']},clear=True):
 try:common.NativeSession.begin('A',common.COMMON.parent/common.DRIVERS['A'])
 except NativeSentinel:pass
assert hits==['native']
cleanup_base={'LC_ALL':'C','NQ_CLEANUP_RUN_ID':'17','NQ_CLEANUP_RUN_ATTEMPT':'1','NQ_CLEANUP_HEAD_SHA':'a'*40,
 'NQ_UPLOAD_ARTIFACT_ID':'','NQ_UPLOAD_ARTIFACT_SHA256':''}
socket_hits=[]
def socket_sentinel(*_args,**_kwargs):socket_hits.append('socket');raise NativeSentinel()
common.socket.socket=socket_sentinel
for job in common.DRIVERS:
 with patch.dict(os.environ,cleanup_base,clear=True):
  try:common.cleanup_report(job);raise AssertionError(('failed upload admitted',job))
  except common.QualificationError:pass
assert socket_hits==[]
valid={**cleanup_base,'NQ_UPLOAD_ARTIFACT_ID':'7','NQ_UPLOAD_ARTIFACT_SHA256':'c'*64}
with patch.dict(os.environ,valid,clear=True):
 try:common.cleanup_report('A')
 except NativeSentinel:pass
assert socket_hits==['socket']
final={key:'success' for key in common.FINAL_KEYS};final['LC_ALL']='C';final['PYTHONCOERCECLOCALE']='0'
common.require_final_results(final)
for key in common.FINAL_KEYS-{'LC_ALL','PYTHONCOERCECLOCALE'}:
 for outcome in ('failure','skipped','cancelled'):
  hostile={**final,key:outcome}
  try:common.require_final_results(hostile);raise AssertionError((key,outcome))
  except common.QualificationError:pass`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
});

test("common issuer capsule is consumed by the sole real bootstrap decoder", () => {
  const script = `import hashlib,importlib.util,json,subprocess,sys\nfrom types import SimpleNamespace
sys.path.insert(0,'scripts/native-qualification');import common
spec=importlib.util.spec_from_file_location('held_launcher_contract',common.LAUNCHER_PATH);launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
client='scripts/native-qualification/'+common.DRIVERS['integration'];paths=(*common.SOURCE_PATHS,client)
raw=subprocess.check_output(('/usr/bin/git','ls-tree','-rz','HEAD','--',*paths))
tree={};
for row in raw.split(b'\\0'):
 if row:
  header,path=row.split(b'\\t',1);tree[path.decode()]=header.decode().split()[2]
held={path:common._HeldSource(path,None,(common.ROOT/path).read_bytes(),(),tree[path]) for path in paths}
digest=hashlib.sha256()
for path in common.SOURCE_PATHS:
 encoded=path.encode();data=held[path].raw
 digest.update(len(encoded).to_bytes(4,'big')+encoded+len(data).to_bytes(8,'big')+hashlib.sha256(data).digest())
value=digest.hexdigest();context=SimpleNamespace(job='integration',head_sha='0'*40)
admission,capsule=common.SystemCommonOps._capsule(context,held,value)
decoded=json.loads(admission);sources,driver=launcher._decode_held_source_capsule(capsule,decoded)
assert sources=={path:held[path].raw for path in common.SOURCE_PATHS} and driver==held[client].raw
ambient=type(sys)('completion_elf');ambient.ElfMetadata=ambient.parse_elf64=object();sys.modules['completion_elf']=ambient
saved=sys.path[:];sys.path[:]=[]
try:closure=launcher._load_private_closure(sources,value)
finally:sys.path[:]=saved
package='_cogs_o2_'+value[:16];parser=sys.modules[package+'.completion_elf']
assert closure.__name__==package+'.completion_trusted_runtime_closure' and closure.parse_elf64 is parser.parse_elf64
assert decoded['source_set_sha256']==value and not hasattr(launcher,'invoke_fixed_admitted_operation')`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
});

test("sole held launcher CLI has exact isolated descriptor ABI and no ambient issuer", { skip: process.platform !== "linux" }, () => {
  const script = `import ast,json,sys\nsys.path.insert(0,'scripts/native-qualification');import common
source=b'''import fcntl,json,os,sys
try:
 environment_ok=not os.environ or dict(os.environ)=={'LC_CTYPE':'C.UTF-8'}
 os.environ.clear()
 value={'admission':os.read(3,4096)==b'ADMISSION\\\\n','descriptors':sorted(map(int,os.listdir('/proc/self/fd')))[:5]==[0,1,2,3,4],'environment':environment_ok and not os.environ,'isolated':bool(sys.flags.isolated and sys.flags.dont_write_bytecode),'seals':fcntl.fcntl(4,1034)==31}
except BaseException as error:
 value={'error':type(error).__name__,'errno':getattr(error,'errno',None)}
os.write(1,json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\\\\n')
'''
registry=common.FdRegistry();ops=common.SystemCommonOps(registry)
raw=ops._issue_cli(source,b'ADMISSION\\n',b'CAPSULE')
assert json.loads(raw)=={'admission':True,'descriptors':True,'environment':True,'isolated':True,'seals':True},raw
expected=b'{"source_revision":"'+b'a'*40+b'","source_set_sha256":"'+b'b'*64+b'"}\\n'
assert ops._decode_cli(expected)=={'source_revision':'a'*40,'source_set_sha256':'b'*64}
bad=b'import os\\nos.write(2,b"runtime-launcher-failed\\\\n")\\nraise SystemExit(1)\\n'
try:ops._issue_cli(bad,b'ADMISSION\\n',b'CAPSULE');raise AssertionError('failed launcher accepted')
except BaseException as error:
 label=common._error_label(error)
 assert label=='held-launcher-exit-1-stdout-0-stderr-24-runtime-launcher-failed',label
registry.close_reverse()
tree=ast.parse(open(common.COMMON).read())
issuer=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='_issue_cli')
execve=next(n for n in ast.walk(issuer) if isinstance(n,ast.Call) and ast.unparse(n.func)=='os.execve')
assert isinstance(execve.args[2],ast.Dict) and not execve.args[2].keys
assert 'invoke_fixed_admitted_operation' not in open(common.COMMON).read()`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
});

test("private capability and retained quarantine fail closed across publication and cleanup cuts", () => {
  const script = `import hashlib,sys\nsys.path.insert(0,'scripts/native-qualification');import common
from unittest.mock import patch
G=lambda inode:{'mode':0o100600,'uid':1,'gid':1,'device':1,'inode':inode,'links':1,'size':9,'mtime_ns':1,'ctime_ns':1,'rdevice':0}
R,A,O,F=G(10),G(11),G(12),G(99);digest=hashlib.sha256(b'report-v1').hexdigest()
authority={'report_sha256':digest,'report_size':9,'report_generation':R};receipt={'report_generation':R}
class Lease:
 def __init__(self):self.number=4;self.state=common.FdState.OWNED
 def close(self):self.state=common.FdState.CLOSED
class Registry:pass
def run(initial,has_receipt,accept=True):
 state=dict(initial);retained=[]
 def names(fd,numeric):return tuple(state)
 def identity(fd,name):return state.get(name)
 def file_digest(directory,name,limit):
  generation=state[name];raw=b'foreign!' if generation==F else b'report-v1'
  return hashlib.sha256(raw).hexdigest(),len(raw),generation
 def quarantine(job,parent,directory,capability):
  assert capability==b'K'*32;retained.append(dict(state))
 patches=(patch.object(common,'_enumerate_directory',names),patch.object(common,'_identity_at',identity),
  patch.object(common,'_file_digest_at',file_digest),patch.object(common,'_retain_quarantine',quarantine))
 for item in patches:item.start()
 try:
  try:
   common._cleanup_owned('C',Registry(),Lease(),Lease(),authority,A,receipt if has_receipt else None,O if has_receipt else None,b'K'*32);ok=True
  except common.QualificationError:ok=False
 finally:
  for item in reversed(patches):item.stop()
 assert ok is accept,(initial,state)
 if accept:assert retained==[initial] and state==initial
 return state
for state,owned in [({'.authority.json':A},False),({'.authority.json':A,'.report.stage':R},False),
 ({'.authority.json':A,'report.json':R},False),({'.authority.json':A,'.owner.json':O,'report.json':R},True)]:run(state,owned)
foreign={'.authority.json':A,'.owner.json':O,'report.json':F};assert run(foreign,True,False)==foreign
extra={'.authority.json':A,'.owner.json':O,'report.json':R,'foreign':F};assert run(extra,True,False)==extra`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const receiptSource = common.slice(common.indexOf("def _receipt("), common.indexOf("def _open_report_directory("));
  assert.doesNotMatch(receiptSource, /"capability"\s*:/u, "raw capability must not enter publication receipt");
  assert.match(receiptSource, /"schema_sha256": context\.schema_blob_sha256/u);
  assert.match(receiptSource, /source_generations_sha256/u, "source generations remain in the private authenticated receipt");
  assert.doesNotMatch(receiptSource, /_sha256\(SCHEMA\)/u, "receipt must use the pre-effect schema identity");
  assert.match(receiptSource, /hmac\.new\(capability/u);
  const readReceiptSource = common.slice(common.indexOf("def _read_receipt("), common.indexOf("def _file_digest_at("));
  assert.doesNotMatch(readReceiptSource, /_sha256\(SCHEMA\)/u, "recovery must use the authenticated schema identity");
  assert.match(
    readReceiptSource,
    /_require\(all\(HEX64\.fullmatch\(str\(identity\)\) is not None for identity in code\), "retained receipt code identities"\)/u,
  );
  const authoritySource = common.slice(common.indexOf("def _authority("), common.indexOf("def _receipt("));
  assert.doesNotMatch(authoritySource, /"capability"\s*:/u, "cleanup capability is never durable plaintext");
  const workerSource = common.slice(common.indexOf("def _custodian_worker("), common.indexOf("@dataclass(frozen=True)\nclass _CleanupContext"));
  assert.ok(workerSource.indexOf("if not raw:") < workerSource.indexOf("_publish_transaction"),
    "an operation abort closes the control channel without parsing an empty report");
  const cleanupSource = common.slice(common.indexOf("def cleanup_report("), common.indexOf("class NativeSession:"));
  assert.doesNotMatch(cleanupSource, /_cleanup_owned/u, "disk state cannot select fallback cleanup authority");
  assert.doesNotMatch(cleanupSource, /except \(OSError/u, "pidfd failure cannot become success");
  const quarantineSource = common.slice(common.indexOf("def _retain_quarantine("), common.indexOf("def _custodian_main("));
  assert.match(quarantineSource, /quarantine-retained/u, "quarantine retains every named generation");
  assert.match(quarantineSource, /_rename\(directory\.number, name\.encode\(\), slot, 2, placeholder\.number\)/u,
    "owned files leave public names only through retained exchange");
  assert.match(quarantineSource, /hmac\.new\(capability/u, "quarantine names remain private until exchange");
  assert.match(common, /inotify_add_watch/u, "upload interval has a retained generation watch");
  const sourceReader = common.slice(common.indexOf("def _read_source("), common.indexOf("def _canonical("));
  assert.match(sourceReader, /os\.pread/u); assert.doesNotMatch(sourceReader, /read_bytes|lstat/u);
});

test("authenticated upload cleanup uses retained post-exchange generations", {
  skip: process.platform !== "linux" || process.arch !== "x64",
}, () => {
  const script = `import os,sys,types
from unittest.mock import patch
sys.path.insert(0,'scripts/native-qualification');import common
job='C';head='a'*40;raw=b'{"authenticated":"report"}\\n'
context=types.SimpleNamespace(job=job,job_id=common.JOB_IDS[job],run_id=73,run_attempt=1,head_sha=head,
 workflow_blob_sha256='b'*64,schema_blob_sha256='c'*64,common_blob_sha256='d'*64,
 driver_blob_sha256='e'*64,source_generations=())
common._validate=lambda *_args:None
assert not os.path.lexists(common.report_path(job).parent)
registry=common.FdRegistry();client=common._start_custodian(context,registry);client.publish(raw)
with open(common.report_path(job),'rb') as uploaded:assert uploaded.read()==raw
environment={'LC_ALL':'C','NQ_CLEANUP_RUN_ID':'73','NQ_CLEANUP_RUN_ATTEMPT':'1','NQ_CLEANUP_HEAD_SHA':head,
 'NQ_UPLOAD_ARTIFACT_ID':'7','NQ_UPLOAD_ARTIFACT_SHA256':'f'*64}
with patch.dict(os.environ,environment,clear=True):common.cleanup_report(job)
assert not os.path.lexists(common.report_path(job).parent)
assert not os.path.lexists(common._retired_report_path(job))
waited,status=os.waitpid(client.pid,0)
assert waited==client.pid and os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
registry.close_reverse()`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const quarantineSource = common.slice(common.indexOf("def _retain_quarantine("), common.indexOf("def _cleanup_owned("));
  const exchange = quarantineSource.indexOf("_rename(directory.number, name.encode(), slot, 2, placeholder.number)");
  assert.ok(exchange > 0);
  assert.match(quarantineSource.slice(exchange), /_identity\(os\.fstat\(retained\.number\)\)/u);
  assert.match(quarantineSource.slice(exchange), /_identity\(os\.fstat\(replacement\.number\)\)/u);
});

test("real custodian supervisor hook transfers private proof only after exact child reap", { skip: process.platform !== "linux" }, () => {
  const script = `import json,os,socket,struct,sys,types\nsys.path.insert(0,'scripts/native-qualification');import common
cap=b'R'*32;client,server=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC);control_left,control_right=socket.socketpair()
def worker(control_fd,context,capability,supervisor_fd):
 os.close(control_fd);supervisor=socket.socket(fileno=supervisor_fd);left,right=os.pipe()
 assert supervisor.sendmsg([b'LEASE'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,struct.pack('2i',left,right))])==5
 os.close(left);os.close(right)
 packet=common._canonical({'capability':capability.hex(),'custodian_pid':os.getpid(),'nonce':'a'*64,'upload':{'artifact_id':7}},True)
 assert supervisor.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,struct.pack('i',server.fileno()))])==len(packet)
 supervisor.close();server.close()
common._custodian_worker=worker
broker=os.fork()
if broker==0:
 client.close();control_left.close()
 try:common._custodian_main(control_right.detach(),types.SimpleNamespace(),cap)
 except BaseException:os._exit(1)
 os._exit(0)
server.close();control_right.close();raw=client.recv(4096);waited,status=os.waitpid(broker,0)
assert waited==broker and os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
value=json.loads(raw);assert value['capability']==cap.hex() and value['waitpid_reaped']==value['custodian_pid']
assert value['nonce']=='a'*64 and value['upload']=={'artifact_id':7}`;
  const run = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const supervisorSource = common.slice(common.indexOf("def _custodian_main("), common.indexOf("def _mutation_watch("));
  assert.match(supervisorSource, /_bounded_reap\(pid, pidfd\.number\)/u);
  assert.match(supervisorSource, /SCM_RIGHTS/u);
  assert.ok(supervisorSource.indexOf("_bounded_reap") < supervisorSource.indexOf("endpoint.send"));
});

test("parsed workflow gives only an explicit exact-SHA dispatch native authority", () => {
  const input = parsedWorkflow.on.workflow_dispatch.inputs.reviewed_sha;
  assert.deepEqual(input, { description: "Exact externally reviewed commit SHA to qualify", required: true, type: "string" });

  const authorityId = "native-qualification-eligibility";
  const authority = parsedJob(authorityId);
  const expectedAuthority = "github.event_name == 'workflow_dispatch' && github.run_attempt == 1 && " +
    "github.actor == github.triggering_actor && github.actor == vars.NATIVE_QUALIFICATION_ACTOR && " +
    "github.event.sender.login == github.actor && github.ref_type == 'branch' && " +
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && github.ref_protected == true && " +
    "github.workflow_ref == format('{0}/.github/workflows/ci.yml@{1}', github.repository, github.ref) && " +
    "github.workflow_sha == github.sha";
  assert.equal(authority.if, expectedAuthority);
  assert.equal(authority.steps.some((step) => step.uses?.startsWith("actions/checkout@")), false,
    "event-selected code cannot decide native authority");
  assert.equal(authority.outputs?.reviewed_sha, "${{ steps.authority.outputs.reviewed_sha }}");
  const authorityStep = stepById(authority, "authority");
  assert.equal(authorityStep.env?.REVIEWED_SHA, "${{ inputs.reviewed_sha }}");
  assert.equal(authorityStep.env?.AUTHORIZED_ACTOR, "${{ vars.NATIVE_QUALIFICATION_ACTOR }}");
  assert.match(authorityStep.run ?? "", /\[\[ "\$REVIEWED_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/u);
  assert.match(authorityStep.run ?? "", /reviewed_sha=%s/u);

  const reviewedRef = "${{ needs.native-qualification-eligibility.outputs.reviewed_sha }}";
  const quality = parsedJob("quality");
  assert.deepEqual(needs(quality), [authorityId]);
  assert.equal(quality.if,
    "${{ always() && (github.event_name != 'workflow_dispatch' || needs.native-qualification-eligibility.result == 'success') }}");
  const nativeIds = jobs.map(([, id]) => id);
  const effectIds = ["native-c1", ...nativeIds] as const;
  const nativeInventory = Object.keys(workflowJobs).filter((id) => id.startsWith("native-"));
  assert.deepEqual(nativeInventory.sort(), [authorityId, ...effectIds, "native-qualification-required"].sort(),
    "every native job is included in the authority proof");
  for (const id of effectIds) {
    const parsed = parsedJob(id);
    assert.ok(needs(parsed).includes(authorityId), `${id} directly needs dispatch authority`);
    assert.equal(checkout(parsed).with?.ref, reviewedRef, `${id} exact reviewed checkout`);
    assert.doesNotMatch(JSON.stringify(parsed), /github\.event\.pull_request/u, `${id} has no PR source authority`);
  }
  for (const [job, id, driver] of jobs) {
    const parsed = parsedJob(id);
    const expectedNeeds = job === "integration" ? [authorityId, ...nativeIds.slice(0, 5)] : ["quality", authorityId];
    assert.deepEqual(needs(parsed), expectedNeeds, `${id} causal needs`);
    const invoke = parsed.steps.find((step) => step.env?.NQ_DRIVER !== undefined); assert.ok(invoke);
    assert.equal(invoke.env?.NQ_DRIVER, `scripts/native-qualification/${driver}`);
    assert.equal(invoke.env?.NQ_HEAD_SHA, reviewedRef);
    assert.equal(invoke.env?.NQ_REF, "${{ github.ref }}");
    assert.equal(invoke.env?.NQ_DEFAULT_BRANCH, "${{ github.event.repository.default_branch }}");
    assert.equal(invoke.env?.NQ_REF_PROTECTED, "${{ github.ref_protected }}");
    assert.match(invoke.run ?? "", /["']\$NQ_DRIVER["'] --workflow-bound/u);
    const upload = stepById(parsed, "upload"); const cleanup = stepById(parsed, "cleanup");
    assert.equal(cleanup.if, "${{ always() }}");
    assert.ok(parsed.steps.indexOf(upload) < parsed.steps.indexOf(cleanup), `${id} upload causality`);
    assert.equal(parsed.outputs?.upload, "${{ steps.upload.outcome }}");
    assert.equal(parsed.outputs?.cleanup, "${{ steps.cleanup.outcome }}");
    assert.equal(upload.with?.path, `/tmp/cogs-native-qualification-${job}/report.json`);
    assert.deepEqual(Object.keys(cleanup.env ?? {}).sort(), ["NQ_CLEANUP_HEAD_SHA", "NQ_CLEANUP_RUN_ATTEMPT",
      "NQ_CLEANUP_RUN_ID", "NQ_UPLOAD_ARTIFACT_ID", "NQ_UPLOAD_ARTIFACT_SHA256"]);
    assert.equal(cleanup.env?.NQ_UPLOAD_ARTIFACT_ID, "${{ steps.upload.outputs.artifact-id }}");
    assert.equal(cleanup.env?.NQ_UPLOAD_ARTIFACT_SHA256, "${{ steps.upload.outputs.artifact-digest }}");
    assert.match(cleanup.run ?? "", /NQ_UPLOAD_ARTIFACT_ID="\$NQ_UPLOAD_ARTIFACT_ID"/u);
    assert.match(cleanup.run ?? "", /NQ_UPLOAD_ARTIFACT_SHA256="\$NQ_UPLOAD_ARTIFACT_SHA256"/u);
  }

  const finalJob = parsedJob("native-qualification-required");
  assert.equal(finalJob.if, "${{ always() && needs.native-qualification-eligibility.result == 'success' }}");
  const finalNeeds = ["quality", authorityId, ...nativeIds];
  assert.deepEqual(needs(finalJob), finalNeeds);
  assert.equal(checkout(finalJob).with?.ref, reviewedRef);
  const finalStep = finalJob.steps.find((step) => step.run?.includes("common.py --require-final-results")); assert.ok(finalStep);
  const finalKeys = Object.keys(finalStep.env ?? {});
  assert.deepEqual(finalKeys.sort(), [...new Set(finalKeys)].sort(), "parsed final inventory unique");
  for (const id of finalNeeds) assert.ok(Object.values(finalStep.env ?? {}).some((value) => value.includes(`needs.${id}.result`)), id);
  for (const id of nativeIds) for (const output of ["upload", "cleanup"]) {
    assert.ok(Object.values(finalStep.env ?? {}).includes(`\${{ needs.${id}.outputs.${output} }}`), `${id}/${output}`);
  }

  type DispatchContext = { event: string; attempt: number; actor: string; triggeringActor: string; sender: string;
    configuredActor: string; ref: string; refType: string; defaultBranch: string; protected: boolean;
    workflowRef: string; repository: string; workflowSha: string; sha: string; reviewedSha: string };
  const selected = (context: DispatchContext): boolean => context.event === "workflow_dispatch" && context.attempt === 1 &&
    context.actor === context.triggeringActor && context.actor === context.configuredActor && context.sender === context.actor &&
    context.refType === "branch" && context.ref === `refs/heads/${context.defaultBranch}` && context.protected &&
    context.workflowRef === `${context.repository}/.github/workflows/ci.yml@${context.ref}` &&
    context.workflowSha === context.sha && /^[0-9a-f]{40}$/u.test(context.reviewedSha);
  const exactHead = "a".repeat(40);
  const dispatch: DispatchContext = { event: "workflow_dispatch", attempt: 1, actor: "reviewer", triggeringActor: "reviewer",
    sender: "reviewer", configuredActor: "reviewer", ref: "refs/heads/main", refType: "branch", defaultBranch: "main",
    protected: true, workflowRef: "owner/repo/.github/workflows/ci.yml@refs/heads/main", repository: "owner/repo",
    workflowSha: "b".repeat(40), sha: "b".repeat(40), reviewedSha: exactHead };
  assert.equal(selected({ ...dispatch, event: "pull_request" }), false, "PR can never select native authority");
  const pullRequestOutcomes: Record<string, string> = { quality: "success", [authorityId]: "skipped" };
  for (const id of effectIds) {
    assert.equal(needs(parsedJob(id)).every((dependency) => pullRequestOutcomes[dependency] === "success"), false,
      `${id} is unreachable on pull_request`);
    pullRequestOutcomes[id] = "skipped";
  }
  assert.equal(pullRequestOutcomes[authorityId] === "success", false, "final native gate also remains unreachable");
  for (const hostile of [
    { ...dispatch, attempt: 2 }, { ...dispatch, actor: "other" }, { ...dispatch, configuredActor: "" },
    { ...dispatch, ref: "refs/heads/topic" }, { ...dispatch, protected: false },
    { ...dispatch, workflowSha: "c".repeat(40) }, { ...dispatch, reviewedSha: "A".repeat(40) },
  ]) assert.equal(selected(hostile), false, "authority mutation fails closed");
  assert.equal(selected(dispatch), true);
  const outcomes: Record<string, string> = { quality: "success", [authorityId]: "success" };
  for (const id of effectIds) {
    assert.equal(needs(parsedJob(id)).every((dependency) => outcomes[dependency] === "success"), true, `${id} dispatch`);
    assert.equal(checkout(parsedJob(id)).with?.ref, reviewedRef, `${id} dispatches exact external head`);
    outcomes[id] = "success";
  }
});

test("ADR0093 common surfaces stay within binding readable highs", () => {
  const highs = new Map<string, number>([
    [workflowPath, 400], [schemaPath, 700], [commonPath, 1900],
    ["test/native-qualification-common.test.ts", 1500], ["scripts/validate-schemas.ts", 300],
  ]);
  const diff = spawnSync("git", ["diff", "--numstat", predecessor, "--", ...highs.keys()], { encoding: "utf8" });
  assert.equal(diff.status, 0, diff.stderr);
  const additions = new Map(diff.stdout.trim().split("\n").filter(Boolean).map((line) => {
    const [count, , path] = line.split("\t"); return [path, Number(count)] as const;
  }));
  for (const [path, high] of highs) assert.ok((additions.get(path) ?? 0) <= high, `${path}: ${additions.get(path)}/${high}`);
  assert.ok(readFileSync(commonPath, "utf8").split("\n").every((line) => line.length <= 160), "common readable width");
  assert.doesNotMatch(readFileSync(commonPath, "utf8"), /;/u, "common semicolon-packed transition");
  const staticCheck = `import ast,sys\nfor path in sys.argv[1:]:\n tree=ast.parse(open(path).read(),path)\n for node in ast.walk(tree):\n  if isinstance(node,(ast.Try,ast.With)):\n   assert node.end_lineno>node.lineno,(path,node.lineno,'packed transition')`;
  const readable = spawnSync("python3", ["-I", "-B", "-c", staticCheck, commonPath], { encoding: "utf8" });
  assert.equal(readable.status, 0, readable.stderr);
});
