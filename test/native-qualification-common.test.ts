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
const workflowPath = ".github/workflows/ci.yml";
const commonPath = "scripts/native-qualification/common.py";
const schemaPath = "schemas/native-qualification-report-v1alpha1.json";
const predecessor = "bec0a19b0b984f88ab9c2effc5059f3737915caa";
const isolatedPython = process.platform === "darwin" ? "/opt/homebrew/bin/python3" : "/usr/bin/python3";
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
function report(job: keyof typeof checkText, pass = true): any {
  const found = jobs.find(([name]) => name === job);
  assert.ok(found);
  const checks = checkText[job].split(" ").map((id) => ({ id, outcome: "pass" }));
  const cleanup = Object.fromEntries(cleanupKeys.map((key) => [key, true]));
  if (!pass) { const first = checks[0]; assert.ok(first); first.outcome = "fail"; cleanup.paths = false; }
  return { version: "cogs.native-qualification/v1alpha1", job,
    source: { head_sha: "a".repeat(40), checkout_sha: "a".repeat(40),
      driver_blob_sha256: digestFile(`scripts/native-qualification/${found[2]}`), common_blob_sha256: digestFile(commonPath) },
    envelope: { repository: "owner/repo", head_repository: "owner/repo", event_name: "pull_request",
      github_sha: "b".repeat(40), event_merge_sha: "b".repeat(40), base_sha: "c".repeat(40),
      run_id: 1, run_attempt: 1, pull_request_number: 1 },
    workflow: { path: workflowPath, blob_sha256: digestFile(workflowPath), workflow_sha: "a".repeat(40), job_id: found[1] },
    runner: { image: "ubuntu-24.04", image_version: "20260720.1",
      kernel_release: "6.8.0-100-generic", architecture: "x86_64" },
    authority: "exact-run-native-qualification", result: pass ? "pass" : "fail", checks,
    metadata: pass ? metadata(job) : [], failure_phase: pass ? null : "portable-test",
    diagnostics_sha256: pass ? null : "d".repeat(64), cleanup };
}
function pythonValidate(values: Array<{ value: unknown; accept: boolean }>) {
  const script = `import json,sys\nsys.path.insert(0,'scripts/native-qualification')\nimport common\nfor row in json.load(sys.stdin):\n ok=True\n try: common._validate(row['value'])\n except BaseException: ok=False\n assert ok is row['accept'], (row['value'].get('job'),ok,row['accept'])`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { input: JSON.stringify(values), encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
}
function parsedJobs(source: string): Map<string, { text: string; checkoutRefs: string[]; commands: string[] }> {
  const result = new Map<string, { text: string; checkoutRefs: string[]; commands: string[] }>();
  const lines = source.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^ {2}([a-z0-9-]+):$/u.exec(lines[index] ?? "");
    if (!match?.[1]) continue;
    const body: string[] = [];
    for (index += 1; index < lines.length && !/^ {2}[a-z0-9-]+:$/u.test(lines[index] ?? ""); index += 1) {
      body.push(lines[index] ?? "");
    }
    index -= 1;
    const text = body.join("\n");
    const checkoutRefs = body.flatMap((line) => /ref:\s*["']?([^,"'}]+(?:\}\})?)/u.exec(line)?.[1]?.trim() ?? []);
    const commands = body.filter((line) => /^ {8,}[A-Za-z/]/u.test(line)).map((line) => line.trim());
    result.set(match[1], { text, checkoutRefs, commands });
  }
  return result;
}
const workflowJobs = parsedJobs(workflow);
function block(id: string) {
  const value = workflowJobs.get(id);
  assert.ok(value, `parsed workflow job ${id}`);
  return value.text;
}

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

test("common owns baselines, cleanup checks, leases, and bounded exact dirents", () => {
  const script = `import ast,hashlib,json,os,struct,subprocess,sys\nsys.path.insert(0,'scripts/native-qualification');import common
h=lambda p:hashlib.sha256(open(p,'rb').read()).hexdigest()
launcher=open(common.LAUNCHER_PATH,'rb').read();tree=subprocess.check_output(['git','ls-tree','HEAD','--',common.LAUNCHER_PATH]).decode().split()
assert common.SystemCommonOps._blob_matches(launcher,tree[2]) and not common.SystemCommonOps._blob_matches(launcher+b'x',tree[2])
method=next(n for n in ast.walk(ast.parse(open(common.COMMON).read())) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='run_fixed_operation' and n.lineno<500)
calls=[n.func.attr for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
assert calls.index('_admit_sources')<calls.index('_launcher') and 'invoke_fixed_admitted_operation' in open(common.COMMON).read()
c=common.WorkflowContext('C','owner/repo','owner/repo','a'*40,'b'*40,'a'*40,'b'*40,'c'*40,common.JOB_IDS['C'],1,1,1,'image','6.8.0-100-generic','x86_64',h(common.WORKFLOW),h(common.COMMON.parent/common.DRIVERS['C']),h(common.COMMON))
class Ops:
 def __init__(self): self.fds=common.FdRegistry();self.source_set_sha256='1'*64;self.rows=[];self.calls=0
 def observe(self,c): self.calls+=1;return dict(self.rows[self.calls-1])
 def run_fixed_operation(self,c,o):
  assert o=='C'
  names='nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact inheritance_exact limit_restored descriptors_restored children_reaped'.split()
  return {'version':'cogs.runtime-descriptor-qualification/v1','source_revision':c.head_sha,'source_set_sha256':self.source_set_sha256,**dict.fromkeys(names,True)}
class Cust:
 def publish(self,raw): self.raw=raw
base={k:('value',k) for k in common.CLEANUP_KEYS};base['paths']=(None,None)
ops=Ops();ops.rows=[base,dict(base)];cust=Cust();s=common.NativeSession._begin_with_ops(c,ops,cust)
result=s.run_fixed_operation('C');assert result['inheritance_exact'] is True
try:s.run_fixed_operation('C');raise AssertionError('replay')
except common.QualificationError:pass
e=s.settle_native_phase();assert e.restored
try:e.values['checkout']=False;raise AssertionError('mutable cleanup evidence')
except TypeError:pass
candidate=common.ReportCandidate(dict.fromkeys(common.PRODUCTION_CHECK_IDS['C'],'pass'),[],None,None,None)
p=s.publish(candidate);assert p==common.report_path('C')
r=json.loads(cust.raw);assert r['checks'][-1]=={'id':'cleanup_restored','outcome':'pass'} and all(r['cleanup'].values())
class BadOps(Ops):
 def run_fixed_operation(self,c,o):raise OSError('operation failed')
class AbortCust(Cust):
 def abort(self,error):self.aborted=error
ops=BadOps();ops.rows=[base];abort=AbortCust();s=common.NativeSession._begin_with_ops(c,ops,abort)
try:s.run_fixed_operation('C');raise AssertionError('operation failure escaped abort')
except OSError:pass
assert type(abort.aborted) is OSError
ops=Ops();changed=dict(base);changed['checkout']=('drift',);ops.rows=[base,changed];s=common.NativeSession._begin_with_ops(c,ops,Cust())
try:s.settle_native_phase();raise AssertionError('settled without operation receipt')
except common.QualificationError:pass
s.run_fixed_operation('C');e=s.settle_native_phase();assert not e.restored and e.values['checkout'] is False
ops=Ops();ops.rows=[base,dict(base)];s=common.NativeSession._begin_with_ops(c,ops,Cust());result=s.run_fixed_operation('C');result['inheritance_exact']=False
e=s.settle_native_phase();candidate=common.ReportCandidate(dict.fromkeys(common.PRODUCTION_CHECK_IDS['C'],'pass'),[])
assert s._receipt is not None
bad=dict(s._receipt._result);bad['inheritance_exact']=False
s._receipt=common.OperationReceipt(s._nonce,'C',s.source_set_sha256,hashlib.sha256(common._canonical(bad)).hexdigest(),common.MappingProxyType(bad))
try:s.publish(candidate);raise AssertionError('false C observation published')
except common.QualificationError:pass
closed=[]
reg=common.FdRegistry(lambda n:(_ for _ in ()).throw(OSError('uncertain')));lease=reg.adopt(9,'test')
try:lease.close()
except OSError:pass
try:reg.adopt(9,'reuse');raise AssertionError('reuse')
except common.QualificationError:pass
def dent(name):
 raw=name.encode()+b'\\0';size=((19+len(raw)+7)//8)*8;return struct.pack('QqHB',1,0,size,0)+raw+b'\\0'*(size-19-len(raw))
assert common._parse_dirents(dent('.')+dent('7')+dent('19'),True)==['7','19']
for bad in (dent('07'),dent('7')+dent('7')):
 try:
  names=common._parse_dirents(bad,True)
  if len(names)!=len(set(names)):raise common.QualificationError('duplicate')
  raise AssertionError('bad dirent')
 except common.QualificationError:pass
from unittest.mock import patch
writes=iter([InterruptedError(),2,3])
def write(fd,raw):
 value=next(writes)
 if isinstance(value,BaseException):raise value
 return value
with patch.object(common.os,'write',write):common._write_all(1,b'abcde')
with patch.object(common.os,'write',lambda fd,raw:0):
 try:common._write_all(1,b'x');raise AssertionError('zero write')
 except common.QualificationError:pass
reads=iter([InterruptedError(),b'ab',b'c',b''])
def read(fd,size):
 value=next(reads)
 if isinstance(value,BaseException):raise value
 return value
with patch.object(common.os,'read',read):assert common._read_all(1,3)==b'abc'
status=os.stat_result((0o100600,1,2,1,5,0,3,0,0,0))
with patch.object(common.os,'stat',return_value=status):assert common._identity_at(4,'report.json')==common._identity(status)
replacement=os.stat_result((0o100600,2,2,1,6,0,3,0,0,0))
with patch.object(common.os,'stat',return_value=replacement):assert common._identity_at(4,'report.json')!=common._identity(status)`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(common, /os\.listdir|os\.scandir|fdopendir/u);
  for (const token of ["getdents64", "CLOSE_UNCERTAIN", "report-custodian", "_exchange_verified",
    "publish-intent", "report-worker-pidfd", "ADMITTED", "custodian worker reap",
    "cleanup exchange classification", "operation receipt required", "production_checks"]) {
    assert.ok(common.includes(token), token);
  }
});

test("durable report classifier recovers every legal cut and preserves replacements", () => {
  const script = `import sys,types\nsys.path.insert(0,'scripts/native-qualification');import common
from unittest.mock import patch
R={'device':1,'inode':10,'mode':0o100600,'owner':1,'group':1,'size':9}
S={'device':1,'inode':11,'mode':0o100600,'owner':1,'group':1,'size':32}
O={'device':1,'inode':12,'mode':0o100600,'owner':1,'group':1,'size':90}
Q={'device':1,'inode':13,'mode':0o100600,'owner':1,'group':1,'size':0}
F={'device':1,'inode':99,'mode':0o100600,'owner':1,'group':1,'size':9}
receipt={'report':R,'slot':S}
class Lease:
 def __init__(self,n=4):self.number=n;self.state=common.FdState.OWNED
 def close(self):self.state=common.FdState.CLOSED
class Registry:pass
def run(initial,accept=True):
 state=dict(initial);removed=[]
 def names(fd,numeric):return tuple(state)
 def identity(fd,name):return state.get(name)
 def exchange(directory,left,right,expected_left,expected_right):
  if state.get(left)!=expected_left or state.get(right)!=expected_right:raise common.QualificationError('exchange precondition')
  state[left],state[right]=state[right],state[left]
 def unlink(name,dir_fd=None):del state[name]
 def anonymous(registry,directory,purpose):return Lease(20)
 def link(fd,directory,name):state[name.decode()]=Q
 def remove(job,parent,directory):
  assert state=={};removed.append(True)
 patches=(patch.object(common,'_enumerate_directory',names),patch.object(common,'_identity_at',identity),
  patch.object(common,'_exchange_verified',exchange),patch.object(common.os,'unlink',unlink),
  patch.object(common.os,'fsync',lambda fd:None),patch.object(common.os,'fstat',return_value=types.SimpleNamespace(st_dev=1,st_ino=13,st_mode=0o100600,st_uid=1,st_gid=1,st_size=0)),
  patch.object(common,'_anonymous',anonymous),patch.object(common,'_link_held',link),
  patch.object(common,'_remove_report_directory',remove))
 for item in patches:item.start()
 try:
  try:common._cleanup_owned('C',Registry(),Lease(),Lease(),receipt);ok=True
  except common.QualificationError:ok=False
 finally:
  for item in reversed(patches):item.stop()
 assert ok is accept
 if accept:assert removed==[True] and state=={}
 return state
legal=[{'.owner.json':O,'.cleanup.slot':S,'report.json':R},
 {'.owner.json':O,'.cleanup.slot':R,'report.json':S},
 {'.owner.json':O,'.cleanup.slot':S,'.report.stage':R},
 {'.owner.json':O,'.cleanup.slot':S},{'.owner.json':O},{'.owner.json':O,'report.json':S}]
for state in legal:run(state)
foreign={'.owner.json':O,'.cleanup.slot':S,'report.json':F};assert run(foreign,False)==foreign
extra={'.owner.json':O,'.cleanup.slot':S,'report.json':R,'foreign':F};assert run(extra,False)==extra`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
});

test("workflow eligibility and every named dependency/upload/cleanup fail closed", () => {
  const eligibilityJob = workflowJobs.get("native-qualification-eligibility"); assert.ok(eligibilityJob);
  const eligibility = eligibilityJob.text;
  assert.ok(eligibility.includes("common.py --eligibility") && eligibility.includes("/usr/bin/env -i"));
  assert.ok(eligibilityJob.checkoutRefs.some((value) => value.includes("github.event.pull_request.head.sha")));
  for (const [job, id, driver] of jobs) {
    const value = block(id);
    assert.match(value, /["']\$NQ_DRIVER["']\s+--workflow-bound/u);
    assert.ok(value.includes(`NQ_DRIVER: scripts/native-qualification/${driver}`));
    assert.ok(value.includes("id: upload") && value.includes("id: cleanup"));
    assert.ok(value.includes("steps.upload.outcome") && value.includes("steps.cleanup.outcome"));
    assert.ok(value.includes("NQ_CLEANUP_HEAD_SHA") && value.includes("NQ_CLEANUP_RUN_ATTEMPT"));
    assert.ok(value.indexOf("id: upload") < value.indexOf("id: cleanup"));
    assert.ok(value.includes(`/tmp/cogs-native-qualification-${job}/report.json`));
  }
  const final = block("native-qualification-required");
  assert.match(final, /if:\s*\$\{\{\s*always\(\)\s*\}\}/u);
  assert.ok(final.includes("common.py --require-final-results"));
  assert.doesNotMatch(final, /join\(needs\.\*\.result/u);
  const finalJob = workflowJobs.get("native-qualification-required"); assert.ok(finalJob);
  assert.ok(finalJob.checkoutRefs.some((value) => value.includes("github.event.pull_request.head.sha")));
  const goodEligibility = { LC_ALL: "C", PYTHONCOERCECLOCALE: "0", EVENT_NAME: "pull_request",
    RUN_ATTEMPT: "1", REPOSITORY: "owner/repo",
    HEAD_REPOSITORY: "owner/repo", HEAD_SHA: "a".repeat(40), MERGE_SHA: "b".repeat(40),
    BASE_SHA: "c".repeat(40), PR_NUMBER: "1" };
  const finalKeys = ["QUALITY", "ELIGIBILITY", "A", "B", "C", "D", "E", "INTEGRATION"].map((name) => `${name}_RESULT`)
    .concat(["A", "B", "C", "D", "E", "INTEGRATION"].flatMap((name) => [`${name}_UPLOAD`, `${name}_CLEANUP`]));
  const goodFinal = { LC_ALL: "C", PYTHONCOERCECLOCALE: "0",
    ...Object.fromEntries(finalKeys.map((key) => [key, "success"])) };
  const cases = [
    { args: ["--eligibility"], env: goodEligibility, ok: true },
    { args: ["--eligibility"], env: { ...goodEligibility, RUN_ATTEMPT: "2" }, ok: false },
    { args: ["--eligibility"], env: { ...goodEligibility, HEAD_REPOSITORY: "fork/repo" }, ok: false },
    { args: ["--eligibility"], env: { ...goodEligibility, EVENT_NAME: "push" }, ok: false },
    { args: ["--eligibility"], env: { ...goodEligibility, HEAD_SHA: "bad" }, ok: false },
    { args: ["--eligibility"], env: { ...goodEligibility, EXTRA: "value" }, ok: false },
    { args: ["--require-final-results"], env: goodFinal, ok: true },
  ];
  for (const key of finalKeys) for (const outcome of ["failure", "cancelled", "skipped", "", "unknown"]) {
    cases.push({ args: ["--require-final-results"], env: { ...goodFinal, [key]: outcome }, ok: false });
  }
  const cliWrapper = `import os,runpy,sys\nos.environ.pop('__CF_USER_TEXT_ENCODING',None)\nsys.argv=[sys.argv[1],*sys.argv[2:]]\nrunpy.run_path(sys.argv[0],run_name='__main__')`;
  for (const row of cases) {
    const run = spawnSync(isolatedPython, ["-I", "-B", "-c", cliWrapper, commonPath, ...row.args], {
      encoding: "utf8", env: row.env,
    });
    assert.equal(run.status === 0, row.ok, `${row.args}/${JSON.stringify(row.env)}:${run.stderr}`);
  }
  const dispatchSentinel = `import os,sys\nos.environ.pop('__CF_USER_TEXT_ENCODING',None)\nsys.path.insert(0,'scripts/native-qualification');import common\ncommon.NativeSession.begin=lambda *a:(_ for _ in ()).throw(AssertionError('native selected'))\nassert common._main(['--eligibility'])==0`;
  const sentinel = spawnSync(isolatedPython, ["-I", "-B", "-c", dispatchSentinel], {
    encoding: "utf8", env: goodEligibility,
  });
  assert.equal(sentinel.status, 0, sentinel.stderr);
});

test("ADR0092 common surfaces stay within binding readable highs", () => {
  const highs = new Map<string, number>([
    [workflowPath, 350], [schemaPath, 550], [commonPath, 1250],
    ["test/native-qualification-common.test.ts", 1000], ["scripts/validate-schemas.ts", 220],
  ]);
  const diff = spawnSync("git", ["diff", "--numstat", predecessor, "--", ...highs.keys()], { encoding: "utf8" });
  assert.equal(diff.status, 0, diff.stderr);
  const additions = new Map(diff.stdout.trim().split("\n").filter(Boolean).map((line) => {
    const [count, , path] = line.split("\t"); return [path, Number(count)] as const;
  }));
  for (const [path, high] of highs) assert.ok((additions.get(path) ?? 0) <= high, `${path}: ${additions.get(path)}/${high}`);
  assert.ok(readFileSync(commonPath, "utf8").split("\n").every((line) => line.length <= 160), "common readable width");
  const staticCheck = `import ast,sys\nfor path in sys.argv[1:]:\n tree=ast.parse(open(path).read(),path)\n for node in ast.walk(tree):\n  if getattr(node,'lineno',0)>=800 and isinstance(node,(ast.Try,ast.With)):\n   assert node.end_lineno>node.lineno,(path,node.lineno,'packed transition')`;
  const readable = spawnSync("python3", ["-I", "-B", "-c", staticCheck, commonPath], { encoding: "utf8" });
  assert.equal(readable.status, 0, readable.stderr);
});
