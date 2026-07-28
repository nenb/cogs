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
  if (job === "B") return [objects(3), objects(5)].map((toolRows, index) => {
    const view = normalized(toolRows);
    const mapping = digestValue(view.map(({ role, sha256 }) => [role, sha256]));
    const executable = toolRows[0]; assert.ok(executable);
    return { id: index === 0 ? "gzip" : "zstd", objects: toolRows, closure_sha256: digestValue(view),
      mapping_sha256: mapping, source_sha256: executable.sha256, source_size_bytes: 11,
      sealed_sha256: executable.sha256, sealed_size_bytes: 11, seal_mask: 63,
      execution_mapping_sha256: mapping, output_sha256: markerHash };
  });
  if (job === "E") return [{ id: "sandbox-policy", role: "policy", sha256: "8".repeat(64), size_bytes: 0 }];
  if (job === "integration") return ["closure", "gzip_output", "source_set", "zstd_output"]
    .map((id) => ({ id, role: "digest", sha256: "9".repeat(64), size_bytes: 0 }));
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
function block(id: string) {
  const start = workflow.indexOf(`  ${id}:`);
  assert.notEqual(start, -1);
  const tail = workflow.slice(start + id.length + 3);
  const next = /\n {2}[a-z0-9-]+:\n/u.exec(tail);
  return workflow.slice(start, next ? start + id.length + 3 + (next.index ?? 0) : undefined);
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
  const bWrong = report("B"); bWrong.metadata.forEach((row: any) => { row.output_sha256 = "e".repeat(64); });
  const bMapping = report("B"); bMapping.metadata[1].execution_mapping_sha256 = bMapping.metadata[0].execution_mapping_sha256;
  for (const value of [aOrder, aProvider, aSummary, bWrong, bMapping]) {
    assert.equal(validate(value), true, "relation remains structural");
    semanticRows.push({ value, accept: false });
  }
  const mask = report("B"); mask.metadata[0].seal_mask = 15;
  assert.equal(validate(mask), false, "historical four-bit mask");
  const oversize = report("A"); oversize.metadata[0].size_bytes = 134_217_729;
  assert.equal(validate(oversize), false, "A exact object bound");
  pythonValidate(semanticRows);
});

test("common owns baselines, cleanup checks, leases, and bounded exact dirents", () => {
  const script = `import hashlib,json,os,struct,sys\nsys.path.insert(0,'scripts/native-qualification');import common
h=lambda p:hashlib.sha256(open(p,'rb').read()).hexdigest()
c=common.WorkflowContext('C','owner/repo','owner/repo','a'*40,'b'*40,'a'*40,'b'*40,'c'*40,common.JOB_IDS['C'],1,1,1,'image','6.8.0-100-generic','x86_64',h(common.WORKFLOW),h(common.COMMON.parent/common.DRIVERS['C']),h(common.COMMON))
class Ops:
 def __init__(self): self.fds=common.FdRegistry();self.source_set_sha256='1'*64;self.rows=[];self.calls=0
 def observe(self,c): self.calls+=1;return dict(self.rows[self.calls-1])
 def run_fixed_operation(self,c,o): assert o=='C';return {'typed':'observation'}
class Cust:
 def publish(self,raw): self.raw=raw
base={k:('value',k) for k in common.CLEANUP_KEYS};base['paths']=(None,None)
ops=Ops();ops.rows=[base,dict(base)];cust=Cust();s=common.NativeSession._begin_with_ops(c,ops,cust)
assert s.run_fixed_operation('C')=={'typed':'observation'}
try:s.run_fixed_operation('C');raise AssertionError('replay')
except common.QualificationError:pass
e=s.settle_native_phase();assert e.restored
candidate=common.ReportCandidate(dict.fromkeys(common.PRODUCTION_CHECK_IDS['C'],'pass'),[],None,None,None)
p=s.publish(candidate);assert p==common.report_path('C')
r=json.loads(cust.raw);assert r['checks'][-1]=={'id':'cleanup_restored','outcome':'pass'} and all(r['cleanup'].values())
ops=Ops();changed=dict(base);changed['checkout']=('drift',);ops.rows=[base,changed];s=common.NativeSession._begin_with_ops(c,ops,Cust());e=s.settle_native_phase();assert not e.restored and e.values['checkout'] is False
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
with patch.object(common.os,'stat',return_value=status):assert common._name_matches(4,'report.json',status)
replacement=os.stat_result((0o100600,2,2,1,6,0,3,0,0,0))
with patch.object(common.os,'stat',return_value=replacement):assert not common._name_matches(4,'report.json',status)`;
  const run = spawnSync("python3", ["-I", "-B", "-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(common, /os\.listdir|os\.scandir|fdopendir/u);
  for (const token of ["getdents64", "CLOSE_UNCERTAIN", "report-custodian", "_name_matches",
    "report directory replacement", "cleanup report replacement", "production_checks"]) assert.ok(common.includes(token), token);
});

test("workflow eligibility and every named dependency/upload/cleanup fail closed", () => {
  const eligibility = block("native-qualification-eligibility");
  assert.ok(eligibility.includes("common.py --eligibility") && eligibility.includes("/usr/bin/env -i"));
  for (const [job, id, driver] of jobs) {
    const value = block(id);
    assert.match(value, /["']\$NQ_DRIVER["']\s+--workflow-bound/u);
    assert.ok(value.includes(`NQ_DRIVER: scripts/native-qualification/${driver}`));
    assert.ok(value.includes("id: upload") && value.includes("id: cleanup"));
    assert.ok(value.includes("steps.upload.outcome") && value.includes("steps.cleanup.outcome"));
    assert.ok(value.indexOf("id: upload") < value.indexOf("id: cleanup"));
    assert.ok(value.includes(`/tmp/cogs-native-qualification-${job}/report.json`));
  }
  const final = block("native-qualification-required");
  assert.match(final, /if:\s*\$\{\{\s*always\(\)\s*\}\}/u);
  assert.ok(final.includes("common.py --require-final-results"));
  assert.doesNotMatch(final, /join\(needs\.\*\.result/u);
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
  for (const row of cases) {
    const method = row.args[0] === "--eligibility" ? "evaluate_eligibility" : "require_final_results";
    const script = `import json,sys;sys.path.insert(0,'scripts/native-qualification');import common;getattr(common,'${method}')(json.loads(sys.argv[1]))`;
    const run = spawnSync("python3", ["-I", "-B", "-c", script, JSON.stringify(row.env)], { encoding: "utf8" });
    assert.equal(run.status === 0, row.ok, `${row.args}/${JSON.stringify(row.env)}`);
  }
});

test("ADR0091 W2 surfaces stay within binding highs", () => {
  const highs = new Map<string, number>([
    [workflowPath, 300], [schemaPath, 420], [commonPath, 750],
    ["test/native-qualification-common.test.ts", 500], ["scripts/validate-schemas.ts", 140],
  ]);
  const diff = spawnSync("git", ["diff", "--numstat", predecessor, "--", ...highs.keys()], { encoding: "utf8" });
  assert.equal(diff.status, 0, diff.stderr);
  const additions = new Map(diff.stdout.trim().split("\n").filter(Boolean).map((line) => {
    const [count, , path] = line.split("\t"); return [path, Number(count)] as const;
  }));
  for (const [path, high] of highs) assert.ok((additions.get(path) ?? 0) <= high, `${path}: ${additions.get(path)}/${high}`);
  assert.ok(readFileSync(commonPath, "utf8").split("\n").every((line) => line.length <= 160), "common readable width");
});
