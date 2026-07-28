import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-c-descriptors.py";
const source = readFileSync(path, "utf8");
const observations = [
  "nofile_measured",
  "nofile_normalized",
  "fd_198_exact",
  "fd_4096_exact",
  "close_range_exact",
  "cloexec_exact",
  "inheritance_exact",
  "limit_restored",
  "descriptors_restored",
  "children_reaped",
];
const revision = "a".repeat(40);
const golden: Json = {
  version: "cogs.runtime-descriptor-qualification/v1",
  source_revision: revision,
  source_set_sha256: "b".repeat(64),
  ...Object.fromEntries(observations.map((name) => [name, true])),
};

type Json = Record<string, unknown>;

function decode(cases: Json[]): { accepted: boolean; checks?: Record<string, string> }[] {
  const harness = `
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_c",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
for value in json.loads(${JSON.stringify(JSON.stringify(cases))}):
 try: print(json.dumps({"accepted":True,"checks":m.qualify(value,${JSON.stringify(revision)},${JSON.stringify("b".repeat(64))})}))
 except BaseException: print(json.dumps({"accepted":False}))
`;
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row));
}

test("Job C strictly decodes every production fd/getdents/close_range observation", () => {
  const cases: Json[] = [golden];
  for (const name of observations) {
    cases.push({ ...golden, [name]: false });
    const missing = { ...golden };
    delete missing[name];
    cases.push(missing);
  }
  cases.push({ ...golden, source_revision: "c".repeat(40) });
  cases.push({ ...golden, source_set_sha256: "not-a-digest" });
  cases.push({ ...golden, completed: true });
  const rows = decode(cases);
  const first = rows[0];
  assert.ok(first);
  assert.equal(first.accepted, true);
  assert.deepEqual(Object.keys(first.checks ?? {}), [
    "nofile_measured",
    "nofile_normalized",
    "fd_198_exact",
    "fd_4096_exact",
    "close_range_exact",
    "cloexec_exact",
    "inheritance_exact",
    "limit_restored",
  ]);
  assert.ok(Object.values(first.checks ?? {}).every((value) => value === "pass"));
  assert.ok(rows.slice(1).every((row) => !row.accepted));
});

test("Job C reaches the real common zero-argument operation boundary", () => {
  const harness = `
import importlib.util,sys,types
sys.path.insert(0,'scripts/native-qualification'); import common
spec=importlib.util.spec_from_file_location('job_c',${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
base={key:('baseline',key) for key in common.CLEANUP_KEYS}; base['paths']=(None,None)
class Ops:
 def __init__(self): self.fds=common.FdRegistry(); self.source_set_sha256='b'*64; self.events=[]
 def observe(self,context): return base
 def run_fixed_operation(self,context,operation):
  self.events.append((context.job,operation)); raise RuntimeError('safe native boundary')
class Cust:
 def abort(self,error): self.error=error
ops=Ops(); session=common.NativeSession._begin_with_ops(types.SimpleNamespace(job='C'),ops,Cust())
try: m._invoke_production(session)
except RuntimeError as error: assert str(error)=='safe native boundary'
else: raise AssertionError('completed result substituted')
assert ops.events == [('C','C')]
`;
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("Job C real __main__ preserves a successful exit", () => {
  const harness = `
import json,runpy,sys,types
value=json.loads(${JSON.stringify(JSON.stringify(golden))})
class Evidence: restored=True
class Session:
 context=types.SimpleNamespace(head_sha=${JSON.stringify(revision)})
 source_set_sha256=${JSON.stringify("b".repeat(64))}
 def qualify_fixed_descriptor_primitives(self): return value
 def settle_native_phase(self): return Evidence()
 def publish(self,candidate): assert candidate.primary_error is None
class NativeSession:
 @classmethod
 def begin(cls,job,path): assert job=='C'; return Session()
class Candidate:
 def __init__(self,*values): self.primary_error=values[-1]
common=types.ModuleType('common'); common.NativeSession=NativeSession; common.ReportCandidate=Candidate
sys.modules['common']=common; sys.argv=[${JSON.stringify(path)},'--workflow-bound']
try: runpy.run_path(${JSON.stringify(path)},run_name='__main__')
except SystemExit as error: assert error.code==0
else: raise AssertionError('main did not exit')
`;
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("Job C removes local enumeration, close_range, process, and cleanup branches", () => {
  for (const token of [
    'NativeSession.begin("C", __file__)',
    "session.qualify_fixed_descriptor_primitives()",
    "session.settle_native_phase()",
    "common.ReportCandidate(",
    '"close_range_exact"',
    '"inheritance_exact"',
  ]) {
    assert.ok(source.includes(token), token);
  }
  assert.doesNotMatch(source, /os\.listdir|os\.scandir|\/proc\/self\/fd|SYS_CLOSE_RANGE|libc\.syscall/u);
  assert.doesNotMatch(source, /os\.fork|pidfd_open|pidfd_send_signal|waitid\(|waitpid\(|SystemOps/u);
  assert.doesNotMatch(
    source,
    /WorkflowContext|finalize_report|CLEANUP_KEYS|cleanup\s*=|dict\.fromkeys\(CHECKS,\s*["']pass/u,
  );
  assert.ok(source.split("\n").length - 1 <= 280);
});
