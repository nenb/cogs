import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-c-descriptors.py";
const source = readFileSync(path, "utf8");
const observations = [
  "getdents_exact",
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
const golden = {
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
 try: print(json.dumps({"accepted":True,"checks":m.qualify(value,${JSON.stringify(revision)})}))
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
  assert.equal(rows[0].accepted, true);
  assert.deepEqual(Object.keys(rows[0].checks ?? {}), [
    "nofile_measured",
    "nofile_normalized",
    "fd_198_exact",
    "fd_4096_exact",
    "close_range_exact",
    "cloexec_exact",
    "inheritance_exact",
    "limit_restored",
  ]);
  assert.ok(Object.values(rows[0].checks ?? {}).every((value) => value === "pass"));
  assert.ok(rows.slice(1).every((row) => !row.accepted));
});

test("Job C calls only its zero-argument production-facing adapter", () => {
  const harness = `
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_c",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class ProductionFacingAdapter:
 def __init__(self): self.events=[]
 def qualify_fixed_descriptor_primitives(self):
  self.events.append("qualify_fixed_descriptor_primitives"); return object()
adapter=ProductionFacingAdapter(); result=m._invoke_production(adapter)
print(json.dumps({"events":adapter.events,"identity":result is not None}))
`;
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    events: ["qualify_fixed_descriptor_primitives"],
    identity: true,
  });
});

test("Job C removes local enumeration, close_range, process, and cleanup branches", () => {
  for (const token of [
    'NativeSession.begin("C", __file__)',
    "session.qualify_fixed_descriptor_primitives()",
    "session.settle_native_phase()",
    "common.ReportCandidate(",
    '"getdents_exact"',
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
