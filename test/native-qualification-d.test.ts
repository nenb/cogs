import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-d-process-lifecycle.py";
const source = readFileSync(path, "utf8");
const observations = [
  "pdeathsig_armed",
  "parent_handshake_exact",
  "before_release_death",
  "after_release_death",
  "starttime_revalidated",
  "session_owned",
  "process_group_owned",
  "credentialed_pidfd_transfer",
  "stable_descendant_census",
  "adoption_exact",
  "term_kill_bounded",
  "siginfo_exact",
  "all_reaped",
  "subreaper_restored",
  "descriptors_restored",
];
const revision = "a".repeat(40);
const golden: Json = {
  version: "cogs.runtime-lifecycle-qualification/v1",
  source_revision: revision,
  source_set_sha256: "b".repeat(64),
  ...Object.fromEntries(observations.map((name) => [name, true])),
};

type Json = Record<string, unknown>;

function decode(cases: Json[]): { accepted: boolean; checks?: Record<string, string> }[] {
  const harness = `
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_d",${JSON.stringify(path)})
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

test("Job D strictly decodes every typed production process-owner observation", () => {
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
    "pdeathsig_armed",
    "parent_handshake_exact",
    "before_release_death",
    "after_release_death",
    "starttime_revalidated",
    "session_owned",
    "process_group_owned",
    "term_kill_bounded",
    "all_reaped",
  ]);
  assert.ok(Object.values(first.checks ?? {}).every((value) => value === "pass"));
  assert.ok(rows.slice(1).every((row) => !row.accepted));
});

test("Job D calls only its zero-argument production-facing process adapter", () => {
  const harness = `
import importlib.util,json
spec=importlib.util.spec_from_file_location("job_d",${JSON.stringify(path)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class ProductionFacingAdapter:
 def __init__(self): self.events=[]
 def qualify_fixed_process_lifecycle(self):
  self.events.append("qualify_fixed_process_lifecycle"); return object()
adapter=ProductionFacingAdapter(); result=m._invoke_production(adapter)
print(json.dumps({"events":adapter.events,"identity":result is not None}))
`;
  const result = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    events: ["qualify_fixed_process_lifecycle"],
    identity: true,
  });
});

test("Job D removes its parallel supervisor, fd baseline, and cleanup branches", () => {
  for (const token of [
    'NativeSession.begin("D", __file__)',
    "session.qualify_fixed_process_lifecycle()",
    "session.settle_native_phase()",
    "common.ReportCandidate(",
    "credentialed_pidfd_transfer",
    "stable_descendant_census",
    "term_kill_bounded",
    "siginfo_exact",
    "subreaper_restored",
  ]) {
    assert.ok(source.includes(token), token);
  }
  assert.doesNotMatch(source, /os\.listdir|os\.scandir|\/proc\/self\/fd|SystemOps|_ProcessOwner/u);
  assert.doesNotMatch(source, /os\.fork|pidfd_open|pidfd_send_signal|setsid\(|waitid\(|waitpid\(|killpg/u);
  assert.doesNotMatch(source, /ctypes|prctl\(|socketpair\(|sendmsg\(|recvmsg\(|SCM_RIGHTS\s*=|signal\./u);
  assert.doesNotMatch(
    source,
    /WorkflowContext|finalize_report|CLEANUP_KEYS|cleanup\s*=|dict\.fromkeys\(CHECKS,\s*["']pass/u,
  );
  assert.ok(source.split("\n").length - 1 <= 400);
});
