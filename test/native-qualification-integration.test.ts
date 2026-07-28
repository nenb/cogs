import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/thin-integration.py";
const source = readFileSync(path, "utf8");

function adapter(body: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", body], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

const setup = `
import runpy, types
module = runpy.run_path(${JSON.stringify(path)}, run_name="native_integration_portable")
revision = "1" * 40
source_digest = "2" * 64
observed = {name: True for name in module["RESULT_BOOLEANS"]}
values = {
 "version": module["RESULT_VERSION"], "marker": module["MARKER"],
 "source_revision": revision, "source_set_sha256": source_digest,
 "closure_sha256": "3" * 64,
 "gzip_output_sha256": module["OUTPUT_SHA256"],
 "zstd_output_sha256": module["OUTPUT_SHA256"],
 **observed,
}
def result(row=values):
 return dict(row)
`;

test("integration accepts only the exact complete ordinary result", () => {
  const run = adapter(`${setup}
qualified = module["qualify"](result(), revision, source_digest)
assert tuple(qualified["checks"]) == module["PRODUCTION_CHECK_IDS"]
assert all(qualified["checks"].values())
assert qualified["metadata"]["closure_sha256"] == "3" * 64
for name in module["RESULT_BOOLEANS"]:
 mutant = dict(values); mutant[name] = False
 try: module["qualify"](result(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("false production observation accepted: " + name)
for name, wrong in (
 ("version", True), ("marker", "wrong"), ("source_revision", "4" * 40),
 ("source_set_sha256", "g" * 64), ("closure_sha256", "4" * 63),
 ("gzip_output_sha256", "4" * 64), ("zstd_output_sha256", "5" * 64),
 ("pid_one", 1),
):
 mutant = dict(values); mutant[name] = wrong
 try: module["qualify"](result(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("wrong ordinary field accepted: " + name)
`);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout, "");
});

test("integration rejects missing, reordered, open, and sandbox profiles", () => {
  const run = adapter(`${setup}
for hostile in (
 {name: values[name] for name in module["RESULT_FIELDS"][:-1]},
 {**values, "extra": True},
 {name: values[name] for name in reversed(module["RESULT_FIELDS"])},
 {"version": "cogs.sandbox-qualification/v1", "seccomp_program_sha256": "4" * 64},
):
 try: module["qualify"](hostile, revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("open or cross-profile ordinary value accepted")
`);
  assert.equal(run.status, 0, run.stderr);
});

test("integration reaches the real common ordinary operation boundary", () => {
  const run = adapter(`${setup}
import sys
sys.path.insert(0, "scripts/native-qualification")
import common
base = {key: ("baseline", key) for key in common.CLEANUP_KEYS}
base["paths"] = (None, None)
class Ops:
 def __init__(self):
  self.fds = common.FdRegistry(); self.source_set_sha256 = source_digest; self.events = []
 def observe(self, context): return base
 def run_fixed_operation(self, context, operation):
  self.events.append((context.job, operation))
  raise RuntimeError("safe native boundary")
ops = Ops()
class Cust:
    def abort(self, error): self.error = error
session = common.NativeSession._begin_with_ops(types.SimpleNamespace(job="integration"), ops, Cust())
try: module["_invoke_complete_runtime"](session)
except RuntimeError as error: assert str(error) == "safe native boundary"
else: raise AssertionError("completed result substituted")
assert ops.events == [("integration", "integration")]
`);
  assert.equal(run.status, 0, run.stderr);
});

test("integration real __main__ preserves a successful exit", () => {
  const run = adapter(`${setup}
import sys
class Candidate:
 def __init__(self, **keywords): self.__dict__.update(keywords)
class Evidence: restored = True
class Session:
 context = types.SimpleNamespace(head_sha=revision)
 source_set_sha256 = source_digest
 def run_fixed_operation(self, operation): assert operation == "integration"; return result()
 def settle_native_phase(self): return Evidence()
 def publish(self, candidate): assert candidate.primary_error is None
class NativeSession:
 @staticmethod
 def begin(job, driver): assert job == "integration"; return Session()
common = types.ModuleType("common")
common.NativeSession = NativeSession; common.ReportCandidate = Candidate
sys.modules["common"] = common
sys.argv = [${JSON.stringify(path)}, "--workflow-bound"]
try: runpy.run_path(${JSON.stringify(path)}, run_name="__main__")
except SystemExit as error: assert error.code == 0
else: raise AssertionError("main did not exit")
`);
  assert.equal(run.status, 0, run.stderr);
});

test("integration has no substitute bootstrap, transport, or native owner", () => {
  assert.match(source, /session\.run_fixed_operation\("integration"\)/u);
  assert.match(source, /session\.settle_native_phase\(\)/u);
  assert.match(source, /common\.ReportCandidate\(/u);
  assert.doesNotMatch(source, /sudo|\/tmp\/cogs|\/run\/cogs|completion_trusted_runtime/u);
  assert.doesNotMatch(source, /SOURCES\s*=|LAUNCHER|subprocess|ctypes|fcntl|resource/u);
  assert.doesNotMatch(source, /select|signal|socket|struct|pipe2|fork\(|execve|pidfd/u);
  assert.doesNotMatch(source, /waitid|unshare|mount\(|source-admission|_strict_json|json\./u);
  assert.doesNotMatch(source, /finalize_report|CLEANUP_KEYS|cleanup\s*=|_baseline|_observe/u);
  assert.equal((source.match(/run_fixed_operation\(/gu) ?? []).length, 1);
  assert.ok(source.split("\n").length - 1 <= 400);
});
