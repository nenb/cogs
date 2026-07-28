import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-e-sandbox.py";
const source = readFileSync(path, "utf8");

function adapter(body: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", body], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

const setup = `
import runpy, types
module = runpy.run_path(${JSON.stringify(path)}, run_name="native_e_portable")
revision = "1" * 40
source_digest = "2" * 64
observed = {name: True for name in module["SANDBOX_RESULT_BOOLEANS"]}
values = {
 "version": module["SANDBOX_RESULT_VERSION"],
 "source_revision": revision,
 "source_set_sha256": source_digest,
 "seccomp_program_sha256": module["POLICY_SHA256"],
 **observed,
}
def result(row=values):
 return dict(row)
`;

test("Job E accepts only the exact closed sandbox result", () => {
  const run = adapter(`${setup}
qualified = module["qualify"](result(), revision, source_digest)
assert tuple(qualified["checks"]) == module["PRODUCTION_CHECK_IDS"]
assert all(qualified["checks"].values())
assert qualified["policy_sha256"] == module["POLICY_SHA256"]
for name in module["SANDBOX_RESULT_BOOLEANS"]:
 mutant = dict(values); mutant[name] = False
 try: module["qualify"](result(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("false sandbox observation accepted: " + name)
for name, wrong in (
 ("version", True), ("source_revision", "4" * 40),
 ("source_set_sha256", "g" * 64), ("seccomp_program_sha256", "4" * 64),
 ("pid_one", 1),
):
 mutant = dict(values); mutant[name] = wrong
 try: module["qualify"](result(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("wrong sandbox field accepted: " + name)
`);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout, "");
});

test("Job E rejects reordered, open, and cross-profile primitive results", () => {
  const run = adapter(`${setup}
for hostile in (
 {name: values[name] for name in module["SANDBOX_RESULT_FIELDS"][:-1]},
 {**values, "extra": True},
 {name: values[name] for name in reversed(module["SANDBOX_RESULT_FIELDS"])},
 {"version": "cogs.runtime-qualification/v1", "closure_sha256": "3" * 64},
):
 try: module["qualify"](hostile, revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("open or cross-profile sandbox value accepted")
assert not ({"closure_sha256", "gzip_output_sha256", "zstd_output_sha256"} & set(module["SANDBOX_RESULT_FIELDS"]))
`);
  assert.equal(run.status, 0, run.stderr);
});

test("Job E reaches the real common sandbox operation boundary", () => {
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
session = common.NativeSession._begin_with_ops(types.SimpleNamespace(job="E"), ops, Cust())
try: module["_invoke_sandbox"](session)
except RuntimeError as error: assert str(error) == "safe native boundary"
else: raise AssertionError("completed result substituted")
assert ops.events == [("E", "E")]
`);
  assert.equal(run.status, 0, run.stderr);
});

test("Job E real __main__ preserves a successful exit", () => {
  const run = adapter(`${setup}
import sys
class Candidate:
 def __init__(self, **keywords): self.__dict__.update(keywords)
class Evidence: restored = True
class Session:
 context = types.SimpleNamespace(head_sha=revision)
 source_set_sha256 = source_digest
 def run_fixed_operation(self, operation): assert operation == "E"; return result()
 def settle_native_phase(self): return Evidence()
 def publish(self, candidate): assert candidate.primary_error is None
class NativeSession:
 @staticmethod
 def begin(job, driver): assert job == "E"; return Session()
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

test("Job E contains no root pathname bootstrap or parallel native owner", () => {
  assert.match(source, /session\.run_fixed_operation\("E"\)/u);
  assert.match(source, /session\.settle_native_phase\(\)/u);
  assert.match(source, /common\.ReportCandidate\(/u);
  assert.doesNotMatch(source, /\/tmp\/cogs|\/run\/cogs|completion_trusted_runtime/u);
  assert.doesNotMatch(source, /LAUNCHER|SOURCES\s*=/u);
  assert.doesNotMatch(source, /sudo|subprocess|ctypes|fcntl|resource|select|signal/u);
  assert.doesNotMatch(source, /pipe2|fork\(|execve|pidfd|waitid|unshare|mount\(/u);
  assert.doesNotMatch(source, /finalize_report|CLEANUP_KEYS|cleanup\s*=|_baseline|_observe/u);
  assert.doesNotMatch(source, /closure_sha256|gzip_output|zstd_output|compression-v1/u);
  assert.ok(source.split("\n").length - 1 <= 500);
});
