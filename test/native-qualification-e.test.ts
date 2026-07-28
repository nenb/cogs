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
 "seccomp_program_sha256": "3" * 64,
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
assert qualified["policy_sha256"] == "3" * 64
for name in module["SANDBOX_RESULT_BOOLEANS"]:
 mutant = dict(values); mutant[name] = False
 try: module["qualify"](result(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("false sandbox observation accepted: " + name)
for name, wrong in (
 ("version", True), ("source_revision", "4" * 40),
 ("source_set_sha256", "g" * 64), ("seccomp_program_sha256", "4" * 63),
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

test("Job E composes runner admission with one fixed held-byte root capsule", () => {
  const run = adapter(`${setup}
events = []
checkout = {"owner": 1000, "launcher": b"held-generation"}
root_envelope = (
 "/usr/bin/sudo", "-n", "--close-from=3", "/usr/bin/env", "-i",
 "/usr/bin/python3", "-I", "-B", "-c", b"held-root-bootstrap",
)
class Session:
 source_set_sha256 = ""
 context = types.SimpleNamespace(head_sha=revision)
 def run_fixed_operation(self, operation):
  assert operation == "E"
  self.source_set_sha256 = source_digest
  held = bytes(checkout["launcher"])
  events.append(("runner-admitted", checkout["owner"], held))
  checkout["launcher"] = b"replacement"
  assert all("checkout" not in str(item) for item in root_envelope)
  events.append(("root-consumed", held, 0))
  return result()
value, admitted_revision, admitted_digest = module["_invoke_sandbox"](Session())
assert type(value) is dict and value == values
assert (admitted_revision, admitted_digest) == (revision, source_digest)
assert events == [
 ("runner-admitted", 1000, b"held-generation"),
 ("root-consumed", b"held-generation", 0),
]
`);
  assert.equal(run.status, 0, run.stderr);
});

test("Job E delegates baseline, report, and cleanup authority to common", () => {
  const run = adapter(`${setup}
class Candidate:
 def __init__(self, **keywords): self.__dict__.update(keywords)
class Evidence: restored = True
class Session:
 context = types.SimpleNamespace(head_sha=revision)
 source_set_sha256 = source_digest
 def run_fixed_operation(self, operation): events.append(("operation", operation)); return result()
 def settle_native_phase(self): events.append("settle"); return Evidence()
 def publish(self, candidate): events.append(("publish", candidate))
class NativeSession:
 @staticmethod
 def begin(job, driver): events.append(("begin", job)); return session
events = []
session = Session()
common = types.SimpleNamespace(NativeSession=NativeSession, ReportCandidate=Candidate)
assert module["_run"](common) == 0
candidate = events[-1][1]
assert tuple(candidate.production_checks) == module["PRODUCTION_CHECK_IDS"]
assert set(candidate.production_checks.values()) == {"pass"}
assert not hasattr(candidate, "cleanup") and not hasattr(candidate, "result")
assert events[0] == ("begin", "E") and events[-2] == "settle"
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
