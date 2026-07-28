import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/job-e-sandbox.py";
const launcher = "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py";
const source = readFileSync(path, "utf8");

function adapter(sourceText: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", sourceText], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

const portableSetup = `
import dataclasses, json, runpy, types
module = runpy.run_path(${JSON.stringify(path)}, run_name="native_e_adapter")
launcher = open(${JSON.stringify(launcher)}, "rb").read()
digest = module["hashlib"].sha256(launcher).hexdigest()
production = module["_load_held_launcher"](launcher, digest)
revision = "1" * 40
source_digest = "2" * 64
value = {name: True for name in module["RESULT_BOOLEANS"]}
value.update({
 "version": module["RESULT_VERSION"], "marker": module["MARKER"],
 "source_revision": revision, "source_set_sha256": source_digest,
 "closure_sha256": "3" * 64, "gzip_output_sha256": "4" * 64,
 "zstd_output_sha256": "5" * 64,
})
def raw(row): return json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\\n"
result = module["_decode_result"](production, raw(value), revision, source_digest)
outer = {name: True for name in ("descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout")}
policy = production._seccomp_digest()
`;

test("Job E derives every check and the policy digest from the exact production result", () => {
  const result = adapter(`${portableSetup}
qualified = module["qualify"](result, production.RuntimeQualificationResult, policy, outer)
assert tuple(qualified["checks"]) == module["CHECK_IDS"]
assert all(qualified["checks"].values())
assert qualified["policy_sha256"] == policy
for name in module["RESULT_BOOLEANS"]:
 mutant = dataclasses.replace(result, **{name: False})
 try: module["qualify"](mutant, production.RuntimeQualificationResult, policy, outer)
 except RuntimeError: pass
 else: raise SystemExit("false production fact accepted: " + name)
for name in outer:
 mutant = dict(outer); mutant[name] = False
 try: module["qualify"](result, production.RuntimeQualificationResult, policy, mutant)
 except RuntimeError: pass
 else: raise SystemExit("false outer cleanup accepted: " + name)
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("Job E rejects incompatible fields, digests, and substitutable result objects", () => {
  const result = adapter(`${portableSetup}
for name in tuple(value):
 mutant = dict(value); mutant.pop(name)
 try: module["_decode_result"](production, raw(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("missing result field accepted: " + name)
mutant = dict(value); mutant["unrelated_true"] = True
try: module["_decode_result"](production, raw(mutant), revision, source_digest)
except RuntimeError: pass
else: raise SystemExit("extra result field accepted")
for name, wrong in (("pid_one", 1), ("version", True), ("closure_sha256", "g" * 64)):
 mutant = dict(value); mutant[name] = wrong
 try: module["_decode_result"](production, raw(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("wrong type/digest accepted: " + name)
substitute = types.SimpleNamespace(**result.__dict__)
try: module["qualify"](substitute, production.RuntimeQualificationResult, policy, outer)
except RuntimeError: pass
else: raise SystemExit("SimpleNamespace result accepted")
`);
  assert.equal(result.status, 0, result.stderr);
});

test("Job E sole sudo root enters the admitted production coordinator", () => {
  assert.match(source, /"\/usr\/bin\/sudo", "-n", "--close-from=3", "\/usr\/bin\/env", "-i"/u);
  assert.match(source, /"--production-root"/u);
  assert.match(source, /\(admission_read, admission_write\) == \(3, 4\)/u);
  assert.match(source, /root_fd == 4/u);
  assert.match(source, /os\.execve\("\/usr\/bin\/python3", \("\/usr\/bin\/python3", "-I", "-B", os\.fspath\(ROOT \/ LAUNCHER\)\), \{\}\)/u);
  assert.match(source, /type\(result\) is result_type/u);
  assert.match(source, /checkout\[0\] == \(context\.head_sha \+ "\\n"\)\.encode\(\) and checkout\[1\] == b""/u);
  assert.match(source, /policy_digest = module\._seccomp_digest\(\)/u);
  assert.doesNotMatch(source, /module\._enter_boundary|_root_setup|def _mount|libc\.mount|libc\.unshare|os\.chroot/u);
});

test("Job E registers before release and bounds all process cleanup", () => {
  assert.match(source, /gate_read, gate_write = os\.pipe2/u);
  assert.match(source, /pidfd = os\.pidfd_open\(pid, 0\)[\s\S]*os\.write\(gate_write, b"G"\)/u);
  assert.match(source, /os\.waitid\(os\.P_PIDFD, pidfd, os\.WEXITED \| os\.WNOHANG\)/u);
  assert.match(source, /signal\.pidfd_send_signal\(pidfd, signal\.SIGTERM\)[\s\S]*signal\.SIGKILL/u);
  assert.match(source, /ExceptionGroup\("Job E process cleanup"/u);
  assert.match(source, /libc\.prctl\(1, signal\.SIGKILL/u);
  assert.doesNotMatch(source, /waitpid\([^\n]*, 0\)|subprocess\.run\([^\n]*sudo|communicate\(/u);
});

test("Job E reports individually observed cleanup and stays within ADR 0090", () => {
  assert.match(source, /for name, value in before\.items\(\):[\s\S]*result\[name\] = False/u);
  assert.match(source, /"checkout_unchanged": outer\["checkout"\]/u);
  assert.match(source, /"mounts_restored": result\.mounts_restored and outer\["mounts"\]/u);
  assert.match(source, /common\.finalize_report/u);
  assert.doesNotMatch(source, /dict\.fromkeys\(common\.CLEANUP_KEYS, True\)/u);
  assert.ok(source.split("\n").length - 1 <= 450);
});
