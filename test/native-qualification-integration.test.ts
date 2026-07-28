import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const path = "scripts/native-qualification/thin-integration.py";
const launcher = "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py";
const source = readFileSync(path, "utf8");

function adapter(sourceText: string) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", sourceText], {
    encoding: "utf8",
    env: { PYTHONDONTWRITEBYTECODE: "1" },
  });
}

const portableSetup = `
import json, runpy, types
module = runpy.run_path(${JSON.stringify(path)}, run_name="native_integration_adapter")
launcher = open(${JSON.stringify(launcher)}, "rb").read()
digest = module["hashlib"].sha256(launcher).hexdigest()
production = module["_load_held_launcher"](launcher, digest)
revision = "1" * 40
source_digest = "2" * 64
value = {name: True for name in module["RESULT_BOOLEANS"]}
value.update({
 "version": module["RESULT_VERSION"], "marker": module["MARKER"],
 "source_revision": revision, "source_set_sha256": source_digest,
 "closure_sha256": "3" * 64,
 "gzip_output_sha256": module["OUTPUT_SHA256"],
 "zstd_output_sha256": module["OUTPUT_SHA256"],
})
def raw(row): return json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\\n"
`;

test("integration requires the exact RuntimeQualificationResult fields", () => {
  const result = adapter(`${portableSetup}
qualified = module["qualify"](production, raw(value), revision, source_digest)
assert tuple(qualified["checks"]) == module["CHECK_IDS"]
assert all(qualified["checks"].values())
assert qualified["metadata"]["closure_sha256"] == "3" * 64
for name in tuple(value):
 mutant = dict(value); mutant.pop(name)
 try: module["qualify"](production, raw(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("missing field accepted: " + name)
mutant = dict(value); mutant["unrelated_true"] = True
try: module["qualify"](production, raw(mutant), revision, source_digest)
except RuntimeError: pass
else: raise SystemExit("extra field accepted")
mutant = dict(value); mutant["closure_digest"] = mutant.pop("closure_sha256")
try: module["qualify"](production, raw(mutant), revision, source_digest)
except RuntimeError: pass
else: raise SystemExit("renamed field accepted")
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("integration rejects false, wrongly typed, malformed, and substituted results", () => {
  const result = adapter(`${portableSetup}
for name in module["RESULT_BOOLEANS"]:
 mutant = dict(value); mutant[name] = False
 try: module["qualify"](production, raw(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("false field accepted: " + name)
for name, wrong in (("pid_one", 1), ("version", True), ("closure_sha256", "g" * 64), ("gzip_output_sha256", "4" * 64)):
 mutant = dict(value); mutant[name] = wrong
 try: module["qualify"](production, raw(mutant), revision, source_digest)
 except RuntimeError: pass
 else: raise SystemExit("wrong field accepted: " + name)
for malformed in (raw(value)[:-1], raw(value) + b"\\n", b'{"version":1,"version":2}\\n'):
 try: module["qualify"](production, malformed, revision, source_digest)
 except (RuntimeError, ValueError): pass
 else: raise SystemExit("malformed result accepted")
try: module["qualify"](types.SimpleNamespace(RuntimeQualificationResult=types.SimpleNamespace), raw(value), revision, source_digest)
except (RuntimeError, TypeError): pass
else: raise SystemExit("SimpleNamespace result accepted")
`);
  assert.equal(result.status, 0, result.stderr);
});

test("integration uses complete held-source admission and fixed fd ABI", () => {
  assert.match(source, /SOURCES = \([\s\S]*completion_elf\.py[\s\S]*completion_trusted_runtime_closure\.py[\s\S]*completion_trusted_runtime_launcher\.py[\s\S]*trusted-runtime-closure-v1\.json/u);
  assert.match(source, /version="cogs\.runtime-source-admission\/v1"/u);
  assert.match(source, /checkout\[0\] == \(context\.head_sha \+ "\\n"\)\.encode\(\) and checkout\[1\] == b""/u);
  assert.match(source, /F_DUPFD_CLOEXEC, 64[\s\S]*zip\(sources, \(0, 1, 2, 3, 4\), strict=True\)/u);
  assert.match(source, /os\.execve\("\/usr\/bin\/python3"/u);
  assert.match(source, /type\(result\) is result_type/u);
  assert.doesNotMatch(source, /SimpleNamespace|len\(booleans\)|"evidence" not in result|dict\.fromkeys\(CHECK_IDS, True\)/u);
});

test("integration owns bounded preregistered cleanup on every launch path", () => {
  assert.match(source, /gate_read, gate_write = os\.pipe2/u);
  assert.match(source, /pidfd = os\.pidfd_open\(pid, 0\)[\s\S]*os\.write\(gate_write, b"G"\)/u);
  assert.match(source, /os\.waitid\(os\.P_PIDFD, pidfd, os\.WEXITED \| os\.WNOHANG\)/u);
  assert.match(source, /signal\.pidfd_send_signal\(pidfd, signal\.SIGTERM\)[\s\S]*signal\.SIGKILL/u);
  assert.match(source, /ExceptionGroup\("integration cleanup"/u);
  assert.match(source, /for name, value in before\.items\(\):[\s\S]*result\[name\] = False/u);
  assert.doesNotMatch(source, /waitpid\([^\n]*, 0\)|subprocess\.Popen|communicate\(/u);
});

test("thin integration remains metadata-only and within ADR 0090", () => {
  assert.match(source, /sys\.argv != \[sys\.argv\[0\], "--workflow-bound"\]/u);
  assert.doesNotMatch(source, /sudo|download-artifact|upload-artifact|needs\.|requests|urllib|boto|AWS/u);
  assert.ok(source.split("\n").length - 1 <= 350);
});
