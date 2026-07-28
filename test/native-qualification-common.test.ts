import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js");
const root = process.cwd();
const commonPath = `${root}/scripts/native-qualification/common.py`;
const schemaPath = `${root}/schemas/native-qualification-report-v1alpha1.json`;
const workflowPath = `${root}/.github/workflows/ci.yml`;
const pythonProgram = `
import importlib.util, json, os, pathlib, sys
spec = importlib.util.spec_from_file_location("native_common", sys.argv[1])
common = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = common
spec.loader.exec_module(common)
common.platform.release = lambda: "6.8.0-100-generic"
common.platform.machine = lambda: "x86_64"
common.DRIVERS["A"] = "common.py"
values = {
 "LC_ALL":"C", "PYTHONDONTWRITEBYTECODE":"1", "PYTHONHASHSEED":"0",
 "NQ_REPOSITORY":"owner/repository", "NQ_HEAD_SHA":"1"*40,
 "NQ_ENVELOPE_SHA":"2"*40, "NQ_WORKFLOW_SHA":"3"*40,
 "NQ_MERGE_SHA":"4"*40, "NQ_BASE_SHA":"5"*40,
 "NQ_JOB_ID":"native-qualification-a", "NQ_RUN_ID":"10",
 "NQ_RUN_ATTEMPT":"1", "NQ_PR_NUMBER":"7", "NQ_RUNNER_VERSION":"20260728.1"
}
os.environ.clear(); os.environ.update(values)
context = common.WorkflowContext.from_environ("A", sys.argv[1])
def rejects(call):
 try: call()
 except common.QualificationError: return
 raise RuntimeError("mutation accepted")
os.environ["HOME"] = "/forbidden"
rejects(lambda: common.WorkflowContext.from_environ("A", sys.argv[1]))
os.environ.pop("HOME")
clock = iter((0, 500_000_000, 1_000_000_000)).__next__
deadline = common.Deadline(1, clock)
if deadline.remaining() != 0.5: raise RuntimeError("remaining")
rejects(deadline.check)
baseline = common.Baseline.capture({"fds":[1,2], "clean":True})
baseline.require_restored({"clean":True, "fds":[1,2]})
rejects(lambda: baseline.require_restored({"clean":False, "fds":[1,2]}))
checks = {name:"pass" for name in common.CHECK_IDS["A"]}
cleanup = {name:True for name in common.CLEANUP_KEYS}
metadata = [{"id":"closure", "role":"mapping", "sha256":"a"*64, "size_bytes":1}]
target = pathlib.Path("/tmp/cogs-native-qualification-A.json")
target.unlink(missing_ok=True)
path = common.finalize_report(context, "pass", checks, metadata, cleanup)
raw = path.read_bytes(); path.unlink()
rejects(lambda: common.finalize_report(context, "pass", dict(reversed(tuple(checks.items()))), metadata, cleanup))
bad_cleanup = dict(cleanup); bad_cleanup["paths"] = False
rejects(lambda: common.finalize_report(context, "pass", checks, metadata, bad_cleanup))
print(raw.decode(), end="")
`;
function runCommon() {
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", pythonProgram, commonPath], {
    cwd: root,
    env: { PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 5_000,
  });
}
test("native common utilities reject hostile metadata without native execution", () => {
  const result = runCommon();
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout) as Record<string, unknown>;
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  const validate = ajv.compile(schema);
  assert.equal(validate(report), true, JSON.stringify(validate.errors));
  assert.equal(report.authority, "exact-run-native-qualification");
  assert.equal(result.stdout, `${JSON.stringify(report)}\n`);
  assert.equal(validate({ ...report, raw_diagnostic: "forbidden" }), false);
});

test("Outcome 2 workflow is six thin exact-head jobs with metadata-only artifacts", () => {
  const workflow = readFileSync(workflowPath, "utf8");
  const ids = ["a", "b", "c", "d", "e"];
  const drivers = [
    "job-a-runtime-mappings",
    "job-b-compression",
    "job-c-descriptors",
    "job-d-process-lifecycle",
    "job-e-sandbox",
  ];
  for (const [index, id] of ids.entries()) {
    const start = workflow.indexOf(`  native-qualification-${id}:`);
    const next = index + 1 < ids.length ? `  native-qualification-${ids[index + 1]}:` : "  native-closure-integration:";
    const declaration = workflow.slice(start, workflow.indexOf(next, start));
    assert.ok(start > 0 && declaration.includes("needs: quality"), id);
    assert.match(declaration, /github\.run_attempt == 1.*head\.repo\.full_name == github\.repository/u);
    assert.match(declaration, /permissions: \{ contents: read \}/u);
    assert.match(declaration, /runs-on: ubuntu-24\.04[\s\S]*timeout-minutes: 10/u);
    assert.match(declaration, /persist-credentials: false[\s\S]*\/usr\/bin\/env -i/u);
    assert.ok(declaration.includes(`scripts/native-qualification/${drivers[index]}.py`));
    assert.match(declaration, /actions\/upload-artifact@[0-9a-f]{40}/u);
  }
  const integration = workflow.slice(
    workflow.indexOf("  native-closure-integration:"),
    workflow.indexOf("  secret-scan:"),
  );
  for (const id of ids) assert.ok(integration.includes(`native-qualification-${id}`));
  assert.match(integration, /github\.run_attempt == 1.*head\.repo\.full_name == github\.repository/u);
  assert.match(integration, /permissions: \{ contents: read \}[\s\S]*\/usr\/bin\/env -i/u);
  assert.match(integration, /scripts\/native-qualification\/thin-integration\.py/u);
  assert.doesNotMatch(
    workflow.slice(workflow.indexOf("  native-qualification-a:"), workflow.indexOf("  secret-scan:")),
    /apt-get|curl|wget|docker|containerd|\bkvm\b|\baws\b|download-artifact/u,
  );
});

test("native common-owned surfaces remain within ADR 0089 exact highs", () => {
  assert.ok(readFileSync(commonPath, "utf8").split("\n").length - 1 <= 220);
  assert.ok(readFileSync(schemaPath, "utf8").split("\n").length - 1 <= 150);
  assert.ok(readFileSync(import.meta.filename, "utf8").split("\n").length - 1 <= 120);
});
