import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "scripts/native-qualification/job-a-runtime-mappings.py");
const python = "/usr/bin/python3";
const environment = { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" };

function run(arguments_: string[]) {
  return spawnSync(python, arguments_, {
    cwd: root,
    env: environment,
    encoding: "utf8",
    timeout: 5_000,
  });
}

test("Job A self-test is portable and has no proc or process effects", () => {
  const audit = `
import runpy,sys
path=sys.argv[1]
def guard(event,args):
 if event in {'os.fork','os.posix_spawn','subprocess.Popen'}: raise RuntimeError(event)
 if event == 'open' and str(args[0]).startswith('/proc/'): raise RuntimeError(args[0])
sys.addaudithook(guard)
sys.argv=[path,'--self-test']
runpy.run_path(path,run_name='__main__')
`;
  const result = run(["-I", "-B", "-c", audit, script]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "native qualification A static self-test passed\n");
});

test("Job A exposes only explicit fixed native and static selectors", () => {
  for (const arguments_ of [["-I", "-B", script], ["-I", "-B", script, "--fixture"]]) {
    const result = run(arguments_);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /usage: job-a-runtime-mappings\.py/u);
  }
  const optimized = run(["-O", "-I", "-B", script, "--self-test"]);
  assert.notEqual(optimized.status, 0);
  assert.match(optimized.stderr, /optimized mode is forbidden/u);
});

test("Job A delegates the one real matrix to production closure primitives", () => {
  const source = readFileSync(script, "utf8");
  assert.ok(source.split("\n").length - 1 <= 160);
  assert.match(source, /_resolve_tool\(ops, \*_TOOL\)/u);
  assert.match(source, /_spawn_helper\(ops, preparation, resolved\)/u);
  assert.match(source, /_mapped_closure\(ops, helper, resolved\)/u);
  assert.match(source, /_stop_helper\(ops, preparation, helper\)/u);
  assert.match(source, /_snapshot_fds\(ops\) == baseline_fds/u);
  assert.match(source, /_child_baseline\(ops\) == baseline_children/u);
  assert.match(source, /helper\.pidfd\.state is runtime\._FdState\.CLOSED/u);
  assert.match(source, /WorkflowContext\.from_environ\("A", __file__\)/u);
  assert.match(source, /common\.finalize_report\(context, "pass"/u);
  assert.doesNotMatch(source, /def (?:parse_elf|parse_maps)|subprocess|socket|requests/u);
  assert.doesNotMatch(source, /--path|--pid|--tool|--fixture|--command/u);
  assert.match(source, /"id": "python-mapping", "role": "mapping"/u);
  assert.doesNotMatch(source, /logical_path|\.transcript|\.identity/u);
});
