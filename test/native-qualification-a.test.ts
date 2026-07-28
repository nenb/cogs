import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "scripts/native-qualification/job-a-runtime-mappings.py");
const common = join(root, "scripts/native-qualification/common.py");
const source = readFileSync(script, "utf8");

function portable(program: string) {
  const harness = `
import inspect, runpy, sys
path, common_path = sys.argv[1:]
def audit(event, args):
 if event in {'os.fork','os.posix_spawn','subprocess.Popen'}: raise RuntimeError(event)
 if event == 'open' and str(args[0]).startswith('/proc/'): raise RuntimeError(args[0])
sys.addaudithook(audit)
ns = runpy.run_path(path)
${program}
`;
  return spawnSync("/usr/bin/python3", ["-I", "-B", "-c", harness, script, common], {
    cwd: root,
    env: { PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 5_000,
  });
}

test("Job A portable oracle requires production mapping observations", () => {
  const result = portable(`
revision = '1' * 40
value = {
 'version':'cogs.runtime-qualification/v1', 'marker':'cogs-runtime-qualification-v1',
 'source_revision':revision, 'source_set_sha256':'2'*64, 'closure_sha256':'3'*64,
 'gzip_output_sha256':'4'*64, 'zstd_output_sha256':'4'*64,
 'mapped_generations_exact':True, 'children_reaped':True, 'descendants_reaped':True,
 'mapping_sha256':'5'*64,
 'mapping_objects':[
  {'role':'executable','sha256':'6'*64,'size_bytes':10,'soname':None,'needed':['libc.so.6']},
  {'role':'loader','sha256':'7'*64,'size_bytes':11,'soname':'ld.so.2','needed':[]},
 ],
}
assert len(ns['qualify'](value, revision)) == 3
for name in ('mapped_generations_exact','children_reaped','descendants_reaped'):
 bad=dict(value); bad[name]=False
 try: ns['qualify'](bad, revision)
 except ns['QualificationError']: pass
 else: raise AssertionError(name)
bad=dict(value); bad['source_revision']='0'*40
try: ns['qualify'](bad, revision)
except ns['QualificationError']: pass
else: raise AssertionError('source')
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("Job A exact workflow selector has a no-effects dispatch seam", () => {
  const result = portable(`
events=[]
assert ns['_dispatch'](['--workflow-bound'], lambda: events.append('workflow') or 7) == 7
assert events == ['workflow']
for arguments in ([], ['--native'], ['--native-fixed'], ['--self-test'], ['--fixture']):
 try: ns['_dispatch'](arguments, lambda: events.append('effect'))
 except ns['QualificationError']: pass
 else: raise AssertionError(arguments)
assert events == ['workflow']
`);
  assert.equal(result.status, 0, result.stderr);
});

test("Job A invokes admitted production mapping facts and measures cleanup", () => {
  assert.ok(source.trimEnd().split("\n").length <= 300);
  assert.match(source, /completion_trusted_runtime_launcher\.py/u);
  assert.match(source, /_source_admission\(revision\)/u);
  assert.match(source, /os\.pidfd_open\(pid, 0\)[\s\S]*os\.write\(release_write, b"R"\)/u);
  assert.match(source, /mapped_generations_exact/u);
  assert.match(source, /Snapshot\.capture\(private_root\)/u);
  assert.match(source, /cleanup = baseline\.compare\(private_root\)/u);
  assert.match(source, /WorkflowContext\.from_environ\("A", __file__\)/u);
  assert.match(source, /common\.finalize_report\(context, "pass"/u);
  assert.doesNotMatch(source, /_resolve_tool|_spawn_helper|_mapped_closure|_stop_helper/u);
  assert.doesNotMatch(source, /dict\.fromkeys\(common\.CLEANUP_KEYS, True\)/u);
  assert.doesNotMatch(source, /--native-fixed|--self-test|--fixture|--path|--tool/u);
});

test("Job A uses the tracked common API shape", () => {
  const result = portable(`
common_ns = runpy.run_path(common_path)
assert tuple(inspect.signature(common_ns['WorkflowContext'].from_environ).parameters) == ('expected_job','driver_file')
assert tuple(inspect.signature(common_ns['finalize_report']).parameters)[:5] == ('context','result','checks','metadata','cleanup')
assert common_ns['DRIVERS']['A'] == 'job-a-runtime-mappings.py'
assert tuple(common_ns['CHECK_IDS']['A']) == tuple(ns['CHECKS'])
`);
  assert.equal(result.status, 0, result.stderr);
});
