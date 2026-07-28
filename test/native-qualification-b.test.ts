import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "scripts/native-qualification/job-b-compression.py");
const common = join(root, "scripts/native-qualification/common.py");
const source = readFileSync(script, "utf8");
const facts = `
  mapped_generations_exact user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact namespace_ownership_exact
  namespace_handles_exact pid_one supplementary_groups_empty effective_capabilities_zero permitted_capabilities_zero inheritable_capabilities_zero
  bounding_capabilities_zero ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
  seccomp_program_exact seccomp_denials_exact exec_descriptor_consumed no_acquisition_route root_readonly_noexec root_has_no_proc
  host_paths_absent checkout_absent limits_exact descriptors_restored children_reaped descendants_reaped mounts_restored paths_restored
  namespaces_released namespace_handles_released
`
  .trim()
  .split(/\s+/u);

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

test("Job B portable oracle requires the exact production closure result", () => {
  const result = portable(`
revision='1'*40
names=${JSON.stringify(facts)}
value={name:True for name in names}
value.update(version='cogs.runtime-qualification/v1', marker='cogs-runtime-qualification-v1',
 source_revision=revision, source_set_sha256='2'*64, closure_sha256='3'*64,
 gzip_output_sha256='4'*64, zstd_output_sha256='4'*64,
 compression_tools=[
  {'id':name, 'source_sha256':digest, 'source_size_bytes':10,
   'sealed_sha256':digest, 'sealed_size_bytes':10, 'seal_mask':63,
   'execution_mapping_sha256':mapping, 'output_sha256':'4'*64}
  for name,digest,mapping in (('gzip','5'*64,'6'*64),('zstd','7'*64,'8'*64))])
rows=ns['qualify'](value, revision)
assert len(rows) == 2 and all(row['seal_mask'] == 15 for row in rows)
for name in names:
 bad=dict(value); bad[name]=False
 try: ns['qualify'](bad, revision)
 except ns['QualificationError']: pass
 else: raise AssertionError(name)
for name, replacement in (('source_revision','0'*40), ('zstd_output_sha256','5'*64)):
 bad=dict(value); bad[name]=replacement
 try: ns['qualify'](bad, revision)
 except ns['QualificationError']: pass
 else: raise AssertionError(name)
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("Job B exact workflow selector dispatches without native effects", () => {
  const result = portable(`
events=[]
assert ns['_dispatch'](['--workflow-bound'], lambda: events.append('workflow') or 9) == 9
for arguments in ([], ['--native'], ['--native-fixed'], ['--fixture'], ['--command']):
 try: ns['_dispatch'](arguments, lambda: events.append('effect'))
 except ns['QualificationError']: pass
 else: raise AssertionError(arguments)
assert events == ['workflow']
`);
  assert.equal(result.status, 0, result.stderr);
});

test("Job B supplies compatible fixed T0 source/root authority to production", () => {
  assert.ok(source.trimEnd().split("\n").length <= 350);
  assert.match(source, /completion_trusted_runtime_launcher\.py/u);
  assert.match(source, /_source_admission\(revision\)/u);
  assert.match(source, /cogs\.runtime-source-admission\/compression-v1/u);
  assert.match(source, /libc\.unshare\(0x10000000 \| 0x00020000\)/u);
  assert.match(source, /libc\.mount\(source, b"\/run"/u);
  assert.match(source, /os\.pidfd_open\(pid, 0\)[\s\S]*os\.write\(release_write, b"R"\)/u);
  assert.match(source, /os\.execve\("\/usr\/bin\/python3"/u);
  assert.match(source, /Snapshot\.capture\(private_root\)/u);
  assert.match(source, /cleanup = baseline\.compare\(private_root\)/u);
  assert.match(source, /WorkflowContext\.from_environ\("B", __file__\)/u);
  assert.match(source, /common\.finalize_report\(context, "pass"/u);
  assert.doesNotMatch(source, /NativeAdapter|subprocess\.Popen|ROOT, os\.O_RDONLY[\s\S]*pass_fds/u);
  assert.doesNotMatch(source, /dict\.fromkeys\(common\.CLEANUP_KEYS, True\)/u);
  assert.doesNotMatch(source, /--native-fixed|--fixture|--path|--command/u);
});

test("Job B uses exact tracked common API identities", () => {
  const result = portable(`
common_ns=runpy.run_path(common_path)
assert tuple(inspect.signature(common_ns['WorkflowContext'].from_environ).parameters) == ('expected_job','driver_file')
assert tuple(inspect.signature(common_ns['finalize_report']).parameters)[:5] == ('context','result','checks','metadata','cleanup')
assert common_ns['DRIVERS']['B'] == 'job-b-compression.py'
assert tuple(common_ns['CHECK_IDS']['B']) == tuple(ns['CHECKS'])
`);
  assert.equal(result.status, 0, result.stderr);
});
