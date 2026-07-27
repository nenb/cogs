import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const productionPath = join(root, "deploy/aws-feasibility/remote/completion_kata_process.py");
const pythonTestPath = join(root, "test/aws-stage2-completion-kata-process.py");
const ciPath = join(root, ".github/workflows/ci.yml");
const selector = "COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1";

test("S1 portable process suite and narrow native boundary remain exact", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  delete env[selector];
  const result = spawnSync("python3", [pythonTestPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "completion Kata process portable matrix passed; native runtime preflight SKIPPED\n");

  const optimized = spawnSync("python3", ["-O", pythonTestPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.notEqual(optimized.status, 0);
  const [source, companion, workflow] = await Promise.all([
    readFile(productionPath, "utf8"),
    readFile(pythonTestPath, "utf8"),
    readFile(ciPath, "utf8"),
  ]);
  const productionLines = source.split("\n").length - 1;
  assert.ok(productionLines <= 1_843, `production exceeds ADR 0070 hard 1,843: ${productionLines}`);
  assert.match(source, /CommandId = actions\.CommandId/u);
  assert.match(source, /def _parse_contract\(raw, expected_sha256\):/u);
  assert.match(source, /F_SEAL_WRITE \| fcntl\.F_SEAL_GROW \| fcntl\.F_SEAL_SHRINK \| fcntl\.F_SEAL_SEAL/u);
  assert.match(source, /os\.setsid\(\)/u);
  assert.match(source, /os\.fork\(\)/u);
  assert.match(source, /if spec\.inherited_fds:\n {12}_install_inherited_fds\(spec\.inherited_fds\)/u);
  assert.match(source, /libc\.syscall\(436,/u);
  assert.doesNotMatch(source, /RLIMIT_NOFILE|os\.closerange/u);
  assert.match(source, /def _set_parent_death_signal\(expected_parent\):/u);
  assert.match(source, /def _wait_for_preinput_read\(pid, deadline_ns\):/u);
  assert.match(source, /"map_files\/" \+ address/u);

  assert.match(companion, /selected != \[\(_NATIVE_SELECTOR \+ "=1"\)\.encode\(\)\]/u);
  assert.match(companion, /CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb/u);
  assert.match(companion, /fcntl\.F_DUPFD, 4096/u);
  assert.match(companion, /os\.dup2\(base, 198, inheritable=True\)/u);
  assert.match(companion, /_wait_for_preinput_read[\s\S]*_mapped_closure/u);
  assert.match(companion, /_native_parent_death\(False\)[\s\S]*_native_parent_death\(True\)/u);
  assert.match(
    companion,
    /_RuntimeDiscoveryHost\(\)[\s\S]*FixedArchive\.KATA_ZSTD[\s\S]*FixedArchive\.CONTAINERD_GZIP/u,
  );

  const nativeJob = workflow.slice(workflow.indexOf("  native-runtime-preflight:"));
  assert.match(
    nativeJob,
    /"\/usr\/bin\/sudo","-n","--close-from=3","\/usr\/bin\/setpriv","--reuid","0","--regid","0","--clear-groups","--no-new-privs","\/usr\/bin\/unshare","--user","--map-users=0:0:1","--map-groups=0:0:1","--net","--pid","--fork","--mount"/u,
  );
  assert.doesNotMatch(nativeJob, /map-root-user|str\(uid\)|str\(gid\)|newuidmap|newgidmap|chown|RootView/u);
  assert.match(nativeJob, /raw\.count\("\\n"\) != 1 or raw\.split\(\) != \["0", "0", "1"\]/u);
  assert.match(
    nativeJob,
    /"\/usr\/bin\/python3", "\/usr\/bin\/zstd", "\/usr\/bin\/gzip", "\/dev\/null", "\/dev\/urandom"[\s\S]*st_uid,value\.st_gid\) != \(0,0\)/u,
  );
  assert.match(nativeJob, /--bounding-set=-all --inh-caps=-all --ambient-caps=-all[\s\S]*--no-new-privs/u);
  const launcherMatch = nativeJob.match(/<<'SECCOMP'[\s\S]*?\n {10}SECCOMP/u);
  assert.ok(launcherMatch);
  const launcher = launcherMatch[0];
  const direct = launcher.slice(launcher.indexOf("ins=("), launcher.indexOf("F(0x15,0,3,157)"));
  assert.deepEqual(
    [...direct.matchAll(/F\(0x15,0,1,([0-9]+)\),F\(0x06,0,0,0x00050001\)/gu)].map((row) => Number(row[1])),
    [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307, 425, 426, 427, 272, 308, 317],
  );
  assert.match(
    launcher,
    /F\(0x20,0,0,4\),F\(0x15,1,0,0xc000003e\),F\(0x06,0,0,0x80000000\),F\(0x20,0,0,0\),F\(0x45,0,1,0x40000000\),F\(0x06,0,0,0x80000000\)/u,
  );
  assert.match(
    launcher,
    /F\(0x15,0,3,157\),F\(0x20,0,0,16\),F\(0x15,0,1,22\),F\(0x06,0,0,0x00050001\),F\(0x06,0,0,0x7fff0000\)/u,
  );
  assert.equal(launcher.match(/0x80000000/gu)?.length, 2);
  assert.equal(launcher.match(/0x00050001/gu)?.length, 25);
  assert.equal(launcher.match(/0x7fff0000/gu)?.length, 1);
  assert.ok(
    launcher.indexOf("status(False)") < launcher.indexOf("libc.prctl(38,1,0,0,0)") &&
      launcher.indexOf("libc.prctl(38,1,0,0,0)") < launcher.indexOf("libc.prctl(22,2,ctypes.addressof(program),0,0)") &&
      launcher.indexOf("libc.prctl(22,2,ctypes.addressof(program),0,0)") < launcher.indexOf("status(True)") &&
      launcher.indexOf("status(True)") < launcher.indexOf("os.execve"),
  );
  assert.match(
    launcher,
    /os\.execve\("\/usr\/bin\/python3",\("\/usr\/bin\/python3","-I","-B",path\),\{"COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1":"1","PYTHONDONTWRITEBYTECODE":"1"\}\)/u,
  );
  assert.match(
    launcher,
    /except BaseException:[\s\S]*os\.write\(2,b"native seccomp launcher failed\\n"\)[\s\S]*os\._exit\(126\)/u,
  );
  assert.doesNotMatch(launcher, /libseccomp|subprocess|platform|uname|importlib|compile\(/u);
  assert.match(nativeJob, /stdout=output_fd, stderr=subprocess\.STDOUT, close_fds=True, env=\{\}/u);
  assert.match(nativeJob, /os\.unlink\(leaf[\s\S]*st_nlink != 0[\s\S]*os\.rmdir\(name/u);
  assert.match(
    nativeJob,
    /\/usr\/bin\/cmp","--silent"[\s\S]*result\.returncode != 0 or compared\.returncode != 0[\s\S]*print\(marker/u,
  );
  assert.doesNotMatch(nativeJob, /\b(?:apt-get|apt|dnf|yum|apk|brew|curl|wget)\b/u);
});
