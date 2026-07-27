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
  const sandbox = nativeJob.slice(nativeJob.indexOf("SANDBOX'"), nativeJob.indexOf("          SANDBOX"));
  assert.match(nativeJob, /os\.open\(checkout, os\.O_PATH\|os\.O_DIRECTORY\|os\.O_NOFOLLOW\|os\.O_CLOEXEC\)/u);
  assert.ok(nativeJob.indexOf("checkout_fd = os.open") < nativeJob.indexOf("temp_fd = os.open"));
  assert.match(
    nativeJob,
    /if checkout_fd != 3:[\s\S]*os\.dup2\(checkout_fd, 3, inheritable=False\)[\s\S]*os\.close\(checkout_fd\)[\s\S]*else:[\s\S]*os\.set_inheritable\(3, False\)[\s\S]*checkout_identity = os\.fstat\(3\)/u,
  );
  assert.match(
    nativeJob,
    /"\/usr\/bin\/sudo","-n","--close-from=4","\/usr\/bin\/setpriv","--reuid","0","--regid","0","--clear-groups","--no-new-privs","\/usr\/bin\/unshare","--user","--map-users=0:0:1","--map-groups=0:0:1","--net","--pid","--fork","--mount"/u,
  );
  assert.match(
    nativeJob,
    /subprocess\.run\(command, stdin=subprocess\.DEVNULL, stdout=output_fd, stderr=subprocess\.STDOUT, close_fds=True, pass_fds=\(3,\), env=\{\}, check=False\)/u,
  );
  assert.doesNotMatch(nativeJob, /preexec_fn|stdin=None|--close-from=(?:[0-35-9]|[1-9][0-9]+)|--preserve-env|"-C"/u);
  assert.match(
    sandbox,
    /os\.getppid\(\)[\s\S]*\{"0","1","2","3"\}[\s\S]*\/fdinfo\/3[\s\S]*os\.O_PATH\|os\.O_DIRECTORY\|os\.O_NOFOLLOW/u,
  );
  assert.match(sandbox, /raw\.count\("\\n"\) != 1 or raw\.split\(\) != \["0","0","1"\]/u);
  assert.match(sandbox, /wanted = \(\*expected\[:2\],\*overflow,stat\.S_IFDIR\)/u);
  assert.equal(
    sandbox.match(/^ {10}\/usr\/bin\/mount --no-canonicalize --bind \/proc\/self\/fd\/3 "\$root\/src"$/gmu)?.length,
    1,
  );
  assert.equal(sandbox.match(/\/proc\/self\/fd\/3/gu)?.length, 1);
  assert.equal(sandbox.match(/\/usr\/bin\/python3 -I -c "\$verify_checkout_bind"/gu)?.length, 2);
  assert.match(
    sandbox,
    /fdinfo\/3[\s\S]*source = one[\s\S]*identity\(descriptor\)[\s\S]*identity\(target_stat\)[\s\S]*bound\["source"\]/u,
  );
  assert.match(
    sandbox,
    / {10}VERIFY\n {10}exec 3>&-\n {10}\/usr\/bin\/python3 -I - <<'CLOSED'[\s\S]*\{"0","1","2"\}[\s\S]* {10}CLOSED\n {10}COGS_NATIVE_TEST_PATH=\$test_path exec \/usr\/sbin\/chroot/u,
  );
  assert.doesNotMatch(
    sandbox,
    /close_inherited_fds|\/proc\/\$\$\/fd\/\*|mount --bind "\$checkout"|realpath\([^\n]*checkout|readlink[^\n]*checkout|\/home\/runner\/work/u,
  );
  assert.doesNotMatch(nativeJob, /map-root-user|newuidmap|newgidmap|chown|chmod|setfacl|copyfile|RootView/u);
  assert.match(nativeJob, /--bounding-set=-all --inh-caps=-all --ambient-caps=-all[\s\S]*--no-new-privs/u);
  assert.match(nativeJob, /os\.unlink\(leaf[\s\S]*st_nlink != 0[\s\S]*os\.rmdir\(name/u);
  assert.match(nativeJob, /\/usr\/bin\/cmp","--silent"[\s\S]*print\(marker/u);
  assert.doesNotMatch(nativeJob, /\b(?:apt-get|apt|dnf|yum|apk|brew|curl|wget)\b/u);
});
