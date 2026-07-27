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

  assert.match(workflow, /^ {2}native-runtime-preflight:$/mu);
  const nativeJob = workflow.slice(workflow.indexOf("  native-runtime-preflight:"));
  const observerMatch = nativeJob.match(/<<'DESCRIPTOR'[\s\S]*?\n {10}DESCRIPTOR/u);
  assert.ok(observerMatch);
  const observer = observerMatch[0];
  assert.match(observer, /\['PPid'\][\s\S]*\["NSpid"\]\.split\(\)[\s\S]*names = set\(os\.listdir\(base\+"\/fd"\)\)/u);
  assert.match(observer, /open\(base\+"\/fdinfo\/"\+name[\s\S]*row\[0\]=="flags:"[\s\S]*flags = int\(values\[0\],8\)/u);
  assert.match(observer, /number == 3 and sys\.argv\[5\] == "before"[\s\S]*flags & os\.O_CLOEXEC/u);
  assert.match(observer, /stat\.S_ISSOCK\(before\.st_mode\)[\s\S]*object_id in namespaces/u);
  assert.match(observer, /elif object_id == expected\[:2\] or not flags & os\.O_CLOEXEC/u);
  assert.match(observer, /unstable parent descriptor table[\s\S]*checkout descriptor lifecycle/u);
  assert.doesNotMatch(observer, /F_GETFL|set\(os\.listdir\([^)]*\)\) != \{"0","1","2"/u);
  const acceptsNonCloexec = observer.replace(" or not flags & os.O_CLOEXEC", "");
  assert.notEqual(acceptsNonCloexec, observer);
  assert.doesNotMatch(acceptsNonCloexec, /not flags & os\.O_CLOEXEC/u);
  assert.match(
    nativeJob,
    /exec 3>&-\n {10}\/usr\/bin\/python3 -I -c "\$descriptor_observer"[^\n]+ after\n {10}COGS_NATIVE_TEST_PATH=\$test_path exec \/usr\/sbin\/chroot/u,
  );
});
