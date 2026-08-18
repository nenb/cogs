import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const productionPath = join(root, "deploy/aws-feasibility/remote/completion_kata_process.py");
const historical = join(root, "test/aws-stage2-completion-kata-process.py");
const correction = join(root, "test/aws-stage2-completion-kata-slice-a.py");
const foundations = join(root, ".github/workflows/stage2-workload-linux-foundations.yml");

test("S1 historical process matrix and journal-gated correction", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const history = spawnSync("python3", [historical], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(history.status, 0, history.stderr);
  assert.match(history.stdout, /completion Kata process/u);
  for (const args of [[correction], ["-O", correction]]) {
    const result = spawnSync("python3", args, {
      cwd: root,
      env,
      encoding: "utf8",
      timeout: 120_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Slice A correction matrix passed/u);
  }

  const source = await readFile(productionPath, "utf8");
  assert.match(
    source,
    /def _transact_fixed\(journal, fixed, executable, inherited=\(\), daemon_owner=None, consumption_owner=None, launch_permit=None\):/u,
  );
  assert.match(source, /_record_command_intent[\s\S]*_record_command_preexec[\s\S]*os\.write\(release_w, b"R"\)/u);
  assert.match(source, /selectors\.DefaultSelector/u);
  assert.match(source, /cgroup\.kill/u);
  assert.match(source, /pidfd_send_signal/u);
  assert.match(source, /_set_subreaper\(True\)/u);
  assert.match(source, /def _recover_pending_fixed/u);
  assert.match(source, /LONG_LIVED_CONTAINERD = LongLivedCommand/u);
  assert.match(source, /def _daemon_routes\(\):/u);
  assert.match(source, /def start\(journal, executable\):/u);
  assert.match(source, /signal\.pidfd_send_signal\(state\[2\], signal\.SIGTERM\)/u);
  assert.doesNotMatch(source, /COGS_KATA_PROCESS_TESTING_V1|def _make_test_issuer\(|def _supervise\(/u);
  assert.doesNotMatch(source, /os\.kill(?:pg)?\(/u);
  assert.doesNotMatch(source, /^def (?:run|execute|spawn|issue_command)\(/mu);
  const workflow = await readFile(foundations, "utf8");
  assert.match(workflow, /COGS_REQUIRE_STAGE2_KATA_NATIVE_FOUNDATIONS=1/u);
  assert.match(workflow, /aws-stage2-completion-kata-operation\.py[\s\S]*aws-stage2-completion-kata-process\.py/u);
  assert.match(workflow, /cleanup_native_fixture\(\)[\s\S]*test ! -L[\s\S]*\|\| return 1/u);
  assert.match(workflow, /trap cleanup_on_exit EXIT/u);
  assert.match(
    workflow,
    /COGS_REQUIRE_STAGE2_KATA_NATIVE_SSH_INPUT=1[\s\S]*aws-stage2-completion-kata-ssh-native\.py/u,
  );
  assert.match(workflow, /cleanup_ssh_fixture\(\)[\s\S]*cmp --silent[\s\S]*rm -- "\$target"/u);
  assert.doesNotMatch(workflow, /rm -rf|rm --force/u);
});
