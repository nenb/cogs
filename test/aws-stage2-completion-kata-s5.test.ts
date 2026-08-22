import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const py = join(root, "test/aws-stage2-completion-kata-s5.py");
const remote = join(root, "deploy/aws-feasibility/remote");

test("S5 qualification gate and complete lifecycle remain offline and fail closed", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [py], { cwd: root, env, encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion Kata S5 offline qualification\/lifecycle matrix passed/u);

  const optimized = spawnSync("python3", ["-O", py], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.notEqual(optimized.status, 0);

  const [ssh, operation, qualification, entry, ledger, processOwner, coordinator] = await Promise.all([
    readFile(join(remote, "completion_kata_ssh.py"), "utf8"),
    readFile(join(remote, "completion_kata_operation.py"), "utf8"),
    readFile(join(remote, "completion_kata_qualification.py"), "utf8"),
    readFile(join(remote, "run-stage2-completion-remote.sh"), "utf8"),
    readFile(join(remote, "completion_rootfs_ledger.py"), "utf8"),
    readFile(join(remote, "completion_kata_process.py"), "utf8"),
    readFile(join(remote, "completion_kata_coordinator.py"), "utf8"),
  ]);
  assert.match(ssh, /production SSH requires exact attestation\/coordinator/u);
  assert.match(ssh, /ConnectionAttempts=1/u);
  assert.match(operation, /ROOTFS_RELEASE_READY/u);
  assert.match(operation, /ROOTFS_RELEASE_AUTHORIZED/u);
  assert.doesNotMatch(operation, /def append\(/u);
  assert.match(qualification, /host-tools-unqualified/u);
  assert.match(qualification, /kvm-missing-or-unqualified/u);
  assert.doesNotMatch(qualification, /subprocess|socket|boto|urllib|requests/u);
  assert.match(entry, /\/usr\/bin\/python3 -I/u);
  assert.doesNotMatch(entry, /\/usr\/bin\/(?:aws|tofu|terraform|ssh|ctr|ip|nft)(?:\s|$)/u);
  assert.doesNotMatch(ledger, /release_private|release-authorized.*True/u);
  assert.match(ledger, /def _append_release_authorized_record/u);
  assert.match(processOwner, /_install_inherited_fds/u);
  assert.match(processOwner, /adapt_ssh_process_outcome/u);
  assert.match(coordinator, /preparation_bridge\._claim_fixed_static_preparation/u);
  assert.doesNotMatch(coordinator, /_claim_committed_gate|load_final_pin/u);
  assert.match(coordinator, /revoke_before_teardown/u);
});
