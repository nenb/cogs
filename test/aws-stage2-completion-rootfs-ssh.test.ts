import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const probe = join(root, "test/aws-stage2-completion-rootfs-ssh.py");
const plan = join(root, "deploy/aws-feasibility/remote/completion_rootfs_plan.py");

test("generated rootfs root account and SSH policy are exact and hostile-safe", async () => {
  for (const optimized of [false, true]) {
    const result = spawnSync("python3", [...(optimized ? ["-O"] : []), probe], {
      cwd: root,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /completion rootfs SSH portable policy tests passed/u);
  }

  const source = await readFile(plan, "utf8");
  assert.match(source, /_ROOT_SHADOW_SOURCE = b"root:\*:20627:0:99999:7:::"/u);
  assert.match(source, /_ROOT_SHADOW_PASSWORD = b"x"/u);
  assert.match(source, /AuthenticationMethods publickey/u);
  for (const directive of [
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PermitEmptyPasswords no",
    "UsePAM no",
  ]) {
    assert.equal(source.split(directive).length, 2, directive);
  }
  assert.doesNotMatch(source, /PasswordAuthentication yes|KbdInteractiveAuthentication yes|UsePAM yes/u);
});

test("no-KVM Linux probe is explicit, root-only, pin-bound, and uses the generated sshd", async () => {
  const source = await readFile(probe, "utf8");
  assert.match(source, /COGS_REQUIRE_STAGE2_ROOTFS_SSH_LINUX/u);
  assert.match(source, /FIXED_TAR\.read_bytes\(\)/u);
  assert.match(source, /pins\["ustar"\]\["sha256"\]/u);
  assert.match(source, /unshare\(0x40000000\)/u);
  assert.match(source, /"\/usr\/sbin\/sshd", "-D", "-e"/u);
  assert.match(source, /shadow\[0\] == FINAL_ROOT/u);
  assert.match(source, /bad_key\.returncode != 0/u);
  assert.match(source, /disabled\.returncode != 0/u);
  assert.doesNotMatch(source, /\/dev\/kvm|osito/iu);
});
