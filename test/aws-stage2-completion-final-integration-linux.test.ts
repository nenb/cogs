import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const image = "ghcr.io/nenb/cogs/sandbox@sha256:db475ee1d01d446fe79cc9efdad40c9589cefe60eb69bce2f35108ea44eb94fe";
const run = (args: string[], timeout = 60_000) =>
  spawnSync("docker", args, {
    encoding: "utf8",
    timeout,
  });

test("pinned Linux Docker without KVM refuses unstaged reviewed G before mutation", { timeout: 240_000 }, () => {
  const available = run(["info", "--format", "{{.OSType}}"], 15_000);
  if (available.status !== 0 || available.stdout.trim() !== "linux") return;
  const volumeResult = run(["volume", "create"], 15_000);
  assert.equal(volumeResult.status, 0, volumeResult.stderr);
  const volume = volumeResult.stdout.trim();
  let helper = "";
  let container = "";
  try {
    const helperResult = run(
      ["create", "--mount", `type=volume,src=${volume},dst=/workspace`, "--entrypoint", "/bin/true", image],
      180_000,
    );
    assert.equal(helperResult.status, 0, helperResult.stderr);
    helper = helperResult.stdout.trim();
    for (const path of ["deploy", "test"]) {
      const copied = run(["cp", path, `${helper}:/workspace/${path}`]);
      assert.equal(copied.status, 0, copied.stderr);
    }
    const created = run(
      [
        "create",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--tmpfs",
        "/run:rw,nosuid,nodev,mode=755",
        "--tmpfs",
        "/var/lib:rw,nosuid,nodev,noexec,mode=755",
        "--mount",
        `type=volume,src=${volume},dst=/workspace,readonly`,
        "--workdir",
        "/workspace",
        "--entrypoint",
        "/usr/bin/python3",
        image,
        "-I",
        "-B",
        "test/aws-stage2-completion-final-integration-linux.py",
      ],
      180_000,
    );
    assert.equal(created.status, 0, created.stderr);
    container = created.stdout.trim();
    const result = run(["start", "--attach", container]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /pinned Linux no-KVM reviewed-G admission refusal passed/u);
    const waited = run(["wait", container], 15_000);
    assert.equal(waited.status, 0, waited.stderr);
    assert.equal(waited.stdout.trim(), "0");
  } finally {
    if (container) run(["rm", "--force", container], 15_000);
    if (helper) run(["rm", "--force", helper], 15_000);
    run(["volume", "rm", "--force", volume], 15_000);
  }
});
