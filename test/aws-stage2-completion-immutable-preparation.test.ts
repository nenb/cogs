import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const script = "test/aws-stage2-completion-immutable-preparation.py";
const image = "ghcr.io/nenb/cogs/sandbox@sha256:db475ee1d01d446fe79cc9efdad40c9589cefe60eb69bce2f35108ea44eb94fe";

test("fresh-root immutable preparation transaction is exact and rolls back every fault cut", () => {
  const result = spawnSync("python3", ["-B", script], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 60_000,
    env: { PATH: "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /fresh-root immutable preparation transaction\/no-KVM fault matrix passed/u);
});

test("Linux Docker with no KVM runs immutable preparation tests without launch authority", { timeout: 240_000 }, () => {
  const available = spawnSync("docker", ["info", "--format", "{{.OSType}}"], {
    encoding: "utf8",
    timeout: 15_000,
  });
  if (available.status !== 0 || available.stdout.trim() !== "linux") return;
  const volumeResult = spawnSync("docker", ["volume", "create"], { encoding: "utf8", timeout: 15_000 });
  assert.equal(volumeResult.status, 0, volumeResult.stderr);
  const volume = volumeResult.stdout.trim();
  let helper = "";
  let container = "";
  const run = (args: string[], timeout = 180_000) => spawnSync("docker", args, { encoding: "utf8", timeout });
  try {
    const helperResult = run([
      "create",
      "--mount",
      `type=volume,src=${volume},dst=/workspace`,
      "--entrypoint",
      "/bin/true",
      image,
    ]);
    assert.equal(helperResult.status, 0, helperResult.stderr);
    helper = helperResult.stdout.trim();
    for (const path of ["deploy", "test"]) {
      const copied = run(["cp", path, `${helper}:/workspace/${path}`]);
      assert.equal(copied.status, 0, copied.stderr);
    }
    const created = run([
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
      "--mount",
      `type=volume,src=${volume},dst=/workspace,readonly`,
      "--workdir",
      "/workspace",
      "--env",
      "COGS_EXPECT_NO_KVM=1",
      "--entrypoint",
      "/usr/bin/python3",
      image,
      "-I",
      "-B",
      script,
    ]);
    assert.equal(created.status, 0, created.stderr);
    container = created.stdout.trim();
    const result = run(["start", "--attach", container]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /fresh-root immutable preparation transaction\/no-KVM fault matrix passed/u);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /QMP|KVM enabled|containerd.*start|SSH/u);
  } finally {
    if (container) run(["rm", "--force", container], 15_000);
    if (helper) run(["rm", "--force", helper], 15_000);
    run(["volume", "rm", "--force", volume], 15_000);
  }
});
