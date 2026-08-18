import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(process.cwd());
const modulePath = join(root, "deploy/aws-feasibility/remote/completion_kata_inputs.py");
const testPath = join(root, "test/aws-stage2-completion-kata-inputs.py");

test("S2 fixed input/control owner is closed, deterministic, and identity-bound", async () => {
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion Kata input\/control owner foundation matrix passed/u);

  const source = await readFile(modulePath, "utf8");
  assert.match(source, /O_TMPFILE/u);
  assert.match(source, /linkat/u);
  assert.match(source, /operation-specific manifest/u);
  assert.match(source, /package-private production/u);
  assert.doesNotMatch(source, /def open_fixed_input_owner/u);
  assert.doesNotMatch(source, /os\.walk|rmtree|glob|subprocess|socket|keyscan/u);
});

test("S2 fixed inputs optional Docker filesystem matrix is explicitly non-authoritative", {
  skip: process.env.COGS_RUN_KATA_INPUTS_DOCKER_V1 !== "1",
}, () => {
  const docker = process.env.COGS_KATA_INPUTS_DOCKER_BINARY ?? "/usr/bin/docker";
  const image = process.env.COGS_KATA_INPUTS_DOCKER_IMAGE ?? "";
  assert.match(docker, /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/u);
  assert.match(image, /^sha256:[0-9a-f]{64}$/u, "set a local Python image ID; pulls are forbidden");
  assert.ok(!root.includes(","), "Docker --mount source cannot contain a comma");

  const privateMount = mkdtempSync(join(tmpdir(), "cogs-kata-inputs-docker-"));
  const sentinel = join(privateMount, ".cogs-kata-inputs-docker-v1");
  const name = `cogs-kata-inputs-${randomUUID()}`;
  chmodSync(privateMount, 0o700);
  writeFileSync(sentinel, "cogs-kata-inputs-docker-v1\n", { mode: 0o400 });
  try {
    const result = spawnSync(
      docker,
      [
        "run",
        "--pull=never",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SYS_ADMIN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "FOWNER",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        "apparmor=unconfined",
        "--pids-limit",
        "128",
        "--memory",
        "768m",
        "--cpus",
        "2",
        "--tmpfs",
        "/work:rw,nosuid,nodev,noexec,mode=0700,size=536870912",
        "--mount",
        `type=bind,src=${root},dst=/repo,readonly`,
        "--mount",
        `type=bind,src=${privateMount},dst=/cogs-private,readonly`,
        "--workdir",
        "/repo",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "COGS_RUN_KATA_INPUTS_LINUX_V1=1",
        "--env",
        "COGS_KATA_INPUTS_DOCKER_V1=1",
        "--env",
        "COGS_KATA_INPUTS_TMPDIR=/work",
        image,
        "python3",
        "/repo/test/aws-stage2-completion-kata-inputs.py",
      ],
      { cwd: root, encoding: "utf8", timeout: 180_000, maxBuffer: 2 * 1024 * 1024 },
    );
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /NONAUTHORITATIVE Docker filesystem functional harness constraints proved/u);
    assert.match(result.stdout, /completion Kata inputs LINUX EUID-0 FUNCTIONAL matrix passed/u);
    assert.equal(readFileSync(sentinel, "utf8"), "cogs-kata-inputs-docker-v1\n");
  } finally {
    spawnSync(docker, ["rm", "--force", name], { encoding: "utf8", timeout: 10_000 });
    rmSync(privateMount, { recursive: true, force: true });
  }
});
